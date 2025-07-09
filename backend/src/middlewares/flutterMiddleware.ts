// backend/src/middlewares/flutterMiddleware.ts
import { Request, Response, NextFunction } from 'express';
import { EnhancedApiError } from './errorHandler';

interface FlutterRequestInfo {
  isFlutter: boolean;
  flutterVersion?: string;
  dartVersion?: string;
  platform?: 'android' | 'ios' | 'web' | 'desktop';
  deviceInfo?: {
    model?: string;
    os?: string;
    appVersion?: string;
  };
}

declare global {
  namespace Express {
    interface Request {
      flutter: FlutterRequestInfo;
    }
  }
}

/**
 * Enhanced Flutter detection and request enrichment middleware
 * Analyzes User-Agent and headers to provide Flutter context
 */
export const flutterDetectionMiddleware = (req: Request, res: Response, next: NextFunction) => {
  try {
    const userAgent = req.get('User-Agent') || '';
    const xFlutterHeader = req.get('X-Flutter-App') || '';
    const xPlatformHeader = req.get('X-Platform') || '';
    
    // Enhanced Flutter detection with multiple signals
    const isFlutter = detectFlutterApp(userAgent, xFlutterHeader);
    
    // Extract version information
    const flutterVersion = extractFlutterVersion(userAgent);
    const dartVersion = extractDartVersion(userAgent);
    
    // Detect platform with fallbacks
    const platform = detectPlatform(userAgent, xPlatformHeader);
    
    // Extract device information
    const deviceInfo = extractDeviceInfo(userAgent, req.headers);
    
    // Add Flutter info to request
    req.flutter = {
      isFlutter,
      flutterVersion,
      dartVersion,
      platform,
      deviceInfo
    };
    
    // Add Flutter-specific headers for debugging (development only)
    if (process.env.NODE_ENV === 'development' && isFlutter) {
      res.set('X-Flutter-Detected', 'true');
      res.set('X-Flutter-Platform', platform || 'unknown');
      if (flutterVersion) res.set('X-Flutter-Version', flutterVersion);
    }
    
    next();
  } catch (error) {
    console.error('Flutter detection middleware error:', error);
    // Don't fail the request if detection fails
    req.flutter = { isFlutter: false };
    next();
  }
};

/**
 * Flutter-optimized request validation middleware
 * Applies Flutter-specific validations and optimizations
 */
export const flutterValidationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.flutter?.isFlutter) {
      return next();
    }
    
    // Flutter-specific content type validation
    const contentType = req.get('Content-Type') || '';
    
    if (req.method === 'POST' && contentType.includes('multipart/form-data')) {
      // Flutter multipart uploads validation
      const contentLength = parseInt(req.get('Content-Length') || '0');
      const maxSize = getMaxUploadSize(req.flutter.platform);
      
      if (contentLength > maxSize) {
        throw EnhancedApiError.validation(
          `File upload exceeds Flutter app limits (${Math.round(maxSize / (1024 * 1024))}MB)`,
          'file_size',
          { 
            maxSizeMB: Math.round(maxSize / (1024 * 1024)),
            receivedSizeMB: Math.round(contentLength / (1024 * 1024)),
            platform: req.flutter.platform 
          }
        );
      }
    }
    
    // Validate Flutter-specific headers
    validateFlutterHeaders(req);
    
    next();
  } catch (error) {
    if (error instanceof EnhancedApiError) {
      return next(error);
    }
    console.error('Flutter validation middleware error:', error);
    next(EnhancedApiError.internalError('Flutter validation failed', error instanceof Error ? error : new Error(String(error))));
  }
};

/**
 * Flutter response optimization middleware
 * Optimizes responses for Flutter HTTP client
 */
export const flutterResponseMiddleware = (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.flutter?.isFlutter) {
      return next();
    }
    
    // Store original json method
    const originalJson = res.json.bind(res);
    
    // Override json method with Flutter optimizations
    res.json = function(body: any) {
      // Add Flutter-optimized headers
      this.set('Cache-Control', 'no-cache, no-store, must-revalidate');
      this.set('X-Flutter-Optimized', 'true');
      this.set('Access-Control-Expose-Headers', 'X-Flutter-Optimized, X-Request-ID, X-Response-Time');
      
      // Add response timing for mobile debugging
      const responseTime = Date.now() - (req as any).startTime;
      if (responseTime) {
        this.set('X-Response-Time', `${responseTime}ms`);
      }
      
      // Ensure consistent response structure for Flutter
      if (body && typeof body === 'object' && !body.success && !body.error) {
        // Wrap non-standard responses for Flutter compatibility
        body = {
          success: true,
          data: body,
          timestamp: new Date().toISOString(),
          requestId: req.get('X-Request-ID') || generateRequestId(),
          meta: {
            platform: req.flutter.platform,
            flutterVersion: req.flutter.flutterVersion,
            responseTime: responseTime ? `${responseTime}ms` : undefined
          }
        };
      }
      
      return originalJson(body);
    };
    
    next();
  } catch (error) {
    console.error('Flutter response middleware error:', error);
    // Continue without Flutter optimizations if error occurs
    next();
  }
};

/**
 * Flutter performance monitoring middleware
 * Tracks performance metrics for mobile optimization
 */
export const flutterPerformanceMiddleware = (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.flutter?.isFlutter) {
      return next();
    }
    
    // Start timing
    (req as any).startTime = Date.now();
    
    // Monitor response completion
    res.on('finish', () => {
      const responseTime = Date.now() - (req as any).startTime;
      const contentLength = res.get('Content-Length') || '0';
      
      // Log performance metrics for Flutter requests
      logFlutterPerformance({
        method: req.method,
        path: req.path,
        platform: req.flutter.platform,
        flutterVersion: req.flutter.flutterVersion,
        responseTime,
        statusCode: res.statusCode,
        contentLength: parseInt(contentLength),
        userAgent: req.get('User-Agent')
      });
      
      // Alert on slow responses for mobile
      if (responseTime > 2000) { // 2 seconds
        console.warn(`Slow Flutter response: ${req.method} ${req.path} - ${responseTime}ms`, {
          platform: req.flutter.platform,
          statusCode: res.statusCode
        });
      }
    });
    
    next();
  } catch (error) {
    console.error('Flutter performance middleware error:', error);
    next();
  }
};

// =========================== HELPER FUNCTIONS ===========================

/**
 * Detect if request is from Flutter app
 */
function detectFlutterApp(userAgent: string, flutterHeader: string): boolean {
  // Check explicit Flutter header first
  if (flutterHeader && flutterHeader.toLowerCase() === 'true') {
    return true;
  }
  
  // Check User-Agent patterns
  const flutterPatterns = [
    /dart\/\d+\.\d+/i,           // Dart version
    /flutter\/\d+\.\d+/i,        // Flutter version
    /dart:io/i,                  // Dart IO library
    /flutter/i,                  // Generic Flutter
    /dartvm/i                    // Dart VM
  ];
  
  return flutterPatterns.some(pattern => pattern.test(userAgent));
}

/**
 * Extract Flutter version from User-Agent
 */
function extractFlutterVersion(userAgent: string): string | undefined {
  const match = userAgent.match(/flutter\/(\d+\.\d+\.\d+(?:\+\d+)?)/i);
  return match?.[1];
}

/**
 * Extract Dart version from User-Agent
 */
function extractDartVersion(userAgent: string): string | undefined {
  const match = userAgent.match(/dart\/(\d+\.\d+\.\d+)/i);
  return match?.[1];
}

/**
 * Detect platform from User-Agent and headers
 */
function detectPlatform(userAgent: string, platformHeader: string): 'android' | 'ios' | 'web' | 'desktop' | undefined {
  // Check explicit platform header first
  const headerPlatform = platformHeader.toLowerCase();
  if (['android', 'ios', 'web', 'desktop'].includes(headerPlatform)) {
    return headerPlatform as any;
  }
  
  // Detect from User-Agent
  if (/android/i.test(userAgent)) return 'android';
  if (/iphone|ipad|ios/i.test(userAgent)) return 'ios';
  if (/chrome|safari|firefox/i.test(userAgent) && !/mobile/i.test(userAgent)) return 'web';
  if (/windows|macos|linux/i.test(userAgent)) return 'desktop';
  
  return undefined;
}

/**
 * Extract device information from User-Agent and headers
 */
function extractDeviceInfo(userAgent: string, headers: any): FlutterRequestInfo['deviceInfo'] {
  const deviceInfo: FlutterRequestInfo['deviceInfo'] = {};
  
  // Extract app version from custom header
  const appVersion = headers['x-app-version'] || headers['x-version'];
  if (appVersion) {
    deviceInfo.appVersion = appVersion;
  }
  
  // Extract device model (basic detection)
  const androidModel = userAgent.match(/\(([^)]+)\)/)?.[1];
  if (androidModel && /android/i.test(userAgent)) {
    deviceInfo.model = androidModel;
    deviceInfo.os = 'Android';
  }
  
  const iosModel = userAgent.match(/(iphone|ipad)/i)?.[1];
  if (iosModel) {
    deviceInfo.model = iosModel;
    deviceInfo.os = 'iOS';
  }
  
  return Object.keys(deviceInfo).length > 0 ? deviceInfo : undefined;
}

/**
 * Get maximum upload size based on platform
 */
function getMaxUploadSize(platform?: string): number {
  const baseSizes = {
    android: 50 * 1024 * 1024,  // 50MB for Android
    ios: 25 * 1024 * 1024,      // 25MB for iOS (more memory constrained)
    web: 10 * 1024 * 1024,      // 10MB for web
    desktop: 100 * 1024 * 1024  // 100MB for desktop
  };
  
  return baseSizes[platform as keyof typeof baseSizes] || baseSizes.web;
}

/**
 * Validate Flutter-specific headers
 */
function validateFlutterHeaders(req: Request): void {
  const suspiciousHeaders = [
    'x-flutter-exploit',
    'x-dart-injection',
    'x-mobile-hack'
  ];
  
  for (const header of suspiciousHeaders) {
    if (req.get(header)) {
      throw EnhancedApiError.validation(
        'Invalid request headers detected',
        'headers',
        { suspiciousHeader: header }
      );
    }
  }
}

/**
 * Log Flutter performance metrics
 */
function logFlutterPerformance(metrics: {
  method: string;
  path: string;
  platform?: string;
  flutterVersion?: string;
  responseTime: number;
  statusCode: number;
  contentLength: number;
  userAgent?: string;
}): void {
  // In production, this would send to monitoring service
  if (process.env.NODE_ENV === 'development') {
    console.log('📱 Flutter Performance:', {
      endpoint: `${metrics.method} ${metrics.path}`,
      platform: metrics.platform,
      responseTime: `${metrics.responseTime}ms`,
      status: metrics.statusCode,
      size: `${Math.round(metrics.contentLength / 1024)}KB`
    });
  }
}

/**
 * Generate request ID for tracking
 */
function generateRequestId(): string {
  return `flutter_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Combined Flutter middleware stack
 * Use this for easy application to routes
 */
export const flutterMiddlewareStack = [
  flutterDetectionMiddleware,
  flutterValidationMiddleware,
  flutterResponseMiddleware,
  flutterPerformanceMiddleware
];

/**
 * Flutter middleware for specific use cases
 */
export const flutterMiddleware = {
  detection: flutterDetectionMiddleware,
  validation: flutterValidationMiddleware,
  response: flutterResponseMiddleware,
  performance: flutterPerformanceMiddleware,
  stack: flutterMiddlewareStack
};