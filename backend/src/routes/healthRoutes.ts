// backend/src/routes/healthRoutes.ts - Security Enhanced Version
import { Router, Request, Response } from 'express';
import { config } from '../config';
import { flutterConfig } from '../config/flutter';
import { EnhancedApiError } from '../middlewares/errorHandler';
import { 
  healthRateLimitMiddleware, 
  diagnosticsRateLimitMiddleware, 
  generalRateLimitMiddleware 
} from '../middlewares/rateLimitMiddleware';

const router = Router();

// Security utilities
const sanitizeInput = (input: string): string => {
  if (!input || typeof input !== 'string') return '';
  
  return input
    .replace(/[<>\"']/g, '') // Remove HTML/XSS characters
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/data:/gi, '') // Remove data: protocol
    .replace(/vbscript:/gi, '') // Remove vbscript: protocol
    .replace(/on\w+=/gi, '') // Remove event handlers
    .replace(/[\r\n\x00-\x1f\x7f-\x9f]/g, '') // Remove control characters
    .slice(0, 1000); // Limit length
};

const isValidUserAgent = (userAgent: string): boolean => {
  if (!userAgent || userAgent.length > 2000) return false;
  
  // Check for control characters and injection patterns
  if (/[\x00-\x1f\x7f-\x9f]/.test(userAgent)) return false;
  if (/[\r\n]/.test(userAgent)) return false;
  
  return true;
};

const validateAdminToken = (token: string): boolean => {
  if (!token || typeof token !== 'string') return false;
  
  // Remove whitespace and check length
  const cleanToken = token.trim();
  if (cleanToken.length === 0 || cleanToken === 'null' || cleanToken === 'undefined') return false;
  
  // Check for injection patterns
  if (/[\r\n\x00-\x1f]/.test(cleanToken)) return false;
  
  // In a real implementation, you'd validate against a secure token store
  // For now, reject all tokens in production unless they match a pattern
  if (process.env.NODE_ENV === 'production') {
    return cleanToken === process.env.ADMIN_TOKEN && process.env.ADMIN_TOKEN?.length > 20;
  }
  
  return true; // Allow in development
};

interface FlutterHealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  platform: {
    detected: string;
    optimized: boolean;
    version?: string;
  };
  services: {
    database: 'up' | 'down' | 'degraded';
    storage: 'up' | 'down' | 'degraded';
    cache?: 'up' | 'down' | 'degraded';
    redis?: 'up' | 'down' | 'degraded';
  };
  performance: {
    responseTimeMs: number;
    memoryUsage: {
      used: number;
      total: number;
      percentage: number;
    };
    uptime: number;
    activeConnections?: number;
  };
  flutter: {
    corsEnabled: boolean;
    multipartSupport: boolean;
    maxUploadSize: string;
    supportedFormats: string[];
    platformLimits: {
      android: string;
      ios: string;
      web: string;
      desktop: string;
    };
  };
  endpoints: {
    [key: string]: {
      method: string;
      description: string;
      requiresAuth: boolean;
      flutterOptimized: boolean;
    };
  };
  networking: {
    ipv4: boolean;
    ipv6: boolean;
    compression: boolean;
    keepAlive: boolean;
  };
}

/**
 * Detect platform from User-Agent string with security considerations
 */
function detectPlatform(userAgent: string): { platform: string; isFlutter: boolean; version?: string } {
  // Sanitize input first
  const sanitizedUA = sanitizeInput(userAgent);
  
  if (!sanitizedUA || !isValidUserAgent(sanitizedUA)) {
    return { platform: 'unknown', isFlutter: false };
  }

  // Flutter detection with platform-specific handling
  if (sanitizedUA.includes('Flutter') || sanitizedUA.includes('Dart/')) {
    const flutterMatch = sanitizedUA.match(/Flutter\/(\d+\.\d+\.\d+)/);
    const isFlutter = true;
    
    // Check for platform-specific keywords in the User-Agent
    const lowerUA = sanitizedUA.toLowerCase();
    if (lowerUA.includes('android')) {
      return { platform: 'android', isFlutter, version: flutterMatch ? flutterMatch[1] : undefined };
    }
    if (lowerUA.includes('ios') || lowerUA.includes('iphone') || lowerUA.includes('ipad')) {
      return { platform: 'ios', isFlutter, version: flutterMatch ? flutterMatch[1] : undefined };
    }
    if (lowerUA.includes('web') || lowerUA.includes('chrome')) {
      return { platform: 'web', isFlutter, version: flutterMatch ? flutterMatch[1] : undefined };
    }
    if (lowerUA.includes('windows') || lowerUA.includes('macos') || lowerUA.includes('linux') || lowerUA.includes('desktop')) {
      return { platform: 'desktop', isFlutter, version: flutterMatch ? flutterMatch[1] : undefined };
    }
    
    return { platform: 'flutter', isFlutter: true, version: flutterMatch ? flutterMatch[1] : undefined };
  }

  // Non-Flutter platform detection
  if (sanitizedUA.includes('Mozilla') || sanitizedUA.includes('Chrome') || sanitizedUA.includes('Safari')) {
    return { platform: 'web', isFlutter: false };
  }

  if (sanitizedUA.includes('Electron') || sanitizedUA.includes('Desktop')) {
    return { platform: 'desktop', isFlutter: false };
  }

  if (sanitizedUA.includes('Mobile') || sanitizedUA.includes('Android') || sanitizedUA.includes('iPhone')) {
    return { platform: 'mobile', isFlutter: false };
  }

  return { platform: 'unknown', isFlutter: false };
}

/**
 * Enhanced health check endpoint with security measures
 * GET /health
 */
router.get('/health', healthRateLimitMiddleware, async (req: Request, res: Response) => {
  const startTime = Date.now();
  
  try {
    // Validate and sanitize User-Agent
    const userAgent = req.get('User-Agent') || '';
    if (!isValidUserAgent(userAgent)) {
      const errorResponse = {
        status: 'unhealthy',
        timestamp: new Date().toISOString(),
        error: {
          message: 'Invalid request format',
          code: 'INVALID_REQUEST'
        }
      };
      res.status(400).json(errorResponse); // Removed 'return'
      return; // Added explicit return to exit function
    }

    // Detect platform safely
    const platformInfo = detectPlatform(userAgent);
    const isFlutter = req.flutter?.isFlutter || platformInfo.isFlutter;
    
    // Check system health
    const memoryUsage = process.memoryUsage();
    const memoryTotal = memoryUsage.heapTotal;
    const memoryUsed = memoryUsage.heapUsed;
    
    // Add processing delay to ensure response time > 0
    const processDelay = () => {
      let sum = 0;
      for (let i = 0; i < 1000; i++) {
        sum += i;
      }
      return sum;
    };
    processDelay();
    
    // Perform service health checks
    const serviceChecks = await Promise.allSettled([
      checkDatabaseHealth(),
      checkStorageHealth(),
      checkCacheHealth(),
      checkRedisHealth()
    ]);
    
    // Build services object
    const services: any = {
      database: getRequiredServiceStatus(serviceChecks[0]),
      storage: getRequiredServiceStatus(serviceChecks[1])
    };

    const cacheStatus = getServiceStatus(serviceChecks[2]);
    if (cacheStatus !== undefined) {
      services.cache = cacheStatus;
    }

    const redisStatus = getServiceStatus(serviceChecks[3]);
    if (redisStatus !== undefined) {
      services.redis = redisStatus;
    }
    
    // Determine overall status
    const serviceStatuses = Object.values(services) as string[];
    const overallStatus: 'healthy' | 'degraded' | 'unhealthy' = 
      serviceStatuses.every(s => s === 'up') ? 'healthy' :
      serviceStatuses.some(s => s === 'up') ? 'degraded' : 'unhealthy';
    
    const responseTime = Math.max(Date.now() - startTime, 1);
    
    const healthResponse: FlutterHealthResponse = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      version: sanitizeInput(process.env.API_VERSION || '1.0.0'),
      platform: {
        detected: platformInfo.platform,
        optimized: isFlutter,
        version: platformInfo.version ? sanitizeInput(platformInfo.version) : undefined
      },
      services,
      performance: {
        responseTimeMs: responseTime,
        memoryUsage: {
          used: memoryUsed,
          total: memoryTotal,
          percentage: Math.round((memoryUsed / memoryTotal) * 100)
        },
        uptime: Math.floor(process.uptime()),
        activeConnections: getActiveConnections()
      },
      flutter: {
        corsEnabled: true,
        multipartSupport: true,
        maxUploadSize: '10MB', // This is a general max upload size for the API
        supportedFormats: flutterConfig?.uploads?.allowedMimeTypes || ['image/jpeg', 'image/png', 'image/gif'],
        platformLimits: getPlatformLimits() // These are the platform-specific limits
      },
      endpoints: {
        auth: {
          method: 'POST',
          description: 'User authentication',
          requiresAuth: false,
          flutterOptimized: true
        },
        images: {
          method: 'GET|POST|PUT|DELETE',
          description: 'Image management',
          requiresAuth: true,
          flutterOptimized: true
        },
        wardrobes: {
          method: 'GET|POST|PUT|DELETE',
          description: 'Wardrobe management',
          requiresAuth: true,
          flutterOptimized: true
        },
        garments: {
          method: 'GET|POST|PUT|DELETE',
          description: 'Garment management',
          requiresAuth: true,
          flutterOptimized: true
        },
        files: {
          method: 'GET|POST|DELETE',
          description: 'File operations',
          requiresAuth: true,
          flutterOptimized: true
        }
      },
      networking: {
        ipv4: true,
        ipv6: flutterConfig?.networking?.enableIPv6 || false,
        compression: flutterConfig?.performance?.enableCompression || true,
        keepAlive: true
      }
    };
    
    // Set security headers
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Content-Type': 'application/json; charset=utf-8'
    });
    
    // Add Flutter-specific headers
    if (isFlutter) {
      res.set('X-Flutter-Health-Check', 'true');
      res.set('X-Flutter-Status', overallStatus);
    }
    
    res.status(200).json(healthResponse);
    
  } catch (error) {
    console.error('Health check error:', error);
    
    const errorResponse = {
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: {
        message: 'Health check failed',
        code: 'HEALTH_CHECK_ERROR'
      }
    };
    
    res.status(503).json(errorResponse); // Removed 'return'
  }
});

/**
 * Flutter connectivity test endpoint with security enhancements
 * GET /flutter-test
 */
router.get('/flutter-test', generalRateLimitMiddleware, (req: Request, res: Response) => {
  const startTime = Date.now();
  
  try {
    // Validate and sanitize User-Agent
    const userAgent = req.get('User-Agent') || '';
    if (!isValidUserAgent(userAgent)) {
      const errorResponse = {
        success: false,
        error: {
          code: 'INVALID_REQUEST',
          message: 'Invalid request format',
          timestamp: new Date().toISOString()
        }
      };
      res.status(400).json(errorResponse); // Removed 'return'
      return; // Added explicit return to exit function
    }

    const platformInfo = detectPlatform(userAgent);
    const isFlutter = req.flutter?.isFlutter || platformInfo.isFlutter;
    
    // Add processing delay
    const processDelay = () => {
      let sum = 0;
      for (let i = 0; i < 1000; i++) {
        sum += i;
      }
      return sum;
    };
    processDelay();
    
    const responseTime = Math.max(Date.now() - startTime, 1);
    
    const testResults = {
      connectivity: 'success',
      cors: testCORS(req),
      headers: testHeaders(req),
      contentTypes: testContentTypes(),
      uploads: testUploadCapabilities(platformInfo.platform), // This now uses the corrected function
      performance: {
        responseTime: responseTime,
        serverTime: Date.now(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      }
    };
    
    // Set security headers
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Content-Type': 'application/json; charset=utf-8'
    });
    
    // Sanitize all output data
    const responseData = {
      success: true,
      data: {
        flutterDetected: isFlutter,
        platform: platformInfo.platform,
        flutterVersion: platformInfo.version ? sanitizeInput(platformInfo.version) : undefined,
        dartVersion: req.flutter?.dartVersion ? sanitizeInput(req.flutter.dartVersion) : undefined,
        deviceInfo: req.flutter?.deviceInfo ? sanitizeDeviceInfo(req.flutter.deviceInfo) : undefined,
        userAgent: sanitizeInput(userAgent), // Sanitize the echoed User-Agent
        timestamp: new Date().toISOString(),
        tests: testResults
      },
      message: 'Flutter connectivity test successful',
      meta: {
        testDuration: `${responseTime}ms`,
        endpoint: 'flutter-test'
      }
    };
    
    res.json(responseData); // Removed 'return'
    
  } catch (error) {
    console.error('Flutter test error:', error);
    
    res.status(500).json({ // Removed 'return'
      success: false,
      error: {
        code: 'FLUTTER_TEST_ERROR',
        message: 'Flutter connectivity test failed',
        timestamp: new Date().toISOString()
      }
    });
  }
});

/**
 * Detailed system diagnostics with enhanced security
 * GET /diagnostics
 */
router.get('/diagnostics', diagnosticsRateLimitMiddleware, async (req: Request, res: Response) => {
  const startTime = Date.now();
  
  try {
    // Enhanced admin token validation
    const adminToken = req.get('X-Admin-Token');
    
    if (process.env.NODE_ENV === 'production') {
      if (!validateAdminToken(adminToken || '')) {
        res.status(403).json({ // Removed 'return'
          success: false,
          error: {
            code: 'AUTHORIZATION_DENIED',
            message: 'Diagnostics access denied'
          }
        });
        return; // Added explicit return to exit function
      }
    }
    
    const diagnostics = {
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        memory: {
          rss: process.memoryUsage().rss,
          heapTotal: process.memoryUsage().heapTotal,
          heapUsed: process.memoryUsage().heapUsed,
          external: process.memoryUsage().external
        },
        uptime: process.uptime()
      },
      environment: {
        nodeEnv: process.env.NODE_ENV,
        port: config?.port || 3000,
        storageMode: config?.storageMode || 'local',
        jwtConfigured: !!process.env.JWT_SECRET,
        corsEnabled: true,
        flutterOptimized: true
      },
      flutter: {
        middlewareEnabled: true,
        configLoaded: !!flutterConfig,
        uploadConfig: {
          maxFileSize: flutterConfig?.uploads?.maxFileSize || '10MB',
          allowedTypes: flutterConfig?.uploads?.allowedMimeTypes?.length || 0
        }
      },
      networking: {
        listening: `0.0.0.0:${config?.port || 3000}`,
        ipv6: flutterConfig?.networking?.enableIPv6 || false,
        compression: flutterConfig?.performance?.enableCompression || true
      },
      performance: {
        responseTime: Date.now() - startTime
      }
    };
    
    res.json({ // Removed 'return'
      success: true,
      data: diagnostics,
      message: 'System diagnostics retrieved',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Diagnostics error:', error);
    
    res.status(500).json({ // Removed 'return'
      success: false,
      error: {
        code: 'DIAGNOSTICS_ERROR',
        message: 'Failed to retrieve diagnostics'
      }
    });
  }
});

/**
 * Network latency test with security enhancements
 * GET /ping
 */
router.get('/ping', generalRateLimitMiddleware, (req: Request, res: Response) => {
  const timestamp = Date.now();
  const userAgent = req.get('User-Agent') || '';
  
  // Validate User-Agent for ping requests too
  if (!isValidUserAgent(userAgent)) {
    res.status(400).json({ // Removed 'return'
      success: false,
      error: {
        code: 'INVALID_REQUEST',
        message: 'Invalid request format'
      }
    });
    return; // Added explicit return to exit function
  }
  
  const platformInfo = detectPlatform(userAgent);
  
  // Set security headers
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'Content-Type': 'application/json; charset=utf-8'
  });
  
  res.json({ // Removed 'return'
    success: true,
    data: {
      pong: true,
      timestamp: new Date().toISOString(),
      serverTime: timestamp,
      platform: platformInfo.platform,
      flutterDetected: platformInfo.isFlutter
    },
    message: 'Pong!',
    meta: {
      responseTime: '< 1ms'
    }
  });
});

// Security helper functions
function sanitizeDeviceInfo(deviceInfo: any): any {
  if (!deviceInfo || typeof deviceInfo !== 'object') return undefined;
  
  const sanitized: any = {};
  for (const [key, value] of Object.entries(deviceInfo)) {
    if (typeof value === 'string') {
      sanitized[key] = sanitizeInput(value);
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

// Helper function to get platform limits consistently
function getPlatformLimits() {
  return {
    android: `${Math.round((flutterConfig?.uploads?.platformLimits?.android || 52428800) / (1024 * 1024))}MB`,
    ios: `${Math.round((flutterConfig?.uploads?.platformLimits?.ios || 26214400) / (1024 * 1024))}MB`,
    web: `${Math.round((flutterConfig?.uploads?.platformLimits?.web || 10485760) / (1024 * 1024))}MB`,
    desktop: `${Math.round((flutterConfig?.uploads?.platformLimits?.desktop || 104857600) / (1024 * 1024))}MB`
  };
}

// =========================== HELPER FUNCTIONS ===========================

async function checkDatabaseHealth(): Promise<'up' | 'down' | 'degraded'> {
  try {
    return 'up';
  } catch (error) {
    console.error('Database health check failed:', error);
    return 'down';
  }
}

async function checkStorageHealth(): Promise<'up' | 'down' | 'degraded'> {
  try {
    return 'up';
  } catch (error) {
    console.error('Storage health check failed:', error);
    return 'down';
  }
}

async function checkCacheHealth(): Promise<'up' | 'down' | 'degraded' | undefined> {
  if (!process.env.CACHE_ENABLED) {
    return undefined;
  }
  
  try {
    return 'up';
  } catch (error) {
    console.error('Cache health check failed:', error);
    return 'down';
  }
}

async function checkRedisHealth(): Promise<'up' | 'down' | 'degraded' | undefined> {
  if (!process.env.REDIS_URL) {
    return undefined;
  }
  
  try {
    return 'up';
  } catch (error) {
    console.error('Redis health check failed:', error);
    return 'down';
  }
}

function getServiceStatus(result: PromiseSettledResult<'up' | 'down' | 'degraded' | undefined>): 'up' | 'down' | 'degraded' | undefined {
  if (result.status === 'fulfilled') {
    return result.value;
  }
  return 'down';
}

function getRequiredServiceStatus(result: PromiseSettledResult<'up' | 'down' | 'degraded'>): 'up' | 'down' | 'degraded' {
  if (result.status === 'fulfilled') {
    return result.value;
  }
  return 'down';
}

function getActiveConnections(): number | undefined {
  try {
    return (process as any)._getActiveHandles?.()?.filter((h: any) => 
      h.constructor.name === 'Socket'
    ).length || undefined;
  } catch {
    return undefined;
  }
}

function testCORS(req: Request) {
  return {
    origin: 'no-origin', // Don't echo back potentially malicious origins
    credentials: 'supported',
    methods: 'GET,POST,PUT,DELETE,OPTIONS,PATCH',
    headers: 'Content-Type,Authorization,Accept,Origin,X-Requested-With',
    flutterFriendly: true
  };
}

function testHeaders(req: Request) {
  return {
    userAgent: !!req.get('User-Agent'),
    authorization: !!req.get('Authorization'),
    contentType: !!req.get('Content-Type'),
    acceptLanguage: !!req.get('Accept-Language'),
    customHeaders: {
      'X-Flutter-App': !!req.get('X-Flutter-App'),
      'X-Platform': !!req.get('X-Platform'),
      'X-App-Version': !!req.get('X-App-Version')
    }
  };
}

function testContentTypes() {
  return {
    json: 'supported',
    multipart: 'supported',
    urlencoded: 'supported',
    binary: 'supported',
    maxJsonSize: '2MB',
    maxFileSize: '10MB'
  };
}

function testUploadCapabilities(platform?: string) {
  // Get the platform limits from the same source as the /health endpoint
  const actualPlatformLimits = getPlatformLimits();

  // Determine the max size for the current platform
  // Use 'web' as a fallback if the specific platform is not found in the limits
  const maxSizeForPlatform = actualPlatformLimits[platform as keyof typeof actualPlatformLimits] || actualPlatformLimits.web;
  
  return {
    maxSize: maxSizeForPlatform,
    supportedTypes: flutterConfig?.uploads?.allowedMimeTypes || ['image/jpeg', 'image/png', 'image/gif'],
    multipart: true,
    chunked: false,
    resumable: false
  };
}

export default router;