// backend/src/middlewares/security.ts - Enhanced with path traversal protection
import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { config } from '../config';
import { ApiError } from '../utils/ApiError';
import path from 'path';

// Extend the session interface to include csrfToken
declare module 'express-session' {
  interface SessionData {
    csrfToken?: string;
  }
}

/**
 * Path traversal protection middleware
 * Protects against directory traversal attacks in URLs and parameters
 */
export const pathTraversalProtection = (req: Request, res: Response, next: NextFunction) => {
  try {
    // Safely get request properties with fallbacks
    const urlPath = req.path || req.url || '';
    const params = req.params || {};
    const query = req.query || {};
    const body = req.body || {};
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';

    // Check URL path for traversal patterns
    if (containsTraversalPatterns(urlPath)) {
      console.warn(`Path traversal attempt detected in URL: ${urlPath} from IP: ${ip}`);
      return next(ApiError.forbidden(
        'Path traversal not allowed',
        'PATH_TRAVERSAL_DETECTED'
      ));
    }

    // Check all path parameters for traversal patterns
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string' && containsTraversalPatterns(value)) {
        console.warn(`Path traversal attempt in param ${key}: ${value} from IP: ${ip}`);
        return next(ApiError.forbidden(
          `Invalid path parameter: ${key}`,
          'PATH_TRAVERSAL_DETECTED'
        ));
      }
    }

    // Check query parameters that might contain file paths
    const pathQueryParams = ['filepath', 'path', 'file', 'dir', 'folder', 'location'];
    for (const param of pathQueryParams) {
      const value = query[param];
      if (typeof value === 'string' && containsTraversalPatterns(value)) {
        console.warn(`Path traversal attempt in query ${param}: ${value} from IP: ${ip}`);
        return next(ApiError.forbidden(
          `Invalid query parameter: ${param}`,
          'PATH_TRAVERSAL_DETECTED'
        ));
      }
    }

    // Check request body for path-related fields
    if (body && typeof body === 'object') {
      const pathBodyFields = ['filepath', 'path', 'filename', 'directory', 'location'];
      for (const field of pathBodyFields) {
        const value = body[field];
        if (typeof value === 'string' && containsTraversalPatterns(value)) {
          console.warn(`Path traversal attempt in body ${field}: ${value} from IP: ${ip}`);
          return next(ApiError.forbidden(
            `Invalid field: ${field}`,
            'PATH_TRAVERSAL_DETECTED'
          ));
        }
      }
    }

    next();
  } catch (error) {
    console.error('Path traversal protection error:', error);
    next(ApiError.internal('Security check failed'));
  }
};

/**
 * Enhanced file path validation specifically for file operations
 */
export const filePathSecurity = (req: Request, res: Response, next: NextFunction) => {
  try {
    // Extract filepath from params (common in file routes)
    const filepath = req.params.filepath || req.params['0']; // '0' for wildcard routes
    
    if (!filepath) {
      return next(); // No filepath to validate
    }

    // Comprehensive file path validation
    const validation = validateFilePath(filepath);
    
    if (!validation.isValid) {
      console.warn(`File path security violation: ${validation.reason} - Path: ${filepath} from IP: ${req.ip}`);
      return next(ApiError.forbidden(
        validation.reason,
        'INVALID_FILE_PATH'
      ));
    }

    // Sanitize and normalize the path - with proper type checking
    if (validation.sanitizedPath) {
      if (req.params.filepath) {
        req.params.filepath = validation.sanitizedPath;
      }
      if (req.params['0']) {
        req.params['0'] = validation.sanitizedPath;
      }
    }

    next();
  } catch (error) {
    console.error('File path security error:', error);
    next(ApiError.internal('File path security check failed'));
  }
};

/**
 * Check if a string contains path traversal patterns
 */
function containsTraversalPatterns(input: string): boolean {
  if (!input || typeof input !== 'string') {
    return false;
  }

  try {
    // Normalize the input for better detection
    const normalized = input.toLowerCase().replace(/\\/g, '/');
    
    // Path traversal patterns to detect
    const traversalPatterns = [
      '../',           // Basic traversal
      '..\\',          // Windows style
      '%2e%2e%2f',     // URL encoded ../
      '%2e%2e%5c',     // URL encoded ..\
      '..%2f',         // Partial encoding
      '..%5c',         // Partial encoding
      '%252e%252e%252f', // Double encoded
      '....//',        // Double dot bypass
      '....\\\\',      // Windows double dot bypass
      '..;/',          // Semicolon bypass
      '..//',          // Extra slash
      '..\\\\',        // Extra backslash
    ];

    // Check for any traversal patterns
    for (const pattern of traversalPatterns) {
      if (normalized.includes(pattern)) {
        return true;
      }
    }

    // Check for absolute paths (could be dangerous)
    if (normalized.startsWith('/') || /^[a-z]:/i.test(normalized)) {
      return true;
    }

    // Check for null bytes (can bypass some filters)
    if (input.includes('\0') || input.includes('%00')) {
      return true;
    }

    return false;
  } catch (error) {
    // If any error occurs in pattern checking, err on the side of caution
    console.error('Error in traversal pattern detection:', error);
    return true; // Block potentially malicious input
  }
}

/**
 * Comprehensive file path validation
 */
function validateFilePath(filepath: string): {
  isValid: boolean;
  reason?: string;
  sanitizedPath?: string;
} {
  try {
    if (!filepath || typeof filepath !== 'string') {
      return { isValid: false, reason: 'Invalid file path format' };
    }

    // Check for traversal patterns
    if (containsTraversalPatterns(filepath)) {
      return { isValid: false, reason: 'Path traversal not allowed' };
    }

    // Check path length
    if (filepath.length > 500) {
      return { isValid: false, reason: 'File path too long' };
    }

    // Check for dangerous characters
    const dangerousChars = /[<>:"|?*\x00-\x1f]/;
    if (dangerousChars.test(filepath)) {
      return { isValid: false, reason: 'Invalid characters in file path' };
    }

    // Normalize path separators
    let normalized = filepath.replace(/\\/g, '/');
    
    // Remove leading slashes
    normalized = normalized.replace(/^\/+/, '');
    
    // Remove trailing slashes
    normalized = normalized.replace(/\/+$/, '');
    
    // Remove double slashes
    normalized = normalized.replace(/\/+/g, '/');
    
    // Check if path becomes empty after normalization
    if (!normalized) {
      return { isValid: false, reason: 'Empty file path after normalization' };
    }

    // Validate file extension (if present)
    const extension = path.extname(normalized).toLowerCase();
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp'];
    
    if (extension && !allowedExtensions.includes(extension)) {
      return { isValid: false, reason: `File type not allowed: ${extension}` };
    }

    return {
      isValid: true,
      sanitizedPath: normalized
    };
  } catch (error) {
    console.error('File path validation error:', error);
    return { isValid: false, reason: 'File path validation failed' };
  }
}

/**
 * CORS configuration
 */
const corsOptions = {
  origin: function (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
    try {
      const allowedOrigins = (config as any).allowedOrigins || process.env.ALLOWED_ORIGINS?.split(',') || 
      ['http://localhost:3000', 'http://localhost:5173'];
      
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin) return callback(null, true);
      
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`CORS: Origin ${origin} not allowed`);
        callback(new Error('Not allowed by CORS'), false);
      }
    } catch (error) {
      console.error('CORS configuration error:', error);
      callback(new Error('CORS configuration error'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-CSRF-Token',
    'X-Request-ID'
  ],
  exposedHeaders: ['X-CSRF-Token', 'X-Request-ID'],
  maxAge: 86400 // 24 hours
};

/**
 * Content Security Policy configuration
 */
const cspDirectives = {
  defaultSrc: ["'self'"],
  styleSrc: ["'self'", "'unsafe-inline'"],
  scriptSrc: ["'self'"],
  imgSrc: ["'self'", "data:", "https:"],
  connectSrc: ["'self'"],
  fontSrc: ["'self'"],
  objectSrc: ["'none'"],
  mediaSrc: ["'self'"],
  frameSrc: ["'none'"],
  baseUri: ["'self'"],
  formAction: ["'self'"],
  frameAncestors: ["'none'"],
  upgradeInsecureRequests: []
};

/**
 * Rate limiting configurations for different endpoint types
 */
export const createRateLimit = (windowMs: number, max: number, message?: string) => {
  return rateLimit({
    windowMs,
    max,
    message: message || 'Too many requests from this IP',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        status: 'error',
        message: 'Rate limit exceeded',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

/**
 * Request ID middleware for tracking
 */
export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const requestId = req.get('X-Request-ID') || generateRequestId();
  req.headers['x-request-id'] = requestId;
  res.set('X-Request-ID', requestId);
  next();
};

function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * General security middleware with path protection
 */
export const generalSecurity = [
  // Request tracking first
  requestIdMiddleware,
  
  // Path traversal protection early in the chain
  pathTraversalProtection,
  
  // CORS
  cors(corsOptions),
  
  // Helmet for security headers
  helmet({
    contentSecurityPolicy: {
      directives: cspDirectives,
      reportOnly: config.nodeEnv === 'development'
    },
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true
    },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
  }),
  
  // Additional security headers
  (req: Request, res: Response, next: NextFunction) => {
    try {
      // Safely get request properties
      const path = req.path || req.url || '';
      
      // Prevent clickjacking
      res.setHeader('X-Frame-Options', 'DENY');
      
      // Prevent MIME type sniffing
      res.setHeader('X-Content-Type-Options', 'nosniff');
      
      // Enable XSS protection
      res.setHeader('X-XSS-Protection', '1; mode=block');
      
      // Referrer policy
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      
      // Feature policy (restrict browser features)
      res.setHeader('Permissions-Policy', 
        'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()'
      );
      
      // Cache control for sensitive routes
      if (path.includes('/auth/') || path.includes('/api/')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Surrogate-Control', 'no-store');
      }
      
      next();
    } catch (error) {
      console.error('Security headers middleware error:', error);
      // Still proceed with the request even if headers fail
      next();
    }
  }
];

/**
 * File-specific security middleware
 */
export const fileSecurity = [
  ...generalSecurity,
  
  // Enhanced file path validation
  filePathSecurity,
  
  // File-specific rate limiting
  createRateLimit(60 * 1000, 50, 'Too many file requests'), // 50 per minute
  
  // File-specific headers
  (req: Request, res: Response, next: NextFunction) => {
    // Prevent execution of served files
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Download-Options', 'noopen');
    
    // Add cache headers for static files
    if (req.path.match(/\.(jpg|jpeg|png|bmp|gif|webp)$/i)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1 year
    }
    
    next();
  }
];

/**
 * Authentication-specific security middleware
 */
export const authSecurity = [
  ...generalSecurity,
  
  // Conditional rate limiting - more permissive for tests
  ...(process.env.NODE_ENV === 'test' 
    ? [createRateLimit(60 * 1000, 1000, 'Too many test requests')] // 1000 per minute for tests
    : [createRateLimit(15 * 60 * 1000, 10, 'Too many authentication attempts')] // 10 per 15 minutes for production
  ),
  
  // Additional auth-specific headers
  (req: Request, res: Response, next: NextFunction) => {
    // Prevent caching of auth responses
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    
    // Security headers for auth
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    
    next();
  }
];

/**
 * API-specific security middleware
 */
export const apiSecurity = [
  ...generalSecurity,
  
  // Standard API rate limiting
  createRateLimit(15 * 60 * 1000, 100), // 100 per 15 minutes
  
  // API-specific headers
  (req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-API-Version', '1.0');
    next();
  }
];

/**
 * File upload security middleware
 */
export const fileUploadSecurity = [
  ...generalSecurity,
  
  // Stricter rate limiting for uploads
  createRateLimit(60 * 60 * 1000, 20), // 20 uploads per hour
  
  // Upload-specific headers
  (req: Request, res: Response, next: NextFunction) => {
    // Prevent execution of uploaded files
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', 'attachment');
    
    next();
  }
];

/**
 * CSRF Protection Middleware
 * Note: This is a basic implementation. For production, consider using 'csurf' package
 */
export const csrfProtection = (req: Request, res: Response, next: NextFunction) => {
  // Skip CSRF for GET requests and certain endpoints
  if (req.method === 'GET' || req.path.includes('/auth/login') || req.path.includes('/auth/register')) {
    return next();
  }
  
  // Defensive programming: handle malformed request objects
  const headers = req.headers || {};
  const session = req.session || {};
  
  const token = headers['x-csrf-token'] as string;
  const sessionToken = session.csrfToken;
  
  if (!token || !sessionToken || token !== sessionToken) {
    return res.status(403).json({
      status: 'error',
      message: 'Invalid CSRF token',
      code: 'CSRF_INVALID'
    });
  }
  
  next();
};

/**
 * Request size protection middleware
 */
export const requestSizeLimits = (req: Request, res: Response, next: NextFunction) => {
  try {
    const contentType = req.get('Content-Type') || '';
    
    if (contentType.includes('multipart/form-data')) {
      req.setTimeout(5 * 60 * 1000); // 5 minute timeout for uploads
    } else if (contentType.includes('application/json')) {
      req.setTimeout(30 * 1000); // 30 second timeout for JSON
    } else {
      req.setTimeout(10 * 1000); // 10 second timeout for others
    }
    
    next();
  } catch (error) {
    console.error('Request size limits error:', error);
    next(); // Continue even if timeout setting fails
  }
};

/**
 * Complete security middleware stack for different use cases
 */
export const securityMiddleware = {
  general: generalSecurity,
  auth: authSecurity,
  api: apiSecurity,
  fileUpload: fileUploadSecurity,
  file: fileSecurity, // New: specific for file serving
  csrf: csrfProtection,
  pathTraversal: pathTraversalProtection, // Standalone for custom use
  filePath: filePathSecurity // Standalone for file operations
};

/**
 * Enhanced general security middleware with request limits
 */
export const enhancedGeneralSecurity = [
  ...generalSecurity,
  requestSizeLimits
];