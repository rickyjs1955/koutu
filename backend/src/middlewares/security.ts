// backend/src/middlewares/security.ts
import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { config } from '../config';

// Extend the session interface to include csrfToken
declare module 'express-session' {
  interface SessionData {
    csrfToken?: string;
  }
}

/**
 * CORS configuration
 */
const corsOptions = {
  origin: function (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
    const allowedOrigins = (config as any).allowedOrigins || process.env.ALLOWED_ORIGINS?.split(',') || 
    ['http://localhost:3000', 'http://localhost:5173'];
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'), false);
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
    'X-CSRF-Token'
  ],
  exposedHeaders: ['X-CSRF-Token'],
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
 * General security middleware
 */
export const generalSecurity = [
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
    if (req.path.includes('/auth/') || req.path.includes('/api/')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.setHeader('Surrogate-Control', 'no-store');
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
  
  const token = req.headers['x-csrf-token'] as string;
  const sessionToken = req.session?.csrfToken;
  
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
 * Note: Input sanitization is handled by the dedicated sanitize.ts module
 * This avoids redundancy and ensures consistent sanitization across the app
 */

/**
 * Complete security middleware stack for different use cases
 * Note: Input sanitization is handled by the dedicated sanitize.ts module
 */
export const securityMiddleware = {
  general: generalSecurity,
  auth: authSecurity,
  api: apiSecurity,
  fileUpload: fileUploadSecurity,
  csrf: csrfProtection
  // inputSanitization removed to avoid redundancy with sanitize.ts
};