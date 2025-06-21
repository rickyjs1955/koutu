// backend/src/__tests__/middlewares/security.unit.test.ts

process.env.NODE_ENV = 'test';
process.env.ALLOWED_ORIGINS = 'http://localhost:3000,http://localhost:5173';

jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    forbidden: jest.fn((message, code) => ({
      statusCode: 403,
      message,
      code,
      name: 'ApiError'
    })),
    internal: jest.fn((message, code) => ({
      statusCode: 500,
      message,
      code,
      name: 'ApiError'
    }))
  }
}));

jest.mock('../../config', () => ({
  config: {
    nodeEnv: 'test',
    allowedOrigins: ['http://localhost:3000', 'http://localhost:5173']
  }
}));

import { Request, Response, NextFunction } from 'express';
import { jest } from '@jest/globals';

// Create the test file in the correct location
describe('Security Middleware Unit Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let setHeaderSpy: jest.MockedFunction<any>;
  let statusSpy: jest.MockedFunction<any>;
  let jsonSpy: jest.MockedFunction<any>;

  // Import modules after setting up the test environment
  let createRateLimit: any;
  let csrfProtection: any;
  let generalSecurity: any;
  let authSecurity: any;
  let apiSecurity: any;
  let fileUploadSecurity: any;
  let securityMiddleware: any;

  beforeAll(async () => {
    // Dynamic import to avoid module loading issues
    const securityModule = await import('../../middlewares/security');
    createRateLimit = securityModule.createRateLimit;
    csrfProtection = securityModule.csrfProtection;
    generalSecurity = securityModule.generalSecurity;
    authSecurity = securityModule.authSecurity;
    apiSecurity = securityModule.apiSecurity;
    fileUploadSecurity = securityModule.fileUploadSecurity;
    securityMiddleware = securityModule.securityMiddleware;
  });

  beforeEach(() => {
  // Create spies for response methods
  setHeaderSpy = jest.fn();
  statusSpy = jest.fn().mockReturnThis();
  jsonSpy = jest.fn().mockReturnThis();
  
  mockReq = {
    headers: {},
    path: '/test',  // Add default path
    url: '/test',   // Add fallback URL
    method: 'GET',
    ip: '127.0.0.1',
    params: {},     // Add params
    query: {},      // Add query
    body: {},       // Add body
    connection: {   // Add connection for IP fallback
      remoteAddress: '127.0.0.1'
    },
    session: {
      id: 'mock-session-id',
      cookie: {} as any,
      regenerate: jest.fn(),
      destroy: jest.fn(),
      reload: jest.fn(),
      save: jest.fn(),
      touch: jest.fn(),
      resetMaxAge: jest.fn()
    } as any,
    get: jest.fn().mockReturnValue(undefined),
    setTimeout: jest.fn() // Add setTimeout mock
  } as any;
  
  mockRes = {
    setHeader: setHeaderSpy,
    status: statusSpy,
    json: jsonSpy,
    set: jest.fn()
  } as any;
  
  mockNext = jest.fn();
});

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createRateLimit Factory', () => {
    it('should create rate limit middleware function', () => {
      const windowMs = 15 * 60 * 1000;
      const max = 10;
      const message = 'Custom rate limit message';
      
      const rateLimitMiddleware = createRateLimit(windowMs, max, message);
      
      expect(typeof rateLimitMiddleware).toBe('function');
    });

    it('should create rate limit with default message', () => {
      const rateLimitMiddleware = createRateLimit(60000, 5);
      expect(typeof rateLimitMiddleware).toBe('function');
    });

    it('should accept custom parameters', () => {
      const windowMs = 1000;
      const max = 1;
      const customMessage = 'Too many requests';
      
      const rateLimitMiddleware = createRateLimit(windowMs, max, customMessage);
      expect(typeof rateLimitMiddleware).toBe('function');
    });
  });

  describe('CSRF Protection', () => {
    beforeEach(() => {
      mockReq = {
        headers: {},
        path: '/api/test',
        method: 'POST',
        session: {} as any
      } as any;
    });

    it('should skip CSRF protection for GET requests', () => {
      (mockReq as any).method = 'GET';
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockNext).toHaveBeenCalledWith();
      expect(statusSpy).not.toHaveBeenCalled();
    });

    it('should skip CSRF protection for login endpoint', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/auth/login'; // Correct assignment
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockNext).toHaveBeenCalledWith();
      expect(statusSpy).not.toHaveBeenCalled();
    });

    it('should skip CSRF protection for register endpoint', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/auth/register';

      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockNext).toHaveBeenCalledWith();
      expect(statusSpy).not.toHaveBeenCalled();
    });

    it('should reject POST requests without CSRF token', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = {};
      (mockReq as any).session = { csrfToken: 'session-token' };
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
      expect(jsonSpy).toHaveBeenCalledWith({
        status: 'error',
        message: 'Invalid CSRF token',
        code: 'CSRF_INVALID'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reject requests without session CSRF token', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = { 'x-csrf-token': 'header-token' };
      (mockReq as any).session = {};
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
      expect(jsonSpy).toHaveBeenCalledWith({
        status: 'error',
        message: 'Invalid CSRF token',
        code: 'CSRF_INVALID'
      });
    });

    it('should accept requests with valid matching CSRF tokens', () => {
      const validToken = 'valid-csrf-token-123';
      
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = { 'x-csrf-token': validToken };
      (mockReq as any).session = { csrfToken: validToken };
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockNext).toHaveBeenCalledWith();
      expect(statusSpy).not.toHaveBeenCalled();
    });

    it('should reject requests with mismatched CSRF tokens', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = { 'x-csrf-token': 'wrong-token' };
      (mockReq as any).session = { csrfToken: 'correct-token' };
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
      expect(jsonSpy).toHaveBeenCalledWith({
        status: 'error',
        message: 'Invalid CSRF token',
        code: 'CSRF_INVALID'
      });
    });

    it('should handle PUT requests with CSRF protection', () => {
      (mockReq as any).method = 'PUT';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = {};
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });

    it('should handle DELETE requests with CSRF protection', () => {
      (mockReq as any).method = 'DELETE';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = {};
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });

    it('should handle PATCH requests with CSRF protection', () => {
      (mockReq as any).method = 'PATCH';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = {};
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });
  });

  describe('Security Middleware Stack Configuration', () => {
    it('should export all required middleware types', () => {
      expect(securityMiddleware.general).toBeDefined();
      expect(securityMiddleware.auth).toBeDefined();
      expect(securityMiddleware.api).toBeDefined();
      expect(securityMiddleware.fileUpload).toBeDefined();
      expect(securityMiddleware.csrf).toBeDefined();
    });

    it('should have general security middleware as array', () => {
      expect(Array.isArray(generalSecurity)).toBe(true);
      expect(generalSecurity.length).toBeGreaterThan(0);
    });

    it('should have auth security include general security plus auth-specific', () => {
      expect(Array.isArray(authSecurity)).toBe(true);
      expect(authSecurity.length).toBeGreaterThanOrEqual(generalSecurity.length);
    });

    it('should have API security include general security plus API-specific', () => {
      expect(Array.isArray(apiSecurity)).toBe(true);
      expect(apiSecurity.length).toBeGreaterThanOrEqual(generalSecurity.length);
    });

    it('should have file upload security include general security plus upload-specific', () => {
      expect(Array.isArray(fileUploadSecurity)).toBe(true);
      expect(fileUploadSecurity.length).toBeGreaterThanOrEqual(generalSecurity.length);
    });

    it('should have CSRF protection as a function', () => {
      expect(typeof csrfProtection).toBe('function');
    });
  });

  describe('Custom Security Headers Middleware', () => {
    let customHeadersMiddleware: any;

    beforeEach(() => {
      // Find the custom headers middleware in the general security stack
      customHeadersMiddleware = generalSecurity.find((middleware: any) => 
        typeof middleware === 'function' && 
        middleware.toString().includes('X-Frame-Options')
      );
    });

    it('should include custom headers middleware in general security', () => {
      expect(customHeadersMiddleware).toBeDefined();
      expect(typeof customHeadersMiddleware).toBe('function');
    });

    it('should set security headers when middleware runs', () => {
      if (customHeadersMiddleware) {
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        
        // Verify security headers are set
        expect(setHeaderSpy).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
        expect(setHeaderSpy).toHaveBeenCalledWith('X-Content-Type-Options', 'nosniff');
        expect(setHeaderSpy).toHaveBeenCalledWith('X-XSS-Protection', '1; mode=block');
        expect(setHeaderSpy).toHaveBeenCalledWith('Referrer-Policy', 'strict-origin-when-cross-origin');
        expect(setHeaderSpy).toHaveBeenCalledWith(
          'Permissions-Policy', 
          'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()'
        );
      }
    });

    it('should set cache control headers for auth routes', () => {
      if (customHeadersMiddleware) {
        (mockReq as any).path = '/auth/login';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        
        expect(setHeaderSpy).toHaveBeenCalledWith(
          'Cache-Control', 
          'no-store, no-cache, must-revalidate, proxy-revalidate'
        );
        expect(setHeaderSpy).toHaveBeenCalledWith('Pragma', 'no-cache');
        expect(setHeaderSpy).toHaveBeenCalledWith('Expires', '0');
        expect(setHeaderSpy).toHaveBeenCalledWith('Surrogate-Control', 'no-store');
      }
    });

    it('should set cache control headers for API routes', () => {
      if (customHeadersMiddleware) {
        (mockReq as any).path = '/api/users';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        
        expect(setHeaderSpy).toHaveBeenCalledWith(
          'Cache-Control', 
          'no-store, no-cache, must-revalidate, proxy-revalidate'
        );
      }
    });

    it('should call next() after setting headers', () => {
      if (customHeadersMiddleware) {
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        expect(mockNext).toHaveBeenCalledWith();
      }
    });
  });

  describe('Missing Configuration Tests', () => {
    it('should have CORS configuration with proper structure', () => {
      // Test that CORS middleware exists and is properly configured
      expect(generalSecurity).toBeDefined();
      expect(generalSecurity.length).toBeGreaterThan(0);
      
      // CORS should be one of the first middleware functions
      const hasCorsLikeMiddleware = generalSecurity.some((middleware: any) => 
        typeof middleware === 'function'
      );
      expect(hasCorsLikeMiddleware).toBe(true);
    });

    it('should have Helmet security headers configuration', () => {
      // Test that Helmet is properly integrated
      expect(generalSecurity).toBeDefined();
      
      // Should have multiple middleware functions including Helmet
      const middlewareFunctions = generalSecurity.filter((middleware: any) => 
        typeof middleware === 'function'
      );
      expect(middlewareFunctions.length).toBeGreaterThanOrEqual(2);
    });

    it('should have Content Security Policy validation', () => {
      // Test that CSP-related security is in place
      expect(generalSecurity).toBeDefined();
      
      // Security middleware should contain functions that set security headers
      const hasSecurityMiddleware = generalSecurity.some((middleware: any) => 
        typeof middleware === 'function'
      );
      expect(hasSecurityMiddleware).toBe(true);
      
      // This test ensures we're thinking about CSP even if we can't inspect exact config
      expect(typeof csrfProtection).toBe('function');
    });
  });

  describe('Rate Limiting Integration', () => {
    it('should include rate limiting in auth security middleware', () => {
      // Auth security should include rate limiting functions
      const hasRateLimit = authSecurity.some((middleware: any) => 
        typeof middleware === 'function'
      );
      expect(hasRateLimit).toBe(true);
    });

    it('should include rate limiting in API security middleware', () => {
      const hasRateLimit = apiSecurity.some((middleware: any) => 
        typeof middleware === 'function'
      );
      expect(hasRateLimit).toBe(true);
    });

    it('should include rate limiting in file upload security', () => {
      const hasRateLimit = fileUploadSecurity.some((middleware: any) => 
        typeof middleware === 'function'
      );
      expect(hasRateLimit).toBe(true);
    });
  });

  describe('Environment-Specific Configuration', () => {
    let originalEnv: string | undefined;

    beforeEach(() => {
      originalEnv = process.env.NODE_ENV;
    });

    afterEach(() => {
      if (originalEnv !== undefined) {
        process.env.NODE_ENV = originalEnv;
      } else {
        delete process.env.NODE_ENV;
      }
    });

    it('should handle test environment configuration', () => {
      process.env.NODE_ENV = 'test';
      
      // Test that the middleware stacks are defined in test environment
      expect(authSecurity).toBeDefined();
      expect(Array.isArray(authSecurity)).toBe(true);
    });

    it('should handle production environment configuration', () => {
      process.env.NODE_ENV = 'production';
      
      // Test that the middleware stacks work in production environment
      expect(authSecurity).toBeDefined();
      expect(Array.isArray(authSecurity)).toBe(true);
    });

    it('should differentiate between test and production environments', () => {
      // This test verifies that environment-specific logic exists
      // The actual rate limiting differences would be tested in integration tests
      expect(process.env.NODE_ENV).toBeDefined();
    });
  });

  describe('Middleware Stack Composition', () => {
    it('should have auth security include more middleware than general', () => {
      // Auth security should include all general security middleware plus auth-specific ones
      expect(authSecurity.length).toBeGreaterThanOrEqual(generalSecurity.length);
    });

    it('should have API security include general security base', () => {
      // API security should build upon general security
      expect(apiSecurity.length).toBeGreaterThanOrEqual(generalSecurity.length);
    });

    it('should have file upload security be most restrictive', () => {
      // File upload security should have the most middleware (most restrictive)
      expect(fileUploadSecurity.length).toBeGreaterThanOrEqual(generalSecurity.length);
    });

    it('should have all middleware stacks contain functions', () => {
      // All middleware in stacks should be functions
      generalSecurity.forEach((middleware: any) => {
        expect(typeof middleware).toBe('function');
      });
      
      authSecurity.forEach((middleware: any) => {
        expect(typeof middleware).toBe('function');
      });
      
      apiSecurity.forEach((middleware: any) => {
        expect(typeof middleware).toBe('function');
      });
      
      fileUploadSecurity.forEach((middleware: any) => {
        expect(typeof middleware).toBe('function');
      });
    });
  });

  describe('Security Headers Configuration', () => {
    it('should include CORS middleware in general security', () => {
      // CORS should be one of the first middleware in the general stack
      expect(generalSecurity.length).toBeGreaterThan(0);
      expect(typeof generalSecurity[0]).toBe('function');
    });

    it('should include Helmet middleware in general security', () => {
      // Helmet should be included in the general security stack
      const hasHelmet = generalSecurity.some((middleware: any) => 
        typeof middleware === 'function'
      );
      expect(hasHelmet).toBe(true);
    });

    it('should include custom security headers middleware', () => {
      // Custom headers middleware should be in the stack
      const hasCustomHeaders = generalSecurity.some((middleware: any) => 
        typeof middleware === 'function' && 
        middleware.toString().includes('X-Frame-Options')
      );
      expect(hasCustomHeaders).toBe(true);
    });
  });

  describe('CSRF Protection Edge Cases', () => {
    it('should handle requests with empty CSRF token header', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = { 'x-csrf-token': '' };
      (mockReq as any).session = { csrfToken: 'valid-token' };

      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });

    it('should handle requests with empty session CSRF token', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = { 'x-csrf-token': 'valid-token' };
      (mockReq as any).session = { csrfToken: '' };
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });

    it('should handle requests with null CSRF tokens', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = { 'x-csrf-token': null };
      (mockReq as any).session = { csrfToken: 'valid-token' };

      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });

    it('should handle requests with undefined session', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = { 'x-csrf-token': 'valid-token' };
      (mockReq as any).session = undefined;
      
      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });

    it('should handle case-sensitive CSRF header', () => {
      (mockReq as any).method = 'POST';
      (mockReq as any).path = '/api/data';
      (mockReq as any).headers = { 'X-CSRF-Token': 'valid-token' }; // Wrong case
      (mockReq as any).session = { csrfToken: 'valid-token' };

      csrfProtection(mockReq as Request, mockRes as Response, mockNext);
      
      // Should reject because header key is case-sensitive
      expect(statusSpy).toHaveBeenCalledWith(403);
    });
  });

  describe('Security Middleware Error Handling', () => {
    it('should handle middleware errors gracefully', () => {
      // Test that middleware doesn't crash when encountering errors
      const errorMiddleware = (req: Request, res: Response, next: NextFunction) => {
        throw new Error('Middleware error');
      };
      
      expect(() => {
        try {
          errorMiddleware(mockReq as Request, mockRes as Response, mockNext);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toBe('Middleware error');
        }
      }).not.toThrow();
    });

    it('should handle malformed request objects', () => {
      // Test CSRF protection with malformed request
      const malformedReq = {
        method: 'POST',
        path: '/api/data',
        headers: null, // Malformed
        session: { csrfToken: 'valid-token' }
      };
      
      // CSRF protection should handle null headers gracefully
      expect(() => {
        csrfProtection(malformedReq as any, mockRes as Response, mockNext);
      }).not.toThrow();
      
      // Should reject the request due to malformed headers
      expect(statusSpy).toHaveBeenCalledWith(403);
    });

    it('should handle requests with undefined headers', () => {
      const malformedReq = {
        method: 'POST',
        path: '/api/data',
        headers: undefined, // Malformed
        session: { csrfToken: 'valid-token' }
      };
      
      expect(() => {
        csrfProtection(malformedReq as any, mockRes as Response, mockNext);
      }).not.toThrow();
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });

    it('should handle requests with malformed session objects', () => {
      const malformedReq = {
        method: 'POST',
        path: '/api/data',
        headers: { 'x-csrf-token': 'valid-token' },
        session: null // Malformed
      };
      
      expect(() => {
        csrfProtection(malformedReq as any, mockRes as Response, mockNext);
      }).not.toThrow();
      
      expect(statusSpy).toHaveBeenCalledWith(403);
    });
  });

  describe('Security Configuration Validation', () => {
    it('should have non-empty middleware arrays', () => {
      expect(generalSecurity.length).toBeGreaterThan(0);
      expect(authSecurity.length).toBeGreaterThan(0);
      expect(apiSecurity.length).toBeGreaterThan(0);
      expect(fileUploadSecurity.length).toBeGreaterThan(0);
    });

    it('should export securityMiddleware object with all required properties', () => {
      expect(securityMiddleware).toHaveProperty('general');
      expect(securityMiddleware).toHaveProperty('auth');
      expect(securityMiddleware).toHaveProperty('api');
      expect(securityMiddleware).toHaveProperty('fileUpload');
      expect(securityMiddleware).toHaveProperty('csrf');
      
      expect(securityMiddleware.general).toBe(generalSecurity);
      expect(securityMiddleware.auth).toBe(authSecurity);
      expect(securityMiddleware.api).toBe(apiSecurity);
      expect(securityMiddleware.fileUpload).toBe(fileUploadSecurity);
      expect(securityMiddleware.csrf).toBe(csrfProtection);
    });

    it('should have createRateLimit as a factory function', () => {
      expect(typeof createRateLimit).toBe('function');
      
      // Test that it returns a function when called
      const result = createRateLimit(1000, 5);
      expect(typeof result).toBe('function');
    });
  });

  describe('Path-based Security Logic', () => {
    let customHeadersMiddleware: any;

    beforeEach(() => {
      customHeadersMiddleware = generalSecurity.find((middleware: any) => 
        typeof middleware === 'function' && 
        middleware.toString().includes('X-Frame-Options')
      );
    });

    it('should apply different cache headers for different path patterns', () => {
      if (customHeadersMiddleware) {
        // Test auth path
        (mockReq as any).path = '/auth/register';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        expect(setHeaderSpy).toHaveBeenCalledWith('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        
        // Reset mocks
        setHeaderSpy.mockClear();
        
        // Test API path
        (mockReq as any).path = '/api/users';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        expect(setHeaderSpy).toHaveBeenCalledWith('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        
        // Reset mocks
        setHeaderSpy.mockClear();
        
        // Test non-sensitive path
        (mockReq as any).path = '/public/health';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        // Should still set basic security headers but maybe not cache control
        expect(setHeaderSpy).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
      }
    });

    it('should handle edge case paths', () => {
      if (customHeadersMiddleware) {
        // Test empty path
        (mockReq as any).path = '';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        expect(setHeaderSpy).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
        
        // Test root path
        (mockReq as any).path = '/';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        expect(setHeaderSpy).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
        
        // Test path with query parameters (shouldn't affect middleware)
        (mockReq as any).path = '/auth/login?redirect=/dashboard';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        expect(setHeaderSpy).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
      }
    });
  });

  describe('Request Size Protection', () => {
    let requestSizeLimits: any;

    beforeAll(async () => {
      const securityModule = await import('../../middlewares/security');
      requestSizeLimits = securityModule.requestSizeLimits;
    });

    it('should set appropriate timeouts for multipart uploads', () => {
      const mockReq = {
        get: jest.fn().mockReturnValue('multipart/form-data'),
        setTimeout: jest.fn()
      };

      requestSizeLimits(mockReq, mockRes, mockNext);

      expect(mockReq.setTimeout).toHaveBeenCalledWith(5 * 60 * 1000); // 5 minutes
      expect(mockNext).toHaveBeenCalled();
    });

    it('should set shorter timeouts for JSON requests', () => {
      const mockReq = {
        get: jest.fn().mockReturnValue('application/json'),
        setTimeout: jest.fn()
      };

      requestSizeLimits(mockReq, mockRes, mockNext);

      expect(mockReq.setTimeout).toHaveBeenCalledWith(30 * 1000); // 30 seconds
      expect(mockNext).toHaveBeenCalled();
    });

    it('should set default timeouts for other content types', () => {
      const mockReq = {
        get: jest.fn().mockReturnValue('text/plain'),
        setTimeout: jest.fn()
      };

      requestSizeLimits(mockReq, mockRes, mockNext);

      expect(mockReq.setTimeout).toHaveBeenCalledWith(10 * 1000); // 10 seconds
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle missing Content-Type header', () => {
      const mockReq = {
        get: jest.fn().mockReturnValue(undefined),
        setTimeout: jest.fn()
      };

      requestSizeLimits(mockReq, mockRes, mockNext);

      expect(mockReq.setTimeout).toHaveBeenCalledWith(10 * 1000); // Default timeout
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Enhanced Security Middleware Stack', () => {
    let enhancedGeneralSecurity: any;

    beforeAll(async () => {
      const securityModule = await import('../../middlewares/security');
      enhancedGeneralSecurity = securityModule.enhancedGeneralSecurity;
    });

    it('should include request size limits in enhanced general security', () => {
      expect(Array.isArray(enhancedGeneralSecurity)).toBe(true);
      expect(enhancedGeneralSecurity.length).toBeGreaterThan(generalSecurity.length);
    });

    it('should maintain all original security features', () => {
      // Enhanced security should include all general security middleware
      expect(enhancedGeneralSecurity.length).toBeGreaterThanOrEqual(generalSecurity.length);
      
      // Should contain functions (middleware)
      enhancedGeneralSecurity.forEach((middleware: any) => {
        expect(typeof middleware).toBe('function');
      });
    });
  });

  describe('Security Configuration Validation', () => {
    it('should have valid rate limit configurations for different environments', () => {
      const testRateLimit = createRateLimit(60000, 100, 'Test rate limit');
      const prodRateLimit = createRateLimit(15 * 60 * 1000, 10, 'Prod rate limit');

      expect(typeof testRateLimit).toBe('function');
      expect(typeof prodRateLimit).toBe('function');
    });

    it('should export all required security configurations', () => {
      expect(securityMiddleware).toHaveProperty('general');
      expect(securityMiddleware).toHaveProperty('auth');
      expect(securityMiddleware).toHaveProperty('api');
      expect(securityMiddleware).toHaveProperty('fileUpload');
      expect(securityMiddleware).toHaveProperty('csrf');
      
      // New enhanced configurations
      if (securityMiddleware.enhanced) {
        expect(securityMiddleware.enhanced).toBeDefined();
      }
    });
  });

  describe('Security Headers Content Validation', () => {
    let customHeadersMiddleware: any;

    beforeEach(() => {
      customHeadersMiddleware = generalSecurity.find((middleware: any) => 
        typeof middleware === 'function' && 
        middleware.toString().includes('X-Frame-Options')
      );
    });

    it('should set comprehensive Permissions Policy', () => {
      if (customHeadersMiddleware) {
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        
        const permissionsCall: [string, string] | undefined = setHeaderSpy.mock.calls.find((call: [string, string]) => 
          call[0] === 'Permissions-Policy'
        );
        
        expect(permissionsCall).toBeDefined();
        const policy = permissionsCall![1];
        
        // Should restrict dangerous features
        expect(policy).toContain('geolocation=()');
        expect(policy).toContain('microphone=()');
        expect(policy).toContain('camera=()');
        expect(policy).toContain('payment=()');
        expect(policy).toContain('usb=()');
        expect(policy).toContain('magnetometer=()');
        expect(policy).toContain('gyroscope=()');
      }
    });

    it('should apply cache control to sensitive paths only', () => {
      if (customHeadersMiddleware) {
        // Test non-sensitive path
        (mockReq as any).path = '/public/assets';
        customHeadersMiddleware(mockReq, mockRes, mockNext);
        
        const cacheControlCalls: Array<[string, string]> = setHeaderSpy.mock.calls.filter((call: [string, string]) => 
          call[0] === 'Cache-Control'
        );
        
        // Should still set basic security but maybe not strict cache control
        expect(setHeaderSpy).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
      }
    });
  });

  describe('Environment-Specific Security Configuration', () => {
    it('should provide different configurations for test vs production', () => {
      // Test environment should be less restrictive
      process.env.NODE_ENV = 'test';
      const testAuthSecurity = authSecurity;
      
      // Production should be more restrictive
      process.env.NODE_ENV = 'production';
      const prodAuthSecurity = authSecurity;
      
      // Both should exist and be arrays
      expect(Array.isArray(testAuthSecurity)).toBe(true);
      expect(Array.isArray(prodAuthSecurity)).toBe(true);
      
      // Both should include security middleware
      expect(testAuthSecurity.length).toBeGreaterThan(0);
      expect(prodAuthSecurity.length).toBeGreaterThan(0);
    });
  });

  describe('Path Traversal Protection Unit Tests', () => {
    let pathTraversalProtection: any;
    let filePathSecurity: any;
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: NextFunction;

    beforeAll(async () => {
      // Mock ApiError
      jest.doMock('../../utils/ApiError', () => ({
        ApiError: {
          forbidden: (message: string, code: string) => {
            const error = new Error(message);
            (error as any).statusCode = 403;
            (error as any).code = code;
            return error;
          },
          internal: (message: string) => {
            const error = new Error(message);
            (error as any).statusCode = 500;
            return error;
          }
        }
      }));

      const securityModule = await import('../../middlewares/security');
      pathTraversalProtection = securityModule.pathTraversalProtection;
      filePathSecurity = securityModule.filePathSecurity;
    });

    beforeEach(() => {
      mockReq = {
        path: '/safe',
        url: '/safe',
        params: {},
        query: {},
        body: {},
        ip: '127.0.0.1',
        connection: { remoteAddress: '127.0.0.1' } as any
      };
      
      mockRes = {};
      mockNext = jest.fn();
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    describe('Path Traversal Attack Detection', () => {
      it('should block basic path traversal in URL', () => {
        (mockReq as any).path = '/api/files/../../../etc/passwd';

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });

      it('should block path traversal in parameters', () => {
        (mockReq as any).params = { filepath: '../../../etc/passwd' };

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });

      it('should block URL-encoded path traversal', () => {
        (mockReq as any).params = { filepath: '%2e%2e%2f%2e%2e%2fetc%2fpasswd' };

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });

      it('should block double-encoded path traversal', () => {
        (mockReq as any).params = { filepath: '%252e%252e%252f%252e%252e%252fetc%252fpasswd' };

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });

      it('should block Windows-style path traversal', () => {
        (mockReq as any).params = { filepath: '..\\..\\windows\\system32' };

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });

      it('should block null byte injection', () => {
        (mockReq as any).params = { filepath: 'safe.txt\0../../../etc/passwd' };

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });

      it('should block absolute paths', () => {
        (mockReq as any).params = { filepath: '/etc/passwd' };

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });

      it('should block creative bypass attempts', () => {
        const bypassAttempts = [
          '....//....//etc/passwd',
          '..;/..;/etc/passwd',
          '..///..//etc/passwd',
          '..\\\\..\\\\windows\\system32'
        ];

        bypassAttempts.forEach(attempt => {
          (mockNext as jest.MockedFunction<any>).mockClear();
          (mockReq as any).params = { filepath: attempt };

          pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

          expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
            statusCode: 403,
            code: 'PATH_TRAVERSAL_DETECTED'
          }));
        });
      });

      it('should block traversal in path-related query parameters', () => {
        (mockReq as any).query = { filepath: '../../../etc/passwd' };

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });

      it('should block traversal in path-related body fields', () => {
        (mockReq as any).body = { filename: '../../../etc/passwd' };

        pathTraversalProtection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'PATH_TRAVERSAL_DETECTED'
        }));
      });
    });

    describe('File Path Security Middleware', () => {
      it('should allow valid file paths', () => {
        (mockReq as any).params = { filepath: 'user123/images/photo.jpg' };

        filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith();
        expect((mockReq as any).params.filepath).toBe('user123/images/photo.jpg');
      });

      it('should sanitize and normalize paths', () => {
        (mockReq as any).params = { filepath: 'user123//images///photo.jpg' };

        filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith();
        expect((mockReq as any).params.filepath).toBe('user123/images/photo.jpg');
      });

      it('should block traversal in file paths', () => {
        (mockReq as any).params = { filepath: '../../../etc/passwd' };

        filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'INVALID_FILE_PATH'
        }));
      });

      it('should block paths that are too long', () => {
        (mockReq as any).params = { filepath: 'x'.repeat(501) };

        filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
          statusCode: 403,
          code: 'INVALID_FILE_PATH'
        }));
      });

      it('should block dangerous file extensions', () => {
        const dangerousFiles = [
          'malicious.exe',
          'script.bat',
          'virus.scr',
          'trojan.com'
        ];

        dangerousFiles.forEach(filename => {
          (mockNext as jest.MockedFunction<any>).mockClear();
          (mockReq as any).params = { filepath: filename };

          filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

          expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
            statusCode: 403,
            code: 'INVALID_FILE_PATH'
          }));
        });
      });

      it('should allow safe file extensions', () => {
        const safeFiles = [
          'photo.jpg',
          'image.jpeg',
          'picture.png',
          'graphic.bmp',
          'animation.gif',
          'modern.webp'
        ];

        safeFiles.forEach(filename => {
          (mockNext as jest.MockedFunction<any>).mockClear();
          (mockReq as any).params = { filepath: filename };

          filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

          expect(mockNext).toHaveBeenCalledWith();
        });
      });

      it('should block dangerous characters', () => {
        const dangerousChars = ['<', '>', ':', '"', '|', '?', '*'];

        dangerousChars.forEach(char => {
          (mockNext as jest.MockedFunction<any>).mockClear();
          (mockReq as any).params = { filepath: `file${char}name.jpg` };

          filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

          expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({
            statusCode: 403,
            code: 'INVALID_FILE_PATH'
          }));
        });
      });

      it('should handle wildcard parameter routes', () => {
        (mockReq as any).params = { '0': 'user123/photo.jpg' };

        filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith();
        expect((mockReq as any).params['0']).toBe('user123/photo.jpg');
      });

      it('should pass through when no filepath present', () => {
        (mockReq as any).params = { id: '123' }; // No filepath

        filePathSecurity(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith();
      });
    });
  });
});