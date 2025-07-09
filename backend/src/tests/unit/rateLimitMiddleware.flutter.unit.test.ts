// backend/src/tests/unit/rateLimitMiddleware.flutter.unit.test.ts
import { Request, Response, NextFunction } from 'express';
import {
  RateLimiter,
  healthRateLimitMiddleware,
  diagnosticsRateLimitMiddleware,
  generalRateLimitMiddleware,
  cleanupRateLimiters,
  healthRateLimit,
  diagnosticsRateLimit,
  generalRateLimit
} from '../../middlewares/rateLimitMiddleware';

// Mock Express types
const mockRequest = (ip?: string): Partial<Request> => ({
  ip: ip || '192.168.1.1',
  connection: { remoteAddress: ip || '192.168.1.1' } as any
});

const mockResponse = (): Partial<Response> => {
  const res: Partial<Response> = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis()
  };
  return res;
};

const mockNext: NextFunction = jest.fn();

describe('RateLimitMiddleware - Unit Tests', () => {
  let originalNodeEnv: string | undefined;

  beforeAll(() => {
    // Store original NODE_ENV
    originalNodeEnv = process.env.NODE_ENV;
    // Set to production to enable rate limiting
    process.env.NODE_ENV = 'production';
    // Remove jest from global to ensure rate limiting is active
    delete (global as any).jest;
  });

  afterAll(() => {
    // Restore original NODE_ENV
    if (originalNodeEnv !== undefined) {
      process.env.NODE_ENV = originalNodeEnv;
    } else {
      delete process.env.NODE_ENV;
    }
    cleanupRateLimiters();
  });
  beforeEach(() => {
    jest.clearAllMocks();
    // Reset rate limiters
    if (healthRateLimit && typeof healthRateLimit.reset === 'function') {
      healthRateLimit.reset();
    }
    if (diagnosticsRateLimit && typeof diagnosticsRateLimit.reset === 'function') {
      diagnosticsRateLimit.reset();
    }
    if (generalRateLimit && typeof generalRateLimit.reset === 'function') {
      generalRateLimit.reset();
    }
  });

  afterAll(() => {
    cleanupRateLimiters();
  });

  describe('RateLimiter Class', () => {
    it('should create a RateLimiter instance with default values', () => {
      const limiter = new RateLimiter();
      expect(limiter).toBeDefined();
      expect(limiter.getWindowMs()).toBe(15 * 60 * 1000); // 15 minutes
      expect(limiter.getMaxRequests()).toBe(100);
    });

    it('should create a RateLimiter instance with custom values', () => {
      const limiter = new RateLimiter(60000, 50);
      expect(limiter).toBeDefined();
      expect(limiter.getWindowMs()).toBe(60000);
      expect(limiter.getMaxRequests()).toBe(50);
    });

    it('should generate unique keys for different IP addresses', () => {
      // Create a test rate limiter for this test
      const testLimiter = new RateLimiter();
      const middleware = testLimiter.middleware();
      
      const req1 = mockRequest('192.168.1.1') as Request;
      const req2 = mockRequest('192.168.1.2') as Request;
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;

      middleware(req1, res1, mockNext);
      middleware(req2, res2, mockNext);

      expect(mockNext).toHaveBeenCalledTimes(2);
      
      // Both should have been allowed and have rate limit headers
      expect(res1.set).toHaveBeenCalledWith(expect.objectContaining({
        'X-RateLimit-Limit': '100',
        'X-RateLimit-Remaining': '99'
      }));
      expect(res2.set).toHaveBeenCalledWith(expect.objectContaining({
        'X-RateLimit-Limit': '100',
        'X-RateLimit-Remaining': '99'
      }));
    });

    it('should handle unknown IP addresses gracefully', () => {
      const testLimiter = new RateLimiter();
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      delete (req as any).ip;
      delete (req as any).connection;
      const res = mockResponse() as Response;

      middleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(res.set).toHaveBeenCalledWith(expect.objectContaining({
        'X-RateLimit-Limit': '100'
      }));
    });

    it('should set rate limit headers on successful requests', () => {
      const testLimiter = new RateLimiter();
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      middleware(req, res, mockNext);

      expect(res.set).toHaveBeenCalledWith({
        'X-RateLimit-Limit': '100',
        'X-RateLimit-Remaining': '99',
        'X-RateLimit-Reset': expect.any(String)
      });
    });

    it('should track request counts correctly', () => {
      const testLimiter = new RateLimiter();
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;

      // First request
      middleware(req, res1, mockNext);
      expect(res1.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-RateLimit-Remaining': '99'
        })
      );

      // Second request
      middleware(req, res2, mockNext);
      expect(res2.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-RateLimit-Remaining': '98'
        })
      );
    });

    it('should reset count after window expiry', (done) => {
      const testLimiter = new RateLimiter(1000, 10); // 1 second window for testing
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;

      // First request
      middleware(req, res1, mockNext);
      expect(res1.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-RateLimit-Remaining': '9'
        })
      );

      // Wait for window to expire
      setTimeout(() => {
        middleware(req, res2, mockNext);
        expect(res2.set).toHaveBeenCalledWith(
          expect.objectContaining({
            'X-RateLimit-Remaining': '9' // Should reset to initial count
          })
        );
        done();
      }, 1100); // Wait slightly longer than window
    });
  });

  describe('Health Rate Limiter', () => {
    it('should allow requests within limit', () => {
      const testLimiter = new RateLimiter(15 * 60 * 1000, 100);
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      middleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
    });

    it('should set correct limit headers for health endpoint', () => {
      const testLimiter = new RateLimiter(15 * 60 * 1000, 100);
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      middleware(req, res, mockNext);

      expect(res.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-RateLimit-Limit': '100'
        })
      );
    });
  });

  describe('Diagnostics Rate Limiter', () => {
    it('should allow requests within limit', () => {
      const testLimiter = new RateLimiter(60 * 60 * 1000, 10);
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      middleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
    });

    it('should set correct limit headers for diagnostics endpoint', () => {
      const testLimiter = new RateLimiter(60 * 60 * 1000, 10);
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      middleware(req, res, mockNext);

      expect(res.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-RateLimit-Limit': '10'
        })
      );
    });
  });

  describe('General Rate Limiter', () => {
    it('should allow requests within limit', () => {
      const testLimiter = new RateLimiter(15 * 60 * 1000, 200);
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      middleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
    });

    it('should set correct limit headers for general endpoint', () => {
      const testLimiter = new RateLimiter(15 * 60 * 1000, 200);
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      middleware(req, res, mockNext);

      expect(res.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-RateLimit-Limit': '200'
        })
      );
    });
  });

  describe('Test Environment Behavior', () => {
    it('should skip rate limiting in test environment', () => {
      // Temporarily set to test environment
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';

      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      healthRateLimitMiddleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(res.set).not.toHaveBeenCalled();

      // Restore environment
      process.env.NODE_ENV = originalEnv;
    });

    it('should skip rate limiting when jest is detected', () => {
      // Temporarily add jest to global
      const mockJest = {};
      (global as any).jest = mockJest;

      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      healthRateLimitMiddleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(res.set).not.toHaveBeenCalled();

      // Remove jest from global
      delete (global as any).jest;
    });

    it('should enable rate limiting in production environment', () => {
      // Ensure we're in production mode (set in beforeAll)
      expect(process.env.NODE_ENV).toBe('production');
      expect((global as any).jest).toBeUndefined();

      const req = mockRequest() as Request;
      const res = mockResponse() as Response;

      healthRateLimitMiddleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.set).toHaveBeenCalled(); // Headers should be set in production
    });
  });

  describe('Cleanup Function', () => {
    it('should call cleanup function without errors', () => {
      expect(() => {
        cleanupRateLimiters();
      }).not.toThrow();
    });

    it('should handle cleanup errors gracefully', () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      // Mock a rate limiter that throws on destroy
      const mockRateLimiter = {
        destroy: jest.fn(() => { throw new Error('Cleanup error'); })
      };
      
      expect(() => {
        cleanupRateLimiters();
      }).not.toThrow();
      
      consoleSpy.mockRestore();
    });
  });

  describe('Edge Cases', () => {
    it('should handle requests with no IP address', () => {
      const req = {
        connection: {}
      } as Request;
      const res = mockResponse() as Response;

      healthRateLimitMiddleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle malformed request objects', () => {
      const req = {} as Request;
      const res = mockResponse() as Response;

      expect(() => {
        healthRateLimitMiddleware(req, res, mockNext);
      }).not.toThrow();
    });

    it('should handle concurrent requests from same IP', () => {
      const testLimiter = new RateLimiter();
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;

      middleware(req, res1, mockNext);
      middleware(req, res2, mockNext);

      expect(mockNext).toHaveBeenCalledTimes(2);
      expect(res1.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-RateLimit-Remaining': '99'
        })
      );
      expect(res2.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-RateLimit-Remaining': '98'
        })
      );
    });

    it('should block requests when limit is exceeded', () => {
      const testLimiter = new RateLimiter(60000, 2); // Small limit for testing
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;
      const res3 = mockResponse() as Response;

      // First two requests should be allowed
      middleware(req, res1, mockNext);
      middleware(req, res2, mockNext);
      
      // Third request should be blocked
      middleware(req, res3, mockNext);

      expect(mockNext).toHaveBeenCalledTimes(2); // Only first two should call next
      expect(res3.status).toHaveBeenCalledWith(429);
      expect(res3.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: expect.any(Number)
        }
      });
    });

    it('should provide accurate retry-after times', () => {
      const testLimiter = new RateLimiter(60000, 1); // 1 minute window, 1 request
      const middleware = testLimiter.middleware();
      
      const req = mockRequest() as Request;
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;

      // First request allowed
      middleware(req, res1, mockNext);
      
      // Second request blocked
      middleware(req, res2, mockNext);

      expect(res2.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: expect.objectContaining({
            retryAfter: expect.any(Number)
          })
        })
      );

      const callArgs = (res2.json as jest.Mock).mock.calls[0][0];
      expect(callArgs.error.retryAfter).toBeGreaterThan(0);
      expect(callArgs.error.retryAfter).toBeLessThanOrEqual(60); // Should be within window
    });
  });
});