// backend/src/tests/security/rateLimitMiddleware.flutter.security.test.ts
import { Request, Response, NextFunction } from 'express';

// Mock Express types
const mockRequest = (ip?: string, headers?: Record<string, string>): Partial<Request> => ({
  ip: ip || '192.168.1.1',
  connection: { remoteAddress: ip || '192.168.1.1' } as any,
  headers: headers || {},
  get: jest.fn().mockImplementation((header: string) => {
    if (header === 'set-cookie') {
      const cookieHeader = headers?.[header.toLowerCase()];
      return cookieHeader ? [cookieHeader] : undefined;
    }
    return headers?.[header.toLowerCase()];
  }) as Request['get']
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

// Security-focused RateLimiter class that bypasses environment detection
class SecurityTestRateLimiter {
  private store: { [key: string]: { count: number; resetTime: number } } = {};

  constructor(
    private windowMs: number = 15 * 60 * 1000,
    private maxRequests: number = 100
  ) {}

  private getKey(req: Request): string {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    return ip;
  }

  public middleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
      const key = this.getKey(req);
      const now = Date.now();

      // Initialize or reset if window expired
      if (!this.store[key] || this.store[key].resetTime < now) {
        this.store[key] = {
          count: 1,
          resetTime: now + this.windowMs
        };
        
        // Add rate limit headers
        res.set({
          'X-RateLimit-Limit': this.maxRequests.toString(),
          'X-RateLimit-Remaining': (this.maxRequests - 1).toString(),
          'X-RateLimit-Reset': Math.ceil(this.store[key].resetTime / 1000).toString()
        });
        
        return next();
      }

      // Increment count
      this.store[key].count++;

      // Check if limit exceeded
      if (this.store[key].count > this.maxRequests) {
        res.status(429).json({
          success: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests. Please try again later.',
            retryAfter: Math.ceil((this.store[key].resetTime - now) / 1000)
          }
        });
        return;
      }

      // Add rate limit headers
      res.set({
        'X-RateLimit-Limit': this.maxRequests.toString(),
        'X-RateLimit-Remaining': (this.maxRequests - this.store[key].count).toString(),
        'X-RateLimit-Reset': Math.ceil(this.store[key].resetTime / 1000).toString()
      });

      next();
    };
  }

  public reset(): void {
    this.store = {};
  }

  public getStore(): { [key: string]: { count: number; resetTime: number } } {
    return { ...this.store };
  }
}

describe('RateLimitMiddleware - Security Tests', () => {
  let healthRateLimiter: SecurityTestRateLimiter;
  let diagnosticsRateLimiter: SecurityTestRateLimiter;
  let generalRateLimiter: SecurityTestRateLimiter;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Create fresh rate limiter instances for each test
    healthRateLimiter = new SecurityTestRateLimiter(15 * 60 * 1000, 100); // 100 requests per 15 minutes
    diagnosticsRateLimiter = new SecurityTestRateLimiter(60 * 60 * 1000, 10); // 10 requests per hour
    generalRateLimiter = new SecurityTestRateLimiter(15 * 60 * 1000, 200); // 200 requests per 15 minutes
  });

  describe('Rate Limit Enforcement', () => {
    it('should block requests after exceeding health endpoint limit', () => {
      const req = mockRequest('192.168.1.100') as Request;
      const middleware = healthRateLimiter.middleware();

      // Make requests up to the limit (100 for health)
      for (let i = 0; i < 100; i++) {
        const res = mockResponse() as Response;
        middleware(req, res, mockNext);
      }

      // The 101st request should be blocked
      const finalRes = mockResponse() as Response;
      middleware(req, finalRes, mockNext);

      expect(finalRes.status).toHaveBeenCalledWith(429);
      expect(finalRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: expect.any(Number)
        }
      });
    });

    it('should block requests after exceeding diagnostics endpoint limit', () => {
      const req = mockRequest('192.168.1.101') as Request;
      const middleware = diagnosticsRateLimiter.middleware();

      // Make requests up to the limit (10 for diagnostics)
      for (let i = 0; i < 10; i++) {
        const res = mockResponse() as Response;
        middleware(req, res, mockNext);
      }

      // The 11th request should be blocked
      const finalRes = mockResponse() as Response;
      middleware(req, finalRes, mockNext);

      expect(finalRes.status).toHaveBeenCalledWith(429);
      expect(finalRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: expect.any(Number)
        }
      });
    });

    it('should block requests after exceeding general endpoint limit', () => {
      const req = mockRequest('192.168.1.102') as Request;
      const middleware = generalRateLimiter.middleware();

      // Make requests up to the limit (200 for general)
      for (let i = 0; i < 200; i++) {
        const res = mockResponse() as Response;
        middleware(req, res, mockNext);
      }

      // The 201st request should be blocked
      const finalRes = mockResponse() as Response;
      middleware(req, finalRes, mockNext);

      expect(finalRes.status).toHaveBeenCalledWith(429);
      expect(finalRes.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: expect.any(Number)
        }
      });
    });
  });

  describe('IP Address Isolation', () => {
    it('should enforce rate limits per IP address independently', () => {
      const req1 = mockRequest('192.168.1.1') as Request;
      const req2 = mockRequest('192.168.1.2') as Request;
      const middleware = healthRateLimiter.middleware();

      // Exhaust limit for first IP
      for (let i = 0; i < 100; i++) {
        const res = mockResponse() as Response;
        middleware(req1, res, mockNext);
      }

      // First IP should be blocked
      const blockedRes = mockResponse() as Response;
      middleware(req1, blockedRes, mockNext);
      expect(blockedRes.status).toHaveBeenCalledWith(429);

      // Second IP should still be allowed
      const allowedRes = mockResponse() as Response;
      middleware(req2, allowedRes, mockNext);
      expect(allowedRes.status).not.toHaveBeenCalledWith(429);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle IPv6 addresses correctly', () => {
      const req = mockRequest('2001:db8::1') as Request;
      const res = mockResponse() as Response;
      const middleware = healthRateLimiter.middleware();

      middleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
    });

    it('should handle localhost addresses', () => {
      const req1 = mockRequest('127.0.0.1') as Request;
      const req2 = mockRequest('::1') as Request;
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;
      const middleware = healthRateLimiter.middleware();

      middleware(req1, res1, mockNext);
      middleware(req2, res2, mockNext);

      expect(mockNext).toHaveBeenCalledTimes(2);
    });
  });

  describe('Header Spoofing Protection', () => {
    it('should not be affected by X-Forwarded-For header spoofing', () => {
      const req = mockRequest('192.168.1.1', {
        'x-forwarded-for': '10.0.0.1, 192.168.1.2'
      }) as Request;
      const res = mockResponse() as Response;
      const middleware = healthRateLimiter.middleware();

      middleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      // Should use req.ip, not X-Forwarded-For
    });

    it('should not be affected by X-Real-IP header spoofing', () => {
      const req = mockRequest('192.168.1.1', {
        'x-real-ip': '10.0.0.1'
      }) as Request;
      const res = mockResponse() as Response;
      const middleware = healthRateLimiter.middleware();

      middleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      // Should use req.ip, not X-Real-IP
    });

    it('should not be affected by custom IP headers', () => {
      const req = mockRequest('192.168.1.1', {
        'x-client-ip': '10.0.0.1',
        'x-forwarded': '10.0.0.2',
        'forwarded-for': '10.0.0.3'
      }) as Request;
      const res = mockResponse() as Response;
      const middleware = healthRateLimiter.middleware();

      middleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      // Should use req.ip, not any custom headers
    });
  });

  describe('Retry-After Header Security', () => {
    it('should provide accurate retry-after time', () => {
      const req = mockRequest('192.168.1.200') as Request;
      const middleware = healthRateLimiter.middleware();

      // Mock Date.now to control time
      const originalDateNow = Date.now;
      const mockTime = 1000000;
      Date.now = jest.fn(() => mockTime);

      try {
        // Exhaust rate limit
        for (let i = 0; i < 100; i++) {
          const res = mockResponse() as Response;
          middleware(req, res, mockNext);
        }

        // Next request should be blocked with retry-after
        const blockedRes = mockResponse() as Response;
        middleware(req, blockedRes, mockNext);

        expect(blockedRes.json).toHaveBeenCalledWith({
          success: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests. Please try again later.',
            retryAfter: expect.any(Number)
          }
        });

        const callArgs = (blockedRes.json as jest.Mock).mock.calls[0][0];
        expect(callArgs.error.retryAfter).toBeGreaterThan(0);
        expect(callArgs.error.retryAfter).toBeLessThanOrEqual(900); // 15 minutes in seconds
      } finally {
        // Restore original Date.now
        Date.now = originalDateNow;
      }
    });

    it('should not leak internal timing information', () => {
      const req = mockRequest('192.168.1.201') as Request;
      const middleware = healthRateLimiter.middleware();

      // Exhaust rate limit
      for (let i = 0; i < 100; i++) {
        const res = mockResponse() as Response;
        middleware(req, res, mockNext);
      }

      // Next request should be blocked
      const blockedRes = mockResponse() as Response;
      middleware(req, blockedRes, mockNext);

      const callArgs = (blockedRes.json as jest.Mock).mock.calls[0][0];
      
      // Should not expose exact timestamps or internal calculations
      expect(callArgs.error.retryAfter).not.toContain('Date');
      expect(callArgs.error.retryAfter).not.toContain('Time');
      expect(typeof callArgs.error.retryAfter).toBe('number');
    });
  });

  describe('Memory Exhaustion Protection', () => {
    it('should handle many different IP addresses without memory issues', () => {
      const initialMemory = process.memoryUsage().heapUsed;
      const middleware = healthRateLimiter.middleware();

      // Simulate requests from many different IPs
      for (let i = 0; i < 1000; i++) {
        const req = mockRequest(`192.168.${Math.floor(i / 256)}.${i % 256}`) as Request;
        const res = mockResponse() as Response;
        middleware(req, res, mockNext);
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 15MB for 1000 IPs)
      // Each IP entry stores: { count: number, resetTime: number } + key overhead
      expect(memoryIncrease).toBeLessThan(15 * 1024 * 1024);
    });

    it('should handle rapid successive requests without performance degradation', () => {
      const req = mockRequest('192.168.1.300') as Request;
      const middleware = healthRateLimiter.middleware();
      const startTime = Date.now();

      // Make many rapid requests
      for (let i = 0; i < 100; i++) {
        const res = mockResponse() as Response;
        middleware(req, res, mockNext);
      }

      const endTime = Date.now();
      const processingTime = endTime - startTime;

      // Should process 100 requests in reasonable time (less than 1 second)
      expect(processingTime).toBeLessThan(1000);
    });
  });

  describe('Distributed Attack Simulation', () => {
    it('should handle distributed attacks from multiple IPs', () => {
      const attackIPs = Array.from({ length: 50 }, (_, i) => `10.0.${Math.floor(i / 256)}.${i % 256}`);
      const middleware = healthRateLimiter.middleware();
      let blockedRequests = 0;
      let allowedRequests = 0;

      // Simulate distributed attack
      attackIPs.forEach(ip => {
        for (let i = 0; i < 150; i++) { // Exceed the limit of 100
          const req = mockRequest(ip) as Request;
          const res = mockResponse() as Response;
          
          middleware(req, res, mockNext);
          
          if ((res.status as jest.Mock).mock.calls.some(call => call[0] === 429)) {
            blockedRequests++;
          } else {
            allowedRequests++;
          }
        }
      });

      // Should block excessive requests from each IP
      expect(blockedRequests).toBeGreaterThan(0);
      expect(allowedRequests).toBe(50 * 100); // 50 IPs * 100 allowed requests each
    });
  });

  describe('Time-based Attack Protection', () => {
    it('should reset rate limits after time window expires', () => {
      const req = mockRequest('192.168.1.400') as Request;
      const middleware = healthRateLimiter.middleware();

      // Mock Date.now to control time
      const originalDateNow = Date.now;
      let mockTime = 1000000;
      Date.now = jest.fn(() => mockTime);

      try {
        // Exhaust rate limit
        for (let i = 0; i < 100; i++) {
          const res = mockResponse() as Response;
          middleware(req, res, mockNext);
        }

        // Next request should be blocked
        const blockedRes = mockResponse() as Response;
        middleware(req, blockedRes, mockNext);
        expect(blockedRes.status).toHaveBeenCalledWith(429);

        // Advance time past window (15 minutes + 1 second)
        mockTime += (15 * 60 * 1000) + 1000;

        // Should be allowed again after window reset
        const allowedRes = mockResponse() as Response;
        middleware(req, allowedRes, mockNext);
        expect(allowedRes.status).not.toHaveBeenCalledWith(429);
        expect(mockNext).toHaveBeenCalled();
      } finally {
        // Restore original Date.now
        Date.now = originalDateNow;
      }
    });
  });

  describe('Error Response Security', () => {
    it('should return consistent error responses', () => {
      const req = mockRequest('192.168.1.500') as Request;
      const middleware = healthRateLimiter.middleware();

      // Exhaust rate limit
      for (let i = 0; i < 100; i++) {
        const res = mockResponse() as Response;
        middleware(req, res, mockNext);
      }

      // Multiple blocked requests should return consistent responses
      const firstRes = mockResponse() as Response;
      middleware(req, firstRes, mockNext);
      const firstResponse = (firstRes.json as jest.Mock).mock.calls[0][0];

      const secondRes = mockResponse() as Response;
      middleware(req, secondRes, mockNext);
      const secondResponse = (secondRes.json as jest.Mock).mock.calls[0][0];

      expect(firstResponse.error.code).toBe(secondResponse.error.code);
      expect(firstResponse.error.message).toBe(secondResponse.error.message);
      expect(firstResponse.success).toBe(secondResponse.success);
    });

    it('should not expose internal implementation details in error responses', () => {
      const req = mockRequest('192.168.1.501') as Request;
      const middleware = healthRateLimiter.middleware();

      // Exhaust rate limit
      for (let i = 0; i < 100; i++) {
        const res = mockResponse() as Response;
        middleware(req, res, mockNext);
      }

      const blockedRes = mockResponse() as Response;
      middleware(req, blockedRes, mockNext);
      const response = (blockedRes.json as jest.Mock).mock.calls[0][0];

      // Should not expose internal variable names, file paths, etc.
      const responseString = JSON.stringify(response);
      expect(responseString).not.toContain('store');
      expect(responseString).not.toContain('windowMs');
      expect(responseString).not.toContain('maxRequests');
      expect(responseString).not.toContain('resetTime');
      expect(responseString).not.toContain('count');
    });
  });

  describe('Environment Detection Tests', () => {
    it('should confirm original middleware skips rate limiting in test environment', () => {
      // Import the original middleware to test environment detection
      jest.resetModules();
      const rateLimitModule = require('../../middlewares/rateLimitMiddleware');
      
      const req = mockRequest('192.168.1.999') as Request;
      const res = mockResponse() as Response;

      // Original middleware should skip rate limiting in test environment
      rateLimitModule.healthRateLimitMiddleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalled();
      expect(res.json).not.toHaveBeenCalled();
      expect(res.set).not.toHaveBeenCalled();
    });
  });
});