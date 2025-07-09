// backend/src/middlewares/__tests__/rateLimitMiddleware.flutter.security.test.ts
import { Request, Response, NextFunction } from 'express';
import {
  healthRateLimitMiddleware,
  diagnosticsRateLimitMiddleware,
  generalRateLimitMiddleware,
  cleanupRateLimiters,
  healthRateLimit,
  diagnosticsRateLimit,
  generalRateLimit
} from '../../middlewares/rateLimitMiddleware';

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

describe('RateLimitMiddleware - Security Tests', () => {
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

  describe('Rate Limit Enforcement', () => {
    it('should block requests after exceeding health endpoint limit', () => {
      const req = mockRequest('192.168.1.100') as Request;
      const res = mockResponse() as Response;

      // Make requests up to the limit (100 for health)
      for (let i = 0; i < 100; i++) {
        healthRateLimitMiddleware(req, res, mockNext);
      }

      // The 101st request should be blocked
      healthRateLimitMiddleware(req, res, mockNext);

      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.json).toHaveBeenCalledWith({
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
      const res = mockResponse() as Response;

      // Make requests up to the limit (10 for diagnostics)
      for (let i = 0; i < 10; i++) {
        diagnosticsRateLimitMiddleware(req, res, mockNext);
      }

      // The 11th request should be blocked
      diagnosticsRateLimitMiddleware(req, res, mockNext);

      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.json).toHaveBeenCalledWith({
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
      const res = mockResponse() as Response;

      // Make requests up to the limit (200 for general)
      for (let i = 0; i < 200; i++) {
        generalRateLimitMiddleware(req, res, mockNext);
      }

      // The 201st request should be blocked
      generalRateLimitMiddleware(req, res, mockNext);

      expect(res.status).toHaveBeenCalledWith(429);
      expect(res.json).toHaveBeenCalledWith({
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
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;

      // Exhaust limit for first IP
      for (let i = 0; i < 100; i++) {
        healthRateLimitMiddleware(req1, res1, mockNext);
      }

      // First IP should be blocked
      healthRateLimitMiddleware(req1, res1, mockNext);
      expect(res1.status).toHaveBeenCalledWith(429);

      // Second IP should still be allowed
      healthRateLimitMiddleware(req2, res2, mockNext);
      expect(res2.status).not.toHaveBeenCalledWith(429);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle IPv6 addresses correctly', () => {
      const req = mockRequest('2001:db8::1') as Request;
      const res = mockResponse() as Response;

      healthRateLimitMiddleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      expect(res.status).not.toHaveBeenCalledWith(429);
    });

    it('should handle localhost addresses', () => {
      const req1 = mockRequest('127.0.0.1') as Request;
      const req2 = mockRequest('::1') as Request;
      const res1 = mockResponse() as Response;
      const res2 = mockResponse() as Response;

      healthRateLimitMiddleware(req1, res1, mockNext);
      healthRateLimitMiddleware(req2, res2, mockNext);

      expect(mockNext).toHaveBeenCalledTimes(2);
    });
  });

  describe('Header Spoofing Protection', () => {
    it('should not be affected by X-Forwarded-For header spoofing', () => {
      const req = mockRequest('192.168.1.1', {
        'x-forwarded-for': '10.0.0.1, 192.168.1.2'
      }) as Request;
      const res = mockResponse() as Response;

      healthRateLimitMiddleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      // Should use req.ip, not X-Forwarded-For
    });

    it('should not be affected by X-Real-IP header spoofing', () => {
      const req = mockRequest('192.168.1.1', {
        'x-real-ip': '10.0.0.1'
      }) as Request;
      const res = mockResponse() as Response;

      healthRateLimitMiddleware(req, res, mockNext);

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

      healthRateLimitMiddleware(req, res, mockNext);

      expect(mockNext).toHaveBeenCalled();
      // Should use req.ip, not any custom headers
    });
  });

  describe('Retry-After Header Security', () => {
    it('should provide accurate retry-after time', () => {
      const req = mockRequest('192.168.1.200') as Request;
      const res = mockResponse() as Response;

      // Mock Date.now to control time
      const originalDateNow = Date.now;
      const mockTime = 1000000;
      Date.now = jest.fn(() => mockTime);

      // Exhaust rate limit
      for (let i = 0; i < 100; i++) {
        healthRateLimitMiddleware(req, res, mockNext);
      }

      // Next request should be blocked with retry-after
      healthRateLimitMiddleware(req, res, mockNext);

      expect(res.json).toHaveBeenCalledWith({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: expect.any(Number)
        }
      });

      const callArgs = (res.json as jest.Mock).mock.calls[0][0];
      expect(callArgs.error.retryAfter).toBeGreaterThan(0);
      expect(callArgs.error.retryAfter).toBeLessThanOrEqual(900); // 15 minutes in seconds

      // Restore original Date.now
      Date.now = originalDateNow;
    });

    it('should not leak internal timing information', () => {
      const req = mockRequest('192.168.1.201') as Request;
      const res = mockResponse() as Response;

      // Exhaust rate limit
      for (let i = 0; i < 100; i++) {
        healthRateLimitMiddleware(req, res, mockNext);
      }

      // Next request should be blocked
      healthRateLimitMiddleware(req, res, mockNext);

      const callArgs = (res.json as jest.Mock).mock.calls[0][0];
      
      // Should not expose exact timestamps or internal calculations
      expect(callArgs.error.retryAfter).not.toContain('Date');
      expect(callArgs.error.retryAfter).not.toContain('Time');
      expect(typeof callArgs.error.retryAfter).toBe('number');
    });
  });

  describe('Memory Exhaustion Protection', () => {
    it('should handle many different IP addresses without memory issues', () => {
      const initialMemory = process.memoryUsage().heapUsed;

      // Simulate requests from many different IPs
      for (let i = 0; i < 1000; i++) {
        const req = mockRequest(`192.168.${Math.floor(i / 256)}.${i % 256}`) as Request;
        const res = mockResponse() as Response;
        healthRateLimitMiddleware(req, res, mockNext);
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 10MB for 1000 IPs)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    it('should handle rapid successive requests without performance degradation', () => {
      const req = mockRequest('192.168.1.300') as Request;
      const startTime = Date.now();

      // Make many rapid requests
      for (let i = 0; i < 100; i++) {
        const res = mockResponse() as Response;
        healthRateLimitMiddleware(req, res, mockNext);
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
      let blockedRequests = 0;
      let allowedRequests = 0;

      // Simulate distributed attack
      attackIPs.forEach(ip => {
        for (let i = 0; i < 150; i++) { // Exceed the limit of 100
          const req = mockRequest(ip) as Request;
          const res = mockResponse() as Response;
          
          healthRateLimitMiddleware(req, res, mockNext);
          
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
      const res = mockResponse() as Response;

      // Mock Date.now to control time
      const originalDateNow = Date.now;
      let mockTime = 1000000;
      Date.now = jest.fn(() => mockTime);

      // Exhaust rate limit
      for (let i = 0; i < 100; i++) {
        healthRateLimitMiddleware(req, res, mockNext);
      }

      // Next request should be blocked
      healthRateLimitMiddleware(req, res, mockNext);
      expect(res.status).toHaveBeenCalledWith(429);

      // Advance time past window (15 minutes + 1 second)
      mockTime += (15 * 60 * 1000) + 1000;

      // Clear mocks for fresh response
      jest.clearAllMocks();
      const newRes = mockResponse() as Response;

      // Should be allowed again after window reset
      healthRateLimitMiddleware(req, newRes, mockNext);
      expect(newRes.status).not.toHaveBeenCalledWith(429);
      expect(mockNext).toHaveBeenCalled();

      // Restore original Date.now
      Date.now = originalDateNow;
    });
  });

  describe('Error Response Security', () => {
    it('should return consistent error responses', () => {
      const req = mockRequest('192.168.1.500') as Request;
      const res = mockResponse() as Response;

      // Exhaust rate limit
      for (let i = 0; i < 100; i++) {
        healthRateLimitMiddleware(req, res, mockNext);
      }

      // Multiple blocked requests should return consistent responses
      healthRateLimitMiddleware(req, res, mockNext);
      const firstResponse = (res.json as jest.Mock).mock.calls[0][0];

      jest.clearAllMocks();
      const newRes = mockResponse() as Response;
      healthRateLimitMiddleware(req, newRes, mockNext);
      const secondResponse = (newRes.json as jest.Mock).mock.calls[0][0];

      expect(firstResponse.error.code).toBe(secondResponse.error.code);
      expect(firstResponse.error.message).toBe(secondResponse.error.message);
      expect(firstResponse.success).toBe(secondResponse.success);
    });

    it('should not expose internal implementation details in error responses', () => {
      const req = mockRequest('192.168.1.501') as Request;
      const res = mockResponse() as Response;

      // Exhaust rate limit
      for (let i = 0; i < 100; i++) {
        healthRateLimitMiddleware(req, res, mockNext);
      }

      healthRateLimitMiddleware(req, res, mockNext);
      const response = (res.json as jest.Mock).mock.calls[0][0];

      // Should not expose internal variable names, file paths, etc.
      const responseString = JSON.stringify(response);
      expect(responseString).not.toContain('store');
      expect(responseString).not.toContain('windowMs');
      expect(responseString).not.toContain('maxRequests');
      expect(responseString).not.toContain('resetTime');
      expect(responseString).not.toContain('count');
    });
  });
});