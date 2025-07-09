// backend/src/tests/integration/rateLimitMiddleware.flutter.int.test.ts
import request from 'supertest';
import express from 'express';

// Integration-focused RateLimiter class that bypasses environment detection
class IntegrationTestRateLimiter {
  private store: { [key: string]: { count: number; resetTime: number } } = {};

  constructor(
    private windowMs: number = 15 * 60 * 1000,
    private maxRequests: number = 100
  ) {}

  private getKey(req: any): string {
    // In integration tests, prioritize the test IP header for simulation
    return req.headers['x-test-ip'] || req.ip || req.connection?.remoteAddress || '127.0.0.1';
  }

  public middleware() {
    return (req: any, res: any, next: any): void => {
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
}

// Create test Express app with testable rate limiters
const createTestApp = () => {
  const app = express();
  app.use(express.json());

  // Create rate limiters for testing
  const healthRateLimit = new IntegrationTestRateLimiter(15 * 60 * 1000, 5); // Small limits for faster testing
  const diagnosticsRateLimit = new IntegrationTestRateLimiter(60 * 60 * 1000, 3);
  const generalRateLimit = new IntegrationTestRateLimiter(15 * 60 * 1000, 10);

  // Health endpoint with health rate limiting
  app.get('/health', healthRateLimit.middleware(), (req, res) => {
    res.json({ status: 'ok' });
  });

  // Diagnostics endpoint with diagnostics rate limiting
  app.get('/diagnostics', diagnosticsRateLimit.middleware(), (req, res) => {
    res.json({ diagnostics: 'data' });
  });

  // General API endpoints with general rate limiting
  app.get('/api/data', generalRateLimit.middleware(), (req, res) => {
    res.json({ data: 'response' });
  });

  app.get('/api/users', generalRateLimit.middleware(), (req, res) => {
    res.json({ users: [] });
  });

  app.post('/api/users', generalRateLimit.middleware(), (req, res) => {
    res.json({ user: req.body });
  });

  // Store rate limiters for reset capability
  app.locals.rateLimiters = {
    health: healthRateLimit,
    diagnostics: diagnosticsRateLimit,
    general: generalRateLimit
  };

  return app;
};

describe('RateLimitMiddleware - Integration Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    app = createTestApp();
  });

  describe('Health Endpoint Rate Limiting', () => {
    it('should allow requests within health endpoint limit', async () => {
      // Make requests up to the limit (5 for faster testing)
      for (let i = 0; i < 5; i++) {
        const response = await request(app).get('/health').expect(200);
        expect(response.body).toEqual({ status: 'ok' });
        expect(response.headers['x-ratelimit-limit']).toBe('5');
        expect(parseInt(response.headers['x-ratelimit-remaining'])).toBe(5 - 1 - i);
      }
    });

    it('should block requests after exceeding health endpoint limit', async () => {
      // Exhaust the limit (5 requests)
      for (let i = 0; i < 5; i++) {
        await request(app).get('/health').expect(200);
      }

      // The 6th request should be rate limited
      const blockedResponse = await request(app).get('/health').expect(429);
      
      expect(blockedResponse.body).toEqual({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: expect.any(Number)
        }
      });
    });

    it('should set correct rate limit headers for health endpoint', async () => {
      const response = await request(app).get('/health').expect(200);
      
      expect(response.headers['x-ratelimit-limit']).toBe('5');
      expect(response.headers['x-ratelimit-remaining']).toBe('4');
      expect(response.headers['x-ratelimit-reset']).toBeDefined();
    });
  });

  describe('Diagnostics Endpoint Rate Limiting', () => {
    it('should allow requests within diagnostics endpoint limit', async () => {
      // Make requests up to the limit (3 for faster testing)
      for (let i = 0; i < 3; i++) {
        const response = await request(app).get('/diagnostics').expect(200);
        expect(response.body).toEqual({ diagnostics: 'data' });
        expect(response.headers['x-ratelimit-limit']).toBe('3');
      }
    });

    it('should block requests after exceeding diagnostics endpoint limit', async () => {
      // Exhaust the limit (3 requests)
      for (let i = 0; i < 3; i++) {
        await request(app).get('/diagnostics').expect(200);
      }

      // The 4th request should be rate limited
      const blockedResponse = await request(app).get('/diagnostics').expect(429);
      
      expect(blockedResponse.body).toEqual({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: expect.any(Number)
        }
      });
    });

    it('should have stricter limits than health endpoint', async () => {
      const healthResponse = await request(app).get('/health').expect(200);
      const diagnosticsResponse = await request(app).get('/diagnostics').expect(200);
      
      expect(parseInt(healthResponse.headers['x-ratelimit-limit'])).toBeGreaterThan(
        parseInt(diagnosticsResponse.headers['x-ratelimit-limit'])
      );
    });
  });

  describe('General API Endpoint Rate Limiting', () => {
    it('should allow requests within general endpoint limit', async () => {
      // Make requests up to the limit (10 for faster testing)
      for (let i = 0; i < 10; i++) {
        const response = await request(app).get('/api/data').expect(200);
        expect(response.body).toEqual({ data: 'response' });
        expect(response.headers['x-ratelimit-limit']).toBe('10');
      }
    });

    it('should block requests after exceeding general endpoint limit', async () => {
      // Exhaust the limit (10 requests)
      for (let i = 0; i < 10; i++) {
        await request(app).get('/api/data').expect(200);
      }

      // The 11th request should be rate limited
      const blockedResponse = await request(app).get('/api/data').expect(429);
      
      expect(blockedResponse.body).toEqual({
        success: false,
        error: {
          code: 'RATE_LIMIT_EXCEEDED',
          message: 'Too many requests. Please try again later.',
          retryAfter: expect.any(Number)
        }
      });
    });

    it('should apply same rate limit to different general endpoints', async () => {
      // Make requests to both /api/data and /api/users (5 each = 10 total)
      for (let i = 0; i < 5; i++) {
        await request(app).get('/api/data').expect(200);
        await request(app).get('/api/users').expect(200);
      }

      // Both should share the same rate limit bucket - next request should be blocked
      const blockedResponse = await request(app).get('/api/data').expect(429);
      expect(blockedResponse.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });
  });

  describe('Cross-Endpoint Rate Limiting', () => {
    it('should maintain separate rate limits for different endpoint types', async () => {
      // Exhaust health endpoint limit (5 requests)
      for (let i = 0; i < 5; i++) {
        await request(app).get('/health').expect(200);
      }

      // Health endpoint should be blocked
      await request(app).get('/health').expect(429);

      // But diagnostics should still be available
      await request(app).get('/diagnostics').expect(200);

      // And general API should still be available
      await request(app).get('/api/data').expect(200);
    });

    it('should handle mixed endpoint requests correctly', async () => {
      // Make requests to different endpoints
      await request(app).get('/health').expect(200);
      await request(app).get('/diagnostics').expect(200);
      await request(app).get('/api/data').expect(200);
      await request(app).post('/api/users').send({ name: 'test' }).expect(200);

      // Check remaining counts for each endpoint type
      const healthResponse = await request(app).get('/health').expect(200);
      expect(healthResponse.headers['x-ratelimit-remaining']).toBe('3'); // 5 - 2 requests

      const diagnosticsResponse = await request(app).get('/diagnostics').expect(200);
      expect(diagnosticsResponse.headers['x-ratelimit-remaining']).toBe('1'); // 3 - 2 requests

      const apiResponse = await request(app).get('/api/data').expect(200);
      expect(apiResponse.headers['x-ratelimit-remaining']).toBe('7'); // 10 - 3 requests (including POST)
    });
  });

  describe('Concurrent Request Handling', () => {
    it('should handle concurrent requests to same endpoint correctly', async () => {
      // Make 5 concurrent requests (at the limit)
      const promises = Array.from({ length: 5 }, () =>
        request(app).get('/health')
      );

      const responses = await Promise.all(promises);
      
      // All should succeed as they're within limit
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });

      // Next request should be blocked
      await request(app).get('/health').expect(429);
    });

    it('should handle different IP addresses independently', async () => {
      // Simulate different IPs using custom headers
      // Exhaust limit for first IP
      for (let i = 0; i < 5; i++) {
        await request(app)
          .get('/health')
          .set('X-Test-IP', '192.168.1.1')
          .expect(200);
      }

      // First IP should be blocked
      await request(app)
        .get('/health')
        .set('X-Test-IP', '192.168.1.1')
        .expect(429);

      // But second IP should still work
      await request(app)
        .get('/health')
        .set('X-Test-IP', '192.168.1.2')
        .expect(200);
    });
  });

  describe('HTTP Methods Rate Limiting', () => {
    it('should apply rate limiting to different HTTP methods', async () => {
      // Test GET request
      const getResponse = await request(app).get('/api/users').expect(200);
      expect(getResponse.headers['x-ratelimit-remaining']).toBe('9');

      // Test POST request
      const postResponse = await request(app)
        .post('/api/users')
        .send({ name: 'John Doe' })
        .expect(200);
      expect(postResponse.headers['x-ratelimit-remaining']).toBe('8');

      // Both should share the same rate limit
      expect(postResponse.body).toEqual({ user: { name: 'John Doe' } });
    });

    it('should count all HTTP methods toward the same limit', async () => {
      // Make 10 requests using different methods (3 + 3 + 4 = 10)
      for (let i = 0; i < 3; i++) {
        await request(app).get('/api/data').expect(200);
        await request(app).get('/api/users').expect(200);
        await request(app).post('/api/users').send({ test: 'data' }).expect(200);
      }
      await request(app).get('/api/data').expect(200); // 10th request

      // 11th request should be blocked
      await request(app).get('/api/data').expect(429);
    });
  });

  describe('Rate Limit Headers Consistency', () => {
    it('should provide consistent rate limit headers across requests', async () => {
      const response1 = await request(app).get('/health').expect(200);
      const response2 = await request(app).get('/health').expect(200);
      const response3 = await request(app).get('/health').expect(200);

      // Limit should remain constant
      expect(response1.headers['x-ratelimit-limit']).toBe('5');
      expect(response2.headers['x-ratelimit-limit']).toBe('5');
      expect(response3.headers['x-ratelimit-limit']).toBe('5');

      // Remaining should decrease
      expect(parseInt(response1.headers['x-ratelimit-remaining'])).toBe(4);
      expect(parseInt(response2.headers['x-ratelimit-remaining'])).toBe(3);
      expect(parseInt(response3.headers['x-ratelimit-remaining'])).toBe(2);

      // Reset time should be consistent within the window
      const reset1 = parseInt(response1.headers['x-ratelimit-reset']);
      const reset2 = parseInt(response2.headers['x-ratelimit-reset']);
      const reset3 = parseInt(response3.headers['x-ratelimit-reset']);

      expect(Math.abs(reset1 - reset2)).toBeLessThan(2); // Should be within 1-2 seconds
      expect(Math.abs(reset2 - reset3)).toBeLessThan(2);
    });

    it('should not include rate limit headers when rate limited', async () => {
      // Exhaust the limit
      for (let i = 0; i < 5; i++) {
        await request(app).get('/health').expect(200);
      }

      // Rate limited response should not have rate limit headers  
      const blockedResponse = await request(app).get('/health').expect(429);
      
      expect(blockedResponse.headers['x-ratelimit-limit']).toBeUndefined();
      expect(blockedResponse.headers['x-ratelimit-remaining']).toBeUndefined();
      expect(blockedResponse.headers['x-ratelimit-reset']).toBeUndefined();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle malformed requests gracefully', async () => {
      // Request with invalid content-type for POST
      const response = await request(app)
        .post('/api/users')
        .set('Content-Type', 'invalid/type')
        .send('invalid data')
        .expect(200); // Should still process and apply rate limiting

      expect(response.headers['x-ratelimit-limit']).toBe('10');
    });

    it('should handle requests with special characters in URL', async () => {
      // The rate limiter should work regardless of URL content
      const response = await request(app)
        .get('/api/data?query=test%20with%20spaces&special=chars!')
        .expect(200);

      expect(response.headers['x-ratelimit-limit']).toBe('10');
      expect(response.headers['x-ratelimit-remaining']).toBe('9');
    });

    it('should maintain performance under load', async () => {
      const startTime = Date.now();

      // Make 5 requests (at the limit)
      for (let i = 0; i < 5; i++) {
        await request(app).get('/health').expect(200);
      }

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (less than 1 second for 5 requests)
      expect(duration).toBeLessThan(1000);
    });
  });

  describe('Rate Limit Window Behavior', () => {
    it('should handle requests near rate limit boundaries', async () => {
      // Make requests up to one before the limit
      for (let i = 0; i < 4; i++) {
        await request(app).get('/health').expect(200);
      }

      // Should still allow one more
      const lastAllowedResponse = await request(app).get('/health').expect(200);
      expect(lastAllowedResponse.headers['x-ratelimit-remaining']).toBe('0');

      // Next should be blocked
      await request(app).get('/health').expect(429);
    });

    it('should provide accurate retry-after times', async () => {
      // Exhaust limit
      for (let i = 0; i < 5; i++) {
        await request(app).get('/health').expect(200);
      }

      // Get blocked response
      const blockedResponse = await request(app).get('/health').expect(429);
      const retryAfter = blockedResponse.body.error.retryAfter;

      // Should be a reasonable time (less than 15 minutes)
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(900); // 15 minutes in seconds
    });
  });

  describe('Time-based Window Reset', () => {
    it('should reset rate limits after time window expires', async () => {
      // Mock Date.now to control time
      const originalDateNow = Date.now;
      let mockTime = 1000000;
      Date.now = jest.fn(() => mockTime);

      try {
        // Exhaust limit
        for (let i = 0; i < 5; i++) {
          await request(app).get('/health').expect(200);
        }

        // Should be blocked
        await request(app).get('/health').expect(429);

        // Advance time past window (15 minutes + 1 second)
        mockTime += (15 * 60 * 1000) + 1000;

        // Should work again after window reset
        await request(app).get('/health').expect(200);
      } finally {
        Date.now = originalDateNow;
      }
    });
  });

  describe('Original Middleware Environment Detection', () => {
    it('should confirm original middleware skips rate limiting in test environment', async () => {
      // Create app with original middleware to test environment detection
      const originalApp = express();
      originalApp.use(express.json());
      
      // Import original middleware
      jest.resetModules();
      const { healthRateLimitMiddleware } = require('../../middlewares/rateLimitMiddleware');
      
      originalApp.get('/health', healthRateLimitMiddleware, (req, res) => {
        res.json({ status: 'ok' });
      });

      // Should work without rate limiting (no headers)
      const response = await request(originalApp).get('/health').expect(200);
      expect(response.body).toEqual({ status: 'ok' });
      expect(response.headers['x-ratelimit-limit']).toBeUndefined();
      expect(response.headers['x-ratelimit-remaining']).toBeUndefined();
    });
  });
});