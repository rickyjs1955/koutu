// backend/src/middlewares/__tests__/rateLimitMiddleware.flutter.int.test.ts
import request from 'supertest';
import express from 'express';
import {
  healthRateLimitMiddleware,
  diagnosticsRateLimitMiddleware,
  generalRateLimitMiddleware,
  cleanupRateLimiters
} from '../../middlewares/rateLimitMiddleware';

// Create test Express app
const createTestApp = () => {
  const app = express();
  app.use(express.json());

  // Health endpoint with health rate limiting
  app.get('/health', healthRateLimitMiddleware, (req, res) => {
    res.json({ status: 'ok' });
  });

  // Diagnostics endpoint with diagnostics rate limiting
  app.get('/diagnostics', diagnosticsRateLimitMiddleware, (req, res) => {
    res.json({ diagnostics: 'data' });
  });

  // General API endpoint with general rate limiting
  app.get('/api/data', generalRateLimitMiddleware, (req, res) => {
    res.json({ data: 'response' });
  });

  // Multiple endpoints with different rate limiting
  app.get('/api/users', generalRateLimitMiddleware, (req, res) => {
    res.json({ users: [] });
  });

  app.post('/api/users', generalRateLimitMiddleware, (req, res) => {
    res.json({ user: req.body });
  });

  return app;
};

describe('RateLimitMiddleware - Integration Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    app = createTestApp();
    // Reset rate limiters between tests
    cleanupRateLimiters();
  });

  afterAll(() => {
    cleanupRateLimiters();
  });

  describe('Health Endpoint Rate Limiting', () => {
    it('should allow requests within health endpoint limit', async () => {
      // Make 50 requests to health endpoint
      const promises = Array.from({ length: 50 }, () =>
        request(app).get('/health').expect(200)
      );

      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.body).toEqual({ status: 'ok' });
        expect(response.headers['x-ratelimit-limit']).toBe('100');
        expect(parseInt(response.headers['x-ratelimit-remaining'])).toBeGreaterThanOrEqual(0);
      });
    });

    it('should block requests after exceeding health endpoint limit', async () => {
      // Make requests to exhaust the limit (100 requests)
      const allowedPromises = Array.from({ length: 100 }, () =>
        request(app).get('/health')
      );

      await Promise.all(allowedPromises);

      // The next request should be rate limited
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
      
      expect(response.headers['x-ratelimit-limit']).toBe('100');
      expect(response.headers['x-ratelimit-remaining']).toBe('99');
      expect(response.headers['x-ratelimit-reset']).toBeDefined();
    });
  });

  describe('Diagnostics Endpoint Rate Limiting', () => {
    it('should allow requests within diagnostics endpoint limit', async () => {
      // Make 5 requests to diagnostics endpoint
      const promises = Array.from({ length: 5 }, () =>
        request(app).get('/diagnostics').expect(200)
      );

      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.body).toEqual({ diagnostics: 'data' });
        expect(response.headers['x-ratelimit-limit']).toBe('10');
      });
    });

    it('should block requests after exceeding diagnostics endpoint limit', async () => {
      // Make requests to exhaust the limit (10 requests)
      const allowedPromises = Array.from({ length: 10 }, () =>
        request(app).get('/diagnostics')
      );

      await Promise.all(allowedPromises);

      // The next request should be rate limited
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
      // Diagnostics should have lower limit (10) than health (100)
      const healthResponse = await request(app).get('/health').expect(200);
      const diagnosticsResponse = await request(app).get('/diagnostics').expect(200);
      
      expect(parseInt(healthResponse.headers['x-ratelimit-limit'])).toBeGreaterThan(
        parseInt(diagnosticsResponse.headers['x-ratelimit-limit'])
      );
    });
  });

  describe('General API Endpoint Rate Limiting', () => {
    it('should allow requests within general endpoint limit', async () => {
      // Make 100 requests to general API endpoint
      const promises = Array.from({ length: 100 }, () =>
        request(app).get('/api/data').expect(200)
      );

      const responses = await Promise.all(promises);
      
      responses.forEach(response => {
        expect(response.body).toEqual({ data: 'response' });
        expect(response.headers['x-ratelimit-limit']).toBe('200');
      });
    });

    it('should block requests after exceeding general endpoint limit', async () => {
      // Make requests to exhaust the limit (200 requests)
      const allowedPromises = Array.from({ length: 200 }, () =>
        request(app).get('/api/data')
      );

      await Promise.all(allowedPromises);

      // The next request should be rate limited
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
      // Make requests to both /api/data and /api/users
      const dataPromises = Array.from({ length: 100 }, () =>
        request(app).get('/api/data')
      );
      const userPromises = Array.from({ length: 100 }, () =>
        request(app).get('/api/users')
      );

      await Promise.all([...dataPromises, ...userPromises]);

      // Both should share the same rate limit bucket
      const blockedResponse = await request(app).get('/api/data').expect(429);
      expect(blockedResponse.body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });
  });

  describe('Cross-Endpoint Rate Limiting', () => {
    it('should maintain separate rate limits for different endpoint types', async () => {
      // Exhaust health endpoint limit
      const healthPromises = Array.from({ length: 100 }, () =>
        request(app).get('/health')
      );
      await Promise.all(healthPromises);

      // Health endpoint should be blocked
      await request(app).get('/health').expect(429);

      // But diagnostics should still be available
      await request(app).get('/diagnostics').expect(200);

      // And general API should still be available
      await request(app).get('/api/data').expect(200);
    });

    it('should handle mixed endpoint requests correctly', async () => {
      // Make requests to different endpoints in sequence
      await request(app).get('/health').expect(200);
      await request(app).get('/diagnostics').expect(200);
      await request(app).get('/api/data').expect(200);
      await request(app).post('/api/users').send({ name: 'test' }).expect(200);

      // All should work independently
      const healthResponse = await request(app).get('/health').expect(200);
      expect(healthResponse.headers['x-ratelimit-remaining']).toBe('98'); // 100 - 2 requests

      const diagnosticsResponse = await request(app).get('/diagnostics').expect(200);
      expect(diagnosticsResponse.headers['x-ratelimit-remaining']).toBe('8'); // 10 - 2 requests

      const apiResponse = await request(app).get('/api/data').expect(200);
      expect(apiResponse.headers['x-ratelimit-remaining']).toBe('197'); // 200 - 3 requests (including POST)
    });
  });

  describe('Concurrent Request Handling', () => {
    it('should handle concurrent requests to same endpoint correctly', async () => {
      // Make 50 concurrent requests
      const promises = Array.from({ length: 50 }, () =>
        request(app).get('/health')
      );

      const responses = await Promise.all(promises);
      
      // All should succeed as they're within limit
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });

      // Verify final remaining count
      const finalResponse = await request(app).get('/health').expect(200);
      expect(parseInt(finalResponse.headers['x-ratelimit-remaining'])).toBe(49);
    });

    it('should handle concurrent requests from different clients', async () => {
      const app1 = createTestApp();
      const app2 = createTestApp();

      // Concurrent requests from different app instances (simulating different clients)
      const promises1 = Array.from({ length: 25 }, () =>
        request(app1).get('/health')
      );
      const promises2 = Array.from({ length: 25 }, () =>
        request(app2).get('/health')
      );

      const [responses1, responses2] = await Promise.all([
        Promise.all(promises1),
        Promise.all(promises2)
      ]);

      // All should succeed
      [...responses1, ...responses2].forEach(response => {
        expect(response.status).toBe(200);
      });
    });
  });

  describe('HTTP Methods Rate Limiting', () => {
    it('should apply rate limiting to different HTTP methods', async () => {
      // Test GET request
      const getResponse = await request(app).get('/api/users').expect(200);
      expect(getResponse.headers['x-ratelimit-remaining']).toBe('199');

      // Test POST request
      const postResponse = await request(app)
        .post('/api/users')
        .send({ name: 'John Doe' })
        .expect(200);
      expect(postResponse.headers['x-ratelimit-remaining']).toBe('198');

      // Both should share the same rate limit
      expect(postResponse.body).toEqual({ user: { name: 'John Doe' } });
    });

    it('should count all HTTP methods toward the same limit', async () => {
      // Make requests using different methods but same rate limiter
      const requests = [
        () => request(app).get('/api/data'),
        () => request(app).get('/api/users'),
        () => request(app).post('/api/users').send({ test: 'data' })
      ];

      // Make 66 requests using different methods (66 * 3 = 198)
      for (let i = 0; i < 66; i++) {
        await requests[0](); // GET /api/data
        await requests[1](); // GET /api/users  
        await requests[2](); // POST /api/users
      }

      // Should have 2 requests remaining
      const response = await request(app).get('/api/data').expect(200);
      expect(parseInt(response.headers['x-ratelimit-remaining'])).toBe(1);

      // Next request should still work
      await request(app).get('/api/data').expect(200);

      // But the one after should be blocked
      await request(app).get('/api/data').expect(429);
    });
  });

  describe('Rate Limit Headers Consistency', () => {
    it('should provide consistent rate limit headers across requests', async () => {
      const response1 = await request(app).get('/health').expect(200);
      const response2 = await request(app).get('/health').expect(200);
      const response3 = await request(app).get('/health').expect(200);

      // Limit should remain constant
      expect(response1.headers['x-ratelimit-limit']).toBe('100');
      expect(response2.headers['x-ratelimit-limit']).toBe('100');
      expect(response3.headers['x-ratelimit-limit']).toBe('100');

      // Remaining should decrease
      expect(parseInt(response1.headers['x-ratelimit-remaining'])).toBe(99);
      expect(parseInt(response2.headers['x-ratelimit-remaining'])).toBe(98);
      expect(parseInt(response3.headers['x-ratelimit-remaining'])).toBe(97);

      // Reset time should be consistent within the window
      const reset1 = parseInt(response1.headers['x-ratelimit-reset']);
      const reset2 = parseInt(response2.headers['x-ratelimit-reset']);
      const reset3 = parseInt(response3.headers['x-ratelimit-reset']);

      expect(Math.abs(reset1 - reset2)).toBeLessThan(2); // Should be within 1-2 seconds
      expect(Math.abs(reset2 - reset3)).toBeLessThan(2);
    });

    it('should not include rate limit headers when rate limited', async () => {
      // Exhaust the limit
      const allowedPromises = Array.from({ length: 100 }, () =>
        request(app).get('/health')
      );
      await Promise.all(allowedPromises);

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

      expect(response.headers['x-ratelimit-limit']).toBe('200');
    });

    it('should handle requests with special characters in URL', async () => {
      // The rate limiter should work regardless of URL content
      const response = await request(app)
        .get('/api/data?query=test%20with%20spaces&special=chars!')
        .expect(200);

      expect(response.headers['x-ratelimit-limit']).toBe('200');
      expect(response.headers['x-ratelimit-remaining']).toBe('199');
    });

    it('should maintain performance under load', async () => {
      const startTime = Date.now();

      // Make many concurrent requests
      const promises = Array.from({ length: 100 }, () =>
        request(app).get('/health')
      );

      await Promise.all(promises);

      const endTime = Date.now();
      const duration = endTime - startTime;

      // Should complete within reasonable time (less than 5 seconds)
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Rate Limit Window Behavior', () => {
    it('should handle requests near rate limit boundaries', async () => {
      // Make requests up to one before the limit
      const promises = Array.from({ length: 99 }, () =>
        request(app).get('/health')
      );
      await Promise.all(promises);

      // Should still allow one more
      const lastAllowedResponse = await request(app).get('/health').expect(200);
      expect(lastAllowedResponse.headers['x-ratelimit-remaining']).toBe('0');

      // Next should be blocked
      await request(app).get('/health').expect(429);
    });

    it('should provide accurate retry-after times', async () => {
      // Exhaust limit
      const promises = Array.from({ length: 100 }, () =>
        request(app).get('/health')
      );
      await Promise.all(promises);

      // Get blocked response
      const blockedResponse = await request(app).get('/health').expect(429);
      const retryAfter = blockedResponse.body.error.retryAfter;

      // Should be a reasonable time (less than 15 minutes)
      expect(retryAfter).toBeGreaterThan(0);
      expect(retryAfter).toBeLessThanOrEqual(900); // 15 minutes in seconds
    });
  });
});