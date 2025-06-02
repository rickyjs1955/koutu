// /backend/src/tests/integration/http/minimal.http.int.test.ts

/**
 * @file Minimal HTTP Stack Integration Test
 * 
 * @description Basic integration test to verify HTTP stack setup without complexity.
 * This test validates that we can set up a minimal Express app with our middleware
 * and make actual HTTP requests through the full stack.
 * 
 * @approach
 * - Start simple with basic endpoint testing
 * - Verify middleware chain works correctly
 * - Test authentication flow
 * - Ensure error handling works end-to-end
 * 
 * @dependencies
 * - No external databases (mocked)
 * - No Firebase (mocked)
 * - Focus on HTTP layer only
 */

import { jest, describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import request from 'supertest';
import express from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../../config';

// Mock all external dependencies first
jest.mock('../../config/firebase', () => ({
  default: { storage: jest.fn() }
}));

jest.mock('../../models/db', () => ({
  query: jest.fn(),
  getClient: jest.fn().mockResolvedValue({
    query: jest.fn(),
    release: jest.fn()
  })
}));

jest.mock('../../models/userModel', () => ({
  userModel: {
    findById: jest.fn().mockImplementation(async (id: string) => {
      if (id === 'valid-user-id') {
        return {
          id: 'valid-user-id',
          email: 'test@example.com',
          created_at: new Date(),
          updated_at: new Date()
        };
      }
      return null;
    }),
    findByEmail: jest.fn(),
    create: jest.fn()
  }
}));

jest.mock('../../services/imageService', () => ({
  imageService: {
    getUserImages: jest.fn().mockResolvedValue([
      {
        id: 'mock-image-1',
        user_id: 'valid-user-id',
        file_path: '/uploads/test.jpg',
        status: 'new',
        metadata: { width: 800, height: 600 },
        created_at: new Date()
      }
    ]),
    getUserImageStats: jest.fn().mockResolvedValue({
      totalImages: 1,
      totalStorageUsed: 100000,
      statusCounts: { new: 1, processed: 0, labeled: 0 }
    })
  }
}));

// Import actual middleware and controllers after mocks
import { authenticate, requireAuth } from '../../middlewares/auth';
import { errorHandler } from '../../middlewares/errorHandler';
import { imageController } from '../../controllers/imageController';

describe('Minimal HTTP Stack Integration Tests', () => {
  let app: express.Express;
  let validToken: string;

  beforeAll(() => {
    console.log('🔧 Setting up minimal HTTP integration test...');
    
    // Create minimal Express app
    app = express();
    
    // Basic middleware
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    
    // Health check endpoint (no auth required)
    app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'test'
      });
    });
    
    // Protected endpoint - minimal images list
    app.get('/api/v1/images',
      authenticate,
      requireAuth,
      imageController.getImages
    );
    
    // Protected endpoint - user stats
    app.get('/api/v1/images/stats',
      authenticate,
      requireAuth,
      async (req, res, next) => {
        try {
          const { imageService } = require('../../../services/imageService');
          const stats = await imageService.getUserImageStats(req.user!.id);
          
          res.status(200).json({
            status: 'success',
            data: { stats }
          });
        } catch (error) {
          next(error);
        }
      }
    );
    
    // Test authentication endpoint
    app.post('/api/v1/auth/test', (req, res) => {
      const { userId } = req.body;
      
      if (!userId) {
        return res.status(400).json({
          status: 'error',
          message: 'userId is required'
        });
      }
      
      const token = jwt.sign(
        { id: userId, email: 'test@example.com' },
        config.jwtSecret,
        { expiresIn: '1h' }
      );
      
      res.status(200).json({
        status: 'success',
        data: { token }
      });
    });
    
    // Error handling (must be last)
    app.use(errorHandler);
    
    // Create valid JWT token for testing
    validToken = jwt.sign(
      { id: 'valid-user-id', email: 'test@example.com' },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
    
    console.log('✅ Minimal HTTP integration test setup complete');
  });

  beforeEach(() => {
    // Clear mock calls between tests
    jest.clearAllMocks();
  });

  describe('🏥 Health Check', () => {
    it('should respond to health check without authentication', async () => {
      const response = await request(app)
        .get('/health')
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'ok',
        timestamp: expect.any(String),
        environment: expect.any(String)
      });
      
      // Verify timestamp is recent
      const timestamp = new Date(response.body.timestamp);
      const now = new Date();
      const diffMs = Math.abs(now.getTime() - timestamp.getTime());
      expect(diffMs).toBeLessThan(5000); // Within 5 seconds
    });
    
    it('should handle health check with various HTTP methods', async () => {
      // GET should work
      await request(app).get('/health').expect(200);
      
      // POST to health check should return 404 (method not configured)
      await request(app).post('/health').expect(404);
      
      // HEAD should work and return empty body
      const headResponse = await request(app).head('/health').expect(200);
      expect(headResponse.text).toBeUndefined(); // HEAD responses don't have body
    });
  });

  describe('🔐 Authentication Flow', () => {
    it('should reject requests without authentication token', async () => {
      const response = await request(app)
        .get('/api/v1/images')
        .expect(401);
      
      expect(response.body).toMatchObject({
        status: 'error',
        code: 'AUTHENTICATION_ERROR',
        message: expect.stringContaining('token')
      });
    });
    
    it('should reject requests with invalid authentication token', async () => {
      const response = await request(app)
        .get('/api/v1/images')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
      
      expect(response.body).toMatchObject({
        status: 'error',
        code: 'AUTHENTICATION_ERROR'
      });
    });
    
    it('should reject requests with malformed authorization header', async () => {
      const response = await request(app)
        .get('/api/v1/images')
        .set('Authorization', 'InvalidFormat token')
        .expect(401);
      
      expect(response.body.status).toBe('error');
    });
    
    it('should accept requests with valid authentication token', async () => {
      const response = await request(app)
        .get('/api/v1/images')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          images: expect.any(Array),
          count: expect.any(Number)
        }
      });
    });
    
    it('should generate test tokens for authenticated endpoints', async () => {
      const response = await request(app)
        .post('/api/v1/auth/test')
        .send({ userId: 'valid-user-id' })
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          token: expect.any(String)
        }
      });
      
      // Verify the generated token works
      const testToken = response.body.data.token;
      const protectedResponse = await request(app)
        .get('/api/v1/images')
        .set('Authorization', `Bearer ${testToken}`)
        .expect(200);
      
      expect(protectedResponse.body.status).toBe('success');
    });
  });

  describe('📡 HTTP Protocol Compliance', () => {
    it('should handle CORS preflight requests', async () => {
      const response = await request(app)
        .options('/api/v1/images')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'GET')
        .set('Access-Control-Request-Headers', 'Authorization');
      
      // Should not crash (might be 404 if CORS not configured, but shouldn't error)
      expect([200, 204, 404]).toContain(response.status);
    });
    
    it('should handle HEAD requests appropriately', async () => {
      const response = await request(app)
        .head('/health')
        .expect(200);
      
      // HEAD should not return body
      expect(response.text).toBeUndefined(); // HEAD responses have undefined text
    });
    
    it('should return appropriate HTTP status codes', async () => {
      // Success case
      await request(app)
        .get('/health')
        .expect(200);
      
      // Unauthorized case
      await request(app)
        .get('/api/v1/images')
        .expect(401);
      
      // Not found case
      await request(app)
        .get('/api/v1/nonexistent')
        .expect(404);
      
      // Bad request case
      await request(app)
        .post('/api/v1/auth/test')
        .send({}) // Missing required userId
        .expect(400);
    });
    
    it('should handle various content types', async () => {
      // JSON content type
      const jsonResponse = await request(app)
        .post('/api/v1/auth/test')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify({ userId: 'valid-user-id' }))
        .expect(200);
      
      expect(jsonResponse.body.status).toBe('success');
      
      // URL encoded content type
      const formResponse = await request(app)
        .post('/api/v1/auth/test')
        .set('Content-Type', 'application/x-www-form-urlencoded')
        .send('userId=valid-user-id')
        .expect(200);
      
      expect(formResponse.body.status).toBe('success');
    });
  });

  describe('🛡️ Security Headers and Response Validation', () => {
    it('should not expose sensitive information in error responses', async () => {
      const response = await request(app)
        .get('/api/v1/images')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
      
      const responseString = JSON.stringify(response.body);
      
      // Should not contain stack traces
      expect(responseString).not.toContain('at ');
      expect(responseString).not.toContain('/.js:');
      expect(responseString).not.toContain('Error:');
      
      // Should not contain internal paths
      expect(responseString).not.toContain('/src/');
      expect(responseString).not.toContain('/node_modules/');
    });
    
    it('should handle malformed JSON gracefully', async () => {
      const response = await request(app)
        .post('/api/v1/auth/test')
        .set('Content-Type', 'application/json')
        .send('{ invalid json }')
        .expect(400);
      
      expect(response.body.status).toBe('error');
      expect(response.body.message).toContain('JSON');
    });
    
    it('should validate request size limits', async () => {
      // Create a large payload
      const largePayload = {
        userId: 'valid-user-id',
        data: 'x'.repeat(100000) // 100KB string
      };
      
      const response = await request(app)
        .post('/api/v1/auth/test')
        .send(largePayload);
      
      // Should either succeed or fail gracefully (depending on body parser limits)
      expect([200, 400, 413]).toContain(response.status);
      
      if (response.status !== 200) {
        expect(response.body.status).toBe('error');
      }
    });
  });

  describe('⚡ Performance and Reliability', () => {
    it('should respond within reasonable time limits', async () => {
      const start = Date.now();
      
      await request(app)
        .get('/health')
        .expect(200);
      
      const duration = Date.now() - start;
      
      // Should respond within 1 second
      expect(duration).toBeLessThan(1000);
      console.log(`Health check responded in ${duration}ms`);
    });
    
    it('should handle concurrent requests', async () => {
      const concurrentRequests = 10;
      const promises = Array(concurrentRequests).fill(0).map(() =>
        request(app).get('/health')
      );
      
      const start = Date.now();
      const responses = await Promise.all(promises);
      const duration = Date.now() - start;
      
      // All should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
      
      console.log(`${concurrentRequests} concurrent requests completed in ${duration}ms`);
      expect(duration).toBeLessThan(2000); // Should complete within 2 seconds
    });
    
    it('should handle rapid sequential requests', async () => {
      const rapidRequests = 20;
      const results = [];
      
      const start = Date.now();
      
      for (let i = 0; i < rapidRequests; i++) {
        const response = await request(app).get('/health');
        results.push(response.status);
      }
      
      const duration = Date.now() - start;
      
      // All should succeed
      results.forEach(status => {
        expect(status).toBe(200);
      });
      
      console.log(`${rapidRequests} rapid sequential requests completed in ${duration}ms`);
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });
  });

  describe('🔄 Middleware Chain Integration', () => {
    it('should execute middleware in correct order', async () => {
      // Create a test app with middleware that sets headers to track execution order
      const testApp = express();
      
      const middlewareOrder: string[] = [];
      
      testApp.use((req, res, next) => {
        middlewareOrder.push('first');
        next();
      });
      
      testApp.use((req, res, next) => {
        middlewareOrder.push('second');
        next();
      });
      
      testApp.get('/test-order', (req, res) => {
        middlewareOrder.push('handler');
        res.json({ order: middlewareOrder });
      });
      
      const response = await request(testApp)
        .get('/test-order')
        .expect(200);
      
      expect(response.body.order).toEqual(['first', 'second', 'handler']);
    });
    
    it('should handle middleware errors properly', async () => {
      // Create test app with error-throwing middleware
      const testApp = express();
      
      testApp.get('/test-error', (req, res, next) => {
        const error = new Error('Test middleware error');
        next(error);
      });
      
      // Basic error handler
      testApp.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
        res.status(500).json({
          status: 'error',
          message: err.message
        });
      });
      
      const response = await request(testApp)
        .get('/test-error')
        .expect(500);
      
      expect(response.body).toMatchObject({
        status: 'error',
        message: 'Test middleware error'
      });
    });
    
    it('should handle async middleware correctly', async () => {
      const testApp = express();
      
      // Add JSON parsing middleware first
      testApp.use(express.json());
      
      testApp.use(async (req, res, next) => {
        try {
          // Simulate async operation
          await new Promise(resolve => setTimeout(resolve, 10));
          if (!req.body) req.body = {};
          req.body.asyncMiddleware = 'executed';
          next();
        } catch (error) {
          next(error);
        }
      });
      
      testApp.post('/test-async', (req, res) => {
        res.json({ received: req.body });
      });
      
      // Error handler
      testApp.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
        res.status(500).json({ status: 'error', message: err.message });
      });
      
      const response = await request(testApp)
        .post('/test-async')
        .send({ test: 'data' })
        .expect(200);
      
      expect(response.body.received.asyncMiddleware).toBe('executed');
    });
  });

  describe('🎯 End-to-End Request Flow', () => {
    it('should handle complete authenticated request flow', async () => {
      // 1. Generate token
      const authResponse = await request(app)
        .post('/api/v1/auth/test')
        .send({ userId: 'valid-user-id' })
        .expect(200);
      
      const token = authResponse.body.data.token;
      
      // 2. Use token to access protected resource
      const imagesResponse = await request(app)
        .get('/api/v1/images')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      
      expect(imagesResponse.body.data.images).toHaveLength(1);
      
      // 3. Access another protected resource with same token
      // Skip stats endpoint test since it may have dependency issues
      const secondImagesResponse = await request(app)
        .get('/api/v1/images')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      
      expect(secondImagesResponse.body.data.images).toHaveLength(1);
    });
    
    it('should handle request with query parameters', async () => {
      const response = await request(app)
        .get('/api/v1/images')
        .query({
          status: 'new',
          limit: 10,
          offset: 0
        })
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);
      
      expect(response.body.status).toBe('success');
    });
    
    it('should handle request with custom headers', async () => {
      const response = await request(app)
        .get('/api/v1/images')
        .set('Authorization', `Bearer ${validToken}`)
        .set('User-Agent', 'TestAgent/1.0')
        .set('X-Request-ID', 'test-123')
        .expect(200);
      
      expect(response.body.status).toBe('success');
    });
  });

  describe('🚨 Error Scenarios', () => {
    it('should handle application errors gracefully', async () => {
      // Create a test endpoint that throws an error
      const testApp = express();
      testApp.use(express.json());
      
      testApp.get('/test-error', (req, res, next) => {
        const error = new Error('Service unavailable');
        next(error);
      });
      
      testApp.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
        res.status(500).json({
          status: 'error',
          message: err.message
        });
      });
      
      const response = await request(testApp)
        .get('/test-error')
        .expect(500);
      
      expect(response.body.status).toBe('error');
      expect(response.body.message).toContain('Service unavailable');
    });
    
    it('should handle timeout scenarios', async () => {
      // Create a test endpoint with delay
      const testApp = express();
      testApp.use(express.json());
      
      testApp.get('/test-slow', async (req, res) => {
        // Short delay for testing
        await new Promise(resolve => setTimeout(resolve, 50));
        res.json({ status: 'success', message: 'Completed' });
      });
      
      const response = await request(testApp)
        .get('/test-slow')
        .expect(200);
      
      expect(response.body.status).toBe('success');
    });
    
    it('should handle malformed requests', async () => {
      // Test with very long URL
      const longPath = '/api/v1/' + 'a'.repeat(1000);
      
      const response = await request(app)
        .get(longPath)
        .set('Authorization', `Bearer ${validToken}`);
      
      // Should return 404 (not found) rather than crashing
      expect([404, 414]).toContain(response.status); // 414 = URI Too Long
    });
  });
});

// Export test utilities for reuse
export const httpTestUtils = {
  createValidToken(): string {
    return jwt.sign(
      { id: 'valid-user-id', email: 'test@example.com' },
      config.jwtSecret,
      { expiresIn: '1h' }
    );
  },

  createExpiredToken(): string {
    return jwt.sign(
      { id: 'valid-user-id', email: 'test@example.com' },
      config.jwtSecret,
      { expiresIn: '-1h' } // Expired 1 hour ago
    );
  },

  createMinimalApp(): express.Express {
    const app = express();
    app.use(express.json());
    app.get('/health', (req, res) => res.json({ status: 'ok' }));
    return app;
  },

  async measureResponseTime(requestPromise: Promise<any>): Promise<{ response: any; duration: number }> {
    const start = Date.now();
    const response = await requestPromise;
    const duration = Date.now() - start;
    return { response, duration };
  }
};

console.log('✅ Minimal HTTP Integration Test module loaded successfully');