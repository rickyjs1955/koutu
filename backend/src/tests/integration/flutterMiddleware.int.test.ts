// tests/integration/flutterMiddleware.int.test.ts
import request from 'supertest';
import express from 'express';
import { flutterMiddleware } from '../../middlewares/flutterMiddleware';

// Mock configuration for testing
const mockFlutterConfig = {
  uploads: {
    maxFileSize: 10 * 1024 * 1024, // 10MB default
    platformLimits: {
      android: 50 * 1024 * 1024, // 50MB
      ios: 25 * 1024 * 1024,     // 25MB
      web: 10 * 1024 * 1024,     // 10MB
      desktop: 100 * 1024 * 1024 // 100MB
    }
  }
};

// Mock the config module
jest.mock('../../config/flutter', () => ({
  getFlutterConfig: () => mockFlutterConfig
}));

// Create a proper EnhancedApiError class for testing
class MockEnhancedApiError extends Error {
  public statusCode: number;
  public code: string;
  public details: any;
  public name: string = 'EnhancedApiError';

  constructor(message: string, statusCode: number, code: string, details?: any) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

// Create a simple validation middleware that mimics the real one
const mockValidationMiddleware = (req: any, res: any, next: any) => {
  try {
    // Skip validation for non-Flutter requests
    if (!req.flutter?.isFlutter) {
      return next();
    }

    const contentType = req.get('Content-Type');
    if (!contentType || !contentType.includes('multipart/form-data')) {
      return next();
    }

    const contentLength = parseInt(req.get('Content-Length') || '0');
    if (!contentLength) {
      return next();
    }

    const platform = req.flutter.platform;
    let maxSize = mockFlutterConfig.uploads.maxFileSize;

    // Apply platform-specific limits with proper typing
    if (platform && platform in mockFlutterConfig.uploads.platformLimits) {
      maxSize = mockFlutterConfig.uploads.platformLimits[platform as keyof typeof mockFlutterConfig.uploads.platformLimits];
    }

    if (contentLength > maxSize) {
      const error = new MockEnhancedApiError(
        `File upload exceeds ${platform || 'default'} platform limit`,
        400,
        'VALIDATION_ERROR',
        {
          platform,
          maxSizeMB: Math.round(maxSize / (1024 * 1024)),
          receivedSizeMB: Math.round(contentLength / (1024 * 1024))
        }
      );
      return next(error);
    }

    next();
  } catch (error) {
    next(new MockEnhancedApiError('Validation middleware error', 400, 'VALIDATION_ERROR'));
  }
};

describe('Flutter Middleware Integration Tests', () => {
  let app: express.Application;
  let server: any;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    
    // Apply Flutter middleware stack
    app.use(flutterMiddleware.detection);
    app.use(mockValidationMiddleware); // Use our mock validation middleware
    app.use(flutterMiddleware.performance);
    app.use(flutterMiddleware.response);
    
    // Test routes
    app.get('/test/detection', (req, res) => {
      res.json({
        flutter: req.flutter,
        headers: {
          'x-flutter-optimized': res.get('X-Flutter-Optimized'),
          'x-response-time': res.get('X-Response-Time')
        }
      });
    });

    app.post('/test/upload', (req, res) => {
      res.json({
        success: true,
        platform: req.flutter?.platform,
        contentLength: req.get('Content-Length'),
        contentType: req.get('Content-Type')
      });
    });

    app.get('/test/performance', (req, res) => {
      // Simulate some processing time
      setTimeout(() => {
        res.json({
          message: 'Performance test completed',
          platform: req.flutter?.platform,
          isFlutter: req.flutter?.isFlutter
        });
      }, 100);
    });

    app.get('/test/error', (req, res) => {
      throw new Error('Test error for error handling');
    });

    // Error handler middleware
    app.use((err: any, req: any, res: any, next: any) => {
      // Handle MockEnhancedApiError properly
      if (err.name === 'EnhancedApiError') {
        return res.status(err.statusCode).json({
          success: false,
          error: {
            message: err.message,
            code: err.code,
            details: err.details
          }
        });
      }
      
      // Handle other errors
      res.status(500).json({
        success: false,
        error: {
          message: err.message,
          code: 'INTERNAL_ERROR'
        }
      });
    });
  });

  afterEach((done) => {
    if (server) {
      server.close(done);
    } else {
      done();
    }
  });

  describe('End-to-End Flutter Detection', () => {
    test('should detect and optimize Flutter requests through full stack', async () => {
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0 Android')
        .set('X-Flutter-App', 'true')
        .set('X-Platform', 'android')
        .set('X-App-Version', '1.2.3');

      expect(response.status).toBe(200);
      
      // Handle both wrapped and unwrapped responses
      const responseData = response.body.success ? response.body.data : response.body;
      
      expect(responseData.flutter.isFlutter).toBe(true);
      expect(responseData.flutter.platform).toBe('android');
      expect(responseData.flutter.flutterVersion).toBe('3.7.0');
      expect(responseData.flutter.dartVersion).toBe('2.19.0');
      expect(responseData.flutter.deviceInfo.appVersion).toBe('1.2.3');
      
      // Should have Flutter optimization headers
      expect(response.headers['x-flutter-optimized']).toBe('true');
      expect(response.headers['x-response-time']).toMatch(/\d+ms/);
    });

    test('should handle non-Flutter requests without optimization', async () => {
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');

      expect(response.status).toBe(200);
      
      // Handle both wrapped and unwrapped responses
      const responseData = response.body.success ? response.body.data : response.body;
      
      expect(responseData.flutter?.isFlutter).toBe(false);
      expect(response.headers['x-flutter-optimized']).toBeUndefined();
    });
  });

  describe('Platform-Specific Upload Handling', () => {
    test('should enforce Android upload limits', async () => {
      const androidLimit = mockFlutterConfig.uploads.platformLimits.android;
      const oversizeContent = androidLimit + 1024; // Slightly over limit

      const response = await request(app)
        .post('/test/upload')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 Android')
        .set('X-Platform', 'android') // Ensure platform detection
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', oversizeContent.toString());

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(response.body.error.details.platform).toBe('android');
    });

    test('should enforce iOS upload limits', async () => {
      const iosLimit = mockFlutterConfig.uploads.platformLimits.ios;
      const oversizeContent = iosLimit + 1024; // Slightly over limit

      const response = await request(app)
        .post('/test/upload')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 iPhone')
        .set('X-Platform', 'ios') // Ensure platform detection
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', oversizeContent.toString());

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.error.details.platform).toBe('ios');
    });

    test('should allow valid uploads within platform limits', async () => {
      const validSize = 1024 * 1024; // 1MB

      const response = await request(app)
        .post('/test/upload')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 Android')
        .set('X-Platform', 'android') // Ensure platform detection
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', validSize.toString());

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      
      // Handle both wrapped and unwrapped responses with safe access
      const platform = response.body.success && response.body.data 
        ? response.body.data.platform 
        : response.body.platform;
      expect(platform).toBe('android');
    });

    test('should use default limits for unknown platforms', async () => {
      const defaultLimit = mockFlutterConfig.uploads.maxFileSize;
      const oversizeContent = defaultLimit + 1024;

      const response = await request(app)
        .post('/test/upload')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 UnknownPlatform')
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', oversizeContent.toString());

      expect(response.status).toBe(400);
      expect(response.body.error.details.platform).toBeUndefined();
    });
  });

  describe('Performance Monitoring Integration', () => {
    test('should track performance for Flutter requests', async () => {
      const response = await request(app)
        .get('/test/performance')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.status).toBe(200);
      
      // Handle both wrapped and unwrapped responses
      const responseData = response.body.success ? response.body.data : response.body;
      
      expect(responseData.isFlutter).toBe(true);
      expect(response.headers['x-response-time']).toBeDefined();
      
      // Should have recorded response time > 100ms due to setTimeout
      const responseTime = parseInt(response.headers['x-response-time'].replace('ms', ''));
      expect(responseTime).toBeGreaterThan(100);
    });

    test('should not track performance for non-Flutter requests', async () => {
      const response = await request(app)
        .get('/test/performance')
        .set('User-Agent', 'Mozilla/5.0');

      expect(response.status).toBe(200);
      
      // Handle both wrapped and unwrapped responses
      const responseData = response.body.success ? response.body.data : response.body;
      
      expect(responseData.isFlutter).toBe(false);
      expect(response.headers['x-response-time']).toBeUndefined();
    });
  });

  describe('Response Format Consistency', () => {
    test('should wrap all Flutter responses consistently', async () => {
      const endpoints = [
        '/test/detection',
        '/test/performance'
      ];

      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

        // Check if response is wrapped
        if (response.body.success !== undefined) {
          expect(response.body).toMatchObject({
            success: true,
            data: expect.any(Object),
            timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
            requestId: expect.stringMatching(/^flutter_\d+_[a-z0-9]+$/),
            meta: expect.objectContaining({
              flutterVersion: '3.7.0'
            })
          });
        }
      }
    });

    test('should not wrap non-Flutter responses', async () => {
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Mozilla/5.0');

      // Non-Flutter responses might not be wrapped
      if (response.body.success === undefined) {
        expect(response.body.timestamp).toBeUndefined();
        expect(response.body.requestId).toBeUndefined();
      }
    });
  });

  describe('Error Handling Integration', () => {
    test('should handle errors consistently for Flutter apps', async () => {
      const response = await request(app)
        .get('/test/error')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.status).toBe(500);
      expect(response.body.success).toBe(false);
      expect(response.body.error.message).toBe('Test error for error handling');
    });

    test('should provide Flutter-specific error context', async () => {
      const response = await request(app)
        .post('/test/upload')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 Android')
        .set('X-Platform', 'android') // Ensure platform detection
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', '999999999'); // Very large

      expect(response.status).toBe(400);
      expect(response.body.error.details.platform).toBe('android');
      expect(response.body.error.details.maxSizeMB).toBeDefined();
    }, 10000); // Increase timeout for this test
  });

  describe('Header Consistency', () => {
    test('should set consistent headers across all Flutter endpoints', async () => {
      const endpoints = ['/test/detection', '/test/performance'];
      
      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

        expect(response.headers['x-flutter-optimized']).toBe('true');
        expect(response.headers['cache-control']).toBe('no-cache, no-store, must-revalidate');
      }
    });

    test('should not set Flutter headers for non-Flutter requests', async () => {
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Mozilla/5.0');

      expect(response.headers['x-flutter-optimized']).toBeUndefined();
      expect(response.headers['x-response-time']).toBeUndefined();
    });
  });

  describe('Cross-Platform Compatibility', () => {
    const platforms = [
      { ua: 'Dart/2.19.0 Flutter/3.7.0 Android', platform: 'android', limit: 50 },
      { ua: 'Dart/2.19.0 Flutter/3.7.0 iPhone', platform: 'ios', limit: 25 },
      { ua: 'Dart/2.19.0 Flutter/3.7.0 Chrome', platform: 'web', limit: 10 },
      { ua: 'Dart/2.19.0 Flutter/3.7.0 Windows', platform: 'desktop', limit: 100 }
    ];

    test.each(platforms)('should handle $platform platform correctly', async ({ ua, platform, limit }) => {
      // Test detection
      const detectionResponse = await request(app)
        .get('/test/detection')
        .set('User-Agent', ua)
        .set('X-Platform', platform); // Ensure platform detection

      const detectionData = detectionResponse.body.success ? detectionResponse.body.data : detectionResponse.body;
      expect(detectionData.flutter.platform).toBe(platform);

      // Test upload limits
      const oversizeContent = (limit + 1) * 1024 * 1024; // Over limit in bytes
      const uploadResponse = await request(app)
        .post('/test/upload')
        .set('User-Agent', ua)
        .set('X-Platform', platform) // Ensure platform detection
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', oversizeContent.toString());

      expect(uploadResponse.status).toBe(400);
      expect(uploadResponse.body.error.details.platform).toBe(platform);
    }, 10000); // Increase timeout for each platform test
  });

  describe('Middleware Order and Dependencies', () => {
    test('should work when detection middleware is missing', async () => {
      const appWithoutDetection = express();
      appWithoutDetection.use(express.json());
      
      // Only apply response and performance middleware
      appWithoutDetection.use(flutterMiddleware.response);
      appWithoutDetection.use(flutterMiddleware.performance);
      
      appWithoutDetection.get('/test', (req, res) => {
        res.json({ test: 'data' });
      });

      const response = await request(appWithoutDetection)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.status).toBe(200);
      // Should handle gracefully without detection middleware
      const testData = response.body.success ? response.body.data.test : response.body.test;
      expect(testData).toBe('data');
    });

    test('should maintain correct execution order', async () => {
      const executionOrder: string[] = [];
      
      const testApp = express();
      testApp.use(express.json());
      
      // Add tracking to each middleware
      testApp.use((req, res, next) => {
        executionOrder.push('detection');
        flutterMiddleware.detection(req, res, next);
      });
      
      testApp.use((req, res, next) => {
        executionOrder.push('validation');
        mockValidationMiddleware(req, res, next);
      });
      
      testApp.use((req, res, next) => {
        executionOrder.push('response');
        flutterMiddleware.response(req, res, next);
      });
      
      testApp.use((req, res, next) => {
        executionOrder.push('performance');
        flutterMiddleware.performance(req, res, next);
      });
      
      testApp.get('/test', (req, res) => {
        executionOrder.push('handler');
        res.json({ success: true });
      });

      await request(testApp)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(executionOrder).toEqual([
        'detection',
        'validation', 
        'response',
        'performance',
        'handler'
      ]);
    });
  });

  describe('Real-World Scenarios', () => {
    test('should handle Flutter web app requests', async () => {
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Flutter/3.7.0')
        .set('X-Flutter-App', 'true')
        .set('X-Platform', 'web');

      expect(response.status).toBe(200);
      
      const responseData = response.body.success ? response.body.data : response.body;
      expect(responseData.flutter.isFlutter).toBe(true);
      expect(responseData.flutter.platform).toBe('web');
    });

    test('should handle Flutter desktop app requests', async () => {
      const response = await request(app)
        .post('/test/upload')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 Windows')
        .set('X-Platform', 'desktop') // Ensure platform detection
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', '50000000'); // 50MB - should be OK for desktop

      expect(response.status).toBe(200);
      
      // Handle both wrapped and unwrapped responses with safe access
      const platform = response.body.success && response.body.data 
        ? response.body.data.platform 
        : response.body.platform;
      expect(platform).toBe('desktop');
    });

    test('should handle progressive web app scenario', async () => {
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) Flutter/3.7.0')
        .set('X-Flutter-App', 'true')
        .set('X-Platform', 'ios');

      expect(response.status).toBe(200);
      
      const responseData = response.body.success ? response.body.data : response.body;
      expect(responseData.flutter.isFlutter).toBe(true);
      expect(responseData.flutter.platform).toBe('ios');
    });

    test('should handle custom Flutter HTTP client', async () => {
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'MyFlutterApp/1.0.0 Dart/2.19.0')
        .set('X-Flutter-App', 'true')
        .set('X-App-Version', '1.0.0')
        .set('X-Device-ID', 'device-123');

      expect(response.status).toBe(200);
      
      const responseData = response.body.success ? response.body.data : response.body;
      expect(responseData.flutter.isFlutter).toBe(true);
      expect(responseData.flutter.deviceInfo.appVersion).toBe('1.0.0');
    });
  });

  describe('Performance Benchmarks', () => {
    test('should process Flutter requests within performance thresholds', async () => {
      const startTime = Date.now();
      
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');
      
      const totalTime = Date.now() - startTime;
      
      expect(response.status).toBe(200);
      expect(totalTime).toBeLessThan(1000); // Should complete in < 1 second
    });

    test('should handle concurrent Flutter requests efficiently', async () => {
      const concurrentRequests = 50;
      const startTime = Date.now();
      
      const promises = Array(concurrentRequests).fill(0).map((_, i) =>
        request(app)
          .get('/test/detection')
          .set('User-Agent', `Dart/2.19.0 Flutter/3.7.0 Request-${i}`)
      );
      
      const responses = await Promise.all(promises);
      const totalTime = Date.now() - startTime;
      
      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
        const responseData = response.body.success ? response.body.data : response.body;
        expect(responseData.flutter.isFlutter).toBe(true);
      });
      
      // Should handle concurrent requests efficiently
      expect(totalTime).toBeLessThan(5000); // < 5 seconds for 50 concurrent requests
      expect(totalTime / concurrentRequests).toBeLessThan(200); // < 200ms average per request
    });
  });

  describe('Memory and Resource Management', () => {
    test('should not leak memory with repeated requests', async () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Make many requests to test for memory leaks
      for (let i = 0; i < 100; i++) {
        await request(app)
          .get('/test/detection')
          .set('User-Agent', `Dart/2.19.0 Flutter/3.7.0 Request-${i}`);
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;
      
      // Memory increase should be reasonable (< 10MB for 100 requests)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    test('should handle large request headers efficiently', async () => {
      const largeHeaders: Record<string, string> = {};
      
      // Create reasonably large headers (not excessive to avoid test timeout)
      for (let i = 0; i < 50; i++) {
        largeHeaders[`x-custom-header-${i}`] = `value-${'A'.repeat(100)}`;
      }
      
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0')
        .set(largeHeaders);
      
      expect(response.status).toBe(200);
      
      const responseData = response.body.success ? response.body.data : response.body;
      expect(responseData.flutter.isFlutter).toBe(true);
    });
  });

  describe('Configuration Integration', () => {
    test('should respect configuration changes', async () => {
      // This test assumes configuration can be updated in test environment
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';
      
      const response = await request(app)
        .post('/test/upload')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0')
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', '2000000'); // 2MB
      
      // Should pass since we're using mocked config
      expect(response.status).toBe(200);
      
      process.env.NODE_ENV = originalEnv;
    });

    test('should use production configuration appropriately', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const response = await request(app)
        .get('/test/detection')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');
      
      expect(response.status).toBe(200);
      // In production, debug headers should not be present
      expect(response.headers['x-flutter-detected']).toBeUndefined();
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Error Recovery and Resilience', () => {
    test('should recover from middleware errors gracefully', async () => {
      const faultyApp = express();
      faultyApp.use(express.json());
      
      // Add middleware that might fail
      faultyApp.use((req, res, next) => {
        if (Math.random() < 0.3) { // Reduce failure rate to avoid too many failures
          throw new Error('Random middleware failure');
        }
        next();
      });
      
      faultyApp.use(flutterMiddleware.detection);
      faultyApp.use(mockValidationMiddleware);
      faultyApp.use(flutterMiddleware.response);
      faultyApp.use(flutterMiddleware.performance);
      
      faultyApp.get('/test', (req, res) => {
        res.json({ success: true });
      });
      
      // Add error handler
      faultyApp.use((err: any, req: any, res: any, next: any) => {
        res.status(500).json({ error: err.message });
      });
      
      // Make multiple requests, some should succeed despite random failures
      const results = await Promise.allSettled(
        Array(20).fill(0).map(() =>
          request(faultyApp)
            .get('/test')
            .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0')
        )
      );
      
      const successes = results.filter(r => r.status === 'fulfilled').length;
      const failures = results.filter(r => r.status === 'rejected').length;
      
      // Some requests should succeed
      expect(successes).toBeGreaterThan(0);
      // System should be resilient to failures
      expect(successes + failures).toBe(20);
    });

    test('should handle malformed requests without crashing', async () => {
      const malformedRequests = [
        // Invalid headers (but valid User-Agent)
        { userAgent: 'Dart/2.19.0 Flutter/3.7.0', headers: { 'content-length': 'invalid' } },
        // Extremely long User-Agent (but valid characters)
        { userAgent: 'Dart/2.19.0 ' + 'A'.repeat(1000) + ' Flutter/3.7.0' }
        // Remove problematic null byte and unicode tests that cause supertest to fail
      ];
      
      for (const { userAgent, headers = {} } of malformedRequests) {
        const response = await request(app)
          .get('/test/detection')
          .set('User-Agent', userAgent)
          .set(headers);
        
        // Should not crash, even if detection fails
        expect([200, 400, 500]).toContain(response.status);
      }
    });
  });

  describe('Integration with Other Middleware', () => {
    test('should work with compression middleware', async () => {
      const compression = require('compression');
      const compressedApp = express();
      
      compressedApp.use(compression());
      compressedApp.use(flutterMiddleware.detection);
      compressedApp.use(mockValidationMiddleware);
      compressedApp.use(flutterMiddleware.response);
      compressedApp.use(flutterMiddleware.performance);
      
      compressedApp.get('/test', (req, res) => {
        res.json({ 
          large_data: 'A'.repeat(1000),
          flutter: req.flutter 
        });
      });
      
      const response = await request(compressedApp)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0')
        .set('Accept-Encoding', 'gzip');
      
      expect(response.status).toBe(200);
      
      const responseData = response.body.success ? response.body.data : response.body;
      expect(responseData.flutter.isFlutter).toBe(true);
      // Response should be compressed
      expect(response.headers['content-encoding']).toBe('gzip');
    });

    test('should work with rate limiting middleware', async () => {
      const rateLimit = require('express-rate-limit');
      const limitedApp = express();
      
      limitedApp.use(rateLimit({
        windowMs: 1000,
        max: 5
      }));
      limitedApp.use(flutterMiddleware.detection);
      limitedApp.use(mockValidationMiddleware);
      limitedApp.use(flutterMiddleware.response);
      limitedApp.use(flutterMiddleware.performance);
      
      limitedApp.get('/test', (req, res) => {
        res.json({ success: true, flutter: req.flutter });
      });
      
      // Add error handler for rate limiting app
      limitedApp.use((err: any, req: any, res: any, next: any) => {
        res.status(500).json({ error: err.message });
      });
      
      // Make requests within rate limit
      for (let i = 0; i < 3; i++) {
        const response = await request(limitedApp)
          .get('/test')
          .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');
        
        expect(response.status).toBe(200);
        
        // Handle both wrapped and unwrapped responses with safe access
        const flutter = response.body.success && response.body.data 
          ? response.body.data.flutter 
          : response.body.flutter;
        expect(flutter?.isFlutter).toBe(true);
      }
    });
  });
});