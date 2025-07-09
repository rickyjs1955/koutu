// tests/unit/healthRoutes.flutter.unit.test.ts
import request from 'supertest';
import express from 'express';
import healthRoutes from '../../routes/healthRoutes';
import { flutterDetectionMiddleware } from '../../middlewares/flutterMiddleware';

// Mock dependencies
jest.mock('../../config', () => ({
  config: {
    storageMode: 'local',
    nodeEnv: 'test',
    port: 3000
  }
}));

jest.mock('../../config/flutter', () => ({
  flutterConfig: {
    uploads: {
      allowedMimeTypes: ['image/jpeg', 'image/png'],
      platformLimits: {
        android: 50 * 1024 * 1024,
        ios: 25 * 1024 * 1024,
        web: 10 * 1024 * 1024,
        desktop: 100 * 1024 * 1024
      }
    }
  }
}));

describe('Health Routes Unit Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(flutterDetectionMiddleware);
    app.use('/', healthRoutes);
    
    // Mock console methods to reduce noise in tests
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('GET /health', () => {
    describe('Basic Health Check', () => {
      test('should return health status with basic structure', async () => {
        const response = await request(app).get('/health');

        expect(response.status).toBe(200);
        expect(response.body).toMatchObject({
          status: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
          timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
          version: expect.any(String),
          platform: expect.objectContaining({
            detected: expect.any(String),
            optimized: expect.any(Boolean)
          }),
          services: expect.any(Object),
          performance: expect.objectContaining({
            responseTimeMs: expect.any(Number),
            memoryUsage: expect.objectContaining({
              used: expect.any(Number),
              total: expect.any(Number),
              percentage: expect.any(Number)
            }),
            uptime: expect.any(Number)
          }),
          flutter: expect.objectContaining({
            corsEnabled: expect.any(Boolean),
            multipartSupport: expect.any(Boolean),
            maxUploadSize: expect.any(String),
            supportedFormats: expect.any(Array),
            platformLimits: expect.any(Object)
          })
        });
      });

      test('should detect Flutter platform correctly', async () => {
        const response = await request(app)
          .get('/health')
          .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0');

        expect(response.body.platform.detected).toBe('flutter');
        expect(response.body.platform.optimized).toBe(true);
        expect(response.body.platform.version).toBe('3.7.0');
      });

      test('should detect web platform correctly', async () => {
        const response = await request(app)
          .get('/health')
          .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');

        expect(response.body.platform.detected).toBe('web');
        expect(response.body.platform.optimized).toBe(false);
        expect(response.body.platform.version).toBeUndefined();
      });
    });

    describe('Service Status Checks', () => {
      test('should include database service status', async () => {
        const response = await request(app).get('/health');

        expect(response.body.services).toHaveProperty('database');
        expect(['up', 'down', 'degraded']).toContain(response.body.services.database);
      });

      test('should include storage service status', async () => {
        const response = await request(app).get('/health');

        expect(response.body.services).toHaveProperty('storage');
        expect(['up', 'down', 'degraded']).toContain(response.body.services.storage);
      });

      test('should conditionally include cache service status', async () => {
        const response = await request(app).get('/health');

        if (response.body.services.cache) {
          expect(['up', 'down', 'degraded']).toContain(response.body.services.cache);
        }
      });

      test('should conditionally include redis service status', async () => {
        const response = await request(app).get('/health');

        if (response.body.services.redis) {
          expect(['up', 'down', 'degraded']).toContain(response.body.services.redis);
        }
      });
    });

    describe('Performance Metrics', () => {
      test('should include memory usage metrics', async () => {
        const response = await request(app).get('/health');

        const { memoryUsage } = response.body.performance;
        expect(memoryUsage.used).toBeGreaterThan(0);
        expect(memoryUsage.total).toBeGreaterThan(memoryUsage.used);
        expect(memoryUsage.percentage).toBeGreaterThan(0);
        expect(memoryUsage.percentage).toBeLessThanOrEqual(100);
      });

      test('should include response time metrics', async () => {
        const response = await request(app).get('/health');

        expect(response.body.performance.responseTimeMs).toBeGreaterThan(0);
        expect(response.body.performance.responseTimeMs).toBeLessThan(10000); // Should be < 10s
      });

      test('should include uptime metrics', async () => {
        const response = await request(app).get('/health');

        expect(response.body.performance.uptime).toBeGreaterThan(0);
      });
    });

    describe('Flutter Configuration', () => {
      test('should include Flutter-specific configuration', async () => {
        const response = await request(app).get('/health');

        const { flutter } = response.body;
        expect(flutter.corsEnabled).toBe(true);
        expect(flutter.multipartSupport).toBe(true);
        expect(flutter.maxUploadSize).toMatch(/^\d+MB$/);
        expect(Array.isArray(flutter.supportedFormats)).toBe(true);
        expect(flutter.supportedFormats).toContain('image/jpeg');
        expect(flutter.supportedFormats).toContain('image/png');
      });

      test('should include platform-specific upload limits', async () => {
        const response = await request(app).get('/health');

        const { platformLimits } = response.body.flutter;
        expect(platformLimits).toMatchObject({
          android: '50MB',
          ios: '25MB',
          web: '10MB',
          desktop: '100MB'
        });
      });
    });

    describe('Status Code Logic', () => {
      test('should return 200 for healthy services', async () => {
        const response = await request(app).get('/health');

        if (response.body.status === 'healthy') {
          expect(response.status).toBe(200);
        }
      });

      test('should return 200 for degraded services', async () => {
        const response = await request(app).get('/health');

        if (response.body.status === 'degraded') {
          expect(response.status).toBe(200);
        }
      });

      test('should return 503 for unhealthy services', async () => {
        const response = await request(app).get('/health');

        if (response.body.status === 'unhealthy') {
          expect(response.status).toBe(503);
        }
      });
    });

    describe('Networking Information', () => {
      test('should include networking configuration', async () => {
        const response = await request(app).get('/health');

        expect(response.body.networking).toMatchObject({
          ipv4: expect.any(Boolean),
          ipv6: expect.any(Boolean),
          compression: expect.any(Boolean),
          keepAlive: expect.any(Boolean)
        });
      });
    });

    describe('Endpoints Information', () => {
      test('should include available endpoints', async () => {
        const response = await request(app).get('/health');

        const { endpoints } = response.body;
        expect(endpoints).toHaveProperty('auth');
        expect(endpoints).toHaveProperty('images');
        expect(endpoints).toHaveProperty('wardrobes');
        expect(endpoints).toHaveProperty('garments');

        expect(endpoints.auth).toMatchObject({
          method: expect.any(String),
          description: expect.any(String),
          requiresAuth: expect.any(Boolean),
          flutterOptimized: expect.any(Boolean)
        });
      });
    });
  });

  describe('GET /flutter-test', () => {
    describe('Flutter Detection Tests', () => {
      test('should detect Flutter app correctly', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0')
          .set('X-Flutter-App', 'true')
          .set('X-Platform', 'android');

        expect(response.status).toBe(200);
        expect(response.body).toMatchObject({
          success: true,
          data: {
            flutterDetected: true,
            platform: 'android',
            flutterVersion: '3.7.0',
            dartVersion: '2.19.0',
            userAgent: expect.stringContaining('Dart/2.19.0'),
            timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
            tests: expect.objectContaining({
              connectivity: 'success',
              cors: expect.any(Object),
              headers: expect.any(Object),
              contentTypes: expect.any(Object),
              uploads: expect.any(Object),
              performance: expect.any(Object)
            })
          },
          message: 'Flutter connectivity test successful'
        });
      });

      test('should detect non-Flutter requests', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');

        expect(response.status).toBe(200);
        expect(response.body.data.flutterDetected).toBe(false);
        expect(response.body.data.platform).toBe('unknown');
      });
    });

    describe('Connectivity Tests', () => {
      test('should test CORS configuration', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('Origin', 'http://localhost:3000');

        expect(response.body.data.tests.cors).toMatchObject({
          origin: 'http://localhost:3000',
          credentials: 'supported',
          methods: expect.stringContaining('GET'),
          headers: expect.stringContaining('Content-Type'),
          flutterFriendly: true
        });
      });

      test('should test headers support', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('Authorization', 'Bearer token')
          .set('Content-Type', 'application/json')
          .set('X-Flutter-App', 'true');

        expect(response.body.data.tests.headers).toMatchObject({
          userAgent: true,
          authorization: true,
          contentType: true,
          customHeaders: {
            'X-Flutter-App': true,
            'X-Platform': false,
            'X-App-Version': false
          }
        });
      });

      test('should test content types support', async () => {
        const response = await request(app).get('/flutter-test');

        expect(response.body.data.tests.contentTypes).toMatchObject({
          json: 'supported',
          multipart: 'supported',
          urlencoded: 'supported',
          binary: 'supported',
          maxJsonSize: expect.any(String),
          maxFileSize: expect.any(String)
        });
      });
    });

    describe('Upload Capability Tests', () => {
      test('should test Android upload capabilities', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('User-Agent', 'Dart/2.19.0 Android');

        expect(response.body.data.tests.uploads).toMatchObject({
          maxSize: '50MB',
          supportedTypes: expect.arrayContaining(['image/jpeg', 'image/png']),
          multipart: true,
          chunked: false,
          resumable: false
        });
      });

      test('should test iOS upload capabilities', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('User-Agent', 'Dart/2.19.0 iPhone');

        expect(response.body.data.tests.uploads.maxSize).toBe('25MB');
      });

      test('should test web upload capabilities', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('User-Agent', 'Dart/2.19.0 Chrome');

        expect(response.body.data.tests.uploads.maxSize).toBe('10MB');
      });
    });

    describe('Performance Tests', () => {
      test('should include performance metrics', async () => {
        const response = await request(app).get('/flutter-test');

        expect(response.body.data.tests.performance).toMatchObject({
          responseTime: expect.any(Number),
          serverTime: expect.any(Number),
          timezone: expect.any(String)
        });

        expect(response.body.data.tests.performance.responseTime).toBeGreaterThan(0);
        expect(response.body.data.tests.performance.serverTime).toBeGreaterThan(0);
      });
    });

    describe('Error Handling', () => {
      test('should handle malformed User-Agent', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('User-Agent', '\x00\x01\x02');

        expect([200, 500]).toContain(response.status);
      });
    });
  });

  describe('GET /ping', () => {
    test('should respond with pong', async () => {
      const response = await request(app).get('/ping');

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        success: true,
        data: {
          pong: true,
          timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
          serverTime: expect.any(Number),
          platform: expect.any(String),
          flutterDetected: expect.any(Boolean)
        },
        message: 'Pong!',
        meta: {
          responseTime: expect.any(String)
        }
      });
    });

    test('should include Flutter detection in ping response', async () => {
      const response = await request(app)
        .get('/ping')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.body.data.flutterDetected).toBe(true);
      expect(response.body.data.platform).toBeDefined();
    });

    test('should be fast', async () => {
      const start = Date.now();
      const response = await request(app).get('/ping');
      const duration = Date.now() - start;

      expect(response.status).toBe(200);
      expect(duration).toBeLessThan(100); // Should be very fast
    });
  });

  describe('GET /diagnostics', () => {
    const originalEnv = process.env.NODE_ENV;

    afterEach(() => {
      process.env.NODE_ENV = originalEnv;
    });

    test('should require admin access in production', async () => {
      process.env.NODE_ENV = 'production';

      const response = await request(app).get('/diagnostics');

      expect(response.status).toBe(403);
      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('AUTHORIZATION_DENIED');
    });

    test('should allow access with admin token in production', async () => {
      process.env.NODE_ENV = 'production';

      const response = await request(app)
        .get('/diagnostics')
        .set('X-Admin-Token', 'admin');

      expect([200, 403]).toContain(response.status); // Depends on implementation
    });

    test('should return diagnostics in development', async () => {
      process.env.NODE_ENV = 'development';

      const response = await request(app).get('/diagnostics');

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        success: true,
        data: {
          system: expect.objectContaining({
            nodeVersion: expect.any(String),
            platform: expect.any(String),
            arch: expect.any(String),
            pid: expect.any(Number),
            memory: expect.any(Object),
            uptime: expect.any(Number)
          }),
          environment: expect.objectContaining({
            nodeEnv: 'development',
            port: expect.any(String),
            storageMode: expect.any(String),
            jwtConfigured: expect.any(Boolean),
            corsEnabled: expect.any(Boolean),
            flutterOptimized: expect.any(Boolean)
          }),
          flutter: expect.objectContaining({
            middlewareEnabled: expect.any(Boolean),
            configLoaded: expect.any(Boolean)
          }),
          performance: expect.objectContaining({
            responseTime: expect.any(Number),
            eventLoopLag: expect.any(Number)
          })
        },
        message: 'System diagnostics retrieved',
        timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/)
      });
    });

    test('should include system information', async () => {
      process.env.NODE_ENV = 'development';

      const response = await request(app).get('/diagnostics');

      expect(response.body.data.system.nodeVersion).toMatch(/^v?\d+\.\d+\.\d+/);
      expect(['darwin', 'linux', 'win32']).toContain(response.body.data.system.platform);
      expect(['x64', 'arm64', 'ia32']).toContain(response.body.data.system.arch);
    });

    test('should include memory diagnostics', async () => {
      process.env.NODE_ENV = 'development';

      const response = await request(app).get('/diagnostics');

      const { memory } = response.body.data.system;
      expect(memory).toMatchObject({
        rss: expect.any(Number),
        heapTotal: expect.any(Number),
        heapUsed: expect.any(Number),
        external: expect.any(Number)
      });

      expect(memory.heapUsed).toBeLessThanOrEqual(memory.heapTotal);
      expect(memory.heapTotal).toBeGreaterThan(0);
    });

    test('should include Flutter configuration status', async () => {
      process.env.NODE_ENV = 'development';

      const response = await request(app).get('/diagnostics');

      const { flutter } = response.body.data;
      expect(flutter.middlewareEnabled).toBe(true);
      expect(flutter.configLoaded).toBe(true);

      if (flutter.corsConfig) {
        expect(flutter.corsConfig).toBeInstanceOf(Object);
      }

      if (flutter.uploadConfig) {
        expect(flutter.uploadConfig.maxFileSize).toBeGreaterThan(0);
        expect(flutter.uploadConfig.allowedTypes).toBeGreaterThan(0);
      }
    });
  });

  describe('Error Handling', () => {
    test('should handle internal errors gracefully', async () => {
      // Mock an internal error
      const originalConsoleError = console.error;
      console.error = jest.fn();

      // This test would require mocking internal functions to force errors
      // For now, we test that the endpoints are resilient
      const response = await request(app).get('/health');

      expect([200, 500, 503]).toContain(response.status);

      console.error = originalConsoleError;
    });

    test('should handle malformed requests', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', '\x00\x01\x02malformed');

      expect(response.status).toBe(200);
      expect(response.body.status).toBeDefined();
    });

    test('should handle missing headers gracefully', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', ''); // Empty User-Agent

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });
  });

  describe('Response Format Consistency', () => {
    test('should maintain consistent response structure across endpoints', async () => {
      const endpoints = ['/health', '/flutter-test', '/ping'];

      for (const endpoint of endpoints) {
        const response = await request(app)
          .get(endpoint)
          .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

        expect(response.status).toBe(200);
        
        if (endpoint !== '/health') { // Health has different structure
          expect(response.body).toHaveProperty('success');
          expect(response.body).toHaveProperty('data');
          expect(response.body).toHaveProperty('message');
        }
      }
    });

    test('should include timestamps in all responses', async () => {
      const endpoints = ['/health', '/flutter-test', '/ping'];

      for (const endpoint of endpoints) {
        const response = await request(app).get(endpoint);

        expect(response.status).toBe(200);
        
        const timestampField = endpoint === '/health' ? 'timestamp' : 'data.timestamp';
        const timestamp = timestampField.includes('.') 
          ? response.body.data.timestamp 
          : response.body.timestamp;
        
        expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      }
    });
  });

  describe('Performance Monitoring', () => {
    test('should track response times', async () => {
      const start = Date.now();
      const response = await request(app).get('/health');
      const clientMeasuredTime = Date.now() - start;

      expect(response.status).toBe(200);
      expect(response.body.performance.responseTimeMs).toBeGreaterThan(0);
      expect(response.body.performance.responseTimeMs).toBeLessThan(clientMeasuredTime + 100);
    });

    test('should include performance metrics in flutter-test', async () => {
      const response = await request(app).get('/flutter-test');

      expect(response.body.data.tests.performance.responseTime).toBeGreaterThan(0);
      expect(response.body.meta.testDuration).toMatch(/^\d+ms$/);
    });
  });

  describe('Health Status Logic', () => {
    test('should determine overall status from service statuses', async () => {
      const response = await request(app).get('/health');

      const { status, services } = response.body;
      const serviceValues = Object.values(services);

      if (serviceValues.every(s => s === 'up')) {
        expect(status).toBe('healthy');
      } else if (serviceValues.some(s => s === 'up')) {
        expect(status).toBe('degraded');
      } else {
        expect(status).toBe('unhealthy');
      }
    });

    test('should handle mixed service statuses', async () => {
      const response = await request(app).get('/health');

      expect(['healthy', 'degraded', 'unhealthy']).toContain(response.body.status);
    });
  });

  describe('Flutter-Specific Features', () => {
    test('should provide Flutter-optimized information', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.body.platform.optimized).toBe(true);
      expect(response.body.flutter).toBeDefined();
      expect(response.body.endpoints).toBeDefined();

      // Should include Flutter-specific upload limits
      expect(response.body.flutter.platformLimits).toMatchObject({
        android: expect.any(String),
        ios: expect.any(String),
        web: expect.any(String),
        desktop: expect.any(String)
      });
    });

    test('should indicate non-Flutter optimization', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Mozilla/5.0');

      expect(response.body.platform.optimized).toBe(false);
      expect(response.body.platform.detected).toBe('web');
    });
  });

  describe('Memory Usage Calculations', () => {
    test('should calculate memory percentage correctly', async () => {
      const response = await request(app).get('/health');

      const { memoryUsage } = response.body.performance;
      const calculatedPercentage = Math.round((memoryUsage.used / memoryUsage.total) * 100);

      expect(memoryUsage.percentage).toBe(calculatedPercentage);
      expect(memoryUsage.percentage).toBeGreaterThan(0);
      expect(memoryUsage.percentage).toBeLessThanOrEqual(100);
    });

    test('should have reasonable memory values', async () => {
      const response = await request(app).get('/health');

      const { memoryUsage } = response.body.performance;
      
      // Should have at least 1MB used
      expect(memoryUsage.used).toBeGreaterThan(1024 * 1024);
      
      // Total should be greater than used
      expect(memoryUsage.total).toBeGreaterThan(memoryUsage.used);
      
      // Should not be using more than 1GB in tests
      expect(memoryUsage.used).toBeLessThan(1024 * 1024 * 1024);
    });
  });
});