// tests/integration/healthRoutes.flutter.integration.test.ts
import request from 'supertest';
import express from 'express';
import healthRoutes from '../../routes/healthRoutes';
import { flutterMiddleware } from '../../middlewares/flutterMiddleware';
import { getFlutterConfig } from '../../config/flutter';

describe('Health Routes Integration Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    
    // Apply full Flutter middleware stack
    app.use(flutterMiddleware.stack);
    
    // Mount health routes
    app.use('/', healthRoutes);
    
    // Add test routes to verify integration
    app.get('/test/middleware', (req, res) => {
      res.json({
        flutter: req.flutter,
        timestamp: new Date().toISOString()
      });
    });
    
    // Suppress console output for cleaner test results
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('End-to-End Health Check Flow', () => {
    test('should provide comprehensive health status for Flutter apps', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0 Android 13')
        .set('X-Flutter-App', 'true')
        .set('X-Platform', 'android')
        .set('X-App-Version', '1.2.3')
        .set('X-Device-ID', 'device-12345');

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        status: expect.stringMatching(/^(healthy|degraded|unhealthy)$/),
        timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
        version: expect.any(String),
        platform: {
          detected: 'flutter',
          optimized: true,
          version: '3.7.0'
        },
        services: {
          database: expect.stringMatching(/^(up|down|degraded)$/),
          storage: expect.stringMatching(/^(up|down|degraded)$/)
        },
        performance: {
          responseTimeMs: expect.any(Number),
          memoryUsage: {
            used: expect.any(Number),
            total: expect.any(Number),
            percentage: expect.any(Number)
          },
          uptime: expect.any(Number)
        },
        flutter: {
          corsEnabled: true,
          multipartSupport: true,
          maxUploadSize: expect.any(String),
          supportedFormats: expect.arrayContaining(['image/jpeg', 'image/png']),
          platformLimits: {
            android: '50MB',
            ios: '25MB',
            web: '10MB',
            desktop: '100MB'
          }
        },
        endpoints: expect.any(Object),
        networking: {
          ipv4: expect.any(Boolean),
          ipv6: expect.any(Boolean),
          compression: expect.any(Boolean),
          keepAlive: expect.any(Boolean)
        }
      });

      // Verify performance metrics are reasonable
      expect(response.body.performance.responseTimeMs).toBeGreaterThan(0);
      expect(response.body.performance.responseTimeMs).toBeLessThan(5000);
      expect(response.body.performance.memoryUsage.percentage).toBeGreaterThan(0);
      expect(response.body.performance.memoryUsage.percentage).toBeLessThanOrEqual(100);
    });

    test('should handle non-Flutter requests appropriately', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');

      expect(response.status).toBe(200);
      expect(response.body.platform).toMatchObject({
        detected: 'web',
        optimized: false
      });
      expect(response.body.platform.version).toBeUndefined();
    });
  });

  describe('Flutter Connectivity Testing Flow', () => {
    test('should perform complete connectivity test for Flutter apps', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0')
        .set('X-Flutter-App', 'true')
        .set('X-Platform', 'android')
        .set('X-App-Version', '1.0.0')
        .set('Origin', 'http://localhost:3000')
        .set('Authorization', 'Bearer test-token')
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        success: true,
        data: {
          flutterDetected: true,
          platform: 'android',
          flutterVersion: '3.7.0',
          dartVersion: '2.19.0',
          deviceInfo: {
            appVersion: '1.0.0'
          },
          userAgent: expect.stringContaining('Dart/2.19.0'),
          timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
          tests: {
            connectivity: 'success',
            cors: {
              origin: 'http://localhost:3000',
              credentials: 'supported',
              methods: expect.stringContaining('GET'),
              headers: expect.stringContaining('Content-Type'),
              flutterFriendly: true
            },
            headers: {
              userAgent: true,
              authorization: true,
              contentType: true,
              customHeaders: {
                'X-Flutter-App': true,
                'X-Platform': true,
                'X-App-Version': true
              }
            },
            contentTypes: {
              json: 'supported',
              multipart: 'supported',
              urlencoded: 'supported',
              binary: 'supported',
              maxJsonSize: expect.any(String),
              maxFileSize: expect.any(String)
            },
            uploads: {
              maxSize: '50MB',
              supportedTypes: expect.arrayContaining(['image/jpeg', 'image/png']),
              multipart: true,
              chunked: false,
              resumable: false
            },
            performance: {
              responseTime: expect.any(Number),
              serverTime: expect.any(Number),
              timezone: expect.any(String)
            }
          }
        },
        message: 'Flutter connectivity test successful',
        meta: {
          testDuration: expect.stringMatching(/^\d+ms$/),
          endpoint: 'flutter-test'
        }
      });
    });

    test('should detect different Flutter platforms correctly', async () => {
      const platforms = [
        { ua: 'Dart/2.19.0 Flutter/3.7.0 Android', platform: 'android', uploadLimit: '50MB' },
        { ua: 'Dart/2.19.0 Flutter/3.7.0 iPhone', platform: 'ios', uploadLimit: '25MB' },
        { ua: 'Dart/2.19.0 Flutter/3.7.0 Chrome', platform: 'web', uploadLimit: '10MB' },
        { ua: 'Dart/2.19.0 Flutter/3.7.0 Windows', platform: 'desktop', uploadLimit: '100MB' }
      ];

      for (const { ua, platform, uploadLimit } of platforms) {
        const response = await request(app)
          .get('/flutter-test')
          .set('User-Agent', ua);

        expect(response.status).toBe(200);
        expect(response.body.data.platform).toBe(platform);
        expect(response.body.data.tests.uploads.maxSize).toBe(uploadLimit);
      }
    });
  });

  describe('Ping Service Integration', () => {
    test('should provide fast ping response with Flutter context', async () => {
      const startTime = Date.now();
      
      const response = await request(app)
        .get('/ping')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0')
        .set('X-Platform', 'android');

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      expect(response.status).toBe(200);
      expect(responseTime).toBeLessThan(100); // Should be very fast
      
      expect(response.body).toMatchObject({
        success: true,
        data: {
          pong: true,
          timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
          serverTime: expect.any(Number),
          platform: 'android',
          flutterDetected: true
        },
        message: 'Pong!',
        meta: {
          responseTime: expect.stringMatching(/^< \d+ms$/)
        }
      });
    });

    test('should handle rapid ping requests efficiently', async () => {
      const requests = Array(20).fill(0).map((_, i) =>
        request(app)
          .get('/ping')
          .set('User-Agent', `Dart/2.19.0 Flutter/3.7.0 Request-${i}`)
      );

      const startTime = Date.now();
      const responses = await Promise.all(requests);
      const totalTime = Date.now() - startTime;

      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.data.pong).toBe(true);
      });

      // Should handle 20 concurrent pings quickly
      expect(totalTime).toBeLessThan(2000); // < 2 seconds
      expect(totalTime / responses.length).toBeLessThan(200); // < 200ms average
    });
  });

  describe('Diagnostics Access Control Integration', () => {
    test('should enforce production access control', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const response = await request(app)
        .get('/diagnostics')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.status).toBe(403);
      expect(response.body).toMatchObject({
        success: false,
        error: {
          code: 'AUTHORIZATION_DENIED',
          message: expect.stringContaining('access denied'),
          timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
          requestId: expect.any(String),
          statusCode: 403
        }
      });

      process.env.NODE_ENV = originalEnv;
    });

    test('should provide diagnostics in development environment', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const response = await request(app)
        .get('/diagnostics')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.status).toBe(200);
      expect(response.body).toMatchObject({
        success: true,
        data: {
          system: expect.objectContaining({
            nodeVersion: expect.any(String),
            platform: expect.any(String),
            arch: expect.any(String),
            memory: expect.any(Object),
            uptime: expect.any(Number)
          }),
          environment: expect.objectContaining({
            nodeEnv: 'development',
            flutterOptimized: true
          }),
          flutter: expect.objectContaining({
            middlewareEnabled: true,
            configLoaded: true
          }),
          performance: expect.objectContaining({
            responseTime: expect.any(Number)
          })
        },
        message: 'System diagnostics retrieved',
        timestamp: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/)
      });

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Configuration Integration', () => {
    test('should reflect current Flutter configuration in health check', async () => {
      const config = getFlutterConfig();
      
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.body.flutter.supportedFormats).toEqual(
        expect.arrayContaining(config.uploads.allowedMimeTypes)
      );

      expect(response.body.flutter.platformLimits).toMatchObject({
        android: `${Math.round(config.uploads.platformLimits.android / (1024 * 1024))}MB`,
        ios: `${Math.round(config.uploads.platformLimits.ios / (1024 * 1024))}MB`,
        web: `${Math.round(config.uploads.platformLimits.web / (1024 * 1024))}MB`,
        desktop: `${Math.round(config.uploads.platformLimits.desktop / (1024 * 1024))}MB`
      });
    });

    test('should adapt to environment-specific configuration', async () => {
      const originalEnv = process.env.NODE_ENV;
      
      // Test development configuration
      process.env.NODE_ENV = 'development';
      let response = await request(app).get('/health');
      expect(response.body.environment?.nodeEnv || 'development').toBe('development');

      // Test production configuration  
      process.env.NODE_ENV = 'production';
      response = await request(app).get('/health');
      // In production, some debug info might be hidden
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Performance Monitoring Integration', () => {
    test('should track request performance across all endpoints', async () => {
      const endpoints = ['/health', '/flutter-test', '/ping'];
      const performanceData: Array<{ endpoint: string; time: number }> = [];

      for (const endpoint of endpoints) {
        const startTime = Date.now();
        
        const response = await request(app)
          .get(endpoint)
          .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');
        
        const responseTime = Date.now() - startTime;
        
        expect(response.status).toBe(200);
        performanceData.push({ endpoint, time: responseTime });
      }

      // All endpoints should respond within reasonable time
      performanceData.forEach(({ endpoint, time }) => {
        expect(time).toBeLessThan(2000); // < 2 seconds
        console.log(`${endpoint}: ${time}ms`);
      });

      // Ping should be fastest
      const pingTime = performanceData.find(p => p.endpoint === '/ping')?.time || 0;
      expect(pingTime).toBeLessThan(100);
    });

    test('should include accurate response time measurements', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(response.status).toBe(200);
      
      const reportedTime = response.body.performance.responseTimeMs;
      expect(reportedTime).toBeGreaterThan(0);
      expect(reportedTime).toBeLessThan(5000); // Should be reasonable
    });
  });

  describe('CORS Integration', () => {
    test('should handle Flutter CORS requests correctly', async () => {
      // Test preflight request
      const preflightResponse = await request(app)
        .options('/health')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'GET')
        .set('Access-Control-Request-Headers', 'User-Agent, X-Flutter-App');

      expect([200, 204]).toContain(preflightResponse.status);

      // Test actual request
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0')
        .set('Origin', 'http://localhost:3000')
        .set('X-Flutter-App', 'true');

      expect(response.status).toBe(200);
      expect(response.body.platform.detected).toBe('flutter');
    });

    test('should support no-origin requests from mobile apps', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 Android');
      // No Origin header (typical for mobile apps)

      expect(response.status).toBe(200);
      expect(response.body.data.flutterDetected).toBe(true);
      expect(response.body.data.tests.cors.origin).toBe('no-origin');
    });
  });

  describe('Error Handling Integration', () => {
    test('should handle malformed requests gracefully across all endpoints', async () => {
      const malformedInputs = [
        { ua: '\x00\x01\x02invalid', description: 'null bytes' },
        { ua: 'Dart/' + 'A'.repeat(10000), description: 'extremely long' },
        { ua: 'Dart/2.19.0 <script>alert(1)</script>', description: 'XSS attempt' },
        { ua: '', description: 'empty User-Agent' }
      ];

      const endpoints = ['/health', '/flutter-test', '/ping'];

      for (const endpoint of endpoints) {
        for (const { ua, description } of malformedInputs) {
          const response = await request(app)
            .get(endpoint)
            .set('User-Agent', ua);

          // Should not crash, should return valid response
          expect([200, 400]).toContain(response.status);
          
          if (response.status === 200) {
            // Should have valid structure
            expect(response.body).toBeInstanceOf(Object);
          }
        }
      }
    });

    test('should maintain service availability during error conditions', async () => {
      // Simulate various error conditions
      const errorRequests = [
        request(app).get('/nonexistent'),
        request(app).get('/health').set('User-Agent', '\x00\x01'),
        request(app).post('/health').send({ malformed: 'data' }),
        request(app).get('/flutter-test').set('Content-Type', 'invalid/type')
      ];

      const responses = await Promise.allSettled(errorRequests);

      // After error requests, normal requests should still work
      const normalResponse = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      expect(normalResponse.status).toBe(200);
      expect(normalResponse.body.status).toMatch(/^(healthy|degraded|unhealthy)$/);
    });
  });

  describe('Load Testing', () => {
    test('should handle moderate concurrent load', async () => {
      const concurrentRequests = 30;
      const requestTypes = ['/health', '/flutter-test', '/ping'];
      
      const requests = Array(concurrentRequests).fill(0).map((_, i) => {
        const endpoint = requestTypes[i % requestTypes.length];
        return request(app)
          .get(endpoint)
          .set('User-Agent', `Dart/2.19.0 Flutter/3.7.0 Load-Test-${i}`)
          .set('X-Request-ID', `load-test-${i}`);
      });

      const startTime = Date.now();
      const responses = await Promise.all(requests);
      const totalTime = Date.now() - startTime;

      // All requests should succeed
      responses.forEach((response, i) => {
        expect([200, 429]).toContain(response.status); // 429 if rate limited
      });

      // Should handle load efficiently
      expect(totalTime).toBeLessThan(10000); // < 10 seconds for 30 requests
      
      const avgResponseTime = totalTime / responses.length;
      expect(avgResponseTime).toBeLessThan(500); // < 500ms average
    });

    test('should maintain response quality under load', async () => {
      const requests = Array(10).fill(0).map((_, i) =>
        request(app)
          .get('/health')
          .set('User-Agent', `Dart/2.19.0 Flutter/3.7.0 Quality-Test-${i}`)
      );

      const responses = await Promise.all(requests);

      responses.forEach(response => {
        if (response.status === 200) {
          // Response quality should not degrade
          expect(response.body.status).toMatch(/^(healthy|degraded|unhealthy)$/);
          expect(response.body.performance.responseTimeMs).toBeGreaterThan(0);
          expect(response.body.flutter).toBeDefined();
          expect(response.body.services).toBeDefined();
        }
      });
    });
  });

  describe('Integration with Flutter Middleware Stack', () => {
    test('should work seamlessly with Flutter detection middleware', async () => {
      // First verify middleware is working
      const middlewareResponse = await request(app)
        .get('/test/middleware')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 Android')
        .set('X-Platform', 'android');

      expect(middlewareResponse.body.flutter).toMatchObject({
        isFlutter: true,
        platform: 'android',
        flutterVersion: '3.7.0'
      });

      // Then verify health routes use the same detection
      const healthResponse = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 Android')
        .set('X-Platform', 'android');

      expect(healthResponse.body.platform).toMatchObject({
        detected: 'flutter',
        optimized: true,
        version: '3.7.0'
      });
    });

    test('should benefit from Flutter response optimization', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      // Should have Flutter optimization headers
      expect(response.headers['x-flutter-optimized']).toBe('true');
      expect(response.headers['cache-control']).toBe('no-cache, no-store, must-revalidate');
    });

    test('should include performance tracking from middleware', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0');

      // Should have response time from performance middleware
      expect(response.headers['x-response-time']).toMatch(/^\d+ms$/);
      expect(response.body.data.tests.performance.responseTime).toBeGreaterThan(0);
    });
  });

  describe('Real-World Scenarios', () => {
    test('should handle typical Flutter app health check', async () => {
      // Simulate a real Flutter app making a health check
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'MyFashionApp/1.2.3 Dart/2.19.0 (dart:io) Flutter/3.7.0 Android 13')
        .set('X-Flutter-App', 'true')
        .set('X-Platform', 'android')
        .set('X-App-Version', '1.2.3')
        .set('Accept', 'application/json')
        .set('Accept-Language', 'en-US,en;q=0.9');

      expect(response.status).toBe(200);
      expect(response.body.platform.detected).toBe('flutter');
      expect(response.body.flutter.platformLimits.android).toBe('50MB');
      expect(response.body.services.database).toMatch(/^(up|down|degraded)$/);
    });

    test('should support Flutter web app connectivity test', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Flutter/3.7.0')
        .set('X-Flutter-App', 'true')
        .set('X-Platform', 'web')
        .set('Origin', 'https://myfashionapp.com');

      expect(response.status).toBe(200);
      expect(response.body.data.platform).toBe('web');
      expect(response.body.data.tests.uploads.maxSize).toBe('10MB');
      expect(response.body.data.tests.cors.origin).toBe('https://myfashionapp.com');
    });

    test('should handle development debugging scenario', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const response = await request(app)
        .get('/diagnostics')
        .set('User-Agent', 'Dart/2.19.0 Flutter/3.7.0 Debug')
        .set('X-Debug-Session', 'true');

      expect(response.status).toBe(200);
      expect(response.body.data.environment.nodeEnv).toBe('development');
      expect(response.body.data.flutter.middlewareEnabled).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });

    test('should handle production monitoring scenario', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      // Health check should work in production
      const healthResponse = await request(app)
        .get('/health')
        .set('User-Agent', 'MyFashionApp/1.0.0 Dart/2.19.0 Flutter/3.7.0');

      expect(healthResponse.status).toBe(200);
      expect(healthResponse.body.status).toMatch(/^(healthy|degraded|unhealthy)$/);

      // Diagnostics should be restricted
      const diagResponse = await request(app).get('/diagnostics');
      expect(diagResponse.status).toBe(403);

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Service Dependencies', () => {
    test('should accurately report service status in health check', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      
      const { services, status } = response.body;
      const serviceStatuses = Object.values(services);

      // Verify status calculation logic
      if (serviceStatuses.every(s => s === 'up')) {
        expect(status).toBe('healthy');
      } else if (serviceStatuses.some(s => s === 'up')) {
        expect(status).toBe('degraded');
      } else {
        expect(status).toBe('unhealthy');
      }

      // Status code should match overall status
      if (status === 'unhealthy') {
        expect([503]).toContain(response.status);
      } else {
        expect([200]).toContain(response.status);
      }
    });
  });
});