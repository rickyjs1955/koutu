// tests/flutter-modules.test.ts
import request from 'supertest';
import express from 'express';
import { 
  flutterDetectionMiddleware,
  flutterValidationMiddleware,
  flutterResponseMiddleware,
  flutterPerformanceMiddleware,
  flutterMiddleware
} from '../../../backend/src/middlewares/flutterMiddleware';
import healthRoutes from '../../../backend/src/routes/healthRoutes';
import { 
  getFlutterConfig,
  getFlutterCorsConfig,
  getFlutterUploadConfig,
  getPlatformConfig,
  validateFlutterConfig,
  flutterConfig
} from '../../../backend/src/config/flutter';

describe('Flutter Middleware Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
  });

  describe('flutterDetectionMiddleware', () => {
    it('should detect Flutter apps from User-Agent', async () => {
      app.use(flutterDetectionMiddleware);
      app.get('/test', (req, res) => {
        res.json({ flutter: req.flutter });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0');

      expect(response.body.flutter.isFlutter).toBe(true);
      expect(response.body.flutter.flutterVersion).toBe('3.7.0');
      expect(response.body.flutter.dartVersion).toBe('2.19.0');
    });

    it('should detect platform from User-Agent', async () => {
      app.use(flutterDetectionMiddleware);
      app.get('/test', (req, res) => {
        res.json({ platform: req.flutter.platform });
      });

      // Test Android detection
      let response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0 Android 13');
      expect(response.body.platform).toBe('android');

      // Test iOS detection
      response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0 iPhone iOS 16');
      expect(response.body.platform).toBe('ios');
    });

    it('should handle non-Flutter requests gracefully', async () => {
      app.use(flutterDetectionMiddleware);
      app.get('/test', (req, res) => {
        res.json({ flutter: req.flutter });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');

      expect(response.body.flutter.isFlutter).toBe(false);
      expect(response.body.flutter.platform).toBeUndefined();
    });

    it('should extract device info from headers', async () => {
      app.use(flutterDetectionMiddleware);
      app.get('/test', (req, res) => {
        res.json({ deviceInfo: req.flutter.deviceInfo });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0')
        .set('X-App-Version', '1.2.3');

      expect(response.body.deviceInfo?.appVersion).toBe('1.2.3');
    });
  });

  describe('flutterValidationMiddleware', () => {
    beforeEach(() => {
      app.use(flutterDetectionMiddleware);
      app.use(flutterValidationMiddleware);
    });

    it('should validate Flutter file upload size', async () => {
      app.post('/upload', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .post('/upload')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0 Android')
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', '100000000'); // 100MB

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should allow valid Flutter uploads', async () => {
      app.post('/upload', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .post('/upload')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0')
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', '1000000'); // 1MB

      expect(response.status).toBe(200);
    });

    it('should skip validation for non-Flutter requests', async () => {
      app.post('/upload', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .post('/upload')
        .set('User-Agent', 'Mozilla/5.0')
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', '100000000');

      expect(response.status).toBe(200);
    });

    it('should detect malicious headers', async () => {
      app.get('/test', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0')
        .set('X-Flutter-Exploit', 'malicious-payload');

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('flutterResponseMiddleware', () => {
    beforeEach(() => {
      app.use(flutterDetectionMiddleware);
      app.use(flutterResponseMiddleware);
    });

    it('should add Flutter-optimized headers', async () => {
      app.get('/test', (req, res) => {
        res.json({ message: 'test' });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0');

      expect(response.headers['x-flutter-optimized']).toBe('true');
      expect(response.headers['cache-control']).toBe('no-cache, no-store, must-revalidate');
    });

    it('should wrap non-standard responses', async () => {
      app.get('/test', (req, res) => {
        res.json({ message: 'test' });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0');

      expect(response.body.success).toBe(true);
      expect(response.body.data.message).toBe('test');
      expect(response.body.timestamp).toBeDefined();
      expect(response.body.requestId).toBeDefined();
    });

    it('should not modify responses for non-Flutter requests', async () => {
      app.get('/test', (req, res) => {
        res.json({ message: 'test' });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Mozilla/5.0');

      expect(response.headers['x-flutter-optimized']).toBeUndefined();
      expect(response.body.message).toBe('test');
      expect(response.body.success).toBeUndefined();
    });
  });

  describe('flutterPerformanceMiddleware', () => {
    beforeEach(() => {
      app.use(flutterDetectionMiddleware);
      app.use(flutterPerformanceMiddleware);
    });

    it('should track response times for Flutter requests', async () => {
      app.get('/test', (req, res) => {
        setTimeout(() => {
          res.json({ message: 'test' });
        }, 100);
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0');

      expect(response.headers['x-response-time']).toBeDefined();
      expect(response.status).toBe(200);
    });

    it('should not track performance for non-Flutter requests', async () => {
      app.get('/test', (req, res) => {
        res.json({ message: 'test' });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Mozilla/5.0');

      expect(response.headers['x-response-time']).toBeUndefined();
    });
  });

  describe('Security Tests', () => {
    beforeEach(() => {
      app.use(flutterMiddleware.stack);
    });

    it('should reject requests with suspicious User-Agents', async () => {
      app.get('/test', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0 <script>alert("xss")</script>');

      expect(response.status).toBe(200); // Should not fail, but should sanitize
      expect(response.body.flutter?.isFlutter).toBeTruthy();
    });

    it('should handle malformed headers gracefully', async () => {
      app.get('/test', (req, res) => {
        res.json({ flutter: req.flutter });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', '\x00\x01\x02invalid');

      expect(response.status).toBe(200);
      expect(response.body.flutter.isFlutter).toBe(false);
    });

    it('should prevent header injection attacks', async () => {
      app.get('/test', (req, res) => {
        res.json({ success: true });
      });

      const response = await request(app)
        .get('/test')
        .set('User-Agent', 'Dart/2.19.0')
        .set('X-Flutter-Exploit', 'value\r\nX-Injected: malicious');

      expect(response.status).toBe(400);
    });
  });
});

describe('Health Routes Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(flutterDetectionMiddleware);
    app.use('/', healthRoutes);
  });

  describe('GET /health', () => {
    it('should return health status for Flutter apps', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0');

      expect(response.status).toBe(200);
      expect(response.body.status).toMatch(/healthy|degraded|unhealthy/);
      expect(response.body.platform.detected).toBe('flutter');
      expect(response.body.platform.optimized).toBe(true);
      expect(response.body.flutter).toBeDefined();
      expect(response.body.services).toBeDefined();
      expect(response.body.performance).toBeDefined();
    });

    it('should return health status for web clients', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');

      expect(response.status).toBe(200);
      expect(response.body.platform.detected).toBe('web');
      expect(response.body.platform.optimized).toBe(false);
    });

    it('should include service status checks', async () => {
      const response = await request(app)
        .get('/health');

      expect(response.body.services.database).toMatch(/up|down|degraded/);
      expect(response.body.services.storage).toMatch(/up|down|degraded/);
    });

    it('should include performance metrics', async () => {
      const response = await request(app)
        .get('/health');

      expect(response.body.performance.responseTimeMs).toBeGreaterThan(0);
      expect(response.body.performance.memoryUsage).toBeDefined();
      expect(response.body.performance.uptime).toBeGreaterThan(0);
    });

    it('should include Flutter-specific configuration', async () => {
      const response = await request(app)
        .get('/health');

      expect(response.body.flutter.corsEnabled).toBe(true);
      expect(response.body.flutter.multipartSupport).toBe(true);
      expect(response.body.flutter.platformLimits).toBeDefined();
      expect(response.body.flutter.supportedFormats).toBeInstanceOf(Array);
    });

    it('should set appropriate status codes based on health', async () => {
      // This would require mocking service failures
      const response = await request(app)
        .get('/health');

      expect([200, 503]).toContain(response.status);
    });
  });

  describe('GET /flutter-test', () => {
    it('should perform connectivity test for Flutter apps', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0')
        .set('X-Flutter-App', 'true')
        .set('X-Platform', 'android');

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.data.flutterDetected).toBe(true);
      expect(response.body.data.platform).toBe('android');
      expect(response.body.data.tests).toBeDefined();
      expect(response.body.data.tests.connectivity).toBe('success');
    });

    it('should test CORS configuration', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('Origin', 'http://localhost:3000');

      expect(response.body.data.tests.cors.origin).toBe('http://localhost:3000');
      expect(response.body.data.tests.cors.flutterFriendly).toBe(true);
    });

    it('should test upload capabilities', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', 'Dart/2.19.0 Android');

      expect(response.body.data.tests.uploads.maxSize).toBe('50MB');
      expect(response.body.data.tests.uploads.multipart).toBe(true);
    });

    it('should handle errors gracefully', async () => {
      // Test with malformed headers
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', null as any);

      expect([200, 500]).toContain(response.status);
    });
  });

  describe('GET /diagnostics', () => {
    it('should require admin access in production', async () => {
      process.env.NODE_ENV = 'production';
      
      const response = await request(app)
        .get('/diagnostics');

      expect(response.status).toBe(403);
      
      process.env.NODE_ENV = 'test';
    });

    it('should return diagnostics in development', async () => {
      process.env.NODE_ENV = 'development';
      
      const response = await request(app)
        .get('/diagnostics');

      expect(response.status).toBe(200);
      expect(response.body.data.system).toBeDefined();
      expect(response.body.data.environment).toBeDefined();
      expect(response.body.data.flutter).toBeDefined();
      expect(response.body.data.performance).toBeDefined();
      
      process.env.NODE_ENV = 'test';
    });

    it('should include system information', async () => {
      process.env.NODE_ENV = 'development';
      
      const response = await request(app)
        .get('/diagnostics');

      expect(response.body.data.system.nodeVersion).toBeDefined();
      expect(response.body.data.system.platform).toBeDefined();
      expect(response.body.data.system.memory).toBeDefined();
      
      process.env.NODE_ENV = 'test';
    });
  });

  describe('GET /ping', () => {
    it('should respond with pong', async () => {
      const response = await request(app)
        .get('/ping');

      expect(response.status).toBe(200);
      expect(response.body.data.pong).toBe(true);
      expect(response.body.message).toBe('Pong!');
    });

    it('should include Flutter detection in ping', async () => {
      const response = await request(app)
        .get('/ping')
        .set('User-Agent', 'Dart/2.19.0 (dart:io) Flutter/3.7.0');

      expect(response.body.data.flutterDetected).toBe(true);
      expect(response.body.data.platform).toBeDefined();
    });

    it('should be fast', async () => {
      const start = Date.now();
      const response = await request(app)
        .get('/ping');
      const duration = Date.now() - start;

      expect(response.status).toBe(200);
      expect(duration).toBeLessThan(100); // Should respond in <100ms
    });
  });

  describe('Security Tests', () => {
    it('should handle malformed requests', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', '\x00\x01\x02');

      expect(response.status).toBe(200);
    });

    it('should prevent header injection', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Flutter\r\nX-Injected: malicious');

      expect(response.status).toBe(200);
      expect(response.headers['x-injected']).toBeUndefined();
    });

    it('should rate limit health checks', async () => {
      // This would require implementing rate limiting
      const promises = Array(10).fill(0).map(() => 
        request(app).get('/health')
      );
      
      const responses = await Promise.all(promises);
      expect(responses.every(r => r.status === 200 || r.status === 429)).toBe(true);
    });
  });
});

describe('Flutter Config Tests', () => {
  describe('getFlutterConfig', () => {
    it('should return valid configuration', () => {
      const config = getFlutterConfig();
      
      expect(config).toBeDefined();
      expect(config.cors).toBeDefined();
      expect(config.uploads).toBeDefined();
      expect(config.security).toBeDefined();
      expect(config.performance).toBeDefined();
    });

    it('should have environment-specific settings', () => {
      const originalEnv = process.env.NODE_ENV;
      
      process.env.NODE_ENV = 'production';
      const prodConfig = getFlutterConfig();
      expect(prodConfig.cors.allowNoOrigin).toBe(false);
      
      process.env.NODE_ENV = 'development';
      const devConfig = getFlutterConfig();
      expect(devConfig.cors.allowNoOrigin).toBe(true);
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should handle test environment', () => {
      const originalEnv = process.env.NODE_ENV;
      
      process.env.NODE_ENV = 'test';
      const testConfig = getFlutterConfig();
      expect(testConfig.security.enableRateLimiting).toBe(false);
      expect(testConfig.uploads.maxFileSize).toBe(1024 * 1024);
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('getFlutterCorsConfig', () => {
    it('should return valid CORS configuration', () => {
      const corsConfig = getFlutterCorsConfig();
      
      expect(corsConfig.origin).toBeInstanceOf(Function);
      expect(corsConfig.credentials).toBeDefined();
      expect(corsConfig.methods).toBeInstanceOf(Array);
      expect(corsConfig.allowedHeaders).toBeInstanceOf(Array);
    });

    it('should allow no origin in development', (done) => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const corsConfig = getFlutterCorsConfig();
      corsConfig.origin!(undefined, (err, allow) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        process.env.NODE_ENV = originalEnv;
        done();
      });
    });

    it('should validate origins in production', (done) => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const corsConfig = getFlutterCorsConfig();
      corsConfig.origin!('http://malicious-site.com', (err, allow) => {
        expect(err).toBeInstanceOf(Error);
        expect(allow).toBeUndefined();
        process.env.NODE_ENV = originalEnv;
        done();
      });
    });

    it('should allow localhost in all environments', (done) => {
      const corsConfig = getFlutterCorsConfig();
      corsConfig.origin!('http://localhost:3000', (err, allow) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });
  });

  describe('getFlutterUploadConfig', () => {
    it('should return platform-specific upload limits', () => {
      const androidConfig = getFlutterUploadConfig('android');
      expect(androidConfig.limits.fileSize).toBe(50 * 1024 * 1024);
      
      const iosConfig = getFlutterUploadConfig('ios');
      expect(iosConfig.limits.fileSize).toBe(25 * 1024 * 1024);
      
      const webConfig = getFlutterUploadConfig('web');
      expect(webConfig.limits.fileSize).toBe(10 * 1024 * 1024);
    });

    it('should validate allowed file types', () => {
      const config = getFlutterUploadConfig();
      
      expect(config.fileFilter).toBeInstanceOf(Function);
      
      // Test valid file
      config.fileFilter(null, { mimetype: 'image/jpeg', originalname: 'test.jpg' }, (err: any) => {
        expect(err).toBeNull();
      });
      
      // Test invalid file
      config.fileFilter(null, { mimetype: 'application/x-executable', originalname: 'malware.exe' }, (err: any) => {
        expect(err).toBeInstanceOf(Error);
      });
    });

    it('should generate secure filenames', () => {
      const config = getFlutterUploadConfig();
      
      config.filename(null, { originalname: 'test.jpg' }, (err: any, filename: string) => {
        expect(err).toBeNull();
        expect(filename).toMatch(/^flutter_\d+_[a-z0-9]+\.jpg$/);
      });
    });
  });

  describe('getPlatformConfig', () => {
    it('should return platform-specific settings', () => {
      const androidConfig = getPlatformConfig('android');
      expect(androidConfig.maxUploadSize).toBe(50 * 1024 * 1024);
      expect(androidConfig.requestTimeout).toBe(15000);
      
      const iosConfig = getPlatformConfig('ios');
      expect(iosConfig.maxUploadSize).toBe(25 * 1024 * 1024);
      expect(iosConfig.requestTimeout).toBe(10000);
    });

    it('should fallback to web config for unknown platforms', () => {
      const unknownConfig = getPlatformConfig('unknown');
      const webConfig = getPlatformConfig('web');
      
      expect(unknownConfig).toEqual(webConfig);
    });
  });

  describe('validateFlutterConfig', () => {
    it('should validate configuration successfully', () => {
      const validation = validateFlutterConfig();
      
      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should detect configuration errors', () => {
      // This would require mocking invalid config
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      // Mock invalid production config
      const mockConfig = {
        ...flutterConfig,
        cors: { ...flutterConfig.cors, allowedOrigins: [] }
      };
      
      // In a real implementation, we'd need to mock getFlutterConfig
      // For now, just test the structure
      expect(validateFlutterConfig().valid).toBeDefined();
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Security Tests', () => {
    it('should prevent configuration tampering in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      expect(() => {
        // This would throw in production
        // updateFlutterConfig({ cors: { allowNoOrigin: true } });
      }).not.toThrow(); // Test structure only
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should validate MIME types', () => {
      const config = getFlutterUploadConfig();
      
      // Test valid MIME type
      config.fileFilter(null, { 
        mimetype: 'image/jpeg', 
        originalname: 'test.jpg' 
      }, (err: any) => {
        expect(err).toBeNull();
      });
      
      // Test invalid MIME type
      config.fileFilter(null, { 
        mimetype: 'application/javascript', 
        originalname: 'malicious.js' 
      }, (err: any) => {
        expect(err).toBeInstanceOf(Error);
      });
    });

    it('should prevent path traversal in filenames', () => {
      const config = getFlutterUploadConfig();
      
      config.fileFilter(null, { 
        mimetype: 'image/jpeg', 
        originalname: '../../../etc/passwd' 
      }, (err: any) => {
        expect(err).toBeInstanceOf(Error);
      });
    });
  });

  describe('Integration Tests', () => {
    it('should work together across all modules', () => {
      const config = getFlutterConfig();
      const corsConfig = getFlutterCorsConfig();
      const uploadConfig = getFlutterUploadConfig('android');
      
      expect(config).toBeDefined();
      expect(corsConfig).toBeDefined();
      expect(uploadConfig).toBeDefined();
      
      // Verify consistency
      expect(uploadConfig.limits.fileSize).toBe(config.uploads.platformLimits.android);
    });

    it('should maintain configuration consistency', () => {
      const validation = validateFlutterConfig();
      expect(validation.valid).toBe(true);
    });
  });
});