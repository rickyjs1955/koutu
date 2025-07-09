// backend/src/config/__tests__/flutter.int.test.ts
import request from 'supertest';
import express, { Express } from 'express';
import cors from 'cors';
import multer from 'multer';
import { createRateLimiter, createTestRateLimiter } from '../__helpers__/ratelimit.helper';
import {
  getFlutterConfig,
  getFlutterCorsConfig,
  getFlutterUploadConfig,
  getPlatformConfig,
  validateFlutterConfig
} from '../../config/flutter';

describe('Flutter Configuration Integration Tests', () => {
  let app: Express;
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
    app = express();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('CORS Integration', () => {
    beforeEach(() => {
      const corsConfig = getFlutterCorsConfig();
      app.use(cors(corsConfig));
      app.get('/test', (req, res) => {
        res.json({ message: 'success' });
      });
    });

    it('should handle valid CORS requests in development', async () => {
      process.env.NODE_ENV = 'development';
      
      const response = await request(app)
        .get('/test')
        .set('Origin', 'http://localhost:3000')
        .expect(200);

      expect(response.headers['access-control-allow-origin']).toBe('http://localhost:3000');
      expect(response.headers['access-control-allow-credentials']).toBe('true');
    });

    it('should handle preflight requests correctly', async () => {
      process.env.NODE_ENV = 'development';
      
      const response = await request(app)
        .options('/test')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type,X-Flutter-App')
        .expect(204);

      expect(response.headers['access-control-allow-methods']).toContain('POST');
      expect(response.headers['access-control-allow-headers']).toContain('Content-Type');
      expect(response.headers['access-control-allow-headers']).toContain('X-Flutter-App');
    });

    it('should reject invalid origins in production', async () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_ORIGINS = 'https://example.com';
      
      // Recreate app with production config
      app = express();
      const corsConfig = getFlutterCorsConfig();
      app.use(cors(corsConfig));
      app.get('/test', (req, res) => {
        res.json({ message: 'success' });
      });

      await request(app)
        .get('/test')
        .set('Origin', 'https://malicious.com')
        .expect(500); // CORS error
    });

    it('should allow configured origins in production', async () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_ORIGINS = 'https://example.com,https://app.example.com';
      
      // Recreate app with production config
      app = express();
      const corsConfig = getFlutterCorsConfig();
      app.use(cors(corsConfig));
      app.get('/test', (req, res) => {
        res.json({ message: 'success' });
      });

      const response = await request(app)
        .get('/test')
        .set('Origin', 'https://example.com')
        .expect(200);

      expect(response.headers['access-control-allow-origin']).toBe('https://example.com');
    });

    it('should handle Flutter-specific headers', async () => {
      process.env.NODE_ENV = 'development';
      
      const response = await request(app)
        .options('/test')
        .set('Origin', 'http://localhost:3000')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'X-Flutter-App,X-Platform,X-Device-ID')
        .expect(204);

      const allowedHeaders = response.headers['access-control-allow-headers'];
      expect(allowedHeaders).toContain('X-Flutter-App');
      expect(allowedHeaders).toContain('X-Platform');
      expect(allowedHeaders).toContain('X-Device-ID');
    });

    it('should expose Flutter-optimized headers', async () => {
      process.env.NODE_ENV = 'development';
      
      app.get('/test-headers', (req, res) => {
        res.set('X-Flutter-Optimized', 'true');
        res.set('X-Response-Time', '123ms');
        res.set('X-Request-ID', 'test-123');
        res.json({ message: 'success' });
      });

      const response = await request(app)
        .get('/test-headers')
        .set('Origin', 'http://localhost:3000')
        .expect(200);

      const exposedHeaders = response.headers['access-control-expose-headers'];
      expect(exposedHeaders).toContain('X-Flutter-Optimized');
      expect(exposedHeaders).toContain('X-Response-Time');
      expect(exposedHeaders).toContain('X-Request-ID');
    });
  });

  describe('File Upload Integration', () => {
    beforeEach(() => {
      const uploadConfig = getFlutterUploadConfig();
      const upload = multer(uploadConfig);
      
      app.use(cors(getFlutterCorsConfig()));
      app.post('/upload', upload.single('file'), (req, res) => {
        res.json({ 
          message: 'success',
          filename: req.file?.filename,
          size: req.file?.size,
          mimetype: req.file?.mimetype
        });
      });
      
      app.post('/upload-multiple', upload.array('files', 5), (req, res) => {
        const files = req.files as Express.Multer.File[];
        res.json({ 
          message: 'success',
          count: files?.length || 0,
          files: files?.map(f => ({ filename: f.filename, size: f.size }))
        });
      });
    });

    it('should accept valid image uploads', async () => {
      const buffer = Buffer.from('fake-image-data');
      
      const response = await request(app)
        .post('/upload')
        .attach('file', buffer, 'test.jpg')
        .expect(200);

      expect(response.body.message).toBe('success');
      expect(response.body.filename).toMatch(/^flutter_\d+_[a-z0-9]+\.jpg$/);
      expect(response.body.mimetype).toBe('image/jpeg');
    });

    it('should reject non-image files', async () => {
      const buffer = Buffer.from('malicious-script');
      
      await request(app)
        .post('/upload')
        .attach('file', buffer, { filename: 'script.js', contentType: 'application/javascript' })
        .expect(500); // Multer error for invalid file type
    });

    it('should handle platform-specific upload limits', async () => {
      // Test Android platform
      const androidConfig = getFlutterUploadConfig('android');
      const androidApp = express();
      const androidUpload = multer(androidConfig);
      
      androidApp.post('/upload', androidUpload.single('file'), (req, res) => {
        res.json({ message: 'success', size: req.file?.size });
      });

      // Create a buffer that's within Android limits but exceeds web limits
      const largeBuffer = Buffer.alloc(30 * 1024 * 1024); // 30MB
      
      const response = await request(androidApp)
        .post('/upload')
        .attach('file', largeBuffer, 'large.jpg')
        .expect(200);

      expect(response.body.message).toBe('success');
    });

    it('should reject files exceeding size limits', async () => {
      // Create a buffer larger than the default 10MB limit
      const oversizedBuffer = Buffer.alloc(15 * 1024 * 1024); // 15MB
      
      await request(app)
        .post('/upload')
        .attach('file', oversizedBuffer, 'huge.jpg')
        .expect(500); // File too large error
    });

    it('should handle multiple file uploads', async () => {
      const buffer1 = Buffer.from('image1');
      const buffer2 = Buffer.from('image2');
      
      const response = await request(app)
        .post('/upload-multiple')
        .attach('files', buffer1, 'image1.jpg')
        .attach('files', buffer2, 'image2.png')
        .expect(200);

      expect(response.body.message).toBe('success');
      expect(response.body.count).toBe(2);
      expect(response.body.files).toHaveLength(2);
    });

    it('should reject too many files', async () => {
      const buffer = Buffer.from('image');
      const request_builder = request(app).post('/upload-multiple');
      
      // Try to upload 6 files (limit is 5)
      for (let i = 0; i < 6; i++) {
        request_builder.attach('files', buffer, `image${i}.jpg`);
      }
      
      await request_builder.expect(500); // Too many files error
    });

    it('should generate secure filenames', async () => {
      const buffer = Buffer.from('test-image');
      
      const response1 = await request(app)
        .post('/upload')
        .attach('file', buffer, 'test.jpg')
        .expect(200);

      const response2 = await request(app)
        .post('/upload')
        .attach('file', buffer, 'test.jpg')
        .expect(200);

      // Filenames should be different
      expect(response1.body.filename).not.toBe(response2.body.filename);
      
      // Both should follow the secure pattern
      expect(response1.body.filename).toMatch(/^flutter_\d+_[a-z0-9]+\.jpg$/);
      expect(response2.body.filename).toMatch(/^flutter_\d+_[a-z0-9]+\.jpg$/);
    });
  });

  describe('Rate Limiting Integration', () => {
    it('should apply rate limiting in production', async () => {
      process.env.NODE_ENV = 'production';
      const config = getFlutterConfig();
      
      const limiter = await createRateLimiter({
        windowMs: config.security.rateLimitWindowMs,
        limit: config.security.rateLimitMax,
        message: { error: 'Too many requests' },
        standardHeaders: true,
        legacyHeaders: false
      });
      
      app.use(limiter);
      app.get('/test', (req, res) => {
        res.json({ message: 'success' });
      });

      // Make requests up to the limit (but test with smaller number for performance)
      const testLimit = Math.min(config.security.rateLimitMax, 10);
      for (let i = 0; i < testLimit; i++) {
        await request(app).get('/test').expect(200);
      }

      // Next request should be rate limited
      const response = await request(app)
        .get('/test')
        .expect(429);
        
      expect(response.body.error).toBe('Too many requests');
    });

    it('should have more lenient rate limiting in development', async () => {
      process.env.NODE_ENV = 'development';
      const config = getFlutterConfig();
      
      expect(config.security.rateLimitMax).toBe(1000);
      
      const limiter = await createRateLimiter({
        windowMs: config.security.rateLimitWindowMs,
        limit: 50, // Use smaller limit for testing
        message: { error: 'Too many requests' }
      });
      
      app.use(limiter);
      app.get('/test', (req, res) => {
        res.json({ message: 'success' });
      });

      // Test with reasonable number of requests
      const promises = [];
      for (let i = 0; i < 20; i++) {
        promises.push(request(app).get('/test').expect(200));
      }
      
      await Promise.all(promises);
    });

    it('should include rate limit headers', async () => {
      process.env.NODE_ENV = 'development';
      
      const limiter = await createRateLimiter({
        windowMs: 15 * 60 * 1000,
        limit: 10,
        standardHeaders: true,
        legacyHeaders: false
      });
      
      app.use(limiter);
      app.get('/test', (req, res) => {
        res.json({ message: 'success' });
      });

      const response = await request(app)
        .get('/test')
        .expect(200);

      expect(response.headers['ratelimit-limit']).toBe('10');
      expect(response.headers['ratelimit-remaining']).toBe('9');
      expect(response.headers['ratelimit-reset']).toBeDefined();
    });
  });

  describe('Platform-Specific Configuration Integration', () => {
    it('should handle Android platform requests', async () => {
      const platformConfig = getPlatformConfig('android');
      const uploadConfig = getFlutterUploadConfig('android');
      
      app.use(cors(getFlutterCorsConfig()));
      
      const upload = multer(uploadConfig);
      app.post('/android-upload', upload.single('file'), (req, res) => {
        res.json({ 
          message: 'success',
          platform: 'android',
          maxSize: platformConfig.maxUploadSize,
          filename: req.file?.filename
        });
      });

      const buffer = Buffer.from('android-image');
      
      const response = await request(app)
        .post('/android-upload')
        .set('X-Platform', 'android')
        .set('X-Flutter-App', 'true')
        .attach('file', buffer, 'android.jpg')
        .expect(200);

      expect(response.body.message).toBe('success');
      expect(response.body.platform).toBe('android');
      expect(response.body.maxSize).toBe(50 * 1024 * 1024); // 50MB
    });

    it('should handle iOS platform requests', async () => {
      const platformConfig = getPlatformConfig('ios');
      const uploadConfig = getFlutterUploadConfig('ios');
      
      app.use(cors(getFlutterCorsConfig()));
      
      const upload = multer(uploadConfig);
      app.post('/ios-upload', upload.single('file'), (req, res) => {
        res.json({ 
          message: 'success',
          platform: 'ios',
          maxSize: platformConfig.maxUploadSize,
          timeout: platformConfig.requestTimeout
        });
      });

      const buffer = Buffer.from('ios-image');
      
      const response = await request(app)
        .post('/ios-upload')
        .set('X-Platform', 'ios')
        .set('X-Flutter-App', 'true')
        .attach('file', buffer, 'ios.jpg')
        .expect(200);

      expect(response.body.message).toBe('success');
      expect(response.body.platform).toBe('ios');
      expect(response.body.maxSize).toBe(25 * 1024 * 1024); // 25MB
      expect(response.body.timeout).toBe(10000); // 10 seconds
    });

    it('should handle web platform requests', async () => {
      const platformConfig = getPlatformConfig('web');
      
      app.use(cors(getFlutterCorsConfig()));
      app.get('/web-config', (req, res) => {
        res.json({
          platform: 'web',
          config: platformConfig
        });
      });

      const response = await request(app)
        .get('/web-config')
        .set('X-Platform', 'web')
        .set('Origin', 'http://localhost:3000')
        .expect(200);

      expect(response.body.platform).toBe('web');
      expect(response.body.config.maxUploadSize).toBe(10 * 1024 * 1024); // 10MB
      expect(response.body.config.requestTimeout).toBe(8000); // 8 seconds
    });

    it('should handle desktop platform requests', async () => {
      const platformConfig = getPlatformConfig('desktop');
      
      app.use(cors(getFlutterCorsConfig()));
      app.get('/desktop-config', (req, res) => {
        res.json({
          platform: 'desktop',
          config: platformConfig
        });
      });

      const response = await request(app)
        .get('/desktop-config')
        .set('X-Platform', 'desktop')
        .expect(200);

      expect(response.body.platform).toBe('desktop');
      expect(response.body.config.maxUploadSize).toBe(100 * 1024 * 1024); // 100MB
      expect(response.body.config.requestTimeout).toBe(30000); // 30 seconds
    });
  });

  describe('Response Headers Integration', () => {
    beforeEach(() => {
      const config = getFlutterConfig();
      
      app.use(cors(getFlutterCorsConfig()));
      app.use((req, res, next) => {
        if (config.responses.includeTimestamp) {
          res.set('X-Timestamp', new Date().toISOString());
        }
        if (config.responses.includeRequestId) {
          res.set('X-Request-ID', `req_${Date.now()}_${Math.random().toString(36).substring(2)}`);
        }
        if (config.responses.includeMeta) {
          res.set('X-Flutter-Optimized', 'true');
          res.set('X-API-Version', '1.0.0');
        }
        next();
      });
      
      app.get('/test', (req, res) => {
        res.json({ message: 'success' });
      });
    });

    it('should include Flutter-optimized response headers', async () => {
      const response = await request(app)
        .get('/test')
        .expect(200);

      expect(response.headers['x-timestamp']).toBeDefined();
      expect(response.headers['x-request-id']).toBeDefined();
      expect(response.headers['x-flutter-optimized']).toBe('true');
      expect(response.headers['x-api-version']).toBe('1.0.0');
    });

    it('should disable debug headers in production', async () => {
      process.env.NODE_ENV = 'production';
      
      // Recreate app with production config
      const prodApp = express();
      const config = getFlutterConfig();
      
      prodApp.use(cors(getFlutterCorsConfig()));
      prodApp.use((req, res, next) => {
        if (config.responses.includeTimestamp) {
          res.set('X-Timestamp', new Date().toISOString());
        }
        if (config.responses.includeRequestId) {
          res.set('X-Request-ID', `req_${Date.now()}`);
        }
        if (config.responses.enableDebugMode) {
          res.set('X-Debug-Mode', 'true');
        }
        next();
      });
      
      prodApp.get('/test', (req, res) => {
        res.json({ message: 'success' });
      });

      const response = await request(prodApp)
        .get('/test')
        .expect(200);

      expect(response.headers['x-debug-mode']).toBeUndefined();
      expect(config.responses.enableDebugMode).toBe(false);
    });
  });

  describe('Compression Integration', () => {
    it('should apply compression for responses above threshold', async () => {
      const compression = require('compression');
      const config = getFlutterConfig();
      
      app.use(compression({
        threshold: config.responses.compressionThreshold
      }));
      
      app.get('/large-response', (req, res) => {
        const largeData = 'x'.repeat(2048); // 2KB response
        res.json({ data: largeData });
      });

      const response = await request(app)
        .get('/large-response')
        .set('Accept-Encoding', 'gzip')
        .expect(200);

      expect(response.headers['content-encoding']).toBe('gzip');
    });

    it('should not compress small responses', async () => {
      const compression = require('compression');
      const config = getFlutterConfig();
      
      app.use(compression({
        threshold: config.responses.compressionThreshold
      }));
      
      app.get('/small-response', (req, res) => {
        res.json({ message: 'small' }); // Small response
      });

      const response = await request(app)
        .get('/small-response')
        .set('Accept-Encoding', 'gzip')
        .expect(200);

      expect(response.headers['content-encoding']).toBeUndefined();
    });
  });

  describe('Error Handling Integration', () => {
    beforeEach(() => {
      app.use(cors(getFlutterCorsConfig()));
      
      app.get('/error', (req, res, next) => {
        const error = new Error('Test error');
        next(error);
      });
      
      app.get('/validation-error', (req, res) => {
        res.status(400).json({
          error: 'Validation failed',
          details: ['Invalid input']
        });
      });
      
      // Error handler
      app.use((err: any, req: any, res: any, next: any) => {
        const config = getFlutterConfig();
        
        const errorResponse: any = {
          error: err.message || 'Internal server error'
        };
        
        if (config.responses.includeRequestId) {
          errorResponse.requestId = `req_${Date.now()}`;
        }
        
        if (config.responses.enableDebugMode) {
          errorResponse.stack = err.stack;
        }
        
        res.status(500).json(errorResponse);
      });
    });

    it('should handle errors with proper CORS headers', async () => {
      const response = await request(app)
        .get('/error')
        .set('Origin', 'http://localhost:3000')
        .expect(500);

      expect(response.headers['access-control-allow-origin']).toBe('http://localhost:3000');
      expect(response.body.error).toBe('Test error');
    });

    it('should include debug information in development', async () => {
      process.env.NODE_ENV = 'development';
      
      const response = await request(app)
        .get('/error')
        .expect(500);

      expect(response.body.stack).toBeDefined();
    });

    it('should handle validation errors gracefully', async () => {
      const response = await request(app)
        .get('/validation-error')
        .expect(400);

      expect(response.body.error).toBe('Validation failed');
      expect(response.body.details).toEqual(['Invalid input']);
    });
  });

  describe('Environment-Specific Integration', () => {
    it('should work correctly in test environment', async () => {
      process.env.NODE_ENV = 'test';
      
      const testApp = express();
      const config = getFlutterConfig();
      const uploadConfig = getFlutterUploadConfig();
      
      testApp.use(cors(getFlutterCorsConfig()));
      
      const upload = multer(uploadConfig);
      testApp.post('/test-upload', upload.single('file'), (req, res) => {
        res.json({ 
          message: 'success',
          maxSize: config.uploads.maxFileSize,
          rateLimitEnabled: config.security.enableRateLimiting
        });
      });

      const buffer = Buffer.from('test-data');
      
      const response = await request(testApp)
        .post('/test-upload')
        .attach('file', buffer, 'test.jpg')
        .expect(200);

      expect(response.body.message).toBe('success');
      expect(response.body.maxSize).toBe(1024 * 1024); // 1MB in test
      expect(response.body.rateLimitEnabled).toBe(false); // Disabled in test
    });

    it('should handle development environment correctly', async () => {
      process.env.NODE_ENV = 'development';
      
      const devApp = express();
      const config = getFlutterConfig();
      
      devApp.use(cors(getFlutterCorsConfig()));
      devApp.get('/dev-config', (req, res) => {
        res.json({
          environment: 'development',
          debugMode: config.responses.enableDebugMode,
          allowNoOrigin: config.cors.allowNoOrigin,
          rateLimitMax: config.security.rateLimitMax
        });
      });

      const response = await request(devApp)
        .get('/dev-config')
        .expect(200);

      expect(response.body.environment).toBe('development');
      expect(response.body.debugMode).toBe(true);
      expect(response.body.allowNoOrigin).toBe(true);
      expect(response.body.rateLimitMax).toBe(1000);
    });
  });

  describe('Configuration Validation Integration', () => {
    it('should validate configuration on startup', () => {
      process.env.NODE_ENV = 'development';
      const validation = validateFlutterConfig();
      
      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should detect invalid production configuration', () => {
      process.env.NODE_ENV = 'production';
      delete process.env.ALLOWED_ORIGINS;
      
      const validation = validateFlutterConfig();
      
      expect(validation.valid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(0);
    });

    it('should handle configuration warnings gracefully', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      process.env.NODE_ENV = 'production';
      delete process.env.ALLOWED_ORIGINS;
      
      // Re-require the module to trigger validation
      jest.resetModules();
      require('../../config/flutter');
      
      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });

  describe('Real-world Scenario Integration', () => {
    it('should handle complete Flutter app request flow', async () => {
      process.env.NODE_ENV = 'development';
      
      const fullApp = express();
      const config = getFlutterConfig();
      const uploadConfig = getFlutterUploadConfig('android');
      
      // Apply middleware in correct order
      fullApp.use(cors(getFlutterCorsConfig()));
      fullApp.use(express.json({ limit: '10mb' }));
      
      const upload = multer(uploadConfig);
      
      // Middleware to add Flutter-specific headers
      fullApp.use((req, res, next) => {
        if (config.responses.includeTimestamp) {
          res.set('X-Timestamp', new Date().toISOString());
        }
        if (config.responses.includeRequestId) {
          res.set('X-Request-ID', `flutter_${Date.now()}_${Math.random().toString(36).substring(2)}`);
        }
        res.set('X-Flutter-Optimized', 'true');
        next();
      });
      
      // API endpoints
      fullApp.get('/api/config', (req, res) => {
        const platform = req.headers['x-platform'] as string;
        const platformConfig = getPlatformConfig(platform);
        
        res.json({
          platform: platform || 'web',
          config: platformConfig,
          uploadLimits: {
            maxSize: platformConfig.maxUploadSize,
            allowedTypes: config.uploads.allowedMimeTypes
          }
        });
      });
      
      fullApp.post('/api/upload', upload.single('image'), (req, res) => {
        if (!req.file) {
          res.status(400).json({ error: 'No file uploaded' });
          return;
        }
        
        res.json({
          success: true,
          file: {
            filename: req.file.filename,
            size: req.file.size,
            mimetype: req.file.mimetype
          },
          platform: req.headers['x-platform'],
          deviceId: req.headers['x-device-id']
        });
      });
      
      fullApp.post('/api/data', (req, res) => {
        res.json({
          success: true,
          data: req.body,
          timestamp: new Date().toISOString()
        });
      });

      // Test config endpoint
      const configResponse = await request(fullApp)
        .get('/api/config')
        .set('X-Platform', 'android')
        .set('X-Flutter-App', 'true')
        .set('Origin', 'http://localhost:3000')
        .expect(200);

      expect(configResponse.body.platform).toBe('android');
      expect(configResponse.body.config.maxUploadSize).toBe(50 * 1024 * 1024);
      expect(configResponse.headers['x-flutter-optimized']).toBe('true');

      // Test upload endpoint
      const buffer = Buffer.from('flutter-image-data');
      const uploadResponse = await request(fullApp)
        .post('/api/upload')
        .set('X-Platform', 'android')
        .set('X-Device-ID', 'android-device-123')
        .set('X-Flutter-App', 'true')
        .set('Origin', 'http://localhost:3000')
        .attach('image', buffer, 'flutter-image.jpg')
        .expect(200);

      expect(uploadResponse.body.success).toBe(true);
      expect(uploadResponse.body.file.filename).toMatch(/^flutter_\d+_[a-z0-9]+\.jpg$/);
      expect(uploadResponse.body.platform).toBe('android');
      expect(uploadResponse.body.deviceId).toBe('android-device-123');

      // Test data endpoint
      const dataResponse = await request(fullApp)
        .post('/api/data')
        .set('X-Platform', 'android')
        .set('X-Flutter-App', 'true')
        .set('Origin', 'http://localhost:3000')
        .send({ message: 'Hello from Flutter', userId: 123 })
        .expect(200);

      expect(dataResponse.body.success).toBe(true);
      expect(dataResponse.body.data.message).toBe('Hello from Flutter');
      expect(dataResponse.body.data.userId).toBe(123);
    });

    it('should handle production deployment scenario', async () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_ORIGINS = 'https://myapp.com,https://api.myapp.com';
      
      const prodApp = express();
      const config = getFlutterConfig();
      
      prodApp.use(cors(getFlutterCorsConfig()));
      prodApp.use(express.json());
      
      // Production health check
      prodApp.get('/health', (req, res) => {
        const validation = validateFlutterConfig();
        
        res.json({
          status: 'healthy',
          environment: process.env.NODE_ENV,
          configValid: validation.valid,
          timestamp: new Date().toISOString(),
          features: {
            rateLimiting: config.security.enableRateLimiting,
            compression: config.performance.enableCompression,
            caching: config.performance.enableCaching
          }
        });
      });

      const response = await request(prodApp)
        .get('/health')
        .set('Origin', 'https://myapp.com')
        .expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.environment).toBe('production');
      expect(response.body.configValid).toBe(true);
      expect(response.body.features.rateLimiting).toBe(true);
      expect(response.body.features.compression).toBe(true);
      expect(response.body.features.caching).toBe(true);
    });

    it('should handle error scenarios gracefully', async () => {
      process.env.NODE_ENV = 'development';
      
      const errorApp = express();
      const uploadConfig = getFlutterUploadConfig();
      
      errorApp.use(cors(getFlutterCorsConfig()));
      
      const upload = multer(uploadConfig);
      
      errorApp.post('/upload-error', upload.single('file'), (req, res) => {
        // This should trigger file filter error
        res.json({ success: true });
      });
      
      // Try to upload a disallowed file type
      const buffer = Buffer.from('malicious-script');
      
      await request(errorApp)
        .post('/upload-error')
        .attach('file', buffer, { filename: 'script.js', contentType: 'application/javascript' })
        .expect(500);
    });
  });

  describe('Performance Integration', () => {
    it('should handle concurrent requests efficiently', async () => {
      process.env.NODE_ENV = 'development';
      
      const perfApp = express();
      perfApp.use(cors(getFlutterCorsConfig()));
      
      perfApp.get('/fast', (req, res) => {
        res.json({ message: 'fast response', timestamp: Date.now() });
      });

      const startTime = Date.now();
      const promises = [];
      
      // Make 50 concurrent requests
      for (let i = 0; i < 50; i++) {
        promises.push(
          request(perfApp)
            .get('/fast')
            .expect(200)
        );
      }
      
      const responses = await Promise.all(promises);
      const endTime = Date.now();
      
      expect(responses).toHaveLength(50);
      expect(endTime - startTime).toBeLessThan(5000); // Should complete within 5 seconds
      
      responses.forEach(response => {
        expect(response.body.message).toBe('fast response');
      });
    });
  });
});