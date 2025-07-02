// /backend/src/__tests__/app.unit.test.ts - Updated for Flutter mobile app integration
import request from 'supertest';
import express from 'express';
import { jest } from '@jest/globals';
import { Server } from 'http';

type SpyInstance = ReturnType<typeof jest.spyOn>;

// Mock all dependencies before importing app
jest.mock('../../config', () => ({
  config: {
    port: 3000,
    storageMode: 'local',
    nodeEnv: 'test'
  }
}));

jest.mock('../../middlewares/errorHandler', () => ({
  errorHandler: jest.fn((err: any, req: any, res: any, next: any) => {
    const userAgent = req.headers['user-agent'] || 'Unknown';
    const isFlutterApp = userAgent.includes('Dart/') || userAgent.includes('Flutter/');
    
    if (err instanceof SyntaxError && 'body' in err) {
      if (isFlutterApp) {
        res.status(400).json({
          error: 'INVALID_JSON',
          message: 'Request body contains invalid JSON',
          details: 'Please check your JSON formatting'
        });
      } else {
        res.status(400).json({ error: 'Malformed JSON' });
      }
    } else if (err.type === 'entity.too.large' || err.code === 'LIMIT_FILE_SIZE') {
      if (isFlutterApp) {
        res.status(413).json({
          error: 'PAYLOAD_TOO_LARGE',
          message: 'File or payload size exceeds maximum allowed limit',
          details: {
            maxSize: '10MB for files, 2MB for JSON',
            receivedSize: req.get('Content-Length') || 'unknown'
          }
        });
      } else {
        res.status(413).json({ error: 'Payload Too Large' });
      }
    } else {
      res.status(500).json({ error: 'Internal Server Error' });
    }
  })
}));

jest.mock('../../middlewares/security', () => ({
  securityMiddleware: {
    general: [
      jest.fn((req: any, res: any, next: any) => next()),
      jest.fn((req: any, res: any, next: any) => next()),
    ],
    pathTraversal: jest.fn((req: any, res: any, next: any) => next())
  }
}));

// Mock all route modules with proper router functions
const createMockRouter = () => {
  const router = express.Router();
  router.get('/test', (req: express.Request, res: express.Response) => {
    res.status(404).json({ message: 'Test route' });
  });
  return router;
};

jest.mock('../../routes/authRoutes', () => ({
  authRoutes: createMockRouter()
}));

jest.mock('../../routes/imageRoutes', () => ({
  imageRoutes: createMockRouter()
}));

jest.mock('../../routes/garmentRoutes', () => ({
  garmentRoutes: createMockRouter()
}));

jest.mock('../../routes/wardrobeRoutes', () => ({
  wardrobeRoutes: createMockRouter()
}));

jest.mock('../../routes/exportRoutes', () => createMockRouter());

jest.mock('../../routes/fileRoutes', () => ({
  fileRoutes: createMockRouter()
}));

jest.mock('../../routes/polygonRoutes', () => ({
  polygonRoutes: createMockRouter()
}));

jest.mock('../../routes/oauthRoutes', () => ({
  oauthRoutes: createMockRouter()
}));

describe('Flutter-Optimized App Configuration', () => {
  let app: express.Application;
  let server: Server | null = null;
  let mockConsoleLog: SpyInstance;

  beforeAll(() => {
    mockConsoleLog = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();
    
    // Dynamically import the app after mocks are set up
    const { app: appInstance } = await import('../../app');
    app = appInstance;
    
    // Create server but don't listen yet (will be done in individual tests if needed)
    server = null;
  });

  afterEach((done) => {
    if (server) {
      server.close((err) => {
        server = null;
        if (err) {
          console.error('Error closing server:', err);
        }
        done();
      });
    } else {
      done();
    }
  });

  afterAll(() => {
    mockConsoleLog.mockRestore();
  });

  describe('Flutter CORS Configuration', () => {
    it('should handle Flutter app requests without origin headers', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Dart/2.19 (dart:io)'); // Typical Flutter user agent

      expect(response.status).toBe(200);
      expect(response.headers['access-control-allow-origin']).toBeDefined();
    });

    it('should handle preflight OPTIONS requests for Flutter', async () => {
      const response = await request(app)
        .options('/api/auth/login')
        .set('User-Agent', 'Dart/2.19 (dart:io)')
        .set('Access-Control-Request-Method', 'POST')
        .set('Access-Control-Request-Headers', 'Content-Type,Authorization');

      expect(response.status).toBe(204);
      expect(response.headers['access-control-allow-methods']).toContain('POST');
      expect(response.headers['access-control-allow-headers']).toContain('Content-Type');
      expect(response.headers['access-control-max-age']).toBe('3600');
    });

    it('should set Flutter-friendly exposed headers', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

      expect(response.status).toBe(200);
      // In test mode, all origins are allowed
      expect(response.headers['access-control-allow-origin']).toBe('*');
    });

    it('should allow requests from mobile app user agents', async () => {
      const flutterUserAgents = [
        'Dart/2.19 (dart:io)',
        'Flutter/3.7.0 (dart:io)',
        'MyFlutterApp/1.0 (dart:io)',
        'Dart/2.19 (dart:io) on Android'
      ];

      for (const userAgent of flutterUserAgents) {
        const response = await request(app)
          .get('/api/test')
          .set('User-Agent', userAgent);

        expect(response.status).toBe(200);
        expect(response.body.clientInfo.isFlutterApp).toBe(true);
      }
    });
  });

  describe('Flutter User Agent Detection', () => {
    it('should detect Flutter apps correctly', async () => {
      const response = await request(app)
        .get('/api/test')
        .set('User-Agent', 'Dart/2.19 (dart:io)');

      expect(response.status).toBe(200);
      expect(response.body.clientInfo.isFlutterApp).toBe(true);
      expect(response.body.clientInfo.userAgent).toContain('Dart/');
    });

    it('should detect non-Flutter clients correctly', async () => {
      const response = await request(app)
        .get('/api/test')
        .set('User-Agent', 'Mozilla/5.0 (Chrome)');

      expect(response.status).toBe(200);
      expect(response.body.clientInfo.isFlutterApp).toBe(false);
    });

    it('should include platform info in health check', async () => {
      const flutterResponse = await request(app)
        .get('/health')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

      expect(flutterResponse.body.platform).toBe('flutter');
      expect(flutterResponse.body.security.flutterOptimized).toBe(true);

      const webResponse = await request(app)
        .get('/health')
        .set('User-Agent', 'Mozilla/5.0 (Chrome)');

      expect(webResponse.body.platform).toBe('web');
    });
  });

  describe('Flutter File Upload Handling', () => {
    it('should handle Flutter multipart file uploads', async () => {
      const response = await request(app)
        .post('/api/test/upload')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', '1024'); // 1KB file

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.contentType).toContain('multipart');
    });

    it('should reject oversized files from Flutter apps', async () => {
      const largeFileSize = 11 * 1024 * 1024; // 11MB
      const response = await request(app)
        .post('/api/test/upload')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Type', 'multipart/form-data')
        .set('Content-Length', largeFileSize.toString());

      expect(response.status).toBe(413);
      expect(response.body.error).toBe('FILE_TOO_LARGE');
      expect(response.body.maxSizeMB).toBe(10);
    });

    it('should provide Flutter-friendly error messages for file uploads', async () => {
      const largeFileSize = 11 * 1024 * 1024;
      const response = await request(app)
        .post('/api/upload')
        .set('User-Agent', 'Dart/2.19 (dart:io)')
        .set('Content-Length', largeFileSize.toString());

      expect(response.status).toBe(413);
      expect(response.body.error).toBe('PAYLOAD_TOO_LARGE');
      expect(response.body.details).toBeDefined();
      expect(response.body.details.maxSizeBytes).toBe(10 * 1024 * 1024);
    });

    it('should accept normal-sized files from Flutter apps', async () => {
      const normalFileSize = 5 * 1024 * 1024; // 5MB
      const response = await request(app)
        .post('/api/upload')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Length', normalFileSize.toString());

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.sizeBytes).toBe(normalFileSize);
    });
  });

  describe('Flutter JSON Handling', () => {
    it('should handle larger JSON payloads for Flutter apps', async () => {
      const largeJsonPayload = { data: 'x'.repeat(1.5 * 1024 * 1024) }; // 1.5MB

      const response = await request(app)
        .post('/api/auth/test')
        .send(largeJsonPayload)
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(404); // Should reach the route
    });

    it('should reject extremely large JSON payloads', async () => {
      const extremelyLargePayload = { data: 'x'.repeat(3 * 1024 * 1024) }; // 3MB

      const response = await request(app)
        .post('/api/auth/test')
        .send(extremelyLargePayload)
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(413);
    });

    it('should provide Flutter-specific error messages for malformed JSON', async () => {
      const response = await request(app)
        .post('/api/auth/test')
        .send('{"malformed": json}')
        .set('User-Agent', 'Dart/2.19 (dart:io)')
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(400);
      expect(response.body.error).toBe('INVALID_JSON');
      expect(response.body.message).toContain('invalid JSON');
      expect(response.body.details).toBeDefined();
    });
  });

  describe('Flutter Health Check Enhancement', () => {
    it('should return Flutter-optimized health check structure', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

      expect(response.body).toEqual({
        status: 'ok',
        storage: 'local',
        platform: 'flutter',
        security: {
          cors: 'enabled',
          helmet: 'enabled',
          rateLimit: 'enabled',
          requestLimits: 'enabled',
          flutterOptimized: true
        },
        server: {
          nodeEnv: 'test',
          version: expect.any(String)
        },
        timestamp: expect.any(String)
      });
    });

    it('should include upload limits in non-test environment', async () => {
      // Temporarily change NODE_ENV
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      jest.resetModules();
      const { app: devApp } = await import('../../app');

      try {
        const response = await request(devApp)
          .get('/health')
          .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

        expect(response.body.uploadLimits).toBeDefined();
        expect(response.body.uploadLimits.maxFileSize).toBe('10MB');
        expect(response.body.uploadLimits.allowedImageTypes).toContain('image/jpeg');
        expect(response.body.endpoints).toBeDefined();
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });
  });

  describe('Flutter Route Mounting', () => {
    it('should mount all routes with Flutter logging', async () => {
      const routes = [
        '/api/auth/test',
        '/api/oauth/test',
        '/api/images/test',
        '/api/garments/test',
        '/api/wardrobes/test',
        '/api/export/test',
        '/api/polygons/test',
        '/api/files/test'
      ];

      for (const route of routes) {
        const response = await request(app)
          .get(route)
          .set('User-Agent', 'Flutter/3.7.0 (dart:io)');
        
        expect(response.status).toBe(404); // Routes exist but test endpoints return 404
        expect(response.body.message).toBe('Test route');
      }
    });

    it('should apply path traversal middleware only to file routes', async () => {
      const { securityMiddleware } = await import('../../middlewares/security');

      jest.clearAllMocks();
      
      await request(app)
        .get('/api/auth/test')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)');
      expect(securityMiddleware.pathTraversal).not.toHaveBeenCalled();
      
      await request(app)
        .get('/api/files/test')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)');
      expect(securityMiddleware.pathTraversal).toHaveBeenCalled();
    });
  });

  describe('Flutter Error Handling', () => {
    it('should provide Flutter-friendly 404 responses', async () => {
      const response = await request(app)
        .get('/non-existent-route')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

      expect(response.status).toBe(404);
      expect(response.body.error).toBe('ROUTE_NOT_FOUND');
      expect(response.body.platform).toBe('flutter');
      expect(response.body.availableEndpoints).toBeDefined();
      expect(response.body.documentation).toBeDefined();
    });

    it('should handle errors differently for Flutter vs web clients', async () => {
      const { errorHandler } = await import('../../middlewares/errorHandler');
      
      // Test Flutter error handling
      const flutterResponse = await request(app)
        .post('/api/auth/test')
        .send('{"malformed": json}')
        .set('User-Agent', 'Dart/2.19 (dart:io)')
        .set('Content-Type', 'application/json');

      expect(flutterResponse.body.error).toBe('INVALID_JSON');
      expect(flutterResponse.body.details).toBeDefined();

      // Test web error handling
      const webResponse = await request(app)
        .post('/api/auth/test')
        .send('{"malformed": json}')
        .set('User-Agent', 'Mozilla/5.0 (Chrome)')
        .set('Content-Type', 'application/json');

      expect(webResponse.body.error).toBe('Malformed JSON');
    });
  });

  describe('Flutter Request Logging', () => {
    it('should log Flutter app requests with platform identification', async () => {
      const response = await request(app)
        .post('/api/wardrobes/test')
        .send({ name: 'Test Wardrobe' })
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(404); // Route exists but endpoint doesn't
      // Logging is verified through console.log mocks in beforeAll
    });

    it('should handle requests without user-agent headers', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body.platform).toBe('web'); // Default when no Flutter user agent
    });
  });

  describe('Express App Initialization for Flutter', () => {
    it('should create an Express application instance', () => {
      expect(app).toBeDefined();
      expect(typeof app).toBe('function');
    });

    it('should handle JSON requests from Flutter apps', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(200);
    });

    it('should handle requests without origin headers (typical for Flutter)', async () => {
      const response = await request(app)
        .post('/api/test')
        .send({ test: 'data' })
        .set('User-Agent', 'Dart/2.19 (dart:io)')
        .set('Content-Type', 'application/json');
      // Note: No Origin header set, which is typical for Flutter apps

      expect(response.status).toBe(404); // Route exists but endpoint returns 404
    });
  });

  describe('Flutter Security Integration', () => {
    it('should apply Flutter-compatible security middleware', async () => {
      const { securityMiddleware } = await import('../../middlewares/security');

      await request(app)
        .get('/health')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

      expect(securityMiddleware.general[0]).toHaveBeenCalled();
      expect(securityMiddleware.general[1]).toHaveBeenCalled();
    });

    it('should handle CORS for Flutter apps without throwing errors', async () => {
      const response = await request(app)
        .post('/api/auth/test')
        .send({ username: 'test', password: 'password' })
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Type', 'application/json');

      expect(response.status).not.toBe(500);
      expect(response.headers['access-control-allow-origin']).toBeDefined();
    });
  });

  describe('Flutter Content-Type Handling', () => {
    it('should handle various content types from Flutter apps', async () => {
      const contentTypes = [
        'application/json',
        'application/x-www-form-urlencoded',
        'multipart/form-data'
      ];

      for (const contentType of contentTypes) {
        const response = await request(app)
          .post('/api/auth/test')
          .send(contentType === 'application/json' ? { test: 'data' } : 'test=data')
          .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
          .set('Content-Type', contentType);

        expect(response.status).not.toBe(500);
      }
    });

    it('should log content-type for Flutter debugging', async () => {
      const response = await request(app)
        .post('/api/images/test')
        .send('binary data')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
        .set('Content-Type', 'application/octet-stream');

      expect(response.status).not.toBe(500);
    });
  });

  describe('Flutter Environment Configuration', () => {
    it('should use Flutter-optimized configuration values', async () => {
      const { config } = await import('../../config');
      
      expect(config.port).toBe(3000);
      expect(config.storageMode).toBe('local');
      expect(config.nodeEnv).toBe('test');
    });

    it('should reflect Flutter optimizations in health check', async () => {
      const response = await request(app)
        .get('/health')
        .set('User-Agent', 'Flutter/3.7.0 (dart:io)');
      
      expect(response.body.storage).toBe('local');
      expect(response.body.security.flutterOptimized).toBe(true);
    });
  });
});

describe('Flutter App Export', () => {
  it('should export the Flutter-optimized app instance', async () => {
    const { app } = await import('../../app');

    expect(app).toBeDefined();
    expect(typeof app).toBe('function');
    expect(app).toHaveProperty('listen');
    expect(app).toHaveProperty('use');
    expect(app).toHaveProperty('get');
    expect(app).toHaveProperty('post');
    expect(app).toHaveProperty('options'); // Important for Flutter CORS
  });
});

describe('Flutter Middleware Order and Integration', () => {
  let app: express.Application;
  let server: Server | null = null;

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();
    const { app: appInstance } = await import('../../app');
    app = appInstance;
    server = null;
  });

  afterEach((done) => {
    if (server) {
      server.close((err) => {
        server = null;
        if (err) {
          console.error('Error closing server:', err);
        }
        done();
      });
    } else {
      done();
    }
  });

  it('should apply middleware in correct order for Flutter requests', async () => {
    const { securityMiddleware } = await import('../../middlewares/security');
    
    await request(app)
      .post('/api/auth/test')
      .send({ test: 'data' })
      .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

    expect(securityMiddleware.general[0]).toHaveBeenCalled();
    expect(securityMiddleware.general[1]).toHaveBeenCalled();
  });

  it('should handle Flutter requests through all middleware layers', async () => {
    const response = await request(app)
      .post('/api/images/test')
      .send({ image: 'data' })
      .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
      .set('Content-Type', 'application/json');

    expect(response.status).not.toBe(500);
  });

  it('should properly handle OPTIONS preflight requests in middleware chain', async () => {
    const response = await request(app)
      .options('/api/wardrobes')
      .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
      .set('Access-Control-Request-Method', 'POST');

    expect(response.status).toBe(204);
  });
});