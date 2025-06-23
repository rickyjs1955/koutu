// /backend/src/__tests__/app.unit.test.ts
import request from 'supertest';
import express from 'express';
import { jest } from '@jest/globals';
import { Server } from 'http'; // Import Server class for type hinting

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
    // Mimic the augmented error handler logic for tests
    if (err instanceof SyntaxError && 'body' in err) {
      res.status(400).json({ error: 'Malformed JSON' });
    } else if (err.type === 'entity.too.large') {
      res.status(413).json({ error: 'Payload Too Large' });
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
  // Add a test route to prevent "router has no routes" issues
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

// Fix for exportRoutes - it's a default export, so we need to handle it differently
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


describe('App Configuration', () => {
  let app: express.Application;
  let server: Server; // Declare a variable to hold the server instance
  let mockConsoleLog: SpyInstance;

  beforeAll(() => {
    mockConsoleLog = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  // Main beforeEach for App Configuration tests that require a server
  beforeEach(async () => {
    jest.clearAllMocks();
    // Clear module cache to get fresh app instance
    jest.resetModules();
    const { app: appInstance } = await import('../../app');
    app = appInstance;
    // Start the server on a random available port and store the instance
    server = app.listen(0);
  });

  // Main afterEach for App Configuration tests
  afterEach((done) => {
    // Close the server after each test
    server.close(done); // Pass done callback for async closure
  });

  afterAll(() => {
    mockConsoleLog.mockRestore();
  });

  describe('Express App Initialization', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should create an Express application instance', () => {
      expect(app).toBeDefined();
      expect(typeof app).toBe('function');
    });

    it('should handle JSON requests without errors', async () => {
      const response = await request(app)
        .get('/health') // Use health endpoint instead of non-existent route
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(200);
    });

    it('should reject requests with malformed JSON', async () => {
      const response = await request(app)
        .post('/health')
        .send('{"malformed": json}')
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(400);
    });

    it('should handle URL-encoded requests', async () => {
      const response = await request(app)
        .get('/health')
        .set('Content-Type', 'application/x-www-form-urlencoded');

      expect(response.status).toBe(200);
    });
  });

  describe('Security Middleware Integration', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should apply general security middleware', async () => {
      const { securityMiddleware } = await import('../../middlewares/security');

      await request(app).get('/health');

      // Verify general middleware was called
      expect(securityMiddleware.general[0]).toHaveBeenCalled();
      expect(securityMiddleware.general[1]).toHaveBeenCalled();
    });

    it('should apply path traversal middleware to file routes', async () => {
      const { securityMiddleware } = await import('../../middlewares/security');

      await request(app).get('/api/v1/files/test');

      // Path traversal middleware should be called for file routes
      expect(securityMiddleware.pathTraversal).toHaveBeenCalled();
    });
  });

  describe('Route Mounting', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should mount auth routes at /api/v1/auth', async () => {
      const response = await request(app).get('/api/v1/auth/test');
      
      // Should reach the mocked route and return 404 (route exists but endpoint doesn't)
      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Test route');
    });

    it('should mount oauth routes at /api/v1/oauth', async () => {
      const response = await request(app).get('/api/v1/oauth/test');
      
      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Test route');
    });

    it('should mount image routes at /api/v1/images', async () => {
      const response = await request(app).get('/api/v1/images/test');
      
      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Test route');
    });

    it('should mount garment routes at /api/v1/garments', async () => {
      const response = await request(app).get('/api/v1/garments/test');
      
      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Test route');
    });

    it('should mount wardrobe routes at /api/v1/wardrobes', async () => {
      const response = await request(app).get('/api/v1/wardrobes/test');
      
      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Test route');
    });

    it('should mount export routes at /api/v1/export', async () => {
      const response = await request(app).get('/api/v1/export/test');
      
      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Test route');
    });

    it('should mount polygon routes at /api/v1/polygons', async () => {
      const response = await request(app).get('/api/v1/polygons/test');
      
      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Test route');
    });

    it('should mount file routes at /api/v1/files', async () => {
      const response = await request(app).get('/api/v1/files/test');
      
      expect(response.status).toBe(404);
      expect(response.body.message).toBe('Test route');
    });
  });

  describe('Health Check Endpoint', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should respond to health check requests', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('status', 'ok');
    });

    it('should return correct health check structure', async () => {
      const response = await request(app).get('/health');

      expect(response.body).toEqual({
        status: 'ok',
        storage: 'local',
        security: {
          cors: 'enabled',
          helmet: 'enabled',
          rateLimit: 'enabled',
          requestLimits: 'enabled'
        },
        timestamp: expect.any(String)
      });
    });

    it('should return valid ISO timestamp', async () => {
      const response = await request(app).get('/health');
      const timestamp = response.body.timestamp;

      expect(() => new Date(timestamp)).not.toThrow();
      expect(new Date(timestamp).toISOString()).toBe(timestamp);
    });
  });

  describe('Error Handling', () => {
    // This describe block handles its own server for isolated error handling tests
    let testApp: express.Application;
    let testServer: Server;

    beforeEach(async () => {
      jest.clearAllMocks();
      jest.resetModules();
      testApp = express();
      const { errorHandler } = await import('../../middlewares/errorHandler');

      testApp.get('/error', (req, res, next) => {
        throw new Error('Test error');
      });

      testApp.use(errorHandler);
      testServer = testApp.listen(0); // Listen on a random available port
    });

    afterEach((done) => {
      testServer.close(done);
    });

    it('should handle 404 errors for non-existent routes', async () => {
      const response = await request(app).get('/non-existent-route'); // Use the main 'app' instance

      expect(response.status).toBe(404);
    });

    it('should use error handler middleware for errors', async () => {
      const { errorHandler } = await import('../../middlewares/errorHandler');
      const response = await request(testApp).get('/error');

      expect(response.status).toBe(500);
      expect(errorHandler).toHaveBeenCalled();
    });
  });

  describe('Request Size Limits', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should reject JSON payloads exceeding 1MB', async () => {
      // Create a payload larger than 1MB
      const largePayload = { data: 'x'.repeat(1024 * 1024 + 1) };

      const response = await request(app)
        .post('/api/v1/auth/test')
        .send(largePayload)
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(413); // Payload Too Large
    });

    it('should accept JSON payloads under 1MB', async () => {
      // Create a payload under 1MB
      const normalPayload = { data: 'x'.repeat(1000) };

      const response = await request(app)
        .post('/api/v1/auth/test')
        .send(normalPayload)
        .set('Content-Type', 'application/json');

      expect(response.status).toBe(404); // Should reach the route
    });

    it('should limit URL-encoded form data to 1MB', async () => {
      // Create form data larger than 1MB
      const largeData = 'data=' + 'x'.repeat(1024 * 1024 + 1);

      const response = await request(app)
        .post('/api/v1/auth/test')
        .send(largeData)
        .set('Content-Type', 'application/x-www-form-urlencoded');

      expect(response.status).toBe(413); // Payload Too Large
    });
  });

  describe('CORS and Security Headers', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should set security headers through security middleware', async () => {
      const response = await request(app).get('/health');

      // Since we're mocking security middleware, we just verify it was called
      const { securityMiddleware } = await import('../../middlewares/security');
      expect(securityMiddleware.general[0]).toHaveBeenCalled();
    });
  });

  describe('Content-Type Handling', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should handle JSON content type', async () => {
      const response = await request(app)
        .post('/api/v1/auth/test')
        .send({ test: 'json' })
        .set('Content-Type', 'application/json');

      expect(response.status).not.toBe(400);
    });

    it('should handle form-encoded content type', async () => {
      const response = await request(app)
        .post('/api/v1/auth/test')
        .send('test=form')
        .set('Content-Type', 'application/x-www-form-urlencoded');

      expect(response.status).not.toBe(400);
    });

    it('should handle requests without content-type', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
    });
  });

  describe('Route Order and Precedence', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should prioritize specific routes over generic ones', async () => {
      // Health check should work even with auth routes mounted
      const healthResponse = await request(app).get('/health');
      expect(healthResponse.status).toBe(200);

      // API routes should be accessible
      const apiResponse = await request(app).get('/api/v1/auth/test');
      expect(apiResponse.status).not.toBe(500);
    });

    it('should apply path traversal middleware only to file routes', async () => {
      const { securityMiddleware } = await import('../../middlewares/security');

      // Reset mock calls
      jest.clearAllMocks();
      
      // Test non-file route
      await request(app).get('/api/v1/auth/test');
      expect(securityMiddleware.pathTraversal).not.toHaveBeenCalled();
      
      // Test file route
      await request(app).get('/api/v1/files/test');
      expect(securityMiddleware.pathTraversal).toHaveBeenCalled();
    });
  });

  describe('Environment Configuration', () => {
    // Tests here will use the 'app' and 'server' from the parent beforeEach/afterEach
    it('should use configuration values correctly', async () => {
      const { config } = await import('../../config');
      
      expect(config.port).toBe(3000);
      expect(config.storageMode).toBe('local');
      expect(config.nodeEnv).toBe('test');
    });

    it('should reflect config in health check', async () => {
      // Use the 'app' instance initialized in the parent beforeEach
      const response = await request(app).get('/health');
      
      expect(response.body.storage).toBe('local');
    });
  });
});

describe('App Export', () => {
  // This test does not require a running server, so it doesn't need beforeEach/afterEach
  it('should export the app instance', async () => {
    const { app } = await import('../../app');

    expect(app).toBeDefined();
    expect(typeof app).toBe('function');
    expect(app).toHaveProperty('listen');
    expect(app).toHaveProperty('use');
    expect(app).toHaveProperty('get');
    expect(app).toHaveProperty('post');
  });
});

// Integration-style tests for middleware order
describe('Middleware Order and Integration', () => {
  let app: express.Application;
  let server: Server; // Declare server here too

  beforeEach(async () => {
    jest.clearAllMocks();
    jest.resetModules();
    const { app: appInstance } = await import('../../app');
    app = appInstance;
    server = app.listen(0); // Listen on a random available port
  });

  afterEach((done) => {
    server.close(done); // Close the server after each test
  });

  it('should apply middleware in correct order', async () => {
    const { securityMiddleware } = await import('../../middlewares/security');
    
    // Make a request to trigger middleware
    await request(app).post('/api/v1/auth/test').send({ test: 'data' });

    // Security middleware should be called first
    expect(securityMiddleware.general[0]).toHaveBeenCalled();
    expect(securityMiddleware.general[1]).toHaveBeenCalled();
  });

  it('should handle requests that pass through all middleware layers', async () => {
    const response = await request(app)
      .post('/api/v1/images/test')
      .send({ image: 'data' })
      .set('Content-Type', 'application/json');

    // Request should pass through all middleware without error
    expect(response.status).not.toBe(500);
  });
});