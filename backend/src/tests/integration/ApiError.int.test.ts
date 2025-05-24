// backend/src/__tests__/integration/ApiError.integration.test.ts
import { jest } from '@jest/globals';
import express, { ErrorRequestHandler } from 'express';
import request from 'supertest';
import { Request, Response, NextFunction } from 'express';

// Import the real ApiError class for integration testing
import { ApiError } from '../../utils/ApiError';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';

// Test data and scenarios
const testErrorScenarios = {
  validation: {
    error: ApiError.validation('Invalid email format', 'email', 'invalid-email', 'email'),
    expectedResponse: {
      statusCode: 400,
      body: {
        status: 'error',
        code: 'VALIDATION_ERROR',
        message: 'Invalid email format'
      }
    }
  },
  authentication: {
    error: ApiError.authentication('Token has expired', 'token_expired'),
    expectedResponse: {
      statusCode: 401,
      body: {
        status: 'error',
        code: 'AUTHENTICATION_ERROR',
        message: 'Token has expired'
      }
    }
  },
  authorization: {
    error: ApiError.authorization('Access denied to resource', 'image', 'delete'),
    expectedResponse: {
      statusCode: 403,
      body: {
        status: 'error',
        code: 'AUTHORIZATION_ERROR',
        message: 'Access denied to resource'
      }
    }
  },
  notFound: {
    error: ApiError.notFound('User not found'),
    expectedResponse: {
      statusCode: 404,
      body: {
        status: 'error',
        code: 'NOT_FOUND',
        message: 'User not found'
      }
    }
  },
  rateLimited: {
    error: ApiError.rateLimited('Too many requests', 100, 3600000, 1800),
    expectedResponse: {
      statusCode: 429,
      body: {
        status: 'error',
        code: 'RATE_LIMITED',
        message: 'Too many requests'
      }
    }
  },
  internal: {
    error: ApiError.internal('Database connection failed'),
    expectedResponse: {
      statusCode: 500,
      body: {
        status: 'error',
        code: 'INTERNAL_ERROR',
        message: 'Database connection failed'
      }
    }
  }
};

describe('ApiError Integration Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    // Reset app for each test suite
    app = express();
    app.use(express.json());
  });

  beforeAll(async () => {
    // Set environment to test
    process.env.NODE_ENV = 'test';
    
    // Initialize test database
    await setupTestDatabase();
  });

  afterAll(async () => {
    // Close database connections
    await teardownTestDatabase();
  });

  describe('Context Serialization in Different Environments', () => {
    beforeEach(() => {
      app.get('/context-error', (req: Request, res: Response) => {
        const error = ApiError.validation('Invalid input', 'email', 'test@invalid', 'email');
        throw error;
      });

      const errorHandler: ErrorRequestHandler = (error: any, req: Request, res: Response, next: NextFunction) => {
          if (error instanceof ApiError) {
            const response = error.toJSON();
            res.status(error.statusCode).json(response);
            return;
          }
          
          const convertedError = ApiError.fromUnknown(error);
          res.status(convertedError.statusCode).json(convertedError.toJSON());
      };
      
      app.use(errorHandler);
    });

    it('should include context in development environment', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const response = await request(app)
        .get('/context-error')
        .expect(400);

      expect(response.body).toMatchObject({
        status: 'error',
        code: 'VALIDATION_ERROR',
        message: 'Invalid input',
        context: {
          field: 'email',
          value: 'test@invalid',
          rule: 'email'
        }
      });

      process.env.NODE_ENV = originalEnv;
    });

    it('should exclude context in production environment', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const response = await request(app)
        .get('/context-error')
        .expect(400);

      expect(response.body).toEqual({
        status: 'error',
        code: 'VALIDATION_ERROR',
        message: 'Invalid input'
      });

      expect(response.body.context).toBeUndefined();

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Error Chaining Integration', () => {
    beforeEach(() => {
      app.get('/chained-error', (req: Request, res: Response) => {
        const dbError = new Error('Connection timeout');
        const serviceError = ApiError.database('Database operation failed', 'SELECT', 'users', dbError);
        throw serviceError;
      });

      app.get('/complex-chain', (req: Request, res: Response) => {
        const networkError = new Error('Network unreachable');
        const dbError = ApiError.database('Database connection failed', 'CONNECT', undefined, networkError);
        const serviceError = ApiError.externalService('External service unavailable', 'payment-service', dbError);
        throw serviceError;
      });

      const errorHandler: ErrorRequestHandler = (error: any, req: Request, res: Response, next: NextFunction) => {
          if (error instanceof ApiError) {
            const response = error.toJSON();
            res.status(error.statusCode).json(response);
            return;
          }
          
          const convertedError = ApiError.fromUnknown(error);
          res.status(convertedError.statusCode).json(convertedError.toJSON());
      };
      
      app.use(errorHandler);
    });

    it('should handle single-level error chaining', async () => {
      const response = await request(app)
        .get('/chained-error')
        .expect(500);

      expect(response.body).toMatchObject({
        status: 'error',
        code: 'DATABASE_ERROR',
        message: 'Database operation failed'
      });
    });

    it('should handle complex error chaining', async () => {
      const response = await request(app)
        .get('/complex-chain')
        .expect(502);

      expect(response.body).toMatchObject({
        status: 'error',
        code: 'EXTERNAL_SERVICE_ERROR',
        message: 'External service unavailable'
      });
    });
  });

  describe('Real-world Error Scenarios', () => {
    beforeEach(() => {
      // Authentication middleware for protected routes
      const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
          throw ApiError.authentication('Authentication token required', 'missing_token');
        }
        
        if (authHeader === 'Bearer invalid') {
          throw ApiError.authentication('Invalid authentication token', 'invalid_token');
        }
        
        if (authHeader === 'Bearer expired') {
          throw ApiError.authentication('Authentication token has expired', 'expired_token');
        }
        
        // Simulate successful authentication
        (req as any).user = { id: 'user123', email: 'test@example.com' };
        next();
      };

      // Authorization middleware for admin routes
      const adminAuthMiddleware = (req: Request, res: Response, next: NextFunction) => {
        const user = (req as any).user;
        
        if (!user || user.email !== 'admin@example.com') {
          throw ApiError.authorization('Access denied to admin resource', 'admin', 'access');
        }
        
        next();
      };

      // Protected routes
      app.get('/protected/profile', authMiddleware, (req: Request, res: Response) => {
        res.json({ user: (req as any).user });
      });

      app.get('/protected/admin/users', authMiddleware, adminAuthMiddleware, (req: Request, res: Response) => {
        res.json({ users: [] });
      });

      // Route with validation
      app.post('/users', (req: Request, res: Response) => {
        const { email, age } = req.body;
        
        if (!email) {
          throw ApiError.validation('Email is required', 'email', undefined, 'required');
        }
        
        if (!email.includes('@')) {
          throw ApiError.validation('Invalid email format', 'email', email, 'email');
        }
        
        if (age && (age < 0 || age > 150)) {
          throw ApiError.validation('Age must be between 0 and 150', 'age', age, 'range');
        }
        
        res.status(201).json({ message: 'User created successfully' });
      });

      // Route with rate limiting simulation
      let requestCount = 0;
      app.get('/rate-limited', (req: Request, res: Response) => {
        requestCount++;
        
        if (requestCount > 3) {
          throw ApiError.rateLimited('Rate limit exceeded', 3, 60000, 30);
        }
        
        res.json({ message: 'Request successful', count: requestCount });
      });

      // Route that simulates database errors
      app.get('/database-test', (req: Request, res: Response) => {
        const operation = req.query.operation as string;
        
        switch (operation) {
          case 'timeout':
            throw ApiError.database('Query timeout', 'SELECT', 'users', new Error('Connection timeout'));
          case 'constraint':
            throw ApiError.database('Unique constraint violation', 'INSERT', 'users', new Error('UNIQUE constraint failed'));
          case 'connection':
            throw ApiError.database('Database connection failed', 'CONNECT', undefined, new Error('Connection refused'));
          default:
            res.json({ message: 'Database operation successful' });
        }
      });

      // Error handling middleware
      const errorHandler: ErrorRequestHandler = (error: any, req: Request, res: Response, next: NextFunction) => {
          if (error instanceof ApiError) {
            const response = error.toJSON();
            res.status(error.statusCode).json(response);
            return;
          }
          
          const convertedError = ApiError.fromUnknown(error);
          res.status(convertedError.statusCode).json(convertedError.toJSON());
        };
      
      app.use(errorHandler);
    });

    describe('Authentication Flow', () => {
      it('should require authentication token', async () => {
        const response = await request(app)
          .get('/protected/profile')
          .expect(401);

        expect(response.body).toEqual({
          status: 'error',
          code: 'AUTHENTICATION_ERROR',
          message: 'Authentication token required'
        });
      });

      it('should reject invalid tokens', async () => {
        const response = await request(app)
          .get('/protected/profile')
          .set('Authorization', 'Bearer invalid')
          .expect(401);

        expect(response.body).toEqual({
          status: 'error',
          code: 'AUTHENTICATION_ERROR',
          message: 'Invalid authentication token'
        });
      });

      it('should reject expired tokens', async () => {
        const response = await request(app)
          .get('/protected/profile')
          .set('Authorization', 'Bearer expired')
          .expect(401);

        expect(response.body).toEqual({
          status: 'error',
          code: 'AUTHENTICATION_ERROR',
          message: 'Authentication token has expired'
        });
      });

      it('should allow valid tokens', async () => {
        const response = await request(app)
          .get('/protected/profile')
          .set('Authorization', 'Bearer valid')
          .expect(200);

        expect(response.body).toEqual({
          user: { id: 'user123', email: 'test@example.com' }
        });
      });
    });

    describe('Authorization Flow', () => {
      it('should deny access to admin resources for regular users', async () => {
        const response = await request(app)
          .get('/protected/admin/users')
          .set('Authorization', 'Bearer valid')
          .expect(403);

        expect(response.body).toEqual({
          status: 'error',
          code: 'AUTHORIZATION_ERROR',
          message: 'Access denied to admin resource'
        });
      });
    });

    describe('Validation Flow', () => {
      it('should validate required fields', async () => {
        const response = await request(app)
          .post('/users')
          .send({})
          .expect(400);

        expect(response.body).toEqual({
          status: 'error',
          code: 'VALIDATION_ERROR',
          message: 'Email is required'
        });
      });

      it('should validate email format', async () => {
        const response = await request(app)
          .post('/users')
          .send({ email: 'invalid-email' })
          .expect(400);

        expect(response.body).toEqual({
          status: 'error',
          code: 'VALIDATION_ERROR',
          message: 'Invalid email format'
        });
      });

      it('should validate age range', async () => {
        const response = await request(app)
          .post('/users')
          .send({ email: 'test@example.com', age: 200 })
          .expect(400);

        expect(response.body).toEqual({
          status: 'error',
          code: 'VALIDATION_ERROR',
          message: 'Age must be between 0 and 150'
        });
      });

      it('should create user with valid data', async () => {
        const response = await request(app)
          .post('/users')
          .send({ email: 'test@example.com', age: 25 })
          .expect(201);

        expect(response.body).toEqual({
          message: 'User created successfully'
        });
      });
    });

    describe('Rate Limiting Flow', () => {
      beforeEach(() => {
        // Reset request count for each test by reinitializing the app
        app = express();
        app.use(express.json());
        
        // Re-setup the rate limited route with fresh counter
        let requestCount = 0;
        app.get('/rate-limited', (req: Request, res: Response) => {
          requestCount++;
          
          if (requestCount > 3) {
            throw ApiError.rateLimited('Rate limit exceeded', 3, 60000, 30);
          }
          
          res.json({ message: 'Request successful', count: requestCount });
        });

        // Add error middleware
        const errorHandler: ErrorRequestHandler = (error: any, req: Request, res: Response, next: NextFunction) => {
          if (error instanceof ApiError) {
            const response = error.toJSON();
            res.status(error.statusCode).json(response);
            return;
          }
          
          const convertedError = ApiError.fromUnknown(error);
          res.status(convertedError.statusCode).json(convertedError.toJSON());
        };
        
        app.use(errorHandler);
      });

      it('should allow requests under limit', async () => {
        await request(app).get('/rate-limited').expect(200);
        await request(app).get('/rate-limited').expect(200);
        await request(app).get('/rate-limited').expect(200);
      });

      it('should reject requests over limit', async () => {
        // Make requests up to the limit
        await request(app).get('/rate-limited').expect(200);
        await request(app).get('/rate-limited').expect(200);
        await request(app).get('/rate-limited').expect(200);
        
        // This should be rate limited
        const response = await request(app)
          .get('/rate-limited')
          .expect(429);

        expect(response.body).toEqual({
          status: 'error',
          code: 'RATE_LIMITED',
          message: 'Rate limit exceeded'
        });
      });
    });

    describe('Database Error Flow', () => {
      it('should handle query timeout errors', async () => {
        const response = await request(app)
          .get('/database-test?operation=timeout')
          .expect(500);

        expect(response.body).toEqual({
          status: 'error',
          code: 'DATABASE_ERROR',
          message: 'Query timeout'
        });
      });

      it('should handle constraint violation errors', async () => {
        const response = await request(app)
          .get('/database-test?operation=constraint')
          .expect(500);

        expect(response.body).toEqual({
          status: 'error',
          code: 'DATABASE_ERROR',
          message: 'Unique constraint violation'
        });
      });

      it('should handle connection errors', async () => {
        const response = await request(app)
          .get('/database-test?operation=connection')
          .expect(500);

        expect(response.body).toEqual({
          status: 'error',
          code: 'DATABASE_ERROR',
          message: 'Database connection failed'
        });
      });

      it('should handle successful database operations', async () => {
        const response = await request(app)
          .get('/database-test')
          .expect(200);

        expect(response.body).toEqual({
          message: 'Database operation successful'
        });
      });
    });
  });

  describe('Error Classification Integration', () => {
    let errors: ApiError[];

    beforeAll(() => {
      errors = [
        ApiError.badRequest('Bad request'),
        ApiError.unauthorized('Unauthorized'),
        ApiError.forbidden('Forbidden'),
        ApiError.notFound('Not found'),
        ApiError.conflict('Conflict'),
        ApiError.unprocessableEntity('Unprocessable'),
        ApiError.tooManyRequests('Too many requests'),
        ApiError.internal('Internal error'),
        ApiError.serviceUnavailable('Service unavailable')
      ];
    });

    it('should correctly classify client vs server errors', () => {
      const clientErrors = errors.filter(e => e.isClientError());
      const serverErrors = errors.filter(e => e.isServerError());

      expect(clientErrors).toHaveLength(7); // 400, 401, 403, 404, 409, 422, 429
      expect(serverErrors).toHaveLength(2);  // 500, 503

      // Verify specific classifications
      expect(errors[0].isClientError()).toBe(true); // 400
      expect(errors[7].isServerError()).toBe(true); // 500
    });

    it('should correctly identify retryable errors', () => {
      const retryableErrors = errors.filter(e => e.isRetryable());
      const nonRetryableErrors = errors.filter(e => !e.isRetryable());

      // 429, 500, 503 should be retryable
      expect(retryableErrors).toHaveLength(3);
      expect(nonRetryableErrors).toHaveLength(6);

      expect(errors[6].isRetryable()).toBe(true); // 429
      expect(errors[7].isRetryable()).toBe(true); // 500
      expect(errors[8].isRetryable()).toBe(true); // 503
    });

    it('should correctly assign severity levels', () => {
      const severityMap = errors.map(e => e.getSeverity());
      
      expect(severityMap).toEqual([
        'medium',   // 400
        'medium',   // 401
        'medium',   // 403
        'medium',   // 404
        'medium',   // 409
        'medium',   // 422
        'high',     // 429
        'critical', // 500
        'critical'  // 503
      ]);
    });
  });

  describe('Performance and Memory Tests', () => {
    it('should handle large numbers of errors without memory issues', () => {
      const errors: ApiError[] = [];
      
      // Create 1000 errors
      for (let i = 0; i < 1000; i++) {
        errors.push(ApiError.validation(`Error ${i}`, `field${i}`, `value${i}`, 'test'));
      }
      
      expect(errors).toHaveLength(1000);
      
      // Verify each error is properly formed
      errors.forEach((error, index) => {
        expect(error.message).toBe(`Error ${index}`);
        expect(error.statusCode).toBe(400);
        expect(error.code).toBe('VALIDATION_ERROR');
        expect(error.isOperational).toBe(true);
      });
    });

    it('should handle complex context objects without issues', () => {
      const complexContext = {
        user: { id: 123, email: 'test@example.com', roles: ['user', 'admin'] },
        request: { 
          method: 'POST', 
          path: '/api/complex', 
          headers: { 'user-agent': 'test-agent' },
          body: { nested: { deeply: { nested: 'value' } } }
        },
        metadata: {
          timestamp: new Date(),
          version: '1.0.0',
          environment: 'test',
          features: ['feature1', 'feature2', 'feature3']
        }
      };
      
      const error = ApiError.custom('Complex error', 400, 'COMPLEX_ERROR', undefined, complexContext);
      
      expect(error.context).toEqual(complexContext);
      expect(() => error.toJSON()).not.toThrow();
      
      const json = error.toJSON();
      expect(json.code).toBe('COMPLEX_ERROR');
      expect(json.message).toBe('Complex error');
    });
  });

  describe('Error Middleware Integration', () => {
    beforeEach(() => {
      // Setup routes that throw different types of errors
      app.get('/validation-error', (req: Request, res: Response) => {
        throw testErrorScenarios.validation.error;
      });

      app.get('/authentication-error', (req: Request, res: Response) => {
        throw testErrorScenarios.authentication.error;
      });

      app.get('/authorization-error', (req: Request, res: Response) => {
        throw testErrorScenarios.authorization.error;
      });

      app.get('/not-found-error', (req: Request, res: Response) => {
        throw testErrorScenarios.notFound.error;
      });

      app.get('/rate-limited-error', (req: Request, res: Response) => {
        throw testErrorScenarios.rateLimited.error;
      });

      app.get('/internal-error', (req: Request, res: Response) => {
        throw testErrorScenarios.internal.error;
      });

      app.get('/unknown-error', (req: Request, res: Response) => {
        throw new Error('Unexpected system error');
      });

      app.get('/string-error', (req: Request, res: Response) => {
        throw 'String error thrown';
      });

      app.get('/non-error-object', (req: Request, res: Response) => {
        throw { weird: 'object', thrown: true };
      });

      // Error handling middleware
      const errorHandler: ErrorRequestHandler = (error: any, req: Request, res: Response, next: NextFunction) => {
          if (error instanceof ApiError) {
            const response = error.toJSON();
            res.status(error.statusCode).json(response);
            return;
          }
          
          const convertedError = ApiError.fromUnknown(error);
          res.status(convertedError.statusCode).json(convertedError.toJSON());
      };
      
      app.use(errorHandler);
    });

    Object.entries(testErrorScenarios).forEach(([errorType, scenario]) => {
      it(`should handle ${errorType} error correctly`, async () => {
        const routePath = `/${errorType.replace(/([A-Z])/g, '-$1').toLowerCase()}-error`;
        
        const response = await request(app)
          .get(routePath)
          .expect(scenario.expectedResponse.statusCode);

        expect(response.body).toMatchObject(scenario.expectedResponse.body);

        // Verify error properties are correctly serialized
        expect(response.body.status).toBe('error');
        expect(response.body.code).toBe(scenario.expectedResponse.body.code);
        expect(response.body.message).toBe(scenario.expectedResponse.body.message);
      });
    });

    it('should handle unknown Error objects', async () => {
      const response = await request(app)
        .get('/unknown-error')
        .expect(500);

      expect(response.body).toEqual({
        status: 'error',
        code: 'UNKNOWN_ERROR',
        message: 'Unexpected system error'
      });
    });

    it('should handle string errors', async () => {
      const response = await request(app)
        .get('/string-error')
        .expect(500);

      expect(response.body).toEqual({
        status: 'error',
        code: 'UNKNOWN_ERROR',
        message: 'String error thrown'
      });
    });

    it('should handle non-error objects', async () => {
      const response = await request(app)
        .get('/non-error-object')
        .expect(500);

      expect(response.body).toEqual({
        status: 'error',
        code: 'UNKNOWN_ERROR',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('Database Integration with ApiError', () => {
    beforeEach(() => {
      // Route that simulates real database operations with errors
      app.get('/db/users/:id', async (req: Request, res: Response) => {
        const userId = req.params.id;
        
        // Simulate various database scenarios
        if (userId === 'invalid-uuid') {
          throw ApiError.validation('Invalid user ID format', 'id', userId, 'uuid');
        }
        
        if (userId === 'timeout') {
          const dbError = new Error('Connection timeout after 30s');
          throw ApiError.database('Database query timeout', 'SELECT', 'users', dbError);
        }
        
        if (userId === 'not-found') {
          throw ApiError.notFound('User not found');
        }
        
        if (userId === 'constraint-error') {
          const constraintError = new Error('UNIQUE constraint failed: users.email');
          throw ApiError.database('Email already exists', 'INSERT', 'users', constraintError);
        }
        
        // Successful case
        res.json({ id: userId, email: 'test@example.com', name: 'Test User' });
      });

      // Route that simulates file operations with database
      app.post('/db/images', async (req: Request, res: Response) => {
        const { file_path, user_id } = req.body;
        
        if (!file_path) {
          throw ApiError.validation('File path is required', 'file_path', undefined, 'required');
        }
        
        if (!user_id) {
          throw ApiError.validation('User ID is required', 'user_id', undefined, 'required');
        }
        
        // Simulate file operation error
        if (file_path.includes('invalid')) {
          throw ApiError.fileOperation('File upload failed', 'upload', file_path, new Error('Invalid file format'));
        }
        
        // Simulate database insert error
        if (user_id === 'foreign-key-error') {
          const fkError = new Error('FOREIGN KEY constraint failed');
          throw ApiError.database('Invalid user ID', 'INSERT', 'images', fkError);
        }
        
        res.status(201).json({ id: 'image-123', file_path, user_id });
      });

      // Error handling middleware
      const errorHandler: ErrorRequestHandler = (error: any, req: Request, res: Response, next: NextFunction) => {
          if (error instanceof ApiError) {
            const response = error.toJSON();
            res.status(error.statusCode).json(response);
            return;
          }
          
          const convertedError = ApiError.fromUnknown(error);
          res.status(convertedError.statusCode).json(convertedError.toJSON());
      };
      
      app.use(errorHandler);
    });

    it('should handle database timeout errors correctly', async () => {
      const response = await request(app)
        .get('/db/users/timeout')
        .expect(500);

      expect(response.body).toEqual({
        status: 'error',
        code: 'DATABASE_ERROR',
        message: 'Database query timeout'
      });
    });

    it('should handle validation errors for invalid IDs', async () => {
      const response = await request(app)
        .get('/db/users/invalid-uuid')
        .expect(400);

      expect(response.body).toEqual({
        status: 'error',
        code: 'VALIDATION_ERROR',
        message: 'Invalid user ID format'
      });
    });

    it('should handle not found errors', async () => {
      const response = await request(app)
        .get('/db/users/not-found')
        .expect(404);

      expect(response.body).toEqual({
        status: 'error',
        code: 'NOT_FOUND',
        message: 'User not found'
      });
    });

    it('should handle constraint violation errors', async () => {
      const response = await request(app)
        .get('/db/users/constraint-error')
        .expect(500);

      expect(response.body).toEqual({
        status: 'error',
        code: 'DATABASE_ERROR',
        message: 'Email already exists'
      });
    });

    it('should handle successful database operations', async () => {
      const response = await request(app)
        .get('/db/users/valid-user-123')
        .expect(200);

      expect(response.body).toEqual({
        id: 'valid-user-123',
        email: 'test@example.com',
        name: 'Test User'
      });
    });

    it('should handle file operation errors', async () => {
      const response = await request(app)
        .post('/db/images')
        .send({ file_path: 'invalid/path.txt', user_id: 'user-123' })
        .expect(500);

      expect(response.body).toEqual({
        status: 'error',
        code: 'FILE_OPERATION_ERROR',
        message: 'File upload failed'
      });
    });

    it('should handle foreign key constraint errors', async () => {
      const response = await request(app)
        .post('/db/images')
        .send({ file_path: 'valid/path.jpg', user_id: 'foreign-key-error' })
        .expect(500);

      expect(response.body).toEqual({
        status: 'error',
        code: 'DATABASE_ERROR',
        message: 'Invalid user ID'
      });
    });

    it('should handle successful database operations with files', async () => {
      const response = await request(app)
        .post('/db/images')
        .send({ file_path: 'uploads/image.jpg', user_id: 'valid-user-123' })
        .expect(201);

      expect(response.body).toEqual({
        id: 'image-123',
        file_path: 'uploads/image.jpg',
        user_id: 'valid-user-123'
      });
    });
  });

  describe('Business Logic Error Integration', () => {
    beforeEach(() => {
      // Simulate business logic with various rules
      app.post('/business/garments', (req: Request, res: Response) => {
        const { user_id, type, status } = req.body;
        
        if (!user_id) {
          throw ApiError.validation('User ID is required', 'user_id', undefined, 'required');
        }
        
        if (status === 'archived' && type === 'active') {
          throw ApiError.businessLogic(
            'Cannot create active garment with archived status',
            'no_active_archived_garment',
            'garment'
          );
        }
        
        if (user_id === 'banned-user') {
          throw ApiError.authorization('User account is banned', 'garment', 'create');
        }
        
        res.status(201).json({ id: 'garment-123', user_id, type, status });
      });

      // Simulate external service integration
      app.post('/external/payment', async (req: Request, res: Response) => {
        const { amount, currency } = req.body;
        
        if (!amount || amount <= 0) {
          throw ApiError.validation('Invalid payment amount', 'amount', amount, 'positive');
        }
        
        if (currency === 'INVALID') {
          throw ApiError.externalService(
            'Payment service rejected currency',
            'stripe',
            new Error('Unsupported currency: INVALID')
          );
        }
        
        if (amount > 10000) {
          throw ApiError.businessLogic(
            'Payment amount exceeds maximum limit',
            'max_payment_limit',
            'payment'
          );
        }
        
        res.json({ payment_id: 'pay-123', amount, currency, status: 'completed' });
      });

      // Error handling middleware
      const errorHandler: ErrorRequestHandler = (error: any, req: Request, res: Response, next: NextFunction) => {
          if (error instanceof ApiError) {
            const response = error.toJSON();
            res.status(error.statusCode).json(response);
            return;
          }
          
          const convertedError = ApiError.fromUnknown(error);
          res.status(convertedError.statusCode).json(convertedError.toJSON());
      };
      
      app.use(errorHandler);
    });

    it('should handle business logic violations', async () => {
      const response = await request(app)
        .post('/business/garments')
        .send({ user_id: 'user-123', type: 'active', status: 'archived' })
        .expect(400);

      expect(response.body).toEqual({
        status: 'error',
        code: 'BUSINESS_LOGIC_ERROR',
        message: 'Cannot create active garment with archived status'
      });
    });

    it('should handle authorization errors in business context', async () => {
      const response = await request(app)
        .post('/business/garments')
        .send({ user_id: 'banned-user', type: 'shirt', status: 'active' })
        .expect(403);

      expect(response.body).toEqual({
        status: 'error',
        code: 'AUTHORIZATION_ERROR',
        message: 'User account is banned'
      });
    });

    it('should handle external service errors', async () => {
      const response = await request(app)
        .post('/external/payment')
        .send({ amount: 100, currency: 'INVALID' })
        .expect(502);

      expect(response.body).toEqual({
        status: 'error',
        code: 'EXTERNAL_SERVICE_ERROR',
        message: 'Payment service rejected currency'
      });
    });

    it('should handle business rule violations in payments', async () => {
      const response = await request(app)
        .post('/external/payment')
        .send({ amount: 15000, currency: 'USD' })
        .expect(400);

      expect(response.body).toEqual({
        status: 'error',
        code: 'BUSINESS_LOGIC_ERROR',
        message: 'Payment amount exceeds maximum limit'
      });
    });

    it('should handle successful business operations', async () => {
      const response = await request(app)
        .post('/business/garments')
        .send({ user_id: 'user-123', type: 'shirt', status: 'active' })
        .expect(201);

      expect(response.body).toEqual({
        id: 'garment-123',
        user_id: 'user-123',
        type: 'shirt',
        status: 'active'
      });
    });

    it('should handle successful external service operations', async () => {
      const response = await request(app)
        .post('/external/payment')
        .send({ amount: 100, currency: 'USD' })
        .expect(200);

      expect(response.body).toEqual({
        payment_id: 'pay-123',
        amount: 100,
        currency: 'USD',
        status: 'completed'
      });
    });
  });
});