// backend/src/__tests__/integration/auth.integration.test.ts
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import express from 'express';
import request from 'supertest';

// Mock external dependencies but keep middleware logic real
const mockJWT = {
  verify: jest.fn(),
  sign: jest.fn()
} as any;

const mockConfig = {
  jwtSecret: 'test-integration-secret-key'
} as any;

// Mock database models with more realistic behavior
const mockUserModel = {
  findById: jest.fn()
} as any;

const mockImageModel = {
  findById: jest.fn()
} as any;

const mockGarmentModel = {
  findById: jest.fn()
} as any;

const mockPolygonModel = {
  findById: jest.fn()
} as any;

const mockWardrobeModel = {
  findById: jest.fn()
} as any;

// Mock ApiError to behave like real errors
class MockApiError extends Error {
  statusCode: number;
  type: string;
  code?: string;
  isOperational: boolean;

  constructor(message: string, statusCode: number, type: string, code?: string) {
    super(message);
    this.statusCode = statusCode;
    this.type = type;
    this.code = code;
    this.isOperational = true;
    this.name = 'ApiError';
  }

  static authentication(message: string, code?: string) {
    return new MockApiError(message, 401, 'authentication', code);
  }

  static unauthorized(message: string, code?: string) {
    return new MockApiError(message, 401, 'unauthorized', code);
  }

  static authorization(message: string, resource?: string, action?: string) {
    return new MockApiError(message, 403, 'authorization');
  }

  static badRequest(message: string, code?: string) {
    return new MockApiError(message, 400, 'badRequest', code);
  }

  static notFound(message: string) {
    return new MockApiError(message, 404, 'notFound');
  }

  static internal(message: string) {
    return new MockApiError(message, 500, 'internal');
  }

  static rateLimited(message: string, maxRequests?: number, windowMs?: number, retryAfter?: number) {
    return new MockApiError(message, 429, 'rateLimited');
  }
}

// Mock modules before importing middleware
jest.mock('jsonwebtoken', () => mockJWT);
jest.mock('../../config', () => ({ config: mockConfig }));
jest.mock('../../utils/ApiError', () => ({ ApiError: MockApiError }));
jest.mock('../../models/userModel', () => ({ userModel: mockUserModel }));
jest.mock('../../models/imageModel', () => ({ imageModel: mockImageModel }));
jest.mock('../../models/garmentModel', () => ({ garmentModel: mockGarmentModel }));
jest.mock('../../models/polygonModel', () => ({ polygonModel: mockPolygonModel }));
jest.mock('../../models/wardrobeModel', () => ({ wardrobeModel: mockWardrobeModel }));

// Import middleware after mocking
import {
  authenticate,
  requireAuth,
  authorizeResource,
  optionalAuth,
  rateLimitByUser,
  cleanupRateLimitCache
} from '../../middlewares/auth';

// Test data
const testUser = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  email: 'integration@test.com',
  password: 'hashedPassword',
  created_at: new Date(),
  updated_at: new Date()
};

const testImage = {
  id: '456e7890-e89b-12d3-a456-426614174001',
  user_id: testUser.id,
  file_path: '/path/to/image.jpg',
  metadata: {},
  created_at: new Date(),
  updated_at: new Date()
};

const testGarment = {
  id: '789e1234-e89b-12d3-a456-426614174002',
  user_id: testUser.id,
  original_image_id: testImage.id,
  file_path: '/path/to/garment.jpg',
  mask_path: '/path/to/mask.jpg',
  metadata: {},
  created_at: new Date(),
  updated_at: new Date()
};

const testPolygon = {
  id: '012e3456-e89b-12d3-a456-426614174003',
  original_image_id: testImage.id,
  polygon_data: '[]',
  metadata: {},
  created_at: new Date(),
  updated_at: new Date()
};

const testWardrobe = {
  id: '345e6789-e89b-12d3-a456-426614174004',
  user_id: testUser.id,
  name: 'Integration Test Wardrobe',
  metadata: {},
  created_at: new Date(),
  updated_at: new Date()
};

const otherUser = {
  id: '987e6543-e89b-12d3-a456-426614174005',
  email: 'other@test.com'
};

const validToken = 'valid.integration.token';
const invalidToken = 'invalid.integration.token';
const expiredToken = 'expired.integration.token';

const mockJwtPayload = {
  id: testUser.id,
  email: testUser.email,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600
};

describe('Auth Middleware Integration Tests', () => {
  let app: express.Application;

  beforeAll(() => {
    // Create Express app for integration testing
    app = express();
    app.use(express.json());
  });

  beforeEach(() => {
    jest.clearAllMocks();
    cleanupRateLimitCache();

    // Recreate app for each test to ensure clean state
    app = express();
    app.use(express.json());

    // Add error handling middleware after routes are defined
    const setupErrorHandler = () => {
      app.use((error: any, req: Request, res: Response, next: NextFunction) => {
        console.log('Error handler called:', error);
        
        if (error && error.isOperational) {
          const errorResponse: any = {
            message: error.message,
            type: error.type
          };
          
          if (error.code) {
            errorResponse.code = error.code;
          }
          
          res.status(error.statusCode).json({
            error: errorResponse
          });
          return;
        }
        
        // Handle non-operational errors
        res.status(500).json({
          error: {
            message: error?.message || 'Internal server error',
            type: 'internal'
          }
        });
      });
    };

    // Setup JWT mock responses
    mockJWT.verify.mockImplementation((token: string) => {
      switch (token) {
        case validToken:
          return mockJwtPayload;
        case expiredToken:
          const expiredError = new Error('jwt expired');
          expiredError.name = 'TokenExpiredError';
          throw expiredError;
        case invalidToken:
          const invalidError = new Error('invalid token');
          invalidError.name = 'JsonWebTokenError';
          throw invalidError;
        default:
          const defaultError = new Error('invalid token');
          defaultError.name = 'JsonWebTokenError';
          throw defaultError;
      }
    });

    // Setup default model responses
    mockUserModel.findById.mockResolvedValue(testUser);
    mockImageModel.findById.mockResolvedValue(testImage);
    mockGarmentModel.findById.mockResolvedValue(testGarment);
    mockPolygonModel.findById.mockResolvedValue(testPolygon);
    mockWardrobeModel.findById.mockResolvedValue(testWardrobe);

    // Setup routes and error handler for each test section
    (app as any).setupErrorHandler = setupErrorHandler;
  });

  afterEach(() => {
    cleanupRateLimitCache();
  });

  describe('Authentication Flow Integration', () => {
    beforeEach(() => {
      // Setup test routes
      app.get('/test-auth', authenticate, (req: Request, res: Response) => {
        res.json({ user: req.user, authenticated: true });
      });

      app.get('/test-optional-auth', optionalAuth, (req: Request, res: Response) => {
        res.json({ user: req.user || null, hasAuth: !!req.user });
      });

      app.get('/test-require-auth', requireAuth, (req: Request, res: Response) => {
        res.json({ message: 'Protected resource accessed' });
      });

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should successfully authenticate with valid token', async () => {
      const response = await request(app)
        .get('/test-auth')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body).toEqual({
        user: {
          id: testUser.id,
          email: testUser.email
        },
        authenticated: true
      });

      expect(mockJWT.verify).toHaveBeenCalledWith(validToken, mockConfig.jwtSecret);
      expect(mockUserModel.findById).toHaveBeenCalledWith(testUser.id);
    });

    it('should reject request with invalid token', async () => {
      const response = await request(app)
        .get('/test-auth')
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(401);

      expect(response.body.error).toEqual({
        message: 'Invalid authentication token',
        type: 'authentication',
        code: 'invalid_token'
      });
    });

    it('should reject request with expired token', async () => {
      const response = await request(app)
        .get('/test-auth')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);

      expect(response.body.error).toEqual({
        message: 'Authentication token has expired',
        type: 'authentication',
        code: 'expired_token'
      });
    });

    it('should reject request without token', async () => {
      const response = await request(app)
        .get('/test-auth')
        .expect(401);

      expect(response.body.error).toEqual({
        message: 'Authentication token required',
        type: 'authentication',
        code: 'missing_token'
      });
    });

    it('should handle optional auth with valid token', async () => {
      const response = await request(app)
        .get('/test-optional-auth')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body).toEqual({
        user: {
          id: testUser.id,
          email: testUser.email
        },
        hasAuth: true
      });
    });

    it('should handle optional auth without token', async () => {
      const response = await request(app)
        .get('/test-optional-auth')
        .expect(200);

      expect(response.body).toEqual({
        user: null,
        hasAuth: false
      });
    });

    it('should handle optional auth with invalid token gracefully', async () => {
      const response = await request(app)
        .get('/test-optional-auth')
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(200);

      expect(response.body).toEqual({
        user: null,
        hasAuth: false
      });
    });

    it('should handle user not found scenario', async () => {
      mockUserModel.findById.mockResolvedValue(null);

      const response = await request(app)
        .get('/test-auth')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(401);

      expect(response.body.error).toEqual({
        message: 'User not found',
        type: 'authentication',
        code: 'user_not_found'
      });
    });

    it('should handle database errors during authentication', async () => {
      mockUserModel.findById.mockRejectedValue(new Error('Database connection failed'));

      const response = await request(app)
        .get('/test-auth')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(500);

      expect(response.body.error).toEqual({
        message: 'Authentication error',
        type: 'internal'
      });
    });
  });

  describe('Authorization Flow Integration', () => {
    beforeEach(() => {
      // Setup protected resource routes
      app.get('/images/:id', authenticate, authorizeResource('image'), (req: Request, res: Response) => {
        res.json({ 
          message: 'Image accessed successfully',
          resourceContext: req.resourceContext 
        });
      });

      app.get('/garments/:id', authenticate, authorizeResource('garment'), (req: Request, res: Response) => {
        res.json({ 
          message: 'Garment accessed successfully',
          resourceContext: req.resourceContext 
        });
      });

      app.get('/polygons/:id', authenticate, authorizeResource('polygon'), (req: Request, res: Response) => {
        res.json({ 
          message: 'Polygon accessed successfully',
          resourceContext: req.resourceContext 
        });
      });

      app.get('/wardrobes/:id', authenticate, authorizeResource('wardrobe'), (req: Request, res: Response) => {
        res.json({ 
          message: 'Wardrobe accessed successfully',
          resourceContext: req.resourceContext 
        });
      });

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should authorize access to owned image', async () => {
      const response = await request(app)
        .get(`/images/${testImage.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body).toEqual({
        message: 'Image accessed successfully',
        resourceContext: {
          resourceType: 'image',
          resourceId: testImage.id,
          ownerId: testUser.id
        }
      });

      expect(mockImageModel.findById).toHaveBeenCalledWith(testImage.id);
    });

    it('should reject access to non-existent image', async () => {
      mockImageModel.findById.mockResolvedValue(null);

      const response = await request(app)
        .get(`/images/${testImage.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(404);

      expect(response.body.error).toEqual({
        message: 'Image not found',
        type: 'notFound'
      });
    });

    it('should reject access to image owned by other user', async () => {
      const otherUserImage = { ...testImage, user_id: otherUser.id };
      mockImageModel.findById.mockResolvedValue(otherUserImage);

      const response = await request(app)
        .get(`/images/${testImage.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(403);

      expect(response.body.error).toEqual({
        message: 'You do not have permission to access this image',
        type: 'authorization'
      });
    });

    it('should reject access with invalid UUID format', async () => {
      const response = await request(app)
        .get('/images/invalid-uuid')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(400);

      expect(response.body.error).toEqual({
        message: 'Invalid image ID format',
        type: 'badRequest',
        code: 'INVALID_UUID'
      });
    });

    it('should authorize polygon access through image ownership', async () => {
      const response = await request(app)
        .get(`/polygons/${testPolygon.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body).toEqual({
        message: 'Polygon accessed successfully',
        resourceContext: {
          resourceType: 'polygon',
          resourceId: testPolygon.id,
          ownerId: testUser.id
        }
      });

      expect(mockPolygonModel.findById).toHaveBeenCalledWith(testPolygon.id);
      expect(mockImageModel.findById).toHaveBeenCalledWith(testPolygon.original_image_id);
    });

    it('should reject polygon access when associated image is not found', async () => {
      mockImageModel.findById.mockResolvedValue(null);

      const response = await request(app)
        .get(`/polygons/${testPolygon.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(404);

      expect(response.body.error).toEqual({
        message: 'Associated image not found',
        type: 'notFound'
      });
    });

    it('should handle database errors during authorization', async () => {
      mockImageModel.findById.mockRejectedValue(new Error('Database error'));

      const response = await request(app)
        .get(`/images/${testImage.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(500);

      expect(response.body.error).toEqual({
        message: 'Authorization error',
        type: 'internal'
      });
    });
  });

  describe('Rate Limiting Integration', () => {
    beforeEach(() => {
      // Setup rate limited route
      app.get('/rate-limited', 
        authenticate, 
        rateLimitByUser(2, 1000), // 2 requests per second
        (req: Request, res: Response) => {
          res.json({ message: 'Rate limited endpoint accessed' });
        }
      );

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should allow requests under rate limit', async () => {
      const response1 = await request(app)
        .get('/rate-limited')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      const response2 = await request(app)
        .get('/rate-limited')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response1.body.message).toBe('Rate limited endpoint accessed');
      expect(response2.body.message).toBe('Rate limited endpoint accessed');
    });

    it('should reject requests when rate limit exceeded', async () => {
      // Make requests up to the limit
      await request(app)
        .get('/rate-limited')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      await request(app)
        .get('/rate-limited')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      // This should be rate limited
      const response = await request(app)
        .get('/rate-limited')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(429);

      expect(response.body.error.message).toContain('Rate limit exceeded');
      expect(response.body.error.type).toBe('rateLimited');
    });

    it('should handle different users separately', async () => {
      // Setup second user
      const secondUser = { ...testUser, id: 'different-user-id', email: 'different@test.com' };
      const secondToken = 'second.user.token';
      
      mockJWT.verify.mockImplementation((token: string) => {
        if (token === secondToken) {
          return { ...mockJwtPayload, id: secondUser.id, email: secondUser.email };
        }
        return mockJwtPayload;
      });

      mockUserModel.findById.mockImplementation((id: string) => {
        if (id === secondUser.id) {
          return Promise.resolve(secondUser);
        }
        return Promise.resolve(testUser);
      });

      // Both users should be able to make requests
      await request(app)
        .get('/rate-limited')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      await request(app)
        .get('/rate-limited')
        .set('Authorization', `Bearer ${secondToken}`)
        .expect(200);
    });
  });

  describe('Complete Auth Flow Integration', () => {
    beforeEach(() => {
      // Setup a complete protected endpoint
      app.get('/protected-images/:id',
        authenticate,           // Step 1: Authenticate user
        requireAuth,           // Step 2: Ensure authentication (redundant but for demo)
        authorizeResource('image'), // Step 3: Authorize resource access
        rateLimitByUser(5, 60000), // Step 4: Apply rate limiting
        (req: Request, res: Response) => {
          res.json({
            message: 'Successfully accessed protected image',
            user: req.user,
            resourceContext: req.resourceContext,
            timestamp: new Date().toISOString()
          });
        }
      );

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should successfully complete full authentication and authorization flow', async () => {
      const response = await request(app)
        .get(`/protected-images/${testImage.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body).toMatchObject({
        message: 'Successfully accessed protected image',
        user: {
          id: testUser.id,
          email: testUser.email
        },
        resourceContext: {
          resourceType: 'image',
          resourceId: testImage.id,
          ownerId: testUser.id
        }
      });

      expect(response.body.timestamp).toBeDefined();

      // Verify all middleware was called in order
      expect(mockJWT.verify).toHaveBeenCalledWith(validToken, mockConfig.jwtSecret);
      expect(mockUserModel.findById).toHaveBeenCalledWith(testUser.id);
      expect(mockImageModel.findById).toHaveBeenCalledWith(testImage.id);
    });

    it('should fail at authentication step with invalid token', async () => {
      const response = await request(app)
        .get(`/protected-images/${testImage.id}`)
        .set('Authorization', `Bearer ${invalidToken}`)
        .expect(401);

      expect(response.body.error).toEqual({
        message: 'Invalid authentication token',
        type: 'authentication',
        code: 'invalid_token'
      });

      // Authorization should not be called if authentication fails
      expect(mockImageModel.findById).not.toHaveBeenCalled();
    });

    it('should fail at authorization step with unauthorized resource', async () => {
      const otherUserImage = { ...testImage, user_id: otherUser.id };
      mockImageModel.findById.mockResolvedValue(otherUserImage);

      const response = await request(app)
        .get(`/protected-images/${testImage.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(403);

      expect(response.body.error).toEqual({
        message: 'You do not have permission to access this image',
        type: 'authorization'
      });

      // Authentication should succeed but authorization should fail
      expect(mockJWT.verify).toHaveBeenCalledWith(validToken, mockConfig.jwtSecret);
      expect(mockUserModel.findById).toHaveBeenCalledWith(testUser.id);
      expect(mockImageModel.findById).toHaveBeenCalledWith(testImage.id);
    });
  });

  describe('Error Handling Integration', () => {
    beforeEach(() => {
      // Setup a route that could fail at multiple points
      app.get('/error-cascade/:id',
        authenticate,
        authorizeResource('image'),
        (req: Request, res: Response) => {
          res.json({ message: 'Should not reach here' });
        }
      );

      app.get('/error-test',
        authenticate,
        (req: Request, res: Response) => {
          throw new Error('Unexpected error');
        }
      );

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should handle cascading errors properly', async () => {
      // Test authentication error first
      await request(app)
        .get(`/error-cascade/${testImage.id}`)
        .set('Authorization', 'Bearer invalid')
        .expect(401);

      // Test authorization error (authentication succeeds)
      mockImageModel.findById.mockResolvedValue({ ...testImage, user_id: otherUser.id });
      
      await request(app)
        .get(`/error-cascade/${testImage.id}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(403);
    });

    it('should handle unexpected errors gracefully', async () => {
      const response = await request(app)
        .get('/error-test')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(500);

      expect(response.body.error.type).toBe('internal');
    });
  });
});