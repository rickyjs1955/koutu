// backend/src/__tests__/middlewares/auth.p2.unit.test.ts
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';

// Mock dependencies before importing the module under test
const mockJWT = {
  verify: jest.fn(),
  sign: jest.fn()
};

const mockConfig: { jwtSecret: string | undefined } = {
  jwtSecret: 'test-secret-key'
};

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

const mockApiError = {
  authentication: jest.fn(),
  unauthorized: jest.fn(),
  authorization: jest.fn(),
  badRequest: jest.fn(),
  notFound: jest.fn(),
  internal: jest.fn(),
  rateLimited: jest.fn()
};

// Mock modules
jest.mock('jsonwebtoken', () => mockJWT);
jest.mock('../../config', () => ({ config: mockConfig }));
jest.mock('../../utils/ApiError', () => ({ ApiError: mockApiError }));
jest.mock('../../models/userModel', () => ({ userModel: mockUserModel }));
jest.mock('../../models/imageModel', () => ({ imageModel: mockImageModel }));
jest.mock('../../models/garmentModel', () => ({ garmentModel: mockGarmentModel }));
jest.mock('../../models/polygonModel', () => ({ polygonModel: mockPolygonModel }));
jest.mock('../../models/wardrobeModel', () => ({ wardrobeModel: mockWardrobeModel }));

// Import test utilities
import {
  mockUser,
  createRequestWithValidToken,
  createRequestWithInvalidToken,
  createRequestWithExpiredToken,
  createRequestWithMalformedHeader,
  createRequestWithoutAuth,
  createRequestWithEmptyBearer,
  createAuthenticatedRequest,
  createUnauthenticatedRequest,
  mockImage,
  mockGarment,
  mockPolygon,
  mockWardrobe,
  otherUser,
  setupJWTMocks
} from '../__mocks__/auth.mock';

import {
  cleanupTest,
  generateTestUUID,
  generateInvalidUUID,
  createMockApiError
} from '../__helpers__/auth.helper';

import {
  authenticate,
  requireAuth,
  authorizeResource,
  authorizeImage,
  authorizeGarment,
  authorizePolygon,
  authorizeWardrobe,
  optionalAuth,
  rateLimitByUser,
  rateLimitCache,
  cleanupRateLimitCache
} from '../../middlewares/auth';

describe('Authentication Middleware', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    jest.clearAllMocks();
    setupJWTMocks(mockJWT);
    
    // Clear rate limit cache before each test
    rateLimitCache.clear();
    
    mockReq = { headers: {}, params: {} };
    
    // Fix Response mock - properly cast to avoid type issues
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis()
    } as Partial<Response>;
    
    // Fix NextFunction mock - cast to NextFunction directly
    mockNext = jest.fn() as NextFunction;

    // Setup API Error mocks with proper type safety
    mockApiError.authentication.mockImplementation((...args: unknown[]) => {
      const [message, code] = args as [string, string?];
      return createMockApiError('authentication', message, code, 401);
    });
    mockApiError.unauthorized.mockImplementation((...args: unknown[]) => {
      const [message, code] = args as [string, string?];
      return createMockApiError('unauthorized', message, code, 401);
    });
    mockApiError.internal.mockImplementation((...args: unknown[]) => {
      const [message] = args as [string];
      return createMockApiError('internal', message, undefined, 500);
    });
    mockApiError.rateLimited.mockImplementation((...args: unknown[]) => {
      const [message, maxRequests, windowMs, retryAfter] = args as [string, number?, number?, number?];
      return createMockApiError('rateLimited', message, undefined, 429);
    });
  });

  afterEach(() => {
    cleanupTest();
    // Clear rate limit cache between tests
    rateLimitCache.clear();
  });

  afterAll(() => {
    // Clear all timers to prevent Jest from hanging
    jest.clearAllTimers();
    jest.useRealTimers();
    // Clear the cache
    rateLimitCache.clear();
  });

  describe('authenticate', () => {
    beforeEach(() => {
      mockUserModel.findById.mockResolvedValue(mockUser);
    });

    it('should authenticate user with valid token', async () => {
      const req = createRequestWithValidToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(req.user).toEqual({
        id: mockUser.id,
        email: mockUser.email
      });
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should reject request without authorization header', async () => {
      const req = createRequestWithoutAuth();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.authentication).toHaveBeenCalledWith(
        'Authentication token required',
        'missing_token'
      );
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'authentication',
          message: 'Authentication token required'
        })
      );
    });

    it('should reject request with malformed authorization header', async () => {
      const req = createRequestWithMalformedHeader();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.authentication).toHaveBeenCalledWith(
        'Authentication token required',
        'missing_token'
      );
    });

    it('should reject request with empty bearer token', async () => {
      const req = createRequestWithEmptyBearer();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.authentication).toHaveBeenCalledWith(
        'Authentication token required',
        'missing_token'
      );
    });

    it('should reject request with invalid token', async () => {
      const req = createRequestWithInvalidToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.authentication).toHaveBeenCalledWith(
        'Invalid authentication token',
        'invalid_token'
      );
    });

    it('should reject request with expired token', async () => {
      const req = createRequestWithExpiredToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.authentication).toHaveBeenCalledWith(
        'Authentication token has expired',
        'expired_token'
      );
    });

    it('should handle premature token error', async () => {
      mockJWT.verify.mockImplementation(() => {
        const error = new Error('jwt not active');
        error.name = 'NotBeforeError';
        throw error;
      });
      
      const req = createRequestWithValidToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.authentication).toHaveBeenCalledWith(
        'Authentication token not yet valid',
        'premature_token'
      );
    });

    it('should handle user not found', async () => {
      mockUserModel.findById.mockResolvedValue(null);
      const req = createRequestWithValidToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.authentication).toHaveBeenCalledWith(
        'User not found',
        'user_not_found'
      );
    });

    it('should handle database errors', async () => {
      mockUserModel.findById.mockRejectedValue(new Error('Database error'));
      const req = createRequestWithValidToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.internal).toHaveBeenCalledWith('Authentication error');
    });

    it('should handle unknown JWT errors', async () => {
      mockJWT.verify.mockImplementation(() => {
        throw new Error('Unknown JWT error');
      });
      
      const req = createRequestWithValidToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.internal).toHaveBeenCalledWith('Authentication error');
    });
  });

  describe('requireAuth', () => {
    it('should pass through authenticated requests', () => {
      const req = createAuthenticatedRequest();
      
      requireAuth(req as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should reject unauthenticated requests', () => {
      const req = createUnauthenticatedRequest();
      
      requireAuth(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.unauthorized).toHaveBeenCalledWith(
        'Authentication required',
        'AUTH_REQUIRED'
      );
    });
  });

  describe('authorizeResource', () => {
    const validUUID = generateTestUUID();
    const invalidUUID = generateInvalidUUID();

    beforeEach(() => {
      mockApiError.badRequest.mockImplementation((...args: unknown[]) => {
        const [message, code] = args as [string, string?];
        return createMockApiError('badRequest', message, code, 400);
      });
      mockApiError.notFound.mockImplementation((...args: unknown[]) => {
        const [message] = args as [string];
        return createMockApiError('notFound', message, undefined, 404);
      });
      mockApiError.authorization.mockImplementation((...args: unknown[]) => {
        const [message, resource, action] = args as [string, string?, string?];
        return createMockApiError('authorization', message, undefined, 403);
      });
    });

    describe('image authorization', () => {
      const middleware = authorizeResource('image');

      it('should authorize access to owned image', async () => {
        mockImageModel.findById.mockResolvedValue(mockImage);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockImageModel.findById).toHaveBeenCalledWith(validUUID);
        expect(req.resourceContext).toEqual({
          resourceType: 'image',
          resourceId: validUUID,
          ownerId: mockUser.id
        });
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should reject access without authentication', async () => {
        const req = {
          ...createUnauthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.unauthorized).toHaveBeenCalledWith(
          'Authentication required for resource access'
        );
      });

      it('should reject access with invalid UUID', async () => {
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: invalidUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.badRequest).toHaveBeenCalledWith(
          'Invalid image ID format',
          'INVALID_UUID'
        );
      });

      it('should reject access without resource ID', async () => {
        const req = {
          ...createAuthenticatedRequest(),
          params: {}
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.badRequest).toHaveBeenCalledWith('Missing id parameter');
      });

      it('should reject access to non-existent image', async () => {
        mockImageModel.findById.mockResolvedValue(null);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.notFound).toHaveBeenCalledWith('Image not found');
      });

      it('should reject access to image owned by other user', async () => {
        const otherUserImage = { ...mockImage, user_id: otherUser.id };
        mockImageModel.findById.mockResolvedValue(otherUserImage);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.authorization).toHaveBeenCalledWith(
          'You do not have permission to access this image',
          'image',
          'access'
        );
      });

      it('should handle database errors', async () => {
        mockImageModel.findById.mockRejectedValue(new Error('Database error'));
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.internal).toHaveBeenCalledWith('Authorization error');
      });
    });

    describe('garment authorization', () => {
      const middleware = authorizeResource('garment');

      it('should authorize access to owned garment', async () => {
        mockGarmentModel.findById.mockResolvedValue(mockGarment);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockGarmentModel.findById).toHaveBeenCalledWith(validUUID);
        expect(req.resourceContext).toEqual({
          resourceType: 'garment',
          resourceId: validUUID,
          ownerId: mockUser.id
        });
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should reject access to non-existent garment', async () => {
        mockGarmentModel.findById.mockResolvedValue(null);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.notFound).toHaveBeenCalledWith('Garment not found');
      });
    });

    describe('polygon authorization', () => {
      const middleware = authorizeResource('polygon');

      it('should authorize access to polygon with owned image', async () => {
        mockPolygonModel.findById.mockResolvedValue(mockPolygon);
        mockImageModel.findById.mockResolvedValue(mockImage);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockPolygonModel.findById).toHaveBeenCalledWith(validUUID);
        expect(mockImageModel.findById).toHaveBeenCalledWith(mockPolygon.original_image_id);
        expect(req.resourceContext).toEqual({
          resourceType: 'polygon',
          resourceId: validUUID,
          ownerId: mockUser.id
        });
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should reject access when associated image not found', async () => {
        mockPolygonModel.findById.mockResolvedValue(mockPolygon);
        mockImageModel.findById.mockResolvedValue(null);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.notFound).toHaveBeenCalledWith('Associated image not found');
      });

      it('should reject access to polygon when image owned by other user', async () => {
        const otherUserImage = { ...mockImage, user_id: otherUser.id };
        mockPolygonModel.findById.mockResolvedValue(mockPolygon);
        mockImageModel.findById.mockResolvedValue(otherUserImage);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.authorization).toHaveBeenCalledWith(
          'You do not have permission to access this polygon',
          'polygon',
          'access'
        );
      });
    });

    describe('wardrobe authorization', () => {
      const middleware = authorizeResource('wardrobe');

      it('should authorize access to owned wardrobe', async () => {
        mockWardrobeModel.findById.mockResolvedValue(mockWardrobe);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockWardrobeModel.findById).toHaveBeenCalledWith(validUUID);
        expect(req.resourceContext).toEqual({
          resourceType: 'wardrobe',
          resourceId: validUUID,
          ownerId: mockUser.id
        });
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should reject access to non-existent wardrobe', async () => {
        mockWardrobeModel.findById.mockResolvedValue(null);
        const req = {
          ...createAuthenticatedRequest(),
          params: { id: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.notFound).toHaveBeenCalledWith('Wardrobe not found');
      });
    });

    describe('custom parameter name', () => {
      it('should use custom parameter name', async () => {
        const middleware = authorizeResource('image', 'imageId');
        mockImageModel.findById.mockResolvedValue(mockImage);
        const req = {
          ...createAuthenticatedRequest(),
          params: { imageId: validUUID }
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockImageModel.findById).toHaveBeenCalledWith(validUUID);
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should handle missing custom parameter', async () => {
        const middleware = authorizeResource('image', 'imageId');
        const req = {
          ...createAuthenticatedRequest(),
          params: {}
        };

        await middleware(req as Request, mockRes as Response, mockNext);

        expect(mockApiError.badRequest).toHaveBeenCalledWith('Missing imageId parameter');
      });
    });

    it('should handle unknown resource type', async () => {
      // This test requires casting to bypass TypeScript checking
      const middleware = authorizeResource('unknown' as any);
      const req = {
        ...createAuthenticatedRequest(),
        params: { id: validUUID }
      };

      await middleware(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.internal).toHaveBeenCalledWith('Unknown resource type');
    });
  });

  describe('convenience middleware functions', () => {
    it('should export authorizeImage middleware', () => {
      expect(typeof authorizeImage).toBe('function');
    });

    it('should export authorizeGarment middleware', () => {
      expect(typeof authorizeGarment).toBe('function');
    });

    it('should export authorizePolygon middleware', () => {
      expect(typeof authorizePolygon).toBe('function');
    });

    it('should export authorizeWardrobe middleware', () => {
      expect(typeof authorizeWardrobe).toBe('function');
    });
  });

  describe('optionalAuth', () => {
    beforeEach(() => {
      mockUserModel.findById.mockResolvedValue(mockUser);
    });

    it('should authenticate user with valid token', async () => {
      const req = createRequestWithValidToken();
      
      await optionalAuth(req as Request, mockRes as Response, mockNext);

      expect(req.user).toEqual({
        id: mockUser.id,
        email: mockUser.email
      });
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should continue without authentication when no token provided', async () => {
      const req = createRequestWithoutAuth();
      
      await optionalAuth(req as Request, mockRes as Response, mockNext);

      expect(req.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should continue without authentication when token is malformed', async () => {
      const req = createRequestWithMalformedHeader();
      
      await optionalAuth(req as Request, mockRes as Response, mockNext);

      expect(req.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should continue without authentication when token is empty', async () => {
      const req = createRequestWithEmptyBearer();
      
      await optionalAuth(req as Request, mockRes as Response, mockNext);

      expect(req.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should continue without authentication when token is invalid', async () => {
      const req = createRequestWithInvalidToken();
      
      await optionalAuth(req as Request, mockRes as Response, mockNext);

      expect(req.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should continue without authentication when user not found', async () => {
      mockUserModel.findById.mockResolvedValue(null);
      const req = createRequestWithValidToken();
      
      await optionalAuth(req as Request, mockRes as Response, mockNext);

      expect(req.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should continue without authentication on database error', async () => {
      mockUserModel.findById.mockRejectedValue(new Error('Database error'));
      const req = createRequestWithValidToken();
      
      await optionalAuth(req as Request, mockRes as Response, mockNext);

      expect(req.user).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
    });
  });

  describe('rateLimitByUser', () => {
    beforeEach(() => {
      // Clear rate limit cache before each test
      rateLimitCache.clear();
    });

    it('should allow requests under rate limit', () => {
      const middleware = rateLimitByUser(2, 1000); // 2 requests per second for testing
      const req = createAuthenticatedRequest();
      
      middleware(req as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should skip rate limiting for unauthenticated requests', () => {
      const middleware = rateLimitByUser(2, 1000);
      const req = createUnauthenticatedRequest();
      
      middleware(req as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should reject requests when rate limit exceeded', () => {
      const middleware = rateLimitByUser(1, 1000); // Very strict limit for this test
      const req = createAuthenticatedRequest();

      // First request should succeed
      const mockNext1 = jest.fn();
      middleware(req as Request, mockRes as Response, mockNext1);
      expect(mockNext1).toHaveBeenCalledWith();
      
      // Second request should be rejected
      const mockNext2 = jest.fn();
      middleware(req as Request, mockRes as Response, mockNext2);

      expect(mockApiError.rateLimited).toHaveBeenCalledWith(
        expect.stringContaining('Rate limit exceeded'),
        1,
        1000,
        expect.any(Number)
      );
    });

    it('should reset count after window expires', () => {
      jest.useFakeTimers();
      const middleware = rateLimitByUser(2, 1000);
      const req = createAuthenticatedRequest();

      // Make requests up to the limit
      middleware(req as Request, mockRes as Response, mockNext);
      middleware(req as Request, mockRes as Response, mockNext);

      // Advance time to expire the window
      jest.advanceTimersByTime(1100);

      // Should be able to make a request again
      const mockNextAfter = jest.fn();
      middleware(req as Request, mockRes as Response, mockNextAfter);
      expect(mockNextAfter).toHaveBeenCalledWith();

      jest.useRealTimers();
    });

    it('should handle different users separately', () => {
      const middleware = rateLimitByUser(2, 1000);
      const req1 = createAuthenticatedRequest('user1');
      const req2 = createAuthenticatedRequest('user2');

      // Both users should be able to make requests
      middleware(req1 as Request, mockRes as Response, mockNext);
      middleware(req2 as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledTimes(2);
    });

    it('should use default parameters when not specified', () => {
      const defaultMiddleware = rateLimitByUser();
      const req = createAuthenticatedRequest();

      defaultMiddleware(req as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should cleanup rate limit cache', () => {
      // Test the cleanup function exists and can be called
      expect(typeof cleanupRateLimitCache).toBe('function');
      expect(() => cleanupRateLimitCache()).not.toThrow();
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle missing JWT secret', async () => {
      mockConfig.jwtSecret = undefined;
      mockJWT.verify.mockImplementation(() => {
        throw new Error('secret required');
      });

      const req = createRequestWithValidToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      expect(mockApiError.internal).toHaveBeenCalledWith('Authentication error');
    });

    it('should handle malformed JWT payload', async () => {
      mockJWT.verify.mockReturnValue({ invalid: 'payload' });
      const req = createRequestWithValidToken();
      
      await authenticate(req as Request, mockRes as Response, mockNext);

      // Should handle missing id/email gracefully
      expect(mockUserModel.findById).toHaveBeenCalledWith(undefined);
    });
  });
});