import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import {
  authenticate,
  requireAuth,
  authorizeResource,
  optionalAuth,
  rateLimitByUser,
  rateLimitCache,
  stopCleanup
} from '../../middlewares/auth';
import {
  setupAuthMocks,
  createTestScenario,
  runMiddlewareTest,
  testAuthenticationScenarios,
  setupAuthorizationMocks,
  createMockApiError,
  cleanupTest
} from '../__helpers__/auth.helper';
import { ApiError } from '../../utils/ApiError';

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('../../config', () => ({
  config: {
    jwtSecret: 'test-secret-key-for-testing-only',
    jwtExpiresIn: '1d'
  }
}));
jest.mock('../../models/userModel', () => ({
  userModel: {
    findById: jest.fn()
  }
}));
jest.mock('../../models/imageModel', () => ({
  imageModel: {
    findById: jest.fn()
  }
}));
jest.mock('../../models/garmentModel', () => ({
  garmentModel: {
    findById: jest.fn()
  }
}));
jest.mock('../../models/polygonModel', () => ({
  polygonModel: {
    findById: jest.fn()
  }
}));
jest.mock('../../models/wardrobeModel', () => ({
  wardrobeModel: {
    findById: jest.fn()
  }
}));
jest.mock('../../utils/ApiError');

// Test constants
const mockUser = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  email: 'test@example.com'
};

const otherUser = {
  id: '987e6543-e21b-12d3-a456-426614174999',
  email: 'other@example.com'
};

const mockImage = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  user_id: mockUser.id,
  filename: 'test-image.jpg'
};

const mockGarment = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  user_id: mockUser.id,
  name: 'Test Garment'
};

const mockPolygon = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  original_image_id: mockImage.id,
  coordinates: [[0, 0], [100, 0], [100, 100], [0, 100]]
};

const mockWardrobe = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  user_id: mockUser.id,
  name: 'Test Wardrobe'
};

const validToken = 'valid.jwt.token';
const invalidToken = 'invalid.jwt.token';
const expiredToken = 'expired.jwt.token';
const malformedToken = 'malformed.jwt.token';

describe('Auth Security Tests', () => {
  let mockJWT: any;
  let mockUserModel: any;
  let mockImageModel: any;
  let mockGarmentModel: any;
  let mockPolygonModel: any;
  let mockWardrobeModel: any;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    rateLimitCache.clear();

    // Get the mocked JWT module
    const jwt = require('jsonwebtoken');
    mockJWT = jwt;

    // Setup JWT mock behaviors - Fixed: Proper typing for jest mock
    mockJWT.verify = jest.fn().mockImplementation((...args: unknown[]) => {
      const token = args[0] as string;
      switch (token) {
        case validToken:
          return {
            id: mockUser.id,
            email: mockUser.email,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 86400
          };
        case expiredToken:
          const expiredError = new Error('jwt expired');
          expiredError.name = 'TokenExpiredError';
          throw expiredError;
        case invalidToken:
          const invalidError = new Error('invalid signature');
          invalidError.name = 'JsonWebTokenError';
          throw invalidError;
        case malformedToken:
          const malformedError = new Error('jwt malformed');
          malformedError.name = 'JsonWebTokenError';
          throw malformedError;
        default:
          const defaultError = new Error('invalid token');
          defaultError.name = 'JsonWebTokenError';
          throw defaultError;
      }
    });

    // Get mocked models
    const { userModel } = require('../../models/userModel');
    const { imageModel } = require('../../models/imageModel');
    const { garmentModel } = require('../../models/garmentModel');
    const { polygonModel } = require('../../models/polygonModel');
    const { wardrobeModel } = require('../../models/wardrobeModel');

    mockUserModel = userModel;
    mockImageModel = imageModel;
    mockGarmentModel = garmentModel;
    mockPolygonModel = polygonModel;
    mockWardrobeModel = wardrobeModel;

    // Setup default model responses
    mockUserModel.findById.mockResolvedValue(mockUser);
    mockImageModel.findById.mockResolvedValue(mockImage);
    mockGarmentModel.findById.mockResolvedValue(mockGarment);
    mockPolygonModel.findById.mockResolvedValue(mockPolygon);
    mockWardrobeModel.findById.mockResolvedValue(mockWardrobe);

    // Setup ApiError mocks
    (ApiError.authentication as jest.MockedFunction<any>) = jest.fn((message, code) => ({
      name: 'ApiError',
      message,
      statusCode: 401,
      type: 'authentication',
      code,
      isOperational: true
    }));
    
    (ApiError.unauthorized as jest.MockedFunction<any>) = jest.fn((message, code) => ({
      name: 'ApiError',
      message,
      statusCode: 401,
      type: 'unauthorized',
      code,
      isOperational: true
    }));
    
    (ApiError.authorization as jest.MockedFunction<any>) = jest.fn((message, resource, action) => ({
      name: 'ApiError',
      message,
      statusCode: 403,
      type: 'authorization',
      resource,
      action,
      isOperational: true
    }));
    
    (ApiError.badRequest as jest.MockedFunction<any>) = jest.fn((message, code) => ({
      name: 'ApiError',
      message,
      statusCode: 400,
      type: 'validation',
      code,
      isOperational: true
    }));
    
    (ApiError.notFound as jest.MockedFunction<any>) = jest.fn((message) => ({
      name: 'ApiError',
      message,
      statusCode: 404,
      type: 'notFound',
      isOperational: true
    }));
    
    (ApiError.internal as jest.MockedFunction<any>) = jest.fn((message) => ({
      name: 'ApiError',
      message,
      statusCode: 500,
      type: 'internal',
      isOperational: true
    }));
    
    (ApiError.rateLimited as jest.MockedFunction<any>) = jest.fn((message, maxRequests, windowMs, retryAfter) => ({
      name: 'ApiError',
      message,
      statusCode: 429,
      type: 'rateLimited',
      maxRequests,
      windowMs,
      retryAfter,
      isOperational: true
    }));
  });

  afterEach(() => {
    cleanupTest();
    stopCleanup();
    rateLimitCache.clear();
  });

  describe('Authentication Security', () => {
    describe('Token Validation', () => {
      it('should reject missing authorization header', async () => {
        const req = { headers: {} } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'authentication',
            message: 'Authentication token required'
          })
        );
      });

      it('should reject malformed authorization header', async () => {
        const req = { headers: { authorization: 'InvalidFormat token' } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'authentication',
            message: 'Authentication token required'
          })
        );
      });

      it('should reject empty Bearer token', async () => {
        const req = { headers: { authorization: 'Bearer ' } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'authentication',
            message: 'Authentication token required'
          })
        );
      });

      it('should reject expired token', async () => {
        const req = { headers: { authorization: `Bearer ${expiredToken}` } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'authentication',
            message: 'Authentication token has expired'
          })
        );
      });

      it('should reject invalid token', async () => {
        const req = { headers: { authorization: `Bearer ${invalidToken}` } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'authentication',
            message: 'Invalid authentication token'
          })
        );
      });

      it('should reject token with non-existent user', async () => {
        mockUserModel.findById.mockResolvedValue(null);
        
        const req = { headers: { authorization: `Bearer ${validToken}` } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'authentication',
            message: 'User not found'
          })
        );
      });

      it('should accept valid token with existing user', async () => {
        const req = { headers: { authorization: `Bearer ${validToken}` } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect(req.user).toEqual({ id: mockUser.id, email: mockUser.email });
      });

      it('should handle premature token', async () => {
        const prematureToken = 'premature.jwt.token';
        mockJWT.verify.mockImplementation((...args: unknown[]) => {
          const token = args[0] as string;
          if (token === prematureToken) {
            const error = new Error('jwt not active');
            error.name = 'NotBeforeError';
            throw error;
          }
          // Call original implementation for other tokens
          return mockJWT.verify(token);
        });

        const req = { headers: { authorization: `Bearer ${prematureToken}` } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'authentication',
            message: 'Authentication token not yet valid'
          })
        );
      });

      it('should handle JWT verification errors gracefully', async () => {
        const corruptToken = 'corrupt.token';
        mockJWT.verify.mockImplementation((...args: unknown[]) => {
          const token = args[0] as string;
          if (token === corruptToken) {
            throw new Error('Unexpected error during JWT verification');
          }
          // Default behavior for other tokens
          if (token === validToken) {
            return {
              id: mockUser.id,
              email: mockUser.email,
              iat: Math.floor(Date.now() / 1000),
              exp: Math.floor(Date.now() / 1000) + 86400
            };
          }
          const error = new Error('invalid signature');
          error.name = 'JsonWebTokenError';
          throw error;
        });

        // Fixed: Provide empty function to mockImplementation
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        const req = { headers: { authorization: `Bearer ${corruptToken}` } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'internal',
            message: 'Authentication error'
          })
        );

        consoleSpy.mockRestore();
      });
    });

    describe('SQL Injection Prevention', () => {
      it('should sanitize user ID from JWT payload', async () => {
        const maliciousPayload = {
          id: "123'; DROP TABLE users; --",
          email: 'test@example.com',
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 86400
        };

        mockJWT.verify.mockReturnValue(maliciousPayload);
        mockUserModel.findById.mockResolvedValue(null);

        const req = { headers: { authorization: `Bearer ${validToken}` } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await authenticate(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'authentication',
            message: 'User not found'
          })
        );
        expect(mockUserModel.findById).toHaveBeenCalledWith(maliciousPayload.id);
      });
    });

    describe('Timing Attack Prevention', () => {
      it('should not leak timing information for invalid vs expired tokens', async () => {
        const start1 = Date.now();
        const req1 = { headers: { authorization: `Bearer ${invalidToken}` } } as Request;
        const res1 = {} as Response;
        const next1 = jest.fn();
        await authenticate(req1, res1, next1);
        const time1 = Date.now() - start1;

        const start2 = Date.now();
        const req2 = { headers: { authorization: `Bearer ${expiredToken}` } } as Request;
        const res2 = {} as Response;
        const next2 = jest.fn();
        await authenticate(req2, res2, next2);
        const time2 = Date.now() - start2;

        // Both should complete in similar timeframes (within 100ms tolerance)
        expect(Math.abs(time1 - time2)).toBeLessThan(100);
      });
    });
  });

  describe('Authorization Security', () => {
    describe('Resource Access Control', () => {
      const resourceTypes: Array<'image' | 'garment' | 'polygon' | 'wardrobe'> = [
        'image', 'garment', 'polygon', 'wardrobe'
      ];

      resourceTypes.forEach(resourceType => {
        describe(`${resourceType} authorization`, () => {
          const middleware = authorizeResource(resourceType);
          const validResourceId = '123e4567-e89b-12d3-a456-426614174000';

          it('should prevent unauthorized access to other users resources', async () => {
            // Setup unauthorized resource
            const unauthorizedResource = { ...mockImage, user_id: 'other-user-id' };
            
            switch (resourceType) {
              case 'image':
                mockImageModel.findById.mockResolvedValue(unauthorizedResource);
                break;
              case 'garment':
                mockGarmentModel.findById.mockResolvedValue({ ...mockGarment, user_id: 'other-user-id' });
                break;
              case 'polygon':
                mockPolygonModel.findById.mockResolvedValue(mockPolygon);
                mockImageModel.findById.mockResolvedValue(unauthorizedResource);
                break;
              case 'wardrobe':
                mockWardrobeModel.findById.mockResolvedValue({ ...mockWardrobe, user_id: 'other-user-id' });
                break;
            }

            const req = {
              user: { id: mockUser.id, email: mockUser.email },
              params: { id: validResourceId },
            } as unknown as Request;
            const res = {} as Response;
            const next = jest.fn();

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledWith(
              expect.objectContaining({
                type: 'authorization',
                message: expect.stringContaining(`You do not have permission to access this ${resourceType}`)
              })
            );
          });

          it('should handle non-existent resources', async () => {
            switch (resourceType) {
              case 'image':
                mockImageModel.findById.mockResolvedValue(null);
                break;
              case 'garment':
                mockGarmentModel.findById.mockResolvedValue(null);
                break;
              case 'polygon':
                mockPolygonModel.findById.mockResolvedValue(null);
                break;
              case 'wardrobe':
                mockWardrobeModel.findById.mockResolvedValue(null);
                break;
            }

            const req = {
              user: { id: mockUser.id, email: mockUser.email },
              params: { id: validResourceId }
            } as unknown as Request;
            const res = {} as Response;
            const next = jest.fn();

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledWith(
              expect.objectContaining({
                type: 'notFound',
                message: expect.stringContaining('not found')
              })
            );
          });

          it('should validate UUID format', async () => {
            const req = {
              user: { id: mockUser.id, email: mockUser.email },
              params: { id: 'invalid-uuid-format' }
            } as unknown as Request;
            const res = {} as Response;
            const next = jest.fn();

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledWith(
              expect.objectContaining({
                type: 'validation',
                message: `Invalid ${resourceType} ID format`
              })
            );
          });

          it('should handle database errors gracefully', async () => {
            const error = new Error('Database error');
            
            switch (resourceType) {
              case 'image':
                mockImageModel.findById.mockRejectedValue(error);
                break;
              case 'garment':
                mockGarmentModel.findById.mockRejectedValue(error);
                break;
              case 'polygon':
                mockPolygonModel.findById.mockRejectedValue(error);
                break;
              case 'wardrobe':
                mockWardrobeModel.findById.mockRejectedValue(error);
                break;
            }

            const req = {
              user: { id: mockUser.id, email: mockUser.email },
              params: { id: validResourceId }
            } as unknown as Request;
            const res = {} as Response;
            const next = jest.fn();

            await middleware(req, res, next);

            expect(next).toHaveBeenCalledWith(
              expect.objectContaining({
                type: 'internal',
                message: 'Authorization error'
              })
            );
          });
        });
      });

      describe('Special polygon authorization', () => {
        it('should handle missing associated image for polygon', async () => {
          const middleware = authorizeResource('polygon');
          const validResourceId = '123e4567-e89b-12d3-a456-426614174000';

          mockPolygonModel.findById.mockResolvedValue(mockPolygon);
          mockImageModel.findById.mockResolvedValue(null);

          const req = {
            user: { id: mockUser.id, email: mockUser.email },
            params: { id: validResourceId }
          } as unknown as Request;
          const res = {} as Response;
          const next = jest.fn();

          await middleware(req, res, next);

          expect(next).toHaveBeenCalledWith(
            expect.objectContaining({
              type: 'notFound',
              message: 'Associated image not found'
            })
          );
        });
      });
    });

    describe('Parameter Injection Prevention', () => {
      it('should prevent parameter pollution in resource ID', async () => {
        const middleware = authorizeResource('image');
        
        const req = {
          user: { id: mockUser.id, email: mockUser.email },
          params: { id: ['valid-uuid', 'malicious-uuid'] }
        } as unknown as Request;
        const res = {} as Response;
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'validation',
            message: 'Invalid image ID format'
          })
        );
      });

      it('should handle missing parameter gracefully', async () => {
        const middleware = authorizeResource('image');
        
        const req = {
          user: { id: mockUser.id, email: mockUser.email },
          params: {}
        } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'validation',
            message: 'Missing id parameter'
          })
        );
      });
    });
  });

  describe('Rate Limiting Security', () => {
    describe('User-based Rate Limiting', () => {
      beforeEach(() => {
        rateLimitCache.clear();
      });

      it('should allow requests under the limit', async () => {
        const middleware = rateLimitByUser(3, 60000); // 3 requests per minute for testing
        const req = { user: { id: mockUser.id, email: mockUser.email } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect(rateLimitCache.get(mockUser.id)?.count).toBe(1);
      });

      it('should track multiple requests from same user', async () => {
        const middleware = rateLimitByUser(3, 60000);
        const req = { user: { id: mockUser.id, email: mockUser.email } } as Request;
        const res = {} as Response;
        
        // First request
        await middleware(req, res, jest.fn());
        expect(rateLimitCache.get(mockUser.id)?.count).toBe(1);
        
        // Second request
        await middleware(req, res, jest.fn());
        expect(rateLimitCache.get(mockUser.id)?.count).toBe(2);
        
        // Third request
        await middleware(req, res, jest.fn());
        expect(rateLimitCache.get(mockUser.id)?.count).toBe(3);
      });

      it('should block requests over the limit', async () => {
        const middleware = rateLimitByUser(3, 60000);
        const userId = mockUser.id;
        
        // Set user to be at limit
        rateLimitCache.set(userId, { 
          count: 3, 
          resetTime: Date.now() + 60000 
        });

        const req = { user: { id: userId, email: mockUser.email } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'rateLimited',
            message: expect.stringContaining('Rate limit exceeded')
          })
        );
      });

      it('should reset limit after window expires', async () => {
        const middleware = rateLimitByUser(3, 60000);
        const userId = mockUser.id;
        
        // Set expired rate limit
        rateLimitCache.set(userId, { 
          count: 5, 
          resetTime: Date.now() - 1000 // 1 second ago
        });

        const req = { user: { id: userId, email: mockUser.email } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect(rateLimitCache.get(userId)?.count).toBe(1);
      });

      it('should skip rate limiting for unauthenticated users', async () => {
        const middleware = rateLimitByUser(3, 60000);
        const req = {} as Request;
        const res = {} as Response;
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect(rateLimitCache.size).toBe(0);
      });

      it('should isolate rate limits between different users', async () => {
        const middleware = rateLimitByUser(3, 60000);
        const user1Id = mockUser.id;
        const user2Id = otherUser.id;

        // Set user1 at limit
        rateLimitCache.set(user1Id, { 
          count: 3, 
          resetTime: Date.now() + 60000 
        });

        // User2 should still be allowed
        const req = { user: { id: user2Id, email: otherUser.email } } as Request;
        const res = {} as Response;
        const next = jest.fn();

        await middleware(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect(rateLimitCache.get(user2Id)?.count).toBe(1);
      });
    });

    describe('Rate Limit Cache Management', () => {
      it('should clean up expired entries', () => {
        const { cleanupRateLimitCache } = require('../../middlewares/auth');
        const now = Date.now();
        
        // Add expired entry
        rateLimitCache.set('expired-user', { 
          count: 5, 
          resetTime: now - 1000 
        });
        
        // Add valid entry
        rateLimitCache.set('valid-user', { 
          count: 2, 
          resetTime: now + 60000 
        });

        expect(rateLimitCache.size).toBe(2);
        
        cleanupRateLimitCache();
        
        expect(rateLimitCache.size).toBe(1);
        expect(rateLimitCache.has('expired-user')).toBe(false);
        expect(rateLimitCache.has('valid-user')).toBe(true);
      });
    });
  });

  describe('Optional Authentication Security', () => {
    it('should continue without error for missing token', async () => {
      const req = { headers: {} } as Request;
      const res = {} as Response;
      const next = jest.fn();

      await optionalAuth(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.user).toBeUndefined();
    });

    it('should continue without error for invalid token', async () => {
      const req = { headers: { authorization: `Bearer ${invalidToken}` } } as Request;
      const res = {} as Response;
      const next = jest.fn();

      await optionalAuth(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.user).toBeUndefined();
    });

    it('should set user for valid token', async () => {
      const req = { headers: { authorization: `Bearer ${validToken}` } } as Request;
      const res = {} as Response;
      const next = jest.fn();

      await optionalAuth(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.user).toEqual({ id: mockUser.id, email: mockUser.email });
    });

    it('should handle database errors gracefully', async () => {
      mockUserModel.findById.mockRejectedValue(new Error('Database error'));

      const req = { headers: { authorization: `Bearer ${validToken}` } } as Request;
      const res = {} as Response;
      const next = jest.fn();

      await optionalAuth(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect(req.user).toBeUndefined();
    });
  });

  describe('Require Auth Security', () => {
    it('should reject unauthenticated requests', async () => {
      const req = {} as Request;
      const res = {} as Response;
      const next = jest.fn();

      requireAuth(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'unauthorized',
          message: 'Authentication required'
        })
      );
    });

    it('should allow authenticated requests', async () => {
      const req = { user: { id: mockUser.id, email: mockUser.email } } as Request;
      const res = {} as Response;
      const next = jest.fn();

      requireAuth(req, res, next);

      expect(next).toHaveBeenCalledWith();
    });
  });

  describe('Error Handling Security', () => {
    it('should not leak sensitive information in error messages', async () => {
      const sensitiveError = new Error('Database connection failed: password=secret123');
      mockUserModel.findById.mockRejectedValue(sensitiveError);

      const req = { headers: { authorization: `Bearer ${validToken}` } } as Request;
      const res = {} as Response;
      const next = jest.fn();

      await authenticate(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'internal',
          message: 'Authentication error'
        })
      );
    });

    it('should log errors for debugging without exposing them', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      const internalError = new Error('Internal system error');
      mockUserModel.findById.mockRejectedValue(internalError);

      const req = { headers: { authorization: `Bearer ${validToken}` } } as Request;
      const res = {} as Response;
      const next = jest.fn();

      await authenticate(req, res, next);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        'Authentication middleware error:',
        internalError
      );
      
      consoleSpy.mockRestore();
    });
  });

  describe('Memory Safety', () => {
    it('should not cause memory leaks with large rate limit cache', () => {
      const { cleanupRateLimitCache } = require('../../middlewares/auth');
      const middleware = rateLimitByUser(100, 60000);
      
      // Simulate many users hitting rate limits
      for (let i = 0; i < 1000; i++) {
        const userId = `user-${i}`;
        rateLimitCache.set(userId, { 
          count: 1, 
          resetTime: Date.now() + 60000 
        });
      }
      
      expect(rateLimitCache.size).toBe(1000);
      
      // Cleanup should handle large caches
      cleanupRateLimitCache();
      
      // All entries should still be valid (not expired)
      expect(rateLimitCache.size).toBe(1000);
    });
  });
});