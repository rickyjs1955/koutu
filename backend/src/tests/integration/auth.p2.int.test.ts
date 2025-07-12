// backend/src/tests/integration/auth.p2.int.test.ts - Part 2: Mobile/Flutter Integration Tests
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
  jwtSecret: 'test-integration-secret-key',
  jwtExpiresIn: '1h'
} as any;

// Mock database models with more realistic behavior
const mockUserModel = {
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
jest.mock('../../models/imageModel', () => ({ imageModel: { findById: jest.fn() } }));
jest.mock('../../models/garmentModel', () => ({ garmentModel: { findById: jest.fn() } }));
jest.mock('../../models/polygonModel', () => ({ polygonModel: { findById: jest.fn() } }));
jest.mock('../../models/wardrobeModel', () => ({ wardrobeModel: { findById: jest.fn() } }));

// Import middleware after mocking
import {
  authenticate,
  generateRefreshToken,
  refreshAccessToken,
  revokeRefreshToken,
  rateLimitByUser,
  rateLimitCache,
  refreshTokenCache
} from '../../middlewares/auth';

// Test data
const testUser = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  email: 'flutter@test.com',
  password: 'hashedPassword',
  created_at: new Date(),
  updated_at: new Date()
};

const flutterAndroidHeaders = {
  'user-agent': 'Dart/2.19 (dart:io)',
  'x-platform': 'android',
  'x-app-version': '1.0.0',
  'x-device-id': 'android-device-123'
};

const flutterIOSHeaders = {
  'user-agent': 'Flutter/iOS Dart/2.19',
  'x-platform': 'ios',
  'x-app-version': '1.0.0',
  'x-device-id': 'ios-device-456'
};

const webHeaders = {
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
};

const validAccessToken = 'valid.flutter.access.token';

const mockJwtPayload = {
  id: testUser.id,
  email: testUser.email,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  lastRefresh: Math.floor(Date.now() / 1000)
};

describe('Auth P2 Integration Tests - Mobile/Flutter Enhancements', () => {
  let app: express.Application;

  beforeAll(() => {
    // Create Express app for integration testing
    app = express();
    app.use(express.json());
  });

  beforeEach(() => {
    jest.clearAllMocks();
    rateLimitCache.clear();
    refreshTokenCache.clear();

    // Recreate app for each test to ensure clean state
    app = express();
    app.use(express.json());

    // Add error handling middleware after routes are defined
    const setupErrorHandler = () => {
      app.use((error: any, req: Request, res: Response, next: NextFunction) => {
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
      if (token === validAccessToken) {
        return mockJwtPayload;
      }
      if (token.startsWith('refresh.')) {
        const parts = token.split('.');
        return {
          userId: parts[1],
          deviceId: parts[2] !== 'undefined' ? parts[2] : undefined,
          type: 'refresh',
          iat: parseInt(parts[3]) || Math.floor(Date.now() / 1000)
        };
      }
      const error = new Error('invalid token');
      error.name = 'JsonWebTokenError';
      throw error;
    });

    let tokenCounter = 0;
    mockJWT.sign.mockImplementation((payload: any, secret: string, options?: any) => {
      if (payload.type === 'refresh') {
        tokenCounter++;
        return `refresh.${payload.userId}.${payload.deviceId || 'undefined'}.${payload.iat}.${tokenCounter}`;
      }
      return 'new.flutter.access.token';
    });

    // Setup default model responses
    mockUserModel.findById.mockResolvedValue(testUser);

    // Setup routes and error handler for each test section
    (app as any).setupErrorHandler = setupErrorHandler;
  });

  afterEach(() => {
    rateLimitCache.clear();
    refreshTokenCache.clear();
  });

  describe('Flutter Device Detection Integration', () => {
    beforeEach(() => {
      // Setup test routes
      app.get('/flutter-auth-test', authenticate, (req: Request, res: Response) => {
        res.json({ 
          user: req.user,
          deviceDetected: !!req.user.deviceInfo,
          platform: req.user.deviceInfo?.platform
        });
      });

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should detect Flutter Android app and enhance authentication', async () => {
      const response = await request(app)
        .get('/flutter-auth-test')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(flutterAndroidHeaders)
        .expect(200);

      expect(response.body).toEqual({
        user: {
          id: testUser.id,
          email: testUser.email,
          deviceInfo: {
            platform: 'android',
            version: '1.0.0',
            deviceId: 'android-device-123'
          },
          lastRefresh: expect.any(Number)
        },
        deviceDetected: true,
        platform: 'android'
      });
    });

    it('should detect Flutter iOS app and enhance authentication', async () => {
      const response = await request(app)
        .get('/flutter-auth-test')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(flutterIOSHeaders)
        .expect(200);

      expect(response.body).toEqual({
        user: {
          id: testUser.id,
          email: testUser.email,
          deviceInfo: {
            platform: 'ios',
            version: '1.0.0',
            deviceId: 'ios-device-456'
          },
          lastRefresh: expect.any(Number)
        },
        deviceDetected: true,
        platform: 'ios'
      });
    });

    it('should handle web requests without device enhancement', async () => {
      const response = await request(app)
        .get('/flutter-auth-test')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(webHeaders)
        .expect(200);

      expect(response.body).toEqual({
        user: {
          id: testUser.id,
          email: testUser.email,
          deviceInfo: undefined,
          lastRefresh: expect.any(Number)
        },
        deviceDetected: false,
        platform: undefined
      });
    });

    it('should detect Flutter by user agent when x-platform header is missing', async () => {
      const response = await request(app)
        .get('/flutter-auth-test')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set('User-Agent', 'Dart/2.19 (dart:io) Android')
        .expect(200);

      expect(response.body.user.deviceInfo).toMatchObject({
        platform: 'android'
      });
    });
  });

  describe('Token Refresh Integration', () => {
    beforeEach(() => {
      // Setup refresh endpoint
      app.post('/auth/refresh', refreshAccessToken);
      app.post('/auth/logout', revokeRefreshToken);

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should refresh tokens for Flutter Android app', async () => {
      // Generate a refresh token first
      const refreshToken = generateRefreshToken(testUser.id, 'android-device-123');

      const response = await request(app)
        .post('/auth/refresh')
        .set(flutterAndroidHeaders)
        .send({ refreshToken })
        .expect(200);

      expect(response.body).toEqual({
        accessToken: 'new.flutter.access.token',
        refreshToken: expect.any(String),
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      // New refresh token should be different (rotated for mobile)
      expect(response.body.refreshToken).not.toBe(refreshToken);

      // Original token should be revoked
      const originalTokenData = refreshTokenCache.get(refreshToken);
      expect(originalTokenData?.isRevoked).toBe(true);
    });

    it('should refresh tokens for Flutter iOS app', async () => {
      const refreshToken = generateRefreshToken(testUser.id, 'ios-device-456');

      const response = await request(app)
        .post('/auth/refresh')
        .set(flutterIOSHeaders)
        .send({ refreshToken })
        .expect(200);

      expect(response.body).toEqual({
        accessToken: 'new.flutter.access.token',
        refreshToken: expect.any(String),
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      // Token should be rotated for iOS as well
      expect(response.body.refreshToken).not.toBe(refreshToken);
    });

    it('should not rotate refresh token for web platforms', async () => {
      const refreshToken = generateRefreshToken(testUser.id); // No device ID

      const response = await request(app)
        .post('/auth/refresh')
        .set(webHeaders)
        .send({ refreshToken })
        .expect(200);

      // Should return the same refresh token for web
      expect(response.body.refreshToken).toBe(refreshToken);

      // Original token should not be revoked for web
      const originalTokenData = refreshTokenCache.get(refreshToken);
      expect(originalTokenData?.isRevoked).toBe(false);
    });

    it('should reject invalid refresh token', async () => {
      const response = await request(app)
        .post('/auth/refresh')
        .send({ refreshToken: 'invalid.refresh.token' })
        .expect(401);

      expect(response.body.error).toEqual({
        message: 'Invalid or expired refresh token',
        type: 'authentication',
        code: 'invalid_refresh_token'
      });
    });

    it('should reject missing refresh token', async () => {
      const response = await request(app)
        .post('/auth/refresh')
        .send({})
        .expect(401);

      expect(response.body.error).toEqual({
        message: 'Refresh token required',
        type: 'authentication',
        code: 'missing_refresh_token'
      });
    });

    it('should handle user not found during refresh', async () => {
      const refreshToken = generateRefreshToken('non-existent-user', 'device-123');
      mockUserModel.findById.mockResolvedValue(null);

      const response = await request(app)
        .post('/auth/refresh')
        .send({ refreshToken })
        .expect(401);

      // For security reasons, we don't expose whether a user exists or not
      // Instead, we return a generic "Invalid or expired refresh token" error
      expect(response.body.error).toEqual({
        message: 'Invalid or expired refresh token',
        type: 'authentication',
        code: 'invalid_refresh_token'
      });
    });

    it('should revoke refresh token on logout', async () => {
      const refreshToken = generateRefreshToken(testUser.id, 'device-123');

      const response = await request(app)
        .post('/auth/logout')
        .send({ refreshToken })
        .expect(200);

      expect(response.body).toEqual({
        message: 'Token revoked successfully'
      });

      // Token should be revoked
      const tokenData = refreshTokenCache.get(refreshToken);
      expect(tokenData?.isRevoked).toBe(true);
    });

    it('should handle logout without refresh token gracefully', async () => {
      const response = await request(app)
        .post('/auth/logout')
        .send({})
        .expect(200);

      expect(response.body).toEqual({
        message: 'Token revoked successfully'
      });
    });
  });

  describe('Mobile-Aware Rate Limiting Integration', () => {
    beforeEach(() => {
      // Clear cache before each test
      rateLimitCache.clear();
      
      // Setup rate limited routes with different limits
      app.get('/api/mobile-limited', 
        authenticate, 
        rateLimitByUser(4, 1000), // 4 requests per second, mobile gets 6
        (req: Request, res: Response) => {
          res.json({ 
            message: 'Mobile endpoint accessed',
            requestCount: rateLimitCache.get(
              req.user.deviceInfo?.deviceId ? 
                `${req.user.id}:${req.user.deviceInfo.deviceId}` : 
                req.user.id
            )?.count || 0
          });
        }
      );

      app.get('/api/web-limited',
        authenticate,
        rateLimitByUser(2, 1000), // 2 requests per second, mobile gets 3
        (req: Request, res: Response) => {
          res.json({ message: 'Web endpoint accessed' });
        }
      );

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should apply higher rate limits for Flutter Android app', async () => {
      // Android should get 6 requests (4 * 1.5)
      for (let i = 1; i <= 6; i++) {
        const response = await request(app)
          .get('/api/mobile-limited')
          .set('Authorization', `Bearer ${validAccessToken}`)
          .set(flutterAndroidHeaders)
          .expect(200);

        expect(response.body.message).toBe('Mobile endpoint accessed');
        expect(response.body.requestCount).toBe(i);
      }

      // 7th request should be rate limited
      const rateLimitedResponse = await request(app)
        .get('/api/mobile-limited')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(flutterAndroidHeaders)
        .expect(429);

      expect(rateLimitedResponse.body.error.type).toBe('rateLimited');
      expect(rateLimitedResponse.body.error.message).toContain('Rate limit exceeded');
    });

    it('should apply higher rate limits for Flutter iOS app', async () => {
      // iOS should also get 6 requests (4 * 1.5)
      for (let i = 1; i <= 6; i++) {
        await request(app)
          .get('/api/mobile-limited')
          .set('Authorization', `Bearer ${validAccessToken}`)
          .set(flutterIOSHeaders)
          .expect(200);
      }

      // 7th request should be rate limited
      await request(app)
        .get('/api/mobile-limited')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(flutterIOSHeaders)
        .expect(429);
    });

    it('should apply standard rate limits for web requests', async () => {
      // Web should get 4 requests (no boost)
      for (let i = 1; i <= 4; i++) {
        await request(app)
          .get('/api/mobile-limited')
          .set('Authorization', `Bearer ${validAccessToken}`)
          .set(webHeaders)
          .expect(200);
      }

      // 5th request should be rate limited
      await request(app)
        .get('/api/mobile-limited')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(webHeaders)
        .expect(429);
    });

    it('should track rate limits separately per device', async () => {
      const androidHeaders = { ...flutterAndroidHeaders, 'x-device-id': 'android-device-1' };
      const iosHeaders = { ...flutterIOSHeaders, 'x-device-id': 'ios-device-1' };

      // Both devices should be able to make requests independently
      await request(app)
        .get('/api/web-limited')  // 2 base limit, mobile gets 3
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(androidHeaders)
        .expect(200);

      await request(app)
        .get('/api/web-limited')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(iosHeaders)
        .expect(200);

      // Each device should have its own rate limit counter
      expect(rateLimitCache.has(`${testUser.id}:android-device-1`)).toBe(true);
      expect(rateLimitCache.has(`${testUser.id}:ios-device-1`)).toBe(true);
    });

    it('should reset rate limits after window expires', async () => {
      jest.useFakeTimers();

      // Make requests up to limit
      for (let i = 1; i <= 6; i++) {
        await request(app)
          .get('/api/mobile-limited')
          .set('Authorization', `Bearer ${validAccessToken}`)
          .set(flutterAndroidHeaders)
          .expect(200);
      }

      // Next request should be rate limited
      await request(app)
        .get('/api/mobile-limited')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(flutterAndroidHeaders)
        .expect(429);

      // Advance time to expire the window
      jest.advanceTimersByTime(1100);

      // Should be able to make requests again
      await request(app)
        .get('/api/mobile-limited')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(flutterAndroidHeaders)
        .expect(200);

      jest.useRealTimers();
    });
  });

  describe('Complete Flutter App Workflow Integration', () => {
    beforeEach(() => {
      // Clear caches
      rateLimitCache.clear();
      refreshTokenCache.clear();
      
      // Setup a complete Flutter app workflow
      app.post('/auth/refresh', refreshAccessToken);
      app.post('/auth/logout', revokeRefreshToken);
      
      app.get('/api/flutter-profile',
        authenticate,
        rateLimitByUser(10, 60000),
        (req: Request, res: Response) => {
          res.json({
            profile: {
              id: req.user.id,
              email: req.user.email,
              device: req.user.deviceInfo
            },
            metadata: {
              platform: req.user.deviceInfo?.platform || 'unknown',
              isFlutterApp: !!req.user.deviceInfo,
              lastRefresh: req.user.lastRefresh
            }
          });
        }
      );

      // Add error handler after routes
      (app as any).setupErrorHandler();
    });

    it('should complete full Flutter app authentication workflow', async () => {
      // Step 1: Access protected resource with Flutter app
      const profileResponse = await request(app)
        .get('/api/flutter-profile')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(flutterAndroidHeaders)
        .expect(200);

      expect(profileResponse.body).toEqual({
        profile: {
          id: testUser.id,
          email: testUser.email,
          device: {
            platform: 'android',
            version: '1.0.0',
            deviceId: 'android-device-123'
          }
        },
        metadata: {
          platform: 'android',
          isFlutterApp: true,
          lastRefresh: expect.any(Number)
        }
      });

      // Step 2: Refresh token
      const refreshToken = generateRefreshToken(testUser.id, 'android-device-123');
      
      const refreshResponse = await request(app)
        .post('/auth/refresh')
        .set(flutterAndroidHeaders)
        .send({ refreshToken })
        .expect(200);

      expect(refreshResponse.body).toMatchObject({
        accessToken: expect.any(String),
        refreshToken: expect.any(String),
        expiresIn: 3600,
        tokenType: 'Bearer'
      });

      // Step 3: Logout (revoke tokens)
      const logoutResponse = await request(app)
        .post('/auth/logout')
        .send({ refreshToken: refreshResponse.body.refreshToken })
        .expect(200);

      expect(logoutResponse.body).toEqual({
        message: 'Token revoked successfully'
      });

      // Verify token is revoked
      const revokedTokenData = refreshTokenCache.get(refreshResponse.body.refreshToken);
      expect(revokedTokenData?.isRevoked).toBe(true);
    });

    it('should handle token expiration and refresh seamlessly for Flutter', async () => {
      // Setup an expired access token scenario
      mockJWT.verify.mockImplementation((token: string) => {
        if (token === 'expired.access.token') {
          const error = new Error('jwt expired');
          error.name = 'TokenExpiredError';
          throw error;
        }
        if (token.startsWith('refresh.')) {
          const parts = token.split('.');
          return {
            userId: parts[1],
            deviceId: parts[2] !== 'undefined' ? parts[2] : undefined,
            type: 'refresh',
            iat: Math.floor(Date.now() / 1000)
          };
        }
        return mockJwtPayload;
      });

      // Try to access protected resource with expired token
      const expiredResponse = await request(app)
        .get('/api/flutter-profile')
        .set('Authorization', 'Bearer expired.access.token')
        .set(flutterAndroidHeaders)
        .expect(401);

      expect(expiredResponse.body.error).toEqual({
        message: 'Authentication token has expired',
        type: 'authentication',
        code: 'expired_token'
      });

      // Refresh the token
      const refreshToken = generateRefreshToken(testUser.id, 'android-device-123');
      
      const refreshResponse = await request(app)
        .post('/auth/refresh')
        .set(flutterAndroidHeaders)
        .send({ refreshToken })
        .expect(200);

      // Should now be able to access the resource with new token
      mockJWT.verify.mockImplementation((token: string) => {
        if (token === refreshResponse.body.accessToken) {
          return mockJwtPayload;
        }
        return mockJwtPayload;
      });

      const successResponse = await request(app)
        .get('/api/flutter-profile')
        .set('Authorization', `Bearer ${refreshResponse.body.accessToken}`)
        .set(flutterAndroidHeaders)
        .expect(200);

      expect(successResponse.body.metadata.isFlutterApp).toBe(true);
    });

    it('should handle multiple Flutter devices for same user', async () => {
      const device1Headers = { ...flutterAndroidHeaders, 'x-device-id': 'android-device-1' };
      const device2Headers = { ...flutterIOSHeaders, 'x-device-id': 'ios-device-2' };

      // Generate separate refresh tokens for each device
      const refreshToken1 = generateRefreshToken(testUser.id, 'android-device-1');
      const refreshToken2 = generateRefreshToken(testUser.id, 'ios-device-2');

      // Both devices should be able to access resources independently
      await request(app)
        .get('/api/flutter-profile')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(device1Headers)
        .expect(200);

      await request(app)
        .get('/api/flutter-profile')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(device2Headers)
        .expect(200);

      // Both devices should be able to refresh tokens independently
      const refresh1Response = await request(app)
        .post('/auth/refresh')
        .set(device1Headers)
        .send({ refreshToken: refreshToken1 })
        .expect(200);

      const refresh2Response = await request(app)
        .post('/auth/refresh')
        .set(device2Headers)
        .send({ refreshToken: refreshToken2 })
        .expect(200);

      // Tokens should be different
      expect(refresh1Response.body.refreshToken).not.toBe(refresh2Response.body.refreshToken);

      // Logout one device shouldn't affect the other
      await request(app)
        .post('/auth/logout')
        .send({ refreshToken: refresh1Response.body.refreshToken })
        .expect(200);

      // Device 2 should still be able to refresh
      await request(app)
        .post('/auth/refresh')
        .set(device2Headers)
        .send({ refreshToken: refresh2Response.body.refreshToken })
        .expect(200);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    beforeEach(() => {
      app.post('/auth/refresh', refreshAccessToken);
      app.get('/test-auth', authenticate, (req: Request, res: Response) => {
        res.json({ authenticated: true });
      });

      (app as any).setupErrorHandler();
    });

    it('should handle malformed Flutter headers gracefully', async () => {
      const response = await request(app)
        .get('/test-auth')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set('x-platform', 'invalid-platform')
        .set('x-device-id', '') // Empty device ID
        .expect(200);

      // Should still authenticate successfully
      expect(response.body.authenticated).toBe(true);
    });

    it('should handle database errors during refresh as authentication errors', async () => {     
      const refreshToken = generateRefreshToken(testUser.id, 'device-123');
      
      // Create a database error that occurs during user lookup
      const dbError = new Error('Database connection failed');
      dbError.name = 'DatabaseError';
      mockUserModel.findById.mockRejectedValue(dbError);

      const response = await request(app)
        .post('/auth/refresh')
        .send({ refreshToken })
        .expect(401); // The middleware converts database errors to 401

      expect(response.body.error).toEqual({
        message: 'Invalid refresh token',
        type: 'authentication',
        code: 'invalid_refresh_token'
      });
    });

    it('should handle concurrent refresh requests gracefully', async () => {
      const refreshToken = generateRefreshToken(testUser.id, 'device-123');

      // Make two concurrent refresh requests
      const [response1, response2] = await Promise.all([
        request(app).post('/auth/refresh').send({ refreshToken }),
        request(app).post('/auth/refresh').send({ refreshToken })
      ]);

      // First request should succeed
      expect(response1.status).toBe(200);
      
      // Second request might succeed or fail depending on timing
      // but should not cause server errors
      expect([200, 401].includes(response2.status)).toBe(true);
    });

    it('should handle very long device IDs appropriately', async () => {
      const longDeviceId = 'a'.repeat(1000); // Very long device ID
      const headers = { 
        ...flutterAndroidHeaders, 
        'x-device-id': longDeviceId 
      };

      // Should still work with long device ID
      const response = await request(app)
        .get('/test-auth')
        .set('Authorization', `Bearer ${validAccessToken}`)
        .set(headers)
        .expect(200);

      expect(response.body.authenticated).toBe(true);
    });
  });

  describe('Performance and Load Testing', () => {
    beforeEach(() => {
      rateLimitCache.clear();
      refreshTokenCache.clear();

      app.get('/perf-test', 
        authenticate, 
        rateLimitByUser(1000, 60000), // High limit for performance testing
        (req: Request, res: Response) => {
          res.json({ success: true });
        }
      );

      (app as any).setupErrorHandler();
    });

    it('should handle many concurrent Flutter authentication requests', async () => {
      const concurrentRequests = 50;
      const requests = Array.from({ length: concurrentRequests }, (_, i) => 
        request(app)
          .get('/perf-test')
          .set('Authorization', `Bearer ${validAccessToken}`)
          .set({ ...flutterAndroidHeaders, 'x-device-id': `device-${i}` })
      );

      const responses = await Promise.all(requests);
      
      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });
    });

    it('should handle rapid refresh token operations', async () => {
      const refreshTokens: string[] = [];
      
      // Generate many refresh tokens
      for (let i = 0; i < 100; i++) {
        refreshTokens.push(generateRefreshToken(testUser.id, `device-${i}`));
      }

      expect(refreshTokenCache.size).toBe(100);

      // Cleanup should handle large cache efficiently
      const { cleanupRefreshTokens } = require('../../middlewares/auth');
      const startTime = Date.now();
      cleanupRefreshTokens();
      const endTime = Date.now();

      // Cleanup should be fast (under 100ms for 100 tokens)
      expect(endTime - startTime).toBeLessThan(100);
    });
  });
});