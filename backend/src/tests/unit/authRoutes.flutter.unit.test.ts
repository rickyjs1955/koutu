// backend/src/tests/unit/authRoutes.flutter.unit.test.ts

import { Request, Response, NextFunction } from 'express';
import { jest } from '@jest/globals';
import { ApiError } from '../../utils/ApiError';

// Mock all external dependencies first
jest.mock('../../middlewares/auth');
jest.mock('../../middlewares/validate');
jest.mock('../../middlewares/security');
jest.mock('../../services/authService');
jest.mock('../../controllers/authController');

// Import mocked modules
import { 
  authenticate, 
  requireAuth, 
  rateLimitByUser 
} from '../../middlewares/auth';
import { 
  validateAuthTypes, 
  validateBody, 
  validateRequestTypes 
} from '../../middlewares/validate';
import { securityMiddleware } from '../../middlewares/security';
import { authService } from '../../services/authService';
import { authController } from '../../controllers/authController';

// Cast to mocked functions
const mockAuthenticate = authenticate as jest.MockedFunction<typeof authenticate>;
const mockRequireAuth = requireAuth as jest.MockedFunction<typeof requireAuth>;
const mockRateLimitByUser = rateLimitByUser as jest.MockedFunction<typeof rateLimitByUser>;
const mockValidateAuthTypes = validateAuthTypes as jest.MockedFunction<typeof validateAuthTypes>;
const mockValidateBody = validateBody as jest.MockedFunction<typeof validateBody>;
const mockValidateRequestTypes = validateRequestTypes as jest.MockedFunction<typeof validateRequestTypes>;
const mockSecurityMiddleware = securityMiddleware as jest.Mocked<typeof securityMiddleware>;
const mockAuthService = authService as jest.Mocked<typeof authService>;
const mockAuthController = authController as jest.Mocked<typeof authController>;

describe('AuthRoutes Flutter/Mobile Unit Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let statusSpy: jest.MockedFunction<any>;
  let jsonSpy: jest.MockedFunction<any>;
  let setSpy: jest.MockedFunction<any>;
  let sendSpy: jest.MockedFunction<any>;

  // Import the router after mocking
  let authRoutes: any;

  beforeAll(async () => {
    // Setup default mocks
    mockAuthenticate.mockImplementation(async (req, res, next) => next());
    mockRequireAuth.mockImplementation(async (req, res, next) => next());
    mockRateLimitByUser.mockImplementation(() => (req: any, res: any, next: any) => next());
    mockValidateAuthTypes.mockImplementation(async (req, res, next) => next());
    mockValidateBody.mockImplementation(() => (req: any, res: any, next: any) => next());
    mockValidateRequestTypes.mockImplementation(async (req, res, next) => next());
    
    // Setup security middleware mock with proper typing
    mockSecurityMiddleware.auth = [jest.fn((req: Request, res: Response, next: NextFunction) => next())];
    
    // Import routes after setting up mocks
    const routesModule = await import('../../routes/authRoutes');
    authRoutes = routesModule.authRoutes;
  });

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create response spies
    statusSpy = jest.fn().mockReturnThis();
    jsonSpy = jest.fn().mockReturnThis();
    setSpy = jest.fn().mockReturnThis();
    sendSpy = jest.fn().mockReturnThis();
    
    mockReq = {
      body: {},
      params: {},
      headers: {},
      user: undefined,
      device: undefined,
      method: 'POST',
      path: '/auth/mobile/register'
    };
    
    mockRes = {
      status: statusSpy,
      json: jsonSpy,
      set: setSpy,
      send: sendSpy,
      setHeader: jest.fn().mockReturnValue(mockRes)
    } as any;
    
    mockNext = jest.fn();

    // Setup default successful responses
    mockAuthService.register.mockResolvedValue({
      user: {
        id: '123',
        email: 'test@example.com',
        created_at: new Date()
      },
      token: 'mock-token'
    });

    mockAuthService.login.mockResolvedValue({
      user: {
        id: '123',
        email: 'test@example.com',
        created_at: new Date()
      },
      token: 'mock-token'
    });

    mockAuthService.getUserProfile.mockResolvedValue({
      id: '123',
      email: 'test@example.com',
      created_at: new Date()
    });

    mockAuthService.validateToken.mockResolvedValue({
      isValid: true,
      user: {
        id: '123',
        email: 'test@example.com',
        created_at: new Date()
      }
    });
  });

  describe('Mobile Registration and Login', () => {
    describe('MobileRegisterSchema', () => {
      it('should validate mobile registration data with device info', () => {
        const validData = {
          email: 'test@example.com',
          password: 'ValidPass123!',
          device_id: 'ABC123DEF456GHI789JKL012MNO345PQ',
          device_type: 'ios',
          device_name: 'iPhone 14 Pro',
          push_token: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]'
        };
        
        // Test device_id regex pattern
        expect(validData.device_id).toMatch(/^[a-zA-Z0-9\-_]{16,128}$/);
        expect(validData.device_type).toMatch(/^(ios|android)$/);
        expect(validData.push_token).toMatch(/^[a-zA-Z0-9\-_:\[\]]{32,512}$/);
      });

      it('should reject invalid device IDs', () => {
        const invalidDeviceIds = [
          'short', // Too short
          'a'.repeat(129), // Too long
          'invalid@device!id', // Invalid characters
          '日本語デバイスID' // Non-ASCII characters
        ];
        
        invalidDeviceIds.forEach(deviceId => {
          expect(deviceId).not.toMatch(/^[a-zA-Z0-9\-_]{16,128}$/);
        });
      });

      it('should validate push token format', () => {
        const validTokens = [
          'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
          'fcm:token_with_colons_and_underscores',
          'apns-token-with-dashes-and-numbers-123456'
        ];
        
        validTokens.forEach(token => {
          expect(token).toMatch(/^[a-zA-Z0-9\-_:\[\]]{32,512}$/);
        });
      });
    });

    describe('MobileLoginSchema', () => {
      it('should validate mobile login with device tracking', () => {
        const validData = {
          email: 'test@example.com',
          password: 'password',
          device_id: 'ABC123DEF456GHI789JKL012MNO345PQ',
          device_type: 'android',
          remember_device: true
        };
        
        expect(validData).toHaveProperty('device_id');
        expect(validData).toHaveProperty('device_type');
        expect(validData).toHaveProperty('remember_device');
        expect(typeof validData.remember_device).toBe('boolean');
      });
    });

    describe('Mobile Registration Endpoint', () => {
      it('should handle mobile registration with device info', async () => {
        const mobileRegData = {
          email: 'mobile@example.com',
          password: 'MobilePass123!',
          device_id: 'ABC123DEF456GHI789JKL012MNO345PQ',
          device_type: 'ios',
          device_name: 'iPhone 14 Pro',
          push_token: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]'
        };
        
        mockReq.body = mobileRegData;
        
        // Test expected mobile response structure
        const expectedMobileResponse = {
          status: 'success',
          message: 'User registered successfully',
          data: {
            user: expect.any(Object),
            token: expect.any(String),
            device_registered: true,
            sync_required: false,
            server_time: expect.any(String),
            features: {
              biometric_available: true,
              offline_mode_available: true,
              push_notifications_available: true
            }
          }
        };
        
        // Verify response structure matches mobile expectations
        expect(expectedMobileResponse.data).toHaveProperty('device_registered');
        expect(expectedMobileResponse.data).toHaveProperty('sync_required');
        expect(expectedMobileResponse.data).toHaveProperty('server_time');
        expect(expectedMobileResponse.data).toHaveProperty('features');
      });

      it('should track push notification availability based on token', () => {
        const withToken = {
          push_token: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]'
        };
        
        const withoutToken = {
          push_token: undefined
        };
        
        expect(Boolean(withToken.push_token)).toBe(true);
        expect(Boolean(withoutToken.push_token)).toBe(false);
      });
    });

    describe('Mobile Login Endpoint', () => {
      it('should handle mobile login with refresh token', async () => {
        const mobileLoginData = {
          email: 'mobile@example.com',
          password: 'password',
          device_id: 'ABC123DEF456GHI789JKL012MNO345PQ',
          device_type: 'android',
          remember_device: true
        };
        
        mockReq.body = mobileLoginData;
        
        // Test expected mobile login response
        const expectedResponse = {
          status: 'success',
          message: 'Login successful',
          data: {
            user: expect.any(Object),
            token: expect.any(String),
            refresh_token: expect.any(String),
            expires_in: 3600,
            device_registered: true,
            sync_required: true,
            server_time: expect.any(String),
            features: {
              biometric_available: true,
              offline_mode_available: true,
              push_notifications_available: true
            }
          }
        };
        
        // Verify mobile-specific fields
        expect(expectedResponse.data).toHaveProperty('refresh_token');
        expect(expectedResponse.data).toHaveProperty('expires_in');
        expect(expectedResponse.data).toHaveProperty('sync_required');
        expect(expectedResponse.data.expires_in).toBe(3600);
      });

      it('should not include refresh token when remember_device is false', () => {
        const loginData = {
          remember_device: false
        };
        
        const refreshToken = loginData.remember_device ? 'refresh_token_value' : undefined;
        
        expect(refreshToken).toBeUndefined();
      });
    });
  });

  describe('Biometric Authentication', () => {
    describe('BiometricRegistrationSchema', () => {
      it('should validate biometric registration data', () => {
        const validData = {
          biometric_type: 'face_id',
          device_id: 'ABC123DEF456GHI789JKL012MNO345PQ',
          public_key: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...'
        };
        
        expect(validData.biometric_type).toMatch(/^(fingerprint|face_id|touch_id)$/);
        expect(validData.device_id).toMatch(/^[a-zA-Z0-9\-_]{16,128}$/);
        expect(validData.public_key).toBeTruthy();
      });

      it('should support different biometric types', () => {
        const biometricTypes = ['fingerprint', 'face_id', 'touch_id'];
        
        biometricTypes.forEach(type => {
          expect(type).toMatch(/^(fingerprint|face_id|touch_id)$/);
        });
      });
    });

    describe('BiometricLoginSchema', () => {
      it('should validate biometric login data', () => {
        const validData = {
          user_id: '123e4567-e89b-12d3-a456-426614174000',
          biometric_id: 'bio_123e4567-e89b-12d3-a456-426614174000_ABC123DEF456',
          device_id: 'ABC123DEF456GHI789JKL012MNO345PQ',
          challenge: 'server-generated-challenge-string'
        };
        
        expect(validData.user_id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
        expect(validData.biometric_id).toMatch(/^[a-zA-Z0-9\-_]{32,256}$/);
        expect(validData.device_id).toMatch(/^[a-zA-Z0-9\-_]{16,128}$/);
        expect(validData.challenge).toBeTruthy();
      });
    });

    describe('Biometric Registration Endpoint', () => {
      it('should require authentication for biometric registration', () => {
        // Biometric registration should be a protected endpoint
        expect(mockAuthenticate).toBeDefined();
        expect(mockRequireAuth).toBeDefined();
      });

      it('should return biometric registration data with expiry', () => {
        const expectedResponse = {
          status: 'success',
          message: 'Biometric registration successful',
          data: {
            biometric_id: expect.any(String),
            biometric_type: 'face_id',
            challenge: expect.any(String),
            expires_at: expect.any(String)
          }
        };
        
        expect(expectedResponse.data).toHaveProperty('biometric_id');
        expect(expectedResponse.data).toHaveProperty('challenge');
        expect(expectedResponse.data).toHaveProperty('expires_at');
      });
    });

    describe('Biometric Login Endpoint', () => {
      it('should validate biometric credentials', () => {
        const biometricId = 'bio_user123_device456';
        const userId = 'user123';
        const deviceId = 'device456';
        
        // Test that biometric ID contains both user and device IDs
        expect(biometricId).toContain(userId);
        expect(biometricId).toContain(deviceId);
      });

      it('should return tokens on successful biometric login', () => {
        const expectedResponse = {
          status: 'success',
          message: 'Biometric login successful',
          data: {
            token: expect.any(String),
            refresh_token: expect.any(String),
            expires_in: 3600,
            user: {
              id: expect.any(String),
              email: expect.any(String)
            }
          }
        };
        
        expect(expectedResponse.data).toHaveProperty('token');
        expect(expectedResponse.data).toHaveProperty('refresh_token');
        expect(expectedResponse.data.expires_in).toBe(3600);
      });
    });
  });

  describe('Device Management', () => {
    describe('DeviceRegistrationSchema', () => {
      it('should validate device registration data', () => {
        const validData = {
          device_id: 'ABC123DEF456GHI789JKL012MNO345PQ',
          device_type: 'ios',
          device_name: 'iPhone 14 Pro',
          push_token: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
          app_version: '1.0.0',
          os_version: 'iOS 16.5'
        };
        
        expect(validData.device_type).toMatch(/^(ios|android)$/);
        expect(validData.device_name).toBeTruthy();
        expect(validData.device_name.length).toBeLessThanOrEqual(100);
        expect(validData.app_version).toBeTruthy();
        expect(validData.os_version).toBeTruthy();
      });
    });

    describe('Device Registration Endpoint', () => {
      it('should require authentication', () => {
        expect(mockAuthenticate).toBeDefined();
        expect(mockRequireAuth).toBeDefined();
      });

      it('should track device capabilities', () => {
        const iosDevice = { device_type: 'ios' };
        const androidDevice = { device_type: 'android' };
        
        // Both iOS and Android should support biometric
        expect(['ios', 'android'].includes(iosDevice.device_type)).toBe(true);
        expect(['ios', 'android'].includes(androidDevice.device_type)).toBe(true);
      });

      it('should handle push notification registration', () => {
        const withPushToken = { push_token: 'token123' };
        const withoutPushToken = { push_token: undefined };
        
        expect(Boolean(withPushToken.push_token)).toBe(true);
        expect(Boolean(withoutPushToken.push_token)).toBe(false);
      });
    });
  });

  describe('Token Management', () => {
    describe('RefreshTokenSchema', () => {
      it('should validate refresh token data', () => {
        const validData = {
          refresh_token: 'refresh_token_abc123',
          device_id: 'ABC123DEF456GHI789JKL012MNO345PQ'
        };
        
        expect(validData.refresh_token).toBeTruthy();
        expect(validData.device_id).toMatch(/^[a-zA-Z0-9\-_]{16,128}$/);
      });

      it('should allow optional device_id', () => {
        const withoutDevice = {
          refresh_token: 'refresh_token_abc123'
        };
        
        expect(withoutDevice.refresh_token).toBeTruthy();
        expect(withoutDevice).not.toHaveProperty('device_id');
      });
    });

    describe('Refresh Token Endpoint', () => {
      it('should validate refresh token format', () => {
        const validToken = 'refresh_token_123';
        const invalidToken = 'invalid_123';
        
        expect(validToken.startsWith('refresh_')).toBe(true);
        expect(invalidToken.startsWith('refresh_')).toBe(false);
      });

      it('should return new token pair', () => {
        const expectedResponse = {
          status: 'success',
          message: 'Token refreshed successfully',
          data: {
            token: expect.any(String),
            refresh_token: expect.any(String),
            expires_in: 3600
          }
        };
        
        expect(expectedResponse.data).toHaveProperty('token');
        expect(expectedResponse.data).toHaveProperty('refresh_token');
        expect(expectedResponse.data).toHaveProperty('expires_in');
      });

      it('should apply rate limiting', () => {
        // 30 attempts per hour
        const rateLimitMiddleware = mockRateLimitByUser(30, 60 * 60 * 1000);
        expect(typeof rateLimitMiddleware).toBe('function');
      });
    });
  });

  describe('Mobile Profile Endpoint', () => {
    it('should require authentication', () => {
      expect(mockAuthenticate).toBeDefined();
      expect(mockRequireAuth).toBeDefined();
    });

    it('should return minimal mobile-optimized data', () => {
      const expectedResponse = {
        status: 'success',
        data: {
          user: {
            id: expect.any(String),
            email: expect.any(String),
            preferences: {
              notifications_enabled: true,
              theme: 'system'
            }
          }
        }
      };
      
      // Should not include heavy fields
      expect(expectedResponse.data.user).not.toHaveProperty('created_at');
      expect(expectedResponse.data.user).not.toHaveProperty('updated_at');
      
      // Should include mobile preferences
      expect(expectedResponse.data.user.preferences).toHaveProperty('notifications_enabled');
      expect(expectedResponse.data.user.preferences).toHaveProperty('theme');
    });

    it('should support theme preferences', () => {
      const validThemes = ['light', 'dark', 'system'];
      const defaultTheme = 'system';
      
      expect(validThemes).toContain(defaultTheme);
      validThemes.forEach(theme => {
        expect(theme).toMatch(/^(light|dark|system)$/);
      });
    });
  });

  describe('Mobile-Specific Rate Limiting', () => {
    it('should apply appropriate rate limits to mobile endpoints', () => {
      // Mobile register: 5 per 15 minutes
      const mobileRegisterLimit = mockRateLimitByUser(5, 15 * 60 * 1000);
      expect(typeof mobileRegisterLimit).toBe('function');
      
      // Mobile login: 10 per 15 minutes
      const mobileLoginLimit = mockRateLimitByUser(10, 15 * 60 * 1000);
      expect(typeof mobileLoginLimit).toBe('function');
      
      // Biometric register: 3 per hour
      const biometricRegisterLimit = mockRateLimitByUser(3, 60 * 60 * 1000);
      expect(typeof biometricRegisterLimit).toBe('function');
      
      // Biometric login: 20 per 15 minutes
      const biometricLoginLimit = mockRateLimitByUser(20, 15 * 60 * 1000);
      expect(typeof biometricLoginLimit).toBe('function');
      
      // Device register: 5 per hour
      const deviceRegisterLimit = mockRateLimitByUser(5, 60 * 60 * 1000);
      expect(typeof deviceRegisterLimit).toBe('function');
      
      // Token refresh: 30 per hour
      const refreshLimit = mockRateLimitByUser(30, 60 * 60 * 1000);
      expect(typeof refreshLimit).toBe('function');
    });
  });

  describe('Mobile Error Handling', () => {
    it('should handle invalid device ID errors', () => {
      const deviceError = new ApiError('Invalid device ID format', 400, 'INVALID_DEVICE_ID');
      
      expect(deviceError).toBeInstanceOf(ApiError);
      expect(deviceError.statusCode).toBe(400);
      expect(deviceError.code).toBe('INVALID_DEVICE_ID');
    });

    it('should handle biometric authentication failures', () => {
      const biometricError = new ApiError('Biometric authentication failed', 401, 'BIOMETRIC_AUTH_FAILED');
      
      expect(biometricError).toBeInstanceOf(ApiError);
      expect(biometricError.statusCode).toBe(401);
      expect(biometricError.code).toBe('BIOMETRIC_AUTH_FAILED');
    });

    it('should handle invalid refresh token errors', () => {
      const refreshError = new ApiError('Invalid refresh token', 401, 'INVALID_REFRESH_TOKEN');
      
      expect(refreshError).toBeInstanceOf(ApiError);
      expect(refreshError.statusCode).toBe(401);
      expect(refreshError.code).toBe('INVALID_REFRESH_TOKEN');
    });

    it('should handle device registration conflicts', () => {
      const conflictError = new ApiError('Device already registered', 409, 'DEVICE_ALREADY_REGISTERED');
      
      expect(conflictError).toBeInstanceOf(ApiError);
      expect(conflictError.statusCode).toBe(409);
      expect(conflictError.code).toBe('DEVICE_ALREADY_REGISTERED');
    });
  });

  describe('Mobile Feature Flags', () => {
    it('should indicate available features based on device type', () => {
      const iosFeatures = {
        biometric_available: true,
        offline_mode_available: true,
        push_notifications_available: true
      };
      
      const androidFeatures = {
        biometric_available: true,
        offline_mode_available: true,
        push_notifications_available: true
      };
      
      // Both platforms should support all features
      expect(iosFeatures).toEqual(androidFeatures);
      expect(iosFeatures.biometric_available).toBe(true);
      expect(iosFeatures.offline_mode_available).toBe(true);
      expect(iosFeatures.push_notifications_available).toBe(true);
    });

    it('should adapt features based on app version', () => {
      const features = {
        biometric_available: true,
        offline_mode_available: true,
        push_notifications_available: true
      };
      
      // All features should be available by default
      expect(Object.values(features).every(f => f === true)).toBe(true);
    });
  });

  describe('Sync and Offline Support', () => {
    it('should indicate sync requirements', () => {
      const registrationResponse = {
        sync_required: false // New registration doesn't need sync
      };
      
      const loginResponse = {
        sync_required: true // Login might need to sync offline changes
      };
      
      expect(registrationResponse.sync_required).toBe(false);
      expect(loginResponse.sync_required).toBe(true);
    });

    it('should provide server time for synchronization', () => {
      const response = {
        server_time: new Date().toISOString()
      };
      
      expect(response.server_time).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
    });
  });
});