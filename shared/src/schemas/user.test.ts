// /shared/src/schemas/user.test.ts
import { describe, test, expect } from '@jest/globals';
import { 
  UserSchema, 
  MobileUserFieldsSchema,
  RegisterUserSchema,
  LoginUserSchema,
  BiometricLoginSchema,
  DeviceRegistrationSchema,
  UserResponseSchema,
  MobileUserResponseSchema,
  AuthResponseSchema,
  MobileAuthResponseSchema,
  UpdateUserSchema
} from './user';

describe('User Schema Tests', () => {
  describe('MobileUserFieldsSchema', () => {
    test('should validate valid mobile user fields', () => {
      const validMobileFields = {
        device_id: 'iPhone14Pro-A1B2C3D4E5F6G7H8',
        device_type: 'ios',
        device_name: 'John\'s iPhone',
        push_token: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
        biometric_enabled: true,
        biometric_id: 'FaceID-1234567890abcdef1234567890abcdef',
        app_version: '1.2.3',
        os_version: 'iOS 16.5',
        last_sync_at: new Date(),
        profile_picture_url: 'https://example.com/profile.jpg',
        profile_picture_thumbnail: 'https://example.com/profile_thumb.jpg',
        preferences: {
          notifications_enabled: true,
          offline_mode_enabled: false,
          data_saver_mode: false,
          theme: 'dark',
          language: 'en'
        }
      };

      const result = MobileUserFieldsSchema.safeParse(validMobileFields);
      expect(result.success).toBe(true);
    });

    test('should validate device_id patterns', () => {
      const validDeviceIds = [
        'iPhone14Pro-A1B2C3D4E5F6G7H8',
        'SM-S908B_1234567890abcdef',
        'Pixel7Pro_ABCDEFGHIJKLMNOP',
        '1234567890abcdef_AndroidDevice'
      ];

      validDeviceIds.forEach(deviceId => {
        const result = MobileUserFieldsSchema.safeParse({ device_id: deviceId });
        expect(result.success).toBe(true);
      });

      const invalidDeviceIds = [
        'short', // Too short
        'invalid device id', // Contains spaces
        'invalid@device#id', // Invalid characters
        'a'.repeat(129) // Too long
      ];

      invalidDeviceIds.forEach(deviceId => {
        const result = MobileUserFieldsSchema.safeParse({ device_id: deviceId });
        expect(result.success).toBe(false);
      });
    });

    test('should validate push token patterns', () => {
      const validTokens = [
        'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
        'fcm:APA91bHun4MxP5egoKMwt2KZFBaFUH-1RYqx',
        'apns:740f4707bebcf74f9b7c25d4d2a4a4a2d2a4a4a2',
        'web:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
      ];

      validTokens.forEach(token => {
        const result = MobileUserFieldsSchema.safeParse({ push_token: token });
        expect(result.success).toBe(true);
      });
    });

    test('should validate biometric ID patterns', () => {
      const validBiometricIds = [
        'FaceID-1234567890abcdef1234567890abcdef',
        'TouchID_abcdefghijklmnopqrstuvwxyz123456',
        'Android-Fingerprint-0123456789ABCDEF0123456789ABCDEF'
      ];

      validBiometricIds.forEach(biometricId => {
        const result = MobileUserFieldsSchema.safeParse({ biometric_id: biometricId });
        expect(result.success).toBe(true);
      });
    });

    test('should validate device types', () => {
      const validTypes = ['ios', 'android', 'web'];
      
      validTypes.forEach(type => {
        const result = MobileUserFieldsSchema.safeParse({ device_type: type });
        expect(result.success).toBe(true);
      });

      const result = MobileUserFieldsSchema.safeParse({ device_type: 'windows' });
      expect(result.success).toBe(false);
    });

    test('should validate preferences with defaults', () => {
      const minimalPrefs = {};
      const result = MobileUserFieldsSchema.safeParse({ preferences: minimalPrefs });
      expect(result.success).toBe(true);
      
      if (result.success && result.data.preferences) {
        expect(result.data.preferences.notifications_enabled).toBe(true);
        expect(result.data.preferences.offline_mode_enabled).toBe(false);
        expect(result.data.preferences.data_saver_mode).toBe(false);
        expect(result.data.preferences.theme).toBe('system');
        expect(result.data.preferences.language).toBe('en');
      }
    });
  });

  describe('UserSchema', () => {
    test('should validate complete user with mobile fields', () => {
      const validUser = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        email: 'test@example.com',
        name: 'John Doe',
        password_hash: '$2b$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        created_at: new Date(),
        updated_at: new Date(),
        linkedProviders: ['google', 'apple'],
        oauth_provider: 'google',
        device_id: 'iPhone14Pro-A1B2C3D4E5F6G7H8',
        device_type: 'ios',
        device_name: 'John\'s iPhone',
        push_token: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
        biometric_enabled: true,
        app_version: '1.2.3',
        os_version: 'iOS 16.5',
        profile_picture_url: 'https://example.com/profile.jpg'
      };

      const result = UserSchema.safeParse(validUser);
      expect(result.success).toBe(true);
    });

    test('should validate minimal user', () => {
      const minimalUser = {
        email: 'minimal@example.com'
      };

      const result = UserSchema.safeParse(minimalUser);
      expect(result.success).toBe(true);
    });

    test('should reject invalid emails', () => {
      const invalidEmails = [
        'notanemail',
        '@example.com',
        'user@',
        'user@.com',
        'user..name@example.com',
        'user name@example.com',
        ''
      ];

      invalidEmails.forEach(email => {
        const result = UserSchema.safeParse({ email });
        expect(result.success).toBe(false);
      });
    });
  });

  describe('RegisterUserSchema', () => {
    test('should validate valid registration with mobile info', () => {
      const validRegistration = {
        email: 'newuser@example.com',
        password: 'SecureP@ssw0rd123',
        name: 'New User',
        device_id: 'iPhone14Pro-A1B2C3D4E5F6G7H8',
        device_type: 'ios',
        device_name: 'New User\'s iPhone',
        push_token: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]'
      };

      const result = RegisterUserSchema.safeParse(validRegistration);
      expect(result.success).toBe(true);
    });

    test('should enforce password requirements', () => {
      const weakPasswords = [
        'short', // Too short (less than 8 chars)
        '1234567' // 7 chars, too short
      ];

      weakPasswords.forEach(password => {
        const result = RegisterUserSchema.safeParse({
          email: 'test@example.com',
          password
        });
        expect(result.success).toBe(false);
      });

      // Valid passwords (8+ chars)
      const validPasswords = [
        '12345678',
        'password',
        'abcdefgh',
        'SecureP@ssw0rd123'
      ];

      validPasswords.forEach(password => {
        const result = RegisterUserSchema.safeParse({
          email: 'test@example.com',
          password
        });
        expect(result.success).toBe(true);
      });
    });

    test('should validate minimal registration', () => {
      const minimal = {
        email: 'minimal@example.com',
        password: 'MinimalP@ss123'
      };

      const result = RegisterUserSchema.safeParse(minimal);
      expect(result.success).toBe(true);
    });
  });

  describe('LoginUserSchema', () => {
    test('should validate login with email/password', () => {
      const validLogin = {
        email: 'user@example.com',
        password: 'UserP@ssw0rd',
        device_id: 'iPhone14Pro-A1B2C3D4E5F6G7H8',
        biometric_token: 'biometric_auth_token_123'
      };

      const result = LoginUserSchema.safeParse(validLogin);
      expect(result.success).toBe(true);
    });

    test('should validate biometric login', () => {
      const biometricLogin = {
        user_id: '123e4567-e89b-12d3-a456-426614174000',
        biometric_id: 'FaceID-1234567890abcdef1234567890abcdef',
        device_id: 'iPhone14Pro-A1B2C3D4E5F6G7H8',
        challenge: 'server-challenge-string-123'
      };

      const result = BiometricLoginSchema.safeParse(biometricLogin);
      expect(result.success).toBe(true);
    });

    test('should reject login without email', () => {
      const invalidLogin = {
        password: 'SomePassword123'
      };

      const result = LoginUserSchema.safeParse(invalidLogin);
      expect(result.success).toBe(false);
    });
  });

  describe('DeviceRegistrationSchema', () => {
    test('should validate device registration', () => {
      const validRegistration = {
        device_id: 'iPhone14Pro-A1B2C3D4E5F6G7H8',
        device_type: 'ios',
        device_name: 'John\'s iPhone',
        push_token: 'ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]',
        app_version: '1.2.3',
        os_version: 'iOS 16.5'
      };

      const result = DeviceRegistrationSchema.safeParse(validRegistration);
      expect(result.success).toBe(true);
    });

    test('should validate device types', () => {
      const types = ['ios', 'android'];
      
      types.forEach(device_type => {
        const registration = {
          device_id: 'device-123-456-789-012', // At least 16 characters
          device_type,
          device_name: 'Test Device',
          app_version: '1.2.3',
          os_version: device_type === 'ios' ? 'iOS 16.5' : 'Android 13'
        };
        
        const result = DeviceRegistrationSchema.safeParse(registration);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('AuthResponseSchema', () => {
    test('should validate auth response', () => {
      const validResponse = {
        user: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          email: 'user@example.com',
          name: 'John Doe'
        },
        token: 'jwt-token-string',
        refreshToken: 'refresh-token-string',
        expiresIn: 3600
      };

      const result = AuthResponseSchema.safeParse(validResponse);
      expect(result.success).toBe(true);
    });

    test('should validate minimal auth response', () => {
      const minimalResponse = {
        user: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          email: 'user@example.com'
        },
        token: 'jwt-token',
        expiresIn: 3600
      };

      const result = AuthResponseSchema.safeParse(minimalResponse);
      expect(result.success).toBe(true);
    });
  });

  describe('MobileAuthResponseSchema', () => {
    test('should validate mobile auth response', () => {
      const mobileResponse = {
        user: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          email: 'user@example.com',
          name: 'John Doe'
        },
        token: 'jwt-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
        sync_required: true,
        server_time: new Date().toISOString(),
        features: {
          biometric_available: true,
          offline_mode_available: true,
          push_notifications_available: true
        }
      };

      const result = MobileAuthResponseSchema.safeParse(mobileResponse);
      expect(result.success).toBe(true);
    });

    test('should extend base auth response', () => {
      const baseOnlyFields = {
        user: {
          id: '123e4567-e89b-12d3-a456-426614174000',
          email: 'user@example.com'
        },
        token: 'jwt-token',
        expires_in: 3600,
        server_time: new Date().toISOString() // Required field for MobileAuthResponseSchema
      };

      // Should work for mobile too (extended schema)
      const result = MobileAuthResponseSchema.safeParse(baseOnlyFields);
      expect(result.success).toBe(true);
    });
  });

  describe('UserResponseSchema', () => {
    test('should omit sensitive fields', () => {
      const userResponse = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        email: 'user@example.com',
        name: 'John Doe',
        created_at: new Date(),
        updated_at: new Date(),
        device_type: 'ios',
        biometric_enabled: true
      };

      const result = UserResponseSchema.safeParse(userResponse);
      expect(result.success).toBe(true);
      
      // Should not include password_hash
      const withPassword = {
        ...userResponse,
        password_hash: 'should-be-stripped'
      };
      
      const resultWithPwd = UserResponseSchema.safeParse(withPassword);
      expect(resultWithPwd.success).toBe(true);
      if (resultWithPwd.success) {
        expect(resultWithPwd.data).not.toHaveProperty('password_hash');
      }
    });
  });

  describe('Cross-platform compatibility', () => {
    test('should handle date serialization', () => {
      const userWithDates = {
        email: 'test@example.com',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        last_sync_at: new Date().toISOString()
      };

      const result = UserSchema.safeParse({
        ...userWithDates,
        created_at: new Date(userWithDates.created_at),
        updated_at: new Date(userWithDates.updated_at),
        last_sync_at: new Date(userWithDates.last_sync_at)
      });

      expect(result.success).toBe(true);
    });

    test('should handle optional fields gracefully', () => {
      const sparseUser = {
        email: 'sparse@example.com',
        device_type: 'android'
        // Most fields omitted
      };

      const result = UserSchema.safeParse(sparseUser);
      expect(result.success).toBe(true);
      
      if (result.success) {
        expect(result.data.biometric_enabled).toBe(false); // Default value
        expect(result.data.device_id).toBeUndefined();
        expect(result.data.push_token).toBeUndefined();
      }
    });
  });

  describe('Security validations', () => {
    test('should not expose password_hash in serialization', () => {
      const userWithPassword = {
        email: 'secure@example.com',
        password_hash: '$2b$10$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
      };

      const result = UserSchema.safeParse(userWithPassword);
      expect(result.success).toBe(true);
      
      // In practice, password_hash should be stripped before sending to client
      const clientSafeUser = UserSchema.omit({ password_hash: true }).safeParse(userWithPassword);
      expect(clientSafeUser.success).toBe(true);
    });

    test('should validate OAuth provider consistency', () => {
      const user = {
        email: 'oauth@example.com',
        linkedProviders: ['google', 'apple'],
        oauth_provider: 'google' // Should be in linkedProviders
      };

      const result = UserSchema.safeParse(user);
      expect(result.success).toBe(true);
    });
  });
});