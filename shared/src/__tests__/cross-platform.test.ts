// shared/src/schemas/__tests__/cross-platform.test.ts

import { describe, test, expect, beforeAll, afterAll } from '@jest/globals';
import { z } from 'zod';
import {
  UniversalValidator,
  BackendValidator,
  MobileValidator,
  createValidationMiddleware
} from '../schemas/validator';
import {
  UserSchema,
  GarmentSchema,
  CreateGarmentSchema,
  ImageSchema
} from '../schemas/index';
import { PolygonSchema } from '../schemas/polygon';

/**
 * Cross-Platform Compatibility Testing
 * 
 * Tests to ensure schemas work consistently across:
 * 1. Node.js backend
 * 2. React Native mobile app
 * 3. Different JavaScript environments
 * 4. Various data serialization formats
 */

describe('Cross-Platform Compatibility', () => {

  // 1. SERIALIZATION/DESERIALIZATION TESTS
  describe('Data Serialization/Deserialization', () => {
    test('should handle JSON serialization round-trip', () => {
      const originalData = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        email: 'test@example.com',
        created_at: new Date(),
        linkedProviders: ['google', 'github']
      };

      // Simulate JSON round-trip (common in API calls)
      const serialized = JSON.stringify(originalData);
      const deserialized = JSON.parse(serialized);

      // Note: Dates become strings after JSON serialization
      const expectedAfterJson = {
        ...originalData,
        created_at: originalData.created_at.toISOString()
      };

      expect(deserialized).toEqual(expectedAfterJson);

      // Test that schema can handle both formats
      const originalResult = UserSchema.safeParse(originalData);
      const deserializedResult = UserSchema.safeParse(deserialized);

      expect(originalResult.success).toBe(true);
      expect(deserializedResult.success).toBe(true);
    });

    test('should handle FormData serialization (mobile to backend)', () => {
      // Simulate FormData conversion (strings only)
      const formData = {
        email: 'test@example.com',
        name: 'Test User',
        // FormData converts everything to strings
        linkedProviders: JSON.stringify(['google', 'github'])
      };

      // Test if schema can handle string arrays that need parsing
      const result = UserSchema.safeParse({
        ...formData,
        linkedProviders: JSON.parse(formData.linkedProviders)
      });

      expect(result.success).toBe(true);
    });

    test('should handle URL query parameters (all strings)', () => {
      // URL params are always strings
      const queryParams = {
        email: 'test@example.com',
        page: '1',
        limit: '10'
      };

      // Test pagination schema with coercion
      const paginationSchema = z.object({
        page: z.coerce.number().int().min(1).optional(),
        limit: z.coerce.number().int().min(1).max(100).optional()
      });

      const result = paginationSchema.safeParse(queryParams);
      expect(result.success).toBe(true);

      if (result.success) {
        expect(typeof result.data.page).toBe('number');
        expect(typeof result.data.limit).toBe('number');
        expect(result.data.page).toBe(1);
        expect(result.data.limit).toBe(10);
      }
    });
  });

  // 2. PLATFORM-SPECIFIC VALIDATOR TESTS
  describe('Platform-Specific Validators', () => {
    test('should work with UniversalValidator', () => {
      const testData = {
        email: 'test@example.com',
        name: 'Test User'
      };

      const result = UniversalValidator.validate(UserSchema, testData);
      
      expect(result.success).toBe(true);
      expect(result.data).toEqual(testData);
      expect(result.errors).toBeUndefined();
    });

    test('should work with BackendValidator and context', () => {
      const testData = {
        email: 'test@example.com',
        name: 'Test User'
      };

      const context = {
        operation: 'create_user',
        resource: '/api/users',
        userId: 'admin-123'
      };

      const result = BackendValidator.validateWithContext(
        UserSchema,
        testData,
        context
      );

      expect(result.success).toBe(true);
      expect(result.context).toEqual(context);
    });

    test('should work with MobileValidator lightweight validation', () => {
      const testData = {
        email: 'test@example.com',
        name: 'Test User'
      };

      const result = MobileValidator.validateLightweight(UserSchema, testData);

      expect(result.success).toBe(true);
      expect(result.data).toEqual(testData);
      expect(result.error).toBeUndefined();
    });

    test('should handle MobileValidator batch validation', () => {
      const testDataArray = [
        { email: 'user1@example.com', name: 'User 1' },
        { email: 'invalid-email', name: 'User 2' }, // Invalid
        { email: 'user3@example.com', name: 'User 3' }
      ];

      const result = MobileValidator.validateBatch(UserSchema, testDataArray);

      expect(result.success).toBe(false); // One invalid item
      expect(result.validItems).toHaveLength(2);
      expect(result.invalidItems).toHaveLength(1);
      expect(result.invalidItems[0].index).toBe(1);
    });
  });

  // 3. ENVIRONMENT-SPECIFIC TESTS
  describe('Environment-Specific Behavior', () => {
    test('should handle Node.js specific features', () => {
      // Test Buffer handling (Node.js specific)
      if (typeof Buffer !== 'undefined') {
        const bufferData = Buffer.from('test data');
        
        // Test if schema can handle Buffer in mask data
        const maskData = {
          width: 100,
          height: 100,
          data: Array.from(bufferData) // Convert to array for validation
        };

        const garmentData = {
          original_image_id: '123e4567-e89b-12d3-a456-426614174000',
          metadata: {
            type: 'shirt',
            color: 'blue'
          },
          mask_data: maskData
        };

        const result = CreateGarmentSchema.safeParse(garmentData);
        expect(result.success).toBe(true);
      }
    });

    test('should handle browser-specific features', () => {
      // Test File/Blob handling (browser specific)
      // Mock File object for testing
      const mockFile = {
        name: 'test.jpg',
        type: 'image/jpeg',
        size: 1024
      };

      // Test file metadata schema
      const fileMetadataSchema = z.object({
        name: z.string(),
        type: z.string(),
        size: z.number()
      });

      const result = fileMetadataSchema.safeParse(mockFile);
      expect(result.success).toBe(true);
    });

    test('should handle React Native specific features', () => {
      // Test AsyncStorage-like data (strings only)
      const asyncStorageData = {
        user: JSON.stringify({
          email: 'test@example.com',
          name: 'Test User'
        }),
        settings: JSON.stringify({
          theme: 'dark',
          notifications: true
        })
      };

      // Parse and validate
      const userData = JSON.parse(asyncStorageData.user);
      const result = UserSchema.safeParse(userData);

      expect(result.success).toBe(true);
    });
  });

  // 4. MIDDLEWARE INTEGRATION TESTS
  describe('Middleware Integration', () => {
    test('should work with Express-style middleware', () => {
      const mockRequest = {
        body: {
          email: 'test@example.com',
          name: 'Test User'
        },
        user: {
          id: 'current-user-123'
        },
        route: {
          path: '/api/users'
        }
      };

      const mockResponse = {};
      let nextCalled = false;
      let nextError: any = null;

      const mockNext = (error?: any) => {
        nextCalled = true;
        nextError = error;
      };

      const middleware = createValidationMiddleware.forExpress(UserSchema, 'body');
      middleware(mockRequest, mockResponse, mockNext);

      expect(nextCalled).toBe(true);
      expect(nextError).toBeNull();
      expect(mockRequest.body).toEqual({
        email: 'test@example.com',
        name: 'Test User'
      });
    });

    test('should handle validation errors in Express middleware', () => {
      const mockRequest = {
        body: {
          email: 'invalid-email', // Invalid email
          name: 'Test User'
        },
        user: {
          id: 'current-user-123'
        },
        route: {
          path: '/api/users'
        }
      };

      const mockResponse = {};
      let nextCalled = false;
      let nextError: any = null;

      const mockNext = (error?: any) => {
        nextCalled = true;
        nextError = error;
      };

      const middleware = createValidationMiddleware.forExpress(UserSchema, 'body');
      middleware(mockRequest, mockResponse, mockNext);

      expect(nextCalled).toBe(true);
      expect(nextError).toBeTruthy();
      expect(nextError.statusCode).toBe(400);
      expect(nextError.code).toBe('VALIDATION_ERROR');
    });

    test('should work with React Native form validation', () => {
      const formValidator = createValidationMiddleware.forReactNative(UserSchema);

      const validData = {
        email: 'test@example.com',
        name: 'Test User'
      };

      const invalidData = {
        email: 'invalid-email',
        name: 'Test User'
      };

      const validResult = formValidator(validData);
      const invalidResult = formValidator(invalidData);

      expect(validResult.success).toBe(true);
      expect(validResult.data).toEqual(validData);

      expect(invalidResult.success).toBe(false);
      expect(invalidResult.error).toContain('email');
    });
  });

  // 5. PERFORMANCE ACROSS PLATFORMS
  describe('Performance Across Platforms', () => {
    test('should maintain consistent performance', () => {
      const testData = {
        email: 'test@example.com',
        name: 'Test User'
      };

      // Test UniversalValidator performance
      const universalStart = Date.now();
      for (let i = 0; i < 1000; i++) {
        UniversalValidator.validate(UserSchema, testData);
      }
      const universalTime = Date.now() - universalStart;

      // Test BackendValidator performance
      const backendStart = Date.now();
      for (let i = 0; i < 1000; i++) {
        BackendValidator.validateWithContext(UserSchema, testData, {
          operation: 'test',
          resource: 'test'
        });
      }
      const backendTime = Date.now() - backendStart;

      // Test MobileValidator performance
      const mobileStart = Date.now();
      for (let i = 0; i < 1000; i++) {
        MobileValidator.validateLightweight(UserSchema, testData);
      }
      const mobileTime = Date.now() - mobileStart;

      // Performance should be reasonable for all validators
      expect(universalTime).toBeLessThan(1000); // 1 second for 1000 validations
      expect(backendTime).toBeLessThan(1500); // Backend validator has more overhead
      expect(mobileTime).toBeLessThan(800); // Mobile validator should be fastest

      console.log(`Performance results:
        Universal: ${universalTime}ms
        Backend: ${backendTime}ms  
        Mobile: ${mobileTime}ms`);
    });
  });

  // 6. DATA CONSISTENCY TESTS
  describe('Data Consistency Across Platforms', () => {
    test('should produce identical validation results', () => {
      const testCases = [
        {
          name: 'valid user',
          data: { email: 'test@example.com', name: 'Test User' },
          shouldSucceed: true
        },
        {
          name: 'invalid email',
          data: { email: 'invalid-email', name: 'Test User' },
          shouldSucceed: false
        },
        {
          name: 'missing email',
          data: { name: 'Test User' },
          shouldSucceed: false
        }
      ];

      testCases.forEach(({ name, data, shouldSucceed }) => {
        const universalResult = UniversalValidator.validate(UserSchema, data);
        const backendResult = BackendValidator.validateWithContext(
          UserSchema, 
          data, 
          { operation: 'test' }
        );
        const mobileResult = MobileValidator.validateLightweight(UserSchema, data);

        // All validators should agree on success/failure
        expect(universalResult.success).toBe(shouldSucceed);
        expect(backendResult.success).toBe(shouldSucceed);
        expect(mobileResult.success).toBe(shouldSucceed);

        // If successful, data should be identical
        if (shouldSucceed) {
          expect(universalResult.data).toEqual(backendResult.data);
          expect(universalResult.data).toEqual(mobileResult.data);
        }
      });
    });

    test('should handle timezone differences consistently', () => {
      const dateString = '2023-01-01T12:00:00.000Z';
      const dateObject = new Date(dateString);

      const dataWithStringDate = {
        email: 'test@example.com',
        created_at: dateString
      };

      const dataWithDateObject = {
        email: 'test@example.com',
        created_at: dateObject
      };

      const stringResult = UserSchema.safeParse(dataWithStringDate);
      const objectResult = UserSchema.safeParse(dataWithDateObject);

      // Both should be valid
      expect(stringResult.success).toBe(true);
      expect(objectResult.success).toBe(true);

      // Results should be consistent across platforms
      if (stringResult.success && objectResult.success) {
        // Normalize for comparison
        const stringDate = new Date(stringResult.data.created_at!);
        const objectDate = new Date(objectResult.data.created_at!);
        
        expect(stringDate.getTime()).toBe(objectDate.getTime());
      }
    });
  });

  // 7. ERROR HANDLING CONSISTENCY
  describe('Error Handling Consistency', () => {
    test('should provide consistent error formats across platforms', () => {
      const invalidData = {
        email: 'invalid-email',
        name: 'A'.repeat(200) // Assuming there's a length limit
      };

      const universalResult = UniversalValidator.validate(UserSchema, invalidData);
      const backendResult = BackendValidator.validateWithContext(
        UserSchema, 
        invalidData, 
        { operation: 'test' }
      );
      const mobileResult = MobileValidator.validateLightweight(UserSchema, invalidData);

      // All should fail
      expect(universalResult.success).toBe(false);
      expect(backendResult.success).toBe(false);
      expect(mobileResult.success).toBe(false);

      // Error structures should be comparable
      if (!universalResult.success && !backendResult.success) {
        const universalEmailError = universalResult.errors?.find(e => e.field.includes('email'));
        const backendEmailError = backendResult.errors?.find(e => e.field.includes('email'));

        if (universalEmailError && backendEmailError) {
          expect(universalEmailError.message).toBe(backendEmailError.message);
          expect(universalEmailError.code).toBe(backendEmailError.code);
        }
      }

      // Mobile should have simplified error
      expect(mobileResult.error).toBeTruthy();
      expect(mobileResult.error).toContain('email');
    });
  });
});

// 8. INTEGRATION TEST SUITE FOR REAL-WORLD SCENARIOS
describe('Real-World Integration Scenarios', () => {
  
  test('should handle complete user registration flow', async () => {
    // Simulate mobile app registration
    const mobileRegistrationData = {
      email: 'newuser@example.com',
      password: 'SecurePassword123!',
      name: 'New User'
    };

    // Validate on mobile
    const mobileValidation = MobileValidator.validateLightweight(
      UserSchema.pick({ email: true, name: true }), // Mobile doesn't send password in user schema
      { email: mobileRegistrationData.email, name: mobileRegistrationData.name }
    );

    expect(mobileValidation.success).toBe(true);

    // Simulate API call serialization
    const apiPayload = JSON.stringify(mobileRegistrationData);
    const deserializedPayload = JSON.parse(apiPayload);

    // Validate on backend
    const registerSchema = z.object({
      email: z.string().email(),
      password: z.string().min(8),
      name: z.string().optional()
    });

    const backendValidation = BackendValidator.validateWithContext(
      registerSchema,
      deserializedPayload,
      { operation: 'register', resource: '/api/auth/register' }
    );

    expect(backendValidation.success).toBe(true);
  });

  test('should handle image upload with polygon annotation flow', () => {
    // Simulate complete flow from mobile to backend
    const imageUploadData = {
      file_path: '/uploads/image123.jpg',
      original_metadata: {
        filename: 'shirt.jpg',
        mimetype: 'image/jpeg',
        size: 1024000,
        width: 800,
        height: 600
      }
    };

    const polygonData = {
      original_image_id: '123e4567-e89b-12d3-a456-426614174000',
      points: [
        { x: 100, y: 100 },
        { x: 200, y: 100 },
        { x: 200, y: 200 },
        { x: 100, y: 200 }
      ],
      label: 'shirt'
    };

    const garmentData = {
      original_image_id: '123e4567-e89b-12d3-a456-426614174000',
      metadata: {
        type: 'shirt',
        color: 'blue',
        pattern: 'solid',
        season: 'summer'
      },
      mask_data: {
        width: 800,
        height: 600,
        data: new Array(800 * 600).fill(0)
      }
    };

    // Validate each step
    const imageResult = ImageSchema.safeParse({
      user_id: '123e4567-e89b-12d3-a456-426614174000',
      ...imageUploadData
    });

    const polygonResult = PolygonSchema.safeParse(polygonData);
    const garmentResult = CreateGarmentSchema.safeParse(garmentData);

    expect(imageResult.success).toBe(true);
    expect(polygonResult.success).toBe(true);
    expect(garmentResult.success).toBe(true);

    // Ensure referential integrity
    if (imageResult.success && polygonResult.success && garmentResult.success) {
      expect(polygonResult.data.original_image_id).toBe(garmentResult.data.original_image_id);
    }
  });
});

// 9. HELPER UTILITIES FOR TESTING
export const crossPlatformTestHelpers = {
  /**
   * Test a schema across all platform validators
   */
  testAcrossAllPlatforms: <T>(schema: z.ZodSchema<T>, data: unknown, shouldSucceed: boolean) => {
    const results = {
      universal: UniversalValidator.validate(schema, data),
      backend: BackendValidator.validateWithContext(schema, data, { operation: 'test' }),
      mobile: MobileValidator.validateLightweight(schema, data)
    };

    // Check that all platforms agree
    expect(results.universal.success).toBe(shouldSucceed);
    expect(results.backend.success).toBe(shouldSucceed);
    expect(results.mobile.success).toBe(shouldSucceed);

    return results;
  },

  /**
   * Simulate JSON serialization round-trip
   */
  simulateApiRoundTrip: (data: any) => {
    return JSON.parse(JSON.stringify(data));
  },

  /**
   * Simulate FormData conversion (all values become strings)
   */
  simulateFormDataConversion: (data: Record<string, any>) => {
    const formData: Record<string, string> = {};
    
    Object.entries(data).forEach(([key, value]) => {
      if (typeof value === 'object' && value !== null) {
        formData[key] = JSON.stringify(value);
      } else {
        formData[key] = String(value);
      }
    });

    return formData;
  },

  /**
   * Test performance across platforms
   */
  benchmarkValidation: <T>(schema: z.ZodSchema<T>, data: unknown, iterations: number = 1000) => {
    const results: Record<string, number> = {};

    // Universal validator
    const universalStart = Date.now();
    for (let i = 0; i < iterations; i++) {
      UniversalValidator.validate(schema, data);
    }
    results.universal = Date.now() - universalStart;

    // Backend validator
    const backendStart = Date.now();
    for (let i = 0; i < iterations; i++) {
      BackendValidator.validateWithContext(schema, data, { operation: 'bench' });
    }
    results.backend = Date.now() - backendStart;

    // Mobile validator
    const mobileStart = Date.now();
    for (let i = 0; i < iterations; i++) {
      MobileValidator.validateLightweight(schema, data);
    }
    results.mobile = Date.now() - mobileStart;

    return results;
  }
};