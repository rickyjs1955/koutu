// shared/src/schemas/__tests__/schema-validation.test.ts

import { describe, test, expect } from '@jest/globals';
import { z } from 'zod';
import {
  UserSchema,
  GarmentSchema,
  ImageSchema,
  WardrobeSchema,
  CreateGarmentSchema,
  UpdateGarmentMetadataSchema
} from '../schemas/index';
import { PolygonSchema } from '../schemas/polygon';

/**
 * Comprehensive Schema Validation Testing Strategy
 * 
 * This file demonstrates testing patterns for:
 * 1. Valid data validation
 * 2. Invalid data rejection
 * 3. Edge cases and boundary conditions
 * 4. Cross-schema relationships
 * 5. Performance validation
 * 6. Error message quality
 */

describe('Schema Validation Strategy', () => {
  
  // 1. VALID DATA VALIDATION TESTS
  describe('Valid Data Validation', () => {
    test('should validate complete valid user', () => {
      const validUser = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        email: 'test@example.com',
        name: 'John Doe',
        linkedProviders: ['google', 'github'],
        oauth_provider: 'google',
        created_at: new Date(),
        updated_at: new Date()
      };

      const result = UserSchema.safeParse(validUser);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toEqual(validUser);
      }
    });

    test('should validate minimal valid user', () => {
      const minimalUser = {
        email: 'minimal@example.com'
      };

      const result = UserSchema.safeParse(minimalUser);
      expect(result.success).toBe(true);
    });

    test('should validate complex garment with all fields', () => {
      const complexGarment = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        original_image_id: '123e4567-e89b-12d3-a456-426614174002',
        file_path: '/uploads/garments/garment_123.jpg',
        mask_path: '/uploads/masks/mask_123.png',
        metadata: {
          type: 'shirt',
          color: 'navy blue',
          pattern: 'striped',
          season: 'summer',
          brand: 'Nike',
          tags: ['casual', 'cotton', 'breathable']
        },
        created_at: new Date(),
        updated_at: new Date(),
        data_version: 1
      };

      const result = GarmentSchema.safeParse(complexGarment);
      expect(result.success).toBe(true);
    });
  });

  // 2. INVALID DATA REJECTION TESTS
  describe('Invalid Data Rejection', () => {
    test('should reject invalid email formats', () => {
      const invalidEmails = [
        'not-an-email',
        '@example.com',
        'user@',
        'user@.com',
        'user..name@example.com',
        ''
      ];

      invalidEmails.forEach(email => {
        const result = UserSchema.safeParse({ email });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].path).toContain('email');
        }
      });
    });

    test('should reject invalid UUIDs', () => {
      const invalidUUIDs = [
        'not-a-uuid',
        '123',
        '123e4567-e89b-12d3-a456-42661417400', // too short
        '123e4567-e89b-12d3-a456-4266141740000', // too long
        'ggge4567-e89b-12d3-a456-426614174000' // invalid characters
      ];

      invalidUUIDs.forEach(id => {
        const result = UserSchema.safeParse({ email: 'test@example.com', id });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].path).toContain('id');
        }
      });
    });

    test('should reject invalid garment types', () => {
      const invalidTypes = ['invalid_type', 'shoe', 'accessory', ''];

      invalidTypes.forEach(type => {
        const garmentData = {
          user_id: '123e4567-e89b-12d3-a456-426614174000',
          original_image_id: '123e4567-e89b-12d3-a456-426614174001',
          file_path: '/path/to/file.jpg',
          mask_path: '/path/to/mask.png',
          metadata: {
            type,
            color: 'blue'
          }
        };

        const result = GarmentSchema.safeParse(garmentData);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.issues[0].path).toEqual(['metadata', 'type']);
        }
      });
    });
  });

  // 3. EDGE CASES AND BOUNDARY CONDITIONS
  describe('Edge Cases and Boundary Conditions', () => {
    test('should handle maximum string lengths', () => {
      const maxLengthTests = [
        {
          schema: UserSchema,
          data: { 
            email: 'a'.repeat(255) + '@example.com', // Over email limit
            name: 'A'.repeat(101) // Over name limit if it exists
          },
          shouldFail: true
        }
      ];

      maxLengthTests.forEach(({ schema, data, shouldFail }) => {
        const result = schema.safeParse(data);
        expect(result.success).toBe(!shouldFail);
      });
    });

    test('should handle empty and null values appropriately', () => {
      const edgeCases = [
        { data: null, shouldSucceed: false },
        { data: undefined, shouldSucceed: false },
        { data: {}, shouldSucceed: false }, // Missing required email
        { data: { email: null }, shouldSucceed: false },
        { data: { email: '' }, shouldSucceed: false }
      ];

      edgeCases.forEach(({ data, shouldSucceed }) => {
        const result = UserSchema.safeParse(data);
        expect(result.success).toBe(shouldSucceed);
      });
    });

    test('should handle array boundary conditions', () => {
      // Test empty arrays
      const garmentWithEmptyTags = {
        user_id: '123e4567-e89b-12d3-a456-426614174000',
        original_image_id: '123e4567-e89b-12d3-a456-426614174001',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png',
        metadata: {
          type: 'shirt',
          color: 'blue',
          tags: []
        }
      };

      const result = GarmentSchema.safeParse(garmentWithEmptyTags);
      expect(result.success).toBe(true);

      // Test arrays with many items (if there are limits)
      const garmentWithManyTags = {
        ...garmentWithEmptyTags,
        metadata: {
          ...garmentWithEmptyTags.metadata,
          tags: new Array(20).fill('tag') // Test if there's a limit
        }
      };

      const manyTagsResult = GarmentSchema.safeParse(garmentWithManyTags);
      // This should be documented based on your business rules
    });
  });

  // 4. CROSS-SCHEMA RELATIONSHIP TESTS
  describe('Cross-Schema Relationships', () => {
    test('should validate relationships between schemas', () => {
      const userId = '123e4567-e89b-12d3-a456-426614174000';
      const imageId = '123e4567-e89b-12d3-a456-426614174001';
      const garmentId = '123e4567-e89b-12d3-a456-426614174002';

      // Create related data
      const user = {
        id: userId,
        email: 'user@example.com'
      };

      const image = {
        id: imageId,
        user_id: userId,
        file_path: '/uploads/image.jpg'
      };

      const garment = {
        id: garmentId,
        user_id: userId,
        original_image_id: imageId,
        file_path: '/uploads/garment.jpg',
        mask_path: '/uploads/mask.png',
        metadata: {
          type: 'shirt',
          color: 'blue'
        }
      };

      // Validate each schema
      expect(UserSchema.safeParse(user).success).toBe(true);
      expect(ImageSchema.safeParse(image).success).toBe(true);
      expect(GarmentSchema.safeParse(garment).success).toBe(true);

      // Test referential integrity (UUIDs match)
      expect(image.user_id).toBe(userId);
      expect(garment.user_id).toBe(userId);
      expect(garment.original_image_id).toBe(imageId);
    });
  });

  // 5. PERFORMANCE VALIDATION TESTS
  describe('Performance Validation', () => {
    test('should validate large datasets efficiently', () => {
      const startTime = Date.now();
      
      // Create array of 1000 valid users
      const users = Array.from({ length: 1000 }, (_, i) => ({
        id: `123e4567-e89b-12d3-a456-42661417${i.toString().padStart(4, '0')}`,
        email: `user${i}@example.com`,
        name: `User ${i}`
      }));

      users.forEach(user => {
        const result = UserSchema.safeParse(user);
        expect(result.success).toBe(true);
      });

      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Should validate 1000 users in reasonable time (adjust threshold as needed)
      expect(duration).toBeLessThan(1000); // 1 second
    });

    test('should handle deeply nested objects efficiently', () => {
      const complexPolygon = {
        original_image_id: '123e4567-e89b-12d3-a456-426614174000',
        points: Array.from({ length: 100 }, (_, i) => ({ x: i, y: i * 2 })),
        label: 'complex_shape',
        metadata: {
          complexity: 'high',
          generatedBy: 'algorithm',
          confidence: 0.95,
          additionalData: {
            nested: {
              deeply: {
                veryDeep: 'value'
              }
            }
          }
        }
      };

      const startTime = Date.now();
      const result = PolygonSchema.safeParse(complexPolygon);
      const endTime = Date.now();

      expect(result.success).toBe(true);
      expect(endTime - startTime).toBeLessThan(100); // Should be very fast
    });
  });

  // 6. ERROR MESSAGE QUALITY TESTS
  describe('Error Message Quality', () => {
    test('should provide clear error messages for common mistakes', () => {
      const invalidData = {
        email: 'invalid-email',
        name: 'A'.repeat(200) // Assuming there's a length limit
      };

      const result = UserSchema.safeParse(invalidData);
      expect(result.success).toBe(false);

      if (!result.success) {
        const emailError = result.error.issues.find(issue => 
          issue.path.includes('email')
        );
        expect(emailError?.message).toContain('email');
        
        // Error messages should be user-friendly
        expect(emailError?.message).not.toContain('regex');
        expect(emailError?.message).not.toContain('ZodError');
      }
    });

    test('should provide specific field path information', () => {
      const invalidGarment = {
        user_id: '123e4567-e89b-12d3-a456-426614174000',
        original_image_id: '123e4567-e89b-12d3-a456-426614174001',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png',
        metadata: {
          type: 'invalid_type',
          color: '', // Empty color
          season: 'invalid_season'
        }
      };

      const result = GarmentSchema.safeParse(invalidGarment);
      expect(result.success).toBe(false);

      if (!result.success) {
        const typeError = result.error.issues.find(issue => 
          issue.path.includes('type')
        );
        const colorError = result.error.issues.find(issue => 
          issue.path.includes('color')
        );
        const seasonError = result.error.issues.find(issue => 
          issue.path.includes('season')
        );

        expect(typeError?.path).toEqual(['metadata', 'type']);
        expect(colorError?.path).toEqual(['metadata', 'color']);
        expect(seasonError?.path).toEqual(['metadata', 'season']);
      }
    });
  });

  // 7. TRANSFORMATION AND COERCION TESTS
  describe('Data Transformation and Coercion', () => {
    test('should handle date string to Date object conversion', () => {
      const userWithStringDate = {
        email: 'test@example.com',
        created_at: '2023-01-01T00:00:00.000Z'
      };

      const result = UserSchema.safeParse(userWithStringDate);
      expect(result.success).toBe(true);

      if (result.success) {
        // Depending on your schema, this might be coerced to Date
        expect(typeof result.data.created_at).toBe('object');
      }
    });

    test('should trim whitespace from strings', () => {
      const userWithWhitespace = {
        email: '  test@example.com  ',
        name: '  John Doe  '
      };

      const result = UserSchema.safeParse(userWithWhitespace);
      
      // This test depends on whether you've added .trim() to your schemas
      // If not, consider adding it for better user experience
    });
  });

  // 8. VERSION COMPATIBILITY TESTS
  describe('Schema Version Compatibility', () => {
    test('should handle backward compatibility', () => {
      // Test old format without new fields
      const oldFormatUser = {
        email: 'old@example.com'
        // Missing newer fields like linkedProviders, oauth_provider
      };

      const result = UserSchema.safeParse(oldFormatUser);
      expect(result.success).toBe(true);
    });

    test('should ignore unknown fields gracefully', () => {
      const userWithExtraFields = {
        email: 'test@example.com',
        unknownField: 'should be ignored',
        anotherUnknownField: 123
      };

      // Depending on your schema configuration (.strict() or not)
      const result = UserSchema.safeParse(userWithExtraFields);
      
      // Document expected behavior:
      // - If using .strict(), this should fail
      // - If not using .strict(), this should succeed and ignore extra fields
    });
  });
});

// 9. INTEGRATION TEST HELPERS
export const testHelpers = {
  /**
   * Generate valid test data for any schema
   */
  generateValidData: {
    user: (overrides: Partial<any> = {}) => ({
      id: '123e4567-e89b-12d3-a456-426614174000',
      email: 'test@example.com',
      name: 'Test User',
      created_at: new Date(),
      ...overrides
    }),

    garment: (overrides: Partial<any> = {}) => ({
      id: '123e4567-e89b-12d3-a456-426614174000',
      user_id: '123e4567-e89b-12d3-a456-426614174001',
      original_image_id: '123e4567-e89b-12d3-a456-426614174002',
      file_path: '/uploads/garment.jpg',
      mask_path: '/uploads/mask.png',
      metadata: {
        type: 'shirt',
        color: 'blue',
        pattern: 'solid',
        season: 'summer'
      },
      created_at: new Date(),
      updated_at: new Date(),
      data_version: 1,
      ...overrides
    }),

    polygon: (overrides: Partial<any> = {}) => ({
      id: '123e4567-e89b-12d3-a456-426614174000',
      original_image_id: '123e4567-e89b-12d3-a456-426614174001',
      points: [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
        { x: 100, y: 100 },
        { x: 0, y: 100 }
      ],
      label: 'test_polygon',
      created_at: new Date(),
      ...overrides
    })
  },

  /**
   * Validate schema and return detailed results
   */
  validateWithDetails: <T>(schema: z.ZodSchema<T>, data: unknown) => {
    const result = schema.safeParse(data);
    return {
      isValid: result.success,
      data: result.success ? result.data : null,
      errors: result.success ? [] : result.error.issues,
      errorCount: result.success ? 0 : result.error.issues.length,
      errorsByField: result.success ? {} : result.error.issues.reduce((acc, issue) => {
        const field = issue.path.join('.');
        if (!acc[field]) acc[field] = [];
        acc[field].push(issue.message);
        return acc;
      }, {} as Record<string, string[]>)
    };
  }
};