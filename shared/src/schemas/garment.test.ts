// shared/src/schemas/garment.test.ts
import { describe, test, expect } from '@jest/globals';
import { 
  GarmentSchema, 
  CreateGarmentSchema, 
  UpdateGarmentMetadataSchema,
  MobileGarmentFieldsSchema,
  EnhancedMetadataSchema,
  MobileGarmentListItemSchema,
  BatchCreateGarmentSchema,
  GarmentResponseSchema,
  MobileGarmentResponseSchema,
  GarmentFilterSchema
} from './garment';

describe('Garment Schema Tests', () => {
  describe('MobileGarmentFieldsSchema', () => {
    test('should validate mobile-specific garment fields', () => {
      const validMobileFields = {
        thumbnail_url: 'https://example.com/thumbs/garment_123_thumb.jpg',
        preview_url: 'https://example.com/preview/garment_123_preview.jpg',
        full_image_url: 'https://example.com/full/garment_123.jpg',
        mask_thumbnail_url: 'https://example.com/masks/mask_123_thumb.png',
        is_favorite: true,
        wear_count: 15,
        last_worn_date: new Date('2024-01-15'),
        local_id: 'local_garment_123',
        sync_status: 'synced',
        cached_at: new Date(),
        file_size: 2048576, // 2MB
        dimensions: {
          width: 1024,
          height: 1536
        }
      };

      const result = MobileGarmentFieldsSchema.safeParse(validMobileFields);
      expect(result.success).toBe(true);
    });

    test('should validate sync status values', () => {
      const validStatuses = ['synced', 'pending', 'conflict'];
      
      validStatuses.forEach(status => {
        const result = MobileGarmentFieldsSchema.safeParse({ sync_status: status });
        expect(result.success).toBe(true);
      });

      const result = MobileGarmentFieldsSchema.safeParse({ sync_status: 'invalid' });
      expect(result.success).toBe(false);
    });

    test('should handle default values', () => {
      const minimal = {};
      const result = MobileGarmentFieldsSchema.safeParse(minimal);
      
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.is_favorite).toBe(false);
        expect(result.data.wear_count).toBe(0);
        expect(result.data.sync_status).toBe('synced');
      }
    });
  });

  describe('EnhancedMetadataSchema', () => {
    test('should validate complete enhanced metadata', () => {
      const validMetadata = {
        type: 'dress',
        color: 'navy blue',
        secondary_colors: ['white', 'gold'],
        pattern: 'floral',
        season: 'spring',
        occasion: 'formal',
        brand: 'Chanel',
        size: 'M',
        material: '100% Silk',
        care_instructions: ['Dry clean only', 'Iron on low heat'],
        purchase_date: new Date('2023-12-01'),
        purchase_price: 299.99,
        tags: ['evening', 'cocktail', 'designer'],
        notes: 'Bought for wedding reception'
      };

      const result = EnhancedMetadataSchema.safeParse(validMetadata);
      expect(result.success).toBe(true);
    });

    test('should validate garment types', () => {
      const validTypes = ['shirt', 'pants', 'dress', 'jacket', 'skirt', 'accessories', 'shoes', 'bags', 'other'];
      
      validTypes.forEach(type => {
        const result = EnhancedMetadataSchema.safeParse({ type, color: 'black' });
        expect(result.success).toBe(true);
      });
    });

    test('should validate patterns', () => {
      const validPatterns = ['solid', 'striped', 'plaid', 'floral', 'geometric', 'abstract', 'animal_print', 'other'];
      
      validPatterns.forEach(pattern => {
        const result = EnhancedMetadataSchema.safeParse({ 
          type: 'shirt', 
          color: 'white',
          pattern 
        });
        expect(result.success).toBe(true);
      });
    });

    test('should enforce array length limits', () => {
      const tooManyTags = Array(101).fill('tag'); // 101 tags, exceeds MAX_MOBILE_ARRAY_LENGTH
      
      const result = EnhancedMetadataSchema.safeParse({
        type: 'shirt',
        color: 'blue',
        tags: tooManyTags
      });
      
      expect(result.success).toBe(false);
    });

    test('should enforce text length limits', () => {
      const longNotes = 'x'.repeat(501); // Exceeds MAX_MOBILE_TEXT_LENGTH
      
      const result = EnhancedMetadataSchema.safeParse({
        type: 'pants',
        color: 'black',
        notes: longNotes
      });
      
      expect(result.success).toBe(false);
    });
  });

  describe('GarmentSchema', () => {
    test('should validate complete garment with mobile fields', () => {
      const validGarment = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        original_image_id: '123e4567-e89b-12d3-a456-426614174002',
        file_path: '/uploads/garments/garment_123.jpg',
        mask_path: '/uploads/masks/mask_123.png',
        metadata: {
          type: 'shirt',
          color: 'blue',
          pattern: 'striped',
          season: 'summer',
          brand: 'Nike',
          tags: ['casual', 'sport']
        },
        thumbnail_url: 'https://example.com/thumbs/garment_123_thumb.jpg',
        is_favorite: true,
        wear_count: 5,
        last_worn_date: new Date('2024-01-20'),
        sync_status: 'synced',
        created_at: new Date(),
        updated_at: new Date(),
        data_version: 1
      };

      const result = GarmentSchema.safeParse(validGarment);
      expect(result.success).toBe(true);
    });

    test('should require essential fields', () => {
      const missingRequired = {
        // Missing user_id, original_image_id, file_path, mask_path, metadata
        id: '123e4567-e89b-12d3-a456-426614174000'
      };

      const result = GarmentSchema.safeParse(missingRequired);
      expect(result.success).toBe(false);
    });

    test('should validate UUID formats', () => {
      const invalidUUIDs = {
        id: 'not-a-uuid',
        user_id: '123',
        original_image_id: 'invalid',
        file_path: '/test.jpg',
        mask_path: '/test.png',
        metadata: { type: 'shirt', color: 'red' }
      };

      const result = GarmentSchema.safeParse(invalidUUIDs);
      expect(result.success).toBe(false);
    });

    test('should reject invalid garment type', () => {
      const invalidGarment = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        original_image_id: '123e4567-e89b-12d3-a456-426614174002',
        file_path: '/uploads/garment.png',
        mask_path: '/uploads/garment_mask.png',
        metadata: {
          type: 'invalidType', // Invalid type
          color: 'blue',
          season: 'summer'
        }
      };

      const result = GarmentSchema.safeParse(invalidGarment);
      expect(result.success).toBe(false);
      if (!result.success) {
        // Fix: Zod returns path as an array of strings, not a single string with dots
        expect(result.error.issues[0].path).toEqual(['metadata', 'type']);
      }
    });
  });

  describe('MobileGarmentListItemSchema', () => {
    test('should validate mobile list item', () => {
      const validListItem = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        thumbnail_url: 'https://example.com/thumbs/garment_123_thumb.jpg',
        metadata: {
          type: 'jacket',
          color: 'brown',
          brand: 'Zara'
        },
        is_favorite: false,
        wear_count: 3,
        last_worn_date: new Date('2024-01-10'),
        sync_status: 'pending'
      };

      const result = MobileGarmentListItemSchema.safeParse(validListItem);
      expect(result.success).toBe(true);
    });

    test('should require minimal metadata', () => {
      const minimalItem = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        thumbnail_url: 'https://example.com/thumb.jpg',
        metadata: {
          type: 'shoes',
          color: 'black'
          // brand is optional
        },
        is_favorite: true,
        wear_count: 0,
        sync_status: 'synced'
      };

      const result = MobileGarmentListItemSchema.safeParse(minimalItem);
      expect(result.success).toBe(true);
    });
  });

  describe('CreateGarmentSchema', () => {
    test('should validate garment creation with mobile fields', () => {
      const createData = {
        original_image_id: '123e4567-e89b-12d3-a456-426614174002',
        metadata: {
          type: 'pants',
          color: 'black',
          brand: 'Levi\'s',
          size: '32W 34L',
          tags: ['denim', 'casual']
        },
        mask_data: {
          data: [0, 0, 100, 0, 100, 200, 0, 200], // Flattened array of points
          width: 500,
          height: 700,
          format: 'raw'
        },
        local_id: 'temp_garment_456'
      };

      const result = CreateGarmentSchema.safeParse(createData);
      expect(result.success).toBe(true);
    });

    test('should validate mask data format', () => {
      const validMaskData = {
        original_image_id: '123e4567-e89b-12d3-a456-426614174002',
        metadata: { type: 'shirt', color: 'white' },
        mask_data: {
          data: [0, 0, 100, 0, 100, 100, 0, 100], // Valid polygon data
          width: 500,
          height: 700,
          format: 'raw'
        }
      };

      const result = CreateGarmentSchema.safeParse(validMaskData);
      expect(result.success).toBe(true);

      // Test with different format
      const rleFormat = {
        ...validMaskData,
        mask_data: {
          ...validMaskData.mask_data,
          format: 'rle' // Run-length encoding format
        }
      };
      
      const rleResult = CreateGarmentSchema.safeParse(rleFormat);
      expect(rleResult.success).toBe(true);
    });

    test('should require mask_data', () => {
      const invalidInput = {
        original_image_id: '123e4567-e89b-12d3-a456-426614174001',
        metadata: {
          type: 'pants',
          color: 'black'
        }
        // Missing mask_data
      };

      const result = CreateGarmentSchema.safeParse(invalidInput);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0].path).toContain('mask_data');
      }
    });
  });

  describe('UpdateGarmentMetadataSchema', () => {
    test('should allow partial metadata updates', () => {
      const updateData = {
        metadata: {
          color: 'red',
          season: 'winter',
          tags: ['updated', 'winter-collection']
        },
        wear_count: 10,
        last_worn_date: new Date(),
        is_favorite: true
      };

      const result = UpdateGarmentMetadataSchema.safeParse(updateData);
      expect(result.success).toBe(true);
    });

    test('should validate mobile-specific updates', () => {
      const mobileUpdate = {
        metadata: {}, // Empty metadata for partial update
        wear_count_increment: 1,
        mark_as_worn: true,
        is_favorite: true
      };

      const result = UpdateGarmentMetadataSchema.safeParse(mobileUpdate);
      expect(result.success).toBe(true);
    });

    test('should validate a valid metadata update', () => {
      const validUpdate = {
        metadata: {
          type: 'jacket',
          color: 'red',
          pattern: 'plaid',
          season: 'winter',
          brand: 'Example',
          tags: ['warm', 'outdoor']
        }
      };

      const result = UpdateGarmentMetadataSchema.safeParse(validUpdate);
      expect(result.success).toBe(true);
    });
  });

  describe('BatchCreateGarmentSchema', () => {
    test('should validate batch garment creation', () => {
      const batchCreate = {
        garments: [
          {
            original_image_id: '123e4567-e89b-12d3-a456-426614174000',
            metadata: {
              type: 'shirt',
              color: 'blue',
              brand: 'Nike'
            },
            mask_data: {
              data: [0, 0, 100, 0, 100, 100, 0, 100],
              width: 500,
              height: 500,
              format: 'raw'
            }
          },
          {
            original_image_id: '223e4567-e89b-12d3-a456-426614174000',
            metadata: {
              type: 'pants',
              color: 'black',
              brand: 'Levi\'s'
            },
            mask_data: {
              data: [0, 0, 100, 0, 100, 200, 0, 200],
              width: 500,
              height: 700,
              format: 'raw'
            }
          }
        ]
      };

      const result = BatchCreateGarmentSchema.safeParse(batchCreate);
      expect(result.success).toBe(true);
    });

    test('should enforce batch size limits', () => {
      const tooManyGarments = Array(21).fill({
        original_image_id: '123e4567-e89b-12d3-a456-426614174000',
        metadata: { type: 'shirt', color: 'blue' },
        mask_data: { data: [0, 0, 1, 0, 1, 1], width: 100, height: 100, format: 'raw' }
      });
      
      const batchOp = {
        garments: tooManyGarments
      };

      const result = BatchCreateGarmentSchema.safeParse(batchOp);
      expect(result.success).toBe(false);
    });
  });

  describe('GarmentResponseSchema', () => {
    test('should omit user_id from response', () => {
      const garmentData = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        original_image_id: '123e4567-e89b-12d3-a456-426614174002',
        file_path: '/uploads/garment.jpg',
        mask_path: '/uploads/mask.png',
        metadata: {
          type: 'shirt',
          color: 'blue'
        },
        is_favorite: true,
        wear_count: 5,
        created_at: new Date(),
        updated_at: new Date()
      };

      const result = GarmentResponseSchema.safeParse(garmentData);
      expect(result.success).toBe(true);
      
      // Should not include user_id even if provided
      const withUserId = {
        ...garmentData,
        user_id: '123e4567-e89b-12d3-a456-426614174001'
      };
      
      const resultWithUser = GarmentResponseSchema.safeParse(withUserId);
      expect(resultWithUser.success).toBe(true);
      if (resultWithUser.success) {
        expect(resultWithUser.data).not.toHaveProperty('user_id');
      }
    });
  });

  describe('MobileGarmentResponseSchema', () => {
    test('should include mobile-optimized fields', () => {
      const mobileResponse = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        metadata: {
          type: 'dress',
          color: 'red',
          brand: 'Zara'
        },
        thumbnail_url: 'https://cdn.example.com/t/123.jpg',
        preview_url: 'https://cdn.example.com/p/123.jpg',
        is_favorite: true,
        wear_count: 3,
        last_worn_date: new Date('2024-01-15'),
        sync_status: 'synced',
        cached_at: new Date()
      };

      const result = MobileGarmentResponseSchema.safeParse(mobileResponse);
      expect(result.success).toBe(true);
    });
  });

  describe('GarmentFilterSchema', () => {
    test('should validate filter options', () => {
      const validFilter = {
        types: ['shirt', 'pants'],
        colors: ['blue', 'black', 'white'],
        brands: ['Nike', 'Adidas'],
        seasons: ['summer', 'spring'],
        occasions: ['casual', 'sport'],
        is_favorite: true,
        min_wear_count: 5,
        max_wear_count: 20,
        worn_after: new Date('2024-01-01'),
        worn_before: new Date('2024-12-31'),
        tags: ['comfortable', 'everyday'],
        has_notes: true
      };

      const result = GarmentFilterSchema.safeParse(validFilter);
      expect(result.success).toBe(true);
    });

    test('should allow partial filters', () => {
      const partialFilter = {
        types: ['dress'],
        is_favorite: true
      };

      const result = GarmentFilterSchema.safeParse(partialFilter);
      expect(result.success).toBe(true);
    });
  });


  describe('Cross-platform compatibility', () => {
    test('should handle date serialization', () => {
      const garmentWithDates = {
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        original_image_id: '123e4567-e89b-12d3-a456-426614174002',
        file_path: '/test.jpg',
        mask_path: '/test.png',
        metadata: { type: 'shirt', color: 'blue' },
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        last_worn_date: new Date().toISOString(),
        cached_at: new Date().toISOString()
      };

      const result = GarmentSchema.safeParse({
        ...garmentWithDates,
        created_at: new Date(garmentWithDates.created_at),
        updated_at: new Date(garmentWithDates.updated_at),
        last_worn_date: new Date(garmentWithDates.last_worn_date),
        cached_at: new Date(garmentWithDates.cached_at)
      });

      expect(result.success).toBe(true);
    });

    test('should handle optional fields for offline support', () => {
      const offlineGarment = {
        user_id: '123e4567-e89b-12d3-a456-426614174001',
        original_image_id: '123e4567-e89b-12d3-a456-426614174002',
        file_path: 'local://garment_123.jpg', // Local file
        mask_path: 'local://mask_123.png',
        metadata: { type: 'pants', color: 'gray' },
        local_id: 'offline_garment_123',
        sync_status: 'pending'
        // No URLs since it's offline
      };

      const result = GarmentSchema.safeParse(offlineGarment);
      expect(result.success).toBe(true);
    });
  });

  describe('Performance considerations', () => {
    test('should handle large metadata efficiently', () => {
      const largeMetadata = {
        type: 'accessories',
        color: 'multicolor',
        tags: Array(50).fill(0).map((_, i) => `tag${i}`), // 50 tags
        notes: 'x'.repeat(400), // 400 chars
        care_instructions: Array(10).fill('Instruction'),
        brand: 'LongBrandName'.repeat(5)
      };

      const result = EnhancedMetadataSchema.safeParse(largeMetadata);
      expect(result.success).toBe(true);
    });

    test('should validate within mobile constraints', () => {
      const mobileOptimized = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        thumbnail_url: 'https://cdn.example.com/t/123.jpg', // Short URL
        metadata: {
          type: 'shirt',
          color: 'blue',
          brand: 'Nike'
        },
        is_favorite: true,
        wear_count: 10,
        sync_status: 'synced'
      };

      const result = MobileGarmentListItemSchema.safeParse(mobileOptimized);
      expect(result.success).toBe(true);
    });
  });
});