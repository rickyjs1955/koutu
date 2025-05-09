// shared/src/schemas/garment.test.ts
import { 
    GarmentSchema, 
    CreateGarmentSchema, 
    UpdateGarmentMetadataSchema 
  } from './garment';
  
  describe('Garment Schemas', () => {
    describe('GarmentSchema', () => {
      test('should validate a valid garment', () => {
        const validGarment = {
          id: '123e4567-e89b-12d3-a456-426614174000',
          original_image_id: '123e4567-e89b-12d3-a456-426614174001',
          file_path: '/uploads/garment.png',
          mask_path: '/uploads/garment_mask.png',
          metadata: {
            type: 'shirt',
            color: 'blue',
            season: 'summer',
            tags: ['casual', 'cotton']
          },
          created_at: new Date(),
          updated_at: new Date(),
          data_version: 1
        };
  
        const result = GarmentSchema.safeParse(validGarment);
        expect(result.success).toBe(true);
      });
  
      test('should reject invalid garment type', () => {
        const invalidGarment = {
          id: '123e4567-e89b-12d3-a456-426614174000',
          original_image_id: '123e4567-e89b-12d3-a456-426614174001',
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
  
    describe('CreateGarmentSchema', () => {
      test('should validate a valid create garment input', () => {
        const validInput = {
          original_image_id: '123e4567-e89b-12d3-a456-426614174001',
          metadata: {
            type: 'pants',
            color: 'black',
            pattern: 'solid',
            season: 'all'
          },
          mask_data: {
            width: 800,
            height: 600,
            data: [0, 0, 1, 1, 0, 0]
          }
        };
  
        const result = CreateGarmentSchema.safeParse(validInput);
        expect(result.success).toBe(true);
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
  });