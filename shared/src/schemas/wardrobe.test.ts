// /shared/src/schemas/wardrobe.test.ts
import { describe, test, expect } from '@jest/globals';
import {
  WardrobeSchema,
  CreateWardrobeSchema,
  UpdateWardrobeSchema,
  AddGarmentToWardrobeSchema,
  WardrobeResponseSchema
} from './wardrobe';

describe('Wardrobe Schema Tests', () => {
  describe('WardrobeSchema', () => {
    test('should validate complete wardrobe', () => {
      const validWardrobe = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        name: 'Summer Collection',
        description: 'My favorite summer outfits and garments',
        created_at: new Date(),
        updated_at: new Date()
      };

      const result = WardrobeSchema.safeParse(validWardrobe);
      expect(result.success).toBe(true);
    });

    test('should validate minimal wardrobe', () => {
      const minimalWardrobe = {
        name: 'Casual Wear'
      };

      const result = WardrobeSchema.safeParse(minimalWardrobe);
      expect(result.success).toBe(true);
    });

    test('should enforce name constraints', () => {
      // Empty name
      const emptyName = { name: '' };
      expect(WardrobeSchema.safeParse(emptyName).success).toBe(false);

      // Too long name
      const longName = { name: 'x'.repeat(101) };
      expect(WardrobeSchema.safeParse(longName).success).toBe(false);

      // Valid name
      const validName = { name: 'My Wardrobe' };
      expect(WardrobeSchema.safeParse(validName).success).toBe(true);
    });

    test('should enforce description constraints', () => {
      // Too long description
      const longDesc = { 
        name: 'Test',
        description: 'x'.repeat(1001) 
      };
      expect(WardrobeSchema.safeParse(longDesc).success).toBe(false);

      // Valid description
      const validDesc = { 
        name: 'Test',
        description: 'A collection of my favorite garments for special occasions'
      };
      expect(WardrobeSchema.safeParse(validDesc).success).toBe(true);
    });

    test('should validate UUID format', () => {
      const invalidUUID = {
        id: 'not-a-uuid',
        name: 'Test Wardrobe'
      };
      expect(WardrobeSchema.safeParse(invalidUUID).success).toBe(false);

      const validUUID = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        name: 'Test Wardrobe'
      };
      expect(WardrobeSchema.safeParse(validUUID).success).toBe(true);
    });
  });

  describe('CreateWardrobeSchema', () => {
    test('should omit system fields', () => {
      const createData = {
        name: 'New Wardrobe',
        description: 'A brand new wardrobe collection',
        // Should not include id, created_at, updated_at
      };

      const result = CreateWardrobeSchema.safeParse(createData);
      expect(result.success).toBe(true);
    });

    test('should reject system fields', () => {
      const withSystemFields = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        name: 'New Wardrobe',
        created_at: new Date(),
        updated_at: new Date()
      };

      const result = CreateWardrobeSchema.safeParse(withSystemFields);
      expect(result.success).toBe(true);
      
      // But the schema should strip these fields
      if (result.success) {
        expect(result.data).not.toHaveProperty('id');
        expect(result.data).not.toHaveProperty('created_at');
        expect(result.data).not.toHaveProperty('updated_at');
      }
    });
  });

  describe('UpdateWardrobeSchema', () => {
    test('should allow partial updates', () => {
      const updateName = { name: 'Updated Name' };
      expect(UpdateWardrobeSchema.safeParse(updateName).success).toBe(true);

      const updateDesc = { description: 'Updated description' };
      expect(UpdateWardrobeSchema.safeParse(updateDesc).success).toBe(true);

      const updateBoth = { 
        name: 'Updated Name',
        description: 'Updated description'
      };
      expect(UpdateWardrobeSchema.safeParse(updateBoth).success).toBe(true);

      const updateNothing = {};
      expect(UpdateWardrobeSchema.safeParse(updateNothing).success).toBe(true);
    });

    test('should enforce same constraints as create', () => {
      const invalidUpdate = {
        name: '', // Empty name not allowed
        description: 'x'.repeat(1001) // Too long
      };

      const result = UpdateWardrobeSchema.safeParse(invalidUpdate);
      expect(result.success).toBe(false);
    });
  });

  describe('AddGarmentToWardrobeSchema', () => {
    test('should validate garment addition', () => {
      const validAddition = {
        garmentId: '123e4567-e89b-12d3-a456-426614174000',
        position: 5
      };

      const result = AddGarmentToWardrobeSchema.safeParse(validAddition);
      expect(result.success).toBe(true);
    });

    test('should provide default position', () => {
      const withoutPosition = {
        garmentId: '123e4567-e89b-12d3-a456-426614174000'
      };

      const result = AddGarmentToWardrobeSchema.safeParse(withoutPosition);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.position).toBe(0);
      }
    });

    test('should reject negative positions', () => {
      const negativePosition = {
        garmentId: '123e4567-e89b-12d3-a456-426614174000',
        position: -1
      };

      const result = AddGarmentToWardrobeSchema.safeParse(negativePosition);
      expect(result.success).toBe(false);
    });

    test('should reject non-integer positions', () => {
      const floatPosition = {
        garmentId: '123e4567-e89b-12d3-a456-426614174000',
        position: 2.5
      };

      const result = AddGarmentToWardrobeSchema.safeParse(floatPosition);
      expect(result.success).toBe(false);
    });

    test('should validate garment ID format', () => {
      const invalidId = {
        garmentId: 'not-a-uuid',
        position: 0
      };

      const result = AddGarmentToWardrobeSchema.safeParse(invalidId);
      expect(result.success).toBe(false);
    });
  });

  describe('WardrobeResponseSchema', () => {
    test('should include garments array', () => {
      const responseWithGarments = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        name: 'My Wardrobe',
        description: 'Test wardrobe',
        created_at: new Date(),
        updated_at: new Date(),
        garments: [
          { id: '1', name: 'Shirt' },
          { id: '2', name: 'Pants' }
        ]
      };

      const result = WardrobeResponseSchema.safeParse(responseWithGarments);
      expect(result.success).toBe(true);
    });

    test('should allow empty garments array', () => {
      const emptyGarments = {
        name: 'Empty Wardrobe',
        garments: []
      };

      const result = WardrobeResponseSchema.safeParse(emptyGarments);
      expect(result.success).toBe(true);
    });

    test('should allow missing garments array', () => {
      const noGarments = {
        name: 'Wardrobe Without Garments'
      };

      const result = WardrobeResponseSchema.safeParse(noGarments);
      expect(result.success).toBe(true);
    });
  });

  describe('Mobile/Flutter considerations', () => {
    test('should handle date serialization for cross-platform', () => {
      const wardrobeWithStringDates = {
        name: 'Cross-platform Wardrobe',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      // Parse with Date objects (from string)
      const result = WardrobeSchema.safeParse({
        ...wardrobeWithStringDates,
        created_at: new Date(wardrobeWithStringDates.created_at),
        updated_at: new Date(wardrobeWithStringDates.updated_at)
      });

      expect(result.success).toBe(true);
    });

    test('should validate wardrobe names suitable for mobile display', () => {
      const mobileNames = [
        'Favorites ❤️',
        'Work Attire',
        'Weekend Casual',
        'Special Events ✨',
        'Sports & Fitness 🏃',
        'Travel Essentials ✈️'
      ];

      mobileNames.forEach(name => {
        const result = WardrobeSchema.safeParse({ name });
        expect(result.success).toBe(true);
      });
    });

    test('should handle special characters in names', () => {
      const specialCharNames = [
        'Spring/Summer 2024',
        'Black & White Collection',
        'Retro 80\'s Style',
        'High-End Designer',
        'Mix & Match Basics'
      ];

      specialCharNames.forEach(name => {
        const result = WardrobeSchema.safeParse({ name });
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Batch operations preparation', () => {
    test('should validate multiple garment additions', () => {
      const garmentIds = [
        '123e4567-e89b-12d3-a456-426614174000',
        '223e4567-e89b-12d3-a456-426614174001',
        '323e4567-e89b-12d3-a456-426614174002'
      ];

      const additions = garmentIds.map((id, index) => ({
        garmentId: id,
        position: index
      }));

      additions.forEach(addition => {
        const result = AddGarmentToWardrobeSchema.safeParse(addition);
        expect(result.success).toBe(true);
      });
    });

    test('should handle reordering scenarios', () => {
      // Simulate reordering by updating positions
      const reorderOps = [
        { garmentId: '123e4567-e89b-12d3-a456-426614174000', position: 2 },
        { garmentId: '223e4567-e89b-12d3-a456-426614174001', position: 0 },
        { garmentId: '323e4567-e89b-12d3-a456-426614174002', position: 1 }
      ];

      reorderOps.forEach(op => {
        const result = AddGarmentToWardrobeSchema.safeParse(op);
        expect(result.success).toBe(true);
      });
    });
  });

  describe('Type inference', () => {
    test('should infer correct types', () => {
      const wardrobe: z.infer<typeof WardrobeSchema> = {
        id: '123e4567-e89b-12d3-a456-426614174000',
        name: 'Type Test',
        description: 'Testing type inference',
        created_at: new Date(),
        updated_at: new Date()
      };

      // This should compile without errors
      expect(typeof wardrobe.id).toBe('string');
      expect(typeof wardrobe.name).toBe('string');
      expect(wardrobe.description).toBeDefined();
      expect(wardrobe.created_at).toBeInstanceOf(Date);
    });
  });
});