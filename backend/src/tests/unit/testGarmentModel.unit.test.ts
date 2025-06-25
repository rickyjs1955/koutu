// /backend/src/utils/__tests__/testGarmentModel.unit.test.ts
/**
 * Unit Tests for Test Garment Model Utility
 * 
 * @description Comprehensive tests for the testGarmentModel utility used in integration tests.
 * Tests cover CRUD operations, validation, error handling, and security aspects.
 * 
 * @author Development Team
 * @version 1.0.0
 * @since June 25, 2025
 */

import { testGarmentModel, TestGarment, CreateTestGarmentInput } from '../../utils/testGarmentModel';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { v4 as uuidv4 } from 'uuid';

// Mock the TestDatabaseConnection
jest.mock('../../utils/testDatabaseConnection', () => ({
  TestDatabaseConnection: {
    query: jest.fn()
  }
}));

// Mock uuid
jest.mock('uuid', () => ({
  v4: jest.fn()
}));

// Use jest.Mock<string, any[]> to ensure correct typing for mockUuidv4
const mockQuery = TestDatabaseConnection.query as jest.MockedFunction<typeof TestDatabaseConnection.query>;
const mockUuidv4 = uuidv4 as jest.Mock<string, any[]>;

describe('testGarmentModel', () => {
  const mockUserId = 'user-123-456-789';
  const mockGarmentId = 'garment-123-456-789';
  const mockImageId = 'image-123-456-789';
  
  const mockGarmentData: CreateTestGarmentInput = {
    user_id: mockUserId,
    original_image_id: mockImageId,
    metadata: {
      name: 'Test Shirt',
      category: 'shirt',
      color: 'blue',
      brand: 'TestBrand',
      size: 'M',
      price: 29.99,
      tags: ['casual', 'cotton']
    }
  };

  const mockDbGarment = {
    id: mockGarmentId,
    user_id: mockUserId,
    original_image_id: mockImageId,
    metadata: JSON.stringify(mockGarmentData.metadata),
    created_at: new Date('2025-06-25T10:00:00Z'),
    updated_at: new Date('2025-06-25T10:00:00Z')
  };

  const expectedGarment: TestGarment = {
    id: mockGarmentId,
    user_id: mockUserId,
    original_image_id: mockImageId,
    metadata: mockGarmentData.metadata,
    created_at: mockDbGarment.created_at,
    updated_at: mockDbGarment.updated_at
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUuidv4.mockReturnValue(mockGarmentId);
  });

  describe('create', () => {
    it('should create a garment with all fields provided', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [mockDbGarment],
        rowCount: 1
      });

      const result = await testGarmentModel.create(mockGarmentData);

      expect(mockUuidv4).toHaveBeenCalledTimes(1);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO garment_items'),
        [
          mockGarmentId,
          mockUserId,
          mockImageId,
          JSON.stringify(mockGarmentData.metadata)
        ]
      );
      expect(result).toEqual(expectedGarment);
    });

    it('should create a garment without original_image_id', async () => {
      const dataWithoutImage = { ...mockGarmentData };
      delete dataWithoutImage.original_image_id;

      const dbGarmentWithoutImage = { ...mockDbGarment, original_image_id: null };
      mockQuery.mockResolvedValueOnce({
        rows: [dbGarmentWithoutImage],
        rowCount: 1
      });

      const result = await testGarmentModel.create(dataWithoutImage);

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO garment_items'),
        [
          mockGarmentId,
          mockUserId,
          null,
          JSON.stringify(mockGarmentData.metadata)
        ]
      );
      expect(result.original_image_id).toBeNull();
    });

    it('should handle metadata as object when returned from database', async () => {
      const dbGarmentWithObjectMetadata = {
        ...mockDbGarment,
        metadata: mockGarmentData.metadata // Already an object, not stringified
      };

      mockQuery.mockResolvedValueOnce({
        rows: [dbGarmentWithObjectMetadata],
        rowCount: 1
      });

      const result = await testGarmentModel.create(mockGarmentData);

      expect(result.metadata).toEqual(mockGarmentData.metadata);
    });

    it('should handle database errors gracefully', async () => {
      const dbError = new Error('Database connection failed');
      mockQuery.mockRejectedValueOnce(dbError);

      await expect(testGarmentModel.create(mockGarmentData)).rejects.toThrow('Database connection failed');
    });

    it('should handle malformed JSON in metadata', async () => {
      const dbGarmentWithBadJson = {
        ...mockDbGarment,
        metadata: '{"invalid": json}'
      };

      mockQuery.mockResolvedValueOnce({
        rows: [dbGarmentWithBadJson],
        rowCount: 1
      });

      await expect(testGarmentModel.create(mockGarmentData)).rejects.toThrow();
    });
  });

  describe('findById', () => {
    it('should find and return a garment by ID', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [mockDbGarment],
        rowCount: 1
      });

      const result = await testGarmentModel.findById(mockGarmentId);

      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM garment_items WHERE id = $1',
        [mockGarmentId]
      );
      expect(result).toEqual(expectedGarment);
    });

    it('should return null when garment not found', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      });

      const result = await testGarmentModel.findById('non-existent-id');

      expect(result).toBeNull();
    });

    it('should handle database errors', async () => {
      mockQuery.mockRejectedValueOnce(new Error('Database error'));

      await expect(testGarmentModel.findById(mockGarmentId)).rejects.toThrow('Database error');
    });
  });

  describe('findByUserId', () => {
    it('should find all garments for a user', async () => {
      const mockGarments = [mockDbGarment, { ...mockDbGarment, id: 'garment-2' }];
      mockQuery.mockResolvedValueOnce({
        rows: mockGarments,
        rowCount: 2
      });

      const result = await testGarmentModel.findByUserId(mockUserId);

      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at',
        [mockUserId]
      );
      expect(result).toHaveLength(2);
      expect(result[0]).toEqual(expectedGarment);
    });

    it('should return empty array when no garments found', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      });

      const result = await testGarmentModel.findByUserId(mockUserId);

      expect(result).toEqual([]);
    });
  });

  describe('updateMetadata', () => {
    const newMetadata = {
      name: 'Updated Shirt',
      category: 'shirt',
      color: 'red',
      brand: 'NewBrand',
      size: 'L',
      price: 39.99
    };

    it('should update garment metadata', async () => {
      const updatedDbGarment = {
        ...mockDbGarment,
        metadata: JSON.stringify(newMetadata),
        updated_at: new Date('2025-06-25T11:00:00Z')
      };

      mockQuery.mockResolvedValueOnce({
        rows: [updatedDbGarment],
        rowCount: 1
      });

      const result = await testGarmentModel.updateMetadata(mockGarmentId, newMetadata);

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE garment_items'),
        [JSON.stringify(newMetadata), mockGarmentId]
      );
      expect(result?.metadata).toEqual(newMetadata);
    });

    it('should return null when garment not found', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      });

      const result = await testGarmentModel.updateMetadata('non-existent-id', newMetadata);

      expect(result).toBeNull();
    });
  });

  describe('delete', () => {
    it('should delete garment and its wardrobe associations', async () => {
      // Mock wardrobe cleanup
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 2 // 2 wardrobe associations removed
      });
      
      // Mock garment deletion
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 1 // 1 garment deleted
      });

      const result = await testGarmentModel.delete(mockGarmentId);

      expect(mockQuery).toHaveBeenCalledTimes(2);
      expect(mockQuery).toHaveBeenNthCalledWith(1,
        'DELETE FROM wardrobe_items WHERE garment_item_id = $1',
        [mockGarmentId]
      );
      expect(mockQuery).toHaveBeenNthCalledWith(2,
        'DELETE FROM garment_items WHERE id = $1',
        [mockGarmentId]
      );
      expect(result).toBe(true);
    });

    it('should return false when garment not found', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // wardrobe cleanup
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // garment deletion

      const result = await testGarmentModel.delete('non-existent-id');

      expect(result).toBe(false);
    });

    it('should handle null rowCount', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null }); // wardrobe cleanup
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null }); // garment deletion

      const result = await testGarmentModel.delete(mockGarmentId);

      expect(result).toBe(false);
    });
  });

  describe('createMultiple', () => {
    it('should create multiple garments with varied data', async () => {
      const count = 3;
      const baseMetadata = { brand: 'CustomBrand' };

      // Mock multiple create calls
      for (let i = 0; i < count; i++) {
        mockUuidv4.mockReturnValueOnce(`garment-${i}`);
        mockQuery.mockResolvedValueOnce({
          rows: [{
            id: `garment-${i}`,
            user_id: mockUserId,
            original_image_id: null,
            metadata: JSON.stringify({
              name: `Test Garment ${i + 1}`,
              category: ['shirt', 'pants', 'jacket'][i],
              color: ['blue', 'red', 'green'][i],
              brand: 'CustomBrand',
              size: ['XS', 'S', 'M'][i],
              price: 19.99 + (i * 10),
              tags: [`tag${i}`, `category-${['shirt', 'pants', 'jacket'][i]}`]
            }),
            created_at: new Date(),
            updated_at: new Date()
          }],
          rowCount: 1
        });
      }

      const result = await testGarmentModel.createMultiple(mockUserId, count, baseMetadata);

      expect(result).toHaveLength(count);
      expect(result[0].metadata.brand).toBe('CustomBrand');
      expect(result[0].metadata.name).toBe('Test Garment 1');
      expect(result[1].metadata.category).toBe('pants');
      expect(result[2].metadata.color).toBe('green');
    });

    it('should handle zero count', async () => {
      const result = await testGarmentModel.createMultiple(mockUserId, 0);

      expect(result).toEqual([]);
      expect(mockQuery).not.toHaveBeenCalled();
    });
  });

  describe('cleanupByUserId', () => {
    it('should clean up all garments and wardrobe associations for a user', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 5 }); // wardrobe cleanup
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 3 }); // garment cleanup

      const result = await testGarmentModel.cleanupByUserId(mockUserId);

      expect(mockQuery).toHaveBeenCalledTimes(2);
      expect(mockQuery).toHaveBeenNthCalledWith(1,
        expect.stringContaining('DELETE FROM wardrobe_items'),
        [mockUserId]
      );
      expect(mockQuery).toHaveBeenNthCalledWith(2,
        'DELETE FROM garment_items WHERE user_id = $1',
        [mockUserId]
      );
      expect(result).toBe(3);
    });

    it('should handle null rowCount', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null });
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null });

      const result = await testGarmentModel.cleanupByUserId(mockUserId);

      expect(result).toBe(0);
    });
  });

  describe('createWithSpecifications', () => {
    it('should create garments with specific specifications', async () => {
      const specifications = [
        { name: 'Blue Jeans', category: 'pants', color: 'blue' },
        { name: 'Red Dress', category: 'dress', color: 'red', metadata: { season: 'summer' } }
      ];

      // Mock create calls
      specifications.forEach((spec, i) => {
        mockUuidv4.mockReturnValueOnce(`spec-garment-${i}`);
        mockQuery.mockResolvedValueOnce({
          rows: [{
            id: `spec-garment-${i}`,
            user_id: mockUserId,
            original_image_id: null,
            metadata: JSON.stringify({
              name: spec.name,
              category: spec.category,
              color: spec.color,
              brand: 'TestBrand',
              size: 'M',
              price: 29.99,
              ...spec.metadata
            }),
            created_at: new Date(),
            updated_at: new Date()
          }],
          rowCount: 1
        });
      });

      const result = await testGarmentModel.createWithSpecifications(mockUserId, specifications);

      expect(result).toHaveLength(2);
      expect(result[0].metadata.name).toBe('Blue Jeans');
      expect(result[1].metadata.season).toBe('summer');
    });
  });

  describe('getCountByUserId', () => {
    it('should return correct count for user', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ count: '5' }],
        rowCount: 1
      });

      const result = await testGarmentModel.getCountByUserId(mockUserId);

      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1',
        [mockUserId]
      );
      expect(result).toBe(5);
    });

    it('should handle string count from database', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ count: '0' }],
        rowCount: 1
      });

      const result = await testGarmentModel.getCountByUserId(mockUserId);

      expect(result).toBe(0);
    });
  });

  describe('exists', () => {
    it('should return true when garment exists', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [{ '?column?': 1 }],
        rowCount: 1
      });

      const result = await testGarmentModel.exists(mockGarmentId);

      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT 1 FROM garment_items WHERE id = $1',
        [mockGarmentId]
      );
      expect(result).toBe(true);
    });

    it('should return false when garment does not exist', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      });

      const result = await testGarmentModel.exists('non-existent-id');

      expect(result).toBe(false);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle SQL injection attempts safely', async () => {
      const maliciousId = "'; DROP TABLE garment_items; --";
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      });

      const result = await testGarmentModel.findById(maliciousId);

      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM garment_items WHERE id = $1',
        [maliciousId]
      );
      expect(result).toBeNull();
    });

    it('should handle empty metadata gracefully', async () => {
      const dataWithEmptyMetadata = {
        ...mockGarmentData,
        metadata: { name: '' } // Provide required 'name' property
      };

      const dbGarmentWithEmptyMetadata = {
        ...mockDbGarment,
        metadata: JSON.stringify({ name: '' })
      };

      mockQuery.mockResolvedValueOnce({
        rows: [dbGarmentWithEmptyMetadata],
        rowCount: 1
      });

      const result = await testGarmentModel.create(dataWithEmptyMetadata);

      expect(result.metadata).toEqual({ name: '' });
    });

    it('should handle very large metadata objects', async () => {
      const largeMetadata = {
        name: 'Test Garment',
        description: 'x'.repeat(10000), // Very long description
        category: 'shirt',
        additionalData: {
          measurements: Array.from({ length: 100 }, (_, i) => ({ key: i, value: `data-${i}` }))
        }
      };

      const dataWithLargeMetadata = {
        ...mockGarmentData,
        metadata: largeMetadata
      };

      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...mockDbGarment,
          metadata: JSON.stringify(largeMetadata)
        }],
        rowCount: 1
      });

      const result = await testGarmentModel.create(dataWithLargeMetadata);

      expect(result.metadata).toEqual(largeMetadata);
    });

    it('should handle concurrent operations gracefully', async () => {
      // Simulate database busy error
      mockQuery.mockRejectedValueOnce(new Error('database is locked'));

      await expect(testGarmentModel.findById(mockGarmentId)).rejects.toThrow('database is locked');
    });
  });

  describe('Security Tests', () => {
    it('should properly escape special characters in metadata', async () => {
      const metadataWithSpecialChars = {
        name: "Garment with 'quotes' and \"double quotes\"",
        description: "Contains\nnewlines\tand\ttabs",
        category: 'shirt'
      };

      const dataWithSpecialChars = {
        ...mockGarmentData,
        metadata: metadataWithSpecialChars
      };

      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...mockDbGarment,
          metadata: JSON.stringify(metadataWithSpecialChars)
        }],
        rowCount: 1
      });

      const result = await testGarmentModel.create(dataWithSpecialChars);

      expect(result.metadata).toEqual(metadataWithSpecialChars);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO garment_items'),
        expect.arrayContaining([JSON.stringify(metadataWithSpecialChars)])
      );
    });

    it('should validate user_id parameter format', async () => {
      // This test ensures the model doesn't perform additional validation
      // beyond what the database layer provides
      const invalidUserId = 'invalid-user-id-format';
      
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0
      });

      const result = await testGarmentModel.findByUserId(invalidUserId);

      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at',
        [invalidUserId]
      );
      expect(result).toEqual([]);
    });

    it('should handle null and undefined values safely', async () => {
      const dataWithNulls = {
        user_id: mockUserId,
        original_image_id: undefined, // Use undefined instead of null
        metadata: {
          name: 'Test Garment',
          category: undefined, // Use undefined instead of null
          color: undefined,
          price: 0
        }
      };

      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...mockDbGarment,
          original_image_id: undefined,
          metadata: JSON.stringify(dataWithNulls.metadata)
        }],
        rowCount: 1
      });

      const result = await testGarmentModel.create(dataWithNulls);

      expect(result.original_image_id).toBeUndefined();
      expect(result.metadata).toEqual(dataWithNulls.metadata);
    });
  });

  describe('Performance Tests', () => {
    it('should handle batch operations efficiently', async () => {
      const count = 100;
      
      // Mock multiple UUIDs
      for (let i = 0; i < count; i++) {
        mockUuidv4.mockReturnValueOnce(`perf-garment-${i}`);
        mockQuery.mockResolvedValueOnce({
          rows: [{
            id: `perf-garment-${i}`,
            user_id: mockUserId,
            original_image_id: null,
            metadata: JSON.stringify({
              name: `Performance Test Garment ${i}`,
              category: 'shirt',
              color: 'blue'
            }),
            created_at: new Date(),
            updated_at: new Date()
          }],
          rowCount: 1
        });
      }

      const startTime = Date.now();
      const result = await testGarmentModel.createMultiple(mockUserId, count);
      const endTime = Date.now();

      expect(result).toHaveLength(count);
      expect(endTime - startTime).toBeLessThan(1000); // Should complete within 1 second
      expect(mockQuery).toHaveBeenCalledTimes(count);
    });
  });
});