// filepath: /backend/src/tests/unit/garmentModel.security.test.ts
// Mock the database query function and uuid
jest.mock('../../models/db', () => ({
  query: jest.fn()
}));

jest.mock('uuid', () => ({
  v4: jest.fn(),
  validate: jest.fn((id) => {
    // Simple UUID validation for testing
    return typeof id === 'string' && 
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
  })
}));

import { v4 as uuidv4 } from 'uuid';
import { garmentModel } from '../../models/garmentModel';
import { query } from '../../models/db';

// Using type assertion to treat the mocked modules as jest.Mock
const mockQuery = query as jest.Mock;
const mockUuidv4 = uuidv4 as jest.Mock;

describe('Garment Model Security Tests', () => {
  // Sample test data
  const validUuid = '123e4567-e89b-12d3-a456-426614174000';
  const invalidUuid = 'not-a-valid-uuid';
  const sqlInjectionAttempt = "'; DROP TABLE garment_items; --";
  const mockTimestamp = new Date();
  
  const mockGarment = {
    id: validUuid,
    user_id: 'user123',
    original_image_id: 'image123',
    file_path: '/path/to/file.jpg',
    mask_path: '/path/to/mask.png',
    metadata: { type: 'shirt' },
    created_at: mockTimestamp,
    updated_at: mockTimestamp,
    data_version: 1
  };

  beforeEach(() => {
    mockQuery.mockReset();
    mockUuidv4.mockReset();
    // Default implementation for UUID generation
    mockUuidv4.mockReturnValue(validUuid);
  });

  describe('UUID Validation', () => {
    it('should reject invalid UUIDs in findById', async () => {
      const result = await garmentModel.findById(invalidUuid);
      
      expect(result).toBeNull();
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it('should reject invalid UUIDs in updateMetadata', async () => {
      const result = await garmentModel.updateMetadata(invalidUuid, { metadata: { updated: true } });
      
      expect(result).toBeNull();
      expect(mockQuery).not.toHaveBeenCalled();
    });

    it('should reject invalid UUIDs in delete', async () => {
      const result = await garmentModel.delete(invalidUuid);
      
      expect(result).toBe(false);
      expect(mockQuery).not.toHaveBeenCalled();
    });
  });

  describe('SQL Injection Prevention', () => {
    it('should safely handle potential SQL injection in user_id parameter', async () => {
      await garmentModel.findByUserId(sqlInjectionAttempt);
      
      // Verify the raw SQL string was passed as a parameter, not interpolated
      expect(mockQuery).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining([sqlInjectionAttempt])
      );
    });

    it('should safely handle potential SQL injection in garment_id', async () => {
      // Mock the UUID validation to allow our SQL injection string to pass validation
      jest.spyOn(require('uuid'), 'validate').mockReturnValueOnce(true);
      
      await garmentModel.findById(sqlInjectionAttempt);
      
      // Verify the raw input was passed as a parameter, not interpolated
      expect(mockQuery).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining([sqlInjectionAttempt])
      );
    });

    it('should safely handle malicious content in metadata', async () => {
      const maliciousMetadata = {
        attack: `"'); DROP TABLE users; --`,
        script: `<script>alert('XSS')</script>`,
        nested: { dangerous: `'); DELETE FROM garment_items; --` }
      };
      
      mockQuery.mockResolvedValueOnce({ rows: [mockGarment] });
      
      await garmentModel.create({
        user_id: 'user123',
        original_image_id: 'image123',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png',
        metadata: maliciousMetadata
      });
      
      // Verify metadata was properly JSON stringified
      expect(mockQuery).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining([expect.any(String), expect.any(String), 
          expect.any(String), expect.any(String), expect.any(String), 
          JSON.stringify(maliciousMetadata)])
      );
    });
  });

  describe('Metadata Security', () => {
    it('should safely handle deeply nested metadata objects', async () => {
      const complexMetadata = {
        level1: {
          level2: {
            level3: {
              level4: { sensitive: 'data' }
            }
          }
        },
        array: [1, 2, { nested: 'value' }]
      };
      
      mockQuery.mockResolvedValueOnce({ rows: [mockGarment] });
      
      await garmentModel.create({
        user_id: 'user123',
        original_image_id: 'image123',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png',
        metadata: complexMetadata
      });
      
      // Verify complex object was properly stringified
      expect(mockQuery).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining([
          expect.any(String),
          expect.any(String),
          expect.any(String),
          expect.any(String),
          expect.any(String),
          JSON.stringify(complexMetadata)
        ])
      );
    });

    it('should prevent metadata prototype pollution', async () => {
      // Create an object with a potentially dangerous __proto__ property
      const dangerousMetadata = JSON.parse('{"__proto__": {"polluted": true}}');
      
      mockQuery.mockResolvedValueOnce({ rows: [mockGarment] });
      
      await garmentModel.create({
        user_id: 'user123',
        original_image_id: 'image123',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png',
        metadata: dangerousMetadata
      });
      
      // Verify the dangerous object was passed as-is to be stringified
      expect(mockQuery).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining([expect.any(String), expect.any(String), 
          expect.any(String), expect.any(String), expect.any(String), 
          expect.stringContaining("__proto__")])
      );
      
      // Verify Object prototype wasn't polluted
      expect({}.hasOwnProperty('polluted')).toBe(false);
    });

    it('should properly merge metadata during updates without losing data', async () => {
      // Setup existing garment with metadata
      const existingMetadata = { color: 'blue', size: 'medium' };
      const existingGarment = {
        ...mockGarment,
        metadata: existingMetadata
      };
      
      // Setup update with new partial metadata
      const updateMetadata = { color: 'red', material: 'cotton' };
      
      // Mock the first query (findById) to return existing garment
      mockQuery.mockResolvedValueOnce({ rows: [existingGarment] });
      // Mock the second query (update) to return updated garment
      mockQuery.mockResolvedValueOnce({ 
        rows: [{
          ...existingGarment,
          metadata: { ...existingMetadata, ...updateMetadata },
          data_version: 2
        }]
      });
      
      const result = await garmentModel.updateMetadata(validUuid, { metadata: updateMetadata });
      
      // Verify the update query was called with properly merged metadata
      expect(mockQuery).toHaveBeenNthCalledWith(2,
        expect.any(String),
        [JSON.stringify({ color: 'red', size: 'medium', material: 'cotton' }), validUuid]
      );
      
      // Verify the returned object has the correctly merged metadata
      expect(result?.metadata).toEqual({
        color: 'red',
        size: 'medium',
        material: 'cotton'
      });
    });
  });

  describe('Error Handling', () => {
    it('should propagate database errors during creation', async () => {
      const dbError = new Error('Database connection failed');
      mockQuery.mockRejectedValueOnce(dbError);
      
      await expect(garmentModel.create({
        user_id: 'user123',
        original_image_id: 'image123',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png'
      })).rejects.toThrow('Database connection failed');
    });

    it('should propagate database errors during findById', async () => {
      const dbError = new Error('Query execution failed');
      mockQuery.mockRejectedValueOnce(dbError);
      
      await expect(garmentModel.findById(validUuid)).rejects.toThrow('Query execution failed');
    });

    it('should handle empty result sets gracefully', async () => {
      mockQuery.mockResolvedValueOnce({ rows: [] });
      
      const result = await garmentModel.findById(validUuid);
      
      expect(result).toBeNull();
    });
  });

  describe('Data Integrity', () => {
    it('should increment data_version during metadata updates', async () => {
      // Mock findById to return garment
      mockQuery.mockResolvedValueOnce({ rows: [mockGarment] });
      
      // Mock the update query
      mockQuery.mockResolvedValueOnce({ 
        rows: [{
          ...mockGarment,
          metadata: { type: 'shirt', updated: true },
          data_version: 2
        }]
      });
      
      const result = await garmentModel.updateMetadata(validUuid, { 
        metadata: { updated: true } 
      });
      
      // Verify data_version was incremented in the query
      expect(mockQuery).toHaveBeenNthCalledWith(2,
        expect.stringContaining('data_version = data_version + 1'),
        expect.any(Array)
      );
      
      expect(result?.data_version).toBe(2);
    });

    it('should handle undefined metadata in create by using empty object', async () => {
      mockQuery.mockResolvedValueOnce({ 
        rows: [{
          ...mockGarment,
          metadata: {}
        }]
      });
      
      await garmentModel.create({
        user_id: 'user123',
        original_image_id: 'image123',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png'
        // metadata intentionally omitted
      });
      
      // Verify empty object was used for metadata
      expect(mockQuery).toHaveBeenCalledWith(
        expect.any(String),
        expect.arrayContaining([expect.any(String), expect.any(String), 
          expect.any(String), expect.any(String), expect.any(String), 
          '{}'])
      );
    });
  });
});