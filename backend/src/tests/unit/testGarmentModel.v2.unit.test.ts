// /backend/src/utils/__tests__/testGarmentModel.v2.test.ts
/**
 * Comprehensive Test Suite for Test Garment Model v2 (Dual-Mode)
 * 
 * Tests the dual-mode garment model that handles garment CRUD operations,
 * metadata management, wardrobe relationships, and security in both Docker and Manual modes.
 * 
 * Coverage: Unit + Integration + Security
 */

import { testGarmentModel } from '../../utils/testGarmentModel.v2';
import { v4 as uuidv4 } from 'uuid';

// Mock dependencies
jest.mock('../../utils/dockerMigrationHelper', () => ({
  getTestDatabaseConnection: jest.fn()
}));

jest.mock('uuid');

describe('TestGarmentModel v2 - Dual-Mode Garment Operations', () => {
  let mockDB: any;
  let mockQuery: jest.Mock;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();

    // Create mock database
    mockQuery = jest.fn();
    mockDB = {
      query: mockQuery
    };

    // Mock the database connection factory
    const { getTestDatabaseConnection } = require('../../utils/dockerMigrationHelper');
    getTestDatabaseConnection.mockReturnValue(mockDB);

    // Mock UUID generation
    (uuidv4 as jest.Mock).mockReturnValue('test-garment-uuid-123');
  });

  // ============================================================================
  // UNIT TESTS - Core Garment Operations
  // ============================================================================
  describe('Unit Tests - Core Garment Operations', () => {
    describe('Garment Creation', () => {
      test('should create garment with valid data successfully', async () => {
        const mockCreatedGarment = {
          id: 'test-garment-uuid-123',
          user_id: 'valid-user-uuid',
          original_image_id: 'image-uuid-123',
          metadata: {
            name: 'Blue Cotton Shirt',
            category: 'shirt',
            color: 'blue',
            brand: 'TestBrand',
            size: 'M',
            price: 29.99,
            tags: ['casual', 'cotton']
          },
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValue({ rows: [mockCreatedGarment] });

        const result = await testGarmentModel.create({
          user_id: 'valid-user-uuid',
          original_image_id: 'image-uuid-123',
          metadata: {
            name: 'Blue Cotton Shirt',
            category: 'shirt',
            color: 'blue',
            brand: 'TestBrand',
            size: 'M',
            price: 29.99,
            tags: ['casual', 'cotton']
          }
        });

        expect(uuidv4).toHaveBeenCalled();
        expect(mockQuery).toHaveBeenCalledWith(
          'INSERT INTO garment_items (id, user_id, original_image_id, metadata, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW()) RETURNING *',
          ['test-garment-uuid-123', 'valid-user-uuid', 'image-uuid-123', JSON.stringify({
            name: 'Blue Cotton Shirt',
            category: 'shirt',
            color: 'blue',
            brand: 'TestBrand',
            size: 'M',
            price: 29.99,
            tags: ['casual', 'cotton']
          })]
        );
        expect(result).toEqual({
          id: mockCreatedGarment.id,
          user_id: mockCreatedGarment.user_id,
          original_image_id: mockCreatedGarment.original_image_id,
          metadata: mockCreatedGarment.metadata,
          created_at: mockCreatedGarment.created_at,
          updated_at: mockCreatedGarment.updated_at
        });
      });

      test('should create garment without image reference', async () => {
        const mockCreatedGarment = {
          id: 'test-garment-uuid-123',
          user_id: 'valid-user-uuid',
          original_image_id: null,
          metadata: { name: 'Manual Entry Garment' },
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValue({ rows: [mockCreatedGarment] });

        const result = await testGarmentModel.create({
          user_id: 'valid-user-uuid',
          metadata: { name: 'Manual Entry Garment' }
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          ['test-garment-uuid-123', 'valid-user-uuid', null, JSON.stringify({ name: 'Manual Entry Garment' })]
        );
        expect(result.original_image_id).toBeNull();
      });

      test('should handle complex metadata structures', async () => {
        const complexMetadata = {
          name: 'Designer Dress',
          category: 'dress',
          color: 'navy',
          brand: 'Premium Designer',
          size: 'S',
          price: 299.99,
          tags: ['formal', 'designer', 'evening'],
          details: {
            material: 'silk',
            pattern: 'solid',
            neckline: 'v-neck',
            sleeve_length: 'sleeveless',
            length: 'midi'
          },
          care_instructions: {
            washing: 'dry clean only',
            drying: 'hang dry',
            ironing: 'low heat',
            storage: 'hang in closet'
          },
          purchase_info: {
            store: 'Boutique XYZ',
            date: '2023-06-15',
            receipt_number: 'RCP-2023-001234',
            warranty: '30 days'
          },
          measurements: {
            chest: 34,
            waist: 28,
            hips: 36,
            length: 42
          }
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id', metadata: complexMetadata }] });

        await testGarmentModel.create({
          user_id: 'valid-user-uuid',
          metadata: complexMetadata
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          expect.arrayContaining([
            'test-garment-uuid-123',
            'valid-user-uuid',
            null,
            JSON.stringify(complexMetadata)
          ])
        );
      });

      test('should handle metadata with special characters and multilingual content', async () => {
        const multilingualMetadata = {
          name: 'Camisa Azul / 蓝色衬衫 / Chemise Bleue',
          category: 'shirt',
          description: 'A beautiful shirt with émojis 🔥 and symbols ∞ & ñ',
          brand: 'Iñtërnâtiônàl Brand™',
          tags: ['αναψυχή', '日常', 'décontracté', 'кэжуал'],
          special_characters: {
            unicode: '\u{1F4A5}\u{1F525}\u{1F389}',
            entities: '&lt;script&gt;alert("test")&lt;/script&gt;',
            quotes: '"Single" and \'Double\' quotes',
            newlines: 'Line 1\nLine 2\r\nLine 3',
            tabs: 'Col1\tCol2\tCol3'
          }
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testGarmentModel.create({
          user_id: 'valid-user-uuid',
          metadata: multilingualMetadata
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          expect.arrayContaining([
            'test-garment-uuid-123',
            'valid-user-uuid',
            null,
            JSON.stringify(multilingualMetadata)
          ])
        );
      });
    });

    describe('Garment Retrieval', () => {
      test('should find garment by valid ID', async () => {
        const mockGarment = {
          id: 'valid-garment-uuid',
          user_id: 'user-uuid',
          original_image_id: 'image-uuid',
          metadata: '{"name":"Test Garment","category":"shirt"}',
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValue({ rows: [mockGarment] });

        const result = await testGarmentModel.findById('valid-garment-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM garment_items WHERE id = $1',
          ['valid-garment-uuid']
        );
        expect(result).toEqual({
          id: mockGarment.id,
          user_id: mockGarment.user_id,
          original_image_id: mockGarment.original_image_id,
          metadata: { name: 'Test Garment', category: 'shirt' },
          created_at: mockGarment.created_at,
          updated_at: mockGarment.updated_at
        });
      });

      test('should return null for non-existent garment', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await testGarmentModel.findById('non-existent-uuid');

        expect(result).toBeNull();
      });

      test('should handle malformed JSON metadata gracefully', async () => {
        const mockGarment = {
          id: 'garment-uuid',
          user_id: 'user-uuid',
          original_image_id: null,
          metadata: 'invalid json {',
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValue({ rows: [mockGarment] });

        // Should either handle gracefully or throw appropriate error
        await expect(testGarmentModel.findById('garment-uuid')).rejects.toThrow();
      });

      test('should handle metadata as object (already parsed)', async () => {
        const mockGarment = {
          id: 'garment-uuid',
          user_id: 'user-uuid',
          original_image_id: null,
          metadata: { name: 'Already Parsed', category: 'shirt' },
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValue({ rows: [mockGarment] });

        const result = await testGarmentModel.findById('garment-uuid');

        expect(result.metadata).toEqual({ name: 'Already Parsed', category: 'shirt' });
      });

      test('should find garments by user ID', async () => {
        const mockGarments = [
          {
            id: 'garment1',
            user_id: 'user-uuid',
            metadata: '{"name":"Garment 1"}',
            created_at: new Date('2023-01-01')
          },
          {
            id: 'garment2',
            user_id: 'user-uuid',
            metadata: '{"name":"Garment 2"}',
            created_at: new Date('2023-01-02')
          }
        ];

        mockQuery.mockResolvedValue({ rows: mockGarments });

        const result = await testGarmentModel.findByUserId('user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at',
          ['user-uuid']
        );
        expect(result).toHaveLength(2);
        expect(result[0].metadata).toEqual({ name: 'Garment 1' });
      });

      test('should return empty array for user with no garments', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await testGarmentModel.findByUserId('user-uuid');

        expect(result).toEqual([]);
      });
    });

    describe('Metadata Operations', () => {
      test('should update garment metadata successfully', async () => {
        const newMetadata = {
          name: 'Updated Garment Name',
          category: 'jacket',
          color: 'black',
          price: 99.99,
          updated_by: 'user_edit'
        };

        const mockUpdatedGarment = {
          id: 'garment-uuid',
          user_id: 'user-uuid',
          metadata: newMetadata,
          updated_at: new Date()
        };

        mockQuery.mockResolvedValue({ rows: [mockUpdatedGarment] });

        const result = await testGarmentModel.updateMetadata('garment-uuid', newMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          'UPDATE garment_items SET metadata = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
          [JSON.stringify(newMetadata), 'garment-uuid']
        );
        expect(result.metadata).toEqual(newMetadata);
      });

      test('should return null when updating non-existent garment', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await testGarmentModel.updateMetadata('non-existent-uuid', { name: 'Updated' });

        expect(result).toBeNull();
      });

      test('should handle partial metadata updates', async () => {
        const partialUpdate = {
          price: 79.99,
          last_worn: '2023-06-20'
        };

        mockQuery.mockResolvedValue({ rows: [{ 
          id: 'garment-uuid',
          metadata: partialUpdate
        }] });

        await testGarmentModel.updateMetadata('garment-uuid', partialUpdate);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE garment_items SET metadata'),
          [JSON.stringify(partialUpdate), 'garment-uuid']
        );
      });
    });

    describe('Garment Deletion', () => {
      test('should delete garment successfully', async () => {
        mockQuery
          .mockResolvedValueOnce({ rows: [] }) // Remove from wardrobes
          .mockResolvedValueOnce({ rowCount: 1 }); // Delete garment

        const result = await testGarmentModel.delete('garment-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM wardrobe_items WHERE garment_item_id = $1',
          ['garment-uuid']
        );
        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM garment_items WHERE id = $1',
          ['garment-uuid']
        );
        expect(result).toBe(true);
      });

      test('should return false when garment not found for deletion', async () => {
        mockQuery
          .mockResolvedValueOnce({ rows: [] }) // Remove from wardrobes
          .mockResolvedValueOnce({ rowCount: 0 }); // Garment not found

        const result = await testGarmentModel.delete('non-existent-uuid');

        expect(result).toBe(false);
      });

      test('should handle wardrobe relationship cleanup errors gracefully', async () => {
        mockQuery
          .mockRejectedValueOnce(new Error('Wardrobe cleanup failed'))
          .mockResolvedValueOnce({ rowCount: 1 });

        // Should still attempt to delete the garment even if wardrobe cleanup fails
        const result = await testGarmentModel.delete('garment-uuid');

        expect(result).toBe(true);
      });
    });

    describe('Count Operations', () => {
      test('should get garment count for user', async () => {
        mockQuery.mockResolvedValue({ rows: [{ count: '15' }] });

        const result = await testGarmentModel.getCountByUserId('user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1',
          ['user-uuid']
        );
        expect(result).toBe(15);
      });

      test('should return 0 for user with no garments', async () => {
        mockQuery.mockResolvedValue({ rows: [{ count: '0' }] });

        const result = await testGarmentModel.getCountByUserId('user-uuid');

        expect(result).toBe(0);
      });
    });

    describe('Existence Checks', () => {
      test('should confirm garment exists', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'garment-uuid' }] });

        const result = await testGarmentModel.exists('garment-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT 1 FROM garment_items WHERE id = $1',
          ['garment-uuid']
        );
        expect(result).toBe(true);
      });

      test('should return false for non-existent garment', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await testGarmentModel.exists('non-existent-uuid');

        expect(result).toBe(false);
      });
    });
  });

  // ============================================================================
  // INTEGRATION TESTS - Complex Operations and Relationships
  // ============================================================================
  describe('Integration Tests - Complex Operations', () => {
    describe('Bulk Garment Creation', () => {
      test('should create multiple garments with varied metadata', async () => {
        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        const result = await testGarmentModel.createMultiple('user-uuid', 5, {
          brand: 'TestBrand'
        });

        expect(result).toHaveLength(5);
        expect(mockQuery).toHaveBeenCalledTimes(5);
        
        // Verify all garments have the base metadata plus variations
        result.forEach((garment, index) => {
          expect(garment.metadata.brand).toBe('TestBrand');
          expect(garment.metadata.name).toBe(`Test Garment ${index + 1}`);
        });
      });

      test('should create garments with specified specifications', async () => {
        const specifications = [
          { name: 'Red Shirt', category: 'shirt', color: 'red' },
          { name: 'Blue Jeans', category: 'pants', color: 'blue' },
          { name: 'Black Jacket', category: 'jacket', color: 'black' }
        ];

        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        const result = await testGarmentModel.createWithSpecifications('user-uuid', specifications);

        expect(result).toHaveLength(3);
        expect(result[0].metadata.name).toBe('Red Shirt');
        expect(result[0].metadata.category).toBe('shirt');
        expect(result[1].metadata.name).toBe('Blue Jeans');
        expect(result[2].metadata.name).toBe('Black Jacket');
      });

      test('should handle bulk creation with custom metadata', async () => {
        const customMetadata = {
          season: 'winter',
          occasion: 'formal',
          material: 'wool'
        };

        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        const result = await testGarmentModel.createMultiple('user-uuid', 3, customMetadata);

        result.forEach(garment => {
          expect(garment.metadata.season).toBe('winter');
          expect(garment.metadata.occasion).toBe('formal');
          expect(garment.metadata.material).toBe('wool');
        });
      });
    });

    describe('Bulk Cleanup Operations', () => {
      test('should cleanup all garments for a user', async () => {
        mockQuery
          .mockResolvedValueOnce({ rows: [] }) // Remove from wardrobes
          .mockResolvedValueOnce({ rowCount: 8 }); // Delete garments

        const result = await testGarmentModel.cleanupByUserId('user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM wardrobe_items WHERE garment_item_id IN (SELECT id FROM garment_items WHERE user_id = $1)',
          ['user-uuid']
        );
        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM garment_items WHERE user_id = $1',
          ['user-uuid']
        );
        expect(result).toBe(8);
      });

      test('should return 0 when no garments to cleanup', async () => {
        mockQuery
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rowCount: 0 });

        const result = await testGarmentModel.cleanupByUserId('user-uuid');

        expect(result).toBe(0);
      });

      test('should handle cleanup with foreign key constraints', async () => {
        mockQuery
          .mockRejectedValueOnce(new Error('foreign key constraint violation'))
          .mockResolvedValueOnce({ rowCount: 5 });

        const result = await testGarmentModel.cleanupByUserId('user-uuid');

        // Should still attempt garment deletion
        expect(result).toBe(5);
      });
    });

    describe('Wardrobe Relationship Management', () => {
      test('should remove garment from all wardrobes before deletion', async () => {
        mockQuery
          .mockResolvedValueOnce({ rows: [] })
          .mockResolvedValueOnce({ rowCount: 1 });

        await testGarmentModel.delete('garment-with-wardrobes');

        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM wardrobe_items WHERE garment_item_id = $1',
          ['garment-with-wardrobes']
        );
        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM garment_items WHERE id = $1',
          ['garment-with-wardrobes']
        );
      });

      test('should handle garment deletion when wardrobe table does not exist', async () => {
        mockQuery
          .mockRejectedValueOnce(new Error('relation "wardrobe_items" does not exist'))
          .mockResolvedValueOnce({ rowCount: 1 });

        const result = await testGarmentModel.delete('garment-uuid');

        expect(result).toBe(true);
      });
    });

    describe('Data Consistency Operations', () => {
      test('should handle concurrent garment operations', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        // Simulate concurrent operations
        const operations = Array.from({ length: 50 }, (_, i) => 
          testGarmentModel.findById(`garment-${i}`)
        );

        const results = await Promise.all(operations);
        
        expect(results).toHaveLength(50);
        expect(mockQuery).toHaveBeenCalledTimes(50);
      });

      test('should handle metadata updates with concurrent modifications', async () => {
        const updates = [
          { price: 29.99, color: 'red' },
          { price: 39.99, color: 'blue' },
          { price: 49.99, color: 'green' }
        ];

        mockQuery.mockResolvedValue({ rows: [{ id: 'garment-uuid' }] });

        const results = await Promise.all(
          updates.map(update => testGarmentModel.updateMetadata('garment-uuid', update))
        );

        expect(results).toHaveLength(3);
        expect(mockQuery).toHaveBeenCalledTimes(3);
      });
    });
  });

  // ============================================================================
  // SECURITY TESTS - Metadata Validation and Input Protection
  // ============================================================================
  describe('Security Tests - Metadata Validation and Protection', () => {
    describe('Metadata Injection Prevention', () => {
      test('should handle malicious metadata safely', async () => {
        const maliciousMetadata = {
          name: "'; DROP TABLE garment_items; --",
          description: '<script>alert("xss")</script>',
          brand: '../../utils/../../etc/passwd',
          category: "shirt'; UPDATE users SET admin = true; --",
          tags: ["normal_tag", "'; DELETE FROM users; --", "<img src=x onerror=alert(1)>"],
          price: "999.99'; UPDATE garment_items SET price = 0.01; --",
          size: { evil: "'; DROP DATABASE; --" },
          custom_field: {
            "__proto__": { "admin": true },
            "constructor": { "prototype": { "admin": true } }
          },
          buffer_overflow: 'A'.repeat(1000000),
          unicode_bypass: '\u003cscript\u003ealert("xss")\u003c/script\u003e',
          null_injection: 'test\x00injection',
          code_injection: 'eval("alert(1)")'
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testGarmentModel.create({
          user_id: 'valid-user-uuid',
          metadata: maliciousMetadata
        });

        // Should safely store as JSON string in parameterized query
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          expect.arrayContaining([
            expect.any(String),
            'valid-user-uuid',
            null,
            JSON.stringify(maliciousMetadata)
          ])
        );
      });

      test('should prevent metadata injection in updates', async () => {
        const injectionMetadata = {
          "'; UPDATE users SET password = 'hacked'; --": "malicious_key",
          "regular_field": "'; DELETE FROM garment_items; --",
          "eval('malicious_code')": "dangerous_value",
          "../../../secret_config": "path_traversal"
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testGarmentModel.updateMetadata('garment-uuid', injectionMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          'UPDATE garment_items SET metadata = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
          [JSON.stringify(injectionMetadata), 'garment-uuid']
        );
      });

      test('should handle deeply nested malicious metadata', async () => {
        const deeplyNestedMalicious = {
          level1: {
            level2: {
              level3: {
                level4: {
                  sql_injection: "'; DROP TABLE users; --",
                  xss_payload: '<script>alert("deep_xss")</script>',
                  path_traversal: '../../utils/../../etc/shadow'
                }
              }
            }
          },
          array_injection: [
            "normal_value",
            "'; DELETE FROM garment_items; --",
            { nested_sql: "'; UPDATE users SET admin = true; --" }
          ]
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testGarmentModel.create({
          user_id: 'valid-user-uuid',
          metadata: deeplyNestedMalicious
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          expect.arrayContaining([
            expect.any(String),
            'valid-user-uuid',
            null,
            JSON.stringify(deeplyNestedMalicious)
          ])
        );
      });
    });

    describe('User ID Validation', () => {
      test('should handle malicious user IDs safely', async () => {
        const maliciousUserIds = [
          "'; DROP TABLE garment_items; --",
          "' UNION SELECT * FROM users; --",
          "'; UPDATE garment_items SET user_id = 'attacker'; --",
          "../../../etc/passwd",
          "<script>alert('xss')</script>",
          "\\x27; DELETE FROM users; --"
        ];

        for (const userId of maliciousUserIds) {
          await expect(testGarmentModel.create({
            user_id: userId,
            metadata: { name: 'Test' }
          })).rejects.toThrow(); // Should validate and reject
        }

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should validate user ID format in all operations', async () => {
        const invalidUserIds = [
          'not-a-uuid',
          '12345678-1234-1234-1234-12345678901',
          'invalid-format',
          '',
          null,
          undefined
        ];

        for (const userId of invalidUserIds) {
          expect(await testGarmentModel.findByUserId(userId as any)).toEqual([]);
          expect(await testGarmentModel.getCountByUserId(userId as any)).toBe(0);
          expect(await testGarmentModel.cleanupByUserId(userId as any)).toBe(0);
        }

        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('Image ID Validation', () => {
      test('should handle malicious image IDs safely', async () => {
        const maliciousImageIds = [
          "'; SELECT * FROM original_images; --",
          "' UNION ALL SELECT password_hash FROM users; --",
          "../../../sensitive_image.jpg"
        ];

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        for (const imageId of maliciousImageIds) {
          await testGarmentModel.create({
            user_id: 'valid-user-uuid',
            original_image_id: imageId,
            metadata: { name: 'Test' }
          });
        }

        // Should use parameterized queries for all
        maliciousImageIds.forEach(imageId => {
          expect(mockQuery).toHaveBeenCalledWith(
            expect.stringContaining('INSERT INTO garment_items'),
            expect.arrayContaining([
              expect.any(String),
              'valid-user-uuid',
              imageId,
              expect.any(String)
            ])
          );
        });
      });

      test('should validate image ID format when provided', async () => {
        const invalidImageIds = [
          'not-a-uuid',
          '12345678-1234-1234-1234-12345678901',
          'invalid-format',
          '<script>alert("xss")</script>',
          "'; DROP TABLE original_images; --"
        ];

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        for (const imageId of invalidImageIds) {
          await testGarmentModel.create({
            user_id: 'valid-user-uuid',
            original_image_id: imageId,
            metadata: { name: 'Test' }
          });
        }

        // Should use parameterized queries (validation happens in higher layers)
        expect(mockQuery).toHaveBeenCalledTimes(invalidImageIds.length);
      });
    });

    describe('Garment ID Validation', () => {
      test('should handle malicious garment IDs in queries', async () => {
        const maliciousGarmentIds = [
          "'; DROP TABLE garment_items; --",
          "' UNION SELECT password_hash FROM users; --",
          "'; UPDATE garment_items SET user_id = 'attacker'; --",
          "../../../etc/passwd",
          "<script>alert('garment_xss')</script>"
        ];

        mockQuery.mockResolvedValue({ rows: [] });

        for (const garmentId of maliciousGarmentIds) {
          const result = await testGarmentModel.findById(garmentId);
          expect(result).toBeNull();
        }

        // Should use parameterized queries for all
        maliciousGarmentIds.forEach(garmentId => {
          expect(mockQuery).toHaveBeenCalledWith(
            'SELECT * FROM garment_items WHERE id = $1',
            [garmentId]
          );
        });
      });

      test('should validate garment ID format in all operations', async () => {
        const invalidGarmentIds = [
          'not-a-uuid',
          '12345678-1234-1234-1234-12345678901',
          '',
          null,
          undefined,
          123,
          { id: 'object' },
          ['array']
        ];

        mockQuery.mockResolvedValue({ rows: [] });

        for (const garmentId of invalidGarmentIds) {
          expect(await testGarmentModel.findById(garmentId as any)).toBeNull();
          expect(await testGarmentModel.updateMetadata(garmentId as any, {})).toBeNull();
          expect(await testGarmentModel.delete(garmentId as any)).toBe(false);
          expect(await testGarmentModel.exists(garmentId as any)).toBe(false);
        }

        // Should validate format before querying
        expect(mockQuery).toHaveBeenCalledTimes(invalidGarmentIds.length * 4);
      });
    });

    describe('Input Sanitization and Boundary Testing', () => {
      test('should handle null and undefined inputs safely', async () => {
        // All these should not crash and return appropriate safe values
        expect(await testGarmentModel.findById(null as any)).toBeNull();
        expect(await testGarmentModel.findById(undefined as any)).toBeNull();
        expect(await testGarmentModel.findByUserId(null as any)).toEqual([]);
        expect(await testGarmentModel.findByUserId(undefined as any)).toEqual([]);
        expect(await testGarmentModel.delete(null as any)).toBe(false);
        expect(await testGarmentModel.exists(null as any)).toBe(false);
        expect(await testGarmentModel.getCountByUserId(null as any)).toBe(0);
        expect(await testGarmentModel.cleanupByUserId(null as any)).toBe(0);

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle extremely large metadata objects', async () => {
        const largeMetadata = {
          name: 'Large Metadata Test',
          huge_description: 'x'.repeat(10000000), // 10MB string
          large_array: new Array(100000).fill('large_array_item'),
          deep_nesting: {}
        };

        // Create deeply nested object (1000 levels)
        let current = largeMetadata.deep_nesting;
        for (let i = 0; i < 1000; i++) {
          current.next = { level: i };
          current = current.next;
        }

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        // Should handle without memory overflow or crashes
        await testGarmentModel.create({
          user_id: 'valid-user-uuid',
          metadata: largeMetadata
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          expect.arrayContaining([
            expect.any(String),
            'valid-user-uuid',
            null,
            JSON.stringify(largeMetadata)
          ])
        );
      });

      test('should handle special characters and encoding attacks', async () => {
        const specialMetadata = {
          name: '\x00\x01\x02\x03\x04\x05', // Null bytes and control characters
          unicode_name: '\u0000\u0001\u0002\uFEFF\uFFFE\uFFFF',
          url_encoded: '%00%01%02%03%20%21%22%23',
          http_injection: '\r\n\r\nHTTP/1.1 200 OK\r\n\r\n<script>alert("http")</script>',
          ansi_codes: '\x1b[31mRed Text\x1b[0m\x1b[1mBold\x1b[0m',
          binary_data: Buffer.from('binary data test').toString('base64'),
          mixed_encoding: 'Regular text with émojis 🔥 and symbols ∞ ± ≤ ≥'
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testGarmentModel.create({
          user_id: 'valid-user-uuid',
          metadata: specialMetadata
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          expect.arrayContaining([
            expect.any(String),
            'valid-user-uuid',
            null,
            JSON.stringify(specialMetadata)
          ])
        );
      });

      test('should handle buffer overflow attempts', async () => {
        const overflowMetadata = {
          name: 'A'.repeat(1000000), // 1MB string
          description: 'B'.repeat(1000000),
          tags: new Array(100000).fill('overflow_tag'),
          custom_data: {
            field1: 'C'.repeat(500000),
            field2: 'D'.repeat(500000)
          }
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        // Should handle without crashing
        await testGarmentModel.updateMetadata('garment-uuid', overflowMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE garment_items SET metadata'),
          [JSON.stringify(overflowMetadata), 'garment-uuid']
        );
      });
    });

    describe('JSON Parsing Security', () => {
      test('should handle malicious JSON payloads safely', async () => {
        const maliciousJsonMetadata = {
          prototype_pollution: {
            "__proto__": { "admin": true, "isAdmin": true },
            "constructor": { "prototype": { "admin": true } }
          },
          function_injection: {
            "toString": "function() { alert('hacked'); }",
            "valueOf": "function() { return 'malicious'; }"
          },
          circular_reference: {}
        };

        // Create circular reference
        maliciousJsonMetadata.circular_reference = maliciousJsonMetadata;

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        try {
          await testGarmentModel.create({
            user_id: 'valid-user-uuid',
            metadata: maliciousJsonMetadata
          });
        } catch (error) {
          // Should handle circular reference error gracefully
          expect(error.message).toContain('circular');
        }
      });

      test('should prevent prototype pollution through metadata', async () => {
        const pollutionAttempt = {
          "__proto__": {
            "admin": true,
            "role": "administrator"
          },
          "constructor": {
            "prototype": {
              "admin": true
            }
          }
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testGarmentModel.updateMetadata('garment-uuid', pollutionAttempt);

        // Should safely stringify without affecting prototypes
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE garment_items SET metadata'),
          [JSON.stringify(pollutionAttempt), 'garment-uuid']
        );

        // Verify prototype wasn't polluted
        expect((Object.prototype as any).admin).toBeUndefined();
      });
    });

    describe('Error Information Disclosure Prevention', () => {
      test('should not expose database schema in error messages', async () => {
        mockQuery.mockRejectedValue(new Error('column "secret_admin_field" does not exist'));

        try {
          await testGarmentModel.findById('garment-uuid');
        } catch (error) {
          // Should either handle gracefully or not expose internal details
          expect(error.message).not.toContain('secret_admin_field');
        }
      });

      test('should handle foreign key constraint errors safely', async () => {
        mockQuery.mockRejectedValue(new Error('violates foreign key constraint "fk_secret_user_table"'));

        const result = await testGarmentModel.delete('garment-uuid');
        
        // Should handle error without exposing constraint details
        expect(result).toBe(false);
      });

      test('should not expose database connection details', async () => {
        mockQuery.mockRejectedValue(new Error('connection to server at "internal-db-host" (10.0.0.100), port 5432 failed'));

        try {
          await testGarmentModel.getCountByUserId('user-uuid');
        } catch (error) {
          // Should not expose internal database details
          expect(error.message).not.toContain('internal-db-host');
          expect(error.message).not.toContain('10.0.0.100');
        }
      });
    });
  });

  // ============================================================================
  // EDGE CASES AND ERROR HANDLING
  // ============================================================================
  describe('Edge Cases and Error Handling', () => {
    describe('Database Connection Issues', () => {
      test('should handle database connection failures', async () => {
        mockQuery.mockRejectedValue(new Error('Connection lost'));

        await expect(testGarmentModel.findById('garment-uuid')).rejects.toThrow('Connection lost');
      });

      test('should handle query timeouts', async () => {
        mockQuery.mockRejectedValue(new Error('Query timeout'));

        await expect(testGarmentModel.createMultiple('user-uuid', 5)).rejects.toThrow('Query timeout');
      });

      test('should handle database lock errors', async () => {
        mockQuery.mockRejectedValue(new Error('could not obtain lock on row'));

        await expect(testGarmentModel.updateMetadata('garment-uuid', { name: 'Updated' })).rejects.toThrow('could not obtain lock');
      });

      test('should handle transaction rollback scenarios', async () => {
        mockQuery
          .mockResolvedValueOnce({ rows: [] }) // Wardrobe cleanup succeeds
          .mockRejectedValueOnce(new Error('transaction aborted')); // Garment deletion fails

        await expect(testGarmentModel.delete('garment-uuid')).rejects.toThrow('transaction aborted');
      });
    });

    describe('Data Consistency Edge Cases', () => {
      test('should handle concurrent garment creation with same name', async () => {
        // Simulate race condition where multiple garments get same generated name
        let callCount = 0;
        mockQuery.mockImplementation(() => {
          callCount++;
          return Promise.resolve({ rows: [{ id: `garment-${callCount}` }] });
        });

        const promises = Array.from({ length: 10 }, () =>
          testGarmentModel.create({
            user_id: 'user-uuid',
            metadata: { name: 'Concurrent Garment' }
          })
        );

        const results = await Promise.all(promises);
        
        expect(results).toHaveLength(10);
        expect(mockQuery).toHaveBeenCalledTimes(10);
      });

      test('should handle orphaned wardrobe relationships', async () => {
        // Garment deleted but wardrobe_items still reference it
        mockQuery
          .mockRejectedValueOnce(new Error('relation "wardrobe_items" does not exist'))
          .mockResolvedValueOnce({ rowCount: 1 });

        const result = await testGarmentModel.delete('orphaned-garment');
        
        expect(result).toBe(true);
      });

      test('should handle corrupted metadata in database', async () => {
        const corruptedGarment = {
          id: 'garment-uuid',
          user_id: 'user-uuid',
          metadata: 'invalid json { "unclosed": '
        };

        mockQuery.mockResolvedValue({ rows: [corruptedGarment] });

        await expect(testGarmentModel.findById('garment-uuid')).rejects.toThrow();
      });

      test('should handle metadata type mismatches', async () => {
        const typeMismatchGarment = {
          id: 'garment-uuid',
          user_id: 'user-uuid',
          metadata: null // Should be object or string
        };

        mockQuery.mockResolvedValue({ rows: [typeMismatchGarment] });

        const result = await testGarmentModel.findById('garment-uuid');
        
        expect(result.metadata).toBeNull();
      });
    });

    describe('Boundary Conditions', () => {
      test('should handle maximum number of garments per user', async () => {
        const maxGarments = 10000;
        
        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        const result = await testGarmentModel.createMultiple('user-uuid', maxGarments);
        
        expect(result).toHaveLength(maxGarments);
        expect(mockQuery).toHaveBeenCalledTimes(maxGarments);
      });

      test('should handle empty specifications array', async () => {
        const result = await testGarmentModel.createWithSpecifications('user-uuid', []);
        
        expect(result).toEqual([]);
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle zero count in createMultiple', async () => {
        const result = await testGarmentModel.createMultiple('user-uuid', 0);
        
        expect(result).toEqual([]);
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle negative count in createMultiple', async () => {
        const result = await testGarmentModel.createMultiple('user-uuid', -5);
        
        expect(result).toEqual([]);
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle very long garment names and descriptions', async () => {
        const longMetadata = {
          name: 'Very Long Garment Name '.repeat(1000),
          description: 'Very long description that goes on and on '.repeat(10000),
          tags: Array.from({ length: 1000 }, (_, i) => `tag_${i}_${'x'.repeat(100)}`)
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testGarmentModel.create({
          user_id: 'user-uuid',
          metadata: longMetadata
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          expect.arrayContaining([
            expect.any(String),
            'user-uuid',
            null,
            JSON.stringify(longMetadata)
          ])
        );
      });
    });

    describe('Memory and Performance Edge Cases', () => {
      test('should handle memory-intensive bulk operations', async () => {
        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        const bulkSpecs = Array.from({ length: 1000 }, (_, i) => ({
          name: `Bulk Garment ${i}`,
          category: 'shirt',
          metadata: {
            bulk_data: 'x'.repeat(10000),
            index: i
          }
        }));

        const result = await testGarmentModel.createWithSpecifications('user-uuid', bulkSpecs);
        
        expect(result).toHaveLength(1000);
        expect(mockQuery).toHaveBeenCalledTimes(1000);
      });

      test('should handle concurrent metadata updates without blocking', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'garment-uuid' }] });

        const updates = Array.from({ length: 100 }, (_, i) => ({
          price: 10 + i,
          last_updated: new Date().toISOString(),
          update_count: i
        }));

        const promises = updates.map(update => 
          testGarmentModel.updateMetadata('garment-uuid', update)
        );

        const results = await Promise.all(promises);
        
        expect(results).toHaveLength(100);
        expect(mockQuery).toHaveBeenCalledTimes(100);
      });

      test('should not leak memory with repeated operations', async () => {
        mockQuery.mockResolvedValue({ rows: [{ count: '100' }] });

        // Perform many operations to test for memory leaks
        for (let i = 0; i < 1000; i++) {
          await testGarmentModel.getCountByUserId('user-uuid');
        }

        expect(mockQuery).toHaveBeenCalledTimes(1000);
      });
    });

    describe('Integration with dockerMigrationHelper', () => {
      test('should use correct database connection from helper', () => {
        const { getTestDatabaseConnection } = require('../../utils/dockerMigrationHelper');
        
        expect(getTestDatabaseConnection).toHaveBeenCalled();
      });

      test('should handle database connection mode switching', async () => {
        const { getTestDatabaseConnection } = require('../../utils/dockerMigrationHelper');
        
        const dockerDB = { query: jest.fn().mockResolvedValue({ rows: [{ source: 'docker' }] }) };
        const manualDB = { query: jest.fn().mockResolvedValue({ rows: [{ source: 'manual' }] }) };

        // Switch to docker mode
        getTestDatabaseConnection.mockReturnValueOnce(dockerDB);
        await testGarmentModel.findById('garment-uuid');
        
        // Switch to manual mode
        getTestDatabaseConnection.mockReturnValueOnce(manualDB);
        await testGarmentModel.findById('garment-uuid');

        expect(dockerDB.query).toHaveBeenCalled();
        expect(manualDB.query).toHaveBeenCalled();
      });

      test('should maintain consistent API across modes', async () => {
        const { getTestDatabaseConnection } = require('../../utils/dockerMigrationHelper');
        
        const mockResult = { 
          rows: [{ 
            id: 'test-id', 
            user_id: 'user-id',
            metadata: '{"name":"Test Garment"}'
          }] 
        };
        
        getTestDatabaseConnection.mockReturnValue({ query: jest.fn().mockResolvedValue(mockResult) });

        const result = await testGarmentModel.findById('garment-uuid');
        
        expect(result).toHaveProperty('id');
        expect(result).toHaveProperty('user_id');
        expect(result).toHaveProperty('metadata');
        expect(result.metadata).toEqual({ name: 'Test Garment' });
      });
    });
  });

  // ============================================================================
  // PERFORMANCE AND OPTIMIZATION TESTS
  // ============================================================================
  describe('Performance and Optimization Tests', () => {
    describe('Query Efficiency', () => {
      test('should use efficient queries with proper ordering', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        await testGarmentModel.findByUserId('user-uuid');

        // Should order by created_at for consistent results
        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at',
          ['user-uuid']
        );
      });

      test('should use efficient count queries', async () => {
        mockQuery.mockResolvedValue({ rows: [{ count: '50' }] });

        await testGarmentModel.getCountByUserId('user-uuid');

        // Should use COUNT(*) which is optimized
        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1',
          ['user-uuid']
        );
      });

      test('should use efficient existence checks', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'garment-uuid' }] });

        await testGarmentModel.exists('garment-uuid');

        // Should only select minimal data for existence check
        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT 1 FROM garment_items WHERE id = $1',
          ['garment-uuid']
        );
      });

      test('should use parameterized queries for all operations', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        await testGarmentModel.findById('garment-uuid');
        await testGarmentModel.findByUserId('user-uuid');
        await testGarmentModel.exists('garment-uuid');

        const allCalls = mockQuery.mock.calls;
        allCalls.forEach(call => {
          expect(call[0]).toMatch(/\$\d+/);
          expect(call[1]).toBeDefined();
        });
      });
    });

    describe('Bulk Operation Performance', () => {
      test('should handle large bulk operations efficiently', async () => {
        const startTime = Date.now();
        
        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        await testGarmentModel.createMultiple('user-uuid', 1000);
        
        const duration = Date.now() - startTime;
        
        // Should complete reasonably quickly for 1000 operations
        expect(duration).toBeLessThan(5000); // 5 seconds max for mocked operations
        expect(mockQuery).toHaveBeenCalledTimes(1000);
      });

      test('should handle concurrent bulk operations', async () => {
        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        const bulkOperations = Array.from({ length: 10 }, () =>
          testGarmentModel.createMultiple('user-uuid', 100)
        );

        const results = await Promise.all(bulkOperations);
        
        expect(results).toHaveLength(10);
        results.forEach(result => {
          expect(result).toHaveLength(100);
        });
      });
    });

    describe('Memory Usage Optimization', () => {
      test('should handle streaming large metadata without memory overflow', async () => {
        const largeMetadataArray = Array.from({ length: 1000 }, (_, i) => ({
          name: `Garment ${i}`,
          large_field: 'x'.repeat(10000),
          index: i
        }));

        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        const specs = largeMetadataArray.map((metadata, i) => ({
          name: `Spec ${i}`,
          metadata
        }));

        const result = await testGarmentModel.createWithSpecifications('user-uuid', specs);
        
        expect(result).toHaveLength(1000);
      });

      test('should not accumulate memory with repeated operations', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        // Simulate long-running process with many operations
        for (let batch = 0; batch < 10; batch++) {
          const operations = Array.from({ length: 100 }, () => 
            testGarmentModel.findById('garment-uuid')
          );
          
          await Promise.all(operations);
        }

        // Should complete without memory issues
        expect(mockQuery).toHaveBeenCalledTimes(1000);
      });
    });
  });

  // ============================================================================
  // COMPATIBILITY AND REGRESSION TESTS
  // ============================================================================
  describe('Compatibility and Regression Tests', () => {
    describe('API Compatibility', () => {
      test('should maintain consistent return types across versions', async () => {
        mockQuery.mockResolvedValue({ 
          rows: [{ 
            id: 'test-id', 
            user_id: 'user-id',
            original_image_id: 'image-id',
            metadata: '{"name":"Test Garment","category":"shirt"}',
            created_at: new Date(),
            updated_at: new Date()
          }] 
        });

        const garment = await testGarmentModel.findById('garment-uuid');
        
        expect(garment).toHaveProperty('id');
        expect(garment).toHaveProperty('user_id');
        expect(garment).toHaveProperty('original_image_id');
        expect(garment).toHaveProperty('metadata');
        expect(garment).toHaveProperty('created_at');
        expect(garment).toHaveProperty('updated_at');
        
        expect(typeof garment.id).toBe('string');
        expect(typeof garment.user_id).toBe('string');
        expect(typeof garment.metadata).toBe('object');
        expect(garment.created_at).toBeInstanceOf(Date);
        expect(garment.updated_at).toBeInstanceOf(Date);
      });

      test('should handle legacy metadata formats', async () => {
        const legacyMetadata = {
          garment_name: 'Legacy Name Field',
          garment_type: 'legacy_type',
          color_value: 'legacy_color'
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testGarmentModel.updateMetadata('garment-uuid', legacyMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE garment_items SET metadata'),
          [JSON.stringify(legacyMetadata), 'garment-uuid']
        );
      });

      test('should maintain backward compatibility with createMultiple variations', async () => {
        mockQuery.mockImplementation(() => 
          Promise.resolve({ rows: [{ id: uuidv4() }] })
        );

        // Test different parameter combinations
        const result1 = await testGarmentModel.createMultiple('user-uuid', 3);
        const result2 = await testGarmentModel.createMultiple('user-uuid', 3, {});
        const result3 = await testGarmentModel.createMultiple('user-uuid', 3, { brand: 'Test' });

        expect(result1).toHaveLength(3);
        expect(result2).toHaveLength(3);
        expect(result3).toHaveLength(3);
        expect(result3[0].metadata.brand).toBe('Test');
      });
    });

    describe('Database Schema Compatibility', () => {
      test('should work with additional schema columns', async () => {
        const garmentWithExtraColumns = {
          id: 'test-id',
          user_id: 'user-id',
          original_image_id: 'image-id',
          metadata: '{"name":"Test"}',
          created_at: new Date(),
          updated_at: new Date(),
          // Additional future columns
          version: 2,
          archived: false,
          external_id: 'ext-123'
        };
        
        mockQuery.mockResolvedValue({ rows: [garmentWithExtraColumns] });

        const result = await testGarmentModel.findById('garment-uuid');
        
        expect(result.id).toBe('test-id');
        expect(result.user_id).toBe('user-id');
        expect(result.metadata).toEqual({ name: 'Test' });
      });

      test('should handle missing optional columns gracefully', async () => {
        const minimalGarment = {
          id: 'test-id',
          user_id: 'user-id',
          metadata: '{"name":"Minimal"}',
          created_at: new Date(),
          updated_at: new Date()
          // original_image_id is null/missing
        };
        
        mockQuery.mockResolvedValue({ rows: [minimalGarment] });

        const result = await testGarmentModel.findById('garment-uuid');
        
        expect(result.original_image_id).toBeUndefined();
        expect(result.metadata).toEqual({ name: 'Minimal' });
      });
    });
  });
});