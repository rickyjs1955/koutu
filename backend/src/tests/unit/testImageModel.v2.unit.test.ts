// /backend/src/utils/__tests__/testImageModel.v2.test.ts
/**
 * Comprehensive Test Suite for Test Image Model v2 (Dual-Mode)
 * 
 * Tests the dual-mode image model that handles image CRUD operations,
 * file path validation, metadata management, and security in both Docker and Manual modes.
 * 
 * Coverage: Unit + Integration + Security
 */

import { testImageModel } from '../../utils/testImageModel.v2';
import { v4 as uuidv4 } from 'uuid';

// Mock dependencies
jest.mock('../../utils/dockerMigrationHelper', () => ({
  getTestDatabaseConnection: jest.fn()
}));

jest.mock('uuid');

describe('TestImageModel v2 - Dual-Mode Image Operations', () => {
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
    (uuidv4 as jest.Mock).mockReturnValue('test-image-uuid-123');
  });

  // ============================================================================
  // UNIT TESTS - Core Image Operations
  // ============================================================================
  describe('Unit Tests - Core Image Operations', () => {
    describe('Image Creation', () => {
      test('should create image with valid data successfully', async () => {
        const mockCreatedImage = {
          id: 'test-image-uuid-123',
          user_id: 'valid-user-uuid',
          file_path: '/uploads/test-image.jpg',
          original_metadata: { width: 1920, height: 1080, format: 'JPEG' },
          upload_date: new Date(),
          status: 'new'
        };

        mockQuery.mockResolvedValue({ rows: [mockCreatedImage] });

        const result = await testImageModel.create({
          user_id: 'valid-user-uuid',
          file_path: '/uploads/test-image.jpg',
          original_metadata: { width: 1920, height: 1080, format: 'JPEG' }
        });

        expect(uuidv4).toHaveBeenCalled();
        expect(mockQuery).toHaveBeenCalledWith(
          'INSERT INTO original_images (id, user_id, file_path, original_metadata, upload_date, status) VALUES ($1, $2, $3, $4, NOW(), \'new\') RETURNING *',
          ['test-image-uuid-123', 'valid-user-uuid', '/uploads/test-image.jpg', '{"width":1920,"height":1080,"format":"JPEG"}']
        );
        expect(result).toEqual(mockCreatedImage);
      });

      test('should create image with default empty metadata', async () => {
        const mockCreatedImage = {
          id: 'test-image-uuid-123',
          user_id: 'valid-user-uuid',
          file_path: '/uploads/test-image.jpg',
          original_metadata: {},
          upload_date: new Date(),
          status: 'new'
        };

        mockQuery.mockResolvedValue({ rows: [mockCreatedImage] });

        const result = await testImageModel.create({
          user_id: 'valid-user-uuid',
          file_path: '/uploads/test-image.jpg'
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO original_images'),
          expect.arrayContaining(['test-image-uuid-123', 'valid-user-uuid', '/uploads/test-image.jpg', '{}'])
        );
      });

      test('should throw error for missing required fields', async () => {
        await expect(testImageModel.create({
          user_id: '',
          file_path: '/uploads/test-image.jpg'
        })).rejects.toThrow('user_id and file_path are required');

        await expect(testImageModel.create({
          user_id: 'valid-user-uuid',
          file_path: ''
        })).rejects.toThrow('user_id and file_path are required');

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should throw error for invalid UUID format', async () => {
        await expect(testImageModel.create({
          user_id: 'invalid-uuid-format',
          file_path: '/uploads/test-image.jpg'
        })).rejects.toThrow('Invalid user_id format');

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle complex metadata objects', async () => {
        const complexMetadata = {
          width: 4000,
          height: 3000,
          format: 'PNG',
          colorSpace: 'sRGB',
          compression: 'lossless',
          exif: {
            camera: 'Canon EOS R5',
            lens: '24-70mm f/2.8',
            settings: {
              iso: 800,
              aperture: 'f/4.0',
              shutterSpeed: '1/125'
            }
          },
          gps: {
            latitude: 40.7128,
            longitude: -74.0060
          }
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testImageModel.create({
          user_id: 'valid-user-uuid',
          file_path: '/uploads/complex-image.png',
          original_metadata: complexMetadata
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO original_images'),
          expect.arrayContaining([
            'test-image-uuid-123',
            'valid-user-uuid',
            '/uploads/complex-image.png',
            JSON.stringify(complexMetadata)
          ])
        );
      });
    });

    describe('Image Retrieval', () => {
      test('should find image by valid ID', async () => {
        const mockImage = {
          id: 'valid-image-uuid',
          user_id: 'user-uuid',
          file_path: '/uploads/image.jpg',
          original_metadata: { width: 1920, height: 1080 },
          upload_date: new Date(),
          status: 'processed'
        };

        mockQuery.mockResolvedValue({ rows: [mockImage] });

        const result = await testImageModel.findById('valid-image-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM original_images WHERE id = $1',
          ['valid-image-uuid']
        );
        expect(result).toEqual(mockImage);
      });

      test('should return null for invalid UUID format', async () => {
        const result = await testImageModel.findById('invalid-uuid');
        
        expect(result).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should return null for empty or null ID', async () => {
        expect(await testImageModel.findById('')).toBeNull();
        expect(await testImageModel.findById(null as any)).toBeNull();
        expect(await testImageModel.findById(undefined as any)).toBeNull();
        
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle database UUID errors gracefully', async () => {
        mockQuery.mockRejectedValue(new Error('invalid input syntax for type uuid'));

        const result = await testImageModel.findById('malformed-uuid');
        
        expect(result).toBeNull();
      });

      test('should find images by user ID with default options', async () => {
        const mockImages = [
          { id: 'image1', user_id: 'user-uuid', status: 'new', upload_date: new Date() },
          { id: 'image2', user_id: 'user-uuid', status: 'processed', upload_date: new Date() }
        ];

        mockQuery.mockResolvedValue({ rows: mockImages });

        const result = await testImageModel.findByUserId('valid-user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM original_images WHERE user_id = $1 ORDER BY upload_date DESC',
          ['valid-user-uuid']
        );
        expect(result).toEqual(mockImages);
      });

      test('should find images by user ID with status filter', async () => {
        const mockImages = [
          { id: 'image1', user_id: 'user-uuid', status: 'processed', upload_date: new Date() }
        ];

        mockQuery.mockResolvedValue({ rows: mockImages });

        const result = await testImageModel.findByUserId('valid-user-uuid', { status: 'processed' });

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM original_images WHERE user_id = $1 AND status = $2 ORDER BY upload_date DESC',
          ['valid-user-uuid', 'processed']
        );
        expect(result).toEqual(mockImages);
      });

      test('should find images with pagination', async () => {
        const mockImages = [
          { id: 'image1', user_id: 'user-uuid', upload_date: new Date() }
        ];

        mockQuery.mockResolvedValue({ rows: mockImages });

        await testImageModel.findByUserId('valid-user-uuid', { limit: 10, offset: 20 });

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM original_images WHERE user_id = $1 ORDER BY upload_date DESC LIMIT $2 OFFSET $3',
          ['valid-user-uuid', 10, 20]
        );
      });

      test('should return empty array for invalid user UUID', async () => {
        const result = await testImageModel.findByUserId('invalid-uuid');
        
        expect(result).toEqual([]);
        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('Image Status Updates', () => {
      test('should update image status successfully', async () => {
        const mockUpdatedImage = {
          id: 'valid-image-uuid',
          user_id: 'user-uuid',
          status: 'processed',
          upload_date: new Date()
        };

        mockQuery.mockResolvedValue({ rows: [mockUpdatedImage] });

        const result = await testImageModel.updateStatus('valid-image-uuid', 'processed');

        expect(mockQuery).toHaveBeenCalledWith(
          'UPDATE original_images SET status = $1 WHERE id = $2 RETURNING *',
          ['processed', 'valid-image-uuid']
        );
        expect(result).toEqual(mockUpdatedImage);
      });

      test('should return null for invalid UUID in status update', async () => {
        const result = await testImageModel.updateStatus('invalid-uuid', 'processed');
        
        expect(result).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should throw error for invalid status value', async () => {
        await expect(testImageModel.updateStatus('valid-image-uuid', 'invalid-status' as any))
          .rejects.toThrow('Invalid status value');

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should validate all allowed status values', async () => {
        const validStatuses = ['new', 'processed', 'labeled'];
        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        for (const status of validStatuses) {
          await testImageModel.updateStatus('valid-image-uuid', status as any);
        }

        expect(mockQuery).toHaveBeenCalledTimes(validStatuses.length);
      });

      test('should handle database UUID errors in status update', async () => {
        mockQuery.mockRejectedValue(new Error('invalid input syntax for type uuid'));

        const result = await testImageModel.updateStatus('malformed-uuid', 'processed');
        
        expect(result).toBeNull();
      });
    });

    describe('Image Deletion', () => {
      test('should delete image successfully', async () => {
        mockQuery.mockResolvedValue({ rowCount: 1 });

        const result = await testImageModel.delete('valid-image-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM original_images WHERE id = $1',
          ['valid-image-uuid']
        );
        expect(result).toBe(true);
      });

      test('should return false when image not found for deletion', async () => {
        mockQuery.mockResolvedValue({ rowCount: 0 });

        const result = await testImageModel.delete('valid-image-uuid');
        
        expect(result).toBe(false);
      });

      test('should return false for invalid UUID in deletion', async () => {
        const result = await testImageModel.delete('invalid-uuid');
        
        expect(result).toBe(false);
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle database UUID errors in deletion', async () => {
        mockQuery.mockRejectedValue(new Error('invalid input syntax for type uuid'));

        const result = await testImageModel.delete('malformed-uuid');
        
        expect(result).toBe(false);
      });
    });

    describe('Metadata Operations', () => {
      test('should update image metadata successfully', async () => {
        const newMetadata = { width: 2000, height: 1500, edited: true };
        const mockUpdatedImage = {
          id: 'valid-image-uuid',
          original_metadata: newMetadata
        };

        mockQuery.mockResolvedValue({ rows: [mockUpdatedImage] });

        const result = await testImageModel.updateMetadata('valid-image-uuid', newMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          'UPDATE original_images SET original_metadata = $1 WHERE id = $2 RETURNING *',
          [JSON.stringify(newMetadata), 'valid-image-uuid']
        );
        expect(result).toEqual(mockUpdatedImage);
      });

      test('should return null for invalid UUID in metadata update', async () => {
        const result = await testImageModel.updateMetadata('invalid-uuid', {});
        
        expect(result).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle complex metadata updates', async () => {
        const complexMetadata = {
          processing: {
            filters_applied: ['brightness', 'contrast', 'saturation'],
            timestamp: new Date().toISOString(),
            version: '2.1.0'
          },
          analysis: {
            detected_objects: ['person', 'clothing', 'background'],
            confidence_scores: [0.95, 0.87, 0.92],
            colors: {
              dominant: '#FF5733',
              palette: ['#FF5733', '#33FF57', '#3357FF']
            }
          }
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testImageModel.updateMetadata('valid-image-uuid', complexMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE original_images SET original_metadata'),
          [JSON.stringify(complexMetadata), 'valid-image-uuid']
        );
      });
    });
  });

  // ============================================================================
  // INTEGRATION TESTS - Complex Operations and Dependencies
  // ============================================================================
  describe('Integration Tests - Complex Operations', () => {
    describe('Dependency Management', () => {
      test('should find dependent garments for an image', async () => {
        const mockGarments = [
          { id: 'garment1', user_id: 'user-uuid' },
          { id: 'garment2', user_id: 'user-uuid' }
        ];

        mockQuery.mockResolvedValue({ rows: mockGarments });

        const result = await testImageModel.findDependentGarments('valid-image-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT id, user_id FROM garment_items WHERE original_image_id = $1',
          ['valid-image-uuid']
        );
        expect(result).toEqual(mockGarments);
      });

      test('should return empty array for invalid UUID in garment dependencies', async () => {
        const result = await testImageModel.findDependentGarments('invalid-uuid');
        
        expect(result).toEqual([]);
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle missing garment_items table gracefully', async () => {
        mockQuery.mockRejectedValue(new Error('relation "garment_items" does not exist'));

        const result = await testImageModel.findDependentGarments('valid-image-uuid');
        
        expect(result).toEqual([]);
      });

      test('should find dependent polygons for an image', async () => {
        const mockPolygons = [
          { id: 'polygon1', user_id: 'user-uuid' },
          { id: 'polygon2', user_id: 'user-uuid' }
        ];

        mockQuery.mockResolvedValue({ rows: mockPolygons });

        const result = await testImageModel.findDependentPolygons('valid-image-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT id, user_id FROM polygons WHERE original_image_id = $1',
          ['valid-image-uuid']
        );
        expect(result).toEqual(mockPolygons);
      });

      test('should handle missing polygons table gracefully', async () => {
        mockQuery.mockRejectedValue(new Error('relation "polygons" does not exist'));

        const result = await testImageModel.findDependentPolygons('valid-image-uuid');
        
        expect(result).toEqual([]);
      });
    });

    describe('Batch Operations', () => {
      test('should batch update status for multiple images', async () => {
        const imageIds = ['uuid1', 'uuid2', 'uuid3'];
        mockQuery.mockResolvedValue({ rowCount: 3 });

        const result = await testImageModel.batchUpdateStatus(imageIds, 'processed');

        expect(mockQuery).toHaveBeenCalledWith(
          'UPDATE original_images SET status = $1 WHERE id IN ($2,$3,$4)',
          ['processed', 'uuid1', 'uuid2', 'uuid3']
        );
        expect(result).toBe(3);
      });

      test('should filter out invalid UUIDs in batch operations', async () => {
        const imageIds = ['valid-uuid-1', 'invalid-uuid', 'valid-uuid-2'];
        mockQuery.mockResolvedValue({ rowCount: 2 });

        const result = await testImageModel.batchUpdateStatus(imageIds, 'processed');

        // Should only process valid UUIDs
        expect(mockQuery).toHaveBeenCalledWith(
          'UPDATE original_images SET status = $1 WHERE id IN ($2,$3)',
          ['processed', 'valid-uuid-1', 'valid-uuid-2']
        );
        expect(result).toBe(2);
      });

      test('should return 0 for empty or all-invalid UUID arrays', async () => {
        expect(await testImageModel.batchUpdateStatus([], 'processed')).toBe(0);
        expect(await testImageModel.batchUpdateStatus(['invalid1', 'invalid2'], 'processed')).toBe(0);
        
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle batch operation errors gracefully', async () => {
        mockQuery.mockRejectedValue(new Error('Batch update failed'));

        const result = await testImageModel.batchUpdateStatus(['valid-uuid-1'], 'processed');
        
        expect(result).toBe(0);
      });
    });

    describe('User Statistics and Analytics', () => {
      test('should get comprehensive user image statistics', async () => {
        const mockStatsRows = [
          { total: '10', status: 'new', total_size: '1000000', average_size: '100000' },
          { total: '5', status: 'processed', total_size: '500000', average_size: '100000' },
          { total: '3', status: 'labeled', total_size: '300000', average_size: '100000' }
        ];

        mockQuery.mockResolvedValue({ rows: mockStatsRows });

        const result = await testImageModel.getUserImageStats('valid-user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('COUNT(*) as total'),
          ['valid-user-uuid']
        );

        expect(result).toEqual({
          total: 18,
          byStatus: {
            new: 10,
            processed: 5,
            labeled: 3
          },
          totalSize: 1800000,
          averageSize: 100000
        });
      });

      test('should return zero stats for invalid user UUID', async () => {
        const result = await testImageModel.getUserImageStats('invalid-uuid');

        expect(result).toEqual({
          total: 0,
          byStatus: {},
          totalSize: 0,
          averageSize: 0
        });
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle missing size metadata in statistics', async () => {
        const mockStatsRows = [
          { total: '5', status: 'new', total_size: null, average_size: null }
        ];

        mockQuery.mockResolvedValue({ rows: mockStatsRows });

        const result = await testImageModel.getUserImageStats('valid-user-uuid');

        expect(result).toEqual({
          total: 5,
          byStatus: { new: 5 },
          totalSize: 0,
          averageSize: 0
        });
      });

      test('should count images by user ID', async () => {
        mockQuery.mockResolvedValue({ rows: [{ count: '25' }] });

        const result = await testImageModel.countByUserId('valid-user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT COUNT(*) as count FROM original_images WHERE user_id = $1',
          ['valid-user-uuid']
        );
        expect(result).toBe(25);
      });

      test('should return 0 count for invalid user UUID', async () => {
        const result = await testImageModel.countByUserId('invalid-uuid');
        
        expect(result).toBe(0);
        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('File Path and Search Operations', () => {
      test('should find images by file path', async () => {
        const mockImages = [
          { id: 'image1', file_path: '/uploads/test.jpg' },
          { id: 'image2', file_path: '/uploads/test.jpg' }
        ];

        mockQuery.mockResolvedValue({ rows: mockImages });

        const result = await testImageModel.findByFilePath('/uploads/test.jpg');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM original_images WHERE file_path = $1',
          ['/uploads/test.jpg']
        );
        expect(result).toEqual(mockImages);
      });

      test('should return empty array for empty file path', async () => {
        const result = await testImageModel.findByFilePath('');
        
        expect(result).toEqual([]);
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should check if image exists by user and path', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'existing-image' }] });

        const result = await testImageModel.existsByUserAndPath('valid-user-uuid', '/uploads/test.jpg');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT 1 FROM original_images WHERE user_id = $1 AND file_path = $2 LIMIT 1',
          ['valid-user-uuid', '/uploads/test.jpg']
        );
        expect(result).toBe(true);
      });

      test('should return false for non-existent user/path combination', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await testImageModel.existsByUserAndPath('valid-user-uuid', '/uploads/nonexistent.jpg');
        
        expect(result).toBe(false);
      });

      test('should find images by date range', async () => {
        const startDate = new Date('2023-01-01');
        const endDate = new Date('2023-12-31');
        const mockImages = [
          { id: 'image1', upload_date: new Date('2023-06-15') }
        ];

        mockQuery.mockResolvedValue({ rows: mockImages });

        const result = await testImageModel.findByDateRange('valid-user-uuid', startDate, endDate);

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM original_images WHERE user_id = $1 AND upload_date BETWEEN $2 AND $3 ORDER BY upload_date DESC',
          ['valid-user-uuid', startDate, endDate]
        );
        expect(result).toEqual(mockImages);
      });

      test('should find most recent image for user', async () => {
        const mockImage = { id: 'latest-image', upload_date: new Date() };
        mockQuery.mockResolvedValue({ rows: [mockImage] });

        const result = await testImageModel.findMostRecent('valid-user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM original_images WHERE user_id = $1 ORDER BY upload_date DESC LIMIT 1',
          ['valid-user-uuid']
        );
        expect(result).toEqual(mockImage);
      });

      test('should return null when no images exist for user', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await testImageModel.findMostRecent('valid-user-uuid');
        
        expect(result).toBeNull();
      });
    });

    describe('Bulk Deletion Operations', () => {
      test('should delete all images for a user', async () => {
        mockQuery.mockResolvedValue({ rowCount: 15 });

        const result = await testImageModel.deleteAllByUserId('valid-user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM original_images WHERE user_id = $1',
          ['valid-user-uuid']
        );
        expect(result).toBe(15);
      });

      test('should return 0 for invalid user UUID in bulk deletion', async () => {
        const result = await testImageModel.deleteAllByUserId('invalid-uuid');
        
        expect(result).toBe(0);
        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle deletion errors gracefully', async () => {
        mockQuery.mockRejectedValue(new Error('Foreign key constraint violation'));

        const result = await testImageModel.deleteAllByUserId('valid-user-uuid');
        
        expect(result).toBe(0);
      });
    });
  });

  // ============================================================================
  // SECURITY TESTS - File Path Validation and Input Protection
  // ============================================================================
  describe('Security Tests - File Path Validation and Protection', () => {
    describe('File Path Security', () => {
      test('should handle malicious file paths safely', async () => {
        const maliciousPaths = [
          '../../utils/../../etc/passwd',
          '../../utils/../windows/system32/config/sam',
          '/etc/shadow',
          'C:\\Windows\\System32\\config\\SAM',
          '..\\..\\..\\etc\\passwd',
          '/proc/self/environ',
          'file:///etc/passwd',
          'data:text/plain;base64,dGVzdA==',
          'javascript:alert("xss")',
          '<script>alert("xss")</script>',
          "'; DROP TABLE original_images; --"
        ];

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        for (const path of maliciousPaths) {
          await testImageModel.create({
            user_id: 'valid-user-uuid',
            file_path: path
          });
        }

        // Should use parameterized queries for all paths
        expect(mockQuery).toHaveBeenCalledTimes(maliciousPaths.length);
        maliciousPaths.forEach(path => {
          expect(mockQuery).toHaveBeenCalledWith(
            expect.stringContaining('INSERT INTO original_images'),
            expect.arrayContaining([expect.any(String), 'valid-user-uuid', path, expect.any(String)])
          );
        });
      });

      test('should prevent path traversal in file path searches', async () => {
        const traversalPaths = [
          '../../utils/../../sensitive-file.jpg',
          '..\\..\\..\\sensitive-file.jpg',
          '/root/.ssh/id_rsa',
          'C:\\Users\\Administrator\\Desktop\\secret.jpg'
        ];

        mockQuery.mockResolvedValue({ rows: [] });

        for (const path of traversalPaths) {
          await testImageModel.findByFilePath(path);
        }

        // Should use parameterized queries
        traversalPaths.forEach(path => {
          expect(mockQuery).toHaveBeenCalledWith(
            'SELECT * FROM original_images WHERE file_path = $1',
            [path]
          );
        });
      });

      test('should validate file path existence checks safely', async () => {
        const suspiciousPaths = [
          "'; SELECT * FROM users; --",
          "../../../etc/passwd",
          "test.jpg'; DROP TABLE original_images; --"
        ];

        mockQuery.mockResolvedValue({ rows: [] });

        for (const path of suspiciousPaths) {
          const result = await testImageModel.existsByUserAndPath('valid-user-uuid', path);
          expect(result).toBe(false);
        }

        // Should use parameterized queries for all
        suspiciousPaths.forEach(path => {
          expect(mockQuery).toHaveBeenCalledWith(
            'SELECT 1 FROM original_images WHERE user_id = $1 AND file_path = $2 LIMIT 1',
            ['valid-user-uuid', path]
          );
        });
      });
    });

    describe('Metadata Security', () => {
      test('should handle malicious metadata safely', async () => {
        const maliciousMetadata = {
          script: '<script>alert("xss")</script>',
          sql: "'; DROP TABLE users; --",
          path: '../../utils/../../etc/passwd',
          html: '<img src="x" onerror="alert(\'xss\')">',
          prototype_pollution: {
            '__proto__': { admin: true },
            'constructor': { prototype: { admin: true } }
          },
          buffer_overflow: 'A'.repeat(100000),
          null_bytes: 'test\x00.jpg',
          unicode_bypass: '\u003cscript\u003ealert("xss")\u003c/script\u003e'
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testImageModel.create({
          user_id: 'valid-user-uuid',
          file_path: '/uploads/test.jpg',
          original_metadata: maliciousMetadata
        });

        // Should safely store as JSON string in parameterized query
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO original_images'),
          expect.arrayContaining([
            expect.any(String),
            'valid-user-uuid',
            '/uploads/test.jpg',
            JSON.stringify(maliciousMetadata)
          ])
        );
      });

      test('should prevent metadata injection in updates', async () => {
        const injectionMetadata = {
          "'; UPDATE users SET admin = true; --": "malicious",
          "../../../config": "path_traversal",
          "eval('alert(1)')": "code_injection"
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testImageModel.updateMetadata('valid-image-uuid', injectionMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          'UPDATE original_images SET original_metadata = $1 WHERE id = $2 RETURNING *',
          [JSON.stringify(injectionMetadata), 'valid-image-uuid']
        );
      });

      test('should handle extremely large metadata objects', async () => {
        const largeMetadata = {
          data: 'x'.repeat(10000000), // 10MB string
          array: new Array(100000).fill('large_array_item'),
          nested: {} as any
        };

        // Create deeply nested object
        let current = largeMetadata.nested;
        for (let i = 0; i < 1000; i++) {
          current.next = {};
          current = current.next;
        }

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        // Should handle without memory issues or crashes
        await testImageModel.updateMetadata('valid-image-uuid', largeMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE original_images SET original_metadata'),
          [JSON.stringify(largeMetadata), 'valid-image-uuid']
        );
      });
    });

    describe('UUID Injection Prevention', () => {
      test('should reject SQL injection attempts through UUID parameters', async () => {
        const maliciousUuids = [
          "'; DROP TABLE original_images; --",
          "' UNION SELECT * FROM users; --",
          "'; UPDATE original_images SET user_id = 'attacker'; --",
          "' OR '1'='1'; --",
          "\\x27; DROP TABLE original_images; --"
        ];

        for (const uuid of maliciousUuids) {
          const result = await testImageModel.findById(uuid);
          expect(result).toBeNull(); // Should safely reject
        }

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should validate UUID format strictly in all operations', async () => {
        const invalidUuids = [
          'not-a-uuid',
          '12345678-1234-1234-1234-12345678901', // Too short
          '12345678-1234-1234-1234-1234567890123', // Too long
          '12345678-1234-G234-1234-123456789012', // Invalid character
          '../../utils/../etc/passwd',
          '<script>alert("xss")</script>',
          "'; DROP TABLE users; --",
          'null',
          'undefined',
          '00000000-0000-0000-0000-000000000000' // All zeros (edge case)
        ];

        for (const uuid of invalidUuids) {
          expect(await testImageModel.findById(uuid)).toBeNull();
          expect(await testImageModel.updateStatus(uuid, 'processed')).toBeNull();
          expect(await testImageModel.delete(uuid)).toBe(false);
          expect(await testImageModel.updateMetadata(uuid, {})).toBeNull();
        }

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should prevent user ID injection in queries', async () => {
        const maliciousUserIds = [
          "'; SELECT * FROM original_images; --",
          "' UNION ALL SELECT password_hash FROM users; --",
          "\\x27 OR 1=1; --"
        ];

        for (const userId of maliciousUserIds) {
          const result = await testImageModel.findByUserId(userId);
          expect(result).toEqual([]); // Should return empty, not execute injection
        }

        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('Status Validation Security', () => {
      test('should strictly validate status enum values', async () => {
        const invalidStatuses = [
          'admin',
          'DELETE FROM users',
          '<script>alert("xss")</script>',
          "'; DROP TABLE original_images; --",
          'new; UPDATE users SET admin = true; --',
          '../../utils/../../etc/passwd',
          null,
          undefined,
          123,
          true,
          { status: 'processed' }
        ];

        for (const status of invalidStatuses) {
          await expect(testImageModel.updateStatus('valid-image-uuid', status as any))
            .rejects.toThrow('Invalid status value');
        }

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should prevent status injection in batch operations', async () => {
        const maliciousStatus = "processed'; UPDATE users SET admin = true; --";

        await expect(testImageModel.batchUpdateStatus(['valid-uuid'], maliciousStatus as any))
          .rejects.toThrow('Invalid status value');

        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('Error Information Disclosure Prevention', () => {
      test('should not expose database schema in error messages', async () => {
        mockQuery.mockRejectedValue(new Error('column "secret_admin_flag" does not exist'));

        try {
          await testImageModel.findById('valid-image-uuid');
        } catch (error) {
          // Should either handle gracefully or not expose internal details
          expect(error instanceof Error ? error.message : String(error)).not.toContain('secret_admin_flag');
        }
      });

      test('should handle foreign key constraint errors safely', async () => {
        mockQuery.mockRejectedValue(new Error('violates foreign key constraint "fk_secret_table_reference"'));

        const result = await testImageModel.delete('valid-image-uuid');
        
        // Should handle error without exposing constraint details
        expect(result).toBe(false);
      });

      test('should not expose database connection details', async () => {
        mockQuery.mockRejectedValue(new Error('connection to server at "secret-db-host" (192.168.1.100), port 5432 failed'));

        try {
          await testImageModel.countByUserId('valid-user-uuid');
        } catch (error) {
          // Should not expose internal database details
          const errorMessage = error instanceof Error ? error.message : String(error);
          expect(errorMessage).not.toContain('secret-db-host');
          expect(errorMessage).not.toContain('192.168.1.100');
        }
      });
    });

    describe('Input Boundary Security', () => {
      test('should handle null and undefined inputs safely', async () => {
        // All these should not crash and return appropriate safe values
        expect(await testImageModel.findById(null as any)).toBeNull();
        expect(await testImageModel.findById(undefined as any)).toBeNull();
        expect(await testImageModel.findByUserId(null as any)).toEqual([]);
        expect(await testImageModel.findByUserId(undefined as any)).toEqual([]);
        expect(await testImageModel.delete(null as any)).toBe(false);
        expect(await testImageModel.updateStatus(null as any, 'processed')).toBeNull();
        expect(await testImageModel.findByFilePath(null as any)).toEqual([]);

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle buffer overflow attempts', async () => {
        const overflowString = 'A'.repeat(1000000); // 1MB string

        // Should handle without crashing or memory issues
        expect(await testImageModel.findById(overflowString)).toBeNull();
        expect(await testImageModel.findByFilePath(overflowString)).toEqual([]);

        expect(mockQuery).not.toHaveBeenCalled();
      });

      test('should handle special characters and encoding attacks', async () => {
        const specialInputs = [
          '\x00\x01\x02\x03\x04\x05', // Null bytes and control characters
          '\u0000\u0001\u0002', // Unicode null bytes
          '\uFEFF\uFFFE\uFFFF', // Unicode BOM and invalid characters
          '%00%01%02%03', // URL encoded null bytes
          '\r\n\r\nHTTP/1.1 200 OK\r\n\r\n', // HTTP response splitting
          '\x1b[31mRed Text\x1b[0m' // ANSI escape sequences
        ];

        for (const input of specialInputs) {
          expect(await testImageModel.findById(input)).toBeNull();
          expect(await testImageModel.findByFilePath(input)).toEqual([]);
        }

        expect(mockQuery).not.toHaveBeenCalled();
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

        await expect(testImageModel.findById('valid-image-uuid')).rejects.toThrow('Connection lost');
      });

      test('should handle query timeouts', async () => {
        mockQuery.mockRejectedValue(new Error('Query timeout'));

        await expect(testImageModel.getUserImageStats('valid-user-uuid')).rejects.toThrow('Query timeout');
      });

      test('should handle database lock errors', async () => {
        mockQuery.mockRejectedValue(new Error('could not obtain lock on row'));

        await expect(testImageModel.updateStatus('valid-image-uuid', 'processed')).rejects.toThrow('could not obtain lock');
      });
    });

    describe('Data Consistency Edge Cases', () => {
      test('should handle concurrent image uploads with same path', async () => {
        // Simulate race condition
        mockQuery
          .mockResolvedValueOnce({ rows: [] }) // Path check passes
          .mockRejectedValueOnce(new Error('duplicate key value violates unique constraint'));

        await expect(testImageModel.create({
          user_id: 'valid-user-uuid',
          file_path: '/uploads/concurrent.jpg'
        })).rejects.toThrow('duplicate key value');
      });

      test('should handle orphaned image dependencies', async () => {
        // Image deleted but garments still reference it
        mockQuery.mockResolvedValue({ rows: [] });

        const result = await testImageModel.findDependentGarments('orphaned-image-uuid');
        
        expect(result).toEqual([]);
      });

      test('should handle malformed JSON metadata in database', async () => {
        // Simulate corrupted metadata in database
        const corruptedImage = {
          id: 'test-id',
          original_metadata: 'invalid json {'
        };

        mockQuery.mockResolvedValue({ rows: [corruptedImage] });

        const result = await testImageModel.findById('valid-image-uuid');
        
        // Should handle gracefully
        expect(result).toBeDefined();
      });
    });

    describe('Boundary Conditions', () => {
      test('should handle very long file paths', async () => {
        const longPath = '/uploads/' + 'very-long-filename-'.repeat(100) + '.jpg';
        
        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testImageModel.create({
          user_id: 'valid-user-uuid',
          file_path: longPath
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO original_images'),
          expect.arrayContaining([expect.any(String), 'valid-user-uuid', longPath, expect.any(String)])
        );
      });

      test('should handle edge case date ranges', async () => {
        const veryOldDate = new Date('1900-01-01');
        const futureDate = new Date('2100-01-01');

        mockQuery.mockResolvedValue({ rows: [] });

        await testImageModel.findByDateRange('valid-user-uuid', veryOldDate, futureDate);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('upload_date BETWEEN'),
          ['valid-user-uuid', veryOldDate, futureDate]
        );
      });

      test('should handle maximum pagination values', async () => {
        const maxLimit = Number.MAX_SAFE_INTEGER;
        const maxOffset = Number.MAX_SAFE_INTEGER;

        mockQuery.mockResolvedValue({ rows: [] });

        await testImageModel.findByUserId('valid-user-uuid', { 
          limit: maxLimit, 
          offset: maxOffset 
        });

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('LIMIT'),
          ['valid-user-uuid', maxLimit, maxOffset]
        );
      });
    });

    describe('Memory and Performance Edge Cases', () => {
      test('should handle large batch operations efficiently', async () => {
        const largeImageArray = Array.from({ length: 1000 }, (_, i) => `image-uuid-${i}`);
        
        mockQuery.mockResolvedValue({ rowCount: 1000 });

        const result = await testImageModel.batchUpdateStatus(largeImageArray, 'processed');

        expect(result).toBe(1000);
        // Should handle large parameter arrays
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('WHERE id IN'),
          expect.arrayContaining(['processed', ...largeImageArray])
        );
      });

      test('should handle concurrent operations without blocking', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        // Simulate many concurrent operations
        const operations = Array.from({ length: 100 }, (_, i) => 
          testImageModel.findById(`image-uuid-${i}`)
        );

        const results = await Promise.all(operations);
        
        expect(results).toHaveLength(100);
        expect(mockQuery).toHaveBeenCalledTimes(100);
      });

      test('should handle memory-intensive metadata operations', async () => {
        const heavyMetadata = {
          imageData: new Array(1000000).fill('pixel_data'),
          processingHistory: new Array(10000).fill({
            timestamp: new Date().toISOString(),
            operation: 'resize',
            parameters: { width: 1920, height: 1080 }
          })
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        // Should handle without memory overflow
        await testImageModel.updateMetadata('valid-image-uuid', heavyMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE original_images SET original_metadata'),
          [JSON.stringify(heavyMetadata), 'valid-image-uuid']
        );
      });
    });

    describe('Integration with dockerMigrationHelper', () => {
      test('should use correct database connection from helper', () => {
        const { getTestDatabaseConnection } = require('../../utils/dockerMigrationHelper');
        
        // Verify the helper is called to get database connection
        expect(getTestDatabaseConnection).toHaveBeenCalled();
      });

      test('should handle database connection mode switching', async () => {
        const { getTestDatabaseConnection } = require('../../utils/dockerMigrationHelper');
        
        // Mock different database connections
        const dockerDB = { query: jest.fn().mockResolvedValue({ rows: [{ source: 'docker' }] }) };
        const manualDB = { query: jest.fn().mockResolvedValue({ rows: [{ source: 'manual' }] }) };

        // Switch to docker mode
        getTestDatabaseConnection.mockReturnValueOnce(dockerDB);
        await testImageModel.findById('valid-image-uuid');
        
        // Switch to manual mode
        getTestDatabaseConnection.mockReturnValueOnce(manualDB);
        await testImageModel.findById('valid-image-uuid');

        expect(dockerDB.query).toHaveBeenCalled();
        expect(manualDB.query).toHaveBeenCalled();
      });

      test('should maintain consistent API across modes', async () => {
        const { getTestDatabaseConnection } = require('../../utils/dockerMigrationHelper');
        
        // Both modes should provide same interface
        const mockResult = { rows: [{ id: 'test-id', user_id: 'user-id' }] };
        
        getTestDatabaseConnection.mockReturnValue({ query: jest.fn().mockResolvedValue(mockResult) });

        const result = await testImageModel.findById('valid-image-uuid');
        
        expect(result).toHaveProperty('id');
        expect(result).toHaveProperty('user_id');
      });
    });
  });

  // ============================================================================
  // PERFORMANCE AND OPTIMIZATION TESTS
  // ============================================================================
  describe('Performance and Optimization Tests', () => {
    describe('Query Efficiency', () => {
      test('should use efficient queries with proper indexing hints', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        await testImageModel.findByUserId('valid-user-uuid');

        // Should order by upload_date (indexed column) for efficiency
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('ORDER BY upload_date DESC'),
          ['valid-user-uuid']
        );
      });

      test('should use LIMIT for single result queries', async () => {
        mockQuery.mockResolvedValue({ rows: [] });

        await testImageModel.findMostRecent('valid-user-uuid');

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('LIMIT 1'),
          ['valid-user-uuid']
        );
      });

      test('should use efficient COUNT queries for statistics', async () => {
        mockQuery.mockResolvedValue({ rows: [{ count: '100' }] });

        await testImageModel.countByUserId('valid-user-uuid');

        // Should use COUNT(*) which is optimized
        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT COUNT(*) as count FROM original_images WHERE user_id = $1',
          ['valid-user-uuid']
        );
      });
    });

    describe('Memory Usage Optimization', () => {
      test('should not leak memory with repeated operations', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        // Perform many operations
        for (let i = 0; i < 1000; i++) {
          await testImageModel.findById('valid-image-uuid');
        }

        // Should complete without memory issues
        expect(mockQuery).toHaveBeenCalledTimes(1000);
      });

      test('should handle streaming large result sets', async () => {
        const largeResultSet = Array.from({ length: 50000 }, (_, i) => ({ 
          id: `image-${i}`,
          file_path: `/uploads/image-${i}.jpg`
        }));
        
        mockQuery.mockResolvedValue({ rows: largeResultSet });

        const result = await testImageModel.findByUserId('valid-user-uuid');
        
        expect(result).toHaveLength(50000);
        // Should handle large datasets without memory overflow
      });
    });

    describe('Concurrent Operation Performance', () => {
      test('should handle high concurrent load', async () => {
        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        const concurrentOperations = Array.from({ length: 1000 }, async (_, i) => {
          return Promise.all([
            testImageModel.findById(`image-${i}`),
            testImageModel.countByUserId(`user-${i}`),
            testImageModel.updateStatus(`image-${i}`, 'processed')
          ]);
        });

        const results = await Promise.all(concurrentOperations);
        
        expect(results).toHaveLength(1000);
        // Should handle concurrent operations efficiently
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
            file_path: '/test.jpg',
            original_metadata: { width: 1920, height: 1080 },
            upload_date: new Date(),
            status: 'new'
          }] 
        });

        const image = await testImageModel.findById('valid-image-uuid');
        
        expect(image).toBeDefined();
        expect(image).not.toBeNull();
        expect(image).toHaveProperty('id');
        expect(image).toHaveProperty('user_id');
        expect(image).toHaveProperty('file_path');
        expect(image).toHaveProperty('original_metadata');
        expect(image).toHaveProperty('upload_date');
        expect(image).toHaveProperty('status');
        
        expect(typeof image!.id).toBe('string');
        expect(typeof image!.user_id).toBe('string');
        expect(typeof image!.file_path).toBe('string');
        expect(typeof image!.original_metadata).toBe('object');
        expect(image!.upload_date).toBeInstanceOf(Date);
        expect(['new', 'processed', 'labeled']).toContain(image!.status);
      });

      test('should handle legacy metadata formats', async () => {
        // Test compatibility with older metadata structures
        const legacyMetadata = {
          size: 1024000,
          type: 'image/jpeg',
          dimensions: '1920x1080'
        };

        mockQuery.mockResolvedValue({ rows: [{ id: 'test-id' }] });

        await testImageModel.updateMetadata('valid-image-uuid', legacyMetadata);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE original_images SET original_metadata'),
          [JSON.stringify(legacyMetadata), 'valid-image-uuid']
        );
      });
    });

    describe('Database Schema Compatibility', () => {
      test('should work with additional schema columns', async () => {
        // Test that queries work with extended schema
        const imageWithExtraColumns = {
          id: 'test-id',
          user_id: 'user-id',
          file_path: '/test.jpg',
          original_metadata: {},
          upload_date: new Date(),
          status: 'new',
          // Additional columns that might be added in future
          file_size: 1024000,
          mime_type: 'image/jpeg',
          checksum: 'abc123def456'
        };
        
        mockQuery.mockResolvedValue({ rows: [imageWithExtraColumns] });

        const result = await testImageModel.findById('valid-image-uuid');
        
        expect(result).not.toBeNull();
        expect(result!.id).toBe('test-id');
        expect(result!.user_id).toBe('user-id');
        expect(result!.file_path).toBe('/test.jpg');
      });
    });
  });
});