// tests/models/testImageModel.test.ts
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { testImageModel } from '../../utils/testImageModel';
import { testUserModel } from '../../utils/testUserModel';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

describe('testImageModel', () => {
  let testUserId: string;
  let testUser: any;
  let createdImageIds: string[] = [];
  let createdUserIds: string[] = [];

  beforeAll(async () => {
    console.log('🔧 Setting up testImageModel test environment...');
    
    // Initialize test database
    await TestDatabaseConnection.initialize();
    await setupTestDatabase();
    
    console.log('✅ testImageModel test environment ready');
  }, 30000);

  afterAll(async () => {
    console.log('🧹 Cleaning up testImageModel test environment...');
    
    // Clean up all test data
    await cleanupAllTestData();
    await TestDatabaseConnection.cleanup();
    await teardownTestDatabase();
    
    console.log('✅ testImageModel test cleanup complete');
  }, 15000);

  beforeEach(async () => {
    // Create a test user for each test
    testUser = await testUserModel.create({
      email: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
      password: 'testpassword123'
    });
    testUserId = testUser.id;
    createdUserIds.push(testUserId);
  });

  afterEach(async () => {
    // Clean up images created in this test
    if (createdImageIds.length > 0) {
      await Promise.allSettled(
        createdImageIds.map(id => testImageModel.delete(id))
      );
      createdImageIds = [];
    }
  });

  // Helper function for comprehensive cleanup
  const cleanupAllTestData = async () => {
    try {
      // Delete in dependency order
      if (createdImageIds.length > 0) {
        await TestDatabaseConnection.query('DELETE FROM original_images WHERE id = ANY($1)', [createdImageIds]);
      }
      if (createdUserIds.length > 0) {
        await TestDatabaseConnection.query('DELETE FROM users WHERE id = ANY($1)', [createdUserIds]);
      }
    } catch (error) {
      console.warn('Cleanup error (may be expected):', error);
    }
  };

  // Helper to create test image data
  const createTestImageData = (overrides = {}) => ({
    user_id: testUserId,
    file_path: `uploads/test-image-${Date.now()}.jpg`,
    original_metadata: {
      width: 800,
      height: 600,
      format: 'jpeg',
      size: 204800,
      mimetype: 'image/jpeg',
      filename: `test-image-${Date.now()}.jpg`,
      uploadedAt: new Date().toISOString()
    },
    ...overrides
  });

  describe('Basic CRUD Operations', () => {
    it('should create a new image', async () => {
      const imageData = createTestImageData();
      
      const result = await testImageModel.create(imageData);
      createdImageIds.push(result.id);
      
      expect(result).toBeDefined();
      expect(isUuid(result.id)).toBe(true);
      expect(result.user_id).toBe(testUserId);
      expect(result.file_path).toBe(imageData.file_path);
      expect(result.status).toBe('new');
      expect(result.original_metadata).toEqual(imageData.original_metadata);
      expect(result.upload_date).toBeInstanceOf(Date);
    });

    it('should find image by ID', async () => {
      const imageData = createTestImageData();
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      const found = await testImageModel.findById(created.id);
      
      expect(found).not.toBeNull();
      expect(found!.id).toBe(created.id);
      expect(found!.user_id).toBe(testUserId);
      expect(found!.file_path).toBe(imageData.file_path);
    });

    it('should return null for non-existent image ID', async () => {
      const nonExistentId = uuidv4();
      const result = await testImageModel.findById(nonExistentId);
      
      expect(result).toBeNull();
    });

    it('should return null for invalid UUID format', async () => {
      const result = await testImageModel.findById('invalid-uuid');
      
      expect(result).toBeNull();
    });

    it('should update image status', async () => {
      const imageData = createTestImageData();
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      const updated = await testImageModel.updateStatus(created.id, 'processed');
      
      expect(updated).not.toBeNull();
      expect(updated!.status).toBe('processed');
      expect(updated!.id).toBe(created.id);
    });

    it('should update image metadata', async () => {
      const imageData = createTestImageData();
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      const newMetadata = {
        width: 1920,
        height: 1080,
        processed: true,
        filters: ['brightness', 'contrast']
      };
      
      const updated = await testImageModel.updateMetadata(created.id, newMetadata);
      
      expect(updated).not.toBeNull();
      expect(updated!.original_metadata).toEqual(newMetadata);
    });

    it('should delete image', async () => {
      const imageData = createTestImageData();
      const created = await testImageModel.create(imageData);
      
      const deleted = await testImageModel.delete(created.id);
      expect(deleted).toBe(true);
      
      // Verify deletion
      const found = await testImageModel.findById(created.id);
      expect(found).toBeNull();
    });

    it('should return false when deleting non-existent image', async () => {
      const nonExistentId = uuidv4();
      const result = await testImageModel.delete(nonExistentId);
      
      expect(result).toBe(false);
    });
  });

  describe('Query Operations', () => {
    beforeEach(async () => {
      // Create multiple test images
      const images = await Promise.all([
        testImageModel.create(createTestImageData({ file_path: 'uploads/image1.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/image2.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/image3.jpg' }))
      ]);
      
      createdImageIds.push(...images.map(img => img.id));
      
      // Update some statuses
      await testImageModel.updateStatus(images[0].id, 'processed');
      await testImageModel.updateStatus(images[1].id, 'labeled');
      // Leave images[2] as 'new'
    });

    it('should find images by user ID', async () => {
      const images = await testImageModel.findByUserId(testUserId);
      
      expect(images.length).toBeGreaterThanOrEqual(3);
      images.forEach(img => {
        expect(img.user_id).toBe(testUserId);
      });
    });

    it('should filter images by status', async () => {
      const newImages = await testImageModel.findByUserId(testUserId, { status: 'new' });
      const processedImages = await testImageModel.findByUserId(testUserId, { status: 'processed' });
      const labeledImages = await testImageModel.findByUserId(testUserId, { status: 'labeled' });
      
      expect(newImages.length).toBeGreaterThanOrEqual(1);
      expect(processedImages.length).toBeGreaterThanOrEqual(1);
      expect(labeledImages.length).toBeGreaterThanOrEqual(1);
      
      newImages.forEach(img => expect(img.status).toBe('new'));
      processedImages.forEach(img => expect(img.status).toBe('processed'));
      labeledImages.forEach(img => expect(img.status).toBe('labeled'));
    });

    it('should apply pagination', async () => {
      const limitedImages = await testImageModel.findByUserId(testUserId, { limit: 2 });
      const offsetImages = await testImageModel.findByUserId(testUserId, { limit: 2, offset: 1 });
      
      expect(limitedImages.length).toBeLessThanOrEqual(2);
      expect(offsetImages.length).toBeLessThanOrEqual(2);
    });

    it('should find images by file path', async () => {
      const imageData = createTestImageData({ file_path: 'uploads/unique-path.jpg' });
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      const results = await testImageModel.findByFilePath('uploads/unique-path.jpg');
      
      expect(results).toHaveLength(1);
      expect(results[0].id).toBe(created.id);
    });

    it('should count images by user ID', async () => {
      const count = await testImageModel.countByUserId(testUserId);
      
      expect(count).toBeGreaterThanOrEqual(3);
    });

    it('should find most recent image', async () => {
      const mostRecent = await testImageModel.findMostRecent(testUserId);
      
      expect(mostRecent).not.toBeNull();
      expect(mostRecent!.user_id).toBe(testUserId);
    });

    it('should check if image exists by user and path', async () => {
      const imageData = createTestImageData({ file_path: 'uploads/check-exists.jpg' });
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      const exists = await testImageModel.existsByUserAndPath(testUserId, 'uploads/check-exists.jpg');
      const notExists = await testImageModel.existsByUserAndPath(testUserId, 'uploads/non-existent.jpg');
      
      expect(exists).toBe(true);
      expect(notExists).toBe(false);
    });
  });

  describe('Batch Operations', () => {
    it('should batch update status', async () => {
      // Create multiple images
      const images = await Promise.all([
        testImageModel.create(createTestImageData({ file_path: 'uploads/batch1.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/batch2.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/batch3.jpg' }))
      ]);
      createdImageIds.push(...images.map(img => img.id));
      
      const imageIds = images.map(img => img.id);
      const updateCount = await testImageModel.batchUpdateStatus(imageIds, 'processed');
      
      expect(updateCount).toBe(3);
      
      // Verify all were updated
      for (const id of imageIds) {
        const updated = await testImageModel.findById(id);
        expect(updated!.status).toBe('processed');
      }
    });

    it('should filter out invalid UUIDs in batch update', async () => {
      const validImage = await testImageModel.create(createTestImageData());
      createdImageIds.push(validImage.id);
      
      const mixedIds = [validImage.id, 'invalid-uuid', '', uuidv4()]; // Last one is valid but non-existent
      const updateCount = await testImageModel.batchUpdateStatus(mixedIds, 'labeled');
      
      expect(updateCount).toBe(1); // Only the valid, existing image should be updated
      
      const updated = await testImageModel.findById(validImage.id);
      expect(updated!.status).toBe('labeled');
    });

    it('should delete all images for a user', async () => {
      // Create multiple images
      const images = await Promise.all([
        testImageModel.create(createTestImageData({ file_path: 'uploads/delete1.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/delete2.jpg' }))
      ]);
      
      const deleteCount = await testImageModel.deleteAllByUserId(testUserId);
      expect(deleteCount).toBeGreaterThanOrEqual(2);
      
      // Verify deletion
      const remainingImages = await testImageModel.findByUserId(testUserId);
      expect(remainingImages).toHaveLength(0);
      
      // Clear createdImageIds since they're already deleted
      createdImageIds = [];
    });
  });

  describe('Statistics', () => {
    beforeEach(async () => {
      // Create images with different statuses and sizes
      const images = await Promise.all([
        testImageModel.create(createTestImageData({ 
          file_path: 'uploads/stat1.jpg',
          original_metadata: { size: 100000 }
        })),
        testImageModel.create(createTestImageData({ 
          file_path: 'uploads/stat2.jpg',
          original_metadata: { size: 200000 }
        })),
        testImageModel.create(createTestImageData({ 
          file_path: 'uploads/stat3.jpg',
          original_metadata: { size: 150000 }
        }))
      ]);
      
      createdImageIds.push(...images.map(img => img.id));
      
      // Update statuses
      await testImageModel.updateStatus(images[0].id, 'processed');
      await testImageModel.updateStatus(images[1].id, 'labeled');
      // Leave images[2] as 'new'
    });

    it('should calculate user image statistics', async () => {
      const stats = await testImageModel.getUserImageStats(testUserId);
      
      expect(stats.total).toBeGreaterThanOrEqual(3);
      expect(stats.byStatus.new).toBeGreaterThanOrEqual(1);
      expect(stats.byStatus.processed).toBeGreaterThanOrEqual(1);
      expect(stats.byStatus.labeled).toBeGreaterThanOrEqual(1);
      
      expect(stats.totalSize).toBeGreaterThan(0);
      expect(stats.averageSize).toBeGreaterThan(0);
    });

    it('should handle empty statistics', async () => {
      const emptyUser = await testUserModel.create({
        email: `empty-${Date.now()}@example.com`,
        password: 'password123'
      });
      createdUserIds.push(emptyUser.id);
      
      const stats = await testImageModel.getUserImageStats(emptyUser.id);
      
      expect(stats.total).toBe(0);
      expect(stats.byStatus).toEqual({});
      expect(stats.totalSize).toBe(0);
      expect(stats.averageSize).toBe(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid user_id in create', async () => {
      const imageData = createTestImageData({ user_id: 'invalid-uuid' });
      
      await expect(testImageModel.create(imageData)).rejects.toThrow('Invalid user_id format');
    });

    it('should handle missing required fields', async () => {
      await expect(testImageModel.create({ user_id: '', file_path: '' })).rejects.toThrow('user_id and file_path are required');
    });

    it('should handle invalid status in update', async () => {
      const imageData = createTestImageData();
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      await expect(testImageModel.updateStatus(created.id, 'invalid_status' as any)).rejects.toThrow('Invalid status value');
    });

    it('should handle foreign key constraint violation', async () => {
      const imageData = createTestImageData({
        user_id: uuidv4() // Non-existent user
      });
      
      await expect(testImageModel.create(imageData)).rejects.toThrow(/foreign key constraint/);
    });

    it('should return empty arrays for invalid UUIDs', async () => {
      expect(await testImageModel.findByUserId('invalid-uuid')).toEqual([]);
      expect(await testImageModel.findDependentGarments('invalid-uuid')).toEqual([]);
      expect(await testImageModel.findDependentPolygons('invalid-uuid')).toEqual([]);
    });

    it('should return default values for invalid UUIDs in stats', async () => {
      const stats = await testImageModel.getUserImageStats('invalid-uuid');
      
      expect(stats).toEqual({
        total: 0,
        byStatus: {},
        totalSize: 0,
        averageSize: 0
      });
    });
  });

  describe('Date Range Queries', () => {
    it('should find images by date range', async () => {
      const now = new Date();
      const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
      
      // Create an image (should be created "now")
      const image = await testImageModel.create(createTestImageData());
      createdImageIds.push(image.id);
      
      // Find images in range that includes now
      const imagesInRange = await testImageModel.findByDateRange(testUserId, yesterday, tomorrow);
      
      expect(imagesInRange.length).toBeGreaterThanOrEqual(1);
      expect(imagesInRange.some(img => img.id === image.id)).toBe(true);
      
      // Find images in range that doesn't include now
      const futureStart = new Date(now.getTime() + 24 * 60 * 60 * 1000);
      const futureEnd = new Date(now.getTime() + 48 * 60 * 60 * 1000);
      const imagesNotInRange = await testImageModel.findByDateRange(testUserId, futureStart, futureEnd);
      
      expect(imagesNotInRange).toHaveLength(0);
    });
  });

  describe('Dependencies', () => {
    it('should find dependent garments (when table exists)', async () => {
      const image = await testImageModel.create(createTestImageData());
      createdImageIds.push(image.id);
      
      // This will return empty array if garment_items table exists but no dependencies
      // or empty array if table doesn't exist (error handled gracefully)
      const dependents = await testImageModel.findDependentGarments(image.id);
      
      expect(Array.isArray(dependents)).toBe(true);
    });

    it('should find dependent polygons (when table exists)', async () => {
      const image = await testImageModel.create(createTestImageData());
      createdImageIds.push(image.id);
      
      // This will return empty array if polygons table exists but no dependencies
      // or empty array if table doesn't exist (error handled gracefully)
      const dependents = await testImageModel.findDependentPolygons(image.id);
      
      expect(Array.isArray(dependents)).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle large metadata', async () => {
      const largeMetadata = {
        description: 'a'.repeat(10000),
        tags: Array.from({ length: 100 }, (_, i) => `tag${i}`),
        nested: {
          deep: {
            data: Array.from({ length: 50 }, (_, i) => ({ id: i, value: `value${i}` }))
          }
        }
      };
      
      const imageData = createTestImageData({
        original_metadata: largeMetadata
      });
      
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      expect(created.original_metadata).toEqual(largeMetadata);
      
      // Verify retrieval
      const retrieved = await testImageModel.findById(created.id);
      expect(retrieved!.original_metadata).toEqual(largeMetadata);
    });

    it('should handle special characters in file paths and metadata', async () => {
      const specialMetadata = {
        title: '测试图片 🖼️ Tëst Imágé',
        description: 'Special chars: áéíóú ñ ü ç "quotes" \'apostrophes\'',
        emoji: '📸🎨🌟💫🔥⭐',
        unicode: 'Ωωπ∑∆√∞≈≠≤≥±∓'
      };
      
      const imageData = createTestImageData({
        file_path: 'uploads/spéciál-chärs-测试.jpg',
        original_metadata: specialMetadata
      });
      
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      expect(created.file_path).toBe(imageData.file_path);
      expect(created.original_metadata).toEqual(specialMetadata);
      
      // Verify retrieval
      const retrieved = await testImageModel.findById(created.id);
      expect(retrieved!.file_path).toBe(imageData.file_path);
      expect(retrieved!.original_metadata).toEqual(specialMetadata);
    });

    it('should handle empty metadata', async () => {
      const imageData = createTestImageData({
        original_metadata: {}
      });
      
      const created = await testImageModel.create(imageData);
      createdImageIds.push(created.id);
      
      expect(created.original_metadata).toEqual({});
    });

    it('should handle null and undefined values gracefully', async () => {
      // Test various null/undefined scenarios
      expect(await testImageModel.findById('')).toBeNull();
      expect(await testImageModel.findById(null as any)).toBeNull();
      expect(await testImageModel.findById(undefined as any)).toBeNull();
      
      expect(await testImageModel.findByUserId('')).toEqual([]);
      expect(await testImageModel.findByFilePath('')).toEqual([]);
      
      expect(await testImageModel.countByUserId('')).toBe(0);
      expect(await testImageModel.findMostRecent('')).toBeNull();
      
      expect(await testImageModel.existsByUserAndPath('', '')).toBe(false);
      expect(await testImageModel.existsByUserAndPath(testUserId, '')).toBe(false);
      expect(await testImageModel.existsByUserAndPath('', 'test.jpg')).toBe(false);
    });
  });

  describe('Concurrency', () => {
    it('should handle concurrent operations', async () => {
      const concurrentPromises = Array.from({ length: 10 }, (_, i) =>
        testImageModel.create(createTestImageData({
          file_path: `uploads/concurrent-${i}-${Date.now()}.jpg`
        }))
      );
      
      const results = await Promise.all(concurrentPromises);
      createdImageIds.push(...results.map(r => r.id));
      
      expect(results).toHaveLength(10);
      results.forEach(result => {
        expect(isUuid(result.id)).toBe(true);
        expect(result.user_id).toBe(testUserId);
      });
      
      // Verify all are in database
      const count = await testImageModel.countByUserId(testUserId);
      expect(count).toBeGreaterThanOrEqual(10);
    });

    it('should handle concurrent status updates', async () => {
      const image = await testImageModel.create(createTestImageData());
      createdImageIds.push(image.id);
      
      // Concurrent updates (non-deterministic final state)
      const concurrentUpdates = [
        testImageModel.updateStatus(image.id, 'processed'),
        testImageModel.updateStatus(image.id, 'labeled'),
        testImageModel.updateStatus(image.id, 'new'),
        testImageModel.updateMetadata(image.id, { concurrent: true, timestamp: Date.now() })
      ];
      
      const results = await Promise.allSettled(concurrentUpdates);
      
      // All operations should succeed
      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBe(4);
      
      // Final state should be consistent
      const final = await testImageModel.findById(image.id);
      expect(final).not.toBeNull();
      expect(['new', 'processed', 'labeled']).toContain(final!.status);
    });
  });
});