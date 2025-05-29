// tests/integration/models/imageModel.integration.test.ts
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { testImageModel } from '../../utils/testImageModel';
import { testUserModel } from '../../utils/testUserModel';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

describe('ImageModel Integration Tests', () => {
  let testUserId: string;
  let testUser: any;
  let createdImageIds: string[] = [];
  let createdUserIds: string[] = [];

  beforeAll(async () => {
    console.log('🔧 Setting up integration test environment...');
    
    // Initialize test database
    await TestDatabaseConnection.initialize();
    await setupTestDatabase();
    
    console.log('✅ Integration test environment ready');
  }, 30000);

  afterAll(async () => {
    console.log('🧹 Cleaning up integration test environment...');
    
    // Clean up all test data
    await cleanupAllTestData();
    await TestDatabaseConnection.cleanup();
    await teardownTestDatabase();
    
    console.log('✅ Integration test cleanup complete');
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
        createdImageIds.map(id => TestDatabaseConnection.query('DELETE FROM original_images WHERE id = $1', [id]))
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

  describe('Database Connection Integration', () => {
    it('should connect to PostgreSQL test database', async () => {
      const result = await TestDatabaseConnection.query('SELECT current_database(), version()');
      
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].current_database).toContain('test');
      expect(result.rows[0].version).toContain('PostgreSQL');
    });

    it('should have required tables and schema', async () => {
      const tables = await TestDatabaseConnection.query(`
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('users', 'original_images', 'garment_items', 'user_oauth_providers')
        ORDER BY table_name
      `);
      
    interface TableRow {
        table_name: string;
    }

    const tableNames: string[] = tables.rows.map((row: TableRow) => row.table_name);
      expect(tableNames).toContain('users');
      expect(tableNames).toContain('original_images');
      expect(tableNames).toContain('garment_items');
      expect(tableNames).toContain('user_oauth_providers');
    });

    it('should have required database extensions', async () => {
      const extensions = await TestDatabaseConnection.query(`
        SELECT extname FROM pg_extension 
        WHERE extname IN ('uuid-ossp', 'btree_gist')
      `);
      
    interface ExtensionRow {
      extname: string;
    }

    const extNames: string[] = extensions.rows.map((row: ExtensionRow) => row.extname);
      expect(extNames).toContain('uuid-ossp');
    });
  });

  describe('Image Creation Integration', () => {
    it('should create image with all database constraints', async () => {
      const imageData = createTestImageData();
      
      const result = await testImageModel.create(imageData);
      createdImageIds.push(result.id);
      
      // Verify in database
      const dbResult = await TestDatabaseConnection.query('SELECT * FROM original_images WHERE id = $1', [result.id]);
      expect(dbResult.rows).toHaveLength(1);
      
      const dbImage = dbResult.rows[0];
      expect(dbImage.user_id).toBe(testUserId);
      expect(dbImage.file_path).toBe(imageData.file_path);
      expect(dbImage.status).toBe('new');
      expect(dbImage.original_metadata).toEqual(imageData.original_metadata);
      expect(dbImage.upload_date).toBeInstanceOf(Date);
      expect(isUuid(dbImage.id)).toBe(true);
    });

    it('should enforce foreign key constraint to users table', async () => {
      const imageData = createTestImageData({
        user_id: uuidv4() // Non-existent user
      });
      
      await expect(testImageModel.create(imageData)).rejects.toThrow(/foreign key constraint/);
    });

    it('should handle JSON metadata storage correctly', async () => {
      const complexMetadata = {
        dimensions: { width: 1920, height: 1080 },
        camera: {
          make: 'Canon',
          model: 'EOS 5D',
          settings: {
            iso: 400,
            aperture: 'f/2.8',
            shutter: '1/125'
          }
        },
        tags: ['test', 'integration', 'photo'],
        gps: {
          latitude: 37.7749,
          longitude: -122.4194
        },
        unicode: 'Test with émojis 📸 and ñáméś',
        specialChars: 'Test with "quotes" and \'apostrophes\' and \\ backslashes'
      };
      
      const imageData = createTestImageData({
        original_metadata: complexMetadata
      });
      
      const result = await testImageModel.create(imageData);
      createdImageIds.push(result.id);
      
      // Verify complex JSON is stored correctly
      const retrieved = await testImageModel.findById(result.id);
      expect(retrieved!.original_metadata).toEqual(complexMetadata);
      
      // Verify direct database query also works
      const dbResult = await TestDatabaseConnection.query('SELECT original_metadata FROM original_images WHERE id = $1', [result.id]);
      expect(dbResult.rows[0].original_metadata).toEqual(complexMetadata);
    });

    it('should handle concurrent image creation', async () => {
      const promises = Array.from({ length: 5 }, (_, i) =>
        testImageModel.create(createTestImageData({
          file_path: `uploads/concurrent-${i}-${Date.now()}.jpg`
        }))
      );
      
      const results = await Promise.all(promises);
      createdImageIds.push(...results.map(r => r.id));
      
      // Verify all images were created
      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(isUuid(result.id)).toBe(true);
        expect(result.user_id).toBe(testUserId);
      });
      
      // Verify in database
      const dbCount = await TestDatabaseConnection.query('SELECT COUNT(*) FROM original_images WHERE user_id = $1', [testUserId]);
      expect(parseInt(dbCount.rows[0].count)).toBeGreaterThanOrEqual(5);
    });
  });

  describe('Image Retrieval Integration', () => {
    let testImages: any[] = [];

    beforeEach(async () => {
      // Create multiple test images with different statuses
      const imagePromises = [
        testImageModel.create(createTestImageData({ file_path: 'uploads/new1.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/new2.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/processed1.jpg' }))
      ];
      
      testImages = await Promise.all(imagePromises);
      createdImageIds.push(...testImages.map(img => img.id));
      
      // Update one to processed status
      await testImageModel.updateStatus(testImages[2].id, 'processed');
    });

    it('should find image by ID with proper relationships', async () => {
      const image = testImages[0];
      const result = await testImageModel.findById(image.id);
      
      expect(result).not.toBeNull();
      expect(result!.id).toBe(image.id);
      expect(result!.user_id).toBe(testUserId);
      
      // Verify the user relationship exists
      const userCheck = await TestDatabaseConnection.query('SELECT id FROM users WHERE id = $1', [result!.user_id]);
      expect(userCheck.rows).toHaveLength(1);
    });

    it('should find images by user ID with filtering and pagination', async () => {
      // Test without filters
      const allImages = await testImageModel.findByUserId(testUserId);
      expect(allImages.length).toBeGreaterThanOrEqual(3);
      
      // Test with status filter
      const newImages = await testImageModel.findByUserId(testUserId, { status: 'new' });
      expect(newImages.length).toBeGreaterThanOrEqual(2);
      newImages.forEach(img => expect(img.status).toBe('new'));
      
      const processedImages = await testImageModel.findByUserId(testUserId, { status: 'processed' });
      expect(processedImages.length).toBeGreaterThanOrEqual(1);
      processedImages.forEach(img => expect(img.status).toBe('processed'));
      
      // Test with pagination
      const limitedImages = await testImageModel.findByUserId(testUserId, { limit: 2 });
      expect(limitedImages.length).toBeLessThanOrEqual(2);
      
      const offsetImages = await testImageModel.findByUserId(testUserId, { limit: 2, offset: 1 });
      expect(offsetImages.length).toBeLessThanOrEqual(2);
      
      // Verify ordering (should be by upload_date DESC)
      if (allImages.length > 1) {
        for (let i = 0; i < allImages.length - 1; i++) {
          expect(new Date(allImages[i].upload_date).getTime())
            .toBeGreaterThanOrEqual(new Date(allImages[i + 1].upload_date).getTime());
        }
      }
    });

    it('should find images by file path', async () => {
      const targetPath = testImages[0].file_path;
      const results = await testImageModel.findByFilePath(targetPath);
      
      expect(results).toHaveLength(1);
      expect(results[0].file_path).toBe(targetPath);
      expect(results[0].id).toBe(testImages[0].id);
    });
  });

  describe('Image Updates Integration', () => {
    let testImage: any;

    beforeEach(async () => {
      testImage = await testImageModel.create(createTestImageData());
      createdImageIds.push(testImage.id);
    });

    it('should update image status with database constraints', async () => {
      // Test valid status updates
      const validStatuses: Array<'new' | 'processed' | 'labeled'> = ['processed', 'labeled', 'new'];
      
      for (const status of validStatuses) {
        const result = await testImageModel.updateStatus(testImage.id, status);
        expect(result).not.toBeNull();
        expect(result!.status).toBe(status);
        
        // Verify in database
        const dbResult = await TestDatabaseConnection.query('SELECT status FROM original_images WHERE id = $1', [testImage.id]);
        expect(dbResult.rows[0].status).toBe(status);
      }
    });

    it('should reject invalid status values', async () => {
      // This should be caught by the database constraint
      await expect(
        TestDatabaseConnection.query('UPDATE original_images SET status = $1 WHERE id = $2', ['invalid_status', testImage.id])
      ).rejects.toThrow(/violates check constraint/);
    });

    it('should update metadata preserving JSON structure', async () => {
      const newMetadata = {
        width: 1200,
        height: 900,
        processed: true,
        processingDate: new Date().toISOString(),
        filters: ['brightness', 'contrast'],
        quality: 0.85
      };
      
      const result = await testImageModel.updateMetadata(testImage.id, newMetadata);
      expect(result).not.toBeNull();
      expect(result!.original_metadata).toEqual(newMetadata);
      
      // Verify database storage
      const dbResult = await TestDatabaseConnection.query('SELECT original_metadata FROM original_images WHERE id = $1', [testImage.id]);
      expect(dbResult.rows[0].original_metadata).toEqual(newMetadata);
    });

    it('should handle batch status updates efficiently', async () => {
      // Create multiple images
      const batchImages = await Promise.all([
        testImageModel.create(createTestImageData({ file_path: 'uploads/batch1.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/batch2.jpg' })),
        testImageModel.create(createTestImageData({ file_path: 'uploads/batch3.jpg' }))
      ]);
      createdImageIds.push(...batchImages.map(img => img.id));
      
      const imageIds = batchImages.map(img => img.id);
      const updateCount = await testImageModel.batchUpdateStatus(imageIds, 'processed');
      
      expect(updateCount).toBe(3);
      
      // Verify all were updated
      const results = await TestDatabaseConnection.query(
        'SELECT id, status FROM original_images WHERE id = ANY($1)',
        [imageIds]
      );
      
      expect(results.rows).toHaveLength(3);
    results.rows.forEach((row: { id: string; status: string }) => {
      expect(row.status).toBe('processed');
    });
    });
  });

  describe('Performance and Scalability Integration', () => {
    it('should handle bulk operations efficiently', async () => {
      const start = Date.now();
      
      // Create 20 images (reduced from 50 for faster test)
      const promises = Array.from({ length: 20 }, (_, i) =>
        testImageModel.create(createTestImageData({
          file_path: `uploads/bulk-${i}-${Date.now()}.jpg`
        }))
      );
      
      const results = await Promise.all(promises);
      createdImageIds.push(...results.map(r => r.id));
      
      const duration = Date.now() - start;
      console.log(`Created 20 images in ${duration}ms`);
      
      expect(results).toHaveLength(20);
      expect(duration).toBeLessThan(5000); // Should take less than 5 seconds
      
      // Verify all are in database
      const count = await TestDatabaseConnection.query('SELECT COUNT(*) FROM original_images WHERE user_id = $1', [testUserId]);
      expect(parseInt(count.rows[0].count)).toBeGreaterThanOrEqual(20);
    });

    it('should handle complex queries efficiently', async () => {
      // Create images with various statuses and dates
      const images = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          testImageModel.create(createTestImageData({
            file_path: `uploads/query-test-${i}.jpg`,
            original_metadata: { size: (i + 1) * 100000, index: i }
          }))
        )
      );
      createdImageIds.push(...images.map(img => img.id));
      
      // Update some statuses
      for (let i = 0; i < 5; i++) {
        await testImageModel.updateStatus(images[i].id, i % 2 === 0 ? 'processed' : 'labeled');
      }
      
      const start = Date.now();
      
      // Complex query with joins and aggregations
      const complexResult = await TestDatabaseConnection.query(`
        SELECT 
          u.email,
          COUNT(oi.id) as image_count,
          AVG((oi.original_metadata->>'size')::bigint) as avg_size,
          array_agg(DISTINCT oi.status) as statuses
        FROM users u
        LEFT JOIN original_images oi ON u.id = oi.user_id
        WHERE u.id = $1
        GROUP BY u.id, u.email
      `, [testUserId]);
      
      const duration = Date.now() - start;
      console.log(`Complex query executed in ${duration}ms`);
      
      expect(complexResult.rows).toHaveLength(1);
      expect(parseInt(complexResult.rows[0].image_count)).toBeGreaterThanOrEqual(10);
      expect(duration).toBeLessThan(500); // Should be fast with proper indexing
    });
  });

  describe('Data Integrity and Consistency Integration', () => {
    it('should maintain referential integrity on user deletion', async () => {
      // Create a separate user for this test
      const tempUser = await testUserModel.create({
        email: `temp-${Date.now()}@example.com`,
        password: 'password123'
      });
      
      // Create image for temp user
      const tempImage = await testImageModel.create({
        user_id: tempUser.id,
        file_path: 'uploads/temp-image.jpg',
        original_metadata: { temp: true }
      });
      
      // Delete user should cascade to images
      await testUserModel.delete(tempUser.id);
      
      // Verify image was also deleted due to CASCADE
      const imageCheck = await testImageModel.findById(tempImage.id);
      expect(imageCheck).toBeNull();
      
      const dbCheck = await TestDatabaseConnection.query('SELECT * FROM original_images WHERE id = $1', [tempImage.id]);
      expect(dbCheck.rows).toHaveLength(0);
    });

    it('should maintain data consistency across concurrent operations', async () => {
      const image = await testImageModel.create(createTestImageData());
      createdImageIds.push(image.id);
      
      // Concurrent updates
      const concurrentPromises = [
        testImageModel.updateStatus(image.id, 'processed'),
        testImageModel.updateMetadata(image.id, { concurrent: 1, timestamp: Date.now() }),
        testImageModel.updateStatus(image.id, 'labeled'),
        testImageModel.updateMetadata(image.id, { concurrent: 2, timestamp: Date.now() })
      ];
      
      const results = await Promise.allSettled(concurrentPromises);
      
      // All operations should succeed (though final state is non-deterministic)
      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBe(4);
      
      // Verify final state is consistent
      const finalState = await testImageModel.findById(image.id);
      expect(finalState).not.toBeNull();
      expect(['processed', 'labeled']).toContain(finalState!.status);
    });
  });
});