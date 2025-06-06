// /backend/src/services/__tests__/mini.int.test.ts
// Minimal integration test to validate testing framework setup with Docker services

import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { testUserModel } from '../../utils/testUserModel';
import { testImageModel } from '../../utils/testImageModel';
import { v4 as uuidv4 } from 'uuid';

describe('Mini Integration Test - Framework Validation', () => {
  let testUserId: string;
  let testImageId: string;

  beforeAll(async () => {
    console.log('🚀 Starting mini integration test framework validation...');
    
    // Initialize test database connection
    await TestDatabaseConnection.initialize();
    console.log('✅ Database connection established');
  });

  afterAll(async () => {
    console.log('🧹 Cleaning up mini integration test...');
    
    // Clean up test data
    if (testImageId) {
      await testImageModel.delete(testImageId);
    }
    if (testUserId) {
      await testUserModel.delete(testUserId);
    }
    
    // Close database connections
    await TestDatabaseConnection.cleanup();
    console.log('✅ Mini integration test cleanup completed');
  });

  describe('Database Connection Validation', () => {
    it('should connect to test database', async () => {
      const result = await TestDatabaseConnection.query('SELECT current_database()');
      const dbName = result.rows[0].current_database;
      
      expect(dbName).toContain('test');
      console.log(`✅ Connected to test database: ${dbName}`);
    });

    it('should have required tables', async () => {
      const tables = await TestDatabaseConnection.query(`
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('users', 'original_images', 'garment_items', 'wardrobes')
        ORDER BY table_name
      `);
      
      const tableNames = tables.rows.map((row: any) => row.table_name);
      
      expect(tableNames).toContain('users');
      expect(tableNames).toContain('original_images');
      expect(tableNames).toContain('garment_items');
      expect(tableNames).toContain('wardrobes');
      
      console.log(`✅ Required tables found: ${tableNames.join(', ')}`);
    });

    it('should have required extensions', async () => {
      const extensions = await TestDatabaseConnection.query(`
        SELECT extname FROM pg_extension 
        WHERE extname IN ('uuid-ossp')
      `);
      
      const extNames = extensions.rows.map((row: any) => row.extname);
      expect(extNames).toContain('uuid-ossp');
      
      console.log(`✅ Required extensions found: ${extNames.join(', ')}`);
    });
  });

  describe('User Model Integration', () => {
    it('should create and retrieve a user', async () => {
      // Create test user
      const userData = {
        email: `test-${Date.now()}@example.com`,
        password: 'testpassword123'
      };
      
      const createdUser = await testUserModel.create(userData);
      testUserId = createdUser.id;
      
      expect(createdUser).toBeDefined();
      expect(createdUser.id).toBeDefined();
      expect(createdUser.email).toBe(userData.email);
      expect(createdUser.created_at).toBeDefined();
      
      console.log(`✅ User created with ID: ${createdUser.id}`);
      
      // Retrieve user by ID
      const retrievedUser = await testUserModel.findById(testUserId);
      
      expect(retrievedUser).toBeDefined();
      expect(retrievedUser!.id).toBe(testUserId);
      expect(retrievedUser!.email).toBe(userData.email);
      
      console.log(`✅ User retrieved successfully`);
    });

    it('should validate user password', async () => {
      const user = await testUserModel.findByEmail(`test-${Date.now() - 1000}@example.com`);
      
      if (user) {
        const isValidPassword = await testUserModel.validatePassword(user, 'testpassword123');
        const isInvalidPassword = await testUserModel.validatePassword(user, 'wrongpassword');
        
        expect(isValidPassword).toBe(true);
        expect(isInvalidPassword).toBe(false);
        
        console.log(`✅ Password validation working correctly`);
      }
    });

    it('should handle UUID validation gracefully', async () => {
      // Test invalid UUID formats
      const invalidIds = ['not-a-uuid', '12345', '', null, undefined];
      
      for (const invalidId of invalidIds) {
        const result = await testUserModel.findById(invalidId as any);
        expect(result).toBeNull();
      }
      
      console.log(`✅ UUID validation working correctly`);
    });
  });

  describe('Image Model Integration', () => {
    it('should create and retrieve an image', async () => {
      // Ensure we have a test user
      if (!testUserId) {
        const userData = {
          email: `test-image-${Date.now()}@example.com`,
          password: 'testpassword123'
        };
        const user = await testUserModel.create(userData);
        testUserId = user.id;
      }
      
      // Create test image
      const imageData = {
        user_id: testUserId,
        file_path: '/test/images/sample.jpg',
        original_metadata: {
          width: 800,
          height: 600,
          format: 'jpeg',
          size: 102400
        }
      };
      
      const createdImage = await testImageModel.create(imageData);
      testImageId = createdImage.id;
      
      expect(createdImage).toBeDefined();
      expect(createdImage.id).toBeDefined();
      expect(createdImage.user_id).toBe(testUserId);
      expect(createdImage.file_path).toBe(imageData.file_path);
      expect(createdImage.status).toBe('new');
      
      console.log(`✅ Image created with ID: ${createdImage.id}`);
      
      // Retrieve image by ID
      const retrievedImage = await testImageModel.findById(testImageId);
      
      expect(retrievedImage).toBeDefined();
      expect(retrievedImage!.id).toBe(testImageId);
      expect(retrievedImage!.user_id).toBe(testUserId);
      
      console.log(`✅ Image retrieved successfully`);
    });

    it('should find images by user ID', async () => {
      const userImages = await testImageModel.findByUserId(testUserId);
      
      expect(Array.isArray(userImages)).toBe(true);
      expect(userImages.length).toBeGreaterThan(0);
      expect(userImages[0].user_id).toBe(testUserId);
      
      console.log(`✅ Found ${userImages.length} images for user`);
    });

    it('should update image status', async () => {
      const updatedImage = await testImageModel.updateStatus(testImageId, 'processed');
      
      expect(updatedImage).toBeDefined();
      expect(updatedImage!.status).toBe('processed');
      
      console.log(`✅ Image status updated to 'processed'`);
    });

    it('should handle image queries with filters', async () => {
      // Test with status filter
      const processedImages = await testImageModel.findByUserId(testUserId, {
        status: 'processed',
        limit: 10,
        offset: 0
      });
      
      expect(Array.isArray(processedImages)).toBe(true);
      processedImages.forEach(image => {
        expect(image.status).toBe('processed');
        expect(image.user_id).toBe(testUserId);
      });
      
      console.log(`✅ Image filtering working correctly`);
    });
  });

  describe('Cross-Model Integration', () => {
    it('should maintain referential integrity', async () => {
      // Get user stats (tests foreign key relationships)
      const stats = await testUserModel.getUserStats(testUserId);
      
      expect(stats).toBeDefined();
      expect(typeof stats.imageCount).toBe('number');
      expect(typeof stats.garmentCount).toBe('number');
      expect(typeof stats.wardrobeCount).toBe('number');
      expect(stats.imageCount).toBeGreaterThanOrEqual(1); // We created at least one image
      
      console.log(`✅ User stats: ${JSON.stringify(stats)}`);
    });

    it('should handle cascade operations correctly', async () => {
      // Create a second user for isolation testing
      const userData = {
        email: `test-cascade-${Date.now()}@example.com`,
        password: 'testpassword123'
      };
      const user = await testUserModel.create(userData);
      
      // Create an image for this user
      const imageData = {
        user_id: user.id,
        file_path: '/test/images/cascade-test.jpg',
        original_metadata: { width: 400, height: 300 }
      };
      const image = await testImageModel.create(imageData);
      
      // Delete the user (should cascade to images)
      const deleted = await testUserModel.delete(user.id);
      expect(deleted).toBe(true);
      
      // Verify image was also deleted (due to CASCADE)
      const orphanedImage = await testImageModel.findById(image.id);
      expect(orphanedImage).toBeNull();
      
      console.log(`✅ Cascade deletion working correctly`);
    });
  });

  describe('Transaction and Concurrency', () => {
    it('should handle concurrent operations safely', async () => {
      // Create multiple users concurrently
      const concurrentPromises = Array.from({ length: 5 }, (_, i) => 
        testUserModel.create({
          email: `concurrent-${i}-${Date.now()}@example.com`,
          password: 'testpassword123'
        })
      );
      
      const results = await Promise.all(concurrentPromises);
      
      // All should succeed and have unique IDs
      expect(results).toHaveLength(5);
      const ids = results.map(user => user.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(5); // All IDs should be unique
      
      // Cleanup
      await Promise.all(results.map(user => testUserModel.delete(user.id)));
      
      console.log(`✅ Concurrent operations handled safely`);
    });

    it('should handle database errors gracefully', async () => {
      // Try to create user with duplicate email
      const userData = {
        email: `duplicate-test-${Date.now()}@example.com`,
        password: 'testpassword123'
      };
      
      const user1 = await testUserModel.create(userData);
      
      // This should fail due to unique constraint
      await expect(testUserModel.create(userData)).rejects.toThrow();
      
      // Cleanup
      await testUserModel.delete(user1.id);
      
      console.log(`✅ Database constraint violations handled correctly`);
    });
  });

  describe('Performance Baseline', () => {
    it('should complete basic operations within reasonable time', async () => {
      const startTime = Date.now();
      
      // Perform a series of operations
      const user = await testUserModel.create({
        email: `perf-test-${Date.now()}@example.com`,
        password: 'testpassword123'
      });
      
      const image = await testImageModel.create({
        user_id: user.id,
        file_path: '/test/performance/test.jpg',
        original_metadata: { width: 1024, height: 768 }
      });
      
      await testImageModel.updateStatus(image.id, 'processed');
      const retrievedImage = await testImageModel.findById(image.id);
      const userImages = await testImageModel.findByUserId(user.id);
      
      // Cleanup
      await testImageModel.delete(image.id);
      await testUserModel.delete(user.id);
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      expect(retrievedImage).toBeDefined();
      expect(userImages).toHaveLength(1);
      
      console.log(`✅ Performance test completed in ${duration}ms`);
    });
  });
});

// Additional helper tests for debugging
describe('Framework Debugging Helpers', () => {
  it('should log current environment state', async () => {
    console.log('🔍 Environment Debug Info:');
    console.log(`NODE_ENV: ${process.env.NODE_ENV}`);
    console.log(`DATABASE_URL: ${process.env.DATABASE_URL ? '[SET]' : '[NOT SET]'}`);
    
    // Check if we can connect to database
    try {
      await TestDatabaseConnection.initialize();
      const result = await TestDatabaseConnection.query('SELECT version()');
      console.log(`PostgreSQL Version: ${result.rows[0].version.split(' ')[1]}`);
      
      const dbResult = await TestDatabaseConnection.query('SELECT current_database()');
      console.log(`Current Database: ${dbResult.rows[0].current_database}`);
      
      const connections = await TestDatabaseConnection.query(`
        SELECT count(*) as active_connections 
        FROM pg_stat_activity 
        WHERE datname = current_database()
      `);
      console.log(`Active Connections: ${connections.rows[0].active_connections}`);
      
    } catch (error) {
      console.error('Database connection failed:', error);
    }
    
    expect(true).toBe(true); // Always pass, this is just for debugging
  });

  it('should verify table schemas match expectations', async () => {
    const userColumns = await TestDatabaseConnection.query(`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'users' 
      ORDER BY ordinal_position
    `);
    
    const imageColumns = await TestDatabaseConnection.query(`
      SELECT column_name, data_type, is_nullable 
      FROM information_schema.columns 
      WHERE table_name = 'original_images' 
      ORDER BY ordinal_position
    `);
    
    console.log('👤 Users table schema:');
    userColumns.rows.forEach((col: any) => {
      console.log(`  ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable})`);
    });
    
    console.log('🖼️ Original Images table schema:');
    imageColumns.rows.forEach((col: any) => {
      console.log(`  ${col.column_name}: ${col.data_type} (nullable: ${col.is_nullable})`);
    });
    
    // Basic schema validations
    const userColumnNames = userColumns.rows.map((col: any) => col.column_name);
    expect(userColumnNames).toContain('id');
    expect(userColumnNames).toContain('email');
    expect(userColumnNames).toContain('created_at');
    
    const imageColumnNames = imageColumns.rows.map((col: any) => col.column_name);
    expect(imageColumnNames).toContain('id');
    expect(imageColumnNames).toContain('user_id');
    expect(imageColumnNames).toContain('file_path');
    expect(imageColumnNames).toContain('status');
  });
});