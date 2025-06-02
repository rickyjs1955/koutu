// tests/integration/models/polygonModel.mini.int.test.ts

import { setupTestDatabase, teardownTestDatabase, testQuery } from '../../utils/testSetup';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { testImageModel } from '../../utils/testImageModel';
import { testUserModel } from '../../utils/testUserModel';
import { 
  createMockPolygon,
  createValidPolygonPoints,
  createInvalidPolygonPoints,
  createPolygonMetadataVariations
} from '../__mocks__/polygons.mock';
import {
  calculatePolygonArea,
  calculatePolygonPerimeter,
  hasSelfintersection,
  polygonAssertions
} from '../__helpers__/polygons.helper';
import { v4 as uuidv4 } from 'uuid';

// Mock the database connection BEFORE importing polygonModel
jest.mock('../../models/db', () => ({
  query: jest.fn()
}));

// Import the actual polygonModel AFTER mocking
import { polygonModel } from '../../models/polygonModel';

// Get the mocked query function
const { query: mockDbQuery } = require('../../models/db');

describe('PolygonModel - Mini Integration Tests', () => {
  let testUserId: string;
  let testImageId: string;
  let testUser: any;
  let testImage: any;
  let createdPolygonIds: string[] = [];
  let createdUserIds: string[] = [];
  let createdImageIds: string[] = [];

  beforeAll(async () => {
    console.log('🔧 Setting up polygon integration test environment...');
    
    try {
      // Initialize test database
      await TestDatabaseConnection.initialize();
      await setupTestDatabase();
      
      // Set up the mock to forward calls to testQuery
      mockDbQuery.mockImplementation((text: string, params?: any[]) => {
        return testQuery(text, params);
      });
      
      console.log('✅ Polygon integration test environment ready');
    } catch (error) {
      console.error('❌ Failed to setup test environment:', error);
      throw error;
    }
  }, 30000);

  afterAll(async () => {
    console.log('🧹 Cleaning up polygon integration test environment...');
    
    try {
      // Clean up all test data
      await cleanupAllTestData();
      await TestDatabaseConnection.cleanup();
      await teardownTestDatabase();
      
      console.log('✅ Polygon integration test cleanup complete');
    } catch (error) {
      console.warn('⚠️ Cleanup warning:', error);
    }
  }, 15000);

  beforeEach(async () => {
    try {
      // Create a test user for each test
      testUser = await testUserModel.create({
        email: `polygon-test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
        password: 'testpassword123'
      });
      testUserId = testUser.id;
      createdUserIds.push(testUserId);

      // Create test image that polygons can reference
      testImage = await testImageModel.create({
        user_id: testUserId,
        file_path: `test-images/polygon-integration-test-${Date.now()}.jpg`,
        original_metadata: {
          width: 800,
          height: 600,
          format: 'jpeg',
          size: 204800
        }
      });
      testImageId = testImage.id;
      createdImageIds.push(testImageId);

      // Reset tracking array
      createdPolygonIds = [];
    } catch (error) {
      console.error('❌ Failed to setup test data:', error);
      throw error;
    }
  });

  afterEach(async () => {
    // Clean up polygons created in this test
    if (createdPolygonIds.length > 0) {
      await Promise.allSettled(
        createdPolygonIds.map(id => 
          testQuery('DELETE FROM polygons WHERE id = $1', [id]).catch(() => {})
        )
      );
      createdPolygonIds = [];
    }
  });

  // Helper function for comprehensive cleanup
  const cleanupAllTestData = async () => {
    try {
      // Delete in dependency order (polygons first, then images, then users)
      if (createdPolygonIds.length > 0) {
        await testQuery('DELETE FROM polygons WHERE id = ANY($1)', [createdPolygonIds]).catch(() => {});
      }
      if (createdImageIds.length > 0) {
        await testQuery('DELETE FROM original_images WHERE id = ANY($1)', [createdImageIds]).catch(() => {});
      }
      if (createdUserIds.length > 0) {
        await testQuery('DELETE FROM users WHERE id = ANY($1)', [createdUserIds]).catch(() => {});
      }
    } catch (error) {
      console.warn('Cleanup error (may be expected):', error);
    }
  };

  // ==================== DATABASE SETUP VALIDATION ====================

  describe('🔌 Database Connection Verification', () => {
    test('should connect to PostgreSQL test database', async () => {
      const result = await testQuery('SELECT current_database(), version()');
      const dbName = result.rows[0].current_database;
      
      expect(dbName).toContain('test');
      expect(result.rows[0].version).toContain('PostgreSQL');
      console.log(`✅ Connected to test database: ${dbName}`);
    });

    test('should have all required tables and extensions', async () => {
      // Check for required tables
      const tablesResult = await testQuery(`
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name IN ('users', 'original_images')
        ORDER BY table_name
      `);
      
      interface TableRow {
        table_name: string;
      }

      const tables: string[] = tablesResult.rows.map((row: TableRow) => row.table_name);
      expect(tables).toContain('users');
      expect(tables).toContain('original_images');

      // Check for uuid extension
      const extensionsResult = await testQuery(`
        SELECT extname FROM pg_extension WHERE extname = 'uuid-ossp'
      `);
      expect(extensionsResult.rows).toHaveLength(1);
    });

    test('should create polygons table if not exists', async () => {
      // Create polygons table for testing
      await testQuery(`
        CREATE TABLE IF NOT EXISTS polygons (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          original_image_id UUID NOT NULL REFERENCES original_images(id) ON DELETE CASCADE,
          points JSONB NOT NULL,
          label TEXT,
          metadata JSONB DEFAULT '{}',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      // Verify table was created
      const tableResult = await testQuery(`
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'polygons'
      `);
      expect(tableResult.rows).toHaveLength(1);
    });
  });

  // ==================== BASIC CRUD OPERATIONS ====================

  describe('📝 Basic CRUD Operations', () => {
    test('should create polygon with valid data', async () => {
      // Arrange
      const polygonData = {
        user_id: testUserId,
        original_image_id: testImageId,
        points: createValidPolygonPoints.triangle(),
        label: 'integration_test_triangle',
        metadata: createPolygonMetadataVariations.basic
      };

      // Act
      const result = await polygonModel.create(polygonData);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.user_id).toBe(testUserId);
      expect(result.original_image_id).toBe(testImageId);
      expect(result.label).toBe('integration_test_triangle');
      expect(Array.isArray(result.points)).toBe(true);
      expect(result.points).toHaveLength(3);
      
      // Validate geometry
      polygonAssertions.hasValidGeometry(result);
      polygonAssertions.hasValidMetadata(result);

      // Track for cleanup
      createdPolygonIds.push(result.id);

      // Verify in database - check the raw data
      const dbResult = await testQuery(
        'SELECT * FROM polygons WHERE id = $1',
        [result.id]
      );
      expect(dbResult.rows).toHaveLength(1);
      expect(dbResult.rows[0].user_id).toBe(testUserId);
      
      // Verify points and metadata are stored as JSON in database
      expect(typeof dbResult.rows[0].points).toBe('object'); // JSONB in PostgreSQL
      expect(typeof dbResult.rows[0].metadata).toBe('object'); // JSONB in PostgreSQL
    });

    test('should find polygon by ID', async () => {
      // Arrange - Create a polygon first
      const polygonData = {
        user_id: testUserId,
        original_image_id: testImageId,
        points: createValidPolygonPoints.square(),
        label: 'find_test_square',
        metadata: createPolygonMetadataVariations.detailed
      };
      
      const createdPolygon = await polygonModel.create(polygonData);
      createdPolygonIds.push(createdPolygon.id);

      // Act
      const foundPolygon = await polygonModel.findById(createdPolygon.id);

      // Assert
      expect(foundPolygon).toBeDefined();
      expect(foundPolygon?.id).toBe(createdPolygon.id);
      expect(foundPolygon?.user_id).toBe(testUserId);
      expect(foundPolygon?.original_image_id).toBe(testImageId);
      expect(foundPolygon?.label).toBe('find_test_square');
      expect(foundPolygon?.points).toEqual(polygonData.points);
      expect(foundPolygon?.metadata).toEqual(polygonData.metadata);

      polygonAssertions.hasValidGeometry(foundPolygon!);
    });

    test('should return null for non-existent polygon', async () => {
      const nonExistentId = uuidv4();
      const result = await polygonModel.findById(nonExistentId);
      expect(result).toBeNull();
    });

    test('should update polygon successfully', async () => {
      // Arrange - Create polygon first
      const originalData = {
        user_id: testUserId,
        original_image_id: testImageId,
        points: createValidPolygonPoints.triangle(),
        label: 'original_label',
        metadata: createPolygonMetadataVariations.basic
      };
      
      const createdPolygon = await polygonModel.create(originalData);
      createdPolygonIds.push(createdPolygon.id);

      const updateData = {
        label: 'updated_label',
        points: createValidPolygonPoints.square(),
        metadata: createPolygonMetadataVariations.detailed
      };

      // Act
      const updatedPolygon = await polygonModel.update(createdPolygon.id, updateData);

      // Assert
      expect(updatedPolygon).toBeDefined();
      expect(updatedPolygon?.id).toBe(createdPolygon.id);
      expect(updatedPolygon?.label).toBe('updated_label');
      expect(updatedPolygon?.points).toEqual(updateData.points);
      expect(updatedPolygon?.metadata).toEqual(updateData.metadata);

      polygonAssertions.hasValidGeometry(updatedPolygon!);

      // Verify in database
      const dbResult = await testQuery(
        'SELECT * FROM polygons WHERE id = $1',
        [createdPolygon.id]
      );
      expect(dbResult.rows[0].label).toBe('updated_label');
    });

    test('should delete polygon successfully', async () => {
      // Arrange - Create polygon first
      const polygonData = {
        user_id: testUserId,
        original_image_id: testImageId,
        points: createValidPolygonPoints.triangle(),
        label: 'delete_test_polygon',
        metadata: {}
      };
      
      const createdPolygon = await polygonModel.create(polygonData);

      // Act
      const deleteResult = await polygonModel.delete(createdPolygon.id);

      // Assert
      expect(deleteResult).toBe(true);

      // Verify polygon is gone from database
      const dbResult = await testQuery(
        'SELECT * FROM polygons WHERE id = $1',
        [createdPolygon.id]
      );
      expect(dbResult.rows).toHaveLength(0);

      // Verify findById returns null
      const foundPolygon = await polygonModel.findById(createdPolygon.id);
      expect(foundPolygon).toBeNull();
    });
  });

  // ==================== ERROR HANDLING TESTS ====================

  describe('🚫 Error Handling', () => {
    test('should handle invalid UUID formats gracefully', async () => {
      // Test with valid but non-existent UUID
      const validButNonExistentId = uuidv4();
      const result = await polygonModel.findById(validButNonExistentId);
      expect(result).toBeNull();
      
      // Test with invalid UUID format
      try {
        await polygonModel.findById('not-a-uuid');
        // If we reach here, the model handled it gracefully
        expect(true).toBe(true);
      } catch (error) {
        // If the model doesn't handle it, we expect a database error
        expect(error).toBeDefined();
        expect((error as Error).message).toMatch(/invalid input syntax for type uuid|Invalid UUID/);
      }
    });

    test('should enforce foreign key constraint with users table', async () => {
      // Arrange
      const invalidUserId = uuidv4();
      const polygonData = {
        user_id: invalidUserId,
        original_image_id: testImageId,
        points: createValidPolygonPoints.triangle(),
        label: 'fk_test_polygon'
      };

      // Act & Assert
      await expect(polygonModel.create(polygonData)).rejects.toThrow();
    });

    test('should enforce foreign key constraint with original_images table', async () => {
      // Arrange
      const invalidImageId = uuidv4();
      const polygonData = {
        user_id: testUserId,
        original_image_id: invalidImageId,
        points: createValidPolygonPoints.triangle(),
        label: 'fk_test_polygon'
      };

      // Act & Assert
      await expect(polygonModel.create(polygonData)).rejects.toThrow();
    });
  });

  // ==================== INTEGRATION WORKFLOW TESTS ====================

  describe('🔄 Integration Workflow', () => {
    test('should support complete polygon lifecycle', async () => {
      // 1. Create polygon
      const createData = {
        user_id: testUserId,
        original_image_id: testImageId,
        points: createValidPolygonPoints.triangle(),
        label: 'lifecycle_test',
        metadata: createPolygonMetadataVariations.basic
      };

      const created = await polygonModel.create(createData);
      createdPolygonIds.push(created.id);
      expect(created.id).toBeDefined();

      // 2. Read polygon
      const found = await polygonModel.findById(created.id);
      expect(found).toBeDefined();
      expect(found?.label).toBe('lifecycle_test');

      // 3. Update polygon
      const updateData = {
        label: 'lifecycle_updated',
        points: createValidPolygonPoints.square(),
        metadata: createPolygonMetadataVariations.detailed
      };

      const updated = await polygonModel.update(created.id, updateData);
      expect(updated?.label).toBe('lifecycle_updated');
      expect(updated?.points).toEqual(updateData.points);

      // 4. Verify update persistence
      const foundAfterUpdate = await polygonModel.findById(created.id);
      expect(foundAfterUpdate?.label).toBe('lifecycle_updated');

      // 5. Delete polygon
      const deleted = await polygonModel.delete(created.id);
      expect(deleted).toBe(true);

      // 6. Verify deletion
      const foundAfterDelete = await polygonModel.findById(created.id);
      expect(foundAfterDelete).toBeNull();

      // Remove from tracking since it's deleted
      createdPolygonIds = createdPolygonIds.filter(id => id !== created.id);
    });

    test('should find polygons by image ID', async () => {
      // Arrange - Create multiple polygons
      const polygonData = [
        {
          user_id: testUserId,
          original_image_id: testImageId,
          points: createValidPolygonPoints.triangle(),
          label: 'image_polygon_1',
          metadata: {}
        },
        {
          user_id: testUserId,
          original_image_id: testImageId,
          points: createValidPolygonPoints.square(),
          label: 'image_polygon_2',
          metadata: {}
        }
      ];

      for (const data of polygonData) {
        const created = await polygonModel.create(data);
        createdPolygonIds.push(created.id);
      }

      // Act
      const foundPolygons = await polygonModel.findByImageId(testImageId);

      // Assert
      expect(foundPolygons).toHaveLength(2);
      foundPolygons.forEach(polygon => {
        expect(polygon.original_image_id).toBe(testImageId);
        expect(polygon.user_id).toBe(testUserId);
        polygonAssertions.hasValidGeometry(polygon);
      });

      // Verify order (should be by created_at ASC)
      const labels = foundPolygons.map(p => p.label);
      expect(labels).toEqual(['image_polygon_1', 'image_polygon_2']);
    });
  });

  // Add these test cases to your existing mini.int.test.ts

  // ==================== EDGE CASES ====================

  describe('🔍 Edge Cases', () => {
    test('should handle empty and null metadata gracefully', async () => {
      const testCases = [
        { metadata: {}, label: 'empty_metadata' },
        { metadata: undefined, label: 'undefined_metadata' },
        { metadata: null, label: 'null_metadata' }
      ];

      for (const testCase of testCases) {
        const polygonData = {
          user_id: testUserId,
          original_image_id: testImageId,
          points: createValidPolygonPoints.triangle(),
          label: testCase.label,
          metadata: testCase.metadata
        };

        const result = await polygonModel.create(polygonData);
        createdPolygonIds.push(result.id);

        expect(result).toBeDefined();
        expect(result.metadata).toBeDefined();
        expect(typeof result.metadata).toBe('object');
      }
    });

    test('should handle large coordinate values', async () => {
      const largePoints = [
        { x: 999999.999999, y: 888888.888888 },
        { x: 777777.777777, y: 666666.666666 },
        { x: 555555.555555, y: 444444.444444 }
      ];

      const polygonData = {
        user_id: testUserId,
        original_image_id: testImageId,
        points: largePoints,
        label: 'large_coordinates',
        metadata: {}
      };

      const result = await polygonModel.create(polygonData);
      createdPolygonIds.push(result.id);

      expect(result.points).toHaveLength(3);
      result.points.forEach((point, index) => {
        expect(point.x).toBeCloseTo(largePoints[index].x, 5);
        expect(point.y).toBeCloseTo(largePoints[index].y, 5);
      });
    });

    test('should handle complex nested metadata', async () => {
      const complexMetadata = {
        category: 'clothing',
        attributes: {
          color: { primary: 'blue', secondary: ['white', 'black'] },
          material: { fabric: 'cotton', blend: 0.95 },
          size: { xs: false, s: true, m: false, l: false, xl: false }
        },
        ai_analysis: {
          confidence: 0.892,
          model_version: '2.1.0',
          processing_time_ms: 1250,
          features_detected: ['collar', 'sleeves', 'buttons']
        },
        user_tags: ['favorite', 'work_appropriate', 'summer'],
        created_by_tool: 'polygon_annotator_v3'
      };

      const polygonData = {
        user_id: testUserId,
        original_image_id: testImageId,
        points: createValidPolygonPoints.square(),
        label: 'complex_metadata_test',
        metadata: complexMetadata
      };

      const result = await polygonModel.create(polygonData);
      createdPolygonIds.push(result.id);

      expect(result.metadata).toEqual(complexMetadata);
      
      // Verify nested structure is preserved
      expect(result.metadata.attributes.color.primary).toBe('blue');
      expect(result.metadata.ai_analysis.confidence).toBe(0.892);
      expect(Array.isArray(result.metadata.user_tags)).toBe(true);
    });

    test('should handle partial updates correctly', async () => {
      // Create polygon
      const originalData = {
        user_id: testUserId,
        original_image_id: testImageId,
        points: createValidPolygonPoints.triangle(),
        label: 'partial_update_test',
        metadata: { original: true, version: 1 }
      };

      const created = await polygonModel.create(originalData);
      createdPolygonIds.push(created.id);

      // Update only label
      const updated1 = await polygonModel.update(created.id, { 
        label: 'updated_label_only' 
      });
      expect(updated1?.label).toBe('updated_label_only');
      expect(updated1?.points).toEqual(originalData.points); // Should remain unchanged
      expect(updated1?.metadata).toEqual(originalData.metadata); // Should remain unchanged

      // Update only metadata
      const newMetadata = { original: false, version: 2, updated: true };
      const updated2 = await polygonModel.update(created.id, { 
        metadata: newMetadata 
      });
      expect(updated2?.metadata).toEqual(newMetadata);
      expect(updated2?.label).toBe('updated_label_only'); // Should remain from previous update
      expect(updated2?.points).toEqual(originalData.points); // Should remain unchanged

      // Update only points
      const newPoints = createValidPolygonPoints.square();
      const updated3 = await polygonModel.update(created.id, { 
        points: newPoints 
      });
      expect(updated3?.points).toEqual(newPoints);
      expect(updated3?.label).toBe('updated_label_only'); // Should remain
      expect(updated3?.metadata).toEqual(newMetadata); // Should remain
    });
  });

  // ==================== BATCH OPERATIONS ====================

  describe('📦 Batch Operations', () => {
    test('should handle creating multiple polygons efficiently', async () => {
      const batchSize = 25;
      const startTime = performance.now();

      const createPromises = [];
      for (let i = 0; i < batchSize; i++) {
        const polygonData = {
          user_id: testUserId,
          original_image_id: testImageId,
          points: createValidPolygonPoints.custom(100 + i * 5, 100 + i * 3),
          label: `batch_polygon_${i}`,
          metadata: { batch_index: i, created_in_batch: true }
        };
        createPromises.push(polygonModel.create(polygonData));
      }

      const results = await Promise.all(createPromises);
      const creationTime = performance.now() - startTime;

      // Track all created polygons for cleanup
      results.forEach(result => createdPolygonIds.push(result.id));

      expect(results).toHaveLength(batchSize);
      expect(creationTime).toBeLessThan(3000); // Should complete within 3 seconds

      // Verify all polygons were created correctly
      results.forEach((polygon, index) => {
        expect(polygon.label).toBe(`batch_polygon_${index}`);
        expect(polygon.metadata.batch_index).toBe(index);
        polygonAssertions.hasValidGeometry(polygon);
      });

      console.log(`✅ Created ${batchSize} polygons in ${creationTime.toFixed(2)}ms`);
    });

    test('should find polygons by user across multiple images', async () => {
      // Create additional test image
      const secondImage = await testImageModel.create({
        user_id: testUserId,
        file_path: `test-images/multi-image-test-${Date.now()}.jpg`,
        original_metadata: { width: 800, height: 600, format: 'jpeg' }
      });
      createdImageIds.push(secondImage.id);

      // Create polygons across both images
      const polygonData = [
        {
          user_id: testUserId,
          original_image_id: testImageId,
          points: createValidPolygonPoints.triangle(),
          label: 'multi_image_1',
          metadata: { image_sequence: 1 }
        },
        {
          user_id: testUserId,
          original_image_id: secondImage.id,
          points: createValidPolygonPoints.square(),
          label: 'multi_image_2',
          metadata: { image_sequence: 2 }
        },
        {
          user_id: testUserId,
          original_image_id: testImageId,
          points: createValidPolygonPoints.pentagon(),
          label: 'multi_image_3',
          metadata: { image_sequence: 3 }
        }
      ];

      for (const data of polygonData) {
        const result = await polygonModel.create(data);
        createdPolygonIds.push(result.id);
      }

      // Find all polygons for the user
      const userPolygons = await polygonModel.findByUserId(testUserId);
      
      // Should find at least our 3 polygons (might be more from other tests)
      const ourPolygons = userPolygons.filter(p => 
        p.label?.startsWith('multi_image_')
      );
      expect(ourPolygons).toHaveLength(3);

      // Verify they span multiple images
      const imageIds = new Set(ourPolygons.map(p => p.original_image_id));
      expect(imageIds.size).toBe(2); // Should span 2 different images

      // Verify order (should be by created_at DESC for findByUserId)
      const labels = ourPolygons.map(p => p.label);
      expect(labels).toEqual(['multi_image_3', 'multi_image_2', 'multi_image_1']);
    });

    test('should handle batch deletion by image ID', async () => {
      // Create multiple polygons for one image
      const polygonData = [
        { label: 'delete_batch_1' },
        { label: 'delete_batch_2' },
        { label: 'delete_batch_3' },
        { label: 'delete_batch_4' }
      ];

      for (const data of polygonData) {
        const polygon = await polygonModel.create({
          user_id: testUserId,
          original_image_id: testImageId,
          points: createValidPolygonPoints.triangle(),
          label: data.label,
          metadata: {}
        });
        createdPolygonIds.push(polygon.id);
      }

      // Verify polygons exist
      const beforeDelete = await polygonModel.findByImageId(testImageId);
      const ourPolygons = beforeDelete.filter(p => 
        p.label?.startsWith('delete_batch_')
      );
      expect(ourPolygons).toHaveLength(4);

      // Batch delete all polygons for this image
      const deleteCount = await polygonModel.deleteByImageId(testImageId);
      expect(deleteCount).toBeGreaterThanOrEqual(4); // At least our 4 polygons

      // Verify polygons are gone
      const afterDelete = await polygonModel.findByImageId(testImageId);
      expect(afterDelete).toHaveLength(0);

      // Clear tracking array since polygons are deleted
      createdPolygonIds = [];
    });
  });

  // ==================== PERFORMANCE VALIDATION ====================

  describe('⚡ Performance Baseline', () => {
    test('should maintain reasonable performance with moderate load', async () => {
      const testCount = 50;
      const metrics = {
        creation: 0,
        retrieval: 0,
        updates: 0
      };

      // Measure creation performance
      const createStart = performance.now();
      for (let i = 0; i < testCount; i++) {
        const result = await polygonModel.create({
          user_id: testUserId,
          original_image_id: testImageId,
          points: createValidPolygonPoints.custom(i * 10, i * 5),
          label: `perf_test_${i}`,
          metadata: { performance_test: true, index: i }
        });
        createdPolygonIds.push(result.id);
      }
      metrics.creation = performance.now() - createStart;

      // Measure retrieval performance
      const retrieveStart = performance.now();
      const allPolygons = await polygonModel.findByImageId(testImageId);
      metrics.retrieval = performance.now() - retrieveStart;

      // Measure update performance (update every 5th polygon)
      const updateStart = performance.now();
      const updateIds = createdPolygonIds.filter((_, index) => index % 5 === 0);
      for (const id of updateIds) {
        await polygonModel.update(id, { 
          metadata: { performance_test: true, updated: true } 
        });
      }
      metrics.updates = performance.now() - updateStart;

      // Performance assertions
      expect(metrics.creation).toBeLessThan(8000); // 8 seconds for 50 creates
      expect(metrics.retrieval).toBeLessThan(500);  // 500ms for retrieval
      expect(metrics.updates).toBeLessThan(2000);   // 2 seconds for updates

      // Verify data integrity
      expect(allPolygons.length).toBeGreaterThanOrEqual(testCount);
      
      const ourPolygons = allPolygons.filter(p => 
        p.label?.startsWith('perf_test_')
      );
      expect(ourPolygons).toHaveLength(testCount);

      console.log(`✅ Performance metrics:`);
      console.log(`   - Created ${testCount} polygons: ${metrics.creation.toFixed(2)}ms`);
      console.log(`   - Retrieved ${allPolygons.length} polygons: ${metrics.retrieval.toFixed(2)}ms`);
      console.log(`   - Updated ${updateIds.length} polygons: ${metrics.updates.toFixed(2)}ms`);
    });
  });
});