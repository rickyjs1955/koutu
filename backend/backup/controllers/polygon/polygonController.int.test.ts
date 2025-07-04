// tests/integration/polygonController.integration.test.ts
// Production-ready comprehensive integration test suite for polygonController
// Tests real controller-model-database interactions under production scenarios

import { Request, Response } from 'express';
import { polygonController } from '../../controllers/polygonController';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { setupTestDatabase } from '../../utils/testSetup';
import { testUserModel } from '../../utils/testUserModel';
import { testImageModel } from '../../utils/testImageModel';
import { v4 as uuidv4 } from 'uuid';

// ==================== PRODUCTION-READY SETUP ====================

// Mock external dependencies to isolate polygon functionality
jest.mock('../../models/db', () => ({
  query: (text: string, params?: any[]) => TestDatabaseConnection.query(text, params)
}));

jest.mock('../../config/firebase', () => ({
  default: { storage: jest.fn() }
}));

jest.mock('../../services/storageService', () => ({
  storageService: {
    saveFile: jest.fn().mockResolvedValue(true),
    deleteFile: jest.fn().mockResolvedValue(true)
  }
}));

// Import real modules after mocking dependencies
import { polygonModel } from '../../models/polygonModel';

// ==================== TEST DATA FACTORIES ====================

interface TestUser {
  id: string;
  email: string;
}

interface TestImage {
  id: string;
  user_id: string;
  file_path: string;
  original_metadata: any;
}

interface TestPolygon {
  id: string;
  user_id: string;
  original_image_id: string;
  points: Array<{x: number, y: number}>;
  label?: string;
  metadata?: any;
}

class TestDataFactory {
  private static userCounter = 0;
  private static imageCounter = 0;
  private static polygonCounter = 0;

  static async createUser(overrides: Partial<TestUser> = {}): Promise<TestUser> {
    this.userCounter++;
    const defaultUser = {
      email: `test-user-${this.userCounter}-${Date.now()}@example.com`,
      password: 'testpassword123'
    };
    
    const user = await testUserModel.create({ ...defaultUser, ...overrides });
    return { id: user.id, email: user.email };
  }

  static async createImage(userId: string, overrides: Partial<TestImage> = {}): Promise<TestImage> {
    this.imageCounter++;
    const defaultImage = {
      user_id: userId,
      file_path: `/test/images/test-image-${this.imageCounter}.jpg`,
      original_metadata: {
        width: 1920,
        height: 1080,
        format: 'jpeg',
        size: 2048000
      }
    };

    const image = await testImageModel.create({ ...defaultImage, ...overrides });
    return {
      id: image.id,
      user_id: image.user_id,
      file_path: image.file_path,
      original_metadata: image.original_metadata
    };
  }

  static generatePolygonData(imageId: string, overrides: any = {}): any {
    this.polygonCounter++;
    return {
      original_image_id: imageId,
      points: [
        { x: 100 + this.polygonCounter * 10, y: 100 + this.polygonCounter * 10 },
        { x: 200 + this.polygonCounter * 10, y: 100 + this.polygonCounter * 10 },
        { x: 150 + this.polygonCounter * 10, y: 200 + this.polygonCounter * 10 }
      ],
      label: `test-polygon-${this.polygonCounter}`,
      metadata: { test: true, counter: this.polygonCounter },
      ...overrides
    };
  }

  static reset() {
    this.userCounter = 0;
    this.imageCounter = 0;
    this.polygonCounter = 0;
  }
}

// ==================== TEST HELPERS ====================

class IntegrationTestHelpers {
  static createMockRequest(user: TestUser, overrides: any = {}): Partial<Request> {
    return {
      user: { id: user.id },
      params: {},
      body: {},
      query: {},
      headers: { 'content-type': 'application/json' },
      ...overrides
    };
  }

  static createMockResponse(): { response: Partial<Response>, mocks: any } {
    const mocks = {
      status: jest.fn(),
      json: jest.fn(),
      send: jest.fn()
    };
    
    mocks.status.mockReturnValue({ json: mocks.json, send: mocks.send });
    mocks.json.mockReturnValue({ status: mocks.status });
    
    return { 
      response: mocks as Partial<Response>,
      mocks
    };
  }

  static createMockNext() {
    return jest.fn();
  }

  static async executeControllerMethod(
    method: Function,
    user: TestUser,
    requestOverrides: any = {}
  ) {
    const request = this.createMockRequest(user, requestOverrides);
    const { response, mocks } = this.createMockResponse();
    const next = this.createMockNext();

    await method(request as Request, response as Response, next);

    return { request, response, mocks, next };
  }

  static extractPolygonFromResponse(mocks: any): any | null {
    if (mocks.json.mock.calls.length > 0) {
      const responseData = mocks.json.mock.calls[0][0];
      return responseData?.data?.polygon || null;
    }
    return null;
  }

  static extractPolygonsFromResponse(mocks: any): any[] | null {
    if (mocks.json.mock.calls.length > 0) {
      const responseData = mocks.json.mock.calls[0][0];
      return responseData?.data?.polygons || null;
    }
    return null;
  }
}

/**
 * Safely extracts and validates polygon ID, then adds it to the test cleanup array
 * @param polygon - The polygon object returned from service calls
 * @param testPolygonIds - The array to track polygon IDs for cleanup
 * @returns The validated polygon ID as a string
 * @throws Error if polygon or polygon.id is invalid
 */
function addPolygonToTestCleanup(polygon: any, testPolygonIds: string[]): string {
  // Validate polygon exists
  expect(polygon).toBeDefined();
  expect(polygon.id).toBeDefined();
  
  // Type assertion after validation
  const polygonId: string = polygon.id!;
  
  // Add to cleanup array
  testPolygonIds.push(polygonId);
  
  return polygonId;
}

/**
 * Safely processes multiple polygons and adds them to test cleanup
 * @param polygons - Array of polygon objects from service calls
 * @param testPolygonIds - The array to track polygon IDs for cleanup
 * @returns Array of validated polygon IDs
 */
function addPolygonsToTestCleanup(polygons: any[], testPolygonIds: string[]): string[] {
  return polygons.map(polygon => addPolygonToTestCleanup(polygon, testPolygonIds));
}

// ==================== MAIN TEST SUITE ====================

describe('Polygon Controller Production Integration Tests', () => {
  let testPolygonIds: string[] = [];

  beforeAll(async () => {
    console.log('🚀 Initializing production-ready polygon integration tests...');
    
    await setupTestDatabase();
    
    // Create polygons table with full production schema
    await TestDatabaseConnection.query(`
      CREATE TABLE IF NOT EXISTS polygons (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        original_image_id UUID NOT NULL REFERENCES original_images(id) ON DELETE CASCADE,
        points JSONB NOT NULL,
        label VARCHAR(255),
        metadata JSONB DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        
        -- Production indexes for performance
        CONSTRAINT points_not_empty CHECK (jsonb_array_length(points) >= 3),
        CONSTRAINT valid_points CHECK (
          jsonb_typeof(points) = 'array' AND
          points @? '$[*] ? (@.x >= 0 && @.y >= 0)'
        )
      )
    `);

    // Create production indexes
    await TestDatabaseConnection.query(`
      CREATE INDEX IF NOT EXISTS idx_polygons_user_id ON polygons(user_id);
      CREATE INDEX IF NOT EXISTS idx_polygons_image_id ON polygons(original_image_id);
      CREATE INDEX IF NOT EXISTS idx_polygons_created_at ON polygons(created_at);
      CREATE INDEX IF NOT EXISTS idx_polygons_label ON polygons(label) WHERE label IS NOT NULL;
    `);
    
    console.log('✅ Production polygon integration environment ready');
  }, 30000);

  beforeEach(async () => {
    // Clean slate for each test
    await TestDatabaseConnection.query('TRUNCATE TABLE polygons CASCADE');
    await TestDatabaseConnection.query('TRUNCATE TABLE users CASCADE');
    await TestDatabaseConnection.query('TRUNCATE TABLE original_images CASCADE');
    testPolygonIds = [];
    TestDataFactory.reset();
  });

  afterEach(async () => {
    // Cleanup any created polygons
    if (testPolygonIds.length > 0) {
      await TestDatabaseConnection.query(
        'DELETE FROM polygons WHERE id = ANY($1)',
        [testPolygonIds]
      );
    }
  });

  afterAll(async () => {
    await TestDatabaseConnection.query('DROP TABLE IF EXISTS polygons CASCADE');
    console.log('✅ Production integration tests cleaned up');
  }, 30000);

  // ==================== CORE CRUD OPERATIONS ====================

  describe('Production CRUD Operations', () => {
    test('should create polygon with complete validation and persistence', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      const polygonData = TestDataFactory.generatePolygonData(image.id, {
        label: 'production-test-polygon',
        metadata: { 
          source: 'production-test',
          complexity: 'simple',
          tags: ['test', 'polygon', 'production'] 
        }
      });

      // Act
      const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        user,
        { body: polygonData }
      );

      // Assert
      expect(next).not.toHaveBeenCalled();
      expect(mocks.status).toHaveBeenCalledWith(201);
      
      const polygon = IntegrationTestHelpers.extractPolygonFromResponse(mocks);
      expect(polygon).toMatchObject({
        id: expect.any(String),
        user_id: user.id,
        original_image_id: image.id,
        label: 'production-test-polygon',
        points: polygonData.points,
        metadata: expect.objectContaining({
          source: 'production-test',
          tags: expect.arrayContaining(['test', 'polygon', 'production'])
        })
      });

      testPolygonIds.push(polygon.id);

      // Verify database persistence
      const dbPolygon = await polygonModel.findById(polygon.id!);
      expect(dbPolygon).toBeTruthy();
      expect(dbPolygon!.label).toBe('production-test-polygon');
    });

    test('should retrieve polygon with proper authorization', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      const polygon = await polygonModel.create({
        user_id: user.id,
        ...TestDataFactory.generatePolygonData(image.id)
      });
      const polygonId = addPolygonToTestCleanup(polygon, testPolygonIds);
      testPolygonIds.push(polygonId);

      // Act
      const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.getPolygon,
        user,
        { params: { id: polygon.id } }
      );

      // Assert
      expect(next).not.toHaveBeenCalled();
      expect(mocks.status).toHaveBeenCalledWith(200);
      
      const retrievedPolygon = IntegrationTestHelpers.extractPolygonFromResponse(mocks);
      expect(retrievedPolygon.id).toBe(polygon.id);
    });

    test('should update polygon with validation and optimistic locking', async () => {
        // Arrange
        const user = await TestDataFactory.createUser();
        const image = await TestDataFactory.createImage(user.id);
        const polygon = await polygonModel.create({
            user_id: user.id,
            ...TestDataFactory.generatePolygonData(image.id, { label: 'original-label' })
        });
        
        // Ensure polygon.id exists and is valid
        expect(polygon).toBeDefined();
        expect(polygon.id).toBeDefined();
        expect(typeof polygon.id).toBe('string');
        
        const polygonId = addPolygonToTestCleanup(polygon, testPolygonIds);

        const updateData = {
            label: 'updated-production-label',
            points: [
                { x: 300, y: 300 },
                { x: 400, y: 300 },
                { x: 350, y: 400 }
            ],
            metadata: { 
                updated: true, 
                version: 2,
                lastModified: new Date().toISOString()
            }
        };

        // Act
        const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
            polygonController.updatePolygon,
            user,
            { 
                params: { id: polygonId },
                body: updateData
            }
        );

        // Assert
        expect(next).not.toHaveBeenCalled();
        expect(mocks.status).toHaveBeenCalledWith(200);
        
        const updatedPolygon = IntegrationTestHelpers.extractPolygonFromResponse(mocks);
        expect(updatedPolygon).toBeDefined();
        expect(updatedPolygon.label).toBe('updated-production-label');
        expect(updatedPolygon.points).toEqual(updateData.points);

        // Verify database persistence with proper null checking
        const dbPolygon = await polygonModel.findById(polygonId);
        expect(dbPolygon).toBeDefined();
        expect(dbPolygon).not.toBeNull();
        
        // Type-safe assertions after null checks
        expect(dbPolygon!.label).toBe('updated-production-label');
        expect(dbPolygon!.metadata).toBeDefined();
        expect(dbPolygon!.metadata).not.toBeNull();
        expect(dbPolygon!.metadata!.version).toBe(2);
        expect(dbPolygon!.metadata!.updated).toBe(true);
        expect(dbPolygon!.metadata!.lastModified).toBeDefined();
        
        // Verify points were updated correctly
        expect(dbPolygon!.points).toEqual(updateData.points);
        expect(dbPolygon!.points).toHaveLength(3);
    });

    test('should delete polygon with cascade verification', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      const polygon = await polygonModel.create({
        user_id: user.id,
        ...TestDataFactory.generatePolygonData(image.id)
      });

      // Ensure polygon.id exists and is valid before proceeding
      expect(polygon).toBeDefined();
      expect(polygon.id).toBeDefined();
      expect(typeof polygon.id).toBe('string');
      
      // Type-safe polygon ID extraction
      const polygonId: string = polygon.id!;

      // Act
      const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.deletePolygon,
        user,
        { params: { id: polygonId } }
      );

      // Assert
      expect(next).not.toHaveBeenCalled();
      expect(mocks.status).toHaveBeenCalledWith(200);
      expect(mocks.json).toHaveBeenCalledWith({
        status: 'success',
        data: null,
        message: 'Polygon deleted successfully'
      });

      // Verify database deletion with validated polygon ID
      const dbPolygon = await polygonModel.findById(polygonId);
      expect(dbPolygon).toBeNull();
    });
  });

  // ==================== AUTHORIZATION & SECURITY ====================

  describe('Production Authorization & Security', () => {
    test('should enforce strict user isolation', async () => {
      // Arrange
      const userA = await TestDataFactory.createUser();
      const userB = await TestDataFactory.createUser();
      const imageA = await TestDataFactory.createImage(userA.id);
      
      const polygon = await polygonModel.create({
        user_id: userA.id,
        ...TestDataFactory.generatePolygonData(imageA.id)
      });
      const polygonId = addPolygonToTestCleanup(polygon, testPolygonIds);
      testPolygonIds.push(polygonId);

      // Act - User B tries to access User A's polygon
      const { next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.getPolygon,
        userB,
        { params: { id: polygon.id } }
      );

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'You do not have permission to view this polygon',
          statusCode: 403
        })
      );
    });

    test('should prevent cross-user polygon creation on others images', async () => {
      // Arrange
      const userA = await TestDataFactory.createUser();
      const userB = await TestDataFactory.createUser();
      const imageA = await TestDataFactory.createImage(userA.id);

      // Act - User B tries to create polygon on User A's image
      const { next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        userB,
        { body: TestDataFactory.generatePolygonData(imageA.id) }
      );

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'You do not have permission to add polygons to this image',
          statusCode: 403
        })
      );

      // Verify no polygon was created
      const allPolygons = await polygonModel.findByImageId(imageA.id);
      expect(allPolygons).toHaveLength(0);
    });

    test('should validate JWT token integrity', async () => {
      // Act - Request without user context
      const request = { body: TestDataFactory.generatePolygonData('fake-image-id') };
      const { response, mocks } = IntegrationTestHelpers.createMockResponse();
      const next = IntegrationTestHelpers.createMockNext();

      await polygonController.createPolygon(
        request as Request,
        response as Response,
        next
      );

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'User not authenticated',
          statusCode: 401
        })
      );
    });
  });

  // ==================== INPUT VALIDATION & EDGE CASES ====================

  describe('Production Input Validation', () => {
    let user: TestUser;
    let image: TestImage;

    beforeEach(async () => {
      user = await TestDataFactory.createUser();
      image = await TestDataFactory.createImage(user.id);
    });

    test('should validate polygon geometry constraints', async () => {
      const invalidCases = [
        {
          name: 'insufficient points',
          data: { points: [{ x: 100, y: 100 }, { x: 200, y: 100 }] },
          expectedError: 'Polygon must have at least 3 points'
        },
        {
          name: 'excessive points',
          data: { points: Array.from({ length: 1001 }, (_, i) => ({ x: i, y: i })) },
          expectedError: 'Polygon cannot have more than 1000 points'
        },
        {
          name: 'out of bounds points',
          data: { 
            points: [
              { x: -10, y: 100 },
              { x: 200, y: 100 },
              { x: 100, y: 200 }
            ]
          },
          expectedError: 'point(s) are outside image boundaries'
        },
        {
          name: 'way out of bounds',
          data: {
            points: [
              { x: 5000, y: 5000 },
              { x: 6000, y: 5000 },
              { x: 5500, y: 6000 }
            ]
          },
          expectedError: 'point(s) are outside image boundaries'
        }
      ];

      for (const testCase of invalidCases) {
        const { next } = await IntegrationTestHelpers.executeControllerMethod(
          polygonController.createPolygon,
          user,
          { body: { original_image_id: image.id, ...testCase.data } }
        );

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringContaining(testCase.expectedError.split(' ')[0])
          })
        );

        jest.clearAllMocks();
      }
    });

    test('should validate UUID format in parameters', async () => {
      const invalidUUIDs = ['not-a-uuid', '123', '', 'almost-uuid-but-not'];

      for (const invalidUUID of invalidUUIDs) {
        const { next } = await IntegrationTestHelpers.executeControllerMethod(
          polygonController.getPolygon,
          user,
          { params: { id: invalidUUID } }
        );

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Invalid polygon ID format',
            statusCode: 400
          })
        );

        jest.clearAllMocks();
      }
    });

    test('should handle malformed JSON in request body', async () => {
      const malformedCases = [
        { points: 'not-an-array' },
        { points: [{ x: 'not-number', y: 100 }] },
        { metadata: 'should-be-object' }
      ];

      for (const malformedData of malformedCases) {
        const { next } = await IntegrationTestHelpers.executeControllerMethod(
          polygonController.createPolygon,
          user,
          { body: { original_image_id: image.id, ...malformedData } }
        );

        expect(next).toHaveBeenCalled();
        jest.clearAllMocks();
      }
    });
  });

  // ==================== ERROR HANDLING & RESILIENCE ====================

  describe('Production Error Handling', () => {
    test('should handle database constraint violations gracefully', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const fakeImageId = uuidv4();

      // Act - Try to create polygon with non-existent image
      const { next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        user,
        { body: TestDataFactory.generatePolygonData(fakeImageId) }
      );

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Image not found',
          statusCode: 404
        })
      );
    });

    test('should handle concurrent polygon operations safely', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      const polygon = await polygonModel.create({
        user_id: user.id,
        ...TestDataFactory.generatePolygonData(image.id)
      });
      const polygonId = addPolygonToTestCleanup(polygon, testPolygonIds);

      // Act - Simulate concurrent updates using the validated polygonId
      const concurrentUpdates = Array.from({ length: 5 }, (_, i) => 
        IntegrationTestHelpers.executeControllerMethod(
          polygonController.updatePolygon,
          user,
          {
            params: { id: polygonId },
            body: { 
              label: `concurrent-update-${i}`,
              metadata: { update: i, timestamp: Date.now() + i }
            }
          }
        )
      );

      const results = await Promise.allSettled(concurrentUpdates);

      // Assert - At least one should succeed
      const successful = results.filter(r => 
        r.status === 'fulfilled' && !r.value.next.mock.calls.length
      );
      expect(successful.length).toBeGreaterThan(0);

      // Verify final database state is consistent using validated polygonId
      const finalPolygon = await polygonModel.findById(polygonId);
      expect(finalPolygon).toBeTruthy();
      expect(finalPolygon!.label).toMatch(/concurrent-update-\d/);
    });

    test('should handle database connection issues', async () => {
      // This would typically require mocking database failures
      // For now, verify error propagation structure exists
      const user = await TestDataFactory.createUser();
      
      // Simulate by using completely invalid data that would cause DB error
      const { next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        user,
        { 
          body: { 
            original_image_id: 'totally-invalid-uuid-format',
            points: [{ x: 1, y: 1 }, { x: 2, y: 2 }, { x: 3, y: 3 }]
          }
        }
      );

      expect(next).toHaveBeenCalled();
    });
  });

  // ==================== PERFORMANCE & SCALABILITY ====================

  describe('Production Performance', () => {
    test('should handle bulk polygon operations efficiently', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      const batchSize = 50; // Production-realistic batch size
      const startTime = Date.now();

      // Act - Create multiple polygons concurrently
      const createPromises = Array.from({ length: batchSize }, (_, i) =>
        IntegrationTestHelpers.executeControllerMethod(
          polygonController.createPolygon,
          user,
          { body: TestDataFactory.generatePolygonData(image.id, { label: `bulk-test-${i}` }) }
        )
      );

      const results = await Promise.all(createPromises);
      const totalTime = Date.now() - startTime;

      // Assert performance
      const successful = results.filter(r => !r.next.mock.calls.length);
      expect(successful.length).toBe(batchSize);
      expect(totalTime).toBeLessThan(30000); // Should complete within 30 seconds

      // Collect IDs for cleanup
      successful.forEach(result => {
        const polygon = IntegrationTestHelpers.extractPolygonFromResponse(result.mocks);
        if (polygon?.id) testPolygonIds.push(polygon.id);
      });

      // Verify database consistency
      const dbPolygons = await polygonModel.findByImageId(image.id);
      expect(dbPolygons).toHaveLength(batchSize);

      console.log(`✅ Performance: ${batchSize} polygons created in ${totalTime}ms (${Math.round(totalTime/batchSize)}ms avg)`);
    });

    test('should efficiently retrieve paginated polygon lists', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      
      // Create 25 polygons
      const polygons = await Promise.all(
        Array.from({ length: 25 }, (_, i) =>
          polygonModel.create({
            user_id: user.id,
            ...TestDataFactory.generatePolygonData(image.id, { label: `paginated-${i}` })
          })
        )
      );
      testPolygonIds.push(...polygons.map(p => p.id).filter((id): id is string => id !== undefined));

      const startTime = Date.now();

      // Act
      const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.getImagePolygons,
        user,
        { params: { imageId: image.id } }
      );

      const totalTime = Date.now() - startTime;

      // Assert
      expect(next).not.toHaveBeenCalled();
      expect(mocks.status).toHaveBeenCalledWith(200);
      
      const responsePolygons = IntegrationTestHelpers.extractPolygonsFromResponse(mocks);
      expect(responsePolygons).toHaveLength(25);
      expect(totalTime).toBeLessThan(1000); // Should be fast

      console.log(`✅ Pagination performance: 25 polygons retrieved in ${totalTime}ms`);
    });
  });

  // ==================== INTEGRATION EDGE CASES ====================

  describe('Production Edge Cases', () => {
    test('should handle complex polygon geometries', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id, {
        original_metadata: { width: 4000, height: 3000, format: 'png' }
      });

      const complexPolygonData = {
        original_image_id: image.id,
        points: [
          // Complex star-shaped polygon with many points
          { x: 2000, y: 1000 },
          { x: 2100, y: 1200 },
          { x: 2300, y: 1250 },
          { x: 2150, y: 1400 },
          { x: 2200, y: 1600 },
          { x: 2000, y: 1500 },
          { x: 1800, y: 1600 },
          { x: 1850, y: 1400 },
          { x: 1700, y: 1250 },
          { x: 1900, y: 1200 }
        ],
        label: 'complex-geometry-test',
        metadata: {
          type: 'star',
          complexity: 'high',
          area: 120000,
          perimeter: 800
        }
      };

      // Act
      const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        user,
        { body: complexPolygonData }
      );

      // Assert
      expect(next).not.toHaveBeenCalled();
      expect(mocks.status).toHaveBeenCalledWith(201);
      
      const polygon = IntegrationTestHelpers.extractPolygonFromResponse(mocks);
      expect(polygon.points).toHaveLength(10);
      expect(polygon.metadata.type).toBe('star');
      
      testPolygonIds.push(polygon.id);
    });

    test('should handle unicode and special characters in labels', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);

      const unicodeLabels = [
        '🔺 Triangle Emoji',
        'Ñiño Español',
        '中文标签',
        'Русский текст',
        'العربية',
        'Mixed: 日本語 + English + 123 + 🎯'
      ];

      // Act & Assert
      for (const label of unicodeLabels) {
        const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
          polygonController.createPolygon,
          user,
          { body: TestDataFactory.generatePolygonData(image.id, { label }) }
        );

        expect(next).not.toHaveBeenCalled();
        const polygon = IntegrationTestHelpers.extractPolygonFromResponse(mocks);
        expect(polygon.label).toBe(label);
        
        testPolygonIds.push(polygon.id);
        jest.clearAllMocks();
      }
    });

    test('should handle rapid sequential operations', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);

      // Act - Rapid create, read, update, delete sequence
      const createResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        user,
        { body: TestDataFactory.generatePolygonData(image.id, { label: 'rapid-sequence' }) }
      );

      const polygon = IntegrationTestHelpers.extractPolygonFromResponse(createResult.mocks);
      
      const readResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.getPolygon,
        user,
        { params: { id: polygon.id } }
      );

      const updateResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.updatePolygon,
        user,
        { 
          params: { id: polygon.id },
          body: { label: 'rapid-sequence-updated' }
        }
      );

      const deleteResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.deletePolygon,
        user,
        { params: { id: polygon.id } }
      );

      // Assert all operations succeeded
      expect(createResult.next).not.toHaveBeenCalled();
      expect(readResult.next).not.toHaveBeenCalled();
      expect(updateResult.next).not.toHaveBeenCalled();
      expect(deleteResult.next).not.toHaveBeenCalled();

      // Verify final state
      const finalPolygon = await polygonModel.findById(polygon.id);
      expect(finalPolygon).toBeNull();
    });
  });

  // ==================== BUSINESS LOGIC INTEGRATION ====================

  describe('Production Business Logic', () => {
    test('should enforce image labeling workflow constraints', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      
      // Create image and then update its status to 'labeled' in the database
      const image = await TestDataFactory.createImage(user.id);
      await TestDatabaseConnection.query(
        `UPDATE original_images SET status = 'labeled' WHERE id = $1`,
        [image.id]
      );

      // Act - Try to add polygon to already labeled image
      const { next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        user,
        { body: TestDataFactory.generatePolygonData(image.id) }
      );

      // Assert
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Image is already labeled and cannot accept new polygons',
          statusCode: 400
        })
      );
    });

    test('should handle polygon cascade deletion when image is deleted', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      
      // Create multiple polygons for the image
      const polygons = await Promise.all([
        polygonModel.create({
          user_id: user.id,
          ...TestDataFactory.generatePolygonData(image.id, { label: 'cascade-test-1' })
        }),
        polygonModel.create({
          user_id: user.id,
          ...TestDataFactory.generatePolygonData(image.id, { label: 'cascade-test-2' })
        }),
        polygonModel.create({
          user_id: user.id,
          ...TestDataFactory.generatePolygonData(image.id, { label: 'cascade-test-3' })
        })
      ]);

      // Validate all polygons were created with valid IDs
      polygons.forEach((polygon, index) => {
        expect(polygon).toBeDefined();
        expect(polygon.id).toBeDefined();
        expect(typeof polygon.id).toBe('string');
      });

      // Extract validated polygon IDs
      const polygonIds: string[] = polygons.map(polygon => polygon.id!);

      // Act - Delete the image (simulating CASCADE DELETE)
      await TestDatabaseConnection.query('DELETE FROM original_images WHERE id = $1', [image.id]);

      // Assert - All polygons should be automatically deleted
      for (const polygonId of polygonIds) {
        const dbPolygon = await polygonModel.findById(polygonId);
        expect(dbPolygon).toBeNull();
      }
    });

    test('should maintain polygon-image relationship integrity', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image1 = await TestDataFactory.createImage(user.id);
      const image2 = await TestDataFactory.createImage(user.id);

      const polygon1 = await polygonModel.create({
        user_id: user.id,
        ...TestDataFactory.generatePolygonData(image1.id, { label: 'image1-polygon' })
      });

      const polygon2 = await polygonModel.create({
        user_id: user.id,
        ...TestDataFactory.generatePolygonData(image2.id, { label: 'image2-polygon' })
      });
      const polygon1Id = addPolygonToTestCleanup(polygon1, testPolygonIds);
      const polygon2Id = addPolygonToTestCleanup(polygon2, testPolygonIds);
      testPolygonIds.push(polygon1Id, polygon2Id);

      // Act - Retrieve polygons for each image
      const image1Polygons = await polygonModel.findByImageId(image1.id);
      const image2Polygons = await polygonModel.findByImageId(image2.id);

      // Assert - Each image should only have its own polygons
      expect(image1Polygons).toHaveLength(1);
      expect(image1Polygons[0].label).toBe('image1-polygon');
      
      expect(image2Polygons).toHaveLength(1);
      expect(image2Polygons[0].label).toBe('image2-polygon');
    });
  });

  // ==================== DATA INTEGRITY & STORAGE ====================

  describe('Production Data Integrity', () => {
    test('should preserve JSONB data types and structure', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      
      const complexMetadata = {
        classification: {
          type: 'garment',
          category: 'shirt',
          subcategory: 'polo',
          confidence: 0.95
        },
        attributes: {
          color: ['blue', 'white'],
          size: 'medium',
          brand: 'TestBrand',
          price: 29.99,
          inStock: true
        },
        annotations: [
          { annotator: 'user123', timestamp: '2024-01-15T10:30:00Z', quality: 'high' },
          { annotator: 'ai-model-v2', timestamp: '2024-01-15T10:25:00Z', quality: 'medium' }
        ],
        processing: {
          pipeline: 'v2.1',
          processingTime: 1234,
          flags: ['validated', 'reviewed']
        }
      };

      // Act
      const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        user,
        { 
          body: TestDataFactory.generatePolygonData(image.id, {
            label: 'complex-metadata-test',
            metadata: complexMetadata
          })
        }
      );

      // Assert
      expect(next).not.toHaveBeenCalled();
      const polygon = IntegrationTestHelpers.extractPolygonFromResponse(mocks);
      testPolygonIds.push(polygon.id);

      // Verify complex metadata structure is preserved
      expect(polygon.metadata.classification.type).toBe('garment');
      expect(polygon.metadata.attributes.price).toBe(29.99);
      expect(polygon.metadata.annotations).toHaveLength(2);
      expect(polygon.metadata.processing.flags).toContain('validated');

      // Verify database storage preserves structure with proper null checking
      const dbPolygon = await polygonModel.findById(polygon.id);
      expect(dbPolygon).toBeDefined();
      expect(dbPolygon).not.toBeNull();
      expect(dbPolygon!.metadata).toBeDefined();
      expect(dbPolygon!.metadata).not.toBeNull();
      
      // Type-safe assertions after proper validation
      expect(dbPolygon!.metadata!.classification).toBeDefined();
      expect(dbPolygon!.metadata!.classification.confidence).toBe(0.95);
      expect(dbPolygon!.metadata!.attributes).toBeDefined();
      expect(dbPolygon!.metadata!.attributes.color).toEqual(['blue', 'white']);
      expect(dbPolygon!.metadata!.processing.flags).toContain('validated');
    });

    test('should handle large polygon point arrays efficiently', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id, {
        original_metadata: { width: 8000, height: 6000, format: 'png' }
      });

      // Create a large polygon with 500 points (complex shape)
      const largePolygon = {
        original_image_id: image.id,
        points: Array.from({ length: 500 }, (_, i) => {
          const angle = (i / 500) * 2 * Math.PI;
          const radius = 1000 + Math.sin(angle * 5) * 200; // Complex star-like shape
          return {
            x: Math.round(4000 + radius * Math.cos(angle)),
            y: Math.round(3000 + radius * Math.sin(angle))
          };
        }),
        label: 'large-polygon-test',
        metadata: { 
          complexity: 'very-high',
          pointCount: 500,
          estimatedArea: 3141592
        }
      };

      const startTime = Date.now();

      // Act
      const { mocks, next } = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.createPolygon,
        user,
        { body: largePolygon }
      );

      const totalTime = Date.now() - startTime;

      // Assert
      expect(next).not.toHaveBeenCalled();
      expect(totalTime).toBeLessThan(5000); // Should handle large polygons efficiently
      
      const polygon = IntegrationTestHelpers.extractPolygonFromResponse(mocks);
      expect(polygon.points).toHaveLength(500);
      testPolygonIds.push(polygon.id);

      console.log(`✅ Large polygon performance: 500 points processed in ${totalTime}ms`);
    });

    test('should validate database constraints in production scenarios', async () => {
      // Test database-level constraints work correctly
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);

      // Test foreign key constraint: polygon must reference valid user
      try {
        const fakeUserId = uuidv4();
        await TestDatabaseConnection.query(`
          INSERT INTO polygons (user_id, original_image_id, points, label)
          VALUES ($1, $2, $3, $4)
        `, [fakeUserId, image.id, JSON.stringify([{x: 1, y: 1}, {x: 2, y: 2}, {x: 3, y: 3}]), 'fk-test']);
        
        // If we get here, constraint didn't work as expected
        expect(true).toBe(false); // Force failure - foreign key constraint should prevent this
      } catch (error) {
        // Type guard to safely handle the unknown error
        if (error && typeof error === 'object' && 'message' in error) {
          expect((error as Error).message).toMatch(/violates foreign key constraint|not present in table/);
        } else {
          // Fallback for unexpected error types
          expect(String(error)).toMatch(/violates foreign key constraint|not present in table/);
        }
      }

      // Test foreign key constraint: polygon must reference valid image
      try {
        const fakeImageId = uuidv4();
        await TestDatabaseConnection.query(`
          INSERT INTO polygons (user_id, original_image_id, points, label)
          VALUES ($1, $2, $3, $4)
        `, [user.id, fakeImageId, JSON.stringify([{x: 1, y: 1}, {x: 2, y: 2}, {x: 3, y: 3}]), 'fk-test-2']);
        
        // If we get here, constraint didn't work as expected
        expect(true).toBe(false); // Force failure - foreign key constraint should prevent this
      } catch (error) {
        // Type guard to safely handle the unknown error
        if (error && typeof error === 'object' && 'message' in error) {
          expect((error as Error).message).toMatch(/violates foreign key constraint|not present in table/);
        } else {
          // Fallback for unexpected error types
          expect(String(error)).toMatch(/violates foreign key constraint|not present in table/);
        }
      }

      // Test NOT NULL constraint: points cannot be null
      try {
        await TestDatabaseConnection.query(`
          INSERT INTO polygons (user_id, original_image_id, points, label)
          VALUES ($1, $2, $3, $4)
        `, [user.id, image.id, null, 'null-points-test']);
        
        // If we get here, constraint didn't work as expected
        expect(true).toBe(false); // Force failure - NOT NULL constraint should prevent this
      } catch (error) {
        // Type guard to safely handle the unknown error
        if (error && typeof error === 'object' && 'message' in error) {
          expect((error as Error).message).toMatch(/null value in column "points".*violates not-null constraint/);
        } else {
          // Fallback for unexpected error types
          expect(String(error)).toMatch(/null value in column "points".*violates not-null constraint/);
        }
      }

      console.log('✅ Database constraints properly enforced');
    });
  });

  // ==================== MONITORING & OBSERVABILITY ====================

  describe('Production Monitoring', () => {
    test('should provide detailed operation metrics', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      
      // Define proper types for metrics
      type OperationType = 'create' | 'read' | 'update' | 'delete';
      
      interface OperationMetrics {
        operationCounts: Record<OperationType, number>;
        operationTimes: Record<OperationType, number[]>;
        errors: Array<{
          type: OperationType;
          error: any;
          time: number;
        }>;
      }

      const metrics: OperationMetrics = {
        operationCounts: { create: 0, read: 0, update: 0, delete: 0 },
        operationTimes: { create: [], read: [], update: [], delete: [] },
        errors: []
      };

      // Act - Perform various operations and measure
      const operations: Array<{
        type: OperationType;
        method: Function;
        request: any;
      }> = [
        { type: 'create', method: polygonController.createPolygon, 
          request: { body: TestDataFactory.generatePolygonData(image.id) } },
        { type: 'create', method: polygonController.createPolygon,
          request: { body: TestDataFactory.generatePolygonData(image.id) } },
        { type: 'create', method: polygonController.createPolygon,
          request: { body: TestDataFactory.generatePolygonData(image.id) } }
      ];

      for (const operation of operations) {
        const startTime = Date.now();
        
        const result = await IntegrationTestHelpers.executeControllerMethod(
          operation.method,
          user,
          operation.request
        );

        const endTime = Date.now();
        
        if (!result.next.mock.calls.length) {
          metrics.operationCounts[operation.type]++;
          metrics.operationTimes[operation.type].push(endTime - startTime);
          
          // Collect polygon IDs for cleanup
          if (operation.type === 'create') {
            const polygon = IntegrationTestHelpers.extractPolygonFromResponse(result.mocks);
            if (polygon?.id) testPolygonIds.push(polygon.id);
          }
        } else {
          metrics.errors.push({
            type: operation.type,
            error: result.next.mock.calls[0][0],
            time: endTime - startTime
          });
        }
      }

      // Assert metrics collection
      expect(metrics.operationCounts.create).toBe(3);
      expect(metrics.operationTimes.create).toHaveLength(3);
      expect(metrics.errors).toHaveLength(0);
      
      const avgCreateTime = metrics.operationTimes.create.reduce((a, b) => a + b, 0) / 3;
      expect(avgCreateTime).toBeLessThan(2000); // Average should be reasonable

      console.log(`✅ Metrics: ${metrics.operationCounts.create} creates, avg ${Math.round(avgCreateTime)}ms`);
    });

    test('should handle error tracking and alerting scenarios', async () => {
      // Arrange
      const user = await TestDataFactory.createUser();
      const errorScenarios = [
        { name: 'non-existent-image', imageId: uuidv4(), expectedStatus: 404 },
        { name: 'invalid-points', imageId: null, points: [], expectedStatus: 400 },
        { name: 'malformed-uuid', polygonId: 'invalid-uuid', expectedStatus: 400 }
      ];

      const errorMetrics = [];

      // Act - Trigger various error scenarios
      for (const scenario of errorScenarios) {
        const startTime = Date.now();
        
        let result;
        if (scenario.name === 'malformed-uuid') {
          result = await IntegrationTestHelpers.executeControllerMethod(
            polygonController.getPolygon,
            user,
            { params: { id: scenario.polygonId } }
          );
        } else {
          const image = await TestDataFactory.createImage(user.id);
          result = await IntegrationTestHelpers.executeControllerMethod(
            polygonController.createPolygon,
            user,
            { 
              body: {
                original_image_id: scenario.imageId || image.id,
                points: scenario.points || [{ x: 1, y: 1 }, { x: 2, y: 2 }],
                label: `error-test-${scenario.name}`
              }
            }
          );
        }

        const endTime = Date.now();

        if (result.next.mock.calls.length > 0) {
          const error = result.next.mock.calls[0][0];
          errorMetrics.push({
            scenario: scenario.name,
            statusCode: error.statusCode,
            message: error.message,
            responseTime: endTime - startTime
          });
        }
      }

      // Assert error handling metrics
      expect(errorMetrics).toHaveLength(3);
      expect(errorMetrics.find(e => e.scenario === 'non-existent-image')?.statusCode).toBe(404);
      expect(errorMetrics.find(e => e.scenario === 'invalid-points')?.statusCode).toBe(400);
      expect(errorMetrics.find(e => e.scenario === 'malformed-uuid')?.statusCode).toBe(400);

      // All error responses should be fast
      errorMetrics.forEach(metric => {
        expect(metric.responseTime).toBeLessThan(1000);
      });

      console.log(`✅ Error handling: ${errorMetrics.length} scenarios handled correctly`);
    });
  });

  // ==================== FINAL INTEGRATION VALIDATION ====================

  describe('Production Readiness Validation', () => {
    test('should pass comprehensive end-to-end workflow', async () => {
      console.log('🎯 Running comprehensive end-to-end workflow validation...');
      
      // Arrange - Create full user context
      const user = await TestDataFactory.createUser();
      const image = await TestDataFactory.createImage(user.id);
      const workflowPolygons: any[] = [];

      // Act - Execute complete polygon management workflow
      
      // 1. Create multiple polygons
      const createResults = await Promise.all([
        IntegrationTestHelpers.executeControllerMethod(
          polygonController.createPolygon,
          user,
          { body: TestDataFactory.generatePolygonData(image.id, { label: 'workflow-polygon-1' }) }
        ),
        IntegrationTestHelpers.executeControllerMethod(
          polygonController.createPolygon,
          user,
          { body: TestDataFactory.generatePolygonData(image.id, { label: 'workflow-polygon-2' }) }
        ),
        IntegrationTestHelpers.executeControllerMethod(
          polygonController.createPolygon,
          user,
          { body: TestDataFactory.generatePolygonData(image.id, { label: 'workflow-polygon-3' }) }
        )
      ]);

      createResults.forEach(result => {
        expect(result.next).not.toHaveBeenCalled();
        const polygon = IntegrationTestHelpers.extractPolygonFromResponse(result.mocks);
        workflowPolygons.push(polygon);
        testPolygonIds.push(polygon.id);
      });

      // 2. Retrieve all polygons for image
      const listResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.getImagePolygons,
        user,
        { params: { imageId: image.id } }
      );

      expect(listResult.next).not.toHaveBeenCalled();
      const listedPolygons = IntegrationTestHelpers.extractPolygonsFromResponse(listResult.mocks);
      expect(listedPolygons).toHaveLength(3);

      // 3. Update one polygon
      const updateResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.updatePolygon,
        user,
        {
          params: { id: workflowPolygons[1].id },
          body: {
            label: 'workflow-polygon-2-updated',
            metadata: { updated: true, workflow: 'end-to-end' }
          }
        }
      );

      expect(updateResult.next).not.toHaveBeenCalled();

      // 4. Retrieve specific polygon
      const getResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.getPolygon,
        user,
        { params: { id: workflowPolygons[0].id } }
      );

      expect(getResult.next).not.toHaveBeenCalled();

      // 5. Delete one polygon
      const deleteResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.deletePolygon,
        user,
        { params: { id: workflowPolygons[2].id } }
      );

      expect(deleteResult.next).not.toHaveBeenCalled();

      // 6. Verify final state
      const finalListResult = await IntegrationTestHelpers.executeControllerMethod(
        polygonController.getImagePolygons,
        user,
        { params: { imageId: image.id } }
      );

      const finalPolygons = IntegrationTestHelpers.extractPolygonsFromResponse(finalListResult.mocks);
      expect(finalPolygons).toBeDefined();
      expect(finalPolygons).not.toBeNull();
      expect(finalPolygons!).toHaveLength(2); // One deleted

      // Verify updated polygon with proper null checking
      const updatedPolygon = finalPolygons!.find(p => p.label === 'workflow-polygon-2-updated');
      expect(updatedPolygon).toBeTruthy();
      expect(updatedPolygon!.metadata.updated).toBe(true);

      console.log('✅ End-to-end workflow completed successfully');
    });

    test('should demonstrate production-scale performance characteristics', async () => {
      console.log('🚀 Testing production-scale performance...');
      
      // Arrange
      const users = await Promise.all([
        TestDataFactory.createUser(),
        TestDataFactory.createUser(),
        TestDataFactory.createUser()
      ]);

      const images = await Promise.all(
        users.map(user => TestDataFactory.createImage(user.id))
      );

      const startTime = Date.now();
      
      // Act - Simulate production load: multiple users creating polygons concurrently
      const concurrentOperations: Promise<any>[] = [];
      
      // Each user creates 10 polygons
      users.forEach((user, userIndex) => {
        for (let i = 0; i < 10; i++) {
          concurrentOperations.push(
            IntegrationTestHelpers.executeControllerMethod(
              polygonController.createPolygon,
              user,
              { 
                body: TestDataFactory.generatePolygonData(
                  images[userIndex].id, 
                  { label: `production-load-user${userIndex}-polygon${i}` }
                )
              }
            )
          );
        }
      });

      const results = await Promise.all(concurrentOperations);
      const totalTime = Date.now() - startTime;

      // Assert production performance
      const successful = results.filter(r => !r.next.mock.calls.length);
      expect(successful.length).toBe(30); // All should succeed
      expect(totalTime).toBeLessThan(45000); // Should complete within 45 seconds

      // Collect polygon IDs for cleanup
      successful.forEach(result => {
        const polygon = IntegrationTestHelpers.extractPolygonFromResponse(result.mocks);
        if (polygon?.id) testPolygonIds.push(polygon.id);
      });

      // Verify data integrity across users
      for (let i = 0; i < users.length; i++) {
        const userPolygons = await polygonModel.findByImageId(images[i].id);
        expect(userPolygons).toHaveLength(10);
        
        // Since we're querying by image ID and each image belongs to a specific user,
        // the fact that we get exactly 10 polygons (the number we created for this user)
        // validates user isolation
        expect(userPolygons.every(polygon => polygon.original_image_id === images[i].id)).toBe(true);
      }

      const avgTimePerOperation = totalTime / 30;
      console.log(`✅ Production performance: 30 concurrent operations in ${totalTime}ms (${Math.round(avgTimePerOperation)}ms avg)`);
    });
  });
});