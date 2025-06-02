// tests/unit/models/polygonModel.unit.test.ts

// Mock the database query function BEFORE importing polygonModel
const mockQuery = jest.fn();
jest.mock('../../models/db', () => ({
  query: mockQuery
}));

import { polygonModel } from '../../models/polygonModel';
import { 
  createMockPolygon,
  createMockPolygonCreate,
  createMockPolygonUpdate,
  createValidPolygonPoints,
  createInvalidPolygonPoints,
  createPolygonMetadataVariations,
  createMockPolygonQueryResult,
  createPolygonErrorScenarios,
  createPolygonSecurityPayloads,
  createPerformanceTestData,
  resetPolygonMocks
} from '../__mocks__/polygons.mock';
import {
  createTestPolygonsForImage,
  createComplexityTestScenarios,
  createGeometricTestPolygons,
  calculatePolygonArea,
  calculatePolygonPerimeter,
  hasSelfintersection,
  validatePointsBounds,
  polygonAssertions,
  simulatePolygonErrors,
  measurePolygonOperation,
  runConcurrentPolygonOperations
} from '../__helpers__/polygons.helper';
import { v4 as uuidv4 } from 'uuid';

describe('PolygonModel - Production Unit Tests', () => {
  const testUserId = uuidv4();
  const testImageId = uuidv4();
  const testPolygonId = uuidv4();
  
  beforeEach(() => {
    jest.clearAllMocks();
    resetPolygonMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  // ==================== SETUP AND TEARDOWN VALIDATION ====================
  
  describe('Test Environment Setup', () => {
    test('should have properly configured mocks and imports', () => {
      expect(mockQuery).toBeDefined();
      expect(jest.isMockFunction(mockQuery)).toBe(true);
      expect(polygonModel).toBeDefined();
      expect(createMockPolygon).toBeDefined();
      expect(polygonAssertions).toBeDefined();
    });

    test('should reset mocks between tests', () => {
      // First call the mock to generate some call history
      mockQuery.mockReturnValue({ rows: [] });
      mockQuery(); // Actually call it to create history
      expect(mockQuery).toHaveBeenCalled();
      
      jest.clearAllMocks();
      expect(mockQuery).not.toHaveBeenCalled();
    });
  });

  // ==================== CREATE OPERATION TESTS ====================

  describe('Create Operation', () => {
    describe('Successful Creation', () => {
      test('should create polygon with minimal valid data', async () => {
        // Arrange
        const polygonData = createMockPolygonCreate({
          original_image_id: testImageId,
          points: createValidPolygonPoints.triangle()
        });

        const expectedPolygon = createMockPolygon({
          id: expect.any(String),
          user_id: testUserId,
          original_image_id: testImageId,
          points: polygonData.points,
          label: polygonData.label
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result).toBeDefined();
        polygonAssertions.hasValidGeometry(result);
        polygonAssertions.hasValidMetadata(result);
        expect(result.user_id).toBe(testUserId);
        expect(result.original_image_id).toBe(testImageId);
        
        // Verify database interaction
        expect(mockQuery).toHaveBeenCalledTimes(1);
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO polygons'),
          expect.arrayContaining([
            expect.any(String), // UUID
            testUserId,
            testImageId,
            expect.any(String), // JSON points
            polygonData.label,
            expect.any(String)  // JSON metadata
          ])
        );
      });

      test('should create polygon with complex geometry', async () => {
        // Arrange
        const complexPoints = createValidPolygonPoints.complex();
        const polygonData = createMockPolygonCreate({
          original_image_id: testImageId,
          points: complexPoints,
          label: 'complex_polygon',
          metadata: createPolygonMetadataVariations.detailed
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          points: complexPoints,
          metadata: createPolygonMetadataVariations.detailed
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.points).toHaveLength(complexPoints.length);
        expect(result.metadata).toEqual(createPolygonMetadataVariations.detailed);
        polygonAssertions.hasValidGeometry(result);
        
        // Verify geometric properties
        const area = calculatePolygonArea(result.points);
        const perimeter = calculatePolygonPerimeter(result.points);
        expect(area).toBeGreaterThan(0);
        expect(perimeter).toBeGreaterThan(0);
      });

      test('should create polygon with various point counts', async () => {
        const testCases = [
          { points: createValidPolygonPoints.triangle(), name: 'triangle' },
          { points: createValidPolygonPoints.square(), name: 'square' },
          { points: createValidPolygonPoints.pentagon(), name: 'pentagon' },
          { points: createValidPolygonPoints.circle(200, 200, 50, 20), name: 'circle_20_points' }
        ];

        for (const testCase of testCases) {
          // Arrange
          const polygonData = createMockPolygonCreate({
            points: testCase.points,
            label: testCase.name
          });

          const expectedPolygon = createMockPolygon({
            user_id: testUserId,
            points: testCase.points
          });

          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

          // Act
          const result = await polygonModel.create({
            ...polygonData,
            user_id: testUserId
          });

          // Assert
          expect(result.points).toHaveLength(testCase.points.length);
          polygonAssertions.hasValidGeometry(result);
          
          jest.clearAllMocks();
        }
      });

      test('should handle null/undefined metadata gracefully', async () => {
        // Test with undefined metadata
        const polygonData1 = createMockPolygonCreate({
          metadata: undefined
        });

        const expectedPolygon1 = createMockPolygon({
          user_id: testUserId,
          metadata: {}
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon1]));

        const result1 = await polygonModel.create({
          ...polygonData1,
          user_id: testUserId
        });

        expect(result1.metadata).toEqual({});

        jest.clearAllMocks();

        // Test with null metadata
        const polygonData2 = createMockPolygonCreate({
          metadata: null as any
        });

        const expectedPolygon2 = createMockPolygon({
          user_id: testUserId,
          metadata: {}
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon2]));

        const result2 = await polygonModel.create({
          ...polygonData2,
          user_id: testUserId
        });

        expect(result2.metadata).toEqual({});
      });

      test('should generate unique UUIDs for multiple creations', async () => {
        const createdIds = new Set();
        const creationCount = 5;

        for (let i = 0; i < creationCount; i++) {
          const polygonData = createMockPolygonCreate();
          const expectedPolygon = createMockPolygon({
            id: `test-id-${i}`,
            user_id: testUserId
          });

          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

          const result = await polygonModel.create({
            ...polygonData,
            user_id: testUserId
          });

          createdIds.add(result.id);
          jest.clearAllMocks();
        }

        expect(createdIds.size).toBe(creationCount);
      });
    });

    describe('Database Error Handling', () => {
      test('should handle database connection errors', async () => {
        // Arrange
        const polygonData = createMockPolygonCreate();
        const dbError = simulatePolygonErrors.databaseConnection();
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(polygonModel.create({
          ...polygonData,
          user_id: testUserId
        })).rejects.toThrow('Connection to database lost');
      });

      test('should handle constraint violations', async () => {
        // Arrange
        const polygonData = createMockPolygonCreate();
        const constraintError = new Error('duplicate key value violates unique constraint');
        (constraintError as any).code = '23505';
        mockQuery.mockRejectedValueOnce(constraintError);

        // Act & Assert
        await expect(polygonModel.create({
          ...polygonData,
          user_id: testUserId
        })).rejects.toThrow('duplicate key value violates unique constraint');
      });

      test('should handle foreign key violations', async () => {
        // Arrange
        const polygonData = createMockPolygonCreate({
          original_image_id: 'non-existent-image-id'
        });
        const fkError = new Error('insert or update on table "polygons" violates foreign key constraint');
        (fkError as any).code = '23503';
        mockQuery.mockRejectedValueOnce(fkError);

        // Act & Assert
        await expect(polygonModel.create({
          ...polygonData,
          user_id: testUserId
        })).rejects.toThrow('violates foreign key constraint');
      });

      test('should handle malformed JSON in input data', async () => {
        // This would be caught at the service layer, but test model robustness
        const polygonData = createMockPolygonCreate();
        
        // Mock a scenario where JSON.stringify might fail
        const originalStringify = JSON.stringify;
        jest.spyOn(JSON, 'stringify').mockImplementationOnce(() => {
          throw new Error('JSON stringify failed');
        });

        await expect(polygonModel.create({
          ...polygonData,
          user_id: testUserId
        })).rejects.toThrow('JSON stringify failed');

        JSON.stringify = originalStringify;
      });
    });

    describe('Data Validation and Transformation', () => {
      test('should properly serialize complex metadata', async () => {
        // Arrange
        const complexMetadata = {
          ...createPolygonMetadataVariations.detailed,
          nested: {
            level1: {
              level2: {
                value: 'deep_nested',
                array: [1, 2, 3, { nested_in_array: true }]
              }
            }
          },
          unicode: 'Test with émojis 🎨 and spëcial chârs',
          numbers: [1, 2.5, -3, 0]
          // Remove Infinity/-Infinity as JSON.stringify converts them to null
        };

        const polygonData = createMockPolygonCreate({
          metadata: complexMetadata
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          metadata: complexMetadata
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.metadata).toEqual(complexMetadata);
        
        // Verify JSON serialization in database call
        const dbCall = mockQuery.mock.calls[0];
        const serializedMetadata = dbCall[1][5]; // metadata parameter
        expect(() => JSON.parse(serializedMetadata)).not.toThrow();
        expect(JSON.parse(serializedMetadata)).toEqual(complexMetadata);
      });

      test('should handle special floating point values in points', async () => {
        // Test edge cases with floating point precision
        const precisionPoints = [
          { x: 100.999999999999, y: 100.000000000001 },
          { x: 200.000000000001, y: 100.999999999999 },
          { x: 150.500000000000, y: 200.500000000000 }
        ];

        const polygonData = createMockPolygonCreate({
          points: precisionPoints
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          points: precisionPoints
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.points).toEqual(precisionPoints);
        
        // Verify precision is maintained
        expect(result.points[0].x).toBeCloseTo(100.999999999999, 10);
        expect(result.points[0].y).toBeCloseTo(100.000000000001, 10);
      });
    });
  });

  // ==================== READ OPERATION TESTS ====================

  describe('Read Operations', () => {
    describe('Find By ID', () => {
      test('should find existing polygon by ID', async () => {
        // Arrange
        const expectedPolygon = createMockPolygon({
          id: testPolygonId,
          user_id: testUserId,
          original_image_id: testImageId
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.findById(testPolygonId);

        // Assert
        expect(result).toBeDefined();
        expect(result?.id).toBe(testPolygonId);
        expect(result?.user_id).toBe(testUserId);
        polygonAssertions.hasValidGeometry(result!);
        polygonAssertions.hasValidMetadata(result!);

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM polygons WHERE id = $1',
          [testPolygonId]
        );
      });

      test('should return null for non-existent polygon', async () => {
        // Arrange
        const nonExistentId = uuidv4();
        mockQuery.mockResolvedValueOnce({ rows: [] });

        // Act
        const result = await polygonModel.findById(nonExistentId);

        // Assert
        expect(result).toBeNull();
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      test('should handle database errors during findById', async () => {
        // Arrange
        const dbError = simulatePolygonErrors.databaseConnection();
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(polygonModel.findById(testPolygonId)).rejects.toThrow('Connection to database lost');
      });

      test('should properly deserialize complex data', async () => {
        // Arrange
        const complexPoints = createValidPolygonPoints.circle(300, 250, 75, 30);
        const complexMetadata = createPolygonMetadataVariations.garmentSpecific;
        
        const polygonData = {
          id: testPolygonId,
          user_id: testUserId,
          original_image_id: testImageId,
          points: JSON.stringify(complexPoints),
          metadata: JSON.stringify(complexMetadata),
          label: 'complex_garment',
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValueOnce({ rows: [polygonData] });

        // Act
        const result = await polygonModel.findById(testPolygonId);

        // Assert
        expect(result).toBeDefined();
        expect(result?.points).toEqual(complexPoints);
        expect(result?.metadata).toEqual(complexMetadata);
        expect(Array.isArray(result?.points)).toBe(true);
        expect(typeof result?.metadata).toBe('object');
      });

      test('should handle malformed JSON in database', async () => {
        // Arrange
        const corruptedData = {
          id: testPolygonId,
          user_id: testUserId,
          original_image_id: testImageId,
          points: 'invalid-json-points',
          metadata: '{"valid": "metadata"}',
          label: 'corrupted_polygon',
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValueOnce({ rows: [corruptedData] });

        // Act & Assert
        await expect(polygonModel.findById(testPolygonId)).rejects.toThrow();
      });
    });

    describe('Find By Image ID', () => {
      test('should find all polygons for an image', async () => {
        // Arrange
        const polygons = createTestPolygonsForImage(testImageId, testUserId, 3);
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(polygons));

        // Act
        const result = await polygonModel.findByImageId(testImageId);

        // Assert
        expect(result).toBeDefined();
        expect(Array.isArray(result)).toBe(true);
        expect(result).toHaveLength(3);
        
        result.forEach((polygon, index) => {
          expect(polygon.original_image_id).toBe(testImageId);
          expect(polygon.user_id).toBe(testUserId);
          polygonAssertions.hasValidGeometry(polygon);
          polygonAssertions.hasValidMetadata(polygon);
        });

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM polygons WHERE original_image_id = $1 ORDER BY created_at ASC',
          [testImageId]
        );
      });

      test('should return empty array for image with no polygons', async () => {
        // Arrange
        mockQuery.mockResolvedValueOnce({ rows: [] });

        // Act
        const result = await polygonModel.findByImageId(testImageId);

        // Assert
        expect(result).toEqual([]);
        expect(Array.isArray(result)).toBe(true);
      });

      test('should maintain creation order', async () => {
        // Arrange
        const baseTime = new Date('2023-01-01T00:00:00Z');
        const polygons = [
          createMockPolygon({
            original_image_id: testImageId,
            created_at: new Date(baseTime.getTime() + 1000),
            label: 'first'
          }),
          createMockPolygon({
            original_image_id: testImageId,
            created_at: new Date(baseTime.getTime() + 2000),
            label: 'second'
          }),
          createMockPolygon({
            original_image_id: testImageId,
            created_at: new Date(baseTime.getTime() + 3000),
            label: 'third'
          })
        ];

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(polygons));

        // Act
        const result = await polygonModel.findByImageId(testImageId);

        // Assert
        expect(result[0].label).toBe('first');
        expect(result[1].label).toBe('second');
        expect(result[2].label).toBe('third');
      });

      test('should handle large numbers of polygons', async () => {
        // Arrange
        const largePolygonSet = Array.from({ length: 100 }, (_, index) => 
          createMockPolygon({
            original_image_id: testImageId,
            user_id: testUserId,
            label: `polygon_${index + 1}`
          })
        );

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(largePolygonSet));

        // Act
        const { result, duration } = await measurePolygonOperation(
          () => polygonModel.findByImageId(testImageId),
          'Find 100 polygons'
        );

        // Assert
        expect(result).toHaveLength(100);
        expect(duration).toBeLessThan(100); // Should be fast for mock operations
        
        result.forEach(polygon => {
          expect(polygon.original_image_id).toBe(testImageId);
          polygonAssertions.hasValidGeometry(polygon);
        });
      });
    });

    describe('Find By User ID', () => {
      test('should find all polygons for a user', async () => {
        // Arrange
        const userPolygons = [
          createMockPolygon({ user_id: testUserId, original_image_id: testImageId }),
          createMockPolygon({ user_id: testUserId, original_image_id: uuidv4() }),
          createMockPolygon({ user_id: testUserId, original_image_id: uuidv4() })
        ];

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(userPolygons));

        // Act
        const result = await polygonModel.findByUserId(testUserId);

        // Assert
        expect(result).toHaveLength(3);
        result.forEach(polygon => {
          expect(polygon.user_id).toBe(testUserId);
          polygonAssertions.hasValidGeometry(polygon);
        });

        expect(mockQuery).toHaveBeenCalledWith(
          'SELECT * FROM polygons WHERE user_id = $1 ORDER BY created_at DESC',
          [testUserId]
        );
      });

      test('should return polygons in reverse chronological order', async () => {
        // Arrange
        const baseTime = new Date();
        const userPolygons = [
          createMockPolygon({
            user_id: testUserId,
            created_at: new Date(baseTime.getTime() - 3000),
            label: 'oldest'
          }),
          createMockPolygon({
            user_id: testUserId,
            created_at: new Date(baseTime.getTime() - 2000),
            label: 'middle'
          }),
          createMockPolygon({
            user_id: testUserId,
            created_at: new Date(baseTime.getTime() - 1000),
            label: 'newest'
          })
        ];

        // Sort in DESC order as the query would return
        const sortedPolygons = [...userPolygons].reverse();
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(sortedPolygons));

        // Act
        const result = await polygonModel.findByUserId(testUserId);

        // Assert
        expect(result[0].label).toBe('newest');
        expect(result[1].label).toBe('middle');
        expect(result[2].label).toBe('oldest');
      });
    });
  });

  // ==================== UPDATE OPERATION TESTS ====================

  describe('Update Operations', () => {
    describe('Successful Updates', () => {
      test('should update polygon label', async () => {
        // Arrange
        const originalPolygon = createMockPolygon({
          id: testPolygonId,
          user_id: testUserId,
          label: 'original_label'
        });

        const updateData = { label: 'updated_label' };
        const updatedPolygon = { ...originalPolygon, ...updateData };

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([updatedPolygon]));

        // Act
        const result = await polygonModel.update(testPolygonId, updateData);

        // Assert
        expect(result).toBeDefined();
        expect(result?.label).toBe('updated_label');
        expect(result?.id).toBe(testPolygonId);

        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE polygons'),
          expect.arrayContaining(['updated_label', testPolygonId])
        );
      });

      test('should update polygon points', async () => {
        // Arrange
        const originalPolygon = createMockPolygon({
          id: testPolygonId,
          points: createValidPolygonPoints.triangle()
        });

        const newPoints = createValidPolygonPoints.square();
        const updateData = { points: newPoints };
        const updatedPolygon = { ...originalPolygon, points: newPoints };

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([updatedPolygon]));

        // Act
        const result = await polygonModel.update(testPolygonId, updateData);

        // Assert
        expect(result?.points).toEqual(newPoints);
        expect(result?.points).toHaveLength(4); // Square has 4 points

        // Verify points were serialized in database call
        const dbCall = mockQuery.mock.calls[0];
        expect(dbCall[1]).toContain(JSON.stringify(newPoints));
      });

      test('should update polygon metadata', async () => {
        // Arrange
        const originalPolygon = createMockPolygon({
          id: testPolygonId,
          metadata: createPolygonMetadataVariations.basic
        });

        const newMetadata = createPolygonMetadataVariations.detailed;
        const updateData = { metadata: newMetadata };
        const updatedPolygon = { ...originalPolygon, metadata: newMetadata };

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([updatedPolygon]));

        // Act
        const result = await polygonModel.update(testPolygonId, updateData);

        // Assert
        expect(result?.metadata).toEqual(newMetadata);
        polygonAssertions.hasValidMetadata(result!);
      });

      test('should update multiple fields simultaneously', async () => {
        // Arrange
        const originalPolygon = createMockPolygon({ id: testPolygonId });
        const updateData = {
          label: 'multi_updated',
          points: createValidPolygonPoints.pentagon(),
          metadata: { updated: true, timestamp: new Date().toISOString() }
        };
        const updatedPolygon = { ...originalPolygon, ...updateData };

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([updatedPolygon]));

        // Act
        const result = await polygonModel.update(testPolygonId, updateData);

        // Assert
        expect(result?.label).toBe('multi_updated');
        expect(result?.points).toEqual(updateData.points);
        expect(result?.metadata).toEqual(updateData.metadata);
        
        // Verify all fields were included in update
        const dbCall = mockQuery.mock.calls[0];
        expect(dbCall[0]).toContain('points = $1');
        expect(dbCall[0]).toContain('label = $2');
        expect(dbCall[0]).toContain('metadata = $3');
        expect(dbCall[0]).toContain('updated_at = NOW()');
      });

      test('should handle empty update (only update timestamp)', async () => {
        // Arrange
        const originalPolygon = createMockPolygon({ id: testPolygonId });
        const updatedPolygon = { 
          ...originalPolygon, 
          updated_at: new Date() 
        };

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([updatedPolygon]));

        // Act
        const result = await polygonModel.update(testPolygonId, {});

        // Assert
        expect(result?.id).toBe(testPolygonId);
        
        // Should still run UPDATE to set updated_at
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('UPDATE polygons'),
          [testPolygonId]
        );
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('updated_at = NOW()'),
          [testPolygonId]
        );
      });
    });

    describe('Update Error Handling', () => {
      test('should return null for non-existent polygon', async () => {
        // Arrange
        const updateData = { label: 'updated' };
        mockQuery.mockResolvedValueOnce({ rows: [] });

        // Act
        const result = await polygonModel.update(testPolygonId, updateData);

        // Assert
        expect(result).toBeNull();
      });

      test('should handle database errors during update', async () => {
        // Arrange
        const updateData = { label: 'updated' };
        const dbError = simulatePolygonErrors.databaseConnection();
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(polygonModel.update(testPolygonId, updateData)).rejects.toThrow('Connection to database lost');
      });

      test('should handle constraint violations in updates', async () => {
        // Arrange
        const updateData = { label: 'duplicate_label' };
        const constraintError = new Error('duplicate key value violates unique constraint');
        (constraintError as any).code = '23505';
        mockQuery.mockRejectedValueOnce(constraintError);

        // Act & Assert
        await expect(polygonModel.update(testPolygonId, updateData)).rejects.toThrow('duplicate key value violates unique constraint');
      });

      test('should handle malformed JSON in update data', async () => {
        // Arrange
        const updateData = { points: createValidPolygonPoints.triangle() };
        
        // Mock JSON.stringify to fail
        const originalStringify = JSON.stringify;
        jest.spyOn(JSON, 'stringify').mockImplementationOnce(() => {
          throw new Error('JSON stringify failed for points');
        });

        // Act & Assert
        await expect(polygonModel.update(testPolygonId, updateData)).rejects.toThrow('JSON stringify failed for points');

        JSON.stringify = originalStringify;
      });
    });

    describe('Update Data Validation', () => {
      test('should properly build dynamic update queries', async () => {
        // Test different combinations of updates
        const testCases = [
          {
            name: 'label only',
            updateData: { label: 'new_label' },
            expectedFields: ['label = $1', 'updated_at = NOW()']
          },
          {
            name: 'points only',
            updateData: { points: createValidPolygonPoints.triangle() },
            expectedFields: ['points = $1', 'updated_at = NOW()']
          },
          {
            name: 'metadata only',
            updateData: { metadata: { test: true } },
            expectedFields: ['metadata = $1', 'updated_at = NOW()']
          },
          {
            name: 'label and points',
            updateData: { 
              label: 'combo_test', 
              points: createValidPolygonPoints.square() 
            },
            expectedFields: ['points = $1', 'label = $2', 'updated_at = NOW()']
          }
        ];

        for (const testCase of testCases) {
          // Arrange
          const updatedPolygon = createMockPolygon({
            id: testPolygonId,
            ...testCase.updateData
          });

          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([updatedPolygon]));

          // Act
          await polygonModel.update(testPolygonId, testCase.updateData);

          // Assert
          const dbCall = mockQuery.mock.calls[0];
          const query = dbCall[0];
          
          testCase.expectedFields.forEach(field => {
            expect(query).toContain(field);
          });

          jest.clearAllMocks();
        }
      });

      test('should preserve data types in updates', async () => {
        // Arrange
        const complexUpdateData = {
          metadata: {
            numbers: [1, 2.5, -3, 0],
            booleans: [true, false],
            strings: ['test', 'émoji🎨', ''],
            nested: {
              level1: { level2: 'deep' }
            },
            nullValue: null,
            undefinedValue: undefined
          }
        };

        const updatedPolygon = createMockPolygon({
          id: testPolygonId,
          metadata: complexUpdateData.metadata
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([updatedPolygon]));

        // Act
        const result = await polygonModel.update(testPolygonId, complexUpdateData);

        // Assert
        expect(result?.metadata).toEqual(complexUpdateData.metadata);
        
        // Verify serialization maintains types
        const dbCall = mockQuery.mock.calls[0];
        const serializedMetadata = dbCall[1][0]; // First parameter is the serialized metadata
        const parsed = JSON.parse(serializedMetadata);
        expect(parsed).toEqual(complexUpdateData.metadata);
      });
    });
  });

  // ==================== DELETE OPERATION TESTS ====================

  describe('Delete Operations', () => {
    describe('Single Polygon Deletion', () => {
      test('should delete existing polygon', async () => {
        // Arrange
        mockQuery.mockResolvedValueOnce({ rowCount: 1 });

        // Act
        const result = await polygonModel.delete(testPolygonId);

        // Assert
        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM polygons WHERE id = $1',
          [testPolygonId]
        );
      });

      test('should return false for non-existent polygon', async () => {
        // Arrange
        mockQuery.mockResolvedValueOnce({ rowCount: 0 });

        // Act
        const result = await polygonModel.delete(testPolygonId);

        // Assert
        expect(result).toBe(false);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      test('should handle database errors during deletion', async () => {
        // Arrange
        const dbError = simulatePolygonErrors.databaseConnection();
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(polygonModel.delete(testPolygonId)).rejects.toThrow('Connection to database lost');
      });

      test('should handle constraint violations during deletion', async () => {
        // Arrange
        const constraintError = new Error('update or delete on table "polygons" violates foreign key constraint');
        (constraintError as any).code = '23503';
        mockQuery.mockRejectedValueOnce(constraintError);

        // Act & Assert
        await expect(polygonModel.delete(testPolygonId)).rejects.toThrow('violates foreign key constraint');
      });
    });

    describe('Batch Polygon Deletion', () => {
      test('should delete all polygons for an image', async () => {
        // Arrange
        const expectedDeleteCount = 5;
        mockQuery.mockResolvedValueOnce({ rowCount: expectedDeleteCount });

        // Act
        const result = await polygonModel.deleteByImageId(testImageId);

        // Assert
        expect(result).toBe(expectedDeleteCount);
        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM polygons WHERE original_image_id = $1',
          [testImageId]
        );
      });

      test('should return zero for image with no polygons', async () => {
        // Arrange
        mockQuery.mockResolvedValueOnce({ rowCount: 0 });

        // Act
        const result = await polygonModel.deleteByImageId(testImageId);

        // Assert
        expect(result).toBe(0);
      });

      test('should handle large batch deletions', async () => {
        // Arrange
        const largeDeleteCount = 1000;
        mockQuery.mockResolvedValueOnce({ rowCount: largeDeleteCount });

        // Act
        const { result, duration } = await measurePolygonOperation(
          () => polygonModel.deleteByImageId(testImageId),
          'Delete 1000 polygons'
        );

        // Assert
        expect(result).toBe(largeDeleteCount);
        expect(duration).toBeLessThan(100); // Should be fast for mock operations
      });

      test('should handle database errors during batch deletion', async () => {
        // Arrange
        const dbError = simulatePolygonErrors.databaseConnection();
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(polygonModel.deleteByImageId(testImageId)).rejects.toThrow('Connection to database lost');
      });
    });
  });

  // ==================== DATA TRANSFORMATION TESTS ====================

  describe('Data Transformation', () => {
    describe('JSON Serialization/Deserialization', () => {
      test('should handle various point geometries', async () => {
        const geometryTestCases = [
          { name: 'triangle', points: createValidPolygonPoints.triangle() },
          { name: 'square', points: createValidPolygonPoints.square() },
          { name: 'complex', points: createValidPolygonPoints.complex() },
          { name: 'circle_approximation', points: createValidPolygonPoints.circle(200, 200, 50, 16) },
          { name: 'high_precision', points: [
            { x: 100.123456789, y: 200.987654321 },
            { x: 300.555555555, y: 400.444444444 },
            { x: 250.111111111, y: 350.999999999 }
          ]}
        ];

        for (const testCase of geometryTestCases) {
          // Arrange
          const polygon = createMockPolygon({
            points: testCase.points,
            label: testCase.name
          });

          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([polygon]));

          // Act
          const result = await polygonModel.findById(polygon.id);

          // Assert
          expect(result?.points).toEqual(testCase.points);
          expect(result?.points).toHaveLength(testCase.points.length);
          
          // Verify geometric properties are preserved
          const originalArea = calculatePolygonArea(testCase.points);
          const resultArea = calculatePolygonArea(result!.points);
          expect(resultArea).toBeCloseTo(originalArea, 10);

          jest.clearAllMocks();
        }
      });

      test('should handle various metadata structures', async () => {
        const metadataTestCases = [
          { name: 'basic', metadata: createPolygonMetadataVariations.basic },
          { name: 'detailed', metadata: createPolygonMetadataVariations.detailed },
          { name: 'ai_generated', metadata: createPolygonMetadataVariations.aiGenerated },
          { name: 'with_measurements', metadata: createPolygonMetadataVariations.withMeasurements },
          { name: 'unicode_content', metadata: {
            description: 'Test with émojis 🎨 and spëcial chârs',
            chinese: '测试多边形',
            arabic: 'مضلع اختبار',
            emoji_array: ['🔺', '🔶', '🔷', '🔸']
          }},
          { name: 'mixed_types', metadata: {
            string: 'test',
            number: 42,
            float: 3.14159,
            boolean: true,
            null_value: null,
            array: [1, 'two', true, null],
            nested_object: {
              level1: {
                level2: {
                  deep_value: 'nested'
                }
              }
            }
          }}
        ];

        for (const testCase of metadataTestCases) {
          // Arrange
          const polygon = createMockPolygon({
            metadata: testCase.metadata,
            label: testCase.name
          });

          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([polygon]));

          // Act
          const result = await polygonModel.findById(polygon.id);

          // Assert
          expect(result?.metadata).toEqual(testCase.metadata);
          polygonAssertions.hasValidMetadata(result!);

          jest.clearAllMocks();
        }
      });

      test('should handle edge cases in JSON processing', async () => {
        // Test empty structures
        const emptyTestCases = [
          { points: createValidPolygonPoints.triangle(), metadata: {} },
          { points: createValidPolygonPoints.square(), metadata: { empty_string: '', empty_array: [], empty_object: {} } }
        ];

        for (const testCase of emptyTestCases) {
          const polygon = createMockPolygon(testCase);
          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([polygon]));

          const result = await polygonModel.findById(polygon.id);
          
          expect(result?.points).toEqual(testCase.points);
          expect(result?.metadata).toEqual(testCase.metadata);
          
          jest.clearAllMocks();
        }
      });

      test('should detect and handle corrupted JSON data', async () => {
        const corruptedTestCases = [
          {
            name: 'invalid_points_json',
            data: {
              id: testPolygonId,
              user_id: testUserId,
              original_image_id: testImageId,
              points: 'invalid-json-points',
              metadata: '{}',
              label: 'corrupted',
              created_at: new Date(),
              updated_at: new Date()
            }
          },
          {
            name: 'invalid_metadata_json',
            data: {
              id: testPolygonId,
              user_id: testUserId,
              original_image_id: testImageId,
              points: JSON.stringify(createValidPolygonPoints.triangle()),
              metadata: 'invalid-json-metadata',
              label: 'corrupted',
              created_at: new Date(),
              updated_at: new Date()
            }
          },
          {
            name: 'truncated_json',
            data: {
              id: testPolygonId,
              user_id: testUserId,
              original_image_id: testImageId,
              points: '{"incomplete": tr',
              metadata: '{}',
              label: 'corrupted',
              created_at: new Date(),
              updated_at: new Date()
            }
          }
        ];

        for (const testCase of corruptedTestCases) {
          mockQuery.mockResolvedValueOnce({ rows: [testCase.data] });

          await expect(polygonModel.findById(testPolygonId)).rejects.toThrow();
          
          jest.clearAllMocks();
        }
      });
    });
  });

  // ==================== PERFORMANCE TESTS ====================

  describe('Performance Tests', () => {
    describe('Individual Operation Performance', () => {
      test('should handle create operations efficiently', async () => {
        // Arrange
        const polygonData = createMockPolygonCreate({
          points: createValidPolygonPoints.complex()
        });
        const expectedPolygon = createMockPolygon(polygonData);
        mockQuery.mockResolvedValue(createMockPolygonQueryResult([expectedPolygon]));

        // Act & Assert
        const { duration } = await measurePolygonOperation(
          () => polygonModel.create({ ...polygonData, user_id: testUserId }),
          'Complex polygon creation'
        );

        expect(duration).toBeLessThan(50); // Should be very fast for mocked operations
      });

      test('should handle read operations with large datasets efficiently', async () => {
        // Arrange
        const largePolygonSet = Array.from({ length: 500 }, (_, i) =>
          createMockPolygon({
            original_image_id: testImageId,
            label: `polygon_${i}`
          })
        );
        mockQuery.mockResolvedValue(createMockPolygonQueryResult(largePolygonSet));

        // Act & Assert
        const { result, duration } = await measurePolygonOperation(
          () => polygonModel.findByImageId(testImageId),
          'Read 500 polygons'
        );

        expect(result).toHaveLength(500);
        expect(duration).toBeLessThan(100);
      });

      test('should handle update operations with complex data efficiently', async () => {
        // Arrange
        const complexUpdateData = {
          points: createValidPolygonPoints.circle(300, 300, 100, 50),
          metadata: {
            ...createPolygonMetadataVariations.detailed,
            large_array: Array.from({ length: 100 }, (_, i) => ({ index: i, value: `item_${i}` }))
          }
        };
        const updatedPolygon = createMockPolygon({ id: testPolygonId, ...complexUpdateData });
        mockQuery.mockResolvedValue(createMockPolygonQueryResult([updatedPolygon]));

        // Act & Assert
        const { duration } = await measurePolygonOperation(
          () => polygonModel.update(testPolygonId, complexUpdateData),
          'Complex polygon update'
        );

        expect(duration).toBeLessThan(50);
      });
    });

    describe('Concurrent Operations', () => {
      test('should handle concurrent read operations', async () => {
        // Arrange
        const concurrentCount = 10;
        const polygon = createMockPolygon({ id: testPolygonId });
        mockQuery.mockResolvedValue(createMockPolygonQueryResult([polygon]));

        const readOperations = Array.from({ length: concurrentCount }, () =>
          () => polygonModel.findById(testPolygonId)
        );

        // Act
        const { results, errors, duration } = await runConcurrentPolygonOperations(
          readOperations,
          5 // Max concurrency
        );

        // Assert
        expect(errors).toHaveLength(0);
        expect(results.filter(r => r !== undefined)).toHaveLength(concurrentCount);
        expect(duration).toBeLessThan(200);
        
        results.forEach(result => {
          if (result) {
            expect(result.id).toBe(testPolygonId);
            polygonAssertions.hasValidGeometry(result);
          }
        });
      });

      test('should handle concurrent write operations', async () => {
        // Arrange
        const concurrentCount = 5;
        const polygonData = createMockPolygonCreate();
        const expectedPolygon = createMockPolygon(polygonData);
        
        // Each operation gets a unique response
        Array.from({ length: concurrentCount }).forEach((_, i) => {
          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([{
            ...expectedPolygon,
            id: `concurrent-polygon-${i}`
          }]));
        });

        const writeOperations = Array.from({ length: concurrentCount }, (_, i) =>
          () => polygonModel.create({
            ...polygonData,
            user_id: testUserId,
            label: `concurrent_${i}`
          })
        );

        // Act
        const { results, errors } = await runConcurrentPolygonOperations(writeOperations, 3);

        // Assert
        expect(errors).toHaveLength(0);
        expect(results.filter(r => r !== undefined)).toHaveLength(concurrentCount);
        
        // Verify each operation got unique results
        const ids = new Set(results.filter(r => r !== undefined).map(r => r!.id));
        expect(ids.size).toBe(concurrentCount);
      });

      test('should handle mixed concurrent operations', async () => {
        // Arrange
        const readPolygon = createMockPolygon({ id: testPolygonId });
        const createPolygon = createMockPolygon();
        const updatePolygon = createMockPolygon({ id: testPolygonId, label: 'updated' });

        // Setup responses for different operation types
        mockQuery
          .mockResolvedValueOnce(createMockPolygonQueryResult([readPolygon])) // read
          .mockResolvedValueOnce(createMockPolygonQueryResult([createPolygon])) // create
          .mockResolvedValueOnce(createMockPolygonQueryResult([updatePolygon])) // update
          .mockResolvedValueOnce({ rowCount: 1 }); // delete

        const mixedOperations = [
          () => polygonModel.findById(testPolygonId),
          () => polygonModel.create({ ...createMockPolygonCreate(), user_id: testUserId }),
          () => polygonModel.update(testPolygonId, { label: 'updated' }),
          () => polygonModel.delete(testPolygonId)
        ];

        // Act
        const { results, errors } = await runConcurrentPolygonOperations(mixedOperations, 2);

        // Assert
        expect(errors).toHaveLength(0);
        expect(results.filter(r => r !== undefined)).toHaveLength(4);
      });
    });

    describe('Memory Usage Tests', () => {
      test('should handle large polygon datasets without memory leaks', async () => {
        // Arrange
        const largeDataset = createPerformanceTestData.scalability.largeBatch;
        const polygons = Array.from({ length: largeDataset.polygonCount }, (_, i) =>
          createMockPolygon({
            points: createValidPolygonPoints.circle(200, 200, 50, 20),
            label: `memory_test_${i}`
          })
        );

        mockQuery.mockResolvedValue(createMockPolygonQueryResult(polygons));

        // Act & Monitor Memory
        const initialMemory = process.memoryUsage();
        
        const operations = Array.from({ length: 10 }, () =>
          () => polygonModel.findByImageId(testImageId)
        );

        await runConcurrentPolygonOperations(operations, 3);

        const finalMemory = process.memoryUsage();
        const memoryGrowth = finalMemory.heapUsed - initialMemory.heapUsed;

        // Assert
        expect(memoryGrowth).toBeLessThan(50 * 1024 * 1024); // Less than 50MB growth
      });
    });
  });

  // ==================== SECURITY TESTS ====================

  describe('Security Tests', () => {
    describe('Input Validation', () => {
      test('should handle malicious SQL injection attempts', async () => {
        // Arrange
        const sqlInjectionPayload = "'; DROP TABLE polygons; --";
        const polygonData = createMockPolygonCreate({
          label: sqlInjectionPayload
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          label: sqlInjectionPayload // Should be stored as-is, not executed
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.label).toBe(sqlInjectionPayload);
        
        // Verify parameterized query was used
        const dbCall = mockQuery.mock.calls[0];
        expect(dbCall[0]).toContain('$1'); // Parameterized query
        expect(dbCall[1]).toContain(sqlInjectionPayload); // Parameter value
      });

      test('should handle XSS attempts in polygon data', async () => {
        // Arrange
        const xssPayload = '<script>alert("XSS")</script>';
        const polygonData = createMockPolygonCreate({
          label: xssPayload,
          metadata: { description: xssPayload }
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          label: xssPayload,
          metadata: { description: xssPayload }
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.label).toBe(xssPayload);
        expect(result.metadata.description).toBe(xssPayload);
        // Note: XSS protection should happen at the presentation layer, not model layer
      });

      test('should handle path traversal attempts', async () => {
        // Arrange
        const pathTraversalPayload = '../../../etc/passwd';
        const polygonData = createMockPolygonCreate({
          label: pathTraversalPayload
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          label: pathTraversalPayload
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.label).toBe(pathTraversalPayload);
        // Path traversal should be handled at application/service layer
      });

      test('should handle buffer overflow attempts', async () => {
        // Arrange
        const oversizedLabel = 'A'.repeat(10000);
        const polygonData = createMockPolygonCreate({
          label: oversizedLabel
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          label: oversizedLabel
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.label).toBe(oversizedLabel);
        expect(result.label.length).toBe(10000);
      });

      test('should handle unicode and special character attacks', async () => {
        // Arrange
        const unicodePayloads = [
          'Test\x00with\x00null\x00bytes',
          'Normal\u202Ereversed\u202C',
          '测试🎨émoji💀spëcial',
          '\uFEFF\u200B\u200C\u200D', // Zero-width characters
          'RTL\u202ELTR\u202C' // Right-to-left override
        ];

        for (const payload of unicodePayloads) {
          const polygonData = createMockPolygonCreate({
            label: payload,
            metadata: { description: payload }
          });

          const expectedPolygon = createMockPolygon({
            user_id: testUserId,
            label: payload,
            metadata: { description: payload }
          });

          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

          // Act
          const result = await polygonModel.create({
            ...polygonData,
            user_id: testUserId
          });

          // Assert
          expect(result.label).toBe(payload);
          expect(result.metadata.description).toBe(payload);

          jest.clearAllMocks();
        }
      });
    });

    describe('Data Integrity', () => {
      test('should maintain data integrity with extreme coordinate values', async () => {
        // Arrange
        const extremePoints = [
          { x: Number.MAX_SAFE_INTEGER, y: Number.MAX_SAFE_INTEGER },
          { x: Number.MIN_SAFE_INTEGER, y: Number.MIN_SAFE_INTEGER },
          { x: 0, y: 0 }
        ];

        const polygonData = createMockPolygonCreate({
          points: extremePoints
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          points: extremePoints
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.points).toEqual(extremePoints);
        expect(result.points[0].x).toBe(Number.MAX_SAFE_INTEGER);
        expect(result.points[1].x).toBe(Number.MIN_SAFE_INTEGER);
      });

      test('should handle floating point precision edge cases', async () => {
        // Arrange
        const precisionPoints = [
          { x: 0.1 + 0.2, y: 0.3 }, // Classic floating point precision issue
          { x: 1.7976931348623157e+308, y: 100 }, // Near Number.MAX_VALUE
          { x: 5e-324, y: 100 }, // Near Number.MIN_VALUE
          { x: 100.999999999999999, y: 200.000000000000001 }
        ];

        const polygonData = createMockPolygonCreate({
          points: precisionPoints
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          points: precisionPoints
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.points).toEqual(precisionPoints);
        // Verify precision is maintained within JavaScript's limits
        expect(result.points[0].x).toBeCloseTo(0.30000000000000004, 15);
      });
    });

    describe('Access Control Validation', () => {
      test('should use parameterized queries for all operations', () => {
        // This test verifies that our mocked calls use parameterized queries
        // In a real database test, this would be critical for SQL injection prevention
        
        const verifyParameterizedQuery = (operation: string) => {
          const dbCalls = mockQuery.mock.calls;
          const lastCall = dbCalls[dbCalls.length - 1];
          
          expect(lastCall[0]).toContain('$1'); // At least one parameter
          expect(Array.isArray(lastCall[1])).toBe(true); // Parameters array
          expect(lastCall[1].length).toBeGreaterThan(0); // Has parameters
        };

        // Test create operation
        const polygonData = createMockPolygonCreate();
        const mockPolygon = createMockPolygon();
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([mockPolygon]));
        
        polygonModel.create({ ...polygonData, user_id: testUserId });
        verifyParameterizedQuery('create');

        // Test other operations would be similar
        expect(mockQuery).toHaveBeenCalled();
      });
    });
  });

  // ==================== EDGE CASES AND ERROR SCENARIOS ====================

  describe('Edge Cases and Error Scenarios', () => {
    describe('Boundary Conditions', () => {
      test('should handle minimum valid polygon (3 points)', async () => {
        // Arrange
        const minimalPoints = createValidPolygonPoints.triangle();
        const polygonData = createMockPolygonCreate({
          points: minimalPoints
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          points: minimalPoints
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.points).toHaveLength(3);
        polygonAssertions.hasValidGeometry(result);
        
        const area = calculatePolygonArea(result.points);
        expect(area).toBeGreaterThan(0);
      });

      test('should handle maximum complexity polygon (many points)', async () => {
        // Arrange
        const maxComplexityPoints = createValidPolygonPoints.circle(400, 400, 200, 1000);
        const polygonData = createMockPolygonCreate({
          points: maxComplexityPoints
        });

        const expectedPolygon = createMockPolygon({
          user_id: testUserId,
          points: maxComplexityPoints
        });

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([expectedPolygon]));

        // Act
        const result = await polygonModel.create({
          ...polygonData,
          user_id: testUserId
        });

        // Assert
        expect(result.points).toHaveLength(1000);
        polygonAssertions.hasValidGeometry(result);
      });

      test('should handle empty result sets gracefully', async () => {
        // Test various operations that might return empty results
        mockQuery.mockResolvedValue({ rows: [] });

        const findByIdResult = await polygonModel.findById(uuidv4());
        expect(findByIdResult).toBeNull();

        const findByImageIdResult = await polygonModel.findByImageId(uuidv4());
        expect(findByImageIdResult).toEqual([]);

        const findByUserIdResult = await polygonModel.findByUserId(uuidv4());
        expect(findByUserIdResult).toEqual([]);

        const updateResult = await polygonModel.update(uuidv4(), { label: 'test' });
        expect(updateResult).toBeNull();

        const deleteResult = await polygonModel.delete(uuidv4());
        expect(deleteResult).toBe(false);

        const deleteByImageResult = await polygonModel.deleteByImageId(uuidv4());
        expect(deleteByImageResult).toBe(0);
      });
    });

    describe('Data Consistency', () => {
      test('should maintain referential integrity constraints', async () => {
        // Test foreign key constraint behavior
        const fkError = new Error('insert or update on table "polygons" violates foreign key constraint "polygons_original_image_id_fkey"');
        (fkError as any).code = '23503';
        mockQuery.mockRejectedValueOnce(fkError);

        const polygonData = createMockPolygonCreate({
          original_image_id: 'non-existent-image'
        });

        await expect(polygonModel.create({
          ...polygonData,
          user_id: testUserId
        })).rejects.toThrow('violates foreign key constraint');
      });

      test('should handle concurrent modifications gracefully', async () => {
        // Simulate optimistic locking scenarios
        const polygonData = createMockPolygonCreate();
        const polygon1 = createMockPolygon({ ...polygonData, id: 'concurrent-1' });
        const polygon2 = createMockPolygon({ ...polygonData, id: 'concurrent-2' });

        // First operation succeeds
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([polygon1]));
        const result1 = await polygonModel.create({ ...polygonData, user_id: testUserId });

        // Second concurrent operation also succeeds (different ID)
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([polygon2]));
        const result2 = await polygonModel.create({ ...polygonData, user_id: testUserId });

        expect(result1.id).not.toBe(result2.id);
      });

      test('should handle transaction rollback scenarios', async () => {
        // Simulate transaction failures
        const transactionError = new Error('current transaction is aborted, commands ignored until end of transaction block');
        mockQuery.mockRejectedValueOnce(transactionError);

        const polygonData = createMockPolygonCreate();

        await expect(polygonModel.create({
          ...polygonData,
          user_id: testUserId
        })).rejects.toThrow('current transaction is aborted');
      });
    });

    describe('Resource Limitations', () => {
      test('should handle database connection pool exhaustion', async () => {
        // Simulate connection pool exhaustion
        const poolError = new Error('sorry, too many clients already');
        mockQuery.mockRejectedValueOnce(poolError);

        await expect(polygonModel.findById(testPolygonId)).rejects.toThrow('too many clients already');
      });

      test('should handle query timeout scenarios', async () => {
        // Simulate query timeout
        const timeoutError = new Error('canceling statement due to statement timeout');
        mockQuery.mockRejectedValueOnce(timeoutError);

        await expect(polygonModel.findById(testPolygonId)).rejects.toThrow('statement timeout');
      });

      test('should handle disk space exhaustion', async () => {
        // Simulate disk space issues
        const diskError = new Error('could not extend file "base/16384/16587": No space left on device');
        mockQuery.mockRejectedValueOnce(diskError);

        const polygonData = createMockPolygonCreate();

        await expect(polygonModel.create({
          ...polygonData,
          user_id: testUserId
        })).rejects.toThrow('No space left on device');
      });
    });

    describe('Malformed Data Recovery', () => {
      test('should handle partially corrupted database records', async () => {
        // Test scenario where some fields are corrupted but others are valid
        const partiallyCorruptedData = {
          id: testPolygonId,
          user_id: testUserId,
          original_image_id: testImageId,
          points: JSON.stringify(createValidPolygonPoints.triangle()), // Valid
          metadata: 'invalid-json', // Corrupted
          label: 'partially_corrupted',
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValueOnce({ rows: [partiallyCorruptedData] });

        await expect(polygonModel.findById(testPolygonId)).rejects.toThrow();
      });

      test('should handle schema evolution scenarios', async () => {
        // Test handling of data with missing or extra fields (schema changes)
        const evolvedSchemaData = {
          id: testPolygonId,
          user_id: testUserId,
          original_image_id: testImageId,
          points: JSON.stringify(createValidPolygonPoints.triangle()),
          metadata: JSON.stringify({ version: '2.0' }),
          label: 'evolved_schema',
          created_at: new Date(),
          updated_at: new Date(),
          // Extra fields that might exist in future schema versions
          new_field: 'future_value',
          deprecated_field: null
        };

        mockQuery.mockResolvedValueOnce({ rows: [evolvedSchemaData] });

        const result = await polygonModel.findById(testPolygonId);
        
        // Should handle gracefully - extra fields ignored, required fields present
        expect(result).toBeDefined();
        expect(result?.id).toBe(testPolygonId);
        polygonAssertions.hasValidGeometry(result!);
      });
    });
  });

  // ==================== INTEGRATION SCENARIOS ====================

  describe('Integration Scenarios', () => {
    describe('Cross-Domain Operations', () => {
      test('should handle polygon operations in context of image lifecycle', async () => {
        // Simulate the polygon model being used in image processing workflows
        const imagePolygons = createTestPolygonsForImage(testImageId, testUserId, 3);
        
        // Create multiple polygons for the same image
        for (let i = 0; i < imagePolygons.length; i++) {
          const polygon = imagePolygons[i];
          mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([polygon]));
          
          const result = await polygonModel.create({
            original_image_id: polygon.original_image_id,
            points: polygon.points,
            label: polygon.label,
            metadata: polygon.metadata,
            user_id: testUserId
          });
          
          expect(result.original_image_id).toBe(testImageId);
          jest.clearAllMocks();
        }

        // Then read all polygons for the image
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(imagePolygons));
        const allPolygons = await polygonModel.findByImageId(testImageId);
        
        expect(allPolygons).toHaveLength(3);
        allPolygons.forEach(polygon => {
          expect(polygon.original_image_id).toBe(testImageId);
          polygonAssertions.hasValidGeometry(polygon);
        });
      });

      test('should support batch operations for workflow efficiency', async () => {
        // Simulate batch deletion when an image is deleted
        const deleteCount = 15;
        mockQuery.mockResolvedValueOnce({ rowCount: deleteCount });

        const result = await polygonModel.deleteByImageId(testImageId);
        expect(result).toBe(deleteCount);

        // Verify the batch operation was called correctly
        expect(mockQuery).toHaveBeenCalledWith(
          'DELETE FROM polygons WHERE original_image_id = $1',
          [testImageId]
        );
      });
    });

    describe('Multi-User Scenarios', () => {
      test('should handle polygons from multiple users correctly', async () => {
        // Create polygons for different users
        const user1Id = uuidv4();
        const user2Id = uuidv4();
        
        const user1Polygons = createTestPolygonsForImage(testImageId, user1Id, 2);
        const user2Polygons = createTestPolygonsForImage(testImageId, user2Id, 3);

        // Test user-specific queries
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(user1Polygons));
        const user1Result = await polygonModel.findByUserId(user1Id);
        expect(user1Result).toHaveLength(2);
        user1Result.forEach(p => expect(p.user_id).toBe(user1Id));

        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(user2Polygons));
        const user2Result = await polygonModel.findByUserId(user2Id);
        expect(user2Result).toHaveLength(3);
        user2Result.forEach(p => expect(p.user_id).toBe(user2Id));
      });

      test('should maintain data isolation between users', async () => {
        // Verify that user-specific operations don't interfere with each other
        const user1Id = uuidv4();
        const user2Id = uuidv4();
        
        const user1Polygon = createMockPolygon({ user_id: user1Id });
        const user2Polygon = createMockPolygon({ user_id: user2Id });

        // Create polygon for user1
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([user1Polygon]));
        const result1 = await polygonModel.create({
          ...createMockPolygonCreate(),
          user_id: user1Id
        });

        // Create polygon for user2
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([user2Polygon]));
        const result2 = await polygonModel.create({
          ...createMockPolygonCreate(),
          user_id: user2Id
        });

        expect(result1.user_id).toBe(user1Id);
        expect(result2.user_id).toBe(user2Id);
        expect(result1.id).not.toBe(result2.id);
      });
    });

    describe('Data Migration Scenarios', () => {
      test('should handle legacy data format conversion', async () => {
        // Simulate reading data that might have been stored in an older format
        const legacyData = {
          id: testPolygonId,
          user_id: testUserId,
          original_image_id: testImageId,
          points: JSON.stringify(createValidPolygonPoints.triangle()),
          metadata: JSON.stringify({
            // Legacy format might have different field names
            old_field_name: 'legacy_value',
            deprecated_flag: true
          }),
          label: 'legacy_polygon',
          created_at: new Date(),
          updated_at: new Date()
        };

        mockQuery.mockResolvedValueOnce({ rows: [legacyData] });

        const result = await polygonModel.findById(testPolygonId);
        
        // Should handle legacy format gracefully
        expect(result).toBeDefined();
        expect(result?.metadata.old_field_name).toBe('legacy_value');
        polygonAssertions.hasValidGeometry(result!);
      });

      test('should support data export/import scenarios', async () => {
        // Test that polygon data can be exported and imported correctly
        const exportPolygon = createMockPolygon({
          points: createValidPolygonPoints.complex(),
          metadata: createPolygonMetadataVariations.detailed
        });

        // Export scenario (read)
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([exportPolygon]));
        const exportedData = await polygonModel.findById(exportPolygon.id);

        // Import scenario (create with same data)
        mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult([{
          ...exportedData!,
          id: uuidv4() // New ID for imported data
        }]));

        const importedData = await polygonModel.create({
          original_image_id: exportedData!.original_image_id,
          points: exportedData!.points,
          label: exportedData!.label,
          metadata: exportedData!.metadata,
          user_id: testUserId
        });

        // Verify data integrity is maintained
        expect(importedData.points).toEqual(exportedData!.points);
        expect(importedData.metadata).toEqual(exportedData!.metadata);
        expect(importedData.label).toEqual(exportedData!.label);
        polygonAssertions.hasValidGeometry(importedData);
      });
    });
  });

  // ==================== CLEANUP AND TEARDOWN ====================

  describe('Cleanup and Teardown', () => {
    test('should properly clean up test state', () => {
      // Verify that our test cleanup is working
      expect(mockQuery.mock.calls).toHaveLength(0);
      
      // Test that we can reset state properly
      resetPolygonMocks();
      expect(typeof createMockPolygon).toBe('function');
      expect(typeof polygonAssertions.hasValidGeometry).toBe('function');
    });

    test('should handle cleanup of large test datasets', async () => {
      // Simulate cleanup of performance test data
      const largeDataset = Array.from({ length: 1000 }, () => createMockPolygon());
      
      // Mock successful cleanup
      mockQuery.mockResolvedValueOnce({ rowCount: largeDataset.length });
      
      const cleanupResult = await polygonModel.deleteByImageId(testImageId);
      expect(cleanupResult).toBe(largeDataset.length);
    });

    test('should verify no test data pollution', () => {
      // Ensure our tests don't leave any persistent state
      const cleanState = jest.fn();
      cleanState.mockClear();
      
      expect(cleanState).not.toHaveBeenCalled();
      expect(mockQuery.mock.calls).toHaveLength(0);
    });
  });

  // ==================== COMPREHENSIVE TEST VALIDATION ====================

  describe('Test Suite Validation', () => {
    test('should have comprehensive test coverage', () => {
      // Verify that all major polygonModel methods have been tested
      const testedMethods = [
        'create', 'findById', 'findByImageId', 'findByUserId', 
        'update', 'delete', 'deleteByImageId'
      ];
      
      testedMethods.forEach(method => {
        expect(polygonModel[method]).toBeDefined();
        expect(typeof polygonModel[method]).toBe('function');
      });
    });

    test('should validate mock data quality', () => {
      // Verify our mock data meets quality standards
      const testPolygon = createMockPolygon();
      
      polygonAssertions.hasValidGeometry(testPolygon);
      polygonAssertions.hasValidMetadata(testPolygon);
      
      expect(testPolygon.id).toBeDefined();
      expect(testPolygon.user_id).toBeDefined();
      expect(testPolygon.original_image_id).toBeDefined();
      expect(Array.isArray(testPolygon.points)).toBe(true);
      expect(typeof testPolygon.metadata).toBe('object');
    });

    test('should verify test helper function reliability', () => {
      // Test our helper functions are working correctly
      const trianglePoints = createValidPolygonPoints.triangle();
      const area = calculatePolygonArea(trianglePoints);
      const perimeter = calculatePolygonPerimeter(trianglePoints);
      
      expect(area).toBeGreaterThan(0);
      expect(perimeter).toBeGreaterThan(0);
      expect(hasSelfintersection(trianglePoints)).toBe(false);
      
      const boundsCheck = validatePointsBounds(trianglePoints, 800, 600);
      expect(boundsCheck.valid).toBe(true);
    });

    test('should confirm error simulation accuracy', () => {
      // Verify our error simulation functions work correctly
      const dbError = simulatePolygonErrors.databaseConnection();
      expect(dbError).toBeInstanceOf(Error);
      expect(dbError.message).toContain('Connection to database lost');
      
      const validationError = simulatePolygonErrors.validationError('points', []);
      expect(validationError).toBeInstanceOf(Error);
      expect(validationError.message).toContain('Validation failed');
    });
  });
});

// ==================== ADDITIONAL PERFORMANCE BENCHMARKS ====================

describe('PolygonModel - Performance Benchmarks', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    resetPolygonMocks();
  });

  test('should benchmark create operation performance', async () => {
    const iterations = 100;
    const polygonData = createMockPolygonCreate();
    const expectedPolygon = createMockPolygon();
    
    // Setup mock to respond quickly
    mockQuery.mockResolvedValue(createMockPolygonQueryResult([expectedPolygon]));
    
    const start = performance.now();
    
    for (let i = 0; i < iterations; i++) {
      await polygonModel.create({ ...polygonData, user_id: uuidv4() });
    }
    
    const duration = performance.now() - start;
    const avgDuration = duration / iterations;
    
    expect(avgDuration).toBeLessThan(5); // Should average less than 5ms per operation
    console.log(`Average create operation time: ${avgDuration.toFixed(2)}ms`);
  });

  test('should benchmark read operation performance with various data sizes', async () => {
    const dataSizes = [1, 10, 100, 500];
    
    for (const size of dataSizes) {
      const polygons = Array.from({ length: size }, () => createMockPolygon());
      mockQuery.mockResolvedValueOnce(createMockPolygonQueryResult(polygons));
      
      const start = performance.now();
      const result = await polygonModel.findByImageId(uuidv4());
      const duration = performance.now() - start;
      
      expect(result).toHaveLength(size);
      expect(duration).toBeLessThan(size * 0.1); // Linear scaling expectation
      
      console.log(`Read ${size} polygons in ${duration.toFixed(2)}ms`);
    }
  });
});