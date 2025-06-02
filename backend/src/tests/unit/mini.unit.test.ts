// tests/unit/models/polygonModel.mini.unit.test.ts

// Mock the database query function BEFORE importing polygonModel
const mockQuery = jest.fn();
jest.mock('../../models/db', () => ({
  query: mockQuery
}));

import { polygonModel } from '../../models/polygonModel';
import { 
  createMockPolygon,
  createMockPolygonCreate,
  createValidPolygonPoints,
  resetPolygonMocks,
  mockPolygonModelOperations
} from '../__mocks__/polygons.mock';
import {
  createTestPolygonsForImage,
  calculatePolygonArea,
  polygonAssertions
} from '../__helpers__/polygons.helper';

describe('PolygonModel - Mini Unit Tests', () => {
  const testUserId = 'test-user-123';
  const testImageId = 'test-image-456';
  
  beforeEach(() => {
    jest.clearAllMocks();
    resetPolygonMocks();
  });

  describe('Basic Framework Validation', () => {
    test('should import polygonModel without errors', () => {
      expect(polygonModel).toBeDefined();
      expect(typeof polygonModel).toBe('object');
      expect(polygonModel.create).toBeDefined();
      expect(polygonModel.findById).toBeDefined();
      expect(polygonModel.findByImageId).toBeDefined();
      expect(polygonModel.update).toBeDefined();
      expect(polygonModel.delete).toBeDefined();
    });

    test('should have all required model methods', () => {
      const requiredMethods = [
        'create', 'findById', 'findByImageId', 'findByUserId', 
        'update', 'delete', 'deleteByImageId'
      ];
      
      requiredMethods.forEach(method => {
        expect(polygonModel[method]).toBeDefined();
        expect(typeof polygonModel[method]).toBe('function');
      });
    });
  });

  describe('Create Operation - Basic Test', () => {
    test('should create a polygon with valid data', async () => {
      // Arrange
      const polygonData = createMockPolygonCreate({
        original_image_id: testImageId,
        points: createValidPolygonPoints.triangle(),
        label: 'test_triangle'
      });

      const expectedPolygon = createMockPolygon({
        user_id: testUserId,
        original_image_id: testImageId,
        points: polygonData.points,
        label: polygonData.label
      });

      // Mock database response
      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...expectedPolygon,
          points: JSON.stringify(expectedPolygon.points),
          metadata: JSON.stringify(expectedPolygon.metadata)
        }]
      });

      // Act
      const result = await polygonModel.create({
        ...polygonData,
        user_id: testUserId
      });

      // Assert
      expect(result).toBeDefined();
      expect(result.user_id).toBe(testUserId);
      expect(result.original_image_id).toBe(testImageId);
      expect(result.label).toBe('test_triangle');
      expect(Array.isArray(result.points)).toBe(true);
      expect(result.points).toHaveLength(3);
      
      // Verify database interaction
      expect(mockQuery).toHaveBeenCalledTimes(1);
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO polygons'),
        expect.arrayContaining([
          expect.any(String), // UUID
          testUserId,
          testImageId,
          expect.any(String), // JSON stringified points
          'test_triangle',
          expect.any(String)  // JSON stringified metadata
        ])
      );
    });

    test('should handle database errors gracefully', async () => {
      // Arrange
      const polygonData = createMockPolygonCreate();
      mockQuery.mockRejectedValueOnce(new Error('Database connection failed'));

      // Act & Assert
      await expect(polygonModel.create({
        ...polygonData,
        user_id: testUserId
      })).rejects.toThrow('Database connection failed');
      
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });
  });

  describe('Read Operations - Basic Tests', () => {
    test('should find polygon by ID', async () => {
      // Arrange
      const testPolygon = createMockPolygon({
        user_id: testUserId,
        original_image_id: testImageId
      });

      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...testPolygon,
          points: JSON.stringify(testPolygon.points),
          metadata: JSON.stringify(testPolygon.metadata)
        }]
      });

      // Act
      const result = await polygonModel.findById(testPolygon.id);

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe(testPolygon.id);
      expect(result?.user_id).toBe(testUserId);
      expect(Array.isArray(result?.points)).toBe(true);
      expect(typeof result?.metadata).toBe('object');
      
      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM polygons WHERE id = $1',
        [testPolygon.id]
      );
    });

    test('should return null for non-existent polygon', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({ rows: [] });

      // Act
      const result = await polygonModel.findById('non-existent-id');

      // Assert
      expect(result).toBeNull();
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });

    test('should find polygons by image ID', async () => {
      // Arrange
      const testPolygons = createTestPolygonsForImage(testImageId, testUserId, 2);
      
      mockQuery.mockResolvedValueOnce({
        rows: testPolygons.map(polygon => ({
          ...polygon,
          points: JSON.stringify(polygon.points),
          metadata: JSON.stringify(polygon.metadata)
        }))
      });

      // Act
      const result = await polygonModel.findByImageId(testImageId);

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result).toHaveLength(2);
      
      result.forEach(polygon => {
        expect(polygon.original_image_id).toBe(testImageId);
        expect(Array.isArray(polygon.points)).toBe(true);
        polygonAssertions.hasValidGeometry(polygon);
      });

      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM polygons WHERE original_image_id = $1 ORDER BY created_at ASC',
        [testImageId]
      );
    });
  });

  describe('Update Operation - Basic Test', () => {
    test('should update polygon successfully', async () => {
      // Arrange
      const originalPolygon = createMockPolygon({
        user_id: testUserId,
        label: 'original_label'
      });

      const updateData = {
        label: 'updated_label',
        metadata: { updated: true }
      };

      const updatedPolygon = {
        ...originalPolygon,
        ...updateData,
        updated_at: new Date()
      };

      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...updatedPolygon,
          points: JSON.stringify(updatedPolygon.points),
          metadata: JSON.stringify(updatedPolygon.metadata)
        }]
      });

      // Act
      const result = await polygonModel.update(originalPolygon.id, updateData);

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe(originalPolygon.id);
      expect(result?.label).toBe('updated_label');
      expect(result?.metadata.updated).toBe(true);
      
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE polygons'),
        expect.arrayContaining([
          'updated_label',
          expect.any(String), // JSON stringified metadata
          originalPolygon.id
        ])
      );
    });

    test('should handle empty update gracefully', async () => {
      // Arrange
      const polygonId = 'test-polygon-id';
      const expectedPolygon = createMockPolygon({ id: polygonId });
      
      // Mock the UPDATE query that sets updated_at = NOW()
      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...expectedPolygon,
          points: JSON.stringify(expectedPolygon.points),
          metadata: JSON.stringify(expectedPolygon.metadata),
          updated_at: new Date() // Updated timestamp
        }]
      });

      // Act
      const result = await polygonModel.update(polygonId, {});

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe(polygonId);
      
      // Should call UPDATE query even for empty updates (to set updated_at)
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE polygons'),
        [polygonId]
      );
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('updated_at = NOW()'),
        [polygonId]
      );
    });
  });

  describe('Delete Operation - Basic Test', () => {
    test('should delete polygon successfully', async () => {
      // Arrange
      const polygonId = 'test-polygon-to-delete';
      mockQuery.mockResolvedValueOnce({ rowCount: 1 });

      // Act
      const result = await polygonModel.delete(polygonId);

      // Assert
      expect(result).toBe(true);
      expect(mockQuery).toHaveBeenCalledWith(
        'DELETE FROM polygons WHERE id = $1',
        [polygonId]
      );
    });

    test('should return false when polygon not found for deletion', async () => {
      // Arrange
      const polygonId = 'non-existent-polygon';
      mockQuery.mockResolvedValueOnce({ rowCount: 0 });

      // Act
      const result = await polygonModel.delete(polygonId);

      // Assert
      expect(result).toBe(false);
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });

    test('should delete multiple polygons by image ID', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({ rowCount: 3 });

      // Act
      const result = await polygonModel.deleteByImageId(testImageId);

      // Assert
      expect(result).toBe(3);
      expect(mockQuery).toHaveBeenCalledWith(
        'DELETE FROM polygons WHERE original_image_id = $1',
        [testImageId]
      );
    });
  });

  describe('Data Transformation Tests', () => {
    test('should properly parse JSON points and metadata', async () => {
      // Arrange
      const testPoints = createValidPolygonPoints.square();
      const testMetadata = { type: 'test', area: 10000 };
      
      mockQuery.mockResolvedValueOnce({
        rows: [{
          id: 'test-id',
          user_id: testUserId,
          original_image_id: testImageId,
          points: JSON.stringify(testPoints),
          metadata: JSON.stringify(testMetadata),
          label: 'test_square',
          created_at: new Date(),
          updated_at: new Date()
        }]
      });

      // Act
      const result = await polygonModel.findById('test-id');

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result?.points)).toBe(true);
      expect(result?.points).toHaveLength(4); // Square has 4 points
      expect(result?.points[0]).toEqual({ x: 100, y: 100 }); // Check first point
      expect(typeof result?.metadata).toBe('object');
      expect(result?.metadata).toEqual(testMetadata);
    });

    test('should handle malformed JSON gracefully', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [{
          id: 'test-id',
          user_id: testUserId,
          original_image_id: testImageId,
          points: 'invalid-json',
          metadata: '{"valid": true}',
          label: 'test',
          created_at: new Date(),
          updated_at: new Date()
        }]
      });

      // Act & Assert
      await expect(polygonModel.findById('test-id')).rejects.toThrow();
      expect(mockQuery).toHaveBeenCalledTimes(1);
    });
  });

  describe('Helper Integration Tests', () => {
    test('should work with polygon helper functions', () => {
      // Arrange
      const trianglePoints = createValidPolygonPoints.triangle();
      
      // Act
      const area = calculatePolygonArea(trianglePoints);
      
      // Assert
      expect(typeof area).toBe('number');
      expect(area).toBeGreaterThan(0);
      
      // Verify points are geometrically valid
      expect(trianglePoints).toHaveLength(3);
      trianglePoints.forEach(point => {
        expect(typeof point.x).toBe('number');
        expect(typeof point.y).toBe('number');
        expect(isFinite(point.x)).toBe(true);
        expect(isFinite(point.y)).toBe(true);
      });
    });

    test('should work with mock data factories', () => {
      // Act
      const mockPolygon = createMockPolygon({
        user_id: testUserId,
        original_image_id: testImageId
      });

      // Assert
      expect(mockPolygon).toBeDefined();
      expect(mockPolygon.user_id).toBe(testUserId);
      expect(mockPolygon.original_image_id).toBe(testImageId);
      
      // Use custom assertion
      polygonAssertions.hasValidGeometry(mockPolygon);
      polygonAssertions.hasValidMetadata(mockPolygon);
    });
  });

  describe('Edge Cases - Mini Tests', () => {
    test('should handle UUID generation in create', async () => {
      // Arrange
      const polygonData = createMockPolygonCreate({
        points: createValidPolygonPoints.triangle(),
        label: 'test_triangle'
      });
      
      const mockCreatedPolygon = createMockPolygon({
        user_id: testUserId,
        original_image_id: polygonData.original_image_id,
        points: polygonData.points,
        label: polygonData.label
      });

      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...mockCreatedPolygon,
          points: JSON.stringify(mockCreatedPolygon.points),
          metadata: JSON.stringify(mockCreatedPolygon.metadata)
        }]
      });

      // Act
      const result = await polygonModel.create({
        ...polygonData,
        user_id: testUserId
      });

      // Assert
      expect(result.id).toBeDefined();
      expect(typeof result.id).toBe('string');
      expect(result.id.length).toBeGreaterThan(0);
      
      // Verify the ID was generated and passed to database
      const dbCall = mockQuery.mock.calls[0];
      expect(dbCall[1][0]).toBeDefined(); // First parameter should be the generated ID
      expect(typeof dbCall[1][0]).toBe('string');
      expect(dbCall[1][1]).toBe(testUserId); // Second parameter should be user_id
    });

    test('should handle null/undefined metadata gracefully', async () => {
      // Arrange
      const polygonData = createMockPolygonCreate({
        metadata: undefined
      });

      const expectedResult = createMockPolygon({
        user_id: testUserId,
        metadata: {}
      });

      mockQuery.mockResolvedValueOnce({
        rows: [{
          ...expectedResult,
          points: JSON.stringify(expectedResult.points),
          metadata: JSON.stringify({})
        }]
      });

      // Act
      const result = await polygonModel.create({
        ...polygonData,
        user_id: testUserId
      });

      // Assert
      expect(result.metadata).toBeDefined();
      expect(typeof result.metadata).toBe('object');
      expect(result.metadata).toEqual({});
    });
  });

  describe('Mock Verification Tests', () => {
    test('should verify mock setup is working correctly', () => {
      // Verify mocks are properly imported and configured
      expect(mockQuery).toBeDefined();
      expect(jest.isMockFunction(mockQuery)).toBe(true);
      
      // Verify polygon mock functions
      expect(createMockPolygon).toBeDefined();
      expect(createValidPolygonPoints).toBeDefined();
      expect(polygonAssertions).toBeDefined();
      
      // Test a simple mock call
      const testPolygon = createMockPolygon();
      expect(testPolygon.id).toBeDefined();
      expect(Array.isArray(testPolygon.points)).toBe(true);
    });

    test('should verify cleanup functions work', () => {
      // Set up some mock state
      mockQuery.mockReturnValue({ rows: [] });
      
      // Verify reset works
      resetPolygonMocks();
      jest.clearAllMocks();
      
      // Verify mocks are cleared
      expect(mockQuery).not.toHaveBeenCalled();
    });
  });
});

// Additional describe block for framework confidence
describe('Test Framework Validation', () => {
  test('Jest and TypeScript are working correctly', () => {
    expect(true).toBe(true);
    expect(typeof jest).toBe('object');
    expect(jest.fn).toBeDefined();
  });

  test('Async/await support is working', async () => {
    const asyncFunction = async () => {
      return new Promise(resolve => {
        setTimeout(() => resolve('success'), 10);
      });
    };

    const result = await asyncFunction();
    expect(result).toBe('success');
  });

  test('Mock imports are resolved correctly', () => {
    // Verify all required imports are working
    expect(polygonModel).toBeDefined();
    expect(createMockPolygon).toBeDefined();
    expect(createValidPolygonPoints).toBeDefined();
    expect(polygonAssertions).toBeDefined();
    expect(calculatePolygonArea).toBeDefined();
  });
});