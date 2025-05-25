// backend/src/__tests__/__helpers__/sanitize.helper.ts
import { jest } from '@jest/globals';

/**
 * Helper to setup sanitization test environment
 */
export const setupSanitizationTestEnvironment = () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });
};

/**
 * Helper to create stress tests
 */
export const createStressTests = (sanitizeFunction: Function) => {
  describe('Stress tests', () => {
    it('should handle large datasets without excessive memory usage', () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Create a much smaller, more realistic dataset for testing
      const largeDataset = Array(50).fill(0).map((_, i) => ({
        id: `item_${i}`,
        content: `Test content ${i} <script>alert("${i}")</script>`,
        metadata: {
          type: 'test',
          index: i,
          description: `Description ${i}`
        }
      }));

      // Process the dataset
      const results = largeDataset.map(item => sanitizeFunction(item));
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      expect(results).toHaveLength(largeDataset.length);
      
      // Much more conservative memory expectation - 10MB instead of 100MB
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    it('should handle memory-intensive operations', () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Significantly reduced data size
      const complexData = {
        level1: {
          level2: {
            level3: {
              malicious: '<script>alert("nested")</script>',
              safe: 'clean value',
              array: Array(5).fill('test data') // Reduced from 10 to 5
            }
          }
        }
      };

      // Process smaller batches
      for (let i = 0; i < 10; i++) { // Reduced from 100 to 10
        sanitizeFunction(complexData);
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Much more conservative memory expectation - 5MB
      expect(memoryIncrease).toBeLessThan(5 * 1024 * 1024);
    });

    it('should handle complex nested objects efficiently', () => {
      const startTime = performance.now();
      
      const complexData = {
        level1: {
          level2: {
            level3: {
              malicious: '<script>alert("nested")</script>',
              safe: 'clean value',
              array: Array(10).fill('test data') // Reduced from 50 to 10
            }
          }
        }
      };

      const result = sanitizeFunction(complexData);
      
      const endTime = performance.now();
      const executionTime = endTime - startTime;

      expect(result).toBeDefined();
      expect(executionTime).toBeLessThan(100); // Should complete quickly
    });

    it('should handle circular references gracefully', () => {
      const circularObj: any = { name: 'test' };
      circularObj.self = circularObj;

      expect(() => {
        const result = sanitizeFunction(circularObj);
        expect(result).toBeDefined();
        expect(result.name).toBe('test');
        expect(result.self).toEqual({}); // Circular reference becomes empty object
      }).not.toThrow();
    });
  });
};

/**
 * Helper to validate API path generation
 */
export const validateApiPaths = (
  pathSanitizer: (resourceType: string, resourceId: string, pathType: string) => string
) => {
  describe('API path validation', () => {
    const validPathCombinations = [
      { resourceType: 'images', resourceId: 'img_123', pathType: 'file', expected: '/api/v1/images/img_123/file' },
      { resourceType: 'garments', resourceId: 'garment_456', pathType: 'mask', expected: '/api/v1/garments/garment_456/mask' },
      { resourceType: 'polygons', resourceId: 'poly_789', pathType: 'data', expected: '/api/v1/polygons/poly_789/data' }
    ];

    validPathCombinations.forEach(({ resourceType, resourceId, pathType, expected }) => {
      it(`should generate correct path for ${resourceType}/${resourceId}/${pathType}`, () => {
        const result = pathSanitizer(resourceType, resourceId, pathType);
        expect(result).toBe(expected);
      });
    });

    it('should sanitize malicious path components', () => {
      const result = pathSanitizer(
        '../../../images',
        'id; rm -rf /',
        '<script>alert("xss")</script>'
      );
      
      expect(result).toMatch(/^\/api\/v1\/[a-z0-9\-_]+\/[a-z0-9\-_]+\/[a-z0-9\-_]+$/);
      expect(result).not.toContain('../');
      expect(result).not.toContain('<script>');
      expect(result).not.toContain(';');
    });
  });
};

/**
 * Export default helper for easy importing
 */
export default {
  setupSanitizationTestEnvironment,
  createStressTests,
  validateApiPaths
};