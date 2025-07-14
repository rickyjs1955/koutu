// /backend/tests/performance/wardrobeService.perf.test.ts
import { wardrobeService } from '../../services/wardrobeService';
import { wardrobeModel } from '../../models/wardrobeModel';
import { garmentModel } from '../../models/garmentModel';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';
import { v4 as uuidv4 } from 'uuid';

// Mock the model dependencies
jest.mock('../../models/wardrobeModel');
jest.mock('../../models/garmentModel');

const mockedWardrobeModel = wardrobeModel as jest.Mocked<typeof wardrobeModel>;
const mockedGarmentModel = garmentModel as jest.Mocked<typeof garmentModel>;

describe('WardrobeService Performance Tests', () => {
  let testUserId: string;
  let performanceMetrics: Record<string, number> = {};

  beforeEach(() => {
    jest.clearAllMocks();
    testUserId = uuidv4();
    performanceMetrics = {};
  });

  // Helper function to measure execution time
  const measureTime = async <T>(
    operation: () => Promise<T>,
    metricName: string
  ): Promise<T> => {
    const startTime = process.hrtime.bigint();
    const result = await operation();
    const endTime = process.hrtime.bigint();
    const durationMs = Number(endTime - startTime) / 1000000;
    performanceMetrics[metricName] = durationMs;
    return result;
  };

  // Helper to create mock wardrobes with garments
  const createMockWardrobesWithGarments = (count: number, garmentsPerWardrobe: number = 0) => {
    return Array.from({ length: count }, (_, i) => {
      const wardrobe = wardrobeMocks.createValidWardrobe({
        id: uuidv4(),
        user_id: testUserId,
        name: `Performance Test Wardrobe ${i}`,
        created_at: new Date(Date.now() - i * 1000), // Stagger creation times
        updated_at: new Date(Date.now() - i * 500)
      });
      
      // Add garment count for enhanced responses
      return {
        ...wardrobe,
        garmentCount: garmentsPerWardrobe
      };
    });
  };

  describe('Basic Operations Performance', () => {
    it('should create wardrobe within 50ms', async () => {
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);

      const result = await measureTime(
        () => wardrobeService.createWardrobe({
          userId: testUserId,
          name: 'Performance Test Wardrobe',
          description: 'Test description'
        }),
        'createWardrobe'
      );

      expect(result).toBeDefined();
      expect(performanceMetrics.createWardrobe).toBeLessThan(50);
    });

    it('should get single wardrobe within 30ms', async () => {
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.getWardrobeWithGarments(mockWardrobe.id, testUserId),
        'getWardrobeWithGarments'
      );

      expect(result).toBeDefined();
      expect(performanceMetrics.getWardrobeWithGarments).toBeLessThan(30);
    });

    it('should update wardrobe within 40ms', async () => {
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.findByUserId.mockResolvedValue([mockWardrobe]);
      mockedWardrobeModel.update.mockResolvedValue(mockWardrobe);

      const result = await measureTime(
        () => wardrobeService.updateWardrobe({
          wardrobeId: mockWardrobe.id,
          userId: testUserId,
          name: 'Updated Name'
        }),
        'updateWardrobe'
      );

      expect(result).toBeDefined();
      expect(performanceMetrics.updateWardrobe).toBeLessThan(40);
    });

    it('should delete wardrobe within 40ms', async () => {
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);
      mockedWardrobeModel.delete.mockResolvedValue(true);

      const result = await measureTime(
        () => wardrobeService.deleteWardrobe(mockWardrobe.id, testUserId),
        'deleteWardrobe'
      );

      expect(result.success).toBe(true);
      expect(performanceMetrics.deleteWardrobe).toBeLessThan(40);
    });
  });

  describe('Mobile Pagination Performance', () => {
    it('should handle 1000 wardrobes with cursor pagination within 100ms', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(1000, 5);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: { limit: 20 }
        }),
        'paginationLarge'
      );

      expect(result.wardrobes).toHaveLength(20);
      expect(result.pagination?.hasNext).toBe(true);
      expect(performanceMetrics.paginationLarge).toBeLessThan(100);
    });

    it('should handle backward pagination efficiently', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(500);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const lastWardrobe = mockWardrobes[mockWardrobes.length - 1];

      const result = await measureTime(
        () => wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: {
            cursor: lastWardrobe.id,
            limit: 20,
            direction: 'backward'
          }
        }),
        'backwardPagination'
      );

      expect(result.wardrobes).toBeDefined();
      expect(performanceMetrics.backwardPagination).toBeLessThan(80);
    });

    it('should handle multiple pagination requests efficiently', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(200);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const iterations = 10;
      let cursor: string | undefined = undefined;
      const pageTimes: number[] = [];

      for (let i = 0; i < iterations; i++) {
        const startTime = process.hrtime.bigint();
        
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: {
            cursor,
            limit: 20
          }
        });

        const endTime = process.hrtime.bigint();
        const durationMs = Number(endTime - startTime) / 1000000;
        pageTimes.push(durationMs);

        cursor = result.pagination?.nextCursor;
        if (!cursor) break;
      }

      const avgTime = pageTimes.reduce((a, b) => a + b, 0) / pageTimes.length;
      expect(avgTime).toBeLessThan(50);
      expect(Math.max(...pageTimes)).toBeLessThan(100);
    });
  });

  describe('Filtering and Sorting Performance', () => {
    it('should filter by search term efficiently with 1000 wardrobes', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(1000);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: { search: 'Test' }
        }),
        'searchFilter'
      );

      expect(result.wardrobes).toBeDefined();
      expect(performanceMetrics.searchFilter).toBeLessThan(150);
    });

    it('should sort by different criteria efficiently', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(500, 10);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const sortCriteria: Array<'name' | 'created_at' | 'updated_at' | 'garment_count'> = 
        ['name', 'created_at', 'updated_at', 'garment_count'];
      
      for (const sortBy of sortCriteria) {
        const result = await measureTime(
          () => wardrobeService.getUserWardrobes({
            userId: testUserId,
            filters: { sortBy, sortOrder: 'desc' }
          }),
          `sort_${sortBy}`
        );

        expect(result.wardrobes).toBeDefined();
        expect(performanceMetrics[`sort_${sortBy}`]).toBeLessThan(100);
      }
    });

    it('should handle complex filtering efficiently', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(800, 15);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: {
            search: 'Performance',
            hasGarments: true,
            sortBy: 'garment_count',
            sortOrder: 'desc',
            createdAfter: new Date(Date.now() - 86400000).toISOString()
          },
          pagination: { limit: 20 }
        }),
        'complexFilter'
      );

      expect(result.wardrobes).toBeDefined();
      expect(performanceMetrics.complexFilter).toBeLessThan(200);
    });
  });

  describe('Sync Performance', () => {
    it('should sync 500 wardrobes efficiently', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(500, 5);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.syncWardrobes({
          userId: testUserId,
          lastSyncTimestamp: new Date(Date.now() - 3600000) // 1 hour ago
        }),
        'syncLarge'
      );

      expect(result.sync).toBeDefined();
      expect(performanceMetrics.syncLarge).toBeLessThan(300);
    });

    it('should handle incremental sync efficiently', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(100);
      
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.syncWardrobes({
          userId: testUserId,
          lastSyncTimestamp: new Date(Date.now() - 300000) // 5 minutes ago
        }),
        'incrementalSync'
      );

      expect(result.sync).toBeDefined();
      expect(performanceMetrics.incrementalSync).toBeLessThan(100);
    });
  });

  describe('Batch Operations Performance', () => {
    it('should handle batch of 50 operations within 500ms', async () => {
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(
        wardrobeMocks.createValidWardrobe({ user_id: testUserId })
      );

      const operations = Array.from({ length: 50 }, (_, i) => ({
        type: 'create' as const,
        data: { name: `Batch Wardrobe ${i}` },
        clientId: `client-${i}`
      }));

      const result = await measureTime(
        () => wardrobeService.batchOperations({
          userId: testUserId,
          operations
        }),
        'batchCreate50'
      );

      expect(result.summary.total).toBe(50);
      expect(performanceMetrics.batchCreate50).toBeLessThan(500);
    });

    it('should handle mixed batch operations efficiently', async () => {
      const existingWardrobes = createMockWardrobesWithGarments(20);
      
      mockedWardrobeModel.findByUserId.mockResolvedValue(existingWardrobes);
      mockedWardrobeModel.findById.mockImplementation((id) => 
        Promise.resolve(existingWardrobes.find(w => w.id === id) || null)
      );
      mockedWardrobeModel.create.mockResolvedValue(
        wardrobeMocks.createValidWardrobe({ user_id: testUserId })
      );
      mockedWardrobeModel.update.mockResolvedValue(existingWardrobes[0]);
      mockedWardrobeModel.delete.mockResolvedValue(true);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const operations = [
        // 10 creates
        ...Array.from({ length: 10 }, (_, i) => ({
          type: 'create' as const,
          data: { name: `New Batch ${i}` },
          clientId: `create-${i}`
        })),
        // 10 updates
        ...existingWardrobes.slice(0, 10).map((w, i) => ({
          type: 'update' as const,
          data: { id: w.id, name: `Updated Batch ${i}` },
          clientId: `update-${i}`
        })),
        // 10 deletes
        ...existingWardrobes.slice(10, 20).map((w, i) => ({
          type: 'delete' as const,
          data: { id: w.id },
          clientId: `delete-${i}`
        }))
      ];

      const result = await measureTime(
        () => wardrobeService.batchOperations({
          userId: testUserId,
          operations
        }),
        'mixedBatch30'
      );

      expect(result.summary.total).toBe(30);
      expect(performanceMetrics.mixedBatch30).toBeLessThan(400);
    });
  });

  describe('Garment Operations Performance', () => {
    it('should add garment to wardrobe within 30ms', async () => {
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      const mockGarment = wardrobeMocks.garments.createMockGarment({ user_id: testUserId });
      
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedGarmentModel.findById.mockResolvedValue(mockGarment);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);
      mockedWardrobeModel.addGarment.mockResolvedValue(true);

      const result = await measureTime(
        () => wardrobeService.addGarmentToWardrobe({
          wardrobeId: mockWardrobe.id,
          userId: testUserId,
          garmentId: mockGarment.id
        }),
        'addGarment'
      );

      expect(result.success).toBe(true);
      expect(performanceMetrics.addGarment).toBeLessThan(30);
    });

    it('should reorder 100 garments within 200ms', async () => {
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      const mockGarments = Array.from({ length: 100 }, () => 
        wardrobeMocks.garments.createMockGarment({ user_id: testUserId })
      );
      
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue(mockGarments);
      mockedWardrobeModel.addGarment.mockResolvedValue(true);

      const garmentIds = mockGarments.map(g => g.id).reverse();

      const result = await measureTime(
        () => wardrobeService.reorderGarments(
          mockWardrobe.id,
          testUserId,
          garmentIds
        ),
        'reorder100'
      );

      expect(result.success).toBe(true);
      expect(performanceMetrics.reorder100).toBeLessThan(200);
    });
  });

  describe('Statistics and Search Performance', () => {
    it('should calculate user statistics with 50 wardrobes within 150ms', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(50);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      
      // Mock different garment counts for each wardrobe
      mockedWardrobeModel.getGarments.mockImplementation(() => 
        Promise.resolve(Array.from({ length: Math.floor(Math.random() * 20) }, () =>
          wardrobeMocks.garments.createMockGarment({ user_id: testUserId })
        ))
      );

      const result = await measureTime(
        () => wardrobeService.getUserWardrobeStats(testUserId),
        'userStats50'
      );

      expect(result.totalWardrobes).toBe(50);
      expect(performanceMetrics.userStats50).toBeLessThan(150);
    });

    it('should search through 1000 wardrobes within 100ms', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(1000);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.searchWardrobes(testUserId, 'Performance Test'),
        'search1000'
      );

      expect(Array.isArray(result)).toBe(true);
      expect(performanceMetrics.search1000).toBeLessThan(100);
    });
  });

  describe('Concurrent Operations Performance', () => {
    it('should handle 20 concurrent wardrobe creations efficiently', async () => {
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockImplementation(() => 
        new Promise(resolve => setTimeout(() => 
          resolve(wardrobeMocks.createValidWardrobe({ user_id: testUserId })), 
          10
        ))
      );

      const startTime = process.hrtime.bigint();
      
      const promises = Array.from({ length: 20 }, (_, i) =>
        wardrobeService.createWardrobe({
          userId: testUserId,
          name: `Concurrent Wardrobe ${i}`
        })
      );

      const results = await Promise.all(promises);
      
      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1000000;

      expect(results).toHaveLength(20);
      expect(durationMs).toBeLessThan(250); // Should be parallel, not 20 * 10ms
    });

    it('should handle mixed concurrent operations efficiently', async () => {
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      
      mockedWardrobeModel.findByUserId.mockResolvedValue([mockWardrobe]);
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.update.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const startTime = process.hrtime.bigint();
      
      const operations = [
        // 5 creates
        ...Array.from({ length: 5 }, (_, i) =>
          wardrobeService.createWardrobe({
            userId: testUserId,
            name: `Mixed Concurrent ${i}`
          })
        ),
        // 5 reads
        ...Array.from({ length: 5 }, () =>
          wardrobeService.getWardrobe(mockWardrobe.id, testUserId)
        ),
        // 5 updates
        ...Array.from({ length: 5 }, (_, i) =>
          wardrobeService.updateWardrobe({
            wardrobeId: mockWardrobe.id,
            userId: testUserId,
            name: `Updated ${i}`
          })
        ),
        // 5 list operations
        ...Array.from({ length: 5 }, () =>
          wardrobeService.getUserWardrobes({ userId: testUserId })
        )
      ];

      const results = await Promise.all(operations);
      
      const endTime = process.hrtime.bigint();
      const durationMs = Number(endTime - startTime) / 1000000;

      expect(results).toHaveLength(20);
      expect(durationMs).toBeLessThan(300);
    });
  });

  describe('Memory Usage Performance', () => {
    it('should handle large dataset without excessive memory usage', async () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Create 5000 wardrobes
      const mockWardrobes = createMockWardrobesWithGarments(5000, 10);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      await wardrobeService.getUserWardrobes({
        userId: testUserId,
        pagination: { limit: 50 }
      });

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncreaseMB = (finalMemory - initialMemory) / 1024 / 1024;

      // Should not use more than 50MB for this operation
      expect(memoryIncreaseMB).toBeLessThan(50);
    });

    it('should clean up memory after batch operations', async () => {
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(
        wardrobeMocks.createValidWardrobe({ user_id: testUserId })
      );

      const operations = Array.from({ length: 50 }, (_, i) => ({
        type: 'create' as const,
        data: { 
          name: `Memory Test ${i}`,
          description: 'A'.repeat(1000) // 1KB description
        },
        clientId: `memory-${i}`
      }));

      const initialMemory = process.memoryUsage().heapUsed;
      
      await wardrobeService.batchOperations({
        userId: testUserId,
        operations
      });

      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncreaseMB = (finalMemory - initialMemory) / 1024 / 1024;

      // Memory increase should be minimal after operation completes
      expect(memoryIncreaseMB).toBeLessThan(10);
    });
  });

  describe('Edge Case Performance', () => {
    it('should handle empty results efficiently', async () => {
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: { search: 'NonExistent' }
        }),
        'emptySearch'
      );

      expect(result.wardrobes).toHaveLength(0);
      expect(performanceMetrics.emptySearch).toBeLessThan(20);
    });

    it('should handle maximum pagination limit efficiently', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(100);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: { limit: 50 } // Maximum allowed
        }),
        'maxPagination'
      );

      expect(result.wardrobes).toHaveLength(50);
      expect(performanceMetrics.maxPagination).toBeLessThan(80);
    });

    it('should handle deeply nested filter combinations', async () => {
      const mockWardrobes = createMockWardrobesWithGarments(300, 5);
      mockedWardrobeModel.findByUserId.mockResolvedValue(mockWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const result = await measureTime(
        () => wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: {
            search: 'Test',
            hasGarments: true,
            sortBy: 'name',
            sortOrder: 'asc',
            createdAfter: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
            updatedAfter: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
          },
          pagination: {
            limit: 20,
            direction: 'forward'
          }
        }),
        'deepFilters'
      );

      expect(result.wardrobes).toBeDefined();
      expect(performanceMetrics.deepFilters).toBeLessThan(150);
    });
  });

  afterAll(() => {
    console.log('\n=== Performance Test Summary ===');
    console.log('Operation Timings (ms):');
    
    Object.entries(performanceMetrics).forEach(([operation, time]) => {
      const status = time < getThreshold(operation) ? '✓' : '✗';
      console.log(`${status} ${operation}: ${time.toFixed(2)}ms`);
    });

    const values = Object.values(performanceMetrics);
    const avgTime = values.length > 0 
      ? values.reduce((a, b) => a + b, 0) / values.length
      : 0;
    console.log(`\nAverage operation time: ${avgTime.toFixed(2)}ms`);
  });
});

// Helper function to get performance thresholds
function getThreshold(operation: string): number {
  const thresholds: Record<string, number> = {
    createWardrobe: 50,
    getWardrobeWithGarments: 30,
    updateWardrobe: 40,
    deleteWardrobe: 40,
    paginationLarge: 100,
    backwardPagination: 80,
    searchFilter: 150,
    complexFilter: 200,
    syncLarge: 300,
    incrementalSync: 100,
    batchCreate50: 500,
    mixedBatch30: 400,
    addGarment: 30,
    reorder100: 200,
    userStats50: 150,
    search1000: 100,
    emptySearch: 20,
    maxPagination: 80,
    deepFilters: 150
  };
  
  return thresholds[operation] || 100;
}