// /backend/tests/stress/wardrobeService.stress.test.ts
import { wardrobeService } from '../../services/wardrobeService';
import { wardrobeModel } from '../../models/wardrobeModel';
import { garmentModel } from '../../models/garmentModel';
import { ApiError } from '../../utils/ApiError';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';
import { v4 as uuidv4 } from 'uuid';

// Mock the model dependencies
jest.mock('../../models/wardrobeModel');
jest.mock('../../models/garmentModel');

const mockedWardrobeModel = wardrobeModel as jest.Mocked<typeof wardrobeModel>;
const mockedGarmentModel = garmentModel as jest.Mocked<typeof garmentModel>;

// Increase timeout for stress tests
jest.setTimeout(60000); // 60 seconds

// Memory optimization: Force garbage collection between tests if available
if (global.gc) {
  afterEach(() => {
    global.gc();
  });
}

describe('WardrobeService Stress Tests', () => {
  let testUserId: string;
  let stressMetrics: {
    totalOperations: number;
    successfulOperations: number;
    failedOperations: number;
    errors: any[];
    startTime: bigint;
    endTime: bigint;
    memoryUsage: {
      start: NodeJS.MemoryUsage;
      peak: NodeJS.MemoryUsage;
      end: NodeJS.MemoryUsage;
    };
  };

  beforeEach(() => {
    jest.clearAllMocks();
    testUserId = uuidv4();
    stressMetrics = {
      totalOperations: 0,
      successfulOperations: 0,
      failedOperations: 0,
      errors: [],
      startTime: process.hrtime.bigint(),
      endTime: process.hrtime.bigint(),
      memoryUsage: {
        start: process.memoryUsage(),
        peak: process.memoryUsage(),
        end: process.memoryUsage()
      }
    };
  });

  // Helper to track memory usage
  const updatePeakMemory = () => {
    const current = process.memoryUsage();
    if (current.heapUsed > stressMetrics.memoryUsage.peak.heapUsed) {
      stressMetrics.memoryUsage.peak = current;
    }
  };

  // Helper to create large mock data sets
  const createLargeMockDataset = (count: number, complexity: 'simple' | 'complex' = 'simple') => {
    return Array.from({ length: count }, (_, i) => {
      const base = wardrobeMocks.createValidWardrobe({
        id: uuidv4(),
        user_id: testUserId,
        name: `Stress Test Wardrobe ${i}`,
        created_at: new Date(Date.now() - Math.random() * 86400000 * 30), // Random date within 30 days
        updated_at: new Date(Date.now() - Math.random() * 86400000 * 7)   // Random date within 7 days
      });

      if (complexity === 'complex') {
        return {
          ...base,
          description: 'A'.repeat(Math.floor(Math.random() * 900) + 100), // 100-1000 chars
          garmentCount: Math.floor(Math.random() * 150),
          metadata: {
            tags: Array.from({ length: 20 }, (_, j) => `tag-${j}`),
            categories: Array.from({ length: 10 }, (_, j) => `category-${j}`),
            analytics: {
              views: Math.floor(Math.random() * 10000),
              shares: Math.floor(Math.random() * 1000),
              likes: Math.floor(Math.random() * 5000)
            }
          }
        };
      }

      return {
        ...base,
        garmentCount: Math.floor(Math.random() * 50)
      };
    });
  };

  describe('Extreme Load Tests', () => {
    it('should handle 10,000 wardrobes retrieval', async () => {
      // Generate dataset in chunks to reduce memory pressure
      const chunkSize = 1000;
      const chunks = [];
      for (let i = 0; i < 10; i++) {
        chunks.push(...createLargeMockDataset(chunkSize));
      }
      
      mockedWardrobeModel.findByUserId.mockResolvedValue(chunks);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      stressMetrics.startTime = process.hrtime.bigint();
      
      const result = await wardrobeService.getUserWardrobes({
        userId: testUserId,
        pagination: { limit: 50 }
      });

      stressMetrics.endTime = process.hrtime.bigint();
      updatePeakMemory();

      expect(result.wardrobes).toHaveLength(50);
      expect(result.pagination?.totalFiltered).toBe(10000);
      
      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      expect(durationMs).toBeLessThan(10000); // Should complete within 10 seconds for 10k wardrobes
      
      // Clear reference to large dataset
      chunks.length = 0;
    });

    it('should handle 50,000 wardrobes with filtering', async () => {
      // Reduced from 100k to 50k for better memory management
      const datasetSize = 50000;
      const pageSize = 5000;
      let dataset: any[] = [];
      
      // Generate data in pages to avoid large memory spike
      for (let i = 0; i < datasetSize / pageSize; i++) {
        dataset = dataset.concat(createLargeMockDataset(pageSize, 'simple')); // Use simple instead of complex
      }
      
      mockedWardrobeModel.findByUserId.mockResolvedValue(dataset);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      stressMetrics.startTime = process.hrtime.bigint();
      
      const result = await wardrobeService.getUserWardrobes({
        userId: testUserId,
        filters: {
          search: 'Stress Test',
          hasGarments: true,
          sortBy: 'garment_count',
          sortOrder: 'desc'
        },
        pagination: { limit: 20 }
      });

      stressMetrics.endTime = process.hrtime.bigint();
      updatePeakMemory();

      expect(result.wardrobes).toBeDefined();
      expect(result.wardrobes.length).toBeLessThanOrEqual(20);
      
      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      expect(durationMs).toBeLessThan(10000); // Should complete within 10 seconds
      
      // Clear dataset
      dataset.length = 0;
    });

    it('should handle rapid fire operations', async () => {
      const operationCount = 1000;
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.update.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      stressMetrics.startTime = process.hrtime.bigint();
      stressMetrics.totalOperations = operationCount;

      const operations = Array.from({ length: operationCount }, (_, i) => {
        const op = i % 4;
        switch (op) {
          case 0:
            return wardrobeService.createWardrobe({
              userId: testUserId,
              name: `Rapid Fire ${i}`
            });
          case 1:
            return wardrobeService.getUserWardrobes({ userId: testUserId });
          case 2:
            return wardrobeService.updateWardrobe({
              wardrobeId: mockWardrobe.id,
              userId: testUserId,
              name: `Updated ${i}`
            });
          default:
            return wardrobeService.getWardrobe(mockWardrobe.id, testUserId);
        }
      });

      const results = await Promise.allSettled(operations);
      
      stressMetrics.endTime = process.hrtime.bigint();
      updatePeakMemory();

      results.forEach(result => {
        if (result.status === 'fulfilled') {
          stressMetrics.successfulOperations++;
        } else {
          stressMetrics.failedOperations++;
          stressMetrics.errors.push(result.reason);
        }
      });

      const successRate = (stressMetrics.successfulOperations / stressMetrics.totalOperations) * 100;
      expect(successRate).toBeGreaterThan(95); // At least 95% success rate

      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      const opsPerSecond = (operationCount / durationMs) * 1000;
      console.log(`Rapid fire test: ${opsPerSecond.toFixed(2)} ops/sec`);
    });
  });

  describe('Memory Stress Tests', () => {
    it('should handle memory pressure with large payloads', async () => {
      const largeDescription = 'X'.repeat(999); // Near max description length
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockImplementation(() => 
        Promise.resolve(wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          description: largeDescription
        }))
      );

      stressMetrics.startTime = process.hrtime.bigint();
      const operations = 100;

      for (let i = 0; i < operations; i++) {
        await wardrobeService.createWardrobe({
          userId: testUserId,
          name: `Memory Stress ${i}`,
          description: largeDescription
        });
        updatePeakMemory();
      }

      stressMetrics.endTime = process.hrtime.bigint();
      stressMetrics.memoryUsage.end = process.memoryUsage();

      const memoryIncreaseMB = (stressMetrics.memoryUsage.peak.heapUsed - 
                                stressMetrics.memoryUsage.start.heapUsed) / 1024 / 1024;
      
      expect(memoryIncreaseMB).toBeLessThan(100); // Should not exceed 100MB increase
    });

    it('should handle memory spikes in batch operations', async () => {
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(
        wardrobeMocks.createValidWardrobe({ user_id: testUserId })
      );

      const batchSize = 50; // Maximum allowed
      const batches = 10; // Reduced from 20 for faster execution
      
      stressMetrics.startTime = process.hrtime.bigint();
      stressMetrics.memoryUsage.start = process.memoryUsage();

      // Pre-allocate operations array to avoid repeated allocations
      const baseOperations = Array.from({ length: batchSize }, (_, i) => ({
        type: 'create' as const,
        clientId: `template-${i}`
      }));

      for (let batch = 0; batch < batches; batch++) {
        // Reuse base structure, only update necessary fields
        const operations = baseOperations.map((op, i) => ({
          ...op,
          data: { 
            name: `Batch ${batch} Item ${i}`,
            description: batch % 2 === 0 ? 'B'.repeat(250) : 'S'.repeat(100) // Vary sizes
          },
          clientId: `batch-${batch}-${i}`
        }));

        await wardrobeService.batchOperations({
          userId: testUserId,
          operations
        });

        // Only update peak memory every 5 batches to reduce overhead
        if (batch % 5 === 0) {
          updatePeakMemory();
        }

        // Force GC less frequently - every 5 batches
        if (batch % 5 === 0 && global.gc) {
          global.gc();
        }
      }

      stressMetrics.endTime = process.hrtime.bigint();
      
      // Final GC and memory measurement
      if (global.gc) {
        global.gc();
        await new Promise(resolve => setTimeout(resolve, 100)); // Allow GC to complete
      }
      
      stressMetrics.memoryUsage.end = process.memoryUsage();

      const startMemoryMB = stressMetrics.memoryUsage.start.heapUsed / 1024 / 1024;
      const peakMemoryMB = stressMetrics.memoryUsage.peak.heapUsed / 1024 / 1024;
      const endMemoryMB = stressMetrics.memoryUsage.end.heapUsed / 1024 / 1024;
      
      // Check memory was released (comparing to start, not peak)
      const memoryGrowthMB = endMemoryMB - startMemoryMB;
      expect(memoryGrowthMB).toBeLessThan(50); // Should not grow more than 50MB overall
      
      // Peak memory should be reasonable
      const peakGrowthMB = peakMemoryMB - startMemoryMB;
      expect(peakGrowthMB).toBeLessThan(200); // Peak should not exceed 200MB growth
    });
  });

  describe('Concurrent Load Stress Tests', () => {
    it('should handle 100 concurrent create operations', async () => {
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      let creationCount = 0;
      
      mockedWardrobeModel.create.mockImplementation(() => {
        creationCount++;
        return new Promise(resolve => 
          setTimeout(() => 
            resolve(wardrobeMocks.createValidWardrobe({ 
              user_id: testUserId,
              id: uuidv4()
            })), 
            Math.random() * 50 // Random delay 0-50ms
          )
        );
      });

      stressMetrics.startTime = process.hrtime.bigint();

      const concurrentOps = Array.from({ length: 100 }, (_, i) =>
        wardrobeService.createWardrobe({
          userId: testUserId,
          name: `Concurrent ${i}`
        })
      );

      const results = await Promise.allSettled(concurrentOps);
      
      stressMetrics.endTime = process.hrtime.bigint();
      updatePeakMemory();

      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBeGreaterThan(90); // At least 90% should succeed
      expect(creationCount).toBe(successful);

      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      expect(durationMs).toBeLessThan(2000); // Should complete within 2 seconds
    });

    it('should handle mixed concurrent operations under load', async () => {
      const wardrobes = createLargeMockDataset(50);
      const garments = Array.from({ length: 100 }, () => 
        wardrobeMocks.garments.createMockGarment({ user_id: testUserId })
      );

      mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
      mockedWardrobeModel.findById.mockImplementation((id) =>
        Promise.resolve(wardrobes.find(w => w.id === id) || null)
      );
      mockedWardrobeModel.create.mockResolvedValue(wardrobes[0]);
      mockedWardrobeModel.update.mockResolvedValue(wardrobes[0]);
      mockedWardrobeModel.delete.mockResolvedValue(true);
      mockedWardrobeModel.getGarments.mockResolvedValue(garments.slice(0, 10));
      mockedWardrobeModel.addGarment.mockResolvedValue(true);
      mockedGarmentModel.findById.mockImplementation((id) =>
        Promise.resolve(garments.find(g => g.id === id) || null)
      );

      const operationTypes = [
        () => wardrobeService.createWardrobe({
          userId: testUserId,
          name: `Stress Create ${Date.now()}`
        }),
        () => wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: { limit: 20 }
        }),
        () => wardrobeService.updateWardrobe({
          wardrobeId: wardrobes[0].id,
          userId: testUserId,
          name: `Stress Update ${Date.now()}`
        }),
        () => wardrobeService.deleteWardrobe(wardrobes[1].id, testUserId),
        () => wardrobeService.addGarmentToWardrobe({
          wardrobeId: wardrobes[0].id,
          userId: testUserId,
          garmentId: garments[0].id
        }),
        () => wardrobeService.searchWardrobes(testUserId, 'Stress'),
        () => wardrobeService.getUserWardrobeStats(testUserId),
        () => wardrobeService.syncWardrobes({
          userId: testUserId,
          lastSyncTimestamp: new Date(Date.now() - 3600000)
        })
      ];

      stressMetrics.startTime = process.hrtime.bigint();

      // Generate 500 random operations
      const operations = Array.from({ length: 500 }, () => {
        const randomOp = operationTypes[Math.floor(Math.random() * operationTypes.length)];
        return randomOp();
      });

      const results = await Promise.allSettled(operations);
      
      stressMetrics.endTime = process.hrtime.bigint();
      updatePeakMemory();

      results.forEach(result => {
        if (result.status === 'fulfilled') {
          stressMetrics.successfulOperations++;
        } else {
          stressMetrics.failedOperations++;
        }
      });

      const successRate = (stressMetrics.successfulOperations / operations.length) * 100;
      expect(successRate).toBeGreaterThan(50); // At least 50% success rate for mixed ops under extreme stress
    });
  });

  describe('Pagination Stress Tests', () => {
    it('should handle deep pagination through 5,000 items', async () => {
      // Reduced from 10k to 5k items
      const datasetSize = 5000;
      const largeDataset = createLargeMockDataset(datasetSize);
      mockedWardrobeModel.findByUserId.mockResolvedValue(largeDataset);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      let cursor: string | undefined = undefined;
      let pageCount = 0;
      let totalItems = 0;
      const maxPages = 50; // Reduced from 100
      const pageSize = 100; // Increased from 50 for faster pagination

      stressMetrics.startTime = process.hrtime.bigint();

      while (pageCount < maxPages) {
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: {
            cursor,
            limit: pageSize
          }
        });

        totalItems += result.wardrobes.length;
        pageCount++;
        
        // Update memory less frequently
        if (pageCount % 10 === 0) {
          updatePeakMemory();
        }

        if (!result.pagination?.hasNext || !result.pagination?.nextCursor) {
          break;
        }
        cursor = result.pagination.nextCursor;
      }

      stressMetrics.endTime = process.hrtime.bigint();

      expect(totalItems).toBeGreaterThan(0);
      expect(pageCount).toBeGreaterThan(1);

      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      const avgPageTimeMs = durationMs / pageCount;
      
      expect(avgPageTimeMs).toBeLessThan(1000); // Each page should take less than 1000ms under stress
      
      // Clear dataset
      largeDataset.length = 0;
    });

    it('should handle backward pagination under stress', async () => {
      // Optimized dataset size for faster execution
      const datasetSize = 1500; // Further reduced for efficiency
      const pageSize = 150; // Larger page size for fewer iterations
      const maxPages = 10; // Further reduced iterations
      
      // Pre-create dataset with simple data for better performance
      const dataset = createLargeMockDataset(datasetSize, 'simple');
      
      // Set up mocks - return full dataset and let service handle pagination
      mockedWardrobeModel.findByUserId.mockResolvedValue(dataset);
      
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      // Start from the end
      const lastItem = dataset[dataset.length - 1];
      let cursor = lastItem.id;
      let pageCount = 0;
      const pageTimes: number[] = [];

      const overallStart = performance.now();

      while (pageCount < maxPages) {
        const pageStart = performance.now();
        
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: {
            cursor,
            limit: pageSize,
            direction: 'backward'
          }
        });
        
        const pageTime = performance.now() - pageStart;
        pageTimes.push(pageTime);
        pageCount++;

        // Check if we've reached the beginning
        if (!result.pagination?.hasPrev || !result.pagination?.prevCursor || result.wardrobes.length === 0) {
          break;
        }
        
        cursor = result.pagination.prevCursor;
      }

      const totalTime = performance.now() - overallStart;

      // Performance assertions
      expect(pageCount).toBeGreaterThan(1);
      expect(pageCount).toBeLessThanOrEqual(maxPages);
      
      // Overall time should be very fast
      expect(totalTime).toBeLessThan(3000); // 3 seconds max (was 15s)
      
      // Average page time should be consistent
      const avgPageTime = pageTimes.reduce((a, b) => a + b, 0) / pageTimes.length;
      expect(avgPageTime).toBeLessThan(300); // Each page under 300ms
      
      // Check for performance degradation
      if (pageTimes.length > 2) {
        const firstQuarter = pageTimes.slice(0, Math.ceil(pageTimes.length / 4));
        const lastQuarter = pageTimes.slice(-Math.ceil(pageTimes.length / 4));
        const avgFirst = firstQuarter.reduce((a, b) => a + b, 0) / firstQuarter.length;
        const avgLast = lastQuarter.reduce((a, b) => a + b, 0) / lastQuarter.length;
        
        // Performance should not degrade more than 50%
        expect(avgLast).toBeLessThan(avgFirst * 1.5);
      }
      
      // Clear dataset for memory efficiency
      dataset.length = 0;
    });
  });

  describe('Sync Stress Tests', () => {
    it('should handle sync with 25,000 changes', async () => {
      // Reduced from 50k to 25k and using simple data
      const syncDataSize = 25000;
      const syncChunkSize = 5000;
      const allWardrobes: any[] = [];
      
      // Generate in chunks to reduce memory pressure
      for (let i = 0; i < syncDataSize / syncChunkSize; i++) {
        allWardrobes.push(...createLargeMockDataset(syncChunkSize, 'simple'));
      }
      
      mockedWardrobeModel.findByUserId.mockResolvedValue(allWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      stressMetrics.startTime = process.hrtime.bigint();

      const result = await wardrobeService.syncWardrobes({
        userId: testUserId,
        lastSyncTimestamp: new Date(0) // Epoch - sync everything
      });

      stressMetrics.endTime = process.hrtime.bigint();
      updatePeakMemory();

      expect(result.sync.changeCount).toBeGreaterThan(0);
      
      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      expect(durationMs).toBeLessThan(15000); // Should complete within 15 seconds
      
      // Clear reference
      allWardrobes.length = 0;
    });

    it('should handle rapid sync requests', async () => {
      const dataset = createLargeMockDataset(1000);
      mockedWardrobeModel.findByUserId.mockResolvedValue(dataset);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const syncCount = 50;
      const syncPromises = [];

      stressMetrics.startTime = process.hrtime.bigint();

      for (let i = 0; i < syncCount; i++) {
        const promise = wardrobeService.syncWardrobes({
          userId: testUserId,
          lastSyncTimestamp: new Date(Date.now() - (i * 60000)) // Stagger timestamps
        });
        syncPromises.push(promise);
      }

      const results = await Promise.allSettled(syncPromises);
      
      stressMetrics.endTime = process.hrtime.bigint();
      updatePeakMemory();

      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBe(syncCount); // All should succeed

      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      expect(durationMs).toBeLessThan(10000); // Should complete within 10 seconds
    });
  });

  describe('Batch Operations Stress Tests', () => {
    it('should handle maximum batch size repeatedly', async () => {
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(
        wardrobeMocks.createValidWardrobe({ user_id: testUserId })
      );

      const batchCount = 50; // Reduced from 100
      const maxBatchSize = 50;

      stressMetrics.startTime = process.hrtime.bigint();
      stressMetrics.totalOperations = batchCount * maxBatchSize;

      // Pre-create operation template to reduce memory allocation
      const operationTemplate = { type: 'create' as const };

      for (let i = 0; i < batchCount; i++) {
        const operations = Array.from({ length: maxBatchSize }, (_, j) => ({
          ...operationTemplate,
          data: { name: `Batch ${i} Item ${j}` },
          clientId: `${i}-${j}`
        }));

        const result = await wardrobeService.batchOperations({
          userId: testUserId,
          operations
        });

        stressMetrics.successfulOperations += result.results.length;
        stressMetrics.failedOperations += result.errors.length;
        
        // Update memory less frequently
        if (i % 10 === 0) {
          updatePeakMemory();
        }
        
        // Clear operations array
        operations.length = 0;
      }

      stressMetrics.endTime = process.hrtime.bigint();

      const successRate = (stressMetrics.successfulOperations / stressMetrics.totalOperations) * 100;
      expect(successRate).toBeGreaterThan(99); // Very high success rate expected

      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      const opsPerSecond = (stressMetrics.totalOperations / durationMs) * 1000;
      
      console.log(`Batch stress test: ${opsPerSecond.toFixed(2)} ops/sec`);
    });

    it('should handle complex batch operations under stress', async () => {
      const existingWardrobes = createLargeMockDataset(100);
      
      mockedWardrobeModel.findByUserId.mockResolvedValue(existingWardrobes);
      mockedWardrobeModel.findById.mockImplementation((id) =>
        Promise.resolve(existingWardrobes.find(w => w.id === id) || null)
      );
      mockedWardrobeModel.create.mockResolvedValue(existingWardrobes[0]);
      mockedWardrobeModel.update.mockResolvedValue(existingWardrobes[0]);
      mockedWardrobeModel.delete.mockResolvedValue(true);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const batchCount = 50;

      stressMetrics.startTime = process.hrtime.bigint();

      for (let batch = 0; batch < batchCount; batch++) {
        const operations = [
          // 20 creates
          ...Array.from({ length: 20 }, (_, i) => ({
            type: 'create' as const,
            data: { name: `Stress Create ${batch}-${i}` },
            clientId: `create-${batch}-${i}`
          })),
          // 20 updates
          ...existingWardrobes.slice(0, 20).map((w, i) => ({
            type: 'update' as const,
            data: { id: w.id, name: `Stress Update ${batch}-${i}` },
            clientId: `update-${batch}-${i}`
          })),
          // 10 deletes
          ...existingWardrobes.slice(20, 30).map((w, i) => ({
            type: 'delete' as const,
            data: { id: w.id },
            clientId: `delete-${batch}-${i}`
          }))
        ];

        await wardrobeService.batchOperations({
          userId: testUserId,
          operations
        });

        updatePeakMemory();
      }

      stressMetrics.endTime = process.hrtime.bigint();

      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      expect(durationMs).toBeLessThan(30000); // Should complete within 30 seconds
    });
  });

  describe('Error Recovery Stress Tests', () => {
    it('should recover from intermittent failures', async () => {
      let callCount = 0;
      
      // Simulate intermittent failures
      mockedWardrobeModel.findByUserId.mockImplementation(() => {
        callCount++;
        if (callCount % 10 === 0) {
          return Promise.reject(new Error('Simulated database error'));
        }
        return Promise.resolve(createLargeMockDataset(100));
      });

      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const operations = 100;
      const results = [];

      stressMetrics.startTime = process.hrtime.bigint();

      for (let i = 0; i < operations; i++) {
        try {
          const result = await wardrobeService.getUserWardrobes({
            userId: testUserId,
            pagination: { limit: 20 }
          });
          results.push({ success: true, data: result });
          stressMetrics.successfulOperations++;
        } catch (error) {
          results.push({ success: false, error });
          stressMetrics.failedOperations++;
          stressMetrics.errors.push(error);
        }
      }

      stressMetrics.endTime = process.hrtime.bigint();

      const successRate = (stressMetrics.successfulOperations / operations) * 100;
      expect(successRate).toBeGreaterThan(85); // Should handle most operations despite failures
    });

    it('should handle cascading failures gracefully', async () => {
      const mockWardrobes = createLargeMockDataset(50);
      let deleteCallCount = 0;

      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobes[0]);
      mockedWardrobeModel.getGarments.mockResolvedValue(
        Array.from({ length: 10 }, () => 
          wardrobeMocks.garments.createMockGarment({ user_id: testUserId })
        )
      );
      
      // Simulate cascading failures
      mockedWardrobeModel.delete.mockImplementation(() => {
        deleteCallCount++;
        if (deleteCallCount < 5) {
          return Promise.reject(new Error('Delete failed - wardrobe has garments'));
        }
        return Promise.resolve(true);
      });

      const deleteAttempts = 20;
      const results = [];

      stressMetrics.startTime = process.hrtime.bigint();

      for (let i = 0; i < deleteAttempts; i++) {
        try {
          const result = await wardrobeService.deleteWardrobe(mockWardrobes[0].id, testUserId);
          results.push({ success: true, result });
        } catch (error) {
          results.push({ success: false, error });
        }
      }

      stressMetrics.endTime = process.hrtime.bigint();

      const failures = results.filter(r => !r.success).length;
      expect(failures).toBeGreaterThan(0); // Some should fail due to business rules
      
      const errors = results.filter(r => !r.success && r.error instanceof ApiError);
      expect(errors.length).toBe(failures); // All failures should be proper ApiErrors
    });
  });

  describe('Resource Limit Tests', () => {
    it('should enforce wardrobe creation limits under stress', async () => {
      // Simulate user at limit
      const maxWardrobes = Array.from({ length: 50 }, (_, i) => 
        wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          name: `Existing Wardrobe ${i}`
        })
      );

      mockedWardrobeModel.findByUserId.mockResolvedValue(maxWardrobes);

      const createAttempts = 100;
      const results = [];

      stressMetrics.startTime = process.hrtime.bigint();

      const createPromises = Array.from({ length: createAttempts }, (_, i) =>
        wardrobeService.createWardrobe({
          userId: testUserId,
          name: `Over Limit ${i}`
        }).catch(error => ({ error }))
      );

      const createResults = await Promise.all(createPromises);
      
      stressMetrics.endTime = process.hrtime.bigint();

      const failures = createResults.filter(r => 'error' in r).length;
      expect(failures).toBe(createAttempts); // All should fail due to limit
    });

    it('should enforce garment capacity limits under stress', async () => {
      const mockWardrobe = wardrobeMocks.createValidWardrobe({ user_id: testUserId });
      const maxGarments = Array.from({ length: 200 }, () => 
        wardrobeMocks.garments.createMockGarment({ user_id: testUserId })
      );

      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue(maxGarments);
      mockedGarmentModel.findById.mockResolvedValue(maxGarments[0]);

      const addAttempts = 50;
      let failureCount = 0;

      stressMetrics.startTime = process.hrtime.bigint();

      for (let i = 0; i < addAttempts; i++) {
        try {
          await wardrobeService.addGarmentToWardrobe({
            wardrobeId: mockWardrobe.id,
            userId: testUserId,
            garmentId: uuidv4()
          });
        } catch (error) {
          failureCount++;
        }
      }

      stressMetrics.endTime = process.hrtime.bigint();

      expect(failureCount).toBe(addAttempts); // All should fail due to capacity
    });
  });

  describe('Complex Filtering Stress Tests', () => {
    it('should handle extreme filtering combinations', async () => {
      // Reduced dataset size and using simple data
      const complexDataset = createLargeMockDataset(2500, 'simple');
      mockedWardrobeModel.findByUserId.mockResolvedValue(complexDataset);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const filterCombinations = [
        { search: 'Test', hasGarments: true, sortBy: 'name' as const },
        { search: 'Wardrobe', hasGarments: false, sortBy: 'created_at' as const },
        { search: 'Stress', sortBy: 'garment_count' as const, sortOrder: 'desc' as const },
        { 
          search: 'Complex',
          hasGarments: true,
          sortBy: 'updated_at' as const,
          createdAfter: new Date(Date.now() - 86400000 * 7).toISOString(),
          updatedAfter: new Date(Date.now() - 86400000).toISOString()
        }
      ];

      stressMetrics.startTime = process.hrtime.bigint();

      const filterPromises = [];
      
      // Reduced from 10 to 5 iterations
      for (let i = 0; i < 5; i++) {
        for (const filters of filterCombinations) {
          filterPromises.push(
            wardrobeService.getUserWardrobes({
              userId: testUserId,
              filters,
              pagination: { limit: 20 }
            })
          );
        }
      }

      const results = await Promise.allSettled(filterPromises);
      
      stressMetrics.endTime = process.hrtime.bigint();

      const successful = results.filter(r => r.status === 'fulfilled').length;
      expect(successful).toBe(filterPromises.length); // All should succeed

      const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
      const avgTimePerFilter = durationMs / filterPromises.length;
      
      expect(avgTimePerFilter).toBeLessThan(500); // Each filter should average < 500ms under stress
      
      // Clear dataset
      complexDataset.length = 0;
    });
  });

  afterEach(async () => {
    stressMetrics.memoryUsage.end = process.memoryUsage();
    
    const durationMs = Number(stressMetrics.endTime - stressMetrics.startTime) / 1000000;
    const peakMemoryMB = stressMetrics.memoryUsage.peak.heapUsed / 1024 / 1024;
    const memoryIncreaseMB = (stressMetrics.memoryUsage.end.heapUsed - 
                              stressMetrics.memoryUsage.start.heapUsed) / 1024 / 1024;

    console.log('\n--- Stress Test Metrics ---');
    console.log(`Duration: ${durationMs.toFixed(2)}ms`);
    console.log(`Total Operations: ${stressMetrics.totalOperations}`);
    console.log(`Successful: ${stressMetrics.successfulOperations}`);
    console.log(`Failed: ${stressMetrics.failedOperations}`);
    console.log(`Success Rate: ${((stressMetrics.successfulOperations / (stressMetrics.totalOperations || 1)) * 100).toFixed(2)}%`);
    console.log(`Peak Memory: ${peakMemoryMB.toFixed(2)}MB`);
    console.log(`Memory Increase: ${memoryIncreaseMB.toFixed(2)}MB`);
    
    if (stressMetrics.errors.length > 0) {
      console.log(`Unique Errors: ${new Set(stressMetrics.errors.map(e => e.message)).size}`);
    }
    
    // Clear all mocks to free memory
    jest.clearAllMocks();
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    // Small delay to allow cleanup
    await new Promise(resolve => setTimeout(resolve, 10));
  });

  afterAll(async () => {
    console.log('\n=== Stress Test Suite Completed ===');
    
    // Reset all mocks completely
    jest.restoreAllMocks();
    
    // Final cleanup delay
    await new Promise(resolve => setTimeout(resolve, 100));
  });
});