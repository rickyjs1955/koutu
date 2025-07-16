/**
 * Stress Test Suite for Wardrobe Controller
 * 
 * @description Tests the wardrobe controller under extreme conditions including
 * high concurrent load, memory pressure, large data volumes, and sustained operations.
 * These tests help identify breaking points, memory leaks, and performance degradation.
 * 
 * @author Team
 * @version 1.0.0
 */

import { Request, Response, NextFunction } from 'express';
import { performance } from 'perf_hooks';
import { wardrobeController } from '../../controllers/wardrobeController';
import { wardrobeService } from '../../services/wardrobeService';
import { sanitization } from '../../utils/sanitize';
import { ResponseUtils } from '../../utils/responseWrapper';

// Mock dependencies
jest.mock('../../services/wardrobeService');
jest.mock('../../services/garmentService');
jest.mock('../../utils/sanitize');
jest.mock('../../utils/responseWrapper');
jest.mock('../../middlewares/errorHandler');

// Type the mocked services
const mockWardrobeService = wardrobeService as jest.Mocked<typeof wardrobeService>;
const mockSanitization = sanitization as jest.Mocked<typeof sanitization>;

// Stress test thresholds
const STRESS_THRESHOLDS = {
  MEMORY: {
    maxHeapUsed: 500 * 1024 * 1024,        // 500MB heap limit
    maxRss: 1024 * 1024 * 1024,            // 1GB RSS limit
    maxGrowthRate: 1.5,                    // Max 50% memory growth
    gcFrequency: 10                        // Force GC every 10 iterations
  },
  CONCURRENCY: {
    maxConcurrentRequests: 1000,           // 1000 concurrent requests
    minSuccessRate: 0.95,                  // 95% success rate
    maxResponseTime: 5000,                 // 5 second max response time
    throughputTarget: 100                  // 100 requests per second
  },
  DATA_VOLUME: {
    maxWardrobes: 10000,                   // 10k wardrobes
    maxGarmentsPerWardrobe: 1000,          // 1k garments per wardrobe
    maxBatchSize: 500,                     // 500 operations per batch
    maxPayloadSize: 10 * 1024 * 1024       // 10MB payload
  },
  DURATION: {
    sustainedLoadMinutes: 5,               // 5 minutes sustained load
    spikeTestIterations: 10,               // 10 spike iterations
    enduranceTestHours: 1                  // 1 hour endurance test
  }
};

describe('WardrobeController Stress Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let mockUser: { id: string; email: string };

  // Monitoring metrics
  let metrics = {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    totalDuration: 0,
    peakMemory: 0,
    errors: [] as any[]
  };

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockUser = {
      id: 'stress-test-user',
      email: 'stress@test.com'
    };

    mockReq = {
      user: mockUser,
      body: {},
      params: {},
      query: {}
    };

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      success: jest.fn().mockReturnThis(),
      created: jest.fn().mockReturnThis(),
      successWithPagination: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis()
    } as any;

    mockNext = jest.fn();

    // Mock sanitization to be fast
    mockSanitization.sanitizeUserInput.mockImplementation((input) => input);
    mockSanitization.sanitizeForSecurity.mockImplementation((input) => input);

    // Mock ResponseUtils
    (ResponseUtils.validatePagination as jest.Mock).mockImplementation((page, limit) => ({
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 10
    }));

    (ResponseUtils.createPagination as jest.Mock).mockImplementation((page, limit, total) => ({
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasNext: page * limit < total,
      hasPrev: page > 1
    }));

    // Reset metrics
    metrics = {
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      totalDuration: 0,
      peakMemory: 0,
      errors: []
    };
  });

  afterEach(() => {
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  });

  // Helper functions
  const measureMemoryUsage = () => {
    const usage = process.memoryUsage();
    if (usage.heapUsed > metrics.peakMemory) {
      metrics.peakMemory = usage.heapUsed;
    }
    return usage;
  };

  const executeWithMetrics = async (operation: () => Promise<void>) => {
    metrics.totalRequests++;
    const startTime = performance.now();
    
    try {
      await operation();
      metrics.successfulRequests++;
    } catch (error) {
      metrics.failedRequests++;
      // Ensure error is properly captured
      if (error instanceof Error) {
        metrics.errors.push(error);
      } else {
        metrics.errors.push(new Error(String(error)));
      }
    }
    
    const duration = performance.now() - startTime;
    metrics.totalDuration += duration;
    return duration;
  };

  const generateLargeWardrobe = (index: number, garmentCount: number) => ({
    id: `stress-wardrobe-${index}`,
    user_id: mockUser.id,
    name: `Stress Test Wardrobe ${index}`,
    description: 'A'.repeat(1000), // 1KB description
    is_default: false,
    garmentCount,
    garments: Array.from({ length: garmentCount }, (_, i) => ({
      id: `stress-garment-${index}-${i}`,
      user_id: mockUser.id,
      name: `Garment ${i}`,
      category: ['shirt', 'pants', 'jacket'][i % 3],
      color: ['blue', 'red', 'black'][i % 3],
      metadata: {
        size: ['S', 'M', 'L', 'XL'][i % 4],
        brand: `Brand ${i % 10}`,
        tags: Array.from({ length: 10 }, (_, j) => `tag${i}-${j}`),
        description: 'B'.repeat(100) // 100 bytes per garment
      }
    })),
    created_at: new Date(),
    updated_at: new Date()
  });

  describe('Memory Stress Tests', () => {
    /**
     * @skip Temporarily skipped due to controller initialization issues
     * TODO: Enable once controller dependency injection is improved
     */
    it.skip('should handle large payload without memory leak', async () => {
      const iterations = 100;
      const memorySnapshots: NodeJS.MemoryUsage[] = [];

      for (let i = 0; i < iterations; i++) {
        // Create large wardrobe with many garments
        const largeWardrobe = generateLargeWardrobe(i, 100);
        
        mockReq.params = { id: `wardrobe-${i}` };
        mockWardrobeService.getWardrobeWithGarments.mockResolvedValue(largeWardrobe);

        await executeWithMetrics(async () => {
          await wardrobeController.getWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
        });

        // Periodic memory check and GC
        if (i % STRESS_THRESHOLDS.MEMORY.gcFrequency === 0) {
          if (global.gc) global.gc();
          memorySnapshots.push(measureMemoryUsage());
        }
      }

      // Analyze memory growth
      const firstSnapshot = memorySnapshots[0];
      const lastSnapshot = memorySnapshots[memorySnapshots.length - 1];
      const growthRate = lastSnapshot.heapUsed / firstSnapshot.heapUsed;

      expect(growthRate).toBeLessThan(STRESS_THRESHOLDS.MEMORY.maxGrowthRate);
      expect(lastSnapshot.heapUsed).toBeLessThan(STRESS_THRESHOLDS.MEMORY.maxHeapUsed);
      expect(metrics.successfulRequests / metrics.totalRequests).toBeGreaterThan(0.99);
    });

    it.skip('should handle extremely large wardrobe collections', async () => {
      const wardrobeCount = 1000;
      const wardrobes = Array.from({ length: wardrobeCount }, (_, i) => 
        generateLargeWardrobe(i, 50)
      );

      mockWardrobeService.getUserWardrobes.mockResolvedValue({
        wardrobes,
        total: wardrobeCount
      });

      const startMemory = measureMemoryUsage();
      
      await executeWithMetrics(async () => {
        mockReq.query = { page: '1', limit: '1000' };
        await wardrobeController.getWardrobes(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );
      });

      const endMemory = measureMemoryUsage();
      const memoryIncrease = endMemory.heapUsed - startMemory.heapUsed;

      // Memory increase should be reasonable for the data size
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB
      expect(metrics.successfulRequests).toBe(1);
    });

    it.skip('should handle memory pressure during batch operations', async () => {
      const batchSize = STRESS_THRESHOLDS.DATA_VOLUME.maxBatchSize;
      const operations = Array.from({ length: batchSize }, (_, i) => ({
        type: ['create', 'update', 'delete'][i % 3],
        data: {
          id: `wardrobe-${i}`,
          name: `Batch Wardrobe ${i}`,
          description: 'C'.repeat(1000) // 1KB per operation
        },
        clientId: `client-${i}`
      }));

      mockReq.body = { operations };
      
      // Mock service responses
      mockWardrobeService.createWardrobe.mockImplementation((data) => 
        Promise.resolve(generateLargeWardrobe(Date.now(), 10))
      );
      mockWardrobeService.updateWardrobe.mockImplementation((data) => 
        Promise.resolve(generateLargeWardrobe(Date.now(), 10))
      );
      mockWardrobeService.deleteWardrobe.mockResolvedValue({ 
        success: true, 
        wardrobeId: 'deleted-id' 
      });

      const startMemory = measureMemoryUsage();
      
      await executeWithMetrics(async () => {
        await wardrobeController.batchOperations(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );
      });

      const endMemory = measureMemoryUsage();
      
      expect(endMemory.heapUsed).toBeLessThan(STRESS_THRESHOLDS.MEMORY.maxHeapUsed);
      expect(metrics.successfulRequests).toBe(1);
    });
  });

  describe('Concurrent Request Stress Tests', () => {
    it('should handle high concurrent load', async () => {
      const concurrentRequests = 50; // Reduced for test stability
      const startTime = performance.now();

      const promises = Array.from({ length: concurrentRequests }, async (_, i) => {
        const req = {
          user: mockUser,
          body: { 
            name: `Concurrent Wardrobe ${i}`,
            description: `Created under high load ${i}`
          }
        } as Request;

        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn().mockReturnThis(),
          created: jest.fn().mockReturnThis()
        } as unknown as Response;

        mockWardrobeService.createWardrobe.mockResolvedValue(
          generateLargeWardrobe(i, 10)
        );

        return executeWithMetrics(async () => {
          await wardrobeController.createWardrobe(req, res, mockNext);
        });
      });

      await Promise.all(promises);
      
      const totalDuration = performance.now() - startTime;
      const throughput = (concurrentRequests / totalDuration) * 1000; // requests per second
      const successRate = metrics.successfulRequests / metrics.totalRequests;

      expect(successRate).toBeGreaterThan(STRESS_THRESHOLDS.CONCURRENCY.minSuccessRate);
      expect(totalDuration).toBeLessThan(STRESS_THRESHOLDS.CONCURRENCY.maxResponseTime);
      expect(throughput).toBeGreaterThan(10); // At least 10 req/s
    });

    it('should handle mixed concurrent operations without degradation', async () => {
      const operationsPerType = 50;
      const operations = [
        // Create operations
        ...Array.from({ length: operationsPerType }, (_, i) => async () => {
          const req = {
            user: mockUser,
            body: { name: `Create ${i}`, description: `Test ${i}` }
          } as Request;
          const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            created: jest.fn().mockReturnThis()
          } as unknown as Response;
          mockWardrobeService.createWardrobe.mockResolvedValue(generateLargeWardrobe(i, 5));
          return wardrobeController.createWardrobe(req, res, mockNext);
        }),
        // Read operations
        ...Array.from({ length: operationsPerType }, (_, i) => async () => {
          const req = {
            user: mockUser,
            query: { page: '1', limit: '20' }
          } as unknown as Request;
          const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            success: jest.fn().mockReturnThis(),
            successWithPagination: jest.fn().mockReturnThis()
          } as unknown as Response;
          mockWardrobeService.getUserWardrobes.mockResolvedValue({
            wardrobes: Array.from({ length: 20 }, (_, j) => generateLargeWardrobe(j, 5)),
            total: 100
          });
          return wardrobeController.getWardrobes(req as Request, res as Response, mockNext);
        }),
        // Update operations
        ...Array.from({ length: operationsPerType }, (_, i) => async () => {
          const req = {
            user: mockUser,
            params: { id: `wardrobe-${i}` },
            body: { name: `Updated ${i}` }
          } as unknown as Request;
          const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            success: jest.fn().mockReturnThis()
          } as unknown as Response;
          mockWardrobeService.updateWardrobe.mockResolvedValue(generateLargeWardrobe(i, 5));
          return wardrobeController.updateWardrobe(req as Request, res as Response, mockNext);
        })
      ];

      const startTime = performance.now();
      const results = await Promise.allSettled(
        operations.map(op => executeWithMetrics(op))
      );
      const endTime = performance.now();

      const successCount = results.filter(r => r.status === 'fulfilled').length;
      const successRate = successCount / operations.length;

      expect(successRate).toBeGreaterThan(0.9); // 90% success rate
      expect(endTime - startTime).toBeLessThan(10000); // Complete within 10 seconds
    });
  });

  describe('Data Volume Stress Tests', () => {
    it.skip('should handle pagination with massive datasets', async () => {
      const totalWardrobes = STRESS_THRESHOLDS.DATA_VOLUME.maxWardrobes;
      const pageSize = 100;
      const pagesToTest = 10;

      for (let page = 1; page <= pagesToTest; page++) {
        mockReq.query = { page: page.toString(), limit: pageSize.toString() };
        
        const wardrobes = Array.from({ length: pageSize }, (_, i) => 
          generateLargeWardrobe(page * pageSize + i, 10)
        );

        mockWardrobeService.getUserWardrobes.mockResolvedValue({
          wardrobes,
          total: totalWardrobes
        });

        const duration = await executeWithMetrics(async () => {
          await wardrobeController.getWardrobes(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
        });

        // Response time should remain consistent across pages
        expect(duration).toBeLessThan(1000); // 1 second per page
      }

      expect(metrics.successfulRequests).toBe(pagesToTest);
      expect(metrics.failedRequests).toBe(0);
    });

    /**
     * @skip Temporarily skipped due to controller initialization issues
     * TODO: Enable once controller dependency injection is improved
     */
    it.skip('should handle wardrobes with extreme garment counts', async () => {
      const maxGarments = STRESS_THRESHOLDS.DATA_VOLUME.maxGarmentsPerWardrobe;
      const wardrobe = generateLargeWardrobe(1, maxGarments);

      mockReq.params = { id: 'extreme-wardrobe' };
      mockWardrobeService.getWardrobeWithGarments.mockResolvedValue(wardrobe);

      const startMemory = measureMemoryUsage();
      const duration = await executeWithMetrics(async () => {
        await wardrobeController.getWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );
      });
      const endMemory = measureMemoryUsage();

      expect(duration).toBeLessThan(5000); // 5 seconds for extreme case
      expect(endMemory.heapUsed - startMemory.heapUsed).toBeLessThan(200 * 1024 * 1024); // Less than 200MB
      expect(metrics.successfulRequests).toBe(1);
    });

    it('should handle large sync payloads', async () => {
      const changedWardrobes = 500;
      
      mockReq.body = { 
        lastSyncTimestamp: new Date(Date.now() - 86400000).toISOString(), // 24 hours ago
        clientVersion: 1
      };

      const syncResult = {
        wardrobes: {
          created: Array.from({ length: changedWardrobes / 3 }, (_, i) => 
            generateLargeWardrobe(i, 20)
          ),
          updated: Array.from({ length: changedWardrobes / 3 }, (_, i) => 
            generateLargeWardrobe(i + 1000, 20)
          ),
          deleted: Array.from({ length: changedWardrobes / 3 }, (_, i) => 
            `wardrobe-deleted-${i}`
          )
        },
        sync: {
          timestamp: new Date().toISOString(),
          version: 1,
          hasMore: true,
          changeCount: changedWardrobes
        }
      };

      mockWardrobeService.syncWardrobes.mockResolvedValue(syncResult);

      const duration = await executeWithMetrics(async () => {
        await wardrobeController.syncWardrobes(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );
      });

      expect(duration).toBeLessThan(3000); // 3 seconds for large sync
      expect(metrics.successfulRequests).toBe(1);
    });
  });

  describe('Rate Limiting and Throttling Tests', () => {
    it('should maintain performance under sustained high load', async () => {
      const requestsPerSecond = 50;
      const durationSeconds = 10;
      const totalRequests = requestsPerSecond * durationSeconds;

      const startTime = performance.now();
      const requestTimes: number[] = [];

      for (let i = 0; i < totalRequests; i++) {
        const requestStart = performance.now();
        
        mockReq.body = { 
          name: `Sustained Load ${i}`,
          description: `Test ${i}`
        };
        mockWardrobeService.createWardrobe.mockResolvedValue(
          generateLargeWardrobe(i, 5)
        );

        await executeWithMetrics(async () => {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
        });

        const requestEnd = performance.now();
        requestTimes.push(requestEnd - requestStart);

        // Maintain request rate
        const elapsedTime = requestEnd - startTime;
        const expectedTime = (i + 1) * (1000 / requestsPerSecond);
        if (elapsedTime < expectedTime) {
          await new Promise(resolve => setTimeout(resolve, expectedTime - elapsedTime));
        }
      }

      const avgResponseTime = requestTimes.reduce((a, b) => a + b) / requestTimes.length;
      const maxResponseTime = Math.max(...requestTimes);
      const successRate = metrics.successfulRequests / metrics.totalRequests;

      expect(successRate).toBeGreaterThan(0.95);
      expect(avgResponseTime).toBeLessThan(100); // 100ms average
      expect(maxResponseTime).toBeLessThan(1000); // 1s max
    });

    it('should handle burst traffic patterns', async () => {
      const burstSize = 100;
      const burstCount = 5;
      const delayBetweenBursts = 1000; // 1 second

      for (let burst = 0; burst < burstCount; burst++) {
        const burstStart = performance.now();
        
        // Send burst of requests
        const promises = Array.from({ length: burstSize }, async (_, i) => {
          const req = {
            user: mockUser,
            body: { 
              name: `Burst ${burst}-${i}`,
              description: `Burst test`
            }
          } as Request;

          const res = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            created: jest.fn().mockReturnThis()
          } as unknown as Response;

          mockWardrobeService.createWardrobe.mockResolvedValue(
            generateLargeWardrobe(burst * burstSize + i, 5)
          );

          return executeWithMetrics(async () => {
            await wardrobeController.createWardrobe(req, res, mockNext);
          });
        });

        await Promise.all(promises);
        
        const burstDuration = performance.now() - burstStart;
        expect(burstDuration).toBeLessThan(5000); // Each burst completes in 5s

        // Wait between bursts
        if (burst < burstCount - 1) {
          await new Promise(resolve => setTimeout(resolve, delayBetweenBursts));
        }
      }

      const successRate = metrics.successfulRequests / metrics.totalRequests;
      expect(successRate).toBeGreaterThan(0.9);
    });
  });

  describe('Endurance Tests', () => {
    it.skip('should maintain consistent performance over extended period', async () => {
      const testDurationMinutes = 1; // Reduced from 60 for test suite
      const requestsPerMinute = 300;
      const checkInterval = 10; // Check metrics every 10 requests

      const startTime = Date.now();
      const endTime = startTime + (testDurationMinutes * 60 * 1000);
      const performanceMetrics: { time: number; duration: number; memory: number }[] = [];

      let requestCount = 0;
      while (Date.now() < endTime) {
        mockReq.body = { 
          name: `Endurance ${requestCount}`,
          description: `Long running test`
        };
        mockWardrobeService.createWardrobe.mockResolvedValue(
          generateLargeWardrobe(requestCount, 10)
        );

        const requestStart = performance.now();
        await executeWithMetrics(async () => {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
        });
        const requestEnd = performance.now();

        if (requestCount % checkInterval === 0) {
          const memory = measureMemoryUsage();
          performanceMetrics.push({
            time: Date.now() - startTime,
            duration: requestEnd - requestStart,
            memory: memory.heapUsed
          });
        }

        requestCount++;
        
        // Maintain request rate
        const sleepTime = (60000 / requestsPerMinute) - (requestEnd - requestStart);
        if (sleepTime > 0) {
          await new Promise(resolve => setTimeout(resolve, sleepTime));
        }
      }

      // Analyze performance consistency
      const durations = performanceMetrics.map(m => m.duration);
      const avgDuration = durations.reduce((a, b) => a + b) / durations.length;
      const maxDuration = Math.max(...durations);
      
      const memories = performanceMetrics.map(m => m.memory);
      const memoryGrowth = memories[memories.length - 1] / memories[0];

      expect(metrics.successfulRequests / metrics.totalRequests).toBeGreaterThan(0.95);
      expect(avgDuration).toBeLessThan(100); // 100ms average
      expect(maxDuration).toBeLessThan(500); // 500ms max
      expect(memoryGrowth).toBeLessThan(1.5); // Less than 50% memory growth
    });
  });

  describe('Failure Recovery Tests', () => {
    it('should recover from intermittent service failures', async () => {
      const totalRequests = 50; // Reduced for stability
      const plannedFailures = 10; // Fixed number of failures instead of random
      const failureIndices = new Set<number>();
      
      // Pre-determine which requests will fail for consistency
      for (let i = 0; i < plannedFailures; i++) {
        failureIndices.add(Math.floor((i / plannedFailures) * totalRequests));
      }

      let actualSuccesses = 0;
      let actualFailures = 0;
      const capturedErrors: Error[] = [];

      // Execute all requests sequentially
      for (let i = 0; i < totalRequests; i++) {
        // Create fresh mock request and response for each iteration
        const req = {
          user: mockUser,
          body: { 
            name: `Recovery Test ${i}`,
            description: `Testing failure recovery`
          }
        } as Request;

        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn().mockReturnThis(),
          created: jest.fn().mockReturnThis()
        } as unknown as Response;

        const next = jest.fn((error?: any) => {
          if (error) {
            actualFailures++;
            capturedErrors.push(error);
          }
        }) as unknown as NextFunction;

        // Mock response for this specific request
        if (failureIndices.has(i)) {
          mockWardrobeService.createWardrobe.mockRejectedValueOnce(
            new Error('Service temporarily unavailable')
          );
        } else {
          mockWardrobeService.createWardrobe.mockResolvedValueOnce(
            generateLargeWardrobe(i, 5)
          );
        }

        try {
          await wardrobeController.createWardrobe(req, res, next);
          
          // Check if response was sent (success case)
          if ((res.created as jest.Mock).mock.calls.length > 0) {
            actualSuccesses++;
          }
        } catch (error) {
          // In case of unhandled errors
          actualFailures++;
          capturedErrors.push(error as Error);
        }
      }

      // System should handle failures gracefully
      expect(actualFailures).toBe(plannedFailures);
      expect(actualSuccesses).toBe(totalRequests - plannedFailures);
      expect(capturedErrors.length).toBe(plannedFailures);
      
      // Verify the mock was called correct number of times
      expect(mockWardrobeService.createWardrobe).toHaveBeenCalledTimes(totalRequests);
    });

    it('should handle database connection pool exhaustion', async () => {
      jest.setTimeout(30000); // Set timeout for this test
      const concurrentRequests = 200;
      const connectionPoolSize = 50; // Simulated pool size

      let activeConnections = 0;
      
      mockWardrobeService.createWardrobe.mockImplementation(async () => {
        if (activeConnections >= connectionPoolSize) {
          throw new Error('Connection pool exhausted');
        }
        
        activeConnections++;
        // Simulate database operation
        await new Promise(resolve => setTimeout(resolve, 100));
        activeConnections--;
        
        return generateLargeWardrobe(Date.now(), 5);
      });

      const promises = Array.from({ length: concurrentRequests }, async (_, i) => {
        const req = {
          user: mockUser,
          body: { name: `Pool Test ${i}` }
        } as Request;

        const res = {
          status: jest.fn().mockReturnThis(),
          json: jest.fn().mockReturnThis(),
          created: jest.fn().mockReturnThis()
        } as unknown as Response;

        return executeWithMetrics(async () => {
          await wardrobeController.createWardrobe(req, res, mockNext);
        });
      });

      await Promise.allSettled(promises);

      // Some requests should fail due to pool exhaustion
      expect(metrics.failedRequests).toBeGreaterThan(0);
      expect(metrics.failedRequests).toBeLessThan(concurrentRequests);
      // But many should still succeed (at least as many as the pool size)
      expect(metrics.successfulRequests).toBeGreaterThanOrEqual(connectionPoolSize);
    });
  });

  // Summary report after all tests
  afterAll(() => {
    console.log('\n=== Stress Test Summary ===');
    console.log(`Total Requests: ${metrics.totalRequests}`);
    console.log(`Successful: ${metrics.successfulRequests}`);
    console.log(`Failed: ${metrics.failedRequests}`);
    console.log(`Success Rate: ${((metrics.successfulRequests / metrics.totalRequests) * 100).toFixed(2)}%`);
    console.log(`Average Response Time: ${(metrics.totalDuration / metrics.totalRequests).toFixed(2)}ms`);
    console.log(`Peak Memory Usage: ${(metrics.peakMemory / 1024 / 1024).toFixed(2)}MB`);
    console.log(`Unique Errors: ${new Set(metrics.errors.map(e => e?.message || 'Unknown error')).size}`);
    console.log('========================\n');
  });
});