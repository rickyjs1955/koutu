// tests/stress/imageRoutes.stress.test.ts
import request from 'supertest';
import express from 'express';
import {
  createMockImage,
  resetAllMocks,
  setupHappyPathMocks
} from '../__mocks__/images.mock';

import {
  measurePerformance,
  runConcurrentOperations,
  simulateConcurrentUploads,
  createMemoryTestHelpers,
  createConcurrencyHelpers
} from '../__helpers__/images.helper';

describe('Image Routes - Stress Test Suite', () => {
  let app: express.Application;
  let server: any;
  
  // Stress test metrics
  const stressMetrics: {
    memoryLeaks: boolean;
    performanceDegradation: boolean;
    errorRates: { [key: string]: number };
    maxConcurrency: number;
    throughputLimits: { [key: string]: number };
    resourceExhaustion: boolean;
  } = {
    memoryLeaks: false,
    performanceDegradation: false,
    errorRates: {},
    maxConcurrency: 0,
    throughputLimits: {},
    resourceExhaustion: false
  };

  beforeAll(async () => {
    // Create Express app with stress testing optimizations
    app = express();
    
    // Increase limits for stress testing
    app.use(express.json({ limit: '100mb' }));
    app.use(express.urlencoded({ extended: true, limit: '100mb' }));
    
    // Enhanced auth for stress testing
    const mockAuth = (req: any, res: any, next: any) => {
      req.user = { 
        id: `stress-user-${Math.floor(Math.random() * 1000)}`, 
        email: 'stress@example.com', 
        role: 'user',
        permissions: ['read', 'write']
      };
      next();
    };
    
    // Memory and performance monitoring middleware
    const stressMonitor = (req: any, res: any, next: any) => {
      req.startTime = process.hrtime.bigint();
      req.memoryBefore = process.memoryUsage();
      
      res.on('finish', () => {
        const endTime = process.hrtime.bigint();
        const memoryAfter = process.memoryUsage();
        const duration = Number(endTime - req.startTime) / 1000000;
        
        // Track memory usage
        const memoryGrowth = memoryAfter.heapUsed - req.memoryBefore.heapUsed;
        if (memoryGrowth > 10 * 1024 * 1024) { // 10MB growth
          console.warn(`High memory growth detected: ${memoryGrowth / 1024 / 1024}MB`);
        }
        
        // Track performance degradation
        const route = `${req.method} ${req.route?.path || req.path}`;
        if (duration > 1000) { // Responses taking over 1 second
          console.warn(`Slow response detected for ${route}: ${duration}ms`);
          stressMetrics.performanceDegradation = true;
        }
        
        // Track error rates
        if (res.statusCode >= 400) {
          stressMetrics.errorRates[route] = (stressMetrics.errorRates[route] || 0) + 1;
        }
      });
      
      next();
    };
    
    const router = express.Router();
    
    router.use(stressMonitor);
    router.use(mockAuth);
    
    // Stress-optimized routes
    router.get('/', (req: any, res: any) => {
      const { page = 1, limit = 10, status, stress } = req.query;
      const pageNum = Math.max(1, Math.min(Number(page), 10000));
      const limitNum = Math.max(1, Math.min(Number(limit), 1000)); // Increased for stress testing
      
      // Simulate varying database load
      const loadFactor = stress === 'high' ? 5 : stress === 'medium' ? 2 : 1;
      const baseDelay = Math.random() * 10 * loadFactor;
      
      setTimeout(() => {
        const totalItems = Number(req.headers['x-stress-total-items']) || 100000;
        const data = Array.from({ length: Math.min(limitNum, 100) }, () => 
          createMockImage({ 
            user_id: req.user.id,
            status: status as any || 'new'
          })
        );
        
        res.json({
          success: true,
          data,
          pagination: {
            page: pageNum,
            limit: limitNum,
            total: totalItems,
            totalPages: Math.ceil(totalItems / limitNum)
          },
          stress: {
            loadFactor,
            responseTime: baseDelay,
            memoryUsage: process.memoryUsage().heapUsed
          }
        });
      }, baseDelay);
    });
    
    router.get('/stats', (req: any, res: any) => {
      const stress = req.query.stress || req.headers['x-stress-level'];
      const delay = stress === 'high' ? 100 : stress === 'medium' ? 50 : 10;
      
      setTimeout(() => {
        res.json({
          success: true,
          data: {
            total: 100000,
            byStatus: { new: 30000, processed: 40000, labeled: 30000 },
            totalSize: 204800000000, // 200GB
            averageSize: 2048000,
            storageUsedGB: 204.8,
            storageLimit: {
              maxImages: 1000000,
              maxStorageGB: 1000,
              quotaUsed: 0.2048
            },
            stress: {
              level: stress,
              processingTime: delay,
              activeConnections: Math.floor(Math.random() * 1000),
              queueLength: Math.floor(Math.random() * 100)
            }
          }
        });
      }, delay);
    });
    
    router.post('/upload', (req: any, res: any) => {
      const file = req.body.mockFile || { size: 2048000, mimetype: 'image/jpeg' };
      const stressLevel = req.headers['x-stress-level'] || 'low';
      
      // Simulate varying upload processing times
      const processingTime = stressLevel === 'high' ? 
        Math.random() * 500 + 200 : 
        stressLevel === 'medium' ? 
        Math.random() * 200 + 50 : 
        Math.random() * 50 + 10;
      
      setTimeout(() => {
        const mockImage = createMockImage({
          user_id: req.user.id,
          original_metadata: {
            ...file,
            stressProcessingTime: processingTime,
            stressLevel,
            uploadedAt: new Date().toISOString()
          }
        });
        
        res.status(201).json({
          success: true,
          data: mockImage,
          stress: {
            processingTime,
            fileSize: file.size,
            stressLevel,
            memoryUsage: process.memoryUsage().heapUsed
          }
        });
      }, processingTime);
    });
    
    router.put('/batch/status', (req: any, res: any) => {
      const { imageIds, status } = req.body;
      
      if (!Array.isArray(imageIds) || imageIds.length === 0 || imageIds.length > 10000) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_BATCH_SIZE', message: 'Batch size must be between 1 and 10000' }
        });
      }
      
      // Simulate batch processing with varying load
      const stressLevel = req.headers['x-stress-level'] || 'low';
      const baseProcessingTime = stressLevel === 'high' ? 2 : stressLevel === 'medium' ? 1 : 0.5;
      const processingDelay = Math.floor(imageIds.length * baseProcessingTime);
      
      // Simulate potential failures under stress
      const failureRate = stressLevel === 'high' ? 0.05 : stressLevel === 'medium' ? 0.02 : 0.01;
      const failures = Math.floor(imageIds.length * failureRate);
      
      setTimeout(() => {
        res.json({
          success: true,
          data: { 
            updated: imageIds.length - failures, 
            failed: failures,
            errors: failures > 0 ? Array.from({ length: failures }, (_, i) => ({
              imageId: imageIds[i],
              error: 'Processing timeout under stress',
              errorCode: 'STRESS_TIMEOUT'
            })) : []
          },
          stress: {
            batchSize: imageIds.length,
            processingTime: processingDelay,
            failureRate,
            stressLevel,
            queuePosition: Math.floor(Math.random() * 50)
          }
        });
      }, processingDelay);
    });
    
    router.get('/:id', (req: any, res: any) => {
      const stressLevel = req.headers['x-stress-level'] || 'low';
      const delay = stressLevel === 'high' ? 
        Math.random() * 100 + 50 : 
        stressLevel === 'medium' ? 
        Math.random() * 50 + 10 : 
        Math.random() * 10 + 1;
      
      setTimeout(() => {
        res.json({
          success: true,
          data: createMockImage({ 
            id: req.params.id,
            user_id: req.user.id
          }),
          stress: {
            retrievalTime: delay,
            stressLevel,
            cacheStatus: Math.random() > 0.7 ? 'hit' : 'miss'
          }
        });
      }, delay);
    });
    
    router.post('/:id/thumbnail', (req: any, res: any) => {
      const { size = 'medium', format = 'jpeg' } = req.body;
      const stressLevel = req.headers['x-stress-level'] || 'low';
      
      // Simulate resource-intensive thumbnail generation
      const processingTimes = { 
        small: stressLevel === 'high' ? 200 : 50, 
        medium: stressLevel === 'high' ? 400 : 100, 
        large: stressLevel === 'high' ? 800 : 200 
      };
      const delay = processingTimes[size as keyof typeof processingTimes] || 100;
      
      setTimeout(() => {
        res.json({
          success: true,
          data: { 
            thumbnailPath: `uploads/thumbnails/${req.params.id}_${size}.${format}`,
            size,
            format,
            dimensions: size === 'small' ? '150x150' : size === 'medium' ? '300x300' : '600x600'
          },
          stress: {
            processingTime: delay,
            stressLevel,
            cpuUsage: Math.random() * 100,
            memoryUsage: process.memoryUsage().heapUsed
          }
        });
      }, delay);
    });
    
    router.post('/:id/optimize', (req: any, res: any) => {
      const { quality = 80 } = req.body;
      const stressLevel = req.headers['x-stress-level'] || 'low';
      
      // Simulate CPU-intensive optimization
      const baseTime = 100 - quality; // Higher quality = more processing
      const stressMultiplier = stressLevel === 'high' ? 5 : stressLevel === 'medium' ? 2 : 1;
      const delay = baseTime * stressMultiplier;
      
      setTimeout(() => {
        res.json({
          success: true,
          data: { 
            optimizedPath: `uploads/optimized/${req.params.id}_optimized.jpeg`,
            originalSize: 2048000,
            optimizedSize: Math.floor(2048000 * (quality / 100)),
            compressionRatio: quality / 100
          },
          stress: {
            processingTime: delay,
            stressLevel,
            cpuIntensity: (100 - quality) * stressMultiplier,
            memoryPeak: process.memoryUsage().heapUsed
          }
        });
      }, delay);
    });
    
    router.delete('/:id', (req: any, res: any) => {
      const stressLevel = req.headers['x-stress-level'] || 'low';
      const delay = stressLevel === 'high' ? 50 : stressLevel === 'medium' ? 20 : 5;
      
      setTimeout(() => {
        res.json({
          success: true,
          data: {
            deletedAt: new Date().toISOString(),
            deletedBy: req.user.id
          },
          stress: {
            deletionTime: delay,
            stressLevel
          }
        });
      }, delay);
    });
    
    app.use('/api/v1/images', router);
    setupHappyPathMocks();
    
    server = app.listen(0);
  });
  
  beforeEach(() => {
    resetAllMocks();
    setupHappyPathMocks();
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  });
  
  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
    
    // Output stress test summary
    console.log('\n=== Stress Test Summary ===');
    console.log(`Memory leaks detected: ${stressMetrics.memoryLeaks}`);
    console.log(`Performance degradation: ${stressMetrics.performanceDegradation}`);
    console.log(`Max concurrency achieved: ${stressMetrics.maxConcurrency}`);
    console.log(`Resource exhaustion: ${stressMetrics.resourceExhaustion}`);
    console.log('Error rates by route:');
    Object.entries(stressMetrics.errorRates).forEach(([route, errors]) => {
      console.log(`  ${route}: ${errors} errors`);
    });
    console.log('============================\n');
  });

  describe('🔥 High Concurrency Stress Tests', () => {
    test('should handle extreme concurrent read operations', async () => {
      const concurrentReads = [50, 100, 200, 500];
      
      for (const concurrency of concurrentReads) {
        console.log(`\nTesting ${concurrency} concurrent reads...`);
        
        const readOperations = Array.from({ length: concurrency }, (_, i) => 
          () => request(app)
            .get(`/api/v1/images/stress-test-${i % 100}`)
            .set('x-stress-level', concurrency > 200 ? 'high' : 'medium')
            .timeout(10000)
        );

        const startTime = Date.now();
        const startMemory = process.memoryUsage().heapUsed;
        
        const { results, errors } = await runConcurrentOperations(readOperations, Math.min(concurrency, 50));
        
        const endTime = Date.now();
        const endMemory = process.memoryUsage().heapUsed;
        const totalDuration = endTime - startTime;
        const memoryGrowth = endMemory - startMemory;
        
        // Track maximum concurrency achieved
        stressMetrics.maxConcurrency = Math.max(stressMetrics.maxConcurrency, concurrency);
        
        // Analyze results
        const successRate = (results.length / (results.length + errors.length)) * 100;
        const avgResponseTime = totalDuration / concurrency;
        
        console.log(`  Success rate: ${successRate.toFixed(2)}%`);
        console.log(`  Total time: ${totalDuration}ms`);
        console.log(`  Avg response time: ${avgResponseTime.toFixed(2)}ms`);
        console.log(`  Memory growth: ${(memoryGrowth / 1024 / 1024).toFixed(2)}MB`);
        
        // Assertions based on concurrency level
        if (concurrency <= 100) {
          expect(successRate).toBeGreaterThan(95); // 95%+ success rate for moderate load
          expect(avgResponseTime).toBeLessThan(500); // Average under 500ms
        } else if (concurrency <= 200) {
          expect(successRate).toBeGreaterThan(85); // 85%+ success rate for high load
          expect(avgResponseTime).toBeLessThan(1000); // Average under 1s
        } else {
          expect(successRate).toBeGreaterThan(70); // 70%+ success rate for extreme load
          expect(avgResponseTime).toBeLessThan(2000); // Average under 2s
        }
        
        // Memory growth should be reasonable
        expect(memoryGrowth).toBeLessThan(100 * 1024 * 1024); // Less than 100MB growth
        
        // Cool down period
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    });

    test('should handle mixed high-concurrency workloads', async () => {
      const totalOperations = 300;
      const mixedOperations = [];
      
      // Create a mix of operations
      for (let i = 0; i < totalOperations; i++) {
        const operationType = i % 4;
        
        switch (operationType) {
          case 0: // Read operation
            mixedOperations.push(() => 
              request(app)
                .get(`/api/v1/images/mixed-${i}`)
                .set('x-stress-level', 'high')
                .timeout(15000)
            );
            break;
          case 1: // Batch operation
            mixedOperations.push(() => {
              const batchSize = Math.floor(Math.random() * 20) + 5;
              const imageIds = Array.from({ length: batchSize }, (_, j) => `batch-${i}-${j}`);
              return request(app)
                .put('/api/v1/images/batch/status')
                .send({ imageIds, status: 'processed' })
                .set('x-stress-level', 'high')
                .timeout(15000);
            });
            break;
          case 2: // Upload operation
            mixedOperations.push(() => {
              const fileSize = Math.floor(Math.random() * 5000000) + 500000; // 500KB - 5MB
              return request(app)
                .post('/api/v1/images/upload')
                .send({ 
                  mockFile: { 
                    originalname: `stress-${i}.jpg`, 
                    mimetype: 'image/jpeg', 
                    size: fileSize 
                  }
                })
                .set('x-stress-level', 'high')
                .timeout(15000);
            });
            break;
          case 3: // Stats operation
            mixedOperations.push(() => 
              request(app)
                .get('/api/v1/images/stats')
                .query({ stress: 'high' })
                .timeout(15000)
            );
            break;
        }
      }

      console.log(`\nTesting ${totalOperations} mixed operations...`);
      
      const startTime = Date.now();
      const startMemory = process.memoryUsage().heapUsed;
      
      const { results, errors } = await runConcurrentOperations(mixedOperations, 25);
      
      const endTime = Date.now();
      const endMemory = process.memoryUsage().heapUsed;
      const totalDuration = endTime - startTime;
      const memoryGrowth = endMemory - startMemory;
      
      const successRate = (results.length / (results.length + errors.length)) * 100;
      const throughput = results.length / (totalDuration / 1000); // operations per second
      
      console.log(`  Success rate: ${successRate.toFixed(2)}%`);
      console.log(`  Throughput: ${throughput.toFixed(2)} ops/sec`);
      console.log(`  Memory growth: ${(memoryGrowth / 1024 / 1024).toFixed(2)}MB`);
      
      // Mixed workload should maintain reasonable performance
      expect(successRate).toBeGreaterThan(75); // 75%+ success rate
      expect(throughput).toBeGreaterThan(5); // At least 5 operations per second
      expect(memoryGrowth).toBeLessThan(200 * 1024 * 1024); // Less than 200MB growth
    });

    test('should handle burst traffic patterns', async () => {
      const burstSizes = [10, 50, 100, 200];
      const burstInterval = 500; // 500ms between bursts
      
      for (const burstSize of burstSizes) {
        console.log(`\nTesting burst of ${burstSize} operations...`);
        
        const burstOperations = Array.from({ length: burstSize }, (_, i) => 
          () => request(app)
            .get('/api/v1/images')
            .query({ page: 1, limit: 10, stress: 'high' })
            .timeout(10000)
        );

        const startTime = Date.now();
        const { results, errors } = await runConcurrentOperations(burstOperations, burstSize);
        const endTime = Date.now();
        const burstDuration = endTime - startTime;
        
        const successRate = (results.length / (results.length + errors.length)) * 100;
        const peakThroughput = results.length / (burstDuration / 1000);
        
        console.log(`  Burst duration: ${burstDuration}ms`);
        console.log(`  Success rate: ${successRate.toFixed(2)}%`);
        console.log(`  Peak throughput: ${peakThroughput.toFixed(2)} ops/sec`);
        
        // Burst handling should be resilient
        expect(successRate).toBeGreaterThan(60); // At least 60% success during bursts
        expect(burstDuration).toBeLessThan(burstSize * 100); // Reasonable processing time
        
        // Cool down between bursts
        await new Promise(resolve => setTimeout(resolve, burstInterval));
      }
    });
  });

  describe('💾 Memory Stress Tests', () => {
    test('should detect memory leaks under sustained load', async () => {
      const memoryTestHelpers = createMemoryTestHelpers();
      
      const sustainedOperation = async () => {
        const operations = [
          () => request(app).get('/api/v1/images').query({ page: 1, limit: 25 }),
          () => request(app).get('/api/v1/images/stats'),
          () => request(app).post('/api/v1/images/upload').send({ 
            mockFile: { originalname: 'memory-test.jpg', mimetype: 'image/jpeg', size: 1024000 }
          }),
          () => {
            const imageIds = Array.from({ length: 10 }, (_, i) => `memory-${i}`);
            return request(app)
              .put('/api/v1/images/batch/status')
              .send({ imageIds, status: 'processed' });
          }
        ];
        
        const randomOperation = operations[Math.floor(Math.random() * operations.length)];
        await randomOperation();
      };

      const memoryResults = await memoryTestHelpers.detectMemoryLeaks(sustainedOperation, 100);
      
      console.log('\nMemory leak detection results:');
      console.log(`  Initial heap: ${(memoryResults.initial.heapUsed / 1024 / 1024).toFixed(2)}MB`);
      console.log(`  Final heap: ${(memoryResults.final.heapUsed / 1024 / 1024).toFixed(2)}MB`);
      console.log(`  Heap growth: ${(memoryResults.growth.heapUsed / 1024 / 1024).toFixed(2)}MB`);
      console.log(`  Memory leak detected: ${memoryResults.hasLeak}`);
      
      stressMetrics.memoryLeaks = memoryResults.hasLeak;
      
      // Memory growth should be minimal for repeated operations
      expect(memoryResults.hasLeak).toBe(false);
      expect(memoryResults.growth.heapUsed).toBeLessThan(50 * 1024 * 1024); // Less than 50MB growth
    });

    test('should handle large file uploads without memory exhaustion', async () => {
      const fileSizes = [10, 25, 50, 100]; // MB
      
      for (const sizeMB of fileSizes) {
        console.log(`\nTesting ${sizeMB}MB file upload...`);
        
        const fileSize = sizeMB * 1024 * 1024;
        const startMemory = process.memoryUsage().heapUsed;
        
        const result = await measurePerformance(async () => {
          return await request(app)
            .post('/api/v1/images/upload')
            .send({ 
              mockFile: { 
                originalname: `large-${sizeMB}mb.jpg`, 
                mimetype: 'image/jpeg', 
                size: fileSize 
              }
            })
            .set('x-stress-level', 'high')
            .timeout(30000);
        }, `Large Upload ${sizeMB}MB`);
        
        const endMemory = process.memoryUsage().heapUsed;
        const memoryGrowth = endMemory - startMemory;
        
        console.log(`  Upload time: ${result.duration.toFixed(2)}ms`);
        console.log(`  Memory growth: ${(memoryGrowth / 1024 / 1024).toFixed(2)}MB`);
        
        expect(result.result.body.success).toBe(true);
        
        // Memory growth should be reasonable relative to file size
        expect(memoryGrowth).toBeLessThan(fileSize * 2); // Less than 2x file size
        
        // Force garbage collection
        if (global.gc) {
          global.gc();
        }
        
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    });

    test('should handle concurrent large operations', async () => {
      const concurrentLargeOps = 10;
      
      const largeOperations = Array.from({ length: concurrentLargeOps }, (_, i) => {
        const opType = i % 3;
        
        switch (opType) {
          case 0: // Large upload
            return () => request(app)
              .post('/api/v1/images/upload')
              .send({ 
                mockFile: { 
                  originalname: `concurrent-large-${i}.jpg`, 
                  mimetype: 'image/jpeg', 
                  size: 10 * 1024 * 1024 // 10MB
                }
              })
              .set('x-stress-level', 'high')
              .timeout(30000);
              
          case 1: // Large batch
            return () => {
              const imageIds = Array.from({ length: 500 }, (_, j) => `large-batch-${i}-${j}`);
              return request(app)
                .put('/api/v1/images/batch/status')
                .send({ imageIds, status: 'processed' })
                .set('x-stress-level', 'high')
                .timeout(30000);
            };
            
          case 2: // Large listing
            return () => request(app)
              .get('/api/v1/images')
              .query({ page: 1, limit: 100, stress: 'high' })
              .set('x-stress-total-items', '100000')
              .timeout(30000);
              
          default:
            return () => request(app).get('/api/v1/images/stats');
        }
      });

      const startMemory = process.memoryUsage().heapUsed;
      
      const { results, errors } = await runConcurrentOperations(largeOperations, 5);
      
      const endMemory = process.memoryUsage().heapUsed;
      const memoryGrowth = endMemory - startMemory;
      
      const successRate = (results.length / (results.length + errors.length)) * 100;
      
      console.log(`\nConcurrent large operations results:`);
      console.log(`  Success rate: ${successRate.toFixed(2)}%`);
      console.log(`  Memory growth: ${(memoryGrowth / 1024 / 1024).toFixed(2)}MB`);
      
      expect(successRate).toBeGreaterThan(50); // At least 50% success for large operations
      expect(memoryGrowth).toBeLessThan(500 * 1024 * 1024); // Less than 500MB growth
    });
  });

  describe('⚡ Throughput Stress Tests', () => {
    test('should maintain throughput under sustained high load', async () => {
      const testDuration = 30000; // 30 seconds
      const requestInterval = 50; // 50ms between requests
      const totalRequests = Math.floor(testDuration / requestInterval);
      
      console.log(`\nSustained load test: ${totalRequests} requests over ${testDuration / 1000}s`);
      
      const throughputResults: number[] = [];
      const errorCount: number[] = [];
      let requestCount = 0;
      
      const startTime = Date.now();
      
      // Launch requests at regular intervals
      const requestPromises: Promise<any>[] = [];
      
      for (let i = 0; i < totalRequests; i++) {
        const requestPromise = new Promise((resolve) => {
          setTimeout(async () => {
            try {
              const response = await request(app)
                .get('/api/v1/images')
                .query({ page: Math.floor(Math.random() * 100) + 1, limit: 10 })
                .set('x-stress-level', 'medium')
                .timeout(5000);
                
              requestCount++;
              resolve({ success: true, status: response.status });
            } catch (error) {
              resolve({ success: false, error });
            }
          }, i * requestInterval);
        });
        
        requestPromises.push(requestPromise);
      }
      
      // Track throughput every 5 seconds
      const throughputInterval = setInterval(() => {
        const currentTime = Date.now();
        const elapsed = currentTime - startTime;
        const currentThroughput = (requestCount / elapsed) * 1000; // requests per second
        throughputResults.push(currentThroughput);
        
        console.log(`  ${(elapsed / 1000).toFixed(1)}s: ${currentThroughput.toFixed(2)} req/s`);
      }, 5000);
      
      await Promise.allSettled(requestPromises);
      clearInterval(throughputInterval);
      
      const endTime = Date.now();
      const actualDuration = endTime - startTime;
      const avgThroughput = (requestCount / actualDuration) * 1000;
      
      console.log(`\nSustained load results:`);
      console.log(`  Total requests: ${requestCount}/${totalRequests}`);
      console.log(`  Average throughput: ${avgThroughput.toFixed(2)} req/s`);
      console.log(`  Duration: ${(actualDuration / 1000).toFixed(2)}s`);
      
      // Track throughput limits
      stressMetrics.throughputLimits['sustained_load'] = avgThroughput;
      
      expect(avgThroughput).toBeGreaterThan(5); // At least 5 requests per second
      expect(requestCount / totalRequests).toBeGreaterThan(0.8); // At least 80% completion rate
    });

    test('should handle throughput spikes gracefully', async () => {
      const spikeDurations = [1000, 2000, 5000]; // Spike durations in ms
      const spikeIntensities = [20, 50, 100]; // Requests per spike
      
      for (let i = 0; i < spikeDurations.length; i++) {
        const duration = spikeDurations[i];
        const intensity = spikeIntensities[i];
        
        console.log(`\nTesting throughput spike: ${intensity} requests in ${duration}ms`);
        
        const spikeOperations = Array.from({ length: intensity }, (_, j) => 
          () => request(app)
            .get('/api/v1/images')
            .query({ page: j % 10 + 1, limit: 5 })
            .set('x-stress-level', 'high')
            .timeout(10000)
        );

        const startTime = Date.now();
        const { results, errors } = await runConcurrentOperations(spikeOperations, Math.min(intensity, 20));
        const endTime = Date.now();
        const actualDuration = endTime - startTime;
        
        const successRate = (results.length / (results.length + errors.length)) * 100;
        const peakThroughput = results.length / (actualDuration / 1000);
        
        console.log(`  Success rate: ${successRate.toFixed(2)}%`);
        console.log(`  Peak throughput: ${peakThroughput.toFixed(2)} req/s`);
        console.log(`  Actual duration: ${actualDuration}ms`);
        
        // Spike handling should degrade gracefully
        expect(successRate).toBeGreaterThan(40); // At least 40% success during spikes
        
        // Cool down between spikes
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    });
  });

  describe('🛠️ Resource Exhaustion Tests', () => {
    test('should handle CPU-intensive operations under load', async () => {
      const cpuIntensiveOps = 20;
      
      const intensiveOperations = Array.from({ length: cpuIntensiveOps }, (_, i) => {
        const opType = i % 3;
        
        switch (opType) {
          case 0: // High-quality optimization
            return () => request(app)
              .post(`/api/v1/images/cpu-test-${i}/optimize`)
              .send({ quality: 95, format: 'jpeg' })
              .set('x-stress-level', 'high')
              .timeout(15000);
              
          case 1: // Large thumbnail generation
            return () => request(app)
              .post(`/api/v1/images/cpu-test-${i}/thumbnail`)
              .send({ size: 'large', format: 'png' })
              .set('x-stress-level', 'high')
              .timeout(15000);
              
          case 2: // Complex stats calculation
            return () => request(app)
              .get('/api/v1/images/stats')
              .query({ stress: 'high' })
              .timeout(15000);
              
          default:
            return () => request(app).get('/api/v1/images/stats');
        }
      });

      console.log(`\nTesting ${cpuIntensiveOps} CPU-intensive operations...`);
      
      const startTime = Date.now();
      const { results, errors } = await runConcurrentOperations(intensiveOperations, 5);
      const endTime = Date.now();
      const totalDuration = endTime - startTime;
      
      const successRate = (results.length / (results.length + errors.length)) * 100;
      const avgProcessingTime = totalDuration / cpuIntensiveOps;
      
      console.log(`  Success rate: ${successRate.toFixed(2)}%`);
      console.log(`  Total duration: ${totalDuration}ms`);
      console.log(`  Avg processing time: ${avgProcessingTime.toFixed(2)}ms`);
      
      expect(successRate).toBeGreaterThan(60); // At least 60% success for CPU-intensive ops
      expect(totalDuration).toBeLessThan(30000); // Should complete within 30 seconds
    });

    test('should handle extreme batch sizes', async () => {
      const extremeBatchSizes = [1000, 2500, 5000, 10000];
      
      for (const batchSize of extremeBatchSizes) {
        console.log(`\nTesting extreme batch size: ${batchSize} items`);
        
        const imageIds = Array.from({ length: batchSize }, (_, i) => `extreme-${batchSize}-${i}`);
        
        const startTime = Date.now();
        const startMemory = process.memoryUsage().heapUsed;
        
        try {
          const response = await request(app)
            .put('/api/v1/images/batch/status')
            .send({ imageIds, status: 'processed' })
            .set('x-stress-level', 'high')
            .timeout(60000);
            
          const endTime = Date.now();
          const endMemory = process.memoryUsage().heapUsed;
          const duration = endTime - startTime;
          const memoryGrowth = endMemory - startMemory;
          
          console.log(`  Duration: ${duration}ms`);
          console.log(`  Memory growth: ${(memoryGrowth / 1024 / 1024).toFixed(2)}MB`);
          console.log(`  Success: ${response.body.success}`);
          
          if (response.body.success) {
            expect(response.body.data.updated).toBeGreaterThan(batchSize * 0.8); // At least 80% processed
            expect(duration).toBeLessThan(batchSize * 2); // Reasonable processing time
          }
          
        } catch (error) {
          console.log(`  Failed with error: ${error}`);
          // Large batches may fail, which is acceptable behavior
          if (batchSize <= 2500) {
            throw error; // Smaller batches should succeed
          }
        }
        
        // Clean up memory
        if (global.gc) {
          global.gc();
        }
        
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    });

    test('should handle resource starvation scenarios', async () => {
      const concurrencyHelpers = createConcurrencyHelpers();
      
      // Create resource-heavy operations
      const resourceHeavyOps = [
        // Multiple large uploads
        ...Array.from({ length: 5 }, (_, i) => () => 
          request(app)
            .post('/api/v1/images/upload')
            .send({ 
              mockFile: { 
                originalname: `heavy-${i}.jpg`, 
                mimetype: 'image/jpeg', 
                size: 20 * 1024 * 1024 // 20MB
              }
            })
            .set('x-stress-level', 'high')
            .timeout(30000)
        ),
        // Multiple large batches
        ...Array.from({ length: 3 }, (_, i) => () => {
          const imageIds = Array.from({ length: 1000 }, (_, j) => `resource-${i}-${j}`);
          return request(app)
            .put('/api/v1/images/batch/status')
            .send({ imageIds, status: 'processed' })
            .set('x-stress-level', 'high')
            .timeout(30000);
        }),
        // Multiple CPU-intensive operations
        ...Array.from({ length: 5 }, (_, i) => () => 
          request(app)
            .post(`/api/v1/images/resource-test-${i}/optimize`)
            .send({ quality: 98, format: 'png' })
            .set('x-stress-level', 'high')
            .timeout(30000)
        )
      ];

      console.log(`\nTesting resource starvation with ${resourceHeavyOps.length} heavy operations...`);
      
      const startTime = Date.now();
      const results = await concurrencyHelpers.runConcurrentValidations(
        Array.from({ length: resourceHeavyOps.length }, () => Buffer.alloc(1024)),
        async () => {
          const randomOp = resourceHeavyOps[Math.floor(Math.random() * resourceHeavyOps.length)];
          return await randomOp();
        }
      );
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      console.log(`  Successful: ${results.successful}`);
      console.log(`  Failed: ${results.failed}`);
      console.log(`  Total duration: ${duration}ms`);
      
      const successRate = (results.successful / (results.successful + results.failed)) * 100;
      
      // Under resource starvation, some failures are expected
      expect(successRate).toBeGreaterThan(30); // At least 30% success under starvation
      expect(duration).toBeLessThan(120000); // Should complete within 2 minutes
      
      if (successRate < 50) {
        stressMetrics.resourceExhaustion = true;
      }
    });
  });

  describe('🔄 Resilience and Recovery Tests', () => {
    test('should recover from temporary overload', async () => {
      console.log('\nTesting recovery from overload...');
      
      // Phase 1: Create overload
      const overloadOps = Array.from({ length: 100 }, (_, i) => 
        () => request(app)
          .get('/api/v1/images')
          .query({ page: i % 50 + 1, limit: 20 })
          .set('x-stress-level', 'high')
          .timeout(5000)
      );

      console.log('  Phase 1: Creating overload...');
      const overloadResults = await runConcurrentOperations(overloadOps, 30);
      const overloadSuccessRate = (overloadResults.results.length / 
        (overloadResults.results.length + overloadResults.errors.length)) * 100;
      
      console.log(`  Overload success rate: ${overloadSuccessRate.toFixed(2)}%`);
      
      // Phase 2: Cool down period
      console.log('  Phase 2: Cool down period...');
      await new Promise(resolve => setTimeout(resolve, 5000));
      
      // Phase 3: Test recovery
      console.log('  Phase 3: Testing recovery...');
      const recoveryOps = Array.from({ length: 20 }, (_, i) => 
        () => request(app)
          .get('/api/v1/images')
          .query({ page: i % 10 + 1, limit: 10 })
          .set('x-stress-level', 'low')
          .timeout(5000)
      );

      const recoveryResults = await runConcurrentOperations(recoveryOps, 10);
      const recoverySuccessRate = (recoveryResults.results.length / 
        (recoveryResults.results.length + recoveryResults.errors.length)) * 100;
      
      console.log(`  Recovery success rate: ${recoverySuccessRate.toFixed(2)}%`);
      
      // System should recover to near-normal performance
      expect(recoverySuccessRate).toBeGreaterThan(80); // 80%+ success after recovery
      expect(recoverySuccessRate).toBeGreaterThan(overloadSuccessRate); // Better than during overload
    });

    test('should maintain partial functionality under stress', async () => {
      const criticalOps = [
        () => request(app).get('/api/v1/images/stats').timeout(10000),
        () => request(app).get('/api/v1/images').query({ page: 1, limit: 5 }).timeout(10000)
      ];
      
      const nonCriticalOps = [
        () => request(app).post('/api/v1/images/upload').send({ 
          mockFile: { originalname: 'test.jpg', mimetype: 'image/jpeg', size: 5000000 }
        }).timeout(10000),
        () => {
          const imageIds = Array.from({ length: 100 }, (_, i) => `partial-${i}`);
          return request(app)
            .put('/api/v1/images/batch/status')
            .send({ imageIds, status: 'processed' })
            .timeout(10000);
        }
      ];

      // Create stress with non-critical operations
      const stressOps = Array.from({ length: 50 }, () => 
        nonCriticalOps[Math.floor(Math.random() * nonCriticalOps.length)]
      );
      
      // Run stress operations
      const stressPromise = runConcurrentOperations(stressOps, 20);
      
      // While under stress, test critical operations
      await new Promise(resolve => setTimeout(resolve, 1000)); // Let stress build up
      
      const criticalResults = await runConcurrentOperations(
        Array.from({ length: 10 }, () => 
          criticalOps[Math.floor(Math.random() * criticalOps.length)]
        ), 
        5
      );
      
      const criticalSuccessRate = (criticalResults.results.length / 
        (criticalResults.results.length + criticalResults.errors.length)) * 100;
      
      await stressPromise; // Wait for stress operations to complete
      
      console.log(`  Critical operations success rate under stress: ${criticalSuccessRate.toFixed(2)}%`);
      
      // Critical operations should maintain higher success rate even under stress
      expect(criticalSuccessRate).toBeGreaterThan(70); // 70%+ success for critical ops
    });
  });
});