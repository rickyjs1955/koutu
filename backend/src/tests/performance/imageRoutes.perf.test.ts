// tests/performance/imageRoutes.perf.test.ts
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
  createTestImageRecords,
  generateLargeDataset
} from '../__helpers__/images.helper';

describe('Image Routes - Performance Test Suite', () => {
  let app: express.Application;
  let server: any;
  
  // Performance tracking
  const performanceMetrics: {
    [key: string]: {
      min: number;
      max: number;
      avg: number;
      p95: number;
      p99: number;
      throughput: number;
      samples: number[];
    }
  } = {};

  beforeAll(async () => {
    // Create Express app optimized for performance testing
    app = express();
    
    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ extended: true, limit: '50mb' }));
    
    // Simplified auth for performance testing
    const mockAuth = (req: any, res: any, next: any) => {
      req.user = { 
        id: 'perf-test-user-id', 
        email: 'perf@example.com', 
        role: 'user',
        permissions: ['read', 'write']
      };
      next();
    };
    
    // Performance monitoring middleware
    const performanceMonitor = (req: any, res: any, next: any) => {
      req.startTime = process.hrtime.bigint();
      
      res.on('finish', () => {
        const endTime = process.hrtime.bigint();
        const duration = Number(endTime - req.startTime) / 1000000; // Convert to milliseconds
        
        const route = `${req.method} ${req.route?.path || req.path}`;
        
        if (!performanceMetrics[route]) {
          performanceMetrics[route] = {
            min: duration,
            max: duration,
            avg: duration,
            p95: duration,
            p99: duration,
            throughput: 0,
            samples: []
          };
        }
        
        const metrics = performanceMetrics[route];
        metrics.samples.push(duration);
        metrics.min = Math.min(metrics.min, duration);
        metrics.max = Math.max(metrics.max, duration);
        metrics.avg = metrics.samples.reduce((sum, val) => sum + val, 0) / metrics.samples.length;
        
        // Calculate percentiles
        const sorted = [...metrics.samples].sort((a, b) => a - b);
        metrics.p95 = sorted[Math.floor(sorted.length * 0.95)];
        metrics.p99 = sorted[Math.floor(sorted.length * 0.99)];
        metrics.throughput = 1000 / metrics.avg; // requests per second
      });
      
      next();
    };
    
    const router = express.Router();
    
    router.use(performanceMonitor);
    router.use(mockAuth);
    
    // Optimized routes for performance testing
    router.get('/', (req: any, res: any) => {
      const { page = 1, limit = 10, status } = req.query;
      const pageNum = Math.max(1, Math.min(Number(page), 1000));
      const limitNum = Math.max(1, Math.min(Number(limit), 100));
      
      // Simulate database query with controlled delay
      const queryDelay = req.headers['x-perf-delay'] ? Number(req.headers['x-perf-delay']) : 0;
      
      setTimeout(() => {
        const totalItems = req.headers['x-perf-total-items'] ? Number(req.headers['x-perf-total-items']) : 1000;
        const data = Array.from({ length: Math.min(limitNum, totalItems) }, (_, i) => 
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
          performance: {
            queryTime: queryDelay,
            itemCount: data.length,
            timestamp: new Date().toISOString()
          }
        });
      }, queryDelay);
    });
    
    router.get('/stats', (req: any, res: any) => {
      const delay = req.headers['x-perf-delay'] ? Number(req.headers['x-perf-delay']) : 0;
      
      setTimeout(() => {
        res.json({
          success: true,
          data: {
            total: 10000,
            byStatus: { new: 3000, processed: 4000, labeled: 3000 },
            totalSize: 20480000000, // 20GB
            averageSize: 2048000, // 2MB
            storageUsedGB: 20.48,
            storageLimit: {
              maxImages: 100000,
              maxStorageGB: 500,
              quotaUsed: 0.04
            },
            performance: {
              calculationTime: delay,
              cacheHit: req.headers['x-perf-cache-hit'] === 'true',
              timestamp: new Date().toISOString()
            }
          }
        });
      }, delay);
    });
    
    router.post('/upload', (req: any, res: any) => {
      const file = req.body.mockFile || { size: 2048000, mimetype: 'image/jpeg' };
      const processingDelay = Math.floor(file.size / 100000); // Simulate processing time based on size
      
      setTimeout(() => {
        const mockImage = createMockImage({
          user_id: req.user.id,
          original_metadata: {
            ...file,
            processingTime: processingDelay,
            uploadedAt: new Date().toISOString()
          }
        });
        
        res.status(201).json({
          success: true,
          data: mockImage,
          performance: {
            processingTime: processingDelay,
            fileSize: file.size,
            throughput: file.size / processingDelay || 0
          }
        });
      }, processingDelay);
    });
    
    router.put('/batch/status', (req: any, res: any) => {
      const { imageIds, status } = req.body;
      
      if (!Array.isArray(imageIds) || imageIds.length === 0 || imageIds.length > 1000) {
        return res.status(400).json({
          success: false,
          error: { code: 'INVALID_BATCH_SIZE', message: 'Batch size must be between 1 and 1000' }
        });
      }
      
      // Simulate batch processing time
      const processingDelay = Math.floor(imageIds.length / 10); // 10ms per item
      
      setTimeout(() => {
        res.json({
          success: true,
          data: { 
            updated: imageIds.length, 
            failed: 0 
          },
          performance: {
            batchSize: imageIds.length,
            processingTime: processingDelay,
            itemsPerSecond: imageIds.length / (processingDelay / 1000) || 0
          }
        });
      }, processingDelay);
    });
    
    router.get('/:id', (req: any, res: any) => {
      const delay = req.headers['x-perf-delay'] ? Number(req.headers['x-perf-delay']) : 1;
      
      setTimeout(() => {
        res.json({
          success: true,
          data: createMockImage({ 
            id: req.params.id,
            user_id: req.user.id
          }),
          performance: {
            queryTime: delay,
            cached: req.headers['x-perf-cached'] === 'true'
          }
        });
      }, delay);
    });
    
    router.post('/:id/thumbnail', (req: any, res: any) => {
      const { size = 'medium', format = 'jpeg' } = req.body;
      
      // Simulate thumbnail generation time based on size
      const processingTimes = { small: 50, medium: 100, large: 200 };
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
          performance: {
            processingTime: delay,
            outputSize: size,
            format
          }
        });
      }, delay);
    });
    
    router.post('/:id/optimize', (req: any, res: any) => {
      const { quality = 80 } = req.body;
      
      // Simulate optimization time based on quality
      const delay = Math.floor(100 - quality); // Higher quality = more processing time
      
      setTimeout(() => {
        res.json({
          success: true,
          data: { 
            optimizedPath: `uploads/optimized/${req.params.id}_optimized.jpeg`,
            originalSize: 2048000,
            optimizedSize: Math.floor(2048000 * (quality / 100)),
            compressionRatio: quality / 100
          },
          performance: {
            processingTime: delay,
            compressionRatio: quality / 100,
            spaceSaved: Math.floor(2048000 * (1 - quality / 100))
          }
        });
      }, delay);
    });
    
    router.delete('/:id', (req: any, res: any) => {
      const delay = req.headers['x-perf-delay'] ? Number(req.headers['x-perf-delay']) : 5;
      
      setTimeout(() => {
        res.json({
          success: true,
          data: {
            deletedAt: new Date().toISOString(),
            deletedBy: req.user.id
          },
          performance: {
            deletionTime: delay
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
  });
  
  afterAll(async () => {
    if (server) {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    }
    
    // Output performance summary
    console.log('\n=== Performance Test Summary ===');
    Object.entries(performanceMetrics).forEach(([route, metrics]) => {
      console.log(`${route}:`);
      console.log(`  Samples: ${metrics.samples.length}`);
      console.log(`  Min: ${metrics.min.toFixed(2)}ms`);
      console.log(`  Avg: ${metrics.avg.toFixed(2)}ms`);
      console.log(`  Max: ${metrics.max.toFixed(2)}ms`);
      console.log(`  P95: ${metrics.p95.toFixed(2)}ms`);
      console.log(`  P99: ${metrics.p99.toFixed(2)}ms`);
      console.log(`  Throughput: ${metrics.throughput.toFixed(2)} req/s`);
      console.log('');
    });
    console.log('================================\n');
  });

  describe('📊 Basic Performance Benchmarks', () => {
    test('should handle single image listing with acceptable latency', async () => {
      const { result, duration } = await measurePerformance(async () => {
        return await request(app)
          .get('/api/v1/images')
          .query({ page: 1, limit: 10 })
          .expect(200);
      }, 'Single Image Listing');

      expect(result.body.success).toBe(true);
      expect(result.body.data).toHaveLength(10);
      expect(duration).toBeLessThan(100); // Should complete within 100ms
    });

    test('should handle image stats retrieval efficiently', async () => {
      const { result, duration } = await measurePerformance(async () => {
        return await request(app)
          .get('/api/v1/images/stats')
          .expect(200);
      }, 'Stats Retrieval');

      expect(result.body.success).toBe(true);
      expect(result.body.data.total).toBeDefined();
      expect(duration).toBeLessThan(50); // Should be very fast
    });

    test('should handle single image upload efficiently', async () => {
      const mockFile = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024000 // 1MB
      };

      const { result, duration } = await measurePerformance(async () => {
        return await request(app)
          .post('/api/v1/images/upload')
          .send({ mockFile })
          .expect(201);
      }, 'Single Upload');

      expect(result.body.success).toBe(true);
      expect(result.body.data.id).toBeDefined();
      expect(duration).toBeLessThan(500); // Should complete within 500ms for 1MB
    });

    test('should handle individual image retrieval quickly', async () => {
      const { result, duration } = await measurePerformance(async () => {
        return await request(app)
          .get('/api/v1/images/123e4567-e89b-12d3-a456-426614174000')
          .set('x-perf-cached', 'true')
          .expect(200);
      }, 'Individual Image Retrieval');

      expect(result.body.success).toBe(true);
      expect(result.body.data.id).toBeDefined();
      expect(duration).toBeLessThan(25); // Cached retrieval should be very fast
    });

    test('should handle thumbnail generation within time limits', async () => {
      const sizes = ['small', 'medium', 'large'];
      const maxTimes = { small: 100, medium: 150, large: 250 };

      for (const size of sizes) {
        const { result, duration } = await measurePerformance(async () => {
          return await request(app)
            .post('/api/v1/images/123e4567-e89b-12d3-a456-426614174000/thumbnail')
            .send({ size, format: 'jpeg' })
            .expect(200);
        }, `Thumbnail Generation (${size})`);

        expect(result.body.success).toBe(true);
        expect(result.body.data.size).toBe(size);
        expect(duration).toBeLessThan(maxTimes[size as keyof typeof maxTimes]);
      }
    });

    test('should handle image optimization efficiently', async () => {
      const qualities = [50, 75, 90];
      
      for (const quality of qualities) {
        const { result, duration } = await measurePerformance(async () => {
          return await request(app)
            .post('/api/v1/images/123e4567-e89b-12d3-a456-426614174000/optimize')
            .send({ quality, format: 'jpeg' })
            .expect(200);
        }, `Image Optimization (quality: ${quality})`);

        expect(result.body.success).toBe(true);
        expect(result.body.data.compressionRatio).toBe(quality / 100);
        expect(duration).toBeLessThan(150); // Should complete within 150ms
      }
    });
  });

  describe('🔄 Batch Operation Performance', () => {
    test('should handle small batch operations efficiently', async () => {
      const batchSizes = [5, 10, 25, 50];
      
      for (const batchSize of batchSizes) {
        const imageIds = Array.from({ length: batchSize }, (_, i) => 
          `123e4567-e89b-12d3-a456-42661417400${i.toString().padStart(1, '0')}`
        );

        const { result, duration } = await measurePerformance(async () => {
          return await request(app)
            .put('/api/v1/images/batch/status')
            .send({ imageIds, status: 'processed' })
            .expect(200);
        }, `Batch Update (${batchSize} items)`);

        expect(result.body.success).toBe(true);
        expect(result.body.data.updated).toBe(batchSize);
        
        // Time should scale linearly with batch size (roughly 1ms per item + overhead)
        const expectedMaxTime = batchSize * 2 + 50; // 2ms per item + 50ms overhead
        expect(duration).toBeLessThan(expectedMaxTime);
      }
    });

    test('should handle large batch operations within acceptable time', async () => {
      const largeBatchSizes = [100, 200, 500];
      
      for (const batchSize of largeBatchSizes) {
        const imageIds = Array.from({ length: batchSize }, (_, i) => 
          `123e4567-e89b-12d3-a456-${(426614174000 + i).toString()}`
        );

        const { result, duration } = await measurePerformance(async () => {
          return await request(app)
            .put('/api/v1/images/batch/status')
            .send({ imageIds, status: 'processed' })
            .expect(200);
        }, `Large Batch Update (${batchSize} items)`);

        expect(result.body.success).toBe(true);
        expect(result.body.data.updated).toBe(batchSize);
        
        // Large batches should still complete in reasonable time
        const expectedMaxTime = batchSize / 2 + 100; // 0.5ms per item + 100ms overhead
        expect(duration).toBeLessThan(expectedMaxTime);
      }
    });

    test('should maintain performance with multiple concurrent batches', async () => {
      const concurrentBatches = 5;
      const batchSize = 20;
      
      const batchOperations = Array.from({ length: concurrentBatches }, (_, batchIndex) => {
        const imageIds = Array.from({ length: batchSize }, (_, i) => 
          `batch${batchIndex}-${i.toString().padStart(3, '0')}-${Date.now()}`
        );
        
        return () => request(app)
          .put('/api/v1/images/batch/status')
          .send({ imageIds, status: 'processed' });
      });

      const startTime = Date.now();
      const { results, errors } = await runConcurrentOperations(batchOperations);
      const endTime = Date.now();
      const totalDuration = endTime - startTime;

      expect(errors.length).toBe(0);
      expect(results.length).toBe(concurrentBatches);
      
      // All batches should complete within reasonable time
      expect(totalDuration).toBeLessThan(1000); // 1 second for all concurrent batches
      
      // Each result should be successful
      results.forEach(result => {
        expect(result.body.success).toBe(true);
        expect(result.body.data.updated).toBe(batchSize);
      });
    });
  });

  describe('📈 Pagination Performance', () => {
    test('should handle pagination efficiently across different page sizes', async () => {
      const pageSizes = [10, 25, 50, 100];
      
      for (const pageSize of pageSizes) {
        const { result, duration } = await measurePerformance(async () => {
          return await request(app)
            .get('/api/v1/images')
            .query({ page: 1, limit: pageSize })
            .set('x-perf-total-items', '10000')
            .expect(200);
        }, `Pagination (${pageSize} items per page)`);

        expect(result.body.success).toBe(true);
        expect(result.body.data).toHaveLength(pageSize);
        expect(result.body.pagination.limit).toBe(pageSize);
        
        // Larger page sizes should not significantly impact performance
        expect(duration).toBeLessThan(150);
      }
    });

    test('should handle deep pagination efficiently', async () => {
      const deepPages = [1, 10, 50, 100];
      
      for (const page of deepPages) {
        const { result, duration } = await measurePerformance(async () => {
          return await request(app)
            .get('/api/v1/images')
            .query({ page, limit: 20 })
            .set('x-perf-total-items', '10000')
            .expect(200);
        }, `Deep Pagination (page ${page})`);

        expect(result.body.success).toBe(true);
        expect(result.body.pagination.page).toBe(page);
        
        // Deep pagination should maintain consistent performance
        expect(duration).toBeLessThan(100);
      }
    });

    test('should handle pagination with large datasets', async () => {
      const datasetSizes = [1000, 10000, 100000];
      
      for (const totalItems of datasetSizes) {
        const { result, duration } = await measurePerformance(async () => {
          return await request(app)
            .get('/api/v1/images')
            .query({ page: 1, limit: 25 })
            .set('x-perf-total-items', totalItems.toString())
            .expect(200);
        }, `Large Dataset Pagination (${totalItems} total items)`);

        expect(result.body.success).toBe(true);
        expect(result.body.pagination.total).toBe(totalItems);
        
        // Performance should not degrade significantly with larger datasets
        expect(duration).toBeLessThan(120);
      }
    });
  });

  describe('⚡ Concurrent Access Performance', () => {
    test('should handle multiple concurrent reads efficiently', async () => {
      const concurrentReads = 20;
      
      const readOperations = Array.from({ length: concurrentReads }, (_, i) => 
        () => request(app)
          .get(`/api/v1/images/test-image-${i}`)
          .set('x-perf-delay', '1')
      );

      const startTime = Date.now();
      const { results, errors } = await runConcurrentOperations(readOperations, 10);
      const endTime = Date.now();
      const totalDuration = endTime - startTime;

      expect(errors.length).toBe(0);
      expect(results.length).toBe(concurrentReads);
      
      // Concurrent reads should be efficient
      expect(totalDuration).toBeLessThan(500); // Should complete within 500ms
      
      // Average response time per request
      const avgResponseTime = totalDuration / concurrentReads;
      expect(avgResponseTime).toBeLessThan(50);
    });

    test('should handle mixed read/write operations', async () => {
      const readOperations = Array.from({ length: 10 }, (_, i) => 
        () => request(app).get(`/api/v1/images/read-test-${i}`)
      );
      
      const writeOperations = Array.from({ length: 5 }, (_, i) => {
        const imageIds = [`write-test-${i}`];
        return () => request(app)
          .put('/api/v1/images/batch/status')
          .send({ imageIds, status: 'processed' });
      });

      const mixedOperations = [...readOperations, ...writeOperations];
      
      const startTime = Date.now();
      const { results, errors } = await runConcurrentOperations(mixedOperations, 8);
      const endTime = Date.now();
      const totalDuration = endTime - startTime;

      expect(errors.length).toBe(0);
      expect(results.length).toBe(15);
      expect(totalDuration).toBeLessThan(800);
    });

    test('should maintain performance under sustained load', async () => {
      const sustainedRequests = 50;
      const batchSize = 10;
      
      const performanceResults: number[] = [];
      
      // Run multiple batches to simulate sustained load
      for (let batch = 0; batch < sustainedRequests / batchSize; batch++) {
        const batchOperations = Array.from({ length: batchSize }, (_, i) => 
          () => request(app)
            .get('/api/v1/images')
            .query({ page: 1, limit: 5 })
        );

        const batchStartTime = Date.now();
        const { results, errors } = await runConcurrentOperations(batchOperations, batchSize);
        const batchEndTime = Date.now();
        const batchDuration = batchEndTime - batchStartTime;
        
        performanceResults.push(batchDuration);
        
        expect(errors.length).toBe(0);
        expect(results.length).toBe(batchSize);
        
        // Small delay between batches
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      
      // Performance should remain consistent across batches
      const avgBatchTime = performanceResults.reduce((sum, time) => sum + time, 0) / performanceResults.length;
      const maxBatchTime = Math.max(...performanceResults);
      const minBatchTime = Math.min(...performanceResults);
      
      expect(avgBatchTime).toBeLessThan(300);
      expect(maxBatchTime - minBatchTime).toBeLessThan(200); // Performance variance should be low
    });
  });

  describe('🗄️ Cache Performance', () => {
    test('should demonstrate cache effectiveness for stats', async () => {
      // First request (cache miss)
      const { duration: uncachedDuration } = await measurePerformance(async () => {
        return await request(app)
          .get('/api/v1/images/stats')
          .set('x-perf-delay', '50')
          .expect(200);
      }, 'Stats - Cache Miss');

      // Second request (cache hit)
      const { duration: cachedDuration } = await measurePerformance(async () => {
        return await request(app)
          .get('/api/v1/images/stats')
          .set('x-perf-cache-hit', 'true')
          .expect(200);
      }, 'Stats - Cache Hit');

      // Cached request should be significantly faster
      expect(cachedDuration).toBeLessThan(uncachedDuration * 0.5);
      expect(cachedDuration).toBeLessThan(25);
    });

    test('should show cache benefits for individual image retrieval', async () => {
      const imageId = '123e4567-e89b-12d3-a456-426614174000';
      
      // Uncached request
      const { duration: uncachedDuration } = await measurePerformance(async () => {
        return await request(app)
          .get(`/api/v1/images/${imageId}`)
          .set('x-perf-delay', '10')
          .expect(200);
      }, 'Image Retrieval - Uncached');

      // Cached request
      const { duration: cachedDuration } = await measurePerformance(async () => {
        return await request(app)
          .get(`/api/v1/images/${imageId}`)
          .set('x-perf-cached', 'true')
          .expect(200);
      }, 'Image Retrieval - Cached');

      expect(cachedDuration).toBeLessThan(uncachedDuration * 0.3);
      expect(cachedDuration).toBeLessThan(15);
    });
  });

  describe('📊 Throughput Performance', () => {
    test('should achieve acceptable upload throughput', async () => {
      const fileSizes = [
        { size: 512000, name: '512KB' },
        { size: 1024000, name: '1MB' },
        { size: 2048000, name: '2MB' },
        { size: 5120000, name: '5MB' }
      ];

      for (const fileSpec of fileSizes) {
        const mockFile = {
          originalname: `test-${fileSpec.name}.jpg`,
          mimetype: 'image/jpeg',
          size: fileSpec.size
        };

        const { result, duration } = await measurePerformance(async () => {
          return await request(app)
            .post('/api/v1/images/upload')
            .send({ mockFile })
            .expect(201);
        }, `Upload Throughput (${fileSpec.name})`);

        expect(result.body.success).toBe(true);
        
        // Calculate throughput (MB/s)
        const throughputMBps = (fileSpec.size / 1024 / 1024) / (duration / 1000);
        
        // Should achieve reasonable throughput
        expect(throughputMBps).toBeGreaterThan(1); // At least 1 MB/s
        
        console.log(`Upload ${fileSpec.name}: ${duration.toFixed(2)}ms (${throughputMBps.toFixed(2)} MB/s)`);
      }
    });

    test('should maintain throughput under concurrent uploads', async () => {
      const concurrentUploads = 5;
      const fileSize = 1024000; // 1MB each
      
      const uploadOperations = Array.from({ length: concurrentUploads }, (_, i) => {
        const mockFile = {
          originalname: `concurrent-${i}.jpg`,
          mimetype: 'image/jpeg',
          size: fileSize
        };
        
        return () => request(app)
          .post('/api/v1/images/upload')
          .send({ mockFile });
      });

      const startTime = Date.now();
      const { results, errors } = await runConcurrentOperations(uploadOperations, concurrentUploads);
      const endTime = Date.now();
      const totalDuration = endTime - startTime;

      expect(errors.length).toBe(0);
      expect(results.length).toBe(concurrentUploads);
      
      // Calculate aggregate throughput
      const totalDataMB = (fileSize * concurrentUploads) / 1024 / 1024;
      const aggregateThroughput = totalDataMB / (totalDuration / 1000);
      
      expect(aggregateThroughput).toBeGreaterThan(2); // At least 2 MB/s aggregate
      
      console.log(`Concurrent uploads: ${totalDuration}ms for ${totalDataMB}MB (${aggregateThroughput.toFixed(2)} MB/s aggregate)`);
    });
  });

  describe('🎯 Performance Regression Tests', () => {
    test('should maintain baseline performance for critical operations', async () => {
      const baselines = {
        'image-listing': 50,      // 50ms max for listing 10 images
        'single-image': 25,       // 25ms max for single image retrieval
        'stats': 30,              // 30ms max for stats
        'small-batch': 100,       // 100ms max for 10-item batch
        'thumbnail-small': 75,    // 75ms max for small thumbnail
        'delete': 20              // 20ms max for deletion
      };

      // Test image listing
      const listingResult = await measurePerformance(async () => {
        return await request(app)
          .get('/api/v1/images')
          .query({ page: 1, limit: 10 });
      }, 'Baseline - Image Listing');
      expect(listingResult.duration).toBeLessThan(baselines['image-listing']);

      // Test single image retrieval
      const singleResult = await measurePerformance(async () => {
        return await request(app)
          .get('/api/v1/images/123e4567-e89b-12d3-a456-426614174000')
          .set('x-perf-cached', 'true');
      }, 'Baseline - Single Image');
      expect(singleResult.duration).toBeLessThan(baselines['single-image']);

      // Test stats
      const statsResult = await measurePerformance(async () => {
        return await request(app)
          .get('/api/v1/images/stats')
          .set('x-perf-cache-hit', 'true');
      }, 'Baseline - Stats');
      expect(statsResult.duration).toBeLessThan(baselines['stats']);

      // Test small batch
      const batchResult = await measurePerformance(async () => {
        const imageIds = Array.from({ length: 10 }, (_, i) => `test-${i}`);
        return await request(app)
          .put('/api/v1/images/batch/status')
          .send({ imageIds, status: 'processed' });
      }, 'Baseline - Small Batch');
      expect(batchResult.duration).toBeLessThan(baselines['small-batch']);

      // Test thumbnail generation
      const thumbnailResult = await measurePerformance(async () => {
        return await request(app)
          .post('/api/v1/images/123e4567-e89b-12d3-a456-426614174000/thumbnail')
          .send({ size: 'small', format: 'jpeg' });
      }, 'Baseline - Thumbnail');
      expect(thumbnailResult.duration).toBeLessThan(baselines['thumbnail-small']);

      // Test deletion
      const deleteResult = await measurePerformance(async () => {
        return await request(app)
          .delete('/api/v1/images/123e4567-e89b-12d3-a456-426614174000')
          .set('x-perf-delay', '5');
      }, 'Baseline - Delete');
      expect(deleteResult.duration).toBeLessThan(baselines['delete']);
    });

    test('should detect performance degradation', async () => {
      // Simulate a performance regression scenario
      const operations = [
        'image-listing',
        'single-image',
        'stats',
        'batch-update'
      ];

      const performanceSamples: { [key: string]: number[] } = {};

      // Collect multiple samples for each operation
      for (const operation of operations) {
        performanceSamples[operation] = [];
        
        for (let sample = 0; sample < 5; sample++) {
          let result: any;
          
          switch (operation) {
            case 'image-listing':
              result = await measurePerformance(async () => {
                return await request(app)
                  .get('/api/v1/images')
                  .query({ page: 1, limit: 10 });
              });
              break;
            case 'single-image':
              result = await measurePerformance(async () => {
                return await request(app)
                  .get('/api/v1/images/123e4567-e89b-12d3-a456-426614174000');
              });
              break;
            case 'stats':
              result = await measurePerformance(async () => {
                return await request(app).get('/api/v1/images/stats');
              });
              break;
            case 'batch-update':
              result = await measurePerformance(async () => {
                const imageIds = Array.from({ length: 5 }, (_, i) => `sample-${sample}-${i}`);
                return await request(app)
                  .put('/api/v1/images/batch/status')
                  .send({ imageIds, status: 'processed' });
              });
              break;
          }
          
          performanceSamples[operation].push(result.duration);
        }
      }

      // Analyze performance consistency
      for (const [operation, samples] of Object.entries(performanceSamples)) {
        const avg = samples.reduce((sum, val) => sum + val, 0) / samples.length;
        const max = Math.max(...samples);
        const min = Math.min(...samples);
        const variance = max - min;
        
        // Performance should be consistent (low variance)
        expect(variance).toBeLessThan(avg * 0.5); // Variance should be less than 50% of average
        
        console.log(`${operation}: avg=${avg.toFixed(2)}ms, variance=${variance.toFixed(2)}ms`);
      }
    });
  });
});