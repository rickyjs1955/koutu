// /backend/src/tests/performance/exportRoutes.perf.test.ts
// Performance tests for export routes

import request from 'supertest';
import express, { Express } from 'express';
import { performance } from 'perf_hooks';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { jest } from '@jest/globals';
import crypto from 'crypto';

// Mock Firebase first
jest.doMock('../../config/firebase', () => ({
  default: { storage: jest.fn() }
}) as any);

// Mock database to avoid connection issues
jest.doMock('../../utils/testDatabaseConnection', () => {
  const mockFn = jest.fn as any;
  return {
    TestDatabaseConnection: {
      initialize: mockFn().mockResolvedValue(true),
      getConnection: mockFn().mockReturnValue({
        query: mockFn().mockResolvedValue({ rows: [] }),
        transaction: mockFn().mockImplementation(async (fn: any) => fn({
          query: mockFn().mockResolvedValue({ rows: [] })
        }))
      }),
      cleanup: mockFn().mockResolvedValue(true),
      query: mockFn().mockResolvedValue({ rows: [] })
    }
  };
});

// ==================== TEST DATA TYPES ====================

interface TestUser {
  id: string;
  email: string;
  token: string;
  devices?: string[];
}

interface TestExportJob {
  id: string;
  user_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed' | 'canceled';
  format: 'zip' | 'tar' | 'json' | 'csv';
  options?: any;
  progress?: number;
  total_items?: number;
  processed_items?: number;
  file_path?: string;
  file_size?: number;
  error?: string;
  created_at: string;
  updated_at: string;
  completed_at?: string;
  timeouts?: NodeJS.Timeout[];
}

interface TestGarment {
  id: string;
  user_id: string;
  name: string;
  category: string;
  image_path: string;
  mask_path: string;
  metadata?: any;
}

// ==================== GLOBAL TEST STATE ====================

let testUsers = new Map<string, TestUser>();
let exportJobs = new Map<string, TestExportJob>();
let garments = new Map<string, TestGarment>();
let results: any[] = [];

let primaryUser: TestUser;
let secondaryUser: TestUser;

// ==================== MOCK SETUP ====================

const createTestApp = (): Express => {
  const app = express();
  app.use(express.json({ limit: '50mb' }));
  
  // Mock authentication middleware
  const authenticate = (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    const token = authHeader.substring(7);
    const user = Array.from(testUsers.values()).find(u => u.token === token);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }
    
    req.user = { id: user.id, email: user.email };
    next();
  };
  
  // Mock validation middleware
  const validate = (_schema: any) => {
    return (req: any, res: any, next: any) => {
      const { format, options } = req.body;
      
      if (req.method === 'POST' && req.path === '/ml') {
        if (!options || typeof options !== 'object') {
          return res.status(422).json({
            success: false,
            error: 'Export options are required',
            code: 'VALIDATION_ERROR'
          });
        }
        
        if (!['zip', 'tar', 'json', 'csv'].includes(format || options.format)) {
          return res.status(422).json({
            success: false,
            error: 'Invalid export format',
            code: 'VALIDATION_ERROR'
          });
        }
      }
      
      next();
    };
  };
  
  // ==================== EXPORT ROUTE HANDLERS ====================
  
  const exportRouter = express.Router();
  exportRouter.use(authenticate);
  
  // Create ML export
  exportRouter.post('/ml', validate({}), async (req: any, res: any) => {
    const userId = req.user.id;
    const { options } = req.body;
    
    // Simulate processing delay
    await new Promise(resolve => setTimeout(resolve, 10));
    
    const jobId = uuidv4();
    const job: TestExportJob = {
      id: jobId,
      user_id: userId,
      status: 'pending',
      format: options.format || 'zip',
      options,
      progress: 0,
      total_items: 100,
      processed_items: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    exportJobs.set(jobId, job);
    
    // Simulate background processing with cleanup
    const timeout1 = setTimeout(() => {
      if (!exportJobs.has(jobId)) return; // Job was deleted, skip
      
      job.status = 'processing';
      job.progress = 50;
      job.processed_items = 50;
      
      const timeout2 = setTimeout(() => {
        if (!exportJobs.has(jobId)) return; // Job was deleted, skip
        
        job.status = 'completed';
        job.progress = 100;
        job.processed_items = 100;
        job.file_path = `/exports/${jobId}.${job.format}`;
        job.file_size = 1024 * 1024 * 10; // 10MB
        job.completed_at = new Date().toISOString();
      }, 100);
      
      // Store timeout for cleanup if needed
      if (!job.timeouts) job.timeouts = [];
      job.timeouts.push(timeout2);
    }, 50);
    
    // Store timeout for cleanup if needed
    if (!job.timeouts) job.timeouts = [];
    job.timeouts.push(timeout1);
    
    res.status(202).json({
      success: true,
      data: {
        jobId,
        message: 'Export job created successfully',
        meta: {
          jobId,
          userId,
          jobType: 'ml_export',
          status: 'queued',
          createdAt: job.created_at
        }
      }
    });
  });
  
  // Get export job status
  exportRouter.get('/ml/jobs/:jobId', (req: any, res: any) => {
    const { jobId } = req.params;
    const userId = req.user.id;
    
    const job = exportJobs.get(jobId);
    
    if (!job) {
      return res.status(404).json({
        success: false,
        error: 'Export job not found',
        code: 'JOB_NOT_FOUND'
      });
    }
    
    if (job.user_id !== userId) {
      return res.status(403).json({
        success: false,
        error: 'Access denied',
        code: 'ACCESS_DENIED'
      });
    }
    
    res.status(200).json({
      success: true,
      data: job,
      meta: {
        jobId,
        userId,
        status: job.status,
        retrievedAt: new Date().toISOString()
      }
    });
  });
  
  // Get all export jobs for user
  exportRouter.get('/ml/jobs', (req: any, res: any) => {
    const userId = req.user.id;
    
    const userJobs = Array.from(exportJobs.values())
      .filter(job => job.user_id === userId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    
    res.status(200).json({
      success: true,
      data: userJobs,
      meta: {
        userId,
        jobCount: userJobs.length,
        retrievedAt: new Date().toISOString()
      }
    });
  });
  
  // Download export file
  exportRouter.get('/ml/download/:jobId', (req: any, res: any) => {
    const { jobId } = req.params;
    const userId = req.user.id;
    
    const job = exportJobs.get(jobId);
    
    if (!job) {
      return res.status(404).json({
        success: false,
        error: 'Export job not found',
        code: 'JOB_NOT_FOUND'
      });
    }
    
    if (job.user_id !== userId) {
      return res.status(403).json({
        success: false,
        error: 'Access denied',
        code: 'ACCESS_DENIED'
      });
    }
    
    if (job.status !== 'completed') {
      return res.status(400).json({
        success: false,
        error: `Export job is not ready for download (status: ${job.status})`,
        code: 'JOB_NOT_READY'
      });
    }
    
    // Simulate file download
    const fileContent = Buffer.alloc(job.file_size || 1024);
    crypto.randomFillSync(fileContent);
    
    res.status(200)
      .set({
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="export-${jobId}.${job.format}"`,
        'Content-Length': fileContent.length.toString()
      })
      .send(fileContent);
  });
  
  // Get dataset statistics
  exportRouter.get('/ml/stats', async (req: any, res: any) => {
    const userId = req.user.id;
    
    // Simulate processing delay
    await new Promise(resolve => setTimeout(resolve, 5));
    
    const userGarments = Array.from(garments.values())
      .filter(g => g.user_id === userId);
    
    const stats = {
      total_garments: userGarments.length,
      total_images: userGarments.length,
      total_masks: userGarments.length,
      categories: {
        shirts: userGarments.filter(g => g.category === 'shirts').length,
        pants: userGarments.filter(g => g.category === 'pants').length,
        dresses: userGarments.filter(g => g.category === 'dresses').length,
        shoes: userGarments.filter(g => g.category === 'shoes').length
      },
      storage_used: userGarments.length * 1024 * 1024 * 2, // 2MB per garment
      last_export: Array.from(exportJobs.values())
        .filter(j => j.user_id === userId && j.status === 'completed')
        .sort((a, b) => new Date(b.completed_at!).getTime() - new Date(a.completed_at!).getTime())[0]?.completed_at
    };
    
    res.status(200).json({
      success: true,
      data: stats,
      meta: {
        userId,
        statsType: 'ml_dataset',
        generatedAt: new Date().toISOString()
      }
    });
  });
  
  // Cancel export job
  exportRouter.delete('/ml/jobs/:jobId', (req: any, res: any) => {
    const { jobId } = req.params;
    const userId = req.user.id;
    
    const job = exportJobs.get(jobId);
    
    if (!job) {
      return res.status(404).json({
        success: false,
        error: 'Export job not found',
        code: 'JOB_NOT_FOUND'
      });
    }
    
    if (job.user_id !== userId) {
      return res.status(403).json({
        success: false,
        error: 'Access denied',
        code: 'ACCESS_DENIED'
      });
    }
    
    if (job.status === 'completed' || job.status === 'failed') {
      return res.status(400).json({
        success: false,
        error: `Cannot cancel job with status: ${job.status}`,
        code: 'INVALID_STATUS'
      });
    }
    
    job.status = 'canceled';
    job.updated_at = new Date().toISOString();
    
    res.status(200).json({
      success: true,
      data: {},
      meta: {
        jobId,
        userId,
        previousStatus: job.status,
        newStatus: 'canceled',
        canceledAt: job.updated_at
      }
    });
  });
  
  app.use('/api/v1/export', exportRouter);
  
  // Error handler
  app.use((error: any, _req: any, res: any, _next: any) => {
    res.status(error.statusCode || 500).json({
      success: false,
      error: error.message || 'Internal server error',
      code: error.code || 'INTERNAL_ERROR'
    });
  });
  
  return app;
};

// ==================== TEST HELPERS ====================

const cleanupJob = (jobId: string): void => {
  const job = exportJobs.get(jobId);
  if (job && job.timeouts) {
    job.timeouts.forEach(timeout => clearTimeout(timeout));
  }
  exportJobs.delete(jobId);
};

const createMockGarments = (userId: string, count: number): void => {
  const categories = ['shirts', 'pants', 'dresses', 'shoes'];
  
  for (let i = 0; i < count; i++) {
    const garmentId = uuidv4();
    const garment: TestGarment = {
      id: garmentId,
      user_id: userId,
      name: `Garment ${i + 1}`,
      category: categories[i % categories.length],
      image_path: `/images/${garmentId}.jpg`,
      mask_path: `/masks/${garmentId}.png`,
      metadata: {
        color: ['red', 'blue', 'green', 'black'][i % 4],
        size: ['S', 'M', 'L', 'XL'][i % 4],
        brand: `Brand ${(i % 5) + 1}`
      }
    };
    garments.set(garmentId, garment);
  }
};

const createLargeExportOptions = (itemCount: number): any => {
  return {
    format: 'zip',
    include_images: true,
    include_masks: true,
    include_metadata: true,
    compression_level: 'high',
    split_size_mb: 100,
    categories: ['shirts', 'pants', 'dresses', 'shoes'],
    date_range: {
      start: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
      end: new Date().toISOString()
    },
    custom_fields: {
      include_annotations: true,
      include_embeddings: true,
      embedding_format: 'numpy'
    },
    estimated_items: itemCount
  };
};

// ==================== PERFORMANCE TESTS ====================

describe('Export Routes Performance Tests', () => {
  let app: Express;
  
  beforeAll(async () => {
    // Create test users
    primaryUser = {
      id: uuidv4(),
      email: 'perf-test@example.com',
      token: 'perf-test-token',
      devices: ['device-1', 'device-2']
    };
    testUsers.set(primaryUser.id, primaryUser);
    
    secondaryUser = {
      id: uuidv4(),
      email: 'perf-test-2@example.com',
      token: 'perf-test-token-2',
      devices: ['device-3']
    };
    testUsers.set(secondaryUser.id, secondaryUser);
    
    // Create mock garments
    createMockGarments(primaryUser.id, 1000);
    createMockGarments(secondaryUser.id, 500);
    
    // Create some existing export jobs
    for (let i = 0; i < 50; i++) {
      const jobId = uuidv4();
      const job: TestExportJob = {
        id: jobId,
        user_id: i % 2 === 0 ? primaryUser.id : secondaryUser.id,
        status: ['completed', 'failed', 'canceled'][i % 3] as any,
        format: ['zip', 'tar', 'json', 'csv'][i % 4] as any,
        options: { test: true },
        progress: 100,
        total_items: 100,
        processed_items: 100,
        file_path: `/exports/${jobId}.zip`,
        file_size: 1024 * 1024 * (i + 1),
        created_at: new Date(Date.now() - i * 3600000).toISOString(),
        updated_at: new Date(Date.now() - i * 3600000).toISOString(),
        completed_at: new Date(Date.now() - i * 3600000 + 300000).toISOString()
      };
      exportJobs.set(jobId, job);
    }
    
    // Create app
    app = createTestApp();
  });
  
  afterEach(() => {
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  });

  afterAll(async () => {
    // Save performance results
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const resultsPath = path.join(__dirname, `../../../performance-results/export-routes-${timestamp}.json`);
    await fs.mkdir(path.dirname(resultsPath), { recursive: true });
    await fs.writeFile(resultsPath, JSON.stringify(results, null, 2));
    
    console.log(`Performance results saved to: ${resultsPath}`);
    
    // Clean up all test data to prevent memory leaks
    // Clear all job timeouts first
    exportJobs.forEach((job, jobId) => {
      cleanupJob(jobId);
    });
    
    testUsers.clear();
    garments.clear();
    results = [];
    
    // Clear references
    testUsers = null as any;
    exportJobs = null as any;
    garments = null as any;
    primaryUser = null as any;
    secondaryUser = null as any;
  });
  
  describe('Response Time Tests', () => {
    const measureResponseTime = async (name: string, fn: () => Promise<any>) => {
      const iterations = 100;
      const times: number[] = [];
      
      // Warm up
      for (let i = 0; i < 10; i++) {
        await fn();
      }
      
      // Measure
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        await fn();
        const end = performance.now();
        times.push(end - start);
      }
      
      const avg = times.reduce((a, b) => a + b) / times.length;
      const min = Math.min(...times);
      const max = Math.max(...times);
      const sorted = times.sort((a, b) => a - b);
      const p95 = sorted[Math.floor(times.length * 0.95)];
      const p99 = sorted[Math.floor(times.length * 0.99)];
      
      const result = {
        test: name,
        type: 'response_time',
        iterations,
        metrics: {
          avg: parseFloat(avg.toFixed(2)),
          min: parseFloat(min.toFixed(2)),
          max: parseFloat(max.toFixed(2)),
          p95: parseFloat(p95.toFixed(2)),
          p99: parseFloat(p99.toFixed(2))
        },
        unit: 'ms'
      };
      
      results.push(result);
      console.log(`\n${name}:`, result.metrics);
      
      // Performance assertions
      expect(avg).toBeLessThan(50); // Average should be under 50ms
      expect(p95).toBeLessThan(100); // 95th percentile under 100ms
      expect(p99).toBeLessThan(200); // 99th percentile under 200ms
    };
    
    test('POST /api/v1/export/ml - create export job', async () => {
      await measureResponseTime('POST /api/v1/export/ml', async () => {
        const response = await request(app)
          .post('/api/v1/export/ml')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            options: {
              format: 'zip',
              include_images: true,
              include_masks: true,
              compression_level: 'medium'
            }
          });
        
        expect(response.status).toBe(202);
      });
    });
    
    test('GET /api/v1/export/ml/jobs/:jobId - get job status', async () => {
      const jobIds = Array.from(exportJobs.keys())
        .filter(id => exportJobs.get(id)!.user_id === primaryUser.id);
      let jobIndex = 0;
      
      await measureResponseTime('GET /api/v1/export/ml/jobs/:jobId', async () => {
        const jobId = jobIds[jobIndex % jobIds.length];
        jobIndex++;
        
        const response = await request(app)
          .get(`/api/v1/export/ml/jobs/${jobId}`)
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        expect(response.status).toBe(200);
      });
    });
    
    test('GET /api/v1/export/ml/jobs - list all jobs', async () => {
      await measureResponseTime('GET /api/v1/export/ml/jobs', async () => {
        const response = await request(app)
          .get('/api/v1/export/ml/jobs')
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        expect(response.status).toBe(200);
      });
    });
    
    test('GET /api/v1/export/ml/stats - get dataset statistics', async () => {
      await measureResponseTime('GET /api/v1/export/ml/stats', async () => {
        const response = await request(app)
          .get('/api/v1/export/ml/stats')
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        expect(response.status).toBe(200);
      });
    });
    
    test('DELETE /api/v1/export/ml/jobs/:jobId - cancel job', async () => {
      // Create jobs to cancel
      const jobsToCancel: string[] = [];
      for (let i = 0; i < 200; i++) {
        const jobId = uuidv4();
        const job: TestExportJob = {
          id: jobId,
          user_id: primaryUser.id,
          status: 'processing',
          format: 'zip',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        exportJobs.set(jobId, job);
        jobsToCancel.push(jobId);
      }
      
      let cancelIndex = 0;
      await measureResponseTime('DELETE /api/v1/export/ml/jobs/:jobId', async () => {
        const jobId = jobsToCancel[cancelIndex];
        cancelIndex++;
        
        const response = await request(app)
          .delete(`/api/v1/export/ml/jobs/${jobId}`)
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        expect(response.status).toBe(200);
      });
    });
  });
  
  describe('Load Tests', () => {
    test('Handle concurrent export job creation', async () => {
      const concurrentRequests = 50;
      const start = performance.now();
      
      const promises = Array.from({ length: concurrentRequests }, (_, i) => 
        request(app)
          .post('/api/v1/export/ml')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            options: {
              format: ['zip', 'tar', 'json', 'csv'][i % 4],
              include_images: true,
              include_masks: i % 2 === 0,
              compression_level: ['low', 'medium', 'high'][i % 3]
            }
          })
      );
      
      const responses = await Promise.all(promises);
      const end = performance.now();
      
      const totalTime = end - start;
      const avgTime = totalTime / concurrentRequests;
      
      const result = {
        test: 'Concurrent export job creation',
        type: 'load_test',
        concurrentRequests,
        metrics: {
          totalTime: parseFloat(totalTime.toFixed(2)),
          avgTime: parseFloat(avgTime.toFixed(2)),
          requestsPerSecond: parseFloat((concurrentRequests / (totalTime / 1000)).toFixed(2))
        },
        unit: 'ms'
      };
      
      results.push(result);
      console.log('\nConcurrent job creation:', result.metrics);
      
      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(202);
      });
      
      // Performance assertions
      expect(avgTime).toBeLessThan(100); // Average time per request under 100ms
      expect(totalTime).toBeLessThan(5000); // Total time under 5 seconds
    });
    
    test('Handle large export options', async () => {
      const itemCounts = [100, 500, 1000, 5000, 10000];
      const largeExportResults: any[] = [];
      
      for (const itemCount of itemCounts) {
        const start = performance.now();
        
        const response = await request(app)
          .post('/api/v1/export/ml')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            options: createLargeExportOptions(itemCount)
          });
        
        const end = performance.now();
        const time = end - start;
        
        expect(response.status).toBe(202);
        
        largeExportResults.push({
          itemCount,
          time: parseFloat(time.toFixed(2)),
          status: response.status
        });
      }
      
      const result = {
        test: 'Large export options handling',
        type: 'scalability_test',
        results: largeExportResults
      };
      
      results.push(result);
      console.log('\nLarge export handling:', largeExportResults);
      
      // Performance should scale linearly with item count
      const times = largeExportResults.map(r => r.time);
      const avgIncrease = times.slice(1).reduce((acc, time, i) => 
        acc + (time - times[i]) / times[i], 0) / (times.length - 1);
      
      expect(avgIncrease).toBeLessThan(0.5); // Less than 50% increase per step
    });
    
    test('Handle multiple users accessing jobs concurrently', async () => {
      const users = [primaryUser, secondaryUser];
      const operations: (() => Promise<any>)[] = [];
      
      // Mix of operations from different users
      for (let i = 0; i < 100; i++) {
        const user = users[i % users.length];
        const operation = i % 4;
        
        switch (operation) {
          case 0: // Create job
            operations.push(() => 
              request(app)
                .post('/api/v1/export/ml')
                .set('Authorization', `Bearer ${user.token}`)
                .send({ options: { format: 'zip' } })
            );
            break;
          case 1: // List jobs
            operations.push(() => 
              request(app)
                .get('/api/v1/export/ml/jobs')
                .set('Authorization', `Bearer ${user.token}`)
            );
            break;
          case 2: // Get stats
            operations.push(() => 
              request(app)
                .get('/api/v1/export/ml/stats')
                .set('Authorization', `Bearer ${user.token}`)
            );
            break;
          case 3: // Get specific job
            const userJobs = Array.from(exportJobs.values())
              .filter(j => j.user_id === user.id);
            if (userJobs.length > 0) {
              const job = userJobs[i % userJobs.length];
              operations.push(() => 
                request(app)
                  .get(`/api/v1/export/ml/jobs/${job.id}`)
                  .set('Authorization', `Bearer ${user.token}`)
              );
            }
            break;
        }
      }
      
      const start = performance.now();
      const responses = await Promise.all(operations.map(op => op()));
      const end = performance.now();
      
      const totalTime = end - start;
      const avgTime = totalTime / operations.length;
      
      const result = {
        test: 'Multi-user concurrent operations',
        type: 'load_test',
        totalOperations: operations.length,
        metrics: {
          totalTime: parseFloat(totalTime.toFixed(2)),
          avgTime: parseFloat(avgTime.toFixed(2)),
          operationsPerSecond: parseFloat((operations.length / (totalTime / 1000)).toFixed(2))
        },
        unit: 'ms'
      };
      
      results.push(result);
      console.log('\nMulti-user operations:', result.metrics);
      
      // All operations should succeed
      responses.forEach(response => {
        expect([200, 202]).toContain(response.status);
      });
    });
  });
  
  describe('Memory Usage Tests', () => {
    test('Memory efficiency with many export jobs', async () => {
      // Force garbage collection before test
      if (global.gc) {
        global.gc();
      }
      
      const initialMemory = process.memoryUsage();
      const jobCount = 1000;
      const createdJobIds: string[] = [];
      
      // Create many export jobs
      for (let i = 0; i < jobCount; i++) {
        const response = await request(app)
          .post('/api/v1/export/ml')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            options: {
              format: 'zip',
              include_images: true,
              include_masks: true,
              metadata: {
                index: i,
                test: 'memory',
                large_field: 'x'.repeat(1000)
              }
            }
          });
        
        if (response.body.data?.jobId) {
          createdJobIds.push(response.body.data.jobId);
        }
      }
      
      // Force garbage collection after creating jobs
      if (global.gc) {
        global.gc();
      }
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = {
        heapUsed: (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024,
        external: (finalMemory.external - initialMemory.external) / 1024 / 1024
      };
      
      const result = {
        test: 'Memory usage with many jobs',
        type: 'memory_test',
        jobCount,
        memoryIncrease: {
          heapUsed: parseFloat(memoryIncrease.heapUsed.toFixed(2)),
          external: parseFloat(memoryIncrease.external.toFixed(2))
        },
        unit: 'MB'
      };
      
      results.push(result);
      console.log('\nMemory usage:', result.memoryIncrease);
      
      // Clean up created jobs to prevent memory leak
      createdJobIds.forEach(jobId => {
        cleanupJob(jobId);
      });
      
      // Memory usage should be reasonable
      expect(memoryIncrease.heapUsed).toBeLessThan(200); // Less than 200MB for 1000 jobs
    });
  });
  
  describe('Export Processing Performance', () => {
    test('Job status update performance', async () => {
      // Create a job and measure how quickly status updates propagate
      const response = await request(app)
        .post('/api/v1/export/ml')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({
          options: { format: 'zip' }
        });
      
      const jobId = response.body.data.jobId;
      const statusChecks: any[] = [];
      const startTime = performance.now();
      
      // Poll job status until completed
      let completed = false;
      let attempts = 0;
      const maxAttempts = 20;
      
      while (!completed && attempts < maxAttempts) {
        const checkStart = performance.now();
        const statusResponse = await request(app)
          .get(`/api/v1/export/ml/jobs/${jobId}`)
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        const checkTime = performance.now() - checkStart;
        const job = statusResponse.body.data;
        
        if (job) {
          statusChecks.push({
            attempt: attempts + 1,
            status: job.status,
            progress: job.progress,
            checkTime: parseFloat(checkTime.toFixed(2)),
            totalElapsed: parseFloat((performance.now() - startTime).toFixed(2))
          });
          
          if (job.status === 'completed') {
            completed = true;
          }
        }
        
        attempts++;
        if (!completed) {
          await new Promise(resolve => setTimeout(resolve, 10));
        }
      }
      
      const result = {
        test: 'Job status update propagation',
        type: 'processing_test',
        statusChecks,
        totalTime: parseFloat((performance.now() - startTime).toFixed(2)),
        completed
      };
      
      results.push(result);
      console.log('\nStatus update performance:', {
        checks: statusChecks.length,
        totalTime: result.totalTime,
        avgCheckTime: parseFloat((statusChecks.reduce((sum, c) => sum + c.checkTime, 0) / statusChecks.length).toFixed(2))
      });
      
      expect(completed).toBe(true);
      expect(result.totalTime).toBeLessThan(500); // Should complete within 500ms
    });
    
    test('Download performance for different file sizes', async () => {
      const fileSizes = [
        { size: 1024 * 1024, label: '1MB' },
        { size: 5 * 1024 * 1024, label: '5MB' },
        { size: 10 * 1024 * 1024, label: '10MB' },
        { size: 50 * 1024 * 1024, label: '50MB' }
      ];
      
      const downloadResults: any[] = [];
      
      for (const { size, label } of fileSizes) {
        // Create a completed job with specific file size
        const jobId = uuidv4();
        const job: TestExportJob = {
          id: jobId,
          user_id: primaryUser.id,
          status: 'completed',
          format: 'zip',
          file_size: size,
          file_path: `/exports/${jobId}.zip`,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          completed_at: new Date().toISOString()
        };
        exportJobs.set(jobId, job);
        
        const start = performance.now();
        const response = await request(app)
          .get(`/api/v1/export/ml/download/${jobId}`)
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        const downloadTime = performance.now() - start;
        const throughput = (size / 1024 / 1024) / (downloadTime / 1000); // MB/s
        
        expect(response.status).toBe(200);
        expect(response.body.length).toBe(size);
        
        downloadResults.push({
          fileSize: label,
          downloadTime: parseFloat(downloadTime.toFixed(2)),
          throughput: parseFloat(throughput.toFixed(2))
        });
      }
      
      const result = {
        test: 'Download performance by file size',
        type: 'download_test',
        results: downloadResults
      };
      
      results.push(result);
      console.log('\nDownload performance:', downloadResults);
      
      // Throughput should be reasonable
      downloadResults.forEach(r => {
        expect(r.throughput).toBeGreaterThan(10); // At least 10 MB/s
      });
    });
  });
  
  describe('Dataset Statistics Performance', () => {
    test('Statistics calculation with varying dataset sizes', async () => {
      const users = [primaryUser, secondaryUser];
      const statResults: any[] = [];
      
      for (const user of users) {
        const userGarmentCount = Array.from(garments.values())
          .filter(g => g.user_id === user.id).length;
        
        const start = performance.now();
        const response = await request(app)
          .get('/api/v1/export/ml/stats')
          .set('Authorization', `Bearer ${user.token}`);
        
        const calcTime = performance.now() - start;
        
        expect(response.status).toBe(200);
        
        statResults.push({
          user: user.email,
          garmentCount: userGarmentCount,
          calculationTime: parseFloat(calcTime.toFixed(2))
        });
      }
      
      const result = {
        test: 'Statistics calculation performance',
        type: 'calculation_test',
        results: statResults
      };
      
      results.push(result);
      console.log('\nStatistics calculation:', statResults);
      
      // Calculation time should scale reasonably with dataset size
      statResults.forEach(r => {
        expect(r.calculationTime).toBeLessThan(50); // Under 50ms
      });
    });
  });
});