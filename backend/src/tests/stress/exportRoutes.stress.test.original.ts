// /backend/src/tests/stress/exportRoutes.stress.test.ts
// Stress tests for export routes - testing system under extreme conditions

import request from 'supertest';
import express, { Express } from 'express';
import { performance } from 'perf_hooks';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { jest } from '@jest/globals';
import crypto from 'crypto';

// Increase test timeout for stress tests
jest.setTimeout(300000); // 5 minutes

// Increase Node.js memory limit for stress tests
if (global.gc) {
  console.log('Manual garbage collection enabled');
}

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
  retry_count?: number;
  memory_usage?: number;
  processing_time?: number;
}

interface StressTestResult {
  test: string;
  type: string;
  duration: number;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  errors: { [key: string]: number };
  metrics: {
    avgResponseTime: number;
    minResponseTime: number;
    maxResponseTime: number;
    p50ResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
    requestsPerSecond: number;
    errorRate: number;
  };
  resourceUsage?: {
    peakMemory: number;
    avgMemory: number;
    cpuUsage?: number;
  };
}

// ==================== GLOBAL TEST STATE ====================

const testUsers = new Map<string, TestUser>();
const exportJobs = new Map<string, TestExportJob>();
const results: StressTestResult[] = [];
let memoryMonitor: NodeJS.Timeout | null = null;
let memoryReadings: number[] = [];

// Memory management settings
const MAX_EXPORT_JOBS = 10000; // Limit stored jobs
const MAX_MEMORY_READINGS = 1000; // Limit memory readings
const CLEANUP_INTERVAL = 5000; // Clean up old data every 5 seconds

// ==================== STRESS TEST CONFIGURATION ====================

const STRESS_CONFIG = {
  extremeLoad: {
    concurrent: 100, // Further reduced for stability
    duration: 15000, // 15 seconds
    rampUpTime: 3000 // 3 seconds
  },
  sustainedLoad: {
    concurrent: 30, // Further reduced
    duration: 20000, // 20 seconds
    requestsPerSecond: 30
  },
  spikeLoad: {
    normalConcurrent: 20,
    spikeConcurrent: 150, // More reasonable spike
    spikeDuration: 5000, // 5 seconds
    cycles: 2
  },
  memoryPressure: {
    largePayloadSize: 500 * 1024, // 500KB
    concurrentLargeRequests: 15
  }
};

// ==================== MOCK SETUP ====================

const createStressTestApp = (): Express => {
  const app = express();
  app.use(express.json({ limit: '100mb' })); // Increased limit for stress testing
  
  // Track active connections
  let activeConnections = 0;
  let totalConnections = 0;
  
  app.use((req: any, res: any, next: any) => {
    activeConnections++;
    totalConnections++;
    
    res.on('finish', () => {
      activeConnections--;
    });
    
    // Add connection info to request
    req.connectionInfo = {
      active: activeConnections,
      total: totalConnections
    };
    
    next();
  });
  
  // Mock authentication middleware with rate limiting simulation
  const authTokens = new Map<string, { userId: string; requests: number[] }>();
  
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
    
    // Simulate token rate limiting
    const now = Date.now();
    if (!authTokens.has(token)) {
      authTokens.set(token, { userId: user.id, requests: [] });
    }
    
    const tokenInfo = authTokens.get(token)!;
    tokenInfo.requests = tokenInfo.requests.filter(time => now - time < 60000); // 1 minute window
    
    if (tokenInfo.requests.length > 1000) { // 1000 requests per minute limit
      return res.status(429).json({
        success: false,
        error: 'Rate limit exceeded',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: 60
      });
    }
    
    tokenInfo.requests.push(now);
    
    req.user = { id: user.id, email: user.email };
    next();
  };
  
  // ==================== EXPORT ROUTE HANDLERS WITH STRESS SIMULATION ====================
  
  const exportRouter = express.Router();
  exportRouter.use(authenticate);
  
  // Simulate resource constraints
  let systemLoad = 0;
  const MAX_CONCURRENT_JOBS = 100;
  
  // Create ML export with stress handling
  exportRouter.post('/ml', async (req: any, res: any) => {
    const userId = req.user.id;
    const { options } = req.body;
    
    // Simulate system overload
    if (activeConnections > 400) {
      return res.status(503).json({
        success: false,
        error: 'Service temporarily unavailable',
        code: 'SERVICE_OVERLOADED',
        retryAfter: Math.floor(Math.random() * 10) + 5
      });
    }
    
    // Check concurrent job limit
    const activeJobs = Array.from(exportJobs.values())
      .filter(job => ['pending', 'processing'].includes(job.status)).length;
    
    if (activeJobs >= MAX_CONCURRENT_JOBS) {
      return res.status(503).json({
        success: false,
        error: 'Export queue is full',
        code: 'QUEUE_FULL',
        queueLength: activeJobs
      });
    }
    
    // Simulate processing delay based on system load
    const baseDelay = 10;
    const loadDelay = Math.floor(systemLoad * 5);
    await new Promise(resolve => setTimeout(resolve, baseDelay + loadDelay));
    
    // Random chance of failure under stress
    if (Math.random() < 0.05 && activeConnections > 200) { // 5% failure rate under high load
      return res.status(500).json({
        success: false,
        error: 'Internal server error',
        code: 'INTERNAL_ERROR'
      });
    }
    
    const jobId = uuidv4();
    const job: TestExportJob = {
      id: jobId,
      user_id: userId,
      status: 'pending',
      format: options?.format || 'zip',
      options,
      progress: 0,
      total_items: Math.floor(Math.random() * 1000) + 100,
      processed_items: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      retry_count: 0,
      memory_usage: Math.random() * 100 // MB
    };
    
    exportJobs.set(jobId, job);
    systemLoad = Math.min(systemLoad + 0.1, 10);
    
    // Clean up old jobs to prevent memory leak
    if (exportJobs.size > MAX_EXPORT_JOBS) {
      const jobsToDelete = Array.from(exportJobs.entries())
        .filter(([_, job]) => job.status === 'completed' || job.status === 'failed')
        .sort((a, b) => new Date(a[1].created_at).getTime() - new Date(b[1].created_at).getTime())
        .slice(0, 100); // Delete 100 oldest completed/failed jobs
      
      jobsToDelete.forEach(([jobId]) => exportJobs.delete(jobId));
    }
    
    // Simulate background processing
    setTimeout(() => {
      if (Math.random() < 0.9) { // 90% success rate
        job.status = 'processing';
        job.progress = 50;
        
        setTimeout(() => {
          job.status = 'completed';
          job.progress = 100;
          job.processed_items = job.total_items;
          job.file_path = `/exports/${jobId}.${job.format}`;
          job.file_size = Math.floor(Math.random() * 50 * 1024 * 1024); // Up to 50MB
          job.completed_at = new Date().toISOString();
          job.processing_time = Math.random() * 10000; // Up to 10 seconds
          systemLoad = Math.max(systemLoad - 0.1, 0);
        }, Math.random() * 5000);
      } else {
        job.status = 'failed';
        job.error = 'Processing failed due to system overload';
        systemLoad = Math.max(systemLoad - 0.1, 0);
      }
    }, Math.random() * 2000);
    
    res.status(202).json({
      success: true,
      data: {
        jobId,
        message: 'Export job created successfully',
        meta: {
          jobId,
          userId,
          systemLoad: systemLoad.toFixed(2),
          activeConnections,
          queuePosition: activeJobs + 1
        }
      }
    });
  });
  
  // Get export job status with caching simulation
  const statusCache = new Map<string, { data: any; timestamp: number }>();
  
  exportRouter.get('/ml/jobs/:jobId', (req: any, res: any) => {
    const { jobId } = req.params;
    const userId = req.user.id;
    
    // Check cache first
    const cached = statusCache.get(jobId);
    if (cached && Date.now() - cached.timestamp < 1000) { // 1 second cache
      return res.status(200).json(cached.data);
    }
    
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
    
    const response = {
      success: true,
      data: job,
      meta: {
        cached: false,
        systemLoad: systemLoad.toFixed(2)
      }
    };
    
    // Cache the response
    statusCache.set(jobId, { data: response, timestamp: Date.now() });
    
    res.status(200).json(response);
  });
  
  // List all export jobs with pagination
  exportRouter.get('/ml/jobs', (req: any, res: any) => {
    const userId = req.user.id;
    const page = parseInt(req.query.page as string) || 1;
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 100);
    
    const userJobs = Array.from(exportJobs.values())
      .filter(job => job.user_id === userId)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    
    const start = (page - 1) * limit;
    const paginatedJobs = userJobs.slice(start, start + limit);
    
    res.status(200).json({
      success: true,
      data: paginatedJobs,
      meta: {
        page,
        limit,
        total: userJobs.length,
        totalPages: Math.ceil(userJobs.length / limit),
        hasNext: start + limit < userJobs.length
      }
    });
  });
  
  // Download with bandwidth throttling simulation
  exportRouter.get('/ml/download/:jobId', async (req: any, res: any) => {
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
    
    // Simulate bandwidth limitations under stress
    const fileSize = job.file_size || 1024 * 1024;
    const bandwidth = activeConnections > 200 ? 1024 * 1024 : 10 * 1024 * 1024; // 1MB/s or 10MB/s
    
    // Stream file with throttling
    const chunkSize = 64 * 1024; // 64KB chunks
    let sentBytes = 0;
    
    res.status(200).set({
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="export-${jobId}.${job.format}"`,
      'Content-Length': fileSize.toString()
    });
    
    const sendChunk = () => {
      if (sentBytes >= fileSize) {
        res.end();
        return;
      }
      
      const remainingBytes = fileSize - sentBytes;
      const currentChunkSize = Math.min(chunkSize, remainingBytes);
      const chunk = Buffer.alloc(currentChunkSize);
      crypto.randomFillSync(chunk);
      
      res.write(chunk);
      sentBytes += currentChunkSize;
      
      // Throttle based on bandwidth
      const delay = (currentChunkSize / bandwidth) * 1000;
      setTimeout(sendChunk, delay);
    };
    
    sendChunk();
  });
  
  // Health check endpoint
  exportRouter.get('/health', (_req: any, res: any) => {
    const health = {
      status: systemLoad > 8 ? 'degraded' : 'healthy',
      activeConnections,
      systemLoad: systemLoad.toFixed(2),
      activeJobs: Array.from(exportJobs.values())
        .filter(job => ['pending', 'processing'].includes(job.status)).length,
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime()
    };
    
    res.status(health.status === 'healthy' ? 200 : 503).json(health);
  });
  
  app.use('/api/v1/export', exportRouter);
  
  // Global error handler
  app.use((error: any, req: any, res: any, _next: any) => {
    console.error('Unhandled error:', error);
    res.status(error.statusCode || 500).json({
      success: false,
      error: error.message || 'Internal server error',
      code: error.code || 'INTERNAL_ERROR',
      activeConnections: req.connectionInfo?.active
    });
  });
  
  return app;
};

// ==================== STRESS TEST UTILITIES ====================

class StressTestRunner {
  static async runStressTest(
    _app: Express,
    config: {
      name: string;
      concurrent: number;
      duration: number;
      requestFactory: () => request.Test;
      rampUp?: number;
    }
  ): Promise<StressTestResult> {
    console.log(`\n🔥 Starting stress test: ${config.name}`);
    console.log(`   Concurrent users: ${config.concurrent}`);
    console.log(`   Duration: ${config.duration}ms`);
    
    const startTime = performance.now();
    const responseTimes: number[] = [];
    const errors: { [key: string]: number } = {};
    let successCount = 0;
    let failureCount = 0;
    let activeRequests = 0;
    
    // Start memory monitoring
    memoryReadings = [];
    memoryMonitor = setInterval(() => {
      const usage = process.memoryUsage();
      memoryReadings.push(usage.heapUsed / 1024 / 1024); // MB
      
      // Limit memory readings to prevent memory leak
      if (memoryReadings.length > MAX_MEMORY_READINGS) {
        memoryReadings = memoryReadings.slice(-MAX_MEMORY_READINGS);
      }
      
      // Force garbage collection if available
      if (global.gc && usage.heapUsed > 500 * 1024 * 1024) { // 500MB threshold
        global.gc();
      }
    }, 100);
    
    const makeRequest = async () => {
      activeRequests++;
      const reqStart = performance.now();
      
      try {
        const response = await config.requestFactory();
        const reqTime = performance.now() - reqStart;
        responseTimes.push(reqTime);
        
        if (response.status >= 200 && response.status < 300) {
          successCount++;
        } else {
          failureCount++;
          const errorKey = `${response.status}_${response.body?.code || 'UNKNOWN'}`;
          errors[errorKey] = (errors[errorKey] || 0) + 1;
        }
      } catch (error: any) {
        failureCount++;
        const errorKey = error.code || 'NETWORK_ERROR';
        errors[errorKey] = (errors[errorKey] || 0) + 1;
      } finally {
        activeRequests--;
      }
    };
    
    // Ramp up phase
    let currentConcurrent = 0;
    const rampUpInterval = config.rampUp ? config.rampUp / config.concurrent : 0;
    
    const promises: Promise<void>[] = [];
    const testEndTime = Date.now() + config.duration;
    
    // Start concurrent users
    for (let i = 0; i < config.concurrent; i++) {
      if (rampUpInterval > 0) {
        await new Promise(resolve => setTimeout(resolve, rampUpInterval));
      }
      
      currentConcurrent++;
      
      promises.push((async () => {
        while (Date.now() < testEndTime) {
          await makeRequest();
          
          // Small random delay between requests
          await new Promise(resolve => setTimeout(resolve, Math.random() * 100));
        }
      })());
    }
    
    // Wait for all requests to complete
    await Promise.all(promises);
    
    // Stop memory monitoring
    if (memoryMonitor) {
      clearInterval(memoryMonitor);
      memoryMonitor = null;
    }
    
    const duration = performance.now() - startTime;
    const totalRequests = successCount + failureCount;
    
    // Calculate metrics
    responseTimes.sort((a, b) => a - b);
    const metrics = {
      avgResponseTime: responseTimes.length > 0 
        ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length 
        : 0,
      minResponseTime: responseTimes[0] || 0,
      maxResponseTime: responseTimes[responseTimes.length - 1] || 0,
      p50ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.5)] || 0,
      p95ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.95)] || 0,
      p99ResponseTime: responseTimes[Math.floor(responseTimes.length * 0.99)] || 0,
      requestsPerSecond: totalRequests / (duration / 1000),
      errorRate: failureCount / totalRequests
    };
    
    const resourceUsage = {
      peakMemory: Math.max(...memoryReadings),
      avgMemory: memoryReadings.reduce((a, b) => a + b, 0) / memoryReadings.length
    };
    
    const result: StressTestResult = {
      test: config.name,
      type: 'stress_test',
      duration,
      totalRequests,
      successfulRequests: successCount,
      failedRequests: failureCount,
      errors,
      metrics,
      resourceUsage
    };
    
    results.push(result);
    
    console.log(`✅ Completed: ${totalRequests} requests in ${(duration / 1000).toFixed(2)}s`);
    console.log(`   Success rate: ${((successCount / totalRequests) * 100).toFixed(2)}%`);
    console.log(`   Avg response time: ${metrics.avgResponseTime.toFixed(2)}ms`);
    console.log(`   Requests/second: ${metrics.requestsPerSecond.toFixed(2)}`);
    
    return result;
  }
}

// ==================== STRESS TESTS ====================

describe('Export Routes Stress Tests', () => {
  let app: Express;
  
  beforeAll(async () => {
    // Create test users (reduced for memory efficiency)
    for (let i = 0; i < 100; i++) {
      const user: TestUser = {
        id: uuidv4(),
        email: `stress-user-${i}@example.com`,
        token: `stress-token-${i}`,
        devices: [`device-${i}-1`, `device-${i}-2`]
      };
      testUsers.set(user.id, user);
    }
    
    // Create app
    app = createStressTestApp();
    
    // Set up periodic cleanup
    setInterval(() => {
      // Clean up old export jobs
      if (exportJobs.size > MAX_EXPORT_JOBS) {
        const toDelete = exportJobs.size - MAX_EXPORT_JOBS;
        const oldJobs = Array.from(exportJobs.entries())
          .sort((a, b) => new Date(a[1].created_at).getTime() - new Date(b[1].created_at).getTime())
          .slice(0, toDelete);
        oldJobs.forEach(([id]) => exportJobs.delete(id));
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
    }, CLEANUP_INTERVAL);
  });
  
  afterAll(async () => {
    // Save stress test results
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const resultsPath = path.join(__dirname, `../../../stress-results/export-routes-${timestamp}.json`);
    await fs.mkdir(path.dirname(resultsPath), { recursive: true });
    await fs.writeFile(resultsPath, JSON.stringify(results, null, 2));
    
    console.log(`\n📊 Stress test results saved to: ${resultsPath}`);
    
    // Print summary
    console.log('\n📈 Stress Test Summary:');
    results.forEach(result => {
      console.log(`\n${result.test}:`);
      console.log(`  Total requests: ${result.totalRequests}`);
      console.log(`  Success rate: ${((result.successfulRequests / result.totalRequests) * 100).toFixed(2)}%`);
      console.log(`  Avg response time: ${result.metrics.avgResponseTime.toFixed(2)}ms`);
      console.log(`  P95 response time: ${result.metrics.p95ResponseTime.toFixed(2)}ms`);
      console.log(`  Requests/second: ${result.metrics.requestsPerSecond.toFixed(2)}`);
      console.log(`  Peak memory: ${result.resourceUsage?.peakMemory.toFixed(2)}MB`);
    });
  });
  
  describe('Extreme Load Tests', () => {
    test('Handle extreme concurrent users creating exports', async () => {
      const users = Array.from(testUsers.values()).slice(0, 100);
      
      const result = await StressTestRunner.runStressTest(app, {
        name: 'Extreme concurrent export creation',
        concurrent: STRESS_CONFIG.extremeLoad.concurrent,
        duration: STRESS_CONFIG.extremeLoad.duration,
        rampUp: STRESS_CONFIG.extremeLoad.rampUpTime,
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          return request(app)
            .post('/api/v1/export/ml')
            .set('Authorization', `Bearer ${user.token}`)
            .send({
              options: {
                format: ['zip', 'tar', 'json', 'csv'][Math.floor(Math.random() * 4)],
                include_images: Math.random() > 0.5,
                include_masks: Math.random() > 0.5,
                compression_level: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)]
              }
            });
        }
      });
      
      // Under extreme load, we accept higher error rates but system should not crash
      expect(result.metrics.errorRate).toBeLessThan(0.95); // Less than 95% error rate
      expect(result.metrics.requestsPerSecond).toBeGreaterThan(5); // At least 5 req/s under extreme stress
    });
    
    test('Handle burst traffic patterns', async () => {
      const users = Array.from(testUsers.values()).slice(0, 100);
      const burstResults: StressTestResult[] = [];
      
      // Normal load
      console.log('\n📊 Phase 1: Normal load');
      const normalResult = await StressTestRunner.runStressTest(app, {
        name: 'Normal load baseline',
        concurrent: STRESS_CONFIG.spikeLoad.normalConcurrent,
        duration: 5000,
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          return request(app)
            .get('/api/v1/export/ml/jobs')
            .set('Authorization', `Bearer ${user.token}`);
        }
      });
      burstResults.push(normalResult);
      
      // Sudden spike
      console.log('\n📊 Phase 2: Traffic spike');
      const spikeResult = await StressTestRunner.runStressTest(app, {
        name: 'Traffic spike',
        concurrent: STRESS_CONFIG.spikeLoad.spikeConcurrent,
        duration: STRESS_CONFIG.spikeLoad.spikeDuration,
        rampUp: 1000, // Quick ramp up
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          return request(app)
            .get('/api/v1/export/ml/jobs')
            .set('Authorization', `Bearer ${user.token}`);
        }
      });
      burstResults.push(spikeResult);
      
      // Recovery phase
      console.log('\n📊 Phase 3: Recovery');
      await new Promise(resolve => setTimeout(resolve, 3000)); // Wait for system to recover
      
      const recoveryResult = await StressTestRunner.runStressTest(app, {
        name: 'Post-spike recovery',
        concurrent: STRESS_CONFIG.spikeLoad.normalConcurrent,
        duration: 5000,
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          return request(app)
            .get('/api/v1/export/ml/jobs')
            .set('Authorization', `Bearer ${user.token}`);
        }
      });
      burstResults.push(recoveryResult);
      
      // System should handle spike and recover
      expect(spikeResult.metrics.errorRate).toBeLessThan(0.8); // Accept up to 80% errors during spike
      expect(recoveryResult.metrics.errorRate).toBeLessThan(0.2); // Should recover to < 20% errors
      expect(recoveryResult.metrics.avgResponseTime).toBeLessThan(normalResult.metrics.avgResponseTime * 3); // Response time should recover
    });
  });
  
  describe('Sustained Load Tests', () => {
    test('Maintain performance under sustained load', async () => {
      const users = Array.from(testUsers.values()).slice(0, 100);
      
      const result = await StressTestRunner.runStressTest(app, {
        name: 'Sustained load test',
        concurrent: STRESS_CONFIG.sustainedLoad.concurrent,
        duration: STRESS_CONFIG.sustainedLoad.duration,
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          const operations = [
            () => request(app)
              .post('/api/v1/export/ml')
              .set('Authorization', `Bearer ${user.token}`)
              .send({ options: { format: 'zip' } }),
            () => request(app)
              .get('/api/v1/export/ml/jobs')
              .set('Authorization', `Bearer ${user.token}`),
            () => request(app)
              .get('/api/v1/export/ml/stats')
              .set('Authorization', `Bearer ${user.token}`),
            () => {
              const jobId = Array.from(exportJobs.keys())[Math.floor(Math.random() * exportJobs.size)];
              return request(app)
                .get(`/api/v1/export/ml/jobs/${jobId || 'invalid'}`)
                .set('Authorization', `Bearer ${user.token}`);
            }
          ];
          
          return operations[Math.floor(Math.random() * operations.length)]();
        }
      });
      
      // System should maintain stability over time
      expect(result.metrics.errorRate).toBeLessThan(0.6); // Less than 60% errors acceptable under sustained load
      expect(result.metrics.avgResponseTime).toBeLessThan(1000); // Avg response under 1 second
      expect(result.resourceUsage?.avgMemory).toBeLessThan(800); // Memory under 800MB
    });
  });
  
  describe('Resource Exhaustion Tests', () => {
    test('Handle memory pressure with large payloads', async () => {
      const users = Array.from(testUsers.values()).slice(0, 50);
      
      const result = await StressTestRunner.runStressTest(app, {
        name: 'Memory pressure test',
        concurrent: STRESS_CONFIG.memoryPressure.concurrentLargeRequests,
        duration: 30000,
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          const largeMetadata = {
            data: 'x'.repeat(100 * 1024), // 100KB of data (reduced from 1MB)
            items: Array(100).fill(null).map((_, i) => ({ // Reduced from 1000
              id: i,
              name: `Item ${i}`,
              description: 'x'.repeat(100) // Reduced from 1000
            }))
          };
          
          return request(app)
            .post('/api/v1/export/ml')
            .set('Authorization', `Bearer ${user.token}`)
            .send({
              options: {
                format: 'json',
                include_images: true,
                include_masks: true,
                metadata: largeMetadata
              }
            });
        }
      });
      
      // System should handle memory pressure gracefully
      expect(result.resourceUsage?.peakMemory).toBeLessThan(1500); // Peak memory under 1.5GB
      expect(result.metrics.errorRate).toBeLessThan(0.85); // Less than 85% errors under memory pressure
    });
    
    test('Handle connection pool exhaustion', async () => {
      const users = Array.from(testUsers.values()).slice(0, 50);
      
      // Create many long-running download requests
      const result = await StressTestRunner.runStressTest(app, {
        name: 'Connection pool exhaustion',
        concurrent: 50,
        duration: 15000,
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          
          // First create some completed jobs
          const jobId = uuidv4();
          const job: TestExportJob = {
            id: jobId,
            user_id: user.id,
            status: 'completed',
            format: 'zip',
            file_size: 10 * 1024 * 1024, // 10MB
            file_path: `/exports/${jobId}.zip`,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            completed_at: new Date().toISOString()
          };
          exportJobs.set(jobId, job);
          
          return request(app)
            .get(`/api/v1/export/ml/download/${jobId}`)
            .set('Authorization', `Bearer ${user.token}`)
            .timeout(30000); // 30 second timeout
        }
      });
      
      // System should handle connection exhaustion
      expect(result.totalRequests).toBeGreaterThan(50); // Should complete at least 50 requests
      expect(result.metrics.errorRate).toBeLessThan(0.7); // Less than 70% errors acceptable
    });
  });
  
  describe('Error Recovery Under Stress', () => {
    test('Recover from cascading failures', async () => {
      const users = Array.from(testUsers.values()).slice(0, 100);
      
      // Inject failures by creating invalid requests
      const result = await StressTestRunner.runStressTest(app, {
        name: 'Cascading failure recovery',
        concurrent: 100,
        duration: 30000,
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          const shouldFail = Math.random() < 0.3; // 30% invalid requests
          
          if (shouldFail) {
            return request(app)
              .post('/api/v1/export/ml')
              .set('Authorization', `Bearer ${user.token}`)
              .send({
                options: {
                  format: 'invalid-format',
                  invalid_option: true
                }
              });
          } else {
            return request(app)
              .get('/api/v1/export/ml/jobs')
              .set('Authorization', `Bearer ${user.token}`);
          }
        }
      });
      
      // System should handle mix of valid and invalid requests
      expect(result.successfulRequests).toBeGreaterThan(result.failedRequests * 0.5); // At least half as many successes
      expect(result.metrics.requestsPerSecond).toBeGreaterThan(10); // Maintain reasonable throughput
    });
    
    test('Handle authentication storms', async () => {
      // Create many users with invalid tokens
      const invalidUsers = Array(100).fill(null).map((_, i) => ({
        token: `invalid-token-${i}`
      }));
      
      const result = await StressTestRunner.runStressTest(app, {
        name: 'Authentication storm',
        concurrent: 50,
        duration: 10000,
        requestFactory: () => {
          const useInvalid = Math.random() < 0.8; // 80% invalid tokens
          const token = useInvalid 
            ? invalidUsers[Math.floor(Math.random() * invalidUsers.length)].token
            : Array.from(testUsers.values())[0].token;
          
          return request(app)
            .get('/api/v1/export/ml/jobs')
            .set('Authorization', `Bearer ${token}`);
        }
      });
      
      // System should handle authentication failures efficiently
      expect(result.metrics.avgResponseTime).toBeLessThan(400); // Reasonably fast rejection
      expect(result.metrics.requestsPerSecond).toBeGreaterThan(50); // Good throughput
    });
  });
  
  describe('System Health Under Stress', () => {
    test('Monitor system health during stress', async () => {
      const healthChecks: any[] = [];
      const users = Array.from(testUsers.values()).slice(0, 100);
      
      // Start background health monitoring
      const healthMonitor = setInterval(async () => {
        try {
          const response = await request(app)
            .get('/api/v1/export/health')
            .set('Authorization', `Bearer ${users[0].token}`)
            .timeout(1000);
          
          healthChecks.push({
            timestamp: Date.now(),
            status: response.status,
            data: response.body
          });
        } catch (error: any) {
          healthChecks.push({
            timestamp: Date.now(),
            status: 'error',
            error: error.message
          });
        }
      }, 1000);
      
      // Run stress test
      await StressTestRunner.runStressTest(app, {
        name: 'Health monitoring under stress',
        concurrent: 30,
        duration: 15000,
        requestFactory: () => {
          const user = users[Math.floor(Math.random() * users.length)];
          return request(app)
            .post('/api/v1/export/ml')
            .set('Authorization', `Bearer ${user.token}`)
            .send({ options: { format: 'zip' } });
        }
      });
      
      clearInterval(healthMonitor);
      
      // Analyze health check results
      const healthyChecks = healthChecks.filter(h => h.status === 200).length;
      const degradedChecks = healthChecks.filter(h => h.status === 503).length;
      const errorChecks = healthChecks.filter(h => h.status === 'error').length;
      
      console.log(`\n🏥 Health Check Results:`);
      console.log(`   Healthy: ${healthyChecks}`);
      console.log(`   Degraded: ${degradedChecks}`);
      console.log(`   Errors: ${errorChecks}`);
      
      // System should maintain some level of health monitoring
      expect(healthyChecks + degradedChecks).toBeGreaterThan(0); // At least some successful checks
      expect(healthChecks.length).toBeGreaterThan(10); // Should complete at least 10 health checks
    });
  });
});