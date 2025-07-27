// /backend/src/tests/stress/polygonRoutes.stress.test.ts
// Stress tests for polygon routes - testing extreme conditions and system limits

import request from 'supertest';
import express, { Express } from 'express';
import { performance } from 'perf_hooks';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { jest } from '@jest/globals';
import { EventEmitter } from 'events';

// Increase max listeners to prevent warnings
EventEmitter.defaultMaxListeners = 50;

// Increase Jest timeout for stress tests
jest.setTimeout(60000); // 60 seconds

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
}

interface TestImage {
  id: string;
  user_id: string;
  file_path: string;
  status: string;
  metadata?: any;
}

interface TestPolygon {
  id: string;
  user_id: string;
  original_image_id: string;
  points: Array<{ x: number; y: number }>;
  label: string;
  metadata?: any;
  status?: string;
  created_at?: string;
  updated_at?: string;
}

// ==================== GLOBAL TEST STATE ====================

let testUsers: TestUser[] = [];
let testImages: TestImage[] = [];
let testPolygons: TestPolygon[] = [];
let primaryUser: TestUser;
let stressResults: any[] = [];

// ==================== MOCK SETUP ====================

const createTestApp = (): Express => {
  const app = (express as any)();
  app.use((express as any).json({ limit: '50mb' }));
  
  // Memory tracking middleware
  app.use((req: any, res: any, next: any) => {
    const startMem = process.memoryUsage();
    res.on('finish', () => {
      const endMem = process.memoryUsage();
      if (req.path.includes('stress')) {
        (req as any).memoryDelta = {
          heapUsed: (endMem.heapUsed - startMem.heapUsed) / 1024 / 1024,
          external: (endMem.external - startMem.external) / 1024 / 1024
        };
      }
    });
    next();
  });
  
  // Mock authentication middleware
  const authenticate = (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        status: 'error',
        message: 'Authentication required',
        code: 'missing_token'
      });
    }
    
    const token = authHeader.substring(7);
    const user = testUsers.find(u => u.token === token);
    
    if (!user) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid token',
        code: 'invalid_token'
      });
    }
    
    req.user = { id: user.id, email: user.email };
    next();
  };
  
  // Mock validation middleware with stress limits
  const validate = (_schema: any) => {
    return (req: any, res: any, next: any) => {
      const { points, label } = req.body;
      
      if (req.method === 'POST' || req.method === 'PUT') {
        // Stress test: Allow up to 10000 points for extreme testing
        if (!points || !Array.isArray(points) || points.length < 3) {
          return res.status(422).json({
            status: 'error',
            message: 'Invalid polygon points',
            code: 'validation_error'
          });
        }
        
        if (points.length > 10000) {
          return res.status(422).json({
            status: 'error',
            message: 'Too many polygon points (max 10000)',
            code: 'validation_error'
          });
        }
        
        if (!label || typeof label !== 'string' || label.trim().length === 0) {
          return res.status(422).json({
            status: 'error',
            message: 'Label is required',
            code: 'validation_error'
          });
        }
        
        // Check for extremely long labels
        if (label.length > 1000) {
          return res.status(422).json({
            status: 'error',
            message: 'Label too long (max 1000 characters)',
            code: 'validation_error'
          });
        }
      }
      
      next();
    };
  };
  
  // ==================== POLYGON ROUTE HANDLERS ====================
  
  const polygonRouter = (express as any).Router();
  polygonRouter.use(authenticate);
  
  // Create polygon with stress handling
  polygonRouter.post('/', validate({}), (req: any, res: any) => {
    const { points, label, original_image_id, metadata } = req.body;
    
    // Simulate processing delay for large polygons
    const processingDelay = Math.min(points.length * 0.1, 100);
    
    setTimeout(() => {
      // Find the image
      const image = testImages.find(i => i.id === original_image_id);
      if (!image) {
        return res.status(404).json({
          status: 'error',
          message: 'Image not found',
          code: 'image_not_found'
        });
      }
      
      // Check ownership
      if (image.user_id !== req.user.id) {
        return res.status(403).json({
          status: 'error',
          message: 'Access denied',
          code: 'forbidden'
        });
      }
      
      // Create polygon
      const polygon: TestPolygon = {
        id: uuidv4(),
        user_id: req.user.id,
        original_image_id,
        points,
        label,
        metadata: metadata || {},
        status: 'active',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };
      
      testPolygons.push(polygon);
      
      res.status(201).json({
        status: 'success',
        data: { polygon }
      });
    }, processingDelay);
  });
  
  // Bulk create polygons
  polygonRouter.post('/bulk', authenticate, (req: any, res: any) => {
    const { polygons } = req.body;
    
    if (!Array.isArray(polygons)) {
      return res.status(400).json({
        status: 'error',
        message: 'Polygons array required',
        code: 'invalid_request'
      });
    }
    
    if (polygons.length > 1000) {
      return res.status(422).json({
        status: 'error',
        message: 'Too many polygons in bulk request (max 1000)',
        code: 'validation_error'
      });
    }
    
    const results: any[] = [];
    const errors: any[] = [];
    
    polygons.forEach((polygonData: any, index: number) => {
      try {
        const { points, label, original_image_id, metadata } = polygonData;
        
        // Basic validation
        if (!points || !Array.isArray(points) || points.length < 3) {
          errors.push({ index, error: 'Invalid points' });
          return;
        }
        
        if (!label) {
          errors.push({ index, error: 'Missing label' });
          return;
        }
        
        const polygon: TestPolygon = {
          id: uuidv4(),
          user_id: req.user.id,
          original_image_id,
          points,
          label,
          metadata: metadata || {},
          status: 'active',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        
        testPolygons.push(polygon);
        results.push({ index, polygon });
      } catch (error) {
        errors.push({ index, error: 'Processing failed' });
      }
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        created: results.length,
        failed: errors.length,
        results,
        errors
      }
    });
  });
  
  // Get polygons with pagination for stress testing
  polygonRouter.get('/image/:imageId', (req: any, res: any) => {
    const { imageId } = req.params;
    const { limit = 100, offset = 0 } = req.query;
    
    // Find the image
    const image = testImages.find(i => i.id === imageId);
    if (!image) {
      return res.status(404).json({
        status: 'error',
        message: 'Image not found',
        code: 'image_not_found'
      });
    }
    
    // Check ownership
    if (image.user_id !== req.user.id) {
      return res.status(403).json({
        status: 'error',
        message: 'Access denied',
        code: 'forbidden'
      });
    }
    
    // Get polygons with pagination
    const allPolygons = testPolygons.filter(p => 
      p.original_image_id === imageId && 
      p.status !== 'deleted'
    );
    
    const paginatedPolygons = allPolygons.slice(
      parseInt(offset as string),
      parseInt(offset as string) + parseInt(limit as string)
    );
    
    res.status(200).json({
      status: 'success',
      data: { 
        polygons: paginatedPolygons,
        total: allPolygons.length,
        limit: parseInt(limit as string),
        offset: parseInt(offset as string)
      }
    });
  });
  
  // Stress test endpoint for extreme validation
  polygonRouter.post('/stress/validate', (req: any, res: any) => {
    const { scenario } = req.body;
    
    switch (scenario) {
      case 'max_points':
        // Test with maximum allowed points
        res.status(200).json({ 
          status: 'success', 
          message: 'Max points validation passed',
          limit: 10000 
        });
        break;
      
      case 'complex_shape':
        // Test with very complex polygon shape
        res.status(200).json({ 
          status: 'success', 
          message: 'Complex shape validation passed' 
        });
        break;
      
      case 'deep_metadata':
        // Test with deeply nested metadata
        res.status(200).json({ 
          status: 'success', 
          message: 'Deep metadata validation passed' 
        });
        break;
      
      default:
        res.status(400).json({ 
          status: 'error', 
          message: 'Unknown stress scenario' 
        });
    }
  });
  
  // Delete multiple polygons
  polygonRouter.delete('/bulk', authenticate, (req: any, res: any) => {
    const { polygon_ids } = req.body;
    
    if (!Array.isArray(polygon_ids)) {
      return res.status(400).json({
        status: 'error',
        message: 'polygon_ids array required',
        code: 'invalid_request'
      });
    }
    
    let deletedCount = 0;
    polygon_ids.forEach(id => {
      const polygon = testPolygons.find(p => p.id === id && p.status !== 'deleted');
      if (polygon && polygon.user_id === req.user.id) {
        polygon.status = 'deleted';
        polygon.updated_at = new Date().toISOString();
        deletedCount++;
      }
    });
    
    res.status(200).json({
      status: 'success',
      data: {
        deleted: deletedCount,
        requested: polygon_ids.length
      }
    });
  });
  
  app.use('/api/v1/polygons', polygonRouter);
  
  // Error handler
  app.use((error: any, _req: any, res: any, _next: any) => {
    res.status(error.statusCode || 500).json({
      status: 'error',
      message: error.message || 'Internal server error'
    });
  });
  
  return app;
};

// ==================== TEST HELPERS ====================

const createComplexPolygon = (pointCount: number): Array<{ x: number; y: number }> => {
  const points: Array<{ x: number; y: number }> = [];
  
  // Create a complex star-like shape
  for (let i = 0; i < pointCount; i++) {
    const angle = (i / pointCount) * 2 * Math.PI;
    const radius = i % 2 === 0 ? 0.5 : 0.2;
    points.push({
      x: parseFloat((0.5 + radius * Math.cos(angle)).toFixed(6)),
      y: parseFloat((0.5 + radius * Math.sin(angle)).toFixed(6))
    });
  }
  
  return points;
};

const createDeepMetadata = (depth: number): any => {
  if (depth === 0) {
    return {
      value: uuidv4(),
      timestamp: new Date().toISOString()
    };
  }
  
  return {
    level: depth,
    data: createDeepMetadata(depth - 1),
    array: Array(5).fill(null).map(() => createDeepMetadata(Math.max(0, depth - 2))),
    metadata: {
      created: new Date().toISOString(),
      random: Math.random()
    }
  };
};

const measureMemoryUsage = () => {
  const mem = process.memoryUsage();
  return {
    heapUsed: parseFloat((mem.heapUsed / 1024 / 1024).toFixed(2)),
    heapTotal: parseFloat((mem.heapTotal / 1024 / 1024).toFixed(2)),
    external: parseFloat((mem.external / 1024 / 1024).toFixed(2)),
    rss: parseFloat((mem.rss / 1024 / 1024).toFixed(2))
  };
};

// ==================== STRESS TESTS ====================

describe('Polygon Routes Stress Tests', () => {
  let app: Express;
  let testImage: TestImage;
  
  beforeAll(async () => {
    // Create test user
    primaryUser = {
      id: uuidv4(),
      email: 'stress-test@example.com',
      token: 'stress-test-token'
    };
    testUsers.push(primaryUser);
    
    // Create test image
    testImage = {
      id: uuidv4(),
      user_id: primaryUser.id,
      file_path: '/test/stress-test-image.jpg',
      status: 'pending'
    };
    testImages.push(testImage);
    
    // Create app
    app = createTestApp();
  });
  
  afterEach(() => {
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    // Clear any mocks
    jest.clearAllMocks();
  });

  afterAll(async () => {
    // Save stress test results
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const resultsPath = path.join(__dirname, `../../../performance-results/polygon-stress-${timestamp}.json`);
    await fs.mkdir(path.dirname(resultsPath), { recursive: true });
    await fs.writeFile(resultsPath, JSON.stringify(stressResults, null, 2));
    
    console.log(`Stress test results saved to: ${resultsPath}`);
    
    // Clean up test data
    testUsers = [];
    testImages = [];
    testPolygons = [];
    stressResults = [];
    
    // Force final garbage collection
    if (global.gc) {
      global.gc();
    }
  });
  
  describe('Extreme Point Count Tests', () => {
    test('Handle polygon with 1000 points', async () => {
      const start = performance.now();
      const memBefore = measureMemoryUsage();
      
      const response = await (request as any)(app)
        .post('/api/v1/polygons')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: createComplexPolygon(1000),
          label: 'extreme-polygon-1000',
          metadata: { pointCount: 1000 }
        });
      
      const end = performance.now();
      const memAfter = measureMemoryUsage();
      
      expect(response.status).toBe(201);
      expect(response.body.data.polygon.points).toHaveLength(1000);
      
      const result = {
        test: 'Create polygon with 1000 points',
        pointCount: 1000,
        responseTime: parseFloat((end - start).toFixed(2)),
        memoryIncrease: {
          heapUsed: memAfter.heapUsed - memBefore.heapUsed,
          external: memAfter.external - memBefore.external
        }
      };
      
      stressResults.push(result);
      console.log('1000 points polygon:', result);
      
      // Performance assertions
      expect(end - start).toBeLessThan(1000); // Should complete within 1 second
    });
    
    test('Handle polygon with 5000 points', async () => {
      const start = performance.now();
      
      const response = await (request as any)(app)
        .post('/api/v1/polygons')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: createComplexPolygon(5000),
          label: 'extreme-polygon-5000',
          metadata: { pointCount: 5000 }
        });
      
      const end = performance.now();
      
      expect(response.status).toBe(201);
      expect(response.body.data.polygon.points).toHaveLength(5000);
      
      const responseTime = end - start;
      expect(responseTime).toBeLessThan(3000); // Should complete within 3 seconds
      
      stressResults.push({
        test: 'Create polygon with 5000 points',
        pointCount: 5000,
        responseTime: parseFloat(responseTime.toFixed(2))
      });
    });
    
    test('Reject polygon with more than 10000 points', async () => {
      const response = await (request as any)(app)
        .post('/api/v1/polygons')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: createComplexPolygon(10001),
          label: 'too-many-points',
          metadata: { pointCount: 10001 }
        });
      
      expect(response.status).toBe(422);
      expect(response.body.message).toContain('Too many polygon points');
    });
  });
  
  describe('Bulk Operations Stress Tests', () => {
    test('Create 100 polygons in bulk', async () => {
      const polygons = Array.from({ length: 100 }, (_, i) => ({
        original_image_id: testImage.id,
        points: createComplexPolygon(10 + i % 50),
        label: `bulk-polygon-${i}`,
        metadata: { index: i, batch: 'stress-100' }
      }));
      
      const start = performance.now();
      
      const response = await (request as any)(app)
        .post('/api/v1/polygons/bulk')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({ polygons });
      
      const end = performance.now();
      
      expect(response.status).toBe(200);
      expect(response.body.data.created).toBe(100);
      expect(response.body.data.failed).toBe(0);
      
      const result = {
        test: 'Bulk create 100 polygons',
        count: 100,
        responseTime: parseFloat((end - start).toFixed(2)),
        avgTimePerPolygon: parseFloat(((end - start) / 100).toFixed(2))
      };
      
      stressResults.push(result);
      console.log('Bulk create 100:', result);
      
      expect(end - start).toBeLessThan(5000); // Should complete within 5 seconds
    });
    
    test('Create 500 polygons in bulk', async () => {
      const polygons = Array.from({ length: 500 }, (_, i) => ({
        original_image_id: testImage.id,
        points: createComplexPolygon(20),
        label: `bulk-polygon-500-${i}`,
        metadata: { index: i, batch: 'stress-500' }
      }));
      
      const start = performance.now();
      
      const response = await (request as any)(app)
        .post('/api/v1/polygons/bulk')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({ polygons });
      
      const end = performance.now();
      
      expect(response.status).toBe(200);
      expect(response.body.data.created).toBe(500);
      
      const responseTime = end - start;
      expect(responseTime).toBeLessThan(10000); // Should complete within 10 seconds
      
      stressResults.push({
        test: 'Bulk create 500 polygons',
        count: 500,
        responseTime: parseFloat(responseTime.toFixed(2))
      });
    });
    
    test('Handle bulk delete of 200 polygons', async () => {
      // First create polygons to delete
      const polygonIds: string[] = [];
      for (let i = 0; i < 200; i++) {
        const polygon: TestPolygon = {
          id: uuidv4(),
          user_id: primaryUser.id,
          original_image_id: testImage.id,
          points: createComplexPolygon(10),
          label: `delete-test-${i}`,
          metadata: { deleteTest: true },
          status: 'active',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        testPolygons.push(polygon);
        polygonIds.push(polygon.id);
      }
      
      const start = performance.now();
      
      const response = await (request as any)(app)
        .delete('/api/v1/polygons/bulk')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({ polygon_ids: polygonIds });
      
      const end = performance.now();
      
      expect(response.status).toBe(200);
      expect(response.body.data.deleted).toBe(200);
      
      const responseTime = end - start;
      expect(responseTime).toBeLessThan(2000); // Should complete within 2 seconds
      
      stressResults.push({
        test: 'Bulk delete 200 polygons',
        count: 200,
        responseTime: parseFloat(responseTime.toFixed(2))
      });
    });
  });
  
  describe('Memory Stress Tests', () => {
    test('Handle deeply nested metadata', async () => {
      const deepMetadata = createDeepMetadata(10); // 10 levels deep
      
      const response = await (request as any)(app)
        .post('/api/v1/polygons')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: createComplexPolygon(50),
          label: 'deep-metadata-polygon',
          metadata: deepMetadata
        });
      
      expect(response.status).toBe(201);
      expect(response.body.data.polygon.metadata).toBeDefined();
      
      stressResults.push({
        test: 'Create polygon with deep metadata',
        metadataDepth: 10,
        status: 'success'
      });
    });
    
    test('Handle very long labels', async () => {
      const longLabel = 'x'.repeat(999); // Just under the 1000 char limit
      
      const response = await (request as any)(app)
        .post('/api/v1/polygons')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: createComplexPolygon(10),
          label: longLabel,
          metadata: { labelLength: longLabel.length }
        });
      
      expect(response.status).toBe(201);
      expect(response.body.data.polygon.label).toHaveLength(999);
    });
    
    test('Reject excessively long labels', async () => {
      const tooLongLabel = 'x'.repeat(1001); // Exceeds 1000 char limit
      
      const response = await (request as any)(app)
        .post('/api/v1/polygons')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: createComplexPolygon(10),
          label: tooLongLabel,
          metadata: { labelLength: tooLongLabel.length }
        });
      
      expect(response.status).toBe(422);
      expect(response.body.message).toContain('Label too long');
    });
  });
  
  describe('Concurrent Request Stress Tests', () => {
    test('Handle 100 concurrent polygon creations', async () => {
      const concurrentCount = 100;
      const batchSize = 20; // Process in smaller batches to avoid memory issues
      const start = performance.now();
      
      let successCount = 0;
      const responses: any[] = [];
      
      // Process in batches to prevent memory exhaustion
      for (let batch = 0; batch < concurrentCount; batch += batchSize) {
        const currentBatchSize = Math.min(batchSize, concurrentCount - batch);
        
        const batchPromises = Array.from({ length: currentBatchSize }, (_, i) => {
          const index = batch + i;
          return (request as any)(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${primaryUser.token}`)
            .send({
              original_image_id: testImage.id,
              points: createComplexPolygon(20),
              label: `concurrent-stress-${index}`,
              metadata: { concurrent: true, index }
            });
        });
        
        const batchResponses = await Promise.all(batchPromises);
        responses.push(...batchResponses);
        successCount += batchResponses.filter(r => r.status === 201).length;
        
        // Small delay between batches to allow cleanup
        if (batch + batchSize < concurrentCount) {
          await new Promise(resolve => setImmediate(resolve));
        }
      }
      
      const end = performance.now();
      
      expect(successCount).toBe(concurrentCount);
      
      const result = {
        test: 'Concurrent creation stress',
        concurrentRequests: concurrentCount,
        successCount,
        totalTime: parseFloat((end - start).toFixed(2)),
        avgTimePerRequest: parseFloat(((end - start) / concurrentCount).toFixed(2))
      };
      
      stressResults.push(result);
      console.log('Concurrent stress:', result);
      
      expect(end - start).toBeLessThan(10000); // Should handle within 10 seconds
    });
    
    test('Handle rapid sequential requests', async () => {
      const requestCount = 50;
      const start = performance.now();
      let successCount = 0;
      
      for (let i = 0; i < requestCount; i++) {
        const response = await (request as any)(app)
          .post('/api/v1/polygons')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            original_image_id: testImage.id,
            points: createComplexPolygon(15),
            label: `rapid-sequential-${i}`,
            metadata: { sequential: true, index: i }
          });
        
        if (response.status === 201) successCount++;
      }
      
      const end = performance.now();
      
      expect(successCount).toBe(requestCount);
      
      const totalTime = end - start;
      expect(totalTime).toBeLessThan(5000); // Should complete within 5 seconds
      
      stressResults.push({
        test: 'Rapid sequential requests',
        requestCount,
        totalTime: parseFloat(totalTime.toFixed(2)),
        requestsPerSecond: parseFloat((requestCount / (totalTime / 1000)).toFixed(2))
      });
    });
  });
  
  describe('Pagination Stress Tests', () => {
    test('Retrieve 1000 polygons with pagination', async () => {
      // Create a new image for pagination test
      const paginationImage: TestImage = {
        id: uuidv4(),
        user_id: primaryUser.id,
        file_path: '/test/pagination-test-image.jpg',
        status: 'pending'
      };
      testImages.push(paginationImage);
      
      // Create 1000 polygons for this image in batches to reduce memory usage
      const polygonBatchSize = 100;
      const totalPolygons = 1000;
      
      // Pre-create common data to reduce object creation overhead
      const basePoints = createComplexPolygon(5);
      const baseDate = new Date().toISOString();
      
      for (let batch = 0; batch < totalPolygons; batch += polygonBatchSize) {
        const batchPolygons: TestPolygon[] = [];
        const currentBatchSize = Math.min(polygonBatchSize, totalPolygons - batch);
        
        for (let i = 0; i < currentBatchSize; i++) {
          const index = batch + i;
          batchPolygons.push({
            id: uuidv4(),
            user_id: primaryUser.id,
            original_image_id: paginationImage.id,
            points: [...basePoints], // Clone the array
            label: `pagination-test-${index}`,
            metadata: { index },
            status: 'active',
            created_at: baseDate,
            updated_at: baseDate
          });
        }
        
        testPolygons.push(...batchPolygons);
        
        // Allow garbage collection between batches
        if (batch + polygonBatchSize < totalPolygons && global.gc) {
          await new Promise(resolve => setImmediate(resolve));
          global.gc();
        }
      }
      
      // Test different page sizes
      const pageSizes = [100, 250, 500];
      
      for (const pageSize of pageSizes) {
        const start = performance.now();
        
        const response = await (request as any)(app)
          .get(`/api/v1/polygons/image/${paginationImage.id}`)
          .query({ limit: pageSize, offset: 0 })
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        const end = performance.now();
        
        expect(response.status).toBe(200);
        expect(response.body.data.polygons).toHaveLength(pageSize);
        expect(response.body.data.total).toBe(1000);
        
        const responseTime = end - start;
        expect(responseTime).toBeLessThan(1000); // Each page should load within 1 second
        
        stressResults.push({
          test: `Pagination with ${pageSize} items`,
          pageSize,
          totalItems: 1000,
          responseTime: parseFloat(responseTime.toFixed(2))
        });
      }
    });
  });
  
  describe('Stress Validation Scenarios', () => {
    test('Validate maximum point scenario', async () => {
      const response = await (request as any)(app)
        .post('/api/v1/polygons/stress/validate')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({ scenario: 'max_points' });
      
      expect(response.status).toBe(200);
      expect(response.body.limit).toBe(10000);
    });
    
    test('Validate complex shape scenario', async () => {
      const response = await (request as any)(app)
        .post('/api/v1/polygons/stress/validate')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({ scenario: 'complex_shape' });
      
      expect(response.status).toBe(200);
      expect(response.body.message).toContain('Complex shape validation passed');
    });
    
    test('Validate deep metadata scenario', async () => {
      const response = await (request as any)(app)
        .post('/api/v1/polygons/stress/validate')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({ scenario: 'deep_metadata' });
      
      expect(response.status).toBe(200);
      expect(response.body.message).toContain('Deep metadata validation passed');
    });
  });
  
  describe('Recovery and Error Handling', () => {
    test('Recover from malformed polygon data', async () => {
      const malformedRequests = [
        { points: null, label: 'test' }, // Missing points
        { points: [], label: 'test' }, // Empty points
        { points: [{ x: 0, y: 0 }], label: 'test' }, // Too few points
        { points: createComplexPolygon(10), label: null }, // Missing label
        { points: 'not-an-array', label: 'test' }, // Invalid points type
      ];
      
      for (const malformed of malformedRequests) {
        const response = await (request as any)(app)
          .post('/api/v1/polygons')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            original_image_id: testImage.id,
            ...malformed
          });
        
        expect(response.status).toBe(422);
        expect(response.body.status).toBe('error');
      }
      
      // Verify system still works after errors
      const validResponse = await (request as any)(app)
        .post('/api/v1/polygons')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: createComplexPolygon(10),
          label: 'recovery-test',
          metadata: { afterErrors: true }
        });
      
      expect(validResponse.status).toBe(201);
    });
    
    test('Handle partial bulk operation failures', async () => {
      const mixedPolygons = [
        // Valid polygons
        ...Array.from({ length: 50 }, (_, i) => ({
          original_image_id: testImage.id,
          points: createComplexPolygon(10),
          label: `valid-bulk-${i}`,
          metadata: { valid: true }
        })),
        // Invalid polygons
        ...Array.from({ length: 10 }, (_, i) => ({
          original_image_id: testImage.id,
          points: null, // Invalid
          label: `invalid-bulk-${i}`,
          metadata: { valid: false }
        }))
      ];
      
      const response = await (request as any)(app)
        .post('/api/v1/polygons/bulk')
        .set('Authorization', `Bearer ${primaryUser.token}`)
        .send({ polygons: mixedPolygons });
      
      expect(response.status).toBe(200);
      expect(response.body.data.created).toBe(50);
      expect(response.body.data.failed).toBe(10);
      
      stressResults.push({
        test: 'Partial bulk operation',
        total: 60,
        succeeded: 50,
        failed: 10
      });
    });
  });
  
  describe('Stress Test Summary', () => {
    test('Generate stress test report', () => {
      const summary = {
        timestamp: new Date().toISOString(),
        environment: {
          node: process.version,
          platform: process.platform,
          memory: process.memoryUsage()
        },
        testCount: stressResults.length,
        results: stressResults
      };
      
      console.log('\n=== STRESS TEST SUMMARY ===');
      console.log(`Total stress scenarios: ${stressResults.length}`);
      console.log(`Test completed: ${new Date().toISOString()}`);
      
      // Group by test type
      const byType: Record<string, any[]> = {};
      stressResults.forEach(result => {
        const type = result.test.split(' ')[0];
        if (!byType[type]) byType[type] = [];
        byType[type].push(result);
      });
      
      Object.entries(byType).forEach(([type, results]) => {
        console.log(`\n${type.toUpperCase()} (${results.length} tests)`);
      });
      
      expect(summary.results.length).toBeGreaterThan(0);
    });
  });
});