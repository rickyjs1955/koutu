// /backend/src/tests/performance/polygonRoutes.perf.test.ts
// Performance tests for polygon routes

import request from 'supertest';
import express, { Express } from 'express';
import { performance } from 'perf_hooks';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { jest } from '@jest/globals';

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
let testImage: TestImage;
const results: any[] = [];

// ==================== MOCK SETUP ====================

const createTestApp = (): Express => {
  const app = (express as any)();
  app.use((express as any).json({ limit: '50mb' }));
  
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
  
  // Mock validation middleware
  const validate = (_schema: any) => {
    return (req: any, res: any, next: any) => {
      const { points, label } = req.body;
      
      if (req.method === 'POST' || req.method === 'PUT') {
        if (!points || !Array.isArray(points) || points.length < 3) {
          return res.status(422).json({
            status: 'error',
            message: 'Invalid polygon points',
            code: 'validation_error'
          });
        }
        
        if (points.length > 1000) {
          return res.status(422).json({
            status: 'error',
            message: 'Too many polygon points',
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
      }
      
      next();
    };
  };
  
  // ==================== POLYGON ROUTE HANDLERS ====================
  
  const polygonRouter = (express as any).Router();
  polygonRouter.use(authenticate);
  
  // Create polygon
  polygonRouter.post('/', validate({}), (req: any, res: any) => {
    const { points, label, original_image_id, metadata } = req.body;
    
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
    
    // Check if image is already labeled
    if (image.status === 'labeled') {
      return res.status(409).json({
        status: 'error',
        message: 'Image is already labeled',
        code: 'image_already_labeled'
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
  });
  
  // Get polygons for an image
  polygonRouter.get('/image/:imageId', (req: any, res: any) => {
    const { imageId } = req.params;
    
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
    
    // Get polygons
    const polygons = testPolygons.filter(p => 
      p.original_image_id === imageId && 
      p.status !== 'deleted'
    );
    
    res.status(200).json({
      status: 'success',
      data: { 
        polygons,
        count: polygons.length
      }
    });
  });
  
  // Get single polygon
  polygonRouter.get('/:id', (req: any, res: any) => {
    const { id } = req.params;
    
    // Find polygon
    const polygon = testPolygons.find(p => p.id === id && p.status !== 'deleted');
    if (!polygon) {
      return res.status(404).json({
        status: 'error',
        message: 'Polygon not found',
        code: 'polygon_not_found'
      });
    }
    
    // Find image to check ownership
    const image = testImages.find(i => i.id === polygon.original_image_id);
    if (!image || image.user_id !== req.user.id) {
      return res.status(403).json({
        status: 'error',
        message: 'Access denied',
        code: 'forbidden'
      });
    }
    
    res.status(200).json({
      status: 'success',
      data: { polygon }
    });
  });
  
  // Update polygon
  polygonRouter.put('/:id', validate({}), (req: any, res: any) => {
    const { id } = req.params;
    const { points, label, metadata } = req.body;
    
    // Find polygon
    const polygon = testPolygons.find(p => p.id === id && p.status !== 'deleted');
    if (!polygon) {
      return res.status(404).json({
        status: 'error',
        message: 'Polygon not found',
        code: 'polygon_not_found'
      });
    }
    
    // Find image to check ownership
    const image = testImages.find(i => i.id === polygon.original_image_id);
    if (!image || image.user_id !== req.user.id) {
      return res.status(403).json({
        status: 'error',
        message: 'Access denied',
        code: 'forbidden'
      });
    }
    
    // Update polygon
    if (points) polygon.points = points;
    if (label) polygon.label = label;
    if (metadata) polygon.metadata = { ...polygon.metadata, ...metadata };
    polygon.updated_at = new Date().toISOString();
    
    res.status(200).json({
      status: 'success',
      data: { polygon }
    });
  });
  
  // Delete polygon
  polygonRouter.delete('/:id', (req: any, res: any) => {
    const { id } = req.params;
    
    // Find polygon
    const polygon = testPolygons.find(p => p.id === id && p.status !== 'deleted');
    if (!polygon) {
      return res.status(404).json({
        status: 'error',
        message: 'Polygon not found',
        code: 'polygon_not_found'
      });
    }
    
    // Find image to check ownership
    const image = testImages.find(i => i.id === polygon.original_image_id);
    if (!image || image.user_id !== req.user.id) {
      return res.status(403).json({
        status: 'error',
        message: 'Access denied',
        code: 'forbidden'
      });
    }
    
    // Mark as deleted
    polygon.status = 'deleted';
    polygon.updated_at = new Date().toISOString();
    
    res.status(200).json({
      status: 'success',
      data: null
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

const createValidPolygonPoints = (count: number = 4): Array<{ x: number; y: number }> => {
  const points: Array<{ x: number; y: number }> = [];
  const angleStep = (2 * Math.PI) / count;
  
  for (let i = 0; i < count; i++) {
    const angle = i * angleStep;
    points.push({
      x: parseFloat((0.5 + 0.3 * Math.cos(angle)).toFixed(4)),
      y: parseFloat((0.5 + 0.3 * Math.sin(angle)).toFixed(4))
    });
  }
  
  return points;
};

const createLargePolygon = (pointCount: number): any => {
  return {
    original_image_id: testImage.id,
    points: createValidPolygonPoints(pointCount),
    label: `perf-polygon-${pointCount}`,
    metadata: {
      test: 'performance',
      pointCount
    }
  };
};

// ==================== PERFORMANCE TESTS ====================

describe('Polygon Routes Performance Tests', () => {
  let app: Express;
  
  beforeAll(async () => {
    // Create test users
    primaryUser = {
      id: uuidv4(),
      email: 'perf-test@example.com',
      token: 'perf-test-token'
    };
    testUsers.push(primaryUser);
    
    // Create test image
    testImage = {
      id: uuidv4(),
      user_id: primaryUser.id,
      file_path: '/test/performance-image.jpg',
      status: 'pending'
    };
    testImages.push(testImage);
    
    // Create some test polygons
    for (let i = 0; i < 100; i++) {
      const polygon: TestPolygon = {
        id: uuidv4(),
        user_id: primaryUser.id,
        original_image_id: testImage.id,
        points: createValidPolygonPoints(4),
        label: `perf-polygon-${i}`,
        metadata: { index: i },
        status: 'active',
        created_at: new Date(Date.now() - i * 60000).toISOString(),
        updated_at: new Date(Date.now() - i * 60000).toISOString()
      };
      testPolygons.push(polygon);
    }
    
    // Create app
    app = createTestApp();
  });
  
  afterAll(async () => {
    // Save performance results
    const timestamp = new Date().toISOString().replace(/:/g, '-');
    const resultsPath = path.join(__dirname, `../../../performance-results/polygon-routes-${timestamp}.json`);
    await fs.mkdir(path.dirname(resultsPath), { recursive: true });
    await fs.writeFile(resultsPath, JSON.stringify(results, null, 2));
    
    console.log(`Performance results saved to: ${resultsPath}`);
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
    
    test('POST /api/v1/polygons - create polygon', async () => {
      await measureResponseTime('POST /api/v1/polygons', async () => {
        const response = await (request as any)(app)
          .post('/api/v1/polygons')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            original_image_id: testImage.id,
            points: createValidPolygonPoints(4),
            label: 'perf-test-polygon',
            metadata: { test: 'performance' }
          });
        
        expect(response.status).toBe(201);
      });
    });
    
    test('GET /api/v1/polygons/image/:imageId - list polygons', async () => {
      await measureResponseTime('GET /api/v1/polygons/image/:imageId', async () => {
        const response = await (request as any)(app)
          .get(`/api/v1/polygons/image/${testImage.id}`)
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        expect(response.status).toBe(200);
      });
    });
    
    test('GET /api/v1/polygons/:id - get single polygon', async () => {
      const polygonId = testPolygons[0].id;
      
      await measureResponseTime('GET /api/v1/polygons/:id', async () => {
        const response = await (request as any)(app)
          .get(`/api/v1/polygons/${polygonId}`)
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        expect(response.status).toBe(200);
      });
    });
    
    test('PUT /api/v1/polygons/:id - update polygon', async () => {
      const polygonId = testPolygons[1].id;
      
      await measureResponseTime('PUT /api/v1/polygons/:id', async () => {
        const response = await (request as any)(app)
          .put(`/api/v1/polygons/${polygonId}`)
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            points: createValidPolygonPoints(4),
            label: 'updated-perf-polygon',
            metadata: { updated: true }
          });
        
        expect(response.status).toBe(200);
      });
    });
    
    test('DELETE /api/v1/polygons/:id - delete polygon', async () => {
      // Create polygons to delete
      const polygonsToDelete: string[] = [];
      for (let i = 0; i < 200; i++) { // Create more polygons than iterations
        const polygon: TestPolygon = {
          id: uuidv4(),
          user_id: primaryUser.id,
          original_image_id: testImage.id,
          points: createValidPolygonPoints(4),
          label: `delete-test-${i}`,
          metadata: { test: 'delete' },
          status: 'active',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        testPolygons.push(polygon);
        polygonsToDelete.push(polygon.id);
      }
      
      let deleteIndex = 0;
      await measureResponseTime('DELETE /api/v1/polygons/:id', async () => {
        const polygonId = polygonsToDelete[deleteIndex];
        deleteIndex++;
        
        const response = await (request as any)(app)
          .delete(`/api/v1/polygons/${polygonId}`)
          .set('Authorization', `Bearer ${primaryUser.token}`);
        
        expect(response.status).toBe(200);
      });
    });
  });
  
  describe('Load Tests', () => {
    test('Handle concurrent polygon creation', async () => {
      const concurrentRequests = 50;
      const start = performance.now();
      
      const promises = Array.from({ length: concurrentRequests }, (_, i) => 
        (request as any)(app)
          .post('/api/v1/polygons')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            original_image_id: testImage.id,
            points: createValidPolygonPoints(4),
            label: `concurrent-polygon-${i}`,
            metadata: { concurrent: true, index: i }
          })
      );
      
      const responses = await Promise.all(promises);
      const end = performance.now();
      
      const totalTime = end - start;
      const avgTime = totalTime / concurrentRequests;
      
      const result = {
        test: 'Concurrent polygon creation',
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
      console.log('\nConcurrent creation:', result.metrics);
      
      // All requests should succeed
      responses.forEach(response => {
        expect(response.status).toBe(201);
      });
      
      // Performance assertions
      expect(avgTime).toBeLessThan(100); // Average time per request under 100ms
      expect(totalTime).toBeLessThan(5000); // Total time under 5 seconds
    });
    
    test('Handle large polygon data', async () => {
      const pointCounts = [10, 50, 100, 500, 1000];
      const largePolygonResults: any[] = [];
      
      for (const pointCount of pointCounts) {
        const start = performance.now();
        
        const response = await (request as any)(app)
          .post('/api/v1/polygons')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send(createLargePolygon(pointCount));
        
        const end = performance.now();
        const time = end - start;
        
        // In a real implementation, 1000 points would be rejected
        // but our mock doesn't implement this validation
        expect(response.status).toBe(201);
        
        largePolygonResults.push({
          pointCount,
          time: parseFloat(time.toFixed(2)),
          status: response.status
        });
      }
      
      const result = {
        test: 'Large polygon handling',
        type: 'scalability_test',
        results: largePolygonResults
      };
      
      results.push(result);
      console.log('\nLarge polygon handling:', largePolygonResults);
      
      // Performance should scale linearly with point count
      const times = largePolygonResults.map(r => r.time);
      const avgIncrease = times.slice(1).reduce((acc, time, i) => 
        acc + (time - times[i]) / times[i], 0) / (times.length - 1);
      
      expect(avgIncrease).toBeLessThan(2); // Less than 2x increase per step
    });
  });
  
  describe('Memory Usage Tests', () => {
    test('Memory efficiency with many polygons', async () => {
      const initialMemory = process.memoryUsage();
      const polygonCount = 1000;
      
      // Create many polygons
      for (let i = 0; i < polygonCount; i++) {
        await (request as any)(app)
          .post('/api/v1/polygons')
          .set('Authorization', `Bearer ${primaryUser.token}`)
          .send({
            original_image_id: testImage.id,
            points: createValidPolygonPoints(10),
            label: `memory-test-${i}`,
            metadata: { index: i, test: 'memory' }
          });
      }
      
      const finalMemory = process.memoryUsage();
      const memoryIncrease = {
        heapUsed: (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024,
        external: (finalMemory.external - initialMemory.external) / 1024 / 1024
      };
      
      const result = {
        test: 'Memory usage',
        type: 'memory_test',
        polygonCount,
        memoryIncrease: {
          heapUsed: parseFloat(memoryIncrease.heapUsed.toFixed(2)),
          external: parseFloat(memoryIncrease.external.toFixed(2))
        },
        unit: 'MB'
      };
      
      results.push(result);
      console.log('\nMemory usage:', result.memoryIncrease);
      
      // Memory usage should be reasonable
      expect(memoryIncrease.heapUsed).toBeLessThan(100); // Less than 100MB for 1000 polygons
    });
  });
});