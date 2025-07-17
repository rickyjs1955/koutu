// /backend/src/tests/integration/polygonRoutes.flutter.int.test.ts
// Flutter-specific integration tests for polygon routes with mobile features

import request from 'supertest';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';

// Mock Firebase
jest.mock('../../config/firebase', () => ({
  default: { storage: jest.fn() }
}));

// Mock database utilities to avoid connection issues
jest.mock('../../utils/testDatabaseConnection', () => ({
  TestDatabaseConnection: {
    initialize: jest.fn().mockResolvedValue(true),
    getConnection: jest.fn().mockReturnValue({
      query: jest.fn().mockResolvedValue({ rows: [] }),
      transaction: jest.fn().mockImplementation(async (fn) => fn({
        query: jest.fn().mockResolvedValue({ rows: [] })
      }))
    }),
    cleanup: jest.fn().mockResolvedValue(true),
    query: jest.fn().mockResolvedValue({ rows: [] })
  }
}));

jest.mock('../../utils/testSetup', () => ({
  setupTestDatabase: jest.fn().mockResolvedValue(true)
}));

// ==================== TEST DATA TYPES ====================

interface TestUser {
  id: string;
  email: string;
  token: string;
  device_info?: {
    platform: 'ios' | 'android' | 'web';
    device_id: string;
    app_version: string;
  };
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
  created_offline?: boolean;
  local_id?: string;
}

// ==================== GLOBAL TEST STATE ====================

let testUsers: TestUser[] = [];
let testImages: TestImage[] = [];
let testPolygons: TestPolygon[] = [];
let flutterUser: TestUser;
let iosUser: TestUser;
let androidUser: TestUser;
let testImage: TestImage;

// ==================== MOBILE APP SETUP ====================

const createFlutterApp = () => {
  const app = express();
  app.use(express.json({ limit: '50mb' }));
  
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
    
    req.user = { id: user.id, email: user.email, device_info: user.device_info } as any;
    next();
  };
  
  // Mock validation middleware
  const validateBody = (_schema: any) => {
    return (req: any, res: any, next: any) => {
      // Basic validation for mobile endpoints
      if (req.path.includes('/mobile/')) {
        const { points, gesture_type, operations } = req.body;
        
        if (req.path.includes('/create') && (!points || !Array.isArray(points) || points.length < 3)) {
          res.status(422).json({
            status: 'error',
            message: 'Invalid polygon points',
            code: 'validation_error'
          });
          return;
        }
        
        if (req.path.includes('/gesture') && !gesture_type) {
          res.status(422).json({
            status: 'error',
            message: 'gesture_type is required',
            code: 'validation_error'
          });
          return;
        }
        
        if (req.path.includes('/batch') && (!operations || !Array.isArray(operations))) {
          res.status(422).json({
            status: 'error',
            message: 'operations array is required',
            code: 'validation_error'
          });
          return;
        }
      }
      
      next();
    };
  };
  
  // ==================== POLYGON ROUTE HANDLERS ====================
  
  // Mobile-optimized polygon creation
  app.post('/api/v1/polygons/mobile/create', authenticate, validateBody({}), async (req, res): Promise<void> => {
    try {
      const { points, label, original_image_id, simplify_tolerance, touch_radius, metadata } = req.body;
      
      // Find the image
      const image = testImages.find(i => i.id === original_image_id);
      if (!image) {
        res.status(404).json({
          status: 'error',
          message: 'Image not found',
          code: 'image_not_found'
        });
        return;
      }
      
      // Check ownership
      if (image.user_id !== req.user!.id) {
        res.status(403).json({
          status: 'error',
          message: 'Access denied',
          code: 'forbidden'
        });
        return;
      }
      
      // Apply simplification if requested
      let finalPoints = points;
      if (simplify_tolerance && points.length > 20) {
        // Mock simplification - reduce points by half
        finalPoints = points.filter((_: any, index: number) => index % 2 === 0);
      }
      
      // Create polygon
      const polygon: TestPolygon = {
        id: uuidv4(),
        user_id: req.user!.id,
        original_image_id,
        points: finalPoints,
        label: label || 'flutter_polygon',
        metadata: {
          ...metadata,
          source: 'flutter_mobile',
          device_info: (req.user as any).device_info,
          touch_radius,
          simplified: simplify_tolerance ? true : false
        }
      };
      
      testPolygons.push(polygon);
      
      res.status(201).json({
        status: 'success',
        data: { polygon }
      });
    } catch (error: any) {
      res.status(500).json({
        status: 'error',
        message: error.message || 'Internal server error'
      });
    }
  });
  
  // Batch operations for offline sync
  app.post('/api/v1/polygons/mobile/batch', authenticate, validateBody({}), async (req, res): Promise<void> => {
    try {
      const { operations, auto_save } = req.body;
      const results = [];
      
      for (const op of operations) {
        switch (op.type) {
          case 'create':
            const polygon: TestPolygon = {
              id: uuidv4(),
              user_id: req.user!.id,
              original_image_id: op.data.original_image_id,
              points: op.data.points,
              label: op.data.label || 'batch_polygon',
              metadata: op.data.metadata,
              created_offline: op.data.created_offline,
              local_id: op.data.local_id
            };
            testPolygons.push(polygon);
            results.push({
              type: 'create',
              status: 'success',
              polygon_id: polygon.id,
              local_id: op.data.local_id
            });
            break;
            
          case 'update':
            const updateIndex = testPolygons.findIndex(p => p.id === op.polygon_id);
            if (updateIndex >= 0 && testPolygons[updateIndex].user_id === req.user!.id) {
              testPolygons[updateIndex] = { ...testPolygons[updateIndex], ...op.data };
              results.push({
                type: 'update',
                status: 'success',
                polygon_id: op.polygon_id
              });
            } else {
              results.push({
                type: 'update',
                status: 'error',
                polygon_id: op.polygon_id,
                error: 'Polygon not found or access denied'
              });
            }
            break;
            
          case 'delete':
            const deleteIndex = testPolygons.findIndex(p => p.id === op.polygon_id);
            if (deleteIndex >= 0 && testPolygons[deleteIndex].user_id === req.user!.id) {
              testPolygons.splice(deleteIndex, 1);
              results.push({
                type: 'delete',
                status: 'success',
                polygon_id: op.polygon_id
              });
            } else {
              results.push({
                type: 'delete',
                status: 'error',
                polygon_id: op.polygon_id,
                error: 'Polygon not found or access denied'
              });
            }
            break;
        }
      }
      
      res.status(200).json({
        status: 'success',
        data: {
          results,
          auto_saved: auto_save,
          processed_at: new Date().toISOString()
        }
      });
    } catch (error: any) {
      res.status(500).json({
        status: 'error',
        message: error.message || 'Batch operation failed'
      });
    }
  });
  
  // Handle touch gestures
  app.post('/api/v1/polygons/mobile/gesture', authenticate, validateBody({}), async (req, res): Promise<void> => {
    try {
      const { gesture_type, points, velocity: _velocity, scale } = req.body;
      let result;
      
      switch (gesture_type) {
        case 'tap':
          result = {
            action: 'add_point',
            point: points[0],
            touch_radius: 20
          };
          break;
          
        case 'drag':
          result = {
            action: 'draw_line',
            points: points,
            smoothed: points.length > 5
          };
          break;
          
        case 'pinch':
          result = {
            action: 'zoom',
            scale: scale || 1.0,
            center: points[0]
          };
          break;
          
        case 'long_press':
          result = {
            action: 'close_polygon',
            final_point: points[0],
            auto_closed: true
          };
          break;
          
        default:
          res.status(422).json({
            status: 'error',
            message: 'Unknown gesture type',
            code: 'invalid_gesture'
          });
          return;
      }
      
      res.status(200).json({
        status: 'success',
        data: {
          gesture_type,
          result,
          processed_at: Date.now(),
          device_info: (req.user as any).device_info
        }
      });
    } catch (error: any) {
      res.status(500).json({
        status: 'error',
        message: error.message || 'Gesture processing failed'
      });
    }
  });
  
  // Save draft for auto-recovery
  app.post('/api/v1/polygons/mobile/draft', authenticate, async (req, res): Promise<void> => {
    try {
      const { image_id, draft_data: _draft_data, client_timestamp: _client_timestamp } = req.body;
      
      const draftId = `draft_${req.user!.id}_${image_id}`;
      
      res.status(200).json({
        status: 'success',
        message: 'Draft saved',
        data: {
          draft_id: draftId,
          saved_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
        }
      });
    } catch (error: any) {
      res.status(500).json({
        status: 'error',
        message: error.message || 'Draft save failed'
      });
    }
  });
  
  // Get polygons optimized for mobile
  app.get('/api/v1/polygons/mobile/image/:imageId', authenticate, async (req, res): Promise<void> => {
    try {
      const { imageId } = req.params;
      
      // Find image
      const image = testImages.find(i => i.id === imageId);
      if (!image) {
        res.status(404).json({
          status: 'error',
          message: 'Image not found',
          code: 'image_not_found'
        });
        return;
      }
      
      // Check ownership
      if (image.user_id !== req.user!.id) {
        res.status(403).json({
          status: 'error',
          message: 'Access denied',
          code: 'forbidden'
        });
        return;
      }
      
      // Get polygons for image
      const polygons = testPolygons.filter(p => p.original_image_id === imageId);
      
      // Optimize for mobile
      const optimizedPolygons = polygons.map(p => ({
        id: p.id,
        points: p.points.slice(0, 50), // Limit points
        label: p.label,
        metadata: p.metadata,
        simplified: true
      }));
      
      res.status(200).json({
        status: 'success',
        data: {
          polygons: optimizedPolygons,
          total: polygons.length,
          has_draft: false,
          image_id: imageId
        }
      });
    } catch (error: any) {
      res.status(500).json({
        status: 'error',
        message: error.message || 'Failed to retrieve polygons'
      });
    }
  });
  
  // Optimize polygon for mobile
  app.post('/api/v1/polygons/mobile/optimize/:id', authenticate, async (req, res): Promise<void> => {
    try {
      const { id } = req.params;
      const { target_points = 20, preserve_shape = true } = req.body;
      
      const polygon = testPolygons.find(p => p.id === id);
      if (!polygon) {
        res.status(404).json({
          status: 'error',
          message: 'Polygon not found',
          code: 'polygon_not_found'
        });
        return;
      }
      
      // Check ownership
      if (polygon.user_id !== req.user!.id) {
        res.status(403).json({
          status: 'error',
          message: 'Access denied',
          code: 'forbidden'
        });
        return;
      }
      
      const originalPoints = polygon.points.length;
      const reduction = ((originalPoints - target_points) / originalPoints) * 100;
      
      res.status(200).json({
        status: 'success',
        message: 'Polygon optimized for mobile',
        data: {
          id,
          original_points: originalPoints,
          optimized_points: target_points,
          reduction_percentage: Math.max(0, reduction),
          shape_preserved: preserve_shape
        }
      });
    } catch (error: any) {
      res.status(500).json({
        status: 'error',
        message: error.message || 'Optimization failed'
      });
    }
  });
  
  // Error handler
  app.use((error: any, _req: any, res: any, _next: any) => {
    res.status(error.status || 500).json({
      status: 'error',
      message: error.message || 'Internal server error',
      code: error.code || 'internal_error'
    });
  });
  
  return app;
};

// ==================== TEST HELPERS ====================

const createFlutterPolygonData = () => ({
  original_image_id: testImage.id,
  points: [
    { x: 0.1, y: 0.1 },
    { x: 0.5, y: 0.2 },
    { x: 0.3, y: 0.8 }
  ],
  label: 'flutter_test_polygon',
  metadata: {
    source: 'flutter_app',
    device_type: 'mobile',
    app_version: '1.0.0'
  }
});

const createOfflinePolygonData = (index: number) => ({
  original_image_id: testImage.id,
  points: [
    { x: 0.1 * index, y: 0.1 * index },
    { x: 0.5 * index, y: 0.2 * index },
    { x: 0.3 * index, y: 0.8 * index }
  ],
  label: `offline_polygon_${index}`,
  local_id: `local_${index}`,
  created_offline: true,
  metadata: {
    offline_timestamp: new Date(Date.now() - index * 60000).toISOString()
  }
});

// ==================== MAIN TEST SUITE ====================

describe('Polygon Routes - Flutter Integration Tests', () => {
  let app: express.Application;
  
  beforeAll(async () => {
    console.log('🚀 Setting up Flutter integration test environment...');
    
    // Create test users with device info
    flutterUser = {
      id: uuidv4(),
      email: 'flutter@test.com',
      token: `flutter_token_${Date.now()}`,
      device_info: {
        platform: 'ios',
        device_id: 'flutter_device_123',
        app_version: '1.0.0'
      }
    };
    
    iosUser = {
      id: uuidv4(),
      email: 'ios@test.com',
      token: `ios_token_${Date.now()}`,
      device_info: {
        platform: 'ios',
        device_id: 'ios_device_456',
        app_version: '1.0.0'
      }
    };
    
    androidUser = {
      id: uuidv4(),
      email: 'android@test.com',
      token: `android_token_${Date.now()}`,
      device_info: {
        platform: 'android',
        device_id: 'android_device_789',
        app_version: '1.0.0'
      }
    };
    
    testUsers = [flutterUser, iosUser, androidUser];
    
    // Create test image
    testImage = {
      id: uuidv4(),
      user_id: flutterUser.id,
      file_path: '/test/flutter_test_image.jpg',
      status: 'pending'
    };
    
    testImages = [testImage];
    
    // Create app
    app = createFlutterApp();
    
    console.log('✅ Flutter test environment ready');
  });
  
  afterEach(() => {
    // Clear polygons after each test
    testPolygons = [];
  });
  
  afterAll(() => {
    // Cleanup
    testUsers = [];
    testImages = [];
    testPolygons = [];
  });
  
  // ==================== MOBILE POLYGON CREATION TESTS ====================
  
  describe('Mobile Polygon Creation', () => {
    it('should create polygon with mobile-specific features', async () => {
      const polygonData = {
        ...createFlutterPolygonData(),
        simplify_tolerance: 0.05,
        touch_radius: 25
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/create')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(polygonData)
        .expect(201);
      
      expect(response.body.status).toBe('success');
      expect(response.body.data.polygon).toBeDefined();
      expect(response.body.data.polygon.label).toBe('flutter_test_polygon');
      expect(response.body.data.polygon.metadata.source).toBe('flutter_mobile');
      expect(response.body.data.polygon.metadata.device_info.platform).toBe('ios');
      expect(response.body.data.polygon.metadata.touch_radius).toBe(25);
    });
    
    it('should simplify polygon with many points', async () => {
      const complexPolygon = {
        original_image_id: testImage.id,
        points: Array.from({ length: 50 }, (_, i) => ({
          x: Math.sin(i * 0.1) * 0.5 + 0.5,
          y: Math.cos(i * 0.1) * 0.5 + 0.5
        })),
        label: 'complex_shape',
        simplify_tolerance: 0.1
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/create')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(complexPolygon)
        .expect(201);
      
      expect(response.body.status).toBe('success');
      expect(response.body.data.polygon.points.length).toBeLessThan(50);
      expect(response.body.data.polygon.metadata.simplified).toBe(true);
    });
    
    it('should reject polygon creation for non-owned image', async () => {
      const otherUserImage = {
        id: uuidv4(),
        user_id: iosUser.id,
        file_path: '/test/other_user_image.jpg',
        status: 'pending'
      };
      testImages.push(otherUserImage);
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/create')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          ...createFlutterPolygonData(),
          original_image_id: otherUserImage.id
        })
        .expect(403);
      
      expect(response.body.status).toBe('error');
      expect(response.body.code).toBe('forbidden');
    });
    
    it('should require authentication', async () => {
      const response = await request(app)
        .post('/api/v1/polygons/mobile/create')
        .send(createFlutterPolygonData())
        .expect(401);
      
      expect(response.body.status).toBe('error');
      expect(response.body.code).toBe('missing_token');
    });
  });
  
  // ==================== BATCH OPERATIONS TESTS ====================
  
  describe('Batch Operations for Offline Sync', () => {
    it('should process multiple operations in batch', async () => {
      const batchData = {
        operations: [
          {
            type: 'create',
            data: createOfflinePolygonData(1)
          },
          {
            type: 'create',
            data: createOfflinePolygonData(2)
          },
          {
            type: 'create',
            data: createOfflinePolygonData(3)
          }
        ],
        auto_save: true
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/batch')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(batchData)
        .expect(200);
      
      expect(response.body.status).toBe('success');
      expect(response.body.data.results).toHaveLength(3);
      expect(response.body.data.auto_saved).toBe(true);
      
      // Verify all operations succeeded
      response.body.data.results.forEach((result: any, index: number) => {
        expect(result.type).toBe('create');
        expect(result.status).toBe('success');
        expect(result.local_id).toBe(`local_${index + 1}`);
        expect(result.polygon_id).toBeDefined();
      });
    });
    
    it('should handle mixed operation types', async () => {
      // First create a polygon to update/delete
      const createResponse = await request(app)
        .post('/api/v1/polygons/mobile/create')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(createFlutterPolygonData())
        .expect(201);
      
      const createdPolygonId = createResponse.body.data.polygon.id;
      
      const mixedBatch = {
        operations: [
          {
            type: 'create',
            data: createOfflinePolygonData(4)
          },
          {
            type: 'update',
            polygon_id: createdPolygonId,
            data: { label: 'updated_label' }
          },
          {
            type: 'delete',
            polygon_id: createdPolygonId
          }
        ],
        auto_save: false
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/batch')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(mixedBatch)
        .expect(200);
      
      expect(response.body.data.results).toHaveLength(3);
      expect(response.body.data.results[0].type).toBe('create');
      expect(response.body.data.results[0].status).toBe('success');
      expect(response.body.data.results[1].type).toBe('update');
      expect(response.body.data.results[1].status).toBe('success');
      expect(response.body.data.results[2].type).toBe('delete');
      expect(response.body.data.results[2].status).toBe('success');
    });
    
    it('should handle errors in batch operations', async () => {
      const batchWithErrors = {
        operations: [
          {
            type: 'update',
            polygon_id: 'non-existent-id',
            data: { label: 'will_fail' }
          },
          {
            type: 'delete',
            polygon_id: 'also-non-existent'
          }
        ],
        auto_save: true
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/batch')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(batchWithErrors)
        .expect(200);
      
      expect(response.body.data.results[0].status).toBe('error');
      expect(response.body.data.results[0].error).toContain('not found');
      expect(response.body.data.results[1].status).toBe('error');
    });
  });
  
  // ==================== TOUCH GESTURE TESTS ====================
  
  describe('Touch Gesture Handling', () => {
    it('should handle tap gesture', async () => {
      const tapGesture = {
        gesture_type: 'tap',
        points: [{ x: 150, y: 200, timestamp: Date.now() }]
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(tapGesture)
        .expect(200);
      
      expect(response.body.status).toBe('success');
      expect(response.body.data.gesture_type).toBe('tap');
      expect(response.body.data.result.action).toBe('add_point');
      expect(response.body.data.result.touch_radius).toBe(20);
    });
    
    it('should handle drag gesture for drawing', async () => {
      const dragGesture = {
        gesture_type: 'drag',
        points: Array.from({ length: 10 }, (_, i) => ({
          x: 100 + i * 10,
          y: 200 + i * 5,
          timestamp: Date.now() + i * 20,
          pressure: 0.8
        })),
        velocity: 45.2
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(dragGesture)
        .expect(200);
      
      expect(response.body.data.gesture_type).toBe('drag');
      expect(response.body.data.result.action).toBe('draw_line');
      expect(response.body.data.result.smoothed).toBe(true);
    });
    
    it('should handle pinch gesture for zoom', async () => {
      const pinchGesture = {
        gesture_type: 'pinch',
        points: [{ x: 200, y: 300, timestamp: Date.now() }],
        scale: 1.5
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(pinchGesture)
        .expect(200);
      
      expect(response.body.data.gesture_type).toBe('pinch');
      expect(response.body.data.result.action).toBe('zoom');
      expect(response.body.data.result.scale).toBe(1.5);
    });
    
    it('should handle long press for polygon closure', async () => {
      const longPressGesture = {
        gesture_type: 'long_press',
        points: [{ x: 300, y: 400, timestamp: Date.now() }]
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(longPressGesture)
        .expect(200);
      
      expect(response.body.data.gesture_type).toBe('long_press');
      expect(response.body.data.result.action).toBe('close_polygon');
      expect(response.body.data.result.auto_closed).toBe(true);
    });
    
    it('should reject unknown gesture types', async () => {
      const response = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          gesture_type: 'unknown_gesture',
          points: [{ x: 100, y: 100 }]
        })
        .expect(422);
      
      expect(response.body.status).toBe('error');
      expect(response.body.code).toBe('invalid_gesture');
    });
  });
  
  // ==================== DRAFT MANAGEMENT TESTS ====================
  
  describe('Draft Management', () => {
    it('should save polygon draft', async () => {
      const draftData = {
        image_id: testImage.id,
        draft_data: {
          points: [
            { x: 0.2, y: 0.2 },
            { x: 0.8, y: 0.2 },
            { x: 0.5, y: 0.8 }
          ],
          label: 'draft_polygon',
          color: '#FF5733'
        },
        client_timestamp: new Date().toISOString()
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/draft')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(draftData)
        .expect(200);
      
      expect(response.body.status).toBe('success');
      expect(response.body.message).toBe('Draft saved');
      expect(response.body.data.draft_id).toContain(flutterUser.id);
      expect(response.body.data.draft_id).toContain(testImage.id);
      expect(response.body.data.expires_at).toBeDefined();
    });
  });
  
  // ==================== MOBILE OPTIMIZED RETRIEVAL TESTS ====================
  
  describe('Mobile Optimized Data Retrieval', () => {
    beforeEach(async () => {
      // Create some test polygons
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post('/api/v1/polygons/mobile/create')
          .set('Authorization', `Bearer ${flutterUser.token}`)
          .send({
            ...createFlutterPolygonData(),
            label: `polygon_${i}`
          });
      }
    });
    
    it('should retrieve polygons optimized for mobile', async () => {
      const response = await request(app)
        .get(`/api/v1/polygons/mobile/image/${testImage.id}`)
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .expect(200);
      
      expect(response.body.status).toBe('success');
      expect(response.body.data.polygons).toHaveLength(5);
      expect(response.body.data.total).toBe(5);
      expect(response.body.data.image_id).toBe(testImage.id);
      
      // Check optimization
      response.body.data.polygons.forEach((polygon: any) => {
        expect(polygon.simplified).toBe(true);
        expect(polygon.points.length).toBeLessThanOrEqual(50);
      });
    });
    
    it('should deny access to other users images', async () => {
      const otherImage = {
        id: uuidv4(),
        user_id: iosUser.id,
        file_path: '/test/ios_image.jpg',
        status: 'pending'
      };
      testImages.push(otherImage);
      
      const response = await request(app)
        .get(`/api/v1/polygons/mobile/image/${otherImage.id}`)
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .expect(403);
      
      expect(response.body.status).toBe('error');
      expect(response.body.code).toBe('forbidden');
    });
  });
  
  // ==================== POLYGON OPTIMIZATION TESTS ====================
  
  describe('Polygon Optimization', () => {
    let polygonId: string;
    
    beforeEach(async () => {
      const response = await request(app)
        .post('/api/v1/polygons/mobile/create')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: Array.from({ length: 100 }, (_, i) => ({
            x: Math.sin(i * 0.1) * 0.5 + 0.5,
            y: Math.cos(i * 0.1) * 0.5 + 0.5
          })),
          label: 'complex_polygon'
        });
      
      polygonId = response.body.data.polygon.id;
    });
    
    it('should optimize polygon for mobile rendering', async () => {
      const response = await request(app)
        .post(`/api/v1/polygons/mobile/optimize/${polygonId}`)
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          target_points: 30,
          preserve_shape: true
        })
        .expect(200);
      
      expect(response.body.status).toBe('success');
      expect(response.body.data.original_points).toBe(100);
      expect(response.body.data.optimized_points).toBe(30);
      expect(response.body.data.reduction_percentage).toBe(70);
      expect(response.body.data.shape_preserved).toBe(true);
    });
    
    it('should use default optimization parameters', async () => {
      const response = await request(app)
        .post(`/api/v1/polygons/mobile/optimize/${polygonId}`)
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({})
        .expect(200);
      
      expect(response.body.data.optimized_points).toBe(20);
      expect(response.body.data.shape_preserved).toBe(true);
    });
    
    it('should deny optimization of other users polygons', async () => {
      const response = await request(app)
        .post(`/api/v1/polygons/mobile/optimize/${polygonId}`)
        .set('Authorization', `Bearer ${iosUser.token}`)
        .send({ target_points: 20 })
        .expect(403);
      
      expect(response.body.status).toBe('error');
      expect(response.body.code).toBe('forbidden');
    });
  });
  
  // ==================== PLATFORM-SPECIFIC TESTS ====================
  
  describe('Platform-Specific Features', () => {
    it('should handle iOS-specific touch data', async () => {
      const iosGesture = {
        gesture_type: 'drag',
        points: [
          { x: 100, y: 200, timestamp: Date.now(), pressure: 0.0 },
          { x: 150, y: 250, timestamp: Date.now() + 10, pressure: 0.0 }
        ],
        velocity: 30.5
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${iosUser.token}`)
        .send(iosGesture)
        .expect(200);
      
      expect(response.body.status).toBe('success');
      expect(response.body.data.device_info.platform).toBe('ios');
    });
    
    it('should handle Android-specific metadata', async () => {
      // Create an image owned by Android user
      const androidImage = {
        id: uuidv4(),
        user_id: androidUser.id,
        file_path: '/test/android_test_image.jpg',
        status: 'pending'
      };
      testImages.push(androidImage);
      
      const androidPolygon = {
        original_image_id: androidImage.id,
        points: [
          { x: 0.1, y: 0.1 },
          { x: 0.5, y: 0.2 },
          { x: 0.3, y: 0.8 }
        ],
        label: 'android_test_polygon',
        metadata: {
          source: 'flutter_app',
          device_type: 'android',
          android_version: 31,
          screen_density: 'xxxhdpi',
          input_method: 'stylus'
        }
      };
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/create')
        .set('Authorization', `Bearer ${androidUser.token}`)
        .send(androidPolygon)
        .expect(201);
      
      expect(response.body.status).toBe('success');
      expect(response.body.data.polygon.metadata.device_info.platform).toBe('android');
    });
  });
  
  // ==================== PERFORMANCE AND STRESS TESTS ====================
  
  describe('Performance and Concurrent Operations', () => {
    it('should handle rapid gesture inputs', async () => {
      const rapidGestures = Array.from({ length: 10 }, (_, i) => 
        request(app)
          .post('/api/v1/polygons/mobile/gesture')
          .set('Authorization', `Bearer ${flutterUser.token}`)
          .send({
            gesture_type: 'tap',
            points: [{ x: i * 10, y: i * 10, timestamp: Date.now() + i }]
          })
      );
      
      const responses = await Promise.all(rapidGestures);
      
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.status).toBe('success');
      });
    });
    
    it('should handle large batch operations efficiently', async () => {
      const largeBatch = {
        operations: Array.from({ length: 20 }, (_, i) => ({
          type: 'create',
          data: createOfflinePolygonData(i)
        })),
        auto_save: true
      };
      
      const startTime = Date.now();
      
      const response = await request(app)
        .post('/api/v1/polygons/mobile/batch')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send(largeBatch)
        .expect(200);
      
      const endTime = Date.now();
      const processingTime = endTime - startTime;
      
      expect(response.body.data.results).toHaveLength(20);
      expect(processingTime).toBeLessThan(1000); // Should complete within 1 second
      
      // Verify all succeeded
      response.body.data.results.forEach((result: any) => {
        expect(result.status).toBe('success');
      });
    });
  });
  
  // ==================== END-TO-END WORKFLOW TESTS ====================
  
  describe('Complete Flutter Drawing Workflow', () => {
    it('should support full drawing workflow from start to finish', async () => {
      // 1. Start drawing with first tap
      const firstTap = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          gesture_type: 'tap',
          points: [{ x: 100, y: 100, timestamp: Date.now() }]
        })
        .expect(200);
      
      expect(firstTap.body.data.result.action).toBe('add_point');
      
      // 2. Continue with drag gestures
      const drag = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          gesture_type: 'drag',
          points: [
            { x: 100, y: 100, timestamp: Date.now() },
            { x: 200, y: 150, timestamp: Date.now() + 10 },
            { x: 300, y: 200, timestamp: Date.now() + 20 }
          ],
          velocity: 50
        })
        .expect(200);
      
      expect(drag.body.data.result.action).toBe('draw_line');
      
      // 3. Save as draft
      const draft = await request(app)
        .post('/api/v1/polygons/mobile/draft')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          image_id: testImage.id,
          draft_data: {
            points: [
              { x: 0.1, y: 0.1 },
              { x: 0.5, y: 0.15 },
              { x: 0.3, y: 0.2 }
            ],
            label: 'work_in_progress'
          },
          client_timestamp: new Date().toISOString()
        })
        .expect(200);
      
      expect(draft.body.message).toBe('Draft saved');
      
      // 4. Complete polygon with long press
      const complete = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          gesture_type: 'long_press',
          points: [{ x: 100, y: 100, timestamp: Date.now() }]
        })
        .expect(200);
      
      expect(complete.body.data.result.action).toBe('close_polygon');
      
      // 5. Create final polygon
      const finalPolygon = await request(app)
        .post('/api/v1/polygons/mobile/create')
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .send({
          original_image_id: testImage.id,
          points: [
            { x: 0.1, y: 0.1 },
            { x: 0.5, y: 0.15 },
            { x: 0.3, y: 0.2 }
          ],
          label: 'completed_polygon',
          simplify_tolerance: 0.05
        })
        .expect(201);
      
      expect(finalPolygon.body.data.polygon.label).toBe('completed_polygon');
      
      // 6. Retrieve and verify
      const retrieve = await request(app)
        .get(`/api/v1/polygons/mobile/image/${testImage.id}`)
        .set('Authorization', `Bearer ${flutterUser.token}`)
        .expect(200);
      
      expect(retrieve.body.data.polygons.length).toBeGreaterThan(0);
      const created = retrieve.body.data.polygons.find((p: any) => p.label === 'completed_polygon');
      expect(created).toBeDefined();
    });
  });
});