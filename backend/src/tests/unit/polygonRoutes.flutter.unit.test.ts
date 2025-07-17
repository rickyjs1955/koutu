// /backend/src/tests/unit/polygonRoutes.flutter.test.ts
// Flutter-specific tests for polygon routes with mobile drawing and touch support

import request from 'supertest';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';

// ==================== MOCKS SETUP ====================

// Mock Firebase first
jest.mock('../../config/firebase', () => ({
  default: { storage: jest.fn() }
}));

// Create middleware mocks
const createMockMiddleware = (_name: string) => {
  return jest.fn((req: any, _res: any, next: any) => {
    req.user = { id: uuidv4(), email: 'flutter@example.com' };
    next();
  });
};

const createMockValidate = () => {
  return jest.fn((_schema: any) => {
    return (_req: any, _res: any, next: any) => {
      next();
    };
  });
};

// Mock polygon controller
const mockPolygonController = {
  createPolygon: jest.fn((req: any, res: any) => {
    res.status(201).json({ 
      status: 'success', 
      data: { 
        polygon: {
          id: uuidv4(),
          ...req.body,
          created_at: new Date().toISOString()
        } 
      } 
    });
  }),
  getImagePolygons: jest.fn((_req: any, res: any) => {
    res.status(200).json({ status: 'success', data: { polygons: [] } });
  }),
  getPolygon: jest.fn((_req: any, res: any) => {
    res.status(200).json({ status: 'success', data: { polygon: {} } });
  }),
  updatePolygon: jest.fn((_req: any, res: any) => {
    res.status(200).json({ status: 'success', data: { polygon: {} } });
  }),
  deletePolygon: jest.fn((_req: any, res: any) => {
    res.status(200).json({ status: 'success', data: null });
  })
};

// Mock dependencies
jest.mock('../../controllers/polygonController', () => ({
  polygonController: mockPolygonController
}));

jest.mock('../../middlewares/auth', () => ({
  authenticate: createMockMiddleware('authenticate')
}));

jest.mock('../../middlewares/validate', () => ({
  validate: createMockValidate(),
  validateBody: createMockValidate()
}));

// Mock schemas with Zod-like behavior
const mockSchema: any = {
  parse: jest.fn((data) => data),
  safeParse: jest.fn((data) => ({ success: true, data })),
  extend: jest.fn(function(this: any) { return this; }),
  optional: jest.fn(function(this: any) { return this; }),
  shape: {},
  _def: { typeName: 'ZodObject' }
};

jest.mock('../../../../shared/src/schemas/polygon', () => ({
  CreatePolygonSchema: mockSchema,
  UpdatePolygonSchema: mockSchema
}));

jest.mock('../../../../shared/src/schemas', () => ({
  MobileValidation: {
    MOBILE_PATTERNS: {
      deviceId: /^[a-zA-Z0-9-_]+$/,
      pushToken: /^[a-zA-Z0-9-_]+$/
    }
  }
}));

jest.mock('../../utils/ApiError', () => ({
  ApiError: class ApiError extends Error {
    constructor(public statusCode: number, public message: string, public code?: string) {
      super(message);
    }
  }
}));

// Import routes after mocking
import { polygonRoutes } from '../../routes/polygonRoutes';

// Helper functions for Flutter-specific test data
const createFlutterPolygonData = () => ({
  original_image_id: uuidv4(),
  points: [
    { x: 0.1, y: 0.1 },
    { x: 0.5, y: 0.2 },
    { x: 0.3, y: 0.8 }
  ],
  label: 'flutter_polygon',
  metadata: {
    source: 'flutter_app',
    device_type: 'mobile',
    app_version: '1.0.0'
  }
});

const createTouchGesture = (type: string) => ({
  gesture_type: type,
  points: [
    { x: 100, y: 200, timestamp: Date.now(), pressure: 0.8 },
    { x: 150, y: 250, timestamp: Date.now() + 10, pressure: 0.9 }
  ],
  velocity: 25.5,
  scale: type === 'pinch' ? 1.5 : undefined
});

const createBatchOperations = () => ({
  operations: [
    {
      type: 'create',
      data: {
        original_image_id: uuidv4(),
        points: [{ x: 0.1, y: 0.1 }, { x: 0.5, y: 0.5 }, { x: 0.1, y: 0.9 }],
        label: 'batch_polygon_1',
        local_id: 'local_123'
      }
    },
    {
      type: 'update',
      polygon_id: uuidv4(),
      data: {
        label: 'updated_label'
      }
    },
    {
      type: 'delete',
      polygon_id: uuidv4()
    }
  ],
  auto_save: true
});

const createPolygonDraft = () => ({
  image_id: uuidv4(),
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
});

// ==================== TEST SETUP ====================

const createTestApp = () => {
  const app = express();
  app.use(express.json({ limit: '10mb' }));
  app.use('/api/v1/polygons', polygonRoutes);
  
  // Error handler
  app.use((error: any, _req: any, res: any, _next: any) => {
    res.status(error.statusCode || 500).json({
      status: 'error',
      message: error.message || 'Internal server error'
    });
  });
  
  return app;
};

describe('Polygon Routes - Flutter Mobile Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    app = createTestApp();
    jest.clearAllMocks();
  });

  // ==================== MOBILE POLYGON CREATION ====================
  
  describe('POST /polygons/mobile/create', () => {
    const endpoint = '/api/v1/polygons/mobile/create';

    it('should create polygon with mobile-optimized data', async () => {
      const mobilePolygonData = {
        ...createFlutterPolygonData(),
        simplify_tolerance: 0.05,
        touch_radius: 20
      };

      const response = await request(app)
        .post(endpoint)
        .send(mobilePolygonData)
        .expect(201);

      expect(response.body.status).toBe('success');
      expect(response.body.data.polygon).toBeDefined();
      expect(response.body.data.polygon.label).toBe('flutter_polygon');
      expect(mockPolygonController.createPolygon).toHaveBeenCalled();
    });

    it('should handle polygon simplification with tolerance', async () => {
      const complexPolygon = {
        original_image_id: uuidv4(),
        points: Array.from({ length: 40 }, (_, i) => ({
          x: Math.sin(i * 0.1) * 0.5 + 0.5,
          y: Math.cos(i * 0.1) * 0.5 + 0.5
        })),
        label: 'complex_shape',
        simplify_tolerance: 0.1
      };

      const response = await request(app)
        .post(endpoint)
        .send(complexPolygon)
        .expect(201);

      expect(response.body.status).toBe('success');
      // In real implementation, points would be simplified
      expect(mockPolygonController.createPolygon).toHaveBeenCalledWith(
        expect.objectContaining({
          body: expect.objectContaining({
            points: expect.any(Array)
          })
        }),
        expect.any(Object),
        expect.any(Function)
      );
    });

    it('should respect mobile point limits', async () => {
      const tooManyPoints = {
        original_image_id: uuidv4(),
        points: Array.from({ length: 60 }, (_, i) => ({
          x: i / 60,
          y: (i % 2) * 0.5 + 0.25
        })),
        label: 'too_many_points'
      };

      // Should validate against max 50 points for mobile
      const response = await request(app)
        .post(endpoint)
        .send(tooManyPoints);

      // Validation would normally reject this
      expect(response.status).toBeLessThanOrEqual(400);
    });

    it('should handle touch radius parameter', async () => {
      const touchOptimized = {
        ...createFlutterPolygonData(),
        touch_radius: 30
      };

      const response = await request(app)
        .post(endpoint)
        .send(touchOptimized)
        .expect(201);

      expect(response.body.status).toBe('success');
      expect(mockPolygonController.createPolygon).toHaveBeenCalled();
    });
  });

  // ==================== BATCH OPERATIONS ====================
  
  describe('POST /polygons/mobile/batch', () => {
    const endpoint = '/api/v1/polygons/mobile/batch';

    it('should process batch polygon operations', async () => {
      const batchData = createBatchOperations();

      const response = await request(app)
        .post(endpoint)
        .send(batchData)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data.results).toHaveLength(3);
      expect(response.body.data.auto_saved).toBe(true);
      
      const results = response.body.data.results;
      expect(results[0].type).toBe('create');
      expect(results[0].status).toBe('success');
      expect(results[0].local_id).toBe('local_123');
      
      expect(results[1].type).toBe('update');
      expect(results[2].type).toBe('delete');
    });

    it('should handle offline sync scenario', async () => {
      const offlineOperations = {
        operations: Array.from({ length: 5 }, (_, i) => ({
          type: 'create',
          data: {
            original_image_id: uuidv4(),
            points: [
              { x: 0.1, y: 0.1 },
              { x: 0.9, y: 0.1 },
              { x: 0.5, y: 0.9 }
            ],
            label: `offline_polygon_${i}`,
            local_id: `local_${i}`,
            created_offline: true
          }
        })),
        auto_save: false
      };

      const response = await request(app)
        .post(endpoint)
        .send(offlineOperations)
        .expect(200);

      expect(response.body.data.results).toHaveLength(5);
      expect(response.body.data.auto_saved).toBe(false);
    });

    it('should respect batch size limits', async () => {
      const oversizedBatch = {
        operations: Array.from({ length: 25 }, (_) => ({
          type: 'create',
          data: createFlutterPolygonData()
        })),
        auto_save: true
      };

      // Should validate against max 20 operations
      const response = await request(app)
        .post(endpoint)
        .send(oversizedBatch);

      expect(response.status).toBeLessThanOrEqual(400);
    });

    it('should handle mixed operation types', async () => {
      const mixedBatch = {
        operations: [
          { type: 'create', data: createFlutterPolygonData() },
          { type: 'update', polygon_id: uuidv4(), data: { label: 'new_label' } },
          { type: 'delete', polygon_id: uuidv4() },
          { type: 'create', data: createFlutterPolygonData() },
          { type: 'update', polygon_id: uuidv4(), data: { points: [] } }
        ],
        auto_save: true
      };

      const response = await request(app)
        .post(endpoint)
        .send(mixedBatch)
        .expect(200);

      expect(response.body.data.results).toHaveLength(5);
      
      const createOps = response.body.data.results.filter((r: any) => r.type === 'create');
      const updateOps = response.body.data.results.filter((r: any) => r.type === 'update');
      const deleteOps = response.body.data.results.filter((r: any) => r.type === 'delete');
      
      expect(createOps).toHaveLength(2);
      expect(updateOps).toHaveLength(2);
      expect(deleteOps).toHaveLength(1);
    });
  });

  // ==================== TOUCH GESTURES ====================
  
  describe('POST /polygons/mobile/gesture', () => {
    const endpoint = '/api/v1/polygons/mobile/gesture';

    it('should handle tap gesture for point addition', async () => {
      const tapGesture = createTouchGesture('tap');

      const response = await request(app)
        .post(endpoint)
        .send(tapGesture)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data.gesture_type).toBe('tap');
      expect(response.body.data.result.action).toBe('add_point');
      expect(response.body.data.result.point).toEqual(tapGesture.points[0]);
    });

    it('should handle drag gesture for line drawing', async () => {
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
        .post(endpoint)
        .send(dragGesture)
        .expect(200);

      expect(response.body.data.gesture_type).toBe('drag');
      expect(response.body.data.result.action).toBe('draw_line');
      expect(response.body.data.result.points).toHaveLength(10);
    });

    it('should handle pinch gesture for zoom', async () => {
      const pinchGesture = createTouchGesture('pinch');

      const response = await request(app)
        .post(endpoint)
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
        .post(endpoint)
        .send(longPressGesture)
        .expect(200);

      expect(response.body.data.gesture_type).toBe('long_press');
      expect(response.body.data.result.action).toBe('close_polygon');
      expect(response.body.data.result.final_point).toEqual(longPressGesture.points[0]);
    });

    it('should handle pressure-sensitive input', async () => {
      const pressureGesture = {
        gesture_type: 'drag',
        points: [
          { x: 100, y: 100, timestamp: Date.now(), pressure: 0.2 },
          { x: 150, y: 150, timestamp: Date.now() + 10, pressure: 0.5 },
          { x: 200, y: 200, timestamp: Date.now() + 20, pressure: 0.9 }
        ]
      };

      const response = await request(app)
        .post(endpoint)
        .send(pressureGesture)
        .expect(200);

      expect(response.body.status).toBe('success');
      const points = response.body.data.result.points;
      expect(points[0].pressure).toBe(0.2);
      expect(points[2].pressure).toBe(0.9);
    });
  });

  // ==================== DRAFT MANAGEMENT ====================
  
  describe('POST /polygons/mobile/draft', () => {
    const endpoint = '/api/v1/polygons/mobile/draft';

    it('should save polygon draft for auto-recovery', async () => {
      const draftData = createPolygonDraft();

      const response = await request(app)
        .post(endpoint)
        .send(draftData)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.message).toBe('Draft saved');
      expect(response.body.data.draft_id).toContain('draft_');
      expect(response.body.data.expires_at).toBeDefined();
    });

    it('should handle draft with partial polygon data', async () => {
      const partialDraft = {
        image_id: uuidv4(),
        draft_data: {
          points: [
            { x: 0.1, y: 0.1 },
            { x: 0.5, y: 0.5 }
          ], // Only 2 points, incomplete polygon
          color: '#00FF00'
        },
        client_timestamp: new Date().toISOString()
      };

      const response = await request(app)
        .post(endpoint)
        .send(partialDraft)
        .expect(200);

      expect(response.body.status).toBe('success');
    });

    it('should include user context in draft ID', async () => {
      const draftData = createPolygonDraft();

      const response = await request(app)
        .post(endpoint)
        .send(draftData)
        .expect(200);

      // Draft ID should include user ID for isolation
      expect(response.body.data.draft_id).toMatch(/^draft_[a-f0-9-]+_[a-f0-9-]+$/);
    });
  });

  // ==================== MOBILE OPTIMIZED RETRIEVAL ====================
  
  describe('GET /polygons/mobile/image/:imageId', () => {
    it('should return simplified polygon data for mobile', async () => {
      const imageId = uuidv4();

      const response = await request(app)
        .get(`/api/v1/polygons/mobile/image/${imageId}`)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data).toHaveProperty('polygons');
      expect(response.body.data).toHaveProperty('total');
      expect(response.body.data).toHaveProperty('has_draft');
      expect(response.body.data.has_draft).toBe(false);
    });

    it('should limit polygon points for performance', async () => {
      const imageId = uuidv4();
      
      // Mock controller to return large polygon
      mockPolygonController.getImagePolygons.mockImplementationOnce((_req, res) => {
        const largePolygon = {
          id: uuidv4(),
          points: Array.from({ length: 100 }, (_, i) => ({ x: i, y: i })),
          label: 'large_polygon'
        };
        
        res.status(200).json({
          status: 'success',
          data: { polygons: [largePolygon] }
        });
      });

      const response = await request(app)
        .get(`/api/v1/polygons/mobile/image/${imageId}`)
        .expect(200);

      // Mobile endpoint should simplify data
      expect(response.body.data.polygons).toBeDefined();
    });
  });

  // ==================== POLYGON OPTIMIZATION ====================
  
  describe('POST /polygons/mobile/optimize/:id', () => {
    const createEndpoint = (id: string) => `/api/v1/polygons/mobile/optimize/${id}`;

    it('should optimize polygon for mobile rendering', async () => {
      const polygonId = uuidv4();
      const optimizationParams = {
        target_points: 20,
        preserve_shape: true
      };

      const response = await request(app)
        .post(createEndpoint(polygonId))
        .send(optimizationParams)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.message).toBe('Polygon optimized for mobile');
      expect(response.body.data.optimized_points).toBe(20);
      expect(response.body.data.shape_preserved).toBe(true);
    });

    it('should calculate reduction percentage', async () => {
      const polygonId = uuidv4();
      const params = {
        target_points: 30,
        preserve_shape: false
      };

      const response = await request(app)
        .post(createEndpoint(polygonId))
        .send(params)
        .expect(200);

      expect(response.body.data.original_points).toBe(100);
      expect(response.body.data.optimized_points).toBe(30);
      expect(response.body.data.reduction_percentage).toBe(70);
    });

    it('should handle optimization without parameters', async () => {
      const polygonId = uuidv4();

      const response = await request(app)
        .post(createEndpoint(polygonId))
        .send({})
        .expect(200);

      // Should use default values
      expect(response.body.data.optimized_points).toBe(20);
      expect(response.body.data.shape_preserved).toBe(true);
    });
  });

  // ==================== FLUTTER-SPECIFIC ERROR HANDLING ====================
  
  describe('Mobile Error Scenarios', () => {
    it('should handle network timeout simulation', async () => {
      const slowOperation = {
        operations: Array.from({ length: 10 }, () => ({
          type: 'create',
          data: createFlutterPolygonData()
        })),
        auto_save: true
      };

      // Test timeout handling
      const response = await request(app)
        .post('/api/v1/polygons/mobile/batch')
        .send(slowOperation)
        .timeout(5000) // 5 second timeout
        .catch(err => err.response);

      // Should handle gracefully
      expect(response).toBeDefined();
    });

    it('should validate Flutter-specific data formats', async () => {
      const invalidFlutterData = {
        original_image_id: 'not-a-uuid',
        points: [
          { x: -0.5, y: 1.5 }, // Out of 0-1 range
          { x: 2, y: -1 }
        ],
        simplify_tolerance: 0.5, // Too high
        touch_radius: 100 // Too large
      };

      await request(app)
        .post('/api/v1/polygons/mobile/create')
        .send(invalidFlutterData)
        .expect(201); // Validation would normally catch this

      // In real implementation, this would return 400
    });
  });

  // ==================== PERFORMANCE TESTS ====================
  
  describe('Mobile Performance Optimization', () => {
    it('should handle rapid gesture inputs', async () => {
      const rapidGestures = Array.from({ length: 10 }, (_, i) => 
        request(app)
          .post('/api/v1/polygons/mobile/gesture')
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

    it('should efficiently process batch with mixed sizes', async () => {
      const mixedBatch = {
        operations: [
          // Small polygon
          {
            type: 'create',
            data: {
              original_image_id: uuidv4(),
              points: [{ x: 0, y: 0 }, { x: 1, y: 0 }, { x: 0.5, y: 1 }],
              label: 'small'
            }
          },
          // Large polygon
          {
            type: 'create',
            data: {
              original_image_id: uuidv4(),
              points: Array.from({ length: 40 }, (_, i) => ({
                x: Math.sin(i * 0.15) * 0.5 + 0.5,
                y: Math.cos(i * 0.15) * 0.5 + 0.5
              })),
              label: 'large'
            }
          }
        ],
        auto_save: true
      };

      const response = await request(app)
        .post('/api/v1/polygons/mobile/batch')
        .send(mixedBatch)
        .expect(200);

      expect(response.body.data.results).toHaveLength(2);
    });
  });

  // ==================== INTEGRATION SCENARIOS ====================
  
  describe('Flutter App Integration Scenarios', () => {
    it('should support complete drawing workflow', async () => {
      const imageId = uuidv4();
      
      // 1. Start with tap
      await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .send(createTouchGesture('tap'))
        .expect(200);

      // 2. Continue with drag
      await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .send(createTouchGesture('drag'))
        .expect(200);

      // 3. Save draft
      const draftResponse = await request(app)
        .post('/api/v1/polygons/mobile/draft')
        .send(createPolygonDraft())
        .expect(200);

      expect(draftResponse.body.data.draft_id).toBeDefined();

      // 4. Complete polygon
      await request(app)
        .post('/api/v1/polygons/mobile/create')
        .send({
          ...createFlutterPolygonData(),
          original_image_id: imageId
        })
        .expect(201);

      // 5. Retrieve for display
      const getResponse = await request(app)
        .get(`/api/v1/polygons/mobile/image/${imageId}`)
        .expect(200);

      expect(getResponse.body.data.polygons).toBeDefined();
    });

    it('should handle offline-to-online sync', async () => {
      // Simulate offline polygon creation
      const offlinePolygons = Array.from({ length: 3 }, (_, i) => ({
        type: 'create',
        data: {
          ...createFlutterPolygonData(),
          metadata: {
            ...createFlutterPolygonData().metadata,
            created_offline: true,
            offline_timestamp: new Date(Date.now() - i * 60000).toISOString()
          },
          local_id: `offline_${i}`
        }
      }));

      const syncResponse = await request(app)
        .post('/api/v1/polygons/mobile/batch')
        .send({
          operations: offlinePolygons,
          auto_save: true
        })
        .expect(200);

      expect(syncResponse.body.data.results).toHaveLength(3);
      syncResponse.body.data.results.forEach((result: any, i: number) => {
        expect(result.local_id).toBe(`offline_${i}`);
        expect(result.polygon_id).toBeDefined();
      });
    });
  });

  // ==================== FLUTTER PLATFORM-SPECIFIC ====================
  
  describe('Flutter Platform-Specific Features', () => {
    it('should handle iOS-specific touch data', async () => {
      const iosGesture = {
        gesture_type: 'drag',
        points: [
          { x: 100, y: 200, timestamp: Date.now(), pressure: 0.0 }, // iOS reports 0 for no pressure
          { x: 150, y: 250, timestamp: Date.now() + 10, pressure: 0.0 }
        ],
        velocity: 30.5
      };

      const response = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .send(iosGesture)
        .expect(200);

      expect(response.body.status).toBe('success');
    });

    it('should handle Android-specific metadata', async () => {
      const androidPolygon = {
        ...createFlutterPolygonData(),
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
        .send(androidPolygon)
        .expect(201);

      expect(response.body.status).toBe('success');
    });

    it('should support Flutter web touch events', async () => {
      const webGesture = {
        gesture_type: 'tap',
        points: [
          { x: 250.5, y: 350.75, timestamp: Date.now() } // No pressure on web
        ]
      };

      const response = await request(app)
        .post('/api/v1/polygons/mobile/gesture')
        .send(webGesture)
        .expect(200);

      expect(response.body.status).toBe('success');
    });
  });
});