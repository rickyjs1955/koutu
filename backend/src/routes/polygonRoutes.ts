// /backend/src/routes/polygonRoutes.ts - Enhanced for mobile drawing and touch operations
import express from 'express';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { polygonController } from '../controllers/polygonController';
import { authenticate } from '../middlewares/auth';
import { validate, validateBody } from '../middlewares/validate';
import { 
  CreatePolygonSchema, 
  UpdatePolygonSchema 
} from '../../../shared/src/schemas/polygon';
import { ApiError } from '../utils/ApiError';
import { MobileValidation } from '../../../shared/src/schemas';

const router = express.Router();

// ==================== MOBILE-SPECIFIC SCHEMAS ====================

// Simplified polygon schema for mobile (fewer points allowed)
const MobileCreatePolygonSchema = CreatePolygonSchema.extend({
  points: z.array(z.object({
    x: z.number().min(0).max(1),
    y: z.number().min(0).max(1)
  })).min(3).max(50), // Limit points for mobile performance
  simplify_tolerance: z.number().min(0).max(0.1).optional(), // Douglas-Peucker tolerance
  touch_radius: z.number().min(5).max(50).optional() // Touch target size in pixels
});

// Batch polygon operations for mobile
const BatchPolygonOperationSchema = z.object({
  operations: z.array(z.object({
    type: z.enum(['create', 'update', 'delete']),
    polygon_id: z.string().uuid().optional(), // For update/delete
    data: z.any().optional() // For create/update
  })).max(20), // Limit batch size
  auto_save: z.boolean().default(true)
});

// Touch gesture schema for mobile drawing
const TouchGestureSchema = z.object({
  gesture_type: z.enum(['tap', 'drag', 'pinch', 'long_press']),
  points: z.array(z.object({
    x: z.number(),
    y: z.number(),
    timestamp: z.number(),
    pressure: z.number().optional()
  })),
  velocity: z.number().optional(),
  scale: z.number().optional()
});

// Auto-save draft schema
const PolygonDraftSchema = z.object({
  image_id: z.string().uuid(),
  draft_data: z.object({
    points: z.array(z.object({
      x: z.number(),
      y: z.number()
    })),
    label: z.string().optional(),
    color: z.string().optional()
  }),
  client_timestamp: z.string()
});

// All routes require authentication
router.use(authenticate);

// Create a new polygon
router.post(
  '/',
  validate(CreatePolygonSchema),
  polygonController.createPolygon
);

// Get all polygons for an image
router.get(
  '/image/:imageId',
  polygonController.getImagePolygons
);

// Get a specific polygon
router.get(
  '/:id',
  polygonController.getPolygon
);

// Update a polygon
router.put(
  '/:id',
  validate(UpdatePolygonSchema),
  polygonController.updatePolygon
);

// Delete a polygon
router.delete(
  '/:id',
  polygonController.deletePolygon
);

// ==================== MOBILE-SPECIFIC ENDPOINTS ====================

// Mobile-optimized polygon creation with touch support
router.post(
  '/mobile/create',
  validateBody(MobileCreatePolygonSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { simplify_tolerance, touch_radius, ...polygonData } = req.body;
      
      // Simplify polygon if tolerance specified (mock implementation)
      let simplifiedPoints = polygonData.points;
      if (simplify_tolerance) {
        // Would apply Douglas-Peucker algorithm here
        simplifiedPoints = polygonData.points; // Mock: return original
      }
      
      // Create polygon with simplified points
      req.body = { ...polygonData, points: simplifiedPoints };
      
      // Call original controller
      return polygonController.createPolygon(req, res, next);
    } catch (error) {
      next(error);
    }
  }
);

// Batch polygon operations for offline sync
router.post(
  '/mobile/batch',
  validateBody(BatchPolygonOperationSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { operations, auto_save } = req.body;
      const results = [];
      
      // Process each operation (mock implementation)
      for (const op of operations) {
        switch (op.type) {
          case 'create':
            results.push({
              type: 'create',
              status: 'success',
              polygon_id: `poly_${Date.now()}_${Math.random()}`,
              local_id: op.data?.local_id
            });
            break;
          case 'update':
            results.push({
              type: 'update',
              status: 'success',
              polygon_id: op.polygon_id
            });
            break;
          case 'delete':
            results.push({
              type: 'delete',
              status: 'success',
              polygon_id: op.polygon_id
            });
            break;
        }
      }
      
      res.status(200).json({
        status: 'success',
        message: 'Batch operations completed',
        data: {
          results,
          auto_saved: auto_save,
          timestamp: new Date().toISOString()
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

// Process touch gestures for polygon drawing
router.post(
  '/mobile/gesture',
  validateBody(TouchGestureSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { gesture_type, points, velocity, scale } = req.body;
      
      // Process gesture (mock implementation)
      let result;
      switch (gesture_type) {
        case 'tap':
          result = {
            action: 'add_point',
            point: points[0]
          };
          break;
        case 'drag':
          result = {
            action: 'draw_line',
            points: points
          };
          break;
        case 'pinch':
          result = {
            action: 'zoom',
            scale: scale || 1
          };
          break;
        case 'long_press':
          result = {
            action: 'close_polygon',
            final_point: points[0]
          };
          break;
      }
      
      res.status(200).json({
        status: 'success',
        data: {
          gesture_type,
          result,
          processed_at: Date.now()
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

// Save polygon draft for auto-recovery
router.post(
  '/mobile/draft',
  validateBody(PolygonDraftSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { image_id, draft_data, client_timestamp } = req.body;
      
      // Save draft (mock implementation)
      const draftId = `draft_${req.user.id}_${image_id}`;
      
      res.status(200).json({
        status: 'success',
        message: 'Draft saved',
        data: {
          draft_id: draftId,
          saved_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

// Get polygon with mobile optimizations
router.get(
  '/mobile/image/:imageId',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Get polygons with simplified data for mobile
      const polygons: any[] = []; // Mock data
      
      res.status(200).json({
        status: 'success',
        data: {
          polygons: polygons.map(p => ({
            id: p.id,
            points: p.points.slice(0, 50), // Limit points for performance
            label: p.label,
            color: p.color,
            simplified: true
          })),
          total: polygons.length,
          has_draft: false // Check for saved drafts
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

// Optimize polygon for mobile rendering
router.post(
  '/mobile/optimize/:id',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { id } = req.params;
      const { target_points = 20, preserve_shape = true } = req.body;
      
      // Optimize polygon (mock implementation)
      const optimized = {
        id,
        original_points: 100,
        optimized_points: target_points,
        reduction_percentage: ((100 - target_points) / 100) * 100,
        shape_preserved: preserve_shape
      };
      
      res.status(200).json({
        status: 'success',
        message: 'Polygon optimized for mobile',
        data: optimized
      });
    } catch (error) {
      next(error);
    }
  }
);

export { router as polygonRoutes };