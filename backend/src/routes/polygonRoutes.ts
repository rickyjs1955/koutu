// /backend/src/routes/polygonRoutes.ts
import express from 'express';
import { polygonController } from '../controllers/polygonController';
import { authenticate } from '../middlewares/auth';
import { validate } from '../middlewares/validate';
import { 
  CreatePolygonSchema, 
  UpdatePolygonSchema 
} from '../../../shared/src/schemas/polygon';

const router = express.Router();

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

export { router as polygonRoutes };