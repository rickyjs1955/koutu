// /backend/src/routes/garmentRoutes.ts

import express from 'express';
import { garmentController } from '../controllers/garmentController';
import { authenticate } from '../middlewares/auth';
import { validate } from '../middlewares/validate';
import { 
  CreateGarmentSchema, 
  UpdateGarmentMetadataSchema 
} from '../../../shared/src/schemas/garment';

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// Create a garment - using shared schema validation
router.post('/create', 
  validate(CreateGarmentSchema),
  garmentController.createGarment
);

// Get all garments
router.get('/', garmentController.getGarments);

// Get a specific garment
router.get('/:id', garmentController.getGarment);

// Update garment metadata - using shared schema validation
router.put('/:id/metadata', 
  validate(UpdateGarmentMetadataSchema),
  garmentController.updateGarmentMetadata
);

// Delete a garment
router.delete('/:id', garmentController.deleteGarment);

export { router as garmentRoutes };