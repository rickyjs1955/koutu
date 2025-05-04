// src/routes/wardrobeRoutes.ts - Updated with validators
import express from 'express';
import { wardrobeController } from '../controllers/wardrobeController';
import { authenticate } from '../middlewares/auth';
import { 
  createWardrobeValidator, 
  addGarmentToWardrobeValidator,
  uuidValidator,
  createValidator
} from '../validators';

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// Create a wardrobe
router.post('/', createWardrobeValidator, wardrobeController.createWardrobe);

// Get all wardrobes
router.get('/', wardrobeController.getWardrobes);

// Get a specific wardrobe with garments
router.get('/:id', createValidator([uuidValidator()], 'params'), wardrobeController.getWardrobe);

// Update wardrobe details
router.put('/:id', 
  createValidator([uuidValidator()], 'params'),
  createWardrobeValidator, 
  wardrobeController.updateWardrobe
);

// Add garment to wardrobe
router.post('/:id/items', 
  createValidator([uuidValidator()], 'params'),
  addGarmentToWardrobeValidator,
  wardrobeController.addGarmentToWardrobe
);

// Remove garment from wardrobe
router.delete('/:id/items/:itemId', 
  createValidator([
    uuidValidator('id'),
    uuidValidator('itemId')
  ], 'params'),
  wardrobeController.removeGarmentFromWardrobe
);

// Delete a wardrobe
router.delete('/:id', 
  createValidator([uuidValidator()], 'params'),
  wardrobeController.deleteWardrobe
);

export { router as wardrobeRoutes };