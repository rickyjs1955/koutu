// /backend/src/routes/wardrobeRoutes.ts - Updated with current validation system
import express from 'express';
import { wardrobeController } from '../controllers/wardrobeController';
import { authenticate } from '../middlewares/auth';
import { validateBody, validateParams } from '../middlewares/validate';
import { UUIDParamSchema } from '../validators/schemas';
import { z } from 'zod';

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// Validation schemas
const CreateWardrobeSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name cannot exceed 100 characters'),
  description: z.string().max(1000, 'Description cannot exceed 1000 characters').optional()
});

const UpdateWardrobeSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name cannot exceed 100 characters').optional(),
  description: z.string().max(1000, 'Description cannot exceed 1000 characters').optional()
});

const AddGarmentToWardrobeSchema = z.object({
  garmentId: z.string().uuid('Invalid garment ID format'),
  position: z.number().int().min(0, 'Position must be a non-negative integer').optional()
});

const ReorderGarmentsSchema = z.object({
  garmentPositions: z.array(z.object({
    garmentId: z.string().uuid('Invalid garment ID format'),
    position: z.number().int().min(0, 'Position must be non-negative')
  })).min(1).max(100)
});

// Offline sync schemas
const SyncSchema = z.object({
  lastSyncTimestamp: z.string().datetime(),
  clientVersion: z.number().int().min(1).optional()
});

const BatchOperationSchema = z.object({
  operations: z.array(z.object({
    type: z.enum(['create', 'update', 'delete']),
    data: z.record(z.any()),
    clientId: z.string()
  })).min(1).max(50)
});

// Wardrobe routes

/**
 * @route POST /api/v1/wardrobes
 * @desc Create a new wardrobe
 * @access Private
 */
router.post('/', 
  validateBody(CreateWardrobeSchema), 
  wardrobeController.createWardrobe
);

/**
 * @route GET /api/v1/wardrobes
 * @desc Get all wardrobes for the authenticated user
 * @access Private
 */
router.get('/', 
  wardrobeController.getWardrobes
);

/**
 * @route GET /api/v1/wardrobes/:id
 * @desc Get a specific wardrobe with garments
 * @access Private
 */
router.get('/:id', 
  validateParams(UUIDParamSchema),
  wardrobeController.getWardrobe
);

/**
 * @route PUT /api/v1/wardrobes/:id
 * @desc Update wardrobe details
 * @access Private
 */
router.put('/:id', 
  validateParams(UUIDParamSchema),
  validateBody(UpdateWardrobeSchema),
  wardrobeController.updateWardrobe
);

/**
 * @route POST /api/v1/wardrobes/:id/items
 * @desc Add garment to wardrobe
 * @access Private
 */
router.post('/:id/items', 
  validateParams(UUIDParamSchema),
  validateBody(AddGarmentToWardrobeSchema),
  wardrobeController.addGarmentToWardrobe
);

/**
 * @route DELETE /api/v1/wardrobes/:id/items/:itemId
 * @desc Remove garment from wardrobe
 * @access Private
 */
router.delete('/:id/items/:itemId', 
  validateParams(z.object({
    id: z.string().uuid('Invalid wardrobe ID format'),
    itemId: z.string().uuid('Invalid item ID format')
  })),
  wardrobeController.removeGarmentFromWardrobe
);

/**
 * @route DELETE /api/v1/wardrobes/:id
 * @desc Delete a wardrobe
 * @access Private
 */
router.delete('/:id', 
  validateParams(UUIDParamSchema),
  wardrobeController.deleteWardrobe
);

/**
 * @route PUT /api/v1/wardrobes/:id/items/reorder
 * @desc Reorder garments in wardrobe
 * @access Private
 */
router.put('/:id/items/reorder',
  validateParams(UUIDParamSchema),
  validateBody(ReorderGarmentsSchema),
  wardrobeController.reorderGarments
);

/**
 * @route GET /api/v1/wardrobes/:id/stats
 * @desc Get wardrobe statistics
 * @access Private
 */
router.get('/:id/stats',
  validateParams(UUIDParamSchema),
  wardrobeController.getWardrobeStats
);

// Offline sync routes

/**
 * @route POST /api/v1/wardrobes/sync
 * @desc Sync wardrobes - get changes since last sync
 * @access Private
 * @body lastSyncTimestamp - ISO date string of last sync
 * @body clientVersion - Client version number (optional)
 */
router.post('/sync',
  validateBody(SyncSchema),
  wardrobeController.syncWardrobes
);

/**
 * @route POST /api/v1/wardrobes/batch
 * @desc Batch operations for offline sync
 * @access Private
 * @body operations - Array of operations to perform
 */
router.post('/batch',
  validateBody(BatchOperationSchema),
  wardrobeController.batchOperations
);

export { router as wardrobeRoutes };