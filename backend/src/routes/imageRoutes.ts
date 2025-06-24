// /backend/src/routes/imageRoutes.ts - FIXED IMPORTS
import express from 'express';
import { imageController } from '../controllers/imageController';
import { 
  authenticate, 
  requireAuth, 
  authorizeImage,
  rateLimitByUser 
} from '../middlewares/auth';
import { 
  validateQuery, 
  validateParams,
  validateFile,
  validateBody,
  instagramValidationMiddleware
} from '../middlewares/validate';
import { 
  ImageQuerySchema,
  UUIDParamSchema,
  UpdateImageStatusSchema  // ✅ Need to add this to schemas.ts
} from '../validators/schemas';
import { requestIdMiddleware } from '../middlewares/errorHandler';
import { z } from 'zod';
import { UUIDSchema, ImageStatusSchema } from '../../../shared/src/schemas/base/common';

const router = express.Router();

// Apply request ID middleware to all routes
router.use(requestIdMiddleware);

// Apply authentication to all routes
router.use(authenticate);
router.use(requireAuth);

// Apply rate limiting to all image operations
router.use(rateLimitByUser(50, 15 * 60 * 1000)); // 50 requests per 15 minutes

/**
 * @route POST /api/v1/images/upload
 * @desc Upload a new image
 * @access Private
 * @middleware upload, validation, authentication, Instagram validation
 */
router.post('/upload', 
  imageController.uploadMiddleware,
  instagramValidationMiddleware,
  validateFile,
  imageController.uploadImage
);

/**
 * @route GET /api/v1/images
 * @desc Get all images for the authenticated user
 * @access Private
 * @query status, page, limit
 */
router.get('/', 
  validateQuery(ImageQuerySchema),
  imageController.getImages
);

/**
 * @route GET /api/v1/images/stats
 * @desc Get image statistics for the user
 * @access Private
 */
router.get('/stats',
  imageController.getUserStats
);

/**
 * @route GET /api/v1/images/:id
 * @desc Get a specific image by ID
 * @access Private
 * @middleware auth, ownership verification
 */
router.get('/:id', 
  validateParams(UUIDParamSchema),
  authorizeImage,
  imageController.getImage
);

/**
 * @route PUT /api/v1/images/:id/status
 * @desc Update image status
 * @access Private
 * @middleware auth, ownership verification, validation
 */
router.put('/:id/status',
  validateParams(UUIDParamSchema),
  validateBody(UpdateImageStatusSchema),
  authorizeImage,
  imageController.updateImageStatus
);

/**
 * @route POST /api/v1/images/:id/thumbnail
 * @desc Generate thumbnail for an image
 * @access Private
 * @middleware auth, ownership verification
 */
router.post('/:id/thumbnail',
  validateParams(UUIDParamSchema),
  authorizeImage,
  imageController.generateThumbnail
);

/**
 * @route POST /api/v1/images/:id/optimize
 * @desc Optimize image for web delivery
 * @access Private
 * @middleware auth, ownership verification
 */
router.post('/:id/optimize',
  validateParams(UUIDParamSchema),
  authorizeImage,
  imageController.optimizeImage
);

/**
 * @route DELETE /api/v1/images/:id
 * @desc Delete an image
 * @access Private
 * @middleware auth, ownership verification
 */
router.delete('/:id', 
  validateParams(UUIDParamSchema),
  authorizeImage,
  imageController.deleteImage
);

/**
 * @route PUT /api/v1/images/batch/status
 * @desc Batch update image statuses
 * @access Private
 * @middleware auth, validation
 */
router.put('/batch/status',
  validateBody(z.object({
    imageIds: z.array(UUIDSchema).min(1).max(50),
    status: ImageStatusSchema
  })),
  imageController.batchUpdateStatus
);

export { router as imageRoutes };