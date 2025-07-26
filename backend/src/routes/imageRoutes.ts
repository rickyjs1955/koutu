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

/** NEWLY ADDED ROUTES
 * @route GET /api/v1/images/mobile/thumbnails
 * @desc Get thumbnails optimized for mobile display
 * @access Private
 * @query page, limit, size
 */
router.get('/mobile/thumbnails',
  requireAuth,
  validateQuery(z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(50).default(20),
    size: z.enum(['small', 'medium', 'large']).default('medium')
  })),
  imageController.getMobileThumbnails
);

/** NEWLY ADDED ROUTES
 * @route GET /api/v1/images/:id/mobile
 * @desc Get mobile-optimized image with automatic format selection
 * @access Private
 * @middleware auth, ownership verification
 */
router.get('/:id/mobile',
  validateParams(UUIDParamSchema),
  authorizeImage,
  imageController.getMobileOptimizedImage
);

/** NEWLY ADDED ROUTES
 * @route POST /api/v1/images/batch/thumbnails
 * @desc Generate thumbnails for multiple images (Flutter batch operation)
 * @access Private
 * @middleware auth, validation
 */
router.post('/batch/thumbnails',
  validateBody(z.object({
    imageIds: z.array(UUIDSchema).min(1).max(20),
    sizes: z.array(z.enum(['small', 'medium', 'large'])).default(['medium'])
  })),
  imageController.batchGenerateThumbnails
);

/** NEWLY ADDED ROUTES
 * @route GET /api/v1/images/sync
 * @desc Get images with sync metadata for Flutter offline support
 * @access Private
 * @query lastSync, includeDeleted
 */
router.get('/sync',
  validateQuery(z.object({
    lastSync: z.string().datetime().optional(),
    includeDeleted: z.coerce.boolean().default(false),
    limit: z.coerce.number().int().min(1).max(100).default(50)
  })),
  imageController.getSyncData
);

/** NEWLY ADDED ROUTES
 * @route POST /api/v1/images/flutter/upload
 * @desc Flutter-optimized upload with progress support
 * @access Private
 * @middleware upload, validation, authentication
 */
router.post('/flutter/upload',
  imageController.uploadMiddleware,
  validateFile,
  imageController.flutterUploadImage
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

/** NEWLY ADDED ROUTES
 * @route POST /api/v1/images/batch/sync
 * @desc Batch sync operation for Flutter offline/online sync
 * @access Private
 * @middleware auth, validation
 */
router.post('/batch/sync',
  validateBody(z.object({
    operations: z.array(z.object({
      id: UUIDSchema,
      action: z.enum(['create', 'update', 'delete']),
      data: z.record(z.any()).optional(),
      clientTimestamp: z.string().datetime()
    })).min(1).max(25)
  })),
  imageController.batchSyncOperations
);

export { router as imageRoutes };