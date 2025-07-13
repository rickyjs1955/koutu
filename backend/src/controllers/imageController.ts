// /backend/src/controllers/imageController.ts - Fully Flutter-compatible version
import { Request, Response, NextFunction } from 'express';
import multer from 'multer';
import { EnhancedApiError } from '../middlewares/errorHandler';
import { config } from '../config';
import { imageService } from '../services/imageService';
import { sanitization } from '../utils/sanitize';

// Configure multer for memory storage with comprehensive validation
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 8388608, // 8MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    // Update allowed formats
    const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/bmp'];
    const allowedExtensions = /\.(jpeg|jpg|png|bmp)$/i;
    
    if (!allowedMimeTypes.includes(file.mimetype)) {
      return cb(new Error(`Invalid file type: ${file.mimetype}`));
    }
    
    if (!allowedExtensions.test(file.originalname)) {
      return cb(new Error('Invalid file extension'));
    }
    
    if (file.originalname.length > 255) {
      return cb(new Error('Filename too long'));
    }
    
    cb(null, true);
  }
});

export const imageController = {
  /**
   * Upload middleware with enhanced error handling
   * Flutter-optimized for mobile file uploads
   */
  uploadMiddleware: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      return new Promise((resolve) => {
        upload.single('image')(req, res, (err) => {
          if (err instanceof multer.MulterError) {
            switch (err.code) {
              case 'LIMIT_FILE_SIZE':
                throw EnhancedApiError.validation(
                  `File too large. Maximum size: ${Math.round(config.maxFileSize / (1024 * 1024))}MB`,
                  'file_size',
                  { maxSizeMB: Math.round(config.maxFileSize / (1024 * 1024)) }
                );
              case 'LIMIT_FILE_COUNT':
                throw EnhancedApiError.validation('Only one file allowed', 'file_count');
              case 'LIMIT_UNEXPECTED_FILE':
                throw EnhancedApiError.validation('Use "image" field name for file upload', 'field_name');
              default:
                throw EnhancedApiError.validation(`Upload error: ${err.message}`, 'upload_error');
            }
          } else if (err) {
            throw EnhancedApiError.validation(
              'File too large. Maximum size: 8MB',
              'file_size',
              { maxSizeMB: 8 }
            );
          } else {
            next();
          }
          resolve();
        });
      });
    },
    'file upload'
  ),

  /**
   * Upload image - delegate to service
   * Flutter-optimized response format
   */
  uploadImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      if (!req.file) {
        throw EnhancedApiError.validation('No image file provided', 'file');
      }

      const userId = req.user!.id;
      
      // Delegate to service
      const image = await imageService.uploadImage({
        userId,
        fileBuffer: req.file.buffer,
        originalFilename: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size
      });
      
      // Sanitize response
      const safeImage = sanitization.sanitizeImageForResponse(image);
      
      // Flutter-optimized response
      res.created(
        { image: safeImage },
        { 
          message: 'Image uploaded successfully',
          meta: {
            fileSize: req.file.size,
            fileSizeKB: Math.round(req.file.size / 1024),
            mimetype: req.file.mimetype,
            platform: req.get('User-Agent')?.includes('Flutter') ? 'flutter' : 'web'
          }
        }
      );
    },
    'uploading'
  ),

  /**
   * Get images - delegate to service
   * Flutter-optimized with pagination support
   */
  getImages: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      
      // Proper type handling for query parameters
      const options = {
        status: req.query.status as 'new' | 'processed' | 'labeled' | undefined,
        limit: req.query.limit ? parseInt(req.query.limit as string, 10) : undefined,
        offset: req.query.offset ? parseInt(req.query.offset as string, 10) : undefined
      };
      
      // Validate parameters
      if (options.limit && (isNaN(options.limit) || options.limit < 1 || options.limit > 100)) {
        throw EnhancedApiError.validation('Limit must be between 1 and 100', 'limit', options.limit);
      }
      
      if (options.offset && (isNaN(options.offset) || options.offset < 0)) {
        throw EnhancedApiError.validation('Offset must be 0 or greater', 'offset', options.offset);
      }
      
      const images = await imageService.getUserImages(userId, options);
      
      // Sanitize response
      const safeImages = images.map(image => 
        sanitization.sanitizeImageForResponse(image)
      );
      
      // Flutter-optimized response
      res.success(
        safeImages,
        {
          message: 'Images retrieved successfully',
          meta: {
            count: safeImages.length,
            filters: {
              status: options.status,
              limit: options.limit,
              offset: options.offset
            }
          }
        }
      );
    },
    'retrieving'
  ),

  /**
   * Get single image - delegate to service
   * Flutter-optimized response format
   */
  getImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      
      const image = await imageService.getImageById(imageId, userId);
      const safeImage = sanitization.sanitizeImageForResponse(image);
      
      // Flutter-optimized response
      res.success(
        { image: safeImage },
        {
          message: 'Image retrieved successfully',
          meta: {
            imageId,
            status: image.status
          }
        }
      );
    },
    'retrieving'
  ),

  /**
   * Update image status - delegate to service
   * Flutter-optimized response format
   */
  updateImageStatus: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      const { status } = req.body; // Already validated by middleware
      
      // Get current image to track previous status
      const currentImage = await imageService.getImageById(imageId, userId);
      const previousStatus = currentImage.status;
      
      const updatedImage = await imageService.updateImageStatus(imageId, userId, status);
      const safeImage = sanitization.sanitizeImageForResponse(updatedImage);
      
      // Flutter-optimized response
      res.success(
        { image: safeImage },
        {
          message: `Image status updated to ${status}`,
          meta: {
            imageId,
            previousStatus,
            newStatus: status,
            statusChanged: previousStatus !== status,
            statusTransition: `${previousStatus} → ${status}`
          }
        }
      );
    },
    'updating status'
  ),

  /**
   * Generate thumbnail - delegate to service
   * Flutter-optimized response format
   */
  generateThumbnail: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      const size = parseInt(req.query.size as string) || 200;
      
      // Validate size parameter
      if (size < 50 || size > 500) {
        throw EnhancedApiError.validation(
          'Thumbnail size must be between 50 and 500 pixels',
          'size',
          { min: 50, max: 500, provided: size }
        );
      }
      
      const result = await imageService.generateThumbnail(imageId, userId, size);
      
      // Flutter-optimized response
      res.success(
        result,
        {
          message: 'Thumbnail generated successfully',
          meta: {
            imageId,
            thumbnailSize: size,
            generatedAt: new Date().toISOString()
          }
        }
      );
    },
    'generating thumbnail'
  ),

  /**
   * Optimize image - delegate to service
   * Flutter-optimized response format
   */
  optimizeImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      
      const result = await imageService.optimizeForWeb(imageId, userId);
      
      // Flutter-optimized response with available information
      res.success(
        result,
        {
          message: 'Image optimized successfully',
          meta: {
            imageId,
            optimizedAt: new Date().toISOString(),
            operation: 'web_optimization',
            hasOptimizedVersion: !!result.optimizedPath
          }
        }
      );
    },
    'optimizing'
  ),

  /**
   * Delete image - delegate to service
   * Flutter-optimized response format
   */
  deleteImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      
      await imageService.deleteImage(imageId, userId);
      
      // Flutter-optimized response
      res.success(
        {},
        {
          message: 'Image deleted successfully',
          meta: {
            deletedImageId: imageId,
            deletedAt: new Date().toISOString()
          }
        }
      );
    },
    'deleting'
  ),

  /**
   * Get user stats - delegate to service
   * Flutter-optimized response format
   */
  getUserStats: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      
      const stats = await imageService.getUserImageStats(userId);
      
      // Flutter-optimized response
      res.success(
        { stats },
        {
          message: 'Image statistics retrieved successfully',
          meta: {
            userId,
            generatedAt: new Date().toISOString()
          }
        }
      );
    },
    'retrieving stats'
  ),

  /**
   * Batch update status - delegate to service
   * Flutter-optimized response format
   */
  batchUpdateStatus: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const { imageIds, status } = req.body; // Already validated by middleware
      
      const result = await imageService.batchUpdateStatus(imageIds, userId, status);
      
      // Flutter-optimized response
      res.success(
        result,
        {
          message: `Batch updated ${result.updatedCount} of ${result.total} images`,
          meta: {
            operation: 'batch_update_status',
            targetStatus: status,
            requestedCount: imageIds.length,
            successCount: result.updatedCount,
            failedCount: result.total - result.updatedCount
          }
        }
      );
    },
    'batch updating'
  ),

  /**
   * Get mobile thumbnails - Flutter optimized
   */
  getMobileThumbnails: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const { page = 1, limit = 20, size = 'medium' } = req.query;
      
      const result = await imageService.getMobileThumbnails(userId, {
        page: Number(page),
        limit: Number(limit),
        size: size as 'small' | 'medium' | 'large'
      });
      
      res.success(result, {
        message: 'Mobile thumbnails retrieved successfully',
        meta: {
          page: Number(page),
          limit: Number(limit),
          size,
          platform: 'mobile'
        }
      });
    },
    'retrieving mobile thumbnails'
  ),

  /**
   * Get mobile optimized image - Flutter optimized
   */
  getMobileOptimizedImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id;
      
      const result = await imageService.getMobileOptimizedImage(imageId, userId);
      
      res.success(result, {
        message: 'Mobile optimized image retrieved successfully',
        meta: {
          imageId,
          optimizedForMobile: true,
          format: result.format || 'auto'
        }
      });
    },
    'retrieving mobile optimized image'
  ),

  /**
   * Batch generate thumbnails - Flutter optimized
   */
  batchGenerateThumbnails: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const { imageIds, sizes = ['medium'] } = req.body;
      
      const result = await imageService.batchGenerateThumbnails(imageIds, userId, sizes);
      
      res.success(result, {
        message: `Generated thumbnails for ${result.successCount} of ${imageIds.length} images`,
        meta: {
          operation: 'batch_generate_thumbnails',
          requestedCount: imageIds.length,
          successCount: result.successCount,
          sizes
        }
      });
    },
    'batch generating thumbnails'
  ),

  /**
   * Get sync data - Flutter offline support
   */
  getSyncData: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const { lastSync, includeDeleted = false, limit = 50 } = req.query;
      
      const result = await imageService.getSyncData(userId, {
        lastSync: lastSync as string,
        includeDeleted: includeDeleted === 'true',
        limit: Number(limit)
      });
      
      res.success(result, {
        message: 'Sync data retrieved successfully',
        meta: {
          syncTimestamp: new Date().toISOString(),
          includeDeleted,
          itemCount: result.images?.length || 0
        }
      });
    },
    'retrieving sync data'
  ),

  /**
   * Flutter upload - optimized for Flutter apps
   */
  flutterUploadImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      if (!req.file) {
        throw EnhancedApiError.validation('No image file provided', 'file');
      }

      const userId = req.user!.id;
      
      const image = await imageService.flutterUploadImage({
        userId,
        fileBuffer: req.file.buffer,
        originalFilename: req.file.originalname,
        mimetype: req.file.mimetype,
        size: req.file.size
      });
      
      const safeImage = sanitization.sanitizeImageForResponse(image);
      
      res.created(
        { image: safeImage },
        { 
          message: 'Flutter upload successful',
          meta: {
            platform: 'flutter',
            fileSize: req.file.size,
            uploadId: image.id,
            processingStatus: 'initiated'
          }
        }
      );
    },
    'flutter uploading'
  ),

  /**
   * Batch sync operations - Flutter offline/online sync
   */
  batchSyncOperations: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const { operations } = req.body;
      
      const result = await imageService.batchSyncOperations(userId, operations);
      
      res.success(result, {
        message: `Processed ${result.successCount} of ${operations.length} sync operations`,
        meta: {
          operation: 'batch_sync',
          totalOperations: operations.length,
          successCount: result.successCount,
          failedCount: result.failedCount,
          conflicts: result.conflicts || []
        }
      });
    },
    'batch sync operations'
  )
};