// /backend/src/controllers/imageController.ts - FIXED TypeScript Issues
import { Request, Response, NextFunction } from 'express';
import multer from 'multer';
import { ApiError } from '../utils/ApiError';
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
  // Upload middleware with enhanced error handling - FIXED: Make async
  uploadMiddleware: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      return new Promise((resolve) => {
        upload.single('image')(req, res, (err) => {
          if (err instanceof multer.MulterError) {
            switch (err.code) {
              case 'LIMIT_FILE_SIZE':
                next(ApiError.badRequest(
                  `File too large. Maximum size: ${Math.round(config.maxFileSize / (1024 * 1024))}MB`,
                  'FILE_TOO_LARGE'
                ));
                break;
              case 'LIMIT_FILE_COUNT':
                next(ApiError.badRequest('Only one file allowed', 'TOO_MANY_FILES'));
                break;
              case 'LIMIT_UNEXPECTED_FILE':
                next(ApiError.badRequest('Use "image" field name', 'UNEXPECTED_FILE_FIELD'));
                break;
              default:
                next(ApiError.badRequest(`Upload error: ${err.message}`, 'UPLOAD_ERROR'));
            }
          } else if (err) {
            next(ApiError.badRequest(
              `File too large. Maximum size: 8MB`, // Hardcode since we know the limit
              'FILE_TOO_LARGE'
            ));
          } else {
            next();
          }
          resolve();
        });
      });
    },
    'file upload'
  ),

  // Upload image - delegate to service
  uploadImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      if (!req.file) {
        return next(ApiError.badRequest('No image file provided', 'MISSING_FILE'));
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
      
      res.status(201).json({
        status: 'success',
        data: { image: safeImage },
        message: 'Image uploaded successfully'
      });
    },
    'uploading'
  ),

  // Get images - delegate to service - FIXED: Proper type casting
  getImages: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      
      // FIXED: Proper type handling for query parameters
      const options = {
        status: req.query.status as 'new' | 'processed' | 'labeled' | undefined,
        limit: req.query.limit ? parseInt(req.query.limit as string, 10) : undefined,
        offset: req.query.offset ? parseInt(req.query.offset as string, 10) : undefined
      };
      
      const images = await imageService.getUserImages(userId, options);
      
      // Sanitize response
      const safeImages = images.map(image => 
        sanitization.sanitizeImageForResponse(image)
      );
      
      res.status(200).json({
        status: 'success',
        data: { 
          images: safeImages,
          count: safeImages.length,
          pagination: req.query.limit ? {
            limit: options.limit,
            offset: options.offset
          } : undefined
        }
      });
    },
    'retrieving'
  ),

  // Get single image - delegate to service
  getImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      
      const image = await imageService.getImageById(imageId, userId);
      const safeImage = sanitization.sanitizeImageForResponse(image);
      
      res.status(200).json({
        status: 'success',
        data: { image: safeImage }
      });
    },
    'retrieving'
  ),

  // Update image status - delegate to service
  updateImageStatus: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      const { status } = req.body; // Already validated by middleware
      
      const updatedImage = await imageService.updateImageStatus(imageId, userId, status);
      const safeImage = sanitization.sanitizeImageForResponse(updatedImage);
      
      res.status(200).json({
        status: 'success',
        data: { image: safeImage },
        message: `Image status updated to ${status}`
      });
    },
    'updating status'
  ),

  // Generate thumbnail - delegate to service
  generateThumbnail: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      const size = parseInt(req.query.size as string) || 200;
      
      // Validate size parameter
      if (size < 50 || size > 500) {
        return next(ApiError.badRequest('Thumbnail size must be between 50 and 500 pixels', 'INVALID_SIZE'));
      }
      
      const result = await imageService.generateThumbnail(imageId, userId, size);
      
      res.status(200).json({
        status: 'success',
        data: result,
        message: 'Thumbnail generated successfully'
      });
    },
    'generating thumbnail'
  ),

  // Optimize image - delegate to service
  optimizeImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      
      const result = await imageService.optimizeForWeb(imageId, userId);
      
      res.status(200).json({
        status: 'success',
        data: result,
        message: 'Image optimized successfully'
      });
    },
    'optimizing'
  ),

  // Delete image - delegate to service
  deleteImage: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const imageId = req.params.id; // Already validated by middleware
      
      await imageService.deleteImage(imageId, userId);
      
      res.status(200).json({
        status: 'success',
        data: null,
        message: 'Image deleted successfully'
      });
    },
    'deleting'
  ),

  // Get user stats - delegate to service
  getUserStats: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      
      const stats = await imageService.getUserImageStats(userId);
      
      res.status(200).json({
        status: 'success',
        data: { stats }
      });
    },
    'retrieving stats'
  ),

  // Batch update status - delegate to service
  batchUpdateStatus: sanitization.wrapImageController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const { imageIds, status } = req.body; // Already validated by middleware
      
      const result = await imageService.batchUpdateStatus(imageIds, userId, status);
      
      res.status(200).json({
        status: 'success',
        data: result,
        message: `Batch updated ${result.updatedCount} of ${result.total} images`
      });
    },
    'batch updating'
  )
};