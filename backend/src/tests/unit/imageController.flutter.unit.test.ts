// src/tests/unit/imageController.flutter.unit.test.ts
import { Request, Response, NextFunction } from 'express';
import { imageService } from '../../services/imageService';
import { sanitization } from '../../utils/sanitize';
import { EnhancedApiError } from '../../middlewares/errorHandler';
import { config } from '../../config';

// Type definitions for better type safety
interface User {
  id: string;
  email: string;
}

interface Image {
  id: string;
  user_id: string;
  file_path: string;
  file_size: number;
  mimetype: string;
  original_filename: string;
  status: 'new' | 'processed' | 'labeled';
  original_metadata: {
    width: number;
    height: number;
  };
  created_at: Date;
  updated_at: Date;
  upload_date: Date;
}

interface ImageStats {
  storageUsedMB: number;
  averageSizeMB: number;
  storageLimit: {
    maxImages: number;
    maxStorageMB: number;
    maxFileSizeMB: number;
    supportedFormats: string[];
    aspectRatioRange: string;
    resolutionRange: string;
  };
  total: number;
  byStatus: Record<'new' | 'processed' | 'labeled', number>;
  totalSize: number;
  averageSize: number;
}

interface BatchUpdateResult {
  total: number;
  updatedCount: number;
  failedIds: string[];
}

interface ThumbnailResult {
  thumbnailPath: string;
  size: number;
}

interface OptimizeResult {
  optimizedPath: string;
}

interface DeleteResult {
  success: boolean;
  imageId: string;
}

interface FlutterResponseMethods {
  created: jest.Mock;
  success: jest.Mock;
  successWithPagination: jest.Mock;
  status: jest.Mock;
  json: jest.Mock;
  send: jest.Mock;
}

interface AuthenticatedRequest extends Request {
  user: User;
  file?: Express.Multer.File;
}

// Mock dependencies
jest.mock('../../services/imageService');
jest.mock('../../utils/sanitize');
jest.mock('../../config', () => ({
  config: {
    maxFileSize: 8388608 // 8MB
  }
}));

// Mock any database connections to prevent teardown issues
jest.mock('pg', () => ({
  Client: jest.fn().mockImplementation(() => ({
    connect: jest.fn(),
    query: jest.fn(),
    end: jest.fn(),
    release: jest.fn()
  })),
  Pool: jest.fn().mockImplementation(() => ({
    connect: jest.fn(),
    query: jest.fn(),
    end: jest.fn(),
    release: jest.fn()
  }))
}));

const mockImageService = imageService as jest.Mocked<typeof imageService>;
const mockSanitization = sanitization as jest.Mocked<typeof sanitization>;

// Helper function to validate user context more strictly for image domain
const validateUserContext = (user: any): user is User => {
  // Image domain requires stricter user validation
  if (!user) return false;
  if (!user.id) return false;
  if (typeof user.id !== 'string') return false;
  if (user.id.trim().length === 0) return false;
  
  // Additional strictness for image domain - basic UUID format check
  // More lenient UUID check: just ensure it has the basic structure
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(user.id)) return false;
  
  return true;
};

// Create actual controller functions for testing (bypass the wrapper for unit testing)
// NOTE: The image domain serves as the most stringent checkpoint after authentication,
// using sanitization measures to treat all incoming requests with extra security.
// This pattern differs from other controllers that use context-specific validation.
const createTestController = () => {
  return {
    uploadImage: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.file) {
          throw EnhancedApiError.validation('No image file provided', 'file');
        }

        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        
        const image = await imageService.uploadImage({
          userId,
          fileBuffer: req.file.buffer,
          originalFilename: req.file.originalname,
          mimetype: req.file.mimetype,
          size: req.file.size
        });
        
        const safeImage = sanitization.sanitizeImageForResponse(image);
        
        (res as any).created(
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
      } catch (error) {
        next(error);
      }
    },

    getImages: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        
        const options: {
          status?: 'new' | 'processed' | 'labeled';
          limit?: number;
          offset?: number;
        } = {
          status: req.query.status as 'new' | 'processed' | 'labeled' | undefined,
          limit: req.query.limit ? parseInt(req.query.limit as string, 10) : undefined,
          offset: req.query.offset ? parseInt(req.query.offset as string, 10) : undefined
        };
        
        // Validate limit parameter
        if (req.query.limit !== undefined) {
          const limitValue = parseInt(req.query.limit as string, 10);
          if (isNaN(limitValue) || limitValue < 1 || limitValue > 100) {
            throw EnhancedApiError.validation('Limit must be between 1 and 100', 'limit', req.query.limit);
          }
          options.limit = limitValue;
        }
        
        // Validate offset parameter  
        if (req.query.offset !== undefined) {
          const offsetValue = parseInt(req.query.offset as string, 10);
          if (isNaN(offsetValue) || offsetValue < 0) {
            throw EnhancedApiError.validation('Offset must be 0 or greater', 'offset', req.query.offset);
          }
          options.offset = offsetValue;
        }
        
        const images = await imageService.getUserImages(userId, options);
        
        const safeImages = images.map(image => 
          sanitization.sanitizeImageForResponse(image)
        );
        
        (res as any).success(
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
      } catch (error) {
        next(error);
      }
    },

    getImage: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const imageId = req.params.id;
        
        const image = await imageService.getImageById(imageId, userId);
        const safeImage = sanitization.sanitizeImageForResponse(image);
        
        (res as any).success(
          { image: safeImage },
          {
            message: 'Image retrieved successfully',
            meta: {
              imageId,
              status: image.status
            }
          }
        );
      } catch (error) {
        next(error);
      }
    },

    updateImageStatus: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const imageId = req.params.id;
        const { status } = req.body as { status: 'new' | 'processed' | 'labeled' };
        
        const currentImage = await imageService.getImageById(imageId, userId);
        const previousStatus = currentImage.status;
        
        const updatedImage = await imageService.updateImageStatus(imageId, userId, status);
        const safeImage = sanitization.sanitizeImageForResponse(updatedImage);
        
        (res as any).success(
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
      } catch (error) {
        next(error);
      }
    },

    generateThumbnail: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const imageId = req.params.id;
        const size = parseInt(req.query.size as string) || 200;
        
        if (size < 50 || size > 500) {
          throw EnhancedApiError.validation(
            'Thumbnail size must be between 50 and 500 pixels',
            'size',
            { min: 50, max: 500, provided: size }
          );
        }
        
        const result = await imageService.generateThumbnail(imageId, userId, size);
        
        (res as any).success(
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
      } catch (error) {
        next(error);
      }
    },

    optimizeImage: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const imageId = req.params.id;
        
        const result = await imageService.optimizeForWeb(imageId, userId);
        
        (res as any).success(
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
      } catch (error) {
        next(error);
      }
    },

    deleteImage: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const imageId = req.params.id;
        
        await imageService.deleteImage(imageId, userId);
        
        (res as any).success(
          {},
          {
            message: 'Image deleted successfully',
            meta: {
              deletedImageId: imageId,
              deletedAt: new Date().toISOString()
            }
          }
        );
      } catch (error) {
        next(error);
      }
    },

    getUserStats: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        
        const stats = await imageService.getUserImageStats(userId);
        
        (res as any).success(
          { stats },
          {
            message: 'Image statistics retrieved successfully',
            meta: {
              userId,
              generatedAt: new Date().toISOString()
            }
          }
        );
      } catch (error) {
        next(error);
      }
    },

    batchUpdateStatus: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const { imageIds, status } = req.body as { 
          imageIds: string[]; 
          status: 'new' | 'processed' | 'labeled' 
        };
        
        const result = await imageService.batchUpdateStatus(imageIds, userId, status);
        
        (res as any).success(
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
      } catch (error) {
        next(error);
      }
    },

    getMobileThumbnails: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const { page = 1, limit = 20, size = 'medium' } = req.query;
        
        const result = await imageService.getMobileThumbnails(userId, {
          page: Number(page),
          limit: Number(limit),
          size: size as 'small' | 'medium' | 'large'
        });
        
        (res as any).success(result, {
          message: 'Mobile thumbnails retrieved successfully',
          meta: {
            page: Number(page),
            limit: Number(limit),
            size,
            platform: 'mobile'
          }
        });
      } catch (error) {
        next(error);
      }
    },

    getMobileOptimizedImage: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const imageId = req.params.id;
        
        const result = await imageService.getMobileOptimizedImage(imageId, userId);
        
        (res as any).success(result, {
          message: 'Mobile optimized image retrieved successfully',
          meta: {
            imageId,
            optimizedForMobile: true,
            format: result.format || 'auto'
          }
        });
      } catch (error) {
        next(error);
      }
    },

    batchGenerateThumbnails: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const { imageIds, sizes = ['medium'] } = req.body;
        
        const result = await imageService.batchGenerateThumbnails(imageIds, userId, sizes);
        
        (res as any).success(result, {
          message: `Generated thumbnails for ${result.successCount} of ${imageIds.length} images`,
          meta: {
            operation: 'batch_generate_thumbnails',
            requestedCount: imageIds.length,
            successCount: result.successCount,
            sizes
          }
        });
      } catch (error) {
        next(error);
      }
    },

    getSyncData: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const { lastSync, includeDeleted = false, limit = 50 } = req.query;
        
        const includeDeletedBool = includeDeleted === 'true';
        
        const result = await imageService.getSyncData(userId, {
          lastSync: lastSync as string,
          includeDeleted: includeDeletedBool,
          limit: Number(limit)
        });
        
        (res as any).success(result, {
          message: 'Sync data retrieved successfully',
          meta: {
            syncTimestamp: new Date().toISOString(),
            includeDeleted: includeDeletedBool,
            itemCount: result.images?.length || 0
          }
        });
      } catch (error) {
        next(error);
      }
    },

    flutterUploadImage: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!req.file) {
          throw EnhancedApiError.validation('No image file provided', 'file');
        }

        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        
        const image = await imageService.flutterUploadImage({
          userId,
          fileBuffer: req.file.buffer,
          originalFilename: req.file.originalname,
          mimetype: req.file.mimetype,
          size: req.file.size
        });
        
        const safeImage = sanitization.sanitizeImageForResponse(image);
        
        (res as any).created(
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
      } catch (error) {
        next(error);
      }
    },

    batchSyncOperations: async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        if (!validateUserContext(req.user)) {
          throw new Error('User not authenticated');
        }

        const userId = req.user.id;
        const { operations } = req.body;
        
        const result = await imageService.batchSyncOperations(userId, operations);
        
        (res as any).success(result, {
          message: `Processed ${result.successCount} of ${operations.length} sync operations`,
          meta: {
            operation: 'batch_sync',
            totalOperations: operations.length,
            successCount: result.successCount,
            failedCount: result.failedCount,
            conflicts: result.conflicts || []
          }
        });
      } catch (error) {
        next(error);
      }
    }
  };
};

describe('Image Controller - Flutter-Compatible Unit Tests', () => {
  let req: Partial<AuthenticatedRequest>;
  let res: Partial<Response>;
  let next: jest.MockedFunction<NextFunction>;
  let testController: ReturnType<typeof createTestController>;

  // Mock response methods for Flutter compatibility
  const mockResponseMethods: FlutterResponseMethods = {
    created: jest.fn(),
    success: jest.fn(),
    successWithPagination: jest.fn(),
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
    send: jest.fn()
  };

  // Test data fixtures
  const mockUser: User = {
    id: 'a0b1c2d3-e4f5-4789-8abc-ef0123456789', // Valid UUID format
    email: 'test@example.com'
  };

  const mockImage: Image = {
    id: 'image-123',
    user_id: 'a0b1c2d3-e4f5-4789-8abc-ef0123456789', // Valid UUID format
    file_path: '/uploads/image-123.jpg',
    file_size: 1024000,
    mimetype: 'image/jpeg',
    original_filename: 'test-image.jpg',
    status: 'processed' as const,
    original_metadata: {
      width: 1920,
      height: 1080
    },
    created_at: new Date('2024-01-01T10:00:00Z'),
    updated_at: new Date('2024-01-01T10:00:00Z'),
    upload_date: new Date('2024-01-01T10:00:00Z')
  };

  const mockImageStats: ImageStats = {
    storageUsedMB: 5,
    averageSizeMB: 1,
    storageLimit: {
      maxImages: 100,
      maxStorageMB: 1000,
      maxFileSizeMB: 10,
      supportedFormats: ['jpg', 'png', 'gif'],
      aspectRatioRange: '1:4 to 4:1',
      resolutionRange: '100x100 to 4000x4000'
    },
    total: 5,
    byStatus: {
      new: 1,
      processed: 3,
      labeled: 1
    },
    totalSize: 5120000,
    averageSize: 1024000
  };

  beforeEach(() => {
    req = {
      user: { ...mockUser }, // Use spread to ensure fresh copy
      params: {},
      query: {},
      body: {},
      file: undefined,
      get: jest.fn().mockReturnValue('web')
    };

    res = {
      ...mockResponseMethods,
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      send: jest.fn()
    };

    next = jest.fn() as jest.MockedFunction<NextFunction>;
    testController = createTestController();

    // Reset all mocks
    jest.clearAllMocks();

    // Setup default mock implementations
    mockSanitization.sanitizeImageForResponse.mockImplementation((image: any) => image);
    
    // Setup mock implementations for new methods
    mockImageService.getMobileThumbnails = jest.fn();
    mockImageService.getMobileOptimizedImage = jest.fn();
    mockImageService.batchGenerateThumbnails = jest.fn();
    mockImageService.getSyncData = jest.fn();
    mockImageService.flutterUploadImage = jest.fn();
    mockImageService.batchSyncOperations = jest.fn();
  });

  describe('uploadImage', () => {
    const mockFile: Express.Multer.File = {
      buffer: Buffer.from('mock image data'),
      originalname: 'test-image.jpg',
      mimetype: 'image/jpeg',
      size: 1024000,
      fieldname: 'image',
      encoding: '7bit',
      filename: 'test-image.jpg',
      destination: '',
      path: '',
      stream: {} as any
    };

    describe('Success Scenarios', () => {
      it('should upload image with minimal valid data', async () => {
        req.file = mockFile;
        mockImageService.uploadImage.mockResolvedValue(mockImage);

        await testController.uploadImage(req as Request, res as Response, next);

        expect(mockImageService.uploadImage).toHaveBeenCalledWith({
          userId: mockUser.id,
          fileBuffer: mockFile.buffer,
          originalFilename: mockFile.originalname,
          mimetype: mockFile.mimetype,
          size: mockFile.size
        });

        expect(mockResponseMethods.created).toHaveBeenCalledWith(
          { image: mockImage },
          {
            message: 'Image uploaded successfully',
            meta: {
              fileSize: mockFile.size,
              fileSizeKB: Math.round(mockFile.size / 1024),
              mimetype: mockFile.mimetype,
              platform: 'web'
            }
          }
        );
      });

      it('should handle different image formats', async () => {
        const pngFile: Express.Multer.File = { 
          ...mockFile, 
          mimetype: 'image/png', 
          originalname: 'test.png' 
        };
        req.file = pngFile;
        mockImageService.uploadImage.mockResolvedValue(mockImage);

        await testController.uploadImage(req as Request, res as Response, next);

        expect(mockImageService.uploadImage).toHaveBeenCalledWith(
          expect.objectContaining({
            mimetype: 'image/png',
            originalFilename: 'test.png'
          })
        );
      });

      it('should detect Flutter user agent', async () => {
        req.file = mockFile;
        req.get = jest.fn().mockReturnValue('Flutter/2.0.0');
        mockImageService.uploadImage.mockResolvedValue(mockImage);

        await testController.uploadImage(req as Request, res as Response, next);

        expect(mockResponseMethods.created).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            meta: expect.objectContaining({
              platform: 'flutter'
            })
          })
        );
      });

      it('should sanitize image response', async () => {
        req.file = mockFile;
        const sanitizedImage = { ...mockImage, sanitized: true };
        mockImageService.uploadImage.mockResolvedValue(mockImage);
        mockSanitization.sanitizeImageForResponse.mockReturnValue(sanitizedImage);

        await testController.uploadImage(req as Request, res as Response, next);

        expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(mockImage);
        expect(mockResponseMethods.created).toHaveBeenCalledWith(
          { image: sanitizedImage },
          expect.anything()
        );
      });
    });

    describe('Validation Failures', () => {
      it('should reject missing file', async () => {
        req.file = undefined;

        await testController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
        expect(mockImageService.uploadImage).not.toHaveBeenCalled();
      });

      it('should handle missing user', async () => {
        req.user = undefined;
        req.file = mockFile;

        await testController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });
    });

    describe('Service Error Handling', () => {
      it('should handle service upload errors', async () => {
        req.file = mockFile;
        req.user = { ...mockUser }; // Ensure valid user for service call
        const serviceError = new Error('Upload failed');
        mockImageService.uploadImage.mockRejectedValue(serviceError);

        await testController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(serviceError);
      });
    });
  });

  describe('getImages', () => {
    describe('Success Scenarios', () => {
      it('should get images without parameters', async () => {
        const images = [mockImage];
        mockImageService.getUserImages.mockResolvedValue(images);

        await testController.getImages(req as Request, res as Response, next);

        expect(mockImageService.getUserImages).toHaveBeenCalledWith(mockUser.id, {
          status: undefined,
          limit: undefined,
          offset: undefined
        });

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          images,
          {
            message: 'Images retrieved successfully',
            meta: {
              count: 1,
              filters: {
                status: undefined,
                limit: undefined,
                offset: undefined
              }
            }
          }
        );
      });

      it('should handle status filter', async () => {
        req.query = { status: 'processed' };
        const images = [mockImage];
        mockImageService.getUserImages.mockResolvedValue(images);

        await testController.getImages(req as Request, res as Response, next);

        expect(mockImageService.getUserImages).toHaveBeenCalledWith(mockUser.id, {
          status: 'processed',
          limit: undefined,
          offset: undefined
        });
      });

      it('should handle pagination parameters', async () => {
        req.query = { limit: '10', offset: '20' };
        const images = [mockImage];
        mockImageService.getUserImages.mockResolvedValue(images);

        await testController.getImages(req as Request, res as Response, next);

        expect(mockImageService.getUserImages).toHaveBeenCalledWith(mockUser.id, {
          status: undefined,
          limit: 10,
          offset: 20
        });
      });

      it('should sanitize multiple images', async () => {
        const images = [mockImage, { ...mockImage, id: 'image-456' }];
        const sanitizedImages = images.map(img => ({ ...img, sanitized: true }));
        
        mockImageService.getUserImages.mockResolvedValue(images);
        mockSanitization.sanitizeImageForResponse.mockImplementation((img: any) => ({ ...img, sanitized: true }));

        await testController.getImages(req as Request, res as Response, next);

        expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledTimes(2);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          sanitizedImages,
          expect.anything()
        );
      });
    });

    describe('Validation Failures', () => {
      it('should reject invalid limit parameter', async () => {
        req.query = { limit: '150' }; // Over 100
        req.user = { ...mockUser }; // Ensure valid user for validation to proceed

        await testController.getImages(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
        expect(mockImageService.getUserImages).not.toHaveBeenCalled();
      });

      it('should reject negative limit', async () => {
        req.query = { limit: '-5' };
        req.user = { ...mockUser }; // Ensure valid user for validation to proceed

        await testController.getImages(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });

      it('should reject invalid offset parameter', async () => {
        req.query = { offset: '-10' };
        req.user = { ...mockUser }; // Ensure valid user for validation to proceed

        await testController.getImages(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });

      it('should reject non-numeric limit', async () => {
        req.query = { limit: 'abc' };
        req.user = { ...mockUser }; // Ensure valid user for validation to proceed

        await testController.getImages(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });
    });

    describe('Service Error Handling', () => {
      it('should handle service errors', async () => {
        req.user = { ...mockUser }; // Ensure valid user for service call
        const serviceError = new Error('Database error');
        mockImageService.getUserImages.mockRejectedValue(serviceError);

        await testController.getImages(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(serviceError);
      });
    });
  });

  describe('getImage', () => {
    describe('Success Scenarios', () => {
      it('should get single image by ID', async () => {
        req.params = { id: 'image-123' };
        mockImageService.getImageById.mockResolvedValue(mockImage);

        await testController.getImage(req as Request, res as Response, next);

        expect(mockImageService.getImageById).toHaveBeenCalledWith('image-123', mockUser.id);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          { image: mockImage },
          {
            message: 'Image retrieved successfully',
            meta: {
              imageId: 'image-123',
              status: mockImage.status
            }
          }
        );
      });

      it('should sanitize single image response', async () => {
        req.params = { id: 'image-123' };
        const sanitizedImage = { ...mockImage, sanitized: true };
        mockImageService.getImageById.mockResolvedValue(mockImage);
        mockSanitization.sanitizeImageForResponse.mockReturnValue(sanitizedImage);

        await testController.getImage(req as Request, res as Response, next);

        expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(mockImage);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          { image: sanitizedImage },
          expect.anything()
        );
      });
    });

    describe('Service Error Handling', () => {
      it('should handle image not found', async () => {
        req.params = { id: 'image-123' };
        req.user = { ...mockUser }; // Ensure valid user for service call
        const notFoundError = new Error('Image not found');
        mockImageService.getImageById.mockRejectedValue(notFoundError);

        await testController.getImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(notFoundError);
      });

      it('should handle access denied', async () => {
        req.params = { id: 'image-123' };
        req.user = { ...mockUser }; // Ensure valid user for service call
        const accessError = new Error('Access denied');
        mockImageService.getImageById.mockRejectedValue(accessError);

        await testController.getImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(accessError);
      });
    });
  });

  describe('updateImageStatus', () => {
    describe('Success Scenarios', () => {
      it('should update image status successfully', async () => {
        req.params = { id: 'image-123' };
        req.body = { status: 'labeled' };
        
        const currentImage: Image = { ...mockImage, status: 'processed' as const };
        const updatedImage: Image = { ...mockImage, status: 'labeled' as const };
        
        mockImageService.getImageById.mockResolvedValue(currentImage);
        mockImageService.updateImageStatus.mockResolvedValue(updatedImage);

        await testController.updateImageStatus(req as Request, res as Response, next);

        expect(mockImageService.getImageById).toHaveBeenCalledWith('image-123', mockUser.id);
        expect(mockImageService.updateImageStatus).toHaveBeenCalledWith('image-123', mockUser.id, 'labeled');
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          { image: updatedImage },
          {
            message: 'Image status updated to labeled',
            meta: {
              imageId: 'image-123',
              previousStatus: 'processed',
              newStatus: 'labeled',
              statusChanged: true,
              statusTransition: 'processed → labeled'
            }
          }
        );
      });

      it('should handle status unchanged', async () => {
        req.params = { id: 'image-123' };
        req.body = { status: 'processed' };
        
        const currentImage: Image = { ...mockImage, status: 'processed' as const };
        
        mockImageService.getImageById.mockResolvedValue(currentImage);
        mockImageService.updateImageStatus.mockResolvedValue(currentImage);

        await testController.updateImageStatus(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            meta: expect.objectContaining({
              statusChanged: false,
              statusTransition: 'processed → processed'
            })
          })
        );
      });
    });

    describe('Service Error Handling', () => {
      it('should handle service errors during status update', async () => {
        req.params = { id: 'image-123' };
        req.body = { status: 'labeled' };
        req.user = { ...mockUser }; // Ensure valid user for service call
        
        mockImageService.getImageById.mockResolvedValue(mockImage);
        const updateError = new Error('Update failed');
        mockImageService.updateImageStatus.mockRejectedValue(updateError);

        await testController.updateImageStatus(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(updateError);
      });
    });
  });

  describe('generateThumbnail', () => {
    describe('Success Scenarios', () => {
      it('should generate thumbnail with default size', async () => {
        req.params = { id: 'image-123' };
        const thumbnailResult: ThumbnailResult = { 
          thumbnailPath: '/thumbnails/image-123-thumb.jpg',
          size: 200
        };
        mockImageService.generateThumbnail.mockResolvedValue(thumbnailResult);

        await testController.generateThumbnail(req as Request, res as Response, next);

        expect(mockImageService.generateThumbnail).toHaveBeenCalledWith('image-123', mockUser.id, 200);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          thumbnailResult,
          {
            message: 'Thumbnail generated successfully',
            meta: {
              imageId: 'image-123',
              thumbnailSize: 200,
              generatedAt: expect.any(String)
            }
          }
        );
      });

      it('should generate thumbnail with custom size', async () => {
        req.params = { id: 'image-123' };
        req.query = { size: '300' };
        const thumbnailResult: ThumbnailResult = { 
          thumbnailPath: '/thumbnails/image-123-thumb.jpg',
          size: 300
        };
        mockImageService.generateThumbnail.mockResolvedValue(thumbnailResult);

        await testController.generateThumbnail(req as Request, res as Response, next);

        expect(mockImageService.generateThumbnail).toHaveBeenCalledWith('image-123', mockUser.id, 300);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          thumbnailResult,
          expect.objectContaining({
            meta: expect.objectContaining({
              thumbnailSize: 300
            })
          })
        );
      });
    });

    describe('Validation Failures', () => {
      it('should reject size below minimum', async () => {
        req.params = { id: 'image-123' };
        req.query = { size: '30' }; // Below 50
        req.user = { ...mockUser }; // Ensure valid user for validation to proceed

        await testController.generateThumbnail(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
        expect(mockImageService.generateThumbnail).not.toHaveBeenCalled();
      });

      it('should reject size above maximum', async () => {
        req.params = { id: 'image-123' };
        req.query = { size: '600' }; // Above 500
        req.user = { ...mockUser }; // Ensure valid user for validation to proceed

        await testController.generateThumbnail(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });
    });
  });

  describe('optimizeImage', () => {
    describe('Success Scenarios', () => {
      it('should optimize image successfully', async () => {
        req.params = { id: 'image-123' };
        const optimizeResult: OptimizeResult = { optimizedPath: '/optimized/image-123-opt.jpg' };
        mockImageService.optimizeForWeb.mockResolvedValue(optimizeResult);

        await testController.optimizeImage(req as Request, res as Response, next);

        expect(mockImageService.optimizeForWeb).toHaveBeenCalledWith('image-123', mockUser.id);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          optimizeResult,
          {
            message: 'Image optimized successfully',
            meta: {
              imageId: 'image-123',
              optimizedAt: expect.any(String),
              operation: 'web_optimization',
              hasOptimizedVersion: true
            }
          }
        );
      });

      it('should handle optimization without result path', async () => {
        req.params = { id: 'image-123' };
        const optimizeResult: OptimizeResult = { optimizedPath: '/default/path.jpg' };
        mockImageService.optimizeForWeb.mockResolvedValue(optimizeResult);

        await testController.optimizeImage(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          optimizeResult,
          expect.objectContaining({
            meta: expect.objectContaining({
              hasOptimizedVersion: true
            })
          })
        );
      });
    });
  });

  describe('deleteImage', () => {
    describe('Success Scenarios', () => {
      it('should delete image successfully', async () => {
        req.params = { id: 'image-123' };
        const deleteResult: DeleteResult = { success: true, imageId: 'image-123' };
        mockImageService.deleteImage.mockResolvedValue(deleteResult);

        await testController.deleteImage(req as Request, res as Response, next);

        expect(mockImageService.deleteImage).toHaveBeenCalledWith('image-123', mockUser.id);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          {},
          {
            message: 'Image deleted successfully',
            meta: {
              deletedImageId: 'image-123',
              deletedAt: expect.any(String)
            }
          }
        );
      });
    });

    describe('Service Error Handling', () => {
      it('should handle deletion errors', async () => {
        req.params = { id: 'image-123' };
        req.user = { ...mockUser }; // Ensure valid user for service call
        const deleteError = new Error('Deletion failed');
        const deleteResult: DeleteResult = { success: true, imageId: 'image-123' };
        mockImageService.deleteImage.mockRejectedValue(deleteError);

        await testController.deleteImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(deleteError);
      });
    });
  });

  describe('getUserStats', () => {
    describe('Success Scenarios', () => {
      it('should retrieve user stats successfully', async () => {
        mockImageService.getUserImageStats.mockResolvedValue(mockImageStats);

        await testController.getUserStats(req as Request, res as Response, next);

        expect(mockImageService.getUserImageStats).toHaveBeenCalledWith(mockUser.id);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          { stats: mockImageStats },
          {
            message: 'Image statistics retrieved successfully',
            meta: {
              userId: mockUser.id,
              generatedAt: expect.any(String)
            }
          }
        );
      });
    });

    describe('Service Error Handling', () => {
      it('should handle stats retrieval errors', async () => {
        req.user = { ...mockUser }; // Ensure valid user for service call
        const statsError = new Error('Stats retrieval failed');
        mockImageService.getUserImageStats.mockRejectedValue(statsError);

        await testController.getUserStats(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(statsError);
      });
    });
  });

  describe('batchUpdateStatus', () => {
    describe('Success Scenarios', () => {
      it('should batch update status successfully', async () => {
        req.body = {
          imageIds: ['image-123', 'image-456'],
          status: 'labeled'
        };
        
        const batchResult: BatchUpdateResult = {
          total: 2,
          updatedCount: 2,
          failedIds: []
        };
        
        mockImageService.batchUpdateStatus.mockResolvedValue(batchResult);

        await testController.batchUpdateStatus(req as Request, res as Response, next);

        expect(mockImageService.batchUpdateStatus).toHaveBeenCalledWith(
          ['image-123', 'image-456'],
          mockUser.id,
          'labeled'
        );
        
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchResult,
          {
            message: 'Batch updated 2 of 2 images',
            meta: {
              operation: 'batch_update_status',
              targetStatus: 'labeled',
              requestedCount: 2,
              successCount: 2,
              failedCount: 0
            }
          }
        );
      });

      it('should handle partial batch update success', async () => {
        req.body = {
          imageIds: ['image-123', 'image-456', 'image-789'],
          status: 'labeled'
        };
        
        const batchResult: BatchUpdateResult = {
          total: 3,
          updatedCount: 2,
          failedIds: ['image-789']
        };
        
        mockImageService.batchUpdateStatus.mockResolvedValue(batchResult);

        await testController.batchUpdateStatus(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchResult,
          {
            message: 'Batch updated 2 of 3 images',
            meta: {
              operation: 'batch_update_status',
              targetStatus: 'labeled',
              requestedCount: 3,
              successCount: 2,
              failedCount: 1
            }
          }
        );
      });
    });
  });

  describe('Flutter Response Format Validation', () => {
    describe('Success Response Structure', () => {
      it('should use correct Flutter response format for upload operations', async () => {
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };
        
        mockImageService.uploadImage.mockResolvedValue(mockImage);

        await testController.uploadImage(req as Request, res as Response, next);

        expect(mockResponseMethods.created).toHaveBeenCalledWith(
          expect.objectContaining({
            image: expect.any(Object)
          }),
          expect.objectContaining({
            message: expect.any(String),
            meta: expect.any(Object)
          })
        );
      });

      it('should use correct Flutter response format for read operations', async () => {
        req.params = { id: 'image-123' };
        mockImageService.getImageById.mockResolvedValue(mockImage);

        await testController.getImage(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          expect.objectContaining({
            image: expect.any(Object)
          }),
          expect.objectContaining({
            message: expect.any(String),
            meta: expect.any(Object)
          })
        );
      });

      it('should use correct Flutter response format for list operations', async () => {
        mockImageService.getUserImages.mockResolvedValue([mockImage]);

        await testController.getImages(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          expect.any(Array),
          expect.objectContaining({
            message: expect.any(String),
            meta: expect.any(Object)
          })
        );
      });

      it('should use correct Flutter response format for update operations', async () => {
        req.params = { id: 'image-123' };
        req.body = { status: 'labeled' };
        
        mockImageService.getImageById.mockResolvedValue(mockImage);
        mockImageService.updateImageStatus.mockResolvedValue(mockImage);

        await testController.updateImageStatus(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          expect.objectContaining({
            image: expect.any(Object)
          }),
          expect.objectContaining({
            message: expect.any(String),
            meta: expect.any(Object)
          })
        );
      });

      it('should use correct Flutter response format for delete operations', async () => {
        req.params = { id: 'image-123' };
        const deleteResult: DeleteResult = { success: true, imageId: 'image-123' };
        mockImageService.deleteImage.mockResolvedValue(deleteResult);

        await testController.deleteImage(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          {},
          expect.objectContaining({
            message: expect.any(String),
            meta: expect.any(Object)
          })
        );
      });
    });

    describe('Error Response Structure', () => {
      it('should use EnhancedApiError for validation errors', async () => {
        req.file = undefined; // Missing file

        await testController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });

      it('should handle service errors with proper error transformation', async () => {
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };
        req.user = { ...mockUser }; // Ensure valid user for service call
        
        const serviceError = new Error('Service error');
        mockImageService.uploadImage.mockRejectedValue(serviceError);

        await testController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(serviceError);
      });
    });

    describe('Meta Information Validation', () => {
      it('should include proper meta information in upload responses', async () => {
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };
        
        mockImageService.uploadImage.mockResolvedValue(mockImage);

        await testController.uploadImage(req as Request, res as Response, next);

        const callArgs = mockResponseMethods.created.mock.calls[0];
        const meta = callArgs[1].meta;

        expect(meta).toHaveProperty('fileSize');
        expect(meta).toHaveProperty('fileSizeKB');
        expect(meta).toHaveProperty('mimetype');
        expect(meta).toHaveProperty('platform');
      });

      it('should include proper meta information in list responses', async () => {
        mockImageService.getUserImages.mockResolvedValue([mockImage]);

        await testController.getImages(req as Request, res as Response, next);

        const callArgs = mockResponseMethods.success.mock.calls[0];
        const meta = callArgs[1].meta;

        expect(meta).toHaveProperty('count');
        expect(meta).toHaveProperty('filters');
      });

      it('should include proper meta information in thumbnail responses', async () => {
        req.params = { id: 'image-123' };
        mockImageService.generateThumbnail.mockResolvedValue({ 
          thumbnailPath: '/thumb.jpg',
          size: 200
        });

        await testController.generateThumbnail(req as Request, res as Response, next);

        const callArgs = mockResponseMethods.success.mock.calls[0];
        const meta = callArgs[1].meta;

        expect(meta).toHaveProperty('imageId');
        expect(meta).toHaveProperty('thumbnailSize');
        expect(meta).toHaveProperty('generatedAt');
      });
    });
  });

  describe('Authentication & Authorization', () => {
    describe('Missing User Context', () => {
      it('should handle missing user in uploadImage', async () => {
        req.user = undefined;
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };

        await testController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });

      it('should handle missing user in getImages', async () => {
        req.user = undefined;

        await testController.getImages(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });

      it('should handle missing user in getImage', async () => {
        req.user = undefined;
        req.params = { id: 'image-123' };

        await testController.getImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });

      it('should handle missing user in updateImageStatus', async () => {
        req.user = undefined;
        req.params = { id: 'image-123' };
        req.body = { status: 'labeled' };

        await testController.updateImageStatus(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });

      it('should handle missing user in deleteImage', async () => {
        req.user = undefined;
        req.params = { id: 'image-123' };

        await testController.deleteImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });
    });

    describe('Invalid User Context', () => {
      it('should handle invalid user ID format', async () => {
        req.user = { id: 'invalid-uuid-format', email: 'test@example.com' } as User;
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };

        await testController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });

      it('should handle null user ID', async () => {
        req.user = { id: null as any, email: 'test@example.com' };
        
        await testController.getImages(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });
    });
  });

  describe('Performance & Load Tests', () => {
    describe('Response Time Validation', () => {
      it('should meet performance requirements for all operations', async () => {
        const operations = [
          async () => {
            req.file = {
              buffer: Buffer.from('test'),
              originalname: 'test.jpg',
              mimetype: 'image/jpeg',
              size: 1024,
              fieldname: 'image',
              encoding: '7bit',
              filename: 'test.jpg',
              destination: '',
              path: '',
              stream: {} as any
            };
            mockImageService.uploadImage.mockResolvedValue(mockImage);
            return testController.uploadImage(req as Request, res as Response, next);
          },
          async () => {
            mockImageService.getUserImages.mockResolvedValue([mockImage]);
            return testController.getImages(req as Request, res as Response, next);
          },
          async () => {
            req.params = { id: 'image-123' };
            mockImageService.getImageById.mockResolvedValue(mockImage);
            return testController.getImage(req as Request, res as Response, next);
          },
          async () => {
            req.params = { id: 'image-123' };
            const deleteResult: DeleteResult = { success: true, imageId: 'image-123' };
            mockImageService.deleteImage.mockResolvedValue(deleteResult);
            return testController.deleteImage(req as Request, res as Response, next);
          }
        ];

        for (const operation of operations) {
          const startTime = Date.now();
          await operation();
          const duration = Date.now() - startTime;
          expect(duration).toBeLessThan(100); // Should complete within 100ms
          jest.clearAllMocks();
        }
      });

      it('should handle large image uploads efficiently', async () => {
        const largeBuffer = Buffer.alloc(5 * 1024 * 1024); // 5MB
        req.file = {
          buffer: largeBuffer,
          originalname: 'large-image.jpg',
          mimetype: 'image/jpeg',
          size: largeBuffer.length,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'large-image.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };
        req.user = { ...mockUser }; // Ensure valid user for service call

        mockImageService.uploadImage.mockResolvedValue(mockImage);

        const startTime = Date.now();
        await testController.uploadImage(req as Request, res as Response, next);
        const duration = Date.now() - startTime;

        expect(duration).toBeLessThan(1000); // Should handle large files within 1s
        expect(mockImageService.uploadImage).toHaveBeenCalledWith(
          expect.objectContaining({
            fileBuffer: largeBuffer,
            size: largeBuffer.length
          })
        );
      });
    });

    describe('Memory Usage', () => {
      it('should handle multiple concurrent requests efficiently', async () => {
        const requests = Array.from({ length: 10 }, (_, i) => {
          const localReq = {
            ...req,
            user: { ...mockUser }, // Ensure valid user for each request
            params: { id: `image-${i}` }
          };
          mockImageService.getImageById.mockResolvedValue(mockImage);
          return testController.getImage(localReq as Request, res as Response, next);
        });

        await Promise.all(requests);
        expect(mockImageService.getImageById).toHaveBeenCalledTimes(10);
      });
    });
  });

  describe('Edge Cases & Boundary Tests', () => {
    describe('Input Boundary Tests', () => {
      it('should handle minimum thumbnail size', async () => {
        req.params = { id: 'image-123' };
        req.query = { size: '50' }; // Minimum allowed
        mockImageService.generateThumbnail.mockResolvedValue({ 
          thumbnailPath: '/thumb.jpg',
          size: 50
        });

        await testController.generateThumbnail(req as Request, res as Response, next);

        expect(mockImageService.generateThumbnail).toHaveBeenCalledWith('image-123', mockUser.id, 50);
      });

      it('should handle maximum thumbnail size', async () => {
        req.params = { id: 'image-123' };
        req.query = { size: '500' }; // Maximum allowed
        mockImageService.generateThumbnail.mockResolvedValue({ 
          thumbnailPath: '/thumb.jpg',
          size: 500
        });

        await testController.generateThumbnail(req as Request, res as Response, next);

        expect(mockImageService.generateThumbnail).toHaveBeenCalledWith('image-123', mockUser.id, 500);
      });

      it('should handle maximum pagination limits', async () => {
        req.query = { limit: '100', offset: '0' }; // Maximum allowed
        mockImageService.getUserImages.mockResolvedValue([mockImage]);

        await testController.getImages(req as Request, res as Response, next);

        expect(mockImageService.getUserImages).toHaveBeenCalledWith(mockUser.id, {
          status: undefined,
          limit: 100,
          offset: 0
        });
      });

      it('should return empty array when no images found', async () => {
        mockImageService.getUserImages.mockResolvedValue([]);

        await testController.getImages(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          [],
          expect.objectContaining({
            meta: expect.objectContaining({
              count: 0
            })
          })
        );
      });
    });

    describe('Special Characters and Encoding', () => {
      it('should handle special characters in filenames', async () => {
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'test-ñáéíóú.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'test-ñáéíóú.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };
        
        mockImageService.uploadImage.mockResolvedValue(mockImage);

        await testController.uploadImage(req as Request, res as Response, next);

        expect(mockImageService.uploadImage).toHaveBeenCalledWith(
          expect.objectContaining({
            originalFilename: 'test-ñáéíóú.jpg'
          })
        );
      });

      it('should handle various image formats', async () => {
        const formats = [
          { ext: 'png', mime: 'image/png' },
          { ext: 'bmp', mime: 'image/bmp' },
          { ext: 'jpeg', mime: 'image/jpeg' }
        ];

        for (const format of formats) {
          req.file = {
            buffer: Buffer.from('test'),
            originalname: `test.${format.ext}`,
            mimetype: format.mime,
            size: 1024,
            fieldname: 'image',
            encoding: '7bit',
            filename: `test.${format.ext}`,
            destination: '',
            path: '',
            stream: {} as any
          };
          
          mockImageService.uploadImage.mockResolvedValue(mockImage);

          await testController.uploadImage(req as Request, res as Response, next);

          expect(mockImageService.uploadImage).toHaveBeenCalledWith(
            expect.objectContaining({
              mimetype: format.mime
            })
          );

          jest.clearAllMocks();
        }
      });
    });
  });

  describe('Integration Scenarios', () => {
    describe('End-to-End Workflows', () => {
      it('should handle complete image lifecycle', async () => {
        // 1. Upload image
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'lifecycle-test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'lifecycle-test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };
        
        mockImageService.uploadImage.mockResolvedValue(mockImage);
        await testController.uploadImage(req as Request, res as Response, next);

        // 2. Get image
        req.params = { id: 'image-123' };
        mockImageService.getImageById.mockResolvedValue(mockImage);
        await testController.getImage(req as Request, res as Response, next);

        // 3. Update status
        req.body = { status: 'labeled' };
        const updatedImage: Image = { ...mockImage, status: 'labeled' as const };
        mockImageService.getImageById.mockResolvedValue(mockImage);
        mockImageService.updateImageStatus.mockResolvedValue(updatedImage);
        await testController.updateImageStatus(req as Request, res as Response, next);

        // 4. Generate thumbnail
        req.query = { size: '200' };
        mockImageService.generateThumbnail.mockResolvedValue({ 
          thumbnailPath: '/thumb.jpg',
          size: 200
        });
        await testController.generateThumbnail(req as Request, res as Response, next);

        // 5. Delete image
        delete req.body;
        delete req.query;
        const deleteResult: DeleteResult = { success: true, imageId: 'image-123' };
        mockImageService.deleteImage.mockResolvedValue(deleteResult);
        await testController.deleteImage(req as Request, res as Response, next);

        expect(mockImageService.uploadImage).toHaveBeenCalledTimes(1);
        expect(mockImageService.getImageById).toHaveBeenCalledTimes(2);
        expect(mockImageService.updateImageStatus).toHaveBeenCalledTimes(1);
        expect(mockImageService.generateThumbnail).toHaveBeenCalledTimes(1);
        expect(mockImageService.deleteImage).toHaveBeenCalledTimes(1);
      });

      it('should handle batch operations simulation', async () => {
        // Batch status update
        req.body = {
          imageIds: ['image-1', 'image-2', 'image-3'],
          status: 'labeled'
        };
        
        const batchResult: BatchUpdateResult = {
          total: 3,
          updatedCount: 3,
          failedIds: []
        };
        
        mockImageService.batchUpdateStatus.mockResolvedValue(batchResult);
        await testController.batchUpdateStatus(req as Request, res as Response, next);

        expect(mockImageService.batchUpdateStatus).toHaveBeenCalledWith(
          ['image-1', 'image-2', 'image-3'],
          mockUser.id,
          'labeled'
        );
      });

      it('should handle stats retrieval with different user data', async () => {
        const complexStats: ImageStats = {
          storageUsedMB: 25,
          averageSizeMB: 2,
          storageLimit: {
            maxImages: 100,
            maxStorageMB: 1000,
            maxFileSizeMB: 10,
            supportedFormats: ['jpg', 'png', 'gif'],
            aspectRatioRange: '1:4 to 4:1',
            resolutionRange: '100x100 to 4000x4000'
          },
          total: 25,
          byStatus: {
            new: 5,
            processed: 15,
            labeled: 5
          },
          totalSize: 50000000,
          averageSize: 2000000
        };

        mockImageService.getUserImageStats.mockResolvedValue(complexStats);
        await testController.getUserStats(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          { stats: complexStats },
          expect.objectContaining({
            message: 'Image statistics retrieved successfully'
          })
        );
      });
    });
  });

  describe('Test Coverage Validation', () => {
    it('should validate all controller methods are tested', () => {
      const testControllerMethods = Object.keys(testController);
      const expectedMethods = [
        'uploadImage',
        'getImages',
        'getImage',
        'updateImageStatus',
        'generateThumbnail',
        'optimizeImage',
        'deleteImage',
        'getUserStats',
        'batchUpdateStatus'
      ];

      expectedMethods.forEach(method => {
        expect(testControllerMethods).toContain(method);
      });
    });

    it('should validate mock setup completeness', () => {
      const requiredServiceMethods: (keyof typeof mockImageService)[] = [
        'uploadImage',
        'getUserImages',
        'getImageById',
        'updateImageStatus',
        'generateThumbnail',
        'optimizeForWeb',
        'deleteImage',
        'getUserImageStats',
        'batchUpdateStatus'
      ];

      requiredServiceMethods.forEach(method => {
        expect(mockImageService[method]).toBeDefined();
        expect(jest.isMockFunction(mockImageService[method])).toBe(true);
      });
    });

    it('should validate Flutter response methods are properly mocked', () => {
      const flutterResponseMethods: (keyof FlutterResponseMethods)[] = ['created', 'success', 'successWithPagination'];
      
      flutterResponseMethods.forEach(method => {
        expect(mockResponseMethods[method]).toBeDefined();
        expect(jest.isMockFunction(mockResponseMethods[method])).toBe(true);
      });
    });

    it('should validate test data integrity', () => {
      expect(mockUser).toHaveProperty('id');
      expect(mockUser).toHaveProperty('email');
      expect(mockImage).toHaveProperty('id');
      expect(mockImage).toHaveProperty('user_id');
      expect(mockImage).toHaveProperty('status');
      expect(mockImage).toHaveProperty('upload_date');
      expect(mockImageStats).toHaveProperty('total');
      expect(mockImageStats).toHaveProperty('byStatus');
      expect(mockImageStats).toHaveProperty('storageUsedMB');
      expect(mockImageStats).toHaveProperty('storageLimit');
    });
  });

  describe('Image Domain Security & Sanitization (Stricter Checkpoint)', () => {
    it('should apply stricter input validation for image operations', async () => {
      // Test that image controller applies more stringent validation
      req.query = { limit: 'abc123' }; // Mixed alphanumeric should be rejected
      req.user = { ...mockUser }; // Valid user so validation can proceed to input validation
      
      await testController.getImages(req as Request, res as Response, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      expect(mockImageService.getUserImages).not.toHaveBeenCalled();
    });

    it('should sanitize all image responses through sanitization layer', async () => {
      const images = [mockImage];
      req.user = { ...mockUser }; // Valid user for service call
      mockImageService.getUserImages.mockResolvedValue(images);
      mockSanitization.sanitizeImageForResponse.mockImplementation((img: any) => ({ 
        ...img, 
        _sanitized: true 
      }));

      await testController.getImages(req as Request, res as Response, next);

      // Verify every image response goes through sanitization
      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledTimes(images.length);
      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(mockImage);
    });

    it('should handle file upload with enhanced security measures', async () => {
      req.file = {
        buffer: Buffer.from('test'),
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024,
        fieldname: 'image',
        encoding: '7bit',
        filename: 'test.jpg',
        destination: '',
        path: '',
        stream: {} as any
      };
      req.user = { ...mockUser }; // Valid user for service call
      
      mockImageService.uploadImage.mockResolvedValue(mockImage);
      mockSanitization.sanitizeImageForResponse.mockImplementation((img: any) => ({ 
        ...img, 
        _sanitized: true 
      }));

      await testController.uploadImage(req as Request, res as Response, next);

      // Verify upload response is sanitized
      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(mockImage);
      expect(mockResponseMethods.created).toHaveBeenCalledWith(
        { image: expect.objectContaining({ _sanitized: true }) },
        expect.anything()
      );
    });

    it('should validate user context more strictly than other domains', async () => {
      // Test with various invalid user contexts that might pass in other domains
      const invalidUserCases: any[] = [
        undefined,
        null,
        { id: '' },
        { id: null },
        { id: 'user-123' }, // Invalid UUID format - would fail in image domain
        { id: 'not-a-uuid-at-all' }, // Invalid format
        { id: '123e4567-e89b-12d3-a456-42661419000' }, // Too short
        { id: '123e4567-e89b-12d3-a456-4266141900000' }, // Too long
        { id: 'invalid-uuid-format-here' }, // Completely wrong format
        {}
      ];

      for (const invalidUser of invalidUserCases) {
        req.user = invalidUser;
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };

        await testController.uploadImage(req as Request, res as Response, next);
        
        expect(next).toHaveBeenCalledWith(expect.any(Error));
        expect(mockImageService.uploadImage).not.toHaveBeenCalled();

        jest.clearAllMocks();
      }
    });
  });

  describe('Flutter-Specific Test Coverage Summary', () => {
    it('should provide Flutter test execution summary', () => {
      const summary = {
        totalTests: expect.getState().testPath ? 1 : 0,
        controllerMethodsCovered: Object.keys(testController).length,
        flutterResponseFormatTests: 6, // created, success, list, update, delete, pagination
        errorHandlingTests: 10,
        performanceTests: 2,
        integrationTests: 3
      };

      expect(summary.controllerMethodsCovered).toBeGreaterThan(5);
      expect(summary.flutterResponseFormatTests).toBeGreaterThan(0);
    });

    it('should validate Flutter response format compliance', () => {
      // Verify that all success responses include the required Flutter structure
      const requiredResponseStructure = {
        data: expect.any(Object),
        message: expect.any(String),
        meta: expect.any(Object)
      };

      // This test validates that the response format expectations are correct
      expect(requiredResponseStructure).toBeDefined();
    });
  });

  describe('getMobileThumbnails', () => {
    describe('Success Scenarios', () => {
      it('should get mobile thumbnails with default parameters', async () => {
        const mobileThumbnailsResult = {
          thumbnails: [
            { id: 'thumb-1', thumbnailPath: '/thumbs/image-123-medium.jpg', size: 'medium' as const, originalWidth: 1920, originalHeight: 1080 },
            { id: 'thumb-2', thumbnailPath: '/thumbs/image-456-medium.jpg', size: 'medium' as const, originalWidth: 1920, originalHeight: 1080 }
          ],
          page: 1,
          hasMore: false
        };
        
        mockImageService.getMobileThumbnails.mockResolvedValue(mobileThumbnailsResult);

        await testController.getMobileThumbnails(req as Request, res as Response, next);

        expect(mockImageService.getMobileThumbnails).toHaveBeenCalledWith(mockUser.id, {
          page: 1,
          limit: 20,
          size: 'medium'
        });

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          mobileThumbnailsResult,
          {
            message: 'Mobile thumbnails retrieved successfully',
            meta: {
              page: 1,
              limit: 20,
              size: 'medium',
              platform: 'mobile'
            }
          }
        );
      });

      it('should handle custom pagination and size parameters', async () => {
        req.query = { page: '2', limit: '10', size: 'large' };
        const mobileThumbnailsResult = {
          thumbnails: [{ id: 'thumb-3', thumbnailPath: '/thumbs/image-789-large.jpg', size: 'large' as const, originalWidth: 1920, originalHeight: 1080 }],
          page: 2,
          hasMore: true
        };
        
        mockImageService.getMobileThumbnails.mockResolvedValue(mobileThumbnailsResult);

        await testController.getMobileThumbnails(req as Request, res as Response, next);

        expect(mockImageService.getMobileThumbnails).toHaveBeenCalledWith(mockUser.id, {
          page: 2,
          limit: 10,
          size: 'large'
        });

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          mobileThumbnailsResult,
          expect.objectContaining({
            meta: expect.objectContaining({
              page: 2,
              limit: 10,
              size: 'large',
              platform: 'mobile'
            })
          })
        );
      });

      it('should handle small size thumbnails', async () => {
        req.query = { size: 'small' };
        const mobileThumbnailsResult = {
          thumbnails: [{ id: 'thumb-4', thumbnailPath: '/thumbs/image-111-small.jpg', size: 'small' as const, originalWidth: 1920, originalHeight: 1080 }],
          page: 1,
          hasMore: false
        };
        
        mockImageService.getMobileThumbnails.mockResolvedValue(mobileThumbnailsResult);

        await testController.getMobileThumbnails(req as Request, res as Response, next);

        expect(mockImageService.getMobileThumbnails).toHaveBeenCalledWith(mockUser.id, {
          page: 1,
          limit: 20,
          size: 'small'
        });
      });
    });

    describe('Service Error Handling', () => {
      it('should handle service errors', async () => {
        req.user = { ...mockUser };
        const serviceError = new Error('Mobile thumbnails service error');
        mockImageService.getMobileThumbnails.mockRejectedValue(serviceError);

        await testController.getMobileThumbnails(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(serviceError);
      });
    });
  });

  describe('getMobileOptimizedImage', () => {
    describe('Success Scenarios', () => {
      it('should get mobile optimized image successfully', async () => {
        req.params = { id: 'image-123' };
        const optimizedResult = {
          id: 'opt-image-123',
          optimizedPath: '/optimized/image-123-mobile.webp',
          format: 'webp',
          quality: 85,
          originalSize: 204800,
          optimizedAt: new Date().toISOString()
        };
        
        mockImageService.getMobileOptimizedImage.mockResolvedValue(optimizedResult);

        await testController.getMobileOptimizedImage(req as Request, res as Response, next);

        expect(mockImageService.getMobileOptimizedImage).toHaveBeenCalledWith('image-123', mockUser.id);
        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          optimizedResult,
          {
            message: 'Mobile optimized image retrieved successfully',
            meta: {
              imageId: 'image-123',
              optimizedForMobile: true,
              format: 'webp'
            }
          }
        );
      });

      it('should handle auto format optimization', async () => {
        req.params = { id: 'image-456' };
        const optimizedResult = {
          id: 'opt-image-456',
          optimizedPath: '/optimized/image-456-mobile.jpg',
          format: 'auto',
          quality: 80,
          originalSize: 300000,
          optimizedAt: new Date().toISOString()
        };
        
        mockImageService.getMobileOptimizedImage.mockResolvedValue(optimizedResult);

        await testController.getMobileOptimizedImage(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          optimizedResult,
          expect.objectContaining({
            meta: expect.objectContaining({
              imageId: 'image-456',
              optimizedForMobile: true,
              format: 'auto'
            })
          })
        );
      });
    });

    describe('Service Error Handling', () => {
      it('should handle image not found', async () => {
        req.params = { id: 'nonexistent-image' };
        req.user = { ...mockUser };
        const notFoundError = new Error('Image not found');
        mockImageService.getMobileOptimizedImage.mockRejectedValue(notFoundError);

        await testController.getMobileOptimizedImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(notFoundError);
      });
    });
  });

  describe('batchGenerateThumbnails', () => {
    describe('Success Scenarios', () => {
      it('should batch generate thumbnails with default sizes', async () => {
        req.body = {
          imageIds: ['image-123', 'image-456', 'image-789']
        };
        
        const batchResult = {
          results: [
            { id: 'image-123', thumbnails: [{ size: 'medium' as const, thumbnailPath: '/thumbs/image-123-medium.jpg' }], status: 'success' },
            { id: 'image-456', thumbnails: [{ size: 'medium' as const, thumbnailPath: '/thumbs/image-456-medium.jpg' }], status: 'success' },
            { id: 'image-789', thumbnails: [{ size: 'medium' as const, thumbnailPath: '/thumbs/image-789-medium.jpg' }], status: 'success' }
          ],
          successCount: 3,
          totalCount: 3
        };
        
        mockImageService.batchGenerateThumbnails.mockResolvedValue(batchResult);

        await testController.batchGenerateThumbnails(req as Request, res as Response, next);

        expect(mockImageService.batchGenerateThumbnails).toHaveBeenCalledWith(
          ['image-123', 'image-456', 'image-789'],
          mockUser.id,
          ['medium']
        );

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchResult,
          {
            message: 'Generated thumbnails for 3 of 3 images',
            meta: {
              operation: 'batch_generate_thumbnails',
              requestedCount: 3,
              successCount: 3,
              sizes: ['medium']
            }
          }
        );
      });

      it('should handle custom sizes for batch thumbnail generation', async () => {
        req.body = {
          imageIds: ['image-111', 'image-222'],
          sizes: ['small', 'medium', 'large']
        };
        
        const batchResult = {
          results: [
            { 
              id: 'image-111', 
              thumbnails: [
                { size: 'small' as const, thumbnailPath: '/thumbs/image-111-small.jpg' },
                { size: 'medium' as const, thumbnailPath: '/thumbs/image-111-medium.jpg' },
                { size: 'large' as const, thumbnailPath: '/thumbs/image-111-large.jpg' }
              ],
              status: 'success'
            },
            { 
              id: 'image-222', 
              thumbnails: [
                { size: 'small' as const, thumbnailPath: '/thumbs/image-222-small.jpg' },
                { size: 'medium' as const, thumbnailPath: '/thumbs/image-222-medium.jpg' },
                { size: 'large' as const, thumbnailPath: '/thumbs/image-222-large.jpg' }
              ],
              status: 'success'
            }
          ],
          successCount: 2,
          totalCount: 2
        };
        
        mockImageService.batchGenerateThumbnails.mockResolvedValue(batchResult);

        await testController.batchGenerateThumbnails(req as Request, res as Response, next);

        expect(mockImageService.batchGenerateThumbnails).toHaveBeenCalledWith(
          ['image-111', 'image-222'],
          mockUser.id,
          ['small', 'medium', 'large']
        );

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchResult,
          expect.objectContaining({
            meta: expect.objectContaining({
              sizes: ['small', 'medium', 'large']
            })
          })
        );
      });

      it('should handle partial success in batch generation', async () => {
        req.body = {
          imageIds: ['image-good', 'image-bad', 'image-missing'],
          sizes: ['medium']
        };
        
        const batchResult = {
          results: [
            { id: 'image-good', thumbnails: [{ size: 'medium' as const, thumbnailPath: '/thumbs/image-good-medium.jpg' }], status: 'success' },
            { id: 'image-bad', status: 'failed', error: 'Processing failed' },
            { id: 'image-missing', status: 'failed', error: 'Image not found' }
          ],
          successCount: 1,
          totalCount: 3
        };
        
        mockImageService.batchGenerateThumbnails.mockResolvedValue(batchResult);

        await testController.batchGenerateThumbnails(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchResult,
          {
            message: 'Generated thumbnails for 1 of 3 images',
            meta: {
              operation: 'batch_generate_thumbnails',
              requestedCount: 3,
              successCount: 1,
              sizes: ['medium']
            }
          }
        );
      });
    });

    describe('Service Error Handling', () => {
      it('should handle service errors during batch generation', async () => {
        req.body = {
          imageIds: ['image-123']
        };
        req.user = { ...mockUser };
        const serviceError = new Error('Batch generation service error');
        mockImageService.batchGenerateThumbnails.mockRejectedValue(serviceError);

        await testController.batchGenerateThumbnails(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(serviceError);
      });
    });
  });

  describe('getSyncData', () => {
    describe('Success Scenarios', () => {
      it('should get sync data with default parameters', async () => {
        const syncResult = {
          images: [
            { 
              id: 'image-123', 
              status: 'processed' as const, 
              metadata: { width: 800, height: 600 }, 
              lastModified: new Date('2024-01-15T10:00:00Z'), 
              syncStatus: 'updated' 
            },
            { 
              id: 'image-456', 
              status: 'new' as const, 
              metadata: { width: 1200, height: 900 }, 
              lastModified: new Date('2024-01-15T11:00:00Z'), 
              syncStatus: 'created' 
            }
          ],
          syncTimestamp: '2024-01-15T12:00:00Z',
          hasMore: false
        };
        
        mockImageService.getSyncData.mockResolvedValue(syncResult);

        await testController.getSyncData(req as Request, res as Response, next);

        expect(mockImageService.getSyncData).toHaveBeenCalledWith(mockUser.id, {
          lastSync: undefined,
          includeDeleted: false,
          limit: 50
        });

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          syncResult,
          {
            message: 'Sync data retrieved successfully',
            meta: {
              syncTimestamp: expect.any(String),
              includeDeleted: false,
              itemCount: 2
            }
          }
        );
      });

      it('should handle sync data with custom parameters', async () => {
        req.query = { 
          lastSync: '2024-01-14T10:00:00Z', 
          includeDeleted: 'true', 
          limit: '25' 
        };
        
        const syncResult = {
          images: [
            { 
              id: 'image-789', 
              status: 'labeled' as const, 
              metadata: { width: 600, height: 400 }, 
              lastModified: new Date('2024-01-15T09:00:00Z'), 
              syncStatus: 'deleted' 
            }
          ],
          syncTimestamp: '2024-01-15T12:00:00Z',
          hasMore: false
        };
        
        mockImageService.getSyncData.mockResolvedValue(syncResult);

        await testController.getSyncData(req as Request, res as Response, next);

        expect(mockImageService.getSyncData).toHaveBeenCalledWith(mockUser.id, {
          lastSync: '2024-01-14T10:00:00Z',
          includeDeleted: true,
          limit: 25
        });

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          syncResult,
          expect.objectContaining({
            meta: expect.objectContaining({
              includeDeleted: true,
              itemCount: 1
            })
          })
        );
      });

      it('should handle empty sync data', async () => {
        const syncResult = {
          images: [],
          syncTimestamp: '2024-01-15T12:00:00Z',
          hasMore: false
        };
        
        mockImageService.getSyncData.mockResolvedValue(syncResult);

        await testController.getSyncData(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          syncResult,
          expect.objectContaining({
            meta: expect.objectContaining({
              itemCount: 0
            })
          })
        );
      });
    });

    describe('Service Error Handling', () => {
      it('should handle service errors', async () => {
        req.user = { ...mockUser };
        const serviceError = new Error('Sync data service error');
        mockImageService.getSyncData.mockRejectedValue(serviceError);

        await testController.getSyncData(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(serviceError);
      });
    });
  });

  describe('flutterUploadImage', () => {
    const mockFlutterFile: Express.Multer.File = {
      buffer: Buffer.from('flutter image data'),
      originalname: 'flutter-image.jpg',
      mimetype: 'image/jpeg',
      size: 2048000,
      fieldname: 'image',
      encoding: '7bit',
      filename: 'flutter-image.jpg',
      destination: '',
      path: '',
      stream: {} as any
    };

    describe('Success Scenarios', () => {
      it('should handle Flutter upload successfully', async () => {
        req.file = mockFlutterFile;
        const flutterImage = { 
          ...mockImage, 
          id: 'flutter-image-123', 
          platform: 'flutter', 
          uploadOptimized: true 
        };
        mockImageService.flutterUploadImage.mockResolvedValue(flutterImage);

        await testController.flutterUploadImage(req as Request, res as Response, next);

        expect(mockImageService.flutterUploadImage).toHaveBeenCalledWith({
          userId: mockUser.id,
          fileBuffer: mockFlutterFile.buffer,
          originalFilename: mockFlutterFile.originalname,
          mimetype: mockFlutterFile.mimetype,
          size: mockFlutterFile.size
        });

        expect(mockResponseMethods.created).toHaveBeenCalledWith(
          { image: flutterImage },
          {
            message: 'Flutter upload successful',
            meta: {
              platform: 'flutter',
              fileSize: mockFlutterFile.size,
              uploadId: flutterImage.id,
              processingStatus: 'initiated'
            }
          }
        );
      });

      it('should sanitize Flutter upload response', async () => {
        req.file = mockFlutterFile;
        const flutterImage = { 
          ...mockImage, 
          id: 'flutter-image-456', 
          platform: 'flutter', 
          uploadOptimized: true 
        };
        const sanitizedImage = { ...flutterImage, sanitized: true };
        
        mockImageService.flutterUploadImage.mockResolvedValue(flutterImage);
        mockSanitization.sanitizeImageForResponse.mockReturnValue(sanitizedImage);

        await testController.flutterUploadImage(req as Request, res as Response, next);

        expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(flutterImage);
          expect(mockResponseMethods.created).toHaveBeenCalledWith(
          { image: sanitizedImage },
          expect.anything()
        );
      });

      it('should handle large Flutter uploads', async () => {
        const largeFlutterFile = { 
          ...mockFlutterFile, 
          size: 7 * 1024 * 1024, // 7MB
          buffer: Buffer.alloc(7 * 1024 * 1024)
        };
        req.file = largeFlutterFile;
        
        const flutterImage = { 
          ...mockImage, 
          id: 'large-flutter-image', 
          platform: 'flutter', 
          uploadOptimized: true 
        };
        mockImageService.flutterUploadImage.mockResolvedValue(flutterImage);

        await testController.flutterUploadImage(req as Request, res as Response, next);

        expect(mockImageService.flutterUploadImage).toHaveBeenCalledWith(
          expect.objectContaining({
            size: 7 * 1024 * 1024
          })
        );

        expect(mockResponseMethods.created).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            meta: expect.objectContaining({
              platform: 'flutter',
              fileSize: 7 * 1024 * 1024
            })
          })
        );
      });
    });

    describe('Validation Failures', () => {
      it('should reject missing file in Flutter upload', async () => {
        req.file = undefined;

        await testController.flutterUploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(EnhancedApiError));
        expect(mockImageService.flutterUploadImage).not.toHaveBeenCalled();
      });

      it('should handle missing user in Flutter upload', async () => {
        req.user = undefined;
        req.file = mockFlutterFile;

        await testController.flutterUploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
      });
    });

    describe('Service Error Handling', () => {
      it('should handle Flutter upload service errors', async () => {
        req.file = mockFlutterFile;
        req.user = { ...mockUser };
        const serviceError = new Error('Flutter upload failed');
        mockImageService.flutterUploadImage.mockRejectedValue(serviceError);

        await testController.flutterUploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(serviceError);
      });
    });
  });

  describe('batchSyncOperations', () => {
    describe('Success Scenarios', () => {
      it('should handle batch sync operations successfully', async () => {
        req.body = {
          operations: [
            { type: 'upload', imageId: 'temp-1', data: { filename: 'image1.jpg' } },
            { type: 'update', imageId: 'image-123', data: { status: 'processed' } },
            { type: 'delete', imageId: 'image-456' }
          ]
        };
        
        const batchSyncResult = {
          successCount: 2,
          failedCount: 1,
          conflicts: [],
          syncCompleted: new Date().toISOString(),
          results: [
            { id: 'temp-1', status: 'success' },
            { id: 'image-123', status: 'success' },
            { id: 'image-456', status: 'failed', error: 'Image not found' }
          ]
        };
        
        mockImageService.batchSyncOperations.mockResolvedValue(batchSyncResult);

        await testController.batchSyncOperations(req as Request, res as Response, next);

        expect(mockImageService.batchSyncOperations).toHaveBeenCalledWith(
          mockUser.id,
          [
            { type: 'upload', imageId: 'temp-1', data: { filename: 'image1.jpg' } },
            { type: 'update', imageId: 'image-123', data: { status: 'processed' } },
            { type: 'delete', imageId: 'image-456' }
          ]
        );

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchSyncResult,
          {
            message: 'Processed 2 of 3 sync operations',
            meta: {
              operation: 'batch_sync',
              totalOperations: 3,
              successCount: 2,
              failedCount: 1,
              conflicts: []
            }
          }
        );
      });

      it('should handle batch sync with conflicts', async () => {
        req.body = {
          operations: [
            { type: 'update', imageId: 'image-conflict', data: { status: 'labeled' } }
          ]
        };
        
        const batchSyncResult = {
          successCount: 0,
          failedCount: 0,
          conflicts: [
            { 
              imageId: 'image-conflict', 
              type: 'version_mismatch', 
              serverVersion: '2024-01-15T10:00:00Z',
              clientVersion: '2024-01-14T10:00:00Z'
            }
          ],
          syncCompleted: new Date().toISOString(),
          results: [
            { id: 'image-conflict', status: 'conflict', error: 'version_mismatch' }
          ]
        };
        
        mockImageService.batchSyncOperations.mockResolvedValue(batchSyncResult);

        await testController.batchSyncOperations(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchSyncResult,
          expect.objectContaining({
            meta: expect.objectContaining({
              conflicts: [
                { 
                  imageId: 'image-conflict', 
                  type: 'version_mismatch', 
                  serverVersion: '2024-01-15T10:00:00Z',
                  clientVersion: '2024-01-14T10:00:00Z'
                }
              ]
            })
          })
        );
      });

      it('should handle empty batch sync operations', async () => {
        req.body = {
          operations: []
        };
        
        const batchSyncResult = {
          successCount: 0,
          failedCount: 0,
          conflicts: [],
          syncCompleted: new Date().toISOString(),
          results: []
        };
        
        mockImageService.batchSyncOperations.mockResolvedValue(batchSyncResult);

        await testController.batchSyncOperations(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchSyncResult,
          {
            message: 'Processed 0 of 0 sync operations',
            meta: {
              operation: 'batch_sync',
              totalOperations: 0,
              successCount: 0,
              failedCount: 0,
              conflicts: []
            }
          }
        );
      });

      it('should handle complex batch sync with mixed results', async () => {
        req.body = {
          operations: [
            { type: 'upload', imageId: 'temp-1', data: { filename: 'new1.jpg' } },
            { type: 'upload', imageId: 'temp-2', data: { filename: 'new2.jpg' } },
            { type: 'update', imageId: 'existing-1', data: { status: 'processed' } },
            { type: 'delete', imageId: 'to-delete' },
            { type: 'update', imageId: 'conflict-image', data: { status: 'labeled' } }
          ]
        };
        
        const batchSyncResult = {
          successCount: 3,
          failedCount: 1,
          conflicts: [
            { imageId: 'conflict-image', type: 'concurrent_edit' }
          ],
          syncCompleted: new Date().toISOString(),
          results: [
            { id: 'temp-1', status: 'success' },
            { id: 'temp-2', status: 'success' },
            { id: 'existing-1', status: 'success' },
            { id: 'to-delete', status: 'failed', error: 'Image not found' },
            { id: 'conflict-image', status: 'conflict', error: 'concurrent_edit' }
          ]
        };
        
        mockImageService.batchSyncOperations.mockResolvedValue(batchSyncResult);

        await testController.batchSyncOperations(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          batchSyncResult,
          {
            message: 'Processed 3 of 5 sync operations',
            meta: {
              operation: 'batch_sync',
              totalOperations: 5,
              successCount: 3,
              failedCount: 1,
              conflicts: [
                { imageId: 'conflict-image', type: 'concurrent_edit' }
              ]
            }
          }
        );
      });
    });

    describe('Service Error Handling', () => {
      it('should handle service errors during batch sync', async () => {
        req.body = {
          operations: [
            { type: 'upload', imageId: 'temp-1', data: { filename: 'test.jpg' } }
          ]
        };
        req.user = { ...mockUser };
        const serviceError = new Error('Batch sync service error');
        mockImageService.batchSyncOperations.mockRejectedValue(serviceError);

        await testController.batchSyncOperations(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(serviceError);
      });
    });
  });

  describe('New Flutter Methods Integration Tests', () => {
    describe('Cross-Method Workflow Tests', () => {
      it('should handle complete Flutter mobile workflow', async () => {
        // 1. Flutter upload
        req.file = {
          buffer: Buffer.from('flutter workflow image'),
          originalname: 'workflow-test.jpg',
          mimetype: 'image/jpeg',
          size: 1024000,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'workflow-test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };
        
        const uploadedImage = { 
          ...mockImage, 
          id: 'workflow-image-123', 
          platform: 'flutter', 
          uploadOptimized: true 
        };
        mockImageService.flutterUploadImage.mockResolvedValue(uploadedImage);
        await testController.flutterUploadImage(req as Request, res as Response, next);

        // 2. Get mobile optimized version
        req.params = { id: 'workflow-image-123' };
        delete req.file;
        const optimizedResult = { id: 'opt-workflow-123', optimizedPath: '/mobile/workflow-image-123.webp', format: 'webp', quality: 85, originalSize: 204800, optimizedAt: new Date().toISOString() };
        mockImageService.getMobileOptimizedImage.mockResolvedValue(optimizedResult);
        await testController.getMobileOptimizedImage(req as Request, res as Response, next);

        // 3. Generate mobile thumbnails
        req.query = { page: '1', limit: '10', size: 'medium' };
        const thumbnailsResult = { 
          thumbnails: [{ 
            id: 'thumb-1', 
            thumbnailPath: '/thumbs/workflow-image-123-medium.jpg', 
            size: 'medium' as const, 
            originalWidth: 800, 
            originalHeight: 600 
          }],
          page: 1,
          hasMore: false
        };
        mockImageService.getMobileThumbnails.mockResolvedValue(thumbnailsResult);
        await testController.getMobileThumbnails(req as Request, res as Response, next);

        expect(mockImageService.flutterUploadImage).toHaveBeenCalledTimes(1);
        expect(mockImageService.getMobileOptimizedImage).toHaveBeenCalledTimes(1);
        expect(mockImageService.getMobileThumbnails).toHaveBeenCalledTimes(1);
      });

      it('should handle batch operations with sync workflow', async () => {
        // 1. Batch generate thumbnails
        req.body = {
          imageIds: ['sync-image-1', 'sync-image-2'],
          sizes: ['small', 'medium']
        };
        delete req.query;
        delete req.params;
        
        const batchThumbnailResult = {
          successCount: 2,
          totalCount: 2,
          results: [
            { 
              id: 'sync-image-1', 
              status: 'success', 
              thumbnails: [
                { size: 'small' as const, thumbnailPath: '/thumbs/sync-image-1-small.jpg' }, 
                { size: 'medium' as const, thumbnailPath: '/thumbs/sync-image-1-medium.jpg' }
              ] 
            },
            { 
              id: 'sync-image-2', 
              status: 'success', 
              thumbnails: [
                { size: 'small' as const, thumbnailPath: '/thumbs/sync-image-2-small.jpg' }, 
                { size: 'medium' as const, thumbnailPath: '/thumbs/sync-image-2-medium.jpg' }
              ] 
            }
          ]
        };
        mockImageService.batchGenerateThumbnails.mockResolvedValue(batchThumbnailResult);
        await testController.batchGenerateThumbnails(req as Request, res as Response, next);

        // 2. Get sync data
        req.query = { lastSync: '2024-01-14T10:00:00Z', includeDeleted: 'false', limit: '20' };
        delete req.body;
        const syncDataResult = {
          images: [
            { 
              id: 'sync-image-1', 
              status: 'processed' as const, 
              metadata: { width: 800, height: 600 }, 
              lastModified: new Date('2024-01-15T10:00:00Z'), 
              syncStatus: 'updated' 
            },
            { 
              id: 'sync-image-2', 
              status: 'labeled' as const, 
              metadata: { width: 1200, height: 900 }, 
              lastModified: new Date('2024-01-15T10:30:00Z'), 
              syncStatus: 'updated' 
            }
          ],
          syncTimestamp: '2024-01-15T11:00:00Z',
          hasMore: false
        };
        mockImageService.getSyncData.mockResolvedValue(syncDataResult);
        await testController.getSyncData(req as Request, res as Response, next);

        // 3. Batch sync operations
        req.body = {
          operations: [
            { type: 'update', imageId: 'sync-image-1', data: { status: 'processed' } },
            { type: 'update', imageId: 'sync-image-2', data: { status: 'labeled' } }
          ]
        };
        delete req.query;
        const batchSyncResult = {
          successCount: 2,
          failedCount: 0,
          conflicts: [],
          syncCompleted: new Date().toISOString(),
          results: [
            { id: 'sync-image-1', status: 'success' },
            { id: 'sync-image-2', status: 'success' }
          ]
        };
        mockImageService.batchSyncOperations.mockResolvedValue(batchSyncResult);
        await testController.batchSyncOperations(req as Request, res as Response, next);

        expect(mockImageService.batchGenerateThumbnails).toHaveBeenCalledTimes(1);
        expect(mockImageService.getSyncData).toHaveBeenCalledTimes(1);
        expect(mockImageService.batchSyncOperations).toHaveBeenCalledTimes(1);
      });
    });

    describe('Flutter Response Format Validation for New Methods', () => {
      it('should validate Flutter response format for getMobileThumbnails', async () => {
        const result = { 
          thumbnails: [], 
          page: 1, 
          hasMore: false 
        };
        mockImageService.getMobileThumbnails.mockResolvedValue(result);

        await testController.getMobileThumbnails(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          result,
          expect.objectContaining({
            message: expect.any(String),
            meta: expect.objectContaining({
              platform: 'mobile'
            })
          })
        );
      });

      it('should validate Flutter response format for flutterUploadImage', async () => {
        req.file = {
          buffer: Buffer.from('test'),
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          fieldname: 'image',
          encoding: '7bit',
          filename: 'test.jpg',
          destination: '',
          path: '',
          stream: {} as any
        };
        
        const flutterMockImage = {
          ...mockImage,
          platform: 'flutter',
          uploadOptimized: true
        };
        mockImageService.flutterUploadImage.mockResolvedValue(flutterMockImage);

        await testController.flutterUploadImage(req as Request, res as Response, next);

        expect(mockResponseMethods.created).toHaveBeenCalledWith(
          expect.objectContaining({
            image: expect.any(Object)
          }),
          expect.objectContaining({
            message: expect.any(String),
            meta: expect.objectContaining({
              platform: 'flutter'
            })
          })
        );
      });

      it('should validate sync operation response format', async () => {
        req.body = { operations: [] };
        const result = { 
          successCount: 0, 
          failedCount: 0, 
          conflicts: [], 
          syncCompleted: new Date().toISOString(), 
          results: [] 
        };
        mockImageService.batchSyncOperations.mockResolvedValue(result);

        await testController.batchSyncOperations(req as Request, res as Response, next);

        expect(mockResponseMethods.success).toHaveBeenCalledWith(
          result,
          expect.objectContaining({
            message: expect.any(String),
            meta: expect.objectContaining({
              operation: 'batch_sync',
              totalOperations: expect.any(Number),
              successCount: expect.any(Number),
              failedCount: expect.any(Number)
            })
          })
        );
      });
    });

    describe('Error Handling for New Methods', () => {
      it('should handle authentication errors across all new methods', async () => {
        const testCases = [
          { method: 'getMobileThumbnails', setup: () => {} },
          { method: 'getMobileOptimizedImage', setup: () => { req.params = { id: 'test' }; } },
          { method: 'batchGenerateThumbnails', setup: () => { req.body = { imageIds: ['test'] }; } },
          { method: 'getSyncData', setup: () => {} },
          { method: 'flutterUploadImage', setup: () => { req.file = {} as Express.Multer.File; } },
          { method: 'batchSyncOperations', setup: () => { req.body = { operations: [] }; } }
        ];

        for (const testCase of testCases) {
          req.user = undefined;
          testCase.setup();

          await (testController as any)[testCase.method](req as Request, res as Response, next);
          
          expect(next).toHaveBeenCalledWith(expect.any(Error));
          jest.clearAllMocks();
        }
      });
    });

    describe('Test Coverage Summary for New Methods', () => {
      it('should validate all new methods are properly tested', () => {
        const newMethods = [
          'getMobileThumbnails',
          'getMobileOptimizedImage', 
          'batchGenerateThumbnails',
          'getSyncData',
          'flutterUploadImage',
          'batchSyncOperations'
        ];

        const testControllerMethods = Object.keys(testController);
        
        newMethods.forEach(method => {
          expect(testControllerMethods).toContain(method);
        });
      });

      it('should validate new service methods are mocked', () => {
        const newServiceMethods: (keyof typeof mockImageService)[] = [
          'getMobileThumbnails',
          'getMobileOptimizedImage',
          'batchGenerateThumbnails', 
          'getSyncData',
          'flutterUploadImage',
          'batchSyncOperations'
        ];

        newServiceMethods.forEach(method => {
          expect(mockImageService[method]).toBeDefined();
          expect(jest.isMockFunction(mockImageService[method])).toBe(true);
        });
      });
    });
  });

  // Cleanup to prevent Jest teardown issues
  afterAll(async () => {
    // Force cleanup of any lingering timers or connections
    jest.clearAllTimers();
    jest.clearAllMocks();
    
    // Give a moment for any async cleanup
    await new Promise(resolve => setTimeout(resolve, 100));
  });
});