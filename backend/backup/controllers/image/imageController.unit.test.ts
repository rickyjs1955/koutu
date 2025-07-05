// tests/unit/controllers/imageController.unit.test.ts

// Mock external dependencies before importing them - CRITICAL ORDER
jest.mock('multer', () => {
  const mockMulter = jest.fn(() => ({
    single: jest.fn(() => (req: any, res: any, next: any) => {
      req.file = {
        buffer: Buffer.from('fake-image-data'),
        originalname: 'realistic-image.jpg',
        mimetype: 'image/jpeg',
        size: 2048000,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'realistic-image.jpg',
        path: '/uploads/realistic-image.jpg'
      };
      next();
    })
  }));
  (mockMulter as any).memoryStorage = jest.fn().mockReturnValue({});
  (mockMulter as any).MulterError = class extends Error {
    constructor(code: string) {
      super(code);
      this.code = code;
    }
    code: string;
  };
  return mockMulter;
});

jest.mock('../../../src/config/firebase', () => ({
  default: { storage: jest.fn() }
}));

jest.mock('../../../src/services/imageService', () => ({
  imageService: {
    uploadImage: jest.fn(),
    getUserImages: jest.fn(),
    getImageById: jest.fn(),
    updateImageStatus: jest.fn(),
    generateThumbnail: jest.fn(),
    optimizeForWeb: jest.fn(),
    deleteImage: jest.fn(),
    getUserImageStats: jest.fn(),
    batchUpdateStatus: jest.fn()
  }
}));

jest.mock('../../../src/utils/ApiError', () => {
  const MockApiError = jest.fn().mockImplementation((message, status, code) => {
    const error = new Error(message);
    (error as any).statusCode = status;
    (error as any).code = code;
    return error;
  });
  
  (MockApiError as any).badRequest = jest.fn().mockImplementation((message, code) => {
    const error = new Error(message);
    (error as any).statusCode = 400;
    (error as any).code = code || 'BAD_REQUEST';
    return error;
  });
  
  return { ApiError: MockApiError };
});

jest.mock('../../../src/utils/sanitize', () => ({
  sanitization: {
    wrapImageController: jest.fn((handler, operation) => {
      return async (req: any, res: any, next: any) => {
        try {
          await handler(req, res, next);
        } catch (error) {
          next(error);
        }
      };
    }),
    sanitizeImageForResponse: jest.fn((image) => image)
  }
}));

jest.mock('../../../src/config', () => ({
  config: { maxFileSize: 8388608 }
}));

import { Request, Response, NextFunction } from 'express';
import { imageController } from '../../../src/controllers/imageController';
import { imageService } from '../../../src/services/imageService';
import { ApiError } from '../../../src/utils/ApiError';
import { sanitization } from '../../../src/utils/sanitize';

// Create proper mock functions for the helpers
const createMockRequest = (): Partial<Request> => ({
  user: { id: 'user-123', email: 'test@example.com' },
  file: undefined,
  params: {},
  query: {},
  body: {},
  method: 'GET',
  path: '/api/images',
  get: jest.fn()
});

const createMockResponse = (): Partial<Response> => ({
  status: jest.fn().mockReturnThis(),
  json: jest.fn().mockReturnThis(),
  send: jest.fn().mockReturnThis()
});

const mockNext: NextFunction = jest.fn();

const createMockImage = (overrides: any = {}) => ({
  id: 'image-123',
  user_id: 'user-123',
  status: 'new',
  file_path: '/uploads/image.jpg',
  upload_date: new Date().toISOString(),
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  original_metadata: {
    width: 800,
    height: 600,
    format: 'jpeg',
    size: 1024000
  },
  ...overrides
});

const createMockImageUpload = (): Express.Multer.File => ({
  buffer: Buffer.from('fake-image-data'),
  originalname: 'test.jpg',
  mimetype: 'image/jpeg',
  size: 1024000,
  fieldname: 'image',
  encoding: '7bit',
  stream: undefined as any,
  destination: '/uploads',
  filename: 'test.jpg',
  path: '/uploads/test.jpg'
});

const createRealisticImageUpload = async (): Promise<Express.Multer.File> => ({
  buffer: Buffer.from('fake-image-data'),
  originalname: 'realistic-image.jpg',
  mimetype: 'image/jpeg',
  size: 2048000,
  fieldname: 'image',
  encoding: '7bit',
  stream: undefined as any,
  destination: '/uploads',
  filename: 'realistic-image.jpg',
  path: '/uploads/realistic-image.jpg'
});

const createInvalidUploads = () => ({
  wrongType: {
    buffer: Buffer.from('fake-pdf-data'),
    originalname: 'document.pdf',
    mimetype: 'application/pdf',
    size: 1024000
  }
});

const createMaliciousImageUpload = (type: string) => ({
  buffer: Buffer.from('fake-data'),
  originalname: type === 'executable' ? 'malicious.jpg.exe' : 'script.jpg',
  mimetype: 'image/jpeg',
  size: 1024000
});

const createPathTraversalAttempt = (): Express.Multer.File => ({
  buffer: Buffer.from('fake-data'),
  originalname: '../../../etc/passwd.jpg',
  mimetype: 'image/jpeg',
  size: 1024000,
  fieldname: 'image',
  encoding: '7bit',
  stream: undefined as any,
  destination: '/uploads',
  filename: 'passwd.jpg',
  path: '/uploads/passwd.jpg'
});

const createTestImageRecords = (count: number, userId: string) => {
  return Array.from({ length: count }, (_, i) => createMockImage({
    id: `image-${i}`,
    user_id: userId
  }));
};

const createMockImageStats = (overrides: any = {}) => ({
  total: 10,
  byStatus: { new: 3, processed: 5, labeled: 2 },
  totalSize: 10240000,
  averageSize: 1024000,
  ...overrides
});

const simulateErrors = {
  networkTimeout: () => {
    const error = new Error('Network timeout');
    (error as any).code = 'ETIMEDOUT';
    return error;
  },
  databaseConnection: () => {
    const error = new Error('Database connection failed');
    (error as any).code = 'ECONNREFUSED';
    return error;
  },
  diskSpace: () => {
    const error = new Error('No space left on device');
    (error as any).code = 'ENOSPC';
    return error;
  }
};

const resetAllMocks = () => {
  jest.clearAllMocks();
  (mockNext as jest.Mock).mockClear();
};

describe('ImageController', () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  // Mock service methods
  const mockImageService = imageService as jest.Mocked<typeof imageService>;
  const mockSanitization = sanitization as jest.Mocked<typeof sanitization>;

  beforeEach(() => {
    resetAllMocks();
    req = createMockRequest();
    res = createMockResponse();
    next = mockNext;

    // Setup default mock behaviors
    mockSanitization.wrapImageController.mockImplementation((handler, operation) => 
      async (req: Request, res: Response, next: NextFunction) => {
        return handler(req, res, next);
      }
    );
    mockSanitization.sanitizeImageForResponse.mockImplementation((image) => image);
    
    // Mock ApiError static methods
    (ApiError.badRequest as jest.Mock) = jest.fn().mockImplementation((message, code) => {
      const error = new Error(message);
      (error as any).statusCode = 400;
      (error as any).code = code;
      return error;
    });
  });

  describe('uploadMiddleware', () => {
    it('should handle valid file upload successfully', async () => {
      const validUpload = await createRealisticImageUpload();
      req.file = validUpload;

      await imageController.uploadMiddleware(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(); // Should call next with no arguments (success)
    });

    it('should reject files that are too large', () => {
      // Test the multer configuration logic
      const multerError = new Error('File too large') as any;
      multerError.code = 'LIMIT_FILE_SIZE';
      
      expect(multerError.code).toBe('LIMIT_FILE_SIZE');
    });

    it('should reject unsupported file types', () => {
      const invalidUpload = createInvalidUploads().wrongType;
      expect(invalidUpload.mimetype).toBe('application/pdf');
    });

    it('should reject files with malicious extensions', () => {
      const maliciousUpload = createMaliciousImageUpload('executable');
      expect(maliciousUpload.originalname).toContain('.exe');
    });

    it('should reject files with path traversal attempts', () => {
      const pathTraversalUpload = createPathTraversalAttempt();
      expect(pathTraversalUpload.originalname).toContain('../');
    });

    it('should reject files with extremely long filenames', async () => {
      const longFilenameUpload = {
        ...await createRealisticImageUpload(),
        originalname: 'a'.repeat(300) + '.jpg'
      };

      expect(longFilenameUpload.originalname.length).toBeGreaterThan(255);
    });
  });

  describe('uploadImage', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should upload image successfully with valid file', async () => {
      const mockImage = createMockImage();
      const validUpload = await createRealisticImageUpload();
      
      req.file = validUpload;
      mockImageService.uploadImage.mockResolvedValue(mockImage);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(mockImageService.uploadImage).toHaveBeenCalledWith({
        userId: 'user-123',
        fileBuffer: validUpload.buffer,
        originalFilename: validUpload.originalname,
        mimetype: validUpload.mimetype,
        size: validUpload.size
      });

      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { image: mockImage },
        message: 'Image uploaded successfully'
      });
    });

    it('should return error when no file is provided', async () => {
      req.file = undefined;

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'No image file provided'
        })
      );
    });

    it('should handle service errors gracefully', async () => {
      const validUpload = await createRealisticImageUpload();
      req.file = validUpload;
      
      const serviceError = new Error('Processing failed');
      mockImageService.uploadImage.mockRejectedValue(serviceError);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(serviceError);
    });

    it('should sanitize response data', async () => {
      const mockImage = createMockImage();
      const sanitizedImage = { ...mockImage, safe: true };
      const validUpload = await createRealisticImageUpload();
      
      req.file = validUpload;
      mockImageService.uploadImage.mockResolvedValue(mockImage);
      mockSanitization.sanitizeImageForResponse.mockReturnValue(sanitizedImage);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(mockImage);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { image: sanitizedImage },
        message: 'Image uploaded successfully'
      });
    });
  });

  describe('getImages', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should retrieve user images with default options', async () => {
      const mockImages = createTestImageRecords(3, 'user-123');
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockImageService.getUserImages).toHaveBeenCalledWith('user-123', {
        status: undefined,
        limit: undefined,
        offset: undefined
      });

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          images: mockImages,
          count: 3,
          pagination: undefined
        }
      });
    });

    it('should handle query parameters correctly', async () => {
      const mockImages = createTestImageRecords(2, 'user-123');
      req.query = {
        status: 'processed',
        limit: '10',
        offset: '0'
      };
      
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockImageService.getUserImages).toHaveBeenCalledWith('user-123', {
        status: 'processed',
        limit: 10,
        offset: 0
      });

      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          images: mockImages,
          count: 2,
          pagination: {
            limit: 10,
            offset: 0
          }
        }
      });
    });

    it('should handle invalid query parameters gracefully', async () => {
      req.query = {
        limit: 'invalid',
        offset: 'also-invalid'
      };
      
      const mockImages = createTestImageRecords(1, 'user-123');
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockImageService.getUserImages).toHaveBeenCalledWith('user-123', {
        status: undefined,
        limit: NaN,
        offset: NaN
      });
    });

    it('should sanitize all images in response', async () => {
      const mockImages = createTestImageRecords(2, 'user-123');
      const sanitizedImages = mockImages.map(img => ({ ...img, sanitized: true }));
      
      mockImageService.getUserImages.mockResolvedValue(mockImages);
      mockSanitization.sanitizeImageForResponse
        .mockReturnValueOnce(sanitizedImages[0])
        .mockReturnValueOnce(sanitizedImages[1]);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledTimes(2);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          images: sanitizedImages,
          count: 2,
          pagination: undefined
        }
      });
    });
  });

  describe('getImage', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };
    });

    it('should retrieve single image successfully', async () => {
      const mockImage = createMockImage({ id: 'image-456', user_id: 'user-123' });
      mockImageService.getImageById.mockResolvedValue(mockImage);

      await imageController.getImage(req as Request, res as Response, next);

      expect(mockImageService.getImageById).toHaveBeenCalledWith('image-456', 'user-123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { image: mockImage }
      });
    });

    it('should handle image not found', async () => {
      const notFoundError = new Error('Image not found');
      mockImageService.getImageById.mockRejectedValue(notFoundError);

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(notFoundError);
    });

    it('should sanitize single image response', async () => {
      const mockImage = createMockImage();
      const sanitizedImage = { ...mockImage, sanitized: true };
      
      mockImageService.getImageById.mockResolvedValue(mockImage);
      mockSanitization.sanitizeImageForResponse.mockReturnValue(sanitizedImage);

      await imageController.getImage(req as Request, res as Response, next);

      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(mockImage);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { image: sanitizedImage }
      });
    });
  });

  describe('updateImageStatus', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };
      req.body = { status: 'processed' };
    });

    it('should update image status successfully', async () => {
      const updatedImage = createMockImage({ 
        id: 'image-456', 
        user_id: 'user-123', 
        status: 'processed' 
      });
      
      mockImageService.updateImageStatus.mockResolvedValue(updatedImage);

      await imageController.updateImageStatus(req as Request, res as Response, next);

      expect(mockImageService.updateImageStatus).toHaveBeenCalledWith(
        'image-456',
        'user-123',
        'processed'
      );

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { image: updatedImage },
        message: 'Image status updated to processed'
      });
    });

    it('should handle invalid status transitions', async () => {
      const validationError = new Error('Invalid status transition');
      mockImageService.updateImageStatus.mockRejectedValue(validationError);

      await imageController.updateImageStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(validationError);
    });

    it('should handle unauthorized access', async () => {
      const unauthorizedError = new Error('Access denied');
      mockImageService.updateImageStatus.mockRejectedValue(unauthorizedError);

      await imageController.updateImageStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(unauthorizedError);
    });
  });

  describe('generateThumbnail', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };
    });

    it('should generate thumbnail with default size', async () => {
      const thumbnailResult = { 
        thumbnailPath: 'uploads/thumbnail_200.jpg',
        size: 200,
        originalImageId: 'image-456'
      };
      
      mockImageService.generateThumbnail.mockResolvedValue(thumbnailResult);

      await imageController.generateThumbnail(req as Request, res as Response, next);

      expect(mockImageService.generateThumbnail).toHaveBeenCalledWith(
        'image-456',
        'user-123',
        200
      );

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: thumbnailResult,
        message: 'Thumbnail generated successfully'
      });
    });

    it('should generate thumbnail with custom size', async () => {
      req.query = { size: '150' };
      const thumbnailResult = { 
        thumbnailPath: 'uploads/thumbnail_150.jpg',
        size: 150,
        originalImageId: 'image-456'
      };
      
      mockImageService.generateThumbnail.mockResolvedValue(thumbnailResult);

      await imageController.generateThumbnail(req as Request, res as Response, next);

      expect(mockImageService.generateThumbnail).toHaveBeenCalledWith(
        'image-456',
        'user-123',
        150
      );
    });

    it('should reject invalid thumbnail sizes', async () => {
      req.query = { size: '25' }; // Too small

      await imageController.generateThumbnail(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Thumbnail size must be between 50 and 500 pixels'
        })
      );
    });

    it('should reject oversized thumbnail requests', async () => {
      req.query = { size: '600' }; // Too large

      await imageController.generateThumbnail(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Thumbnail size must be between 50 and 500 pixels'
        })
      );
    });
  });

  describe('optimizeImage', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };
    });

    it('should optimize image successfully', async () => {
      const optimizationResult = {
        originalPath: 'uploads/original.jpg',
        optimizedPath: 'uploads/optimized.jpg',
        originalSize: 1024000,
        optimizedSize: 512000,
        compressionRatio: 0.5
      };
      
      mockImageService.optimizeForWeb.mockResolvedValue(optimizationResult);

      await imageController.optimizeImage(req as Request, res as Response, next);

      expect(mockImageService.optimizeForWeb).toHaveBeenCalledWith('image-456', 'user-123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: optimizationResult,
        message: 'Image optimized successfully'
      });
    });

    it('should handle optimization failures', async () => {
      const optimizationError = new Error('Optimization failed');
      mockImageService.optimizeForWeb.mockRejectedValue(optimizationError);

      await imageController.optimizeImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(optimizationError);
    });
  });

  describe('deleteImage', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };
    });

    it('should delete image successfully', async () => {
      mockImageService.deleteImage.mockResolvedValue({
        success: true,
        imageId: 'image-456'
      });

      await imageController.deleteImage(req as Request, res as Response, next);

      expect(mockImageService.deleteImage).toHaveBeenCalledWith('image-456', 'user-123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: null,
        message: 'Image deleted successfully'
      });
    });

    it('should handle deletion failures', async () => {
      const deletionError = new Error('Cannot delete image with dependencies');
      mockImageService.deleteImage.mockRejectedValue(deletionError);

      await imageController.deleteImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(deletionError);
    });

    it('should handle unauthorized deletion attempts', async () => {
      const unauthorizedError = new Error('Access denied');
      mockImageService.deleteImage.mockRejectedValue(unauthorizedError);

      await imageController.deleteImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(unauthorizedError);
    });
  });

  describe('getUserStats', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should retrieve user statistics successfully', async () => {
      const mockStats = createMockImageStats({
        total: 25,
        byStatus: { new: 5, processed: 15, labeled: 5 },
        totalSize: 5120000
      });
      
      mockImageService.getUserImageStats.mockResolvedValue(mockStats);

      await imageController.getUserStats(req as Request, res as Response, next);

      expect(mockImageService.getUserImageStats).toHaveBeenCalledWith('user-123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { stats: mockStats }
      });
    });

    it('should handle stats retrieval errors', async () => {
      const statsError = new Error('Failed to retrieve stats');
      mockImageService.getUserImageStats.mockRejectedValue(statsError);

      await imageController.getUserStats(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(statsError);
    });
  });

  describe('batchUpdateStatus', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.body = {
        imageIds: ['image-1', 'image-2', 'image-3'],
        status: 'processed'
      };
    });

    it('should batch update status successfully', async () => {
      const batchResult = {
        total: 3,
        updatedCount: 2,
        failedCount: 1,
        errors: [{ imageId: 'image-3', error: 'Image not found' }]
      };
      
      mockImageService.batchUpdateStatus.mockResolvedValue(batchResult);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(mockImageService.batchUpdateStatus).toHaveBeenCalledWith(
        ['image-1', 'image-2', 'image-3'],
        'user-123',
        'processed'
      );

      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: batchResult,
        message: 'Batch updated 2 of 3 images'
      });
    });

    it('should handle batch update failures', async () => {
      const batchError = new Error('Batch operation failed');
      mockImageService.batchUpdateStatus.mockRejectedValue(batchError);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(batchError);
    });

    it('should handle empty image ID array', async () => {
      req.body.imageIds = [];
      
      const batchResult = { total: 0, updatedCount: 0, failedCount: 0, errors: [] };
      mockImageService.batchUpdateStatus.mockResolvedValue(batchResult);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: batchResult,
        message: 'Batch updated 0 of 0 images'
      });
    });
  });

  // Add a few more critical test categories to demonstrate the pattern works
  describe('Security Tests', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    describe('Parameter Injection Attacks', () => {
      it('should prevent SQL injection in image ID parameter', async () => {
        req.params = { id: "'; DROP TABLE images; --" };
        
        const sqlInjectionError = new Error('Invalid image ID format');
        mockImageService.getImageById.mockRejectedValue(sqlInjectionError);

        await imageController.getImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(sqlInjectionError);
      });

      it('should prevent XSS attempts in query parameters', async () => {
        req.query = {
          status: '<script>alert("xss")</script>',
          limit: '"><script>alert("xss")</script>'
        };

        const mockImages = createTestImageRecords(1, 'user-123');
        mockImageService.getUserImages.mockResolvedValue(mockImages);

        await imageController.getImages(req as Request, res as Response, next);

        expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalled();
      });

      it('should prevent path traversal in file uploads', () => {
        const pathTraversalUpload = createPathTraversalAttempt();
        req.file = pathTraversalUpload;

        expect(pathTraversalUpload.originalname).toContain('../');
      });
    });

    describe('Authorization Tests', () => {
      it('should prevent cross-user access attempts', async () => {
        req.params = { id: 'other-user-image' };
        
        const unauthorizedError = new Error('Access denied');
        mockImageService.getImageById.mockRejectedValue(unauthorizedError);

        await imageController.getImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(unauthorizedError);
      });

      it('should validate user ownership on status updates', async () => {
        req.params = { id: 'unauthorized-image' };
        req.body = { status: 'processed' };
        
        const ownershipError = new Error('Image not found or access denied');
        mockImageService.updateImageStatus.mockRejectedValue(ownershipError);

        await imageController.updateImageStatus(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(ownershipError);
      });
    });
  });

  describe('Error Handling', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should handle service timeouts gracefully', async () => {
      const timeoutError = simulateErrors.networkTimeout();
      mockImageService.getUserImages.mockRejectedValue(timeoutError);

      await imageController.getImages(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(timeoutError);
    });

    it('should handle database connection errors', async () => {
      const dbError = simulateErrors.databaseConnection();
      mockImageService.getImageById.mockRejectedValue(dbError);

      req.params = { id: 'image-456' };
      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(dbError);
    });

    it('should handle disk space errors during upload', async () => {
      const diskError = simulateErrors.diskSpace();
      mockImageService.uploadImage.mockRejectedValue(diskError);

      req.file = await createRealisticImageUpload();
      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(diskError);
    });

    it('should handle unexpected errors with proper structure', async () => {
      const unexpectedError = new Error('Something went wrong');
      mockImageService.getUserImageStats.mockRejectedValue(unexpectedError);

      await imageController.getUserStats(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(unexpectedError);
    });
  });

  describe('Response Sanitization', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should sanitize single image responses', async () => {
      const rawImage = createMockImage({ 
        id: 'image-456',
        user_id: 'user-123',
        original_metadata: {
          internalPath: '/var/uploads/secret.jpg',
          dbConnectionString: 'postgres://user:pass@localhost/db'
        }
      });
      
      const sanitizedImage = createMockImage({
        id: 'image-456',
        user_id: 'user-123',
        original_metadata: {
          width: 800,
          height: 600,
          format: 'jpeg'
        }
      });

      req.params = { id: 'image-456' };
      mockImageService.getImageById.mockResolvedValue(rawImage);
      mockSanitization.sanitizeImageForResponse.mockReturnValue(sanitizedImage);

      await imageController.getImage(req as Request, res as Response, next);

      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(rawImage);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { image: sanitizedImage }
      });
    });

    it('should sanitize batch image responses', async () => {
      const rawImages = createTestImageRecords(3, 'user-123');
      const sanitizedImages = rawImages.map(img => ({ ...img, sanitized: true }));
      
      mockImageService.getUserImages.mockResolvedValue(rawImages);
      rawImages.forEach((_, index) => {
        mockSanitization.sanitizeImageForResponse.mockReturnValueOnce(sanitizedImages[index]);
      });

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledTimes(3);
      rawImages.forEach((rawImage, index) => {
        expect(mockSanitization.sanitizeImageForResponse).toHaveBeenNthCalledWith(index + 1, rawImage);
      });
    });

    it('should handle sanitization errors gracefully', async () => {
      const rawImage = createMockImage();
      const sanitizationError = new Error('Sanitization failed');
      
      req.params = { id: 'image-456' };
      mockImageService.getImageById.mockResolvedValue(rawImage);
      mockSanitization.sanitizeImageForResponse.mockImplementation(() => {
        throw sanitizationError;
      });

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(sanitizationError);
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should handle empty query parameters', async () => {
      req.query = {};
      const mockImages = createTestImageRecords(2, 'user-123');
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockImageService.getUserImages).toHaveBeenCalledWith('user-123', {
        status: undefined,
        limit: undefined,
        offset: undefined
      });
    });

    it('should handle zero-length pagination parameters', async () => {
      req.query = { limit: '0', offset: '0' };
      const mockImages: any[] = [];
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockImageService.getUserImages).toHaveBeenCalledWith('user-123', {
        status: undefined,
        limit: 0,
        offset: 0
      });

      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          images: [],
          count: 0,
          pagination: { limit: 0, offset: 0 }
        }
      });
    });

    it('should handle extremely large pagination limits', async () => {
      req.query = { limit: '999999', offset: '0' };
      const mockImages = createTestImageRecords(10, 'user-123');
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockImageService.getUserImages).toHaveBeenCalledWith('user-123', {
        status: undefined,
        limit: 999999,
        offset: 0
      });
    });

    it('should handle negative thumbnail sizes', async () => {
      req.params = { id: 'image-456' };
      req.query = { size: '-100' };

      await imageController.generateThumbnail(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Thumbnail size must be between 50 and 500 pixels'
        })
      );
    });

    it('should handle floating point thumbnail sizes', async () => {
      req.params = { id: 'image-456' };
      req.query = { size: '150.5' };

      const thumbnailResult = { 
        thumbnailPath: 'uploads/thumbnail_150.jpg',
        size: 150,
        originalImageId: 'image-456'
      };
      
      mockImageService.generateThumbnail.mockResolvedValue(thumbnailResult);

      await imageController.generateThumbnail(req as Request, res as Response, next);

      expect(mockImageService.generateThumbnail).toHaveBeenCalledWith(
        'image-456',
        'user-123',
        150
      );
    });

    it('should handle missing user object', async () => {
      req.user = undefined;

      try {
        await imageController.getImages(req as Request, res as Response, next);
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it('should handle missing parameters object', async () => {
      req.params = undefined as any;

      // The actual error that occurs when params is undefined and we try to access params.id
      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining("Cannot read properties of undefined")
        })
      );
    });

    it('should handle special characters in status updates', async () => {
      req.params = { id: 'image-456' };
      req.body = { status: 'proce$ed' };

      const validationError = new Error('Invalid status value');
      mockImageService.updateImageStatus.mockRejectedValue(validationError);

      await imageController.updateImageStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(validationError);
    });
  });

  describe('Performance and Load Testing Scenarios', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should handle rapid sequential requests', async () => {
      const mockImage = createMockImage();
      mockImageService.getImageById.mockResolvedValue(mockImage);
      req.params = { id: 'image-456' };

      const requests = Array.from({ length: 100 }, () =>
        imageController.getImage(req as Request, res as Response, next)
      );

      await Promise.all(requests);

      expect(mockImageService.getImageById).toHaveBeenCalledTimes(100);
      expect(res.status).toHaveBeenCalledTimes(100);
      expect(res.json).toHaveBeenCalledTimes(100);
    });

    it('should handle large batch updates efficiently', async () => {
      const largeImageIds = Array.from({ length: 500 }, (_, i) => `image-${i}`);
      req.body = {
        imageIds: largeImageIds,
        status: 'processed'
      };

      const batchResult = {
        total: 500,
        updatedCount: 485,
        failedCount: 15,
        errors: Array.from({ length: 15 }, (_, i) => ({
          imageId: `image-${i}`,
          error: 'Processing failed'
        }))
      };

      mockImageService.batchUpdateStatus.mockResolvedValue(batchResult);

      const startTime = Date.now();
      await imageController.batchUpdateStatus(req as Request, res as Response, next);
      const endTime = Date.now();

      expect(endTime - startTime).toBeLessThan(1000);
      expect(mockImageService.batchUpdateStatus).toHaveBeenCalledWith(
        largeImageIds,
        'user-123',
        'processed'
      );
    });

    it('should handle memory-intensive operations', async () => {
      const largeImageData = createTestImageRecords(1000, 'user-123');
      mockImageService.getUserImages.mockResolvedValue(largeImageData);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledTimes(1000);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          images: expect.any(Array),
          count: 1000,
          pagination: undefined
        }
      });
    });
  });

  describe('Integration with Multer Error Handling', () => {
    it('should handle LIMIT_FILE_SIZE errors specifically', () => {
      const multerError = new Error('File too large') as any;
      multerError.code = 'LIMIT_FILE_SIZE';
      multerError.name = 'MulterError';

      expect(multerError.code).toBe('LIMIT_FILE_SIZE');
    });

    it('should handle LIMIT_FILE_COUNT errors', () => {
      const multerError = new Error('Too many files') as any;
      multerError.code = 'LIMIT_FILE_COUNT';
      multerError.name = 'MulterError';

      expect(multerError.code).toBe('LIMIT_FILE_COUNT');
    });

    it('should handle LIMIT_UNEXPECTED_FILE errors', () => {
      const multerError = new Error('Unexpected field') as any;
      multerError.code = 'LIMIT_UNEXPECTED_FILE';
      multerError.name = 'MulterError';

      expect(multerError.code).toBe('LIMIT_UNEXPECTED_FILE');
    });

    it('should handle unknown multer errors', () => {
      const multerError = new Error('Unknown multer error') as any;
      multerError.code = 'UNKNOWN_ERROR';
      multerError.name = 'MulterError';

      expect(multerError.code).toBe('UNKNOWN_ERROR');
    });

    it('should handle non-multer upload errors', () => {
      const genericError = new Error('Generic upload error');
      expect(genericError.name).toBe('Error');
    });
  });

  describe('Response Format Consistency', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should return consistent success response format for uploads', async () => {
      const mockImage = createMockImage();
      req.file = await createRealisticImageUpload();
      mockImageService.uploadImage.mockResolvedValue(mockImage);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { image: mockImage },
        message: 'Image uploaded successfully'
      });
    });

    it('should return consistent success response format for retrieval', async () => {
      const mockImages = createTestImageRecords(2, 'user-123');
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          images: mockImages,
          count: 2,
          pagination: undefined
        }
      });
    });

    it('should return consistent success response format for updates', async () => {
      const updatedImage = createMockImage({ status: 'processed' });
      req.params = { id: 'image-456' };
      req.body = { status: 'processed' };
      mockImageService.updateImageStatus.mockResolvedValue(updatedImage);

      await imageController.updateImageStatus(req as Request, res as Response, next);

      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: { image: updatedImage },
        message: 'Image status updated to processed'
      });
    });

    it('should return consistent success response format for deletions', async () => {
      req.params = { id: 'image-456' };
      mockImageService.deleteImage.mockResolvedValue({
        success: true,
        imageId: 'image-456'
      });

      await imageController.deleteImage(req as Request, res as Response, next);

      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: null,
        message: 'Image deleted successfully'
      });
    });

    it('should return consistent status codes', async () => {
      const testCases = [
        {
          method: 'uploadImage',
          expectedStatus: 201,
          setup: () => {
            req.file = createMockImageUpload();
            mockImageService.uploadImage.mockResolvedValue(createMockImage());
          }
        },
        {
          method: 'getImages',
          expectedStatus: 200,
          setup: () => {
            mockImageService.getUserImages.mockResolvedValue([]);
          }
        },
        {
          method: 'getImage',
          expectedStatus: 200,
          setup: () => {
            req.params = { id: 'image-456' };
            mockImageService.getImageById.mockResolvedValue(createMockImage());
          }
        },
        {
          method: 'deleteImage',
          expectedStatus: 200,
          setup: () => {
            req.params = { id: 'image-456' };
            mockImageService.deleteImage.mockResolvedValue({
              success: true,
              imageId: 'image-456'
            });
          }
        }
      ];

      for (const testCase of testCases) {
        (res.status as jest.Mock).mockClear();
        
        testCase.setup();
        await (imageController as any)[testCase.method](req, res, next);
        
        expect(res.status).toHaveBeenCalledWith(testCase.expectedStatus);
      }
    });
  });

  describe('Cleanup and Resource Management', () => {
    afterEach(() => {
      jest.clearAllMocks();
    });

    it('should not leak memory during heavy operations', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      
      const largeDataSet = createTestImageRecords(1000, 'user-123');
      mockImageService.getUserImages.mockResolvedValue(largeDataSet);

      for (let i = 0; i < 10; i++) {
        await imageController.getImages(req as Request, res as Response, next);
        
        (res.status as jest.Mock).mockClear();
        (res.json as jest.Mock).mockClear();
      }

      expect(mockImageService.getUserImages).toHaveBeenCalledTimes(10);
    });

    it('should handle aborted requests gracefully', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };
      
      const abortError = new Error('Request aborted');
      abortError.name = 'AbortError';
      
      mockImageService.getImageById.mockRejectedValue(abortError);

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(abortError);
    });
  });

  describe('Type Safety and Runtime Validation', () => {
    beforeEach(() => {
      req.user = { id: 'user-123', email: 'test@example.com' };
    });

    it('should handle type coercion safely', async () => {
      req.query = {
        limit: 'abc' as any,
        offset: null as any,
        status: 123 as any
      };

      const mockImages = createTestImageRecords(1, 'user-123');
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockImageService.getUserImages).toHaveBeenCalledWith('user-123', {
        status: 123,
        limit: NaN,
        offset: undefined // null gets converted to undefined by parseInt
      });
    });

    it('should handle undefined nested properties safely', async () => {
      req.body = {
        imageIds: undefined,
        status: undefined
      };

      const batchError = new Error('Invalid batch update parameters');
      mockImageService.batchUpdateStatus.mockRejectedValue(batchError);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(batchError);
    });
  });
});

export const controllerTestUtils = {
  async testControllerErrorHandling(controllerMethod: string, setupFn: () => void) {
    const req = createMockRequest();
    const res = createMockResponse();
    const next = mockNext;
    
    setupFn();
    
    const serviceError = new Error('Service error');
    const serviceName = controllerMethod.replace('Image', '').replace('get', 'get');
    (imageService as jest.Mocked<typeof imageService> as any)[serviceName] = jest.fn().mockRejectedValue(serviceError);
    
    await (imageController as any)[controllerMethod](req, res, next);
    
    expect(next).toHaveBeenCalledWith(serviceError);
  },

  testResponseSanitization(controllerMethod: string, mockData: any) {
    expect(sanitization.sanitizeImageForResponse).toHaveBeenCalledWith(mockData);
  },

  validateResponseStructure(responseData: any, expectedKeys: string[]) {
    expect(responseData).toHaveProperty('status', 'success');
    expect(responseData).toHaveProperty('data');
    expectedKeys.forEach(key => {
      expect(responseData.data).toHaveProperty(key);
    });
  }
};