// src/tests/unit/imageController.flutter.test.ts - Flutter-Compatible Unit Tests
import { Request, Response, NextFunction } from 'express';
import { imageController } from '../../controllers/imageController';
import { imageService } from '../../services/imageService';
import { sanitization } from '../../utils/sanitize';
import { EnhancedApiError } from '../../middlewares/errorHandler';
import { config } from '../../config';
import {
  createMockImage,
  createMockImageUpload,
  MockImage,
  MockImageUpload
} from '../__mocks__/images.mock';
import {
  createTestImageBuffer,
  validateImageBuffer
} from '../__helpers__/images.helper';

// Type definitions for better type safety
interface User {
  id: string;
  email: string;
}

interface AuthenticatedRequest extends Request {
  user: User;
  file?: Express.Multer.File;
}

interface FlutterResponseMethods {
  created: jest.Mock;
  success: jest.Mock;
  successWithPagination: jest.Mock;
  status: jest.Mock;
  json: jest.Mock;
  send: jest.Mock;
}

// Mock external dependencies
jest.mock('../../services/imageService');
jest.mock('../../utils/sanitize');
jest.mock('../../config', () => ({
  config: {
    maxFileSize: 8388608 // 8MB
  }
}));

// Mock Sharp to avoid runtime issues in tests
jest.mock('sharp', () => {
  return jest.fn().mockImplementation(() => ({
    metadata: jest.fn().mockResolvedValue({
      width: 1000,
      height: 800,
      format: 'jpeg'
    }),
    resize: jest.fn().mockReturnThis(),
    jpeg: jest.fn().mockReturnThis(),
    png: jest.fn().mockReturnThis(),
    webp: jest.fn().mockReturnThis(),
    toBuffer: jest.fn().mockResolvedValue(Buffer.alloc(1024)),
    toFile: jest.fn().mockResolvedValue({ size: 1024 })
  }));
});

// Mock database connections to prevent teardown issues
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

// Test Configuration
const TEST_CONFIG = {
  TIMEOUT: 10000,
  PERFORMANCE_THRESHOLDS: {
    UPLOAD: 200,
    GET: 50,
    UPDATE: 100,
    DELETE: 100,
    THUMBNAIL: 150,
    OPTIMIZE: 200
  },
  MAX_FILE_SIZE: 8388608, // 8MB
  SUPPORTED_FORMATS: ['image/jpeg', 'image/png', 'image/bmp']
};

describe('ImageController - Flutter-Compatible Unit Tests', () => {
  let mockRequest: Partial<AuthenticatedRequest>;
  let mockResponse: Partial<Response> & FlutterResponseMethods;
  let mockNext: jest.MockedFunction<NextFunction>;
  let testUser: User;
  let testImage: MockImage;

  // Global Setup
  beforeAll(() => {
    jest.setTimeout(TEST_CONFIG.TIMEOUT);
  });

  // Test Setup
  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Create test user
    testUser = {
      id: 'test-user-123',
      email: 'test@example.com'
    };

    // Create test image
    testImage = createMockImage({
      user_id: testUser.id,
      status: 'new'
    });

    // Setup mock request
    mockRequest = {
      user: testUser,
      params: {},
      query: {},
      body: {},
      get: jest.fn().mockReturnValue('Flutter/Test-Agent')
    };

    // Setup mock response with Flutter-specific methods
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      created: jest.fn().mockReturnThis(),
      success: jest.fn().mockReturnThis(),
      successWithPagination: jest.fn().mockReturnThis()
    };

    // Setup mock next function
    mockNext = jest.fn();

    // Setup sanitization mocks
    mockSanitization.wrapImageController = jest.fn().mockImplementation((handler) => handler);
    mockSanitization.sanitizeImageForResponse = jest.fn().mockImplementation((image) => image);
  });

  afterEach(() => {
    jest.clearAllTimers();
  });

  describe('Upload Image - Flutter Optimized', () => {
    beforeEach(() => {
      mockImageService.uploadImage = jest.fn().mockResolvedValue(testImage);
    });

    it('should upload image successfully with Flutter metadata', async () => {
      const mockFile = createMockImageUpload({
        originalname: 'flutter-test.jpg',
        mimetype: 'image/jpeg',
        size: 1024000
      });

      mockRequest.file = mockFile as Express.Multer.File;

      await imageController.uploadImage(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockImageService.uploadImage).toHaveBeenCalledWith({
        userId: testUser.id,
        fileBuffer: mockFile.buffer,
        originalFilename: mockFile.originalname,
        mimetype: mockFile.mimetype,
        size: mockFile.size
      });

      expect(mockResponse.created).toHaveBeenCalledWith(
        { image: testImage },
        expect.objectContaining({
          message: 'Image uploaded successfully',
          meta: expect.objectContaining({
            fileSize: mockFile.size,
            fileSizeKB: Math.round(mockFile.size / 1024),
            mimetype: mockFile.mimetype,
            platform: 'flutter'
          })
        })
      );
    });

    it('should detect Flutter user agent and set platform metadata', async () => {
      const mockFile = createMockImageUpload();
      mockRequest.file = mockFile as Express.Multer.File;
      
      (mockRequest.get as jest.Mock).mockReturnValue('Flutter/2.5.0 (iOS)');

      await imageController.uploadImage(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.created).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          meta: expect.objectContaining({
            platform: 'flutter'
          })
        })
      );
    });

    it('should handle web user agent and set platform metadata', async () => {
      const mockFile = createMockImageUpload();
      mockRequest.file = mockFile as Express.Multer.File;
      
      (mockRequest.get as jest.Mock).mockReturnValue('Mozilla/5.0 Chrome/91.0');

      await imageController.uploadImage(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.created).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          meta: expect.objectContaining({
            platform: 'web'
          })
        })
      );
    });

    it('should throw validation error when no file provided', async () => {
      mockRequest.file = undefined;

      await expect(
        imageController.uploadImage(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        )
      ).rejects.toThrow();
    });

    it('should handle large file uploads within limits', async () => {
      const mockFile = createMockImageUpload({
        size: TEST_CONFIG.MAX_FILE_SIZE - 1000 // Just under the limit
      });
      mockRequest.file = mockFile as Express.Multer.File;

      await imageController.uploadImage(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockImageService.uploadImage).toHaveBeenCalled();
      expect(mockResponse.created).toHaveBeenCalled();
    });
  });

  describe('Get Images - Flutter Optimized Pagination', () => {
    beforeEach(() => {
      const mockImages = [testImage, createMockImage(), createMockImage()];
      mockImageService.getUserImages = jest.fn().mockResolvedValue(mockImages);
    });

    it('should get images with default parameters', async () => {
      await imageController.getImages(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockImageService.getUserImages).toHaveBeenCalledWith(
        testUser.id,
        {
          status: undefined,
          limit: undefined,
          offset: undefined
        }
      );

      expect(mockResponse.success).toHaveBeenCalledWith(
        expect.any(Array),
        expect.objectContaining({
          message: 'Images retrieved successfully',
          meta: expect.objectContaining({
            count: 3,
            filters: expect.any(Object)
          })
        })
      );
    });

    it('should handle pagination parameters for Flutter lists', async () => {
      mockRequest.query = {
        limit: '20',
        offset: '10',
        status: 'processed'
      };

      await imageController.getImages(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockImageService.getUserImages).toHaveBeenCalledWith(
        testUser.id,
        {
          status: 'processed',
          limit: 20,
          offset: 10
        }
      );
    });

    it('should validate limit parameter bounds', async () => {
      mockRequest.query = { limit: '150' }; // Over the limit

      await expect(
        imageController.getImages(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        )
      ).rejects.toThrow();
    });

    it('should validate offset parameter', async () => {
      mockRequest.query = { offset: '-5' }; // Negative offset

      await expect(
        imageController.getImages(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        )
      ).rejects.toThrow();
    });
  });

  describe('Get Single Image - Flutter Optimized', () => {
    beforeEach(() => {
      mockImageService.getImageById = jest.fn().mockResolvedValue(testImage);
    });

    it('should get single image with Flutter metadata', async () => {
      mockRequest.params = { id: testImage.id };

      await imageController.getImage(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockImageService.getImageById).toHaveBeenCalledWith(
        testImage.id,
        testUser.id
      );

      expect(mockResponse.success).toHaveBeenCalledWith(
        { image: testImage },
        expect.objectContaining({
          message: 'Image retrieved successfully',
          meta: expect.objectContaining({
            imageId: testImage.id,
            status: testImage.status
          })
        })
      );
    });
  });

  describe('Update Image Status - Flutter Optimized', () => {
    beforeEach(() => {
      const updatedImage = { ...testImage, status: 'processed' as const };
      mockImageService.getImageById = jest.fn().mockResolvedValue(testImage);
      mockImageService.updateImageStatus = jest.fn().mockResolvedValue(updatedImage);
    });

    it('should update image status with transition metadata', async () => {
      mockRequest.params = { id: testImage.id };
      mockRequest.body = { status: 'processed' };

      await imageController.updateImageStatus(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      expect(mockImageService.updateImageStatus).toHaveBeenCalledWith(
        testImage.id,
        testUser.id,
        'processed'
      );

      expect(mockResponse.success).toHaveBeenCalledWith(
        expect.any(Object),
        expect.objectContaining({
          message: 'Image status updated to processed',
          meta: expect.objectContaining({
            imageId: testImage.id,
            previousStatus: 'new',
            newStatus: 'processed',
            statusChanged: true,
            statusTransition: 'new → processed'
          })
        })
      );
    });
  });

  describe('Mobile-Specific Features', () => {
    describe('Get Mobile Thumbnails', () => {
      beforeEach(() => {
        const mockThumbnails = {
          thumbnails: [
            { id: '1', url: 'thumb1.jpg', size: 'medium' },
            { id: '2', url: 'thumb2.jpg', size: 'medium' }
          ],
          pagination: { page: 1, limit: 20, total: 2 }
        };
        mockImageService.getMobileThumbnails = jest.fn().mockResolvedValue(mockThumbnails);
      });

      it('should get mobile thumbnails with default parameters', async () => {
        await imageController.getMobileThumbnails(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        );

        expect(mockImageService.getMobileThumbnails).toHaveBeenCalledWith(
          testUser.id,
          {
            page: 1,
            limit: 20,
            size: 'medium'
          }
        );

        expect(mockResponse.success).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({
            message: 'Mobile thumbnails retrieved successfully',
            meta: expect.objectContaining({
              platform: 'mobile'
            })
          })
        );
      });

      it('should handle custom thumbnail parameters', async () => {
        mockRequest.query = {
          page: '2',
          limit: '10',
          size: 'large'
        };

        await imageController.getMobileThumbnails(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        );

        expect(mockImageService.getMobileThumbnails).toHaveBeenCalledWith(
          testUser.id,
          {
            page: 2,
            limit: 10,
            size: 'large'
          }
        );
      });
    });

    describe('Get Mobile Optimized Image', () => {
      beforeEach(() => {
        const mockOptimizedImage = {
          id: testImage.id,
          url: 'optimized-mobile.jpg',
          format: 'webp',
          size: { width: 800, height: 600 }
        };
        mockImageService.getMobileOptimizedImage = jest.fn().mockResolvedValue(mockOptimizedImage);
      });

      it('should get mobile optimized image', async () => {
        mockRequest.params = { id: testImage.id };

        await imageController.getMobileOptimizedImage(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        );

        expect(mockImageService.getMobileOptimizedImage).toHaveBeenCalledWith(
          testImage.id,
          testUser.id
        );

        expect(mockResponse.success).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({
            message: 'Mobile optimized image retrieved successfully',
            meta: expect.objectContaining({
              imageId: testImage.id,
              optimizedForMobile: true
            })
          })
        );
      });
    });

    describe('Flutter Upload', () => {
      beforeEach(() => {
        mockImageService.flutterUploadImage = jest.fn().mockResolvedValue(testImage);
      });

      it('should handle Flutter-specific upload', async () => {
        const mockFile = createMockImageUpload({
          originalname: 'flutter-upload.jpg'
        });
        mockRequest.file = mockFile as Express.Multer.File;

        await imageController.flutterUploadImage(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        );

        expect(mockImageService.flutterUploadImage).toHaveBeenCalledWith({
          userId: testUser.id,
          fileBuffer: mockFile.buffer,
          originalFilename: mockFile.originalname,
          mimetype: mockFile.mimetype,
          size: mockFile.size
        });

        expect(mockResponse.created).toHaveBeenCalledWith(
          { image: testImage },
          expect.objectContaining({
            message: 'Flutter upload successful',
            meta: expect.objectContaining({
              platform: 'flutter',
              uploadId: testImage.id,
              processingStatus: 'initiated'
            })
          })
        );
      });
    });

    describe('Sync Operations', () => {
      beforeEach(() => {
        const mockSyncData = {
          images: [testImage],
          deletedIds: [],
          lastSync: new Date().toISOString()
        };
        mockImageService.getSyncData = jest.fn().mockResolvedValue(mockSyncData);

        const mockBatchResult = {
          successCount: 2,
          failedCount: 0,
          conflicts: []
        };
        mockImageService.batchSyncOperations = jest.fn().mockResolvedValue(mockBatchResult);
      });

      it('should get sync data for offline support', async () => {
        mockRequest.query = {
          lastSync: '2023-01-01T00:00:00Z',
          includeDeleted: 'true',
          limit: '50'
        };

        await imageController.getSyncData(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        );

        expect(mockImageService.getSyncData).toHaveBeenCalledWith(
          testUser.id,
          {
            lastSync: '2023-01-01T00:00:00Z',
            includeDeleted: true,
            limit: 50
          }
        );

        expect(mockResponse.success).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({
            message: 'Sync data retrieved successfully',
            meta: expect.objectContaining({
              syncTimestamp: expect.any(String),
              includeDeleted: true
            })
          })
        );
      });

      it('should handle batch sync operations', async () => {
        const operations = [
          { type: 'update', id: '1', data: { status: 'processed' } },
          { type: 'delete', id: '2' }
        ];
        mockRequest.body = { operations };

        await imageController.batchSyncOperations(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        );

        expect(mockImageService.batchSyncOperations).toHaveBeenCalledWith(
          testUser.id,
          operations
        );

        expect(mockResponse.success).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({
            message: 'Processed 2 of 2 sync operations',
            meta: expect.objectContaining({
              operation: 'batch_sync',
              totalOperations: 2,
              successCount: 2,
              failedCount: 0
            })
          })
        );
      });
    });
  });

  describe('Batch Operations', () => {
    describe('Batch Update Status', () => {
      beforeEach(() => {
        const mockBatchResult = {
          total: 3,
          updatedCount: 2,
          failedIds: ['failed-id']
        };
        mockImageService.batchUpdateStatus = jest.fn().mockResolvedValue(mockBatchResult);
      });

      it('should handle batch status updates', async () => {
        const imageIds = ['id1', 'id2', 'id3'];
        mockRequest.body = {
          imageIds,
          status: 'processed'
        };

        await imageController.batchUpdateStatus(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        );

        expect(mockImageService.batchUpdateStatus).toHaveBeenCalledWith(
          imageIds,
          testUser.id,
          'processed'
        );

        expect(mockResponse.success).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({
            message: 'Batch updated 2 of 3 images',
            meta: expect.objectContaining({
              operation: 'batch_update_status',
              targetStatus: 'processed',
              requestedCount: 3,
              successCount: 2,
              failedCount: 1
            })
          })
        );
      });
    });

    describe('Batch Generate Thumbnails', () => {
      beforeEach(() => {
        const mockBatchResult = {
          successCount: 2,
          failedCount: 1,
          results: []
        };
        mockImageService.batchGenerateThumbnails = jest.fn().mockResolvedValue(mockBatchResult);
      });

      it('should handle batch thumbnail generation', async () => {
        const imageIds = ['id1', 'id2', 'id3'];
        const sizes = ['small', 'medium'];
        mockRequest.body = { imageIds, sizes };

        await imageController.batchGenerateThumbnails(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        );

        expect(mockImageService.batchGenerateThumbnails).toHaveBeenCalledWith(
          imageIds,
          testUser.id,
          sizes
        );

        expect(mockResponse.success).toHaveBeenCalledWith(
          expect.any(Object),
          expect.objectContaining({
            message: 'Generated thumbnails for 2 of 3 images',
            meta: expect.objectContaining({
              operation: 'batch_generate_thumbnails',
              requestedCount: 3,
              successCount: 2,
              sizes
            })
          })
        );
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle service errors gracefully', async () => {
      const serviceError = new Error('Database connection failed');
      mockImageService.getUserImages = jest.fn().mockRejectedValue(serviceError);

      await expect(
        imageController.getImages(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        )
      ).rejects.toThrow('Database connection failed');
    });

    it('should handle thumbnail size validation', async () => {
      mockRequest.params = { id: testImage.id };
      mockRequest.query = { size: '600' }; // Over the limit

      await expect(
        imageController.generateThumbnail(
          mockRequest as AuthenticatedRequest,
          mockResponse as Response,
          mockNext
        )
      ).rejects.toThrow();
    });
  });

  describe('Performance Monitoring', () => {
    it('should complete upload within performance threshold', async () => {
      const mockFile = createMockImageUpload();
      mockRequest.file = mockFile as Express.Multer.File;

      const startTime = Date.now();
      
      await imageController.uploadImage(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(TEST_CONFIG.PERFORMANCE_THRESHOLDS.UPLOAD);
    });

    it('should complete get operation within performance threshold', async () => {
      const startTime = Date.now();
      
      await imageController.getImages(
        mockRequest as AuthenticatedRequest,
        mockResponse as Response,
        mockNext
      );

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(TEST_CONFIG.PERFORMANCE_THRESHOLDS.GET);
    });
  });
});