// src/tests/unit/imageService.unit.test.ts

// ===== IMPORT AND SETUP FIREBASE MOCKS FIRST =====
import { 
  MockFirebaseAdmin} from '../__mocks__/firebase.mock';

import {
  setupFirebaseTestEnvironment,
  cleanupFirebaseTests
} from '../__helpers__/firebase.helper';

// Mock Firebase Admin before any other imports
jest.mock('firebase-admin', () => ({
  apps: MockFirebaseAdmin.apps,
  auth: MockFirebaseAdmin.auth,
  storage: MockFirebaseAdmin.storage,
  credential: MockFirebaseAdmin.credential,
  initializeApp: MockFirebaseAdmin.initializeApp
}));

// Mock Sharp
const mockSharp = jest.fn().mockImplementation(() => ({
  metadata: jest.fn().mockResolvedValue({
    width: 800,
    height: 600,
    format: 'jpeg',
    channels: 3,
    space: 'srgb'
  }),
  resize: jest.fn().mockReturnThis(),
  jpeg: jest.fn().mockReturnThis(),
  png: jest.fn().mockReturnThis(),
  toColorspace: jest.fn().mockReturnThis(),
  toFile: jest.fn().mockResolvedValue({ size: 204800 }),
  toBuffer: jest.fn().mockResolvedValue(Buffer.from('mock-data'))
}));

jest.mock('sharp', () => mockSharp);

// Mock config files
jest.mock('../../config/firebase', () => ({
  initializeFirebase: jest.fn(),
  getFirebaseApp: jest.fn(),
  getStorageBucket: jest.fn()
}));

jest.mock('../../models/db', () => ({
  pool: {
    query: jest.fn(),
    connect: jest.fn(),
    end: jest.fn()
  }
}));

// Mock the service dependencies
const mockImageModel = {
  create: jest.fn(),
  findById: jest.fn(),
  findByUserId: jest.fn(),
  updateStatus: jest.fn(),
  updateMetadata: jest.fn(),
  delete: jest.fn(),
  findDependentGarments: jest.fn(),
  findDependentPolygons: jest.fn(),
  getUserImageStats: jest.fn(),
  batchUpdateStatus: jest.fn()
};

const mockImageProcessingService = {
  validateImageBuffer: jest.fn(),
  convertToSRGB: jest.fn(),
  extractMetadata: jest.fn(),
  generateThumbnail: jest.fn(),
  optimizeForWeb: jest.fn()
};

const mockStorageService = {
  saveFile: jest.fn(),
  deleteFile: jest.fn()
};

// Mock ApiError class
class MockApiError extends Error {
  public statusCode: number;
  public code: string;
  public context?: any;

  constructor(message: string, statusCode: number = 500, code: string = 'INTERNAL_ERROR', context?: any) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.context = context;
  }

  static validation(message: string, field?: string, value?: any) {
    const error = new MockApiError(message, 400, 'VALIDATION_ERROR', { field, value });
    throw error;
  }

  static businessLogic(message: string, rule?: string, resource?: string) {
    const error = new MockApiError(message, 400, 'BUSINESS_LOGIC_ERROR', { rule, resource });
    throw error;
  }

  static authorization(message: string, resource?: string, action?: string) {
    const error = new MockApiError(message, 403, 'AUTHORIZATION_ERROR', { resource, action });
    throw error;
  }

  static notFound(message: string, code?: string, context?: any) {
    const error = new MockApiError(message, 404, code || 'NOT_FOUND', context);
    throw error;
  }

  static internal(message: string, code?: string, context?: any) {
    const error = new MockApiError(message, 500, code || 'INTERNAL_ERROR', context);
    throw error;
  }
}

jest.mock('../../models/imageModel', () => ({
  imageModel: mockImageModel
}));

jest.mock('../../services/imageProcessingService', () => ({
  imageProcessingService: mockImageProcessingService
}));

jest.mock('../../services/storageService', () => ({
  storageService: mockStorageService
}));

jest.mock('../../utils/ApiError', () => ({
  ApiError: MockApiError
}));

// ===== NOW IMPORT THE SERVICE TO TEST =====
import { imageService } from '../../services/imageService';

describe('ImageService Unit Tests', () => {
  const userId = 'user-123';
  const imageId = 'image-456';

  // Setup Firebase test environment
  setupFirebaseTestEnvironment();

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default successful responses
    mockImageModel.create.mockResolvedValue({
      id: imageId,
      user_id: userId,
      file_path: 'uploads/test.jpg',
      original_metadata: {},
      status: 'new',
      upload_date: new Date()
    });

    mockImageModel.findById.mockResolvedValue({
      id: imageId,
      user_id: userId,
      file_path: 'uploads/test.jpg',
      original_metadata: {},
      status: 'new',
      upload_date: new Date()
    });

    mockImageModel.getUserImageStats.mockResolvedValue({
      total: 50,
      totalSize: 100 * 1024 * 1024 // 100MB
    });

    mockImageModel.findDependentGarments.mockResolvedValue([]);
    mockImageModel.findDependentPolygons.mockResolvedValue([]);

    mockStorageService.saveFile.mockResolvedValue('uploads/saved-file.jpg');
    mockStorageService.deleteFile.mockResolvedValue(true);

    mockImageProcessingService.validateImageBuffer.mockResolvedValue({
      width: 800,
      height: 600,
      format: 'jpeg',
      channels: 3,
      space: 'srgb'
    });

    mockImageProcessingService.extractMetadata.mockResolvedValue({
      width: 800,
      height: 600,
      format: 'jpeg'
    });

    mockImageProcessingService.convertToSRGB.mockResolvedValue('uploads/converted.jpg');
    mockImageProcessingService.generateThumbnail.mockResolvedValue('uploads/thumb.jpg');
    mockImageProcessingService.optimizeForWeb.mockResolvedValue('uploads/optimized.jpg');
  });

  afterAll(() => {
    cleanupFirebaseTests();
  });

  describe('uploadImage', () => {
    const validUploadParams = {
      userId,
      fileBuffer: Buffer.from('valid-image-data'),
      originalFilename: 'test-image.jpg',
      mimetype: 'image/jpeg',
      size: 204800
    };

    it('should successfully upload a valid image', async () => {
      const result = await imageService.uploadImage(validUploadParams);

      expect(result).toBeDefined();
      expect(result.user_id).toBe(userId);
      expect(mockImageProcessingService.validateImageBuffer).toHaveBeenCalled();
      expect(mockStorageService.saveFile).toHaveBeenCalled();
      expect(mockImageModel.create).toHaveBeenCalled();
    });

    it('should convert non-sRGB images to sRGB', async () => {
      mockImageProcessingService.validateImageBuffer.mockResolvedValue({
        width: 800,
        height: 600,
        format: 'jpeg',
        channels: 4,
        space: 'cmyk' // Non-sRGB
      });

      await imageService.uploadImage(validUploadParams);

      expect(mockImageProcessingService.convertToSRGB).toHaveBeenCalled();
      expect(mockImageProcessingService.extractMetadata).toHaveBeenCalledTimes(2);
    });

    it('should reject oversized files', async () => {
      const oversizedParams = {
        ...validUploadParams,
        size: 10 * 1024 * 1024 // 10MB
      };

      await expect(imageService.uploadImage(oversizedParams)).rejects.toThrow();
    });

    it('should reject invalid image formats', async () => {
      const invalidParams = {
        ...validUploadParams,
        mimetype: 'image/gif'
      };

      await expect(imageService.uploadImage(invalidParams)).rejects.toThrow();
    });

    it('should check user upload limits', async () => {
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 1000, // At limit
        totalSize: 100 * 1024 * 1024
      });

      await expect(imageService.uploadImage(validUploadParams)).rejects.toThrow();
    });
  });

  describe('validateImageFile', () => {
    it('should validate a valid JPEG image', async () => {
      const buffer = Buffer.from('mock-jpeg-data');
      
      const result = await imageService.validateImageFile(buffer, 'image/jpeg', 204800);

      expect(result.isValid).toBe(true);
      expect(result.metadata).toBeDefined();
    });

    it('should reject files that are too large', async () => {
      const buffer = Buffer.from('mock-data');
      const largeSize = 10 * 1024 * 1024; // 10MB

      const result = await imageService.validateImageFile(buffer, 'image/jpeg', largeSize);

      expect(result.isValid).toBe(false);
      expect(result.errors).toEqual(expect.arrayContaining([expect.stringMatching(/File too large/)]));
    });

    it('should reject unsupported MIME types', async () => {
      const buffer = Buffer.from('mock-data');

      const result = await imageService.validateImageFile(buffer, 'image/gif', 204800);

      expect(result.isValid).toBe(false);
      expect(result.errors).toEqual(expect.arrayContaining([expect.stringMatching(/Unsupported format/)]));
    });

    it('should validate Instagram dimension requirements', async () => {
      mockImageProcessingService.validateImageBuffer.mockResolvedValue({
        width: 200, // Too small
        height: 150,
        format: 'jpeg',
        channels: 3,
        space: 'srgb'
      });

      const result = await imageService.validateImageFile(Buffer.from('mock-data'), 'image/jpeg', 204800);

      expect(result.isValid).toBe(false);
      expect(result.errors).toEqual(expect.arrayContaining([expect.stringMatching(/width too small/)]));
    });

    it('should validate Instagram aspect ratio requirements', async () => {
      mockImageProcessingService.validateImageBuffer.mockResolvedValue({
        width: 1000,
        height: 100, // Too wide (10:1 ratio)
        format: 'jpeg',
        channels: 3,
        space: 'srgb'
      });

      const result = await imageService.validateImageFile(Buffer.from('mock-data'), 'image/jpeg', 204800);

      expect(result.isValid).toBe(false);
      expect(result.errors).toEqual(expect.arrayContaining([expect.stringMatching(/too wide for Instagram/)]));
    });
  });

  describe('getImageById', () => {
    it('should return image for valid owner', async () => {
      const result = await imageService.getImageById(imageId, userId);

      expect(result).toBeDefined();
      expect(result.id).toBe(imageId);
      expect(result.user_id).toBe(userId);
    });

    it('should throw error for non-existent image', async () => {
      mockImageModel.findById.mockResolvedValue(null);

      await expect(imageService.getImageById(imageId, userId)).rejects.toThrow('Image not found');
    });

    it('should throw authorization error for wrong owner', async () => {
      mockImageModel.findById.mockResolvedValue({
        id: imageId,
        user_id: 'different-user',
        file_path: 'uploads/test.jpg',
        original_metadata: {},
        status: 'new'
      });

      await expect(imageService.getImageById(imageId, userId)).rejects.toThrow('permission');
    });
  });

  describe('updateImageStatus', () => {
    it('should update status for valid transition', async () => {
      const updatedImage = {
        id: imageId,
        user_id: userId,
        status: 'processed' as const,
        file_path: 'uploads/test.jpg',
        original_metadata: {}
      };

      mockImageModel.updateStatus.mockResolvedValue(updatedImage);

      const result = await imageService.updateImageStatus(imageId, userId, 'processed');

      expect(result.status).toBe('processed');
      expect(mockImageModel.updateStatus).toHaveBeenCalledWith(imageId, 'processed');
    });

    it('should reject invalid status transitions', async () => {
      mockImageModel.findById.mockResolvedValue({
        id: imageId,
        user_id: userId,
        status: 'labeled', // Cannot transition from labeled
        file_path: 'uploads/test.jpg',
        original_metadata: {}
      });

      await expect(
        imageService.updateImageStatus(imageId, userId, 'new')
      ).rejects.toThrow("Cannot change image status from 'labeled' to 'new'");
    });
  });

  describe('deleteImage', () => {
    it('should successfully delete image with no dependencies', async () => {
      mockImageModel.delete.mockResolvedValue(true);

      const result = await imageService.deleteImage(imageId, userId);

      expect(result).toEqual({ success: true, imageId });
      expect(mockStorageService.deleteFile).toHaveBeenCalled();
      expect(mockImageModel.delete).toHaveBeenCalledWith(imageId);
    });

    it('should prevent deletion when image has dependent garments', async () => {
      mockImageModel.findDependentGarments.mockResolvedValue([{ id: 'garment-1' }]);

      await expect(imageService.deleteImage(imageId, userId)).rejects.toThrow(
        'Cannot delete image. It is being used by 1 garment(s).'
      );
    });

    it('should prevent deletion when image has dependent polygons', async () => {
      mockImageModel.findDependentPolygons.mockResolvedValue([{ id: 'polygon-1' }, { id: 'polygon-2' }]);

      await expect(imageService.deleteImage(imageId, userId)).rejects.toThrow(
        'Cannot delete image. It has 2 associated polygon(s).'
      );
    });
  });

  describe('getUserImages', () => {
    it('should retrieve user images with default pagination', async () => {
      const mockImages = [
        { id: 'img-1', user_id: userId, status: 'new' },
        { id: 'img-2', user_id: userId, status: 'processed' }
      ];
      mockImageModel.findByUserId.mockResolvedValue(mockImages);

      const result = await imageService.getUserImages(userId);

      expect(result).toEqual(mockImages);
      expect(mockImageModel.findByUserId).toHaveBeenCalledWith(userId, {
        limit: 20,
        offset: 0
      });
    });

    it('should apply custom pagination options', async () => {
      const options = { limit: 50, offset: 10 };
      mockImageModel.findByUserId.mockResolvedValue([]);

      await imageService.getUserImages(userId, options);

      expect(mockImageModel.findByUserId).toHaveBeenCalledWith(userId, {
        limit: 50, // Should respect user's request when within limits
        offset: 10
      });
    });
  });

  describe('generateThumbnail', () => {
    it('should generate thumbnail and update metadata', async () => {
      const thumbnailPath = 'uploads/thumbnail.jpg';
      mockImageProcessingService.generateThumbnail.mockResolvedValue(thumbnailPath);

      const result = await imageService.generateThumbnail(imageId, userId, 300);

      expect(result).toEqual({ thumbnailPath, size: 300 });
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalled();
      expect(mockImageModel.updateMetadata).toHaveBeenCalled();
    });

    it('should use default size when not specified', async () => {
      const mockImage = { id: imageId, user_id: userId, file_path: 'uploads/test.jpg' };
      mockImageModel.findById.mockResolvedValue(mockImage);

      await imageService.generateThumbnail(imageId, userId);

      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith(mockImage.file_path, 200);
    });
  });

  describe('getUserImageStats', () => {
    it('should return enhanced statistics with business logic calculations', async () => {
      const mockStats = {
        total: 10,
        byStatus: { new: 3, processed: 4, labeled: 3 },
        totalSize: 2048000, // 2MB
        averageSize: 204800 // 200KB
      };
      
      mockImageModel.getUserImageStats.mockResolvedValue(mockStats);

      const result = await imageService.getUserImageStats(userId);

      expect(result).toEqual({
        ...mockStats,
        storageUsedMB: 1.95,
        averageSizeMB: 0.2,
        storageLimit: {
          maxImages: 1000,
          maxStorageMB: 500,
          maxFileSizeMB: 8,
          supportedFormats: ['JPEG', 'PNG', 'BMP'],
          aspectRatioRange: '4:5 to 1.91:1',
          resolutionRange: '320px to 1440px width'
        }
      });
    });
  });

  describe('batchUpdateStatus', () => {
    it('should update multiple images after verifying ownership', async () => {
      const imageIds = ['img-1', 'img-2', 'img-3'];
      const mockImages = imageIds.map(id => ({ id, user_id: userId, status: 'new' }));
      
      mockImageModel.findById
        .mockResolvedValueOnce(mockImages[0])
        .mockResolvedValueOnce(mockImages[1])
        .mockResolvedValueOnce(mockImages[2]);
      
      mockImageModel.batchUpdateStatus.mockResolvedValue(3);

      const result = await imageService.batchUpdateStatus(imageIds, userId, 'processed');

      expect(result).toEqual({ updatedCount: 3, total: 3 });
      expect(mockImageModel.findById).toHaveBeenCalledTimes(3);
      expect(mockImageModel.batchUpdateStatus).toHaveBeenCalledWith(imageIds, 'processed');
    });

    it('should fail if user does not own all images', async () => {
      const imageIds = ['img-1', 'img-2'];
      const mockImages = [
        { id: 'img-1', user_id: userId, status: 'new' },
        { id: 'img-2', user_id: 'different-user', status: 'new' }
      ];
      
      mockImageModel.findById
        .mockResolvedValueOnce(mockImages[0])
        .mockResolvedValueOnce(mockImages[1]);

      await expect(
        imageService.batchUpdateStatus(imageIds, userId, 'processed')
      ).rejects.toThrow('You do not have permission to access this image');
      
      expect(mockImageModel.batchUpdateStatus).not.toHaveBeenCalled();
    });
  });
});