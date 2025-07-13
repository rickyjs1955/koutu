// src/tests/unit/imageService.p2.unit.test.ts

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
  webp: jest.fn().mockReturnThis(),
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
  optimizeForWeb: jest.fn(),
  optimizeForMobile: jest.fn()
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

describe('ImageService P2 Tests - Flutter Features', () => {
  const userId = 'user-123';
  const imageId = 'image-456';

  // Setup Firebase test environment
  setupFirebaseTestEnvironment();

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default successful responses
    mockImageModel.findById.mockResolvedValue({
      id: imageId,
      user_id: userId,
      file_path: 'uploads/test.jpg',
      original_metadata: { width: 800, height: 600, size: 204800 },
      status: 'new',
      upload_date: new Date()
    });

    mockImageModel.findByUserId.mockResolvedValue([
      { id: 'img-1', user_id: userId, file_path: 'uploads/img1.jpg', original_metadata: { width: 800, height: 600 } },
      { id: 'img-2', user_id: userId, file_path: 'uploads/img2.jpg', original_metadata: { width: 1200, height: 900 } }
    ]);

    mockImageProcessingService.generateThumbnail.mockResolvedValue('uploads/thumb.jpg');
    mockImageProcessingService.optimizeForMobile.mockResolvedValue('uploads/mobile.webp');
    mockStorageService.saveFile.mockResolvedValue('uploads/saved.jpg');
  });

  afterAll(() => {
    cleanupFirebaseTests();
  });

  describe('getMobileThumbnails', () => {
    it('should generate small thumbnails with correct size mapping', async () => {
      const options = { page: 1, limit: 10, size: 'small' as const };
      
      const result = await imageService.getMobileThumbnails(userId, options);

      expect(result.thumbnails).toHaveLength(2);
      expect(result.page).toBe(1);
      expect(result.hasMore).toBe(false);
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('uploads/img1.jpg', 100);
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('uploads/img2.jpg', 100);
    });

    it('should generate medium thumbnails with correct size mapping', async () => {
      const options = { page: 1, limit: 10, size: 'medium' as const };
      
      await imageService.getMobileThumbnails(userId, options);

      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('uploads/img1.jpg', 200);
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('uploads/img2.jpg', 200);
    });

    it('should generate large thumbnails with correct size mapping', async () => {
      const options = { page: 1, limit: 10, size: 'large' as const };
      
      await imageService.getMobileThumbnails(userId, options);

      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('uploads/img1.jpg', 400);
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('uploads/img2.jpg', 400);
    });

    it('should handle pagination correctly', async () => {
      mockImageModel.findByUserId.mockResolvedValue(Array(5).fill(0).map((_, i) => ({
        id: `img-${i}`,
        user_id: userId,
        file_path: `uploads/img${i}.jpg`,
        original_metadata: { width: 800, height: 600 }
      })));

      const options = { page: 2, limit: 5, size: 'small' as const };
      
      const result = await imageService.getMobileThumbnails(userId, options);

      expect(mockImageModel.findByUserId).toHaveBeenCalledWith(userId, { limit: 5, offset: 5 });
      expect(result.page).toBe(2);
      expect(result.hasMore).toBe(true);
    });

    it('should handle thumbnail generation failures gracefully', async () => {
      mockImageProcessingService.generateThumbnail
        .mockResolvedValueOnce('uploads/thumb1.jpg')
        .mockRejectedValueOnce(new Error('Thumbnail failed'));

      const options = { page: 1, limit: 10, size: 'small' as const };
      
      const result = await imageService.getMobileThumbnails(userId, options);

      expect(result.thumbnails[0]).toEqual({
        id: 'img-1',
        thumbnailPath: 'uploads/thumb1.jpg',
        size: 'small',
        originalWidth: 800,
        originalHeight: 600
      });

      expect(result.thumbnails[1]).toEqual({
        id: 'img-2',
        thumbnailPath: null,
        size: 'small',
        error: 'Failed to generate thumbnail'
      });
    });

    it('should include original dimensions in response', async () => {
      const options = { page: 1, limit: 10, size: 'medium' as const };
      
      const result = await imageService.getMobileThumbnails(userId, options);

      expect(result.thumbnails[0]).toEqual(expect.objectContaining({
        originalWidth: 800,
        originalHeight: 600
      }));
    });
  });

  describe('getMobileOptimizedImage', () => {
    it('should generate mobile-optimized webp image', async () => {
      const result = await imageService.getMobileOptimizedImage(imageId, userId);

      expect(mockImageProcessingService.optimizeForMobile).toHaveBeenCalledWith('uploads/test.jpg');
      expect(result).toEqual({
        id: imageId,
        optimizedPath: 'uploads/mobile.webp',
        format: 'webp',
        quality: 85,
        originalSize: 204800,
        optimizedAt: expect.any(String)
      });
    });

    it('should verify ownership before optimization', async () => {
      mockImageModel.findById.mockResolvedValue({
        id: imageId,
        user_id: 'different-user',
        file_path: 'uploads/test.jpg',
        original_metadata: {}
      });

      await expect(imageService.getMobileOptimizedImage(imageId, userId))
        .rejects.toThrow('permission');
    });

    it('should handle optimization service failures', async () => {
      mockImageProcessingService.optimizeForMobile.mockRejectedValue(new Error('Optimization failed'));

      await expect(imageService.getMobileOptimizedImage(imageId, userId))
        .rejects.toThrow('Failed to get mobile optimized image');
    });

    it('should include timestamp in response', async () => {
      const beforeTime = new Date().toISOString();
      
      const result = await imageService.getMobileOptimizedImage(imageId, userId);
      
      const afterTime = new Date().toISOString();
      expect(new Date(result.optimizedAt).getTime()).toBeGreaterThanOrEqual(new Date(beforeTime).getTime());
      expect(new Date(result.optimizedAt).getTime()).toBeLessThanOrEqual(new Date(afterTime).getTime());
    });
  });

  describe('batchGenerateThumbnails', () => {
    const imageIds = ['img-1', 'img-2', 'img-3'];
    const sizes: ('small' | 'medium' | 'large')[] = ['small', 'medium'];

    it('should generate multiple thumbnail sizes for all images', async () => {
      jest.clearAllMocks();
      mockImageModel.findById
        .mockResolvedValueOnce({ id: 'img-1', user_id: userId, file_path: 'path1.jpg' })
        .mockResolvedValueOnce({ id: 'img-2', user_id: userId, file_path: 'path2.jpg' })
        .mockResolvedValueOnce({ id: 'img-3', user_id: userId, file_path: 'path3.jpg' });
      mockImageProcessingService.generateThumbnail.mockResolvedValue('thumb.jpg');

      const result = await imageService.batchGenerateThumbnails(imageIds, userId, sizes);

      expect(result.successCount).toBe(3);
      expect(result.totalCount).toBe(3);
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledTimes(6); // 3 images � 2 sizes
      
      // Verify size mapping
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('path1.jpg', 100); // small
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('path1.jpg', 200); // medium
    });

    it('should track success and failure counts', async () => {
      jest.clearAllMocks();
      mockImageModel.findById
        .mockResolvedValueOnce({ id: 'img-1', user_id: userId, file_path: 'path1.jpg' })
        .mockResolvedValueOnce({ id: 'img-2', user_id: userId, file_path: 'path2.jpg' })
        .mockResolvedValueOnce({ id: 'img-3', user_id: userId, file_path: 'path3.jpg' });
        
      mockImageProcessingService.generateThumbnail
        .mockResolvedValueOnce('thumb1-small.jpg')
        .mockResolvedValueOnce('thumb1-medium.jpg')
        .mockRejectedValueOnce(new Error('Failed'))
        .mockRejectedValueOnce(new Error('Failed'))
        .mockResolvedValueOnce('thumb3-small.jpg')
        .mockResolvedValueOnce('thumb3-medium.jpg');

      const result = await imageService.batchGenerateThumbnails(imageIds, userId, sizes);

      expect(result.successCount).toBe(2);
      expect(result.totalCount).toBe(3);
      expect(result.results).toHaveLength(3);
      
      expect(result.results[0]).toEqual({
        id: 'img-1',
        thumbnails: [
          { size: 'small', thumbnailPath: 'thumb1-small.jpg' },
          { size: 'medium', thumbnailPath: 'thumb1-medium.jpg' }
        ],
        status: 'success'
      });

      expect(result.results[1]).toEqual({
        id: 'img-2',
        status: 'failed',
        error: 'Thumbnail generation failed'
      });
    });

    it('should verify ownership of all images before processing', async () => {
      jest.clearAllMocks();
      mockImageModel.findById
        .mockResolvedValueOnce({ id: 'img-1', user_id: userId, file_path: 'path1.jpg' })
        .mockResolvedValueOnce({ id: 'img-2', user_id: 'different-user', file_path: 'path2.jpg' });

      await expect(imageService.batchGenerateThumbnails(['img-1', 'img-2'], userId, sizes))
        .rejects.toThrow('You do not have permission to access this image');
      
      expect(mockImageProcessingService.generateThumbnail).not.toHaveBeenCalled();
    });

    it('should handle single size generation', async () => {
      jest.clearAllMocks();
      mockImageModel.findById
        .mockResolvedValueOnce({ id: 'img-1', user_id: userId, file_path: 'path1.jpg' })
        .mockResolvedValueOnce({ id: 'img-2', user_id: userId, file_path: 'path2.jpg' })
        .mockResolvedValueOnce({ id: 'img-3', user_id: userId, file_path: 'path3.jpg' });
      mockImageProcessingService.generateThumbnail.mockResolvedValue('thumb.jpg');

      const result = await imageService.batchGenerateThumbnails(imageIds, userId, ['large']);

      expect(result.successCount).toBe(3);
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledTimes(3);
      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('path1.jpg', 400);
    });
  });

  describe('getSyncData', () => {
    beforeEach(() => {
      mockImageModel.findByUserId.mockResolvedValue([
        {
          id: 'img-1',
          status: 'processed',
          original_metadata: { width: 800, height: 600 },
          upload_date: new Date('2024-01-01')
        },
        {
          id: 'img-2',
          status: 'new',
          original_metadata: { width: 1200, height: 900 },
          upload_date: new Date('2024-01-02')
        }
      ]);
    });

    it('should return sync data with proper format', async () => {
      const options = { includeDeleted: false, limit: 50 };
      
      const result = await imageService.getSyncData(userId, options);

      expect(result.images).toHaveLength(2);
      expect(result.images[0]).toEqual({
        id: 'img-1',
        status: 'processed',
        metadata: { width: 800, height: 600 },
        lastModified: new Date('2024-01-01'),
        syncStatus: 'synced'
      });
      expect(result.syncTimestamp).toBeDefined();
      expect(result.hasMore).toBe(false);
    });

    it('should handle lastSync parameter', async () => {
      const options = { lastSync: '2024-01-01T12:00:00Z', includeDeleted: false, limit: 50 };
      
      await imageService.getSyncData(userId, options);

      // Verify the sync timestamp was logged (basic functionality for now)
      expect(mockImageModel.findByUserId).toHaveBeenCalledWith(userId, { limit: 50 });
    });

    it('should respect limit parameter for hasMore flag', async () => {
      const options = { includeDeleted: false, limit: 2 };
      
      const result = await imageService.getSyncData(userId, options);

      expect(result.hasMore).toBe(true);
    });

    it('should handle empty result set', async () => {
      mockImageModel.findByUserId.mockResolvedValue([]);
      const options = { includeDeleted: false, limit: 50 };
      
      const result = await imageService.getSyncData(userId, options);

      expect(result.images).toHaveLength(0);
      expect(result.hasMore).toBe(false);
    });

    it('should include sync timestamp in response', async () => {
      const beforeTime = new Date().toISOString();
      const options = { includeDeleted: false, limit: 50 };
      
      const result = await imageService.getSyncData(userId, options);
      
      const afterTime = new Date().toISOString();
      expect(new Date(result.syncTimestamp).getTime()).toBeGreaterThanOrEqual(new Date(beforeTime).getTime());
      expect(new Date(result.syncTimestamp).getTime()).toBeLessThanOrEqual(new Date(afterTime).getTime());
    });
  });

  describe('flutterUploadImage', () => {
    const uploadParams = {
      userId,
      fileBuffer: Buffer.from('test-image-data'),
      originalFilename: 'flutter-test.jpg',
      mimetype: 'image/jpeg',
      size: 204800
    };

    it('should upload image with Flutter optimizations', async () => {
      jest.clearAllMocks();
      mockImageModel.create.mockResolvedValue({
        id: imageId,
        user_id: userId,
        file_path: 'uploads/flutter-test.jpg',
        original_metadata: {},
        status: 'new'
      });
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 10,
        totalSize: 10 * 1024 * 1024
      });
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
      mockStorageService.saveFile.mockResolvedValue('uploads/flutter-test.jpg');
      mockImageProcessingService.generateThumbnail.mockResolvedValue('uploads/thumb.jpg');
      mockImageModel.updateMetadata.mockResolvedValue(true);
      
      const result = await imageService.flutterUploadImage(uploadParams);

      expect(result.platform).toBe('flutter');
      expect(result.uploadOptimized).toBe(true);
      expect(result.id).toBe(imageId);
      expect(mockImageModel.create).toHaveBeenCalled();
    });

    it('should generate immediate thumbnail for Flutter preview', async () => {
      jest.clearAllMocks();
      mockImageModel.create.mockResolvedValue({
        id: imageId,
        user_id: userId,
        file_path: 'uploads/flutter-test.jpg',
        original_metadata: {},
        status: 'new'
      });
      // Mock for generateThumbnail's getImageById call
      mockImageModel.findById.mockResolvedValue({
        id: imageId,
        user_id: userId,
        file_path: 'uploads/flutter-test.jpg',
        original_metadata: {},
        status: 'new'
      });
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 10,
        totalSize: 10 * 1024 * 1024
      });
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
      mockStorageService.saveFile.mockResolvedValue('uploads/flutter-test.jpg');
      mockImageProcessingService.generateThumbnail.mockResolvedValue('uploads/thumb.jpg');
      mockImageModel.updateMetadata.mockResolvedValue(true);
      
      await imageService.flutterUploadImage(uploadParams);

      expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledWith('uploads/flutter-test.jpg', 200);
      expect(mockImageModel.updateMetadata).toHaveBeenCalled();
    });

    it('should continue if thumbnail generation fails', async () => {
      jest.clearAllMocks();
      mockImageModel.create.mockResolvedValue({
        id: imageId,
        user_id: userId,
        file_path: 'uploads/flutter-test.jpg',
        original_metadata: {},
        status: 'new'
      });
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 10,
        totalSize: 10 * 1024 * 1024
      });
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
      mockStorageService.saveFile.mockResolvedValue('uploads/flutter-test.jpg');
      mockImageProcessingService.generateThumbnail.mockRejectedValue(new Error('Thumbnail failed'));

      const result = await imageService.flutterUploadImage(uploadParams);

      expect(result.platform).toBe('flutter');
      expect(result.uploadOptimized).toBe(true);
      // Should not throw error despite thumbnail failure
    });

    it('should use existing validation and upload logic', async () => {
      jest.clearAllMocks();
      mockImageModel.create.mockResolvedValue({
        id: imageId,
        user_id: userId,
        file_path: 'uploads/flutter-test.jpg',
        original_metadata: {},
        status: 'new'
      });
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 10,
        totalSize: 10 * 1024 * 1024
      });
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
      mockStorageService.saveFile.mockResolvedValue('uploads/flutter-test.jpg');
      mockImageProcessingService.generateThumbnail.mockResolvedValue('uploads/thumb.jpg');
      
      await imageService.flutterUploadImage(uploadParams);

      expect(mockImageProcessingService.validateImageBuffer).toHaveBeenCalled();
      expect(mockStorageService.saveFile).toHaveBeenCalled();
      expect(mockImageModel.getUserImageStats).toHaveBeenCalled();
    });

    it('should handle upload failures properly', async () => {
      jest.clearAllMocks();
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 10,
        totalSize: 10 * 1024 * 1024
      });
      mockImageProcessingService.validateImageBuffer.mockResolvedValue({
        width: 800,
        height: 600,
        format: 'jpeg',
        channels: 3,
        space: 'srgb'
      });
      mockStorageService.saveFile.mockRejectedValue(new Error('Storage failed'));

      await expect(imageService.flutterUploadImage(uploadParams))
        .rejects.toThrow('Failed to process image upload');
    });
  });

  describe('batchSyncOperations', () => {
    const operations = [
      { id: 'img-1', action: 'update' as const, data: { status: 'processed' }, clientTimestamp: '2024-01-01T12:00:00Z' },
      { id: 'img-2', action: 'delete' as const, data: {}, clientTimestamp: '2024-01-01T12:01:00Z' },
      { id: 'img-3', action: 'update' as const, data: { status: 'labeled' }, clientTimestamp: '2024-01-01T12:02:00Z' }
    ];

    it('should process all operations successfully', async () => {
      jest.clearAllMocks();
      
      // Mock for updateImageStatus calls
      mockImageModel.findById
        .mockResolvedValueOnce({ id: 'img-1', user_id: userId, status: 'new', file_path: 'path1.jpg' })
        .mockResolvedValueOnce({ id: 'img-2', user_id: userId, status: 'processed', file_path: 'path2.jpg' })
        .mockResolvedValueOnce({ id: 'img-3', user_id: userId, status: 'processed', file_path: 'path3.jpg' });
      
      mockImageModel.updateStatus.mockResolvedValue({ id: 'updated', status: 'processed' });
      mockImageModel.delete.mockResolvedValue(true);
      mockImageModel.findDependentGarments.mockResolvedValue([]);
      mockImageModel.findDependentPolygons.mockResolvedValue([]);
      mockStorageService.deleteFile.mockResolvedValue(true);
      
      const result = await imageService.batchSyncOperations(userId, operations);

      expect(result.successCount).toBe(3);
      expect(result.failedCount).toBe(0);
      expect(result.results).toHaveLength(3);
      expect(result.results.every(r => r.status === 'success')).toBe(true);
      expect(result.syncCompleted).toBeDefined();
    });

    it('should handle update operations', async () => {
      jest.clearAllMocks();
      
      mockImageModel.findById.mockResolvedValue({ id: 'img-1', user_id: userId, status: 'new', file_path: 'path1.jpg' });
      mockImageModel.updateStatus.mockResolvedValue({ id: 'img-1', status: 'processed' });
      
      const updateOperation = [operations[0]];
      
      await imageService.batchSyncOperations(userId, updateOperation);

      expect(mockImageModel.updateStatus).toHaveBeenCalledWith('img-1', 'processed');
    });

    it('should handle delete operations', async () => {
      const deleteOperation = [operations[1]];
      
      await imageService.batchSyncOperations(userId, deleteOperation);

      expect(mockImageModel.delete).toHaveBeenCalledWith('img-2');
      expect(mockStorageService.deleteFile).toHaveBeenCalled();
    });

    it('should track failed operations', async () => {
      // Clear and reset mocks for this test
      jest.clearAllMocks();
      mockImageModel.findById
        .mockResolvedValueOnce({ id: 'img-1', user_id: userId, status: 'new', file_path: 'path1.jpg' })
        .mockResolvedValueOnce({ id: 'img-2', user_id: userId, status: 'processed', file_path: 'path2.jpg' })
        .mockResolvedValueOnce({ id: 'img-3', user_id: userId, status: 'processed', file_path: 'path3.jpg' });
      
      // Make the first updateStatus call fail
      mockImageModel.updateStatus.mockRejectedValueOnce(new MockApiError('Failed to update image status', 500, 'INTERNAL_ERROR'))
                                  .mockResolvedValue({ id: 'updated', status: 'processed' });
      mockImageModel.delete.mockResolvedValue(true);
      mockImageModel.findDependentGarments.mockResolvedValue([]);
      mockImageModel.findDependentPolygons.mockResolvedValue([]);
      mockStorageService.deleteFile.mockResolvedValue(true);
      
      const result = await imageService.batchSyncOperations(userId, operations);

      expect(result.successCount).toBe(2);
      expect(result.failedCount).toBe(1);
      expect(result.results[0]).toEqual({
        id: 'img-1',
        status: 'failed',
        error: 'Failed to update image status'
      });
    });

    it('should reject unsupported operations', async () => {
      const invalidOperation = [{ 
        id: 'img-1', 
        action: 'create' as any, 
        data: {}, 
        clientTimestamp: '2024-01-01T12:00:00Z' 
      }];
      
      const result = await imageService.batchSyncOperations(userId, invalidOperation);

      expect(result.failedCount).toBe(1);
      expect(result.results[0].error).toContain('Unsupported sync operation: create');
    });

    it('should include sync completion timestamp', async () => {
      const beforeTime = new Date().toISOString();
      
      const result = await imageService.batchSyncOperations(userId, operations);
      
      const afterTime = new Date().toISOString();
      expect(new Date(result.syncCompleted).getTime()).toBeGreaterThanOrEqual(new Date(beforeTime).getTime());
      expect(new Date(result.syncCompleted).getTime()).toBeLessThanOrEqual(new Date(afterTime).getTime());
    });

    it('should handle empty operations array', async () => {
      const result = await imageService.batchSyncOperations(userId, []);

      expect(result.successCount).toBe(0);
      expect(result.failedCount).toBe(0);
      expect(result.results).toHaveLength(0);
      expect(result.conflicts).toHaveLength(0);
    });

    it('should process operations sequentially', async () => {
      // Clear and reset mocks for this test
      jest.clearAllMocks();
      let callOrder: string[] = [];
      
      mockImageModel.findById
        .mockResolvedValueOnce({ id: 'img-1', user_id: userId, status: 'new', file_path: 'path1.jpg' })
        .mockResolvedValueOnce({ id: 'img-2', user_id: userId, status: 'processed', file_path: 'path2.jpg' })
        .mockResolvedValueOnce({ id: 'img-3', user_id: userId, status: 'processed', file_path: 'path3.jpg' });
        
      mockImageModel.updateStatus.mockImplementation(async (id) => {
        callOrder.push(`update-${id}`);
        return { id, status: 'processed' };
      });
      
      mockImageModel.delete.mockImplementation(async (id) => {
        callOrder.push(`delete-${id}`);
        return true;
      });
      
      mockImageModel.findDependentGarments.mockResolvedValue([]);
      mockImageModel.findDependentPolygons.mockResolvedValue([]);
      mockStorageService.deleteFile.mockResolvedValue(true);

      await imageService.batchSyncOperations(userId, operations);

      expect(callOrder).toEqual(['update-img-1', 'delete-img-2', 'update-img-3']);
    });
  });
});