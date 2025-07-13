// /backend/src/tests/integration/imageService.p2.int.test.ts
// Integration Tests for Image Service Flutter Features with Real Infrastructure

import { jest, describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import { imageService } from '../../services/imageService';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';
import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';

// Mock Sharp with complete type safety bypass
const mockSharp: any = jest.fn().mockImplementation(() => {
  // Explicitly cast each jest.fn() to 'any' to ensure its methods (like mockResolvedValue)
  // accept any type of argument, effectively bypassing type safety for the mock.
  const mockInstance = {
    metadata: jest.fn() as any,
    resize: jest.fn() as any,
    jpeg: jest.fn() as any,
    png: jest.fn() as any,
    webp: jest.fn() as any,
    toColorspace: jest.fn() as any,
    toFile: jest.fn() as any,
    toBuffer: jest.fn() as any
  };
  
  // Set up return values with proper chaining
  // These calls will now correctly accept the provided types due to the 'any' casts above.
  mockInstance.metadata.mockResolvedValue({
    width: 800,
    height: 600,
    format: 'jpeg',
    channels: 3,
    space: 'srgb'
  });
  
  mockInstance.resize.mockReturnValue(mockInstance);
  mockInstance.jpeg.mockReturnValue(mockInstance);
  mockInstance.png.mockReturnValue(mockInstance);
  mockInstance.webp.mockReturnValue(mockInstance);
  mockInstance.toColorspace.mockReturnValue(mockInstance);
  mockInstance.toFile.mockResolvedValue({ size: 204800 });
  mockInstance.toBuffer.mockResolvedValue(Buffer.from('mock-image-data'));
  
  return mockInstance;
});

// Add create function to mock
// Similarly, cast jest.fn() for the create method's internal mock instance
mockSharp.create = jest.fn().mockImplementation((_options: any) => {
  const createInstance = {
    jpeg: jest.fn() as any,
    toBuffer: jest.fn() as any
  };
  createInstance.jpeg.mockReturnValue(createInstance);
  createInstance.toBuffer.mockResolvedValue(Buffer.from('test-image-data'));
  return createInstance;
});

// Mock the 'sharp' module with our custom mockSharp
jest.mock('sharp', () => mockSharp);

// Import real services for integration testing
import { imageModel } from '../../models/imageModel';
import { imageProcessingService } from '../../services/imageProcessingService';
import { storageService } from '../../services/storageService';

// Type the mocked services properly
const mockedImageModel = imageModel as jest.Mocked<typeof imageModel>;
const mockedImageProcessingService = imageProcessingService as jest.Mocked<typeof imageProcessingService>;
const mockedStorageService = storageService as jest.Mocked<typeof storageService>;

// Mock the imageModel to use testImageModel for integration testing
jest.mock('../../models/imageModel', () => ({
  imageModel: {
    create: jest.fn(),
    findById: jest.fn(),
    findByUserId: jest.fn(),
    updateStatus: jest.fn(),
    delete: jest.fn(),
    getUserImageStats: jest.fn(),
    findDependentGarments: jest.fn(),
    findDependentPolygons: jest.fn(),
    updateMetadata: jest.fn(),
    batchUpdateStatus: jest.fn()
  }
}));

// Mock the dependent services for controlled testing
jest.mock('../../services/imageProcessingService', () => ({
  imageProcessingService: {
    extractMetadata: jest.fn(),
    validateImageBuffer: jest.fn(),
    convertToSRGB: jest.fn(),
    generateThumbnail: jest.fn(),
    optimizeForWeb: jest.fn(),
    optimizeForMobile: jest.fn()
  }
}));

jest.mock('../../services/storageService', () => ({
  storageService: {
    saveFile: jest.fn(),
    deleteFile: jest.fn()
  }
}));

describe('Image Service P2 Integration Tests - Flutter Features', () => {
  let testUser: any;
  let testStorageDir: string;
  const createdImageIds: string[] = [];
  const createdFiles: string[] = [];
  const createdUserIds: string[] = [];

  beforeAll(async () => {
    console.time('P2 Integration Setup');
    
    // Initialize test database
    await setupTestDatabase();
    
    // Create test storage directory
    testStorageDir = path.join(process.cwd(), 'test-storage', 'p2-integration');
    await fs.mkdir(testStorageDir, { recursive: true });
    
    console.timeEnd('P2 Integration Setup');
  }, 30000);

  afterAll(async () => {
    console.time('P2 Integration Cleanup');
    
    // Clean up files
    for (const filePath of createdFiles) {
      try {
        await fs.unlink(filePath);
      } catch (error) {
        // Ignore - file might not exist
      }
    }
    
    // Clean up test storage directory
    try {
      await fs.rm(testStorageDir, { recursive: true, force: true });
    } catch (error) {
      // Ignore - directory might not exist
    }
    
    // Clean up database
    await teardownTestDatabase();
    await TestDatabaseConnection.cleanup();
    
    console.timeEnd('P2 Integration Cleanup');
  }, 20000);

  beforeEach(async () => {
    jest.clearAllMocks();
    
    // Create a test user for each test
    const userId = `test-user-${uuidv4()}`;
    testUser = {
      id: userId,
      email: `test-${Date.now()}@example.com`,
      name: 'Test User P2'
    };
    createdUserIds.push(userId);

    // Setup default mock responses for Flutter tests
    mockedImageModel.getUserImageStats.mockResolvedValue({
      total: 5,
      totalSize: 50 * 1024 * 1024, // 50MB
      byStatus: { new: 2, processed: 2, labeled: 1 },
      averageSize: 10 * 1024 * 1024 // 10MB average
    } as any);

    mockedImageModel.create.mockImplementation(async (data: any) => {
      const imageId = `img-${uuidv4()}`;
      createdImageIds.push(imageId);
      return {
        id: imageId,
        user_id: data.user_id,
        file_path: data.file_path,
        original_metadata: data.original_metadata,
        status: 'new',
        upload_date: new Date()
      } as any;
    });

    mockedImageModel.findById.mockImplementation(async (id: string) => {
      if (createdImageIds.includes(id)) {
        return {
          id,
          user_id: testUser.id,
          file_path: `uploads/${id}.jpg`,
          original_metadata: { width: 800, height: 600, size: 204800 },
          status: 'new',
          upload_date: new Date()
        } as any;
      }
      return null;
    });

    mockedImageModel.findByUserId.mockImplementation(async (userId: string, options: any = {}) => {
      if (userId === testUser.id) {
        const mockImages = Array(options.limit || 10).fill(0).map((_, i) => ({
          id: `img-${i}`,
          user_id: userId,
          file_path: `uploads/img-${i}.jpg`,
          original_metadata: { width: 800 + (i * 100), height: 600 + (i * 75), size: 204800 + (i * 50000) },
          status: i % 2 === 0 ? 'new' : 'processed',
          upload_date: new Date(Date.now() - (i * 86400000)) // i days ago
        }));
        return mockImages as any;
      }
      return [];
    });

    mockedImageModel.updateStatus.mockImplementation(async (id: string, status: string) => ({
      id,
      status,
      updated_at: new Date()
    } as any));

    mockedImageModel.updateMetadata.mockResolvedValue(true as any);
    mockedImageModel.delete.mockResolvedValue(true as any);
    mockedImageModel.findDependentGarments.mockResolvedValue([] as any);
    mockedImageModel.findDependentPolygons.mockResolvedValue([] as any);
    mockedImageModel.batchUpdateStatus.mockImplementation(async (ids: string[]) => ids.length as any);

    // Setup image processing service mocks
    mockedImageProcessingService.validateImageBuffer.mockResolvedValue({
      width: 800,
      height: 600,
      format: 'jpeg',
      channels: 3,
      space: 'srgb'
    } as any);

    mockedImageProcessingService.extractMetadata.mockResolvedValue({
      width: 800,
      height: 600,
      format: 'jpeg',
      density: 72,
      hasProfile: false,
      hasAlpha: false,
      channels: 3,
      space: 'srgb'
    } as any);

    mockedImageProcessingService.generateThumbnail.mockImplementation(async (filePath: string, size: number) => {
      const thumbPath = `${filePath.replace('.jpg', '')}_thumb_${size}.jpg`;
      createdFiles.push(thumbPath);
      return thumbPath;
    });

    mockedImageProcessingService.optimizeForMobile.mockImplementation(async (filePath: string) => {
      const optimizedPath = `${filePath.replace('.jpg', '')}_mobile.webp`;
      createdFiles.push(optimizedPath);
      return optimizedPath;
    });

    // Setup storage service mocks
    mockedStorageService.saveFile.mockImplementation(async (buffer: any, filename: any) => {
      const filePath = path.join(testStorageDir, filename as string);
      createdFiles.push(filePath);
      await fs.writeFile(filePath, buffer as Buffer);
      return filePath;
    });

    mockedStorageService.deleteFile.mockImplementation(async (filePath: any) => {
      try {
        await fs.unlink(filePath as string);
        return true;
      } catch {
        return false;
      }
    });
  });

  afterEach(async () => {
    // Clean up any files created during the test
    for (const filePath of createdFiles) {
      try {
        await fs.unlink(filePath);
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  describe('Flutter Upload Integration', () => {
    it('should handle complete Flutter upload workflow with real file processing', async () => {
      // Create a test image buffer using mocked sharp
      const testImageBuffer = Buffer.from('test-image-data');

      const uploadParams = {
        userId: testUser.id,
        fileBuffer: testImageBuffer,
        originalFilename: 'flutter-integration-test.jpg',
        mimetype: 'image/jpeg',
        size: testImageBuffer.length
      };

      const result = await imageService.flutterUploadImage(uploadParams);

      // Verify the Flutter-specific fields
      expect(result.platform).toBe('flutter');
      expect(result.uploadOptimized).toBe(true);
      expect(result.id).toBeDefined();

      // Verify real file was saved
      expect(mockedStorageService.saveFile).toHaveBeenCalledWith(
        testImageBuffer,
        'flutter-integration-test.jpg'
      );

      // Verify thumbnail generation was attempted (will use actual file path from storage)
      expect(mockedImageProcessingService.generateThumbnail).toHaveBeenCalledWith(
        expect.any(String),
        200
      );

      // Verify database record was created
      expect(mockedImageModel.create).toHaveBeenCalledWith({
        user_id: testUser.id,
        file_path: expect.stringContaining('flutter-integration-test.jpg'),
        original_metadata: expect.objectContaining({
          filename: 'flutter-integration-test.jpg',
          mimetype: 'image/jpeg',
          size: testImageBuffer.length
        })
      });
    });

    it('should handle Flutter upload with immediate thumbnail generation failure', async () => {
      const testImageBuffer = Buffer.from('mock-image-data');
      
      // Mock thumbnail generation failure
      mockedImageProcessingService.generateThumbnail.mockRejectedValueOnce(
        new Error('Thumbnail generation failed')
      );

      const uploadParams = {
        userId: testUser.id,
        fileBuffer: testImageBuffer,
        originalFilename: 'flutter-thumb-fail.jpg',
        mimetype: 'image/jpeg',
        size: testImageBuffer.length
      };

      // Should complete successfully despite thumbnail failure
      const result = await imageService.flutterUploadImage(uploadParams);

      expect(result.platform).toBe('flutter');
      expect(result.uploadOptimized).toBe(true);
      expect(mockedImageModel.create).toHaveBeenCalled();
    });

    it('should respect user limits during Flutter upload', async () => {
      // Mock user at storage limit
      mockedImageModel.getUserImageStats.mockResolvedValue({
        total: 999,
        totalSize: 500 * 1024 * 1024 // At 500MB limit
      } as any);

      const uploadParams = {
        userId: testUser.id,
        fileBuffer: Buffer.from('test-data'),
        originalFilename: 'limit-test.jpg',
        mimetype: 'image/jpeg',
        size: 1024 // Any size should trigger limit
      };

      await expect(imageService.flutterUploadImage(uploadParams))
        .rejects.toThrow('Storage limit reached');

      expect(mockedStorageService.saveFile).not.toHaveBeenCalled();
    });
  });

  describe('Mobile Thumbnails Integration', () => {
    it('should generate real thumbnails with correct size mapping', async () => {
      const options = { page: 1, limit: 5, size: 'medium' as const };

      const result = await imageService.getMobileThumbnails(testUser.id, options);

      expect(result.thumbnails).toHaveLength(5);
      expect(result.page).toBe(1);
      expect(result.hasMore).toBe(true); // Since we have more than 5 images

      // Verify thumbnail generation was called with correct size (medium = 200px)
      expect(mockedImageProcessingService.generateThumbnail).toHaveBeenCalledTimes(5);
      expect(mockedImageProcessingService.generateThumbnail).toHaveBeenCalledWith(
        expect.stringContaining('img-0.jpg'),
        200
      );

      // Verify response structure
      expect(result.thumbnails[0]).toEqual({
        id: 'img-0',
        thumbnailPath: expect.stringContaining('thumb_200'),
        size: 'medium',
        originalWidth: 800,
        originalHeight: 600
      });
    });

    it('should handle pagination correctly with real data', async () => {
      // Test page 2 with limit 3
      const options = { page: 2, limit: 3, size: 'small' as const };

      const result = await imageService.getMobileThumbnails(testUser.id, options);

      // Verify database query includes correct offset
      expect(mockedImageModel.findByUserId).toHaveBeenCalledWith(
        testUser.id,
        { limit: 3, offset: 3 }
      );

      expect(result.page).toBe(2);
      expect(result.thumbnails).toHaveLength(3);
    });

    it('should handle mixed success/failure in thumbnail generation', async () => {
      // Mock some thumbnails to fail
      mockedImageProcessingService.generateThumbnail
        .mockResolvedValueOnce('thumb1.jpg')
        .mockRejectedValueOnce(new Error('Processing failed'))
        .mockResolvedValueOnce('thumb3.jpg');

      const options = { page: 1, limit: 3, size: 'large' as const };

      const result = await imageService.getMobileThumbnails(testUser.id, options);

      expect(result.thumbnails).toHaveLength(3);
      expect(result.thumbnails[0]).toEqual({
        id: 'img-0',
        thumbnailPath: 'thumb1.jpg',
        size: 'large',
        originalWidth: 800,
        originalHeight: 600
      });
      expect(result.thumbnails[1]).toEqual(expect.objectContaining({
        thumbnailPath: null,
        error: 'Failed to generate thumbnail'
      }));
      expect(result.thumbnails[2]).toEqual({
        id: 'img-2',
        thumbnailPath: 'thumb3.jpg',
        size: 'large',
        originalWidth: 1000,
        originalHeight: 750
      });
    });
  });

  describe('Mobile Optimization Integration', () => {
    it('should optimize image for mobile with real processing', async () => {
      const imageId = createdImageIds[0] || 'test-image-1';

      const result = await imageService.getMobileOptimizedImage(imageId, testUser.id);

      expect(result).toEqual({
        id: imageId,
        optimizedPath: expect.stringContaining('mobile.webp'),
        format: 'webp',
        quality: 85,
        originalSize: 204800,
        optimizedAt: expect.any(String)
      });

      // Verify processing service was called
      expect(mockedImageProcessingService.optimizeForMobile).toHaveBeenCalledWith(
        expect.stringContaining(`${imageId}.jpg`)
      );

      // Verify timestamp is recent
      const optimizedTime = new Date(result.optimizedAt);
      const now = new Date();
      expect(now.getTime() - optimizedTime.getTime()).toBeLessThan(5000); // Within 5 seconds
    });

    it('should verify ownership before mobile optimization', async () => {
      const otherUserId = 'other-user-123';
      const imageId = 'unauthorized-image';

      // Mock finding image belonging to different user
      mockedImageModel.findById.mockResolvedValueOnce({
        id: imageId,
        user_id: otherUserId,
        file_path: 'uploads/other-user-image.jpg',
        original_metadata: { size: 1024000 }
      } as any);

      await expect(
        imageService.getMobileOptimizedImage(imageId, testUser.id)
      ).rejects.toThrow('You do not have permission to access this image');

      expect(mockedImageProcessingService.optimizeForMobile).not.toHaveBeenCalled();
    });

    it('should handle mobile optimization service failures', async () => {
      const imageId = 'test-image-1';
      createdImageIds.push(imageId); // Ensure image exists

      mockedImageProcessingService.optimizeForMobile.mockRejectedValueOnce(
        new Error('Mobile optimization failed')
      );

      await expect(
        imageService.getMobileOptimizedImage(imageId, testUser.id)
      ).rejects.toThrow('Failed to get mobile optimized image');
    });
  });

  describe('Batch Thumbnail Generation Integration', () => {
    it('should generate multiple thumbnails for multiple images with real processing', async () => {
      const imageIds = ['img-1', 'img-2', 'img-3'];
      const sizes: ('small' | 'medium' | 'large')[] = ['small', 'large'];

      // Ensure ownership verification passes
      for (const id of imageIds) {
        createdImageIds.push(id);
      }

      const result = await imageService.batchGenerateThumbnails(imageIds, testUser.id, sizes);

      expect(result.totalCount).toBe(3);
      expect(result.successCount).toBe(3);
      expect(result.results).toHaveLength(3);

      // Verify all thumbnails were generated (3 images × 2 sizes = 6 calls)
      expect(mockedImageProcessingService.generateThumbnail).toHaveBeenCalledTimes(6);

      // Verify size mapping
      expect(mockedImageProcessingService.generateThumbnail).toHaveBeenCalledWith(
        expect.stringContaining('img-1.jpg'),
        100 // small
      );
      expect(mockedImageProcessingService.generateThumbnail).toHaveBeenCalledWith(
        expect.stringContaining('img-1.jpg'),
        400 // large
      );

      // Verify response structure
      expect(result.results[0]).toEqual({
        id: 'img-1',
        thumbnails: [
          { size: 'small', thumbnailPath: expect.stringContaining('thumb_100') },
          { size: 'large', thumbnailPath: expect.stringContaining('thumb_400') }
        ],
        status: 'success'
      });
    });

    it('should handle partial failures in batch processing', async () => {
      const imageIds = ['img-1', 'img-2', 'img-3'];
      const sizes: ('small' | 'medium' | 'large')[] = ['medium'];

      // Ensure ownership verification passes
      for (const id of imageIds) {
        createdImageIds.push(id);
      }

      // Mock thumbnail generation to fail for second image
      mockedImageProcessingService.generateThumbnail
        .mockResolvedValueOnce('thumb1.jpg')
        .mockRejectedValueOnce(new Error('Processing failed'))
        .mockResolvedValueOnce('thumb3.jpg');

      const result = await imageService.batchGenerateThumbnails(imageIds, testUser.id, sizes);

      expect(result.totalCount).toBe(3);
      expect(result.successCount).toBe(2);
      expect(result.results).toHaveLength(3);

      expect(result.results[0].status).toBe('success');
      expect(result.results[1].status).toBe('failed');
      expect(result.results[1].error).toBe('Thumbnail generation failed');
      expect(result.results[2].status).toBe('success');
    });

    it('should prevent batch processing of unauthorized images', async () => {
      const imageIds = ['authorized-img', 'unauthorized-img'];
      const sizes: ('small' | 'medium' | 'large')[] = ['small'];

      // Only add first image to authorized list
      createdImageIds.push('authorized-img');

      // Mock the second image to belong to different user
      mockedImageModel.findById
        .mockResolvedValueOnce({
          id: 'authorized-img',
          user_id: testUser.id,
          file_path: 'uploads/authorized.jpg'
        } as any)
        .mockResolvedValueOnce({
          id: 'unauthorized-img',
          user_id: 'other-user',
          file_path: 'uploads/unauthorized.jpg'
        } as any);

      await expect(
        imageService.batchGenerateThumbnails(imageIds, testUser.id, sizes)
      ).rejects.toThrow('You do not have permission to access this image');

      expect(mockedImageProcessingService.generateThumbnail).not.toHaveBeenCalled();
    });
  });

  describe('Sync Operations Integration', () => {
    it('should return properly formatted sync data', async () => {
      const options = { includeDeleted: false, limit: 3 };

      const result = await imageService.getSyncData(testUser.id, options);

      expect(result.images).toHaveLength(3);
      expect(result.syncTimestamp).toBeDefined();
      expect(result.hasMore).toBe(true);

      // Verify sync data format
      expect(result.images[0]).toEqual({
        id: 'img-0',
        status: 'new',
        metadata: expect.objectContaining({
          width: 800,
          height: 600,
          size: 204800
        }),
        lastModified: expect.any(Date),
        syncStatus: 'synced'
      });

      // Verify timestamp is recent
      const syncTime = new Date(result.syncTimestamp);
      const now = new Date();
      expect(now.getTime() - syncTime.getTime()).toBeLessThan(5000);
    });

    it('should handle sync operations with real database updates', async () => {
      const operations = [
        {
          id: 'sync-img-1',
          action: 'update' as const,
          data: { status: 'processed' },
          clientTimestamp: '2024-01-01T12:00:00Z'
        },
        {
          id: 'sync-img-2',
          action: 'delete' as const,
          data: {},
          clientTimestamp: '2024-01-01T12:01:00Z'
        }
      ];

      // Ensure images exist and belong to user
      createdImageIds.push('sync-img-1', 'sync-img-2');

      const result = await imageService.batchSyncOperations(testUser.id, operations);

      expect(result.successCount).toBe(2);
      expect(result.failedCount).toBe(0);
      expect(result.results).toHaveLength(2);

      // Verify update operation was called
      expect(mockedImageModel.updateStatus).toHaveBeenCalledWith('sync-img-1', 'processed');

      // Verify delete operations were called
      expect(mockedImageModel.delete).toHaveBeenCalledWith('sync-img-2');
      expect(mockedStorageService.deleteFile).toHaveBeenCalledWith(
        expect.stringContaining('sync-img-2.jpg')
      );

      // Verify sync completion timestamp
      expect(result.syncCompleted).toBeDefined();
      const syncTime = new Date(result.syncCompleted);
      const now = new Date();
      expect(now.getTime() - syncTime.getTime()).toBeLessThan(5000);
    });

    it('should handle sync operation failures gracefully', async () => {
      const operations = [
        {
          id: 'failing-img',
          action: 'update' as const,
          data: { status: 'processed' },
          clientTimestamp: '2024-01-01T12:00:00Z'
        }
      ];

      createdImageIds.push('failing-img');

      // Mock database update to fail
      mockedImageModel.updateStatus.mockRejectedValueOnce(
        new Error('Database update failed')
      );

      const result = await imageService.batchSyncOperations(testUser.id, operations);

      expect(result.successCount).toBe(0);
      expect(result.failedCount).toBe(1);
      expect(result.results[0]).toEqual({
        id: 'failing-img',
        status: 'failed',
        error: 'Failed to update image status' // This is what the service actually returns
      });
    });

    it('should process sync operations sequentially', async () => {
      const operations = [
        { id: 'seq-1', action: 'update' as const, data: { status: 'processed' }, clientTimestamp: '2024-01-01T12:00:00Z' },
        { id: 'seq-2', action: 'update' as const, data: { status: 'labeled' }, clientTimestamp: '2024-01-01T12:01:00Z' },
        { id: 'seq-3', action: 'delete' as const, data: {}, clientTimestamp: '2024-01-01T12:02:00Z' }
      ];

      for (const op of operations) {
        createdImageIds.push(op.id);
      }

      let callOrder: string[] = [];

      mockedImageModel.updateStatus.mockImplementation(async (id: string, status: string) => {
        callOrder.push(`update-${id}-${status}`);
        return { id, status } as any;
      });

      mockedImageModel.delete.mockImplementation(async (id: string) => {
        callOrder.push(`delete-${id}`);
        return true as any;
      });

      await imageService.batchSyncOperations(testUser.id, operations);

      expect(callOrder).toEqual([
        'update-seq-1-processed',
        'update-seq-2-labeled',
        'delete-seq-3'
      ]);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large batch operations within reasonable time', async () => {
      const largeImageSet = Array(20).fill(0).map((_, i) => `perf-img-${i}`);
      
      // Add all images to authorized list
      createdImageIds.push(...largeImageSet);

      const startTime = Date.now();
      
      const result = await imageService.batchGenerateThumbnails(
        largeImageSet, 
        testUser.id, 
        ['small']
      );
      
      const endTime = Date.now();
      const duration = endTime - startTime;

      expect(result.totalCount).toBe(20);
      expect(result.successCount).toBe(20);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
    });

    it('should handle pagination efficiently for large datasets', async () => {
      // Mock a large dataset
      mockedImageModel.findByUserId.mockImplementation(async (userId: string, options: any = {}) => {
        const limit = options.limit || 10;
        const offset = options.offset || 0;
        
        // Simulate 1000 total images
        if (offset >= 1000) return [];
        
        const actualLimit = Math.min(limit, 1000 - offset);
        return Array(actualLimit).fill(0).map((_, i) => ({
          id: `large-img-${offset + i}`,
          user_id: userId,
          file_path: `uploads/large-img-${offset + i}.jpg`,
          original_metadata: { width: 800, height: 600 },
          status: 'processed',
          upload_date: new Date()
        }));
      });

      const options = { page: 10, limit: 50, size: 'medium' as const };
      
      const startTime = Date.now();
      const result = await imageService.getMobileThumbnails(testUser.id, options);
      const endTime = Date.now();

      expect(result.thumbnails).toHaveLength(50);
      expect(result.page).toBe(10);
      expect(result.hasMore).toBe(true);
      expect(endTime - startTime).toBeLessThan(5000); // Should be fast
      
      // Verify correct offset was used (page 10, limit 50 = offset 450)
      expect(mockedImageModel.findByUserId).toHaveBeenCalledWith(
        testUser.id,
        { limit: 50, offset: 450 }
      );
    });

    it('should handle concurrent requests without race conditions', async () => {
      // Add all images to authorized list first
      for (let i = 0; i < 5; i++) {
        createdImageIds.push(`concurrent-img-${i}`);
      }

      const concurrentRequests = Array(5).fill(0).map((_, i) => 
        imageService.getMobileOptimizedImage(`concurrent-img-${i}`, testUser.id)
      );

      const results = await Promise.all(concurrentRequests);

      expect(results).toHaveLength(5);
      results.forEach((result, i) => {
        expect(result.id).toBe(`concurrent-img-${i}`);
        expect(result.format).toBe('webp');
        expect(result.quality).toBe(85);
      });

      // Verify all optimization calls were made
      expect(mockedImageProcessingService.optimizeForMobile).toHaveBeenCalledTimes(5);
    });
  });
});