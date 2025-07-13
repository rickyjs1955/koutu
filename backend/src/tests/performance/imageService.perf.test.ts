import { performance } from 'perf_hooks';
import { imageService } from '../../services/imageService';
import { imageModel } from '../../models/imageModel';
import { imageProcessingService } from '../../services/imageProcessingService';
import { storageService } from '../../services/storageService';
import { ApiError } from '../../utils/ApiError';
import fs from 'fs';
import path from 'path';

jest.mock('../../models/imageModel');
jest.mock('../../services/imageProcessingService');
jest.mock('../../services/storageService');

const mockImageModel = imageModel as jest.Mocked<typeof imageModel>;
const mockImageProcessingService = imageProcessingService as jest.Mocked<typeof imageProcessingService>;
const mockStorageService = storageService as jest.Mocked<typeof storageService>;

// Add type declarations for missing methods
declare global {
  var gc: (() => void) | undefined;
}

interface ImageRecord {
  id: string;
  user_id: string;
  file_path: string;
  status: 'new' | 'processed' | 'failed';
  upload_date: string;
  original_metadata: Record<string, any>;
}

interface ImageStats {
  total: number;
  totalSize: number;
}

interface ImageMetadata {
  width: number;
  height: number;
  format: string;
  space: string;
  density?: number;
  hasProfile?: boolean;
  hasAlpha?: boolean;
  channels?: number;
  size?: number;
}

interface ValidationResult {
  width: number;
  height: number;
  format: string;
  space: string;
}

interface UploadParams {
  userId: string;
  fileBuffer: Buffer;
  originalFilename: string;
  mimetype: string;
  size: number;
}

interface SyncOperation {
  id: string;
  action: 'update' | 'delete' | 'create';
  data: { status: 'new' | 'processed' | 'failed' };
  clientTimestamp: string;
}

interface MobileThumbnailOptions {
  page: number;
  limit: number;
  size: 'small' | 'medium' | 'large';
}

describe('ImageService Performance Tests', () => {
  const TEST_USER_ID = 'test-user-123';
  const PERFORMANCE_THRESHOLD = {
    singleUpload: 500, // 500ms
    batchOperations: 1000, // 1s for batch
    thumbnailGeneration: 300, // 300ms
    memoryLeakTolerance: 50 * 1024 * 1024, // 50MB
  };

  beforeEach(() => {
    jest.clearAllMocks();
    // Force garbage collection if available
    if (global.gc) global.gc();
  });

  afterEach(() => {
    jest.clearAllTimers();
  });

  describe('Memory Usage Monitoring', () => {
    const getMemoryUsage = () => {
      const usage = process.memoryUsage();
      return {
        heapUsed: usage.heapUsed,
        heapTotal: usage.heapTotal,
        external: usage.external,
        rss: usage.rss
      };
    };

    it('should not leak memory during multiple image uploads', async () => {
      const initialMemory = getMemoryUsage();
      
      // Mock successful responses
      mockStorageService.saveFile.mockResolvedValue('/test/path/image.jpg');
      mockImageProcessingService.validateImageBuffer.mockResolvedValue({
        width: 1000,
        height: 800,
        format: 'jpeg',
        space: 'srgb'
      });
      mockImageProcessingService.extractMetadata.mockResolvedValue({
        width: 1000,
        height: 800,
        format: 'jpeg',
        space: 'srgb',
        density: 72,
        hasProfile: false,
        hasAlpha: false,
        channels: 3
      });
      mockImageModel.create.mockResolvedValue({
        id: 'test-image-id',
        user_id: TEST_USER_ID,
        file_path: '/test/path/image.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: {}
      } as ImageRecord);
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 10,
        totalSize: 1024 * 1024 * 10 // 10MB
      } as ImageStats);

      const testBuffer = Buffer.alloc(1024 * 1024); // 1MB test image
      const uploadParams: UploadParams = {
        userId: TEST_USER_ID,
        fileBuffer: testBuffer,
        originalFilename: 'test.jpg',
        mimetype: 'image/jpeg',
        size: testBuffer.length
      };

      // Perform multiple uploads
      const uploadPromises = Array.from({ length: 20 }, () => 
        imageService.uploadImage(uploadParams)
      );

      await Promise.all(uploadPromises);

      // Force garbage collection
      if (global.gc) global.gc();

      const finalMemory = getMemoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      expect(memoryIncrease).toBeLessThan(PERFORMANCE_THRESHOLD.memoryLeakTolerance);
    });
  });

  describe('Single Image Upload Performance', () => {
    beforeEach(() => {
      mockStorageService.saveFile.mockResolvedValue('/test/path/image.jpg');
      mockImageProcessingService.validateImageBuffer.mockResolvedValue({
        width: 1000,
        height: 800,
        format: 'jpeg',
        space: 'srgb'
      });
      mockImageProcessingService.extractMetadata.mockResolvedValue({
        width: 1000,
        height: 800,
        format: 'jpeg',
        space: 'srgb',
        density: 72,
        hasProfile: false,
        hasAlpha: false,
        channels: 3
      });
      mockImageModel.create.mockResolvedValue({
        id: 'test-image-id',
        user_id: TEST_USER_ID,
        file_path: '/test/path/image.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: {}
      } as ImageRecord);
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 10,
        totalSize: 1024 * 1024 * 10
      } as ImageStats);
    });

    it('should upload small image within performance threshold', async () => {
      const smallBuffer = Buffer.alloc(512 * 1024); // 512KB
      const uploadParams: UploadParams = {
        userId: TEST_USER_ID,
        fileBuffer: smallBuffer,
        originalFilename: 'small.jpg',
        mimetype: 'image/jpeg',
        size: smallBuffer.length
      };

      const startTime = performance.now();
      await imageService.uploadImage(uploadParams);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.singleUpload);
    });

    it('should upload large image within reasonable time', async () => {
      const largeBuffer = Buffer.alloc(5 * 1024 * 1024); // 5MB
      const uploadParams: UploadParams = {
        userId: TEST_USER_ID,
        fileBuffer: largeBuffer,
        originalFilename: 'large.jpg',
        mimetype: 'image/jpeg',
        size: largeBuffer.length
      };

      const startTime = performance.now();
      await imageService.uploadImage(uploadParams);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.singleUpload * 2); // Allow 2x for large files
    });

    it('should handle concurrent uploads efficiently', async () => {
      const testBuffer = Buffer.alloc(1024 * 1024); // 1MB
      const baseUploadParams: UploadParams = {
        userId: TEST_USER_ID,
        fileBuffer: testBuffer,
        originalFilename: 'concurrent.jpg',
        mimetype: 'image/jpeg',
        size: testBuffer.length
      };

      const concurrentUploads = 5;
      const uploadPromises = Array.from({ length: concurrentUploads }, (_, i) => ({
        ...baseUploadParams,
        originalFilename: `concurrent-${i}.jpg`
      }));

      const startTime = performance.now();
      await Promise.all(uploadPromises.map(params => imageService.uploadImage(params)));
      const endTime = performance.now();

      const avgDuration = (endTime - startTime) / concurrentUploads;
      expect(avgDuration).toBeLessThan(PERFORMANCE_THRESHOLD.singleUpload * 1.5);
    });
  });

  describe('Batch Operations Performance', () => {
    beforeEach(() => {
      const mockImage: ImageRecord = {
        id: 'test-image-id',
        user_id: TEST_USER_ID,
        file_path: '/test/path/image.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: {}
      };

      mockImageModel.findById.mockResolvedValue(mockImage);
      mockImageModel.batchUpdateStatus.mockResolvedValue(10);
      mockImageProcessingService.generateThumbnail.mockResolvedValue('/test/thumbnails/thumb.jpg');
    });

    it('should handle batch status updates efficiently', async () => {
      const imageIds = Array.from({ length: 100 }, (_, i) => `image-${i}`);

      const startTime = performance.now();
      await imageService.batchUpdateStatus(imageIds, TEST_USER_ID, 'processed');
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.batchOperations);
    });

    it('should generate thumbnails in batch within threshold', async () => {
      const imageIds = Array.from({ length: 20 }, (_, i) => `image-${i}`);
      const sizes = ['small', 'medium', 'large'] as const;

      const startTime = performance.now();
      await imageService.batchGenerateThumbnails(imageIds, TEST_USER_ID, sizes);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.batchOperations);
    });

    it('should handle batch sync operations efficiently', async () => {
      const operations: SyncOperation[] = Array.from({ length: 50 }, (_, i) => ({
        id: `image-${i}`,
        action: 'update',
        data: { status: 'processed' },
        clientTimestamp: new Date().toISOString()
      }));

      const startTime = performance.now();
      await imageService.batchSyncOperations(TEST_USER_ID, operations);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.batchOperations);
    });
  });

  describe('Thumbnail Generation Performance', () => {
    beforeEach(() => {
      mockImageModel.findById.mockResolvedValue({
        id: 'test-image-id',
        user_id: TEST_USER_ID,
        file_path: '/test/path/image.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: {}
      } as ImageRecord);
      mockImageProcessingService.generateThumbnail.mockResolvedValue('/test/thumbnails/thumb.jpg');
      mockImageModel.updateMetadata.mockResolvedValue(true);
    });

    it('should generate single thumbnail within threshold', async () => {
      const startTime = performance.now();
      await imageService.generateThumbnail('test-image-id', TEST_USER_ID, 200);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.thumbnailGeneration);
    });

    it('should handle different thumbnail sizes efficiently', async () => {
      const sizes = [100, 200, 400, 800];
      const durations: number[] = [];

      for (const size of sizes) {
        const startTime = performance.now();
        await imageService.generateThumbnail('test-image-id', TEST_USER_ID, size);
        const endTime = performance.now();
        durations.push(endTime - startTime);
      }

      // All thumbnail generations should be within threshold
      durations.forEach(duration => {
        expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.thumbnailGeneration);
      });
    });
  });

  describe('Mobile Operations Performance', () => {
    beforeEach(() => {
      mockImageModel.findByUserId.mockResolvedValue([
        {
          id: 'image-1',
          user_id: TEST_USER_ID,
          file_path: '/test/path/image1.jpg',
          status: 'new',
          upload_date: new Date().toISOString(),
          original_metadata: { width: 1000, height: 800 }
        } as ImageRecord
      ]);
      mockImageProcessingService.generateThumbnail.mockResolvedValue('/test/thumbnails/thumb.jpg');
      mockImageProcessingService.optimizeForMobile.mockResolvedValue('/test/optimized/mobile.webp');
      mockImageModel.findById.mockResolvedValue({
        id: 'image-1',
        user_id: TEST_USER_ID,
        file_path: '/test/path/image1.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: { width: 1000, height: 800, size: 1024 * 1024 }
      } as ImageRecord);
    });

    it('should load mobile thumbnails efficiently', async () => {
      const options: MobileThumbnailOptions = { page: 1, limit: 20, size: 'medium' };

      const startTime = performance.now();
      await imageService.getMobileThumbnails(TEST_USER_ID, options);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.batchOperations);
    });

    it('should optimize images for mobile quickly', async () => {
      const startTime = performance.now();
      await imageService.getMobileOptimizedImage('image-1', TEST_USER_ID);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.singleUpload);
    });

    it('should handle Flutter upload with immediate thumbnail generation', async () => {
      mockStorageService.saveFile.mockResolvedValue('/test/path/flutter.jpg');
      mockImageProcessingService.validateImageBuffer.mockResolvedValue({
        width: 1000,
        height: 800,
        format: 'jpeg',
        space: 'srgb'
      });
      mockImageProcessingService.extractMetadata.mockResolvedValue({
        width: 1000,
        height: 800,
        format: 'jpeg',
        space: 'srgb',
        density: 72,
        hasProfile: false,
        hasAlpha: false,
        channels: 3
      });
      mockImageModel.create.mockResolvedValue({
        id: 'flutter-image-id',
        user_id: TEST_USER_ID,
        file_path: '/test/path/flutter.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: {}
      } as ImageRecord);
      mockImageModel.getUserImageStats.mockResolvedValue({
        total: 10,
        totalSize: 1024 * 1024 * 10
      } as ImageStats);
      mockImageModel.findById.mockResolvedValue({
        id: 'flutter-image-id',
        user_id: TEST_USER_ID,
        file_path: '/test/path/flutter.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: {}
      } as ImageRecord);
      mockImageModel.updateMetadata.mockResolvedValue(true);

      const testBuffer = Buffer.alloc(1024 * 1024); // 1MB
      const uploadParams: UploadParams = {
        userId: TEST_USER_ID,
        fileBuffer: testBuffer,
        originalFilename: 'flutter.jpg',
        mimetype: 'image/jpeg',
        size: testBuffer.length
      };

      const startTime = performance.now();
      await imageService.flutterUploadImage(uploadParams);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.singleUpload * 1.5); // Allow extra time for thumbnail
    });
  });

  describe('Error Handling Performance', () => {
    it('should fail fast for invalid files', async () => {
      const invalidBuffer = Buffer.alloc(1024);
      mockImageProcessingService.validateImageBuffer.mockRejectedValue(new Error('Invalid image'));

      const uploadParams: UploadParams = {
        userId: TEST_USER_ID,
        fileBuffer: invalidBuffer,
        originalFilename: 'invalid.txt',
        mimetype: 'text/plain',
        size: invalidBuffer.length
      };

      const startTime = performance.now();
      
      try {
        await imageService.uploadImage(uploadParams);
      } catch (error) {
        // Expected error
      }
      
      const endTime = performance.now();
      const duration = endTime - startTime;

      // Should fail quickly, not wait for timeouts
      expect(duration).toBeLessThan(100); // 100ms for quick failure
    });

    it('should handle validation errors efficiently', async () => {
      const oversizedBuffer = Buffer.alloc(10 * 1024 * 1024); // 10MB (over limit)
      
      const uploadParams: UploadParams = {
        userId: TEST_USER_ID,
        fileBuffer: oversizedBuffer,
        originalFilename: 'oversized.jpg',
        mimetype: 'image/jpeg',
        size: oversizedBuffer.length
      };

      const startTime = performance.now();
      
      try {
        await imageService.uploadImage(uploadParams);
      } catch (error) {
        expect(error).toBeInstanceOf(ApiError);
      }
      
      const endTime = performance.now();
      const duration = endTime - startTime;

      expect(duration).toBeLessThan(50); // Should fail validation immediately
    });
  });

  describe('Resource Cleanup Performance', () => {
    it('should clean up resources efficiently on delete', async () => {
      mockImageModel.findById.mockResolvedValue({
        id: 'delete-image-id',
        user_id: TEST_USER_ID,
        file_path: '/test/path/delete.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: {}
      } as ImageRecord);
      mockImageModel.findDependentGarments.mockResolvedValue([]);
      mockImageModel.findDependentPolygons.mockResolvedValue([]);
      mockStorageService.deleteFile.mockResolvedValue(undefined);
      mockImageModel.delete.mockResolvedValue(true);

      const startTime = performance.now();
      await imageService.deleteImage('delete-image-id', TEST_USER_ID);
      const endTime = performance.now();

      const duration = endTime - startTime;
      expect(duration).toBeLessThan(PERFORMANCE_THRESHOLD.singleUpload);
    });
  });

  describe('Stress Testing', () => {
    it('should handle high-volume operations without degradation', async () => {
      const imageIds = Array.from({ length: 1000 }, (_, i) => `stress-image-${i}`);
      
      mockImageModel.findById.mockResolvedValue({
        id: 'stress-image-id',
        user_id: TEST_USER_ID,
        file_path: '/test/path/stress.jpg',
        status: 'new',
        upload_date: new Date().toISOString(),
        original_metadata: {}
      } as ImageRecord);

      const durations: number[] = [];
      const batchSize = 100;

      for (let i = 0; i < imageIds.length; i += batchSize) {
        const batch = imageIds.slice(i, i + batchSize);
        
        const startTime = performance.now();
        await imageService.batchUpdateStatus(batch, TEST_USER_ID, 'processed');
        const endTime = performance.now();
        
        durations.push(endTime - startTime);
      }

      // Performance should not degrade significantly across batches
      const firstBatch = durations[0];
      const lastBatch = durations[durations.length - 1];
      const degradation = (lastBatch - firstBatch) / firstBatch;

      expect(degradation).toBeLessThan(0.5); // Less than 50% degradation
    });
  });
});