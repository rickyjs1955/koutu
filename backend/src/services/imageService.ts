// /backend/src/services/imageService.ts
import { imageModel, CreateImageInput, ImageQueryOptions } from '../models/imageModel';
import { imageProcessingService } from './imageProcessingService';
import { storageService } from './storageService';
import { ApiError } from '../utils/ApiError';
import path from 'path';

interface ImageUploadParams {
  userId: string;
  fileBuffer: Buffer;
  originalFilename: string;
  mimetype: string;
  size: number;
}

interface ImageValidationResult {
  isValid: boolean;
  metadata?: any;
  errors?: string[];
}

export const imageService = {
  /**
   * Upload and process an image with comprehensive validation
   */
  async uploadImage(params: ImageUploadParams) {
    const { userId, fileBuffer, originalFilename, mimetype, size } = params;

    // Business Rule 1: Validate file integrity
    const validation = await this.validateImageFile(fileBuffer, mimetype, size);
    if (!validation.isValid) {
      throw ApiError.validation(
        `Image validation failed: ${validation.errors?.join(', ')}`,
        'file',
        { filename: originalFilename, size, mimetype }
      );
    }

    // Business Rule 2: Check user upload limits
    await this.checkUserUploadLimits(userId);

    try {
      // Save the file to storage
      let filePath = await storageService.saveFile(fileBuffer, originalFilename);

      // Extract comprehensive metadata
      let metadata = await imageProcessingService.extractMetadata(filePath);

      // Integrate color space conversion in imageService.uploadImage()
      if (validation.metadata?.space && validation.metadata.space !== 'srgb') {
        console.log(`Converting ${validation.metadata.space} to sRGB for Instagram compatibility`);
        filePath = await imageProcessingService.convertToSRGB(filePath);
        // Re-extract metadata after conversion
        metadata = await imageProcessingService.extractMetadata(filePath);
      }

      // Create enhanced metadata object
      const enhancedMetadata = {
        // Original file information
        filename: originalFilename,
        mimetype,
        size,
        // Processed image information
        width: metadata.width,
        height: metadata.height,
        format: metadata.format,
        // Upload context
        uploadedAt: new Date().toISOString(),
        // Technical details
        density: metadata.density,
        hasProfile: metadata.hasProfile,
        hasAlpha: metadata.hasAlpha,
        channels: metadata.channels,
        space: metadata.space,
        // File hash for deduplication (future enhancement)
        // fileHash: await this.calculateFileHash(fileBuffer)
      };

      // Create database record
      const image = await imageModel.create({
        user_id: userId,
        file_path: filePath,
        original_metadata: enhancedMetadata
      });

      return image;
    } catch (error) {
      // If database creation fails, clean up the uploaded file
      console.error('Error during image upload:', error);
      throw ApiError.internal('Failed to process image upload', 'UPLOAD_PROCESSING_ERROR');
    }
  },

  /**
   * Validate image file integrity and format
   */
  async validateImageFile(fileBuffer: Buffer, mimetype: string, size: number): Promise<ImageValidationResult> {
    const errors: string[] = [];

    try {
      // Validate file size (8MB)
      const MAX_FILE_SIZE = 8388608; // 8MB
      if (size > MAX_FILE_SIZE) {
        errors.push(`File too large (max 8MB, got ${Math.round(size / 1024 / 1024)}MB)`);
      }

      // Validate MIME type - Instagram formats
      const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/bmp'];
      if (!allowedMimeTypes.includes(mimetype)) {
        errors.push(`Unsupported format: ${mimetype}. Only JPEG, PNG, and BMP allowed`);
      }

      // Validate actual image content
      const metadata = await imageProcessingService.validateImageBuffer(fileBuffer);

      if (metadata.width && metadata.height) {
        // Instagram resolution requirements
        const MIN_WIDTH = 320;
        const MAX_WIDTH = 1440;
        
        if (metadata.width < MIN_WIDTH) {
          errors.push(`Image width too small (min: ${MIN_WIDTH}px, got: ${metadata.width}px)`);
        }
        
        if (metadata.width > MAX_WIDTH) {
          errors.push(`Image width too large (max: ${MAX_WIDTH}px, got: ${metadata.width}px)`);
        }

        // Instagram aspect ratio validation (4:5 to 1.91:1)
        const aspectRatio = metadata.width / metadata.height;
        const MIN_ASPECT_RATIO = 0.8; // 4:5
        const MAX_ASPECT_RATIO = 1.91; // 1.91:1
        
        if (aspectRatio < MIN_ASPECT_RATIO) {
          errors.push(`Image too tall for Instagram (min 4:5 ratio, got ${aspectRatio.toFixed(2)}:1). Consider cropping to portrait format.`);
        }
        
        if (aspectRatio > MAX_ASPECT_RATIO) {
          errors.push(`Image too wide for Instagram (max 1.91:1 ratio, got ${aspectRatio.toFixed(2)}:1). Consider cropping to landscape format.`);
        }

        // Color space validation (if available in metadata)
        if (metadata.space && metadata.space !== 'srgb') {
          console.warn(`Non-sRGB color space detected: ${metadata.space}. Consider conversion.`);
          // Note: We might want to auto-convert or warn the user
        }
      } else {
        errors.push('Unable to determine image dimensions');
      }

      // Validate format consistency
      if (metadata.format) {
        const formatMimeMap: Record<string, string> = {
          'jpeg': 'image/jpeg',
          'png': 'image/png',
          'bmp': 'image/bmp'
        };

        const expectedMime = formatMimeMap[metadata.format];
        if (expectedMime && expectedMime !== mimetype) {
          errors.push(`Format mismatch: expected ${expectedMime}, got ${mimetype}`);
        }
      }

      return {
        isValid: errors.length === 0,
        metadata,
        errors: errors.length > 0 ? errors : undefined
      };
    } catch (error) {
      errors.push('Invalid or corrupted image file');
      return { isValid: false, errors };
    }
  },

  /**
   * Check user upload limits (business rule)
   */
  async checkUserUploadLimits(userId: string): Promise<void> {
    try {
      const stats = await imageModel.getUserImageStats(userId);
      
      // Business Rule: Maximum images per user
      const maxImagesPerUser = 1000;
      if (stats.total >= maxImagesPerUser) {
        throw ApiError.businessLogic(
          `Upload limit reached. Maximum ${maxImagesPerUser} images allowed per user.`,
          'max_images_per_user',
          'image'
        );
      }

      // Business Rule: Maximum storage per user (100MB)
      const maxStoragePerUser = 500 * 1024 * 1024; // 500MB
      if (stats.totalSize >= maxStoragePerUser) {
        throw ApiError.businessLogic(
          `Storage limit reached. Maximum ${Math.round(maxStoragePerUser / (1024 * 1024))}MB allowed per user.`,
          'max_storage_per_user',
          'image'
        );
      }
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error checking user upload limits:', error);
      // Don't fail upload for limit check errors, just log
    }
  },

  /**
   * Get images for a user with filtering and pagination
   */
  async getUserImages(userId: string, options: ImageQueryOptions = {}) {
    try {
      // Business Rule: Apply default limits
      const safeOptions = {
        ...options,
        limit: options.limit && options.limit <= 100 ? options.limit : 20,
        offset: options.offset || 0
      };

      const images = await imageModel.findByUserId(userId, safeOptions);
      return images;
    } catch (error) {
      console.error('Error retrieving user images:', error);
      throw ApiError.internal('Failed to retrieve images');
    }
  },

  /**
   * Get image by ID with ownership verification
   */
  async getImageById(imageId: string, userId: string) {
    try {
      const image = await imageModel.findById(imageId);
      
      if (!image) {
        throw ApiError.notFound('Image not found');
      }

      // Business Rule: Verify ownership
      if (image.user_id !== userId) {
        throw ApiError.authorization(
          'You do not have permission to access this image',
          'image',
          'read'
        );
      }

      return image;
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error retrieving image:', error);
      throw ApiError.internal('Failed to retrieve image');
    }
  },

  /**
   * Update image status with business rule validation
   */
  async updateImageStatus(imageId: string, userId: string, newStatus: 'new' | 'processed' | 'labeled') {
    try {
      // First verify ownership
      const image = await this.getImageById(imageId, userId);

      // Business Rule: Status transition validation
      const validTransitions: Record<string, string[]> = {
        'new': ['processed', 'labeled'],
        'processed': ['labeled'],
        'labeled': [] // Cannot change from labeled
      };

      const allowedTransitions = validTransitions[image.status] || [];
      if (!allowedTransitions.includes(newStatus)) {
        throw ApiError.businessLogic(
          `Cannot change image status from '${image.status}' to '${newStatus}'`,
          'invalid_status_transition',
          'image'
        );
      }

      const updatedImage = await imageModel.updateStatus(imageId, newStatus);
      
      if (!updatedImage) {
        throw ApiError.internal('Failed to update image status');
      }

      return updatedImage;
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error updating image status:', error);
      throw ApiError.internal('Failed to update image status');
    }
  },

  /**
   * Delete image with dependency checking
   */
  async deleteImage(imageId: string, userId: string) {
    try {
      // First verify ownership
      const image = await this.getImageById(imageId, userId);

      // Business Rule: Check for dependencies
      const dependentGarments = await imageModel.findDependentGarments(imageId);
      if (dependentGarments.length > 0) {
        throw ApiError.businessLogic(
          `Cannot delete image. It is being used by ${dependentGarments.length} garment(s).`,
          'image_has_dependencies',
          'image'
        );
      }

      const dependentPolygons = await imageModel.findDependentPolygons(imageId);
      if (dependentPolygons.length > 0) {
        throw ApiError.businessLogic(
          `Cannot delete image. It has ${dependentPolygons.length} associated polygon(s).`,
          'image_has_polygons',
          'image'
        );
      }

      // Delete file from storage first
      try {
        await storageService.deleteFile(image.file_path);
      } catch (storageError) {
        console.error('Error deleting image file:', storageError);
        // Continue with database deletion even if file deletion fails
      }

      // Delete from database
      const deleted = await imageModel.delete(imageId);
      if (!deleted) {
        throw ApiError.internal('Failed to delete image from database');
      }

      return { success: true, imageId };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error deleting image:', error);
      throw ApiError.internal('Failed to delete image');
    }
  },

  /**
   * Generate thumbnail for an image
   */
  async generateThumbnail(imageId: string, userId: string, size: number = 200) {
    try {
      // Verify ownership and get image
      const image = await this.getImageById(imageId, userId);

      // Generate thumbnail
      const thumbnailPath = await imageProcessingService.generateThumbnail(image.file_path, size);

      // Update image metadata with thumbnail path
      const updatedMetadata = {
        ...image.original_metadata,
        thumbnailPath,
        thumbnailSize: size,
        thumbnailGeneratedAt: new Date().toISOString()
      };

      await imageModel.updateMetadata(imageId, updatedMetadata);

      return { thumbnailPath, size };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error generating thumbnail:', error);
      throw ApiError.internal('Failed to generate thumbnail');
    }
  },

  /**
   * Optimize image for web delivery
   */
  async optimizeForWeb(imageId: string, userId: string) {
    try {
      // Verify ownership and get image
      const image = await this.getImageById(imageId, userId);

      // Generate optimized version
      const optimizedPath = await imageProcessingService.optimizeForWeb(image.file_path);

      // Update image metadata
      const updatedMetadata = {
        ...image.original_metadata,
        optimizedPath,
        optimizedAt: new Date().toISOString()
      };

      await imageModel.updateMetadata(imageId, updatedMetadata);

      // Update status to processed
      await imageModel.updateStatus(imageId, 'processed');

      return { optimizedPath };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error optimizing image:', error);
      throw ApiError.internal('Failed to optimize image');
    }
  },

  /**
   * Get user image statistics
   */
  async getUserImageStats(userId: string) {
    try {
      const stats = await imageModel.getUserImageStats(userId);
      
      // Add business logic calculations
      const enhancedStats = {
        ...stats,
        storageUsedMB: Math.round(stats.totalSize / (1024 * 1024) * 100) / 100,
        averageSizeMB: Math.round(stats.averageSize / (1024 * 1024) * 100) / 100,
        storageLimit: {
          maxImages: 1000,
          maxStorageMB: 500, // Updated from 100
          maxFileSizeMB: 8,
          supportedFormats: ['JPEG', 'PNG', 'BMP'],
          aspectRatioRange: '4:5 to 1.91:1',
          resolutionRange: '320px to 1440px width'
        }
      };

      return enhancedStats;
    } catch (error) {
      console.error('Error getting user image stats:', error);
      throw ApiError.internal('Failed to retrieve image statistics');
    }
  },

  /**
   * Batch update image statuses
   */
  async batchUpdateStatus(imageIds: string[], userId: string, newStatus: 'new' | 'processed' | 'labeled') {
    try {
      // Verify ownership of all images
      const verificationPromises = imageIds.map(id => this.getImageById(id, userId));
      await Promise.all(verificationPromises);

      // Perform batch update
      const updatedCount = await imageModel.batchUpdateStatus(imageIds, newStatus);

      return { updatedCount, total: imageIds.length };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error batch updating image status:', error);
      throw ApiError.internal('Failed to batch update image status');
    }
  },

  /**
   * Get mobile thumbnails - Flutter optimized
   */
  async getMobileThumbnails(userId: string, options: { page: number; limit: number; size: 'small' | 'medium' | 'large' }) {
    try {
      const sizeMap = { small: 100, medium: 200, large: 400 };
      const thumbnailSize = sizeMap[options.size];
      
      const offset = (options.page - 1) * options.limit;
      const images = await imageModel.findByUserId(userId, { limit: options.limit, offset });
      
      const thumbnails = await Promise.all(
        images.map(async (image) => {
          try {
            const thumbnailPath = await imageProcessingService.generateThumbnail(image.file_path, thumbnailSize);
            return {
              id: image.id,
              thumbnailPath,
              size: options.size,
              originalWidth: image.original_metadata?.width,
              originalHeight: image.original_metadata?.height
            };
          } catch {
            return {
              id: image.id,
              thumbnailPath: null,
              size: options.size,
              error: 'Failed to generate thumbnail'
            };
          }
        })
      );

      return { thumbnails, page: options.page, hasMore: images.length === options.limit };
    } catch (error) {
      console.error('Error getting mobile thumbnails:', error);
      throw ApiError.internal('Failed to retrieve mobile thumbnails');
    }
  },

  /**
   * Get mobile optimized image - Flutter optimized
   */
  async getMobileOptimizedImage(imageId: string, userId: string) {
    try {
      const image = await this.getImageById(imageId, userId);
      
      // Generate mobile-optimized version
      const optimizedPath = await imageProcessingService.optimizeForMobile(image.file_path);
      
      return {
        id: image.id,
        optimizedPath,
        format: 'webp',
        quality: 85,
        originalSize: image.original_metadata?.size,
        optimizedAt: new Date().toISOString()
      };
    } catch (error) {
      if (error instanceof ApiError) throw error;
      console.error('Error getting mobile optimized image:', error);
      throw ApiError.internal('Failed to get mobile optimized image');
    }
  },

  /**
   * Batch generate thumbnails - Flutter optimized
   */
  async batchGenerateThumbnails(imageIds: string[], userId: string, sizes: ('small' | 'medium' | 'large')[]) {
    try {
      // Verify ownership
      const verificationPromises = imageIds.map(id => this.getImageById(id, userId));
      const images = await Promise.all(verificationPromises);
      
      const sizeMap = { small: 100, medium: 200, large: 400 };
      let successCount = 0;
      const results = [];

      for (const image of images) {
        try {
          const thumbnails = await Promise.all(
            sizes.map(async (size) => {
              const thumbnailPath = await imageProcessingService.generateThumbnail(image.file_path, sizeMap[size]);
              return { size, thumbnailPath };
            })
          );
          
          results.push({ id: image.id, thumbnails, status: 'success' });
          successCount++;
        } catch (error) {
          results.push({ id: image.id, status: 'failed', error: 'Thumbnail generation failed' });
        }
      }

      return { results, successCount, totalCount: imageIds.length };
    } catch (error) {
      if (error instanceof ApiError) throw error;
      console.error('Error batch generating thumbnails:', error);
      throw ApiError.internal('Failed to batch generate thumbnails');
    }
  },

  /**
   * Get sync data - Flutter offline support
   */
  async getSyncData(userId: string, options: { lastSync?: string; includeDeleted: boolean; limit: number }) {
    try {
      let query: ImageQueryOptions = { limit: options.limit };
      
      // For sync functionality, we'll use upload_date as a proxy for updated_at
      if (options.lastSync) {
        // We can extend the query later when we add updated_at to the schema
        console.log('Sync timestamp provided:', options.lastSync);
      }

      const images = await imageModel.findByUserId(userId, query);
      
      const syncData = {
        images: images.map(image => ({
          id: image.id,
          status: image.status,
          metadata: image.original_metadata,
          lastModified: image.upload_date,
          syncStatus: 'synced'
        })),
        syncTimestamp: new Date().toISOString(),
        hasMore: images.length === options.limit
      };

      return syncData;
    } catch (error) {
      console.error('Error getting sync data:', error);
      throw ApiError.internal('Failed to get sync data');
    }
  },

  /**
   * Flutter upload - optimized for Flutter apps
   */
  async flutterUploadImage(params: ImageUploadParams) {
    try {
      // Use existing upload logic with Flutter optimizations
      const image = await this.uploadImage(params);
      
      // Generate immediate thumbnail for Flutter preview
      try {
        await this.generateThumbnail(image.id, params.userId, 200);
      } catch (thumbError) {
        console.warn('Failed to generate immediate thumbnail:', thumbError);
      }

      return {
        ...image,
        platform: 'flutter',
        uploadOptimized: true
      };
    } catch (error) {
      if (error instanceof ApiError) throw error;
      console.error('Error in Flutter upload:', error);
      throw ApiError.internal('Failed to process Flutter upload');
    }
  },

  /**
   * Batch sync operations - Flutter offline/online sync
   */
  async batchSyncOperations(userId: string, operations: Array<{
    id: string;
    action: 'create' | 'update' | 'delete';
    data?: any;
    clientTimestamp: string;
  }>) {
    try {
      let successCount = 0;
      let failedCount = 0;
      const conflicts: any[] = [];
      const results = [];

      for (const operation of operations) {
        try {
          switch (operation.action) {
            case 'update':
              if (operation.data?.status) {
                await this.updateImageStatus(operation.id, userId, operation.data.status);
              }
              break;
            case 'delete':
              await this.deleteImage(operation.id, userId);
              break;
            default:
              throw new Error(`Unsupported sync operation: ${operation.action}`);
          }
          
          results.push({ id: operation.id, status: 'success' });
          successCount++;
        } catch (error) {
          results.push({ 
            id: operation.id, 
            status: 'failed', 
            error: error instanceof Error ? error.message : 'Unknown error' 
          });
          failedCount++;
        }
      }

      return {
        results,
        successCount,
        failedCount,
        conflicts,
        syncCompleted: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error in batch sync operations:', error);
      throw ApiError.internal('Failed to process batch sync operations');
    }
  }
};