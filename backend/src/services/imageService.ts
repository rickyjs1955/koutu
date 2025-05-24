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
      const filePath = await storageService.saveFile(fileBuffer, originalFilename);

      // Extract comprehensive metadata
      const metadata = await imageProcessingService.extractMetadata(filePath);

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
      // Validate buffer is not empty
      if (!fileBuffer || fileBuffer.length === 0) {
        errors.push('File buffer is empty');
        return { isValid: false, errors };
      }

      // Validate file size
      if (size !== fileBuffer.length) {
        errors.push('File size mismatch');
      }

      // Validate MIME type
      const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/webp'];
      if (!allowedMimeTypes.includes(mimetype)) {
        errors.push(`Unsupported MIME type: ${mimetype}`);
      }

      // Validate actual image content
      const metadata = await imageProcessingService.validateImageBuffer(fileBuffer);

      // Check minimum dimensions
      const minDimension = 50;
      if (metadata.width && metadata.height) {
        if (metadata.width < minDimension || metadata.height < minDimension) {
          errors.push(`Image dimensions too small (min: ${minDimension}x${minDimension})`);
        }

        // Check maximum dimensions
        const maxDimension = 10000;
        if (metadata.width > maxDimension || metadata.height > maxDimension) {
          errors.push(`Image dimensions too large (max: ${maxDimension}x${maxDimension})`);
        }
      } else {
        errors.push('Unable to determine image dimensions');
      }

      // Validate format consistency
      if (metadata.format) {
        const formatMimeMap: Record<string, string> = {
          'jpeg': 'image/jpeg',
          'png': 'image/png',
          'webp': 'image/webp'
        };

        const expectedMime = formatMimeMap[metadata.format];
        if (expectedMime && expectedMime !== mimetype) {
          errors.push(`MIME type mismatch: expected ${expectedMime}, got ${mimetype}`);
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
      const maxStoragePerUser = 100 * 1024 * 1024; // 100MB
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
          maxStorageMB: 100,
          imagesRemaining: Math.max(0, 1000 - stats.total),
          storageRemainingMB: Math.max(0, Math.round((100 * 1024 * 1024 - stats.totalSize) / (1024 * 1024) * 100) / 100)
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
  }
};