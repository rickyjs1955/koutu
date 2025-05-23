import { garmentModel } from '../models/garmentModel';
import { imageModel } from '../models/imageModel';
import { labelingService } from '../services/labelingService';
import { ApiError } from '../utils/ApiError';

/**
 * Garment Service Layer
 * 
 * This service wraps existing controller logic to maintain backwards compatibility
 * while providing a clean service interface for future refactoring.
 */
export const garmentService = {
  /**
   * Creates a garment - extracted from controller logic
   */
  async createGarment(params: {
    userId: string;
    originalImageId: string;
    maskData: any;
    metadata: Record<string, any>;
  }) {
    // Extract the exact logic from garmentController.createGarment
    // This ensures zero behavioral changes
    
    const { userId, originalImageId, maskData, metadata } = params;
    
    // Find the original image (existing logic)
    const originalImage = await imageModel.findById(originalImageId);
    
    // Check if image exists (existing logic)
    if (!originalImage) {
      throw ApiError.notFound('Original image not found');
    }

    // Check if user owns the image (existing logic)
    if (originalImage.user_id !== userId) {
      throw ApiError.forbidden('You do not have permission to use this image');
    }

    // Check image status (existing logic)
    if (originalImage.status !== 'new') {
      if (originalImage.status === 'labeled') {
        throw ApiError.badRequest('This image has already been used to create a garment');
      } else {
        throw ApiError.badRequest('Image must be in "new" status before creating a garment');
      }
    }
    
    // Apply mask to image (existing logic)
    const { maskedImagePath, maskPath } = await labelingService.applyMaskToImage(
      originalImage.file_path,
      maskData
    );

    // Update image status (existing logic)
    await imageModel.updateStatus(originalImageId, 'labeled');

    // Create garment (existing logic)
    const createdGarment = await garmentModel.create({
      user_id: userId,
      original_image_id: originalImageId,
      file_path: maskedImagePath,
      mask_path: maskPath,
      metadata,
    });

    return createdGarment;
  },

  /**
   * Sanitizes garment data for response - extracted from controller
   */
  sanitizeGarmentForResponse(garment: any) {
    // Copy exact sanitization logic from controller
    return {
      id: garment.id,
      original_image_id: garment.original_image_id,
      // Convert file system paths to safe API routes
      file_path: `/api/garments/${garment.id}/image`,
      mask_path: `/api/garments/${garment.id}/mask`,
      // Filter metadata to only include allowed fields
      metadata: {
        type: garment.metadata?.type,
        color: garment.metadata?.color,
        pattern: garment.metadata?.pattern,
        season: garment.metadata?.season,
        brand: garment.metadata?.brand,
        tags: Array.isArray(garment.metadata?.tags) ? garment.metadata.tags : []
      },
      created_at: garment.created_at,
      updated_at: garment.updated_at,
      data_version: garment.data_version
    };
  }

  // Add other methods as needed, copying exact logic from controller
};