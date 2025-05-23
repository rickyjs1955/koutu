import { garmentModel } from '../models/garmentModel';
import { imageModel } from '../models/imageModel';
import { labelingService } from '../services/labelingService';
import { ApiError } from '../utils/ApiError';
import { storageService } from './storageService';

/**
 * Garment Service Layer
 * 
 * Handles pure business logic for garment operations.
 * Does not handle HTTP concerns, sanitization, or response formatting.
 */
export const garmentService = {
    /**
     * Creates a garment from an image and mask data
     * Throws ApiError for business rule violations
     */
    async createGarment(params: {
        userId: string;
        originalImageId: string;
        maskData: {
        width: number;
        height: number;
        data: Uint8ClampedArray | number[];
        };
        metadata: Record<string, any>;
    }) {
        const { userId, originalImageId, maskData, metadata } = params;
        
        // Business Rule 1: Validate image exists and is owned by user
        const originalImage = await imageModel.findById(originalImageId);
        
        if (!originalImage) {
            throw ApiError.notFound('Original image not found');
        }

        if (originalImage.user_id !== userId) {
            throw ApiError.forbidden('You do not have permission to use this image');
        }

        // Business Rule 2: Image must be in 'new' status
        if (originalImage.status !== 'new') {
        if (originalImage.status === 'labeled') {
            throw ApiError.badRequest('This image has already been used to create a garment');
        } else {
            throw ApiError.badRequest('Image must be in "new" status before creating a garment');
        }
        }
        
        // Business Operation 1: Apply mask to create garment image
        const { maskedImagePath, maskPath } = await labelingService.applyMaskToImage(
        originalImage.file_path,
        maskData
        );

        // Business Operation 2: Update source image status
        await imageModel.updateStatus(originalImageId, 'labeled');

        // Business Operation 3: Create garment record
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
     * Retrieves a specific garment by ID and verifies ownership
     * @throws ApiError if garment doesn't exist or user doesn't own it
     */
    async getGarment(params: { garmentId: string; userId: string }) {
        const { garmentId, userId } = params;
        
        // Get the garment
        const garment = await garmentModel.findById(garmentId);
        
        // Check if garment exists
        if (!garment) {
            throw ApiError.notFound('Garment not found');
        }
        
        // Business Rule: Verify ownership
        if (garment.user_id !== userId) {
            throw ApiError.forbidden('You do not have permission to access this garment');
        }
        
        return garment;
    },

    /**
     * Retrieves all garments belonging to a user
     * Supports optional filtering and pagination
     */
    async getGarments(params: { 
        userId: string;
        filter?: Record<string, any>;
        pagination?: { page: number; limit: number };
    }) {
        const { userId, filter = {}, pagination } = params;
        
        // Get all garments owned by the user
        const allGarments = await garmentModel.findByUserId(userId);
        
        // Apply filtering in the service layer
        let filteredGarments = allGarments;
        
        // Apply any filters if provided
        if (Object.keys(filter).length > 0) {
            filteredGarments = allGarments.filter(garment => {
                // Check each filter criterion
                return Object.entries(filter).every(([key, value]) => {
                    // Handle metadata filters specially
                    if (key.startsWith('metadata.')) {
                        const metadataKey = key.split('.')[1];
                        return garment.metadata && garment.metadata[metadataKey] === value;
                    }
                    
                    // Handle regular fields with proper type checking
                    if (Object.prototype.hasOwnProperty.call(garment, key)) {
                        // Type assertion is safe here because we verified the property exists
                        return (garment as Record<string, any>)[key] === value;
                    }
                    
                    // If the field doesn't exist, the filter doesn't match
                    return false;
                });
            });
        }
        
        // Apply pagination if provided
        if (pagination) {
            const { page, limit } = pagination;
            const startIndex = (page - 1) * limit;
            const endIndex = page * limit;
            
            filteredGarments = filteredGarments.slice(startIndex, endIndex);
        }
        
        return filteredGarments;
    },

    /**
     * Updates metadata for a specific garment
     * @throws ApiError if garment doesn't exist or user doesn't own it
     */
    async updateGarmentMetadata(params: {
        garmentId: string;
        userId: string;
        metadata: Record<string, any>;
        options?: { replace: boolean };
        }) {
        const { garmentId, userId, metadata, options = { replace: false } } = params;
        
        // First verify garment exists and user owns it
        const garment = await this.getGarment({ garmentId, userId });
        
        // Business Rule: Validate metadata fields if needed
        // e.g., check for required fields, validate formats, etc.
        
        // Update the metadata
        const updatedGarment = await garmentModel.updateMetadata(
            garmentId, 
            { metadata },
            options
        );
        
        if (!updatedGarment) {
            throw ApiError.internal('Failed to update garment metadata');
        }
        
        return updatedGarment;
    },

    /**
     * Deletes a garment and associated resources
     * @throws ApiError if garment doesn't exist or user doesn't own it
     */
    async deleteGarment(params: { garmentId: string; userId: string }) {
        const { garmentId, userId } = params;
        
        // First verify garment exists and user owns it
        const garment = await this.getGarment({ garmentId, userId });
        
        // Business Rule: Check if deletion is allowed
        // e.g., check if garment is referenced elsewhere
        
        // Delete the garment
        const deleted = await garmentModel.delete(garmentId);
        
        if (!deleted) {
            throw ApiError.internal('Failed to delete garment');
        }
        
        // Business Operation: Delete associated files
        // This could be moved to a separate helper method
        try {
            // Delete the garment image file
            if (garment.file_path) {
                await storageService.deleteFile(garment.file_path);
            }
            
            // Delete the mask file
            if (garment.mask_path) {
                await storageService.deleteFile(garment.mask_path);
            }
        } catch (error) {
            // Log but don't fail the operation if file deletion fails
            console.error('Error deleting garment files:', error);
        }
        
        return { success: true, garmentId };
    }
};