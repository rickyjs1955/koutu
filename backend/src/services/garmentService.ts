// /backend/src/services/garmentService.ts - Pure Business Logic

import { garmentModel } from '../models/garmentModel';
import { imageModel } from '../models/imageModel';
import { labelingService } from '../services/labelingService';
import { ApiError } from '../utils/ApiError';
import { storageService } from './storageService';

export const garmentService = {
    /**
     * Creates a garment from an image and mask data
     * Handles pure business logic and rules
     */
    async createGarment(params: {
        userId: string;
        originalImageId: string;
        maskData: {
            width: number;
            height: number;
            data: Uint8ClampedArray | number[];
        };
        metadata?: Record<string, any>;
    }) {
        const { userId, originalImageId, maskData, metadata = {} } = params;
        
        // Business Rule 1: Validate image exists and ownership
        const originalImage = await imageModel.findById(originalImageId);
        
        if (!originalImage) {
            throw ApiError.notFound('Original image not found');
        }

        if (originalImage.user_id !== userId) {
            throw ApiError.forbidden('You do not have permission to use this image');
        }

        // Business Rule 2: Image status validation
        if (originalImage.status !== 'new') {
            if (originalImage.status === 'labeled') {
                throw ApiError.businessLogic(
                    'This image has already been used to create a garment',
                    'image_already_labeled',
                    'garment'
                );
            } else {
                throw ApiError.businessLogic(
                    'Image must be in "new" status before creating a garment',
                    'invalid_image_status',
                    'garment'
                );
            }
        }
        
        // Business Rule 3: Mask validation against image dimensions
        const imageMeta = originalImage.original_metadata;
        if (imageMeta?.width && imageMeta?.height) {
            if (maskData.width !== imageMeta.width || maskData.height !== imageMeta.height) {
                throw ApiError.businessLogic(
                    `Mask dimensions (${maskData.width}x${maskData.height}) don't match image dimensions (${imageMeta.width}x${imageMeta.height})`,
                    'mask_dimension_mismatch',
                    'garment'
                );
            }
        }

        // Business Rule 4: Validate mask has meaningful content
        if (this.isMaskEmpty(maskData.data)) {
            throw ApiError.businessLogic(
                'Mask data appears to be empty - no garment area defined',
                'empty_mask',
                'garment'
            );
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
     * Check if mask data is effectively empty
     */
    isMaskEmpty(maskData: Uint8ClampedArray | number[]): boolean {
        // Check if mask has any non-zero values (assuming 0 = transparent)
        const nonZeroCount = Array.from(maskData).filter(value => value > 0).length;
        const totalPixels = maskData.length;
        
        // Consider mask empty if less than 1% of pixels are non-zero
        return (nonZeroCount / totalPixels) < 0.01;
    },

    /**
     * Retrieves a specific garment with ownership verification
     */
    async getGarment(params: { garmentId: string; userId: string }) {
        const { garmentId, userId } = params;
        
        const garment = await garmentModel.findById(garmentId);
        
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
     * Retrieves garments with filtering and pagination
     */
    async getGarments(params: { 
        userId: string;
        filter?: Record<string, any>;
        pagination?: { page: number; limit: number };
    }) {
        const { userId, filter = {}, pagination } = params;
        
        // Get all user garments
        const allGarments = await garmentModel.findByUserId(userId);
        
        // Apply garment-specific filtering
        let filteredGarments = allGarments;
        
        if (Object.keys(filter).length > 0) {
            filteredGarments = this.applyGarmentFilters(allGarments, filter);
        }
        
        // Apply pagination
        if (pagination) {
            const { page, limit } = pagination;
            const startIndex = (page - 1) * limit;
            filteredGarments = filteredGarments.slice(startIndex, startIndex + limit);
        }
        
        return filteredGarments;
    },

    /**
     * Apply garment-specific filters
     */
    applyGarmentFilters(garments: any[], filter: Record<string, any>) {
        return garments.filter(garment => {
            return Object.entries(filter).every(([key, value]) => {
                // Handle metadata filters
                if (key.startsWith('metadata.')) {
                    const metadataKey = key.split('.')[1];
                    return garment.metadata && garment.metadata[metadataKey] === value;
                }
                
                // Handle date filters
                if (key.includes('_date') || key.includes('_at')) {
                    // Could implement date range filtering here
                    return true;
                }
                
                // Handle regular field filtering
                if (Object.prototype.hasOwnProperty.call(garment, key)) {
                    return (garment as Record<string, any>)[key] === value;
                }
                
                return false;
            });
        });
    },

    /**
     * Updates garment metadata with business validation
     */
    async updateGarmentMetadata(params: {
        garmentId: string;
        userId: string;
        metadata: Record<string, any>;
        options?: { replace: boolean };
    }) {
        const { garmentId, userId, metadata, options = { replace: false } } = params;
        
        // Verify ownership first
        await this.getGarment({ garmentId, userId });
        
        // Business Rule: Validate metadata structure for garments
        this.validateGarmentMetadata(metadata);
        
        // Update metadata
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
     * Validate garment-specific metadata rules
     */
    validateGarmentMetadata(metadata: Record<string, any>): void {
        // Handle null/undefined metadata first
        if (!metadata || typeof metadata !== 'object') {
            return; // Allow null/undefined metadata - it's optional
        }

        // Business rules for garment metadata
        if (metadata.category && typeof metadata.category !== 'string') {
            throw ApiError.businessLogic(
                'Garment category must be a string',
                'invalid_category_type',
            );
        }

        // Business rules for garment metadata
        if (metadata.category && typeof metadata.category !== 'string') {
            throw ApiError.businessLogic(
                'Garment category must be a string',
                'invalid_category_type',
                'garment'
            );
        }

        if (metadata.size && !['XS', 'S', 'M', 'L', 'XL', 'XXL'].includes(metadata.size)) {
            throw ApiError.businessLogic(
                'Invalid garment size',
                'invalid_size',
                'garment'
            );
        }

        if (metadata.color && typeof metadata.color !== 'string') {
            throw ApiError.businessLogic(
                'Garment color must be a string',
                'invalid_color_type',
                'garment'
            );
        }

        // Validate custom fields don't exceed reasonable limits
        const metadataString = JSON.stringify(metadata);
        if (metadataString.length > 10000) {
            throw ApiError.businessLogic(
                'Metadata too large (max 10KB)',
                'metadata_too_large',
                'garment'
            );
        }
    },

    /**
     * Deletes a garment with dependency checking
     */
    async deleteGarment(params: { garmentId: string; userId: string }) {
        const { garmentId, userId } = params;
        
        // Verify ownership
        const garment = await this.getGarment({ garmentId, userId });
        
        // Business Rule: Check if garment can be deleted
        // (e.g., not used in exports, wardrobe collections, etc.)
        await this.validateGarmentDeletion(garmentId);
        
        // Delete the garment
        const deleted = await garmentModel.delete(garmentId);
        
        if (!deleted) {
            throw ApiError.internal('Failed to delete garment');
        }
        
        // Cleanup associated files (best effort)
        await this.cleanupGarmentFiles(garment);
        
        return { success: true, garmentId };
    },

    /**
     * Validate if garment can be deleted
     */
    async validateGarmentDeletion(garmentId: string): Promise<void> {
        // Check if garment is used in any exports, wardrobes, etc.
        // This would require checking other tables/services
        
        // For now, allow deletion
        // In future, could check:
        // - Export jobs using this garment
        // - Wardrobe collections containing this garment
        // - Any other dependencies
    },

    /**
     * Cleanup garment files
     */
    async cleanupGarmentFiles(garment: any): Promise<void> {
        try {
            // Delete garment image file
            if (garment.file_path) {
                await storageService.deleteFile(garment.file_path);
            }
            
            // Delete mask file
            if (garment.mask_path) {
                await storageService.deleteFile(garment.mask_path);
            }
        } catch (error) {
            // Log but don't fail the operation
            console.error('Error cleaning up garment files:', error);
        }
    },

    /**
     * Get garment statistics for a user
     */
    async getUserGarmentStats(userId: string) {
        const garments = await garmentModel.findByUserId(userId);
        
        const stats = {
            total: garments.length,
            byCategory: {} as Record<string, number>,
            bySize: {} as Record<string, number>,
            byColor: {} as Record<string, number>,
            recentlyCreated: garments.filter(g => {
                const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
                return new Date(g.created_at) > dayAgo;
            }).length
        };

        // Aggregate metadata statistics
        garments.forEach(garment => {
            if (garment.metadata?.category) {
                const cat = garment.metadata.category;
                stats.byCategory[cat] = (stats.byCategory[cat] || 0) + 1;
            }
            
            if (garment.metadata?.size) {
                const size = garment.metadata.size;
                stats.bySize[size] = (stats.bySize[size] || 0) + 1;
            }
            
            if (garment.metadata?.color) {
                const color = garment.metadata.color;
                stats.byColor[color] = (stats.byColor[color] || 0) + 1;
            }
        });

        return stats;
    }
};