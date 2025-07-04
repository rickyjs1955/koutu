// /backend/src/controllers/polygonController.ts - Fully Flutter-compatible version
import { Request, Response, NextFunction } from 'express';
import { EnhancedApiError } from '../middlewares/errorHandler';
import { polygonModel } from '../models/polygonModel';
import { imageModel } from '../models/imageModel';
import { storageService } from '../services/storageService';
import { 
  CreatePolygonInput, 
  UpdatePolygonInput 
} from '../../../shared/src/schemas/polygon';

export const polygonController = {
    /**
     * Create a new polygon
     * Flutter-optimized response format
     */
    async createPolygon(req: Request, res: Response, next: NextFunction) {
        try {
            const data: CreatePolygonInput = req.body;
            
            if (!req.user) {
                throw EnhancedApiError.authenticationRequired('User not authenticated');
            }
            
            // Context-specific validation: Image must exist and be accessible
            const image = await imageModel.findById(data.original_image_id);
            if (!image) {
                throw EnhancedApiError.notFound('Image not found', 'image');
            }
            
            if (image.user_id !== req.user.id) {
                throw EnhancedApiError.authorizationDenied('You do not have permission to add polygons to this image', 'image');
            }
            
            // Context-specific validation: Image should be in appropriate status
            if (image.status === 'labeled') {
                throw EnhancedApiError.validation('Image is already labeled and cannot accept new polygons', 'image_status', image.status);
            }
            
            // Polygon-specific validation: Check point count and validity
            if (!data.points || data.points.length < 3) {
                throw EnhancedApiError.validation('Polygon must have at least 3 points', 'points', data.points?.length || 0);
            }
            
            if (data.points.length > 1000) {
                throw EnhancedApiError.validation('Polygon cannot have more than 1000 points', 'points', data.points.length);
            }
            
            // Validate point coordinates are within image bounds
            const imageMetadata = image.original_metadata;
            if (imageMetadata.width && imageMetadata.height) {
                const invalidPoints = data.points.filter(point => 
                    point.x < 0 || point.x > imageMetadata.width ||
                    point.y < 0 || point.y > imageMetadata.height
                );
                
                if (invalidPoints.length > 0) {
                    throw EnhancedApiError.validation(
                        `${invalidPoints.length} point(s) are outside image boundaries`,
                        'points_bounds',
                        { 
                            invalidCount: invalidPoints.length,
                            totalPoints: data.points.length,
                            imageBounds: { width: imageMetadata.width, height: imageMetadata.height }
                        }
                    );
                }
            }
            
            // Create the polygon
            const polygon = await polygonModel.create({
                ...data,
                user_id: req.user.id
            });
            
            // Save polygon data for AI/ML operations
            if (polygon.id) {
                await savePolygonData(polygon.id, {
                    polygon,
                    image_path: image.file_path,
                    image_metadata: image.original_metadata
                });
            }
            
            // Flutter-optimized response
            res.created(
                { polygon },
                {
                    message: 'Polygon created successfully',
                    meta: {
                        polygonId: polygon.id,
                        imageId: data.original_image_id,
                        pointCount: data.points.length,
                        createdAt: new Date().toISOString()
                    }
                }
            );

        } catch (error) {
            console.error('Error creating polygon:', error);
            
            if (error instanceof EnhancedApiError) {
                throw error;
            }
            throw EnhancedApiError.internalError('Failed to create polygon', error instanceof Error ? error : new Error(String(error)));
        }
    },
    
    /**
     * Get all polygons for an image
     * Flutter-optimized response format
     */
    async getImagePolygons(req: Request, res: Response, next: NextFunction) {
        try {
            const { imageId } = req.params;
            
            if (!req.user) {
                throw EnhancedApiError.authenticationRequired('User not authenticated');
            }
            
            // Basic UUID validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(imageId)) {
                throw EnhancedApiError.validation('Invalid image ID format', 'imageId', imageId);
            }
            
            // Verify image ownership (lightweight check)
            const image = await imageModel.findById(imageId);
            if (!image) {
                throw EnhancedApiError.notFound('Image not found', 'image');
            }
            
            if (image.user_id !== req.user.id) {
                throw EnhancedApiError.authorizationDenied('You do not have permission to view this image', 'image');
            }
            
            const polygons = await polygonModel.findByImageId(imageId);
            
            // Flutter-optimized response
            res.success(
                polygons,
                {
                    message: 'Polygons retrieved successfully',
                    meta: {
                        imageId,
                        polygonCount: polygons.length,
                        hasPolygons: polygons.length > 0
                    }
                }
            );

        } catch (error) {
            console.error('Error retrieving polygons:', error);
            
            if (error instanceof EnhancedApiError) {
                throw error;
            }
            throw EnhancedApiError.internalError('Failed to retrieve polygons', error instanceof Error ? error : new Error(String(error)));
        }
    },
    
    /**
     * Get a specific polygon
     * Flutter-optimized response format
     */
    async getPolygon(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            
            if (!req.user) {
                throw EnhancedApiError.authenticationRequired('User not authenticated');
            }
            
            // Basic UUID validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(id)) {
                throw EnhancedApiError.validation('Invalid polygon ID format', 'polygonId', id);
            }
            
            const polygon = await polygonModel.findById(id);
            if (!polygon) {
                throw EnhancedApiError.notFound('Polygon not found', 'polygon');
            }
            
            // Verify ownership through image relationship
            const image = await imageModel.findById(polygon.original_image_id);
            if (!image || image.user_id !== req.user.id) {
                throw EnhancedApiError.authorizationDenied('You do not have permission to view this polygon', 'polygon');
            }
            
            // Flutter-optimized response
            res.success(
                { polygon },
                {
                    message: 'Polygon retrieved successfully',
                    meta: {
                        polygonId: id,
                        imageId: polygon.original_image_id,
                        pointCount: polygon.points?.length || 0
                    }
                }
            );

        } catch (error) {
            console.error('Error retrieving polygon:', error);
            
            if (error instanceof EnhancedApiError) {
                throw error;
            }
            throw EnhancedApiError.internalError('Failed to retrieve polygon', error instanceof Error ? error : new Error(String(error)));
        }
    },
    
    /**
     * Update a polygon
     * Flutter-optimized response format
     */
    async updatePolygon(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const data: UpdatePolygonInput = req.body;
            
            if (!req.user) {
                throw EnhancedApiError.authenticationRequired('User not authenticated');
            }
            
            // Basic UUID validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(id)) {
                throw EnhancedApiError.validation('Invalid polygon ID format', 'polygonId', id);
            }
            
            const polygon = await polygonModel.findById(id);
            if (!polygon) {
                throw EnhancedApiError.notFound('Polygon not found', 'polygon');
            }
            
            // Verify ownership through image relationship
            const image = await imageModel.findById(polygon.original_image_id);
            if (!image || image.user_id !== req.user.id) {
                throw EnhancedApiError.authorizationDenied('You do not have permission to update this polygon', 'polygon');
            }
            
            // Context-specific validation: If updating points, validate them
            if (data.points) {
                if (data.points.length < 3) {
                    throw EnhancedApiError.validation('Polygon must have at least 3 points', 'points', data.points.length);
                }
                
                if (data.points.length > 1000) {
                    throw EnhancedApiError.validation('Polygon cannot have more than 1000 points', 'points', data.points.length);
                }
                
                // Validate points are within image bounds
                const imageMetadata = image.original_metadata;
                if (imageMetadata.width && imageMetadata.height) {
                    const invalidPoints = data.points.filter(point => 
                        point.x < 0 || point.x > imageMetadata.width ||
                        point.y < 0 || point.y > imageMetadata.height
                    );
                    
                    if (invalidPoints.length > 0) {
                        throw EnhancedApiError.validation(
                            `${invalidPoints.length} point(s) are outside image boundaries`,
                            'points_bounds',
                            {
                                invalidCount: invalidPoints.length,
                                totalPoints: data.points.length,
                                imageBounds: { width: imageMetadata.width, height: imageMetadata.height }
                            }
                        );
                    }
                }
            }
            
            const updatedPolygon = await polygonModel.update(id, data);
            
            // Update saved polygon data for AI/ML
            if (updatedPolygon) {
                await savePolygonData(id, {
                    polygon: updatedPolygon,
                    image_path: image.file_path,
                    image_metadata: image.original_metadata
                });
            }
            
            // Flutter-optimized response
            res.success(
                { polygon: updatedPolygon },
                {
                    message: 'Polygon updated successfully',
                    meta: {
                        polygonId: id,
                        imageId: polygon.original_image_id,
                        updatedFields: Object.keys(data),
                        pointCount: updatedPolygon?.points?.length || polygon.points?.length || 0
                    }
                }
            );

        } catch (error) {
            console.error('Error updating polygon:', error);
            
            if (error instanceof EnhancedApiError) {
                throw error;
            }
            throw EnhancedApiError.internalError('Failed to update polygon', error instanceof Error ? error : new Error(String(error)));
        }
    },
    
    /**
     * Delete a polygon
     * Flutter-optimized response format
     */
    async deletePolygon(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            
            if (!req.user) {
                throw EnhancedApiError.authenticationRequired('User not authenticated');
            }
            
            // Basic UUID validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(id)) {
                throw EnhancedApiError.validation('Invalid polygon ID format', 'polygonId', id);
            }
            
            const polygon = await polygonModel.findById(id);
            if (!polygon) {
                throw EnhancedApiError.notFound('Polygon not found', 'polygon');
            }
            
            // Verify ownership through image relationship
            const image = await imageModel.findById(polygon.original_image_id);
            if (!image || image.user_id !== req.user.id) {
                throw EnhancedApiError.authorizationDenied('You do not have permission to delete this polygon', 'polygon');
            }
            
            // Delete the polygon
            const deleted = await polygonModel.delete(id);
            if (!deleted) {
                throw EnhancedApiError.internalError('Failed to delete polygon');
            }
            
            // Clean up saved polygon data
            try {
                const dataPath = `data/polygons/${id}.json`;
                await storageService.deleteFile(dataPath);
            } catch (cleanupError) {
                // Log but don't fail the operation for cleanup errors
                console.warn('Failed to delete polygon data file:', cleanupError);
            }
            
            // Flutter-optimized response
            res.success(
                {},
                {
                    message: 'Polygon deleted successfully',
                    meta: {
                        deletedPolygonId: id,
                        imageId: polygon.original_image_id,
                        deletedAt: new Date().toISOString()
                    }
                }
            );

        } catch (error) {
            console.error('Error deleting polygon:', error);
            
            if (error instanceof EnhancedApiError) {
                throw error;
            }
            throw EnhancedApiError.internalError('Failed to delete polygon', error instanceof Error ? error : new Error(String(error)));
        }
    }
};

/**
 * Helper function to save polygon data to storage for AI/ML operations
 */
async function savePolygonData(polygonId: string, data: any): Promise<void> {
    try {
        const jsonData = JSON.stringify(data, null, 2);
        const buffer = Buffer.from(jsonData, 'utf-8');
        
        // Save to a structured path for AI/ML operations
        const filePath = `data/polygons/${polygonId}.json`;
        await storageService.saveFile(buffer, filePath);
    } catch (error) {
        console.error('Error saving polygon data:', error);
        // Don't throw - this is a supplementary operation
    }
}