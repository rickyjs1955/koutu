// /backend/src/controllers/polygonController.ts
import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';
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
     * Context-specific validation: polygon-related business rules
     */
    async createPolygon(req: Request, res: Response, next: NextFunction) {
        try {
            const data: CreatePolygonInput = req.body;
            
            if (!req.user) {
                return next(ApiError.unauthorized('User not authenticated'));
            }
            
            // Context-specific validation: Image must exist and be accessible
            const image = await imageModel.findById(data.original_image_id);
            if (!image) {
                return next(ApiError.notFound('Image not found', 'IMAGE_NOT_FOUND'));
            }
            
            if (image.user_id !== req.user.id) {
                return next(ApiError.forbidden('You do not have permission to add polygons to this image', 'IMAGE_ACCESS_DENIED'));
            }
            
            // Context-specific validation: Image should be in appropriate status
            if (image.status === 'labeled') {
                return next(ApiError.badRequest('Image is already labeled and cannot accept new polygons', 'IMAGE_ALREADY_LABELED'));
            }
            
            // Polygon-specific validation: Check point count and validity
            if (!data.points || data.points.length < 3) {
                return next(ApiError.badRequest('Polygon must have at least 3 points', 'INSUFFICIENT_POINTS'));
            }
            
            if (data.points.length > 1000) {
                return next(ApiError.badRequest('Polygon cannot have more than 1000 points', 'TOO_MANY_POINTS'));
            }
            
            // Validate point coordinates are within image bounds
            const imageMetadata = image.original_metadata;
            if (imageMetadata.width && imageMetadata.height) {
                const invalidPoints = data.points.filter(point => 
                    point.x < 0 || point.x > imageMetadata.width ||
                    point.y < 0 || point.y > imageMetadata.height
                );
                
                if (invalidPoints.length > 0) {
                    return next(ApiError.badRequest(
                        `${invalidPoints.length} point(s) are outside image boundaries`, 
                        'POINTS_OUT_OF_BOUNDS'
                    ));
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
            
            res.status(201).json({
                status: 'success',
                data: { polygon }
            });
        } catch (error) {
            console.error('Error creating polygon:', error);
            next(ApiError.internal('Failed to create polygon'));
        }
    },
    
    /**
     * Get all polygons for an image
     * Lightweight validation for read operations
     */
    async getImagePolygons(req: Request, res: Response, next: NextFunction) {
        try {
            const { imageId } = req.params;
            
            if (!req.user) {
                return next(ApiError.unauthorized('User not authenticated'));
            }
            
            // Basic UUID validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(imageId)) {
                return next(ApiError.badRequest('Invalid image ID format', 'INVALID_UUID'));
            }
            
            // Verify image ownership (lightweight check)
            const image = await imageModel.findById(imageId);
            if (!image) {
                return next(ApiError.notFound('Image not found'));
            }
            
            if (image.user_id !== req.user.id) {
                return next(ApiError.forbidden('You do not have permission to view this image'));
            }
            
            const polygons = await polygonModel.findByImageId(imageId);
            
            res.status(200).json({
                status: 'success',
                data: { 
                    polygons,
                    count: polygons.length,
                    imageId 
                }
            });
        } catch (error) {
            console.error('Error retrieving polygons:', error);
            next(ApiError.internal('Failed to retrieve polygons'));
        }
    },
    
    /**
     * Get a specific polygon
     */
    async getPolygon(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            
            if (!req.user) {
                return next(ApiError.unauthorized('User not authenticated'));
            }
            
            // Basic UUID validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(id)) {
                return next(ApiError.badRequest('Invalid polygon ID format', 'INVALID_UUID'));
            }
            
            const polygon = await polygonModel.findById(id);
            if (!polygon) {
                return next(ApiError.notFound('Polygon not found'));
            }
            
            // Verify ownership through image relationship
            const image = await imageModel.findById(polygon.original_image_id);
            if (!image || image.user_id !== req.user.id) {
                return next(ApiError.forbidden('You do not have permission to view this polygon'));
            }
            
            res.status(200).json({
                status: 'success',
                data: { polygon }
            });
        } catch (error) {
            console.error('Error retrieving polygon:', error);
            next(ApiError.internal('Failed to retrieve polygon'));
        }
    },
    
    /**
     * Update a polygon
     * Context-specific validation for updates
     */
    async updatePolygon(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            const data: UpdatePolygonInput = req.body;
            
            if (!req.user) {
                return next(ApiError.unauthorized('User not authenticated'));
            }
            
            // Basic UUID validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(id)) {
                return next(ApiError.badRequest('Invalid polygon ID format', 'INVALID_UUID'));
            }
            
            const polygon = await polygonModel.findById(id);
            if (!polygon) {
                return next(ApiError.notFound('Polygon not found'));
            }
            
            // Verify ownership through image relationship
            const image = await imageModel.findById(polygon.original_image_id);
            if (!image || image.user_id !== req.user.id) {
                return next(ApiError.forbidden('You do not have permission to update this polygon'));
            }
            
            // Context-specific validation: If updating points, validate them
            if (data.points) {
                if (data.points.length < 3) {
                    return next(ApiError.badRequest('Polygon must have at least 3 points', 'INSUFFICIENT_POINTS'));
                }
                
                if (data.points.length > 1000) {
                    return next(ApiError.badRequest('Polygon cannot have more than 1000 points', 'TOO_MANY_POINTS'));
                }
                
                // Validate points are within image bounds
                const imageMetadata = image.original_metadata;
                if (imageMetadata.width && imageMetadata.height) {
                    const invalidPoints = data.points.filter(point => 
                        point.x < 0 || point.x > imageMetadata.width ||
                        point.y < 0 || point.y > imageMetadata.height
                    );
                    
                    if (invalidPoints.length > 0) {
                        return next(ApiError.badRequest(
                            `${invalidPoints.length} point(s) are outside image boundaries`, 
                            'POINTS_OUT_OF_BOUNDS'
                        ));
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
            
            res.status(200).json({
                status: 'success',
                data: { polygon: updatedPolygon }
            });
        } catch (error) {
            console.error('Error updating polygon:', error);
            next(ApiError.internal('Failed to update polygon'));
        }
    },
    
    /**
     * Delete a polygon
     */
    async deletePolygon(req: Request, res: Response, next: NextFunction) {
        try {
            const { id } = req.params;
            
            if (!req.user) {
                return next(ApiError.unauthorized('User not authenticated'));
            }
            
            // Basic UUID validation
            const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
            if (!uuidRegex.test(id)) {
                return next(ApiError.badRequest('Invalid polygon ID format', 'INVALID_UUID'));
            }
            
            const polygon = await polygonModel.findById(id);
            if (!polygon) {
                return next(ApiError.notFound('Polygon not found'));
            }
            
            // Verify ownership through image relationship
            const image = await imageModel.findById(polygon.original_image_id);
            if (!image || image.user_id !== req.user.id) {
                return next(ApiError.forbidden('You do not have permission to delete this polygon'));
            }
            
            // Delete the polygon
            const deleted = await polygonModel.delete(id);
            if (!deleted) {
                return next(ApiError.internal('Failed to delete polygon'));
            }
            
            // Clean up saved polygon data
            try {
                const dataPath = `data/polygons/${id}.json`;
                await storageService.deleteFile(dataPath);
            } catch (cleanupError) {
                // Log but don't fail the operation for cleanup errors
                console.warn('Failed to delete polygon data file:', cleanupError);
            }
            
            res.status(200).json({
                status: 'success',
                data: null,
                message: 'Polygon deleted successfully'
            });
        } catch (error) {
            console.error('Error deleting polygon:', error);
            next(ApiError.internal('Failed to delete polygon'));
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