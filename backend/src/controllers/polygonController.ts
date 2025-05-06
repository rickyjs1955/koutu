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
     */
    async createPolygon(req: Request, res: Response, next: NextFunction) {
        try {
        const data: CreatePolygonInput = req.body;
        
        if (!req.user) {
            return next(ApiError.unauthorized('User not authenticated'));
        }
        
        // Validate that the image exists and belongs to the user
        const image = await imageModel.findById(data.original_image_id);
        if (!image) {
            return next(ApiError.notFound('Image not found'));
        }
        
        if (image.user_id !== req.user.id) {
            return next(ApiError.forbidden('You do not have permission to add polygons to this image'));
        }
        
        // Create the polygon
        const polygon = await polygonModel.create({
            ...data,
            user_id: req.user.id
        });
        
        // Also save polygon data to a JSON file for future AI/ML operations
        if (!polygon.id) {
            return next(ApiError.internal('Failed to create polygon with a valid ID'));
        }
        
        await savePolygonData(polygon.id, {
            polygon,
            image_path: image.file_path,
            image_metadata: image.original_metadata
        });
        
        res.status(201).json({
            status: 'success',
            data: {
            polygon
            }
        });
        } catch (error) {
        next(error);
        }
    },
    
    /**
     * Get all polygons for an image
     */
    async getImagePolygons(req: Request, res: Response, next: NextFunction) {
        try {
        const { imageId } = req.params;
        
        if (!req.user) {
            return next(ApiError.unauthorized('User not authenticated'));
        }
        
        // Validate that the image exists and belongs to the user
        const image = await imageModel.findById(imageId);
        if (!image) {
            return next(ApiError.notFound('Image not found'));
        }
        
        if (image.user_id !== req.user.id) {
            return next(ApiError.forbidden('You do not have permission to view this image'));
        }
        
        // Get the polygons
        const polygons = await polygonModel.findByImageId(imageId);
        
        res.status(200).json({
            status: 'success',
            data: {
            polygons
            }
        });
        } catch (error) {
        next(error);
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
        
        // Get the polygon
        const polygon = await polygonModel.findById(id);
        if (!polygon) {
            return next(ApiError.notFound('Polygon not found'));
        }
        
        // Validate that the polygon's image belongs to the user
        const image = await imageModel.findById(polygon.original_image_id);
        if (!image || image.user_id !== req.user.id) {
            return next(ApiError.forbidden('You do not have permission to view this polygon'));
        }
        
        res.status(200).json({
            status: 'success',
            data: {
            polygon
            }
        });
        } catch (error) {
        next(error);
        }
    },
    
    /**
     * Update a polygon
     */
    async updatePolygon(req: Request, res: Response, next: NextFunction) {
        try {
        const { id } = req.params;
        const data: UpdatePolygonInput = req.body;
        
        if (!req.user) {
            return next(ApiError.unauthorized('User not authenticated'));
        }
        
        // Get the polygon
        const polygon = await polygonModel.findById(id);
        if (!polygon) {
            return next(ApiError.notFound('Polygon not found'));
        }
        
        // Validate that the polygon's image belongs to the user
        const image = await imageModel.findById(polygon.original_image_id);
        if (!image || image.user_id !== req.user.id) {
            return next(ApiError.forbidden('You do not have permission to update this polygon'));
        }
        
        // Update the polygon
        const updatedPolygon = await polygonModel.update(id, data);
        
        // Update the saved polygon data for AI/ML
        if (updatedPolygon) {
            await savePolygonData(id, {
            polygon: updatedPolygon,
            image_path: image.file_path,
            image_metadata: image.original_metadata
            });
        }
        
        res.status(200).json({
            status: 'success',
            data: {
            polygon: updatedPolygon
            }
        });
        } catch (error) {
        next(error);
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
        
        // Get the polygon
        const polygon = await polygonModel.findById(id);
        if (!polygon) {
            return next(ApiError.notFound('Polygon not found'));
        }
        
        // Validate that the polygon's image belongs to the user
        const image = await imageModel.findById(polygon.original_image_id);
        if (!image || image.user_id !== req.user.id) {
            return next(ApiError.forbidden('You do not have permission to delete this polygon'));
        }
        
        // Delete the polygon
        await polygonModel.delete(id);
        
        // Also delete the saved polygon data
        const dataPath = `data/polygons/${id}.json`;
        await storageService.deleteFile(dataPath);
        
        res.status(200).json({
            status: 'success',
            data: null
        });
        } catch (error) {
        next(error);
        }
    }
};

/**
 * Helper function to save polygon data to storage for AI/ML operations
 */
async function savePolygonData(polygonId: string, data: any): Promise<void> {
    const jsonData = JSON.stringify(data, null, 2);
    const buffer = Buffer.from(jsonData, 'utf-8');
    
    // Save to a structured path for AI/ML operations
    const filePath = `data/polygons/${polygonId}.json`;
    await storageService.saveFile(buffer, filePath);
}