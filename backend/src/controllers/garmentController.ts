// src/controllers/garmentController.ts
import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';
import { garmentModel } from '../models/garmentModel';
import { imageModel } from '../models/imageModel';
import { labelingService } from '../services/labelingService';
import { 
  GarmentResponse, 
  CreateGarmentInput 
} from '../../../shared/src/schemas/garment';

export const garmentController = {
  async createGarment(req: Request, res: Response, next: NextFunction) {
    try {
      // req.body is already validated and typed as CreateGarmentInput
      const data: CreateGarmentInput = req.body;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Check if the original image exists and belongs to the user
      // Fixed: Use original_image_id instead of originalImageId
      const originalImage = await imageModel.findById(data.original_image_id);
      if (!originalImage) {
        return next(ApiError.notFound('Original image not found'));
      }
      
      if (originalImage.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to use this image'));
      }
      
      // Apply the mask to the image
      // Fixed: Use mask_data instead of maskData
      const { maskedImagePath, maskPath } = await labelingService.applyMaskToImage(
        originalImage.file_path,
        data.mask_data
      );
      
      // Update the original image status to 'labeled'
      // Fixed: Use original_image_id instead of originalImageId
      await imageModel.updateStatus(data.original_image_id, 'labeled');
      
      // Create the garment item
      const garment = await garmentModel.create({
        user_id: req.user.id,
        original_image_id: data.original_image_id,
        file_path: maskedImagePath,
        mask_path: maskPath,
        metadata: data.metadata
      });
      
      // Return the response matching our schema
      const response: GarmentResponse = {
        id: garment.id,
        original_image_id: garment.original_image_id,
        file_path: garment.file_path,
        mask_path: garment.mask_path,
        // Fixed: Ensure metadata matches the expected type
        metadata: {
          type: garment.metadata.type as any, // Type assertion to fix compatibility
          color: garment.metadata.color,
          pattern: garment.metadata.pattern,
          season: garment.metadata.season,
          brand: garment.metadata.brand,
          tags: garment.metadata.tags
        },
        created_at: garment.created_at,
        updated_at: garment.updated_at,
        data_version: garment.data_version
      };
      
      res.status(201).json({
        status: 'success',
        data: { garment: response }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async getGarments(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get all garments for the user
      const garments = await garmentModel.findByUserId(req.user.id);
      
      res.status(200).json({
        status: 'success',
        data: {
          garments
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async getGarment(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get the garment
      const garment = await garmentModel.findById(id);
      
      if (!garment) {
        return next(ApiError.notFound('Garment not found'));
      }
      
      // Check if the garment belongs to the user
      if (garment.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to access this garment'));
      }
      
      res.status(200).json({
        status: 'success',
        data: {
          garment
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async updateGarmentMetadata(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { metadata } = req.body;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      if (!metadata || typeof metadata !== 'object') {
        return next(ApiError.badRequest('Valid metadata object is required'));
      }
      
      // Get the garment
      const garment = await garmentModel.findById(id);
      
      if (!garment) {
        return next(ApiError.notFound('Garment not found'));
      }
      
      // Check if the garment belongs to the user
      if (garment.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to update this garment'));
      }
      
      // Update the metadata
      const updatedGarment = await garmentModel.updateMetadata(id, { metadata });
      
      res.status(200).json({
        status: 'success',
        data: {
          garment: updatedGarment
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async deleteGarment(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get the garment
      const garment = await garmentModel.findById(id);
      
      if (!garment) {
        return next(ApiError.notFound('Garment not found'));
      }
      
      // Check if the garment belongs to the user
      if (garment.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to delete this garment'));
      }
      
      // Delete the garment
      await garmentModel.delete(id);
      
      res.status(200).json({
        status: 'success',
        data: null
      });
    } catch (error) {
      next(error);
    }
  }
};