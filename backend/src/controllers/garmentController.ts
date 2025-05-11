// /backend/src/controllers/garmentController.ts
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
      // Authentication check (could be moved to auth middleware)
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }

      const { original_image_id, mask_data, metadata } = req.body as CreateGarmentInput;

      // Find the original image
      const originalImage = await imageModel.findById(original_image_id);
      
      // Check if image exists
      if (!originalImage) {
        return next(ApiError.notFound('Original image not found'));
      }

      // Check if user owns the image
      if (originalImage.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to use this image'));
      }

      // Business rule: validate image status
      if (originalImage.status !== 'new') {
        if (originalImage.status === 'labeled') {
          return next(ApiError.badRequest('This image has already been used to create a garment'));
        } else {
          return next(ApiError.badRequest('Image must be in "new" status before creating a garment'));
        }
      }

      // Process the image using labeling service
      const { maskedImagePath, maskPath } = await labelingService.applyMaskToImage(
        originalImage.file_path,
        mask_data
      );

      // Update image status to labeled
      await imageModel.updateStatus(original_image_id, 'labeled');

      // Create the garment record
      const createdGarment = await garmentModel.create({
        user_id: req.user.id,
        original_image_id,
        file_path: maskedImagePath,
        mask_path: maskPath,
        metadata,
      });

      // Format response
      const garmentResponse: GarmentResponse = {
        id: createdGarment.id,
        original_image_id: createdGarment.original_image_id,
        file_path: createdGarment.file_path,
        mask_path: createdGarment.mask_path,
        metadata: {
          type: createdGarment.metadata.type,
          color: createdGarment.metadata.color,
          pattern: createdGarment.metadata.pattern,
          season: createdGarment.metadata.season,
          brand: createdGarment.metadata.brand,
          tags: Array.isArray(createdGarment.metadata.tags) ? createdGarment.metadata.tags : []
        },
        created_at: createdGarment.created_at,
        updated_at: createdGarment.updated_at,
        data_version: createdGarment.data_version,
      };

      return res.status(201).json({
        status: 'success',
        data: { garment: garmentResponse },
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