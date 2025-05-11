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
      // Authentication check
      if (!req.user) {
        next(ApiError.unauthorized('User not authenticated'));
        return; // Add explicit return after next()
      }

      const { original_image_id, mask_data, metadata } = req.body as CreateGarmentInput;

      // Find the original image
      const originalImage = await imageModel.findById(original_image_id);
      
      // Check if image exists
      if (!originalImage) {
        next(ApiError.notFound('Original image not found'));
        return; // Add explicit return
      }

      // Check if user owns the image
      if (originalImage.user_id !== req.user.id) {
        next(ApiError.forbidden('You do not have permission to use this image'));
        return; // Add explicit return
      }

      // Business rule: validate image status
      if (originalImage.status !== 'new') {
        if (originalImage.status === 'labeled') {
          next(ApiError.badRequest('This image has already been used to create a garment'));
        } else {
          next(ApiError.badRequest('Image must be in "new" status before creating a garment'));
        }
        return; // Add explicit return
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

      // Format response object
      const garmentResponse = {
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

      // Don't return this expression
      res.status(201).json({
        status: 'success',
        data: { garment: garmentResponse },
      });
      // Function implicitly returns undefined here
    } catch (error) {
      next(error);
      // Function returns undefined here too
    }
  },

  async getGarments(req: Request, res: Response, next: NextFunction) {
    try {
      // Check authentication
      if (!req.user) {
        next(ApiError.unauthorized('User not authenticated'));
        return;
      }
      
      // Get all garments for the current user
      const garments = await garmentModel.findByUserId(req.user.id);
      
      // Return the list of garments
      res.status(200).json({
        status: 'success',
        data: { 
          garments,
          count: garments.length 
        }
      });
    } catch (error) {
      next(error);
    }
  },
    
  // Consolidated getGarment method
  async getGarment(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      // Check user authentication
      if (!req.user) {
        next(ApiError.unauthorized('User not authenticated'));
        return;
      }
      
      // Fetch garment from database
      const garment = await garmentModel.findById(id);
      
      // Check if garment exists
      if (!garment) {
        next(ApiError.notFound('Garment not found'));
        return;
      }
      
      // Check if user owns this garment
      if (garment.user_id !== req.user.id) {
        next(ApiError.forbidden('You do not have permission to access this garment'));
        return;
      }
      
      // Return garment data
      res.status(200).json({
        status: 'success',
        data: { garment }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async updateGarmentMetadata(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const metadata = req.body;
      
      // Check authentication
      if (!req.user) {
        next(ApiError.unauthorized('User not authenticated'));
        return;
      }
      
      // Find garment
      const garment = await garmentModel.findById(id);
      
      // Check if garment exists
      if (!garment) {
        next(ApiError.notFound('Garment not found'));
        return;
      }
      
      // Check if user owns this garment
      if (garment.user_id !== req.user.id) {
        next(ApiError.forbidden('You do not have permission to update this garment'));
        return;
      }
      
      // Update metadata
      const updatedGarment = await garmentModel.updateMetadata(id, metadata);
      
      // Return updated garment
      res.status(200).json({
        status: 'success',
        data: { garment: updatedGarment }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async deleteGarment(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      // Check authentication
      if (!req.user) {
        next(ApiError.unauthorized('User not authenticated'));
        return;
      }
      
      // Find garment
      const garment = await garmentModel.findById(id);
      
      // Check if garment exists
      if (!garment) {
        next(ApiError.notFound('Garment not found'));
        return;
      }
      
      // Check if user owns this garment
      if (garment.user_id !== req.user.id) {
        next(ApiError.forbidden('You do not have permission to delete this garment'));
        return;
      }
      
      // Delete the garment
      await garmentModel.delete(id);
      
      // Return success response
      res.status(200).json({
        status: 'success',
        message: 'Garment deleted successfully'
      });
    } catch (error) {
      next(error);
    }
  }
};