// /backend/src/controllers/garmentController.ts - Simplified with Context-Specific Validation

import { Request, Response, NextFunction } from 'express';
import { CreateGarmentInput } from '../../../shared/src/schemas/garment';
import { garmentService } from '../services/garmentService';
import { ApiError } from '../utils/ApiError';

export const garmentController = {
  createGarment: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentData: CreateGarmentInput = req.body;

      // Context-specific validation: Garment business rules only
      const { original_image_id, mask_data, metadata } = garmentData;

      // Garment-specific: Validate mask data structure (not dimensions)
      if (!mask_data || typeof mask_data !== 'object') {
        return next(ApiError.badRequest('Missing or invalid mask_data.'));
      }

      const { width, height, data } = mask_data;
      if (!width || !height || typeof width !== 'number' || typeof height !== 'number') {
        return next(ApiError.badRequest('Mask data must include valid width and height.'));
      }

      // Garment-specific: Validate data format (not content)
      if (!data || (!Array.isArray(data) && !(typeof data === 'object' && 'length' in data))) {
        return next(ApiError.badRequest('Mask data must be an array or Uint8ClampedArray.'));
      }

      // Garment-specific: Basic data consistency check
      const expectedDataLength = width * height;
      if (data.length !== expectedDataLength) {
        return next(ApiError.badRequest(
          `Mask data length doesn't match dimensions.`,
          'MASK_DATA_SIZE_MISMATCH'
        ));
      }

      // Delegate all business logic to service
      const createdGarment = await garmentService.createGarment({
        userId,
        originalImageId: original_image_id,
        maskData: mask_data,
        metadata
      });

      res.status(201).json({
        status: 'success',
        data: { garment: createdGarment },
        message: 'Garment created successfully'
      });
    } catch (error) {
      next(error);
    }
  },

  getGarments: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;

      // Context-specific: Parse garment-specific filters
      let filter = {};
      if (req.query.filter) {
        if (typeof req.query.filter !== 'string') {
          return next(ApiError.badRequest('Filter must be a JSON string.'));
        }
        
        try {
          filter = JSON.parse(req.query.filter);
        } catch (error) {
          return next(ApiError.badRequest('Invalid JSON in filter parameter.'));
        }
      }
      
      // Standard pagination handling
      let pagination: { page: number; limit: number } | undefined;
      if (req.query.page) {
        const page = Number(req.query.page);
        const limit = Number(req.query.limit) || 20;
        
        if (isNaN(page) || page < 1 || isNaN(limit) || limit < 1 || limit > 100) {
          return next(ApiError.badRequest('Invalid pagination parameters.'));
        }
        
        pagination = { page, limit };
      }
      
      const garments = await garmentService.getGarments({
        userId,
        filter,
        pagination
      });
      
      res.status(200).json({
        status: 'success',
        data: { 
          garments,
          count: garments.length,
          ...(pagination && { page: pagination.page, limit: pagination.limit })
        }
      });
    } catch (error) {
      next(error);
    }
  },
    
  getGarment: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentId = req.params.id; // UUID validation handled by middleware
      
      const garment = await garmentService.getGarment({ garmentId, userId });
      
      res.status(200).json({
        status: 'success',
        data: { garment }
      });
    } catch (error) {
      next(error);
    }
  },
  
  updateGarmentMetadata: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentId = req.params.id; // UUID validation handled by middleware

      // Context-specific: Garment metadata validation
      if (!req.body.hasOwnProperty('metadata')) {
        return next(ApiError.badRequest('Metadata field is required for update.'));
      }

      if (typeof req.body.metadata !== 'object' || req.body.metadata === null || Array.isArray(req.body.metadata)) {
        return next(ApiError.badRequest('Metadata must be a valid object.'));
      }

      const updatedGarment = await garmentService.updateGarmentMetadata({
        garmentId,
        userId,
        metadata: req.body.metadata,
        options: { replace: req.query.replace === 'true' }
      });
      
      res.status(200).json({
        status: 'success',
        data: { garment: updatedGarment },
        message: 'Garment metadata updated successfully'
      });
    } catch (error) {
      next(error);
    }
  },
  
  deleteGarment: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentId = req.params.id; // UUID validation handled by middleware
      
      await garmentService.deleteGarment({ garmentId, userId });
      
      res.status(200).json({
        status: 'success',
        data: null,
        message: 'Garment deleted successfully'
      });
    } catch (error) {
      next(error);
    }
  },
};