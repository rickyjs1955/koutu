// /backend/src/controllers/garmentController.ts - Fixed with Proper Error Handling

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

      // Validate original_image_id is provided
      if (!original_image_id) {
        return res.status(400).json({
          status: 'error',
          message: 'Original image ID is required.'
        });
      }

      // Garment-specific: Validate mask data structure (not dimensions)
      if (!mask_data || typeof mask_data !== 'object') {
        return res.status(400).json({
          status: 'error',
          message: 'Missing or invalid mask_data.'
        });
      }

      const { width, height, data } = mask_data;
      if (!width || !height || typeof width !== 'number' || typeof height !== 'number') {
        return res.status(400).json({
          status: 'error',
          message: 'Mask data must include valid width and height.'
        });
      }

      // Garment-specific: Validate data format (not content)
      if (!data || (!Array.isArray(data) && !(typeof data === 'object' && 'length' in data))) {
        return res.status(400).json({
          status: 'error',
          message: 'Mask data must be an array or Uint8ClampedArray.'
        });
      }

      // Garment-specific: Basic data consistency check
      const expectedDataLength = width * height;
      if (data.length !== expectedDataLength) {
        return res.status(400).json({
          status: 'error',
          message: "Mask data length doesn't match dimensions."
        });
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
    } catch (error: any) {
      console.log('🚨 Create garment error:', error);
      
      // Handle specific service errors
      if (error instanceof ApiError || error.statusCode) {
        return res.status(error.statusCode || 500).json({
          status: 'error',
          message: error.message,
          ...(error.code && { code: error.code })
        });
      }
      
      // Handle other errors
      return res.status(500).json({
        status: 'error',
        message: error.message || 'Internal server error'
      });
    }
  },

  getGarments: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;

      // Context-specific: Parse garment-specific filters
      let filter = {};
      if (req.query.filter) {
        if (typeof req.query.filter !== 'string') {
          return res.status(400).json({
            status: 'error',
            message: 'Filter must be a JSON string.'
          });
        }
        
        try {
          filter = JSON.parse(req.query.filter);
        } catch (error) {
          return res.status(400).json({
            status: 'error',
            message: 'Invalid JSON in filter parameter.'
          });
        }
      }
      
      // Fixed pagination handling - validate if ANY pagination params are provided
      let pagination: { page: number; limit: number } | undefined;
      
      // Check if any pagination parameters are provided
      if (req.query.page !== undefined || req.query.limit !== undefined) {
        const page = req.query.page ? Number(req.query.page) : 1;
        const limit = req.query.limit ? Number(req.query.limit) : 20;
        
        // Validate pagination parameters
        if (isNaN(page) || page < 1 || isNaN(limit) || limit < 1 || limit > 100) {
          return res.status(400).json({
            status: 'error',
            message: 'Invalid pagination parameters.'
          });
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
    } catch (error: any) {
      console.log('🚨 Get garments error:', error);
      
      if (error instanceof ApiError || error.statusCode) {
        return res.status(error.statusCode || 500).json({
          status: 'error',
          message: error.message,
          ...(error.code && { code: error.code })
        });
      }
      
      return res.status(500).json({
        status: 'error',
        message: error.message || 'Internal server error'
      });
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
    } catch (error: any) {
      console.log('🚨 Get garment error:', error);
      
      if (error instanceof ApiError || error.statusCode) {
        return res.status(error.statusCode || 500).json({
          status: 'error',
          message: error.message,
          ...(error.code && { code: error.code })
        });
      }
      
      return res.status(500).json({
        status: 'error',
        message: error.message || 'Internal server error'
      });
    }
  },
  
  updateGarmentMetadata: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentId = req.params.id; // UUID validation handled by middleware

      // Context-specific: Garment metadata validation
      if (!req.body.hasOwnProperty('metadata')) {
        return res.status(400).json({
          status: 'error',
          message: 'Metadata field is required.'
        });
      }

      if (typeof req.body.metadata !== 'object' || req.body.metadata === null || Array.isArray(req.body.metadata)) {
        return res.status(400).json({
          status: 'error',
          message: 'Metadata must be a valid object.'
        });
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
    } catch (error: any) {
      console.log('🚨 Update metadata error:', error);
      
      if (error instanceof ApiError || error.statusCode) {
        return res.status(error.statusCode || 500).json({
          status: 'error',
          message: error.message,
          ...(error.code && { code: error.code })
        });
      }
      
      return res.status(500).json({
        status: 'error',
        message: error.message || 'Internal server error'
      });
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
    } catch (error: any) {
      console.log('🚨 Delete garment error:', error);
      
      if (error instanceof ApiError || error.statusCode) {
        return res.status(error.statusCode || 500).json({
          status: 'error',
          message: error.message,
          ...(error.code && { code: error.code })
        });
      }
      
      return res.status(500).json({
        status: 'error',
        message: error.message || 'Internal server error'
      });
    }
  },
};