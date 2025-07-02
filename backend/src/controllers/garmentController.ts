// /backend/src/controllers/garmentController.ts - Fully Flutter-compatible version

import { Request, Response, NextFunction } from 'express';
import { CreateGarmentInput } from '../../../shared/src/schemas/garment';
import { garmentService } from '../services/garmentService';
import { EnhancedApiError } from '../middlewares/errorHandler';
import { ResponseUtils } from '../utils/responseWrapper';

export const garmentController = {
  /**
   * Create a new garment
   * Flutter-optimized response format
   */
  createGarment: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentData: CreateGarmentInput = req.body;

      // Context-specific validation: Garment business rules only
      const { original_image_id, mask_data, metadata } = garmentData;

      // Validate original_image_id is provided
      if (!original_image_id) {
        throw EnhancedApiError.validation('Original image ID is required', 'original_image_id');
      }

      // Garment-specific: Validate mask data structure (not dimensions)
      if (!mask_data || typeof mask_data !== 'object') {
        throw EnhancedApiError.validation('Missing or invalid mask_data', 'mask_data');
      }

      const { width, height, data } = mask_data;
      
      // Ensure width and height are positive numbers
      if (typeof width !== 'number' || typeof height !== 'number' || width <= 0 || height <= 0) {
        throw EnhancedApiError.validation('Mask data must include valid width and height', 'mask_data.dimensions');
      }

      // Garment-specific: Validate data format (not content)
      if (!data || (!Array.isArray(data) && !(typeof data === 'object' && 'length' in data))) {
        throw EnhancedApiError.validation('Mask data must be an array or Uint8ClampedArray', 'mask_data.data');
      }

      // Garment-specific: Basic data consistency check
      const expectedDataLength = width * height;
      if (data.length !== expectedDataLength) {
        throw EnhancedApiError.validation(
          "Mask data length doesn't match dimensions",
          'mask_data.data',
          { expected: expectedDataLength, actual: data.length }
        );
      }

      // Delegate all business logic to service
      const createdGarment = await garmentService.createGarment({
        userId,
        originalImageId: original_image_id,
        maskData: mask_data,
        metadata
      });

      // Flutter-optimized response
      res.created(
        { garment: createdGarment },
        { 
          message: 'Garment created successfully',
          meta: {
            maskDataSize: data.length,
            dimensions: { width, height }
          }
        }
      );

    } catch (error: any) {
      console.log('🚨 Create garment error:', error);
      
      // Re-throw EnhancedApiError as-is
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      // Handle service errors
      if (error.statusCode || error.code) {
        throw EnhancedApiError.business(
          error.message || 'Garment creation failed',
          'create_garment',
          'garment'
        );
      }
      
      // Handle unexpected errors
      throw EnhancedApiError.internalError('Internal server error while creating garment', error);
    }
  },

  /**
   * Get garments for user
   * Flutter-optimized response format with pagination support
   */
  getGarments: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;

      // Context-specific: Parse garment-specific filters
      let filter = {};
      if (req.query.filter) {
        if (typeof req.query.filter !== 'string') {
          throw EnhancedApiError.validation('Filter must be a JSON string', 'filter');
        }
        
        try {
          filter = JSON.parse(req.query.filter);
        } catch (parseError) {
          throw EnhancedApiError.validation('Invalid JSON in filter parameter', 'filter', req.query.filter);
        }
      }
      
      // Handle pagination with ResponseUtils
      let pagination: { page: number; limit: number } | undefined;
      
      // Check if any pagination parameters are provided
      if (req.query.page !== undefined || req.query.limit !== undefined) {
        const validatedPagination = ResponseUtils.validatePagination(req.query.page, req.query.limit);
        
        // Additional validation for garment-specific limits
        if (validatedPagination.limit > 100) {
          throw EnhancedApiError.validation('Limit cannot exceed 100 garments per page', 'limit', validatedPagination.limit);
        }
        
        pagination = validatedPagination;
      }
      
      const garments = await garmentService.getGarments({
        userId,
        filter,
        pagination
      });
      
      // Flutter-optimized response
      if (pagination) {
        // For paginated responses, we need total count from service
        // Assuming service returns { items, totalCount } for paginated requests
        const totalCount = garments.length; // This should come from service in real implementation
        const paginationMeta = ResponseUtils.createPagination(
          pagination.page,
          pagination.limit,
          totalCount
        );
        
        res.successWithPagination(garments, paginationMeta, {
          message: 'Garments retrieved successfully',
          meta: {
            filter: Object.keys(filter).length > 0 ? filter : undefined
          }
        });
      } else {
        // Non-paginated response
        res.success(garments, {
          message: 'Garments retrieved successfully',
          meta: {
            count: garments.length,
            filter: Object.keys(filter).length > 0 ? filter : undefined
          }
        });
      }

    } catch (error: any) {
      console.log('🚨 Get garments error:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      if (error.statusCode || error.code) {
        throw EnhancedApiError.business(error.message || 'Failed to retrieve garments', 'get_garments', 'garment');
      }
      
      throw EnhancedApiError.internalError('Internal server error while fetching garments', error);
    }
  },

  /**
   * Get single garment
   * Flutter-optimized response format
   */    
  getGarment: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentId = req.params.id; // UUID validation handled by middleware
      
      const garment = await garmentService.getGarment({ garmentId, userId });
      
      // Flutter-optimized response
      res.success(
        { garment },
        { 
          message: 'Garment retrieved successfully',
          meta: {
            garmentId
          }
        }
      );

    } catch (error: any) {
      console.log('🚨 Get garment error:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      if (error.statusCode || error.code) {
        if (error.statusCode === 404) {
          throw EnhancedApiError.notFound('Garment not found', 'garment');
        }
        throw EnhancedApiError.business(error.message || 'Failed to retrieve garment', 'get_garment', 'garment');
      }
      
      throw EnhancedApiError.internalError('Internal server error while fetching garment', error);
    }
  },

  /**
   * Update garment metadata
   * Flutter-optimized response format
   */
  updateGarmentMetadata: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentId = req.params.id; // UUID validation handled by middleware

      // Context-specific: Garment metadata validation
      if (!req.body.hasOwnProperty('metadata')) {
        throw EnhancedApiError.validation('Metadata field is required', 'metadata');
      }

      if (typeof req.body.metadata !== 'object' || req.body.metadata === null || Array.isArray(req.body.metadata)) {
        throw EnhancedApiError.validation('Metadata must be a valid object', 'metadata', req.body.metadata);
      }

      const updatedGarment = await garmentService.updateGarmentMetadata({
        garmentId,
        userId,
        metadata: req.body.metadata,
        options: { replace: req.query.replace === 'true' }
      });
      
      // Flutter-optimized response
      res.success(
        { garment: updatedGarment },
        { 
          message: 'Garment metadata updated successfully',
          meta: {
            operation: req.query.replace === 'true' ? 'replace' : 'merge',
            updatedFields: Object.keys(req.body.metadata)
          }
        }
      );

    } catch (error: any) {
      console.log('🚨 Update metadata error:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      if (error.statusCode || error.code) {
        if (error.statusCode === 404) {
          throw EnhancedApiError.notFound('Garment not found', 'garment');
        }
        throw EnhancedApiError.business(error.message || 'Failed to update garment metadata', 'update_metadata', 'garment');
      }

      throw EnhancedApiError.internalError('Internal server error while updating garment metadata', error);
    }
  },

  /**
   * Delete garment
   * Flutter-optimized response format
   */
  deleteGarment: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user!.id;
      const garmentId = req.params.id; // UUID validation handled by middleware
      
      await garmentService.deleteGarment({ garmentId, userId });
      
      // Flutter-optimized response (204 No Content is also acceptable)
      res.success(
        {}, 
        {
          message: 'Garment deleted successfully',
          meta: {
            deletedGarmentId: garmentId
          }
        }
      );

    } catch (error: any) {
      console.log('🚨 Delete garment error:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      if (error.statusCode || error.code) {
        if (error.statusCode === 404) {
          throw EnhancedApiError.notFound('Garment not found', 'garment');
        }
        throw EnhancedApiError.business(error.message || 'Failed to delete garment', 'delete_garment', 'garment');
      }

      throw EnhancedApiError.internalError('Internal server error while deleting garment', error);
    }
  },
};