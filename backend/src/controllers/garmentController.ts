// /backend/src/controllers/garmentController.ts - FIXED TypeScript Issues

import { Request, Response, NextFunction } from 'express';
import { CreateGarmentInput } from '../../../shared/src/schemas/garment';
import { sanitization } from '../utils/sanitize';
import { garmentService } from '../services/garmentService';
import { ApiError } from '../utils/ApiError';

const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const garmentController = {
  createGarment: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;

      // Basic request validation
      if (!req.body || typeof req.body !== 'object') {
        return next(ApiError.badRequest('Request body is missing or invalid.'));
      }

      const { original_image_id, mask_data, metadata } = req.body as CreateGarmentInput;

      // Garment-specific validation
      if (!original_image_id || typeof original_image_id !== 'string') {
        return next(ApiError.badRequest('Missing or invalid original_image_id.'));
      }

      if (!UUID_REGEX.test(original_image_id)) {
        return next(ApiError.badRequest('Invalid original_image_id format.', 'INVALID_UUID'));
      }

      // Mask data validation (garment-specific business rule)
      if (!mask_data || typeof mask_data !== 'object') {
        return next(ApiError.badRequest('Missing or invalid mask_data.'));
      }

      const { width, height, data } = mask_data;
      if (!width || !height || typeof width !== 'number' || typeof height !== 'number') {
        return next(ApiError.badRequest('Mask data must include valid width and height.', 'INVALID_MASK_DIMENSIONS'));
      }

      if (width < 1 || height < 1 || width > 10000 || height > 10000) {
        return next(ApiError.badRequest('Mask dimensions must be between 1 and 10000 pixels.', 'MASK_DIMENSION_OUT_OF_RANGE'));
      }

      // FIXED: Proper type checking for data arrays
      if (!data || (!Array.isArray(data) && !(typeof data === 'object' && 'length' in data))) {
        return next(ApiError.badRequest('Mask data must be an array or Uint8ClampedArray.', 'INVALID_MASK_DATA'));
      }

      const expectedDataLength = width * height;
      if (data.length !== expectedDataLength) {
        return next(ApiError.badRequest(
          `Mask data length (${data.length}) doesn't match dimensions (${width}x${height}=${expectedDataLength}).`,
          'MASK_DATA_SIZE_MISMATCH'
        ));
      }

      // Metadata validation (optional but structured)
      if (metadata !== undefined && (typeof metadata !== 'object' || metadata === null)) {
        return next(ApiError.badRequest('Invalid metadata format. Expected an object.'));
      }

      // Delegate to service for business logic
      const createdGarment = await garmentService.createGarment({
        userId,
        originalImageId: original_image_id,
        maskData: mask_data,
        metadata
      });
      
      const safeGarment = sanitization.sanitizeGarmentForResponse(createdGarment);

      res.status(201).json({
        status: 'success',
        data: { garment: safeGarment },
        message: 'Garment created successfully'
      });
    },
    'creating'
  ),

  getGarments: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;

      // Parse and validate filters
      let filter = {};
      if (req.query.filter) {
        if (typeof req.query.filter !== 'string') {
          return next(ApiError.badRequest('Filter must be a JSON string.'));
        }
        
        try {
          filter = JSON.parse(req.query.filter);
          if (typeof filter !== 'object' || filter === null) {
            return next(ApiError.badRequest('Filter must be a JSON object.'));
          }
        } catch (error) {
          return next(ApiError.badRequest('Invalid JSON in filter parameter.', 'INVALID_JSON'));
        }
      }
      
      // Parse pagination with reasonable limits
      let pagination: { page: number; limit: number } | undefined;
      if (req.query.page) {
        const page = Number(req.query.page);
        const limit = Number(req.query.limit) || 20;
        
        if (isNaN(page) || page < 1) {
          return next(ApiError.badRequest('Page must be a positive number.', 'INVALID_PAGE'));
        }
        
        if (isNaN(limit) || limit < 1 || limit > 100) {
          return next(ApiError.badRequest('Limit must be between 1 and 100.', 'INVALID_LIMIT'));
        }
        
        pagination = { page, limit };
      }
      
      const garments = await garmentService.getGarments({
        userId,
        filter,
        pagination
      });
      
      const safeGarments = garments.map(garment => 
        sanitization.sanitizeGarmentForResponse(garment)
      );
      
      res.status(200).json({
        status: 'success',
        data: { 
          garments: safeGarments,
          count: safeGarments.length,
          ...(pagination && { page: pagination.page, limit: pagination.limit })
        }
      });
    },
    'retrieving'
  ),
    
  getGarment: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const garmentId = req.params.id;

      // Basic UUID validation
      if (!garmentId || typeof garmentId !== 'string' || !UUID_REGEX.test(garmentId)) {
        return next(ApiError.badRequest('Invalid garmentId format.', 'INVALID_UUID'));
      }
      
      const garment = await garmentService.getGarment({ garmentId, userId });
      const safeGarment = sanitization.sanitizeGarmentForResponse(garment);
      
      res.status(200).json({
        status: 'success',
        data: { garment: safeGarment }
      });
    },
    'retrieving'
  ),
  
  updateGarmentMetadata: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const garmentId = req.params.id;

      // Basic UUID validation
      if (!garmentId || typeof garmentId !== 'string' || !UUID_REGEX.test(garmentId)) {
        return next(ApiError.badRequest('Invalid garmentId format.', 'INVALID_UUID'));
      }

      if (!req.body || typeof req.body !== 'object') {
        return next(ApiError.badRequest('Request body is missing or invalid.'));
      }

      if (!req.body.hasOwnProperty('metadata')) {
        return next(ApiError.badRequest('Metadata field is required for update.', 'MISSING_METADATA'));
      }

      if (typeof req.body.metadata !== 'object' || req.body.metadata === null) {
        return next(ApiError.badRequest('Metadata must be a valid object.', 'INVALID_METADATA_TYPE'));
      }

      const incomingMetadata = req.body.metadata;

      // Garment-specific metadata validation
      if (Array.isArray(incomingMetadata)) {
        return next(ApiError.badRequest('Metadata cannot be an array.', 'METADATA_ARRAY_NOT_ALLOWED'));
      }
      
      const sanitizedMetadata = sanitization.sanitizeGarmentMetadata(incomingMetadata);
      
      const updatedGarment = await garmentService.updateGarmentMetadata({
        garmentId,
        userId,
        metadata: sanitizedMetadata,
        options: { replace: req.query.replace === 'true' }
      });
      
      const safeGarment = sanitization.sanitizeGarmentForResponse(updatedGarment);
      
      res.status(200).json({
        status: 'success',
        data: { garment: safeGarment },
        message: 'Garment metadata updated successfully'
      });
    },
    'updating'
  ),
  
  deleteGarment: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      const userId = req.user!.id;
      const garmentId = req.params.id;
      
      // Basic UUID validation
      if (!garmentId || typeof garmentId !== 'string' || !UUID_REGEX.test(garmentId)) {
        return next(ApiError.badRequest('Invalid garmentId format.', 'INVALID_UUID'));
      }
      
      await garmentService.deleteGarment({
        garmentId,
        userId
      });
      
      res.status(200).json({
        status: 'success',
        data: null,
        message: 'Garment deleted successfully'
      });
    },
    'deleting'
  ),
};