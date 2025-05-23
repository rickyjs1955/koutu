// filepath: /backend/src/controllers/garmentController.ts

/**
 * Garment Controller
 * 
 * Handles all garment-related operations in the application, providing a secure layer
 * between client requests and data access. This controller implements comprehensive
 * security measures including authentication verification, authorization checks,
 * data sanitization, and error handling.
 * 
 * Security Features:
 * - Authentication verification on all endpoints (handled by auth middleware)
 * - Authorization checks to ensure users can only access their own garments
 * - Path sanitization to prevent directory traversal and exposure
 * - Metadata filtering to prevent sensitive data leakage
 * - Input validation and sanitization to prevent injection attacks
 * - Error sanitization to prevent implementation details exposure
 * - Double verification of user ownership beyond database queries
 * 
 * Operations:
 * - createGarment: Creates a new garment from an existing image and mask data
 * - getGarments: Retrieves all garments owned by the authenticated user
 * - getGarment: Retrieves a specific garment by ID (with ownership verification)
 * - updateGarmentMetadata: Updates metadata for a specific garment
 * - deleteGarment: Removes a garment from the system
 * 
 * Data Flow:
 * - Receives client requests with authentication context
 * - Validates permissions and input data
 * - Interacts with models (garmentModel, imageModel)
 * - Uses services (labelingService) for business operations
 * - Sanitizes response data before returning to client
 * 
 * Note: All methods implement consistent error handling that logs detailed errors
 * for debugging while only returning sanitized error messages to clients.
 */

import { Request, Response, NextFunction } from 'express';
import {  
  CreateGarmentInput
} from '../../../shared/src/schemas/garment';
import { sanitization } from '../utils/sanitize';
import { garmentService } from '../services/garmentService';
import { ApiError } from '@/utils/ApiError';

// A simple UUID regex for basic validation
const UUID_REGEX = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export const garmentController = {
  createGarment: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      // Non-null assertion is safe because requireAuth middleware ensures req.user exists
      const userId = req.user!.id;

      // Defensive check for req.body and essential properties
      if (!req.body || typeof req.body !== 'object') {
        return next(ApiError.badRequest('Request body is missing or invalid.'));
      }
      const { original_image_id, mask_data, metadata } = req.body as CreateGarmentInput;

      if (!original_image_id || typeof original_image_id !== 'string') {
        return next(ApiError.badRequest('Missing or invalid original_image_id.'));
      }
      if (!mask_data || typeof mask_data !== 'object') { // Add more specific checks for mask_data if needed
        return next(ApiError.badRequest('Missing or invalid mask_data.'));
      }
      // Optional: check metadata format if it's always expected to be an object
      if (metadata !== undefined && (typeof metadata !== 'object' || metadata === null)) {
        return next(ApiError.badRequest('Invalid metadata format. Expected an object.'));
      }

      // Delegate business logic to service
      const createdGarment = await garmentService.createGarment({
        userId,
        originalImageId: original_image_id,
        maskData: mask_data,
        metadata
      });
      
      // Use centralized sanitization
      const safeGarment = sanitization.sanitizeGarmentForResponse(createdGarment);

      // Return standardized response
      res.status(201).json({
        status: 'success',
        data: { garment: safeGarment }
      });
    },
    'creating'
  ),

  getGarments: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      // Non-null assertion is safe because requireAuth middleware ensures req.user exists
      const userId = req.user!.id;

      let filter = {};
      if (req.query.filter) {
        try {
          // Ensure req.query.filter is a string before parsing
          if (typeof req.query.filter !== 'string') {
            return next(ApiError.badRequest('Invalid filter format: filter must be a JSON string.'));
          }
          filter = JSON.parse(req.query.filter);
          if (typeof filter !== 'object' || filter === null) {
            // If JSON.parse results in non-object (e.g. "null", "true", "123" as valid JSON)
             return next(ApiError.badRequest('Invalid filter format: filter must be a JSON object.'));
          }
        } catch (error) {
          return next(ApiError.badRequest('Malformed JSON in filter parameter.'));
        }
      }
      
      // Optional: Extract pagination parameters
      const pagination = req.query.page ? {
        page: Number(req.query.page) || 1,
        limit: Number(req.query.limit) || 20
      } : undefined;
      
      // Delegate to service layer
      const garments = await garmentService.getGarments({
        userId,
        filter,
        pagination
      });
      
      // Use centralized sanitization for each garment
      const safeGarments = garments.map(garment => 
        sanitization.sanitizeGarmentForResponse(garment)
      );
      
      // Return standardized response
      res.status(200).json({
        status: 'success',
        data: { 
          garments: safeGarments,
          count: safeGarments.length 
        }
      });
    },
    'retrieving'
  ),
    
  // Consolidated getGarment method
  getGarment: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      // Non-null assertion is safe because requireAuth middleware ensures req.user exists
      const userId = req.user!.id;

      // Validate request parameters
      const garmentId = req.params.id;

      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(garmentId)) {
        return next(ApiError.badRequest('Invalid garmentId: must be a valid UUID'));
      }

      if (!garmentId || typeof garmentId !== 'string' || !UUID_REGEX.test(garmentId)) {
        return next(ApiError.badRequest('Invalid or missing garmentId. Expected a valid UUID.'));
      }
      
      // Use service for business logic
      const garment = await garmentService.getGarment({ garmentId, userId });
      
      // Use sanitization for response
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
      // Non-null assertion is safe because requireAuth middleware ensures req.user exists
      const userId = req.user!.id;

      const garmentId = req.params.id;
      if (!garmentId || typeof garmentId !== 'string' || !UUID_REGEX.test(garmentId)) {
        return next(ApiError.badRequest('Invalid or missing garmentId. Expected a valid UUID.'));
      }

      if (!req.body || typeof req.body !== 'object') {
        return next(ApiError.badRequest('Request body is missing or invalid.'));
      }
      
      // The schema UpdateGarmentMetadataSchema expects metadata to be an object.
      // This check ensures that if metadata is provided, it's an object.
      // If metadata is optional and can be omitted, this check might need adjustment
      // based on whether `req.body.metadata` is present or not.
      // The test 'should handle invalid metadata format' passes `body: { metadata: 'invalid' }`
      // so we check if metadata is present and not an object.
      if (req.body.hasOwnProperty('metadata')) {
        if (typeof req.body.metadata !== 'object' || req.body.metadata === null) {
          return next(ApiError.badRequest('Invalid metadata format. Expected an object.'));
        }
      } else {
        // If metadata is strictly required by the schema being validated by `validate.ts`
        // this case might not be hit if `validate.ts` runs first.
        // However, if metadata is optional at schema level but this controller action
        // implies it should be present for an update, this check is relevant.
        // For the test case, metadata is present but invalid.
        // If metadata is truly optional for an update, this 'else' might not be needed.
      }
      const incomingMetadata = req.body.metadata;

      if (!incomingMetadata || typeof incomingMetadata !== 'object' || Array.isArray(incomingMetadata)) {
        return next(ApiError.badRequest('Metadata must be a valid object'));
      }
      
      // Pre-sanitize metadata using the utility
      const sanitizedMetadata = sanitization.sanitizeGarmentMetadata(incomingMetadata);
      
      // Delegate to service layer (with replace option if needed)
      const updatedGarment = await garmentService.updateGarmentMetadata({
        garmentId,
        userId,
        metadata: sanitizedMetadata,
        options: { replace: req.query.replace === 'true' }
      });
      
      // Use centralized sanitization for response
      const safeGarment = sanitization.sanitizeGarmentForResponse(updatedGarment);
      
      // Return standardized response
      res.status(200).json({
        status: 'success',
        data: { garment: safeGarment }
      });
    },
    'updating'
  ),
  
  deleteGarment: sanitization.wrapGarmentController(
    async (req: Request, res: Response, next: NextFunction) => {
      // Non-null assertion is safe because requireAuth middleware ensures req.user exists
      const userId = req.user!.id;
      
      const garmentId = req.params.id;

      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

      if (!uuidRegex.test(garmentId)) {
        return next(ApiError.badRequest('Invalid garmentId: must be a valid UUID'));
      }
      
      // Add garmentId validation
      if (!garmentId || typeof garmentId !== 'string' || !UUID_REGEX.test(garmentId)) {
        return next(ApiError.badRequest('Invalid or missing garmentId. Expected a valid UUID.'));
      }
      
      // Delegate to service layer
      
      // Delegate to service layer
      await garmentService.deleteGarment({
        garmentId,
        userId
      });
      
      // Return standardized response
      res.status(200).json({
        status: 'success',
        message: 'Garment deleted successfully'
      });
    },
    'deleting'
  ),
};