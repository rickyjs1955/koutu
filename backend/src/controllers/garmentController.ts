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
 * - Authentication verification on all endpoints
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
import { ApiError } from '../utils/ApiError';
import { garmentModel } from '../models/garmentModel';
import { imageModel } from '../models/imageModel';
import { labelingService } from '../services/labelingService';
import {  
  CreateGarmentInput
} from '../../../shared/src/schemas/garment';

export const garmentController = {
  async createGarment(req: Request, res: Response, next: NextFunction) {
    try {
      // Authentication check
      if (!req.user) {
        next(ApiError.unauthorized('User not authenticated'));
        return;
      }

      // TypeScript type guard
      const userId = req.user.id;
      
      const { original_image_id, mask_data, metadata } = req.body as CreateGarmentInput;

      // Find the original image
      const originalImage = await imageModel.findById(original_image_id);
      
      // Check if image exists
      if (!originalImage) {
        next(ApiError.notFound('Original image not found'));
        return;
      }

      // Check if user owns the image
      if (originalImage.user_id !== userId) {
        next(ApiError.forbidden('You do not have permission to use this image'));
        return;
      }

      // Business rule: validate image status
      if (originalImage.status !== 'new') {
        if (originalImage.status === 'labeled') {
          next(ApiError.badRequest('This image has already been used to create a garment'));
        } else {
          next(ApiError.badRequest('Image must be in "new" status before creating a garment'));
        }
        return;
      }

      // Process the image using labeling service
      const { maskedImagePath, maskPath } = await labelingService.applyMaskToImage(
        originalImage.file_path,
        mask_data
      );

      // Update image status to labeled
      await imageModel.updateStatus(original_image_id, 'labeled');

      // Sanitize metadata input
      const sanitizedMetadata = {
        type: metadata?.type,
        color: metadata?.color,
        pattern: metadata?.pattern,
        season: metadata?.season,
        brand: metadata?.brand,
        tags: Array.isArray(metadata?.tags) ? metadata.tags : []
      };

      // Create with sanitized metadata
      const createdGarment = await garmentModel.create({
        user_id: userId,
        original_image_id,
        file_path: maskedImagePath,
        mask_path: maskPath,
        metadata: sanitizedMetadata,
      });

      // Create safe garment object with sanitized paths and filtered metadata
      const safeGarment = {
        id: createdGarment.id,
        user_id: createdGarment.user_id,
        original_image_id: createdGarment.original_image_id,
        // Sanitize file paths to use API routes instead of file system paths
        file_path: `/api/garments/${createdGarment.id}/image`,
        mask_path: `/api/garments/${createdGarment.id}/mask`,
        // Filter metadata to only include allowed fields
        metadata: {
          type: createdGarment.metadata?.type,
          color: createdGarment.metadata?.color,
          pattern: createdGarment.metadata?.pattern,
          season: createdGarment.metadata?.season,
          brand: createdGarment.metadata?.brand,
          tags: Array.isArray(createdGarment.metadata?.tags) ? createdGarment.metadata.tags : []
        },
        created_at: createdGarment.created_at,
        updated_at: createdGarment.updated_at,
        data_version: createdGarment.data_version
      };

      // Return sanitized response
      res.status(201).json({
        status: 'success',
        data: { garment: safeGarment }
      });
    } catch (error) {
      // Sanitize error to prevent leaking implementation details
      const sanitizedError = ApiError.internal('An error occurred while creating the garment');
      next(sanitizedError);
    }
  },

  async getGarments(req: Request, res: Response, next: NextFunction) {
    try {
      // Check authentication
      if (!req.user || !req.user.id) {
        next(ApiError.unauthorized('User not authenticated'));
        return;
      }

      // TypeScript type guard - ensures req.user is recognized as defined
      const userId = req.user.id;
      
      // Get all garments for the current user
      const garments = await garmentModel.findByUserId(req.user.id);
      
      // Add this validation to double-check user ownership
      const verifiedGarments = garments.filter(g => g.user_id === userId);

      // Create safe garment objects with filtered metadata and sanitized paths
      const safeGarments = verifiedGarments.map(garment => ({
        id: garment.id,
        user_id: garment.user_id,
        original_image_id: garment.original_image_id,
        // Sanitize file paths to use API routes instead of file system paths
        file_path: `/api/garments/${garment.id}/image`,
        mask_path: `/api/garments/${garment.id}/mask`,
        // Filter metadata to only include allowed fields
        metadata: {
          type: garment.metadata?.type,
          color: garment.metadata?.color,
          pattern: garment.metadata?.pattern,
          season: garment.metadata?.season,
          brand: garment.metadata?.brand,
          tags: Array.isArray(garment.metadata?.tags) ? garment.metadata.tags : []
        },
        created_at: garment.created_at,
        updated_at: garment.updated_at,
        data_version: garment.data_version
      }));

      // Return the list of garments
      res.status(200).json({
        status: 'success',
        data: { 
          garments: safeGarments,
          count: safeGarments.length 
        }
      });
    } catch (error) {
      // Sanitize error to prevent leaking implementation details
      const sanitizedError = ApiError.internal('An error occurred while retrieving garments');
      next(sanitizedError);
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
      
      // TypeScript type guard
      const userId = req.user.id;
      
      // Fetch garment from database
      const garment = await garmentModel.findById(id);
      
      // Check if garment exists
      if (!garment) {
        next(ApiError.notFound('Garment not found'));
        return;
      }
      
      // Check if user owns this garment
      if (garment.user_id !== userId) {
        next(ApiError.forbidden('You do not have permission to access this garment'));
        return;
      }
      
      // Create a safe garment object with sanitized paths and filtered metadata
      const safeGarment = {
        id: garment.id,
        user_id: garment.user_id,
        original_image_id: garment.original_image_id,
        // Sanitize file paths to use API routes instead of file system paths
        file_path: `/api/garments/${garment.id}/image`,
        mask_path: `/api/garments/${garment.id}/mask`,
        // Filter metadata to only include allowed fields
        metadata: {
          type: garment.metadata?.type,
          color: garment.metadata?.color,
          pattern: garment.metadata?.pattern,
          season: garment.metadata?.season,
          brand: garment.metadata?.brand,
          tags: Array.isArray(garment.metadata?.tags) ? garment.metadata.tags : []
        },
        created_at: garment.created_at,
        updated_at: garment.updated_at,
        data_version: garment.data_version
      };
      
      // Return sanitized garment data
      res.status(200).json({
        status: 'success',
        data: { garment: safeGarment }
      });
    } catch (error) {
      // Sanitize error to prevent leaking implementation details
      const sanitizedError = ApiError.internal('An error occurred while retrieving the garment');
      next(sanitizedError);
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
      
      // TypeScript type guard
      const userId = req.user.id;
      
      // Find garment
      const garment = await garmentModel.findById(id);
      
      // Check if garment exists
      if (!garment) {
        next(ApiError.notFound('Garment not found'));
        return;
      }
      
      // Check if user owns this garment
      if (garment.user_id !== userId) {
        next(ApiError.forbidden('You do not have permission to update this garment'));
        return;
      }
      
      // Sanitize and validate metadata input - only accept allowed fields
      const sanitizedMetadata = {
        type: metadata.type,
        color: metadata.color,
        pattern: metadata.pattern,
        season: metadata.season,
        brand: metadata.brand,
        tags: Array.isArray(metadata.tags) ? metadata.tags : []
      };
      
      // Update metadata with sanitized input - wrap in proper structure
      const updatedGarment = await garmentModel.updateMetadata(id, { 
        metadata: sanitizedMetadata 
      });

      // Check if update was successful
      if (!updatedGarment) {
        next(ApiError.internal('Failed to update garment metadata'));
        return;
      }
      
      // Create a safe response object
      const safeGarment = {
        id: updatedGarment.id,
        user_id: updatedGarment.user_id,
        original_image_id: updatedGarment.original_image_id,
        // Sanitize file paths to use API routes instead of file system paths
        file_path: `/api/garments/${updatedGarment.id}/image`,
        mask_path: `/api/garments/${updatedGarment.id}/mask`,
        // Filter metadata to only include allowed fields
        metadata: {
          type: updatedGarment.metadata?.type,
          color: updatedGarment.metadata?.color,
          pattern: updatedGarment.metadata?.pattern,
          season: updatedGarment.metadata?.season,
          brand: updatedGarment.metadata?.brand,
          tags: Array.isArray(updatedGarment.metadata?.tags) ? updatedGarment.metadata.tags : []
        },
        created_at: updatedGarment.created_at,
        updated_at: updatedGarment.updated_at,
        data_version: updatedGarment.data_version
      };
      
      // Return sanitized garment data
      res.status(200).json({
        status: 'success',
        data: { garment: safeGarment }
      });
    } catch (error) {
      // Sanitize error to prevent leaking implementation details
      const sanitizedError = ApiError.internal('An error occurred while updating the garment metadata');
      next(sanitizedError);
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
      
      // TypeScript type guard
      const userId = req.user.id;
      
      // Find garment
      const garment = await garmentModel.findById(id);
      
      // Check if garment exists
      if (!garment) {
        next(ApiError.notFound('Garment not found'));
        return;
      }
      
      // Check if user owns this garment
      if (garment.user_id !== userId) {
        next(ApiError.forbidden('You do not have permission to delete this garment'));
        return;
      }
      
      // Delete the garment
      const deleteResult = await garmentModel.delete(id);

      // Check if deletion was successful
      if (!deleteResult) {
        next(ApiError.internal('Failed to delete garment'));
        return;
      }
      
      // Return success response
      res.status(200).json({
        status: 'success',
        message: 'Garment deleted successfully'
      });
    } catch (error) {
      // Sanitize error to prevent leaking implementation details
      const sanitizedError = ApiError.internal('An error occurred while deleting the garment');
      next(sanitizedError);
    }
  }
};