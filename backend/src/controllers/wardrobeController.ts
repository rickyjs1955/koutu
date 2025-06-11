/**
 * @fileoverview Wardrobe Controller - Handles all wardrobe-related HTTP requests
 * 
 * This controller manages the complete wardrobe lifecycle including:
 * - Creating, reading, updating, and deleting wardrobes
 * - Managing garment-wardrobe relationships
 * - Comprehensive input validation and error handling
 * - User authentication and authorization
 * 
 * @author Your Team
 * @version 1.0.0
 * @since 2024
 */

import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';
import { wardrobeModel } from '../models/wardrobeModel';
import { garmentModel } from '../models/garmentModel';

/**
 * Lenient UUID regex - accepts all valid UUID formats (v1, v3, v4, v5, nil)
 * Still provides security against injection attacks and malformed IDs
 * 
 * Pattern breakdown:
 * - [0-9a-f]{8}: 8 hexadecimal characters
 * - [0-9a-f]{4}: 4 hexadecimal characters (repeated 3 times)
 * - Case insensitive flag (/i) allows uppercase and lowercase
 * 
 * @example
 * Valid UUIDs:
 * - "550e8400-e29b-41d4-a716-446655440000" (UUID v4)
 * - "00000000-0000-0000-0000-000000000000" (nil UUID)
 * - "A0B1C2D3-E4F5-6789-ABCD-EF0123456789" (uppercase)
 */
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Invalid name characters regex - rejects problematic characters in wardrobe names
 * Allows: letters, numbers, spaces, hyphens, underscores, dots
 * Rejects: @#$%^&*()+=[]{}|\:";'<>?,/
 * 
 * @rationale Security and display consistency
 */
const INVALID_NAME_CHARS = /[@#$%^&*()+=\[\]{}|\\:";'<>?,/]/;

/**
 * Wardrobe Controller
 * 
 * Handles all HTTP requests related to wardrobe management.
 * Provides comprehensive CRUD operations with robust validation,
 * error handling, and security measures.
 * 
 * @namespace wardrobeController
 */
export const wardrobeController = {
  /**
   * Creates a new wardrobe for the authenticated user
   * 
   * @async
   * @function createWardrobe
   * @param {Request} req - Express request object
   * @param {Object} req.body - Request body
   * @param {string} req.body.name - Wardrobe name (required, 1-100 chars)
   * @param {string} [req.body.description] - Wardrobe description (optional, max 1000 chars)
   * @param {Object} req.user - Authenticated user object
   * @param {string} req.user.id - User ID
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next function for error handling
   * 
   * @returns {Promise<void>} 201 status with created wardrobe data
   * 
   * @throws {ApiError} 401 - User not authenticated
   * @throws {ApiError} 400 - Validation errors (missing/invalid name, invalid description)
   * @throws {ApiError} 500 - Internal server error
   * 
   * @example
   * // Request body
   * {
   *   "name": "Summer Collection",
   *   "description": "Light and airy clothes for summer"
   * }
   * 
   * // Response (201)
   * {
   *   "status": "success",
   *   "data": {
   *     "wardrobe": {
   *       "id": "550e8400-e29b-41d4-a716-446655440000",
   *       "user_id": "user-uuid",
   *       "name": "Summer Collection",
   *       "description": "Light and airy clothes for summer",
   *       "created_at": "2024-01-01T00:00:00.000Z",
   *       "updated_at": "2024-01-01T00:00:00.000Z"
   *     }
   *   },
   *   "message": "Wardrobe created successfully"
   * }
   * 
   * @validation
   * - Name: Required, string, 1-100 characters, no special characters (@#$%^&*()+=[]{}|\:";'<>?,/)
   * - Description: Optional, string, max 1000 characters, accepts undefined/null
   * - User: Must be authenticated
   */
  async createWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { name, description } = req.body;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Basic validation - name is required
      if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return next(ApiError.badRequest('Wardrobe name is required', 'MISSING_NAME'));
      }
      
      // Check for invalid characters in name
      if (INVALID_NAME_CHARS.test(name)) {
        return next(ApiError.badRequest('Name contains invalid characters', 'INVALID_NAME_CHARS'));
      }
      
      if (name.trim().length > 100) {
        return next(ApiError.badRequest('Wardrobe name cannot exceed 100 characters', 'NAME_TOO_LONG'));
      }
      
      // Optional description validation - handles null, undefined, and strings
      if (description !== undefined && description !== null && typeof description !== 'string') {
        return next(ApiError.badRequest('Description must be a string', 'INVALID_DESCRIPTION_TYPE'));
      }
      
      if (description && description.length > 1000) {
        return next(ApiError.badRequest('Description cannot exceed 1000 characters', 'DESCRIPTION_TOO_LONG'));
      }
      
      const wardrobe = await wardrobeModel.create({
        user_id: req.user.id,
        name: name.trim(),
        description: description?.trim() || ''
      });
      
      res.status(201).json({
        status: 'success',
        data: { wardrobe },
        message: 'Wardrobe created successfully'
      });
    } catch (error) {
      console.error('Error creating wardrobe:', error);
      next(ApiError.internal('Failed to create wardrobe'));
    }
  },
  
  /**
   * Retrieves all wardrobes for the authenticated user
   * 
   * @async
   * @function getWardrobes
   * @param {Request} req - Express request object
   * @param {Object} req.user - Authenticated user object
   * @param {string} req.user.id - User ID
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next function for error handling
   * 
   * @returns {Promise<void>} 200 status with user's wardrobes and count
   * 
   * @throws {ApiError} 401 - User not authenticated
   * @throws {ApiError} 500 - Internal server error
   * 
   * @example
   * // Response (200)
   * {
   *   "status": "success",
   *   "data": {
   *     "wardrobes": [
   *       {
   *         "id": "wardrobe-uuid-1",
   *         "user_id": "user-uuid",
   *         "name": "Summer Collection",
   *         "description": "Light clothes",
   *         "created_at": "2024-01-01T00:00:00.000Z",
   *         "updated_at": "2024-01-01T00:00:00.000Z"
   *       }
   *     ],
   *     "count": 1
   *   }
   * }
   */
  async getWardrobes(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      const wardrobes = await wardrobeModel.findByUserId(req.user.id);
      
      res.status(200).json({
        status: 'success',
        data: { 
          wardrobes,
          count: wardrobes.length 
        }
      });
    } catch (error) {
      console.error('Error retrieving wardrobes:', error);
      next(ApiError.internal('Failed to retrieve wardrobes'));
    }
  },
  
  /**
   * Retrieves a specific wardrobe with its garments for the authenticated user
   * 
   * @async
   * @function getWardrobe
   * @param {Request} req - Express request object
   * @param {Object} req.params - URL parameters
   * @param {string} req.params.id - Wardrobe UUID
   * @param {Object} req.user - Authenticated user object
   * @param {string} req.user.id - User ID
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next function for error handling
   * 
   * @returns {Promise<void>} 200 status with wardrobe data including garments
   * 
   * @throws {ApiError} 401 - User not authenticated
   * @throws {ApiError} 400 - Invalid UUID format
   * @throws {ApiError} 404 - Wardrobe not found
   * @throws {ApiError} 403 - User doesn't own the wardrobe
   * @throws {ApiError} 500 - Internal server error
   * 
   * @example
   * // Request: GET /wardrobes/550e8400-e29b-41d4-a716-446655440000
   * 
   * // Response (200)
   * {
   *   "status": "success",
   *   "data": {
   *     "wardrobe": {
   *       "id": "550e8400-e29b-41d4-a716-446655440000",
   *       "user_id": "user-uuid",
   *       "name": "Summer Collection",
   *       "description": "Light clothes",
   *       "created_at": "2024-01-01T00:00:00.000Z",
   *       "updated_at": "2024-01-01T00:00:00.000Z",
   *       "garments": [
   *         {
   *           "id": "garment-uuid",
   *           "metadata": { "category": "shirt", "color": "blue" },
   *           "position": 0
   *         }
   *       ]
   *     }
   *   }
   * }
   * 
   * @security Ensures user can only access their own wardrobes
   */
  async getWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      if (!UUID_REGEX.test(id)) {
        return next(ApiError.badRequest('Invalid wardrobe ID format', 'INVALID_UUID'));
      }
      
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to access this wardrobe'));
      }
      
      // Get garments in the wardrobe
      const garments = await wardrobeModel.getGarments(id);
      
      res.status(200).json({
        status: 'success',
        data: {
          wardrobe: {
            ...wardrobe,
            garments
          }
        }
      });
    } catch (error) {
      console.error('Error retrieving wardrobe:', error);
      next(ApiError.internal('Failed to retrieve wardrobe'));
    }
  },
  
  /**
   * Updates an existing wardrobe (partial updates supported)
   * 
   * @async
   * @function updateWardrobe
   * @param {Request} req - Express request object
   * @param {Object} req.params - URL parameters
   * @param {string} req.params.id - Wardrobe UUID
   * @param {Object} req.body - Request body (partial update)
   * @param {string} [req.body.name] - New wardrobe name (optional)
   * @param {string} [req.body.description] - New wardrobe description (optional)
   * @param {Object} req.user - Authenticated user object
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next function for error handling
   * 
   * @returns {Promise<void>} 200 status with updated wardrobe data
   * 
   * @throws {ApiError} 401 - User not authenticated
   * @throws {ApiError} 400 - Invalid UUID or validation errors
   * @throws {ApiError} 404 - Wardrobe not found
   * @throws {ApiError} 403 - User doesn't own the wardrobe
   * @throws {ApiError} 500 - Internal server error
   * 
   * @example
   * // Request: PATCH /wardrobes/550e8400-e29b-41d4-a716-446655440000
   * {
   *   "name": "Updated Summer Collection"
   * }
   * 
   * // Response (200)
   * {
   *   "status": "success",
   *   "data": {
   *     "wardrobe": {
   *       "id": "550e8400-e29b-41d4-a716-446655440000",
   *       "name": "Updated Summer Collection",
   *       "description": "Original description",
   *       "updated_at": "2024-01-01T01:00:00.000Z"
   *     }
   *   },
   *   "message": "Wardrobe updated successfully"
   * }
   * 
   * @validation Same rules as createWardrobe for provided fields
   */
  async updateWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { name, description } = req.body;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      if (!UUID_REGEX.test(id)) {
        return next(ApiError.badRequest('Invalid wardrobe ID format', 'INVALID_UUID'));
      }
      
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to update this wardrobe'));
      }
      
      // Validate updates if provided
      if (name !== undefined) {
        if (typeof name !== 'string' || name.trim().length === 0) {
          return next(ApiError.badRequest('Name must be a non-empty string', 'INVALID_NAME'));
        }
        
        if (INVALID_NAME_CHARS.test(name)) {
          return next(ApiError.badRequest('Name contains invalid characters', 'INVALID_NAME_CHARS'));
        }
        
        if (name.trim().length > 100) {
          return next(ApiError.badRequest('Name cannot exceed 100 characters', 'NAME_TOO_LONG'));
        }
      }
      
      if (description !== undefined && description !== null && typeof description !== 'string') {
        return next(ApiError.badRequest('Description must be a string', 'INVALID_DESCRIPTION_TYPE'));
      }
      
      if (description && description.length > 1000) {
        return next(ApiError.badRequest('Description cannot exceed 1000 characters', 'DESCRIPTION_TOO_LONG'));
      }
      
      const updatedWardrobe = await wardrobeModel.update(id, {
        name: name?.trim(),
        description: description?.trim()
      });
      
      res.status(200).json({
        status: 'success',
        data: { wardrobe: updatedWardrobe },
        message: 'Wardrobe updated successfully'
      });
    } catch (error) {
      console.error('Error updating wardrobe:', error);
      next(ApiError.internal('Failed to update wardrobe'));
    }
  },
  
  /**
   * Adds a garment to a wardrobe at the specified position
   * 
   * @async
   * @function addGarmentToWardrobe
   * @param {Request} req - Express request object
   * @param {Object} req.params - URL parameters
   * @param {string} req.params.id - Wardrobe UUID
   * @param {Object} req.body - Request body
   * @param {string} req.body.garmentId - Garment UUID to add
   * @param {number} [req.body.position=0] - Position in wardrobe (default: 0)
   * @param {Object} req.user - Authenticated user object
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next function for error handling
   * 
   * @returns {Promise<void>} 200 status with success message
   * 
   * @throws {ApiError} 401 - User not authenticated
   * @throws {ApiError} 400 - Invalid UUIDs or position
   * @throws {ApiError} 404 - Wardrobe or garment not found
   * @throws {ApiError} 403 - User doesn't own wardrobe/garment
   * @throws {ApiError} 500 - Internal server error
   * 
   * @example
   * // Request: POST /wardrobes/wardrobe-uuid/garments
   * {
   *   "garmentId": "garment-uuid",
   *   "position": 2
   * }
   * 
   * // Response (200)
   * {
   *   "status": "success",
   *   "data": null,
   *   "message": "Garment added to wardrobe successfully"
   * }
   * 
   * @validation
   * - Position: Non-negative number, string numbers auto-converted
   * - Both wardrobe and garment must belong to authenticated user
   */
  async addGarmentToWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { garmentId, position } = req.body;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      if (!UUID_REGEX.test(id)) {
        return next(ApiError.badRequest('Invalid wardrobe ID format', 'INVALID_UUID'));
      }
      
      if (!garmentId || !UUID_REGEX.test(garmentId)) {
        return next(ApiError.badRequest('Valid garment ID is required', 'INVALID_GARMENT_ID'));
      }
      
      // Validate position if provided
      if (position !== undefined) {
        const pos = Number(position);
        if (isNaN(pos) || pos < 0) {
          return next(ApiError.badRequest('Position must be a non-negative number', 'INVALID_POSITION'));
        }
      }
      
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to modify this wardrobe'));
      }
      
      // Verify garment exists and belongs to user
      const garment = await garmentModel.findById(garmentId);
      
      if (!garment) {
        return next(ApiError.notFound('Garment not found', 'GARMENT_NOT_FOUND'));
      }
      
      if (garment.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to use this garment', 'GARMENT_ACCESS_DENIED'));
      }
      
      await wardrobeModel.addGarment(id, garmentId, position !== undefined ? Number(position) : 0);
      
      res.status(200).json({
        status: 'success',
        data: null,
        message: 'Garment added to wardrobe successfully'
      });
    } catch (error) {
      console.error('Error adding garment to wardrobe:', error);
      next(ApiError.internal('Failed to add garment to wardrobe'));
    }
  },
  
  /**
   * Removes a garment from a wardrobe
   * 
   * @async
   * @function removeGarmentFromWardrobe
   * @param {Request} req - Express request object
   * @param {Object} req.params - URL parameters
   * @param {string} req.params.id - Wardrobe UUID
   * @param {string} req.params.itemId - Garment UUID to remove
   * @param {Object} req.user - Authenticated user object
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next function for error handling
   * 
   * @returns {Promise<void>} 200 status with success message
   * 
   * @throws {ApiError} 401 - User not authenticated
   * @throws {ApiError} 400 - Invalid UUID format
   * @throws {ApiError} 404 - Wardrobe not found or garment not in wardrobe
   * @throws {ApiError} 403 - User doesn't own the wardrobe
   * @throws {ApiError} 500 - Internal server error
   * 
   * @example
   * // Request: DELETE /wardrobes/wardrobe-uuid/garments/garment-uuid
   * 
   * // Response (200)
   * {
   *   "status": "success",
   *   "data": null,
   *   "message": "Garment removed from wardrobe successfully"
   * }
   */
  async removeGarmentFromWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id, itemId } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      if (!UUID_REGEX.test(id)) {
        return next(ApiError.badRequest('Invalid wardrobe ID format', 'INVALID_UUID'));
      }
      
      if (!UUID_REGEX.test(itemId)) {
        return next(ApiError.badRequest('Invalid item ID format', 'INVALID_ITEM_UUID'));
      }
      
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to modify this wardrobe'));
      }
      
      const removed = await wardrobeModel.removeGarment(id, itemId);
      
      if (!removed) {
        return next(ApiError.notFound('Garment not found in wardrobe', 'GARMENT_NOT_IN_WARDROBE'));
      }
      
      res.status(200).json({
        status: 'success',
        data: null,
        message: 'Garment removed from wardrobe successfully'
      });
    } catch (error) {
      console.error('Error removing garment from wardrobe:', error);
      next(ApiError.internal('Failed to remove garment from wardrobe'));
    }
  },
  
  /**
   * Deletes a wardrobe and all its relationships
   * 
   * @async
   * @function deleteWardrobe
   * @param {Request} req - Express request object
   * @param {Object} req.params - URL parameters
   * @param {string} req.params.id - Wardrobe UUID to delete
   * @param {Object} req.user - Authenticated user object
   * @param {Response} res - Express response object
   * @param {NextFunction} next - Express next function for error handling
   * 
   * @returns {Promise<void>} 200 status with success message
   * 
   * @throws {ApiError} 401 - User not authenticated
   * @throws {ApiError} 400 - Invalid UUID format
   * @throws {ApiError} 404 - Wardrobe not found
   * @throws {ApiError} 403 - User doesn't own the wardrobe
   * @throws {ApiError} 500 - Internal server error or deletion failure
   * 
   * @example
   * // Request: DELETE /wardrobes/550e8400-e29b-41d4-a716-446655440000
   * 
   * // Response (200)
   * {
   *   "status": "success",
   *   "data": null,
   *   "message": "Wardrobe deleted successfully"
   * }
   * 
   * @warning This operation is irreversible. All garment relationships are also removed.
   */
  async deleteWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      if (!UUID_REGEX.test(id)) {
        return next(ApiError.badRequest('Invalid wardrobe ID format', 'INVALID_UUID'));
      }
      
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to delete this wardrobe'));
      }
      
      const deleted = await wardrobeModel.delete(id);
      
      if (!deleted) {
        return next(ApiError.internal('Failed to delete wardrobe'));
      }
      
      res.status(200).json({
        status: 'success',
        data: null,
        message: 'Wardrobe deleted successfully'
      });
    } catch (error) {
      console.error('Error deleting wardrobe:', error);
      next(ApiError.internal('Failed to delete wardrobe'));
    }
  }
};

/**
 * @typedef {Object} Wardrobe
 * @property {string} id - UUID of the wardrobe
 * @property {string} user_id - UUID of the owner
 * @property {string} name - Name of the wardrobe (1-100 chars)
 * @property {string} description - Description of the wardrobe (0-1000 chars)
 * @property {Date} created_at - Creation timestamp
 * @property {Date} updated_at - Last update timestamp
 */

/**
 * @typedef {Object} ApiResponse
 * @property {string} status - Response status ('success' or 'error')
 * @property {*} data - Response data (wardrobe object, array, or null)
 * @property {string} [message] - Success message
 * @property {string} [error] - Error message
 * @property {string} [code] - Error code
 */

/**
 * @typedef {Object} AuthenticatedRequest
 * @extends {Request}
 * @property {Object} user - Authenticated user object
 * @property {string} user.id - User UUID
 * @property {string} user.email - User email
 */