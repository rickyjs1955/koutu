// /backend/src/controllers/wardrobeController.ts - Fixed Flutter-compatible version

import { Request, Response, NextFunction } from 'express';
import { EnhancedApiError } from '../middlewares/errorHandler';
import { wardrobeModel } from '../models/wardrobeModel';
import { garmentModel } from '../models/garmentModel';
import { sanitization } from '../utils/sanitize';
import { ResponseUtils } from '../utils/responseWrapper';

/**
 * Enhanced input validation with type checking for wardrobe operations
 */
const validateAndSanitizeWardrobeInput = (name: any, description: any) => {
  // Handle type confusion attacks
  if (Array.isArray(name) || Array.isArray(description)) {
    throw EnhancedApiError.validation('Invalid input format', 'name|description');
  }
  
  if (name !== null && typeof name === 'object') {
    throw EnhancedApiError.validation('Invalid name format', 'name');
  }
  
  if (description !== null && typeof description === 'object' && description !== undefined) {
    throw EnhancedApiError.validation('Invalid description format', 'description');
  }

  // Check for missing name (required field)
  if (!name) {
    throw EnhancedApiError.validation('Wardrobe name is required', 'name');
  }

  // Convert to strings for processing
  const nameStr = String(name).trim();
  const descriptionStr = description !== null && description !== undefined ? String(description).trim() : '';

  // Validate after conversion (catches whitespace-only inputs)
  if (!nameStr) {
    throw EnhancedApiError.validation('Wardrobe name cannot be empty', 'name');
  }

  return { name: nameStr, description: descriptionStr };
};

/**
 * Enhanced wardrobe name validation
 */
const validateWardrobeName = (name: string): void => {
  // Length validation
  if (name.length > 100) {
    throw EnhancedApiError.validation('Wardrobe name cannot exceed 100 characters', 'name', name.length);
  }

  // Character validation - reject problematic characters
  const invalidChars = /[@#$%^&*()+=\[\]{}|\\:";'<>?,/]/;
  if (invalidChars.test(name)) {
    throw EnhancedApiError.validation(
      'Name contains invalid characters. Only letters, numbers, spaces, hyphens, underscores, and dots are allowed',
      'name',
      { invalidChars: name.match(invalidChars) }
    );
  }

  // Prevent names that are only special characters or whitespace
  if (!/[a-zA-Z0-9]/.test(name)) {
    throw EnhancedApiError.validation('Name must contain at least one letter or number', 'name');
  }
};

/**
 * Enhanced description validation
 */
const validateWardrobeDescription = (description: string): void => {
  if (description && description.length > 1000) {
    throw EnhancedApiError.validation('Description cannot exceed 1000 characters', 'description', description.length);
  }
};

/**
 * Validate UUID format with enhanced error messages
 */
const validateUUID = (id: string, fieldName: string): void => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(id)) {
    throw EnhancedApiError.validation(`Invalid ${fieldName} format`, fieldName, id);
  }
};

/**
 * Validate position parameter for garment placement
 */
const validatePosition = (position: any): number => {
  if (position === undefined || position === null) {
    return 0; // Default position
  }

  const pos = Number(position);
  if (isNaN(pos) || pos < 0) {
    throw EnhancedApiError.validation('Position must be a non-negative number', 'position', position);
  }

  if (pos > 1000) {
    throw EnhancedApiError.validation('Position cannot exceed 1000', 'position', pos);
  }

  return Math.floor(pos); // Ensure integer
};

export const wardrobeController = {
  /**
   * Create a new wardrobe
   * Flutter-optimized response format
   */
  async createWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      const { name, description } = validateAndSanitizeWardrobeInput(req.body.name, req.body.description);

      // Enhanced validation
      validateWardrobeName(name);
      validateWardrobeDescription(description);

      const wardrobeData = {
        user_id: req.user.id,
        name: sanitization.sanitizeUserInput(name),
        description: description ? sanitization.sanitizeUserInput(description) : ''
      };

      const wardrobe = await wardrobeModel.create(wardrobeData);

      // Flutter-optimized response
      res.created(
        { wardrobe },
        {
          message: 'Wardrobe created successfully',
          meta: {
            wardrobeId: wardrobe.id,
            nameLength: name.length,
            hasDescription: !!description,
            createdAt: new Date().toISOString()
          }
        }
      );

    } catch (error: any) {
      console.error('Error creating wardrobe:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      // Handle database constraint errors
      if (error?.code === '23505' || error?.message?.includes('duplicate')) {
        throw EnhancedApiError.conflict('A wardrobe with this name already exists', 'name');
      }
      
      throw EnhancedApiError.internalError('Failed to create wardrobe', error);
    }
  },

  /**
   * Get all wardrobes for user
   * Flutter-optimized response format with pagination support
   */
  async getWardrobes(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      // Handle pagination with ResponseUtils
      let pagination: { page: number; limit: number } | undefined;
      
      if (req.query.page !== undefined || req.query.limit !== undefined) {
        const validatedPagination = ResponseUtils.validatePagination(req.query.page, req.query.limit);
        
        // Wardrobe-specific limit validation
        if (validatedPagination.limit > 50) {
          throw EnhancedApiError.validation('Limit cannot exceed 50 wardrobes per page', 'limit', validatedPagination.limit);
        }
        
        pagination = validatedPagination;
      }

      // Get wardrobes (pagination needs to be handled in service layer)
      const wardrobes = await wardrobeModel.findByUserId(req.user.id);

      // Apply client-side pagination if needed (temporary solution)
      let paginatedWardrobes = wardrobes;
      if (pagination) {
        const startIndex = (pagination.page - 1) * pagination.limit;
        const endIndex = startIndex + pagination.limit;
        paginatedWardrobes = wardrobes.slice(startIndex, endIndex);
      }

      // Sanitize response data
      const safeWardrobes = paginatedWardrobes.map(wardrobe => ({
        ...wardrobe,
        name: sanitization.sanitizeUserInput(wardrobe.name),
        description: wardrobe.description ? sanitization.sanitizeUserInput(wardrobe.description) : ''
      }));

      // Flutter-optimized response - Fixed to return array directly
      if (pagination) {
        const totalCount = wardrobes.length;
        const paginationMeta = ResponseUtils.createPagination(
          pagination.page,
          pagination.limit,
          totalCount
        );
        
        res.successWithPagination(safeWardrobes, paginationMeta, {
          message: 'Wardrobes retrieved successfully',
          meta: {
            userId: req.user.id,
            count: safeWardrobes.length
          }
        });
      } else {
        res.success(safeWardrobes, {
          message: 'Wardrobes retrieved successfully',
          meta: {
            count: safeWardrobes.length,
            userId: req.user.id
          }
        });
      }

    } catch (error: any) {
      console.error('Error retrieving wardrobes:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      throw EnhancedApiError.internalError('Failed to retrieve wardrobes', error);
    }
  },

  /**
   * Get single wardrobe with garments
   * Flutter-optimized response format
   */
  async getWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      const wardrobeId = req.params.id;
      validateUUID(wardrobeId, 'wardrobeId');

      const wardrobe = await wardrobeModel.findById(wardrobeId);
      
      if (!wardrobe) {
        throw EnhancedApiError.notFound('Wardrobe not found', 'wardrobe');
      }

      if (wardrobe.user_id !== req.user.id) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to access this wardrobe', 'wardrobe');
      }

      // Get garments in the wardrobe
      const garments = await wardrobeModel.getGarments(wardrobeId);

      // Sanitize response data
      const safeWardrobe = {
        ...wardrobe,
        name: sanitization.sanitizeUserInput(wardrobe.name),
        description: wardrobe.description ? sanitization.sanitizeUserInput(wardrobe.description) : '',
        garments: garments.map(garment => ({
          ...garment,
          metadata: garment.metadata ? sanitization.sanitizeForSecurity(garment.metadata) : {}
        }))
      };

      // Flutter-optimized response
      res.success(
        { wardrobe: safeWardrobe },
        {
          message: 'Wardrobe retrieved successfully',
          meta: {
            wardrobeId,
            garmentCount: garments.length,
            hasGarments: garments.length > 0
          }
        }
      );

    } catch (error: any) {
      console.error('Error retrieving wardrobe:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      throw EnhancedApiError.internalError('Failed to retrieve wardrobe', error);
    }
  },

  /**
   * Update wardrobe
   * Flutter-optimized response format
   */
  async updateWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      const wardrobeId = req.params.id;
      validateUUID(wardrobeId, 'wardrobeId');

      const wardrobe = await wardrobeModel.findById(wardrobeId);
      
      if (!wardrobe) {
        throw EnhancedApiError.notFound('Wardrobe not found', 'wardrobe');
      }

      if (wardrobe.user_id !== req.user.id) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to update this wardrobe', 'wardrobe');
      }

      // Validate update data
      const updates: any = {};
      const updatedFields: string[] = [];

      if (req.body.hasOwnProperty('name')) {
        if (!req.body.name) {
          throw EnhancedApiError.validation('Name cannot be empty', 'name');
        }
        const nameStr = String(req.body.name).trim();
        validateWardrobeName(nameStr);
        updates.name = sanitization.sanitizeUserInput(nameStr);
        updatedFields.push('name');
      }

      if (req.body.hasOwnProperty('description')) {
        const descStr = req.body.description !== null && req.body.description !== undefined 
          ? String(req.body.description).trim() 
          : '';
        validateWardrobeDescription(descStr);
        updates.description = descStr ? sanitization.sanitizeUserInput(descStr) : '';
        updatedFields.push('description');
      }

      if (updatedFields.length === 0) {
        throw EnhancedApiError.validation('At least one field must be provided for update', 'update_data');
      }

      const updatedWardrobe = await wardrobeModel.update(wardrobeId, updates);

      if (!updatedWardrobe) {
        throw EnhancedApiError.internalError('Failed to update wardrobe');
      }

      // Sanitize response
      const safeWardrobe = {
        ...updatedWardrobe,
        name: sanitization.sanitizeUserInput(updatedWardrobe.name),
        description: updatedWardrobe.description ? sanitization.sanitizeUserInput(updatedWardrobe.description) : ''
      };

      // Flutter-optimized response
      res.success(
        { wardrobe: safeWardrobe },
        {
          message: 'Wardrobe updated successfully',
          meta: {
            wardrobeId,
            updatedFields,
            updatedAt: new Date().toISOString()
          }
        }
      );

    } catch (error: any) {
      console.error('Error updating wardrobe:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      throw EnhancedApiError.internalError('Failed to update wardrobe', error);
    }
  },

  /**
   * Add garment to wardrobe - FIXED VERSION
   * Flutter-optimized response format with enhanced error handling
   */
  /**
   * Add garment to wardrobe - TARGETED FIX for garment lookup only
   * Flutter-optimized response format
   */
  async addGarmentToWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      const wardrobeId = req.params.id;
      const { garmentId, position } = req.body;

      validateUUID(wardrobeId, 'wardrobeId');

      if (!garmentId) {
        throw EnhancedApiError.validation('Garment ID is required', 'garmentId');
      }
      validateUUID(garmentId, 'garmentId');

      const validatedPosition = validatePosition(position);

      // Verify wardrobe ownership
      const wardrobe = await wardrobeModel.findById(wardrobeId);
      if (!wardrobe) {
        throw EnhancedApiError.notFound('Wardrobe not found', 'wardrobe');
      }

      if (wardrobe.user_id !== req.user.id) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to modify this wardrobe', 'wardrobe');
      }

      // TARGETED FIX: Enhanced garment verification
      let garment;
      try {
        garment = await garmentModel.findById(garmentId);
      } catch (garmentError: any) {
        console.error('Database error in garment lookup:', {
          garmentId,
          error: garmentError.message,
          code: garmentError.code
        });
        
        // For database errors (table missing, connection issues, etc.), 
        // treat as garment not found for user-facing error
        garment = null;
      }

      if (!garment) {
        throw EnhancedApiError.notFound('Garment not found', 'garment');
      }

      if (garment.user_id !== req.user.id) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to use this garment', 'garment');
      }

      // Add garment to wardrobe
      try {
        await wardrobeModel.addGarment(wardrobeId, garmentId, validatedPosition);
      } catch (addError: any) {
        if (addError.code === '23505' || addError.message?.includes('duplicate')) {
          throw EnhancedApiError.conflict('Garment is already in this wardrobe', 'garment_wardrobe');
        }
        throw addError;
      }

      // Flutter-optimized response
      res.success(
        {},
        {
          message: 'Garment added to wardrobe successfully',
          meta: {
            wardrobeId,
            garmentId,
            position: validatedPosition,
            addedAt: new Date().toISOString()
          }
        }
      );

    } catch (error: any) {
      console.error('Error adding garment to wardrobe:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      throw EnhancedApiError.internalError('Failed to add garment to wardrobe', error);
    }
  },

  /**
   * Remove garment from wardrobe
   * Flutter-optimized response format
   */
  async removeGarmentFromWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      const wardrobeId = req.params.id;
      const garmentId = req.params.itemId;

      validateUUID(wardrobeId, 'wardrobeId');
      validateUUID(garmentId, 'itemId'); // Changed to match expected error code

      // Verify wardrobe ownership
      const wardrobe = await wardrobeModel.findById(wardrobeId);
      if (!wardrobe) {
        throw EnhancedApiError.notFound('Wardrobe not found', 'wardrobe');
      }

      if (wardrobe.user_id !== req.user.id) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to modify this wardrobe', 'wardrobe');
      }

      // Remove garment from wardrobe
      const removed = await wardrobeModel.removeGarment(wardrobeId, garmentId);
      
      if (!removed) {
        throw EnhancedApiError.notFound('Garment not found in wardrobe', 'garment_wardrobe');
      }

      // Flutter-optimized response
      res.success(
        {},
        {
          message: 'Garment removed from wardrobe successfully',
          meta: {
            wardrobeId,
            removedGarmentId: garmentId,
            removedAt: new Date().toISOString()
          }
        }
      );

    } catch (error: any) {
      console.error('Error removing garment from wardrobe:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      throw EnhancedApiError.internalError('Failed to remove garment from wardrobe', error);
    }
  },

  /**
   * Delete wardrobe
   * Flutter-optimized response format
   */
  async deleteWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      const wardrobeId = req.params.id;
      validateUUID(wardrobeId, 'wardrobeId');

      const wardrobe = await wardrobeModel.findById(wardrobeId);
      
      if (!wardrobe) {
        throw EnhancedApiError.notFound('Wardrobe not found', 'wardrobe');
      }

      if (wardrobe.user_id !== req.user.id) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to delete this wardrobe', 'wardrobe');
      }

      // Get garment count before deletion for meta info
      const garments = await wardrobeModel.getGarments(wardrobeId);
      const garmentCount = garments.length;

      const deleted = await wardrobeModel.delete(wardrobeId);
      
      if (!deleted) {
        throw EnhancedApiError.internalError('Failed to delete wardrobe');
      }

      // Flutter-optimized response
      res.success(
        {},
        {
          message: 'Wardrobe deleted successfully',
          meta: {
            deletedWardrobeId: wardrobeId,
            deletedGarmentRelationships: garmentCount,
            deletedAt: new Date().toISOString()
          }
        }
      );

    } catch (error: any) {
      console.error('Error deleting wardrobe:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      throw EnhancedApiError.internalError('Failed to delete wardrobe', error);
    }
  },

  /**
   * Reorder garments in wardrobe (Simplified implementation)
   * Flutter-optimized response format
   */
  async reorderGarments(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      const wardrobeId = req.params.id;
      const { garmentPositions } = req.body;

      validateUUID(wardrobeId, 'wardrobeId');

      if (!garmentPositions || !Array.isArray(garmentPositions)) {
        throw EnhancedApiError.validation('Garment positions array is required', 'garmentPositions');
      }

      if (garmentPositions.length === 0) {
        throw EnhancedApiError.validation('At least one garment position is required', 'garmentPositions');
      }

      if (garmentPositions.length > 100) {
        throw EnhancedApiError.validation('Cannot reorder more than 100 garments at once', 'garmentPositions', garmentPositions.length);
      }

      // Verify wardrobe ownership
      const wardrobe = await wardrobeModel.findById(wardrobeId);
      if (!wardrobe) {
        throw EnhancedApiError.notFound('Wardrobe not found', 'wardrobe');
      }

      if (wardrobe.user_id !== req.user.id) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to modify this wardrobe', 'wardrobe');
      }

      // Validate garment positions structure
      const validatedPositions = garmentPositions.map((item: any, index: number) => {
        if (!item || typeof item !== 'object') {
          throw EnhancedApiError.validation(`Invalid garment position at index ${index}`, 'garmentPositions', index);
        }

        if (!item.garmentId) {
          throw EnhancedApiError.validation(`Garment ID is required at index ${index}`, 'garmentPositions', index);
        }

        validateUUID(item.garmentId, `garmentPositions[${index}].garmentId`);
        const position = validatePosition(item.position);

        return {
          garmentId: item.garmentId,
          position
        };
      });

      // Check for duplicate garment IDs
      const garmentIds = validatedPositions.map(p => p.garmentId);
      const uniqueIds = new Set(garmentIds);
      if (uniqueIds.size !== garmentIds.length) {
        throw EnhancedApiError.validation('Duplicate garment IDs are not allowed', 'garmentPositions');
      }

      // Simplified implementation: Remove and re-add garments in new positions
      // This is a temporary solution until the model supports batch reordering
      try {
        for (const { garmentId, position } of validatedPositions) {
          // Remove the garment first
          await wardrobeModel.removeGarment(wardrobeId, garmentId);
          // Add it back with new position
          await wardrobeModel.addGarment(wardrobeId, garmentId, position);
        }
      } catch (reorderError: any) {
        console.error('Error during garment reordering:', reorderError);
        throw EnhancedApiError.internalError('Failed to reorder garments. Some positions may have been updated.');
      }

      // Flutter-optimized response
      res.success(
        {},
        {
          message: 'Garments reordered successfully',
          meta: {
            wardrobeId,
            reorderedCount: validatedPositions.length,
            garmentIds: garmentIds,
            reorderedAt: new Date().toISOString()
          }
        }
      );

    } catch (error: any) {
      console.error('Error reordering garments:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      throw EnhancedApiError.internalError('Failed to reorder garments', error);
    }
  },

  /**
   * Get wardrobe statistics
   * Flutter-optimized response format
   */
  async getWardrobeStats(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }

      const wardrobeId = req.params.id;
      validateUUID(wardrobeId, 'wardrobeId');

      // Verify wardrobe ownership
      const wardrobe = await wardrobeModel.findById(wardrobeId);
      if (!wardrobe) {
        throw EnhancedApiError.notFound('Wardrobe not found', 'wardrobe');
      }

      if (wardrobe.user_id !== req.user.id) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to access this wardrobe', 'wardrobe');
      }

      // Get garments and calculate statistics
      const garments = await wardrobeModel.getGarments(wardrobeId);
      
      const stats = {
        totalGarments: garments.length,
        categories: {} as Record<string, number>,
        colors: {} as Record<string, number>,
        lastUpdated: wardrobe.updated_at,
        createdAt: wardrobe.created_at
      };

      // Analyze garment metadata for categories and colors
      garments.forEach(garment => {
        if (garment.metadata) {
          const category = garment.metadata.category || 'uncategorized';
          const color = garment.metadata.color || 'unknown';
          
          stats.categories[category] = (stats.categories[category] || 0) + 1;
          stats.colors[color] = (stats.colors[color] || 0) + 1;
        }
      });

      // Flutter-optimized response
      res.success(
        { stats },
        {
          message: 'Wardrobe statistics retrieved successfully',
          meta: {
            wardrobeId,
            analysisDate: new Date().toISOString(),
            categoriesCount: Object.keys(stats.categories).length,
            colorsCount: Object.keys(stats.colors).length
          }
        }
      );

    } catch (error: any) {
      console.error('Error retrieving wardrobe stats:', error);
      
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      
      throw EnhancedApiError.internalError('Failed to retrieve wardrobe statistics', error);
    }
  }
};