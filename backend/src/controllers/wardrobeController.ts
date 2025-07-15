// /backend/src/controllers/wardrobeController.ts - Fixed Flutter-compatible version

import { Request, Response, NextFunction } from 'express';
import { EnhancedApiError } from '../middlewares/errorHandler';
import { ApiError } from '../utils/ApiError';
import { wardrobeService } from '../services/wardrobeService';
import { sanitization } from '../utils/sanitize';
import { ResponseUtils } from '../utils/responseWrapper';

/**
 * Check if an error is an ApiError (handles various edge cases)
 */
const isApiError = (error: any): boolean => {
  // Direct instanceof check
  if (error instanceof ApiError) return true;
  
  // Check by name property
  if (error?.name === 'ApiError') return true;
  
  // Check by constructor name (handles module boundary issues)
  if (error?.constructor?.name === 'ApiError') return true;
  
  // Duck typing - if it looks like an ApiError
  if (error && 
      typeof error.statusCode === 'number' && 
      typeof error.message === 'string' &&
      typeof error.code === 'string') {
    return true;
  }
  
  return false;
};

/**
 * Map ApiError from service layer to EnhancedApiError for Flutter compatibility
 */
const mapApiErrorToEnhanced = (error: any): EnhancedApiError => {
// Create the appropriate EnhancedApiError based on status code
let enhancedError: EnhancedApiError;

// Ensure we have a valid status code
const statusCode = error.statusCode || 500;

switch (statusCode) {
  case 400:
    enhancedError = EnhancedApiError.validation(error.message);
    break;
  case 401:
    enhancedError = EnhancedApiError.authenticationRequired(error.message);
    break;
  case 403:
    enhancedError = EnhancedApiError.authorizationDenied(error.message);
    break;
  case 404:
    enhancedError = EnhancedApiError.notFound(error.message);
    break;
  case 409:
    enhancedError = EnhancedApiError.conflict(error.message);
    break;
  default:
    // For other status codes, create a generic error with the original status
    enhancedError = new EnhancedApiError(error.message, statusCode, error.code || 'API_ERROR');
}

// Manually set the cause to preserve the original ApiError for the test handler
enhancedError.cause = error;

return enhancedError;
};

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

/**
 * Mobile-optimized pagination with cursor-based scrolling
 */
interface MobilePaginationParams {
cursor?: string;
limit?: number;
direction?: 'forward' | 'backward';
}

/**
 * Mobile filtering options
 */
interface MobileFilterOptions {
search?: string;
sortBy?: 'name' | 'created_at' | 'updated_at' | 'garment_count';
sortOrder?: 'asc' | 'desc';
hasGarments?: boolean;
createdAfter?: string;
updatedAfter?: string;
}

/**
 * Parse and validate mobile pagination parameters
 */
const parseMobilePagination = (query: any): MobilePaginationParams => {
const params: MobilePaginationParams = {
  cursor: query.cursor || undefined,
  limit: Math.min(parseInt(query.limit) || 20, 50), // Default 20, max 50 for mobile
  direction: query.direction === 'backward' ? 'backward' : 'forward'
};

return params;
};

/**
 * Parse and validate mobile filter options
 */
const parseMobileFilters = (query: any): MobileFilterOptions => {
const filters: MobileFilterOptions = {};

if (query.search) {
  filters.search = String(query.search).trim().slice(0, 100); // Limit search length
}

if (query.sortBy && ['name', 'created_at', 'updated_at', 'garment_count'].includes(query.sortBy)) {
  filters.sortBy = query.sortBy;
}

if (query.sortOrder && ['asc', 'desc'].includes(query.sortOrder)) {
  filters.sortOrder = query.sortOrder;
}

if (query.hasGarments !== undefined) {
  filters.hasGarments = query.hasGarments === 'true';
}

if (query.createdAfter) {
  filters.createdAfter = query.createdAfter;
}

if (query.updatedAfter) {
  filters.updatedAfter = query.updatedAfter;
}

return filters;
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

    const wardrobe = await wardrobeService.createWardrobe({
      userId: req.user.id,
      name: sanitization.sanitizeUserInput(name),
      description: description ? sanitization.sanitizeUserInput(description) : ''
    });

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
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
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
 * Supports both legacy pagination and mobile cursor-based pagination
 */
async getWardrobes(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.user) {
      throw EnhancedApiError.authenticationRequired('User authentication required');
    }

    // Check if mobile pagination is requested
    const isMobilePagination = req.query.cursor !== undefined || req.query.direction !== undefined;
    
    if (isMobilePagination) {
      // Mobile cursor-based pagination with filtering
      const mobilePagination = parseMobilePagination(req.query);
      const filters = parseMobileFilters(req.query);
      
      const result = await wardrobeService.getUserWardrobes({
        userId: req.user.id,
        pagination: mobilePagination,
        filters: filters
      });

      // Sanitize response data
      const safeWardrobes = result.wardrobes.map(wardrobe => ({
        id: wardrobe.id,
        name: sanitization.sanitizeUserInput(wardrobe.name),
        description: wardrobe.description ? sanitization.sanitizeUserInput(wardrobe.description) : '',
        garmentCount: wardrobe.garmentCount,
        created_at: wardrobe.created_at,
        updated_at: wardrobe.updated_at
      }));

      // Mobile-optimized response
      res.success({
        wardrobes: safeWardrobes,
        pagination: result.pagination,
        sync: {
          lastSyncTimestamp: new Date().toISOString(),
          version: 1,
          hasMore: result.pagination?.hasNext || false,
          nextCursor: result.pagination?.nextCursor
        }
      }, {
        message: 'Wardrobes retrieved successfully',
        meta: {
          filters: filters,
          mode: 'mobile'
        }
      });
      
    } else {
      // Legacy pagination support
      let legacyPagination: { page: number; limit: number } | undefined;
      
      if (req.query.page !== undefined || req.query.limit !== undefined) {
        const validatedPagination = ResponseUtils.validatePagination(req.query.page, req.query.limit);
        
        // Wardrobe-specific limit validation
        if (validatedPagination.limit > 50) {
          throw EnhancedApiError.validation('Limit cannot exceed 50 wardrobes per page', 'limit', validatedPagination.limit);
        }
        
        legacyPagination = validatedPagination;
      }

      const result = await wardrobeService.getUserWardrobes({
        userId: req.user.id,
        legacy: legacyPagination
      });

      // Sanitize response data
      const safeWardrobes = result.wardrobes.map(wardrobe => ({
        ...wardrobe,
        name: sanitization.sanitizeUserInput(wardrobe.name),
        description: wardrobe.description ? sanitization.sanitizeUserInput(wardrobe.description) : ''
      }));

      // Flutter-optimized response - Fixed to return array directly
      if (legacyPagination) {
        const paginationMeta = ResponseUtils.createPagination(
          legacyPagination.page,
          legacyPagination.limit,
          result.total || 0
        );
        
        res.successWithPagination(safeWardrobes, paginationMeta, {
          message: 'Wardrobes retrieved successfully',
          meta: {
            userId: req.user.id,
            count: safeWardrobes.length,
            mode: 'legacy'
          }
        });
      } else {
        res.success(safeWardrobes, {
          message: 'Wardrobes retrieved successfully',
          meta: {
            count: safeWardrobes.length,
            userId: req.user.id,
            mode: 'legacy'
          }
        });
      }
    }

  } catch (error: any) {
    console.error('Error retrieving wardrobes:', error);
    
    if (error instanceof EnhancedApiError) {
      throw error;
    }
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
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

    const wardrobeWithGarments = await wardrobeService.getWardrobeWithGarments(wardrobeId, req.user.id);

    // Sanitize response data
    const safeWardrobe = {
      ...wardrobeWithGarments,
      name: sanitization.sanitizeUserInput(wardrobeWithGarments.name),
      description: wardrobeWithGarments.description ? sanitization.sanitizeUserInput(wardrobeWithGarments.description) : '',
      garments: wardrobeWithGarments.garments.map(garment => ({
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
          garmentCount: wardrobeWithGarments.garmentCount,
          hasGarments: wardrobeWithGarments.garmentCount > 0
        }
      }
    );

  } catch (error: any) {
    console.error('Error retrieving wardrobe:', error);
    
    if (error instanceof EnhancedApiError) {
      throw error;
    }
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
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

    // Validate update data
    const updatedFields: string[] = [];
    let name: string | undefined;
    let description: string | undefined;

    if (req.body.hasOwnProperty('name')) {
      if (!req.body.name) {
        throw EnhancedApiError.validation('Name cannot be empty', 'name');
      }
      const nameStr = String(req.body.name).trim();
      validateWardrobeName(nameStr);
      name = sanitization.sanitizeUserInput(nameStr);
      updatedFields.push('name');
    }

    if (req.body.hasOwnProperty('description')) {
      const descStr = req.body.description !== null && req.body.description !== undefined 
        ? String(req.body.description).trim() 
        : '';
      validateWardrobeDescription(descStr);
      description = descStr ? sanitization.sanitizeUserInput(descStr) : '';
      updatedFields.push('description');
    }

    if (updatedFields.length === 0) {
      throw EnhancedApiError.validation('At least one field must be provided for update', 'update_data');
    }

    const updatedWardrobe = await wardrobeService.updateWardrobe({
      wardrobeId,
      userId: req.user.id,
      name,
      description
    });

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
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
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

    // Use service to add garment to wardrobe (handles all validation)
    await wardrobeService.addGarmentToWardrobe({
      wardrobeId,
      userId: req.user.id,
      garmentId,
      position: validatedPosition
    });

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
    if (error instanceof EnhancedApiError) {
      throw error;
    }
    
    // Check if it's an ApiError using our comprehensive check
    if (isApiError(error)) {
      throw mapApiErrorToEnhanced(error);
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

    // Use service to remove garment from wardrobe
    await wardrobeService.removeGarmentFromWardrobe({
      wardrobeId,
      userId: req.user.id,
      garmentId
    });

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
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
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

    // Use service to delete wardrobe
    const result = await wardrobeService.deleteWardrobe(wardrobeId, req.user.id);
    const garmentCount = 0; // Service handles business logic, garments should be removed first

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
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
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

    // Validate garment positions structure and extract IDs
    const garmentIds: string[] = [];
    garmentPositions.forEach((item: any, index: number) => {
      if (!item || typeof item !== 'object') {
        throw EnhancedApiError.validation(`Invalid garment position at index ${index}`, 'garmentPositions', index);
      }

      if (!item.garmentId) {
        throw EnhancedApiError.validation(`Garment ID is required at index ${index}`, 'garmentPositions', index);
      }

      validateUUID(item.garmentId, `garmentPositions[${index}].garmentId`);
      garmentIds.push(item.garmentId);
    });

    // Check for duplicate garment IDs
    const uniqueIds = new Set(garmentIds);
    if (uniqueIds.size !== garmentIds.length) {
      throw EnhancedApiError.validation('Duplicate garment IDs are not allowed', 'garmentPositions');
    }

    // Use service to reorder garments
    await wardrobeService.reorderGarments(wardrobeId, req.user.id, garmentIds);

    // Flutter-optimized response
    res.success(
      {},
      {
        message: 'Garments reordered successfully',
        meta: {
          wardrobeId,
          reorderedCount: garmentIds.length,
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
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
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

    // Get wardrobe with garments through service
    const wardrobeWithGarments = await wardrobeService.getWardrobeWithGarments(wardrobeId, req.user.id);
    
    const stats = {
      totalGarments: wardrobeWithGarments.garmentCount,
      categories: {} as Record<string, number>,
      colors: {} as Record<string, number>,
      lastUpdated: wardrobeWithGarments.updated_at,
      createdAt: wardrobeWithGarments.created_at
    };

    // Analyze garment metadata for categories and colors
    wardrobeWithGarments.garments.forEach(garment => {
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
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
    }
    
    throw EnhancedApiError.internalError('Failed to retrieve wardrobe statistics', error);
  }
},

/**
 * Sync wardrobes - get changes since last sync
 * For offline sync support
 */
async syncWardrobes(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.user) {
      throw EnhancedApiError.authenticationRequired('User authentication required');
    }

    const { lastSyncTimestamp, clientVersion = 1 } = req.body;
    
    if (!lastSyncTimestamp) {
      throw EnhancedApiError.validation('Last sync timestamp is required', 'lastSyncTimestamp');
    }

    const syncDate = new Date(lastSyncTimestamp);
    if (isNaN(syncDate.getTime())) {
      throw EnhancedApiError.validation('Invalid sync timestamp format', 'lastSyncTimestamp');
    }

    const syncResult = await wardrobeService.syncWardrobes({
      userId: req.user.id,
      lastSyncTimestamp: syncDate,
      clientVersion
    });

    // Sanitize the response
    const sanitizedResult = {
      wardrobes: {
        created: syncResult.wardrobes.created.map(w => ({
          ...w,
          name: sanitization.sanitizeUserInput(w.name),
          description: w.description ? sanitization.sanitizeUserInput(w.description) : ''
        })),
        updated: syncResult.wardrobes.updated.map(w => ({
          ...w,
          name: sanitization.sanitizeUserInput(w.name),
          description: w.description ? sanitization.sanitizeUserInput(w.description) : ''
        })),
        deleted: syncResult.wardrobes.deleted
      },
      sync: syncResult.sync
    };

    res.success(sanitizedResult, {
      message: 'Sync completed successfully',
      meta: {
        created: syncResult.wardrobes.created.length,
        updated: syncResult.wardrobes.updated.length,
        deleted: syncResult.wardrobes.deleted.length
      }
    });

  } catch (error: any) {
    console.error('Error syncing wardrobes:', error);
    
    if (error instanceof EnhancedApiError) {
      throw error;
    }
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
    }
    
    throw EnhancedApiError.internalError('Failed to sync wardrobes', error);
  }
},

/**
 * Batch operations for offline sync
 * Allows multiple create/update/delete operations in single request
 */
async batchOperations(req: Request, res: Response, next: NextFunction) {
  try {
    if (!req.user) {
      throw EnhancedApiError.authenticationRequired('User authentication required');
    }

    const { operations } = req.body;

    if (!operations || !Array.isArray(operations)) {
      throw EnhancedApiError.validation('Operations array is required', 'operations');
    }

    if (operations.length === 0) {
      throw EnhancedApiError.validation('At least one operation is required', 'operations');
    }

    if (operations.length > 50) {
      throw EnhancedApiError.validation('Cannot process more than 50 operations at once', 'operations');
    }

    const results = [];
    const errors = [];

    // Process each operation
    for (const [index, operation] of operations.entries()) {
      try {
        const { type, data, clientId } = operation;

        // Validate and prepare operation data
        const preparedOperation = {
          type,
          data: { ...data },
          clientId
        };

        // Input validation for controller level
        if (type === 'create' || type === 'update') {
          if (data.name !== undefined) {
            const { name } = validateAndSanitizeWardrobeInput(data.name, data.description || '');
            validateWardrobeName(name);
            preparedOperation.data.name = sanitization.sanitizeUserInput(name);
          }
          if (data.description !== undefined) {
            validateWardrobeDescription(data.description);
            preparedOperation.data.description = sanitization.sanitizeUserInput(data.description);
          }
        }

        // Batch operations are already implemented in the service
        // We'll process them here for now until service is updated
        let result;
        switch (type) {
          case 'create':
            result = await wardrobeService.createWardrobe({
              userId: req.user.id,
              name: preparedOperation.data.name,
              description: preparedOperation.data.description
            });
            results.push({
              clientId,
              serverId: result.id,
              type: 'create',
              success: true,
              data: result
            });
            break;

          case 'update':
            if (!data.id) {
              throw EnhancedApiError.validation('Wardrobe ID is required for update', 'id');
            }

            result = await wardrobeService.updateWardrobe({
              wardrobeId: data.id,
              userId: req.user.id,
              name: preparedOperation.data.name,
              description: preparedOperation.data.description
            });
            results.push({
              clientId,
              serverId: data.id,
              type: 'update',
              success: true,
              data: result
            });
            break;

          case 'delete':
            if (!data.id) {
              throw EnhancedApiError.validation('Wardrobe ID is required for delete', 'id');
            }

            await wardrobeService.deleteWardrobe(data.id, req.user.id);
            results.push({
              clientId,
              serverId: data.id,
              type: 'delete',
              success: true
            });
            break;

          default:
            throw EnhancedApiError.validation(`Unknown operation type: ${type}`, 'type');
        }
      } catch (error: any) {
        errors.push({
          clientId: operation.clientId,
          type: operation.type,
          error: error.message || 'Unknown error',
          code: error.code || 'UNKNOWN_ERROR'
        });
      }
    }

    res.success({
      results,
      errors,
      summary: {
        total: operations.length,
        successful: results.length,
        failed: errors.length
      }
    }, {
      message: 'Batch operations completed',
      meta: {
        timestamp: new Date().toISOString()
      }
    });

  } catch (error: any) {
    console.error('Error processing batch operations:', error);
    
    if (error instanceof EnhancedApiError) {
      throw error;
    }
    
    // Handle ApiError from service layer (React Native era)
    // Check if error looks like ApiError (has statusCode, code, and message)
    if (error && typeof error.statusCode === 'number' && error.message) {
      // This is likely an ApiError from the service layer
      throw mapApiErrorToEnhanced(error);
    }
    
    throw EnhancedApiError.internalError('Failed to process batch operations', error);
  }
}
};