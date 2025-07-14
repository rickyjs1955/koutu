// /backend/src/services/wardrobeService.ts - Pure Business Logic for Wardrobe Management

import { wardrobeModel, CreateWardrobeInput, UpdateWardrobeInput } from '../models/wardrobeModel';
import { garmentModel } from '../models/garmentModel';
import { ApiError } from '../utils/ApiError';

interface CreateWardrobeParams {
  userId: string;
  name: string;
  description?: string;
}

interface UpdateWardrobeParams {
  wardrobeId: string;
  userId: string;
  name?: string;
  description?: string;
}

interface AddGarmentParams {
  wardrobeId: string;
  userId: string;
  garmentId: string;
  position?: number;
}

interface RemoveGarmentParams {
  wardrobeId: string;
  userId: string;
  garmentId: string;
}

interface WardrobeWithGarments {
  id: string;
  user_id: string;
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
  garments: any[];
  garmentCount: number;
}

// Mobile-specific interfaces
interface MobilePaginationParams {
  cursor?: string;
  limit?: number;
  direction?: 'forward' | 'backward';
}

interface MobileFilterOptions {
  search?: string;
  sortBy?: 'name' | 'created_at' | 'updated_at' | 'garment_count';
  sortOrder?: 'asc' | 'desc';
  hasGarments?: boolean;
  createdAfter?: string;
  updatedAfter?: string;
}

interface GetWardrobesParams {
  userId: string;
  pagination?: MobilePaginationParams;
  filters?: MobileFilterOptions;
  legacy?: {
    page: number;
    limit: number;
  };
}

interface SyncParams {
  userId: string;
  lastSyncTimestamp: Date;
  clientVersion?: number;
}

interface BatchOperation {
  type: 'create' | 'update' | 'delete';
  data: any;
  clientId: string;
}

interface BatchOperationsParams {
  userId: string;
  operations: BatchOperation[];
}

export const wardrobeService = {
  /**
   * Create a new wardrobe with validation
   */
  async createWardrobe(params: CreateWardrobeParams) {
    const { userId, name, description = '' } = params;

    // Business Rule 1: Validate wardrobe name
    this.validateWardrobeName(name);

    // Business Rule 2: Validate description if provided
    if (description) {
      this.validateWardrobeDescription(description);
    }

    // Business Rule 3: Check user wardrobe limits
    await this.checkUserWardrobeLimits(userId);

    // Business Rule 4: Check for duplicate names (optional business rule)
    await this.checkDuplicateWardrobeName(userId, name);

    try {
      const wardrobe = await wardrobeModel.create({
        user_id: userId,
        name: name.trim(),
        description: description.trim()
      });

      return wardrobe;
    } catch (error) {
      console.error('Error creating wardrobe:', error);
      throw ApiError.internal('Failed to create wardrobe');
    }
  },

  /**
   * Get all wardrobes for a user with mobile pagination and filtering support
   */
  async getUserWardrobes(params: GetWardrobesParams) {
    const { userId, pagination, filters, legacy } = params;
    
    try {
      // Get all wardrobes for the user
      let wardrobes = await wardrobeModel.findByUserId(userId);

      // Apply search filter
      if (filters?.search) {
        const searchLower = filters.search.toLowerCase();
        wardrobes = wardrobes.filter(w => 
          w.name.toLowerCase().includes(searchLower) ||
          (w.description && w.description.toLowerCase().includes(searchLower))
        );
      }

      // Apply date filters
      if (filters?.createdAfter) {
        const afterDate = new Date(filters.createdAfter);
        wardrobes = wardrobes.filter(w => new Date(w.created_at) > afterDate);
      }

      if (filters?.updatedAfter) {
        const afterDate = new Date(filters.updatedAfter);
        wardrobes = wardrobes.filter(w => new Date(w.updated_at) > afterDate);
      }

      // Enhance with garment counts
      const enhancedWardrobes = await Promise.all(
        wardrobes.map(async (wardrobe) => {
          const garments = await wardrobeModel.getGarments(wardrobe.id);
          return {
            ...wardrobe,
            garmentCount: garments.length
          };
        })
      );

      // Apply hasGarments filter
      let filteredWardrobes = enhancedWardrobes;
      if (filters?.hasGarments !== undefined) {
        filteredWardrobes = enhancedWardrobes.filter(w => 
          filters.hasGarments ? w.garmentCount > 0 : w.garmentCount === 0
        );
      }

      // Apply sorting
      const sortBy = filters?.sortBy || 'updated_at';
      const sortOrder = filters?.sortOrder || 'desc';
      
      filteredWardrobes.sort((a, b) => {
        let compareValue = 0;
        
        switch (sortBy) {
          case 'name':
            compareValue = a.name.localeCompare(b.name);
            break;
          case 'created_at':
            compareValue = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
            break;
          case 'updated_at':
            compareValue = new Date(a.updated_at).getTime() - new Date(b.updated_at).getTime();
            break;
          case 'garment_count':
            compareValue = a.garmentCount - b.garmentCount;
            break;
        }
        
        return sortOrder === 'asc' ? compareValue : -compareValue;
      });

      // Handle mobile cursor-based pagination
      if (pagination) {
        let startIndex = 0;
        if (pagination.cursor) {
          const cursorIndex = filteredWardrobes.findIndex(w => w.id === pagination.cursor);
          if (cursorIndex !== -1) {
            startIndex = pagination.direction === 'forward' 
              ? cursorIndex + 1 
              : Math.max(0, cursorIndex - (pagination.limit || 20));
          }
        }

        const limit = pagination.limit || 20;
        const endIndex = Math.min(startIndex + limit, filteredWardrobes.length);
        const paginatedWardrobes = filteredWardrobes.slice(startIndex, endIndex);

        return {
          wardrobes: paginatedWardrobes,
          pagination: {
            hasNext: endIndex < filteredWardrobes.length,
            hasPrev: startIndex > 0,
            nextCursor: endIndex < filteredWardrobes.length ? filteredWardrobes[endIndex - 1]?.id : undefined,
            prevCursor: startIndex > 0 ? filteredWardrobes[startIndex]?.id : undefined,
            count: paginatedWardrobes.length,
            totalFiltered: filteredWardrobes.length
          }
        };
      }

      // Handle legacy pagination
      if (legacy) {
        const startIndex = (legacy.page - 1) * legacy.limit;
        const endIndex = startIndex + legacy.limit;
        const paginatedWardrobes = filteredWardrobes.slice(startIndex, endIndex);

        return {
          wardrobes: paginatedWardrobes,
          total: filteredWardrobes.length,
          page: legacy.page,
          limit: legacy.limit
        };
      }

      // No pagination - return all
      return {
        wardrobes: filteredWardrobes,
        total: filteredWardrobes.length
      };
    } catch (error) {
      console.error('Error retrieving user wardrobes:', error);
      throw ApiError.internal('Failed to retrieve wardrobes');
    }
  },

  /**
   * Get a specific wardrobe with garments
   */
  async getWardrobeWithGarments(wardrobeId: string, userId: string): Promise<WardrobeWithGarments> {
    try {
      // Verify ownership and get wardrobe
      const wardrobe = await this.getWardrobe(wardrobeId, userId);

      // Get garments in the wardrobe
      const garments = await wardrobeModel.getGarments(wardrobeId);

      return {
        ...wardrobe,
        garments,
        garmentCount: garments.length
      };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error retrieving wardrobe with garments:', error);
      throw ApiError.internal('Failed to retrieve wardrobe');
    }
  },

  /**
   * Get wardrobe by ID with ownership verification
   */
  async getWardrobe(wardrobeId: string, userId: string) {
    try {
      const wardrobe = await wardrobeModel.findById(wardrobeId);

      if (!wardrobe) {
        throw ApiError.notFound('Wardrobe not found');
      }

      // Business Rule: Verify ownership
      if (wardrobe.user_id !== userId) {
        throw ApiError.authorization(
          'You do not have permission to access this wardrobe',
          'wardrobe',
          'read'
        );
      }

      return wardrobe;
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error retrieving wardrobe:', error);
      throw ApiError.internal('Failed to retrieve wardrobe');
    }
  },

  /**
   * Update wardrobe with validation
   */
  async updateWardrobe(params: UpdateWardrobeParams) {
    const { wardrobeId, userId, name, description } = params;

    // Verify ownership first
    await this.getWardrobe(wardrobeId, userId);

    // Validate updates if provided
    if (name !== undefined) {
      this.validateWardrobeName(name);
    }

    if (description !== undefined) {
      this.validateWardrobeDescription(description);
    }

    // Business Rule: Check for duplicate names if name is being changed
    if (name !== undefined) {
      await this.checkDuplicateWardrobeName(userId, name, wardrobeId);
    }

    try {
      const updateData: UpdateWardrobeInput = {};
      
      if (name !== undefined) {
        updateData.name = name.trim();
      }
      
      if (description !== undefined) {
        updateData.description = description.trim();
      }

      const updatedWardrobe = await wardrobeModel.update(wardrobeId, updateData);

      if (!updatedWardrobe) {
        throw ApiError.internal('Failed to update wardrobe');
      }

      return updatedWardrobe;
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error updating wardrobe:', error);
      throw ApiError.internal('Failed to update wardrobe');
    }
  },

  /**
   * Add garment to wardrobe with validation
   */
  async addGarmentToWardrobe(params: AddGarmentParams) {
    const { wardrobeId, userId, garmentId, position = 0 } = params;

    // Business Rule 1: Verify wardrobe ownership
    await this.getWardrobe(wardrobeId, userId);

    // Business Rule 2: Verify garment exists and ownership
    const garment = await garmentModel.findById(garmentId);
    if (!garment) {
      throw ApiError.notFound('Garment not found', 'GARMENT_NOT_FOUND');
    }

    if (garment.user_id !== userId) {
      throw ApiError.authorization(
        'You do not have permission to use this garment',
        'garment',
        'wardrobe_add'
      );
    }

    // Business Rule 3: Check wardrobe capacity limits
    await this.checkWardrobeCapacity(wardrobeId);

    // Business Rule 4: Check if garment is already in wardrobe
    const existingGarments = await wardrobeModel.getGarments(wardrobeId);
    const isAlreadyInWardrobe = existingGarments.some(g => g.id === garmentId);
    
    if (isAlreadyInWardrobe) {
      throw ApiError.businessLogic(
        'Garment is already in this wardrobe',
        'garment_already_in_wardrobe',
        'wardrobe'
      );
    }

    // Business Rule 5: Validate position
    this.validateGarmentPosition(position, existingGarments.length);

    try {
      await wardrobeModel.addGarment(wardrobeId, garmentId, position);
      return { success: true, message: 'Garment added to wardrobe successfully' };
    } catch (error) {
      console.error('Error adding garment to wardrobe:', error);
      throw ApiError.internal('Failed to add garment to wardrobe');
    }
  },

  /**
   * Remove garment from wardrobe
   */
  async removeGarmentFromWardrobe(params: RemoveGarmentParams) {
    const { wardrobeId, userId, garmentId } = params;

    // Verify wardrobe ownership
    await this.getWardrobe(wardrobeId, userId);

    // Business Rule: Verify garment is in the wardrobe
    const garments = await wardrobeModel.getGarments(wardrobeId);
    const garmentInWardrobe = garments.find(g => g.id === garmentId);
    
    if (!garmentInWardrobe) {
      throw ApiError.notFound(
        'Garment not found in wardrobe',
        'GARMENT_NOT_IN_WARDROBE'
      );
    }

    try {
      const removed = await wardrobeModel.removeGarment(wardrobeId, garmentId);
      
      if (!removed) {
        throw ApiError.internal('Failed to remove garment from wardrobe');
      }

      return { success: true, message: 'Garment removed from wardrobe successfully' };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error removing garment from wardrobe:', error);
      throw ApiError.internal('Failed to remove garment from wardrobe');
    }
  },

  /**
   * Delete wardrobe with dependency checking
   */
  async deleteWardrobe(wardrobeId: string, userId: string) {
    // Verify ownership
    await this.getWardrobe(wardrobeId, userId);

    // Business Rule: Check if wardrobe has garments
    const garments = await wardrobeModel.getGarments(wardrobeId);
    if (garments.length > 0) {
      throw ApiError.businessLogic(
        `Cannot delete wardrobe with ${garments.length} garment(s). Remove all garments first.`,
        'wardrobe_has_garments',
        'wardrobe'
      );
    }

    try {
      const deleted = await wardrobeModel.delete(wardrobeId);
      
      if (!deleted) {
        throw ApiError.internal('Failed to delete wardrobe');
      }

      return { success: true, wardrobeId };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error deleting wardrobe:', error);
      throw ApiError.internal('Failed to delete wardrobe');
    }
  },

  /**
   * Reorder garments in wardrobe
   */
  async reorderGarments(wardrobeId: string, userId: string, garmentOrder: string[]) {
    // Verify ownership
    await this.getWardrobe(wardrobeId, userId);

    // Get current garments
    const currentGarments = await wardrobeModel.getGarments(wardrobeId);
    
    // Business Rule: Validate all garments in order exist in wardrobe
    const currentGarmentIds = currentGarments.map(g => g.id);
    const invalidGarments = garmentOrder.filter(id => !currentGarmentIds.includes(id));
    
    if (invalidGarments.length > 0) {
      throw ApiError.validation(
        `Invalid garment IDs in order: ${invalidGarments.join(', ')}`,
        'garmentOrder',
        garmentOrder
      );
    }

    // Business Rule: Ensure all current garments are included
    if (garmentOrder.length !== currentGarments.length) {
      throw ApiError.validation(
        'Order must include all garments currently in wardrobe',
        'garmentOrder',
        garmentOrder
      );
    }

    try {
      // Update positions
      for (let i = 0; i < garmentOrder.length; i++) {
        await wardrobeModel.addGarment(wardrobeId, garmentOrder[i], i);
      }

      return { success: true, message: 'Garments reordered successfully' };
    } catch (error) {
      console.error('Error reordering garments:', error);
      throw ApiError.internal('Failed to reorder garments');
    }
  },

  /**
   * Get wardrobe statistics for a user
   */
  async getUserWardrobeStats(userId: string) {
    try {
      const wardrobes = await wardrobeModel.findByUserId(userId);
      
      let totalGarments = 0;
      const wardrobeGarmentCounts: Record<string, number> = {};
      
      for (const wardrobe of wardrobes) {
        const garments = await wardrobeModel.getGarments(wardrobe.id);
        const garmentCount = garments.length;
        totalGarments += garmentCount;
        wardrobeGarmentCounts[wardrobe.id] = garmentCount;
      }

      const stats = {
        totalWardrobes: wardrobes.length,
        totalGarments,
        averageGarmentsPerWardrobe: wardrobes.length > 0 ? Math.round(totalGarments / wardrobes.length) : 0,
        wardrobeGarmentCounts,
        limits: {
          maxWardrobes: 50,
          maxGarmentsPerWardrobe: 200,
          maxNameLength: 100,
          maxDescriptionLength: 1000
        }
      };

      return stats;
    } catch (error) {
      console.error('Error getting user wardrobe stats:', error);
      throw ApiError.internal('Failed to retrieve wardrobe statistics');
    }
  },

  /**
   * Search wardrobes by name or description
   */
  async searchWardrobes(userId: string, searchTerm: string) {
    try {
      const wardrobes = await wardrobeModel.findByUserId(userId);
      
      // Filter wardrobes based on search term
      const filteredWardrobes = wardrobes.filter(wardrobe => 
        wardrobe.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (wardrobe.description && wardrobe.description.toLowerCase().includes(searchTerm.toLowerCase()))
      );

      // Enhance with garment counts
      const enhancedWardrobes = await Promise.all(
        filteredWardrobes.map(async (wardrobe) => {
          const garments = await wardrobeModel.getGarments(wardrobe.id);
          return {
            ...wardrobe,
            garmentCount: garments.length
          };
        })
      );

      return enhancedWardrobes;
    } catch (error) {
      console.error('Error searching wardrobes:', error);
      throw ApiError.internal('Failed to search wardrobes');
    }
  },

  // Validation helper methods

  /**
   * Validate wardrobe name
   */
  validateWardrobeName(name: string): void {
    if (!name || typeof name !== 'string') {
      throw ApiError.validation(
        'Wardrobe name is required',
        'name',
        name
      );
    }

    const trimmedName = name.trim();
    
    if (trimmedName.length === 0) {
      throw ApiError.validation(
        'Wardrobe name cannot be empty',
        'name',
        name
      );
    }

    if (trimmedName.length > 100) {
      throw ApiError.validation(
        'Wardrobe name cannot exceed 100 characters',
        'name',
        name
      );
    }

    // Business Rule: No special characters in wardrobe names
    const nameRegex = /^[a-zA-Z0-9\s\-_\.]+$/;
    if (!nameRegex.test(trimmedName)) {
      throw ApiError.validation(
        'Wardrobe name can only contain letters, numbers, spaces, hyphens, underscores, and periods',
        'name',
        name
      );
    }
  },

  /**
   * Validate wardrobe description
   */
  validateWardrobeDescription(description: string): void {
    if (typeof description !== 'string') {
      throw ApiError.validation(
        'Description must be a string',
        'description',
        description
      );
    }

    if (description.length > 1000) {
      throw ApiError.validation(
        'Description cannot exceed 1000 characters',
        'description',
        description
      );
    }
  },

  /**
   * Validate garment position in wardrobe
   */
  validateGarmentPosition(position: number, currentGarmentCount: number): void {
    if (typeof position !== 'number' || position < 0) {
      throw ApiError.validation(
        'Position must be a non-negative number',
        'position',
        position
      );
    }

    if (position > currentGarmentCount) {
      throw ApiError.validation(
        `Position cannot be greater than current garment count (${currentGarmentCount})`,
        'position',
        position
      );
    }
  },

  /**
   * Check user wardrobe limits
   */
  async checkUserWardrobeLimits(userId: string): Promise<void> {
    try {
      const wardrobes = await wardrobeModel.findByUserId(userId);
      
      // Business Rule: Maximum wardrobes per user
      const maxWardrobesPerUser = 50;
      if (wardrobes.length >= maxWardrobesPerUser) {
        throw ApiError.businessLogic(
          `Wardrobe limit reached. Maximum ${maxWardrobesPerUser} wardrobes allowed per user.`,
          'max_wardrobes_per_user',
          'wardrobe'
        );
      }
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error checking user wardrobe limits:', error);
      // Don't fail creation for limit check errors, just log
    }
  },

  /**
   * Check for duplicate wardrobe names
   */
  async checkDuplicateWardrobeName(
    userId: string, 
    name: string, 
    excludeWardrobeId?: string
  ): Promise<void> {
    try {
      const wardrobes = await wardrobeModel.findByUserId(userId);
      const trimmedName = name.trim().toLowerCase();
      
      const duplicate = wardrobes.find(wardrobe => 
        wardrobe.name.toLowerCase() === trimmedName &&
        wardrobe.id !== excludeWardrobeId
      );
      
      if (duplicate) {
        throw ApiError.businessLogic(
          'A wardrobe with this name already exists',
          'duplicate_wardrobe_name',
          'wardrobe'
        );
      }
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error checking duplicate wardrobe name:', error);
      // Don't fail for duplicate check errors, just log
    }
  },

  /**
   * Check wardrobe capacity limits
   */
  async checkWardrobeCapacity(wardrobeId: string): Promise<void> {
    try {
      const garments = await wardrobeModel.getGarments(wardrobeId);
      
      // Business Rule: Maximum garments per wardrobe
      const maxGarmentsPerWardrobe = 200;
      if (garments.length >= maxGarmentsPerWardrobe) {
        throw ApiError.businessLogic(
          `Wardrobe is full. Maximum ${maxGarmentsPerWardrobe} garments allowed per wardrobe.`,
          'wardrobe_capacity_exceeded',
          'wardrobe'
        );
      }
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      console.error('Error checking wardrobe capacity:', error);
      throw ApiError.internal('Failed to check wardrobe capacity');
    }
  },

  /**
   * Sync wardrobes - get changes since last sync
   */
  async syncWardrobes(params: SyncParams) {
    const { userId, lastSyncTimestamp, clientVersion = 1 } = params;

    try {
      // Get all wardrobes for the user
      const allWardrobes = await wardrobeModel.findByUserId(userId);

      // Separate into created, updated, and deleted
      const created = allWardrobes.filter(w => new Date(w.created_at) > lastSyncTimestamp);
      const updated = allWardrobes.filter(w => 
        new Date(w.updated_at) > lastSyncTimestamp && 
        new Date(w.created_at) <= lastSyncTimestamp
      );

      // For deleted items, we'd need to track deletions in the database
      // This is a simplified version - in production, use a deletion log
      const deleted: string[] = [];

      // Enhance with garment counts
      const enhancedCreated = await Promise.all(
        created.map(async (wardrobe) => {
          const garments = await wardrobeModel.getGarments(wardrobe.id);
          return {
            ...wardrobe,
            garmentCount: garments.length
          };
        })
      );

      const enhancedUpdated = await Promise.all(
        updated.map(async (wardrobe) => {
          const garments = await wardrobeModel.getGarments(wardrobe.id);
          return {
            ...wardrobe,
            garmentCount: garments.length
          };
        })
      );

      return {
        wardrobes: {
          created: enhancedCreated,
          updated: enhancedUpdated,
          deleted
        },
        sync: {
          timestamp: new Date().toISOString(),
          version: clientVersion,
          hasMore: false,
          changeCount: created.length + updated.length + deleted.length
        }
      };
    } catch (error) {
      console.error('Error syncing wardrobes:', error);
      throw ApiError.internal('Failed to sync wardrobes');
    }
  },

  /**
   * Batch operations for offline sync
   */
  async batchOperations(params: BatchOperationsParams) {
    const { userId, operations } = params;

    // Validate operations
    if (!operations || !Array.isArray(operations) || operations.length === 0) {
      throw ApiError.validation('Operations array is required and must not be empty', 'operations', operations);
    }

    if (operations.length > 50) {
      throw ApiError.validation('Cannot process more than 50 operations at once', 'operations', operations.length);
    }

    const results = [];
    const errors = [];

    // Process each operation
    for (const [index, operation] of operations.entries()) {
      try {
        const { type, data, clientId } = operation;

        let result;
        switch (type) {
          case 'create':
            if (!data.name) {
              throw ApiError.validation('Name is required for create operation', 'name', null);
            }

            result = await this.createWardrobe({
              userId,
              name: data.name,
              description: data.description
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
              throw ApiError.validation('Wardrobe ID is required for update operation', 'id', null);
            }

            result = await this.updateWardrobe({
              wardrobeId: data.id,
              userId,
              name: data.name,
              description: data.description
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
              throw ApiError.validation('Wardrobe ID is required for delete operation', 'id', null);
            }

            await this.deleteWardrobe(data.id, userId);

            results.push({
              clientId,
              serverId: data.id,
              type: 'delete',
              success: true
            });
            break;

          default:
            throw ApiError.validation(`Unknown operation type: ${type}`, 'type', type);
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

    return {
      results,
      errors,
      summary: {
        total: operations.length,
        successful: results.length,
        failed: errors.length
      }
    };
  }
};