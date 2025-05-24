// /backend/src/controllers/wardrobeController.ts
import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';
import { wardrobeModel } from '../models/wardrobeModel';
import { garmentModel } from '../models/garmentModel';

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const wardrobeController = {
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
      
      if (name.trim().length > 100) {
        return next(ApiError.badRequest('Wardrobe name cannot exceed 100 characters', 'NAME_TOO_LONG'));
      }
      
      // Optional description validation
      if (description && typeof description !== 'string') {
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
        
        if (name.trim().length > 100) {
          return next(ApiError.badRequest('Name cannot exceed 100 characters', 'NAME_TOO_LONG'));
        }
      }
      
      if (description !== undefined && typeof description !== 'string') {
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
      
      await wardrobeModel.addGarment(id, garmentId, position || 0);
      
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