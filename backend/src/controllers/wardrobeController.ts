// src/controllers/wardrobeController.ts
import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';
import { wardrobeModel } from '../models/wardrobeModel';
import { garmentModel } from '../models/garmentModel';

export const wardrobeController = {
  async createWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { name, description } = req.body;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      if (!name) {
        return next(ApiError.badRequest('Wardrobe name is required'));
      }
      
      // Create the wardrobe
      const wardrobe = await wardrobeModel.create({
        user_id: req.user.id,
        name,
        description: description || ''
      });
      
      res.status(201).json({
        status: 'success',
        data: {
          wardrobe
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async getWardrobes(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get all wardrobes for the user
      const wardrobes = await wardrobeModel.findByUserId(req.user.id);
      
      res.status(200).json({
        status: 'success',
        data: {
          wardrobes
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async getWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get the wardrobe
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      // Check if the wardrobe belongs to the user
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to access this wardrobe'));
      }
      
      // Get all garments in the wardrobe
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
      next(error);
    }
  },
  
  async updateWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { name, description } = req.body;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get the wardrobe
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      // Check if the wardrobe belongs to the user
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to update this wardrobe'));
      }
      
      // Update the wardrobe
      const updatedWardrobe = await wardrobeModel.update(id, {
        name,
        description
      });
      
      res.status(200).json({
        status: 'success',
        data: {
          wardrobe: updatedWardrobe
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async addGarmentToWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      const { garmentId, position } = req.body;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      if (!garmentId) {
        return next(ApiError.badRequest('Garment ID is required'));
      }
      
      // Get the wardrobe
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      // Check if the wardrobe belongs to the user
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to modify this wardrobe'));
      }
      
      // Check if the garment exists and belongs to the user
      const garment = await garmentModel.findById(garmentId);
      
      if (!garment) {
        return next(ApiError.notFound('Garment not found'));
      }
      
      if (garment.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to use this garment'));
      }
      
      // Add the garment to the wardrobe
      await wardrobeModel.addGarment(id, garmentId, position || 0);
      
      res.status(200).json({
        status: 'success',
        data: null
      });
    } catch (error) {
      next(error);
    }
  },
  
  async removeGarmentFromWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id, itemId } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get the wardrobe
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      // Check if the wardrobe belongs to the user
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to modify this wardrobe'));
      }
      
      // Remove the garment from the wardrobe
      await wardrobeModel.removeGarment(id, itemId);
      
      res.status(200).json({
        status: 'success',
        data: null
      });
    } catch (error) {
      next(error);
    }
  },
  
  async deleteWardrobe(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get the wardrobe
      const wardrobe = await wardrobeModel.findById(id);
      
      if (!wardrobe) {
        return next(ApiError.notFound('Wardrobe not found'));
      }
      
      // Check if the wardrobe belongs to the user
      if (wardrobe.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to delete this wardrobe'));
      }
      
      // Delete the wardrobe
      await wardrobeModel.delete(id);
      
      res.status(200).json({
        status: 'success',
        data: null
      });
    } catch (error) {
      next(error);
    }
  }
};