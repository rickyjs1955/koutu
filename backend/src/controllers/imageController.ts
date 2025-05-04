// /backend/src/controllers/imageController.ts
import { Request, Response, NextFunction } from 'express';
import multer from 'multer';
import path from 'path';
import { ApiError } from '../utils/ApiError';
import { config } from '../config';
import { imageModel } from '../models/imageModel';
import { storageService } from '../services/storageService';
import { imageProcessingService } from '../services/imageProcessingService';

// Configure multer for memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.maxFileSize // 5MB default
  },
  fileFilter: (req, file, cb) => {
    // Accept only image files
    const filetypes = /jpeg|jpg|png|webp/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    
    cb(new Error('File upload only supports image files'));
  }
}).single('image'); // 'image' is the field name in the form

export const imageController = {
  // Middleware to handle file upload
  uploadMiddleware(req: Request, res: Response, next: NextFunction) {
    upload(req, res, (err) => {
      if (err instanceof multer.MulterError) {
        // A Multer error occurred
        if (err.code === 'LIMIT_FILE_SIZE') {
          return next(ApiError.badRequest(`File too large, max size is ${config.maxFileSize / (1024 * 1024)}MB`));
        }
        return next(ApiError.badRequest(err.message));
      } else if (err) {
        // An unknown error occurred
        return next(ApiError.badRequest(err.message));
      }
      
      // No error, continue
      next();
    });
  },
  
  async uploadImage(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.file) {
        return next(ApiError.badRequest('No image file uploaded'));
      }
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Save the file
      const filePath = await storageService.saveFile(req.file.buffer, req.file.originalname);
      
      // Extract metadata
      const metadata = await imageProcessingService.extractMetadata(filePath);
      
      // Save to database
      const image = await imageModel.create({
        user_id: req.user.id,
        file_path: filePath,
        original_metadata: {
          filename: req.file.originalname,
          mimetype: req.file.mimetype,
          size: req.file.size,
          width: metadata.width,
          height: metadata.height,
          format: metadata.format
        }
      });
      
      res.status(201).json({
        status: 'success',
        data: {
          image
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async getImages(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get all images for the user
      const images = await imageModel.findByUserId(req.user.id);
      
      res.status(200).json({
        status: 'success',
        data: {
          images
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async getImage(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get the image
      const image = await imageModel.findById(id);
      
      if (!image) {
        return next(ApiError.notFound('Image not found'));
      }
      
      // Check if the image belongs to the user
      if (image.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to access this image'));
      }
      
      res.status(200).json({
        status: 'success',
        data: {
          image
        }
      });
    } catch (error) {
      next(error);
    }
  },
  
  async deleteImage(req: Request, res: Response, next: NextFunction) {
    try {
      const { id } = req.params;
      
      if (!req.user) {
        return next(ApiError.unauthorized('User not authenticated'));
      }
      
      // Get the image
      const image = await imageModel.findById(id);
      
      if (!image) {
        return next(ApiError.notFound('Image not found'));
      }
      
      // Check if the image belongs to the user
      if (image.user_id !== req.user.id) {
        return next(ApiError.forbidden('You do not have permission to delete this image'));
      }
      
      // Delete the file
      await storageService.deleteFile(image.file_path);
      
      // Delete from database
      await imageModel.delete(id);
      
      res.status(200).json({
        status: 'success',
        data: null
      });
    } catch (error) {
      next(error);
    }
  }
};