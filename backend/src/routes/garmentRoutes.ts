// /backend/src/routes/garmentRoutes.ts

import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import { garmentController } from '../controllers/garmentController';
import { authenticate, requireAuth } from '../middlewares/auth';

const router = express.Router();

// All routes require authentication and authorization
router.use(authenticate);
router.use(requireAuth);

// Simple validation middleware that doesn't depend on external schemas
const createValidationMiddleware = (requiredFields: string[]): RequestHandler => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      const errors: string[] = [];
      
      // Check required fields
      for (const field of requiredFields) {
        if (!req.body || req.body[field] === undefined || req.body[field] === '' || req.body[field] === null) {
          errors.push(`Missing required field: ${field}`);
        }
      }
      
      // Basic UUID validation for fields that should be UUIDs
      const uuidFields = ['user_id', 'original_image_id'];
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      
      for (const field of uuidFields) {
        if (req.body && req.body[field] && !uuidRegex.test(req.body[field])) {
          errors.push(`Invalid UUID format for ${field}`);
        }
      }
      
      if (errors.length > 0) {
        res.status(400).json({
          success: false,
          error: 'Validation failed',
          details: errors
        });
        return;
      }
      
      next();
    } catch (error) {
      res.status(500).json({
        success: false,
        error: 'Validation error',
        details: [(error as Error).message]
      });
    }
  };
};

// Define validation middleware functions
const validateCreateGarment: RequestHandler = createValidationMiddleware([
  'user_id', 
  'original_image_id', 
  'file_path', 
  'mask_path'
]);

const validateUpdateMetadata: RequestHandler = createValidationMiddleware(['metadata']);

// Create proper RequestHandler wrappers for controller methods
const createGarmentHandler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await garmentController.createGarment(req, res, next);
  } catch (error) {
    next(error);
  }
};

const getGarmentsHandler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await garmentController.getGarments(req, res, next);
  } catch (error) {
    next(error);
  }
};

const getGarmentHandler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await garmentController.getGarment(req, res, next);
  } catch (error) {
    next(error);
  }
};

const updateGarmentMetadataHandler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await garmentController.updateGarmentMetadata(req, res, next);
  } catch (error) {
    next(error);
  }
};

const deleteGarmentHandler: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await garmentController.deleteGarment(req, res, next);
  } catch (error) {
    next(error);
  }
};

// Define routes with proper middleware
router.post('/create', validateCreateGarment, createGarmentHandler);
router.get('/', getGarmentsHandler);
router.get('/:id', getGarmentHandler);
router.put('/:id/metadata', validateUpdateMetadata, updateGarmentMetadataHandler);
router.delete('/:id', deleteGarmentHandler);

export { router as garmentRoutes };