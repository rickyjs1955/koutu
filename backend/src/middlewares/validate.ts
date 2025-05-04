// /backend/src/middlewares/validate.ts
import { Request, Response, NextFunction } from 'express';
import { AnyZodObject, ZodError } from 'zod';
import { ApiError } from '../utils/ApiError';

// Middleware factory for request validation using Zod schemas
export const validate = (schema: AnyZodObject, source: 'body' | 'query' | 'params' = 'body') => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = await schema.parseAsync(req[source]);
      req[source] = data; // Replace with validated and transformed data
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        // Format Zod errors for consistent API responses
        const errors = error.errors.map(err => ({
          path: err.path.join('.'),
          message: err.message
        }));
        
        return next(ApiError.badRequest(
          `Validation error: ${errors.map(e => `${e.path}: ${e.message}`).join(', ')}`,
          'VALIDATION_ERROR'
        ));
      }
      next(error);
    }
  };
};