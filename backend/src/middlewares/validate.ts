import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { ApiError } from '../utils/ApiError';

type RequestSource = 'body' | 'query' | 'params';

/**
 * Middleware factory for validating request data against a Zod schema
 */
export const validate = (schema: z.AnyZodObject, source: RequestSource = 'body') => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      // Validate the data from the specified source
      const validatedData = await schema.parseAsync(req[source]);
      
      // Replace the request data with the validated version
      req[source] = validatedData;
      
      // Continue to the next middleware
      next();
    } catch (error) {
      // If it's a Zod validation error, format it nicely
      if (error instanceof z.ZodError) {
        // Format the validation error message
        const errorMessage = `Validation error: ${error.errors.map(
          (e) => `${e.path.join('.')}: ${e.message}`
        ).join(', ')}`;
        
        // Create an API error with a proper HTTP status code and error code
        const apiError = ApiError.badRequest(errorMessage, 'VALIDATION_ERROR');
        
        // Pass the error to the error handling middleware
        next(apiError);
      } else {
        // Ensure non-Zod errors also have a statusCode
        if (typeof error === 'object' && error !== null && 'statusCode' in error) {
          const typedError = error as { statusCode?: number };
          if (!typedError.statusCode) {
            typedError.statusCode = 500; // Or another appropriate code
          }
        }
        next(error);
      }
    }
  };
};