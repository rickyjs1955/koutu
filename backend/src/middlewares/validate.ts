import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { ApiError } from '../utils/ApiError';
import { UUIDParamSchema, 
         ImageQuerySchema, 
         EnhancedFileUploadSchema 
} from '../validators/schemas';

type RequestSource = 'body' | 'query' | 'params';

/**
 * Middleware factory for validating request data against a Zod schema
 * Uses ApiError.badRequest() for consistent error handling
 */
export const validate = (schema: z.AnyZodObject, source: RequestSource = 'body') => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      const validatedData = await schema.parseAsync(req[source]);
      req[source] = validatedData;
      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        const errorMessage = `Validation error: ${error.errors.map(
          (e) => `${e.path.join('.')}: ${e.message}`
        ).join(', ')}`;
        
        // Use context property to store validation details
        const apiError = ApiError.badRequest(
          errorMessage, 
          'VALIDATION_ERROR',
          { 
            validationErrors: error.errors,
            source: source 
          }
        );
        next(apiError);
      } else {
        next(error);
      }
    }
  };
};

/**
 * Generic validation middleware factory
 * Uses custom error objects to match test expectations
 */
export const createValidationMiddleware = (schema: z.ZodSchema, field: 'body' | 'query' | 'params' | 'file') => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Handle null schema case
      if (!schema) {
        const error = new Error('Invalid schema provided');
        (error as any).statusCode = 500;
        (error as any).code = 'MIDDLEWARE_ERROR';
        (error as any).originalError = new Error('Schema is null or undefined');
        return next(error);
      }

      const dataToValidate = req[field];
      
      // Simple security check - only for direct prototype pollution attempts
      if (dataToValidate && typeof dataToValidate === 'object' && dataToValidate !== null) {
        // Check for direct __proto__ or constructor property manipulation
        const hasProtoProperty = Object.prototype.hasOwnProperty.call(dataToValidate, '__proto__');
        const hasConstructorProperty = Object.prototype.hasOwnProperty.call(dataToValidate, 'constructor');
        
        if (hasProtoProperty || hasConstructorProperty) {
          const error = new Error('Validation failed');
          (error as any).statusCode = 400;
          (error as any).code = 'VALIDATION_ERROR';
          (error as any).details = [{ message: 'Invalid object properties', path: ['__proto__'] }];
          return next(error);
        }
      }
      
      // Run schema validation
      const result = schema.safeParse(dataToValidate);
      
      if (result.success) {
        (req as any)[field] = result.data;
        next(); // Success - call next() with no arguments
      } else {
        // Create sanitized error details to prevent information disclosure
        const sensitivePattern = /apiKey|internalSecret|databasePassword|admin|users|sessions|api_keys/gi;
        
        const sanitizedErrors = result.error.issues.map(issue => {
          // Start with a copy of the original issue
          let sanitizedIssue = { ...issue };
          
          // Sanitize the message
          sanitizedIssue.message = issue.message.replace(sensitivePattern, '[FIELD]');
          
          // Special handling for unrecognized_keys errors
          if (issue.code === 'unrecognized_keys' && 'keys' in issue) {
            const originalKeys = (issue as any).keys as string[];
            
            // Sanitize the keys array
            const sanitizedKeys = originalKeys.map((key: string) => {
              return sensitivePattern.test(key) ? '[FIELD]' : key;
            });
            
            // Sanitize the message which contains the key names
            let sanitizedMessage = issue.message;
            originalKeys.forEach((key: string) => {
              if (sensitivePattern.test(key)) {
                // Replace the specific key in the message
                const escapedKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                sanitizedMessage = sanitizedMessage.replace(
                  new RegExp(`'${escapedKey}'`, 'g'),
                  "'[FIELD]'"
                );
              }
            });
            
            sanitizedIssue = {
              ...sanitizedIssue,
              message: sanitizedMessage,
              keys: sanitizedKeys
            } as any;
          }
          
          return sanitizedIssue;
        });
        
        const error = new Error('Validation failed');
        (error as any).statusCode = 400;
        (error as any).code = 'VALIDATION_ERROR';
        (error as any).details = sanitizedErrors;
        next(error); // Failure - call next() with error
      }
    } catch (err) {
      const error = new Error('Validation middleware error');
      (error as any).statusCode = 500;
      (error as any).code = 'MIDDLEWARE_ERROR';
      (error as any).originalError = err;
      next(error);
    }
  };
};

// Specific validation middleware
export const validateBody = (schema: z.ZodSchema) => createValidationMiddleware(schema, 'body');
export const validateQuery = (schema: z.ZodSchema) => createValidationMiddleware(schema, 'query');
export const validateParams = (schema: z.ZodSchema) => createValidationMiddleware(schema, 'params');

// Pre-configured validation middleware
export const validateUUIDParam = createValidationMiddleware(UUIDParamSchema, 'params');
export const validateImageQuery = createValidationMiddleware(ImageQuerySchema, 'query');

// File validation middleware with comprehensive security checks
export const validateFile = (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.file) {
      const error = ApiError.badRequest('No file provided', 'NO_FILE');
      return next(error);
    }

    const file = req.file;
    
    // Security checks before schema validation
    
    // 1. Check for path traversal in filename
    if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
      const error = ApiError.badRequest('Invalid filename - path traversal not allowed', 'INVALID_FILE', {
        validationErrors: [{ message: 'Path traversal detected in filename', path: ['originalname'] }]
      });
      return next(error);
    }
    
    // 2. Check file size limits
    const MAX_FILE_SIZE = 1024 * 1024; // 1MB limit
    if (file.size > MAX_FILE_SIZE) {
      const error = ApiError.badRequest(`File too large (max ${MAX_FILE_SIZE / (1024 * 1024)}MB)`, 'INVALID_FILE', {
        validationErrors: [{ message: 'File size exceeds maximum allowed', path: ['size'] }]
      });
      return next(error);
    }
    
    // 3. Check for negative file size
    if (file.size < 0) {
      const error = ApiError.badRequest('Invalid file size', 'INVALID_FILE', {
        validationErrors: [{ message: 'File size cannot be negative', path: ['size'] }]
      });
      return next(error);
    }
    
    // 4. Check mime type - only allow images
    const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedMimeTypes.includes(file.mimetype.toLowerCase())) {
      const error = ApiError.badRequest('Only image files are allowed', 'INVALID_FILE', {
        validationErrors: [{ message: 'Invalid file type', path: ['mimetype'] }]
      });
      return next(error);
    }
    
    // 5. Check for executable file extensions
    const executableExtensions = ['.exe', '.bat', '.scr', '.com', '.pif', '.cmd', '.ps1', '.vbs', '.js'];
    const extension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
    if (executableExtensions.includes(extension)) {
      const error = ApiError.badRequest('Executable files not allowed', 'INVALID_FILE', {
        validationErrors: [{ message: 'Executable file type detected', path: ['originalname'] }]
      });
      return next(error);
    }

    // 6. Use schema validation as final check
    const result = EnhancedFileUploadSchema.safeParse(file);
    
    if (result.success) {
      req.file = result.data as Express.Multer.File;
      next();
    } else {
      const error = ApiError.badRequest(
        'Invalid file upload',
        'INVALID_FILE',
        { validationErrors: result.error.issues }
      );
      next(error);
    }
  } catch (err) {
    const error = ApiError.internal(
      'File validation error',
      'FILE_VALIDATION_ERROR', 
      err as Error
    );
    next(error);
  }
};