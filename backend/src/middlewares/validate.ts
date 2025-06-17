import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { ApiError } from '../utils/ApiError';
import { UUIDParamSchema, 
         ImageQuerySchema, 
         EnhancedFileUploadSchema 
} from '../validators/schemas';
import sharp from 'sharp';

// Extend Express Request interface to include imageMetadata
declare global {
  namespace Express {
    interface Request {
      imageMetadata?: sharp.Metadata;
    }
  }
}

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
      const error = ApiError.badRequest('Invalid filename - path traversal not allowed', 'INVALID_FILE');
      return next(error);
    }
    
    // 2. Check file size limits
    const MAX_FILE_SIZE = 8388608; // 8MB
    if (file.size > MAX_FILE_SIZE) {
      const error = ApiError.badRequest(
        `File too large (max 8MB, got ${Math.round(file.size / 1024 / 1024)}MB)`, 
        'INVALID_FILE'
      );
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
    const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/bmp'];
    if (!allowedMimeTypes.includes(file.mimetype.toLowerCase())) {
      const error = ApiError.badRequest(
        'Only JPEG, PNG, and BMP images are allowed (Instagram compatible)', 
        'INVALID_FILE'
      );
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
      err as Error);
    next(error);
  }
};

export const instagramValidationMiddleware = async (
  req: Request, 
  res: Response, 
  next: NextFunction
) => {
  if (!req.file) {
    return next(ApiError.badRequest('No image file provided', 'MISSING_FILE'));
  }

  try {
    const metadata = await sharp(req.file.buffer).metadata();
    
    // Instagram-specific validations
    const validationErrors: string[] = [];
    
    // 1. File size (already handled by multer, but double-check)
    if (req.file.size > 8388608) { // 8MB
      validationErrors.push('Image too large (max 8MB)');
    }
    
    // 2. Dimensions
    if (!metadata.width || !metadata.height) {
      validationErrors.push('Unable to determine image dimensions');
    } else {
      if (metadata.width < 320) {
        validationErrors.push(`Width too small (min 320px, got ${metadata.width}px)`);
      }
      if (metadata.width > 1440) {
        validationErrors.push(`Width too large (max 1440px, got ${metadata.width}px)`);
      }
      
      // 3. Aspect ratio
      const aspectRatio = metadata.width / metadata.height;
      if (aspectRatio < 0.8) {
        validationErrors.push(`Image too tall (min 4:5 ratio, got ${aspectRatio.toFixed(2)}:1)`);
      }
      if (aspectRatio > 1.91) {
        validationErrors.push(`Image too wide (max 1.91:1 ratio, got ${aspectRatio.toFixed(2)}:1)`);
      }
    }
    
    // 4. Format validation
    const allowedFormats = ['jpeg', 'png', 'bmp'];
    if (!metadata.format || !allowedFormats.includes(metadata.format)) {
      validationErrors.push(`Unsupported format: ${metadata.format}. Use JPEG, PNG, or BMP`);
    }
    
    // 5. Color space check (warn if not sRGB)
    if (metadata.space && metadata.space !== 'srgb') {
      console.warn(`Non-sRGB color space detected: ${metadata.space}. Will convert to sRGB.`);
    }
    
    // 6. Additional Instagram-style checks
    if (metadata.density && metadata.density < 72) {
      console.warn(`Low DPI detected: ${metadata.density}. Consider higher resolution.`);
    }
    
    if (validationErrors.length > 0) {
      return next(ApiError.badRequest(
        `Instagram validation failed: ${validationErrors.join(', ')}`,
        'INSTAGRAM_VALIDATION_ERROR'
      ));
    }
    
    // Attach metadata to request for later use
    req.imageMetadata = metadata;
    next();
    
  } catch (error) {
    next(ApiError.badRequest('Invalid image file', 'INVALID_IMAGE'));
  }
};

/**
 * Middleware to validate request body types and prevent type confusion attacks
 */
export const validateRequestTypes = (req: Request, res: Response, next: NextFunction) => {
  try {
    const body = req.body;
    
    if (!body || typeof body !== 'object') {
      return next();
    }

    // Check for type confusion attacks
    const typeErrors: string[] = [];
    
    Object.entries(body).forEach(([key, value]) => {
      // Check for array injection where string expected
      if (Array.isArray(value)) {
        typeErrors.push(`Field '${key}' should be a string, received array`);
      }
      
      // Check for object injection where primitive expected
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        // Allow nested objects for specific fields like 'metadata'
        const allowedObjectFields = ['metadata', 'mask_data', 'points'];
        if (!allowedObjectFields.includes(key)) {
          typeErrors.push(`Field '${key}' should be a primitive value, received object`);
        }
      }
      
      // Check for function injection
      if (typeof value === 'function') {
        typeErrors.push(`Field '${key}' contains function, which is not allowed`);
      }
      
      // Check for undefined injection (different from missing field)
      if (value === undefined) {
        typeErrors.push(`Field '${key}' is explicitly undefined`);
      }
    });

    if (typeErrors.length > 0) {
      return next(ApiError.badRequest(
        'Type validation failed: ' + typeErrors.join(', '),
        'TYPE_VALIDATION_ERROR'
      ));
    }

    next();
  } catch (error) {
    next(ApiError.internal('Type validation error', 'TYPE_VALIDATION_ERROR', error as Error));
  }
};

/**
 * Specific middleware for authentication endpoints
 */
export const validateAuthTypes = (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body || {};
    
    // Type validation with helpful error messages
    if (email !== undefined && typeof email !== 'string') {
      return next(ApiError.badRequest('Email must be a string', 'INVALID_EMAIL_TYPE'));
    }
    
    if (password !== undefined && typeof password !== 'string') {
      return next(ApiError.badRequest('Password must be a string', 'INVALID_PASSWORD_TYPE'));
    }
    
    // Check for array/object injection specifically
    if (Array.isArray(email)) {
      return next(ApiError.badRequest('Email cannot be an array', 'INVALID_EMAIL_TYPE'));
    }
    
    if (Array.isArray(password)) {
      return next(ApiError.badRequest('Password cannot be an array', 'INVALID_PASSWORD_TYPE'));
    }
    
    if (email !== null && typeof email === 'object') {
      return next(ApiError.badRequest('Email cannot be an object', 'INVALID_EMAIL_TYPE'));
    }
    
    if (password !== null && typeof password === 'object') {
      return next(ApiError.badRequest('Password cannot be an object', 'INVALID_PASSWORD_TYPE'));
    }

    next();
  } catch (error) {
    next(ApiError.internal('Authentication type validation error', 'AUTH_TYPE_VALIDATION_ERROR', error as Error));
  }
};

export const validateOAuthProvider = (req: Request, res: Response, next: NextFunction) => {
  const { provider } = req.params;
  const validProviders = ['google', 'microsoft', 'github', 'instagram'];
  
  if (!provider || !validProviders.includes(provider)) {
    return next(ApiError.badRequest(`Invalid OAuth provider: ${provider}`));
  }
  
  next();
};

export const validateOAuthTypes = (req: Request, res: Response, next: NextFunction) => {
  // Handle null or undefined query object
  if (!req.query || typeof req.query !== 'object') {
    return next();
  }

  const { code, state, error } = req.query;
  
  // Check for array parameter pollution
  if (Array.isArray(code) || Array.isArray(state) || Array.isArray(error)) {
    return next(ApiError.badRequest('Invalid parameter format'));
  }
  
  // Check for object parameter pollution
  if ((code && typeof code === 'object') || 
      (state && typeof state === 'object') || 
      (error && typeof error === 'object')) {
    return next(ApiError.badRequest('Invalid parameter format'));
  }
  
  next();
};

// Enhanced error messages for better UX
export const instagramErrorMessages = {
  FILE_TOO_LARGE: 'Your image is too large. Please use an image under 8MB.',
  INVALID_ASPECT_RATIO: 'Your image doesn\'t meet Instagram\'s aspect ratio requirements. Try cropping it to be between 4:5 (portrait) and 1.91:1 (landscape).',
  INVALID_DIMENSIONS: 'Your image is too small or too large. Please use an image between 320px and 1440px wide.',
  UNSUPPORTED_FORMAT: 'Please use a JPEG, PNG, or BMP image file.',
  INVALID_COLOR_SPACE: 'Your image will be converted to sRGB for better compatibility.'
};