// backend/src/middlewares/validate.ts
// Enhanced validation middleware with Flutter compatibility and backward compatibility

import { NextFunction, Request, Response } from 'express';
import { z } from 'zod';
import { ApiError } from '../utils/ApiError';
import { UUIDParamSchema, 
         ImageQuerySchema, 
         EnhancedFileUploadSchema 
} from '../validators/schemas';
import sharp from 'sharp';

// Extend Express Request interface to include Flutter-specific properties
declare global {
  namespace Express {
    interface Request {
      imageMetadata?: sharp.Metadata;
      flutterMetadata?: {
        clientType: 'flutter' | 'web' | 'mobile-web';
        deviceInfo?: FlutterDeviceInfo;
        networkInfo?: FlutterNetworkInfo;
        validationConfig?: FlutterValidationConfig;
      };
    }
  }
}

// Flutter-specific interfaces
interface FlutterDeviceInfo {
  platform: 'android' | 'ios' | 'web';
  devicePixelRatio: number;
  screenWidth: number;
  screenHeight: number;
  version?: string;
}

interface FlutterNetworkInfo {
  type: 'wifi' | 'cellular' | 'ethernet' | 'unknown';
  isMetered: boolean;
  speed?: 'slow' | 'fast' | 'unknown';
}

interface FlutterValidationConfig {
  maxFileSize: number;
  allowedMimeTypes: string[];
  enableChunkedUpload: boolean;
  enableWebPConversion: boolean;
  compressionLevel: number;
  enableProgressiveJPEG: boolean;
  thumbnailSizes: number[];
  enableHEICSupport: boolean;
}

// Configuration presets for different client types
const FLUTTER_VALIDATION_CONFIGS: Record<string, FlutterValidationConfig> = {
  flutter: {
    maxFileSize: 20971520, // 20MB - higher for mobile cameras
    allowedMimeTypes: [
      'image/jpeg', 'image/jpg', 'image/png', 'image/bmp', 
      'image/heic', 'image/heif', 'image/webp'
    ],
    enableChunkedUpload: true,
    enableWebPConversion: true,
    compressionLevel: 0.6, // More aggressive for mobile
    enableProgressiveJPEG: true,
    thumbnailSizes: [150, 300, 600], // Multiple sizes for different use cases
    enableHEICSupport: true
  },
  'mobile-web': {
    maxFileSize: 10485760, // 10MB
    allowedMimeTypes: ['image/jpeg', 'image/jpg', 'image/png', 'image/bmp', 'image/webp'],
    enableChunkedUpload: false,
    enableWebPConversion: true,
    compressionLevel: 0.7,
    enableProgressiveJPEG: true,
    thumbnailSizes: [150, 300],
    enableHEICSupport: false
  },
  web: {
    maxFileSize: 8388608, // 8MB - existing behavior
    allowedMimeTypes: ['image/jpeg', 'image/jpg', 'image/png', 'image/bmp'],
    enableChunkedUpload: false,
    enableWebPConversion: false,
    compressionLevel: 0.8,
    enableProgressiveJPEG: false,
    thumbnailSizes: [150],
    enableHEICSupport: false
  }
};

// Enhanced Flutter schemas
const FlutterDeviceInfoSchema = z.object({
  platform: z.enum(['android', 'ios', 'web']),
  devicePixelRatio: z.number().min(0.5).max(5).default(1),
  screenWidth: z.number().int().min(320).max(4096),
  screenHeight: z.number().int().min(568).max(4096),
  version: z.string().optional()
});

const FlutterNetworkInfoSchema = z.object({
  type: z.enum(['wifi', 'cellular', 'ethernet', 'unknown']).default('unknown'),
  isMetered: z.boolean().default(false),
  speed: z.enum(['slow', 'fast', 'unknown']).optional()
});

const FlutterUploadMetadataSchema = z.object({
  compressionQuality: z.number().min(0.1).max(1.0).optional(),
  targetWidth: z.number().int().min(320).max(4096).optional(),
  targetHeight: z.number().int().min(320).max(4096).optional(),
  enableWebPConversion: z.boolean().optional(),
  generateThumbnails: z.boolean().default(true),
  deviceInfo: FlutterDeviceInfoSchema.optional(),
  networkInfo: FlutterNetworkInfoSchema.optional()
});

type RequestSource = 'body' | 'query' | 'params';

/**
 * ORIGINAL FUNCTIONS - Maintained for backward compatibility
 */

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

// Original file validation middleware (preserved for backward compatibility)
const originalValidateFile = (req: Request, res: Response, next: NextFunction) => {
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
    
    // 2. Check file size limits - FIXED: Ensure proper size validation
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

// Original Instagram validation middleware (preserved for backward compatibility)
const originalInstagramValidation = async (
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
    
    // 2. Dimensions - Standard web validation
    if (!metadata.width || !metadata.height) {
      validationErrors.push('Unable to determine image dimensions');
    } else {
      if (metadata.width < 320) {
        validationErrors.push(`Width too small (min 320px, got ${metadata.width}px)`);
      }
      if (metadata.width > 4096) {
        validationErrors.push(`Width too large (max 4096px, got ${metadata.width}px)`);
      }
      
      // 3. Aspect ratio - FIXED: Use proper Instagram validation rules
      const aspectRatio = metadata.width / metadata.height;
      // Instagram's actual aspect ratio limits: 0.8 (4:5 portrait) to 1.91 (1.91:1 landscape)
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

// Helper function to detect prototype pollution attempts
function hasPrototypePollution(obj: any): boolean {
  if (!obj || typeof obj !== 'object') return false;
  
  // Check for dangerous keys that could lead to prototype pollution
  const dangerousKeys = [
    '__proto__', 
    'constructor', 
    'prototype'
  ];
  
  // Check if any dangerous keys exist as direct own properties of this object
  for (const key of dangerousKeys) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      return true;
    }
  }
  
  // Recursively check nested objects, but only those that are plain objects
  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const value = obj[key];
      // Only recurse into plain objects (not arrays, dates, etc.)
      if (value && typeof value === 'object' && value.constructor === Object) {
        if (hasPrototypePollution(value)) {
          return true;
        }
      }
    }
  }
  
  return false;
}

/**
 * NEW FLUTTER-ENHANCED FUNCTIONS
 */

/**
 * Client type detection middleware
 * Determines if request is from Flutter, mobile web, or desktop web
 */
export const flutterClientDetection = (req: Request, res: Response, next: NextFunction) => {
  try {
    const userAgent = req.get('User-Agent') || '';
    const clientType = req.get('X-Client-Type')?.toLowerCase();
    const flutterVersion = req.get('X-Flutter-Version');
    const deviceInfo = req.get('X-Device-Info');
    const networkInfo = req.get('X-Network-Info');

    // Determine client type
    let detectedClientType: 'flutter' | 'web' | 'mobile-web' = 'web';
    
    if (flutterVersion || clientType === 'flutter' || userAgent.includes('Flutter')) {
      detectedClientType = 'flutter';
    } else if (/Mobile|Android|iPhone|iPad|iPod|Opera Mini|IEMobile|WPDesktop/i.test(userAgent)) {
      detectedClientType = 'mobile-web';
    }

    // Parse device info if provided
    let parsedDeviceInfo: FlutterDeviceInfo | undefined;
    if (deviceInfo) {
      try {
        const deviceData = JSON.parse(deviceInfo);
        
        // Security check: Prevent prototype pollution
        if (hasPrototypePollution(deviceData)) {
          console.warn('Prototype pollution attempt detected in device info');
          // Don't set deviceInfo at all for malicious input
          parsedDeviceInfo = undefined;
        } else {
          const result = FlutterDeviceInfoSchema.safeParse(deviceData);
          if (result.success) {
            parsedDeviceInfo = result.data;
          }
        }
      } catch (error) {
        console.warn('Invalid device info header:', error);
      }
    }

    // Parse network info if provided
    let parsedNetworkInfo: FlutterNetworkInfo | undefined;
    if (networkInfo) {
      try {
        const networkData = JSON.parse(networkInfo);
        const result = FlutterNetworkInfoSchema.safeParse(networkData);
        if (result.success) {
          parsedNetworkInfo = result.data;
        }
      } catch (error) {
        console.warn('Invalid network info header:', error);
      }
    }

    // Attach Flutter metadata to request
    req.flutterMetadata = {
      clientType: detectedClientType,
      deviceInfo: parsedDeviceInfo,
      networkInfo: parsedNetworkInfo,
      validationConfig: FLUTTER_VALIDATION_CONFIGS[detectedClientType]
    };

    next();
  } catch (error) {
    console.error('Flutter client detection error:', error);
    // Default to web client on error
    req.flutterMetadata = {
      clientType: 'web',
      validationConfig: FLUTTER_VALIDATION_CONFIGS.web
    };
    next();
  }
};

// Helper function to check file security
function isFileSecure(file: Express.Multer.File): boolean {
  const filename = file.originalname.toLowerCase();
  const buffer = file.buffer;
  
  // Check for dangerous file extensions
  const dangerousExtensions = ['.php', '.jsp', '.asp', '.aspx', '.js', '.html', '.htm'];
  const hasDangerousExtension = dangerousExtensions.some(ext => filename.endsWith(ext));
  
  if (hasDangerousExtension) {
    return false;
  }
  
  // Check buffer content for script patterns
  const content = buffer.toString('utf8', 0, Math.min(buffer.length, 1000));
  const scriptPatterns = [
    /<\?php/i,
    /<script/i,
    /system\s*\(/i,
    /eval\s*\(/i,
    /exec\s*\(/i
  ];
  
  return !scriptPatterns.some(pattern => pattern.test(content));
}

/**
 * Flutter-aware file validation middleware
 * Uses configuration based on detected client type
 */
export const flutterAwareFileValidation = (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.file) {
      // Log the missing file scenario for security monitoring
      console.error('Flutter file validation error: No file provided in request');
      return next(ApiError.badRequest('No file provided', 'NO_FILE'));
    }

    const file = req.file;
    const config = req.flutterMetadata?.validationConfig || FLUTTER_VALIDATION_CONFIGS.web;
    const clientType = req.flutterMetadata?.clientType || 'web';

    // Enhanced security checks first (same as original)
    if (file.originalname.includes('..') || file.originalname.includes('/') || file.originalname.includes('\\')) {
      return next(ApiError.badRequest('Invalid filename - path traversal not allowed', 'INVALID_FILE'));
    }

    // Check for executable file extensions BEFORE other checks
    const executableExtensions = ['.exe', '.bat', '.scr', '.com', '.pif', '.cmd', '.ps1', '.vbs', '.js'];
    const extension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
    if (executableExtensions.includes(extension)) {
      return next(ApiError.badRequest('Executable files not allowed', 'INVALID_FILE'));
    }

    if (!isFileSecure(file)) {
      return next(ApiError.badRequest('Invalid file type', 'INVALID_FILE'));
    }

    // Client-aware file size validation
    if (file.size > config.maxFileSize) {
      const maxSizeMB = Math.round(config.maxFileSize / 1024 / 1024);
      const actualSizeMB = Math.round(file.size / 1024 / 1024);
      
      // Provide consistent error message structure for web clients
      if (clientType === 'web') {
        return next(ApiError.badRequest(
          `File too large (max ${maxSizeMB}MB, got ${actualSizeMB}MB)`, 
          'INVALID_FILE'
        ));
      } else {
        return next(ApiError.badRequest(
          `File too large for ${clientType} client (max ${maxSizeMB}MB, got ${actualSizeMB}MB)`, 
          'INVALID_FILE'
        ));
      }
    }

    // Negative size check (security)
    if (file.size < 0) {
      return next(ApiError.badRequest('Invalid file size', 'INVALID_FILE', {
        validationErrors: [{ message: 'File size cannot be negative', path: ['size'] }]
      }));
    }

    // Client-aware MIME type validation
    if (!config.allowedMimeTypes.includes(file.mimetype.toLowerCase())) {
      if (clientType === 'web') {
        // Provide backward-compatible error message for web
        return next(ApiError.badRequest(
          'Only JPEG, PNG, and BMP images are allowed (Instagram compatible)', 
          'INVALID_FILE'
        ));
      } else {
        const supportedTypes = config.allowedMimeTypes.join(', ');
        return next(ApiError.badRequest(
          `File type '${file.mimetype}' not supported for ${clientType} clients. Supported: ${supportedTypes}`, 
          'INVALID_FILE'
        ));
      }
    }

    // Flutter-specific validations
    if (clientType === 'flutter') {
      // Additional validations for Flutter clients
      const networkInfo = req.flutterMetadata?.networkInfo;
      
      // Warn for large files on cellular networks
      if (networkInfo?.type === 'cellular' && file.size > 5242880) { // 5MB
        console.warn(`Large file upload on cellular network: ${file.size} bytes`);
      }

      // Validate against device constraints
      const deviceInfo = req.flutterMetadata?.deviceInfo;
      if (deviceInfo && file.size > 15728640 && deviceInfo.platform === 'ios') { // 15MB limit for iOS
        return next(ApiError.badRequest(
          'File too large for iOS device capabilities', 
          'INVALID_FILE'
        ));
      }
    }

    next();
  } catch (error) {
    console.error('Flutter file validation error:', error);
    next(ApiError.internal('File validation error', 'FILE_VALIDATION_ERROR', error as Error));
  }
};

/**
 * Flutter-enhanced Instagram validation middleware
 */
export const flutterInstagramValidation = async (
  req: Request, 
  res: Response, 
  next: NextFunction
) => {
  if (!req.file) {
    return next(ApiError.badRequest('No image file provided', 'MISSING_FILE'));
  }

  try {
    const clientType = req.flutterMetadata?.clientType || 'web';
    const config = req.flutterMetadata?.validationConfig || FLUTTER_VALIDATION_CONFIGS.web;
    const deviceInfo = req.flutterMetadata?.deviceInfo;
    
    const metadata = await sharp(req.file.buffer).metadata();
    
    // Security check: Validate format based on actual client type (not config)
    const heicFormats = ['heic', 'heif'];
    if (clientType === 'web' && metadata.format && heicFormats.includes(metadata.format as string)) {
      return next(ApiError.badRequest(
        'Instagram validation failed: Unsupported format for web client', 
        'INSTAGRAM_VALIDATION_ERROR'
      ));
    }
    
    const validationErrors: string[] = [];

    // Dimensions validation with Flutter-specific adjustments
    if (!metadata.width || !metadata.height) {
      validationErrors.push('Unable to determine image dimensions');
    } else {
      // More lenient dimension requirements for Flutter clients
      let minWidth: number;
      let maxWidth: number;
      
      if (clientType === 'flutter') {
        minWidth = 240;
        maxWidth = 4096; // Much higher for Flutter (camera photos)
      } else if (clientType === 'mobile-web') {
        minWidth = 300;
        maxWidth = 2048; // Higher for mobile but less than Flutter
      } else {
        minWidth = 320;
        maxWidth = 4096; // FIXED: Increased from 1440 to 4096 for web
      }
      
      if (metadata.width < minWidth) {
        validationErrors.push(`Width too small (min ${minWidth}px, got ${metadata.width}px)`);
      }
      if (metadata.width > maxWidth) {
        validationErrors.push(`Width too large (max ${maxWidth}px, got ${metadata.width}px)`);
      }

      // Flutter-aware aspect ratio validation
      const aspectRatio = metadata.width / metadata.height;
      
      if (clientType === 'flutter') {
        // More flexible aspect ratios for mobile cameras
        if (aspectRatio < 0.5) { // Very lenient
          validationErrors.push(`Image too tall (min 1:2 ratio, got ${aspectRatio.toFixed(2)}:1)`);
        }
        if (aspectRatio > 4.0) { // Very lenient
          validationErrors.push(`Image too wide (max 4:1 ratio, got ${aspectRatio.toFixed(2)}:1)`);
        }
      } else if (clientType === 'mobile-web') {
        // Much more flexible ratios for mobile-web
        if (aspectRatio < 0.3) { // Allow very tall images
          validationErrors.push(`Image too tall (min 3:10 ratio, got ${aspectRatio.toFixed(2)}:1)`);
        }
        if (aspectRatio > 4.0) { // Allow very wide images
          validationErrors.push(`Image too wide (max 4:1 ratio, got ${aspectRatio.toFixed(2)}:1)`);
        }
      } else {
        // Web client - use ORIGINAL Instagram validation logic
        if (aspectRatio < 0.8) {
          validationErrors.push(`Image too tall (min 4:5 ratio, got ${aspectRatio.toFixed(2)}:1)`);
        }
        if (aspectRatio > 1.91) {
          validationErrors.push(`Image too wide (max 1.91:1 ratio, got ${aspectRatio.toFixed(2)}:1)`);
        }
      }
    }

    // Format validation with Flutter support
    const allowedFormats = config.enableHEICSupport 
      ? ['jpeg', 'png', 'bmp', 'heic', 'heif', 'webp']
      : ['jpeg', 'png', 'bmp', 'webp'];
      
    if (!metadata.format || !allowedFormats.includes(metadata.format)) {
      const supportedFormats = allowedFormats.join(', ').toUpperCase();
      validationErrors.push(`Unsupported format: ${metadata.format}. Use ${supportedFormats}`);
    }

    // Color space handling (more lenient for Flutter)
    if (metadata.space && metadata.space !== 'srgb') {
      if (clientType === 'flutter') {
        console.info(`Non-sRGB color space detected: ${metadata.space}. Will convert for compatibility.`);
      } else {
        console.warn(`Non-sRGB color space detected: ${metadata.space}. Will convert to sRGB.`);
      }
    }

    if (validationErrors.length > 0) {
      return next(ApiError.badRequest(
        `Instagram validation failed: ${validationErrors.join(', ')}`,
        'INSTAGRAM_VALIDATION_ERROR'
      ));
    }

    // Attach enhanced metadata to request
    req.imageMetadata = metadata;
    
    next();
    
  } catch (error) {
    console.error('Flutter Instagram validation error:', error);
    next(ApiError.badRequest('Invalid image file', 'INVALID_IMAGE'));
  }
};

/**
 * Backward compatibility layer - routes requests to appropriate validation
 */
export const validateFile = (req: Request, res: Response, next: NextFunction) => {
  const clientType = req.flutterMetadata?.clientType;
  
  // Always use Flutter-aware validation when flutterMetadata exists
  // This ensures consistent error message structure across all client types
  if (req.flutterMetadata) {
    return flutterAwareFileValidation(req, res, next);
  } else {
    // Only use original validation when no client detection was performed
    return originalValidateFile(req, res, next);
  }
};

export const instagramValidationMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const clientType = req.flutterMetadata?.clientType;
  
  // Use Flutter-enhanced validation for Flutter and mobile-web, original for web
  if (clientType === 'flutter' || clientType === 'mobile-web') {
    return flutterInstagramValidation(req, res, next);
  } else {
    return originalInstagramValidation(req, res, next);
  }
};

/**
 * Remaining original validation functions
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
      // Allow specific object fields that are legitimate for the application
      const allowedObjectFields = [
        'metadata', 
        'mask_data', 
        'points', 
        'flutterMetadata',  // Flutter-specific metadata
        'garment',          // Garment object
        'wardrobe',         // Wardrobe object
        'polygons'          // Polygon data for annotations
      ];
      
      // Allow specific array fields that are legitimate
      const allowedArrayFields = [
        'tags',             // Array of tags
        'polygons',         // Array of polygon data
        'points',           // Array of points
        'thumbnailSizes'    // Array of thumbnail sizes
      ];
      
      // Check for array injection where string expected (but allow legitimate arrays)
      if (Array.isArray(value) && !allowedArrayFields.includes(key)) {
        typeErrors.push(`Field '${key}' should be a string, received array`);
      }
      
      // Check for object injection where primitive expected (but allow legitimate objects)
      if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
        if (!allowedObjectFields.includes(key)) {
          // Special handling for nested objects within allowed objects
          const parentKeys = ['garment', 'wardrobe', 'metadata'];
          const isNestedInAllowedParent = parentKeys.some(parentKey => 
            body[parentKey] && typeof body[parentKey] === 'object' && body[parentKey][key] === value
          );
          
          if (!isNestedInAllowedParent) {
            typeErrors.push(`Field '${key}' should be a primitive value, received object`);
          }
        } else {
          // For allowed object fields, check their nested properties
          if (key === 'garment' || key === 'wardrobe') {
            // Allow certain nested fields in garment and wardrobe objects
            const allowedNestedFields = ['type', 'color', 'brand', 'size', 'tags', 'metadata', 'name', 'isPublic'];
            
            Object.keys(value as object).forEach(nestedKey => {
              if (!allowedNestedFields.includes(nestedKey)) {
                typeErrors.push(`Field '${key}.${nestedKey}' is not allowed`);
              }
            });
          }
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
  const provider = req.params.provider;
  const validProviders = ['google', 'microsoft', 'github', 'instagram'];
  
  // Check for missing or empty provider
  if (!provider || provider === '') {
    return next(ApiError.badRequest('Invalid OAuth provider'));
  }
  
  // Check for non-string types (prevents array pollution, object injection)
  if (typeof provider !== 'string') {
    return next(ApiError.badRequest('Invalid OAuth provider'));
  }
  
  // Security: Strict case-sensitive validation (no normalization to prevent case manipulation attacks)
  if (!validProviders.includes(provider)) {
    return next(ApiError.badRequest('Invalid OAuth provider'));
  }
  
  next();
};

export const validateOAuthTypes = (req: Request, res: Response, next: NextFunction) => {
  // Fix: Robust path checking to handle undefined req.path in test environments
  const requestPath = req.path || req.url || req.originalUrl || '';
  
  // Enhanced security: Check for OAuth-related query parameters and validate them
  // regardless of path to prevent bypassing validation through path manipulation
  const { code, state, error, redirect } = req.query;
  
  // If any OAuth-related parameters are present, validate them
  const hasOAuthParams = code !== undefined || state !== undefined || error !== undefined || redirect !== undefined;
  
  if (hasOAuthParams || requestPath.includes('/callback') || requestPath.includes('/authorize')) {
    
    // Check for array parameter pollution on all OAuth parameters
    if (code !== undefined && Array.isArray(code)) {
      return next(ApiError.badRequest('Invalid parameter format'));
    }
    
    if (state !== undefined && Array.isArray(state)) {
      return next(ApiError.badRequest('Invalid parameter format'));
    }
    
    if (error !== undefined && Array.isArray(error)) {
      return next(ApiError.badRequest('Invalid parameter format'));
    }
    
    if (redirect !== undefined && Array.isArray(redirect)) {
      return next(ApiError.badRequest('Invalid parameter format'));
    }

    // Check for object injection attempts on all OAuth parameters
    if (code !== undefined && typeof code === 'object' && code !== null) {
      return next(ApiError.badRequest('Invalid parameter format'));
    }
    
    if (state !== undefined && typeof state === 'object' && state !== null) {
      return next(ApiError.badRequest('Invalid parameter format'));
    }
    
    if (error !== undefined && typeof error === 'object' && error !== null) {
      return next(ApiError.badRequest('Invalid parameter format'));
    }
    
    if (redirect !== undefined && typeof redirect === 'object' && redirect !== null) {
      return next(ApiError.badRequest('Invalid parameter format'));
    }
    
    // Additional security checks for OAuth parameters
    
    // Check for function injection
    if (typeof code === 'function' || typeof state === 'function' || 
        typeof error === 'function' || typeof redirect === 'function') {
      return next(ApiError.badRequest('Invalid parameter format'));
    }
    
    // Check for NoSQL injection patterns in objects
    if (code && typeof code === 'object' && code !== null) {
      const codeObj = code as any;
      if (codeObj.$ne !== undefined || codeObj.$regex !== undefined || codeObj.$where !== undefined) {
        return next(ApiError.badRequest('Invalid parameter format'));
      }
    }
    
    if (state && typeof state === 'object' && state !== null) {
      const stateObj = state as any;
      if (stateObj.$ne !== undefined || stateObj.$regex !== undefined || stateObj.$where !== undefined) {
        return next(ApiError.badRequest('Invalid parameter format'));
      }
    }
    
    // Check for prototype pollution attempts
    if (code && typeof code === 'object' && code !== null) {
      if (Object.prototype.hasOwnProperty.call(code, '__proto__') || 
          Object.prototype.hasOwnProperty.call(code, 'constructor')) {
        return next(ApiError.badRequest('Invalid parameter format'));
      }
    }
    
    if (state && typeof state === 'object' && state !== null) {
      if (Object.prototype.hasOwnProperty.call(state, '__proto__') || 
          Object.prototype.hasOwnProperty.call(state, 'constructor')) {
        return next(ApiError.badRequest('Invalid parameter format'));
      }
    }
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

/**
 * Export Flutter-specific schemas and configurations for testing
 */
export {
  FlutterDeviceInfoSchema,
  FlutterNetworkInfoSchema,
  FlutterUploadMetadataSchema,
  FLUTTER_VALIDATION_CONFIGS
};

/**
 * Test utilities for maintaining compatibility
 */
export const flutterTestUtils = {
  // Set client type for testing
  setClientType: (req: any, clientType: 'flutter' | 'web' | 'mobile-web') => {
    req.flutterMetadata = {
      clientType,
      validationConfig: FLUTTER_VALIDATION_CONFIGS[clientType]
    };
  },
  
  // Create mock Flutter device info
  createMockDeviceInfo: (overrides: Partial<FlutterDeviceInfo> = {}): FlutterDeviceInfo => ({
    platform: 'android',
    devicePixelRatio: 2.0,
    screenWidth: 1080,
    screenHeight: 1920,
    version: '1.0.0',
    ...overrides
  }),
  
  // Create mock network info
  createMockNetworkInfo: (overrides: Partial<FlutterNetworkInfo> = {}): FlutterNetworkInfo => ({
    type: 'wifi',
    isMetered: false,
    speed: 'fast',
    ...overrides
  }),
  
  // Validation configs for testing
  configs: FLUTTER_VALIDATION_CONFIGS,
  
  // Original functions for backward compatibility testing
  originalValidateFile,
  originalInstagramValidation
};