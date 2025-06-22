// /backend/src/middlewares/fileValidate.ts
import { NextFunction, Request, Response } from 'express';
import path from 'path';
import fs from 'fs/promises';
import { ApiError } from '../utils/ApiError';
import { storageService } from '../services/storageService';

// Extend Express Request interface for file validation
declare global {
  namespace Express {
    interface Request {
      fileValidation?: {
        filepath: string;
        isValid: boolean;
        fileType: string;
        fileSize?: number;
        securityFlags?: string[];
      };
    }
  }
}

/**
 * File content validation configuration
 */
const FILE_VALIDATION_CONFIG = {
  // Maximum file sizes by type (in bytes)
  maxFileSizes: {
    image: 8388608,      // 8MB for images
    document: 10485760,  // 10MB for documents
    default: 5242880     // 5MB default
  },
  
  // Allowed file types and their MIME types
  allowedTypes: {
    'image/jpeg': { extensions: ['.jpg', '.jpeg'], category: 'image' },
    'image/png': { extensions: ['.png'], category: 'image' },
    'image/bmp': { extensions: ['.bmp'], category: 'image' },
    'image/webp': { extensions: ['.webp'], category: 'image' },
    'application/pdf': { extensions: ['.pdf'], category: 'document' },
    'text/plain': { extensions: ['.txt'], category: 'document' }
  },
  
  // Dangerous file signatures (magic bytes)
  dangerousSignatures: [
    // Executable files
    { signature: [0x4D, 0x5A], description: 'PE/DOS executable' }, // MZ
    { signature: [0x7F, 0x45, 0x4C, 0x46], description: 'ELF executable' }, // ELF
    { signature: [0xCA, 0xFE, 0xBA, 0xBE], description: 'Mach-O executable' },
    
    // Scripts
    { signature: [0x23, 0x21], description: 'Shell script' }, // #!
    
    // Archives that could contain executables
    { signature: [0x50, 0x4B, 0x03, 0x04], description: 'ZIP archive' }, // ZIP
    { signature: [0x52, 0x61, 0x72, 0x21], description: 'RAR archive' }, // RAR
  ],
  
  // Blocked file extensions
  blockedExtensions: [
    '.exe', '.bat', '.scr', '.com', '.pif', '.cmd', '.ps1', '.vbs', 
    '.js', '.jar', '.app', '.deb', '.rpm', '.msi', '.dmg', '.pkg',
    '.sh', '.bash', '.zsh', '.fish', '.py', '.rb', '.pl', '.php'
  ]
};

/**
 * Validates file path for security issues
 */
const validateFilePath = (filepath: string): { isValid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  // Check for path traversal
  if (filepath.includes('..') || filepath.includes('//') || filepath.includes('\\')) {
    errors.push('Path traversal detected');
  }
  
  // Check for null bytes
  if (filepath.includes('\0')) {
    errors.push('Null byte injection detected');
  }
  
  // Check for absolute paths (should be relative)
  if (path.isAbsolute(filepath)) {
    errors.push('Absolute paths not allowed');
  }
  
  // Check for hidden files/directories
  const pathParts = filepath.split('/');
  if (pathParts.some(part => part.startsWith('.'))) {
    errors.push('Hidden files/directories not allowed');
  }
  
  // Check file extension
  const extension = path.extname(filepath).toLowerCase();
  if (FILE_VALIDATION_CONFIG.blockedExtensions.includes(extension)) {
    errors.push(`Blocked file extension: ${extension}`);
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Reads file signature (magic bytes) to determine actual file type
 */
const getFileSignature = async (filePath: string): Promise<Buffer> => {
  try {
    const file = await fs.open(filePath, 'r');
    const buffer = Buffer.alloc(8); // Read first 8 bytes
    await file.read(buffer, 0, 8, 0);
    await file.close();
    return buffer;
  } catch (error) {
    throw new Error('Unable to read file signature');
  }
};

/**
 * Validates file content based on signature
 */
const validateFileSignature = async (filePath: string, expectedType?: string): Promise<{ 
  isValid: boolean; 
  actualType: string; 
  securityFlags: string[] 
}> => {
  const securityFlags: string[] = [];
  
  try {
    const signature = await getFileSignature(filePath);
    
    // Check against dangerous signatures
    for (const dangerous of FILE_VALIDATION_CONFIG.dangerousSignatures) {
      const sigBytes = dangerous.signature;
      const matches = sigBytes.every((byte, index) => signature[index] === byte);
      
      if (matches) {
        securityFlags.push(`Dangerous file type detected: ${dangerous.description}`);
        return { isValid: false, actualType: 'unknown', securityFlags };
      }
    }
    
    // Determine actual file type from signature
    let actualType = 'unknown';
    
    // Image signatures
    if (signature[0] === 0xFF && signature[1] === 0xD8) {
      actualType = 'image/jpeg';
    } else if (signature[0] === 0x89 && signature[1] === 0x50 && signature[2] === 0x4E && signature[3] === 0x47) {
      actualType = 'image/png';
    } else if (signature[0] === 0x42 && signature[1] === 0x4D) {
      actualType = 'image/bmp';
    } else if (signature.subarray(0, 4).toString() === 'RIFF' || signature.subarray(8, 12).toString() === 'WEBP') {
      actualType = 'image/webp';
    } else if (signature[0] === 0x25 && signature[1] === 0x50 && signature[2] === 0x44 && signature[3] === 0x46) {
      actualType = 'application/pdf';
    }
    
    // Validate against expected type
    if (expectedType && actualType !== expectedType && actualType !== 'unknown') {
      securityFlags.push(`File type mismatch: expected ${expectedType}, got ${actualType}`);
    }
    
    // Check if file type is allowed
    const isAllowedType = Object.keys(FILE_VALIDATION_CONFIG.allowedTypes).includes(actualType);
    if (!isAllowedType && actualType !== 'unknown') {
      securityFlags.push(`File type not allowed: ${actualType}`);
    }
    
    return {
      isValid: securityFlags.length === 0,
      actualType,
      securityFlags
    };
    
  } catch (error) {
    securityFlags.push('Unable to validate file content');
    return { isValid: false, actualType: 'unknown', securityFlags };
  }
};

/**
 * Validates file size
 */
const validateFileSize = async (filePath: string, fileType: string): Promise<{
  isValid: boolean;
  size: number;
  errors: string[];
}> => {
  const errors: string[] = [];
  
  try {
    const stats = await fs.stat(filePath);
    const fileSize = stats.size;
    
    // Determine max size based on file category
    const typeConfig = Object.values(FILE_VALIDATION_CONFIG.allowedTypes)
      .find(config => Object.keys(FILE_VALIDATION_CONFIG.allowedTypes)
        .find(mime => FILE_VALIDATION_CONFIG.allowedTypes[mime as keyof typeof FILE_VALIDATION_CONFIG.allowedTypes] === config) === fileType);
    
    const category = typeConfig?.category || 'default';
    const maxSize = FILE_VALIDATION_CONFIG.maxFileSizes[category as keyof typeof FILE_VALIDATION_CONFIG.maxFileSizes] 
      || FILE_VALIDATION_CONFIG.maxFileSizes.default;
    
    if (fileSize > maxSize) {
      errors.push(`File too large: ${fileSize} bytes (max: ${maxSize} bytes)`);
    }
    
    if (fileSize === 0) {
      errors.push('Empty file not allowed');
    }
    
    return {
      isValid: errors.length === 0,
      size: fileSize,
      errors
    };
    
  } catch (error) {
    errors.push('Unable to check file size');
    return { isValid: false, size: 0, errors };
  }
};

/**
 * Main file validation middleware
 * Validates file path, content, and size before serving
 */
export const validateFileContent = async (
  req: Request, 
  res: Response, 
  next: NextFunction
): Promise<void> => {
  try {
    const filepath = req.params.filepath;
    
    if (!filepath) {
      return next(ApiError.badRequest('File path is required', 'MISSING_FILEPATH'));
    }
    
    // Step 1: Validate file path
    const pathValidation = validateFilePath(filepath);
    if (!pathValidation.isValid) {
      return next(ApiError.badRequest(
        `Invalid file path: ${pathValidation.errors.join(', ')}`,
        'INVALID_FILEPATH'
      ));
    }
    
    // Step 2: Get absolute file path
    let absolutePath: string;
    try {
      absolutePath = storageService.getAbsolutePath(filepath);
    } catch (error) {
      return next(ApiError.notFound('File not found', 'FILE_NOT_FOUND'));
    }
    
    // Step 3: Check if file exists
    try {
      await fs.access(absolutePath);
    } catch (error) {
      return next(ApiError.notFound('File not found', 'FILE_NOT_FOUND'));
    }
    
    // Step 4: Validate file content
    const contentValidation = await validateFileSignature(absolutePath);
    if (!contentValidation.isValid) {
      return next(ApiError.badRequest(
        `File validation failed: ${contentValidation.securityFlags.join(', ')}`,
        'INVALID_FILE_CONTENT',
        { securityFlags: contentValidation.securityFlags }
      ));
    }
    
    // Step 5: Validate file size
    const sizeValidation = await validateFileSize(absolutePath, contentValidation.actualType);
    if (!sizeValidation.isValid) {
      return next(ApiError.badRequest(
        `File size validation failed: ${sizeValidation.errors.join(', ')}`,
        'INVALID_FILE_SIZE'
      ));
    }
    
    // Attach validation results to request
    req.fileValidation = {
      filepath,
      isValid: true,
      fileType: contentValidation.actualType,
      fileSize: sizeValidation.size,
      securityFlags: contentValidation.securityFlags
    };
    
    next();
    
  } catch (error) {
    next(ApiError.internal(
      'File validation error',
      'FILE_VALIDATION_ERROR',
      error as Error
    ));
  }
};

/**
 * Lightweight file validation for public routes
 * Only checks path and basic file existence
 */
export const validateFileContentBasic = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const filepath = req.params.filepath;
    
    if (!filepath) {
      return next(ApiError.badRequest('File path is required', 'MISSING_FILEPATH'));
    }
    
    // Basic path validation only
    const pathValidation = validateFilePath(filepath);
    if (!pathValidation.isValid) {
      return next(ApiError.badRequest(
        `Invalid file path: ${pathValidation.errors.join(', ')}`,
        'INVALID_FILEPATH'
      ));
    }
    
    // Attach basic validation to request
    req.fileValidation = {
      filepath,
      isValid: true,
      fileType: 'unknown'
    };
    
    next();
    
  } catch (error) {
    next(ApiError.internal(
      'Basic file validation error',
      'FILE_VALIDATION_ERROR',
      error as Error
    ));
  }
};

/**
 * Middleware specifically for image file validation
 * Includes additional image-specific checks
 */
export const validateImageFile = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // First run standard validation
    await validateFileContent(req, res, (err) => {
      if (err) return next(err);
      
      // Additional image-specific validation
      const validation = req.fileValidation;
      if (!validation?.fileType.startsWith('image/')) {
        return next(ApiError.badRequest(
          'File is not a valid image',
          'NOT_AN_IMAGE'
        ));
      }
      
      next();
    });
    
  } catch (error) {
    next(ApiError.internal(
      'Image validation error',
      'IMAGE_VALIDATION_ERROR',
      error as Error
    ));
  }
};

/**
 * Security logging middleware for file access
 */
export const logFileAccess = (
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  const validation = req.fileValidation;
  
  if (validation?.securityFlags && validation.securityFlags.length > 0) {
    console.warn('File security warning:', {
      filepath: validation.filepath,
      flags: validation.securityFlags,
      userAgent: req.get('User-Agent'),
      ip: req.ip,
      timestamp: new Date().toISOString()
    });
  }
  
  next();
};