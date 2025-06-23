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
  
  // Blocked file extensions - MERGED AND EXTENDED from test file
  blockedExtensions: [
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
    '.app', '.deb', '.pkg', '.rpm', '.dmg', '.iso', '.img', '.msi', '.msp',
    '.ps1', '.psm1', '.psd1', '.ps1xml', '.psc1', '.ps2', '.ps2xml',
    '.scf', '.lnk', '.inf', '.reg', '.dll', '.sys', '.drv', '.ocx',
    '.cpl', '.msc', '.hta', '.chm', '.hlp', '.url', '.website',
    '.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx',
    '.jsp', '.jspx', '.pl', '.py', '.rb', '.sh', '.bash', '.zsh',
    '.cgi', '.fcgi', '.wsf', '.wsh', '.action', '.do'
  ],

  // Advanced path traversal patterns - NEW
  pathTraversalPatterns: [
    /\\/,                      // Windows backslash traversal
    /\.\.\//,                  // Standard path traversal
    /\.\.\%2f/i,               // URL encoded traversal
    /\.\.\%2F/i,               // URL encoded traversal (caps)
    /\.\.\%5c/i,               // URL encoded backslash
    /\x2e\x2e\x2f/,            // Hex encoded
    /\u002e\u002e\u002f/,      // Unicode encoded
    /\.%c0%af/i,               // UTF-8 overlong encoding of /
    /\.%e0%80%af/i             // UTF-8 overlong encoding of / (4-byte)
  ],

  // Dangerous characters and sequences in file paths - NEW
  dangerousPathPatterns: [
    /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/,  // Control characters
    /[\u200b-\u200d\ufeff]/,              // Zero-width characters
    /[<>"\|*?:]/,                          // Dangerous filename chars (added colon for ADS)
    /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i, // Windows reserved names
    // No need for /^\./ as hidden files are checked separately
    /\s+$/,                               // Trailing whitespace
    /\x20+$/                              // Trailing spaces (redundant with \s+$, but kept for clarity)
  ]
};

/**
 * Helper function to calculate entropy (for steganography detection)
 */
function calculateEntropy(buffer: Buffer): number {
  const frequencies = new Array(256).fill(0);
  for (const byte of buffer) {
    frequencies[byte]++;
  }

  let entropy = 0;
  const length = buffer.length;
  if (length === 0) return 0; // Avoid division by zero
  for (const freq of frequencies) {
    if (freq > 0) {
      const probability = freq / length;
      entropy -= probability * Math.log2(probability);
    }
  }
  return entropy;
}

/**
 * Validates file path for security issues (UPDATED)
 */
const validateFilePath = (filepath: string): { isValid: boolean; errors: string[] } => {
  const errors: string[] = [];
  
  // Normalize path separators for consistent checking
  const normalizedPath = filepath.replace(/\\/g, '/');

  // Check for path traversal (enhanced)
  for (const pattern of FILE_VALIDATION_CONFIG.pathTraversalPatterns) {
    if (pattern.test(normalizedPath)) {
      errors.push('Advanced path traversal detected');
      break; // Only need to detect one
    }
  }

  // Check for dangerous characters and sequences (new)
  for (const pattern of FILE_VALIDATION_CONFIG.dangerousPathPatterns) {
    if (pattern.test(normalizedPath)) {
      errors.push('Dangerous characters detected in file path');
      break; // Only need to detect one
    }
  }
  
  // Check for absolute paths (should be relative) and URL schemes
  if (path.isAbsolute(normalizedPath) || 
      /^[a-zA-Z]:(\/|\\)/.test(normalizedPath) || // Windows absolute paths like C:/ or C:\
      /^\\\\/.test(normalizedPath) || // UNC paths
      /^(file|javascript|data):/i.test(normalizedPath) // URL schemes
  ) {
    errors.push('Absolute paths or URL schemes not allowed');
  }
  
  // Check for hidden files/directories (parts starting with '.' but not just '.' or '..')
  const pathParts = normalizedPath.split('/').filter(part => part !== ''); // Filter out empty strings from split
  if (pathParts.some(part => part.startsWith('.') && part !== '.' && part !== '..')) {
    errors.push('Hidden files/directories not allowed');
  }
  // NEW: Check for root-level hidden files like ".bashrc" if path starts with "."
  if (normalizedPath.startsWith('.') && normalizedPath !== '.' && normalizedPath !== '..') {
    errors.push('Hidden files/directories not allowed');
  }
  
  // Check for double extension (new)
  const filename = path.basename(normalizedPath);
  const filenameParts = filename.split('.');
  // More than 2 parts implies at least one "hidden" extension or multiple extensions
  // e.g., "archive.tar.gz" has 3 parts, "image.jpg.exe" has 3 parts
  // We allow "tar.gz" but block "jpg.exe". This check needs refinement with extension check.
  // For now, if the last part is a blocked extension and there are more than 2 parts,
  // it's a potential double extension attack.
  if (filenameParts.length > 2) {
    const primaryExtension = '.' + filenameParts[filenameParts.length - 1].toLowerCase();
    if (FILE_VALIDATION_CONFIG.blockedExtensions.includes(primaryExtension)) {
      errors.push(`Multiple file extensions detected with a dangerous extension: ${primaryExtension}`);
    }
  }

  // Check file extension (uses updated blockedExtensions from config)
  const extension = path.extname(normalizedPath).toLowerCase();
  if (FILE_VALIDATION_CONFIG.blockedExtensions.includes(extension)) {
    errors.push(`Blocked file extension: ${extension}`);
  }
  
  return {
    isValid: errors.length === 0,
    errors
  };
};

/**
 * Reads file signature (magic bytes) to determine actual file type (UPDATED buffer size)
 */
const getFileSignature = async (filePath: string): Promise<Buffer> => {
  let file;
  try {
    file = await fs.open(filePath, 'r');
    const buffer = Buffer.alloc(512); // Read more bytes for comprehensive analysis (increased from 16)
    const { bytesRead } = await file.read(buffer, 0, 512, 0);
    await file.close();
    return buffer.subarray(0, bytesRead); // Return only read bytes
  } catch (error) {
    if (file) await file.close(); // Ensure file handle is closed on error
    throw new Error('Unable to read file signature');
  }
};

/**
 * Validates file content based on signature (UPDATED)
 */
const validateFileSignature = async (filePath: string, expectedType?: string): Promise<{ 
  isValid: boolean; 
  actualType: string; 
  securityFlags: string[] 
}> => {
  const securityFlags: string[] = [];
  
  try {
    const signature = await getFileSignature(filePath);
    
    // Remove BOM if present before signature check
    let effectiveSignature = signature;
    if (signature.length >= 3 && signature[0] === 0xEF && signature[1] === 0xBB && signature[2] === 0xBF) {
      effectiveSignature = signature.subarray(3);
      securityFlags.push('BOM detected and skipped');
    }

    // Check against dangerous signatures (existing logic)
    for (const dangerous of FILE_VALIDATION_CONFIG.dangerousSignatures) {
      const sigBytes = dangerous.signature;
      if (effectiveSignature.length >= sigBytes.length) {
        const matches = sigBytes.every((byte, index) => effectiveSignature[index] === byte);
        
        if (matches) {
          securityFlags.push(`Dangerous file type detected: ${dangerous.description}`);
          return { isValid: false, actualType: 'unknown', securityFlags };
        }
      }
    }
    
    // Determine actual file type from signature (Expanded list from test file, plus existing)
    let actualType = 'unknown';
    const detectedSignatures: string[] = [];

    // Consolidated signature detection logic (from test file, combined with existing)
    const allSignatures = {
      // Images
      'image/jpeg': [[0xFF, 0xD8, 0xFF]],
      'image/png': [[0x89, 0x50, 0x4E, 0x47]],
      'image/gif': [[0x47, 0x49, 0x46, 0x38]],
      'image/bmp': [[0x42, 0x4D]],
      'image/webp': [[0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50]], // RIFF...WEBP
      // Documents
      'application/pdf': [[0x25, 0x50, 0x44, 0x46]],
      'application/zip': [[0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06]], // Local file header, Empty archive
      // Executables/Scripts (dangerous, also covered by dangerousSignatures config but good for explicit detection)
      'application/x-msdownload': [[0x4D, 0x5A]],                     // PE/DOS executable (MZ)
      'application/x-elf': [[0x7F, 0x45, 0x4C, 0x46]],               // ELF executable
      'application/x-mach-o': [[0xFE, 0xED, 0xFA, 0xCE]],             // Mach-O executable
      'application/x-rar-compressed': [[0x52, 0x61, 0x72, 0x21]],      // RAR archive
      'application/x-7z-compressed': [[0x37, 0x7A, 0xBC, 0xAF]],      // 7-Zip archive
      'text/html': [[0x3C, 0x68, 0x74, 0x6D, 0x6C], [0x3C, 0x48, 0x54, 0x4D, 0x4C]], // <html or <HTML
      'text/php': [[0x3C, 0x3F, 0x70, 0x68, 0x70]],                     // <?php
      // Consider adding more as needed
    };

    let polyglotDetected = false;
    let firstMatch = '';

    for (const [type, sigs] of Object.entries(allSignatures)) {
      for (const sig of sigs) {
        if (effectiveSignature.length >= sig.length) {
          const matches = sig.every((byte, index) => effectiveSignature[index] === byte);
          if (matches) {
            if (firstMatch === '') {
              firstMatch = type;
            } else if (firstMatch !== type) {
              polyglotDetected = true;
            }
            detectedSignatures.push(type);
          }
        }
      }
    }

    if (polyglotDetected) {
      securityFlags.push('Polyglot file detected');
      // For polyglot files, it's safer to mark as unknown or reject if not explicitly allowed
      actualType = 'unknown';
    } else if (firstMatch !== '') {
      actualType = firstMatch;
    }
    
    // Check for steganographic indicators (for images) - NEW
    if (actualType.startsWith('image/')) {
      const entropy = calculateEntropy(effectiveSignature); // Use effectiveSignature for entropy
      if (entropy > 7.8) { // High entropy might indicate hidden data, threshold can be tuned
        securityFlags.push('High entropy detected - possible steganography');
      }
    }

    // Check for ZIP bomb indicators - NEW
    if (actualType === 'application/zip') {
      securityFlags.push('Archive file detected - ZIP bomb risk (further content analysis recommended)');
    }
    
    // Validate against expected type (existing logic)
    if (expectedType && actualType !== expectedType && actualType !== 'unknown') {
      securityFlags.push(`File type mismatch: expected ${expectedType}, got ${actualType}`);
    }
    
    // Check if file type is allowed (existing logic)
    const isAllowedType = Object.keys(FILE_VALIDATION_CONFIG.allowedTypes).includes(actualType);
    if (!isAllowedType && actualType !== 'unknown') {
      securityFlags.push(`File type not allowed: ${actualType}`);
    }
    // If multiple dangerous signatures are detected, ensure it's marked invalid.
    if (securityFlags.some(flag => flag.startsWith('Dangerous file type detected'))) {
      return { isValid: false, actualType: 'unknown', securityFlags };
    }
    
    return {
      isValid: securityFlags.length === 0 && actualType !== 'unknown' && isAllowedType, // Ensure actualType is recognized and allowed
      actualType,
      securityFlags
    };
    
  } catch (error) {
    securityFlags.push('Unable to validate file content signature');
    return { isValid: false, actualType: 'unknown', securityFlags };
  }
};

/**
 * Validates file size (UPDATED for minFileSize)
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
    
    if (typeof fileSize !== 'number' || isNaN(fileSize)) {
      errors.push('Invalid file size information');
      return { isValid: false, size: 0, errors };
    }

    // Determine max size based on file category
    const typeConfig = Object.values(FILE_VALIDATION_CONFIG.allowedTypes)
      .find(config => Object.keys(FILE_VALIDATION_CONFIG.allowedTypes)
        .find(mime => FILE_VALIDATION_CONFIG.allowedTypes[mime as keyof typeof FILE_VALIDATION_CONFIG.allowedTypes] === config) === fileType);
    
    const category = typeConfig?.category || 'default';
    const maxSize = FILE_VALIDATION_CONFIG.maxFileSizes[category as keyof typeof FILE_VALIDATION_CONFIG.maxFileSizes] 
      || FILE_VALIDATION_CONFIG.maxFileSizes.default;
    
    const minFileSize = 1; // 1 byte minimum - NEW from test file

    if (fileSize > maxSize) {
      errors.push(`File too large: ${fileSize} bytes (max: ${maxSize} bytes)`);
    }
    
    // Modified from original `fileSize === 0` to `fileSize < minFileSize`
    if (fileSize < minFileSize) {
      errors.push(`File too small: ${fileSize} bytes (min: ${minFileSize} bytes)`);
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
 * Main file validation middleware (UPDATED for URL decoding and error handling)
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
    
    // Multi-level URL decoding to catch double/triple encoding attacks (NEW)
    let processedPath = filepath;
    let prevPath = '';
    let decodingAttempts = 0;

    try {
      while (processedPath !== prevPath && decodingAttempts < 5) { // Limit decoding attempts
        prevPath = processedPath;
        processedPath = decodeURIComponent(processedPath);
        decodingAttempts++;
      }
    } catch (error) {
      return next(ApiError.badRequest('Invalid URL encoding in file path', 'INVALID_ENCODING'));
    }

    // Check for suspicious multiple encoding (NEW)
    if (decodingAttempts > 2) {
      return next(ApiError.badRequest('Suspicious multiple URL encoding detected', 'SUSPICIOUS_ENCODING'));
    }

    // Step 1: Validate file path (uses updated validateFilePath)
    const pathValidation = validateFilePath(processedPath); // Use fully decoded path
    if (!pathValidation.isValid) {
      // Use specific error codes from pathValidation.errors if available or a general one
      const errorCode = pathValidation.errors.includes('Advanced path traversal detected') ? 'ADVANCED_PATH_TRAVERSAL' :
                      pathValidation.errors.includes('Dangerous characters detected in file path') ? 'DANGEROUS_CHARACTERS' :
                      pathValidation.errors.includes('Multiple file extensions detected with a dangerous extension') || pathValidation.errors.includes('Blocked file extension') ? 'DANGEROUS_EXTENSION' :
                      'INVALID_FILEPATH';
      return next(ApiError.badRequest(
        `Invalid file path: ${pathValidation.errors.join(', ')}`,
        errorCode
      ));
    }
    
    // Step 2: Get absolute file path
    let absolutePath: string | undefined;
    try {
      absolutePath = storageService.getAbsolutePath(processedPath);
      if (!absolutePath) {
        return next(ApiError.notFound('File not found (path resolution failed)', 'FILE_NOT_FOUND'));
      }
    } catch (error) {
      // Catching specific errors from storageService.getAbsolutePath might be useful here
      return next(ApiError.notFound('File not found (path resolution error)', 'FILE_NOT_FOUND'));
    }
    
    // Step 3: Check if file exists
    try {
      await fs.access(absolutePath);
    } catch (error) {
      return next(ApiError.notFound('File not found', 'FILE_NOT_FOUND'));
    }
    
    // Step 4: Validate file content (uses updated validateFileSignature)
    const contentValidation = await validateFileSignature(absolutePath);
    if (!contentValidation.isValid) {
      // Provide more specific error if available from securityFlags
      const errorCode = contentValidation.securityFlags.some(flag => flag.startsWith('Dangerous file type detected')) ? 'DANGEROUS_FILE_TYPE' :
                      contentValidation.securityFlags.includes('Polyglot file detected') ? 'POLYGLOT_FILE_DETECTED' :
                      contentValidation.securityFlags.includes('High entropy detected - possible steganography') ? 'POSSIBLE_STEGANOGRAPHY' :
                      contentValidation.securityFlags.includes('Archive file detected - ZIP bomb risk') ? 'ZIP_BOMB_RISK' :
                      contentValidation.actualType === 'unknown' ? 'UNKNOWN_FILE_TYPE' :
                      'INVALID_FILE_CONTENT';
      return next(ApiError.badRequest(
        `File validation failed: ${contentValidation.securityFlags.join(', ')}`,
        errorCode,
        { securityFlags: contentValidation.securityFlags }
      ));
    }
    
    // Step 5: Validate file size (uses updated validateFileSize)
    const sizeValidation = await validateFileSize(absolutePath, contentValidation.actualType);
    if (!sizeValidation.isValid) {
      const errorCode = sizeValidation.errors.includes('File too large') ? 'FILE_TOO_LARGE' :
                      sizeValidation.errors.includes('File too small') ? 'FILE_TOO_SMALL' :
                      'INVALID_FILE_SIZE';
      return next(ApiError.badRequest(
        `File size validation failed: ${sizeValidation.errors.join(', ')}`,
        errorCode
      ));
    }
    
    // Attach validation results to request
    req.fileValidation = {
      filepath, // Original filepath
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
    
    // Repeatedly decode URL to handle double encoding attacks (NEW - similar to advanced)
    let processedPath = filepath;
    let prevPath = '';
    let decodingAttempts = 0;
    try {
      while (processedPath !== prevPath && decodingAttempts < 5) {
        prevPath = processedPath;
        processedPath = decodeURIComponent(processedPath);
        decodingAttempts++;
      }
    } catch (error) {
      const validationError = new Error('Invalid URL encoding in file path');
      (validationError as any).statusCode = 400;
      (validationError as any).code = 'INVALID_ENCODING';
      return next(validationError);
    }
    // Check for suspicious multiple encoding (NEW)
    if (decodingAttempts > 2) {
      return next(ApiError.badRequest('Suspicious multiple URL encoding detected', 'SUSPICIOUS_ENCODING'));
    }

    // Basic path validation only on fully decoded path (uses updated validateFilePath)
    const pathValidation = validateFilePath(processedPath); // Use fully decoded path
    if (!pathValidation.isValid) {
      // Use specific error codes from pathValidation.errors if available or a general one
      const errorCode = pathValidation.errors.includes('Advanced path traversal detected') ? 'ADVANCED_PATH_TRAVERSAL' :
                      pathValidation.errors.includes('Dangerous characters detected in file path') ? 'DANGEROUS_CHARACTERS' :
                      pathValidation.errors.includes('Multiple file extensions detected with a dangerous extension') || pathValidation.errors.includes('Blocked file extension') ? 'DANGEROUS_EXTENSION' :
                      'INVALID_FILEPATH';
      return next(ApiError.badRequest(
        `Invalid file path: ${pathValidation.errors.join(', ')}`,
        errorCode
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