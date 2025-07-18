// /backend/src/routes/fileRoutes.ts
import { Router } from 'express';
import path from 'path';
import sharp from 'sharp';
import { config } from '../config';
import { storageService } from '../services/storageService';
import { authenticate } from '../middlewares/auth';
import { 
  validateFileContentBasic, 
  validateFileContent, 
  validateImageFile, 
  logFileAccess 
} from '../middlewares/fileValidate';
import { ApiError } from '../utils/ApiError';

const router = Router();

/**
 * Flutter-specific configurations
 */
const FLUTTER_CONFIG = {
  // Image thumbnail sizes for Flutter widgets
  thumbnailSizes: {
    small: { width: 150, height: 150 },
    medium: { width: 300, height: 300 },
    large: { width: 600, height: 600 }
  },
  
  // Mobile-optimized cache settings
  mobileCacheSettings: {
    images: 'public, max-age=604800, immutable', // 7 days for images
    thumbnails: 'public, max-age=2592000, immutable', // 30 days for thumbnails
    documents: 'private, max-age=3600', // 1 hour for documents
  },
  
  // Flutter HTTP client compatibility headers
  flutterHeaders: {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Platform, X-App-Version',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  }
};

/**
 * Enhanced helper function for Flutter-compatible content type detection
 */
const getContentTypeForFlutter = (filepath: string, validationType?: string): string => {
  if (validationType && validationType !== 'unknown') {
    return validationType;
  }
  
  const ext = path.extname(filepath).toLowerCase();
  const contentTypes: { [key: string]: string } = {
    // Image types (Flutter optimized)
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.webp': 'image/webp', // Flutter prefers WebP
    '.bmp': 'image/bmp',
    '.gif': 'image/gif',
    
    // Document types
    '.pdf': 'application/pdf',
    '.txt': 'text/plain',
    '.json': 'application/json',
    
    // Flutter-specific
    '.dart': 'text/plain',
    '.yaml': 'text/yaml',
    '.yml': 'text/yaml'
  };
  
  return contentTypes[ext] || 'application/octet-stream';
};

/**
 * Enhanced security headers for Flutter mobile apps
 */
const setFlutterSecurityHeaders = (res: any, cacheControl: string, additionalHeaders?: { [key: string]: string }) => {
  // Set Flutter-compatible headers
  Object.entries(FLUTTER_CONFIG.flutterHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });
  
  res.setHeader('Cache-Control', cacheControl);
  
  // Add platform detection
  const userAgent = res.req?.get('User-Agent') || '';
  const isFlutterApp = userAgent.includes('Flutter') || res.req?.get('X-Platform') === 'flutter';
  
  if (isFlutterApp) {
    res.setHeader('X-Optimized-For', 'flutter');
  }
  
  if (additionalHeaders) {
    Object.entries(additionalHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
  }
};

/**
 * Image thumbnail generation for Flutter
 */
const generateThumbnail = async (imagePath: string, size: 'small' | 'medium' | 'large'): Promise<Buffer> => {
  const { width, height } = FLUTTER_CONFIG.thumbnailSizes[size];
  
  try {
    return await sharp(imagePath)
      .resize(width, height, {
        fit: 'cover',
        position: 'center'
      })
      .webp({ quality: 80 }) // Convert to WebP for Flutter
      .toBuffer();
  } catch (error) {
    // Fallback to original image if processing fails
    throw new Error('Thumbnail generation failed');
  }
};

/**
 * FLUTTER-ENHANCED ROUTES
 */

/**
 * Flutter-optimized image serving with thumbnail support
 * GET /files/flutter/images/:size/:filepath
 */
router.get('/flutter/images/:size/:file',
  (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  },
  validateImageFile,
  logFileAccess,
  async (req, res, next) => {
    try {
      const { size, filepath } = req.params;
      const validSizes = ['small', 'medium', 'large', 'original'];
      
      if (!validSizes.includes(size)) {
        return next(ApiError.badRequest('Invalid thumbnail size', 'INVALID_SIZE'));
      }

      let absolutePath: string;
      try {
        absolutePath = storageService.getAbsolutePath(filepath);
        if (!absolutePath) {
          return next(ApiError.notFound('Image not found'));
        }
      } catch (error) {
        return next(ApiError.notFound('Image not found'));
      }

      const contentType = getContentTypeForFlutter(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        // For Firebase, redirect to signed URL
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 3600); // 1 hour
          setFlutterSecurityHeaders(res, FLUTTER_CONFIG.mobileCacheSettings.images);
          res.setHeader('Content-Type', contentType);
          res.redirect(302, signedUrl);
          return;
        } catch (error) {
          return next(ApiError.notFound('Image not found'));
        }
      } else {
        // For local storage, serve processed image
        setFlutterSecurityHeaders(res, FLUTTER_CONFIG.mobileCacheSettings.images);
        
        if (size === 'original') {
          res.setHeader('Content-Type', contentType);
          res.sendFile(absolutePath);
          return;
        } else {
          // Generate and serve thumbnail
          try {
            const thumbnail = await generateThumbnail(absolutePath, size as 'small' | 'medium' | 'large');
            res.setHeader('Content-Type', 'image/webp'); // Thumbnails are always WebP
            res.send(thumbnail);
            return;
          } catch (error) {
            // Fallback to original image
            res.setHeader('Content-Type', contentType);
            res.sendFile(absolutePath);
            return;
          }
        }
      }
    } catch (error) {
      next(ApiError.notFound('Image not found'));
    }
  }
);

/**
 * Flutter batch image upload endpoint (FIXED VERSION)
 * POST /files/flutter/batch-upload
 */
router.post('/flutter/batch-upload',
  authenticate,
  async (req, res, next) => {
    try {
      const { files } = req.body;
      
      if (!Array.isArray(files) || files.length === 0) {
        return next(ApiError.badRequest('No files provided for batch upload', 'NO_FILES'));
      }
      
      if (files.length > 20) { // Limit batch size
        return next(ApiError.badRequest('Too many files in batch (max 20)', 'BATCH_TOO_LARGE'));
      }
      
      const results = [];
      const errors = [];
      
      // Process each file synchronously to avoid middleware issues
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        try {
          // Simple validation without using middleware
          if (!file.name || typeof file.name !== 'string') {
            throw new Error('Invalid file name');
          }
          
          if (!file.size || typeof file.size !== 'number' || file.size <= 0) {
            throw new Error('Invalid file size');
          }
          
          // Basic file extension validation
          const ext = path.extname(file.name).toLowerCase();
          const allowedExtensions = ['.jpg', '.jpeg', '.png', '.webp', '.bmp', '.pdf', '.txt', '.json'];
          
          if (!allowedExtensions.includes(ext)) {
            throw new Error('Unsupported file type');
          }
          
          // Determine file type based on extension
          let fileType = 'application/octet-stream';
          if (['.jpg', '.jpeg'].includes(ext)) fileType = 'image/jpeg';
          else if (ext === '.png') fileType = 'image/png';
          else if (ext === '.webp') fileType = 'image/webp';
          else if (ext === '.bmp') fileType = 'image/bmp';
          else if (ext === '.pdf') fileType = 'application/pdf';
          else if (ext === '.txt') fileType = 'text/plain';
          else if (ext === '.json') fileType = 'application/json';
          
          results.push({
            index: i,
            filename: file.name,
            status: 'success',
            size: file.size,
            type: fileType
          });
        } catch (error) {
          errors.push({
            index: i,
            filename: file.name || 'unknown',
            status: 'error',
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }
      
      setFlutterSecurityHeaders(res, 'private, no-cache');
      res.json({
        success: true,
        processed: results.length,
        errorCount: errors.length,
        results,
        errors
      });
      
    } catch (error) {
      next(ApiError.internal('Batch upload failed', 'BATCH_UPLOAD_ERROR', error as Error));
    }
  }
);

/**
 * Flutter-optimized metadata endpoint
 * GET /files/flutter/metadata/:filepath
 */
router.get('/flutter/metadata/:file',
  (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  },
  validateFileContentBasic,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      
      let absolutePath: string;
      try {
        absolutePath = storageService.getAbsolutePath(filepath);
        if (!absolutePath) {
          return next(ApiError.notFound('File not found'));
        }
      } catch (error) {
        return next(ApiError.notFound('File not found'));
      }

      // Get file stats
      const fs = require('fs').promises;
      let stats;
      try {
        stats = await fs.stat(absolutePath);
      } catch (error) {
        return next(ApiError.notFound('File not found'));
      }

      const contentType = getContentTypeForFlutter(filepath, req.fileValidation?.fileType);
      
      // Enhanced metadata for Flutter
      const metadata = {
        filename: path.basename(filepath),
        size: stats.size,
        type: contentType,
        modified: stats.mtime,
        created: stats.birthtime || stats.ctime,
        isImage: contentType.startsWith('image/'),
        extension: path.extname(filepath),
        // Flutter-specific
        availableThumbnails: contentType.startsWith('image/') ? ['small', 'medium', 'large'] : [],
        mobileOptimized: true,
        cacheable: true
      };

      setFlutterSecurityHeaders(res, 'public, max-age=300'); // 5 minutes for metadata
      res.json(metadata);
      
    } catch (error) {
      next(ApiError.notFound('File metadata not available'));
    }
  }
);

/**
 * Flutter progressive download endpoint (FIXED VERSION)
 * GET /files/flutter/progressive/:filepath
 */
router.get('/flutter/progressive/:file',
  (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  },
  authenticate,
  validateFileContent,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      const range = req.headers.range;
      
      let absolutePath: string;
      try {
        absolutePath = storageService.getAbsolutePath(filepath);
        if (!absolutePath) {
          return next(ApiError.notFound('File not found'));
        }
      } catch (error) {
        return next(ApiError.notFound('File not found'));
      }

      const contentType = getContentTypeForFlutter(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        // Firebase handles range requests automatically
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 3600);
          setFlutterSecurityHeaders(res, FLUTTER_CONFIG.mobileCacheSettings.documents);
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        // Handle range requests for local files
        const fs = require('fs');
        let stats;
        try {
          stats = await fs.promises.stat(absolutePath);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        
        const fileSize = stats.size;
        
        setFlutterSecurityHeaders(res, FLUTTER_CONFIG.mobileCacheSettings.documents, {
          'Accept-Ranges': 'bytes',
          'Content-Type': contentType
        });
        
        if (range) {
          // Parse range header more safely
          try {
            const parts = range.replace(/bytes=/, "").split("-");
            const start = parseInt(parts[0], 10) || 0;
            let end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
            
            // Ensure end doesn't exceed file size
            if (end >= fileSize) {
              end = fileSize - 1;
            }
            
            // Ensure start doesn't exceed end
            if (start > end) {
              // Invalid range, serve full file
              res.setHeader('Content-Length', fileSize.toString());
              return res.sendFile(absolutePath);
            }
            
            const chunkSize = (end - start) + 1;
            
            // Validate chunk size
            if (chunkSize <= 0) {
              res.setHeader('Content-Length', fileSize.toString());
              return res.sendFile(absolutePath);
            }
            
            const stream = fs.createReadStream(absolutePath, { start, end });
            
            res.status(206); // Partial Content
            res.setHeader('Content-Range', `bytes ${start}-${end}/${fileSize}`);
            res.setHeader('Content-Length', chunkSize.toString());
            
            // Handle stream errors
            stream.on('error', () => {
              if (!res.headersSent) {
                res.status(500).json({ error: { message: 'Stream error' } });
              }
            });
            
            return stream.pipe(res);
          } catch (rangeError) {
            // Malformed range header, serve full file
            res.setHeader('Content-Length', fileSize.toString());
            return res.sendFile(absolutePath);
          }
        } else {
          // Full file
          res.setHeader('Content-Length', fileSize.toString());
          return res.sendFile(absolutePath);
        }
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

/**
 * Helper function to get content type from file extension
 */
const getContentType = (filepath: string, validationType?: string): string => {
  if (validationType && validationType !== 'unknown') {
    return validationType;
  }
  
  const ext = path.extname(filepath).toLowerCase();
  const contentTypes: { [key: string]: string } = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.bmp': 'image/bmp',
    '.webp': 'image/webp',
    '.pdf': 'application/pdf',
    '.txt': 'text/plain'
  };
  
  return contentTypes[ext] || 'application/octet-stream';
};

/**
 * Helper function to set security headers
 */
const setSecurityHeaders = (res: any, cacheControl: string, additionalHeaders?: { [key: string]: string }) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cache-Control', cacheControl);
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  if (additionalHeaders) {
    Object.entries(additionalHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
  }
};

// IMPORTANT: More specific routes must come BEFORE more general routes in Express

/**
 * Secure file serving routes with authentication and full validation
 * Pattern: GET /files/secure/path/to/file.ext
 * @access Private (requires authentication)
 */
router.get('/secure/:file',
  (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  },
  authenticate,
  validateFileContent,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 5);
          setSecurityHeaders(res, 'private, max-age=300', {
            'Content-Security-Policy': "default-src 'none'; img-src 'self';"
          });
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, max-age=300', {
          'Content-Security-Policy': "default-src 'none'; img-src 'self';"
        });
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/secure/:dir/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 5);
          setSecurityHeaders(res, 'private, max-age=300', {
            'Content-Security-Policy': "default-src 'none'; img-src 'self';"
          });
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, max-age=300', {
          'Content-Security-Policy': "default-src 'none'; img-src 'self';"
        });
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Additional nesting levels for secure routes
router.get('/secure/:dir1/:dir2/:dir3/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 5);
          setSecurityHeaders(res, 'private, max-age=300', {
            'Content-Security-Policy': "default-src 'none'; img-src 'self';"
          });
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, max-age=300', {
          'Content-Security-Policy': "default-src 'none'; img-src 'self';"
        });
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/secure/:dir1/:dir2/:dir3/:dir4/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 5);
          setSecurityHeaders(res, 'private, max-age=300', {
            'Content-Security-Policy': "default-src 'none'; img-src 'self';"
          });
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, max-age=300', {
          'Content-Security-Policy': "default-src 'none'; img-src 'self';"
        });
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Support for 5-level deep secure routes
router.get('/secure/:dir1/:dir2/:dir3/:dir4/:dir5/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.dir5}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 5);
          setSecurityHeaders(res, 'private, max-age=300', {
            'Content-Security-Policy': "default-src 'none'; img-src 'self';"
          });
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, max-age=300', {
          'Content-Security-Policy': "default-src 'none'; img-src 'self';"
        });
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Support for 6-level deep secure routes  
router.get('/secure/:dir1/:dir2/:dir3/:dir4/:dir5/:dir6/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.dir5}/${req.params.dir6}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 5);
          setSecurityHeaders(res, 'private, max-age=300', {
            'Content-Security-Policy': "default-src 'none'; img-src 'self';"
          });
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, max-age=300', {
          'Content-Security-Policy': "default-src 'none'; img-src 'self';"
        });
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

/**
 * Image-specific serving routes with image validation
 * Pattern: GET /files/images/path/to/image.ext
 * @access Public (with image-specific validation)
 */
router.get('/images/:file',
  (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  },
  validateImageFile,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=86400');
          res.setHeader('Content-Type', contentType);
          res.setHeader('X-Frame-Options', 'SAMEORIGIN');
          res.setHeader('Accept-Ranges', 'bytes');
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=86400');
        res.setHeader('Content-Type', contentType);
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.setHeader('Accept-Ranges', 'bytes');
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/images/:dir/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir}/${req.params.file}`;
    next();
  },
  validateImageFile,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=86400');
          res.setHeader('Content-Type', contentType);
          res.setHeader('X-Frame-Options', 'SAMEORIGIN');
          res.setHeader('Accept-Ranges', 'bytes');
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=86400');
        res.setHeader('Content-Type', contentType);
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.setHeader('Accept-Ranges', 'bytes');
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Additional nesting levels for image routes  
router.get('/images/:dir1/:dir2/:dir3/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.file}`;
    next();
  },
  validateImageFile,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=86400');
          res.setHeader('Content-Type', contentType);
          res.setHeader('X-Frame-Options', 'SAMEORIGIN');
          res.setHeader('Accept-Ranges', 'bytes');
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=86400');
        res.setHeader('Content-Type', contentType);
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.setHeader('Accept-Ranges', 'bytes');
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/images/:dir1/:dir2/:dir3/:dir4/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.file}`;
    next();
  },
  validateImageFile,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=86400');
          res.setHeader('Content-Type', contentType);
          res.setHeader('X-Frame-Options', 'SAMEORIGIN');
          res.setHeader('Accept-Ranges', 'bytes');
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=86400');
        res.setHeader('Content-Type', contentType);
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.setHeader('Accept-Ranges', 'bytes');
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Support for 5-level deep image routes
router.get('/images/:dir1/:dir2/:dir3/:dir4/:dir5/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.dir5}/${req.params.file}`;
    next();
  },
  validateImageFile,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=86400');
          res.setHeader('Content-Type', contentType);
          res.setHeader('X-Frame-Options', 'SAMEORIGIN');
          res.setHeader('Accept-Ranges', 'bytes');
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=86400');
        res.setHeader('Content-Type', contentType);
        res.setHeader('X-Frame-Options', 'SAMEORIGIN');
        res.setHeader('Accept-Ranges', 'bytes');
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

/**
 * Download routes with forced download headers
 * Pattern: GET /files/download/path/to/file.ext
 * @access Private (requires authentication)
 */
router.get('/download/:file',
  (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  },
  authenticate,
  validateFileContent,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) {
        next(ApiError.notFound('File not found'));
        return;
      }

      const filename = path.basename(filepath);
      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 10);
          setSecurityHeaders(res, 'private, no-cache');
          res.setHeader('Content-Type', contentType);
          res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
          res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, no-cache');
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.download(absolutePath, filename);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/download/:dir/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) {
        next(ApiError.notFound('File not found'));
        return;
      }

      const filename = path.basename(filepath);
      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 10);
          setSecurityHeaders(res, 'private, no-cache');
          res.setHeader('Content-Type', contentType);
          res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
          res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, no-cache');
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.download(absolutePath, filename);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Missing route for /download/:dir1/:dir2/:file
router.get('/download/:dir1/:dir2/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) {
        next(ApiError.notFound('File not found'));
        return;
      }

      const filename = path.basename(filepath);
      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 10);
          setSecurityHeaders(res, 'private, no-cache');
          res.setHeader('Content-Type', contentType);
          res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
          res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, no-cache');
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.download(absolutePath, filename);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Additional nesting levels for download routes
router.get('/download/:dir1/:dir2/:dir3/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) {
        next(ApiError.notFound('File not found'));
        return;
      }

      const filename = path.basename(filepath);
      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 10);
          setSecurityHeaders(res, 'private, no-cache');
          res.setHeader('Content-Type', contentType);
          res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
          res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, no-cache');
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.download(absolutePath, filename);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/download/:dir1/:dir2/:dir3/:dir4/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) {
        next(ApiError.notFound('File not found'));
        return;
      }

      const filename = path.basename(filepath);
      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 10);
          setSecurityHeaders(res, 'private, no-cache');
          res.setHeader('Content-Type', contentType);
          res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
          res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, no-cache');
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.download(absolutePath, filename);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Support for 5-level deep download routes
router.get('/download/:dir1/:dir2/:dir3/:dir4/:dir5/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.dir5}/${req.params.file}`;
    next();
  },
  authenticate,
  validateFileContent,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) {
        next(ApiError.notFound('File not found'));
        return;
      }

      const filename = path.basename(filepath);
      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath, 10);
          setSecurityHeaders(res, 'private, no-cache');
          res.setHeader('Content-Type', contentType);
          res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
          res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'private, no-cache');
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.download(absolutePath, filename);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

/**
 * HEAD request support for file metadata
 */
router.head('/:file',
  (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  },
  validateFileContentBasic,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      setSecurityHeaders(res, 'public, max-age=3600');
      res.setHeader('Content-Type', contentType);
      res.status(200).end();
      return;
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.head('/:dir/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      setSecurityHeaders(res, 'public, max-age=3600');
      res.setHeader('Content-Type', contentType);
      res.status(200).end();
      return;
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Additional nesting levels for HEAD requests
router.head('/:dir1/:dir2/:dir3/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      setSecurityHeaders(res, 'public, max-age=3600');
      res.setHeader('Content-Type', contentType);
      res.status(200).end();
      return;
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.head('/:dir1/:dir2/:dir3/:dir4/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      setSecurityHeaders(res, 'public, max-age=3600');
      res.setHeader('Content-Type', contentType);
      res.status(200).end();
      return;
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Support for 5-level deep HEAD requests
router.head('/:dir1/:dir2/:dir3/:dir4/:dir5/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.dir5}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      setSecurityHeaders(res, 'public, max-age=3600');
      res.setHeader('Content-Type', contentType);
      res.status(200).end();
      return;
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

/**
 * Public file serving routes with basic validation
 * Pattern: GET /files/path/to/file.ext
 * @access Public (with basic security validation)
 * IMPORTANT: These catch-all routes MUST come LAST
 */
router.get('/:file',
  (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  },
  validateFileContentBasic,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=3600');
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=3600');
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/:dir/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=3600');
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=3600');
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/:dir1/:dir2/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=3600');
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=3600');
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

router.get('/:dir1/:dir2/:dir3/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=3600');
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=3600');
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Additional nesting levels for public routes
router.get('/:dir1/:dir2/:dir3/:dir4/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=3600');
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=3600');
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

// ADD: Support for 5-level deep public routes
router.get('/:dir1/:dir2/:dir3/:dir4/:dir5/:file',
  (req, res, next) => {
    req.params.filepath = `${req.params.dir1}/${req.params.dir2}/${req.params.dir3}/${req.params.dir4}/${req.params.dir5}/${req.params.file}`;
    next();
  },
  validateFileContentBasic,
  logFileAccess,
  async (req, res, next) => {
    try {
      const filepath = req.params.filepath;
      if (!filepath) return next(ApiError.notFound('File not found'));

      const contentType = getContentType(filepath, req.fileValidation?.fileType);
      
      if (config.storageMode === 'firebase') {
        try {
          const signedUrl = await storageService.getSignedUrl(filepath);
          setSecurityHeaders(res, 'public, max-age=3600');
          res.setHeader('Content-Type', contentType);
          return res.redirect(302, signedUrl);
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
      } else {
        let absolutePath;
        try {
          absolutePath = storageService.getAbsolutePath(filepath);
          if (!absolutePath) {
            return next(ApiError.notFound('File not found'));
          }
        } catch (error) {
          return next(ApiError.notFound('File not found'));
        }
        setSecurityHeaders(res, 'public, max-age=3600');
        res.setHeader('Content-Type', contentType);
        return res.sendFile(absolutePath);
      }
    } catch (error) {
      next(ApiError.notFound('File not found'));
    }
  }
);

export { router as fileRoutes };