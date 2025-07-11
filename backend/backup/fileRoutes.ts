// /backend/src/routes/fileRoutes.ts
import { Router } from 'express';
import path from 'path';
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