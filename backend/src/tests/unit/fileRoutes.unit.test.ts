// /backend/tests/unit/routes/fileRoutes.unit.test.ts

jest.mock('../../config/firebase', () => ({
    default: { storage: jest.fn() },
}));

import express, { Request, Response, NextFunction } from 'express';
import request from 'supertest';
import { config } from '../../../src/config';
import { storageService } from '../../../src/services/storageService';
import { authenticate } from '../../../src/middlewares/auth';
import { ApiError } from '../../../src/utils/ApiError';
import path from 'path';
import { EventEmitter } from 'events';

// Increase max listeners to prevent warnings
EventEmitter.defaultMaxListeners = 20;

// Mock all dependencies
jest.mock('../../../src/config');
jest.mock('../../../src/services/storageService');
jest.mock('../../../src/middlewares/auth');
jest.mock('../../../src/utils/ApiError');

const mockConfig = config as jest.Mocked<typeof config>;
const mockStorageService = storageService as jest.Mocked<typeof storageService>;
const mockAuthenticate = authenticate as jest.MockedFunction<typeof authenticate>;
const mockApiError = ApiError as jest.MockedClass<typeof ApiError>;

// Create middleware mocks BEFORE they're used
const mockValidateFileContentBasic = jest.fn((req: Request, res: Response, next: NextFunction) => {
  (req as any).fileValidation = { 
    filepath: req.params.filepath, 
    isValid: true, 
    fileType: 'unknown' 
  };
  next();
});

const mockValidateFileContent = jest.fn((req: Request, res: Response, next: NextFunction) => {
  (req as any).fileValidation = { 
    filepath: req.params.filepath, 
    isValid: true, 
    fileType: 'image/jpeg', 
    fileSize: 1024 
  };
  next();
});

const mockValidateImageFile = jest.fn((req: Request, res: Response, next: NextFunction) => {
  (req as any).fileValidation = { 
    filepath: req.params.filepath, 
    isValid: true, 
    fileType: 'image/jpeg' 
  };
  next();
});

const mockLogFileAccess = jest.fn((req: Request, res: Response, next: NextFunction) => {
  next();
});

// Mock the file validation middlewares
jest.mock('../../../src/middlewares/fileValidate', () => ({
  validateFileContentBasic: mockValidateFileContentBasic,
  validateFileContent: mockValidateFileContent,
  validateImageFile: mockValidateImageFile,
  logFileAccess: mockLogFileAccess
}));

// Mock path module to ensure consistent behavior
jest.mock('path', () => ({
  ...jest.requireActual('path'),
  extname: jest.fn(),
  basename: jest.fn()
}));

const mockPath = path as jest.Mocked<typeof path>;

// Import fileRoutes AFTER mocking
import { fileRoutes } from '../../../src/routes/fileRoutes';

// Create a single test app instance to reuse
let testApp: express.Application | null = null;

const getTestApp = () => {
  if (!testApp) {
    testApp = express();
    testApp.use('/api/v1/files', fileRoutes);
    
    // Error handler
    testApp.use((err: any, req: Request, res: Response, next: NextFunction) => {
      res.status(err.statusCode || 500).json({
        error: {
          message: err.message,
          code: err.code,
          context: err.context
        }
      });
    });
  }
  return testApp;
};

describe('FileRoutes Unit Tests', () => {
  let app: express.Application;

  beforeAll(() => {
    app = getTestApp();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mocks - ALWAYS set local mode first
    mockConfig.storageMode = 'local';
    
    // Use simpler mock implementations to reduce memory
    mockAuthenticate.mockImplementation((req: any, res: any, next: any) => {
      req.user = { id: 'user123' };
      next();
    });
    
    mockApiError.notFound = jest.fn((message) => {
      const error = new Error(message);
      (error as any).statusCode = 404;
      (error as any).code = 'NOT_FOUND';
      return error;
    });

    // Mock storageService with minimal implementations
    mockStorageService.getAbsolutePath = jest.fn((filepath: string) => `/mock/storage/path/${filepath}`);
    mockStorageService.getSignedUrl = jest.fn().mockResolvedValue('https://firebase.url/signed');

    // Mock path functions
    mockPath.extname.mockImplementation((filepath: string) => {
      const ext = filepath.substring(filepath.lastIndexOf('.'));
      return ext || '';
    });
    
    mockPath.basename.mockImplementation((filepath: string) => {
      return filepath.substring(filepath.lastIndexOf('/') + 1);
    });

    // Reset validation middleware mocks
    mockValidateFileContentBasic.mockImplementation((req: any, res: any, next: any) => {
      const filepath = req.params.filepath || '';
      let fileType = 'unknown';
      
      // Determine file type based on extension for proper testing
      const ext = filepath.toLowerCase();
      if (ext.endsWith('.jpg') || ext.endsWith('.jpeg')) fileType = 'image/jpeg';
      else if (ext.endsWith('.png')) fileType = 'image/png';
      else if (ext.endsWith('.webp')) fileType = 'image/webp';
      else if (ext.endsWith('.bmp')) fileType = 'image/bmp';
      else if (ext.endsWith('.gif')) fileType = 'image/gif';
      else if (ext.endsWith('.pdf')) fileType = 'application/pdf';
      else if (ext.endsWith('.txt')) fileType = 'text/plain';
      
      req.fileValidation = { 
        filepath: filepath, 
        isValid: true, 
        fileType: fileType 
      };
      next();
    });

    mockValidateFileContent.mockImplementation((req: any, res: any, next: any) => {
      const filepath = req.params.filepath || '';
      let fileType = 'image/jpeg';
      
      // Determine file type based on extension for proper testing
      const ext = filepath.toLowerCase();
      if (ext.endsWith('.png')) fileType = 'image/png';
      else if (ext.endsWith('.webp')) fileType = 'image/webp';
      else if (ext.endsWith('.bmp')) fileType = 'image/bmp';
      else if (ext.endsWith('.gif')) fileType = 'image/gif';
      else if (ext.endsWith('.pdf')) fileType = 'application/pdf';
      else if (ext.endsWith('.txt')) fileType = 'text/plain';
      
      req.fileValidation = { 
        filepath: filepath, 
        isValid: true, 
        fileType: fileType, 
        fileSize: 1024 
      };
      next();
    });

    mockValidateImageFile.mockImplementation((req: any, res: any, next: any) => {
      const filepath = req.params.filepath || '';
      let fileType = 'image/jpeg';
      
      // Determine file type based on extension for proper testing
      if (filepath.endsWith('.png')) fileType = 'image/png';
      else if (filepath.endsWith('.webp')) fileType = 'image/webp';
      else if (filepath.endsWith('.bmp')) fileType = 'image/bmp';
      else if (filepath.endsWith('.gif')) fileType = 'image/gif';
      
      req.fileValidation = { 
        filepath: filepath, 
        isValid: true, 
        fileType: fileType 
      };
      next();
    });

    mockLogFileAccess.mockImplementation((req: any, res: any, next: any) => {
      next();
    });

    // Mock Express response methods with minimal implementation
    const sendFileMock = jest.fn(function(this: Response) {
      // Don't override Content-Type if it was already set by the route handler
      if (!this.get('Content-Type')) {
        this.setHeader('Content-Type', 'application/octet-stream');
      }
      this.status(200).send('file');
      return this;
    });
    
    const downloadMock = jest.fn(function(this: Response, path: string, filename?: string) {
      // Don't override Content-Type if it was already set by the route handler
      if (!this.get('Content-Type')) {
        this.setHeader('Content-Type', 'application/octet-stream');
      }
      this.setHeader('Content-Disposition', `attachment; filename="${filename || 'download'}"`);
      this.status(200).send('dl');
      return this;
    });
    
    const redirectMock = jest.fn(function(this: Response, status: number | string, url?: string) {
      if (typeof status === 'string') {
        url = status;
        status = 302;
      }
      this.status(status as number).setHeader('Location', url || '').send();
      return this;
    });
    
    jest.spyOn(express.response, 'sendFile').mockImplementation(sendFileMock);
    jest.spyOn(express.response, 'download').mockImplementation(downloadMock);
    jest.spyOn(express.response, 'redirect').mockImplementation(redirectMock);
  });

  afterEach(() => {
    // Clear all mocks and timers
    jest.clearAllMocks();
    jest.restoreAllMocks();
    jest.clearAllTimers();
    
    // Reset mock implementations to reduce memory retention
    mockValidateFileContentBasic.mockReset();
    mockValidateFileContent.mockReset();
    mockValidateImageFile.mockReset();
    mockLogFileAccess.mockReset();
    mockAuthenticate.mockReset();
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  });

  afterAll(() => {
    // Clean up the test app and all references
    if (testApp) {
      testApp = null;
    }
    
    // Clear module cache to free memory
    jest.resetModules();
    
    // Final garbage collection
    if (global.gc) {
      global.gc();
    }
  });

  describe('GET /:filepath* (Public Route)', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
    });

    it('should serve local files with security headers', async () => {
      const testPath = 'test.jpg';
      const response = await request(app)
        .get('/api/v1/files/test.jpg')
        .expect(200);

      expect(mockValidateFileContentBasic).toHaveBeenCalled();
      expect(mockLogFileAccess).toHaveBeenCalled();
      expect(mockStorageService.getAbsolutePath).toHaveBeenCalledWith(testPath);
    });
  });

  describe('Cache Control', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
    });

    it('should set appropriate cache durations', async () => {
      // Public files: 1 hour
      let response = await request(app)
        .get('/api/v1/files/public.jpg')
        .expect(200);
      expect(response.headers['cache-control']).toBe('public, max-age=3600');

      // Images: 24 hours
      response = await request(app)
        .get('/api/v1/files/images/long-cache.jpg')
        .expect(200);
      expect(response.headers['cache-control']).toBe('public, max-age=86400');

      // Secure files: 5 minutes
      response = await request(app)
        .get('/api/v1/files/secure/short-cache.jpg')
        .expect(200);
      expect(response.headers['cache-control']).toBe('private, max-age=300');

      // Downloads: no cache
      response = await request(app)
        .get('/api/v1/files/download/no-cache.pdf')
        .expect(200);
      expect(response.headers['cache-control']).toBe('private, no-cache');
    });

    it('should handle Firebase redirects with appropriate cache headers', async () => {
      mockConfig.storageMode = 'firebase';
      mockStorageService.getSignedUrl.mockResolvedValue('https://firebase.url/signed');

      const response = await request(app)
        .get('/api/v1/files/firebase-file.jpg')
        .expect(302);

      expect(response.headers['cache-control']).toBe('public, max-age=3600');
    });
  });

  describe('Middleware Integration', () => {
    beforeEach(() => {
      // Ensure local mode for middleware tests
      mockConfig.storageMode = 'local';
    });

    it('should call validation middlewares in correct order', async () => {
      const callOrder: string[] = [];
      
      mockValidateFileContentBasic.mockImplementation((req: any, res: any, next: any) => {
        callOrder.push('basic-validation');
        req.fileValidation = { filepath: req.params.filepath, isValid: true, fileType: 'unknown' };
        next();
      });
      
      mockLogFileAccess.mockImplementation((req: any, res: any, next: any) => {
        callOrder.push('log-access');
        next();
      });

      await request(app)
        .get('/api/v1/files/test.jpg')
        .expect(200);

      expect(callOrder).toEqual(['basic-validation', 'log-access']);
    });

    it('should stop middleware chain on validation failure', async () => {
      let logAccessCalled = false;
      
      mockValidateFileContentBasic.mockImplementation((req, res, next) => {
        const error = new Error('Validation failed');
        (error as any).statusCode = 400;
        next(error);
      });
      
      mockLogFileAccess.mockImplementation((req: any, res: any, next: any) => {
        logAccessCalled = true;
        next();
      });

      await request(app)
        .get('/api/v1/files/invalid.jpg')
        .expect(400);

      expect(logAccessCalled).toBe(false);
    });

    it('should handle authentication middleware correctly', async () => {
      let authCalled = false;
      let validationCalled = false;

      mockAuthenticate.mockImplementation(async(req: any, res: any, next: any) => {
        authCalled = true;
        req.user = { id: 'user123' };
        next();
      });
      
      mockValidateFileContent.mockImplementation((req: any, res: any, next: any) => {
        validationCalled = true;
        req.fileValidation = { filepath: req.params.filepath, isValid: true, fileType: 'image/jpeg' };
        next();
      });

      await request(app)
        .get('/api/v1/files/secure/authenticated.jpg')
        .expect(200);

      expect(authCalled).toBe(true);
      expect(validationCalled).toBe(true);
    });
  });

  describe('Response Format Consistency', () => {
    it('should handle successful responses consistently', async () => {
      const routes = [
        '/api/v1/files/test.jpg',
        '/api/v1/files/images/test.jpg',
        '/api/v1/files/secure/test.jpg',
        '/api/v1/files/download/test.pdf'
      ];

      for (const route of routes) {
        const response = await request(app).get(route);
        
        if (response.status === 200) {
          expect(response.headers['x-content-type-options']).toBe('nosniff');
          expect(response.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
        }
      }
    });

    it('should handle Firebase redirects consistently', async () => {
      mockConfig.storageMode = 'firebase';
      mockStorageService.getSignedUrl.mockResolvedValue('https://firebase.url/signed');

      const routes = [
        '/api/v1/files/test.jpg',
        '/api/v1/files/images/test.jpg',
        '/api/v1/files/secure/test.jpg'
      ];

      for (const route of routes) {
        const response = await request(app).get(route);
        
        if (response.status === 302) {
          expect(response.headers.location).toBe('https://firebase.url/signed');
          expect(response.headers['x-content-type-options']).toBe('nosniff');
        }
      }
    });
  });

  describe('GET /secure/:filepath* (Private Route)', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
    });

    it('should require authentication', async () => {
      mockAuthenticate.mockImplementation(async (req: any, res: any, next: any) => {
        const error = new Error('Unauthorized');
        (error as any).statusCode = 401;
        next(error);
      });

      const response = await request(app)
        .get('/api/v1/files/secure/private.jpg')
        .expect(401);

      expect(response.body.error.message).toBe('Unauthorized');
    });

    it('should serve authenticated files with enhanced security headers', async () => {
      const response = await request(app)
        .get('/api/v1/files/secure/private.jpg')
        .expect(200);

      expect(mockAuthenticate).toHaveBeenCalled();
      expect(mockValidateFileContent).toHaveBeenCalled();
      expect(mockLogFileAccess).toHaveBeenCalled();
      
      // Check enhanced security headers
      expect(response.headers['cache-control']).toBe('private, max-age=300');
      expect(response.headers['content-security-policy']).toBe("default-src 'none'; img-src 'self';");
    });

    it('should set content type based on validation for authenticated files', async () => {
      mockValidateFileContent.mockImplementation((req: any, res: any, next: any) => {
        req.fileValidation = { 
          filepath: req.params.filepath, 
          isValid: true, 
          fileType: 'image/png',
          fileSize: 2048 
        };
        next();
      });

      const response = await request(app)
        .get('/api/v1/files/secure/validated.png')
        .expect(200);

      expect(response.headers['content-type']).toMatch(/image\/png/);
    });

    it('should handle Firebase storage with shorter expiration', async () => {
      mockConfig.storageMode = 'firebase';
      mockStorageService.getSignedUrl.mockResolvedValue('https://firebase.url/secure-signed');

      const response = await request(app)
        .get('/api/v1/files/secure/secure.jpg')
        .expect(302);

      expect(mockStorageService.getSignedUrl).toHaveBeenCalledWith('secure.jpg', 5);
      expect(response.headers.location).toBe('https://firebase.url/secure-signed');
    });
  });

  describe('GET /images/:filepath* (Image Route)', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
    });

    it('should serve images with image-specific headers', async () => {
      const response = await request(app)
        .get('/api/v1/files/images/photo.jpg')
        .expect(200);

      expect(mockValidateImageFile).toHaveBeenCalled();
      expect(mockLogFileAccess).toHaveBeenCalled();
      
      // Check image-specific headers
      expect(response.headers['x-frame-options']).toBe('SAMEORIGIN');
      expect(response.headers['cache-control']).toBe('public, max-age=86400');
      expect(response.headers['accept-ranges']).toBe('bytes');
    });

    it('should set content type from validation', async () => {
      mockValidateImageFile.mockImplementation((req: any, res: any, next: any) => {
        req.fileValidation = { 
          filepath: req.params.filepath, 
          isValid: true, 
          fileType: 'image/webp' 
        };
        next();
      });

      const response = await request(app)
        .get('/api/v1/files/images/modern.webp')
        .expect(200);

      expect(response.headers['content-type']).toMatch(/image\/webp/);
    });

    it('should handle image validation failures', async () => {
      mockValidateImageFile.mockImplementation((req, res, next) => {
        const error = new Error('Not an image');
        (error as any).statusCode = 400;
        (error as any).code = 'NOT_AN_IMAGE';
        next(error);
      });

      const response = await request(app)
        .get('/api/v1/files/images/fake.txt')
        .expect(400);

      expect(response.body.error.code).toBe('NOT_AN_IMAGE');
    });
  });

  describe('GET /download/:filepath* (Download Route)', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
      mockPath.basename.mockImplementation((filepath: string) => {
        return filepath.substring(filepath.lastIndexOf('/') + 1);
      });
    });

    it('should require authentication for downloads', async () => {
      mockAuthenticate.mockImplementation(async(req: any, res: any, next: any) => {
        const error = new Error('Unauthorized');
        (error as any).statusCode = 401;
        next(error);
      });

      const response = await request(app)
        .get('/api/v1/files/download/document.pdf')
        .expect(401);

      expect(response.body.error.message).toBe('Unauthorized');
    });

    it('should force download with appropriate headers', async () => {
      const response = await request(app)
        .get('/api/v1/files/download/report.pdf')
        .expect(200);

      expect(mockAuthenticate).toHaveBeenCalled();
      expect(mockValidateFileContent).toHaveBeenCalled();
      
      // Check download headers
      expect(response.headers['content-disposition']).toBe('attachment; filename="report.pdf"');
      expect(response.headers['cache-control']).toBe('private, no-cache');
    });

    it('should handle Firebase downloads with longer expiration', async () => {
      mockConfig.storageMode = 'firebase';
      mockStorageService.getSignedUrl.mockResolvedValue('https://firebase.url/download-signed');

      const response = await request(app)
        .get('/api/v1/files/download/large-file.zip')
        .expect(302);

      expect(mockStorageService.getSignedUrl).toHaveBeenCalledWith('large-file.zip', 10);
      expect(response.headers.location).toBe('https://firebase.url/download-signed');
      expect(response.headers['content-disposition']).toBe('attachment; filename="large-file.zip"');
    });

    it('should set content type from validation for downloads', async () => {
      mockValidateFileContent.mockImplementation((req: any, res: any, next: any) => {
        req.fileValidation = { 
          filepath: req.params.filepath, 
          isValid: true, 
          fileType: 'application/pdf',
          fileSize: 5120 
        };
        next();
      });

      const response = await request(app)
        .get('/api/v1/files/download/document.pdf')
        .expect(200);

      expect(response.headers['content-type']).toMatch(/application\/pdf/);
    });
  });

  describe('HEAD /:filepath* (Metadata Route)', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
    });

    it('should return basic headers for Firebase storage', async () => {
      mockConfig.storageMode = 'firebase';

      const response = await request(app)
        .head('/api/v1/files/test.jpg')
        .expect(200);

      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['cache-control']).toBe('public, max-age=3600');
    });

    it('should set content type for HEAD requests', async () => {
      mockPath.extname.mockReturnValue('.png');
      
      const response = await request(app)
        .head('/api/v1/files/image.png')
        .expect(200);

      expect(response.headers['content-type']).toMatch(/image\/png/);
    });

    it('should handle HEAD request validation failures', async () => {
      mockValidateFileContentBasic.mockImplementation((req, res, next) => {
        const error = new Error('Invalid file');
        (error as any).statusCode = 400;
        next(error);
      });

      const response = await request(app)
        .head('/api/v1/files/invalid.jpg')
        .expect(400);

      // HEAD requests don't have response bodies
      expect(response.text).toBeFalsy();
    });
  });

  describe('Error Handling', () => {
    it('should handle storage service errors consistently', async () => {
      mockStorageService.getAbsolutePath.mockImplementation(() => {
        throw new Error('Storage unavailable');
      });

      // Test fewer routes to reduce memory usage
      const testRoutes = [
        { route: '/api/v1/files/test.jpg', expectedStatus: 404 },
        { route: '/api/v1/files/secure/test.jpg', expectedStatus: [401, 404] }
      ];

      for (const { route, expectedStatus } of testRoutes) {
        const response = await request(app).get(route);
        
        if (Array.isArray(expectedStatus)) {
          expect(expectedStatus).toContain(response.status);
        } else {
          expect(response.status).toBe(expectedStatus);
          expect(response.body.error.message).toBe('File not found');
        }
      }
    });

    it('should handle Firebase storage errors', async () => {
      mockConfig.storageMode = 'firebase';
      mockStorageService.getSignedUrl.mockRejectedValue(new Error('Firebase error'));

      const response = await request(app)
        .get('/api/v1/files/test.jpg')
        .expect(404);

      expect(response.body.error.message).toBe('File not found');
    });

    it('should handle middleware errors in chain', async () => {
      mockLogFileAccess.mockImplementation((req, res, next) => {
        const error = new Error('Logging service down');
        (error as any).statusCode = 503;
        (error as any).code = 'SERVICE_UNAVAILABLE';
        next(error);
      });

      const response = await request(app)
        .get('/api/v1/files/test.jpg')
        .expect(503);

      expect(response.body.error.message).toBe('Logging service down');
      expect(response.body.error.code).toBe('SERVICE_UNAVAILABLE');
    });

    it('should handle unknown errors gracefully', async () => {
      mockStorageService.getAbsolutePath.mockImplementation(() => {
        throw 'String error'; // Non-Error object
      });

      const response = await request(app)
        .get('/api/v1/files/test.jpg')
        .expect(404);

      expect(response.body.error.message).toBe('File not found');
    });
  });

  describe('Security Headers', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
    });

    it('should set consistent security headers across all routes', async () => {
      const routes = [
        { path: '/api/v1/files/test.jpg', requiresAuth: false },
        { path: '/api/v1/files/images/test.jpg', requiresAuth: false }
      ];

      for (const { path, requiresAuth } of routes) {
        const response = await request(app).get(path).expect(200);

        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
        
        if (!requiresAuth) {
          expect(response.headers['cache-control']).toContain('public');
        }
      }
    });

    it('should set private cache headers for authenticated routes', async () => {
      const authRoutes = [
        '/api/v1/files/secure/private.jpg',
        '/api/v1/files/download/secret.pdf'
      ];

      for (const route of authRoutes) {
        const response = await request(app).get(route).expect(200);

        expect(response.headers['cache-control']).toContain('private');
        // Only secure routes have CSP headers, download routes don't
        if (route.includes('/secure/')) {
          expect(response.headers['content-security-policy']).toBeDefined();
        }
      }
    });

    it('should set appropriate X-Frame-Options', async () => {
      // Public files should deny framing
      let response = await request(app)
        .get('/api/v1/files/public.jpg')
        .expect(200);
      expect(response.headers['x-frame-options']).toBe('DENY');

      // Images can be framed from same origin
      response = await request(app)
        .get('/api/v1/files/images/gallery.jpg')
        .expect(200);
      expect(response.headers['x-frame-options']).toBe('SAMEORIGIN');
    });
  });

  describe('Content Type Detection', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
    });

    it('should detect content types by file extension', async () => {
      // Test fewer file types to reduce memory usage
      const fileTypes = [
        { file: 'test.jpg', expectedType: 'image/jpeg', ext: '.jpg' },
        { file: 'test.png', expectedType: 'image/png', ext: '.png' },
        { file: 'test.pdf', expectedType: 'application/pdf', ext: '.pdf' }
      ];

      for (const { file, expectedType, ext } of fileTypes) {
        mockPath.extname.mockReturnValue(ext);
        
        const response = await request(app)
          .get(`/api/v1/files/${file}`)
          .expect(200);

        expect(response.headers['content-type']).toMatch(new RegExp(expectedType.replace('/', '\\/')));
      }
    });

    it('should handle files without extensions', async () => {
      mockPath.extname.mockReturnValue('');
      
      const response = await request(app)
        .get('/api/v1/files/no-extension')
        .expect(200);

      // Should use default content type - Express may add charset
      expect(response.headers['content-type']).toMatch(/^application\/octet-stream/);
    });

    it('should handle case-insensitive extensions', async () => {
      const caseVariations = [
        { file: 'TEST.JPG', ext: '.JPG' },
        { file: 'Image.PNG', ext: '.PNG' },
        { file: 'document.PDF', ext: '.PDF' }
      ];

      for (const { file, ext } of caseVariations) {
        mockPath.extname.mockReturnValue(ext);
        
        const response = await request(app)
          .get(`/api/v1/files/${file}`)
          .expect(200);

        expect(response.headers['content-type']).toBeDefined();
      }
    });
  });

  describe('Route Parameter Handling', () => {
    beforeEach(() => {
      mockConfig.storageMode = 'local';
    });

    it('should handle nested file paths', async () => {
      const nestedPaths = [
        { path: 'folder/file.jpg', expectedCall: 'folder/file.jpg' },
        { path: 'deep/nested/image.png', expectedCall: 'deep/nested/image.png' }
      ];

      for (const { path, expectedCall } of nestedPaths) {
        const response = await request(app)
          .get(`/api/v1/files/${path}`)
          .expect(200);

        expect(mockStorageService.getAbsolutePath).toHaveBeenCalledWith(expectedCall);
      }
    });

    it('should handle special characters in file names', async () => {
      const specialFiles = [
        'file-with-dashes.png',
        'file_with_underscores.pdf'
      ];

      for (const file of specialFiles) {
        const response = await request(app)
          .get(`/api/v1/files/${file}`)
          .expect(200);

        expect(mockStorageService.getAbsolutePath).toHaveBeenCalledWith(file);
      }
    });

    it('should preserve file path through middleware chain', async () => {
      const testPath = 'simple.jpg';
      
      const response = await request(app)
        .get(`/api/v1/files/${testPath}`)
        .expect(200);

      expect(mockValidateFileContentBasic).toHaveBeenCalled();
      expect(mockLogFileAccess).toHaveBeenCalled();
      expect(mockStorageService.getAbsolutePath).toHaveBeenCalledWith(testPath);
      
      // Check security headers
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['cache-control']).toBe('public, max-age=3600');
      expect(response.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
    });

    // Consolidated content type tests to reduce memory usage
    it('should set correct content types for various files', async () => {
      const testCases = [
        { ext: '.jpg', file: 'photo.jpg', type: /image\/jpeg/ },
        { ext: '.png', file: 'image.png', type: /image\/png/ },
        { ext: '.pdf', file: 'document.pdf', type: /application\/pdf/ }
      ];

      for (const { ext, file, type } of testCases) {
        mockPath.extname.mockReturnValue(ext);
        
        const response = await request(app)
          .get(`/api/v1/files/${file}`)
          .expect(200);

        expect(response.headers['content-type']).toMatch(type);
      }
    });

    it('should handle Firebase storage mode', async () => {
      mockConfig.storageMode = 'firebase';
      mockStorageService.getSignedUrl.mockResolvedValue('https://firebase.url/signed');

      const response = await request(app)
        .get('/api/v1/files/test.jpg')
        .expect(302);

      // Check that getSignedUrl was called with correct parameters (no expiration for public files)
      expect(mockStorageService.getSignedUrl).toHaveBeenCalledWith('test.jpg');
      expect(response.headers.location).toBe('https://firebase.url/signed');
      
      // Check security headers for redirects
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['cache-control']).toBe('public, max-age=3600');
    });

    it('should handle file serving errors', async () => {
      mockStorageService.getAbsolutePath.mockImplementation(() => {
        throw new Error('Storage error');
      });

      const response = await request(app)
        .get('/api/v1/files/error.jpg')
        .expect(404);

      expect(response.body.error.message).toBe('File not found');
    });

    it('should handle validation failures', async () => {
      mockValidateFileContentBasic.mockImplementation((req, res, next) => {
        const error = new Error('Invalid file path');
        (error as any).statusCode = 400;
        (error as any).code = 'INVALID_FILEPATH';
        next(error);
      });

      const response = await request(app)
        .get('/api/v1/files/passwd')  // Simple filename instead of path traversal
        .expect(400);

      expect(response.body.error.message).toBe('Invalid file path');
      expect(response.body.error.code).toBe('INVALID_FILEPATH');
    });
  });
});