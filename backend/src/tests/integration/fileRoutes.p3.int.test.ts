// src/tests/integration/fileRoutes.p3.int.test.ts
import request from 'supertest';
import express from 'express';
import path from 'path';
import fs from 'fs/promises';
import sharp from 'sharp';
import { fileRoutes } from '../../routes/fileRoutes';
import { config } from '../../config';
import { storageService } from '../../services/storageService';

// Mock authentication middleware
jest.mock('../../middlewares/auth', () => ({
  authenticate: (req: any, res: any, next: any) => {
    if (req.headers.authorization === 'Bearer test-token-123') {
      req.user = { id: 'test-user', email: 'test@example.com' };
      next();
    } else {
      const error = new Error('Unauthorized') as any;
      error.statusCode = 401;
      next(error);
    }
  }
}));

// Mock file validation middleware
jest.mock('../../middlewares/fileValidate', () => ({
  validateFileContentBasic: (req: any, res: any, next: any) => {
    const filepath = req.params.filepath || req.params.file;
    req.fileValidation = { 
      fileType: getFileTypeFromPath(filepath),
      isValid: true,
      securityCheck: 'passed'
    };
    next();
  },
  validateFileContent: (req: any, res: any, next: any) => {
    const filepath = req.params.filepath || req.params.file;
    req.fileValidation = { 
      fileType: getFileTypeFromPath(filepath),
      isValid: true,
      securityCheck: 'passed'
    };
    next();
  },
  validateImageFile: (req: any, res: any, next: any) => {
    const filepath = req.params.filepath || req.params.file;
    
    // Block malicious files
    if (filepath?.includes('..') || filepath?.endsWith('.exe') || filepath?.endsWith('.js') || filepath?.endsWith('.php')) {
      const error = new Error('Invalid file type') as any;
      error.statusCode = 400;
      error.code = 'INVALID_FILE_TYPE';
      return next(error);
    }
    
    req.fileValidation = { 
      fileType: getFileTypeFromPath(filepath),
      isValid: true,
      securityCheck: 'passed'
    };
    next();
  },
  logFileAccess: (req: any, res: any, next: any) => next()
}));

// Mock config
jest.mock('../../config', () => ({
  config: {
    storageMode: 'local',
    uploadsDir: '/tmp/test-uploads'
  }
}));

// Helper function to determine file type from path
function getFileTypeFromPath(filepath: string): string {
  if (!filepath) return 'application/octet-stream';
  
  const ext = filepath.toLowerCase();
  if (ext.includes('.jpg') || ext.includes('.jpeg')) return 'image/jpeg';
  if (ext.includes('.png')) return 'image/png';
  if (ext.includes('.webp')) return 'image/webp';
  if (ext.includes('.gif')) return 'image/gif';
  if (ext.includes('.bmp')) return 'image/bmp';
  if (ext.includes('.pdf')) return 'application/pdf';
  if (ext.includes('.txt')) return 'text/plain';
  if (ext.includes('.json')) return 'application/json';
  if (ext.includes('.dart')) return 'text/plain';
  if (ext.includes('.yaml') || ext.includes('.yml')) return 'text/yaml';
  return 'application/octet-stream';
}

describe('Flutter Routes Integration Tests', () => {
  let app: express.Application;
  let testFilesDir: string;
  const authTokenValue = 'Bearer test-token-123';

  const TEST_FILES = {
    jpeg: 'test-image.jpg',
    png: 'test-image.png',
    webp: 'test-image.webp',
    pdf: 'test-document.pdf',
    txt: 'test-document.txt',
    dart: 'main.dart',
    yaml: 'pubspec.yaml'
  };

  beforeAll(async () => {
    // Setup test app
    app = express();
    app.use(express.json());
    app.use('/files', fileRoutes);
    
    // Error handler
    app.use((error: any, req: any, res: any, next: any) => {
      const statusCode = error.statusCode || error.status || 500;
      res.status(statusCode).json({
        error: {
          message: error.message || 'Internal Server Error',
          code: error.code || 'INTERNAL_ERROR'
        }
      });
    });

    // Setup test directory
    testFilesDir = path.join(__dirname, '../../../test-files-integration');
    await fs.mkdir(testFilesDir, { recursive: true });

    // Create test files
    await createTestFiles();

    // Mock storage service to use test directory
    jest.spyOn(storageService, 'getAbsolutePath').mockImplementation((filepath) => {
      if (!filepath) return '';
      
      // Block malicious paths
      if (filepath.includes('..') || filepath.includes('etc/passwd') || filepath.includes('system32')) {
        return '';
      }
      
      const fullPath = path.join(testFilesDir, filepath);
      return fullPath;
    });

    // Mock getSignedUrl for Firebase tests
    jest.spyOn(storageService, 'getSignedUrl').mockImplementation(async (filepath, expiry = 3600) => {
      return `https://firebase.storage.googleapis.com/signed-url/${filepath}?expires=${Date.now() + expiry * 1000}`;
    });
  });

  afterAll(async () => {
    // Cleanup test files
    try {
      await fs.rm(testFilesDir, { recursive: true, force: true });
    } catch (error) {
      console.warn('Failed to cleanup test files:', error);
    }
    
    // Restore mocks
    jest.restoreAllMocks();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  async function createTestFiles() {
    // Create a simple test JPEG image (100x100 pixel)
    const jpegBuffer = await sharp({
      create: {
        width: 100,
        height: 100,
        channels: 3,
        background: { r: 255, g: 0, b: 0 }
      }
    }).jpeg().toBuffer();
    
    // Create a simple test PNG image
    const pngBuffer = await sharp({
      create: {
        width: 100,
        height: 100,
        channels: 4,
        background: { r: 0, g: 255, b: 0, alpha: 1 }
      }
    }).png().toBuffer();

    // Create a WebP image
    const webpBuffer = await sharp({
      create: {
        width: 100,
        height: 100,
        channels: 3,
        background: { r: 0, g: 0, b: 255 }
      }
    }).webp().toBuffer();

    // Write test files
    await fs.writeFile(path.join(testFilesDir, TEST_FILES.jpeg), jpegBuffer);
    await fs.writeFile(path.join(testFilesDir, TEST_FILES.png), pngBuffer);
    await fs.writeFile(path.join(testFilesDir, TEST_FILES.webp), webpBuffer);
    await fs.writeFile(path.join(testFilesDir, TEST_FILES.pdf), 'Mock PDF content');
    await fs.writeFile(path.join(testFilesDir, TEST_FILES.txt), 'Mock text content');
    await fs.writeFile(path.join(testFilesDir, TEST_FILES.dart), 'void main() { print("Hello Flutter!"); }');
    await fs.writeFile(path.join(testFilesDir, TEST_FILES.yaml), 'name: test_app\nversion: 1.0.0');
  }

  describe('Flutter Image Serving with Real Files', () => {
    describe('Original Image Serving', () => {
      it('should serve original JPEG images with proper headers', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/original/${TEST_FILES.jpeg}`)
          .expect(200);

        expect(response.headers['content-type']).toBe('image/jpeg');
        expect(response.headers['cache-control']).toBe('public, max-age=604800, immutable');
        expect(response.headers['access-control-allow-origin']).toBe('*');
        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['x-frame-options']).toBe('DENY');
        expect(response.body).toBeDefined();
      });

      it('should serve original PNG images', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/original/${TEST_FILES.png}`)
          .expect(200);

        expect(response.headers['content-type']).toBe('image/png');
        expect(response.headers['cache-control']).toContain('immutable');
      });

      it('should serve original WebP images', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/original/${TEST_FILES.webp}`)
          .expect(200);

        expect(response.headers['content-type']).toBe('image/webp');
      });
    });

    describe('Real Thumbnail Generation', () => {
      it('should generate small thumbnails using Sharp', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/small/${TEST_FILES.jpeg}`)
          .expect(200);

        expect(response.headers['content-type']).toBe('image/webp');
        expect(response.body).toBeDefined();
        expect(response.body.length).toBeGreaterThan(0);

        // Verify the thumbnail is actually a valid WebP image
        const metadata = await sharp(response.body).metadata();
        expect(metadata.format).toBe('webp');
        expect(metadata.width).toBe(150);
        expect(metadata.height).toBe(150);
      });

      it('should generate medium thumbnails with correct dimensions', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/medium/${TEST_FILES.png}`)
          .expect(200);

        expect(response.headers['content-type']).toBe('image/webp');
        
        const metadata = await sharp(response.body).metadata();
        expect(metadata.format).toBe('webp');
        expect(metadata.width).toBe(300);
        expect(metadata.height).toBe(300);
      });

      it('should generate large thumbnails with correct dimensions', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/large/${TEST_FILES.jpeg}`)
          .expect(200);

        expect(response.headers['content-type']).toBe('image/webp');
        
        const metadata = await sharp(response.body).metadata();
        expect(metadata.format).toBe('webp');
        expect(metadata.width).toBe(600);
        expect(metadata.height).toBe(600);
      });

      it('should fallback to original when Sharp processing fails', async () => {
        // Create a corrupted image file
        const corruptedPath = path.join(testFilesDir, 'corrupted.jpg');
        await fs.writeFile(corruptedPath, 'not-an-image');

        const response = await request(app)
          .get('/files/flutter/images/small/corrupted.jpg')
          .expect(200);

        // Should fallback to original file type
        expect(response.headers['content-type']).toBe('image/jpeg');
      });

      it('should handle concurrent thumbnail generation efficiently', async () => {
        const startTime = Date.now();
        
        const requests = [
          request(app).get(`/files/flutter/images/small/${TEST_FILES.jpeg}`),
          request(app).get(`/files/flutter/images/medium/${TEST_FILES.jpeg}`),
          request(app).get(`/files/flutter/images/large/${TEST_FILES.jpeg}`),
          request(app).get(`/files/flutter/images/small/${TEST_FILES.png}`),
          request(app).get(`/files/flutter/images/medium/${TEST_FILES.png}`)
        ];

        const responses = await Promise.all(requests);
        const endTime = Date.now();

        // All requests should succeed
        responses.forEach(response => {
          expect(response.status).toBe(200);
          expect(response.headers['content-type']).toBe('image/webp');
        });

        // Should complete within reasonable time
        expect(endTime - startTime).toBeLessThan(10000); // 10 seconds
      });
    });

    describe('Platform Detection', () => {
      it('should detect Flutter platform from User-Agent', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/original/${TEST_FILES.jpeg}`)
          .set('User-Agent', 'Dart/2.17 (dart:io) Flutter/3.0')
          .expect(200);

        expect(response.headers['x-optimized-for']).toBe('flutter');
      });

      it('should detect Flutter platform from X-Platform header', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/original/${TEST_FILES.jpeg}`)
          .set('X-Platform', 'flutter')
          .set('X-App-Version', '1.0.0')
          .expect(200);

        expect(response.headers['x-optimized-for']).toBe('flutter');
      });

      it('should not set optimization header for non-Flutter clients', async () => {
        const response = await request(app)
          .get(`/files/flutter/images/original/${TEST_FILES.jpeg}`)
          .set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
          .expect(200);

        expect(response.headers['x-optimized-for']).toBeUndefined();
      });
    });
  });

  describe('Flutter Batch Upload Integration', () => {
    it('should process batch upload validation successfully', async () => {
      const files = [
        { name: 'upload1.jpg', size: 2048 },
        { name: 'upload2.png', size: 1536 },
        { name: 'document.pdf', size: 4096 }
      ];

      const response = await request(app)
        .post('/files/flutter/batch-upload')
        .set('Authorization', authTokenValue)
        .send({ files })
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.processed).toBe(3);
      expect(response.body.errorCount).toBe(0);
      expect(response.body.results).toHaveLength(3);

      // Verify file type detection
      expect(response.body.results[0].type).toBe('image/jpeg');
      expect(response.body.results[1].type).toBe('image/png');
      expect(response.body.results[2].type).toBe('application/pdf');

      // Verify Flutter headers
      expect(response.headers['cache-control']).toBe('private, no-cache');
      expect(response.headers['access-control-allow-origin']).toBe('*');
    });

    it('should handle batch upload with validation errors', async () => {
      const files = [
        { name: 'valid.jpg', size: 1024 },
        { name: 'invalid.exe', size: 2048 },
        { name: '', size: 1024 }, // Invalid name
        { name: 'zerosizefile.jpg', size: 0 }, // Invalid size
        { name: 'valid2.pdf', size: 3072 }
      ];

      const response = await request(app)
        .post('/files/flutter/batch-upload')
        .set('Authorization', authTokenValue)
        .send({ files })
        .expect(200);

      expect(response.body.processed).toBe(2); // Only valid files
      expect(response.body.errorCount).toBe(3); // Three invalid files
      expect(response.body.errors).toHaveLength(3);

      // Check specific error reasons
      const errorMessages = response.body.errors.map((e: any) => e.error);
      expect(errorMessages).toContain('Unsupported file type');
      expect(errorMessages).toContain('Invalid file name');
      expect(errorMessages).toContain('Invalid file size');
    });

    it('should enforce batch size limits', async () => {
      const files = Array.from({ length: 25 }, (_, i) => ({
        name: `file${i}.jpg`,
        size: 1024
      }));

      const response = await request(app)
        .post('/files/flutter/batch-upload')
        .set('Authorization', authTokenValue)
        .send({ files })
        .expect(400);

      expect(response.body.error.message).toBe('Too many files in batch (max 20)');
      expect(response.body.error.code).toBe('BATCH_TOO_LARGE');
    });

    it('should require authentication for batch upload', async () => {
      const files = [{ name: 'test.jpg', size: 1024 }];

      const response = await request(app)
        .post('/files/flutter/batch-upload')
        .send({ files })
        .expect(401);

      expect(response.body.error.message).toBe('Unauthorized');
    });
  });

  describe('Flutter Metadata Integration', () => {
    it('should return comprehensive metadata for real images', async () => {
      const response = await request(app)
        .get(`/files/flutter/metadata/${TEST_FILES.jpeg}`)
        .expect(200);

      expect(response.body).toMatchObject({
        filename: TEST_FILES.jpeg,
        type: 'image/jpeg',
        isImage: true,
        extension: '.jpg',
        availableThumbnails: ['small', 'medium', 'large'],
        mobileOptimized: true,
        cacheable: true
      });

      expect(response.body.size).toBeGreaterThan(0);
      expect(new Date(response.body.modified)).toBeInstanceOf(Date);
      expect(new Date(response.body.created)).toBeInstanceOf(Date);
    });

    it('should return metadata for Flutter-specific files', async () => {
      const testCases = [
        { file: TEST_FILES.dart, expectedType: 'text/plain' },
        { file: TEST_FILES.yaml, expectedType: 'text/yaml' }
      ];

      for (const testCase of testCases) {
        const response = await request(app)
          .get(`/files/flutter/metadata/${testCase.file}`)
          .expect(200);

        expect(response.body.type).toBe(testCase.expectedType);
        expect(response.body.isImage).toBe(false);
        expect(response.body.availableThumbnails).toEqual([]);
        expect(response.body.mobileOptimized).toBe(true);
      }
    });

    it('should handle metadata for non-existent files', async () => {
      const response = await request(app)
        .get('/files/flutter/metadata/nonexistent.jpg')
        .expect(404);

      expect(response.body.error.message).toBe('File not found');
    });
  });

  describe('Firebase Storage Integration', () => {
    beforeEach(() => {
      // Mock Firebase mode
      (config as any).storageMode = 'firebase';
    });

    afterEach(() => {
      // Reset to local mode
      (config as any).storageMode = 'local';
    });

    it('should redirect to Firebase signed URLs for images', async () => {
      const response = await request(app)
        .get(`/files/flutter/images/original/${TEST_FILES.jpeg}`)
        .expect(302);

      expect(response.headers.location).toContain('firebase.storage.googleapis.com');
      expect(response.headers.location).toContain(TEST_FILES.jpeg);
      // Firebase redirects don't set content-type, just location header
      expect(response.headers.location).toBeDefined();
    });

    it('should handle Firebase errors gracefully', async () => {
      // Mock Firebase error
      jest.spyOn(storageService, 'getSignedUrl').mockRejectedValueOnce(
        new Error('Firebase unavailable')
      );

      const response = await request(app)
        .get(`/files/flutter/images/original/${TEST_FILES.jpeg}`)
        .expect(404);

      expect(response.body.error.message).toBe('Image not found');
    });
  });

  describe('End-to-End Flutter Workflows', () => {
    it('should complete full image workflow: metadata → thumbnail → original', async () => {
      const filename = TEST_FILES.jpeg;

      // 1. Get metadata first
      const metadataResponse = await request(app)
        .get(`/files/flutter/metadata/${filename}`)
        .expect(200);

      expect(metadataResponse.body.isImage).toBe(true);
      expect(metadataResponse.body.availableThumbnails).toContain('small');

      // 2. Get thumbnail
      const thumbnailResponse = await request(app)
        .get(`/files/flutter/images/small/${filename}`)
        .expect(200);

      expect(thumbnailResponse.headers['content-type']).toBe('image/webp');
      const thumbnailMetadata = await sharp(thumbnailResponse.body).metadata();
      expect(thumbnailMetadata.width).toBe(150);

      // 3. Get original image
      const originalResponse = await request(app)
        .get(`/files/flutter/images/original/${filename}`)
        .expect(200);

      expect(originalResponse.headers['content-type']).toBe('image/jpeg');
      const originalMetadata = await sharp(originalResponse.body).metadata();
      expect(originalMetadata.width).toBe(100); // Our test image is 100x100
    });

    it('should handle mobile app simulation workflow', async () => {
      const mobileHeaders = {
        'User-Agent': 'MyApp/1.0 Flutter/3.0 (android)',
        'X-Platform': 'flutter',
        'X-App-Version': '1.0.0',
        'Accept': 'image/webp,image/*,*/*'
      };

      // 1. App requests metadata
      const metadataResponse = await request(app)
        .get(`/files/flutter/metadata/${TEST_FILES.png}`)
        .set(mobileHeaders)
        .expect(200);

      expect(metadataResponse.headers['x-optimized-for']).toBe('flutter');

      // 2. App requests thumbnail for list view
      const thumbnailResponse = await request(app)
        .get(`/files/flutter/images/small/${TEST_FILES.png}`)
        .set(mobileHeaders)
        .expect(200);

      expect(thumbnailResponse.headers['content-type']).toBe('image/webp');
      expect(thumbnailResponse.headers['x-optimized-for']).toBe('flutter');

      // 3. App requests medium image for detail view
      const detailResponse = await request(app)
        .get(`/files/flutter/images/medium/${TEST_FILES.png}`)
        .set(mobileHeaders)
        .expect(200);

      expect(detailResponse.headers['content-type']).toBe('image/webp');
      expect(detailResponse.headers['cache-control']).toContain('immutable');
    });
  });

  describe('Security Integration', () => {
    it('should reject malicious file paths', async () => {
      const maliciousPaths = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
      ];

      for (const maliciousPath of maliciousPaths) {
        const response = await request(app)
          .get(`/files/flutter/images/original/${maliciousPath}`);

        // Should be blocked (either 400 or 404 is acceptable security response)
        expect([400, 404]).toContain(response.status);
        
        // If it's a 400 error, should have error object; if 404, may not have error object
        if (response.status === 400) {
          expect(response.body.error).toBeDefined();
        }
        // The important thing is that the malicious path was blocked
        expect(response.status).not.toBe(200);
      }
    });

    it('should validate file types in batch upload', async () => {
      const maliciousFiles = [
        { name: 'script.js', size: 1024 },
        { name: 'malware.exe', size: 2048 },
        { name: 'config.php', size: 512 }
      ];

      const response = await request(app)
        .post('/files/flutter/batch-upload')
        .set('Authorization', authTokenValue)
        .send({ files: maliciousFiles })
        .expect(200);

      expect(response.body.processed).toBe(0);
      expect(response.body.errorCount).toBe(3);
      expect(response.body.errors.every((e: any) => e.error === 'Unsupported file type')).toBe(true);
    });

    it('should handle invalid thumbnail sizes', async () => {
      const response = await request(app)
        .get(`/files/flutter/images/invalid/${TEST_FILES.jpeg}`)
        .expect(400);

      expect(response.body.error.message).toBe('Invalid thumbnail size');
      expect(response.body.error.code).toBe('INVALID_SIZE');
    });
  });

  describe('Performance and Load Testing', () => {
    it('should generate thumbnails within acceptable time limits', async () => {
      const startTime = Date.now();
      
      const response = await request(app)
        .get(`/files/flutter/images/large/${TEST_FILES.jpeg}`)
        .expect(200);
      
      const endTime = Date.now();
      const processingTime = endTime - startTime;
      
      expect(response.headers['content-type']).toBe('image/webp');
      expect(processingTime).toBeLessThan(3000); // Should complete within 3 seconds
    });

    it('should handle multiple file types efficiently', async () => {
      const startTime = Date.now();
      
      const requests = [
        request(app).get(`/files/flutter/images/medium/${TEST_FILES.jpeg}`),
        request(app).get(`/files/flutter/images/medium/${TEST_FILES.png}`),
        request(app).get(`/files/flutter/images/medium/${TEST_FILES.webp}`),
        request(app).get(`/files/flutter/metadata/${TEST_FILES.pdf}`),
        request(app).get(`/files/flutter/metadata/${TEST_FILES.txt}`)
      ];

      const responses = await Promise.all(requests);
      const endTime = Date.now();
      
      // All should succeed
      responses.forEach(response => {
        expect(response.status).toBe(200);
      });
      
      // Should complete within reasonable time
      expect(endTime - startTime).toBeLessThan(5000); // 5 seconds for all
    });

    it('should handle concurrent batch uploads', async () => {
      const createBatch = (batchId: number) => Array.from({ length: 3 }, (_, i) => ({
        name: `batch${batchId}_file${i}.jpg`,
        size: 1024
      }));

      const requests = [
        request(app).post('/files/flutter/batch-upload').set('Authorization', authTokenValue).send({ files: createBatch(1) }),
        request(app).post('/files/flutter/batch-upload').set('Authorization', authTokenValue).send({ files: createBatch(2) }),
        request(app).post('/files/flutter/batch-upload').set('Authorization', authTokenValue).send({ files: createBatch(3) })
      ];

      const responses = await Promise.all(requests);

      responses.forEach((response, index) => {
        expect(response.status).toBe(200);
        expect(response.body.processed).toBe(3);
        expect(response.body.errorCount).toBe(0);
      });
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle corrupted image files gracefully', async () => {
      // Create a file that looks like an image but isn't
      const corruptedFile = 'corrupted-image.jpg';
      await fs.writeFile(path.join(testFilesDir, corruptedFile), 'This is not an image file');

      const response = await request(app)
        .get(`/files/flutter/images/small/${corruptedFile}`)
        .expect(200);

      // Should fallback to serving the original "image" 
      expect(response.headers['content-type']).toBe('image/jpeg');
    });

    it('should handle large file requests', async () => {
      // Test with a larger image
      const largeImageBuffer = await sharp({
        create: {
          width: 500,
          height: 500,
          channels: 3,
          background: { r: 128, g: 128, b: 128 }
        }
      }).jpeg().toBuffer();
      
      await fs.writeFile(path.join(testFilesDir, 'large-image.jpg'), largeImageBuffer);

      const response = await request(app)
        .get('/files/flutter/images/original/large-image.jpg')
        .timeout(10000) // 10 second timeout
        .expect(200);

      // Verify it's larger than our small test images
      expect(response.body.length).toBeGreaterThan(1000);
      expect(response.headers['content-type']).toBe('image/jpeg');
    });
  });

  describe('Cache Behavior Validation', () => {
    it('should set proper cache headers for different content types', async () => {
      // Image cache headers
      const imageResponse = await request(app)
        .get(`/files/flutter/images/original/${TEST_FILES.jpeg}`)
        .expect(200);
      
      expect(imageResponse.headers['cache-control']).toBe('public, max-age=604800, immutable');

      // Thumbnail cache headers  
      const thumbnailResponse = await request(app)
        .get(`/files/flutter/images/small/${TEST_FILES.jpeg}`)
        .expect(200);
      
      expect(thumbnailResponse.headers['cache-control']).toBe('public, max-age=604800, immutable');

      // Metadata cache headers
      const metadataResponse = await request(app)
        .get(`/files/flutter/metadata/${TEST_FILES.jpeg}`)
        .expect(200);
      
      expect(metadataResponse.headers['cache-control']).toBe('public, max-age=300');

      // Batch upload cache headers
      const batchResponse = await request(app)
        .post('/files/flutter/batch-upload')
        .set('Authorization', authTokenValue)
        .send({ files: [{ name: 'test.jpg', size: 1024 }] })
        .expect(200);
      
      expect(batchResponse.headers['cache-control']).toBe('private, no-cache');
    });
  });

  describe('Cross-Platform Compatibility', () => {
    it('should serve different formats based on client capabilities', async () => {
      const filename = TEST_FILES.jpeg;

      // Flutter client (gets thumbnails as WebP)
      const flutterResponse = await request(app)
        .get(`/files/flutter/images/small/${filename}`)
        .set('User-Agent', 'Flutter/3.0')
        .set('Accept', 'image/webp,image/*')
        .expect(200);

      expect(flutterResponse.headers['content-type']).toBe('image/webp');

      // Legacy client (gets original)
      const legacyResponse = await request(app)
        .get(`/files/flutter/images/original/${filename}`)
        .set('User-Agent', 'OldBrowser/1.0')
        .set('Accept', 'image/jpeg,image/*')
        .expect(200);

      expect(legacyResponse.headers['content-type']).toBe('image/jpeg');
    });

    it('should handle CORS for different origins', async () => {
      const corsOrigins = [
        'http://localhost:3000',
        'https://myapp.com',
        'https://staging.myapp.com'
      ];

      for (const origin of corsOrigins) {
        const response = await request(app)
          .get(`/files/flutter/images/original/${TEST_FILES.jpeg}`)
          .set('Origin', origin)
          .expect(200);

        expect(response.headers['access-control-allow-origin']).toBe('*');
        expect(response.headers['access-control-allow-methods']).toContain('GET');
      }
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle very small images correctly', async () => {
      // Create a 1x1 pixel image
      const tinyBuffer = await sharp({
        create: {
          width: 1,
          height: 1,
          channels: 3,
          background: { r: 255, g: 255, b: 255 }
        }
      }).jpeg().toBuffer();
      
      await fs.writeFile(path.join(testFilesDir, 'tiny.jpg'), tinyBuffer);

      const response = await request(app)
        .get('/files/flutter/images/small/tiny.jpg')
        .expect(200);

      expect(response.headers['content-type']).toBe('image/webp');
      
      // Should still generate 150x150 thumbnail (upscaling)
      const metadata = await sharp(response.body).metadata();
      expect(metadata.width).toBe(150);
      expect(metadata.height).toBe(150);
    });

    it('should handle files with special characters in names', async () => {
      const specialFile = 'test-file_name (1).jpg';
      const buffer = await sharp({
        create: {
          width: 50,
          height: 50,
          channels: 3,
          background: { r: 100, g: 100, b: 100 }
        }
      }).jpeg().toBuffer();
      
      await fs.writeFile(path.join(testFilesDir, specialFile), buffer);

      const response = await request(app)
        .get(`/files/flutter/images/original/${encodeURIComponent(specialFile)}`)
        .expect(200);

      expect(response.headers['content-type']).toBe('image/jpeg');
    });

    it('should handle metadata for zero-byte files', async () => {
      const emptyFile = 'empty.txt';
      await fs.writeFile(path.join(testFilesDir, emptyFile), '');

      const response = await request(app)
        .get(`/files/flutter/metadata/${emptyFile}`)
        .expect(200);

      expect(response.body.size).toBe(0);
      expect(response.body.type).toBe('text/plain');
      expect(response.body.isImage).toBe(false);
    });
  });
});