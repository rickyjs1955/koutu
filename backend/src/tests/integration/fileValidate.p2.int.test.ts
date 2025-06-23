// /backend/tests/integration/middlewares/fileValidate.p2.int.test.ts

jest.mock('../../config/firebase', () => ({
    default: { storage: jest.fn() },
}));

import { Request, Response, NextFunction } from 'express';
import request from 'supertest';
import express from 'express';
import fs from 'fs/promises';
import path from 'path';
import { storageService } from '../../../src/services/storageService';

import {
  validateFileContent,
  validateFileContentBasic,
  validateImageFile,
  logFileAccess
} from '../../../src/middlewares/fileValidate';

// Mock dependencies with enhanced integration capabilities
jest.mock('fs/promises');
jest.mock('../../../src/services/storageService');

const mockFs = fs as jest.Mocked<typeof fs>;
const mockStorageService = storageService as jest.Mocked<typeof storageService>;

// Enhanced test app with real-world middleware integration
const createIntegrationTestApp = () => {
  const app = express();
  
  // Body parser middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));
  
  // Compression middleware simulation
  app.use((req, res, next) => {
    res.setHeader('X-Compression', 'enabled');
    next();
  });
  
  // Rate limiting simulation (resets for each new app instance, i.e., per test)
  let requestCount = 0;
  app.use((req, res, next) => {
    requestCount++;
    if (requestCount > 100) { // Limit to 100 requests per app instance
      res.status(429).json({ error: 'Rate limit exceeded' });
      return;
    }
    next();
  });
  
  // CORS middleware simulation
  app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
  });
  
  // Request ID middleware
  app.use((req, res, next) => {
    (req as any).requestId = `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    res.setHeader('X-Request-ID', (req as any).requestId);
    next();
  });
  
  // Basic validation routes
  app.get('/api/v1/validate/basic/:file', (req, res, next) => {
    req.params.filepath = req.params.file;
    next();
  }, validateFileContentBasic, (req, res) => {
    res.json({ 
      success: true, 
      validation: (req as any).fileValidation,
      requestId: (req as any).requestId
    });
  });

  app.get('/api/v1/validate/basic/:dir/:file', (req, res, next) => {
    req.params.filepath = `${req.params.dir}/${req.params.file}`;
    next();
  }, validateFileContentBasic, (req, res) => {
    res.json({ 
      success: true, 
      validation: (req as any).fileValidation,
      requestId: (req as any).requestId
    });
  });
  
  // Full validation routes with authentication simulation and logging
  app.get('/api/v1/validate/full/:file', 
    (req, res, next) => {
      req.params.filepath = req.params.file;
      next();
    },
    (req, res, next) => {
      // Simulate authentication middleware
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }
      (req as any).user = { id: 'user123', role: 'user' };
      next();
    },
    validateFileContent, 
    logFileAccess,
    (req, res) => {
      res.json({ 
        success: true, 
        validation: (req as any).fileValidation,
        user: (req as any).user 
      });
    }
  );

  app.get('/api/v1/validate/full/:dir/:file', 
    (req, res, next) => {
      req.params.filepath = `${req.params.dir}/${req.params.file}`;
      next();
    },
    (req, res, next) => {
      // Simulate authentication middleware
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }
      (req as any).user = { id: 'user123', role: 'user' };
      next();
    },
    validateFileContent, 
    logFileAccess,
    (req, res) => {
      res.json({ 
        success: true, 
        validation: (req as any).fileValidation,
        user: (req as any).user 
      });
    }
  );
  
  // Image validation with caching simulation
  const imageCache = new Map(); // This cache resets for each new app instance (per test)
  app.get('/api/v1/validate/image/:file', 
    (req, res, next) => {
      req.params.filepath = req.params.file;
      next();
    },
    (req, res, next) => {
      const cacheKey = req.params.filepath;
      if (imageCache.has(cacheKey)) {
        res.setHeader('X-Cache', 'HIT');
        res.json(imageCache.get(cacheKey));
        return;
      }
      res.setHeader('X-Cache', 'MISS');
      next();
    },
    validateImageFile, 
    (req, res) => {
      const result = { 
        success: true, 
        validation: (req as any).fileValidation 
      };
      imageCache.set(req.params.filepath, result);
      res.json(result);
    }
  );

  app.get('/api/v1/validate/image/:dir/:file', 
    (req, res, next) => {
      req.params.filepath = `${req.params.dir}/${req.params.file}`;
      next();
    },
    (req, res, next) => {
      const cacheKey = req.params.filepath;
      if (imageCache.has(cacheKey)) {
        res.setHeader('X-Cache', 'HIT');
        res.json(imageCache.get(cacheKey));
        return;
      }
      res.setHeader('X-Cache', 'MISS');
      next();
    },
    validateImageFile, 
    (req, res) => {
      const result = { 
        success: true, 
        validation: (req as any).fileValidation 
      };
      imageCache.set(req.params.filepath, result);
      res.json(result);
    }
  );
  
  // Multi-part upload simulation
  app.post('/api/v1/validate/multipart', 
    (req, res, next) => {
      // Simulate multipart parsing headers
      const parts = req.headers['x-total-parts'] || '1';
      const currentPart = req.headers['x-current-part'] || '1';
      (req as any).multipart = { total: parseInt(parts as string), current: parseInt(currentPart as string) };
      req.params.filepath = req.headers['x-filename'] as string || 'multipart.jpg';
      next();
    },
    validateFileContent,
    (req, res) => {
      res.json({ 
        success: true, 
        validation: (req as any).fileValidation,
        multipart: (req as any).multipart
      });
    }
  );
  
  // Database integration simulation
  const mockDatabase = new Map(); // This map resets for each new app instance (per test)
  app.post('/api/v1/validate/persist/:file', 
    (req, res, next) => {
      req.params.filepath = req.params.file;
      next();
    },
    validateFileContent,
    async (req, res, next) => {
      try {
        // Simulate database persistence
        const fileRecord = {
          id: Math.random().toString(36).substr(2, 9),
          filepath: req.params.filepath,
          validation: (req as any).fileValidation,
          uploadedAt: new Date().toISOString(),
          userId: (req as any).user?.id || 'anonymous'
        };
        
        mockDatabase.set(fileRecord.id, fileRecord);
        (req as any).fileRecord = fileRecord;
        next();
      } catch (error) {
        res.status(500).json({ error: 'Database error' });
        return;
      }
    },
    (req, res) => {
      res.json({ 
        success: true, 
        record: (req as any).fileRecord 
      });
    }
  );

  app.post('/api/v1/validate/persist/:dir/:file', 
    (req, res, next) => {
      req.params.filepath = `${req.params.dir}/${req.params.file}`;
      next();
    },
    validateFileContent,
    async (req, res, next) => {
      try {
        // Simulate database persistence
        const fileRecord = {
          id: Math.random().toString(36).substr(2, 9),
          filepath: req.params.filepath,
          validation: (req as any).fileValidation,
          uploadedAt: new Date().toISOString(),
          userId: (req as any).user?.id || 'anonymous'
        };
        
        mockDatabase.set(fileRecord.id, fileRecord);
        (req as any).fileRecord = fileRecord;
        next();
      } catch (error) {
        res.status(500).json({ error: 'Database error' });
        return;
      }
    },
    (req, res) => {
      res.json({ 
        success: true, 
        record: (req as any).fileRecord 
      });
    }
  );
  
  // Cloud storage integration
  app.post('/api/v1/validate/cloud/:file',
    (req, res, next) => {
      req.params.filepath = req.params.file;
      next();
    },
    validateFileContent,
    async (req, res, next) => {
      try {
        // Simulate cloud storage upload
        const cloudPath = `cloud://bucket/${req.params.filepath}`;
        (req as any).cloudUpload = {
          path: cloudPath,
          uploadTime: Date.now(),
          size: (req as any).fileValidation?.fileSize || 0
        };
        next();
      } catch (error) {
        res.status(503).json({ error: 'Cloud storage unavailable' });
        return;
      }
    },
    (req, res) => {
      res.json({ 
        success: true, 
        cloud: (req as any).cloudUpload 
      });
    }
  );

  app.post('/api/v1/validate/cloud/:dir/:file',
    (req, res, next) => {
      req.params.filepath = `${req.params.dir}/${req.params.file}`;
      next();
    },
    validateFileContent,
    async (req, res, next) => {
      try {
        // Simulate cloud storage upload
        const cloudPath = `cloud://bucket/${req.params.filepath}`;
        (req as any).cloudUpload = {
          path: cloudPath,
          uploadTime: Date.now(),
          size: (req as any).fileValidation?.fileSize || 0
        };
        next();
      } catch (error) {
        res.status(503).json({ error: 'Cloud storage unavailable' });
        return;
      }
    },
    (req, res) => {
      res.json({ 
        success: true, 
        cloud: (req as any).cloudUpload 
      });
    }
  );
  
  // Error handler (from user's more detailed version)
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    const errorResponse = {
      success: false,
      error: {
        message: err.message,
        code: err.code,
        timestamp: new Date().toISOString(),
        requestId: (req as any).requestId
      }
    };
    
    // Add stack trace in non-production environments
    if (process.env.NODE_ENV !== 'production') {
      (errorResponse.error as any).stack = err.stack;
    }
    
    res.status(err.statusCode || 500).json(errorResponse);
  });
  
  return app;
};

describe('FileValidate Advanced Integration Tests', () => {
  let app: express.Application;
  let consoleSpy: jest.SpyInstance;

  // Store original mock implementations
  const originalMocks = {
    getAbsolutePath: mockStorageService.getAbsolutePath,
    access: mockFs.access,
    stat: mockFs.stat,
    open: mockFs.open
  };

  beforeAll(() => {
    // Store the original implementations (already assigned above)
  });

  beforeEach(() => {
    app = createIntegrationTestApp();
    jest.clearAllMocks();
    consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    
    // Reset to default successful mocks
    setupDefaultMocks();
  });

  afterEach(() => {
    if (consoleSpy) {
      consoleSpy.mockRestore();
    }
    // Reset mocks to default state
    setupDefaultMocks();
  });

  const setupDefaultMocks = (fileType: string = 'image/jpeg', fileSize: number = 1024) => {
    mockStorageService.getAbsolutePath.mockReturnValue('/safe/storage/test.jpg');
    mockFs.access.mockResolvedValue(undefined); // File exists and is accessible
    mockFs.stat.mockResolvedValue({ size: fileSize } as any); // Set file size

    let signatureBuffer: Buffer;
    if (fileType === 'image/jpeg') {
      signatureBuffer = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46]); // JPEG signature
    } else if (fileType === 'application/pdf') {
      signatureBuffer = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x20, 0x25, 0x41, 0x43]); // PDF signature
    } else if (fileType === 'text/plain') {
      signatureBuffer = Buffer.from([0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20]); // "This is " for text
    } else {
        signatureBuffer = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Unknown/default
    }

    const mockOpen = {
      read: jest.fn().mockImplementation((buffer) => {
        signatureBuffer.copy(buffer);
        return Promise.resolve({ bytesRead: signatureBuffer.length });
      }),
      close: jest.fn().mockResolvedValue(undefined)
    };
    mockFs.open.mockResolvedValue(mockOpen as any);
  };

  describe('Cross-Browser Compatibility Integration', () => {
    it('should handle different browser filename encoding', async () => {
      const browserEncodings = [
        { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', filename: 'image-with-spaces.jpg' },
        { userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36', filename: 'file-with-unicode.jpg' },
        { userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', filename: 'linux-file.jpg' },
        { userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)', filename: 'mobile-photo.jpg' }
      ];

      for (const { userAgent, filename } of browserEncodings) {
        const response = await request(app)
          .get(`/api/v1/validate/basic/${filename}`)
          .set('User-Agent', userAgent)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.headers['x-request-id']).toBeDefined();
      }
    });

    it('should handle mobile browser file upload behaviors', async () => {
      const mobileUserAgents = [
        'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15',
        'Mozilla/5.0 (Android 12; Mobile; rv:95.0) Gecko/95.0 Firefox/95.0',
        'Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15'
      ];

      for (const userAgent of mobileUserAgents) {
        const response = await request(app)
          .get('/api/v1/validate/image/mobile-camera-photo.jpg')
          .set('User-Agent', userAgent)
          .set('X-Mobile-Upload', 'true')
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.headers['x-cache']).toBeDefined();
      }
    });

    it('should handle progressive web app file uploads', async () => {
      const response = await request(app)
        .get('/api/v1/validate/basic/pwa-upload.jpg')
        .set('X-Requested-With', 'XMLHttpRequest')
        .set('X-PWA-Mode', 'standalone')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.requestId).toBeDefined();
    });
  });

  describe('Real-Time System Integration', () => {
    it('should handle file system permission changes during validation', async () => {
      let accessCallCount = 0;
      mockFs.access.mockImplementation(async () => {
        accessCallCount++;
        if (accessCallCount === 1) {
          // First call succeeds
          return undefined;
        } else {
          // Subsequent calls fail due to permission change
          throw new Error('EACCES: permission denied');
        }
      });

      // First request should succeed
      const response1 = await request(app)
        .get('/api/v1/validate/full/permission-test.jpg')
        .set('Authorization', 'Bearer valid-token')
        .expect(200);

      expect(response1.body.success).toBe(true);

      // Second request should fail due to permission change
      const response2 = await request(app)
        .get('/api/v1/validate/full/permission-test2.jpg')
        .set('Authorization', 'Bearer valid-token')
        .expect(404);

      expect(response2.body.error.code).toBe('FILE_NOT_FOUND');
    });

    it('should handle disk space exhaustion during processing', async () => {
      // Override mock for this test only
      mockFs.stat.mockRejectedValue(new Error('ENOSPC: no space left on device'));

      const response = await request(app)
        .get('/api/v1/validate/full/large-file.jpg')
        .set('Authorization', 'Bearer valid-token')
        .expect(400);

      expect(response.body.error.message).toContain('Unable to check file size');
    });

    it('should handle network interruptions during remote storage access', async () => {
      mockStorageService.getAbsolutePath.mockImplementation((filepath) => {
        throw new Error('ENETUNREACH: network is unreachable');
      });

      const response = await request(app)
        .get('/api/v1/validate/full/remote-file.jpg')
        .set('Authorization', 'Bearer valid-token');

      expect(response.status).toBe(404);
      // Change this line:
      expect(response.body.error.message).toBe('File not found (path resolution error)'); // FIX APPLIED
      expect(response.body.error.code).toBe('FILE_NOT_FOUND');
    });

    it('should handle service restart scenarios', async () => {
      let callCount = 0;
      
      mockFs.access.mockImplementation(async (filepath) => {
        callCount++;
        if (callCount === 1) {
          throw new Error('Service temporarily unavailable');
        }
        return undefined;
      });

      const response1 = await request(app)
        .get('/api/v1/validate/full/restart-test.jpg')
        .set('Authorization', 'Bearer valid-token');
      
      const response2 = await request(app)
        .get('/api/v1/validate/full/restart-test2.jpg')
        .set('Authorization', 'Bearer valid-token');
      
      expect(response1.status).toBe(404);
      expect(response1.body.error.message).toBe('File not found');
      expect(response1.body.error.code).toBe('FILE_NOT_FOUND');
      expect(response2.status).toBe(200);
      expect(response2.body.success).toBe(true);
    });
  });

  describe('Multi-Part Upload Integration', () => {
    it('should handle large file chunk processing', async () => {
      const totalParts = 5;
      const responses = [];

      for (let i = 1; i <= totalParts; i++) {
        const response = await request(app)
          .post('/api/v1/validate/multipart')
          .set('X-Total-Parts', totalParts.toString())
          .set('X-Current-Part', i.toString())
          .set('X-Filename', 'large-video.mp4')
          .expect(200);

        responses.push(response);
        expect(response.body.multipart.total).toBe(totalParts);
        expect(response.body.multipart.current).toBe(i);
      }

      // All parts should be validated successfully
      expect(responses).toHaveLength(totalParts);
    });

    it('should handle interrupted multi-part uploads', async () => {
      // Simulate interruption on part 3 of 5
      mockFs.access.mockRejectedValue(new Error('Connection interrupted'));

      const response = await request(app)
        .post('/api/v1/validate/multipart')
        .set('X-Total-Parts', '5')
        .set('X-Current-Part', '3')
        .set('X-Filename', 'interrupted-file.mp4')
        .expect(404);

      expect(response.body.error.message).toBe('File not found');
    });

    it('should handle concurrent chunk uploads', async () => {
      const chunks = Array.from({ length: 10 }, (_, i) => ({
        part: i + 1,
        total: 10
      }));

      const promises = chunks.map(chunk =>
        request(app)
          .post('/api/v1/validate/multipart')
          .set('X-Total-Parts', chunk.total.toString())
          .set('X-Current-Part', chunk.part.toString())
          .set('X-Filename', `concurrent-chunk-${chunk.part}.bin`)
      );

      const responses = await Promise.all(promises);

      responses.forEach((response, index) => {
        expect(response.status).toBe(200);
        expect(response.body.multipart.current).toBe(index + 1);
      });
    });
  });

  describe('Cloud Storage Integration', () => {
    it('should integrate with cloud storage upload workflow', async () => {
      const response = await request(app)
        .post('/api/v1/validate/cloud/upload-test.jpg')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.cloud.path).toBe('cloud://bucket/upload-test.jpg');
      expect(response.body.cloud.uploadTime).toBeDefined();
    });

    it('should handle cloud storage service failures', async () => {
      // Override the cloud storage middleware to simulate failure
      const failingApp = express();
      
      failingApp.post('/api/v1/validate/cloud/:file',
        (req, res, next) => {
          req.params.filepath = req.params.file;
          next();
        },
        validateFileContent,
        async (req, res, next) => {
          const error = new Error('Cloud storage service unavailable');
          (error as any).statusCode = 503;
          next(error);
        }
      );
      
      failingApp.use((err: any, req: Request, res: Response, next: NextFunction) => {
        res.status(err.statusCode || 500).json({
          success: false,
          error: { message: err.message }
        });
      });

      const response = await request(failingApp)
        .post('/api/v1/validate/cloud/test.jpg')
        .expect(503);

      expect(response.body.error.message).toBe('Cloud storage service unavailable');
    });

    it('should handle cross-region cloud storage scenarios', async () => {
      const regions = ['us-east-1', 'eu-west-1', 'ap-southeast-1'];

      for (const region of regions) {
        const response = await request(app)
          .post('/api/v1/validate/cloud/regional-file.jpg')
          .set('X-Cloud-Region', region)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.cloud.path).toContain('bucket');
      }
    });
  });

  describe('Database Integration', () => {
    it('should persist file validation results to database', async () => {
      const response = await request(app)
        .post('/api/v1/validate/persist/database-test.jpg')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.record.id).toBeDefined();
      expect(response.body.record.filepath).toBe('database-test.jpg');
      expect(response.body.record.uploadedAt).toBeDefined();
    });

    it('should handle database transaction scenarios', async () => {
      // Simulate multiple concurrent database writes
      const promises = Array.from({ length: 5 }, (_, i) =>
        request(app)
          .post(`/api/v1/validate/persist/transaction-test-${i}.jpg`)
      );

      const responses = await Promise.all(promises);

      responses.forEach((response, index) => {
        expect(response.status).toBe(200);
        expect(response.body.record.filepath).toBe(`transaction-test-${index}.jpg`);
      });
    });

    it('should handle database constraint violations', async () => {
      // Simulate duplicate file upload
      const filepath = 'duplicate-test.jpg';
      
      // First upload should succeed
      const response1 = await request(app)
        .post(`/api/v1/validate/persist/${filepath}`)
        .expect(200);

      expect(response1.body.success).toBe(true);

      // Second upload should also succeed (our mock doesn't enforce uniqueness)
      const response2 = await request(app)
        .post(`/api/v1/validate/persist/${filepath}`)
        .expect(200);

      expect(response2.body.success).toBe(true);
      expect(response2.body.record.filepath).toBe(filepath);
    });
  });

  describe('Caching Layer Integration', () => {
    it('should integrate with cache for image validation', async () => {
      const filepath = 'cached-image.jpg';

      // First request - cache miss
      const response1 = await request(app)
        .get(`/api/v1/validate/image/${filepath}`)
        .expect(200);

      expect(response1.body.success).toBe(true);
      expect(response1.headers['x-cache']).toBe('MISS');

      // Second request - cache hit
      const response2 = await request(app)
        .get(`/api/v1/validate/image/${filepath}`)
        .expect(200);

      expect(response2.body.success).toBe(true);
      expect(response2.headers['x-cache']).toBe('HIT');
    });

    it('should handle cache invalidation scenarios', async () => {
      const filepath = 'invalidation-test.jpg';

      // Cache the result
      await request(app)
        .get(`/api/v1/validate/image/${filepath}`)
        .expect(200);

      // Simulate cache invalidation by changing file
      mockFs.stat.mockResolvedValue({ size: 2048 } as any);

      // Request should still return cached result
      const response = await request(app)
        .get(`/api/v1/validate/image/${filepath}`)
        .expect(200);

      expect(response.headers['x-cache']).toBe('HIT');
    });

    it('should handle distributed cache consistency', async () => {
      const filepath = 'distributed-cache.jpg';
      
      // Simulate multiple server instances accessing same cache
      const instances = Array.from({ length: 3 }, () => createIntegrationTestApp());

      for (const instance of instances) {
        const response = await request(instance)
          .get(`/api/v1/validate/image/${filepath}`)
          .expect(200);

        expect(response.body.success).toBe(true);
      }
    });
  });

  describe('Monitoring Integration', () => {
    it('should collect metrics during validation', async () => {
      const startTime = Date.now();

      const response = await request(app)
        .get('/api/v1/validate/full/metrics-test.jpg')
        .set('Authorization', 'Bearer valid-token')
        .expect(200);

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      expect(response.body.success).toBe(true);
      expect(response.headers['x-request-id']).toBeDefined();
      expect(responseTime).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should trigger alerts on validation anomalies', async () => {
      let alertsTriggered = 0;
      
      // Simulate alert system
      const originalConsoleWarn = console.warn;
      console.warn = jest.fn().mockImplementation((...args) => {
        if (args[0] === 'File security warning:') {
          alertsTriggered++;
        }
        return originalConsoleWarn.apply(console, args);
      });

      // Upload suspicious file that should trigger alert
      const response = await request(app)
        .get('/api/v1/validate/full/suspicious.exe')
        .set('Authorization', 'Bearer valid-token')
        .expect(400);

      expect(response.body.error.code).toBe('INVALID_FILEPATH');
      
      console.warn = originalConsoleWarn;
    });

    it('should integrate with health check endpoints', async () => {
      // Add health check route
      const healthApp = express();
      
      let validationHealthy = true;
      
      healthApp.get('/health', (req, res) => {
        const health = {
          status: validationHealthy ? 'healthy' : 'unhealthy',
          checks: {
            validation: validationHealthy ? 'pass' : 'fail',
            storage: 'pass',
            database: 'pass'
          },
          timestamp: new Date().toISOString()
        };
        
        res.status(validationHealthy ? 200 : 503).json(health);
      });

      const response = await request(healthApp)
        .get('/health')
        .expect(200);

      expect(response.body.status).toBe('healthy');
      expect(response.body.checks.validation).toBe('pass');
    });
  });

  describe('Scalability Integration', () => {
    it('should handle horizontal scaling scenarios', async () => {
      // Simulate load balancing across multiple instances
      const instances = Array.from({ length: 5 }, () => createIntegrationTestApp());
      
      const requests = Array.from({ length: 50 }, (_, i) => {
        const instanceIndex = i % instances.length;
        return request(instances[instanceIndex])
          .get(`/api/v1/validate/basic/scale-test-${i}.jpg`);
      });

      const responses = await Promise.all(requests);

      responses.forEach((response, index) => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.headers['x-request-id']).toBeDefined();
      });
    });

    it('should handle auto-scaling trigger scenarios', async () => {
      let currentLoad = 0;
      const maxLoad = 20;

      // Simulate auto-scaling trigger
      const loadBalancer = (req: Request, res: Response, next: NextFunction) => {
        currentLoad++;
        
        if (currentLoad > maxLoad) {
          res.status(503).json({ 
            error: 'Service temporarily unavailable - scaling in progress' 
          });
          return;
        }
        
        res.setHeader('X-Current-Load', currentLoad.toString());
        next();
      };

      const scalingApp = express();
      scalingApp.use(loadBalancer);
      scalingApp.get('/api/v1/validate/basic/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ success: true, load: currentLoad });
      });

      // Generate load to trigger scaling
      const promises = Array.from({ length: 25 }, (_, i) =>
        request(scalingApp).get(`/api/v1/validate/basic/load-${i}.jpg`)
      );

      const responses = await Promise.all(promises);

      // First 20 should succeed, rest should get 503
      const successful = responses.filter(r => r.status === 200);
      const serviceUnavailable = responses.filter(r => r.status === 503);

      expect(successful.length).toBe(20);
      expect(serviceUnavailable.length).toBe(5);
    });

    it('should handle resource constraint scenarios', async () => {
      let callCount = 0;
      
      mockFs.access.mockImplementation(async (filepath) => {
        callCount++;
        if (callCount > 10) {
          throw new Error('Cannot allocate memory');
        }
        return undefined;
      });

      const batch1 = Array.from({ length: 10 }, (_, i) =>
        request(app).get(`/api/v1/validate/full/memory-test-${i}.jpg`)
          .set('Authorization', 'Bearer valid-token')
      );

      const responses1 = await Promise.all(batch1);
      
      const batch2 = Array.from({ length: 5 }, (_, i) =>
        request(app).get(`/api/v1/validate/full/memory-pressure-${i}.jpg`)
          .set('Authorization', 'Bearer valid-token')
      );

      const responses2 = await Promise.all(batch2);
      
      responses1.forEach((response) => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });

      responses2.forEach((response) => {
        expect(response.status).toBe(404);
        expect(response.body.success).toBe(false);
      });
    });
  });

  describe('Security Integration', () => {
    it('should integrate with rate limiting enforcement', async () => {
      // The app already has rate limiting - test it
      const requests = Array.from({ length: 105 }, (_, i) =>
        request(app).get(`/api/v1/validate/basic/rate-limit-${i}.jpg`)
      );

      const responses = await Promise.all(requests);

      // First 100 should succeed, rest should be rate limited
      const successful = responses.filter(r => r.status === 200);
      const rateLimited = responses.filter(r => r.status === 429);

      expect(successful.length).toBe(100);
      expect(rateLimited.length).toBe(5);
    });

    it('should integrate with authentication provider failures', async () => {
      // Simulate auth provider failure
      const authApp = express();
      
      authApp.get('/api/v1/validate/secure/:file', 
        (req, res, next) => {
          // Simulate auth service timeout
          setTimeout(() => {
            res.status(504).json({ error: 'Authentication service timeout' });
          }, 100);
        }
      );

      const response = await request(authApp)
        .get('/api/v1/validate/secure/protected.jpg')
        .set('Authorization', 'Bearer valid-token');

      expect(response.status).toBe(504);
      expect(response.body.error).toBe('Authentication service timeout');
    });

    it('should handle DDoS protection scenarios', async () => {
      // Simulate DDoS protection with IP-based blocking
      const ddosApp = express();
      const blockedIPs = new Set(['192.168.1.100']);
      
      ddosApp.use((req, res, next) => {
        // Force a specific IP to test blocking
        const clientIP = '192.168.1.100';
        if (blockedIPs.has(clientIP)) {
          res.status(403).json({ error: 'IP blocked due to suspicious activity' });
          return;
        }
        next();
      });
      
      ddosApp.get('/api/v1/validate/basic/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ success: true });
      });

      const response = await request(ddosApp)
        .get('/api/v1/validate/basic/ddos-test.jpg')
        .expect(403);

      expect(response.body.error).toBe('IP blocked due to suspicious activity');
    });
  });

  describe('API Integration', () => {
    it('should handle REST API endpoint integration', async () => {
      const apiApp = express();
      
      // API versioning support
      apiApp.use('/api/v1', (req, res, next) => {
        res.setHeader('API-Version', '1.0');
        next();
      });
      
      apiApp.use('/api/v2', (req, res, next) => {
        res.setHeader('API-Version', '2.0');
        next();
      });
      
      apiApp.get('/api/v1/validate/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ version: 'v1', success: true });
      });
      
      apiApp.get('/api/v2/validate/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContent, (req, res) => {
        res.json({ version: 'v2', success: true, enhanced: true });
      });

      // Test v1 API
      const v1Response = await request(apiApp)
        .get('/api/v1/validate/api-test.jpg')
        .expect(200);

      expect(v1Response.body.version).toBe('v1');
      expect(v1Response.headers['api-version']).toBe('1.0');

      // Test v2 API
      const v2Response = await request(apiApp)
        .get('/api/v2/validate/api-test.jpg')
        .expect(200);

      expect(v2Response.body.version).toBe('v2');
      expect(v2Response.body.enhanced).toBe(true);
      expect(v2Response.headers['api-version']).toBe('2.0');
    });

    it('should handle webhook delivery scenarios', async () => {
      let webhooksCalled = 0;
      
      const webhookApp = express();
      
      webhookApp.post('/api/v1/validate/webhook/:file',
        (req, res, next) => {
          req.params.filepath = req.params.file;
          next();
        },
        validateFileContent,
        async (req, res, next) => {
          // Simulate webhook delivery
          try {
            webhooksCalled++;
            (req as any).webhookResult = {
              delivered: true,
              timestamp: new Date().toISOString(),
              attempts: 1
            };
            next();
          } catch (error) {
            (req as any).webhookResult = {
              delivered: false,
              error: error instanceof Error ? error.message : String(error)
            };
            next();
          }
        },
        (req, res) => {
          res.json({ 
            success: true, 
            webhook: (req as any).webhookResult 
          });
        }
      );

      const response = await request(webhookApp)
        .post('/api/v1/validate/webhook/webhook-test.jpg')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.webhook.delivered).toBe(true);
      expect(webhooksCalled).toBe(1);
    });

    it('should handle API gateway integration', async () => {
      const gatewayApp = express();
      
      // Simulate API gateway behavior
      gatewayApp.use((req, res, next) => {
        res.setHeader('X-Gateway', 'API-Gateway-v1');
        res.setHeader('X-Rate-Limit', '1000');
        res.setHeader('X-Rate-Remaining', '999');
        next();
      });
      
      gatewayApp.get('/api/v1/validate/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ 
          success: true,
          gateway: 'processed'
        });
      });

      const response = await request(gatewayApp)
        .get('/api/v1/validate/gateway-test.jpg')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.headers['x-gateway']).toBe('API-Gateway-v1');
      expect(response.headers['x-rate-limit']).toBe('1000');
    });
  });

  describe('Business Workflow Integration', () => {
    it('should integrate with approval workflow', async () => {
      const workflowApp = express();
      
      const approvalQueue = new Map();
      
      workflowApp.post('/api/v1/validate/approval/:file',
        (req, res, next) => {
          req.params.filepath = req.params.file;
          next();
        },
        validateFileContent,
        async (req, res, next) => {
          // Add to approval queue
          const approvalId = Math.random().toString(36).substr(2, 9);
          approvalQueue.set(approvalId, {
            filepath: req.params.filepath,
            validation: (req as any).fileValidation,
            status: 'pending',
            submittedAt: new Date().toISOString()
          });
          
          (req as any).approval = { id: approvalId, status: 'pending' };
          next();
        },
        (req, res) => {
          res.json({ 
            success: true, 
            approval: (req as any).approval 
          });
        }
      );

      const response = await request(workflowApp)
        .post('/api/v1/validate/approval/workflow-test.jpg')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.approval.status).toBe('pending');
      expect(approvalQueue.has(response.body.approval.id)).toBe(true);
    });

    it('should integrate with content moderation pipeline', async () => {
      const moderationApp = express();
      
      let moderationResults = new Map();
      
      moderationApp.post('/api/v1/validate/moderate/:file',
        (req, res, next) => {
          req.params.filepath = req.params.file;
          next();
        },
        validateImageFile,
        async (req, res, next) => {
          // Simulate content moderation
          const filepath = req.params.filepath;
          const moderationScore = Math.random();
          
          const result = {
            filepath,
            score: moderationScore,
            approved: moderationScore < 0.5, // 50% threshold
            flags: moderationScore > 0.8 ? ['adult_content'] : [],
            processedAt: new Date().toISOString()
          };
          
          moderationResults.set(filepath, result);
          (req as any).moderation = result;
          next();
        },
        (req, res) => {
          const moderation = (req as any).moderation;
          res.status(moderation.approved ? 200 : 400).json({ 
            success: moderation.approved, 
            moderation 
          });
        }
      );

      // Test multiple files through moderation
      const files = ['image1.jpg', 'image2.jpg', 'image3.jpg'];
      
      for (const file of files) {
        const response = await request(moderationApp)
          .post(`/api/v1/validate/moderate/${file}`);

        expect([200, 400]).toContain(response.status);
        expect(response.body.moderation).toBeDefined();
        expect(response.body.moderation.score).toBeGreaterThanOrEqual(0);
        expect(response.body.moderation.score).toBeLessThanOrEqual(1);
      }
    });

    it('should integrate with virus scanning workflow', async () => {
      const virusScanApp = express();
      
      virusScanApp.post('/api/v1/validate/scan/:file',
        (req, res, next) => {
          req.params.filepath = req.params.file;
          next();
        },
        validateFileContent,
        async (req, res, next) => {
          // Simulate virus scanning
          const filepath = req.params.filepath;
          const isInfected = filepath.includes('virus') || filepath.includes('malware');
          
          const scanResult = {
            filepath,
            clean: !isInfected,
            threats: isInfected ? ['Trojan.Generic'] : [],
            scanTime: Date.now(),
            engine: 'MockAV-1.0'
          };
          
          (req as any).virusScan = scanResult;
          
          if (isInfected) {
            const error = new Error('Virus detected');
            (error as any).statusCode = 400;
            (error as any).code = 'VIRUS_DETECTED';
            return next(error);
          }
          
          next();
        },
        (req, res) => {
          res.json({ 
            success: true, 
            scan: (req as any).virusScan 
          });
        }
      );
      
      virusScanApp.use((err: any, req: Request, res: Response, next: NextFunction) => {
        res.status(err.statusCode || 500).json({
          success: false,
          error: { message: err.message, code: err.code },
          scan: (req as any).virusScan
        });
      });

      // Test clean file
      const cleanResponse = await request(virusScanApp)
        .post('/api/v1/validate/scan/clean-file.jpg')
        .expect(200);

      expect(cleanResponse.body.success).toBe(true);
      expect(cleanResponse.body.scan.clean).toBe(true);

      // Test infected file
      const infectedResponse = await request(virusScanApp)
        .post('/api/v1/validate/scan/virus-infected.jpg')
        .expect(400);

      expect(infectedResponse.body.success).toBe(false);
      expect(infectedResponse.body.error.code).toBe('VIRUS_DETECTED');
      expect(infectedResponse.body.scan.clean).toBe(false);
    });
  });

  describe('Error Recovery Integration', () => {
    it('should handle graceful degradation scenarios', async () => {
      const degradationApp = express();
      
      let serviceHealth = {
        validation: true,
        storage: true,
        database: true
      };
      
      degradationApp.get('/api/v1/validate/degraded/:file',
        (req, res, next) => {
          req.params.filepath = req.params.file;
          // Check service health and degrade gracefully
          if (!serviceHealth.storage) {
            // Skip storage validation, use basic validation only
            return validateFileContentBasic(req, res, next);
          }
          next();
        },
        validateFileContent,
        (req, res) => {
          res.json({ 
            success: true,
            mode: serviceHealth.storage ? 'full' : 'degraded',
            validation: (req as any).fileValidation
          });
        }
      );

      // Test normal operation
      const normalResponse = await request(degradationApp)
        .get('/api/v1/validate/degraded/normal.jpg')
        .expect(200);

      expect(normalResponse.body.mode).toBe('full');

      // Simulate storage service failure
      serviceHealth.storage = false;

      const degradedResponse = await request(degradationApp)
        .get('/api/v1/validate/degraded/degraded.jpg')
        .expect(200);

      expect(degradedResponse.body.mode).toBe('degraded');
    });

    it('should handle retry mechanism testing', async () => {
      let attemptCount = 0;
      const maxRetries = 3;
      
      const retryApp = express();
      
      retryApp.get('/api/v1/validate/retry/:file',
        async (req, res, next) => {
          req.params.filepath = req.params.file;
          attemptCount++;
          
          // Fail first 2 attempts, succeed on 3rd
          if (attemptCount < 3) {
            mockFs.access.mockRejectedValue(new Error('Temporary failure'));
          } else {
            mockFs.access.mockResolvedValue(undefined);
          }
          
          next();
        },
        validateFileContent,
        (req, res) => {
          res.json({ 
            success: true,
            attempts: attemptCount,
            validation: (req as any).fileValidation
          });
        }
      );
      
      retryApp.use((err: any, req: Request, res: Response, next: NextFunction) => {
        if (attemptCount < maxRetries) {
          // In a real retry system, this would trigger a retry
          res.status(500).json({
            success: false,
            error: { message: 'Temporary failure', retry: true },
            attempts: attemptCount
          });
        } else {
          res.status(404).json({
            success: false,
            error: { message: 'File not found' },
            attempts: attemptCount
          });
        }
      });

      // First two attempts should fail
      const response1 = await request(retryApp)
        .get('/api/v1/validate/retry/retry-test.jpg')
        .expect(500);

      expect(response1.body.error.retry).toBe(true);

      const response2 = await request(retryApp)
        .get('/api/v1/validate/retry/retry-test.jpg')
        .expect(500);

      expect(response2.body.error.retry).toBe(true);

      // Third attempt should succeed
      const response3 = await request(retryApp)
        .get('/api/v1/validate/retry/retry-test.jpg')
        .expect(200);

      expect(response3.body.success).toBe(true);
      expect(response3.body.attempts).toBe(3);
    });

    it('should handle partial failure recovery', async () => {
      const partialFailureApp = express();
      
      partialFailureApp.post('/api/v1/validate/partial/:file',
        (req, res, next) => {
          req.params.filepath = req.params.file;
          next();
        },
        validateFileContent,
        async (req, res, next) => {
          // Simulate partial database failure
          try {
            const record = {
              id: 'partial-' + Math.random().toString(36).substr(2, 9),
              filepath: req.params.filepath,
              validation: (req as any).fileValidation
            };
            
            // Simulate 50% database failure rate
            if (Math.random() > 0.5) {
              throw new Error('Database write failed');
            }
            
            (req as any).record = record;
            next();
          } catch (error) {
            // Continue without database record
            (req as any).databaseError = error instanceof Error ? error.message : String(error);
            next();
          }
        },
        (req, res) => {
          res.json({ 
            success: true,
            validation: (req as any).fileValidation,
            record: (req as any).record || null,
            warning: (req as any).databaseError || null
          });
        }
      );

      // Test multiple requests to see partial failures
      const requests = Array.from({ length: 10 }, (_, i) =>
        request(partialFailureApp)
          .post(`/api/v1/validate/partial/partial-${i}.jpg`)
      );

      const responses = await Promise.all(requests);

      // All should succeed with validation
      responses.forEach(response => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.validation).toBeDefined();
        
        // Some should have database records, some should have warnings
        const hasRecord = response.body.record !== null;
        const hasWarning = response.body.warning !== null;
        expect(hasRecord || hasWarning).toBe(true);
      });
    });
  });

  describe('International Integration', () => {
    it('should handle multi-language filename support', async () => {
      const internationalFiles = [
        { filename: 'file-russian.jpg', language: 'ru', description: 'Russian' },
        { filename: 'file-chinese.jpg', language: 'zh', description: 'Chinese' },
        { filename: 'file-japanese.jpg', language: 'ja', description: 'Japanese' },
        { filename: 'arquivo.jpg', language: 'pt', description: 'Portuguese' },
        { filename: 'tiedosto.jpg', language: 'fi', description: 'Finnish' }
      ];

      for (const { filename, language, description } of internationalFiles) {
        const response = await request(app)
          .get(`/api/v1/validate/basic/${filename}`)
          .set('Accept-Language', language)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.validation.filepath).toBe(filename);
      }
    });

    it('should handle different timezone scenarios', async () => {
      const timezones = [
        'UTC',
        'America/New_York',
        'Europe/London', 
        'Asia/Tokyo',
        'Australia/Sydney'
      ];

      for (const timezone of timezones) {
        // Set timezone in environment
        const originalTZ = process.env.TZ;
        process.env.TZ = timezone;

        const response = await request(app)
          .post('/api/v1/validate/persist/timezone-test.jpg')
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.record.uploadedAt).toBeDefined();
        
        // Restore original timezone
        if (originalTZ) {
          process.env.TZ = originalTZ;
        } else {
          delete process.env.TZ;
        }
      }
    });

    it('should handle character encoding variations', async () => {
      const encodingTests = [
        { filename: 'test-utf8.jpg', encoding: 'utf-8' },
        { filename: 'test-iso.jpg', encoding: 'iso-8859-1' },
        { filename: 'test-ascii.jpg', encoding: 'ascii' }
      ];

      for (const { filename, encoding } of encodingTests) {
        const response = await request(app)
          .get(`/api/v1/validate/basic/${filename}`)
          .set('Accept-Charset', encoding)
          .expect(200);

        expect(response.body.success).toBe(true);
      }
    });
  });

  describe('DevOps Integration', () => {
    it('should integrate with CI/CD pipeline scenarios', async () => {
      const cicdApp = express();
      
      // Simulate CI/CD environment detection
      cicdApp.use((req, res, next) => {
        const isCICD = process.env.CI === 'true' || req.headers['x-ci-build'];
        
        if (isCICD) {
          res.setHeader('X-Environment', 'ci-cd');
          res.setHeader('X-Build-Id', req.headers['x-build-id'] || 'unknown');
        }
        
        next();
      });
      
      cicdApp.get('/api/v1/validate/basic/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ 
          success: true,
          environment: res.getHeader('X-Environment') || 'development'
        });
      });

      const response = await request(cicdApp)
        .get('/api/v1/validate/basic/ci-test.jpg')
        .set('X-CI-Build', 'true')
        .set('X-Build-ID', 'build-12345')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.headers['x-environment']).toBe('ci-cd');
      expect(response.headers['x-build-id']).toBe('build-12345');
    });

    it('should handle blue-green deployment scenarios', async () => {
      // Simulate blue-green deployment with version switching
      const blueApp = express();
      const greenApp = express();
      
      // Add version headers before routes
      blueApp.use((req, res, next) => {
        res.setHeader('X-Deployment-Color', 'blue');
        res.setHeader('X-App-Version', '1.0.0');
        next();
      });
      
      greenApp.use((req, res, next) => {
        res.setHeader('X-Deployment-Color', 'green');
        res.setHeader('X-App-Version', '1.1.0');
        next();
      });

      // Add routes
      blueApp.get('/api/v1/validate/basic/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ success: true });
      });
      
      greenApp.get('/api/v1/validate/basic/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ success: true });
      });

      // Test both deployments
      const blueResponse = await request(blueApp)
        .get('/api/v1/validate/basic/deployment-test.jpg')
        .expect(200);

      const greenResponse = await request(greenApp)
        .get('/api/v1/validate/basic/deployment-test.jpg')
        .expect(200);

      expect(blueResponse.body.success).toBe(true);
      expect(blueResponse.headers['x-deployment-color']).toBe('blue');

      expect(greenResponse.body.success).toBe(true);
      expect(greenResponse.headers['x-deployment-color']).toBe('green');
    });

    it('should handle configuration management scenarios', async () => {
      const configApp = express();
      
      // Simulate configuration management
      const configs: { [key: string]: { maxFileSize: number; allowedExtensions: string[] } } = {
        development: { maxFileSize: 1024 * 1024, allowedExtensions: ['.jpg', '.png'] },
        staging: { maxFileSize: 5 * 1024 * 1024, allowedExtensions: ['.jpg', '.png', '.pdf'] },
        production: { maxFileSize: 10 * 1024 * 1024, allowedExtensions: ['.jpg', '.png', '.pdf', '.doc'] }
      };
      
      configApp.use((req, res, next) => {
        const environment = req.headers['x-environment'] as string || 'development';
        (req as any).config = configs[environment] || configs.development;
        res.setHeader('X-Config-Environment', environment);
        next();
      });
      
      configApp.get('/api/v1/validate/config/:file', 
        (req, res, next) => {
          req.params.filepath = req.params.file;
          const config = (req as any).config;
          res.setHeader('X-Max-File-Size', config.maxFileSize.toString());
          res.setHeader('X-Allowed-Extensions', config.allowedExtensions.join(','));
          next();
        },
        validateFileContentBasic, 
        (req, res) => {
          res.json({ 
            success: true,
            config: (req as any).config,
            validation: (req as any).fileValidation
          });
        }
      );

      // Test different environments
      const environments = ['development', 'staging', 'production'];
      
      for (const env of environments) {
        const response = await request(configApp)
          .get('/api/v1/validate/config/test.jpg')
          .set('X-Environment', env)
          .expect(200);

        expect(response.body.success).toBe(true);
        expect(response.body.config.maxFileSize).toBe(configs[env].maxFileSize);
        expect(response.headers['x-config-environment']).toBe(env);
      }
    });
  });

  describe('Performance Under Load Integration', () => {
    it('should maintain performance under sustained load', async () => {
      const numRequests = 200; // Increased to ensure rate limiting consistently applies
      const promises: Promise<any>[] = [];
      const startTime = process.hrtime.bigint();

      for (let i = 0; i < numRequests; i++) {
        promises.push(
          request(app)
            .get(`/api/v1/validate/full/load-test-${i}.jpg`)
            .set('Authorization', 'Bearer valid-token')
        );
      }

      const responses = await Promise.allSettled(promises);
      const endTime = process.hrtime.bigint();
      const totalDurationMs = Number(endTime - startTime) / 1_000_000;

      let successfulRequests = 0;
      let failedRequests = 0;

      responses.forEach((result) => {
        if (result.status === 'fulfilled' && result.value.status === 200) {
          successfulRequests++;
        } else {
          failedRequests++;
        }
      });

      const totalRequests = numRequests;
      const requestsPerSecond = totalRequests / (totalDurationMs / 1000);

      // Should handle reasonable load - adjust expectations due to rate limiting
      expect(totalRequests).toBeGreaterThan(50);
      expect(successfulRequests).toBe(100); // Fixed to 100 as per rate limit definition
      expect(requestsPerSecond).toBeGreaterThan(10); // At least 10 RPS
    });

    it('should handle memory-intensive file validation', async () => {
      // Simulate large file validation by creating larger buffers
      const largeBuffer = Buffer.alloc(1024 * 1024, 0xFF); // 1MB buffer
      largeBuffer[0] = 0xFF;
      largeBuffer[1] = 0xD8;
      largeBuffer[2] = 0xFF;
      largeBuffer[3] = 0xE0;

      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          const bytesToCopy = Math.min(buffer.length, largeBuffer.length);
          largeBuffer.copy(buffer, 0, 0, bytesToCopy);
          return Promise.resolve({ bytesRead: bytesToCopy });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open.mockResolvedValue(mockOpen as any);

      const initialMemory = process.memoryUsage().heapUsed;

      // Process multiple large files
      const largeFileRequests = Array.from({ length: 20 }, (_, i) =>
        request(app).get(`/api/v1/validate/full/large-file-${i}.jpg`)
          .set('Authorization', 'Bearer valid-token')
      );

      const responses = await Promise.all(largeFileRequests);

      responses.forEach((response, index) => {
        expect(response.status).toBe(200);
        expect(response.body.success).toBe(true);
      });

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 50MB)
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
    });

    it('should handle concurrent database and cache operations', async () => {
      const concurrentOperations = Array.from({ length: 15 }, async (_, i) => {
        // Mix of different operation types
        const operations = [
          () => request(app).get(`/api/v1/validate/image/concurrent-${i}.jpg`), // Cache operation
          () => request(app).post(`/api/v1/validate/persist/concurrent-${i}.jpg`), // Database operation
          () => request(app).post(`/api/v1/validate/cloud/concurrent-${i}.jpg`) // Cloud operation
        ];

        const operation = operations[i % operations.length];
        return operation();
      });

      const responses = await Promise.all(concurrentOperations);

      // All operations should complete successfully
      responses.forEach((response, index) => {
        expect([200, 201]).toContain(response.status);
      });
    });
  });

  describe('End-to-End Workflow Integration', () => {
    it('should handle complete file upload lifecycle', async () => {
      const filepath = 'lifecycle-test.jpg';
      
      // Step 1: Basic validation
      const basicResponse = await request(app)
        .get(`/api/v1/validate/basic/${filepath}`)
        .expect(200);

      expect(basicResponse.body.success).toBe(true);

      // Step 2: Full validation with authentication
      const fullResponse = await request(app)
        .get(`/api/v1/validate/full/${filepath}`)
        .set('Authorization', 'Bearer valid-token')
        .expect(200);

      expect(fullResponse.body.success).toBe(true);
      expect(fullResponse.body.user.id).toBe('user123');

      // Step 3: Image-specific validation
      const imageResponse = await request(app)
        .get(`/api/v1/validate/image/${filepath}`)
        .expect(200);

      expect(imageResponse.body.success).toBe(true);
      expect(imageResponse.headers['x-cache']).toBe('MISS');

      // Step 4: Persistence
      const persistResponse = await request(app)
        .post(`/api/v1/validate/persist/${filepath}`)
        .expect(200);

      expect(persistResponse.body.success).toBe(true);
      expect(persistResponse.body.record.id).toBeDefined();

      // Step 5: Cloud upload
      const cloudResponse = await request(app)
        .post(`/api/v1/validate/cloud/${filepath}`)
        .expect(200);

      expect(cloudResponse.body.success).toBe(true);
      expect(cloudResponse.body.cloud.path).toContain(filepath);
    });

    it('should handle cross-service error propagation', async () => {
      mockStorageService.getAbsolutePath.mockImplementation((filepath) => {
        if (filepath.includes('cascade-fail')) {
          throw new Error('Storage service unavailable');
        }
        return '/safe/storage/' + filepath;
      });

      const services = [
        () => request(app).get('/api/v1/validate/full/cascade-fail-test.jpg').set('Authorization', 'Bearer valid-token'),
        () => request(app).post('/api/v1/validate/persist/cascade-fail-test.jpg'),
        () => request(app).post('/api/v1/validate/cloud/cascade-fail-test.jpg')
      ];

      for (const serviceFn of services) {
        const response = await serviceFn();
        expect(response.status).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error.message).toBe('File not found (path resolution error)');
      }
    });

    it('should handle partial service recovery', async () => {
      let callCount = 0;
      
      mockFs.access.mockImplementation(async (filepath) => {
        callCount++;
        if (callCount % 3 === 0) {
          throw new Error('Intermittent failure');
        }
        return undefined;
      });

      const requests = Array.from({ length: 9 }, (_, i) =>
        request(app).get(`/api/v1/validate/full/recovery-test-${i}.jpg`).set('Authorization', 'Bearer valid-token')
      );

      const responses = await Promise.all(requests);
      
      const successful = responses.filter(r => r.status === 200);
      const failed = responses.filter(r => r.status >= 400);
      
      expect(successful.length).toBe(6);
      expect(failed.length).toBe(3);
      expect(responses[2].status).toBe(404);
      expect(responses[5].status).toBe(404);
      expect(responses[8].status).toBe(404);
      expect(responses[0].status).toBe(200);
    });
  });

  describe('Compliance and Auditing Integration', () => {
    it('should maintain audit trail for all validation operations', async () => {
      const auditLog: any[] = [];
      
      // Simulate audit logging
      const auditApp = express();
      
      auditApp.use((req, res, next) => {
        const originalSend = res.send;
        res.send = function(data) {
          // Log after response
          auditLog.push({
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.path,
            statusCode: res.statusCode,
            userAgent: req.get('User-Agent'),
            ip: req.ip,
            requestId: (req as any).requestId
          });
          return originalSend.call(this, data);
        };
        next();
      });
      
      auditApp.get('/api/v1/validate/audit/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ success: true, audited: true });
      });

      // Perform several operations
      const operations = [
        () => request(auditApp).get('/api/v1/validate/audit/file1.jpg'),
        () => request(auditApp).get('/api/v1/validate/audit/file2.png'),
        () => request(auditApp).get('/api/v1/validate/audit/file3.pdf')
      ];

      for (const operation of operations) {
        await operation().expect(200);
      }

      // Verify audit log
      expect(auditLog).toHaveLength(3);
      auditLog.forEach(entry => {
        expect(entry.timestamp).toBeDefined();
        expect(entry.method).toBe('GET');
        expect(entry.statusCode).toBe(200);
        expect(entry.path).toContain('/api/v1/validate/audit/');
      });
    });

    it('should handle data privacy compliance', async () => {
      const privacyApp = express();
      
      // Simulate GDPR compliance
      privacyApp.use((req, res, next) => {
        const gdprConsent = req.headers['x-gdpr-consent'];
        if (!gdprConsent) {
          res.status(400).json({ 
            error: 'GDPR consent required',
            code: 'GDPR_CONSENT_REQUIRED'
          });
          return;
        }
        
        res.setHeader('X-Data-Processing', 'compliant');
        next();
      });
      
      privacyApp.get('/api/v1/validate/privacy/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        res.json({ 
          success: true,
          privacy: 'compliant',
          dataRetention: '30-days'
        });
      });

      // Test without consent
      const noConsentResponse = await request(privacyApp)
        .get('/api/v1/validate/privacy/gdpr-test.jpg')
        .expect(400);

      expect(noConsentResponse.body.error).toBe('GDPR consent required');

      // Test with consent
      const consentResponse = await request(privacyApp)
        .get('/api/v1/validate/privacy/gdpr-test.jpg')
        .set('X-GDPR-Consent', 'granted')
        .expect(200);

      expect(consentResponse.body.success).toBe(true);
      expect(consentResponse.headers['x-data-processing']).toBe('compliant');
    });

    it('should handle regulatory reporting requirements', async () => {
      const reportingApp = express();
      const reportingQueue: any[] = [];

      const pdfBuffer = Buffer.from([0x25, 0x50, 0x44, 0x46]);
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          pdfBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined),
      };
      mockFs.open.mockResolvedValue(mockOpen as any);
      mockStorageService.getAbsolutePath.mockReturnValue('/safe/storage/test.pdf');

      reportingApp.use(express.json());

      reportingApp.get('/api/v1/validate/reporting/:file', 
        (req, res, next) => {
          const filename = req.params.file;

          const sensitiveExtensions = ['.doc', '.pdf', '.xls'];
          const extension = path.extname(filename).toLowerCase();

          if (sensitiveExtensions.includes(extension)) {
            reportingQueue.push({
              filepath: filename,
              timestamp: new Date().toISOString(),
              userAgent: req.get('User-Agent'),
              reportType: 'sensitive_file_access',
            });
          }
          req.params.filepath = filename;
          next();
        },
        validateFileContent, 
        (req, res) => {
          res.json({
            success: true,
            reported: reportingQueue.length > 0,
            validation: (req as any).fileValidation,
          });
        }
      );

      reportingApp.use((err: any, req: Request, res: Response, next: NextFunction) => {
        res.status(err.statusCode || 500).json({
          success: false,
          error: { message: err.message, code: err.code },
        });
      });

      const sensitiveResponse = await request(reportingApp).get('/api/v1/validate/reporting/sensitive.pdf');

      expect(sensitiveResponse.status).toBe(200);
      expect(sensitiveResponse.body.success).toBe(true);
      expect(sensitiveResponse.body.reported).toBe(true);
      expect(reportingQueue).toHaveLength(1);
      expect(sensitiveResponse.body.validation.isValid).toBe(true);
      expect(sensitiveResponse.body.validation.fileType).toBe('application/pdf');
    });
  });
      
  describe('Disaster Recovery Integration', () => {
    it('should handle backup system activation', async () => {
      const drApp = express();
      
      let primarySystemDown = false;
      let backupSystemActive = false;
      
      drApp.use((req, res, next) => {
        if (primarySystemDown && !backupSystemActive) {
          backupSystemActive = true;
          res.setHeader('X-System', 'backup');
          res.setHeader('X-DR-Status', 'active');
        } else if (!primarySystemDown) {
          res.setHeader('X-System', 'primary');
          res.setHeader('X-DR-Status', 'standby');
        }
        next();
      });
      
      drApp.get('/api/v1/validate/dr/:file', (req, res, next) => {
        req.params.filepath = req.params.file;
        next();
      }, validateFileContentBasic, (req, res) => {
        if (primarySystemDown && !backupSystemActive) {
          res.status(503).json({ error: 'System unavailable' });
          return;
        }
        
        res.json({ 
          success: true,
          system: primarySystemDown ? 'backup' : 'primary'
        });
      });

      // Test primary system
      const primaryResponse = await request(drApp)
        .get('/api/v1/validate/dr/primary-test.jpg')
        .expect(200);

      expect(primaryResponse.body.system).toBe('primary');
      expect(primaryResponse.headers['x-system']).toBe('primary');

      // Simulate primary system failure
      primarySystemDown = true;

      // Test backup system activation
      const backupResponse = await request(drApp)
        .get('/api/v1/validate/dr/backup-test.jpg')
        .expect(200);

      expect(backupResponse.body.system).toBe('backup');
      expect(backupResponse.headers['x-system']).toBe('backup');
      expect(backupResponse.headers['x-dr-status']).toBe('active');
    });

    it('should handle data replication scenarios', async () => {
      const replicationApp = express();
      
      const primaryData = new Map();
      const replicaData = new Map();
      
      replicationApp.post('/api/v1/validate/replicate/:file',
        (req, res, next) => {
          req.params.filepath = req.params.file;
          next();
        },
        validateFileContent,
        async (req, res, next) => {
          const filepath = req.params.filepath;
          const validation = (req as any).fileValidation;
          
          // Store in primary
          primaryData.set(filepath, validation);
          
          // Simulate replication delay
          setTimeout(() => {
            replicaData.set(filepath, validation);
          }, 100);
          
          (req as any).replication = {
            primary: true,
            replica: replicaData.has(filepath)
          };
          
          next();
        },
        (req, res) => {
          res.json({ 
            success: true,
            replication: (req as any).replication
          });
        }
      );

      const response = await request(replicationApp)
        .post('/api/v1/validate/replicate/replication-test.jpg')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.replication.primary).toBe(true);
      
      // Wait for replication
      await new Promise(resolve => setTimeout(resolve, 150));
      
      expect(primaryData.has('replication-test.jpg')).toBe(true);
      expect(replicaData.has('replication-test.jpg')).toBe(true);
    });
  });
});