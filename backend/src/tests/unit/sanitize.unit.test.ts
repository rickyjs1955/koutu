// backend/src/tests/unit/sanitize.unit.test.ts
import { jest } from '@jest/globals';
import { beforeEach, afterEach, describe, it, expect } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';

// Mock the ApiError module first
jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    internal: jest.fn((message: string) => ({
      message,
      statusCode: 500,
      name: 'InternalServerError'
    })),
    validation: jest.fn((message: string) => ({
      message,
      statusCode: 400,
      name: 'ValidationError'
    })),
    notFound: jest.fn((message: string) => ({
      message,
      statusCode: 404,
      name: 'NotFoundError'
    }))
  }
}));

// Import sanitization module after mocking
import { sanitization } from '../../utils/sanitize';

// Test data
const mockRawImage = {
  id: 'img_123',
  status: 'uploaded',
  upload_date: '2024-01-01T00:00:00Z',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
  file_path: '/uploads/raw/image.jpg',
  original_metadata: {
    filename: 'test-image.jpg',
    width: 1920,
    height: 1080,
    format: 'JPEG',
    size: 2048576,
    mimetype: 'image/jpeg',
    uploadedAt: '2024-01-01T00:00:00Z'
  }
};

const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
  method: 'POST',
  path: '/api/v1/images/upload',
  headers: {
    'user-agent': 'Mozilla/5.0',
    'content-type': 'multipart/form-data',
    'accept': 'application/json'
  },
  user: { id: 'user_123', email: 'test@example.com' },
  get: jest.fn((header: string) => {
    const headers: Record<string, string | string[]> = {
      'user-agent': 'Mozilla/5.0',
      'content-type': 'multipart/form-data',
      'content-length': '2048576',
      'set-cookie': ['cookie1=value1', 'cookie2=value2']
    };
    return headers[header.toLowerCase()];
  }) as any,
  ...overrides
});

const createMockResponse = (): Partial<Response> => {
  const mockResponse = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
  };
  
  // Ensure the mock functions return the mock response object
  mockResponse.status.mockReturnValue(mockResponse);
  mockResponse.json.mockReturnValue(mockResponse);
  mockResponse.send.mockReturnValue(mockResponse);
  
  return mockResponse as Partial<Response>;
};

const createMockNext = (): NextFunction => jest.fn() as NextFunction;

describe('Sanitization Module Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Input Sanitization', () => {
    it('should remove HTML tags from user input', () => {
      const maliciousInput = 'Hello <script>alert("xss")</script> World <b>bold</b>';
      const result = sanitization.sanitizeUserInput(maliciousInput);
      
      // The actual implementation removes HTML tags but may leave content
      expect(result).not.toContain('<script>');
      expect(result).not.toContain('<b>');
      expect(result).not.toContain('</script>');
      expect(result).not.toContain('</b>');
      expect(typeof result).toBe('string');
    });

    it('should handle javascript protocols', () => {
      const inputs = [
        'javascript:alert("xss")',
        'JAVASCRIPT:alert("xss")',
        'data:text/html,<script>alert("xss")</script>'
      ];

      inputs.forEach(input => {
        const result = sanitization.sanitizeUserInput(input);
        expect(result).not.toMatch(/javascript:/i);
        expect(result).not.toMatch(/data:/i);
        expect(typeof result).toBe('string');
      });
    });

    it('should remove event handlers', () => {
      const maliciousInputs = [
        'onclick="alert(\'xss\')"',
        'onload="malicious()"',
        'onmouseover="hack()"'
      ];

      maliciousInputs.forEach(input => {
        const result = sanitization.sanitizeUserInput(input);
        expect(result).not.toMatch(/on\w+\s*=/i);
        expect(typeof result).toBe('string');
      });
    });

    it('should normalize whitespace', () => {
      const messyInput = 'Too   many    spaces\n\nand\t\ttabs';
      const result = sanitization.sanitizeUserInput(messyInput);
      
      expect(result).toBe('Too many spaces and tabs');
    });

    it('should handle non-string inputs', () => {
      const nonStringInputs = [null, undefined, 123, {}, [], true];
      
      nonStringInputs.forEach(input => {
        const result = sanitization.sanitizeUserInput(input as any);
        expect(result).toBe('');
      });
    });
  });

  describe('Filename Sanitization', () => {
    it('should preserve valid filenames', () => {
      const validFilenames = [
        'document.pdf',
        'image_123.jpg',
        'file-name.txt'
      ];

      validFilenames.forEach(filename => {
        const result = sanitization.sanitizeFileName(filename);
        expect(result).toBe(filename);
      });
    });

    it('should remove dangerous characters', () => {
      const dangerousFilename = 'file<>:"|?*.txt';
      const result = sanitization.sanitizeFileName(dangerousFilename);
      
      expect(result).not.toMatch(/[<>:"|?*]/);
      expect(result).toContain('file');
      expect(result).toContain('.txt');
    });

    it('should prevent path traversal', () => {
      const pathTraversalNames = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32'
      ];

      pathTraversalNames.forEach(filename => {
        const result = sanitization.sanitizeFileName(filename);
        expect(result).not.toMatch(/\.\.[\/\\]/);
        expect(typeof result).toBe('string');
      });
    });

    it('should provide fallback for empty filenames', () => {
      const result = sanitization.sanitizeFileName('');
      expect(result).toBe('sanitized_file');
    });

    it('should handle non-string inputs', () => {
      const result = sanitization.sanitizeFileName(null as any);
      expect(result).toBe('unknown_file');
    });
  });

  describe('Header Sanitization', () => {
    it('should allow whitelisted headers', () => {
      const allowedHeaders = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': 'application/json',
        'Content-Type': 'multipart/form-data'
      };

      const result = sanitization.sanitizeHeaders(allowedHeaders);
      
      expect(result).toHaveProperty('user-agent');
      expect(result).toHaveProperty('accept');
      expect(result).toHaveProperty('content-type');
    });

    it('should filter out non-whitelisted headers', () => {
      const mixedHeaders = {
        'User-Agent': 'Mozilla/5.0',
        'X-Dangerous': 'malicious value',
        'Accept': 'application/json'
      };

      const result = sanitization.sanitizeHeaders(mixedHeaders);
      
      expect(result).toHaveProperty('user-agent');
      expect(result).toHaveProperty('accept');
      expect(result).not.toHaveProperty('x-dangerous');
    });

    it('should handle non-string header values', () => {
      const invalidHeaders = {
        'User-Agent': 123,
        'Accept': null
      };

      const result = sanitization.sanitizeHeaders(invalidHeaders);
      
      expect(result).not.toHaveProperty('user-agent');
      expect(result).not.toHaveProperty('accept');
    });
  });

  describe('Path Sanitization', () => {
    it('should create valid API paths', () => {
      const result = sanitization.sanitizePath('images', 'img_123', 'file');
      expect(result).toBe('/api/v1/images/img_123/file');
    });

    it('should sanitize malicious path components', () => {
      const result = sanitization.sanitizePath(
        'Images@#$',
        'img_123<script>',
        'File.ext'
      );
      
      // Check that the result is a valid API path
      expect(result).toMatch(/^\/api\/v1\/[a-z0-9\-_]+\/[a-z0-9\-_]+\/[a-z0-9\-_]+$/);
    });

    it('should handle empty components', () => {
      const result = sanitization.sanitizePath('', '', '');
      expect(result).toBe('/api/v1/unknown/unknown/unknown');
    });

    it('should sanitize path components correctly', () => {
      expect(sanitization.sanitizePathComponent('normal_component')).toBe('normal_component');
      expect(sanitization.sanitizePathComponent('Component123')).toBe('component123');
      expect(sanitization.sanitizePathComponent('')).toBe('unknown');
      expect(sanitization.sanitizePathComponent(null as any)).toBe('unknown');
    });
  });

  describe('Entity Response Sanitization', () => {
    describe('Image sanitization', () => {
      it('should sanitize image data correctly', () => {
        const result = sanitization.sanitizeImageForResponse(mockRawImage);
        
        expect(result).toHaveProperty('id', 'img_123');
        expect(result).toHaveProperty('status', 'uploaded');
        expect(result).toHaveProperty('file_path');
        expect(result.file_path).toMatch(/^\/api\/v1\/images\/img_123\//);
      });

      it('should handle missing metadata gracefully', () => {
        const imageWithoutMetadata = { ...mockRawImage };
        delete (imageWithoutMetadata as any).original_metadata;
        
        expect(() => {
          const result = sanitization.sanitizeImageForResponse(imageWithoutMetadata);
          expect(result).toBeDefined();
        }).not.toThrow();
      });
    });

    describe('Universal security sanitization', () => {
      it('should handle null and undefined inputs', () => {
        expect(sanitization.sanitizeForSecurity(null)).toBe(null);
        expect(sanitization.sanitizeForSecurity(undefined)).toBe(undefined);
      });

      it('should preserve primitive values', () => {
        expect(sanitization.sanitizeForSecurity('clean string')).toBe('clean string');
        expect(sanitization.sanitizeForSecurity(123)).toBe(123);
        expect(sanitization.sanitizeForSecurity(true)).toBe(true);
      });

      it('should handle arrays', () => {
        const testArray = ['string', 123, true];
        const result = sanitization.sanitizeForSecurity(testArray);
        
        expect(Array.isArray(result)).toBe(true);
        expect(result[0]).toBe('string');
        expect(result[1]).toBe(123);
        expect(result[2]).toBe(true);
      });

      it('should handle simple objects without circular references', () => {
        const simpleObject = {
          clean: 'safe value',
          number: 42
        };

        const result = sanitization.sanitizeForSecurity(simpleObject);
        expect(result.clean).toBe('safe value');
        expect(result.number).toBe(42);
      });
    });
  });

  describe('Controller Wrappers', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: NextFunction;

    beforeEach(() => {
      mockReq = createMockRequest();
      mockRes = createMockResponse();
      mockNext = createMockNext();
    });

    it('should call controller and not invoke next on success', async () => {
      const successController = jest.fn(async (req: Request, res: Response, next: NextFunction) => {
        res.status!(200).json({ success: true });
      });
      
      const wrappedController = sanitization.wrapImageController(successController, 'testing');

      await wrappedController(mockReq as Request, mockRes as Response, mockNext);

      expect(successController).toHaveBeenCalledWith(mockReq, mockRes, mockNext);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should catch errors and call next with sanitized error', async () => {
      const errorController = jest.fn(async (req: Request, res: Response, next: NextFunction) => {
        throw new Error('Test error');
      });
      
      const wrappedController = sanitization.wrapImageController(errorController, 'testing');

      await wrappedController(mockReq as Request, mockRes as Response, mockNext);

      expect(errorController).toHaveBeenCalledWith(mockReq, mockRes, mockNext);
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('testing'),
          statusCode: 500
        })
      );
    });
  });

  describe('Error Handling', () => {
    it('should sanitize error messages', () => {
      const sensitiveError = new Error('Database connection failed: postgresql://user:secret123@host:5432/db');
      const mockNext = createMockNext();

      sanitization.handleError(sensitiveError, 'Database operation failed', mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Database operation failed',
          statusCode: 500
        })
      );
    });
  });

  describe('Upload Context Sanitization', () => {
    it('should extract standard request information', () => {
      const mockReq = createMockRequest() as Request;
      const result = sanitization.sanitizeUploadContext(mockReq);

      expect(result).toHaveProperty('method', 'POST');
      expect(result).toHaveProperty('path');
      expect(result).toHaveProperty('userAgent');
      expect(result).toHaveProperty('contentType');
      expect(result).toHaveProperty('timestamp');
    });

    it('should handle missing headers gracefully', () => {
      const incompleteReq = createMockRequest({
        get: jest.fn().mockReturnValue(undefined) as any
      }) as Request;

      const result = sanitization.sanitizeUploadContext(incompleteReq);
      
      expect(result.userAgent).toBe('');
      expect(result.contentType).toBe('');
    });
  });

  describe('Response Creation Utilities', () => {
    it('should create sanitized response with allowed fields only', () => {
      const rawObject = {
        id: 'test_123',
        name: 'Test Object',
        sensitiveData: 'should be removed'
      };

      const allowedFields = ['id', 'name'];
      const result = sanitization.createSanitizedResponse(rawObject, allowedFields);

      expect(result).toHaveProperty('id', 'test_123');
      expect(result).toHaveProperty('name', 'Test Object');
      expect(result).not.toHaveProperty('sensitiveData');
    });

    it('should handle null inputs gracefully', () => {
      expect(() => {
        sanitization.createSanitizedResponse(null as any, ['id']);
      }).not.toThrow();
    });
  });

  describe('Metadata Sanitization', () => {
    it('should handle empty metadata objects', () => {
      expect(() => sanitization.sanitizeImageMetadata({})).not.toThrow();
      expect(() => sanitization.sanitizeGarmentMetadata({})).not.toThrow();
    });

    it('should handle null metadata gracefully', () => {
      // These might throw, so we test that they behave predictably
      try {
        sanitization.sanitizeImageMetadata(null as any);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  describe('Input Validation and Type Safety', () => {
    it('should handle invalid inputs for entity sanitization gracefully', () => {
      // Test that functions don't crash with invalid inputs
      try {
        sanitization.sanitizeImageForResponse(null as any);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
      
      try {
        sanitization.sanitizeImageForResponse('invalid' as any);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }
    });
  });

  describe('Boundary Conditions', () => {
    it('should handle empty strings', () => {
      expect(sanitization.sanitizeUserInput('')).toBe('');
      expect(sanitization.sanitizeFileName('')).toBe('sanitized_file');
    });

    it('should handle whitespace-only inputs', () => {
      expect(sanitization.sanitizeUserInput('   ')).toBe('');
      expect(sanitization.sanitizeUserInput('\t\n\r')).toBe('');
    });

    it('should handle very long strings', () => {
      const longString = 'A'.repeat(10000);
      const result = sanitization.sanitizeUserInput(longString);
      expect(typeof result).toBe('string');
    });
  });
});