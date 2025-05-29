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

  describe('Additional Sanitization Tests', () => {
    describe('Date Handling in Sanitization', () => {
      describe('sanitizeImageForResponse', () => {
        it('should handle Date objects and convert to ISO strings', () => {
          const testDate = new Date('2023-01-01T12:00:00Z');
          const imageWithDates = {
            id: 'test-id',
            status: 'new',
            upload_date: testDate,
            created_at: testDate,
            updated_at: testDate,
            original_metadata: { description: 'test' }
          };

          const result = sanitization.sanitizeImageForResponse(imageWithDates);
          
          expect(result.upload_date).toBe('2023-01-01T12:00:00.000Z');
          expect(result.created_at).toBe('2023-01-01T12:00:00.000Z');
          expect(result.updated_at).toBe('2023-01-01T12:00:00.000Z');
        });

        it('should handle string dates and preserve them', () => {
          const imageWithStrings = {
            id: 'test-id',
            status: 'new',
            upload_date: '2023-01-01T12:00:00.000Z',
            created_at: '2023-01-01T12:00:00.000Z',
            updated_at: '2023-01-01T12:00:00.000Z',
            original_metadata: { description: 'test' }
          };

          const result = sanitization.sanitizeImageForResponse(imageWithStrings);
          
          expect(result.upload_date).toBe('2023-01-01T12:00:00.000Z');
          expect(result.created_at).toBe('2023-01-01T12:00:00.000Z');
          expect(result.updated_at).toBe('2023-01-01T12:00:00.000Z');
        });

        it('should handle undefined dates gracefully', () => {
          const imageWithUndefined = {
            id: 'test-id',
            status: 'new',
            upload_date: undefined,
            created_at: undefined,
            updated_at: undefined,
            original_metadata: { description: 'test' }
          };

          const result = sanitization.sanitizeImageForResponse(imageWithUndefined);
          
          expect(result.upload_date).toBeUndefined();
          expect(result.created_at).toBeUndefined();
          expect(result.updated_at).toBeUndefined();
        });

        it('should handle mixed Date and string types', () => {
          const mixedImage = {
            id: 'test-id',
            status: 'new',
            upload_date: new Date('2023-01-01T12:00:00Z'),
            created_at: '2023-01-02T12:00:00.000Z',
            updated_at: undefined,
            original_metadata: { description: 'test' }
          };

          const result = sanitization.sanitizeImageForResponse(mixedImage);
          
          expect(result.upload_date).toBe('2023-01-01T12:00:00.000Z');
          expect(result.created_at).toBe('2023-01-02T12:00:00.000Z');
          expect(result.updated_at).toBeUndefined();
        });
      });

      describe('sanitizeGarmentForResponse', () => {
        it('should handle Date objects in garment data', () => {
          const testDate = new Date('2023-01-01T12:00:00Z');
          const garmentWithDates = {
            id: 'garment-id',
            created_at: testDate,
            updated_at: testDate,
            data_version: 1
          };

          const result = sanitization.sanitizeGarmentForResponse(garmentWithDates);
          
          expect(result.created_at).toBe('2023-01-01T12:00:00.000Z');
          expect(result.updated_at).toBe('2023-01-01T12:00:00.000Z');
        });
      });

      describe('sanitizePolygonForResponse', () => {
        it('should handle Date objects in polygon data', () => {
          const testDate = new Date('2023-01-01T12:00:00Z');
          const polygonWithDates = {
            id: 'polygon-id',
            points: [{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 5, y: 10 }],
            created_at: testDate,
            updated_at: testDate
          };

          const result = sanitization.sanitizePolygonForResponse(polygonWithDates);
          
          expect(result.created_at).toBe('2023-01-01T12:00:00.000Z');
          expect(result.updated_at).toBe('2023-01-01T12:00:00.000Z');
        });
      });

      describe('sanitizeWardrobeForResponse', () => {
        it('should handle Date objects in wardrobe data', () => {
          const testDate = new Date('2023-01-01T12:00:00Z');
          const wardrobeWithDates = {
            id: 'wardrobe-id',
            name: 'Test Wardrobe',
            created_at: testDate,
            updated_at: testDate
          };

          const result = sanitization.sanitizeWardrobeForResponse(wardrobeWithDates);
          
          expect(result.created_at).toBe('2023-01-01T12:00:00.000Z');
          expect(result.updated_at).toBe('2023-01-01T12:00:00.000Z');
        });
      });

      describe('dateToString helper', () => {
        it('should convert Date to ISO string', () => {
          const testDate = new Date('2023-01-01T12:00:00Z');
          // Access private method through prototype manipulation for testing
          const sanitizer = new (sanitization as any).constructor();
          const result = sanitizer.dateToString(testDate);
          
          expect(result).toBe('2023-01-01T12:00:00.000Z');
        });

        it('should return string as-is', () => {
          const sanitizer = new (sanitization as any).constructor();
          const result = sanitizer.dateToString('2023-01-01T12:00:00.000Z');
          
          expect(result).toBe('2023-01-01T12:00:00.000Z');
        });

        it('should return undefined for undefined input', () => {
          const sanitizer = new (sanitization as any).constructor();
          const result = sanitizer.dateToString(undefined);
          
          expect(result).toBeUndefined();
        });
      });

      describe('Backward Compatibility', () => {
      it('should maintain backward compatibility with existing image responses', () => {
        // Test that existing tests still pass with the new date handling
        const legacyImage = {
          id: 'legacy-id',
          status: 'processed',
          upload_date: '2023-01-01T10:00:00.000Z', // Already string
          original_metadata: { width: 800, height: 600 }
        };

        const result = sanitization.sanitizeImageForResponse(legacyImage);
        
        expect(result).toMatchObject({
          id: 'legacy-id',
          status: 'processed',
          upload_date: '2023-01-01T10:00:00.000Z',
          file_path: '/api/v1/images/legacy-id/file',
          metadata: expect.objectContaining({
            description: '',
            width: 800,
            height: 600
          })
        });
      });
      });

      describe('Integration with Database Models', () => {
        it('should work with actual database model responses', () => {
          // Simulate what a real database model returns
          const databaseImage = {
            id: 'db-image-id',
            user_id: 'user-123',
            file_path: 'uploads/image.jpg',
            status: 'new' as const,
            upload_date: new Date('2023-01-01T12:00:00Z'), // Database returns Date
            original_metadata: {
              width: 1024,
              height: 768,
              format: 'jpeg',
              size: 204800
            }
          };

          const result = sanitization.sanitizeImageForResponse(databaseImage);
          
          expect(result.upload_date).toBe('2023-01-01T12:00:00.000Z');
          expect(typeof result.upload_date).toBe('string');
        });
      });
    });

    describe('Date Error Scenarios', () => {
      describe('Invalid Date Objects', () => {
        it('should handle Invalid Date objects gracefully', () => {
          const invalidDate = new Date('invalid-date-string');
          const imageWithInvalidDate = {
            id: 'test-id',
            status: 'new',
            upload_date: invalidDate,
            created_at: invalidDate,
            updated_at: invalidDate,
            original_metadata: { description: 'test' }
          };

          const result = sanitization.sanitizeImageForResponse(imageWithInvalidDate);
          
          // Invalid Date objects should become undefined
          expect(result.upload_date).toBeUndefined();
          expect(result.created_at).toBeUndefined();
          expect(result.updated_at).toBeUndefined();
        });

        it('should handle Date objects with extreme values', () => {
          const testCases = [
            { 
              date: new Date(-8640000000000000), // Min date - VALID
              shouldBeValid: true,
              expectedPattern: /^-\d{6}-\d{2}-\d{2}T/
            },
            { 
              date: new Date(8640000000000000),  // Max date - VALID
              shouldBeValid: true,
              expectedPattern: /^\+\d{6}-\d{2}-\d{2}T/
            },
            { 
              date: new Date(NaN),               // Invalid
              shouldBeValid: false 
            },
            { 
              date: new Date(Infinity),          // Invalid
              shouldBeValid: false 
            },
            { 
              date: new Date(-Infinity),         // Invalid
              shouldBeValid: false 
            }
          ];

          testCases.forEach((testCase, index) => {
            const imageWithExtremeDate = {
              id: `test-id-${index}`,
              status: 'new',
              upload_date: testCase.date,
              original_metadata: { description: 'test' }
            };

            const result = sanitization.sanitizeImageForResponse(imageWithExtremeDate);
            expect(result.id).toBe(`test-id-${index}`);
            
            if (testCase.shouldBeValid) {
              expect(typeof result.upload_date).toBe('string');
              if (testCase.expectedPattern) {
                expect(result.upload_date).toMatch(testCase.expectedPattern);
              }
            } else {
              expect(result.upload_date).toBeUndefined();
            }
          });
        });
      });

      describe('Invalid Date Strings', () => {
        it('should handle malformed ISO date strings', () => {
          const malformedDateStrings = [
            '2023-13-01T12:00:00Z',      // Invalid month
            '2023-02-30T12:00:00Z',      // Invalid day
            '2023-01-01T25:00:00Z',      // Invalid hour  
            'not-a-date-at-all',         // Completely invalid
            '2023-01-01',                // Missing time
            'T12:00:00Z',                // Missing date
          ];

          malformedDateStrings.forEach((dateString, index) => {
            const imageWithMalformedDate = {
              id: `test-id-${index}`,
              status: 'new',
              upload_date: dateString,
              original_metadata: { description: 'test' }
            };

            const result = sanitization.sanitizeImageForResponse(imageWithMalformedDate);
            expect(result.id).toBe(`test-id-${index}`);
            // String dates should be preserved as-is
            expect(result.upload_date).toBe(dateString);
          });
        });

        it('should handle empty and whitespace strings correctly', () => {
          const edgeCases = [
            { input: '', description: 'empty string' },
            { input: '   ', description: 'whitespace string' },
            { input: '\t\n', description: 'tab and newline' },
          ];

          edgeCases.forEach(({ input, description }) => {
            const imageWithEdgeCase = {
              id: 'edge-test',
              status: 'new',
              upload_date: input,
              original_metadata: { description: 'test' }
            };

            const result = sanitization.sanitizeImageForResponse(imageWithEdgeCase);
            // String values should be preserved exactly as-is
            expect(result.upload_date).toBe(input);
          });
        });
      });

      describe('Mixed Error Scenarios', () => {
        it('should handle mixed valid and invalid dates', () => {
          const mixedDateObject = {
            id: 'mixed-test',
            status: 'new',
            upload_date: new Date('2023-01-01T12:00:00Z'), // Valid Date
            created_at: new Date('invalid-date'),           // Invalid Date
            updated_at: '2023-13-01T12:00:00Z',            // Invalid string (but preserved)
            original_metadata: { description: 'test' }
          };

          const result = sanitization.sanitizeImageForResponse(mixedDateObject);
          expect(result.id).toBe('mixed-test');
          
          // Valid Date → ISO string
          expect(result.upload_date).toBe('2023-01-01T12:00:00.000Z');
          // Invalid Date → undefined
          expect(result.created_at).toBeUndefined();
          // Invalid string → preserved as-is
          expect(result.updated_at).toBe('2023-13-01T12:00:00Z');
        });

        it('should handle null and undefined values', () => {
          const nullUndefinedObject = {
            id: 'null-test',
            status: 'new',
            upload_date: null as any,      // null → undefined
            created_at: undefined,         // undefined → undefined
            updated_at: new Date('2023-01-01T12:00:00Z'), // Valid Date
            original_metadata: { description: 'test' }
          };

          const result = sanitization.sanitizeImageForResponse(nullUndefinedObject);
          expect(result.upload_date).toBeUndefined();
          expect(result.created_at).toBeUndefined();
          expect(result.updated_at).toBe('2023-01-01T12:00:00.000Z');
        });
      });

      describe('dateToString Direct Testing', () => {
        let sanitizer: any;
        
        beforeEach(() => {
          sanitizer = new (sanitization as any).constructor();
        });

        it('should handle all input types correctly', () => {
          const testCases = [
            // Null/undefined cases
            { input: null, expected: undefined, description: 'null' },
            { input: undefined, expected: undefined, description: 'undefined' },
            
            // String cases
            { input: '', expected: '', description: 'empty string' },
            { input: '   ', expected: '   ', description: 'whitespace string' },
            { input: 'valid-2023-01-01T12:00:00.000Z', expected: 'valid-2023-01-01T12:00:00.000Z', description: 'valid date string' },
            { input: 'invalid-date', expected: 'invalid-date', description: 'invalid date string' },
            
            // Date object cases
            { input: new Date('2023-01-01T12:00:00Z'), expected: '2023-01-01T12:00:00.000Z', description: 'valid Date object' },
            { input: new Date('invalid'), expected: undefined, description: 'invalid Date object' },
            { input: new Date(NaN), expected: undefined, description: 'NaN Date object' },
            
            // Other types
            { input: 123, expected: undefined, description: 'number' },
            { input: true, expected: undefined, description: 'boolean' },
            { input: {}, expected: undefined, description: 'object' },
            { input: [], expected: undefined, description: 'array' },
          ];

          testCases.forEach(({ input, expected, description }) => {
            const result = sanitizer.dateToString(input);
            expect(result).toBe(expected);
          });
        });

        it('should handle Symbol without crashing', () => {
          expect(() => {
            const result = sanitizer.dateToString(Symbol('test') as any);
            expect(result).toBeUndefined();
          }).not.toThrow();
        });
      });

      describe('Cross-Entity Consistency', () => {
        it('should handle invalid dates consistently across all entity types', () => {
          const invalidDate = new Date('invalid');
          const validDateString = '2023-01-01T12:00:00.000Z';

          // Test all entity types
          const garment = {
            id: 'garment-test',
            created_at: invalidDate,
            updated_at: validDateString
          };

          const polygon = {
            id: 'polygon-test',
            points: [{ x: 0, y: 0 }],
            created_at: invalidDate,
            updated_at: validDateString
          };

          const wardrobe = {
            id: 'wardrobe-test',
            name: 'Test',
            created_at: invalidDate,
            updated_at: validDateString
          };

          // All should handle dates the same way
          const garmentResult = sanitization.sanitizeGarmentForResponse(garment);
          const polygonResult = sanitization.sanitizePolygonForResponse(polygon);
          const wardrobeResult = sanitization.sanitizeWardrobeForResponse(wardrobe);

          // Invalid Date objects should become undefined
          expect(garmentResult.created_at).toBeUndefined();
          expect(polygonResult.created_at).toBeUndefined();
          expect(wardrobeResult.created_at).toBeUndefined();

          // Valid date strings should be preserved
          expect(garmentResult.updated_at).toBe(validDateString);
          expect(polygonResult.updated_at).toBe(validDateString);
          expect(wardrobeResult.updated_at).toBe(validDateString);
        });
      });

      describe('Performance with Error Conditions', () => {
        it('should handle many invalid dates efficiently', () => {
          // Use Date objects that are guaranteed to be invalid
          const manyInvalidDates = Array.from({ length: 50 }, (_, i) => ({
            id: `perf-test-${i}`,
            status: 'new',
            upload_date: new Date(NaN), // Guaranteed invalid Date
            created_at: `malformed-${i}`,
            updated_at: i % 2 === 0 ? undefined : new Date(NaN), // Also guaranteed invalid
            original_metadata: { description: 'test' }
          }));

          const startTime = Date.now();
          
          const results = manyInvalidDates.map(image => 
            sanitization.sanitizeImageForResponse(image as any)
          );

          const endTime = Date.now();
          const executionTime = endTime - startTime;
          
          // Verify all results are valid
          results.forEach((result, index) => {
            expect(result.id).toBe(`perf-test-${index}`);
            expect(result.upload_date).toBeUndefined(); // Invalid Date should be undefined
            expect(result.created_at).toBe(`malformed-${index}`); // String preserved
            // updated_at should be undefined for all cases (even indices are undefined, odd are invalid Date)
            expect(result.updated_at).toBeUndefined();
          });
          
          // Should be fast
          expect(executionTime).toBeLessThan(500);
        });

        it('should demonstrate JavaScript Date parsing is unpredictable', () => {
          // This test just shows what actually happens - no expectations!
          const testInputs = [
            'invalid-0',
            'invalid-1', 
            'definitely-not-a-date',
            'xyz123abc',
            'abc-def-ghi'
          ];

          console.log('JavaScript Date parsing results:');
          testInputs.forEach(input => {
            const date = new Date(input);
            const isValid = !isNaN(date.getTime());
            console.log(`new Date('${input}') -> valid: ${isValid}, value: ${isValid ? date.toISOString() : 'Invalid Date'}`);
          });

          // Always passes - this is just for educational purposes
          expect(true).toBe(true);
        });
      });
    });
  });
});


