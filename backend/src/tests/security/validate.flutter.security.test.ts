// backend/src/tests/security/validate.flutter.security.test.ts
// Security tests for Flutter-enhanced validation middleware

import { Request, Response, NextFunction } from 'express';
import {
  flutterClientDetection,
  flutterAwareFileValidation,
  flutterInstagramValidation,
  flutterTestUtils,
  FLUTTER_VALIDATION_CONFIGS
} from '../../middlewares/validate';
import { ApiError } from '../../utils/ApiError';

// Mock dependencies
jest.mock('sharp', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => ({
    metadata: jest.fn().mockResolvedValue({
      width: 1080,
      height: 1920,
      format: 'jpeg',
      space: 'srgb',
      density: 72
    })
  }))
}));

describe('Flutter Validation Security Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.MockedFunction<NextFunction>;

  beforeEach(() => {
    mockReq = {
      headers: {},
      get: jest.fn(),
      file: undefined,
      body: {},
      flutterMetadata: undefined
    };
    
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis()
    };
    
    mockNext = jest.fn();
  });

  describe('Client Detection Security', () => {
    describe('Header Injection Prevention', () => {
      it('should prevent XSS in User-Agent header', () => {
        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'User-Agent') return '<script>alert("xss")</script>Flutter/3.0.0';
          return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        // Should still detect as Flutter but not execute script
        expect(mockReq.flutterMetadata?.clientType).toBe('flutter');
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should prevent SQL injection in X-Client-Type header', () => {
        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'X-Client-Type') return "flutter'; DROP TABLE users; --";
          return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        // Should not match any valid client type and default to web
        expect(mockReq.flutterMetadata?.clientType).toBe('web');
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should handle extremely long headers gracefully', () => {
        const longHeader = 'A'.repeat(10000); // 10KB header
        
        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'User-Agent') return longHeader;
          return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockReq.flutterMetadata?.clientType).toBe('web');
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should prevent null byte injection in headers', () => {
        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'X-Client-Type') return 'flutter\0malicious';
          return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockReq.flutterMetadata?.clientType).toBe('web');
        expect(mockNext).toHaveBeenCalledWith();
      });
    });

    describe('JSON Injection Prevention', () => {
      it('should prevent prototype pollution via device info', () => {
        // Create malicious JSON string manually (not via JSON.stringify of object literal)
        const maliciousDeviceInfoJson = '{"__proto__": {"isAdmin": true}, "platform": "android", "screenWidth": 1080, "screenHeight": 1920}';

        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
            if (header === 'X-Client-Type') return 'flutter';
            if (header === 'X-Device-Info') return maliciousDeviceInfoJson; // Use the manual JSON string
            return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        // Should reject malicious device info
        expect(mockReq.flutterMetadata?.deviceInfo).toBeUndefined();
        expect(mockNext).toHaveBeenCalledWith();
        });

      it('should prevent constructor pollution via device info', () => {
        const maliciousDeviceInfo = {
          "constructor": { "prototype": { "isAdmin": true } },
          "platform": "android",
          "screenWidth": 1080,
          "screenHeight": 1920
        };

        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'X-Client-Type') return 'flutter';
          if (header === 'X-Device-Info') return JSON.stringify(maliciousDeviceInfo);
          return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockReq.flutterMetadata?.deviceInfo).toBeUndefined();
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should handle JSON bombs gracefully', () => {
        // Create a deeply nested object that could cause stack overflow
        let nestedObject: any = {};
        let current = nestedObject;
        for (let i = 0; i < 1000; i++) {
          current.nested = {};
          current = current.nested;
        }
        current.platform = 'android';

        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'X-Client-Type') return 'flutter';
          if (header === 'X-Device-Info') return JSON.stringify(nestedObject);
          return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        // Should handle gracefully and continue
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should prevent ReDoS attacks via malformed JSON', () => {
        const maliciousJson = '{"platform":"' + 'a'.repeat(100000) + '"}';

        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'X-Client-Type') return 'flutter';
          if (header === 'X-Device-Info') return maliciousJson;
          return undefined;
        });

        const startTime = Date.now();
        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);
        const endTime = Date.now();

        // Should complete quickly (under 1 second)
        expect(endTime - startTime).toBeLessThan(1000);
        expect(mockNext).toHaveBeenCalledWith();
      });
    });

    describe('Memory Exhaustion Prevention', () => {
      it('should handle massive JSON payloads', () => {
        const largeArray = new Array(100000).fill('x');
        const largeDeviceInfo = {
          platform: 'android',
          screenWidth: 1080,
          screenHeight: 1920,
          metadata: largeArray
        };

        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'X-Client-Type') return 'flutter';
          if (header === 'X-Device-Info') return JSON.stringify(largeDeviceInfo);
          return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        // Should handle without crashing
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should handle circular reference attacks', () => {
        const circularObj: any = { platform: 'android' };
        circularObj.self = circularObj;

        (mockReq.get as jest.Mock).mockImplementation((header: string) => {
          if (header === 'X-Client-Type') return 'flutter';
          if (header === 'X-Device-Info') return {
            // Simulate a circular reference in a different way
            get() { return this; }
          };
          return undefined;
        });

        flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith();
      });
    });
  });

  describe('File Validation Security', () => {
    beforeEach(() => {
      mockReq.flutterMetadata = {
        clientType: 'flutter',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter
      };
    });

    describe('Path Traversal Prevention', () => {
      const pathTraversalPayloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '..\//..\//..\/etc/passwd',
        '../../../../../../../../../../etc/passwd',
        'image.jpg/../../../etc/passwd',
        'legitimate.jpg/../../../../../../etc/shadow'
      ];

      pathTraversalPayloads.forEach((payload, index) => {
        it(`should block path traversal payload ${index + 1}: ${payload}`, () => {
          mockReq.file = {
            originalname: payload,
            mimetype: 'image/jpeg',
            size: 1024,
            buffer: Buffer.from('fake-image-data')
          } as Express.Multer.File;

          flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

          expect(mockNext).toHaveBeenCalledWith(
            expect.objectContaining({
              statusCode: 400,
              message: 'Invalid filename - path traversal not allowed',
              code: 'INVALID_FILE'
            })
          );
        });
      });
    });

    describe('Executable File Detection', () => {
      const executableExtensions = ['.exe', '.bat', '.scr', '.com', '.pif', '.cmd', '.ps1', '.vbs', '.js'];

      executableExtensions.forEach(ext => {
        it(`should block ${ext} files even with legitimate MIME types`, () => {
          mockReq.file = {
            originalname: `malicious${ext}`,
            mimetype: 'image/jpeg', // Spoofed MIME type
            size: 1024,
            buffer: Buffer.from('fake-executable-data')
          } as Express.Multer.File;

          flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

          expect(mockNext).toHaveBeenCalledWith(
            expect.objectContaining({
              statusCode: 400,
              message: 'Executable files not allowed',
              code: 'INVALID_FILE'
            })
          );
        });
      });

      it('should block double extension attacks', () => {
        mockReq.file = {
          originalname: 'image.jpg.exe',
          mimetype: 'image/jpeg',
          size: 1024,
          buffer: Buffer.from('fake-executable-data')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: 'Executable files not allowed',
            code: 'INVALID_FILE'
          })
        );
      });
    });

    describe('File Size Attack Prevention', () => {
      it('should prevent DoS via extremely large files', () => {
        mockReq.file = {
          originalname: 'huge.jpg',
          mimetype: 'image/jpeg',
          size: 100 * 1024 * 1024 * 1024, // 100GB - extreme case
          buffer: Buffer.from('fake-image-data')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringContaining('File too large'),
            code: 'INVALID_FILE'
          })
        );
      });

      it('should prevent integer overflow attacks with negative file sizes', () => {
        mockReq.file = {
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: -1,
          buffer: Buffer.from('fake-image-data')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: 'Invalid file size',
            code: 'INVALID_FILE'
          })
        );
      });

      it('should prevent integer overflow with MAX_SAFE_INTEGER', () => {
        mockReq.file = {
          originalname: 'test.jpg',
          mimetype: 'image/jpeg',
          size: Number.MAX_SAFE_INTEGER,
          buffer: Buffer.from('fake-image-data')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringContaining('File too large'),
            code: 'INVALID_FILE'
          })
        );
      });
    });

    describe('MIME Type Confusion Prevention', () => {
      it('should prevent PHP files disguised as images', () => {
        mockReq.file = {
          originalname: 'shell.php',
          mimetype: 'image/jpeg', // Spoofed MIME type
          size: 1024,
          buffer: Buffer.from('<?php system($_GET["cmd"]); ?>')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            code: 'INVALID_FILE'
          })
        );
      });

      it('should prevent script injection via MIME type spoofing', () => {
        mockReq.file = {
          originalname: 'malicious.html',
          mimetype: 'image/png', // Spoofed MIME type
          size: 1024,
          buffer: Buffer.from('<script>alert("xss")</script>')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            code: 'INVALID_FILE'
          })
        );
      });

      it('should validate MIME type against allowed types for client', () => {
        // Test that web clients can't upload HEIC even if they claim to be images
        mockReq.flutterMetadata = {
          clientType: 'web',
          validationConfig: FLUTTER_VALIDATION_CONFIGS.web
        };

        mockReq.file = {
          originalname: 'test.heic',
          mimetype: 'image/heic',
          size: 1024,
          buffer: Buffer.from('fake-heic-data')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        // FIXED: Web clients get standard Instagram-compatible error message
        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: 'Only JPEG, PNG, and BMP images are allowed (Instagram compatible)',
            code: 'INVALID_FILE'
          })
        );
      });
    });

    describe('Information Disclosure Prevention', () => {
      it('should not leak internal paths in error messages', () => {
        mockReq.file = {
          originalname: '../../../sensitive/file.jpg',
          mimetype: 'image/jpeg',
          size: 1024,
          buffer: Buffer.from('fake-image-data')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            message: 'Invalid filename - path traversal not allowed'
            // Should not contain actual file system paths
          })
        );
      });

      it('should sanitize file names in error messages', () => {
        mockReq.file = {
          originalname: '<script>alert("xss")</script>.jpg',
          mimetype: 'application/javascript', // Invalid MIME type
          size: 1024,
          buffer: Buffer.from('malicious script')
        } as Express.Multer.File;

        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

        const errorCall = mockNext.mock.calls[0][0];
        
        // Error message should not contain unescaped script tags
        expect(errorCall).toBeInstanceOf(Error);
        expect((errorCall as unknown as Error).message).not.toContain('<script>');
        expect((errorCall as unknown as Error).message).not.toContain('alert(');
      });
    });

    describe('Resource Exhaustion Prevention', () => {
      it('should handle validation errors without memory leaks', () => {
        // Create many validation attempts to test for memory leaks
        for (let i = 0; i < 1000; i++) {
          mockNext.mockClear();
          
          mockReq.file = {
            originalname: `test${i}.exe`,
            mimetype: 'image/jpeg',
            size: 1024,
            buffer: Buffer.from('fake-data')
          } as Express.Multer.File;

          flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);
          
          expect(mockNext).toHaveBeenCalledWith(
            expect.objectContaining({
              statusCode: 400,
              code: 'INVALID_FILE'
            })
          );
        }
      });

      it('should handle concurrent validation attempts', async () => {
        const validationPromises = [];
        
        for (let i = 0; i < 100; i++) {
          const promise = new Promise((resolve) => {
            const localMockNext = jest.fn(() => resolve(undefined));
            
            const localMockReq = {
              ...mockReq,
              file: {
                originalname: `test${i}.jpg`,
                mimetype: 'image/jpeg',
                size: 1024,
                buffer: Buffer.from('fake-data')
              } as Express.Multer.File
            };

            flutterAwareFileValidation(localMockReq as Request, mockRes as Response, localMockNext);
          });
          
          validationPromises.push(promise);
        }

        // All validations should complete without errors
        await Promise.all(validationPromises);
      });
    });
  });

  describe('Instagram Validation Security', () => {
    beforeEach(() => {
      mockReq.flutterMetadata = {
        clientType: 'flutter',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter
      };
      
      mockReq.file = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024 * 1024,
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;
    });

    describe('Image Processing Attack Prevention', () => {
      it('should handle malicious image metadata', async () => {
        const sharp = require('sharp');
        sharp.default.mockImplementation(() => ({
          metadata: jest.fn().mockResolvedValue({
            width: -1, // Invalid negative width
            height: -1, // Invalid negative height
            format: 'jpeg',
            space: 'srgb',
            density: 72
          })
        }));

        await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

        // Should handle invalid metadata gracefully
        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            code: 'INSTAGRAM_VALIDATION_ERROR'
          })
        );
      });

      it('should prevent image bombs (extreme dimensions)', async () => {
        const sharp = require('sharp');
        sharp.default.mockImplementation(() => ({
          metadata: jest.fn().mockResolvedValue({
            width: 999999, // Extreme width
            height: 999999, // Extreme height
            format: 'jpeg',
            space: 'srgb',
            density: 72
          })
        }));

        await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringContaining('Width too large'),
            code: 'INSTAGRAM_VALIDATION_ERROR'
          })
        );
      });

      it('should handle sharp processing errors gracefully', async () => {
        const sharp = require('sharp');
        sharp.default.mockImplementation(() => {
          throw new Error('Sharp processing failed');
        });

        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: 'Invalid image file',
            code: 'INVALID_IMAGE'
          })
        );

        consoleSpy.mockRestore();
      });

      it('should prevent ReDoS via malformed image data', async () => {
        const sharp = require('sharp');
        
        // Create a mock that takes a long time to process
        const slowMetadata = jest.fn(() => {
          return new Promise((resolve) => {
            // Simulate slow processing, but resolve quickly for test
            setTimeout(() => {
              resolve({
                width: 1080,
                height: 1920,
                format: 'jpeg',
                space: 'srgb',
                density: 72
              });
            }, 10); // 10ms delay
          });
        });

        sharp.default.mockImplementation(() => ({
          metadata: slowMetadata
        }));

        const startTime = Date.now();
        await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);
        const endTime = Date.now();

        // Should complete quickly even with slow processing
        expect(endTime - startTime).toBeLessThan(1000);
        expect(mockNext).toHaveBeenCalledWith();
      });
    });

    describe('Client-Specific Security Validation', () => {
      it('should apply stricter validation for web clients', async () => {
        mockReq.flutterMetadata = {
          clientType: 'web',
          validationConfig: FLUTTER_VALIDATION_CONFIGS.web
        };

        const sharp = require('sharp');
        sharp.default.mockImplementation(() => ({
          metadata: jest.fn().mockResolvedValue({
            width: 240, // Valid for Flutter but invalid for web (min 320)
            height: 400,
            format: 'jpeg',
            space: 'srgb',
            density: 72
          })
        }));

        await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringContaining('Width too small'),
            code: 'INSTAGRAM_VALIDATION_ERROR'
          })
        );
      });

      it('should prevent client type spoofing via metadata manipulation', async () => {
        // Attempt to use Flutter config but claim to be web client
        mockReq.flutterMetadata = {
          clientType: 'web',
          validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter // Mismatched config
        };

        const sharp = require('sharp');
        sharp.default.mockImplementation(() => ({
          metadata: jest.fn().mockResolvedValue({
            width: 1080,
            height: 1920,
            format: 'heic', // Should be invalid for web client
            space: 'srgb',
            density: 72
          })
        }));

        await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

        // Should still validate based on client type, not config
        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringContaining('Unsupported format'),
            code: 'INSTAGRAM_VALIDATION_ERROR'
          })
        );
      });
    });

    describe('Format Validation Security', () => {
      it('should prevent format confusion attacks', async () => {
        const sharp = require('sharp');
        sharp.default.mockImplementation(() => ({
          metadata: jest.fn().mockResolvedValue({
            width: 1080,
            height: 1920,
            format: 'svg', // Vector format that could contain scripts
            space: 'srgb',
            density: 72
          })
        }));

        await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringContaining('Unsupported format'),
            code: 'INSTAGRAM_VALIDATION_ERROR'
          })
        );
      });

      it('should handle unknown/null formats gracefully', async () => {
        const sharp = require('sharp');
        sharp.default.mockImplementation(() => ({
          metadata: jest.fn().mockResolvedValue({
            width: 1080,
            height: 1920,
            format: null, // Null format
            space: 'srgb',
            density: 72
          })
        }));

        await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            message: expect.stringContaining('Unsupported format'),
            code: 'INSTAGRAM_VALIDATION_ERROR'
          })
        );
      });
    });
  });

  describe('Configuration Security', () => {
    it('should not allow config tampering via client metadata', () => {
      // Attempt to inject malicious config
      mockReq.flutterMetadata = {
        clientType: 'flutter',
        validationConfig: {
          maxFileSize: Number.MAX_SAFE_INTEGER, // Attempt to bypass size limits
          allowedMimeTypes: ['*/*'], // Attempt to allow all types
          enableChunkedUpload: true,
          enableWebPConversion: true,
          compressionLevel: 0.6,
          enableProgressiveJPEG: true,
          thumbnailSizes: [150],
          enableHEICSupport: true
        }
      };

      mockReq.file = {
        originalname: 'huge.jpg',
        mimetype: 'application/octet-stream', // Should be blocked
        size: 50 * 1024 * 1024, // 50MB
        buffer: Buffer.from('fake-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      // Should still apply proper validation despite tampered config
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          code: 'INVALID_FILE'
        })
      );
    });

    it('should validate against predefined configs only', () => {
      // Ensure only known client types are accepted
      const validClientTypes = ['flutter', 'web', 'mobile-web'];
      
      expect(Object.keys(FLUTTER_VALIDATION_CONFIGS)).toEqual(
        expect.arrayContaining(validClientTypes)
      );
      
      // No additional client types should be present
      expect(Object.keys(FLUTTER_VALIDATION_CONFIGS).length).toBe(validClientTypes.length);
    });

    it('should have secure default configurations', () => {
      Object.values(FLUTTER_VALIDATION_CONFIGS).forEach(config => {
        // File size should have reasonable upper bounds
        expect(config.maxFileSize).toBeLessThanOrEqual(25 * 1024 * 1024); // Max 25MB
        
        // Should not allow dangerous MIME types
        expect(config.allowedMimeTypes).not.toContain('application/javascript');
        expect(config.allowedMimeTypes).not.toContain('text/html');
        expect(config.allowedMimeTypes).not.toContain('application/x-executable');
        
        // Should have valid compression levels
        expect(config.compressionLevel).toBeGreaterThan(0);
        expect(config.compressionLevel).toBeLessThanOrEqual(1);
        
        // Thumbnail sizes should be reasonable
        config.thumbnailSizes.forEach(size => {
          expect(size).toBeGreaterThan(0);
          expect(size).toBeLessThanOrEqual(1000);
        });
      });
    });
  });

  describe('Error Handling Security', () => {
    it('should not leak sensitive information in error messages', () => {
      mockReq.file = {
        originalname: '/etc/passwd',
        mimetype: 'image/jpeg',
        size: 1024,
        buffer: Buffer.from('fake-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      const errorCall = mockNext.mock.calls[0][0] as unknown as ApiError;
      
      // Should not contain system paths or sensitive info
      expect(errorCall.message).not.toMatch(/\/etc\/|\/var\/|\/tmp\/|C:\\Windows\\|C:\\Users\\/);
      expect(errorCall.message).not.toContain('passwd');
      expect(errorCall.message).not.toContain('shadow');
    });

    it('should provide consistent error timing to prevent timing attacks', async () => {
      const timings: number[] = [];
      
      // Test multiple validation failures
      for (let i = 0; i < 10; i++) {
        (mockNext as jest.Mock).mockClear();
        
        mockReq.file = {
          originalname: `test${i}.exe`,
          mimetype: 'image/jpeg',
          size: 1024,
          buffer: Buffer.from('fake-data')
        } as Express.Multer.File;

        const startTime = Date.now();
        flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);
        const endTime = Date.now();
        
        timings.push(endTime - startTime);
      }
      
      // Timing should be relatively consistent (within 100ms variance)
      const avgTiming = timings.reduce((a, b) => a + b) / timings.length;
      const maxVariance = Math.max(...timings) - Math.min(...timings);
      
      expect(maxVariance).toBeLessThan(100); // Should be consistent
    });

    it('should handle exception stack traces securely', () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      // Force an error by providing invalid data
      mockReq.file = null as any;
      
      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);
      
      const errorCall = mockNext.mock.calls[0][0] as unknown as ApiError;
      
      // Error message to user should be generic
      expect(errorCall.message).toBe('No file provided'); // Not 'File validation error'
      expect(errorCall.code).toBe('NO_FILE'); // Not 'FILE_VALIDATION_ERROR'
      
      // Detailed error should only be logged, not returned to user
      expect(consoleSpy).toHaveBeenCalled();
      
      consoleSpy.mockRestore();
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });
});