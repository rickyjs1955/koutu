// backend/src/tests/unit/validate.flutter.unit.test.ts
// Unit tests for Flutter-enhanced validation middleware

import { Request, Response, NextFunction } from 'express';
import {
  flutterClientDetection,
  flutterAwareFileValidation,
  flutterInstagramValidation,
  validateFile,
  instagramValidationMiddleware,
  flutterTestUtils,
  FLUTTER_VALIDATION_CONFIGS,
  FlutterDeviceInfoSchema,
  FlutterNetworkInfoSchema,
  FlutterUploadMetadataSchema
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

describe('Flutter Validation Unit Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.MockedFunction<NextFunction>;

  beforeEach(() => {
    mockReq = {
      headers: {},
      get: jest.fn((header: string) => {
        const headers: { [key: string]: string | string[] } = {
          'user-agent': 'Mozilla/5.0',
          'x-client-type': 'web',
          ...mockReq.headers
        };
        if (header.toLowerCase() === 'set-cookie') {
          const cookieValue = headers[header.toLowerCase()];
          return cookieValue ? [cookieValue] : undefined;
        }
        return headers[header.toLowerCase()];
      }) as jest.MockedFunction<{ (name: "set-cookie"): string[] | undefined; (name: string): string | undefined; }>,
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

  describe('flutterClientDetection', () => {
    it('should detect Flutter client from User-Agent', () => {
      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'User-Agent') return 'Flutter/3.0.0';
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.clientType).toBe('flutter');
      expect(mockReq.flutterMetadata?.validationConfig).toBe(FLUTTER_VALIDATION_CONFIGS.flutter);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should detect Flutter client from X-Client-Type header', () => {
      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'X-Client-Type') return 'flutter';
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.clientType).toBe('flutter');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should detect Flutter client from X-Flutter-Version header', () => {
      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'X-Flutter-Version') return '3.0.0';
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.clientType).toBe('flutter');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should detect mobile web client from User-Agent', () => {
      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'User-Agent') return 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)';
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.clientType).toBe('mobile-web');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should detect mobile web client from Android User-Agent', () => {
      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'User-Agent') return 'Mozilla/5.0 (Linux; Android 10; SM-G975F)';
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.clientType).toBe('mobile-web');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should default to web client for desktop User-Agent', () => {
      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'User-Agent') return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.clientType).toBe('web');
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should parse valid device info from X-Device-Info header', () => {
      const deviceInfo = {
        platform: 'android',
        devicePixelRatio: 2.0,
        screenWidth: 1080,
        screenHeight: 1920,
        version: '1.0.0'
      };

      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'X-Client-Type') return 'flutter';
        if (header === 'X-Device-Info') return JSON.stringify(deviceInfo);
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.deviceInfo).toEqual(deviceInfo);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should parse valid network info from X-Network-Info header', () => {
      const networkInfo = {
        type: 'wifi',
        isMetered: false,
        speed: 'fast'
      };

      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'X-Client-Type') return 'flutter';
        if (header === 'X-Network-Info') return JSON.stringify(networkInfo);
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.networkInfo).toEqual(networkInfo);
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle invalid JSON in device info gracefully', () => {
      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'X-Client-Type') return 'flutter';
        if (header === 'X-Device-Info') return 'invalid-json';
        return undefined;
      });

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.deviceInfo).toBeUndefined();
      expect(consoleSpy).toHaveBeenCalledWith('Invalid device info header:', expect.any(Error));
      expect(mockNext).toHaveBeenCalledWith();

      consoleSpy.mockRestore();
    });

    it('should handle invalid device info schema gracefully', () => {
      const invalidDeviceInfo = {
        platform: 'invalid-platform', // Invalid enum value
        devicePixelRatio: 'not-a-number' // Invalid type
      };

      (mockReq.get as jest.Mock).mockImplementation((header: string) => {
        if (header === 'X-Client-Type') return 'flutter';
        if (header === 'X-Device-Info') return JSON.stringify(invalidDeviceInfo);
        return undefined;
      });

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.deviceInfo).toBeUndefined();
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle errors gracefully and default to web', () => {
      (mockReq.get as jest.Mock).mockImplementation(() => {
        throw new Error('Header parsing error');
      });

      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      flutterClientDetection(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.flutterMetadata?.clientType).toBe('web');
      expect(consoleSpy).toHaveBeenCalledWith('Flutter client detection error:', expect.any(Error));
      expect(mockNext).toHaveBeenCalledWith();

      consoleSpy.mockRestore();
    });
  });

  describe('flutterAwareFileValidation', () => {
    beforeEach(() => {
      mockReq.flutterMetadata = {
        clientType: 'flutter',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter
      };
    });

    it('should validate valid Flutter file upload', () => {
      mockReq.file = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024 * 1024, // 1MB
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should reject missing file', () => {
      mockReq.file = undefined;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'No file provided',
          code: 'NO_FILE'
        })
      );
    });

    it('should reject oversized files for Flutter client', () => {
      mockReq.file = {
        originalname: 'large.jpg',
        mimetype: 'image/jpeg',
        size: 25 * 1024 * 1024, // 25MB (over 20MB Flutter limit)
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: expect.stringContaining('File too large for flutter client'),
          code: 'INVALID_FILE'
        })
      );
    });

    it('should allow larger files for Flutter vs web clients', () => {
      const largeFileSize = 15 * 1024 * 1024; // 15MB

      // Test Flutter client (should pass)
      mockReq.file = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: largeFileSize,
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(); // No error

      // Reset and test web client (should fail)
      mockNext.mockClear();
      mockReq.flutterMetadata = {
        clientType: 'web',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.web
      };

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);
      
      // FIXED: Web clients get backward-compatible error messages
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'File too large (max 8MB, got 15MB)', // Clean message, no "web client"
          code: 'INVALID_FILE'
        })
      );
    });

    it('should reject unsupported MIME types', () => {
      mockReq.file = {
        originalname: 'test.pdf',
        mimetype: 'application/pdf',
        size: 1024,
        buffer: Buffer.from('fake-pdf-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: expect.stringContaining('File type \'application/pdf\' not supported'),
          code: 'INVALID_FILE'
        })
      );
    });

    it('should support HEIC files for Flutter clients', () => {
      mockReq.file = {
        originalname: 'test.heic',
        mimetype: 'image/heic',
        size: 1024 * 1024,
        buffer: Buffer.from('fake-heic-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should pass
    });

    it('should reject HEIC files for web clients', () => {
      mockReq.flutterMetadata = {
        clientType: 'web',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.web
      };

      mockReq.file = {
        originalname: 'test.heic',
        mimetype: 'image/heic',
        size: 1024 * 1024,
        buffer: Buffer.from('fake-heic-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      // FIXED: Web clients get backward-compatible error messages
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Only JPEG, PNG, and BMP images are allowed (Instagram compatible)', 
          code: 'INVALID_FILE'
        })
      );
    });

    it('should reject executable files', () => {
      mockReq.file = {
        originalname: 'malicious.exe',
        mimetype: 'image/jpeg', // Spoofed MIME type
        size: 1024,
        buffer: Buffer.from('fake-exe-data')
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

    it('should reject path traversal in filename', () => {
      mockReq.file = {
        originalname: '../../../etc/passwd',
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

    it('should reject negative file sizes', () => {
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

    it('should warn about large files on cellular networks', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      mockReq.flutterMetadata = {
        clientType: 'flutter',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter,
        networkInfo: { type: 'cellular', isMetered: true, speed: 'slow' }
      };

      mockReq.file = {
        originalname: 'large.jpg',
        mimetype: 'image/jpeg',
        size: 6 * 1024 * 1024, // 6MB on cellular
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Large file upload on cellular network')
      );
      expect(mockNext).toHaveBeenCalledWith(); // Should still pass

      consoleSpy.mockRestore();
    });

    it('should handle iOS file size limits', () => {
      mockReq.flutterMetadata = {
        clientType: 'flutter',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter,
        deviceInfo: {
          platform: 'ios',
          devicePixelRatio: 2.0,
          screenWidth: 828,
          screenHeight: 1792
        }
      };

      mockReq.file = {
        originalname: 'huge.jpg',
        mimetype: 'image/jpeg',
        size: 18 * 1024 * 1024, // 18MB (over iOS 15MB limit)
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'File too large for iOS device capabilities',
          code: 'INVALID_FILE'
        })
      );
    });

    it('should handle missing flutter metadata gracefully', () => {
      mockReq.flutterMetadata = undefined;
      mockReq.file = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024,
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      // Should use web config as default and pass
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should handle validation errors gracefully', () => {
      mockReq.file = null as any; // Force an error - this will trigger "No file provided"

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'No file provided',
          code: 'NO_FILE'
        })
      );
    });
  });

  describe('flutterInstagramValidation', () => {
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

    it('should validate valid Flutter image', async () => {
      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockReq.imageMetadata).toBeDefined();
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should reject missing file', async () => {
      mockReq.file = undefined;

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'No image file provided',
          code: 'MISSING_FILE'
        })
      );
    });

    it('should allow more flexible dimensions for Flutter', async () => {
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 240, // Below web minimum (320) but above Flutter minimum (240)
          height: 400,
          format: 'jpeg',
          space: 'srgb',
          density: 72
        })
      }));

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should pass for Flutter
    });

    it('should allow more flexible aspect ratios for Flutter', async () => {
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 500,
          height: 800, // 0.625 aspect ratio (above Flutter 0.5 minimum)
          format: 'jpeg',
          space: 'srgb',
          density: 72
        })
      }));

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should pass for Flutter
    });

    it('should support HEIC format for Flutter', async () => {
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 1080,
          height: 1920,
          format: 'heic',
          space: 'srgb',
          density: 72
        })
      }));

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should pass
    });

    it('should reject images that are too small even for Flutter', async () => {
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 200, // Below Flutter minimum of 240
          height: 300,
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

    it('should reject extreme aspect ratios even for Flutter', async () => {
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 500,
          height: 1500, // 0.33 aspect ratio (below Flutter 0.5 minimum)
          format: 'jpeg',
          space: 'srgb',
          density: 72
        })
      }));

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: expect.stringContaining('Image too tall'),
          code: 'INSTAGRAM_VALIDATION_ERROR'
        })
      );
    });

    it('should handle metadata extraction errors', async () => {
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockRejectedValue(new Error('Metadata extraction failed'))
      }));

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

    it('should handle missing metadata dimensions', async () => {
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: undefined,
          height: undefined,
          format: 'jpeg',
          space: 'srgb',
          density: 72
        })
      }));

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: expect.stringContaining('Unable to determine image dimensions'),
          code: 'INSTAGRAM_VALIDATION_ERROR'
        })
      );
    });

    it('should handle unsupported format gracefully', async () => {
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 1080,
          height: 1920,
          format: 'tiff', // Unsupported format
          space: 'srgb',
          density: 72
        })
      }));

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: expect.stringContaining('Unsupported format: tiff'),
          code: 'INSTAGRAM_VALIDATION_ERROR'
        })
      );
    });

    it('should log info for non-sRGB color space on Flutter', async () => {
      const consoleSpy = jest.spyOn(console, 'info').mockImplementation();
      
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 1080,
          height: 1920,
          format: 'jpeg',
          space: 'adobe-rgb', // Non-sRGB
          density: 72
        })
      }));

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Non-sRGB color space detected')
      );
      expect(mockNext).toHaveBeenCalledWith(); // Should still pass

      consoleSpy.mockRestore();
    });

    it('should handle missing flutter metadata gracefully', async () => {
      mockReq.flutterMetadata = undefined;

      // Use dimensions that work for web validation (since it defaults to web)
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 1080, // Above web minimum
          height: 1080, // Square ratio - valid for both
          format: 'jpeg',
          space: 'srgb',
          density: 72
        })
      }));

      await flutterInstagramValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should use web defaults and pass
    });
  });

  describe('validateFile (backward compatibility)', () => {
    it('should route Flutter clients to Flutter validation', () => {
      mockReq.flutterMetadata = { 
        clientType: 'flutter',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter 
      };
      mockReq.file = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024,
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      validateFile(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should pass Flutter validation
    });

    it('should route web clients to Flutter-aware validation when metadata exists', () => {
      // When flutterMetadata exists, even web clients use Flutter-aware validation
      mockReq.flutterMetadata = { 
        clientType: 'web',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.web 
      };
      mockReq.file = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024,
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      validateFile(mockReq as Request, mockRes as Response, mockNext);

      // Should use Flutter-aware validation with web config
      expect(mockNext).toHaveBeenCalledWith(); // Should pass
    });

    it('should use original validation when no flutter metadata', () => {
      mockReq.flutterMetadata = undefined;
      
      // FIXED: Use file parameters that will pass original validation
      mockReq.file = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024 * 1024, // 1MB - well under original 8MB limit
        buffer: Buffer.from('fake-image-data'),
        fieldname: 'image',
        encoding: '7bit',
        destination: '/tmp',
        filename: 'test.jpg',
        path: '/tmp/test.jpg'
      } as Express.Multer.File;

      // FIXED: Mock Sharp to return valid dimensions for original Instagram validation
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 1080,
          height: 1080, // Square - passes original Instagram validation (0.8-1.91 range)
          format: 'jpeg',
          space: 'srgb',
          density: 72
        })
      }));

      validateFile(mockReq as Request, mockRes as Response, mockNext);

      // Should pass original validation since file is valid
      expect(mockNext).toHaveBeenCalledWith(); // No error
    });
  });

  describe('instagramValidationMiddleware (backward compatibility)', () => {
    beforeEach(() => {
      mockReq.file = {
        originalname: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024 * 1024,
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;
    });

    it('should route Flutter clients to Flutter validation', async () => {
      mockReq.flutterMetadata = { clientType: 'flutter' };

      await instagramValidationMiddleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should pass Flutter validation
    });

    it('should route mobile-web clients to Flutter validation', async () => {
      mockReq.flutterMetadata = { clientType: 'mobile-web' };

      // Use dimensions that work for mobile-web (Flutter validation but slightly more restrictive)
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 800,
          height: 1000, // 0.8 aspect ratio - valid for mobile-web
          format: 'jpeg',
          space: 'srgb',
          density: 72
        })
      }));

      await instagramValidationMiddleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should pass Flutter validation
    });

    it('should route web clients to original validation', async () => {
      mockReq.flutterMetadata = { clientType: 'web' };

      // Use dimensions that work for web validation
      const sharp = require('sharp');
      sharp.default.mockImplementation(() => ({
        metadata: jest.fn().mockResolvedValue({
          width: 1080,
          height: 1080, // Square - valid for Instagram web
          format: 'jpeg',
          space: 'srgb',
          density: 72
        })
      }));

      await instagramValidationMiddleware(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(); // Should pass original validation
    });
  });

  describe('Schema Validation', () => {
    describe('FlutterDeviceInfoSchema', () => {
      it('should validate valid device info', () => {
        const validDeviceInfo = {
          platform: 'android',
          devicePixelRatio: 2.0,
          screenWidth: 1080,
          screenHeight: 1920,
          version: '1.0.0'
        };

        const result = FlutterDeviceInfoSchema.safeParse(validDeviceInfo);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data).toEqual(validDeviceInfo);
        }
      });

      it('should reject invalid platform', () => {
        const invalidDeviceInfo = {
          platform: 'windows',
          devicePixelRatio: 2.0,
          screenWidth: 1080,
          screenHeight: 1920
        };

        const result = FlutterDeviceInfoSchema.safeParse(invalidDeviceInfo);
        expect(result.success).toBe(false);
      });

      it('should use default values for optional fields', () => {
        const minimalDeviceInfo = {
          platform: 'ios',
          screenWidth: 828,
          screenHeight: 1792
        };

        const result = FlutterDeviceInfoSchema.safeParse(minimalDeviceInfo);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.devicePixelRatio).toBe(1);
        }
      });

      it('should validate devicePixelRatio bounds', () => {
        const tooLow = {
          platform: 'android',
          devicePixelRatio: 0.3, // Below minimum of 0.5
          screenWidth: 1080,
          screenHeight: 1920
        };

        const tooHigh = {
          platform: 'android',
          devicePixelRatio: 6.0, // Above maximum of 5
          screenWidth: 1080,
          screenHeight: 1920
        };

        expect(FlutterDeviceInfoSchema.safeParse(tooLow).success).toBe(false);
        expect(FlutterDeviceInfoSchema.safeParse(tooHigh).success).toBe(false);
      });

      it('should validate screen dimension bounds', () => {
        const tooSmall = {
          platform: 'android',
          screenWidth: 200, // Below minimum of 320
          screenHeight: 1920
        };

        const tooBig = {
          platform: 'android',
          screenWidth: 5000, // Above maximum of 4096
          screenHeight: 1920
        };

        expect(FlutterDeviceInfoSchema.safeParse(tooSmall).success).toBe(false);
        expect(FlutterDeviceInfoSchema.safeParse(tooBig).success).toBe(false);
      });
    });

    describe('FlutterNetworkInfoSchema', () => {
      it('should validate valid network info', () => {
        const validNetworkInfo = {
          type: 'wifi',
          isMetered: false,
          speed: 'fast'
        };

        const result = FlutterNetworkInfoSchema.safeParse(validNetworkInfo);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data).toEqual(validNetworkInfo);
        }
      });

      it('should use default values', () => {
        const result = FlutterNetworkInfoSchema.safeParse({});
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.type).toBe('unknown');
          expect(result.data.isMetered).toBe(false);
        }
      });

      it('should reject invalid network type', () => {
        const invalidNetworkInfo = {
          type: 'invalid-type'
        };

        const result = FlutterNetworkInfoSchema.safeParse(invalidNetworkInfo);
        expect(result.success).toBe(false);
      });

      it('should reject invalid speed', () => {
        const invalidNetworkInfo = {
          type: 'wifi',
          speed: 'super-fast' // Not in enum
        };

        const result = FlutterNetworkInfoSchema.safeParse(invalidNetworkInfo);
        expect(result.success).toBe(false);
      });
    });

    describe('FlutterUploadMetadataSchema', () => {
      it('should validate valid upload metadata', () => {
        const validMetadata = {
          compressionQuality: 0.8,
          targetWidth: 1080,
          targetHeight: 1920,
          enableWebPConversion: true,
          generateThumbnails: true,
          deviceInfo: {
            platform: 'android',
            devicePixelRatio: 2.0,
            screenWidth: 1080,
            screenHeight: 1920
          }
        };

        const result = FlutterUploadMetadataSchema.safeParse(validMetadata);
        expect(result.success).toBe(true);
      });

      it('should reject invalid compression quality', () => {
        const invalidMetadata = {
          compressionQuality: 1.5 // > 1.0
        };

        const result = FlutterUploadMetadataSchema.safeParse(invalidMetadata);
        expect(result.success).toBe(false);
      });

      it('should reject invalid target dimensions', () => {
        const invalidMetadata = {
          targetWidth: 100 // Below minimum of 320
        };

        const result = FlutterUploadMetadataSchema.safeParse(invalidMetadata);
        expect(result.success).toBe(false);
      });

      it('should use default values for optional fields', () => {
        const minimalMetadata = {};

        const result = FlutterUploadMetadataSchema.safeParse(minimalMetadata);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.generateThumbnails).toBe(true);
        }
      });
    });
  });

  describe('Configuration Tests', () => {
    it('should have correct Flutter config values', () => {
      const config = FLUTTER_VALIDATION_CONFIGS.flutter;
      
      expect(config.maxFileSize).toBe(20971520); // 20MB
      expect(config.allowedMimeTypes).toContain('image/heic');
      expect(config.allowedMimeTypes).toContain('image/webp');
      expect(config.enableChunkedUpload).toBe(true);
      expect(config.enableWebPConversion).toBe(true);
      expect(config.enableHEICSupport).toBe(true);
      expect(config.thumbnailSizes).toEqual([150, 300, 600]);
    });

    it('should have correct web config values', () => {
      const config = FLUTTER_VALIDATION_CONFIGS.web;
      
      expect(config.maxFileSize).toBe(8388608); // 8MB
      expect(config.allowedMimeTypes).not.toContain('image/heic');
      expect(config.enableChunkedUpload).toBe(false);
      expect(config.enableHEICSupport).toBe(false);
      expect(config.thumbnailSizes).toEqual([150]);
    });

    it('should have correct mobile-web config values', () => {
      const config = FLUTTER_VALIDATION_CONFIGS['mobile-web'];
      
      expect(config.maxFileSize).toBe(10485760); // 10MB
      expect(config.allowedMimeTypes).toContain('image/webp');
      expect(config.allowedMimeTypes).not.toContain('image/heic');
      expect(config.enableWebPConversion).toBe(true);
      expect(config.enableHEICSupport).toBe(false);
      expect(config.thumbnailSizes).toEqual([150, 300]);
    });

    it('should have different configs for different client types', () => {
      const flutterConfig = FLUTTER_VALIDATION_CONFIGS.flutter;
      const webConfig = FLUTTER_VALIDATION_CONFIGS.web;
      const mobileWebConfig = FLUTTER_VALIDATION_CONFIGS['mobile-web'];
      
      expect(flutterConfig.maxFileSize).toBeGreaterThan(webConfig.maxFileSize);
      expect(mobileWebConfig.maxFileSize).toBeGreaterThan(webConfig.maxFileSize);
      expect(mobileWebConfig.maxFileSize).toBeLessThan(flutterConfig.maxFileSize);
    });
  });

  describe('Test Utilities', () => {
    it('should create mock device info with defaults', () => {
      const deviceInfo = flutterTestUtils.createMockDeviceInfo();
      
      expect(deviceInfo.platform).toBe('android');
      expect(deviceInfo.devicePixelRatio).toBe(2.0);
      expect(deviceInfo.screenWidth).toBe(1080);
      expect(deviceInfo.screenHeight).toBe(1920);
      expect(deviceInfo.version).toBe('1.0.0');
    });

    it('should create mock device info with overrides', () => {
      const deviceInfo = flutterTestUtils.createMockDeviceInfo({
        platform: 'ios',
        screenWidth: 828
      });
      
      expect(deviceInfo.platform).toBe('ios');
      expect(deviceInfo.screenWidth).toBe(828);
      expect(deviceInfo.screenHeight).toBe(1920); // Default preserved
    });

    it('should create mock network info with defaults', () => {
      const networkInfo = flutterTestUtils.createMockNetworkInfo();
      
      expect(networkInfo.type).toBe('wifi');
      expect(networkInfo.isMetered).toBe(false);
      expect(networkInfo.speed).toBe('fast');
    });

    it('should create mock network info with overrides', () => {
      const networkInfo = flutterTestUtils.createMockNetworkInfo({
        type: 'cellular',
        isMetered: true
      });
      
      expect(networkInfo.type).toBe('cellular');
      expect(networkInfo.isMetered).toBe(true);
      expect(networkInfo.speed).toBe('fast'); // Default preserved
    });

    it('should set client type for testing', () => {
      const mockRequest: any = {};
      
      flutterTestUtils.setClientType(mockRequest, 'flutter');
      
      expect(mockRequest.flutterMetadata.clientType).toBe('flutter');
      expect(mockRequest.flutterMetadata.validationConfig).toBe(FLUTTER_VALIDATION_CONFIGS.flutter);
    });

    it('should expose original functions for testing', () => {
      expect(flutterTestUtils.originalValidateFile).toBeDefined();
      expect(flutterTestUtils.originalInstagramValidation).toBeDefined();
      expect(typeof flutterTestUtils.originalValidateFile).toBe('function');
      expect(typeof flutterTestUtils.originalInstagramValidation).toBe('function');
    });

    it('should expose configs for testing', () => {
      expect(flutterTestUtils.configs).toBe(FLUTTER_VALIDATION_CONFIGS);
      expect(flutterTestUtils.configs.flutter).toBeDefined();
      expect(flutterTestUtils.configs.web).toBeDefined();
      expect(flutterTestUtils.configs['mobile-web']).toBeDefined();
    });
  });

  describe('Client-Aware Error Messages', () => {
    it('should provide client-aware error messages for Flutter clients', () => {
      mockReq.flutterMetadata = {
        clientType: 'flutter',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter
      };

      mockReq.file = {
        originalname: 'huge.jpg',
        mimetype: 'image/jpeg',
        size: 25 * 1024 * 1024, // 25MB - over Flutter limit (20MB)
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'File too large for flutter client (max 20MB, got 25MB)',
          code: 'INVALID_FILE'
        })
      );
    });

    it('should provide client-aware error messages for mobile-web clients', () => {
      mockReq.flutterMetadata = {
        clientType: 'mobile-web',
        validationConfig: FLUTTER_VALIDATION_CONFIGS['mobile-web']
      };

      mockReq.file = {
        originalname: 'huge.jpg',
        mimetype: 'image/jpeg',
        size: 12 * 1024 * 1024, // 12MB - over mobile-web limit (10MB)
        buffer: Buffer.from('fake-image-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'File too large for mobile-web client (max 10MB, got 12MB)',
          code: 'INVALID_FILE'
        })
      );
    });

    it('should provide client-aware MIME type errors for Flutter clients', () => {
      mockReq.flutterMetadata = {
        clientType: 'flutter',
        validationConfig: FLUTTER_VALIDATION_CONFIGS.flutter
      };

      mockReq.file = {
        originalname: 'document.pdf',
        mimetype: 'application/pdf',
        size: 1024,
        buffer: Buffer.from('fake-pdf-data')
      } as Express.Multer.File;

      flutterAwareFileValidation(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: expect.stringContaining('File type \'application/pdf\' not supported for flutter clients'),
          code: 'INVALID_FILE'
        })
      );
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });
});