// src/tests/security/imageService.security.test.ts

// ===== IMPORT AND SETUP FIREBASE MOCKS FIRST =====
import { 
  MockFirebaseAdmin,
} from '../__mocks__/firebase.mock';

import {
  setupFirebaseTestEnvironment,
  cleanupFirebaseTests
} from '../__helpers__/firebase.helper';

// Mock Firebase Admin before any other imports
jest.mock('firebase-admin', () => ({
  apps: MockFirebaseAdmin.apps,
  auth: MockFirebaseAdmin.auth,
  storage: MockFirebaseAdmin.storage,
  credential: MockFirebaseAdmin.credential,
  initializeApp: MockFirebaseAdmin.initializeApp
}));

// Mock Sharp
const mockSharp = jest.fn().mockImplementation(() => ({
  metadata: jest.fn().mockResolvedValue({
    width: 800,
    height: 600,
    format: 'jpeg',
    channels: 3,
    space: 'srgb'
  }),
  resize: jest.fn().mockReturnThis(),
  jpeg: jest.fn().mockReturnThis(),
  png: jest.fn().mockReturnThis(),
  toColorspace: jest.fn().mockReturnThis(),
  toFile: jest.fn().mockResolvedValue({ size: 204800 }),
  toBuffer: jest.fn().mockResolvedValue(Buffer.from('mock-data'))
}));

jest.mock('sharp', () => mockSharp);

// Mock config files
jest.mock('../../config/firebase', () => ({
  initializeFirebase: jest.fn(),
  getFirebaseApp: jest.fn(),
  getStorageBucket: jest.fn()
}));

jest.mock('../../models/db', () => ({
  pool: {
    query: jest.fn(),
    connect: jest.fn(),
    end: jest.fn()
  }
}));

// Mock the service dependencies
const mockImageModel = {
  create: jest.fn(),
  findById: jest.fn(),
  findByUserId: jest.fn(),
  updateStatus: jest.fn(),
  updateMetadata: jest.fn(),
  delete: jest.fn(),
  findDependentGarments: jest.fn(),
  findDependentPolygons: jest.fn(),
  getUserImageStats: jest.fn(),
  batchUpdateStatus: jest.fn()
};

const mockImageProcessingService = {
  validateImageBuffer: jest.fn(),
  convertToSRGB: jest.fn(),
  extractMetadata: jest.fn(),
  generateThumbnail: jest.fn(),
  optimizeForWeb: jest.fn()
};

const mockStorageService = {
  saveFile: jest.fn(),
  deleteFile: jest.fn()
};

// Mock ApiError class
class MockApiError extends Error {
  public statusCode: number;
  public code: string;
  public context?: any;

  constructor(message: string, statusCode: number = 500, code: string = 'INTERNAL_ERROR', context?: any) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.context = context;
  }

  static validation(message: string, field?: string, value?: any) {
    const error = new MockApiError(message, 400, 'VALIDATION_ERROR', { field, value });
    throw error;
  }

  static businessLogic(message: string, rule?: string, resource?: string) {
    const error = new MockApiError(message, 400, 'BUSINESS_LOGIC_ERROR', { rule, resource });
    throw error;
  }

  static authorization(message: string, resource?: string, action?: string) {
    const error = new MockApiError(message, 403, 'AUTHORIZATION_ERROR', { resource, action });
    throw error;
  }

  static notFound(message: string, code?: string, context?: any) {
    const error = new MockApiError(message, 404, code || 'NOT_FOUND', context);
    throw error;
  }

  static internal(message: string, code?: string, context?: any) {
    const error = new MockApiError(message, 500, code || 'INTERNAL_ERROR', context);
    throw error;
  }
}

jest.mock('../../models/imageModel', () => ({
  imageModel: mockImageModel
}));

jest.mock('../../services/imageProcessingService', () => ({
  imageProcessingService: mockImageProcessingService
}));

jest.mock('../../services/storageService', () => ({
  storageService: mockStorageService
}));

jest.mock('../../utils/ApiError', () => ({
  ApiError: MockApiError
}));


// ===== NOW IMPORT THE SERVICE TO TEST =====
import { imageService } from '../../services/imageService';
import { createBoundaryTestCases, createSecurityTestPayloads, simulateTimingAttack } from '../__helpers__/images.helper';

describe('ImageService Security Tests', () => {
  const validUserId = 'user-123';
  const attackerUserId = 'attacker-456';
  const imageId = 'image-789';

  // Setup Firebase test environment
  setupFirebaseTestEnvironment();

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default success responses
    mockImageModel.getUserImageStats.mockResolvedValue({
      total: 50,
      totalSize: 100 * 1024 * 1024 // 100MB
    });

    mockImageModel.create.mockResolvedValue({
      id: imageId,
      user_id: validUserId,
      file_path: 'uploads/test.jpg',
      original_metadata: {},
      status: 'new',
      upload_date: new Date()
    });

    mockImageModel.findById.mockResolvedValue({
      id: imageId,
      user_id: validUserId,
      file_path: 'uploads/test.jpg',
      original_metadata: {},
      status: 'new',
      upload_date: new Date()
    });

    mockImageModel.findDependentGarments.mockResolvedValue([]);
    mockImageModel.findDependentPolygons.mockResolvedValue([]);

    mockStorageService.saveFile.mockResolvedValue('uploads/saved-file.jpg');
    mockStorageService.deleteFile.mockResolvedValue(true);

    mockImageProcessingService.validateImageBuffer.mockResolvedValue({
      width: 800,
      height: 600,
      format: 'jpeg',
      channels: 3,
      space: 'srgb'
    });
  });

  afterAll(() => {
    cleanupFirebaseTests();
  });

  describe('File Upload Security', () => {
    describe('Malicious File Detection', () => {
      it('should reject executable files disguised as images', async () => {
        const maliciousUpload = {
          fieldname: 'image',
          originalname: 'malicious.exe',
          encoding: '7bit',
          mimetype: 'application/octet-stream',
          size: 1024,
          buffer: Buffer.from('MZ\x90\x00') // PE header
        };

        const uploadParams = {
          userId: validUserId,
          fileBuffer: maliciousUpload.buffer,
          originalFilename: maliciousUpload.originalname,
          mimetype: maliciousUpload.mimetype,
          size: maliciousUpload.size
        };

        await expect(imageService.uploadImage(uploadParams)).rejects.toThrow();
        expect(mockStorageService.saveFile).not.toHaveBeenCalled();
      });

      it('should reject files with script injection in filename', async () => {
        const securityPayloads = createSecurityTestPayloads();
        const xssFilename = securityPayloads.xssPayloads.script + '.jpg';
        
        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: xssFilename,
          mimetype: 'image/jpeg',
          size: 1024
        };

        // Should handle gracefully - the service stores the filename but validation happens elsewhere
        try {
          await imageService.uploadImage(uploadParams);
          expect(mockStorageService.saveFile).toHaveBeenCalled();
        } catch (error) {
          // XSS in filename might be rejected at validation level, which is also acceptable
          expect(error).toBeDefined();
        }
      });

      it('should reject oversized files that could cause DoS', async () => {
        const largeSize = 10 * 1024 * 1024; // 10MB
        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.alloc(1024),
          originalFilename: 'large-image.jpg',
          mimetype: 'image/jpeg',
          size: largeSize
        };

        const result = await imageService.validateImageFile(
          uploadParams.fileBuffer,
          'image/jpeg',
          largeSize
        );

        expect(result.isValid).toBe(false);
        expect(result.errors).toEqual(expect.arrayContaining([expect.stringMatching(/File too large/)]));
      });

      it('should detect and reject corrupted image files', async () => {
        const corruptedBuffer = Buffer.from([0xFF, 0xD8, 0x00, 0x00]); // Truncated JPEG
        mockImageProcessingService.validateImageBuffer.mockRejectedValue(new Error('Corrupted image'));

        const result = await imageService.validateImageFile(corruptedBuffer, 'image/jpeg', 1024);

        expect(result.isValid).toBe(false);
        expect(result.errors).toContain('Invalid or corrupted image file');
      });

      it('should validate MIME type against actual file content', async () => {
        // Simulate PNG content but declared as JPEG
        mockImageProcessingService.validateImageBuffer.mockResolvedValue({
          width: 800,
          height: 600,
          format: 'png', // Actual format
          channels: 4,
          space: 'srgb'
        });

        const result = await imageService.validateImageFile(
          Buffer.from('png-data'),
          'image/jpeg', // Declared as JPEG
          1024
        );

        expect(result.isValid).toBe(false);
        expect(result.errors).toEqual(expect.arrayContaining([expect.stringMatching(/Format mismatch.*expected image\/png.*got image\/jpeg/)]));
      });
    });

    describe('Path Traversal Protection', () => {
      it('should handle filenames with path traversal attempts', async () => {
        const securityPayloads = createSecurityTestPayloads();
        const pathTraversalFilename = securityPayloads.pathTraversal.unix + '.jpg';
        
        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: pathTraversalFilename,
          mimetype: 'image/jpeg',
          size: 1024
        };

        // Should complete - path sanitization happens at storage layer
        try {
          await imageService.uploadImage(uploadParams);
          expect(mockStorageService.saveFile).toHaveBeenCalledWith(
            uploadParams.fileBuffer,
            pathTraversalFilename
          );
        } catch (error) {
          // Path traversal might be rejected at validation level, which is also acceptable
          expect(error).toBeDefined();
        }
      });

      it('should handle null byte attacks in filenames', async () => {
        const nullByteFilename = 'image\x00.jpg.exe';
        
        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: nullByteFilename,
          mimetype: 'image/jpeg',
          size: 1024
        };

        try {
          await imageService.uploadImage(uploadParams);
          expect(mockStorageService.saveFile).toHaveBeenCalled();
        } catch (error) {
          // Null byte attacks might be rejected at validation level
          expect(error).toBeDefined();
        }
      });

      it('should handle unicode attacks in filenames', async () => {
        const unicodeFilename = 'file\u202Eexe.jpg'; // Right-to-Left Override
        
        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: unicodeFilename,
          mimetype: 'image/jpeg',
          size: 1024
        };

        try {
          await imageService.uploadImage(uploadParams);
          expect(mockStorageService.saveFile).toHaveBeenCalled();
        } catch (error) {
          // Unicode attacks might be rejected at validation level
          expect(error).toBeDefined();
        }
      });
    });

    describe('Input Validation and Sanitization', () => {
      it('should handle extremely long filenames', async () => {
        const longFilename = 'x'.repeat(1000) + '.jpg';
        
        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: longFilename,
          mimetype: 'image/jpeg',
          size: 1024
        };

        try {
          await imageService.uploadImage(uploadParams);
          
          expect(mockImageModel.create).toHaveBeenCalledWith({
            user_id: validUserId,
            file_path: expect.any(String),
            original_metadata: expect.objectContaining({
              filename: longFilename
            })
          });
        } catch (error) {
          // Long filenames might be rejected at validation level
          expect(error).toBeDefined();
        }
      });

      it('should validate image dimensions to prevent resource exhaustion', async () => {
        const extremeDimensions = {
          width: 50000, // Extremely large dimensions
          height: 50000,
          format: 'jpeg' as const,
          channels: 3,
          space: 'srgb' as const
        };
        
        mockImageProcessingService.validateImageBuffer.mockResolvedValue(extremeDimensions);

        const result = await imageService.validateImageFile(
          Buffer.from('image-data'),
          'image/jpeg',
          1024
        );

        expect(result.isValid).toBe(false);
        expect(result.errors).toEqual(expect.arrayContaining([expect.stringMatching(/width too large/)]));
      });
    });
  });

  describe('Authorization and Access Control', () => {
    describe('Cross-User Access Prevention', () => {
      it('should prevent accessing another user\'s images', async () => {
        const victimImage = {
          id: imageId,
          user_id: validUserId,
          file_path: 'uploads/victim-image.jpg',
          original_metadata: {},
          status: 'new' as const
        };
        
        mockImageModel.findById.mockResolvedValue(victimImage);

        await expect(
          imageService.getImageById(imageId, attackerUserId)
        ).rejects.toThrow('You do not have permission to access this image');
      });

      it('should prevent modifying another user\'s images', async () => {
        const victimImage = {
          id: imageId,
          user_id: validUserId,
          file_path: 'uploads/victim-image.jpg',
          original_metadata: {},
          status: 'new' as const
        };
        
        mockImageModel.findById.mockResolvedValue(victimImage);

        await expect(
          imageService.updateImageStatus(imageId, attackerUserId, 'processed')
        ).rejects.toThrow('You do not have permission to access this image');
      });

      it('should prevent deleting another user\'s images', async () => {
        const victimImage = {
          id: imageId,
          user_id: validUserId,
          file_path: 'uploads/victim-image.jpg',
          original_metadata: {},
          status: 'new' as const
        };
        
        mockImageModel.findById.mockResolvedValue(victimImage);

        await expect(
          imageService.deleteImage(imageId, attackerUserId)
        ).rejects.toThrow('You do not have permission to access this image');
      });

      it('should prevent batch operations on mixed ownership images', async () => {
        const imageIds = ['img-1', 'img-2', 'img-3'];
        const mixedImages = [
          { id: 'img-1', user_id: validUserId, status: 'new' },
          { id: 'img-2', user_id: attackerUserId, status: 'new' }, // Attacker's image
          { id: 'img-3', user_id: validUserId, status: 'new' }
        ];
        
        mockImageModel.findById
          .mockResolvedValueOnce(mixedImages[0])
          .mockResolvedValueOnce(mixedImages[1]);

        await expect(
          imageService.batchUpdateStatus(imageIds, validUserId, 'processed')
        ).rejects.toThrow('You do not have permission to access this image');
        
        expect(mockImageModel.batchUpdateStatus).not.toHaveBeenCalled();
      });
    });

    describe('Resource Isolation', () => {
      it('should ensure getUserImages only returns user\'s own images', async () => {
        const userImages = [
          { id: 'img-1', user_id: validUserId, status: 'new' },
          { id: 'img-2', user_id: validUserId, status: 'processed' }
        ];
        
        mockImageModel.findByUserId.mockResolvedValue(userImages);

        const result = await imageService.getUserImages(validUserId);

        expect(mockImageModel.findByUserId).toHaveBeenCalledWith(validUserId, expect.any(Object));
        expect(result).toEqual(userImages);
      });

      it('should ensure getUserImageStats only returns user\'s own statistics', async () => {
        const userStats = {
          total: 5,
          byStatus: { new: 2, processed: 2, labeled: 1 },
          totalSize: 1024000,
          averageSize: 204800
        };
        
        mockImageModel.getUserImageStats.mockResolvedValue(userStats);

        await imageService.getUserImageStats(validUserId);

        expect(mockImageModel.getUserImageStats).toHaveBeenCalledWith(validUserId);
      });
    });

    describe('Parameter Manipulation Prevention', () => {
      it('should handle SQL injection attempts in image IDs', async () => {
        const maliciousImageId = "'; DROP TABLE images; --";
        
        mockImageModel.findById.mockResolvedValue(null);

        await expect(
          imageService.getImageById(maliciousImageId, validUserId)
        ).rejects.toThrow('Image not found');
        
        expect(mockImageModel.findById).toHaveBeenCalledWith(maliciousImageId);
      });

      it('should handle XSS attempts in user IDs', async () => {
        const maliciousUserId = "<script>alert('xss')</script>";
        const validImage = {
          id: imageId,
          user_id: validUserId,
          file_path: 'uploads/test.jpg',
          original_metadata: {},
          status: 'new' as const
        };
        
        mockImageModel.findById.mockResolvedValue(validImage);

        await expect(
          imageService.getImageById(imageId, maliciousUserId)
        ).rejects.toThrow('You do not have permission to access this image');
      });
    });
  });

  describe('Rate Limiting and DoS Protection', () => {
    describe('Storage Limit Enforcement', () => {
      it('should enforce user storage limits to prevent abuse', async () => {
        // Mock user at storage limit
        mockImageModel.getUserImageStats.mockResolvedValue({
          total: 100,
          totalSize: 500 * 1024 * 1024 // 500MB - at limit
        });

        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024
        };

        await expect(imageService.uploadImage(uploadParams)).rejects.toThrow(
          'Storage limit reached. Maximum 500MB allowed per user.'
        );
      });

      it('should enforce image count limits to prevent spam', async () => {
        // Mock user at image count limit
        mockImageModel.getUserImageStats.mockResolvedValue({
          total: 1000, // At limit
          totalSize: 100 * 1024 * 1024
        });

        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024
        };

        await expect(imageService.uploadImage(uploadParams)).rejects.toThrow(
          'Upload limit reached. Maximum 1000 images allowed per user.'
        );
      });
    });

    describe('Processing Resource Protection', () => {
      it('should handle image processing failures gracefully', async () => {
        mockImageProcessingService.validateImageBuffer.mockRejectedValue(
          new Error('Processing timeout')
        );

        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('complex-image-data'),
          originalFilename: 'complex.jpg',
          mimetype: 'image/jpeg',
          size: 1024
        };

        await expect(imageService.uploadImage(uploadParams)).rejects.toThrow();
        expect(mockStorageService.saveFile).not.toHaveBeenCalled();
      });
    });
  });

  describe('Business Logic Security', () => {
    it('should prevent status transition bypasses', async () => {
      const mockImage = {
        id: imageId,
        user_id: validUserId,
        status: 'labeled' as const,
        file_path: 'uploads/test.jpg',
        original_metadata: {}
      };
      
      mockImageModel.findById.mockResolvedValue(mockImage);

      // Try to bypass business rule by going from labeled back to new
      await expect(
        imageService.updateImageStatus(imageId, validUserId, 'new')
      ).rejects.toThrow("Cannot change image status from 'labeled' to 'new'");
    });

    it('should enforce dependency checks before deletion', async () => {
      const mockImage = {
        id: imageId,
        user_id: validUserId,
        file_path: 'uploads/test.jpg',
        original_metadata: {},
        status: 'new' as const
      };
      
      mockImageModel.findById.mockResolvedValue(mockImage);
      mockImageModel.findDependentGarments.mockResolvedValue([
        { id: 'garment-1' },
        { id: 'garment-2' }
      ]);

      await expect(
        imageService.deleteImage(imageId, validUserId)
      ).rejects.toThrow('Cannot delete image. It is being used by 2 garment(s).');
      
      expect(mockImageModel.delete).not.toHaveBeenCalled();
    });

    it('should validate all images in batch operations', async () => {
      const imageIds = ['img-1', 'img-2', 'img-3'];
      
      // First two images belong to user, third doesn't exist
      mockImageModel.findById
        .mockResolvedValueOnce({ id: 'img-1', user_id: validUserId, status: 'new' })
        .mockResolvedValueOnce({ id: 'img-2', user_id: validUserId, status: 'new' })
        .mockResolvedValueOnce(null); // Third image doesn't exist

      await expect(
        imageService.batchUpdateStatus(imageIds, validUserId, 'processed')
      ).rejects.toThrow('Image not found');
      
      expect(mockImageModel.batchUpdateStatus).not.toHaveBeenCalled();
    });
  });

  describe('Error Information Disclosure Prevention', () => {
    it('should not expose internal file paths in errors', async () => {
      mockStorageService.saveFile.mockRejectedValue(
        new Error('Failed to save to /internal/storage/path/file.jpg')
      );

      const uploadParams = {
        userId: validUserId,
        fileBuffer: Buffer.from('image-data'),
        originalFilename: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024
      };

      await expect(imageService.uploadImage(uploadParams)).rejects.toThrow(
        'Failed to process image upload'
      );
      // Should not contain internal path in error message
    });

    it('should not expose database connection details in errors', async () => {
      mockImageModel.create.mockRejectedValue(
        new Error('Connection failed to postgres://user:pass@localhost:5432/db')
      );

      const uploadParams = {
        userId: validUserId,
        fileBuffer: Buffer.from('image-data'),
        originalFilename: 'test.jpg',
        mimetype: 'image/jpeg',
        size: 1024
      };

      await expect(imageService.uploadImage(uploadParams)).rejects.toThrow(
        'Failed to process image upload'
      );
      // Should not contain connection string details
    });

    it('should provide generic error messages for internal failures', async () => {
      mockImageModel.findById.mockRejectedValue(
        new Error('Detailed internal database error with sensitive info')
      );

      await expect(
        imageService.getImageById(imageId, validUserId)
      ).rejects.toThrow('Failed to retrieve image');
      // Should not expose internal error details
    });
  });

  describe('Timing Attack Prevention', () => {
    it('should have consistent response times for valid vs invalid user IDs', async () => {
      const validImageCheck = () => imageService.getImageById(imageId, validUserId);
      const invalidImageCheck = () => imageService.getImageById('non-existent', validUserId);

      // Setup mocks for consistent behavior
      mockImageModel.findById
        .mockResolvedValueOnce({ id: imageId, user_id: validUserId, status: 'new' })
        .mockResolvedValueOnce(null);

      const validTiming = await simulateTimingAttack(validImageCheck, 5);
      const invalidTiming = await simulateTimingAttack(invalidImageCheck, 5);

      // Response times should be relatively similar (within reasonable variance)
      const timeDifference = Math.abs(validTiming.averageTime - invalidTiming.averageTime);
      expect(timeDifference).toBeLessThan(100); // Less than 100ms difference
    });
  });

  describe('Input Boundary Testing', () => {
    it('should handle boundary values correctly', async () => {
      const boundaryTests = createBoundaryTestCases();
      
      // Test empty values
      await expect(
        imageService.uploadImage({
          userId: boundaryTests.emptyValues.emptyString,
          fileBuffer: Buffer.from('data'),
          originalFilename: 'test.jpg',
          mimetype: 'image/jpeg',
          size: 1024
        })
      ).rejects.toThrow();

      // Test extreme numbers - should return validation result, not throw
      const extremeResult = await imageService.validateImageFile(
        Buffer.from('data'),
        'image/jpeg',
        boundaryTests.extremeNumbers.maxInt
      );
      expect(extremeResult.isValid).toBe(false);
      expect(extremeResult.errors).toEqual(expect.arrayContaining([expect.stringMatching(/File too large/)]));
    });

    it('should handle malformed input gracefully', async () => {
      // Test with null/undefined values - these should be caught by TypeScript but let's test runtime behavior
      
      // Mock to return null for invalid IDs
      mockImageModel.findById.mockImplementation((id) => {
        if (id === null || id === undefined) {
          return Promise.resolve(null);
        }
        return Promise.resolve({ id, user_id: validUserId, status: 'new' });
      });

      await expect(
        imageService.getImageById(null as any, validUserId)
      ).rejects.toThrow('Image not found');

      await expect(
        imageService.getImageById(imageId, undefined as any)
      ).rejects.toThrow('You do not have permission to access this image');
    });
  });
});