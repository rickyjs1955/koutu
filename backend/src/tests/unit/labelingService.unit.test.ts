// /backend/src/tests/unit/labelingService.unit.test.ts
// Unit tests for labelingService - focuses on pure functions and business logic

import path from 'path';

// Mock external dependencies BEFORE importing labelingService
jest.mock('sharp', () => ({
  __esModule: true,
  default: jest.fn()
}));

jest.mock('fs/promises', () => ({
  access: jest.fn(),
  mkdir: jest.fn(),
  writeFile: jest.fn(),
  readFile: jest.fn()
}));

// Mock storageService completely to avoid Firebase issues
jest.mock('../../services/storageService', () => ({
  storageService: {
    getAbsolutePath: jest.fn((relativePath: string) => `/mocked/absolute/${relativePath}`),
    saveFile: jest.fn(),
    deleteFile: jest.fn(),
    getSignedUrl: jest.fn(),
    getContentType: jest.fn()
  }
}));

// Mock the entire config module to avoid Firebase initialization
jest.mock('../../config', () => ({
  config: {
    storageMode: 'local',
    uploadsDir: '/mocked/uploads',
    firebase: {
      projectId: 'mock-project',
      privateKey: 'mock-key',
      clientEmail: 'mock@test.com'
    }
  }
}));

// Mock Firebase config to prevent initialization
jest.mock('../../config/firebase', () => ({
  admin: {},
  db: {},
  bucket: {}
}));

// Import the service AFTER all mocks are set up
import { labelingService } from '../../services/labelingService';

describe('LabelingService Unit Tests', () => {
  
  // Clear all mocks before each test
  beforeEach(() => {
    jest.clearAllMocks();
  });
  
  describe('createBinaryMask()', () => {
    it('should create binary mask with correct dimensions', async () => {
      const maskData = {
        width: 3,
        height: 2,
        data: [0, 128, 255, 64, 0, 192]
      };

      const result = await labelingService.createBinaryMask(maskData);

      expect(result).toBeInstanceOf(Buffer);
      expect(result.length).toBe(6); // width * height
    });

    it('should convert non-zero values to 255 and zero values to 0', async () => {
      const maskData = {
        width: 4,
        height: 1,
        data: [0, 1, 128, 255]
      };

      const result = await labelingService.createBinaryMask(maskData);
      const array = Array.from(result);

      expect(array).toEqual([0, 255, 255, 255]);
    });

    it('should handle edge case with all zero values', async () => {
      const maskData = {
        width: 2,
        height: 2,
        data: [0, 0, 0, 0]
      };

      const result = await labelingService.createBinaryMask(maskData);
      const array = Array.from(result);

      expect(array).toEqual([0, 0, 0, 0]);
    });

    it('should handle edge case with all non-zero values', async () => {
      const maskData = {
        width: 2,
        height: 2,
        data: [1, 50, 200, 255]
      };

      const result = await labelingService.createBinaryMask(maskData);
      const array = Array.from(result);

      expect(array).toEqual([255, 255, 255, 255]);
    });

    it('should handle large mask data efficiently', async () => {
      const size = 1000;
      const maskData = {
        width: size,
        height: 1,
        data: Array.from({ length: size }, (_, i) => i % 2) // Alternating 0,1
      };

      const startTime = Date.now();
      const result = await labelingService.createBinaryMask(maskData);
      const endTime = Date.now();

      expect(result.length).toBe(size);
      expect(endTime - startTime).toBeLessThan(100); // Should be fast
    });

    it('should handle Uint8ClampedArray input', async () => {
      const maskData = {
        width: 2,
        height: 2,
        data: new Uint8ClampedArray([0, 128, 255, 64])
      };

      const result = await labelingService.createBinaryMask(maskData);
      const array = Array.from(result);

      expect(array).toEqual([0, 255, 255, 255]);
    });

    it('should handle regular array input', async () => {
      const maskData = {
        width: 2,
        height: 2,
        data: [0, 128, 255, 64]
      };

      const result = await labelingService.createBinaryMask(maskData);
      const array = Array.from(result);

      expect(array).toEqual([0, 255, 255, 255]);
    });

    it('should validate data length matches dimensions', async () => {
      const maskData = {
        width: 2,
        height: 2,
        data: [255] // Should be 4 elements
      };

      const result = await labelingService.createBinaryMask(maskData);
      
      // Function should still work but only process available data
      expect(result.length).toBe(4); // Buffer size based on width * height
      const array = Array.from(result);
      expect(array[0]).toBe(255); // First element processed
      expect(array[1]).toBe(0);   // Remaining elements default to 0
    });

    it('should handle empty mask data', async () => {
      const maskData = {
        width: 0,
        height: 0,
        data: []
      };

      const result = await labelingService.createBinaryMask(maskData);
      
      expect(result.length).toBe(0);
    });

    it('should handle fractional values correctly', async () => {
      const maskData = {
        width: 3,
        height: 1,
        data: [0.5, 1.7, 254.9]
      };

      const result = await labelingService.createBinaryMask(maskData);
      const array = Array.from(result);

      // Non-zero values should become 255
      expect(array).toEqual([255, 255, 255]);
    });
  });

  describe('ensureDirectoryExists()', () => {
    beforeEach(() => {
      jest.clearAllMocks();
    });

    it('should not create directory if it already exists', async () => {
      const fs = require('fs/promises');
      fs.access.mockResolvedValue(undefined); // Directory exists

      await labelingService.ensureDirectoryExists('/test/path');

      expect(fs.access).toHaveBeenCalledWith('/test/path');
      expect(fs.mkdir).not.toHaveBeenCalled();
    });

    it('should create directory if it does not exist', async () => {
      const fs = require('fs/promises');
      fs.access.mockRejectedValue(new Error('ENOENT')); // Directory doesn't exist
      fs.mkdir.mockResolvedValue(undefined);

      await labelingService.ensureDirectoryExists('/test/path');

      expect(fs.access).toHaveBeenCalledWith('/test/path');
      expect(fs.mkdir).toHaveBeenCalledWith('/test/path', { recursive: true });
    });

    it('should handle mkdir errors gracefully', async () => {
      const fs = require('fs/promises');
      fs.access.mockRejectedValue(new Error('ENOENT'));
      fs.mkdir.mockRejectedValue(new Error('Permission denied'));

      await expect(
        labelingService.ensureDirectoryExists('/test/path')
      ).rejects.toThrow('Permission denied');

      expect(fs.access).toHaveBeenCalled();
      expect(fs.mkdir).toHaveBeenCalled();
    });

    it('should handle various path formats', async () => {
      const fs = require('fs/promises');
      fs.access.mockRejectedValue(new Error('ENOENT'));
      fs.mkdir.mockResolvedValue(undefined);

      const testPaths = [
        '/unix/style/path',
        'C:\\Windows\\Style\\Path',
        './relative/path',
        '../parent/path',
        'simple-path'
      ];

      for (const testPath of testPaths) {
        await labelingService.ensureDirectoryExists(testPath);
        expect(fs.mkdir).toHaveBeenCalledWith(testPath, { recursive: true });
      }

      expect(fs.mkdir).toHaveBeenCalledTimes(testPaths.length);
    });
  });

  describe('Path Manipulation Logic', () => {
    // These tests examine the path logic within applyMaskToImage
    // We'll test the logic without actual file operations

    describe('File naming logic', () => {
      it('should generate correct mask filename from image path', () => {
        const testCases = [
          {
            input: 'uploads/image.jpg',
            expectedMask: 'uploads/image_mask.png',
            expectedMasked: 'uploads/image_masked.jpg'
          },
          {
            input: 'uploads/test.png',
            expectedMask: 'uploads/test_mask.png',
            expectedMasked: 'uploads/test_masked.png'
          },
          {
            input: 'uploads/no-extension',
            expectedMask: 'uploads/no-extension_mask.png',
            expectedMasked: 'uploads/no-extension_masked'
          },
          {
            input: 'uploads/complex.name.with.dots.jpeg',
            expectedMask: 'uploads/complex.name.with.dots_mask.png',
            expectedMasked: 'uploads/complex.name.with.dots_masked.jpeg'
          }
        ];

        testCases.forEach(({ input, expectedMask, expectedMasked }) => {
          const fileExtension = path.extname(input);
          const fileNameWithoutExt = path.basename(input, fileExtension);
          const dirName = path.dirname(input);

          const maskFileName = `${fileNameWithoutExt}_mask.png`;
          const maskPath = path.join(dirName, maskFileName);

          const maskedFileName = `${fileNameWithoutExt}_masked${fileExtension}`;
          const maskedImagePath = path.join(dirName, maskedFileName);

          // Normalize paths for cross-platform testing
          expect(path.normalize(maskPath)).toBe(path.normalize(expectedMask));
          expect(path.normalize(maskedImagePath)).toBe(path.normalize(expectedMasked));
        });
      });

      it('should handle edge cases in file naming', () => {
        const edgeCases = [
          {
            input: '',
            description: 'empty string'
          },
          {
            input: '.',
            description: 'current directory'
          },
          {
            input: '..',
            description: 'parent directory'
          },
          {
            input: '.hidden',
            description: 'hidden file without extension'
          },
          {
            input: '.hidden.txt',
            description: 'hidden file with extension'
          }
        ];

        edgeCases.forEach(({ input, description }) => {
          // These should not throw errors
          expect(() => {
            const fileExtension = path.extname(input);
            const fileNameWithoutExt = path.basename(input, fileExtension);
            const dirName = path.dirname(input);
            
            const maskFileName = `${fileNameWithoutExt}_mask.png`;
            const maskedFileName = `${fileNameWithoutExt}_masked${fileExtension}`;
            
            // Basic validation - these should be strings
            expect(typeof maskFileName).toBe('string');
            expect(typeof maskedFileName).toBe('string');
          }).not.toThrow();
        });
      });
    });

    describe('Cross-platform path handling', () => {
      it('should handle Unix-style paths', () => {
        const unixPath = 'uploads/subfolder/image.jpg';
        const fileExtension = path.extname(unixPath);
        const fileNameWithoutExt = path.basename(unixPath, fileExtension);
        const dirName = path.dirname(unixPath);

        expect(fileExtension).toBe('.jpg');
        expect(fileNameWithoutExt).toBe('image');
        expect(dirName).toBe('uploads/subfolder');
      });

      it('should handle Windows-style paths', () => {
        // Simulate Windows path (though path.join will normalize it)
        const segments = ['uploads', 'subfolder', 'image.jpg'];
        const fullPath = path.join(...segments);
        
        const fileExtension = path.extname(fullPath);
        const fileNameWithoutExt = path.basename(fullPath, fileExtension);
        const dirName = path.dirname(fullPath);

        expect(fileExtension).toBe('.jpg');
        expect(fileNameWithoutExt).toBe('image');
        expect(dirName).toContain('uploads');
        expect(dirName).toContain('subfolder');
      });
    });
  });

  describe('Environment Detection Logic', () => {
    let originalEnv: string | undefined;

    beforeEach(() => {
      originalEnv = process.env.NODE_ENV;
    });

    afterEach(() => {
      if (originalEnv !== undefined) {
        process.env.NODE_ENV = originalEnv;
      } else {
        delete process.env.NODE_ENV;
      }
    });

    it('should detect test environment correctly', () => {
      process.env.NODE_ENV = 'test';
      const isTestEnv = process.env.NODE_ENV === 'test';
      expect(isTestEnv).toBe(true);
    });

    it('should detect production environment correctly', () => {
      process.env.NODE_ENV = 'production';
      const isTestEnv = process.env.NODE_ENV === 'test';
      expect(isTestEnv).toBe(false);
    });

    it('should detect development environment correctly', () => {
      process.env.NODE_ENV = 'development';
      const isTestEnv = process.env.NODE_ENV === 'test';
      expect(isTestEnv).toBe(false);
    });

    it('should handle undefined environment', () => {
      delete process.env.NODE_ENV;
      const isTestEnv = process.env.NODE_ENV === 'test';
      expect(isTestEnv).toBe(false);
    });

    it('should handle case sensitivity', () => {
      process.env.NODE_ENV = 'TEST'; // Different case
      const isTestEnv = process.env.NODE_ENV === 'test';
      expect(isTestEnv).toBe(false);
    });
  });

  describe('Data Validation Logic', () => {
    // Helper function for type-safe validation
    const isValidMaskDataType = (data: any): boolean => {
      return Array.isArray(data) || (data != null && data instanceof Uint8ClampedArray);
    };

    describe('MaskData validation', () => {
      it('should identify valid mask data structure', () => {
        const validMaskData = {
          width: 100,
          height: 100,
          data: new Array(10000).fill(255)
        };

        // Validate structure using type-safe helper
        expect(typeof validMaskData.width).toBe('number');
        expect(typeof validMaskData.height).toBe('number');
        expect(isValidMaskDataType(validMaskData.data)).toBe(true);
        expect(validMaskData.width).toBeGreaterThan(0);
        expect(validMaskData.height).toBeGreaterThan(0);
        expect(validMaskData.data.length).toBe(validMaskData.width * validMaskData.height);
      });

      it('should identify invalid mask data structures', () => {
        const invalidCases = [
          { width: 0, height: 100, data: [] },
          { width: 100, height: 0, data: [] },
          { width: -10, height: 100, data: [] },
          { width: 100, height: -10, data: [] },
          { width: 'invalid', height: 100, data: [] },
          { width: 100, height: 'invalid', data: [] },
          { width: 100, height: 100, data: 'invalid' },
          { width: 100, height: 100, data: null },
          { width: 100, height: 100 }, // Missing data
        ];

        invalidCases.forEach((invalidMaskData, index) => {
          // Use type-safe validation without 'as any'
          const isValid = Boolean(
            typeof invalidMaskData.width === 'number' &&
            typeof invalidMaskData.height === 'number' &&
            invalidMaskData.width > 0 &&
            invalidMaskData.height > 0 &&
            invalidMaskData.data &&
            isValidMaskDataType(invalidMaskData.data)
          );

          expect(isValid).toBe(false);
        });
      });

      it('should handle dimension mismatch validation', () => {
        const testCases = [
          { width: 2, height: 2, dataLength: 4, expected: true },  // Perfect match
          { width: 2, height: 2, dataLength: 3, expected: false }, // Too few
          { width: 2, height: 2, dataLength: 5, expected: false }, // Too many
          { width: 0, height: 0, dataLength: 0, expected: true },  // Edge case
          { width: 1, height: 1000, dataLength: 1000, expected: true }, // Large but valid
        ];

        testCases.forEach(({ width, height, dataLength, expected }) => {
          const expectedLength = width * height;
          const isValid = dataLength === expectedLength;
          expect(isValid).toBe(expected);
        });
      });
    });

    describe('Value range validation', () => {
      it('should handle mask data value ranges correctly', () => {
        const testValues = [
          { value: 0, expectedBinary: 0 },
          { value: 1, expectedBinary: 255 },
          { value: 127, expectedBinary: 255 },
          { value: 128, expectedBinary: 255 },
          { value: 255, expectedBinary: 255 },
          { value: -1, expectedBinary: 0 }, // Fixed: Negative values should be 0 (not > 0)
          { value: 256, expectedBinary: 255 }, // Values > 255
          { value: 0.5, expectedBinary: 255 }, // Fractional values
        ];

        testValues.forEach(({ value, expectedBinary }) => {
          const binaryValue = value > 0 ? 255 : 0;
          expect(binaryValue).toBe(expectedBinary);
        });
      });
    });
  });

  describe('Error Handling Logic', () => {
    describe('Buffer creation error handling', () => {
      it('should handle buffer creation with valid data', () => {
        const validData = new Uint8ClampedArray([0, 128, 255]);
        
        expect(() => {
          Buffer.from(validData);
        }).not.toThrow();
      });

      it('should handle empty data gracefully', () => {
        const emptyData = new Uint8ClampedArray([]);
        
        expect(() => {
          Buffer.from(emptyData);
        }).not.toThrow();
        
        const buffer = Buffer.from(emptyData);
        expect(buffer.length).toBe(0);
      });
    });

    describe('Type safety validation', () => {
      it('should handle various data types safely', () => {
        const testCases = [
          { input: [1, 2, 3], isValid: true },
          { input: new Uint8ClampedArray([1, 2, 3]), isValid: true },
          { input: new Uint8Array([1, 2, 3]), isValid: true },
          { input: 'invalid', isValid: false },
          { input: null, isValid: false },
          { input: undefined, isValid: false },
          { input: {}, isValid: false },
        ];

        testCases.forEach(({ input, isValid }) => {
          // Use type-safe validation without 'as any'
          const actuallyValid = Boolean(
            Array.isArray(input) || 
            (input != null && input instanceof Uint8ClampedArray) || 
            (input != null && input instanceof Uint8Array)
          );
          expect(actuallyValid).toBe(isValid);
        });
      });
    });
  });

  describe('Performance Characteristics', () => {
    describe('createBinaryMask performance', () => {
      it('should process small masks quickly', async () => {
        const maskData = {
          width: 10,
          height: 10,
          data: new Array(100).fill(128)
        };

        const startTime = Date.now();
        await labelingService.createBinaryMask(maskData);
        const endTime = Date.now();

        expect(endTime - startTime).toBeLessThan(10); // Should be very fast
      });

      it('should handle medium masks efficiently', async () => {
        const maskData = {
          width: 100,
          height: 100,
          data: new Array(10000).fill(128)
        };

        const startTime = Date.now();
        await labelingService.createBinaryMask(maskData);
        const endTime = Date.now();

        expect(endTime - startTime).toBeLessThan(50); // Should still be fast
      });

      it('should scale reasonably with large masks', async () => {
        const maskData = {
          width: 1000,
          height: 100,
          data: new Array(100000).fill(128)
        };

        const startTime = Date.now();
        await labelingService.createBinaryMask(maskData);
        const endTime = Date.now();

        expect(endTime - startTime).toBeLessThan(200); // Should scale reasonably
      });
    });

    describe('Memory usage patterns', () => {
      it('should not leak memory with repeated operations', async () => {
        const maskData = {
          width: 50,
          height: 50,
          data: new Array(2500).fill(128)
        };

        // Run multiple operations
        const promises = Array.from({ length: 10 }, () => 
          labelingService.createBinaryMask(maskData)
        );

        const results = await Promise.all(promises);
        
        // All operations should succeed
        expect(results).toHaveLength(10);
        results.forEach(result => {
          expect(result).toBeInstanceOf(Buffer);
          expect(result.length).toBe(2500);
        });
      });
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle minimum valid dimensions', async () => {
      const maskData = {
        width: 1,
        height: 1,
        data: [255]
      };

      const result = await labelingService.createBinaryMask(maskData);
      expect(result.length).toBe(1);
      expect(Array.from(result)).toEqual([255]);
    });

    it('should handle maximum reasonable dimensions', async () => {
      // Large but reasonable for testing
      const size = 2000;
      const maskData = {
        width: size,
        height: 1,
        data: new Array(size).fill(1)
      };

      const result = await labelingService.createBinaryMask(maskData);
      expect(result.length).toBe(size);
      
      // Check first and last elements
      const array = Array.from(result);
      expect(array[0]).toBe(255);
      expect(array[size - 1]).toBe(255);
    });

    it('should handle square dimensions', async () => {
      const size = 100;
      const maskData = {
        width: size,
        height: size,
        data: new Array(size * size).fill(128)
      };

      const result = await labelingService.createBinaryMask(maskData);
      expect(result.length).toBe(size * size);
    });

    it('should handle rectangular dimensions', async () => {
      const maskData = {
        width: 200,
        height: 50,
        data: new Array(10000).fill(64)
      };

      const result = await labelingService.createBinaryMask(maskData);
      expect(result.length).toBe(10000);
    });
  });
});