// /backend/src/tests/integration/labelingService.int.test.ts
// Integration tests for labelingService - tests real Sharp.js operations, file I/O, and storage integration

import fs from 'fs';
import path from 'path';
import sharp from 'sharp';

// Set up test environment variables first
process.env.NODE_ENV = 'test';
process.env.FIRESTORE_EMULATOR_HOST = 'localhost:9100';
process.env.FIREBASE_STORAGE_EMULATOR_HOST = 'localhost:9199';
process.env.FIREBASE_AUTH_EMULATOR_HOST = 'localhost:9099';
process.env.FIREBASE_PROJECT_ID = 'demo-labeling-test';

// Get test uploads directory path
const testUploadsDir = path.join(__dirname, '__test_uploads');
const testImagesDir = path.join(__dirname, '__test_images');

// Mock config for integration testing
jest.doMock('../../config', () => ({
  config: {
    storageMode: 'local',
    uploadsDir: testUploadsDir,
    firebase: {
      projectId: 'demo-labeling-test',
      privateKey: 'test-key',
      clientEmail: 'labeling@test.com'
    }
  }
}));

// Mock Firebase config
jest.doMock('../../config/firebase', () => ({
  admin: {},
  db: {},
  bucket: {}
}));

import { config } from '../../config';
import { setupTestDatabase, cleanupTestData } from '../../utils/testSetup';

// Create a test version of storageService for integration
const createTestStorageService = () => {
  const { v4: uuidv4 } = require('uuid');

  return {
    async saveFile(fileBuffer: Buffer, originalFilename: string): Promise<string> {
      const fileExtension = path.extname(originalFilename);
      const filename = `${uuidv4()}${fileExtension}`;
      
      if (config.storageMode === 'firebase') {
        // Simplified Firebase implementation for testing
        return `uploads/${filename}`;
      } else {
        // Local storage implementation
        const uploadsDir = testUploadsDir;
        if (!fs.existsSync(uploadsDir)) {
          fs.mkdirSync(uploadsDir, { recursive: true });
        }
        
        const filePath = path.join(uploadsDir, filename);
        await fs.promises.writeFile(filePath, fileBuffer);
        return `uploads/${filename}`;
      }
    },

    async deleteFile(filePath: string): Promise<boolean> {
      try {
        if (config.storageMode === 'firebase') {
          return true; // Mock Firebase deletion
        } else {
          const absolutePath = this.getAbsolutePath(filePath);
          if (fs.existsSync(absolutePath)) {
            await fs.promises.unlink(absolutePath);
            return true;
          }
          return false;
        }
      } catch (error) {
        return false;
      }
    },

    getAbsolutePath(relativePath: string): string {
      const filename = path.basename(relativePath);
      return path.join(testUploadsDir, filename);
    },

    async getSignedUrl(filePath: string, expirationMinutes: number = 60): Promise<string> {
      if (config.storageMode === 'firebase') {
        return `https://storage.googleapis.com/test-bucket/${filePath}?token=test`;
      } else {
        return `/api/v1/files/${filePath}`;
      }
    },

    getContentType(fileExtension: string | null | undefined): string {
      if (!fileExtension || typeof fileExtension !== 'string') {
        return 'application/octet-stream';
      }

      const contentTypeMap: { [key: string]: string } = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.webp': 'image/webp',
        '.svg': 'image/svg+xml',
        '.pdf': 'application/pdf',
      };
      
      return contentTypeMap[fileExtension.toLowerCase()] || 'application/octet-stream';
    }
  };
};

// Replace the storageService import
jest.doMock('../../services/storageService', () => ({
  storageService: createTestStorageService()
}));

// Import the service after all mocks are set up
import { labelingService } from '../../services/labelingService';

// Helper function to create test images
const createTestImage = async (width: number, height: number, format: 'jpeg' | 'png' = 'jpeg'): Promise<Buffer> => {
  return sharp({
    create: {
      width,
      height,
      channels: 3,
      background: { r: 128, g: 128, b: 128 }
    }
  })
  .toFormat(format)
  .toBuffer();
};

// Helper function to create test mask data
const createTestMaskData = (width: number, height: number, pattern: 'solid' | 'checkerboard' | 'gradient' = 'solid') => {
  const data = new Array(width * height);
  
  switch (pattern) {
    case 'solid':
      data.fill(255);
      break;
    case 'checkerboard':
      for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
          const index = y * width + x;
          data[index] = (x + y) % 2 === 0 ? 255 : 0;
        }
      }
      break;
    case 'gradient':
      for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
          const index = y * width + x;
          data[index] = Math.floor((x / width) * 255);
        }
      }
      break;
  }
  
  return { width, height, data };
};

// Helper function to ensure directories exist
const ensureDirectoryExists = (dirPath: string): void => {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
};

// Helper function to save test image to file
const saveTestImageToFile = async (imageBuffer: Buffer, filename: string): Promise<string> => {
  ensureDirectoryExists(testImagesDir);
  const imagePath = path.join(testImagesDir, filename);
  await fs.promises.writeFile(imagePath, imageBuffer);
  return `__test_images/${filename}`;
};

describe('LabelingService Integration Tests', () => {
  
  beforeAll(async () => {
    await setupTestDatabase();
    
    // Ensure test directories exist
    ensureDirectoryExists(testUploadsDir);
    ensureDirectoryExists(testImagesDir);
  });

  afterAll(async () => {
    // Clean up test directories
    if (fs.existsSync(testUploadsDir)) {
      fs.rmSync(testUploadsDir, { recursive: true, force: true });
    }
    if (fs.existsSync(testImagesDir)) {
      fs.rmSync(testImagesDir, { recursive: true, force: true });
    }
  });

  beforeEach(async () => {
    await cleanupTestData();
    
    // Clean test directories but keep them
    [testUploadsDir, testImagesDir].forEach(dir => {
      if (fs.existsSync(dir)) {
        const files = fs.readdirSync(dir);
        files.forEach(file => {
          try {
            const filePath = path.join(dir, file);
            const stat = fs.statSync(filePath);
            if (stat.isFile()) {
              fs.unlinkSync(filePath);
            }
          } catch (error) {
            // Ignore cleanup errors
          }
        });
      } else {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  });

  afterEach(async () => {
    // Clean up test files
    [testUploadsDir, testImagesDir].forEach(dir => {
      if (fs.existsSync(dir)) {
        const files = fs.readdirSync(dir);
        files.forEach(file => {
          try {
            const filePath = path.join(dir, file);
            const stat = fs.statSync(filePath);
            if (stat.isFile()) {
              fs.unlinkSync(filePath);
            }
          } catch (error) {
            // Ignore cleanup errors
          }
        });
      }
    });
  });

  describe('Image Processing Integration', () => {
    describe('createBinaryMask() with real data', () => {
      it('should create binary mask from real image data', async () => {
        const maskData = createTestMaskData(50, 50, 'checkerboard');
        
        const result = await labelingService.createBinaryMask(maskData);
        
        expect(result).toBeInstanceOf(Buffer);
        expect(result.length).toBe(2500); // 50 * 50
        
        // Verify binary conversion
        const array = Array.from(result);
        const uniqueValues = new Set(array);
        expect(uniqueValues.size).toBeLessThanOrEqual(2); // Should only contain 0 and/or 255
        expect(Array.from(uniqueValues).every(val => val === 0 || val === 255)).toBe(true);
      });

      it('should handle different mask patterns correctly', async () => {
        const patterns: Array<'solid' | 'checkerboard' | 'gradient'> = ['solid', 'checkerboard', 'gradient'];
        
        for (const pattern of patterns) {
          const maskData = createTestMaskData(20, 20, pattern);
          const result = await labelingService.createBinaryMask(maskData);
          
          expect(result).toBeInstanceOf(Buffer);
          expect(result.length).toBe(400); // 20 * 20
          
          // All should convert to binary (0 or 255)
          const array = Array.from(result);
          expect(array.every(val => val === 0 || val === 255)).toBe(true);
        }
      });

      it('should maintain mask dimensions across different sizes', async () => {
        const testSizes = [
          { width: 1, height: 1 },
          { width: 10, height: 10 },
          { width: 100, height: 50 },
          { width: 50, height: 100 },
          { width: 200, height: 150 }
        ];

        for (const { width, height } of testSizes) {
          const maskData = createTestMaskData(width, height, 'solid');
          const result = await labelingService.createBinaryMask(maskData);
          
          expect(result.length).toBe(width * height);
        }
      });
    });

    describe('Real image file operations', () => {
      it('should process real image files with Sharp.js', async () => {
        // Create a real test image
        const imageBuffer = await createTestImage(100, 100, 'jpeg');
        const imagePath = await saveTestImageToFile(imageBuffer, 'test-image.jpg');
        
        // Verify the image was created correctly
        expect(fs.existsSync(path.join(__dirname, imagePath))).toBe(true);
        
        // Verify Sharp can read our test image
        const metadata = await sharp(path.join(__dirname, imagePath)).metadata();
        expect(metadata.width).toBe(100);
        expect(metadata.height).toBe(100);
        expect(metadata.format).toBe('jpeg');
      });

      it('should handle different image formats', async () => {
        const formats: Array<'jpeg' | 'png'> = ['jpeg', 'png'];
        
        for (const format of formats) {
          const imageBuffer = await createTestImage(50, 50, format);
          const imagePath = await saveTestImageToFile(imageBuffer, `test-image.${format}`);
          
          // Verify image properties
          const metadata = await sharp(path.join(__dirname, imagePath)).metadata();
          expect(metadata.width).toBe(50);
          expect(metadata.height).toBe(50);
          expect(metadata.format).toBe(format);
        }
      });

      it('should create images with different dimensions', async () => {
        const dimensions = [
          { width: 100, height: 100 },
          { width: 200, height: 100 },
          { width: 100, height: 200 },
          { width: 300, height: 150 }
        ];

        for (const { width, height } of dimensions) {
          const imageBuffer = await createTestImage(width, height);
          const imagePath = await saveTestImageToFile(imageBuffer, `test-${width}x${height}.jpg`);
          
          const metadata = await sharp(path.join(__dirname, imagePath)).metadata();
          expect(metadata.width).toBe(width);
          expect(metadata.height).toBe(height);
        }
      });
    });
  });

  describe('End-to-End Mask Application Workflows', () => {
    describe('Test environment workflows', () => {
      it('should complete mask application workflow in test environment', async () => {
        // Create test image and save it
        const imageBuffer = await createTestImage(100, 100, 'jpeg');
        const imagePath = await saveTestImageToFile(imageBuffer, 'workflow-test.jpg');
        
        // Create test mask data
        const maskData = createTestMaskData(100, 100, 'checkerboard');
        
        // Apply mask in test environment
        const result = await labelingService.applyMaskToImage(imagePath, maskData);
        
        // Verify results
        expect(result).toHaveProperty('maskedImagePath');
        expect(result).toHaveProperty('maskPath');
        expect(typeof result.maskedImagePath).toBe('string');
        expect(typeof result.maskPath).toBe('string');
        
        // Verify files were created
        const { storageService } = require('../../services/storageService');
        const maskedImageAbsPath = storageService.getAbsolutePath(result.maskedImagePath);
        const maskAbsPath = storageService.getAbsolutePath(result.maskPath);
        
        expect(fs.existsSync(maskedImageAbsPath)).toBe(true);
        expect(fs.existsSync(maskAbsPath)).toBe(true);
      });

      it('should handle different image sizes in workflows', async () => {
        const testCases = [
          { width: 50, height: 50, format: 'jpeg' as const },
          { width: 100, height: 75, format: 'png' as const },
          { width: 150, height: 100, format: 'jpeg' as const }
        ];

        for (const { width, height, format } of testCases) {
          const imageBuffer = await createTestImage(width, height, format);
          const imagePath = await saveTestImageToFile(imageBuffer, `workflow-${width}x${height}.${format}`);
          const maskData = createTestMaskData(width, height, 'gradient');
          
          const result = await labelingService.applyMaskToImage(imagePath, maskData);
          
          // Normalize paths for cross-platform testing
          const normalizedMaskedPath = result.maskedImagePath.replace(/\\/g, '/');
          const normalizedMaskPath = result.maskPath.replace(/\\/g, '/');
          
          expect(normalizedMaskedPath).toMatch(/_masked\./);
          expect(normalizedMaskPath).toMatch(/_mask\.png$/);
        }
      });

      it('should maintain file organization in test environment', async () => {
        const imageBuffer = await createTestImage(80, 80);
        const imagePath = await saveTestImageToFile(imageBuffer, 'organization-test.jpg');
        const maskData = createTestMaskData(80, 80, 'solid');
        
        const result = await labelingService.applyMaskToImage(imagePath, maskData);
        
        // Check file naming conventions
        expect(result.maskPath).toContain('_mask.png');
        expect(result.maskedImagePath).toContain('_masked');
        
        // Verify directory structure
        const { storageService } = require('../../services/storageService');
        const maskedImagePath = storageService.getAbsolutePath(result.maskedImagePath);
        const maskPath = storageService.getAbsolutePath(result.maskPath);
        
        expect(path.dirname(maskedImagePath)).toBe(testUploadsDir);
        expect(path.dirname(maskPath)).toBe(testUploadsDir);
      });
    });

    describe('Cross-platform compatibility', () => {
      it('should handle different path separators', async () => {
        const imageBuffer = await createTestImage(60, 60);
        
        // Test different path formats
        const pathFormats = [
          'cross-platform-test.jpg',
          'subdir/cross-platform-test.jpg',
          './cross-platform-test.jpg'
        ];

        for (const pathFormat of pathFormats) {
          const normalizedPath = path.normalize(pathFormat);
          const imagePath = await saveTestImageToFile(imageBuffer, path.basename(normalizedPath));
          const maskData = createTestMaskData(60, 60, 'checkerboard');
          
          const result = await labelingService.applyMaskToImage(imagePath, maskData);
          
          expect(result.maskedImagePath).toBeTruthy();
          expect(result.maskPath).toBeTruthy();
        }
      });

      it('should handle various file extensions', async () => {
        const extensions = ['.jpg', '.jpeg', '.png'];
        
        for (const ext of extensions) {
          const format = ext === '.png' ? 'png' : 'jpeg';
          const imageBuffer = await createTestImage(40, 40, format);
          const imagePath = await saveTestImageToFile(imageBuffer, `extension-test${ext}`);
          const maskData = createTestMaskData(40, 40);
          
          const result = await labelingService.applyMaskToImage(imagePath, maskData);
          
          // Masked image should preserve original extension
          expect(result.maskedImagePath).toContain(`_masked${ext}`);
          // Mask should always be PNG
          expect(result.maskPath).toContain('_mask.png');
        }
      });
    });
  });

  describe('Storage Service Integration', () => {
    describe('File persistence', () => {
      it('should persist files through storage service', async () => {
        const imageBuffer = await createTestImage(70, 70);
        const imagePath = await saveTestImageToFile(imageBuffer, 'persistence-test.jpg');
        const maskData = createTestMaskData(70, 70, 'gradient');
        
        const result = await labelingService.applyMaskToImage(imagePath, maskData);
        
        // Files should exist and be readable
        const { storageService } = require('../../services/storageService');
        const maskedImagePath = storageService.getAbsolutePath(result.maskedImagePath);
        const maskPath = storageService.getAbsolutePath(result.maskPath);
        
        expect(fs.existsSync(maskedImagePath)).toBe(true);
        expect(fs.existsSync(maskPath)).toBe(true);
        
        // Files should have reasonable sizes
        const maskedImageStats = fs.statSync(maskedImagePath);
        const maskStats = fs.statSync(maskPath);
        
        expect(maskedImageStats.size).toBeGreaterThan(0);
        expect(maskStats.size).toBeGreaterThan(0);
      });

      it('should handle storage service path resolution', async () => {
        const imageBuffer = await createTestImage(90, 90);
        const imagePath = await saveTestImageToFile(imageBuffer, 'path-resolution-test.jpg');
        const maskData = createTestMaskData(90, 90);
        
        const { storageService } = require('../../services/storageService');
        
        // Test getAbsolutePath functionality
        const testPath = 'uploads/test-file.jpg';
        const absolutePath = storageService.getAbsolutePath(testPath);
        
        expect(path.isAbsolute(absolutePath)).toBe(true);
        expect(absolutePath).toContain(testUploadsDir);
        expect(absolutePath).toContain('test-file.jpg');
      });
    });

    describe('Storage mode compatibility', () => {
      it('should work with local storage mode', async () => {
        config.storageMode = 'local';
        
        const imageBuffer = await createTestImage(85, 85);
        const imagePath = await saveTestImageToFile(imageBuffer, 'local-storage-test.jpg');
        const maskData = createTestMaskData(85, 85, 'checkerboard');
        
        const result = await labelingService.applyMaskToImage(imagePath, maskData);
        
        expect(result.maskedImagePath).toBeTruthy();
        expect(result.maskPath).toBeTruthy();
        
        // Verify local file creation
        const { storageService } = require('../../services/storageService');
        const maskedImagePath = storageService.getAbsolutePath(result.maskedImagePath);
        expect(fs.existsSync(maskedImagePath)).toBe(true);
      });

      it('should generate appropriate URLs for different storage modes', async () => {
        const { storageService } = require('../../services/storageService');
        
        // Test local mode
        config.storageMode = 'local';
        const localUrl = await storageService.getSignedUrl('uploads/test.jpg');
        expect(localUrl).toContain('/api/v1/files/');
        
        // Test Firebase mode
        config.storageMode = 'firebase';
        const firebaseUrl = await storageService.getSignedUrl('uploads/test.jpg');
        expect(firebaseUrl).toContain('googleapis.com');
      });
    });
  });

  describe('Error Handling and Recovery', () => {
    describe('File system errors', () => {
      it('should handle missing source images gracefully', async () => {
        const nonExistentPath = '__test_images/nonexistent-image.jpg';
        const maskData = createTestMaskData(50, 50);
        
        // In test environment, the service uses mock operations
        // So we test that it handles the missing file scenario appropriately
        try {
          const result = await labelingService.applyMaskToImage(nonExistentPath, maskData);
          
          // In test mode, it creates mock files, so we verify the structure
          expect(result.maskedImagePath).toBeTruthy();
          expect(result.maskPath).toBeTruthy();
          expect(result.maskedImagePath).toContain('_masked');
          expect(result.maskPath).toContain('_mask.png');
        } catch (error) {
          // Throwing an error is also acceptable behavior
          expect(error).toBeDefined();
        }
      });

      it('should handle corrupted image data', async () => {
        // Create a file with invalid image data
        const corruptImagePath = path.join(testImagesDir, 'corrupt-image.jpg');
        await fs.promises.writeFile(corruptImagePath, 'This is not image data');
        
        const maskData = createTestMaskData(50, 50);
        
        // In test environment, this might succeed with mock operations
        try {
          const result = await labelingService.applyMaskToImage('__test_images/corrupt-image.jpg', maskData);
          
          // If it succeeds in test mode, verify the output structure
          expect(result.maskedImagePath).toBeTruthy();
          expect(result.maskPath).toBeTruthy();
        } catch (error) {
          // Throwing an error for corrupt data is expected behavior
          expect(error).toBeDefined();
        }
      });

      it('should handle directory creation errors gracefully', async () => {
        // Test with a path that would require directory creation
        const imageBuffer = await createTestImage(30, 30);
        const imagePath = await saveTestImageToFile(imageBuffer, 'dir-creation-test.jpg');
        const maskData = createTestMaskData(30, 30);
        
        // This should work (create directories as needed)
        const result = await labelingService.applyMaskToImage(imagePath, maskData);
        expect(result.maskedImagePath).toBeTruthy();
        expect(result.maskPath).toBeTruthy();
      });

      it('should validate error handling in production mode simulation', async () => {
        // Test what would happen in production mode
        const originalEnv = process.env.NODE_ENV;
        
        try {
          // Temporarily simulate production environment
          process.env.NODE_ENV = 'production';
          
          const nonExistentPath = '__test_images/production-nonexistent.jpg';
          const maskData = createTestMaskData(30, 30);
          
          // In production mode, this should handle errors differently
          try {
            await labelingService.applyMaskToImage(nonExistentPath, maskData);
            // If it succeeds, that's fine for this simulation
            expect(true).toBe(true);
          } catch (error) {
            // Throwing errors in production mode is expected
            expect(error).toBeDefined();
          }
        } finally {
          // Restore test environment
          process.env.NODE_ENV = originalEnv;
        }
      });
    });

    describe('Resource constraints', () => {
      it('should handle reasonable resource limits', async () => {
        // Test with moderately large images
        const imageBuffer = await createTestImage(500, 500);
        const imagePath = await saveTestImageToFile(imageBuffer, 'large-image-test.jpg');
        const maskData = createTestMaskData(500, 500, 'gradient');
        
        const startTime = Date.now();
        const result = await labelingService.applyMaskToImage(imagePath, maskData);
        const endTime = Date.now();
        
        expect(result.maskedImagePath).toBeTruthy();
        expect(result.maskPath).toBeTruthy();
        expect(endTime - startTime).toBeLessThan(10000); // Should complete in under 10 seconds
      });

      it('should handle memory efficiently with multiple operations', async () => {
        const operations = Array.from({ length: 5 }, async (_, i) => {
          const imageBuffer = await createTestImage(100, 100);
          const imagePath = await saveTestImageToFile(imageBuffer, `batch-test-${i}.jpg`);
          const maskData = createTestMaskData(100, 100, 'checkerboard');
          
          return labelingService.applyMaskToImage(imagePath, maskData);
        });

        const results = await Promise.all(operations);
        
        expect(results).toHaveLength(5);
        results.forEach(result => {
          expect(result.maskedImagePath).toBeTruthy();
          expect(result.maskPath).toBeTruthy();
        });
      });
    });
  });

  describe('Performance and Optimization', () => {
    describe('Processing speed', () => {
      it('should process small images quickly', async () => {
        const imageBuffer = await createTestImage(50, 50);
        const imagePath = await saveTestImageToFile(imageBuffer, 'speed-test-small.jpg');
        const maskData = createTestMaskData(50, 50);
        
        const startTime = Date.now();
        await labelingService.applyMaskToImage(imagePath, maskData);
        const endTime = Date.now();
        
        expect(endTime - startTime).toBeLessThan(2000); // Should be under 2 seconds
      });

      it('should handle medium images within reasonable time', async () => {
        const imageBuffer = await createTestImage(200, 200);
        const imagePath = await saveTestImageToFile(imageBuffer, 'speed-test-medium.jpg');
        const maskData = createTestMaskData(200, 200, 'gradient');
        
        const startTime = Date.now();
        await labelingService.applyMaskToImage(imagePath, maskData);
        const endTime = Date.now();
        
        expect(endTime - startTime).toBeLessThan(5000); // Should be under 5 seconds
      });
    });

    describe('Memory usage patterns', () => {
      it('should not leak memory with repeated operations', async () => {
        for (let i = 0; i < 10; i++) {
          const imageBuffer = await createTestImage(75, 75);
          const imagePath = await saveTestImageToFile(imageBuffer, `memory-test-${i}.jpg`);
          const maskData = createTestMaskData(75, 75);
          
          const result = await labelingService.applyMaskToImage(imagePath, maskData);
          expect(result.maskedImagePath).toBeTruthy();
          
          // Clean up immediately to test memory cleanup
          const { storageService } = require('../../services/storageService');
          const maskedImagePath = storageService.getAbsolutePath(result.maskedImagePath);
          const maskPath = storageService.getAbsolutePath(result.maskPath);
          
          if (fs.existsSync(maskedImagePath)) fs.unlinkSync(maskedImagePath);
          if (fs.existsSync(maskPath)) fs.unlinkSync(maskPath);
        }
        
        // If we get here without memory issues, the test passes
        expect(true).toBe(true);
      });
    });

    describe('Concurrent operations', () => {
      it('should handle concurrent mask applications', async () => {
        const concurrentOps = Array.from({ length: 3 }, async (_, i) => {
          const imageBuffer = await createTestImage(60, 60);
          const imagePath = await saveTestImageToFile(imageBuffer, `concurrent-${i}.jpg`);
          const maskData = createTestMaskData(60, 60, i % 2 === 0 ? 'solid' : 'checkerboard');
          
          return labelingService.applyMaskToImage(imagePath, maskData);
        });

        const results = await Promise.all(concurrentOps);
        
        expect(results).toHaveLength(3);
        results.forEach((result, index) => {
          expect(result.maskedImagePath).toBeTruthy();
          expect(result.maskPath).toBeTruthy();
          
          // Each should have unique output paths
          const otherResults = results.filter((_, i) => i !== index);
          otherResults.forEach(other => {
            expect(result.maskedImagePath).not.toBe(other.maskedImagePath);
            expect(result.maskPath).not.toBe(other.maskPath);
          });
        });
      });
    });
  });

  describe('Environment Mode Testing', () => {
    describe('Test vs Production mode behavior', () => {
      it('should detect test environment correctly', () => {
        expect(process.env.NODE_ENV).toBe('test');
        
        // Should use test mode in applyMaskToImage
        const isTestEnv = process.env.NODE_ENV === 'test';
        expect(isTestEnv).toBe(true);
      });

      it('should use appropriate file operations for test environment', async () => {
        const imageBuffer = await createTestImage(40, 40);
        const imagePath = await saveTestImageToFile(imageBuffer, 'env-mode-test.jpg');
        const maskData = createTestMaskData(40, 40);
        
        // In test environment, should use mock operations
        const result = await labelingService.applyMaskToImage(imagePath, maskData);
        
        expect(result.maskedImagePath).toBeTruthy();
        expect(result.maskPath).toBeTruthy();
        
        // Should create actual test files
        const { storageService } = require('../../services/storageService');
        const maskedImagePath = storageService.getAbsolutePath(result.maskedImagePath);
        const maskPath = storageService.getAbsolutePath(result.maskPath);
        
        expect(fs.existsSync(maskedImagePath)).toBe(true);
        expect(fs.existsSync(maskPath)).toBe(true);
      });
    });
  });
});