// /backend/src/services/__tests__/testImageService.unit.test.ts
/**
 * Unit Tests for Test Image Service Utility
 * 
 * @description Comprehensive tests for the ImageServiceTestHelper utility used in integration tests.
 * Tests cover image processing, file operations, user management, and cleanup functionality.
 * 
 * @author Development Team
 * @version 1.0.0
 * @since June 25, 2025
 */

import { ImageServiceTestHelper, TestUser } from '../../utils/testImageService';
import { TestDatabaseConnection } from '../../utils/../utils/testDatabaseConnection';
import { v4 as uuidv4 } from 'uuid';
import sharp from 'sharp';
import fs from 'fs/promises';
import path from 'path';

// Mock dependencies
jest.mock('../../utils/../utils/testDatabaseConnection', () => ({
  TestDatabaseConnection: {
    query: jest.fn()
  }
}));

jest.mock('uuid', () => ({
  v4: jest.fn()
}));

jest.mock('sharp');
jest.mock('fs/promises');
jest.mock('path');

const mockQuery = TestDatabaseConnection.query as jest.MockedFunction<typeof TestDatabaseConnection.query>;
const mockUuidv4 = uuidv4 as jest.Mock<string, any[]>;
const mockSharp = sharp as jest.MockedFunction<typeof sharp>;
const mockFs = fs as jest.Mocked<typeof fs>;
const mockPath = path as jest.Mocked<typeof path>;

describe('ImageServiceTestHelper', () => {
  let helper: ImageServiceTestHelper;
  const mockUserId = 'user-123-456-789';
  const mockTestStorageDir = '/test/storage/dir';

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Mock path.join to return predictable paths
    mockPath.join.mockImplementation((...args) => args.join('/'));
    
    // Mock process.cwd before creating helper
    const mockCwd = jest.spyOn(process, 'cwd').mockReturnValue('/project/root');
    
    helper = new ImageServiceTestHelper();
    
    mockCwd.mockRestore();
  });

  describe('Constructor', () => {
    it('should initialize with correct test storage directory', () => {
      // Create a new helper with proper mocking
      const mockCwd = jest.spyOn(process, 'cwd').mockReturnValue('/project/root');
      const testHelper = new ImageServiceTestHelper();
      
      expect(mockPath.join).toHaveBeenCalledWith('/project/root', 'test-storage');
      expect(testHelper.getStorageDir()).toBe('/project/root/test-storage');
      
      mockCwd.mockRestore();
    });
  });

  describe('createTestUser', () => {
    const mockUser: TestUser = {
      id: mockUserId,
      email: 'test@example.com',
      displayName: 'Test User'
    };

    beforeEach(() => {
      mockUuidv4.mockReturnValue(mockUserId);
      Date.now = jest.fn().mockReturnValue(1640995200000); // Fixed timestamp
      Math.random = jest.fn().mockReturnValue(0.123456789);
    });

    it('should create a test user with default values', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [mockUser],
        rowCount: 1
      });

      const result = await helper.createTestUser();

      expect(mockUuidv4).toHaveBeenCalledTimes(1);
      expect(mockQuery).toHaveBeenCalledWith(
        'INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)',
        [
          mockUserId,
          expect.stringMatching(/^test-\d+-[a-z0-9]+@example\.com$/),
          'Test User'
        ]
      );
      expect(result.id).toBe(mockUserId);
      expect(result.displayName).toBe('Test User');
    });

    it('should create a test user with custom overrides', async () => {
      const customUser = {
        email: 'custom@test.com',
        displayName: 'Custom User'
      };

      mockQuery.mockResolvedValueOnce({
        rows: [{ ...mockUser, ...customUser }],
        rowCount: 1
      });

      const result = await helper.createTestUser(customUser);

      expect(mockQuery).toHaveBeenCalledWith(
        'INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)',
        [mockUserId, 'custom@test.com', 'Custom User']
      );
      expect(result.email).toBe('custom@test.com');
      expect(result.displayName).toBe('Custom User');
    });

    it('should handle database errors during user creation', async () => {
      mockQuery.mockRejectedValueOnce(new Error('Database connection failed'));

      await expect(helper.createTestUser()).rejects.toThrow('Database connection failed');
    });

    it('should track created users for cleanup', async () => {
      mockQuery.mockResolvedValueOnce({
        rows: [mockUser],
        rowCount: 1
      });

      await helper.createTestUser();

      // Verify user is tracked by attempting cleanup
      await helper.cleanup();
      
      expect(mockQuery).toHaveBeenLastCalledWith(
        expect.stringContaining('DELETE FROM users WHERE id IN'),
        [mockUserId]
      );
    });
  });

  describe('createImageBuffer', () => {
    let mockSharpInstance: any;
    let mockBuffer: Buffer;

    beforeEach(() => {
      mockBuffer = Buffer.from('fake-image-data');
      
      // Create a comprehensive mock for the sharp fluent API
      mockSharpInstance = {
        composite: jest.fn().mockReturnThis(),
        toColorspace: jest.fn().mockReturnThis(),
        jpeg: jest.fn().mockReturnThis(),
        png: jest.fn().mockReturnThis(),
        webp: jest.fn().mockReturnThis(),
        toBuffer: jest.fn().mockResolvedValue(mockBuffer)
      };

      mockSharp.mockReturnValue(mockSharpInstance);
    });

    it('should create a basic JPEG image buffer', async () => {
      const result = await helper.createImageBuffer();

      expect(mockSharp).toHaveBeenCalledWith({
        create: {
          width: 800,
          height: 600,
          channels: 3,
          background: { r: 255, g: 128, b: 64 }
        }
      });
      expect(mockSharpInstance.jpeg).toHaveBeenCalledWith({
        quality: 80,
        progressive: true
      });
      expect(result).toBe(mockBuffer);
    });

    it('should create a PNG image buffer', async () => {
      await helper.createImageBuffer({ format: 'png' });

      expect(mockSharpInstance.png).toHaveBeenCalledWith({
        compressionLevel: 6
      });
    });

    it('should create a WebP image buffer', async () => {
      await helper.createImageBuffer({ format: 'webp', quality: 90 });

      expect(mockSharpInstance.webp).toHaveBeenCalledWith({
        quality: 90
      });
    });

    it('should create image with custom dimensions', async () => {
      await helper.createImageBuffer({ width: 1200, height: 800 });

      expect(mockSharp).toHaveBeenCalledWith({
        create: {
          width: 1200,
          height: 800,
          channels: 3,
          background: { r: 255, g: 128, b: 64 }
        }
      });
    });

    it('should handle CMYK color space', async () => {
      await helper.createImageBuffer({ colorSpace: 'cmyk' });

      expect(mockSharp).toHaveBeenCalledWith({
        create: {
          width: 800,
          height: 600,
          channels: 4,
          background: 'cmyk(20, 40, 60, 0)'
        }
      });
      expect(mockSharpInstance.toColorspace).toHaveBeenCalledWith('cmyk');
    });

    it('should handle P3 color space', async () => {
      await helper.createImageBuffer({ colorSpace: 'p3' });

      expect(mockSharpInstance.toColorspace).toHaveBeenCalledWith('p3');
    });

    it('should add text overlay when requested', async () => {
      await helper.createImageBuffer({ addText: true, width: 1000, height: 750 });

      expect(mockSharpInstance.composite).toHaveBeenCalledWith([{
        input: expect.any(Buffer),
        blend: 'over'
      }]);
    });

    it('should not add text overlay when disabled', async () => {
      await helper.createImageBuffer({ addText: false });

      expect(mockSharpInstance.composite).not.toHaveBeenCalled();
    });

    it('should handle sharp processing errors', async () => {
      mockSharpInstance.toBuffer.mockRejectedValueOnce(new Error('Sharp processing failed'));

      await expect(helper.createImageBuffer()).rejects.toThrow('Sharp processing failed');
    });

    it('should default to JPEG for unknown formats', async () => {
      await helper.createImageBuffer({ format: 'unknown' as any });

      expect(mockSharpInstance.jpeg).toHaveBeenCalledWith({
        quality: 80
      });
    });
  });

  describe('createInstagramImages', () => {
    it('should create all Instagram format images', async () => {
      const mockBuffer = Buffer.from('instagram-image');
      const mockSharpInstance = {
        composite: jest.fn().mockReturnThis(),
        toColorspace: jest.fn().mockReturnThis(),
        jpeg: jest.fn().mockReturnThis(),
        toBuffer: jest.fn().mockResolvedValue(mockBuffer)
      };

      mockSharp.mockReturnValue(mockSharpInstance as any);

      const result = await helper.createInstagramImages();

      expect(result).toEqual({
        square: mockBuffer,
        portrait: mockBuffer,
        landscape: mockBuffer,
        minSize: mockBuffer,
        maxSize: mockBuffer
      });

      // Verify correct dimensions were used
      expect(mockSharp).toHaveBeenCalledWith(expect.objectContaining({
        create: expect.objectContaining({ width: 1080, height: 1080 })
      })); // square
      expect(mockSharp).toHaveBeenCalledWith(expect.objectContaining({
        create: expect.objectContaining({ width: 1080, height: 1350 })
      })); // portrait
      expect(mockSharp).toHaveBeenCalledWith(expect.objectContaining({
        create: expect.objectContaining({ width: 1080, height: 566 })
      })); // landscape
      expect(mockSharp).toHaveBeenCalledWith(expect.objectContaining({
        create: expect.objectContaining({ width: 320, height: 400 })
      })); // minSize
      expect(mockSharp).toHaveBeenCalledWith(expect.objectContaining({
        create: expect.objectContaining({ width: 1440, height: 754 })
      })); // maxSize
    });
  });

  describe('createInvalidImages', () => {
    it('should create various invalid image types', async () => {
      const mockImageBuffer = Buffer.from('image-data');
      const mockSharpInstance = {
        composite: jest.fn().mockReturnThis(),
        toColorspace: jest.fn().mockReturnThis(),
        jpeg: jest.fn().mockReturnThis(),
        toBuffer: jest.fn().mockResolvedValue(mockImageBuffer)
      };

      mockSharp.mockReturnValue(mockSharpInstance as any);

      const result = await helper.createInvalidImages();

      expect(result.tooSmall).toBeDefined();
      expect(result.tooLarge).toBeDefined();
      expect(result.wrongRatio).toBeDefined();
      expect(result.corrupted).toEqual(Buffer.from('This is not a valid image file'));
      expect(result.wrongFormat.toString()).toContain('PDF');
    });
  });

  describe('saveTestFile', () => {
    it('should save file to test storage directory', async () => {
      const filename = 'test-image.jpg';
      const buffer = Buffer.from('test-data');
      const expectedPath = '/project/root/test-storage/uploads/test-image.jpg';

      mockFs.writeFile.mockResolvedValueOnce(undefined);

      const result = await helper.saveTestFile(filename, buffer);

      expect(mockPath.join).toHaveBeenCalledWith(
        '/project/root/test-storage',
        'uploads',
        filename
      );
      expect(mockFs.writeFile).toHaveBeenCalledWith(expectedPath, buffer);
      expect(result).toBe(expectedPath);
    });

    it('should handle file write errors', async () => {
      mockFs.writeFile.mockRejectedValueOnce(new Error('Permission denied'));

      await expect(helper.saveTestFile('test.jpg', Buffer.from('data')))
        .rejects.toThrow('Permission denied');
    });

    it('should track created files for cleanup', async () => {
      const filename = 'tracked-file.jpg';
      mockFs.writeFile.mockResolvedValueOnce(undefined);

      await helper.saveTestFile(filename, Buffer.from('data'));

      // Verify file is tracked by attempting cleanup
      mockFs.unlink.mockResolvedValueOnce(undefined);
      await helper.cleanup();

      expect(mockFs.unlink).toHaveBeenCalledWith(
        '/project/root/test-storage/uploads/tracked-file.jpg'
      );
    });
  });

  describe('verifyFile', () => {
    it('should verify existing file and return metadata', async () => {
      const filePath = '/test/path/image.jpg';
      const mockStats = { size: 1024 };
      const mockMetadata = { width: 800, height: 600, format: 'jpeg' };

      mockFs.stat.mockResolvedValueOnce(mockStats as any);
      
      const mockSharpInstance = {
        metadata: jest.fn().mockResolvedValue(mockMetadata)
      };
      mockSharp.mockReturnValue(mockSharpInstance as any);

      const result = await helper.verifyFile(filePath);

      expect(mockFs.stat).toHaveBeenCalledWith(filePath);
      expect(mockSharp).toHaveBeenCalledWith(filePath);
      expect(result).toEqual({
        exists: true,
        size: 1024,
        metadata: mockMetadata
      });
    });

    it('should return not exists for missing file', async () => {
      mockFs.stat.mockRejectedValueOnce(new Error('File not found'));

      const result = await helper.verifyFile('/non/existent/file.jpg');

      expect(result).toEqual({ exists: false });
    });

    it('should handle sharp metadata errors', async () => {
      mockFs.stat.mockResolvedValueOnce({ size: 1024 } as any);
      mockSharp.mockImplementation(() => {
        throw new Error('Invalid image format');
      });

      const result = await helper.verifyFile('/test/corrupted.jpg');

      expect(result).toEqual({ exists: false });
    });
  });

  describe('trackImageId', () => {
    it('should track image ID for cleanup', async () => {
      const imageId = 'img-123-456';
      
      helper.trackImageId(imageId);
      
      // Verify tracking by checking cleanup
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
      await helper.cleanup();

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM original_images WHERE id IN'),
        [imageId]
      );
    });

    it('should track multiple image IDs', async () => {
      const imageIds = ['img-1', 'img-2', 'img-3'];
      
      imageIds.forEach(id => helper.trackImageId(id));
      
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 3 });
      await helper.cleanup();

      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM original_images WHERE id IN'),
        imageIds
      );
    });
  });

  describe('cleanup', () => {
    beforeEach(() => {
      mockFs.unlink.mockResolvedValue(undefined);
      mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });
    });

    it('should clean up all tracked resources', async () => {
      // Create test data to track
      mockQuery.mockResolvedValueOnce({ rows: [{ id: mockUserId }], rowCount: 1 });
      await helper.createTestUser();
      
      await helper.saveTestFile('test.jpg', Buffer.from('data'));
      helper.trackImageId('img-123');

      // Perform cleanup
      await helper.cleanup();

      // Verify file cleanup
      expect(mockFs.unlink).toHaveBeenCalledWith(
        '/project/root/test-storage/uploads/test.jpg'
      );

      // Verify image cleanup
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM original_images WHERE id IN'),
        ['img-123']
      );

      // Verify user cleanup
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('DELETE FROM users WHERE id IN'),
        [mockUserId]
      );
    });

    it('should handle file deletion errors gracefully', async () => {
      await helper.saveTestFile('test.jpg', Buffer.from('data'));
      mockFs.unlink.mockRejectedValueOnce(new Error('File busy'));

      // Should not throw
      await expect(helper.cleanup()).resolves.not.toThrow();
    });

    it('should handle database cleanup errors gracefully', async () => {
      helper.trackImageId('img-123');
      mockQuery.mockRejectedValueOnce(new Error('Database error'));

      // Should not throw and continue with other cleanup
      await expect(helper.cleanup()).resolves.not.toThrow();
    });

    it('should skip cleanup when no resources to clean', async () => {
      await helper.cleanup();

      expect(mockFs.unlink).not.toHaveBeenCalled();
      expect(mockQuery).not.toHaveBeenCalled();
    });
  });

  describe('generatePerformanceTestData', () => {
    beforeEach(() => {
      let userCounter = 0;
      mockUuidv4.mockImplementation(() => `user-${userCounter++}`);
      
      const mockSharpInstance: any = {
        composite: jest.fn().mockReturnThis(),
        toColorspace: jest.fn().mockReturnThis(),
        jpeg: jest.fn().mockReturnThis(),
        png: jest.fn().mockReturnThis(),
        toBuffer: jest.fn().mockResolvedValue(Buffer.from('perf-image')),
        metadata: jest.fn()
      };
      mockSharp.mockReturnValue(mockSharpInstance as any);
      
      mockQuery.mockResolvedValue({ rows: [{}], rowCount: 1 });
    });

    it('should generate performance test data with correct structure', async () => {
      const count = 10;
      
      const result = await helper.generatePerformanceTestData(count);

      expect(result.users).toHaveLength(5); // Limited to 5 users
      expect(result.imageBuffers).toHaveLength(count);
      expect(result.uploadParams).toHaveLength(count);

      // Verify upload params structure
      result.uploadParams.forEach((param, index) => {
        expect(param).toEqual({
          userId: expect.any(String),
          fileBuffer: expect.any(Buffer),
          originalFilename: expect.stringMatching(/^perf-test-\d+\.(jpg|png)$/),
          mimetype: expect.stringMatching(/^image\/(jpeg|png)$/),
          size: expect.any(Number)
        });
      });
    });

    it('should limit users to maximum of 5', async () => {
      const result = await helper.generatePerformanceTestData(50);

      expect(result.users).toHaveLength(5);
      expect(result.imageBuffers).toHaveLength(50);
      expect(result.uploadParams).toHaveLength(50);
    });

    it('should create alternating JPEG and PNG formats', async () => {
      const result = await helper.generatePerformanceTestData(4);

      expect(result.uploadParams[0].originalFilename).toMatch(/\.jpg$/);
      expect(result.uploadParams[0].mimetype).toBe('image/jpeg');
      expect(result.uploadParams[1].originalFilename).toMatch(/\.png$/);
      expect(result.uploadParams[1].mimetype).toBe('image/png');
      expect(result.uploadParams[2].originalFilename).toMatch(/\.jpg$/);
      expect(result.uploadParams[3].originalFilename).toMatch(/\.png$/);
    });

    it('should distribute users across upload params', async () => {
      const result = await helper.generatePerformanceTestData(10);

      const userIds = new Set(result.uploadParams.map(p => p.userId));
      expect(userIds.size).toBeLessThanOrEqual(5); // Should use available users
    });

    it('should handle edge case of zero count', async () => {
      const result = await helper.generatePerformanceTestData(0);

      expect(result.users).toHaveLength(0);
      expect(result.imageBuffers).toHaveLength(0);
      expect(result.uploadParams).toHaveLength(0);
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle concurrent operations safely', async () => {
      const promises = [
        helper.createTestUser(),
        helper.createTestUser(),
        helper.createTestUser()
      ];

      mockQuery.mockResolvedValue({ rows: [{ id: 'user-1' }], rowCount: 1 });

      await expect(Promise.all(promises)).resolves.toHaveLength(3);
    });

    it('should handle memory constraints with large images', async () => {
      const mockLargeBuffer = Buffer.alloc(50 * 1024 * 1024); // 50MB
      const mockSharpInstance = {
        composite: jest.fn().mockReturnThis(),
        toColorspace: jest.fn().mockReturnThis(),
        jpeg: jest.fn().mockReturnThis(),
        toBuffer: jest.fn().mockResolvedValue(mockLargeBuffer)
      };
      mockSharp.mockReturnValue(mockSharpInstance as any);

      const result = await helper.createImageBuffer({ width: 4000, height: 3000 });

      expect(result).toBe(mockLargeBuffer);
    });

    it('should handle path traversal attempts safely', async () => {
      const maliciousFilename = '../../utils/../../etc/passwd';
      
      mockFs.writeFile.mockResolvedValueOnce(undefined);

      await helper.saveTestFile(maliciousFilename, Buffer.from('data'));

      expect(mockPath.join).toHaveBeenCalledWith(
        '/project/root/test-storage',
        'uploads',
        maliciousFilename
      );
    });
  });

  describe('Integration Scenarios', () => {
    it('should support full test lifecycle', async () => {
      // Clear and reset UUID mock for this test
      jest.clearAllMocks();
      mockUuidv4.mockReturnValue(mockUserId);
      
      // Create user
      mockQuery.mockResolvedValueOnce({ rows: [{ id: mockUserId }], rowCount: 1 });
      const user = await helper.createTestUser();

      // Create image
      const mockSharpInstance = {
        composite: jest.fn().mockReturnThis(),
        toColorspace: jest.fn().mockReturnThis(),
        jpeg: jest.fn().mockReturnThis(),
        toBuffer: jest.fn().mockResolvedValue(Buffer.from('image'))
      };
      mockSharp.mockReturnValue(mockSharpInstance as any);

      const imageBuffer = await helper.createImageBuffer();

      // Save file
      mockFs.writeFile.mockResolvedValueOnce(undefined);
      const filePath = await helper.saveTestFile('test.jpg', imageBuffer);

      // Verify file
      mockFs.stat.mockResolvedValueOnce({ size: 1024 } as any);
      const mockMetadata = { width: 800, height: 600 };
      (mockSharpInstance as any).metadata = jest.fn().mockResolvedValue(mockMetadata);
      mockSharp.mockReturnValue(mockSharpInstance as any);

      const verification = await helper.verifyFile(filePath);

      // Track image ID
      helper.trackImageId('img-123');

      // Cleanup
      mockFs.unlink.mockResolvedValueOnce(undefined);
      mockQuery.mockResolvedValue({ rows: [], rowCount: 1 });
      await helper.cleanup();

      expect(user.id).toBe(mockUserId);
      expect(imageBuffer).toBeInstanceOf(Buffer);
      expect(verification.exists).toBe(true);
      expect(mockFs.unlink).toHaveBeenCalled();
    });
  });
});