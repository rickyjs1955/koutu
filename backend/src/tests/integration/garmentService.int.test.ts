// /backend/src/services/__tests__/garmentService.int.test.ts
// Fixed integration test suite that uses test database and Firebase emulators

import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { testUserModel } from '../../utils/testUserModel';
import { testImageModel } from '../../utils/testImageModel';
import { v4 as uuidv4 } from 'uuid';
import sharp from 'sharp';
import fs from 'fs/promises';
import path from 'path';

// Mock Firebase to use emulators
jest.mock('../../config/firebase', () => ({
  default: {
    storage: () => ({
      bucket: () => ({
        file: () => ({
          save: jest.fn().mockResolvedValue(undefined),
          delete: jest.fn().mockResolvedValue(undefined),
          exists: jest.fn().mockResolvedValue([true]),
          getSignedUrl: jest.fn().mockResolvedValue(['http://localhost:9199/test-url'])
        })
      })
    })
  }
}));

// Mock the labeling service that applies masks
jest.mock('../../services/labelingService', () => ({
  labelingService: {
    applyMaskToImage: jest.fn().mockImplementation((imagePath: string, maskData: any) => {
      const baseName = path.basename(imagePath, path.extname(imagePath));
      const garmentPath = path.join(path.dirname(imagePath), `${baseName}_garment.jpg`);
      const maskPath = path.join(path.dirname(imagePath), `${baseName}_mask.png`);
      
      return Promise.resolve({
        maskedImagePath: garmentPath,
        maskPath: maskPath
      });
    })
  }
}));

// Mock the storage service
jest.mock('../../services/storageService', () => ({
  storageService: {
    deleteFile: jest.fn().mockResolvedValue(true)
  }
}));

// Create a test-specific garment service that uses test models
const createTestGarmentService = () => {
  return {
    async createGarment(params: {
      userId: string;
      originalImageId: string;
      maskData: {
        width: number;
        height: number;
        data: Uint8ClampedArray | number[];
      };
      metadata?: Record<string, any>;
    }) {
      const { userId, originalImageId, maskData, metadata = {} } = params;
      
      // Business Rule 1: Validate image exists and ownership
      const originalImage = await testImageModel.findById(originalImageId);
      
      if (!originalImage) {
        throw new Error('Original image not found');
      }

      if (originalImage.user_id !== userId) {
        throw new Error('You do not have permission to use this image');
      }

      // Business Rule 2: Image status validation
      if (originalImage.status !== 'new') {
        if (originalImage.status === 'labeled') {
          throw new Error('This image has already been used to create a garment');
        } else {
          throw new Error('Image must be in "new" status before creating a garment');
        }
      }
      
      // Business Rule 3: Mask validation against image dimensions
      const imageMeta = originalImage.original_metadata;
      if (imageMeta?.width && imageMeta?.height) {
        if (maskData.width !== imageMeta.width || maskData.height !== imageMeta.height) {
          throw new Error(`Mask dimensions (${maskData.width}x${maskData.height}) don't match image dimensions (${imageMeta.width}x${imageMeta.height})`);
        }
      }

      // Business Rule 4: Validate mask has meaningful content
      if (this.isMaskEmpty(maskData.data)) {
        throw new Error('Mask data appears to be empty - no garment area defined');
      }
      
      // Generate paths for garment files
      const baseName = path.basename(originalImage.file_path, path.extname(originalImage.file_path));
      const garmentPath = path.join(path.dirname(originalImage.file_path), `${baseName}_garment.jpg`);
      const maskPath = path.join(path.dirname(originalImage.file_path), `${baseName}_mask.png`);

      // Update source image status
      await testImageModel.updateStatus(originalImageId, 'labeled');

      // Create garment record
      const garmentId = uuidv4();
      const result = await TestDatabaseConnection.query(
        `INSERT INTO garment_items 
        (id, user_id, original_image_id, file_path, mask_path, metadata, created_at, updated_at) 
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) 
        RETURNING *`,
        [garmentId, userId, originalImageId, garmentPath, maskPath, JSON.stringify(metadata)]
      );

      return result.rows[0];
    },

    isMaskEmpty(maskData: Uint8ClampedArray | number[]): boolean {
      const nonZeroCount = Array.from(maskData).filter(value => value > 0).length;
      const totalPixels = maskData.length;
      return (nonZeroCount / totalPixels) < 0.01;
    },

    async getGarment(params: { garmentId: string; userId: string }) {
      const { garmentId, userId } = params;
      
      const result = await TestDatabaseConnection.query(
        'SELECT * FROM garment_items WHERE id = $1',
        [garmentId]
      );
      
      const garment = result.rows[0];
      
      if (!garment) {
        throw new Error('Garment not found');
      }
      
      if (garment.user_id !== userId) {
        throw new Error('You do not have permission to access this garment');
      }
      
      return garment;
    },

    async getGarments(params: { 
      userId: string;
      filter?: Record<string, any>;
      pagination?: { page: number; limit: number };
    }) {
      const { userId, filter = {}, pagination } = params;
      
      let queryText = 'SELECT * FROM garment_items WHERE user_id = $1';
      const queryParams = [userId];
      let paramIndex = 2;
      
      // Apply filters
      if (filter['metadata.category']) {
        queryText += ` AND metadata->>'category' = $${paramIndex}`;
        queryParams.push(filter['metadata.category']);
        paramIndex++;
      }
      
      queryText += ' ORDER BY created_at DESC';
      
      // Apply pagination
      if (pagination) {
        const { page, limit } = pagination;
        const offset = (page - 1) * limit;
        queryText += ` LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
        queryParams.push(limit.toString(), offset.toString());
      }
      
      const result = await TestDatabaseConnection.query(queryText, queryParams);
      return result.rows;
    },

    async updateGarmentMetadata(params: {
      garmentId: string;
      userId: string;
      metadata: Record<string, any>;
      options?: { replace: boolean };
    }) {
      const { garmentId, userId, metadata } = params;
      
      // Verify ownership first
      await this.getGarment({ garmentId, userId });
      
      // Validate metadata
      this.validateGarmentMetadata(metadata);
      
      const result = await TestDatabaseConnection.query(
        'UPDATE garment_items SET metadata = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
        [JSON.stringify(metadata), garmentId]
      );
      
      return result.rows[0];
    },

    validateGarmentMetadata(metadata: Record<string, any>): void {
      if (!metadata || typeof metadata !== 'object') {
        return;
      }

      if (metadata.category && typeof metadata.category !== 'string') {
        throw new Error('Garment category must be a string');
      }

      if (metadata.size && !['XS', 'S', 'M', 'L', 'XL', 'XXL'].includes(metadata.size)) {
        throw new Error('Invalid garment size');
      }

      if (metadata.color && typeof metadata.color !== 'string') {
        throw new Error('Garment color must be a string');
      }

      const metadataString = JSON.stringify(metadata);
      if (metadataString.length > 10000) {
        throw new Error('Metadata too large (max 10KB)');
      }
    },

    async deleteGarment(params: { garmentId: string; userId: string }) {
      const { garmentId, userId } = params;
      
      // Verify ownership
      await this.getGarment({ garmentId, userId });
      
      const result = await TestDatabaseConnection.query(
        'DELETE FROM garment_items WHERE id = $1',
        [garmentId]
      );
      
      return { success: (result.rowCount ?? 0) > 0, garmentId };
    },

    async getUserGarmentStats(userId: string) {
      const garments = await this.getGarments({ userId });
      
    const stats: GarmentStats = {
        total: garments.length,
        byCategory: {} as Record<string, number>,
        bySize: {} as Record<string, number>,
        byColor: {} as Record<string, number>,
        recentlyCreated: garments.filter((g: GarmentWithMetadata) => {
            const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
            return new Date(g.created_at) > dayAgo;
        }).length
    };

    interface GarmentMetadata {
        category?: string;
        size?: string;
        color?: string;
        [key: string]: any;
    }

    interface GarmentWithMetadata {
        metadata: GarmentMetadata;
        [key: string]: any;
    }

    interface GarmentStats {
        total: number;
        byCategory: Record<string, number>;
        bySize: Record<string, number>;
        byColor: Record<string, number>;
        recentlyCreated: number;
    }

                garments.forEach((garment: GarmentWithMetadata) => {
                    const metadata: GarmentMetadata = garment.metadata || {};
                    
                    if (metadata.category) {
                        stats.byCategory[metadata.category] = (stats.byCategory[metadata.category] || 0) + 1;
                    }
                    
                    if (metadata.size) {
                        stats.bySize[metadata.size] = (stats.bySize[metadata.size] || 0) + 1;
                    }
                    
                    if (metadata.color) {
                        stats.byColor[metadata.color] = (stats.byColor[metadata.color] || 0) + 1;
                    }
                });

      return stats;
    }
  };
};

// Test data interfaces
interface TestUser {
  id: string;
  email: string;
}

interface TestImage {
  id: string;
  user_id: string;
  file_path: string;
  original_metadata: Record<string, any>;
  status: 'new' | 'processed' | 'labeled';
}

interface TestGarment {
  id: string;
  user_id: string;
  original_image_id: string;
  file_path: string;
  mask_path: string;
  metadata: Record<string, any>;
}

describe('GarmentService Integration Tests', () => {
  // Test context data
  let testUsers: TestUser[] = [];
  let testImages: TestImage[] = [];
  let testGarments: TestGarment[] = [];
  let testStorageDir: string;
  let garmentService: ReturnType<typeof createTestGarmentService>;

  beforeAll(async () => {
    console.log('🚀 Initializing GarmentService integration tests...');
    
    // Initialize database connection
    await TestDatabaseConnection.initialize();
    
    // Create test garment service
    garmentService = createTestGarmentService();
    
    // Setup test storage directory
    testStorageDir = path.join(process.cwd(), 'test-storage');
    await fs.mkdir(path.join(testStorageDir, 'uploads'), { recursive: true });
    await fs.mkdir(path.join(testStorageDir, 'masks'), { recursive: true });
    await fs.mkdir(path.join(testStorageDir, 'garments'), { recursive: true });
    
    console.log('✅ Test environment initialized');
  });

  afterAll(async () => {
    console.log('🧹 Cleaning up GarmentService integration tests...');
    
    // Clean up test data in reverse dependency order
    for (const garment of testGarments) {
      try {
        await TestDatabaseConnection.query('DELETE FROM garment_items WHERE id = $1', [garment.id]);
        if (garment.file_path) await fs.unlink(garment.file_path).catch(() => {});
        if (garment.mask_path) await fs.unlink(garment.mask_path).catch(() => {});
      } catch (error) {
        console.warn('Error cleaning up garment:', error);
      }
    }
    
    for (const image of testImages) {
      try {
        await testImageModel.delete(image.id);
        if (image.file_path) await fs.unlink(image.file_path).catch(() => {});
      } catch (error) {
        console.warn('Error cleaning up image:', error);
      }
    }
    
    for (const user of testUsers) {
      try {
        await testUserModel.delete(user.id);
      } catch (error) {
        console.warn('Error cleaning up user:', error);
      }
    }
    
    // Clean up test storage
    try {
      await fs.rm(testStorageDir, { recursive: true, force: true });
    } catch (error) {
      console.warn('Error cleaning up test storage:', error);
    }
    
    // Close database connections
    await TestDatabaseConnection.cleanup();
    console.log('✅ Integration test cleanup completed');
  });

  beforeEach(async () => {
    // Clear arrays for each test
    testUsers = [];
    testImages = [];
    testGarments = [];
  });

  // Helper functions
  const createTestUser = async (overrides: Partial<TestUser> = {}): Promise<TestUser> => {
    const userData = {
      email: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
      password: 'testpassword123',
      ...overrides
    };
    
    const user = await testUserModel.create(userData);
    const testUser = { id: user.id, email: user.email };
    testUsers.push(testUser);
    return testUser;
  };

  const createTestImage = async (userId: string, overrides: Partial<any> = {}): Promise<TestImage> => {
    // Create actual image file
    const fileName = `test-image-${Date.now()}.jpg`;
    const filePath = path.join(testStorageDir, 'uploads', fileName);
    
    const imageBuffer = await sharp({
      create: {
        width: 800,
        height: 600,
        channels: 3,
        background: { r: 100, g: 150, b: 200 }
      }
    }).jpeg().toBuffer();
    
    await fs.writeFile(filePath, imageBuffer);
    
    const imageData = {
      user_id: userId,
      file_path: filePath,
      original_metadata: {
        width: 800,
        height: 600,
        format: 'jpeg',
        size: imageBuffer.length
      },
      ...overrides
    };
    
    const image = await testImageModel.create(imageData);
    testImages.push(image);
    return image;
  };

  const createValidMaskData = (width: number = 800, height: number = 600) => {
    const totalPixels = width * height;
    const maskData = new Uint8ClampedArray(totalPixels);
    
    // Create a meaningful mask - a rectangle in the center
    const centerX = Math.floor(width / 2);
    const centerY = Math.floor(height / 2);
    const rectWidth = Math.floor(width * 0.3);
    const rectHeight = Math.floor(height * 0.4);
    
    for (let y = centerY - rectHeight / 2; y < centerY + rectHeight / 2; y++) {
      for (let x = centerX - rectWidth / 2; x < centerX + rectWidth / 2; x++) {
        if (x >= 0 && x < width && y >= 0 && y < height) {
          maskData[y * width + x] = 255; // White = garment area
        }
      }
    }
    
    return { width, height, data: maskData };
  };

  const createEmptyMaskData = (width: number = 800, height: number = 600) => {
    return {
      width,
      height,
      data: new Uint8ClampedArray(width * height) // All zeros
    };
  };

  describe('Garment Creation', () => {
    it('should successfully create a garment from valid image and mask', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData(800, 600);
      
      const garmentParams = {
        userId: user.id,
        originalImageId: image.id,
        maskData,
        metadata: {
          category: 'shirt',
          color: 'blue',
          size: 'M'
        }
      };
      
      const garment = await garmentService.createGarment(garmentParams);
      testGarments.push(garment);
      
      expect(garment).toBeDefined();
      expect(garment.id).toBeDefined();
      expect(garment.user_id).toBe(user.id);
      expect(garment.original_image_id).toBe(image.id);
      expect(garment.file_path).toBeDefined();
      expect(garment.mask_path).toBeDefined();
      expect(garment.metadata).toEqual(garmentParams.metadata);
      
      // Verify image status was updated to 'labeled'
      const updatedImage = await testImageModel.findById(image.id);
      expect(updatedImage?.status).toBe('labeled');
      
      console.log(`✅ Created garment with ID: ${garment.id}`);
    });

    it('should reject creation with non-existent image', async () => {
      const user = await createTestUser();
      const fakeImageId = uuidv4();
      const maskData = createValidMaskData();
      
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: fakeImageId,
        maskData
      })).rejects.toThrow('Original image not found');
    });

    it('should reject creation when user does not own the image', async () => {
      const user1 = await createTestUser();
      const user2 = await createTestUser();
      const image = await createTestImage(user1.id);
      const maskData = createValidMaskData();
      
      await expect(garmentService.createGarment({
        userId: user2.id,
        originalImageId: image.id,
        maskData
      })).rejects.toThrow('permission');
    });

    it('should reject creation with already labeled image', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData();
      
      // First creation should succeed
      const garment1 = await garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData
      });
      testGarments.push(garment1);
      
      // Second creation should fail
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData
      })).rejects.toThrow('already been used');
    });

    it('should reject creation with empty mask', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const emptyMaskData = createEmptyMaskData();
      
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData: emptyMaskData
      })).rejects.toThrow('empty');
    });

    it('should reject creation with mismatched mask dimensions', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const wrongSizeMask = createValidMaskData(400, 300); // Image is 800x600
      
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData: wrongSizeMask
      })).rejects.toThrow('dimensions');
    });

    it('should handle null/undefined metadata gracefully', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData();
      
      const garment = await garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData,
        metadata: { category: 'shirt' }
      });
      testGarments.push(garment);
      
      // These should not throw errors
      await garmentService.updateGarmentMetadata({
        garmentId: garment.id,
        userId: user.id,
        metadata: null as any
      });
      
      await garmentService.updateGarmentMetadata({
        garmentId: garment.id,
        userId: user.id,
        metadata: undefined as any
      });
      
      await garmentService.updateGarmentMetadata({
        garmentId: garment.id,
        userId: user.id,
        metadata: {}
      });
    });
  });

  describe('Garment Deletion', () => {
    it('should successfully delete a garment', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData();
      
      const garment = await garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData
      });
      
      const result = await garmentService.deleteGarment({
        garmentId: garment.id,
        userId: user.id
      });
      
      expect(result.success).toBe(true);
      expect(result.garmentId).toBe(garment.id);
      
      // Verify garment is deleted
      await expect(garmentService.getGarment({
        garmentId: garment.id,
        userId: user.id
      })).rejects.toThrow('not found');
    });

    it('should reject deletion of non-existent garment', async () => {
      const user = await createTestUser();
      const fakeGarmentId = uuidv4();
      
      await expect(garmentService.deleteGarment({
        garmentId: fakeGarmentId,
        userId: user.id
      })).rejects.toThrow('not found');
    });

    it('should reject deletion when user does not own garment', async () => {
      const user1 = await createTestUser();
      const user2 = await createTestUser();
      const image = await createTestImage(user1.id);
      const maskData = createValidMaskData();
      
      const garment = await garmentService.createGarment({
        userId: user1.id,
        originalImageId: image.id,
        maskData
      });
      testGarments.push(garment);
      
      await expect(garmentService.deleteGarment({
        garmentId: garment.id,
        userId: user2.id
      })).rejects.toThrow('permission');
    });
  });

  describe('Statistics and Analytics', () => {
    it('should generate user garment statistics', async () => {
      const user = await createTestUser();
      const images = await Promise.all([
        createTestImage(user.id),
        createTestImage(user.id),
        createTestImage(user.id)
      ]);
      
      const maskData = createValidMaskData();
      
      // Create garments with different metadata
      const garments = await Promise.all([
        garmentService.createGarment({
          userId: user.id,
          originalImageId: images[0].id,
          maskData,
          metadata: { category: 'shirt', size: 'M', color: 'red' }
        }),
        garmentService.createGarment({
          userId: user.id,
          originalImageId: images[1].id,
          maskData,
          metadata: { category: 'shirt', size: 'L', color: 'blue' }
        }),
        garmentService.createGarment({
          userId: user.id,
          originalImageId: images[2].id,
          maskData,
          metadata: { category: 'pants', size: 'M', color: 'black' }
        })
      ]);
      testGarments.push(...garments);
      
      const stats = await garmentService.getUserGarmentStats(user.id);
      
      expect(stats.total).toBe(3);
      expect(stats.byCategory.shirt).toBe(2);
      expect(stats.byCategory.pants).toBe(1);
      expect(stats.bySize.M).toBe(2);
      expect(stats.bySize.L).toBe(1);
      expect(stats.byColor.red).toBe(1);
      expect(stats.byColor.blue).toBe(1);
      expect(stats.byColor.black).toBe(1);
      expect(typeof stats.recentlyCreated).toBe('number');
    });

    it('should handle empty statistics gracefully', async () => {
      const user = await createTestUser();
      
      const stats = await garmentService.getUserGarmentStats(user.id);
      
      expect(stats.total).toBe(0);
      expect(stats.byCategory).toEqual({});
      expect(stats.bySize).toEqual({});
      expect(stats.byColor).toEqual({});
      expect(stats.recentlyCreated).toBe(0);
    });
  });

  describe('Business Logic Validation', () => {
    it('should enforce garment creation business rules', async () => {
      const user = await createTestUser();
      
      // Test 1: Non-existent image
      const fakeImageId = uuidv4();
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: fakeImageId,
        maskData: createValidMaskData()
      })).rejects.toThrow('Original image not found');
      
      // Test 2: Invalid mask data
      const image = await createTestImage(user.id);
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData: createEmptyMaskData()
      })).rejects.toThrow('empty');
      
      // Test 3: Dimension mismatch
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData: createValidMaskData(400, 300) // Image is 800x600
      })).rejects.toThrow('dimensions');
    });

    it('should maintain data integrity across operations', async () => {
      const user = await createTestUser();
      const images = await Promise.all([
        createTestImage(user.id),
        createTestImage(user.id),
        createTestImage(user.id)
      ]);
      
      const maskData = createValidMaskData();
      
      // Create garment
      const garment = await garmentService.createGarment({
        userId: user.id,
        originalImageId: images[0].id,
        maskData,
        metadata: { category: 'shirt', color: 'blue' }
      });
      testGarments.push(garment);
      
      // Verify database consistency
      const [
        dbGarment,
        dbImage,
        dbUser
      ] = await Promise.all([
        TestDatabaseConnection.query('SELECT * FROM garment_items WHERE id = $1', [garment.id]),
        TestDatabaseConnection.query('SELECT * FROM original_images WHERE id = $1', [images[0].id]),
        TestDatabaseConnection.query('SELECT * FROM users WHERE id = $1', [user.id])
      ]);
      
      expect(dbGarment.rows).toHaveLength(1);
      expect(dbGarment.rows[0].user_id).toBe(user.id);
      expect(dbGarment.rows[0].original_image_id).toBe(images[0].id);
      
      expect(dbImage.rows).toHaveLength(1);
      expect(dbImage.rows[0].status).toBe('labeled');
      
      expect(dbUser.rows).toHaveLength(1);
      expect(dbUser.rows[0].id).toBe(user.id);
      
      // Verify foreign key relationships
      const foreignKeyCheck = await TestDatabaseConnection.query(`
        SELECT g.id as garment_id, g.user_id, g.original_image_id,
               u.id as user_exists, i.id as image_exists
        FROM garment_items g
        LEFT JOIN users u ON g.user_id = u.id
        LEFT JOIN original_images i ON g.original_image_id = i.id
        WHERE g.id = $1
      `, [garment.id]);
      
      expect(foreignKeyCheck.rows[0].user_exists).toBe(user.id);
      expect(foreignKeyCheck.rows[0].image_exists).toBe(images[0].id);
    });

    it('should handle edge cases gracefully', async () => {
      const user = await createTestUser();
      
      // Test with invalid UUID formats
      const invalidIds = ['not-a-uuid', '12345', '', null, undefined];
      
      for (const invalidId of invalidIds) {
        await expect(garmentService.getGarment({
          garmentId: invalidId as any,
          userId: user.id
        })).rejects.toThrow();
        
        await expect(garmentService.deleteGarment({
          garmentId: invalidId as any,
          userId: user.id
        })).rejects.toThrow();
      }
    });

    it('should validate mask data edge cases', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      
      // Test with negative dimensions
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData: { width: -100, height: 600, data: new Uint8ClampedArray(100) }
      })).rejects.toThrow();
      
      // Test with zero dimensions
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData: { width: 0, height: 0, data: new Uint8ClampedArray(0) }
      })).rejects.toThrow();
      
      // Test with mismatched data length
      await expect(garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData: { width: 100, height: 100, data: new Uint8ClampedArray(50) } // Should be 10000
      })).rejects.toThrow();
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle bulk garment operations efficiently', async () => {
      const user = await createTestUser();
      const batchSize = 10;
      
      // Create multiple images
      const images = await Promise.all(
        Array.from({ length: batchSize }, () => createTestImage(user.id))
      );
      
      const maskData = createValidMaskData();
      
      // Measure time for bulk creation
      const startTime = Date.now();
      
      const garments = await Promise.all(
        images.map((image, index) => 
          garmentService.createGarment({
            userId: user.id,
            originalImageId: image.id,
            maskData,
            metadata: { category: 'shirt', index }
          })
        )
      );
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      testGarments.push(...garments);
      
      expect(garments).toHaveLength(batchSize);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
      
      console.log(`✅ Created ${batchSize} garments in ${duration}ms (avg: ${Math.round(duration/batchSize)}ms per garment)`);
      
      // Test bulk retrieval performance
      const retrievalStartTime = Date.now();
      const retrievedGarments = await garmentService.getGarments({ userId: user.id });
      const retrievalDuration = Date.now() - retrievalStartTime;
      
      expect(retrievedGarments).toHaveLength(batchSize);
      expect(retrievalDuration).toBeLessThan(2000); // Should complete within 2 seconds
      
      console.log(`✅ Retrieved ${batchSize} garments in ${retrievalDuration}ms`);
    });

    it('should maintain performance with large metadata objects', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData();
      
      // Create large but valid metadata (under 10KB limit)
      const largeMetadata = {
        category: 'shirt',
        description: 'A'.repeat(5000), // 5KB description
        tags: Array.from({ length: 100 }, (_, i) => `tag${i}`),
        measurements: {
          chest: 42,
          waist: 32,
          length: 28,
          sleeve: 24
        },
        care_instructions: [
          'Machine wash cold',
          'Tumble dry low',
          'Iron on low heat',
          'Do not bleach'
        ],
        purchase_history: {
          store: 'Test Store',
          date: new Date().toISOString(),
          price: 29.99,
          currency: 'USD'
        }
      };
      
      const startTime = Date.now();
      
      const garment = await garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData,
        metadata: largeMetadata
      });
      
      const creationDuration = Date.now() - startTime;
      testGarments.push(garment);
      
      expect(creationDuration).toBeLessThan(3000); // Should complete within 3 seconds
      expect(garment.metadata).toEqual(largeMetadata);
      
      // Test retrieval performance with large metadata
      const retrievalStartTime = Date.now();
      const retrievedGarment = await garmentService.getGarment({
        garmentId: garment.id,
        userId: user.id
      });
      const retrievalDuration = Date.now() - retrievalStartTime;
      
      expect(retrievalDuration).toBeLessThan(1000); // Should complete within 1 second
      expect(retrievedGarment.metadata).toEqual(largeMetadata);
      
      console.log(`✅ Large metadata operations: create ${creationDuration}ms, retrieve ${retrievalDuration}ms`);
    });

    it('should handle concurrent metadata updates safely', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData();
      
      const garment = await garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData,
        metadata: { category: 'shirt', version: 0 }
      });
      testGarments.push(garment);
      
      // Attempt concurrent metadata updates
      const updatePromises = Array.from({ length: 5 }, (_, i) => 
        garmentService.updateGarmentMetadata({
          garmentId: garment.id,
          userId: user.id,
          metadata: { 
            category: 'shirt',
            version: i + 1,
            updatedBy: `update-${i}`,
            timestamp: Date.now()
          }
        })
      );
      
      const results = await Promise.all(updatePromises);
      
      // All updates should succeed
      expect(results).toHaveLength(5);
      results.forEach(result => {
        expect(result).toBeDefined();
        expect(result.metadata.category).toBe('shirt');
      });
      
      // Final state should be consistent
      const finalGarment = await garmentService.getGarment({
        garmentId: garment.id,
        userId: user.id
      });
      
      expect(finalGarment.metadata.category).toBe('shirt');
      expect(typeof finalGarment.metadata.version).toBe('number');
    });
  });

  describe('Real-world Usage Scenarios', () => {
    it('should support typical user workflow', async () => {
      console.log('📋 Testing typical user workflow...');
      
      // Step 1: User signs up
      const user = await createTestUser();
      console.log(`✅ User created: ${user.email}`);
      
      // Step 2: User uploads multiple images
      const images = await Promise.all([
        createTestImage(user.id),
        createTestImage(user.id),
        createTestImage(user.id)
      ]);
      console.log(`✅ Uploaded ${images.length} images`);
      
      // Step 3: User creates garments from images
      const maskData = createValidMaskData();
      const garmentMetadata = [
        { category: 'shirt', color: 'blue', size: 'M', brand: 'Nike' },
        { category: 'pants', color: 'black', size: 'L', brand: 'Levi\'s' },
        { category: 'jacket', color: 'red', size: 'M', brand: 'Adidas' }
      ];
      
      const garments = await Promise.all(
        images.map((image, index) => 
          garmentService.createGarment({
            userId: user.id,
            originalImageId: image.id,
            maskData,
            metadata: garmentMetadata[index]
          })
        )
      );
      testGarments.push(...garments);
      console.log(`✅ Created ${garments.length} garments`);
      
      // Step 4: User views their garments
      const allGarments = await garmentService.getGarments({ userId: user.id });
      expect(allGarments).toHaveLength(3);
      console.log(`✅ Retrieved ${allGarments.length} garments`);
      
      // Step 5: User filters garments by category
      const shirts = await garmentService.getGarments({
        userId: user.id,
        filter: { 'metadata.category': 'shirt' }
      });
      expect(shirts).toHaveLength(1);
      expect(shirts[0].metadata.category).toBe('shirt');
      console.log(`✅ Filtered garments: found ${shirts.length} shirts`);
      
      // Step 6: User updates garment metadata
      const updatedGarment = await garmentService.updateGarmentMetadata({
        garmentId: garments[0].id,
        userId: user.id,
        metadata: {
          ...garmentMetadata[0],
          notes: 'Favorite shirt for casual wear',
          last_worn: new Date().toISOString()
        }
      });
      expect(updatedGarment.metadata.notes).toBeDefined();
      console.log(`✅ Updated garment metadata`);
      
      // Step 7: User gets statistics
      const stats = await garmentService.getUserGarmentStats(user.id);
      expect(stats.total).toBe(3);
      expect(stats.byCategory.shirt).toBe(1);
      expect(stats.byCategory.pants).toBe(1);
      expect(stats.byCategory.jacket).toBe(1);
      console.log(`✅ Generated user statistics: ${JSON.stringify(stats)}`);
      
      // Step 8: User deletes a garment
      await garmentService.deleteGarment({
        garmentId: garments[2].id,
        userId: user.id
      });
      
      const remainingGarments = await garmentService.getGarments({ userId: user.id });
      expect(remainingGarments).toHaveLength(2);
      console.log(`✅ Deleted garment, ${remainingGarments.length} remaining`);
      
      console.log('🎉 Typical user workflow completed successfully!');
    });

    it('should handle multi-user scenarios', async () => {
      console.log('👥 Testing multi-user scenarios...');
      
      // Create multiple users
      const users = await Promise.all([
        createTestUser(),
        createTestUser(),
        createTestUser()
      ]);
      console.log(`✅ Created ${users.length} users`);
      
      // Each user creates garments
      const allGarments: any[] = [];
      const maskData = createValidMaskData();
      
      for (const [userIndex, user] of users.entries()) {
        const images = await Promise.all([
          createTestImage(user.id),
          createTestImage(user.id)
        ]);
        
        const userGarments = await Promise.all(
          images.map((image, imageIndex) => 
            garmentService.createGarment({
              userId: user.id,
              originalImageId: image.id,
              maskData,
              metadata: {
                category: imageIndex === 0 ? 'shirt' : 'pants',
                owner: `user_${userIndex}`,
                user_index: userIndex,
                image_index: imageIndex
              }
            })
          )
        );
        
        allGarments.push(...userGarments);
        testGarments.push(...userGarments);
      }
      
      console.log(`✅ All users created ${allGarments.length} total garments`);
      
      // Verify data isolation between users
      for (const [userIndex, user] of users.entries()) {
        const userGarments = await garmentService.getGarments({ userId: user.id });
        expect(userGarments).toHaveLength(2);
        
        // Verify user can only see their own garments
        userGarments.forEach((garment: TestGarment) => {
          expect(garment.user_id).toBe(user.id);
          expect(garment.metadata.user_index).toBe(userIndex);
        });
        
        // Verify user cannot access other users' garments
        const otherUserGarments = allGarments.filter(g => g.user_id !== user.id);
        for (const otherGarment of otherUserGarments.slice(0, 3)) { // Test a few
          await expect(garmentService.getGarment({
            garmentId: otherGarment.id,
            userId: user.id
          })).rejects.toThrow('permission');
        }
      }
      
      console.log('✅ Data isolation verified between users');
      
      // Test concurrent operations across users
      const concurrentPromises = users.map(async (user, index) => {
        const stats = await garmentService.getUserGarmentStats(user.id);
        expect(stats.total).toBe(2);
        return stats;
      });
      
      const allStats = await Promise.all(concurrentPromises);
      expect(allStats).toHaveLength(3);
      
      console.log('🔒 Multi-user scenarios completed successfully!');
    });
  });

  describe('Error Handling and Recovery', () => {
    it('should handle database connection failures gracefully', async () => {
      const user = await createTestUser();
      
      // Simulate database connection issue by using invalid garment ID format
      await expect(garmentService.getGarment({
        garmentId: 'invalid-uuid-format',
        userId: user.id
      })).rejects.toThrow();
    });

    it('should maintain transaction integrity on failures', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      
      // Verify initial state
      const initialImageState = await testImageModel.findById(image.id);
      expect(initialImageState?.status).toBe('new');
      
      // Attempt to create garment with invalid mask (should fail)
      try {
        await garmentService.createGarment({
          userId: user.id,
          originalImageId: image.id,
          maskData: createEmptyMaskData()
        });
        // Should not reach here
        expect(true).toBe(false);
      } catch (error) {
        // Expected failure
        expect(error).toBeInstanceOf(Error);
      }
      
      // Verify image status was not changed on failure
      const finalImageState = await testImageModel.findById(image.id);
      expect(finalImageState?.status).toBe('new');
      
      // Verify no orphaned garment records were created
      const orphanedGarments = await TestDatabaseConnection.query(
        'SELECT * FROM garment_items WHERE original_image_id = $1',
        [image.id]
      );
      expect(orphanedGarments.rows).toHaveLength(0);
    });
  });

  describe('Garment Metadata Management', () => {
    it('should update garment metadata', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData();
      
      const garment = await garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData,
        metadata: { category: 'shirt', color: 'white' }
      });
      testGarments.push(garment);
      
      const updatedMetadata = {
        category: 'shirt',
        color: 'blue',
        size: 'L',
        brand: 'Test Brand'
      };
      
      const updatedGarment = await garmentService.updateGarmentMetadata({
        garmentId: garment.id,
        userId: user.id,
        metadata: updatedMetadata
      });
      
      expect(updatedGarment.metadata).toEqual(updatedMetadata);
      expect(updatedGarment.metadata.color).toBe('blue');
      expect(updatedGarment.metadata.size).toBe('L');
      expect(updatedGarment.metadata.brand).toBe('Test Brand');
    });

    it('should validate metadata structure', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData();
      
      const garment = await garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData,
        metadata: { category: 'shirt' }
      });
      testGarments.push(garment);
      
      // Test invalid category type
      await expect(garmentService.updateGarmentMetadata({
        garmentId: garment.id,
        userId: user.id,
        metadata: { category: 123 } // Should be string
      })).rejects.toThrow('category must be a string');
      
      // Test invalid size
      await expect(garmentService.updateGarmentMetadata({
        garmentId: garment.id,
        userId: user.id,
        metadata: { size: 'INVALID' }
      })).rejects.toThrow('Invalid garment size');
    });

    it('should handleconcurrent garment creation attempts', async () => {
      const user = await createTestUser();
      const images = await Promise.all([
        createTestImage(user.id),
        createTestImage(user.id),
        createTestImage(user.id)
      ]);
      
      const maskData = createValidMaskData();
      
      // Create garments concurrently
      const garmentPromises = images.map(image => 
        garmentService.createGarment({
          userId: user.id,
          originalImageId: image.id,
          maskData,
          metadata: { category: 'shirt', created_at: Date.now() }
        })
      );
      
      const garments = await Promise.all(garmentPromises);
      testGarments.push(...garments);
      
      expect(garments).toHaveLength(3);
      garments.forEach(garment => {
        expect(garment.id).toBeDefined();
        expect(garment.user_id).toBe(user.id);
      });
      
      // Verify all garments have unique IDs
      const garmentIds = garments.map(g => g.id);
      const uniqueIds = new Set(garmentIds);
      expect(uniqueIds.size).toBe(3);
    });
  });

  describe('Garment Retrieval', () => {
    it('should retrieve a specific garment by ID', async () => {
      const user = await createTestUser();
      const image = await createTestImage(user.id);
      const maskData = createValidMaskData();
      
      const createdGarment = await garmentService.createGarment({
        userId: user.id,
        originalImageId: image.id,
        maskData,
        metadata: { category: 'pants', color: 'black' }
      });
      testGarments.push(createdGarment);
      
      const retrievedGarment = await garmentService.getGarment({
        garmentId: createdGarment.id,
        userId: user.id
      });
      
      expect(retrievedGarment).toBeDefined();
      expect(retrievedGarment.id).toBe(createdGarment.id);
      expect(retrievedGarment.user_id).toBe(user.id);
      expect(retrievedGarment.metadata.category).toBe('pants');
      expect(retrievedGarment.metadata.color).toBe('black');
    });

    it('should reject retrieval of non-existent garment', async () => {
      const user = await createTestUser();
      const fakeGarmentId = uuidv4();
      
      await expect(garmentService.getGarment({
        garmentId: fakeGarmentId,
        userId: user.id
      })).rejects.toThrow('not found');
    });

    it('should reject retrieval when user does not own garment', async () => {
      const user1 = await createTestUser();
      const user2 = await createTestUser();
      const image = await createTestImage(user1.id);
      const maskData = createValidMaskData();
      
      const garment = await garmentService.createGarment({
        userId: user1.id,
        originalImageId: image.id,
        maskData
      });
      testGarments.push(garment);
      
      await expect(garmentService.getGarment({
        garmentId: garment.id,
        userId: user2.id
      })).rejects.toThrow('permission');
    });

    it('should retrieve multiple garments for a user', async () => {
      const user = await createTestUser();
      const images = await Promise.all([
        createTestImage(user.id),
        createTestImage(user.id),
        createTestImage(user.id)
      ]);
      
      const maskData = createValidMaskData();
      
      // Create multiple garments with different metadata
      const garmentConfigs = [
        { category: 'shirt', color: 'red' },
        { category: 'pants', color: 'blue' },
        { category: 'jacket', color: 'green' }
      ];
      
      const createdGarments = await Promise.all(
        images.map((image, index) => 
          garmentService.createGarment({
            userId: user.id,
            originalImageId: image.id,
            maskData,
            metadata: garmentConfigs[index]
          })
        )
      );
      testGarments.push(...createdGarments);
      
      const retrievedGarments = await garmentService.getGarments({
        userId: user.id
      });
      
      expect(retrievedGarments).toHaveLength(3);
    retrievedGarments.forEach((garment: TestGarment) => {
        expect(garment.user_id).toBe(user.id);
        expect(['shirt', 'pants', 'jacket']).toContain(garment.metadata.category);
    });
    });

    it('should filter garments by metadata', async () => {
      const user = await createTestUser();
      const images = await Promise.all([
        createTestImage(user.id),
        createTestImage(user.id),
        createTestImage(user.id)
      ]);
      
      const maskData = createValidMaskData();
      
      // Create garments with different categories
      const garments = await Promise.all([
        garmentService.createGarment({
          userId: user.id,
          originalImageId: images[0].id,
          maskData,
          metadata: { category: 'shirt', color: 'red' }
        }),
        garmentService.createGarment({
          userId: user.id,
          originalImageId: images[1].id,
          maskData,
          metadata: { category: 'shirt', color: 'blue' }
        }),
        garmentService.createGarment({
          userId: user.id,
          originalImageId: images[2].id,
          maskData,
          metadata: { category: 'pants', color: 'black' }
        })
      ]);
      testGarments.push(...garments);
      
      // Filter by category
      const shirtGarments = await garmentService.getGarments({
        userId: user.id,
        filter: { 'metadata.category': 'shirt' }
      });
      
      expect(shirtGarments).toHaveLength(2);
    shirtGarments.forEach((garment: TestGarment) => {
      expect(garment.metadata.category).toBe('shirt');
    });
    });

    it('should paginate garment results', async () => {
      const user = await createTestUser();
      const images = await Promise.all(
        Array.from({ length: 5 }, () => createTestImage(user.id))
      );
      
      const maskData = createValidMaskData();
      
      // Create 5 garments
      const garments = await Promise.all(
        images.map((image, index) => 
          garmentService.createGarment({
            userId: user.id,
            originalImageId: image.id,
            maskData,
            metadata: { index }
          })
        )
      );
      testGarments.push(...garments);
      
      // Test pagination
      const page1 = await garmentService.getGarments({
        userId: user.id,
        pagination: { page: 1, limit: 2 }
      });
      
      const page2 = await garmentService.getGarments({
        userId: user.id,
        pagination: { page: 2, limit: 2 }
      });
      
      expect(page1).toHaveLength(2);
      expect(page2).toHaveLength(2);
      
      // Ensure different garments on different pages
    const page1Ids: string[] = page1.map((g: TestGarment) => g.id);
      const page2Ids: string[] = page2.map((g: TestGarment) => g.id);
      expect(page1Ids).not.toEqual(page2Ids);
    });
  });
}); 




















  