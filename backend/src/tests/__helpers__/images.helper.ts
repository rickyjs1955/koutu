// tests/__helpers__/images.helper.ts
import { Buffer } from 'buffer';
import { v4 as uuidv4 } from 'uuid';
import { createMockImage, MockImage, MockImageUpload } from '../__mocks__/images.mock';

// Note: Sharp is optional for Jest tests - using fallback implementations
let sharp: any;
try {
  sharp = require('sharp');
} catch (e) {
  // Sharp not available in test environment, use fallbacks
  sharp = null;
}

// ==================== IMAGE GENERATION HELPERS ====================

/**
 * Generate a valid JPEG buffer for testing
 * This creates an actual image buffer that will pass Sharp validation
 */
export const generateValidImageBuffer = async (
  width: number = 800,
  height: number = 600,
  format: 'jpeg' | 'png' | 'bmp' = 'jpeg'
): Promise<Buffer> => {
  if (sharp) {
    try {
      // Create a solid color image
      const channels = format === 'png' ? 4 : 3; // PNG with alpha, JPEG/BMP without
      const pixelData = Buffer.alloc(width * height * channels, 128); // Gray color
      
      let image = sharp(pixelData, {
        raw: {
          width,
          height,
          channels
        }
      });
      
      switch (format) {
        case 'jpeg':
          return await image.jpeg({ quality: 80 }).toBuffer();
        case 'png':
          return await image.png().toBuffer();
        case 'bmp':
          // Convert to BMP via intermediate PNG (Sharp limitation)
          const pngBuffer = await image.png().toBuffer();
          return pngBuffer; // In real tests, you might use a different library for BMP
        default:
          return await image.jpeg().toBuffer();
      }
    } catch (error) {
      // Fallback: create a minimal valid JPEG header
      return createMinimalJpegBuffer();
    }
  } else {
    // Fallback when Sharp is not available
    return createMinimalJpegBuffer();
  }
};

/**
 * Create a minimal valid JPEG buffer for testing
 */
export const createMinimalJpegBuffer = (): Buffer => {
  // Minimal JPEG file with SOI and EOI markers
  return Buffer.from([
    0xFF, 0xD8, // SOI (Start of Image)
    0xFF, 0xE0, // APP0 marker
    0x00, 0x10, // Length
    0x4A, 0x46, 0x49, 0x46, 0x00, // "JFIF\0"
    0x01, 0x01, // Version
    0x01, 0x00, 0x01, 0x00, 0x01, // Density info
    0x00, 0x00, // Thumbnail size
    0xFF, 0xD9  // EOI (End of Image)
  ]);
};

/**
 * Create invalid image buffer for testing validation
 */
export const createInvalidImageBuffer = (type: 'empty' | 'corrupted' | 'wrong_format' = 'corrupted'): Buffer => {
  switch (type) {
    case 'empty':
      return Buffer.alloc(0);
    case 'wrong_format':
      return Buffer.from('This is not an image file');
    case 'corrupted':
    default:
      return Buffer.from([0xFF, 0xD8, 0x00, 0x00]); // Truncated JPEG
  }
};

// ==================== INSTAGRAM MOCK HELPERS ====================

/**
 * Generate realistic Instagram media URLs
 */
export const generateInstagramMediaUrl = (mediaId?: string): string => {
  const id = mediaId || Math.random().toString(36).substring(2, 15);
  return `https://scontent.cdninstagram.com/v/t51.2885-15/${id}_n.jpg?stp=dst-jpg_e35&_nc_ht=scontent.cdninstagram.com&_nc_cat=1&_nc_ohc=abc123&edm=APs17CUBAAAA&ccb=7-5&oh=abc123&oe=ABC123&_nc_sid=10d13b`;
};

/**
 * Generate Instagram user data
 */
export const generateInstagramUser = (overrides: Partial<any> = {}) => ({
  id: Math.random().toString(36).substring(2, 19),
  username: `testuser_${Math.random().toString(36).substring(2, 8)}`,
  account_type: 'PERSONAL',
  media_count: Math.floor(Math.random() * 1000),
  ...overrides
});

/**
 * Generate Instagram media data
 */
export const generateInstagramMedia = (count: number = 1, overrides: Partial<any> = {}) => {
  return Array.from({ length: count }, (_, index) => ({
    id: Math.random().toString(36).substring(2, 19),
    media_type: 'IMAGE',
    media_url: generateInstagramMediaUrl(),
    thumbnail_url: generateInstagramMediaUrl(),
    caption: `Test post ${index + 1}`,
    timestamp: new Date(Date.now() - index * 86400000).toISOString(), // Spread over days
    ...overrides
  }));
};

// ==================== DATABASE TEST HELPERS ====================

/**
 * Create test image records for database operations
 */
export const createTestImageRecords = (count: number = 3, userId?: string): MockImage[] => {
  const testUserId = userId || uuidv4();
  return Array.from({ length: count }, (_, index) => createMockImage({
    user_id: testUserId,
    file_path: `uploads/test-image-${index + 1}.jpg`,
    status: index === 0 ? 'new' : index === 1 ? 'processed' : 'labeled',
    original_metadata: {
      width: 800 + (index * 100),
      height: 600 + (index * 75),
      format: index % 2 === 0 ? 'jpeg' : 'png',
      size: 204800 + (index * 50000),
      filename: `test-image-${index + 1}.jpg`
    }
  }));
};

/**
 * Create image statistics data for testing
 */
export const createMockImageStats = (overrides: Partial<any> = {}) => ({
  total: 10,
  byStatus: {
    new: 3,
    processed: 4,
    labeled: 3
  },
  totalSize: 2048000, // 2MB
  averageSize: 204800, // 200KB
  storageUsedMB: 1.95,
  averageSizeMB: 0.2,
  storageLimit: {
    maxImages: 1000,
    maxStorageMB: 500,
    maxFileSizeMB: 8,
    supportedFormats: ['JPEG', 'PNG', 'BMP'],
    aspectRatioRange: '4:5 to 1.91:1',
    resolutionRange: '320px to 1440px width'
  },
  ...overrides
});

// ==================== FILE UPLOAD HELPERS ====================

/**
 * Create realistic file upload data
 */
export const createRealisticImageUpload = async (
  options: {
    filename?: string;
    format?: 'jpeg' | 'png' | 'bmp';
    width?: number;
    height?: number;
    sizeKB?: number;
  } = {}
): Promise<MockImageUpload> => {
  const {
    filename = 'test-photo.jpg',
    format = 'jpeg',
    width = 800,
    height = 600,
    sizeKB = 200
  } = options;
  
  const buffer = await generateValidImageBuffer(width, height, format);
  const mimeType = format === 'jpeg' ? 'image/jpeg' : `image/${format}`;
  
  return {
    fieldname: 'image',
    originalname: filename,
    encoding: '7bit',
    mimetype: mimeType,
    size: sizeKB * 1024,
    buffer
  };
};

/**
 * Create Instagram-compatible image uploads
 */
export const createInstagramCompatibleUploads = async () => {
  return {
    square: await createRealisticImageUpload({
      filename: 'square-photo.jpg',
      width: 1080,
      height: 1080
    }),
    portrait: await createRealisticImageUpload({
      filename: 'portrait-photo.jpg',
      width: 1080,
      height: 1350
    }),
    landscape: await createRealisticImageUpload({
      filename: 'landscape-photo.jpg',
      width: 1080,
      height: 566
    }),
    minSize: await createRealisticImageUpload({
      filename: 'min-size.jpg',
      width: 320,
      height: 400
    }),
    maxSize: await createRealisticImageUpload({
      filename: 'max-size.jpg',
      width: 1440,
      height: 754
    })
  };
};

// ==================== VALIDATION HELPERS ====================

/**
 * Instagram aspect ratio validation
 */
export const validateInstagramAspectRatio = (width: number, height: number): boolean => {
  const aspectRatio = width / height;
  return aspectRatio >= 0.8 && aspectRatio <= 1.91;
};

/**
 * Instagram dimension validation
 */
export const validateInstagramDimensions = (width: number, height: number): boolean => {
  return width >= 320 && width <= 1440 && height >= 168 && height <= 1800;
};

/**
 * Create invalid uploads for testing edge cases
 */
export const createInvalidUploads = () => ({
  tooSmall: {
    fieldname: 'image',
    originalname: 'too-small.jpg',
    encoding: '7bit',
    mimetype: 'image/jpeg',
    size: 500, // < 1KB
    buffer: Buffer.alloc(500)
  },
  tooLarge: {
    fieldname: 'image',
    originalname: 'too-large.jpg',
    encoding: '7bit',
    mimetype: 'image/jpeg',
    size: 10 * 1024 * 1024, // 10MB
    buffer: Buffer.alloc(10 * 1024 * 1024)
  },
  wrongType: {
    fieldname: 'image',
    originalname: 'document.pdf',
    encoding: '7bit',
    mimetype: 'application/pdf',
    size: 204800,
    buffer: Buffer.from('%PDF-1.4')
  },
  pathTraversal: {
    fieldname: 'image',
    originalname: '../../../etc/passwd.jpg',
    encoding: '7bit',
    mimetype: 'image/jpeg',
    size: 204800,
    buffer: createMinimalJpegBuffer()
  }
});

// ==================== ERROR SIMULATION HELPERS ====================

/**
 * Simulate various error conditions
 */
export const simulateErrors = {
  networkTimeout: () => {
    const error = new Error('Request timeout');
    (error as any).code = 'ETIMEDOUT';
    return error;
  },
  
  databaseConnection: () => {
    const error = new Error('Connection terminated');
    (error as any).code = 'ECONNRESET';
    return error;
  },
  
  diskSpace: () => {
    const error = new Error('No space left on device');
    (error as any).code = 'ENOSPC';
    return error;
  },
  
  instagramRateLimit: () => {
    const error = new Error('Rate limit exceeded');
    (error as any).status = 429;
    (error as any).headers = {
      'x-ratelimit-remaining': '0',
      'retry-after': '3600'
    };
    return error;
  },
  
  instagramAuthExpired: () => {
    const error = new Error('Token expired');
    (error as any).status = 401;
    (error as any).code = 'INSTAGRAM_AUTH_EXPIRED';
    return error;
  }
};

// ==================== PERFORMANCE TESTING HELPERS ====================

/**
 * Generate large datasets for performance testing
 */
export const generateLargeDataset = (size: number) => ({
  images: createTestImageRecords(size),
  uploads: Array.from({ length: size }, (_, index) => ({
    fieldname: 'image',
    originalname: `bulk-image-${index + 1}.jpg`,
    encoding: '7bit',
    mimetype: 'image/jpeg',
    size: 204800,
    buffer: createMinimalJpegBuffer()
  })),
  instagramMedia: generateInstagramMedia(size)
});

/**
 * Measure operation performance
 */
export const measurePerformance = async <T>(
  operation: () => Promise<T>,
  label: string = 'Operation'
): Promise<{ result: T; duration: number }> => {
  const start = performance.now();
  const result = await operation();
  const duration = performance.now() - start;
  
  console.log(`${label} took ${duration.toFixed(2)}ms`);
  return { result, duration };
};

// ==================== CONCURRENCY TESTING HELPERS ====================

/**
 * Run concurrent operations for testing race conditions
 */
export const runConcurrentOperations = async <T>(
  operations: (() => Promise<T>)[],
  maxConcurrency: number = 10
): Promise<{ results: T[]; errors: Error[] }> => {
  const results: T[] = [];
  const errors: Error[] = [];
  
  // Process operations in batches
  for (let i = 0; i < operations.length; i += maxConcurrency) {
    const batch = operations.slice(i, i + maxConcurrency);
    const promises = batch.map(async (op, index) => {
      try {
        const result = await op();
        results[i + index] = result;
      } catch (error) {
        errors.push(error as Error);
      }
    });
    
    await Promise.allSettled(promises);
  }
  
  return { results, errors };
};

/**
 * Simulate concurrent image uploads
 */
export const simulateConcurrentUploads = async (
  count: number,
  userId: string,
  uploadFunction: (upload: MockImageUpload, userId: string) => Promise<any>
) => {
  const uploads = Array.from({ length: count }, (_, index) => ({
    fieldname: 'image',
    originalname: `concurrent-${index + 1}.jpg`,
    encoding: '7bit',
    mimetype: 'image/jpeg',
    size: 204800,
    buffer: createMinimalJpegBuffer()
  }));
  
  const operations = uploads.map(upload => () => uploadFunction(upload, userId));
  return runConcurrentOperations(operations);
};

// ==================== SECURITY TESTING HELPERS ====================

/**
 * Generate malicious payloads for security testing
 */
export const createMaliciousPayloads = () => ({
  sqlInjection: {
    filename: "'; DROP TABLE images; --",
    metadata: {
      description: "'; DELETE FROM users WHERE '1'='1"
    }
  },
  
  xssAttempts: {
    filename: '<script>alert("XSS")</script>.jpg',
    metadata: {
      description: '<img src="x" onerror="alert(\'XSS\')">'
    }
  },
  
  pathTraversal: {
    filename: '../../../etc/passwd',
    filePath: '../../../../etc/passwd'
  },
  
  oversizedData: {
    filename: 'a'.repeat(1000),
    metadata: {
      description: 'x'.repeat(10000)
    }
  },
  
  nullBytes: {
    filename: 'image\x00.jpg.exe',
    metadata: {
      description: 'Safe description\x00<script>alert("XSS")</script>'
    }
  },
  
  unicodeAttacks: {
    filename: 'image\u202E.gpj.exe', // Right-to-Left Override
    metadata: {
      description: 'Normal text\u202Eexe.gpj'
    }
  }
});

/**
 * Test authorization bypass attempts
 */
export const createAuthorizationBypassAttempts = () => {
  const validUserId = uuidv4();
  const attackerUserId = uuidv4();
  
  return {
    validUserId,
    attackerUserId,
    
    // Attempt to access another user's image
    crossUserAccess: {
      imageId: uuidv4(),
      ownerId: validUserId,
      attackerId: attackerUserId
    },
    
    // Attempt to modify another user's image
    crossUserModification: {
      imageId: uuidv4(),
      originalOwner: validUserId,
      attacker: attackerUserId,
      maliciousUpdate: {
        status: 'labeled',
        metadata: { hacked: true }
      }
    },
    
    // Parameter pollution attacks
    parameterPollution: {
      multipleIds: [uuidv4(), uuidv4()],
      conflictingData: {
        userId: [validUserId, attackerUserId],
        imageId: [uuidv4(), uuidv4()]
      }
    }
  };
};

// ==================== INSTAGRAM TESTING HELPERS ====================

/**
 * Create Instagram API response scenarios
 */
export const createInstagramScenarios = () => ({
  success: {
    tokenResponse: {
      access_token: 'valid_token_12345',
      token_type: 'bearer',
      expires_in: 3600
    },
    userResponse: generateInstagramUser(),
    mediaResponse: {
      data: generateInstagramMedia(5),
      paging: {
        cursors: {
          before: 'cursor_before',
          after: 'cursor_after'
        }
      }
    }
  },
  
  errors: {
    authExpired: {
      error: {
        code: 190,
        message: 'Error validating access token',
        type: 'OAuthException'
      }
    },
    rateLimit: {
      error: {
        code: 4,
        message: 'Application request limit reached',
        type: 'OAuthException'
      }
    },
    userNotFound: {
      error: {
        code: 100,
        message: 'User not found',
        type: 'GraphMethodException'
      }
    }
  },
  
  edgeCases: {
    emptyMedia: {
      data: [],
      paging: {}
    },
    privateAccount: {
      error: {
        code: 10,
        message: 'Permission denied',
        type: 'OAuthException'
      }
    },
    deletedMedia: {
      data: [{
        id: 'deleted_media_id',
        media_type: 'IMAGE',
        media_url: null // Deleted media
      }]
    }
  }
});

// ==================== TEST DATA CLEANUP HELPERS ====================

/**
 * Clean up test files and data
 */
export const cleanupTestData = {
  /**
   * Remove test image files
   */
  async removeTestFiles(filePaths: string[]): Promise<void> {
    // In Jest environment, we might not have fs/promises available
    try {
      const fs = require('fs').promises;
      const path = require('path');
      
      await Promise.allSettled(
        filePaths.map(async (filePath) => {
          try {
            const fullPath = path.resolve(filePath);
            await fs.unlink(fullPath);
          } catch (error) {
            // Ignore file not found errors
            if ((error as any).code !== 'ENOENT') {
              console.warn(`Failed to delete test file ${filePath}:`, error);
            }
          }
        })
      );
    } catch (error) {
      // fs not available in test environment
      console.log(`Would remove test files: ${filePaths.join(', ')}`);
    }
  },
  
  /**
   * Clear test database records
   */
  async clearTestImages(testUserIds: string[]): Promise<void> {
    // This would integrate with your test database cleanup
    console.log(`Would clear images for test users: ${testUserIds.join(', ')}`);
  },
  
  /**
   * Reset Instagram API mocks
   */
  resetInstagramMocks(): void {
    // Reset any persistent mock state
    delete (global as any).fetch;
    delete (global as any).__INSTAGRAM_MOCK_STATE__;
  }
};

// ==================== ASSERTION HELPERS ====================

/**
 * Custom assertions for image testing
 */
export const imageAssertions = {
  /**
   * Assert image has valid metadata
   */
  hasValidMetadata(image: MockImage): void {
    expect(image.original_metadata).toBeDefined();
    expect(image.original_metadata.width).toBeGreaterThan(0);
    expect(image.original_metadata.height).toBeGreaterThan(0);
    expect(image.original_metadata.format).toMatch(/^(jpeg|png|bmp)$/);
  },
  
  /**
   * Assert image is Instagram compatible
   */
  isInstagramCompatible(metadata: any): void {
    const { width, height } = metadata;
    const aspectRatio = width / height;
    
    expect(width).toBeGreaterThanOrEqual(320);
    expect(width).toBeLessThanOrEqual(1440);
    expect(aspectRatio).toBeGreaterThanOrEqual(0.8);
    expect(aspectRatio).toBeLessThanOrEqual(1.91);
  },
  
  /**
   * Assert proper error structure
   */
  hasValidErrorStructure(error: any): void {
    expect(error).toHaveProperty('message');
    expect(error).toHaveProperty('statusCode');
    expect(error).toHaveProperty('code');
    expect(typeof error.message).toBe('string');
    expect(typeof error.statusCode).toBe('number');
    expect(typeof error.code).toBe('string');
  },
  
  /**
   * Assert file upload structure
   */
  hasValidUploadStructure(upload: MockImageUpload): void {
    expect(upload).toHaveProperty('fieldname');
    expect(upload).toHaveProperty('originalname');
    expect(upload).toHaveProperty('mimetype');
    expect(upload).toHaveProperty('size');
    expect(upload).toHaveProperty('buffer');
    expect(Buffer.isBuffer(upload.buffer)).toBe(true);
  }
};

// ==================== EXPORT ALL HELPERS ====================

export default {
  // Image generation
  generateValidImageBuffer,
  createMinimalJpegBuffer,
  createInvalidImageBuffer,
  
  // Instagram helpers
  generateInstagramMediaUrl,
  generateInstagramUser,
  generateInstagramMedia,
  createInstagramScenarios,
  
  // Database helpers
  createTestImageRecords,
  createMockImageStats,
  
  // File upload helpers
  createRealisticImageUpload,
  createInstagramCompatibleUploads,
  createInvalidUploads,
  
  // Validation helpers
  validateInstagramAspectRatio,
  validateInstagramDimensions,
  
  // Error simulation
  simulateErrors,
  
  // Performance testing
  generateLargeDataset,
  measurePerformance,
  runConcurrentOperations,
  simulateConcurrentUploads,
  
  // Security testing
  createMaliciousPayloads,
  createAuthorizationBypassAttempts,
  
  // Cleanup
  cleanupTestData,
  
  // Assertions
  imageAssertions
};