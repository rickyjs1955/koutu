// tests/__helpers__/images.helper.ts
import { Buffer } from 'buffer';
import { v4 as uuidv4 } from 'uuid';
import { createCorruptedImageBuffer, createImageMetadataVariations, createImageProcessingErrors, createMockImage, createValidImageBuffers, MockImage, MockImageUpload } from '../__mocks__/images.mock';

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
 * Creates a valid test image buffer using Sharp
 * This ensures the image is properly formatted and not corrupted
 */
export async function createTestImageBuffer(
  width: number, 
  height: number, 
  format: 'jpeg' | 'png' = 'jpeg'
): Promise<Buffer> {
  try {
    // Create a simple but valid image with Sharp
    const image = sharp({
      create: {
        width,
        height,
        channels: 3,
        background: { r: 255, g: 128, b: 0 } // Orange background
      }
    });

    // Create a simple pattern to make it more realistic
    const svgPattern = `
      <svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
        <rect width="${width}" height="${height}" fill="rgb(255,128,0)"/>
        <circle cx="${width/2}" cy="${height/2}" r="${Math.min(width, height)/6}" fill="rgb(0,128,255)"/>
        <text x="${width/2}" y="${height/2}" text-anchor="middle" dominant-baseline="middle" fill="white" font-size="${Math.max(12, Math.min(width, height)/20)}">TEST</text>
      </svg>
    `;

    const overlayBuffer = Buffer.from(svgPattern);

    if (format === 'jpeg') {
      return await image
        .composite([{ input: overlayBuffer, blend: 'over' }])
        .jpeg({ 
          quality: 80,
          progressive: true
        })
        .toBuffer();
    } else {
      return await image
        .composite([{ input: overlayBuffer, blend: 'over' }])
        .png({ 
          compressionLevel: 6,
          progressive: true
        })
        .toBuffer();
    }
  } catch (error) {
    console.warn('Error creating test image with overlay, creating simple image:', error);
    
    // Fallback: create a simple solid color image without overlay
    const fallbackImage = sharp({
      create: {
        width,
        height,
        channels: 3,
        background: { r: 255, g: 0, b: 0 } // Red background
      }
    });

    if (format === 'jpeg') {
      return await fallbackImage.jpeg({ quality: 80 }).toBuffer();
    } else {
      return await fallbackImage.png({ compressionLevel: 6 }).toBuffer();
    }
  }
}

/**
 * Validates that a buffer is a valid image
 */
export async function validateImageBuffer(buffer: Buffer): Promise<boolean> {
  try {
    const metadata = await sharp(buffer).metadata();
    return !!(metadata.width && metadata.height && metadata.format);
  } catch {
    return false;
  }
}

/**
 * Get image metadata from buffer
 */
export async function getImageMetadata(buffer: Buffer) {
  try {
    return await sharp(buffer).metadata();
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to get image metadata: ${error.message}`);
    }
    throw new Error(`Failed to get image metadata: Unknown error`);
  }
}

/**
 * Test image factory with predefined image types
 */
export class TestImageFactory {
  static async createSmallImage(): Promise<Buffer> {
    return createTestImageBuffer(100, 100, 'jpeg');
  }

  static async createLargeImage(): Promise<Buffer> {
    return createTestImageBuffer(2000, 2000, 'jpeg');
  }

  static async createInstagramSquare(): Promise<Buffer> {
    return createTestImageBuffer(1080, 1080, 'jpeg');
  }

  static async createInstagramPortrait(): Promise<Buffer> {
    return createTestImageBuffer(1080, 1350, 'jpeg');
  }

  static async createInstagramLandscape(): Promise<Buffer> {
    return createTestImageBuffer(1080, 566, 'jpeg');
  }

  static async createMinimumValidSize(): Promise<Buffer> {
    return createTestImageBuffer(320, 320, 'jpeg');
  }

  static async createBelowMinimumSize(): Promise<Buffer> {
    return createTestImageBuffer(200, 200, 'jpeg');
  }

  static async createPngImage(width = 800, height = 600): Promise<Buffer> {
    return createTestImageBuffer(width, height, 'png');
  }

  static async createJpegImage(width = 800, height = 600): Promise<Buffer> {
    return createTestImageBuffer(width, height, 'jpeg');
  }

  static async createValidUploadImage(): Promise<{ 
    buffer: Buffer, 
    mimetype: string, 
    filename: string 
  }> {
    const buffer = await createTestImageBuffer(800, 600, 'jpeg');
    return {
      buffer,
      mimetype: 'image/jpeg',
      filename: `test-image-${Date.now()}.jpg`
    };
  }
}

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

// ==================== IMAGE PROCESSING SERVICE TEST HELPERS ====================

/**
 * Create mock file paths for testing
 */
export const createMockFilePaths = () => ({
  input: 'uploads/input-image.jpg',
  output: 'uploads/processed-image.jpg',
  thumbnail: 'uploads/thumbnail.jpg',
  srgb: 'uploads/image_srgb.jpg',
  resized: 'uploads/image_800x600.jpg',
  optimized: 'uploads/image_optimized.jpg',
  absolute: '/absolute/path/uploads/input-image.jpg'
});

/**
 * Test all image processing service methods with various scenarios
 */
export const createImageProcessingTestScenarios = () => ({
  validateImageBuffer: {
    validInputs: [
      { buffer: createValidImageBuffers.jpeg(), expectedFormat: 'jpeg' },
      { buffer: createValidImageBuffers.png(), expectedFormat: 'png' },
      { buffer: createValidImageBuffers.bmp(), expectedFormat: 'bmp' }
    ],
    
    invalidInputs: [
      { buffer: createCorruptedImageBuffer(), errorType: 'corrupted' },
      { buffer: Buffer.alloc(0), errorType: 'empty' },
      { buffer: Buffer.from('not an image'), errorType: 'invalid_format' }
    ],
    
    dimensionErrors: [
      { metadata: createImageMetadataVariations.tooSmall, errorType: 'too_small' },
      { metadata: createImageMetadataVariations.tooLarge, errorType: 'too_large' },
      { metadata: createImageMetadataVariations.invalidAspectRatio, errorType: 'invalid_ratio' }
    ]
  },
  
  convertToSRGB: {
    alreadySRGB: { space: 'srgb', shouldConvert: false },
    needsConversion: { space: 'cmyk', shouldConvert: true },
    unknownSpace: { space: undefined, shouldConvert: true }
  },
  
  resizeImage: {
    validResizes: [
      { width: 400, height: 400, fit: 'contain' },
      { width: 800, height: 600, fit: 'cover' },
      { width: 1200, height: 800, fit: 'fill' }
    ],
    edgeCases: [
      { width: 50, height: 50, fit: 'contain' }, // Very small
      { width: 2000, height: 2000, fit: 'contain' }, // Large
      { width: 800, height: 600, fit: 'inside' } // withoutEnlargement test
    ]
  }
});

/**
 * Mock Sharp with specific behaviors for testing
 */
export const setupSharpMockForScenario = (scenario: string) => {
  const { mockSharpInstance } = require('../__mocks__/images.mock');
  
  switch (scenario) {
    case 'metadata_error':
      mockSharpInstance.metadata.mockRejectedValue(createImageProcessingErrors.sharpMetadataError());
      break;
      
    case 'processing_error':
      mockSharpInstance.toFile.mockRejectedValue(createImageProcessingErrors.sharpProcessingError());
      break;
      
    case 'already_srgb':
      mockSharpInstance.metadata.mockResolvedValue({
        ...createImageMetadataVariations.valid,
        space: 'srgb'
      });
      break;
      
    case 'needs_conversion':
      mockSharpInstance.metadata.mockResolvedValue({
        ...createImageMetadataVariations.valid,
        space: 'cmyk'
      });
      break;
      
    case 'invalid_dimensions':
      mockSharpInstance.metadata.mockResolvedValue(createImageMetadataVariations.noDimensions);
      break;
      
    case 'unsupported_format':
      mockSharpInstance.metadata.mockResolvedValue(createImageMetadataVariations.unsupportedFormat);
      break;
      
    default:
      // Reset to default behavior
      mockSharpInstance.metadata.mockResolvedValue(createImageMetadataVariations.valid);
      mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });
  }
};

/**
 * Validate image processing service error handling
 */
export const validateImageProcessingError = (error: any, expectedType: string) => {
  expect(error).toBeInstanceOf(Error);
  expect(error.message).toContain('Invalid image');
  
  switch (expectedType) {
    case 'format':
      expect(error.message).toMatch(/format|determine image format/i);
      break;
    case 'dimensions':
      expect(error.message).toMatch(/dimensions|width|height/i);
      break;
    case 'aspect_ratio':
      expect(error.message).toMatch(/aspect ratio|between/i);
      break;
    case 'size_limit':
      expect(error.message).toMatch(/too small|too large|minimum|maximum/i);
      break;
  }
};

/**
 * Test file system operations with various error conditions
 */
export const createFileSystemTestScenarios = () => ({
  fileNotFound: {
    error: createImageProcessingErrors.fileSystemError(),
    expectedBehavior: 'should handle missing input files gracefully'
  },
  
  noSpace: {
    error: createImageProcessingErrors.diskSpaceError(),
    expectedBehavior: 'should handle disk space errors'
  },
  
  permission: {
    error: createImageProcessingErrors.permissionError(),
    expectedBehavior: 'should handle permission errors'
  }
});

// ==================== SECURITY TEST HELPERS ====================

/**
 * Generate various types of malicious payloads for security testing
 */
export const createSecurityTestPayloads = () => ({
  sqlInjection: {
    basic: "'; DROP TABLE images; --",
    union: "' UNION SELECT * FROM users WHERE '1'='1",
    blind: "' AND (SELECT COUNT(*) FROM images) > 0 --",
    timeBase: "'; WAITFOR DELAY '00:00:05' --"
  },
  
  xssPayloads: {
    script: '<script>alert("XSS")</script>',
    img: '<img src="x" onerror="alert(\'XSS\')">',
    iframe: '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    svg: '<svg onload="alert(\'XSS\')">',
    event: 'javascript:alert("XSS")',
    encoded: '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E'
  },
  
  pathTraversal: {
    unix: '../../../etc/passwd',
    windows: '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    encoded: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    null: '../../../etc/passwd\x00.jpg',
    unicode: '\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd'
  },
  
  commandInjection: {
    basic: '; rm -rf /',
    pipe: '| cat /etc/passwd',
    background: '& ping google.com',
    subshell: '$(cat /etc/passwd)',
    backtick: '`whoami`'
  },
  
  bufferOverflow: {
    long: 'A'.repeat(10000),
    nullBytes: 'test\x00\x00\x00\x00',
    controlChars: '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f',
    unicode: '\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007'
  }
});

/**
 * Generate edge case inputs for boundary testing
 */
export const createBoundaryTestCases = () => ({
  emptyValues: {
    emptyString: '',
    nullValue: null,
    undefinedValue: undefined,
    whitespace: '   ',
    newlines: '\n\r\t'
  },
  
  extremeNumbers: {
    zero: 0,
    negative: -1,
    maxInt: Number.MAX_SAFE_INTEGER,
    minInt: Number.MIN_SAFE_INTEGER,
    infinity: Infinity,
    negativeInfinity: -Infinity,
    nan: NaN
  },
  
  extremeStrings: {
    veryLong: 'x'.repeat(100000),
    unicodeMax: '\uFFFF'.repeat(1000),
    mixedEncoding: 'test\u0000\u001F\u007F\u0080\u00FF',
    rtlOverride: 'file\u202Eexe.jpg', // Right-to-Left Override
    bidiOverride: 'safe\u202Ddangerous\u202C.jpg'
  },
  
  fileSystemLimits: {
    maxPathLength: '/'.repeat(4096),
    reservedNames: ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1'],
    invalidChars: '<>:"|?*\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
  }
});

/**
 * Generate authorization bypass test scenarios
 */
export const createAuthorizationBypassScenarios = () => {
  const legitimateUserId = uuidv4();
  const attackerUserId = uuidv4();
  const adminUserId = uuidv4();
  
  return {
    legitimateUserId,
    attackerUserId,
    adminUserId,
    
    // Horizontal privilege escalation attempts
    horizontalEscalation: {
      imageId: uuidv4(),
      ownerId: legitimateUserId,
      attackerId: attackerUserId,
      scenarios: [
        'direct_access_attempt',
        'parameter_manipulation',
        'session_hijacking_simulation',
        'token_reuse_attempt'
      ]
    },
    
    // Vertical privilege escalation attempts
    verticalEscalation: {
      regularUserId: legitimateUserId,
      adminUserId: adminUserId,
      attempts: [
        'admin_endpoint_access',
        'bulk_operation_abuse',
        'system_resource_access'
      ]
    },
    
    // Race condition exploitation
    raceConditions: {
      targetImageId: uuidv4(),
      ownerId: legitimateUserId,
      attackerId: attackerUserId,
      scenarios: [
        'concurrent_access_during_transfer',
        'status_change_race',
        'deletion_race_condition'
      ]
    },
    
    // IDOR (Insecure Direct Object Reference) tests
    idorTests: [
      { imageId: '1', description: 'Sequential ID guessing' },
      { imageId: uuidv4(), description: 'Valid UUID format' },
      { imageId: 'admin-image-123', description: 'Predictable admin naming' },
      { imageId: '../system/config', description: 'Path traversal in ID' }
    ]
  };
};

/**
 * Generate file upload attack vectors
 */
export const createFileUploadAttackVectors = () => ({
  maliciousExtensions: [
    'test.php.jpg',
    'test.jsp.png',
    'test.asp.bmp',
    'test.exe',
    'test.bat',
    'test.sh',
    'test.py',
    'test.js'
  ],
  
  mimeTypeSpoofing: [
    { filename: 'script.php', declaredMime: 'image/jpeg', actualContent: '<?php system($_GET["cmd"]); ?>' },
    { filename: 'payload.exe', declaredMime: 'image/png', actualContent: 'MZ\x90\x00\x03\x00\x00\x00' },
    { filename: 'shell.jsp', declaredMime: 'image/bmp', actualContent: '<%@ page import="java.io.*" %>' }
  ],
  
  polyglotFiles: [
    {
      name: 'jpeg_gif_polyglot.jpg',
      description: 'Valid JPEG and GIF',
      headers: [
        Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]), // JPEG
        Buffer.from('GIF89a') // GIF
      ]
    },
    {
      name: 'png_zip_polyglot.png',
      description: 'Valid PNG and ZIP',
      headers: [
        Buffer.from([0x89, 0x50, 0x4E, 0x47]), // PNG
        Buffer.from('PK\x03\x04') // ZIP
      ]
    }
  ],
  
  zipBombs: {
    small: {
      compressedSize: 1024,
      uncompressedSize: 1024 * 1024 * 100, // 100MB when decompressed
      description: 'Small zip bomb'
    },
    large: {
      compressedSize: 1024 * 10,
      uncompressedSize: 1024 * 1024 * 1024 * 10, // 10GB when decompressed
      description: 'Large zip bomb'
    }
  },
  
  metadataExploits: [
    {
      type: 'exif_xss',
      description: 'XSS in EXIF comment',
      payload: '<script>alert("XSS in EXIF")</script>'
    },
    {
      type: 'exif_sqli',
      description: 'SQL injection in EXIF data',
      payload: "'; DROP TABLE images; --"
    },
    {
      type: 'oversized_metadata',
      description: 'Extremely large metadata',
      payload: 'x'.repeat(1024 * 1024) // 1MB of metadata
    }
  ]
});

/**
 * Generate denial of service attack scenarios
 */
export const createDoSAttackScenarios = () => ({
  resourceExhaustion: {
    largeFiles: Array.from({ length: 100 }, (_, i) => ({
      filename: `large_file_${i}.jpg`,
      size: 8 * 1024 * 1024, // 8MB each
      description: 'Multiple large file uploads'
    })),
    
    complexImages: Array.from({ length: 50 }, (_, i) => ({
      filename: `complex_${i}.jpg`,
      width: 5000,
      height: 5000,
      description: 'High resolution images requiring significant processing'
    })),
    
    rapidRequests: {
      count: 1000,
      timeframe: 1000, // 1 second
      description: 'Rapid fire requests'
    }
  },
  
  memoryExhaustion: {
    scenarios: [
      {
        type: 'large_batch_operations',
        description: 'Process 1000 images simultaneously',
        imageCount: 1000
      },
      {
        type: 'infinite_thumbnails',
        description: 'Request thumbnails for non-existent images',
        requestCount: 10000
      },
      {
        type: 'concurrent_processing',
        description: 'Multiple heavy operations simultaneously',
        concurrency: 100
      }
    ]
  },
  
  storageExhaustion: {
    fillDisk: {
      fileCount: 10000,
      fileSize: 8 * 1024 * 1024, // 8MB each = 80GB total
      description: 'Fill up storage space'
    },
    
    inodeExhaustion: {
      fileCount: 1000000,
      fileSize: 1, // Many tiny files
      description: 'Exhaust file system inodes'
    }
  }
});

/**
 * Generate concurrent access attack patterns
 */
export const createConcurrencyAttackPatterns = () => ({
  raceConditions: {
    statusChange: {
      description: 'Multiple users trying to change status simultaneously',
      operations: [
        { action: 'updateStatus', status: 'processed' },
        { action: 'updateStatus', status: 'labeled' },
        { action: 'delete' }
      ]
    },
    
    ownership: {
      description: 'Transfer ownership during concurrent operations',
      operations: [
        { action: 'read' },
        { action: 'transferOwnership' },
        { action: 'delete' }
      ]
    },
    
    quota: {
      description: 'Multiple uploads when near quota limit',
      scenario: 'user_near_limit',
      concurrentUploads: 20
    }
  },
  
  lockContention: {
    bulkOperations: {
      description: 'Multiple bulk operations on overlapping image sets',
      operations: [
        { type: 'batchUpdate', imageIds: ['1', '2', '3', '4', '5'] },
        { type: 'batchUpdate', imageIds: ['3', '4', '5', '6', '7'] },
        { type: 'batchDelete', imageIds: ['4', '5', '6'] }
      ]
    }
  },
  
  timeOfCheckTimeOfUse: {
    scenarios: [
      {
        description: 'Check permissions then perform operation',
        steps: ['checkOwnership', 'delay', 'performOperation']
      },
      {
        description: 'Check quota then upload',
        steps: ['checkQuota', 'delay', 'uploadFile']
      }
    ]
  }
});

/**
 * Generate business logic abuse scenarios
 */
export const createBusinessLogicAbuseScenarios = () => ({
  workflowBypass: {
    statusTransitions: [
      { from: 'labeled', to: 'new', description: 'Illegal backward transition' },
      { from: 'deleted', to: 'processed', description: 'Restore deleted state' },
      { from: 'new', to: 'labeled', description: 'Skip processing step' }
    ],
    
    dependencyIgnore: [
      {
        scenario: 'delete_with_dependencies',
        description: 'Force delete image with garment dependencies',
        hasGarments: true,
        hasPoly: true
      }
    ]
  },
  
  limitBypass: {
    storageLimit: {
      description: 'Upload files to exceed storage quota',
      currentUsage: 499 * 1024 * 1024, // 499MB
      uploadSize: 10 * 1024 * 1024, // Try to upload 10MB more
      limit: 500 * 1024 * 1024 // 500MB limit
    },
    
    countLimit: {
      description: 'Upload more images than allowed',
      currentCount: 999,
      additionalUploads: 5,
      limit: 1000
    },
    
    rateLimits: {
      description: 'Exceed API rate limits',
      requestsPerMinute: 1000,
      normalLimit: 100
    }
  },
  
  privilegeAbuse: {
    adminFunctions: [
      'bulkDeleteAllUsers',
      'systemConfigAccess',
      'auditLogAccess',
      'userImpersonation'
    ],
    
    crossTenantAccess: {
      description: 'Access resources from different tenant/organization',
      scenarios: ['guessOtherTenantIds', 'manipulateHeaders', 'sessionReuse']
    }
  }
});

/**
 * Generate data validation bypass attempts
 */
export const createValidationBypassAttempts = () => ({
  typeConfusion: [
    { input: '123', expectedType: 'string', actualType: 'number' },
    { input: 'true', expectedType: 'boolean', actualType: 'string' },
    { input: [], expectedType: 'string', actualType: 'array' },
    { input: {}, expectedType: 'string', actualType: 'object' }
  ],
  
  encodingManipulation: [
    {
      description: 'Double URL encoding',
      original: '../etc/passwd',
      encoded: '%252e%252e%252fetc%252fpasswd'
    },
    {
      description: 'Unicode normalization bypass',
      original: 'script',
      encoded: '\u0073\u0063\u0072\u0069\u0070\u0074'
    },
    {
      description: 'HTML entity encoding',
      original: '<script>',
      encoded: '&lt;script&gt;'
    }
  ],
  
  lengthConstraintBypass: [
    {
      field: 'filename',
      maxLength: 255,
      bypassAttempt: 'x'.repeat(1000),
      technique: 'overflow'
    },
    {
      field: 'description',
      maxLength: 500,
      bypassAttempt: 'a'.repeat(10000),
      technique: 'memory_exhaustion'
    }
  ],
  
  formatStringAttacks: [
    '%s%s%s%s%s%s%s%s%s%s',
    '%x%x%x%x%x%x%x%x%x%x',
    '%n%n%n%n%n%n%n%n%n%n',
    '\\x41\\x41\\x41\\x41'
  ]
});

/**
 * Generate session and authentication attack vectors
 */
export const createAuthenticationAttackVectors = () => ({
  sessionManipulation: {
    fixation: {
      description: 'Session fixation attack',
      steps: ['obtainSessionId', 'forceSessionId', 'authenticateVictim', 'hijackSession']
    },
    
    hijacking: {
      description: 'Session hijacking attempts',
      techniques: ['cookieTheft', 'sessionPrediction', 'manInTheMiddle']
    },
    
    replay: {
      description: 'Session replay attacks',
      scenarios: ['reusedTokens', 'timestampManipulation', 'nonceReuse']
    }
  },
  
  tokenManipulation: {
    jwtAttacks: [
      'algorithmConfusion',
      'signatureStripping',
      'claimManipulation',
      'keyConfusion'
    ],
    
    bearerTokenAbuse: [
      'tokenLeakage',
      'crossOriginRequests',
      'tokenInjection'
    ]
  },
  
  authenticationBypass: {
    techniques: [
      'nullByteInjection',
      'sqlInjectionInAuth',
      'ldapInjection',
      'timingAttacks',
      'bruteForce'
    ]
  }
});

/**
 * Helper to simulate timing attacks
 */
export const simulateTimingAttack = async (
  operation: () => Promise<any>,
  iterations: number = 100
): Promise<{ averageTime: number; times: number[]; variance: number }> => {
  const times: number[] = [];
  
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    try {
      await operation();
    } catch (error) {
      // Continue timing even on errors
    }
    const end = performance.now();
    times.push(end - start);
  }
  
  const averageTime = times.reduce((sum, time) => sum + time, 0) / times.length;
  const variance = times.reduce((sum, time) => sum + Math.pow(time - averageTime, 2), 0) / times.length;
  
  return { averageTime, times, variance };
};

/**
 * Helper to detect information leakage in error messages
 */
export const analyzeErrorMessages = (errors: Error[]): {
  leaksInternalPaths: boolean;
  leaksCredentials: boolean;
  leaksSystemInfo: boolean;
  leaksUserData: boolean;
  suspiciousPatterns: string[];
} => {
  const allMessages = errors.map(e => e.message).join(' ');
  
  const patterns = {
    internalPaths: [/\/var\//, /\/opt\//, /\/usr\//, /\/home\//, /C:\\/, /Program Files/],
    credentials: [/password/i, /secret/i, /key/i, /token/i, /auth/i],
    systemInfo: [/mysql/i, /postgres/i, /mongodb/i, /redis/i, /version/i],
    userData: [/user_id/i, /email/i, /phone/i, /address/i]
  };
  
  const suspiciousPatterns: string[] = [];
  
  const leaksInternalPaths = patterns.internalPaths.some(pattern => {
    if (pattern.test(allMessages)) {
      suspiciousPatterns.push(`Internal path pattern: ${pattern}`);
      return true;
    }
    return false;
  });
  
  const leaksCredentials = patterns.credentials.some(pattern => {
    if (pattern.test(allMessages)) {
      suspiciousPatterns.push(`Credential pattern: ${pattern}`);
      return true;
    }
    return false;
  });
  
  const leaksSystemInfo = patterns.systemInfo.some(pattern => {
    if (pattern.test(allMessages)) {
      suspiciousPatterns.push(`System info pattern: ${pattern}`);
      return true;
    }
    return false;
  });
  
  const leaksUserData = patterns.userData.some(pattern => {
    if (pattern.test(allMessages)) {
      suspiciousPatterns.push(`User data pattern: ${pattern}`);
      return true;
    }
    return false;
  });
  
  return {
    leaksInternalPaths,
    leaksCredentials,
    leaksSystemInfo,
    leaksUserData,
    suspiciousPatterns
  };
};

/**
 * Generate comprehensive security test suite data
 */
export const generateSecurityTestSuite = () => ({
  payloads: createSecurityTestPayloads(),
  boundaries: createBoundaryTestCases(),
  authorization: createAuthorizationBypassScenarios(),
  fileAttacks: createFileUploadAttackVectors(),
  dosAttacks: createDoSAttackScenarios(),
  concurrency: createConcurrencyAttackPatterns(),
  businessLogic: createBusinessLogicAbuseScenarios(),
  validation: createValidationBypassAttempts(),
  authentication: createAuthenticationAttackVectors()
});

// ==================== ENHANCED SHARP MOCK SCENARIOS ====================

export const createSharpMockScenarios = () => ({
  // Color space scenarios
  colorSpaceConversion: {
    alreadySRGB: {
      metadata: { space: 'srgb', width: 800, height: 600, format: 'jpeg' },
      shouldConvert: false
    },
    needsConversion: {
      metadata: { space: 'cmyk', width: 800, height: 600, format: 'jpeg' },
      shouldConvert: true
    },
    unknownColorSpace: {
      metadata: { space: undefined, width: 800, height: 600, format: 'jpeg' },
      shouldConvert: true
    }
  },

  // Processing errors
  processingErrors: {
    invalidInput: () => {
      const error = new Error('Input buffer contains unsupported image format');
      (error as any).code = 'SHARP_UNSUPPORTED_FORMAT';
      return error;
    },
    pixelLimit: () => {
      const error = new Error('Input image exceeds pixel limit');
      (error as any).code = 'SHARP_PIXEL_LIMIT';
      return error;
    },
    memoryLimit: () => {
      const error = new Error('Input image exceeds memory limit');
      (error as any).code = 'SHARP_MEMORY_LIMIT';
      return error;
    }
  },

  // Resize scenarios
  resizeScenarios: {
    validResize: {
      input: { width: 1600, height: 1200 },
      target: { width: 800, height: 600 },
      expected: { width: 800, height: 600 }
    },
    withoutEnlargement: {
      input: { width: 400, height: 300 },
      target: { width: 800, height: 600 },
      expected: { width: 400, height: 300 } // Should not enlarge
    },
    aspectRatioPreservation: {
      input: { width: 1000, height: 500 },
      target: { width: 800, height: 800 },
      fit: 'contain',
      expected: { width: 800, height: 400 }
    }
  }
});

// ==================== FILE SYSTEM MOCK SCENARIOS ====================

export const createFileSystemMockScenarios = () => ({
  diskErrors: {
    noSpace: {
      error: new Error('ENOSPC: no space left on device'),
      code: 'ENOSPC',
      errno: -28
    },
    permission: {
      error: new Error('EACCES: permission denied'),
      code: 'EACCES', 
      errno: -13
    },
    fileNotFound: {
      error: new Error('ENOENT: no such file or directory'),
      code: 'ENOENT',
      errno: -2
    }
  },

  pathTraversal: {
    basic: '../../../etc/passwd',
    encoded: '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    nullByte: '../../../etc/passwd\x00.jpg',
    unicode: '\u002e\u002e\u002f\u002e\u002e\u002f\u002e\u002e\u002fetc\u002fpasswd'
  }
});

// ==================== ENHANCED IMAGE METADATA VARIATIONS ====================

export const createAdvancedImageMetadata = () => ({
  extremeDimensions: {
    tinyImage: { width: 1, height: 1, format: 'jpeg' },
    massiveImage: { width: 50000, height: 50000, format: 'jpeg' },
    extremelyWide: { width: 10000, height: 100, format: 'jpeg' },
    extremelyTall: { width: 100, height: 10000, format: 'jpeg' }
  },

  corruptedMetadata: {
    negativeWidth: { width: -800, height: 600, format: 'jpeg' },
    negativeHeight: { width: 800, height: -600, format: 'jpeg' },
    zeroWidth: { width: 0, height: 600, format: 'jpeg' },
    zeroHeight: { width: 800, height: 0, format: 'jpeg' },
    infiniteWidth: { width: Infinity, height: 600, format: 'jpeg' },
    nanDimensions: { width: NaN, height: NaN, format: 'jpeg' }
  },

  edgeFormats: {
    unknownFormat: { width: 800, height: 600, format: 'unknown' },
    emptyFormat: { width: 800, height: 600, format: '' },
    nullFormat: { width: 800, height: 600, format: null }
  }
});

// ==================== PROCESSING PERFORMANCE TEST SCENARIOS ====================

export const createPerformanceTestScenarios = () => ({
  loadTesting: {
    smallBatch: { imageCount: 10, concurrency: 2 },
    mediumBatch: { imageCount: 50, concurrency: 5 },
    largeBatch: { imageCount: 100, concurrency: 10 },
    stressBatch: { imageCount: 500, concurrency: 20 }
  },

  imageSizes: {
    thumbnail: { width: 150, height: 150, expectedTime: 100 },
    small: { width: 400, height: 300, expectedTime: 200 },
    medium: { width: 800, height: 600, expectedTime: 500 },
    large: { width: 1600, height: 1200, expectedTime: 1000 },
    xlarge: { width: 3200, height: 2400, expectedTime: 2000 }
  }
});

// ==================== ENHANCED VALIDATION HELPERS ====================

export const createValidationHelpers = () => ({
  validateMetadata: (metadata: any) => {
    const errors: string[] = [];
    
    if (!metadata.width || metadata.width <= 0) {
      errors.push('Invalid width');
    }
    if (!metadata.height || metadata.height <= 0) {
      errors.push('Invalid height');
    }
    if (!metadata.format || typeof metadata.format !== 'string') {
      errors.push('Invalid format');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  },

  validateAspectRatio: (width: number, height: number) => {
    const ratio = width / height;
    return {
      ratio,
      isValid: ratio >= 0.8 && ratio <= 1.91,
      type: ratio < 0.8 ? 'too_tall' : ratio > 1.91 ? 'too_wide' : 'valid'
    };
  },

  validateDimensions: (width: number, height: number) => {
    return {
      width: {
        value: width,
        isValid: width >= 320 && width <= 1440,
        error: width < 320 ? 'too_small' : width > 1440 ? 'too_large' : null
      },
      height: {
        value: height,
        isValid: height >= 168 && height <= 1800,
        error: height < 168 ? 'too_small' : height > 1800 ? 'too_large' : null
      }
    };
  }
});

// ==================== CONCURRENT OPERATION HELPERS ====================

export const createConcurrencyHelpers = () => ({
  async runConcurrentValidations(
    buffers: Buffer[],
    validateFunction: (buffer: Buffer) => Promise<any>
  ) {
    const results = await Promise.allSettled(
      buffers.map(buffer => validateFunction(buffer))
    );
    
    return {
      successful: results.filter(r => r.status === 'fulfilled').length,
      failed: results.filter(r => r.status === 'rejected').length,
      results: results.map((r, index) => ({
        index,
        status: r.status,
        result: r.status === 'fulfilled' ? r.value : null,
        error: r.status === 'rejected' ? r.reason : null
      }))
    };
  },

  async simulateRaceCondition(
    operation: () => Promise<any>,
    attempts: number = 10
  ) {
    const promises = Array.from({ length: attempts }, () => operation());
    const results = await Promise.allSettled(promises);
    
    return {
      totalAttempts: attempts,
      successful: results.filter(r => r.status === 'fulfilled').length,
      failed: results.filter(r => r.status === 'rejected').length,
      uniqueResults: [...new Set(
        results
          .filter(r => r.status === 'fulfilled')
          .map(r => JSON.stringify((r as any).value))
      )].length
    };
  }
});

// ==================== MEMORY LEAK DETECTION HELPERS ====================

export const createMemoryTestHelpers = () => ({
  async detectMemoryLeaks(
    operation: () => Promise<any>,
    iterations: number = 100
  ) {
    const initialMemory = process.memoryUsage();
    
    for (let i = 0; i < iterations; i++) {
      await operation();
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
    }
    
    const finalMemory = process.memoryUsage();
    
    return {
      initial: initialMemory,
      final: finalMemory,
      growth: {
        heapUsed: finalMemory.heapUsed - initialMemory.heapUsed,
        heapTotal: finalMemory.heapTotal - initialMemory.heapTotal,
        external: finalMemory.external - initialMemory.external
      },
      hasLeak: (finalMemory.heapUsed - initialMemory.heapUsed) > (10 * 1024 * 1024) // 10MB threshold
    };
  }
});

// ==================== ERROR MESSAGE VALIDATION ====================

export const createErrorValidationHelpers = () => ({
  validateErrorStructure: (error: any) => {
    const checks = {
      hasMessage: typeof error.message === 'string',
      messageNotEmpty: error.message && error.message.trim().length > 0,
      noInternalPaths: !error.message?.match(/\/var\/|\/opt\/|\/usr\/|C:\\/),
      noCredentials: !error.message?.match(/password|secret|key|token/i),
      noStackTrace: !error.message?.includes('at '),
      isUserFriendly: error.message?.length < 200
    };
    
    return {
      ...checks,
      isValid: Object.values(checks).every(Boolean),
      score: Object.values(checks).filter(Boolean).length / Object.keys(checks).length
    };
  },

  categorizeError: (error: Error) => {
    const message = error.message.toLowerCase();
    
    if (message.includes('format') || message.includes('unsupported')) {
      return 'FORMAT_ERROR';
    }
    if (message.includes('dimension') || message.includes('size')) {
      return 'DIMENSION_ERROR';
    }
    if (message.includes('aspect ratio')) {
      return 'ASPECT_RATIO_ERROR';
    }
    if (message.includes('space') || message.includes('permission')) {
      return 'FILESYSTEM_ERROR';
    }
    if (message.includes('memory') || message.includes('limit')) {
      return 'RESOURCE_ERROR';
    }
    
    return 'UNKNOWN_ERROR';
  }
});

// ==================== TEST DATA GENERATORS ====================

export const createTestDataGenerators = () => ({
  generateImageBuffers: (count: number) => {
    return Array.from({ length: count }, (_, i) => ({
      id: `test-image-${i}`,
      buffer: createValidImageBuffers.jpeg(),
      metadata: {
        width: 800 + (i * 100),
        height: 600 + (i * 75),
        format: i % 2 === 0 ? 'jpeg' : 'png'
      }
    }));
  },

  generatePathVariations: (basePath: string) => ({
    normal: basePath,
    withSpaces: basePath.replace(/([^\/\\]+)/, 'file with spaces'),
    withUnicode: basePath.replace(/([^\/\\]+)/, 'файл测试🖼️'),
    withDots: basePath.replace(/([^\/\\]+)/, '..hidden.file'),
    veryLong: basePath + 'x'.repeat(500),
    withNullByte: basePath + '\x00.hidden'
  })
});

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
  imageAssertions,

  createTestImageBuffer,  // Added this export
  createSecurityTestPayloads,
  createBoundaryTestCases,
  createAuthorizationBypassScenarios,
  createFileUploadAttackVectors,
  createDoSAttackScenarios,
  createConcurrencyAttackPatterns,
  createBusinessLogicAbuseScenarios,
  createValidationBypassAttempts,
  createAuthenticationAttackVectors,
  simulateTimingAttack,
  analyzeErrorMessages,
  generateSecurityTestSuite,

  createSharpMockScenarios,
  createFileSystemMockScenarios,
  createAdvancedImageMetadata,
  createPerformanceTestScenarios,
  createValidationHelpers,
  createConcurrencyHelpers,
  createMemoryTestHelpers,
  createErrorValidationHelpers,
  createTestDataGenerators
};