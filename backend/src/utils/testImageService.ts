// /backend/src/services/__tests__/imageService.setup.ts
// Shared setup utilities for imageService integration tests

import { TestDatabaseConnection } from './testDatabaseConnection';
import { v4 as uuidv4 } from 'uuid';
import sharp from 'sharp';
import fs from 'fs/promises';
import path from 'path';

export interface TestUser {
  id: string;
  email: string;
  displayName: string;
}

export interface TestFile {
  path: string;
  buffer: Buffer;
  metadata: any;
}

export class ImageServiceTestHelper {
  private createdUsers: TestUser[] = [];
  private createdFiles: string[] = [];
  private createdImageIds: string[] = [];
  private testStorageDir: string;

  constructor() {
    this.testStorageDir = path.join(process.cwd(), 'test-storage');
  }

  /**
   * Create a test user in the database
   */
  async createTestUser(overrides: Partial<TestUser> = {}): Promise<TestUser> {
    const user: TestUser = {
      id: uuidv4(),
      email: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
      displayName: 'Test User',
      ...overrides
    };

    await TestDatabaseConnection.query(
      'INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)',
      [user.id, user.email, user.displayName]
    );

    this.createdUsers.push(user);
    return user;
  }

  /**
   * Create a real image buffer with specific characteristics
   */
  async createImageBuffer(options: {
    width?: number;
    height?: number;
    format?: 'jpeg' | 'png' | 'webp';
    quality?: number;
    colorSpace?: 'srgb' | 'cmyk' | 'p3';
    addText?: boolean;
  } = {}): Promise<Buffer> {
    const {
      width = 800,
      height = 600,
      format = 'jpeg',
      quality = 80,
      colorSpace = 'srgb',
      addText = true
    } = options;

    let image = sharp({
      create: {
        width,
        height,
        channels: colorSpace === 'cmyk' ? 4 : 3,
        background: colorSpace === 'cmyk' 
          ? 'cmyk(20, 40, 60, 0)' // Use CMYK string format
          : { r: 255, g: 128, b: 64 }
      }
    });

    // Add text overlay if requested
    if (addText) {
      const textSvg = `
        <svg width="${width}" height="${height}">
          <rect width="${width}" height="${height}" fill="rgba(0,0,0,0)"/>
          <circle cx="${width/2}" cy="${height/2}" r="${Math.min(width, height)/8}" 
                  fill="rgba(64,128,255,0.8)" stroke="white" stroke-width="2"/>
          <text x="${width/2}" y="${height/2}" text-anchor="middle" dominant-baseline="middle" 
                fill="white" font-size="${Math.max(16, Math.min(width, height)/30)}" 
                font-family="Arial" font-weight="bold">
            ${format.toUpperCase()} ${width}x${height}
          </text>
        </svg>
      `;
      
      const textBuffer = Buffer.from(textSvg);
      image = image.composite([{ input: textBuffer, blend: 'over' }]);
    }

    // Apply color space conversion if needed
    if (colorSpace === 'cmyk') {
      image = image.toColorspace('cmyk');
    } else if (colorSpace === 'p3') {
      image = image.toColorspace('p3');
    }

    // Convert to requested format
    switch (format) {
      case 'jpeg':
        return await image.jpeg({ quality, progressive: true }).toBuffer();
      case 'png':
        return await image.png({ compressionLevel: 6 }).toBuffer();
      case 'webp':
        return await image.webp({ quality }).toBuffer();
      default:
        return await image.jpeg({ quality }).toBuffer();
    }
  }

  /**
   * Create Instagram-compatible test images
   */
  async createInstagramImages(): Promise<{
    square: Buffer;
    portrait: Buffer;
    landscape: Buffer;
    minSize: Buffer;
    maxSize: Buffer;
  }> {
    return {
      square: await this.createImageBuffer({ width: 1080, height: 1080 }),
      portrait: await this.createImageBuffer({ width: 1080, height: 1350 }),
      landscape: await this.createImageBuffer({ width: 1080, height: 566 }),
      minSize: await this.createImageBuffer({ width: 320, height: 400 }),
      maxSize: await this.createImageBuffer({ width: 1440, height: 754 })
    };
  }

  /**
   * Create invalid test images for error testing
   */
  async createInvalidImages(): Promise<{
    tooSmall: Buffer;
    tooLarge: Buffer;
    wrongRatio: Buffer;
    corrupted: Buffer;
    wrongFormat: Buffer;
  }> {
    return {
      tooSmall: await this.createImageBuffer({ width: 200, height: 150 }),
      tooLarge: await this.createImageBuffer({ width: 4000, height: 4000 }),
      wrongRatio: await this.createImageBuffer({ width: 2000, height: 100 }), // 20:1 ratio
      corrupted: Buffer.from('This is not a valid image file'),
      wrongFormat: Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj') // PDF header
    };
  }

  /**
   * Save a file to test storage
   */
  async saveTestFile(filename: string, buffer: Buffer): Promise<string> {
    const filePath = path.join(this.testStorageDir, 'uploads', filename);
    await fs.writeFile(filePath, buffer);
    this.createdFiles.push(filePath);
    return filePath;
  }

  /**
   * Verify file exists and get its metadata
   */
  async verifyFile(filePath: string): Promise<{
    exists: boolean;
    size?: number;
    metadata?: any;
  }> {
    try {
      const stats = await fs.stat(filePath);
      const metadata = await sharp(filePath).metadata();
      
      return {
        exists: true,
        size: stats.size,
        metadata
      };
    } catch (error) {
      return { exists: false };
    }
  }

  /**
   * Track created image ID for cleanup
   */
  trackImageId(imageId: string): void {
    this.createdImageIds.push(imageId);
  }

  /**
   * Clean up all created resources
   */
  async cleanup(): Promise<void> {
    // Clean up files
    for (const filePath of this.createdFiles) {
      try {
        await fs.unlink(filePath);
      } catch (error) {
        // Ignore errors - file might already be deleted
      }
    }

    // Clean up database records
    if (this.createdImageIds.length > 0) {
      try {
        const placeholders = this.createdImageIds.map((_, index) => `${index + 1}`).join(',');
        await TestDatabaseConnection.query(
          `DELETE FROM original_images WHERE id IN (${placeholders})`,
          this.createdImageIds
        );
      } catch (error) {
        console.warn('Error cleaning up image records:', error);
      }
    }

    if (this.createdUsers.length > 0) {
      try {
        const userIds = this.createdUsers.map(u => u.id);
        const placeholders = userIds.map((_, index) => `${index + 1}`).join(',');
        await TestDatabaseConnection.query(
          `DELETE FROM users WHERE id IN (${placeholders})`,
          userIds
        );
      } catch (error) {
        console.warn('Error cleaning up user records:', error);
      }
    }

    // Reset tracking arrays
    this.createdFiles = [];
    this.createdImageIds = [];
    this.createdUsers = [];
  }

  /**
   * Get test storage directory path
   */
  getStorageDir(): string {
    return this.testStorageDir;
  }

  /**
   * Generate performance test data
   */
  async generatePerformanceTestData(count: number): Promise<{
    users: TestUser[];
    imageBuffers: Buffer[];
    uploadParams: Array<{
      userId: string;
      fileBuffer: Buffer;
      originalFilename: string;
      mimetype: string;
      size: number;
    }>;
  }> {
    const users: TestUser[] = [];
    const imageBuffers: Buffer[] = [];
    const uploadParams: any[] = [];

    // Create test users
    for (let i = 0; i < Math.min(count, 5); i++) {
      users.push(await this.createTestUser({
        email: `perf-user-${i}@example.com`,
        displayName: `Performance User ${i}`
      }));
    }

    // Create image buffers and upload params
    for (let i = 0; i < count; i++) {
      const buffer = await this.createImageBuffer({
        width: 800 + (i % 3) * 100,
        height: 600 + (i % 3) * 75,
        format: ['jpeg', 'png'][i % 2] as 'jpeg' | 'png'
      });

      imageBuffers.push(buffer);
      uploadParams.push({
        userId: users[i % users.length].id,
        fileBuffer: buffer,
        originalFilename: `perf-test-${i}.${['jpg', 'png'][i % 2]}`,
        mimetype: `image/${['jpeg', 'png'][i % 2]}`,
        size: buffer.length
      });
    }

    return { users, imageBuffers, uploadParams };
  }
}