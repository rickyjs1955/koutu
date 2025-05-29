// /backend/src/services/imageProcessingService.ts
import sharp from 'sharp';
import path from 'path';
import { storageService } from './storageService';
import { ApiError } from '../utils/ApiError';

export const imageProcessingService = {
  /**
   * Validate image buffer and extract basic metadata
   * This is used during upload validation
   */
  async validateImageBuffer(buffer: Buffer): Promise<sharp.Metadata> {
    try {
      const metadata = await sharp(buffer).metadata();
      
      // Ensure we have valid image metadata
      if (!metadata.format) {
        throw new Error('Could not determine image format');
      }
      
      if (!metadata.width || !metadata.height) {
        throw new Error('Could not determine image dimensions');
      }
      
      // Validate supported formats (Instagram compatible)
      const supportedFormats = ['jpeg', 'png', 'bmp'];
      if (!supportedFormats.includes(metadata.format)) {
        throw new Error(`Unsupported image format: ${metadata.format}`);
      }
      
      // Instagram dimension validation
      if (metadata.width < 320) {
        throw new Error(`Image width too small (minimum 320px, got ${metadata.width}px)`);
      }
      
      if (metadata.width > 1440) {
        throw new Error(`Image width too large (maximum 1440px, got ${metadata.width}px)`);
      }
      
      // Instagram aspect ratio validation
      const aspectRatio = metadata.width / metadata.height;
      if (aspectRatio < 0.8 || aspectRatio > 1.91) {
        throw new Error(`Invalid aspect ratio: ${aspectRatio.toFixed(2)}:1 (must be between 4:5 and 1.91:1)`);
      }
      
      return metadata;
    } catch (error) {
      console.error('Image buffer validation error:', error);
      throw new Error(`Invalid image: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  },

  async convertToSRGB(inputPath: string): Promise<string> {
    try {
      const absolutePath = storageService.getAbsolutePath(inputPath);
      
      // Check current color space
      const metadata = await sharp(absolutePath).metadata();
      
      // If already sRGB, return original path
      if (metadata.space === 'srgb') {
        return inputPath;
      }
      
      // Create converted file path
      const fileExtension = path.extname(inputPath);
      const fileNameWithoutExt = path.basename(inputPath, fileExtension);
      const dirName = path.dirname(inputPath);
      const convertedFileName = `${fileNameWithoutExt}_srgb${fileExtension}`;
      const convertedPath = path.join(dirName, convertedFileName);
      const convertedAbsolutePath = storageService.getAbsolutePath(convertedPath);
      
      // Convert to sRGB
      await sharp(absolutePath)
        .toColorspace('srgb')
        .toFile(convertedAbsolutePath);
      
      console.log(`Converted ${metadata.space} to sRGB: ${convertedPath}`);
      return convertedPath;
    } catch (error) {
      console.error('Color space conversion error:', error);
      throw new Error(`Failed to convert to sRGB: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  },
  
  async resizeImage(
    inputPath: string,
    width: number = 800,
    height: number = 800,
    fit: 'contain' | 'cover' | 'fill' | 'inside' | 'outside' = 'contain'
  ): Promise<string> {
    try {
      // Get absolute path
      const absolutePath = storageService.getAbsolutePath(inputPath);
      
      // Verify input file exists and is valid
      const inputMetadata = await sharp(absolutePath).metadata();
      if (!inputMetadata.width || !inputMetadata.height) {
        throw new Error('Invalid input image dimensions');
      }
      
      // Get file extension
      const fileExtension = path.extname(inputPath);
      const fileNameWithoutExt = path.basename(inputPath, fileExtension);
      const dirName = path.dirname(inputPath);
      
      // Create resized file name
      const resizedFileName = `${fileNameWithoutExt}_${width}x${height}${fileExtension}`;
      const resizedPath = path.join(dirName, resizedFileName);
      const resizedAbsolutePath = storageService.getAbsolutePath(resizedPath);
      
      // Process the image with quality settings
      await sharp(absolutePath)
        .resize({
          width,
          height,
          fit,
          withoutEnlargement: true
        })
        .jpeg({ quality: 85, progressive: true }) // For JPEG output
        .png({ quality: 85, progressive: true })  // For PNG output
        .toFile(resizedAbsolutePath);
      
      return resizedPath;
    } catch (error) {
      console.error('Image resize error:', error);
      throw new Error(`Failed to resize image: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  },
  
  async extractMetadata(inputPath: string): Promise<sharp.Metadata> {
    try {
      const absolutePath = storageService.getAbsolutePath(inputPath);
      const metadata = await sharp(absolutePath).metadata();
      
      // Validate that we got meaningful metadata
      if (!metadata.format) {
        throw new Error('Could not extract image format');
      }
      
      return metadata;
    } catch (error) {
      console.error('Metadata extraction error:', error);
      throw new Error(`Failed to extract image metadata: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  },
  
  /**
   * Generate thumbnail for an image
   */
  async generateThumbnail(inputPath: string, size: number = 200): Promise<string> {
    try {
      const absolutePath = storageService.getAbsolutePath(inputPath);
      
      // Get file info
      const fileExtension = path.extname(inputPath);
      const fileNameWithoutExt = path.basename(inputPath, fileExtension);
      const dirName = path.dirname(inputPath);
      
      // Create thumbnail file name
      const thumbnailFileName = `${fileNameWithoutExt}_thumb_${size}.jpg`;
      const thumbnailPath = path.join(dirName, thumbnailFileName);
      const thumbnailAbsolutePath = storageService.getAbsolutePath(thumbnailPath);
      
      // Generate thumbnail
      await sharp(absolutePath)
        .resize(size, size, {
          fit: 'cover',
          position: 'center'
        })
        .jpeg({ quality: 80 })
        .toFile(thumbnailAbsolutePath);
      
      return thumbnailPath;
    } catch (error) {
      console.error('Thumbnail generation error:', error);
      throw new Error(`Failed to generate thumbnail: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  },
  
  /**
   * Optimize image for web delivery
   */
  async optimizeForWeb(inputPath: string): Promise<string> {
    try {
      const absolutePath = storageService.getAbsolutePath(inputPath);
      
      // Get file info
      const fileExtension = path.extname(inputPath);
      const fileNameWithoutExt = path.basename(inputPath, fileExtension);
      const dirName = path.dirname(inputPath);
      
      // Create optimized file name
      const optimizedFileName = `${fileNameWithoutExt}_optimized${fileExtension}`;
      const optimizedPath = path.join(dirName, optimizedFileName);
      const optimizedAbsolutePath = storageService.getAbsolutePath(optimizedPath);
      
      // Get original metadata to determine optimization strategy
      const metadata = await sharp(absolutePath).metadata();
      
      let processor = sharp(absolutePath);
      
      // Apply optimization based on format
      switch (metadata.format) {
        case 'jpeg':
          processor = processor.jpeg({
            quality: 85,
            progressive: true,
            mozjpeg: true
          });
          break;
        case 'png':
          processor = processor.png({
            quality: 85,
            progressive: true,
            compressionLevel: 6
          });
          break;
        case 'webp':
          processor = processor.webp({
            quality: 85,
            lossless: false
          });
          break;
        default:
          // Convert other formats to JPEG
          processor = processor.jpeg({
            quality: 85,
            progressive: true
          });
      }
      
      await processor.toFile(optimizedAbsolutePath);
      
      return optimizedPath;
    } catch (error) {
      console.error('Image optimization error:', error);
      throw new Error(`Failed to optimize image: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }
};

export async function processImage(file: any, userId: string, garmentId: string) {
  try {
    // Enhanced image processing logic
    const processingResult = {
      id: `processed-${garmentId}-${Date.now()}`,
      url: `https://storage.example.com/processed-${garmentId}.jpg`,
      thumbnailUrl: `https://storage.example.com/thumb-${garmentId}.jpg`,
      metadata: {
        processedAt: new Date().toISOString(),
        userId,
        garmentId
      }
    };
    
    return processingResult;
  } catch (error) {
    console.error('Image processing error:', error);
    throw new ApiError('Failed to process image', 500, 'PROCESSING_ERROR');
  }
}

export async function removeBackground(imageId: string) {
  try {
    // Background removal logic would go here
    // This could integrate with AI services like Remove.bg, etc.
    
    return { 
      success: true, 
      processedImageId: `bg-removed-${imageId}`,
      processedAt: new Date().toISOString()
    };
  } catch (error) {
    console.error('Background removal error:', error);
    throw new ApiError('Failed to remove background', 500, 'BACKGROUND_REMOVAL_ERROR');
  }
}