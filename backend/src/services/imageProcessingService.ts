// /backend/src/services/imageProcessingService.ts
import sharp from 'sharp';
import path from 'path';
import { storageService } from './storageService';

export const imageProcessingService = {
  async resizeImage(
    inputPath: string,
    width: number = 800,
    height: number = 800,
    fit: 'contain' | 'cover' | 'fill' | 'inside' | 'outside' = 'contain'
  ): Promise<string> {
    // Get absolute path
    const absolutePath = storageService.getAbsolutePath(inputPath);
    
    // Get file extension
    const fileExtension = path.extname(inputPath);
    const fileNameWithoutExt = path.basename(inputPath, fileExtension);
    const dirName = path.dirname(inputPath);
    
    // Create resized file name
    const resizedFileName = `${fileNameWithoutExt}_${width}x${height}${fileExtension}`;
    const resizedPath = path.join(dirName, resizedFileName);
    const resizedAbsolutePath = storageService.getAbsolutePath(resizedPath);
    
    // Process the image
    await sharp(absolutePath)
      .resize({
        width,
        height,
        fit,
        withoutEnlargement: true
      })
      .toFile(resizedAbsolutePath);
    
    return resizedPath;
  },
  
  async extractMetadata(inputPath: string): Promise<sharp.Metadata> {
    const absolutePath = storageService.getAbsolutePath(inputPath);
    return sharp(absolutePath).metadata();
  }
};

export async function processImage(file: any, userId: string, garmentId: string) {
  // Add your image processing logic here
  return {
    id: 'processed-image-id',
    url: 'https://storage.example.com/processed-image.jpg'
  };
}

// Ensure removeBackground is also exported if needed
export async function removeBackground(imageId: string) {
  // Add your background removal logic here
  return { success: true };
}