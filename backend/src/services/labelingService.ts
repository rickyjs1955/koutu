// /backend/src/services/labelingService.ts
import sharp from 'sharp';
import path from 'path';
import { storageService } from './storageService';

interface MaskData {
  width: number;
  height: number;
  data: Uint8ClampedArray | number[];
}

export const labelingService = {
  async applyMaskToImage(
    imagePath: string,
    maskData: MaskData
  ): Promise<{ maskedImagePath: string; maskPath: string }> {
    const absoluteImagePath = storageService.getAbsolutePath(imagePath);
    
    // Create a binary mask image from the mask data
    const maskBuffer = await this.createBinaryMask(maskData);
    
    // Generate paths for output files
    const fileExtension = path.extname(imagePath);
    const fileNameWithoutExt = path.basename(imagePath, fileExtension);
    const dirName = path.dirname(imagePath);
    
    const maskFileName = `${fileNameWithoutExt}_mask.png`;
    const maskPath = path.join(dirName, maskFileName);
    const maskAbsolutePath = storageService.getAbsolutePath(maskPath);
    
    const maskedFileName = `${fileNameWithoutExt}_masked${fileExtension}`;
    const maskedImagePath = path.join(dirName, maskedFileName);
    const maskedImageAbsolutePath = storageService.getAbsolutePath(maskedImagePath);
    
    // Save the mask
    await sharp(maskBuffer, {
      raw: {
        width: maskData.width,
        height: maskData.height,
        channels: 1
      }
    })
    .toFile(maskAbsolutePath);
    
    // Apply the mask to the original image
    const originalImage = sharp(absoluteImagePath);
    const metadata = await originalImage.metadata();
    
    // Resize mask if needed to match original image dimensions
    let processedMask = maskBuffer;
    if (metadata.width !== maskData.width || metadata.height !== maskData.height) {
      processedMask = await sharp(maskBuffer, {
        raw: {
          width: maskData.width,
          height: maskData.height,
          channels: 1
        }
      })
      .resize(metadata.width, metadata.height)
      .toBuffer();
    }
    
    // Composite the mask with the original image
    await originalImage
      .composite([
        {
          input: processedMask,
          blend: 'dest-in',
          raw: {
            width: metadata.width as number,
            height: metadata.height as number,
            channels: 1
          }
        }
      ])
      .toFile(maskedImageAbsolutePath);
    
    return {
      maskedImagePath,
      maskPath
    };
  },
  
  async createBinaryMask(maskData: MaskData): Promise<Buffer> {
    // Convert mask data to a binary mask (0 or 255)
    const binaryMask = new Uint8ClampedArray(maskData.width * maskData.height);
    
    for (let i = 0; i < maskData.data.length; i++) {
      // If the mask data is non-zero, set to 255 (white), otherwise 0 (black)
      binaryMask[i] = maskData.data[i] > 0 ? 255 : 0;
    }
    
    return Buffer.from(binaryMask);
  }
};