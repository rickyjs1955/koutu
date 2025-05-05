// /backend/src/services/storageService.ts
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';
import { bucket } from '../config/firebase';

// Ensure uploads directory exists for local storage mode
const uploadsDir = config.uploadsDir;
if (config.storageMode === 'local' && !fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

/**
 * Storage service for handling file operations
 * Supports both local file system and Firebase storage
 */
export const storageService = {
  /**
   * Save a file to storage
   * @param fileBuffer The file buffer to save
   * @param originalFilename The original filename
   * @returns A promise that resolves to the relative path of the saved file
   */
  async saveFile(fileBuffer: Buffer, originalFilename: string): Promise<string> {
    // Generate a unique filename
    const fileExtension = path.extname(originalFilename);
    const filename = `${uuidv4()}${fileExtension}`;
    
    if (config.storageMode === 'firebase') {
      // Firebase Storage implementation
      const file = bucket.file(`uploads/${filename}`);
      
      // Create a write stream and upload the file
      const writeStream = file.createWriteStream({
        metadata: {
          contentType: this.getContentType(fileExtension),
          metadata: {
            originalFilename
          }
        }
      });
      
      return new Promise((resolve, reject) => {
        writeStream.on('error', (error) => {
          reject(error);
        });
        
        writeStream.on('finish', () => {
          resolve(`uploads/${filename}`);
        });
        
        writeStream.end(fileBuffer);
      });
    } else {
      // Local storage implementation
      const filePath = path.join(uploadsDir, filename);
      await fs.promises.writeFile(filePath, fileBuffer);
      return `uploads/${filename}`;
    }
  },
  
  /**
   * Delete a file from storage
   * @param filePath The relative path of the file to delete
   * @returns A promise that resolves to true if the file was deleted, false otherwise
   */
  async deleteFile(filePath: string): Promise<boolean> {
    try {
      if (config.storageMode === 'firebase') {
        // Firebase Storage implementation
        const file = bucket.file(filePath);
        
        // Check if file exists
        const [exists] = await file.exists();
        if (exists) {
          await file.delete();
          return true;
        }
        return false;
      } else {
        // Local storage implementation
        const absolutePath = path.join(__dirname, '../../..', filePath);
        
        // Check if file exists
        if (fs.existsSync(absolutePath)) {
          await fs.promises.unlink(absolutePath);
          return true;
        }
        return false;
      }
    } catch (error) {
      console.error('Error deleting file:', error);
      return false;
    }
  },
  
  /**
   * Get the absolute path of a file
   * @param relativePath The relative path of the file
   * @returns The absolute path of the file
   */
  getAbsolutePath(relativePath: string): string {
    return path.join(__dirname, '../../..', relativePath);
  },
  
  /**
   * Get a signed URL for a file in Firebase Storage
   * @param filePath The relative path of the file
   * @param expirationMinutes How long the URL should be valid for (in minutes)
   * @returns A promise that resolves to the signed URL
   */
  async getSignedUrl(filePath: string, expirationMinutes: number = 60): Promise<string> {
    if (config.storageMode === 'firebase') {
      // Firebase Storage implementation
      const file = bucket.file(filePath);
      
      // Generate a signed URL
      const [url] = await file.getSignedUrl({
        action: 'read',
        expires: Date.now() + expirationMinutes * 60 * 1000,
      });
      
      return url;
    } else {
      // For local storage, just return the relative path
      // In a real app, you would need to have a route that serves these files
      return `/api/v1/files/${filePath}`;
    }
  },
  
  /**
   * Get the content type based on file extension
   * @param fileExtension The file extension
   * @returns The content type
   */
  getContentType(fileExtension: string): string {
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