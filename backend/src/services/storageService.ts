// src/services/storageService.ts
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config';

// Ensure uploads directory exists
const uploadsDir = config.uploadsDir;
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

export const storageService = {
  async saveFile(fileBuffer: Buffer, originalFilename: string): Promise<string> {
    // Generate a unique filename
    const fileExtension = path.extname(originalFilename);
    const filename = `${uuidv4()}${fileExtension}`;
    const filePath = path.join(uploadsDir, filename);
    
    // Write file to disk
    await fs.promises.writeFile(filePath, fileBuffer);
    
    // Return the relative path (for storing in database)
    return `uploads/${filename}`;
  },
  
  async deleteFile(filePath: string): Promise<boolean> {
    try {
      // Convert relative path to absolute path
      const absolutePath = path.join(__dirname, '../..', filePath);
      
      // Check if file exists
      if (fs.existsSync(absolutePath)) {
        await fs.promises.unlink(absolutePath);
        return true;
      }
      return false;
    } catch (error) {
      console.error('Error deleting file:', error);
      return false;
    }
  },
  
  getAbsolutePath(relativePath: string): string {
    return path.join(__dirname, '../..', relativePath);
  }
};