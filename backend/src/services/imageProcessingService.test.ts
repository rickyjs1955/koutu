import { describe, expect, test, jest } from '@jest/globals';
import { processImage, removeBackground } from './imageProcessingService.js';

// Mock any dependencies
jest.mock('./storageService', () => ({
  storageService: {
    getAbsolutePath: jest.fn().mockReturnValue('/mocked/path'),
    uploadFile: jest.fn<() => Promise<string>>().mockResolvedValue('https://storage.example.com/test-image.jpg'),
  }
}));

describe('Image Processing Service', () => {
  test('processImage returns expected structure', async () => {
    const mockFile = {
      buffer: Buffer.from('test-image-data'),
      originalname: 'test-image.jpg',
      mimetype: 'image/jpeg',
      size: 1024
    };
    
    const result = await processImage(mockFile, 'user123', 'garment456');
    
    expect(result).toHaveProperty('id');
    expect(result).toHaveProperty('url');
  });

  test('removeBackground returns success flag', async () => {
    const result = await removeBackground('image123');
    
    expect(result).toHaveProperty('success');
    expect(result.success).toBe(true);
  });
});