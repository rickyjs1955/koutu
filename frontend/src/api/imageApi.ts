// /frontend/src/api/imageApi.ts
import api from './index';
import { ImageResponse, ImageListResponse } from '../../../shared/src/schemas';

export const imageApi = {
  /**
   * Upload a new image
   */
  async uploadImage(file: File): Promise<ImageResponse> {
    // Create form data for file upload
    const formData = new FormData();
    formData.append('image', file);
    
    const response = await api.post('/images/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data'
      }
    });
    
    return response.data.data.image;
  },
  
  /**
   * Get all images for the current user
   */
  async getImages(): Promise<ImageListResponse> {
    const response = await api.get('/images');
    return response.data.data.images;
  },
  
  /**
   * Get a specific image by ID
   */
  async getImage(id: string): Promise<ImageResponse> {
    const response = await api.get(`/images/${id}`);
    return response.data.data.image;
  },
  
  /**
   * Delete an image
   */
  async deleteImage(id: string): Promise<void> {
    await api.delete(`/images/${id}`);
  },
  
  /**
   * Get the URL for an image
   */
  getImageUrl(filePath: string): string {
    // Fix: Handle potentially undefined baseURL
    const baseUrl = api.defaults.baseURL || '';
    // This assumes your backend serves images at /api/v1/files/{filePath}
    // Adjust as needed for your actual backend implementation
    return `${baseUrl.replace('/api/v1', '')}/api/v1/files/${filePath}`;
  }
};