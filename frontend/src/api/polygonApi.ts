// /frontend/src/api/polygonApi.ts
import api from './index';
import { 
  Polygon,
  CreatePolygonInput, 
  UpdatePolygonInput 
} from '../../../shared/src/schemas/polygon';

export const polygonApi = {
  /**
   * Create a new polygon
   */
  async createPolygon(data: CreatePolygonInput): Promise<Polygon> {
    const response = await api.post('/polygons', data);
    return response.data.data.polygon;
  },
  
  /**
   * Get all polygons for an image
   */
  async getImagePolygons(imageId: string): Promise<Polygon[]> {
    const response = await api.get(`/polygons/image/${imageId}`);
    return response.data.data.polygons;
  },
  
  /**
   * Get a specific polygon
   */
  async getPolygon(id: string): Promise<Polygon> {
    const response = await api.get(`/polygons/${id}`);
    return response.data.data.polygon;
  },
  
  /**
   * Update a polygon
   */
  async updatePolygon(id: string, data: UpdatePolygonInput): Promise<Polygon> {
    const response = await api.put(`/polygons/${id}`, data);
    return response.data.data.polygon;
  },
  
  /**
   * Delete a polygon
   */
  async deletePolygon(id: string): Promise<void> {
    await api.delete(`/polygons/${id}`);
  }
};