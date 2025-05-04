// /frontend/src/api/wardrobeApi.ts
import api from './index';
import { 
  CreateWardrobeInput, 
  UpdateWardrobeInput, 
  AddGarmentToWardrobeInput, 
  Wardrobe 
} from '../../../shared/src/schemas';

export const wardrobeApi = {
  /**
   * Create a new wardrobe
   */
  async createWardrobe(data: CreateWardrobeInput): Promise<Wardrobe> {
    const response = await api.post('/wardrobes', data);
    return response.data.data.wardrobe;
  },
  
  /**
   * Get all wardrobes for the current user
   */
  async getWardrobes(): Promise<Wardrobe[]> {
    const response = await api.get('/wardrobes');
    return response.data.data.wardrobes;
  },
  
  /**
   * Get a specific wardrobe by ID, including its garments
   */
  async getWardrobe(id: string): Promise<Wardrobe> {
    const response = await api.get(`/wardrobes/${id}`);
    return response.data.data.wardrobe;
  },
  
  /**
   * Update a wardrobe's details
   */
  async updateWardrobe(id: string, data: UpdateWardrobeInput): Promise<Wardrobe> {
    const response = await api.put(`/wardrobes/${id}`, data);
    return response.data.data.wardrobe;
  },
  
  /**
   * Add a garment to a wardrobe
   */
  async addGarmentToWardrobe(wardrobeId: string, data: AddGarmentToWardrobeInput): Promise<void> {
    await api.post(`/wardrobes/${wardrobeId}/items`, data);
  },
  
  /**
   * Remove a garment from a wardrobe
   */
  async removeGarmentFromWardrobe(wardrobeId: string, garmentId: string): Promise<void> {
    await api.delete(`/wardrobes/${wardrobeId}/items/${garmentId}`);
  },
  
  /**
   * Delete a wardrobe
   */
  async deleteWardrobe(id: string): Promise<void> {
    await api.delete(`/wardrobes/${id}`);
  }
};