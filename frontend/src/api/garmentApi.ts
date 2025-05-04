// /frontend/src/api/garmentApi.ts
import axios from 'axios';
import { 
  CreateGarmentInput, 
  GarmentResponse, 
  UpdateGarmentMetadata
} from '../../../shared/src/schemas/garment';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api/v1';

// Axios instance with auth header
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const garmentApi = {
  async createGarment(data: CreateGarmentInput): Promise<GarmentResponse> {
    const response = await api.post('/garments/create', data);
    return response.data.data.garment;
  },
  
  async getGarments(): Promise<GarmentResponse[]> {
    const response = await api.get('/garments');
    return response.data.data.garments;
  },
  
  async getGarment(id: string): Promise<GarmentResponse> {
    const response = await api.get(`/garments/${id}`);
    return response.data.data.garment;
  },
  
  async updateGarmentMetadata(id: string, data: UpdateGarmentMetadata): Promise<GarmentResponse> {
    const response = await api.put(`/garments/${id}/metadata`, data);
    return response.data.data.garment;
  },
  
  async deleteGarment(id: string): Promise<void> {
    await api.delete(`/garments/${id}`);
  }
};