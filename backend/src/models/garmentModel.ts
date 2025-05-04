// /backend/src/models/garmentModel.ts
import { query } from './db';
import { v4 as uuidv4 } from 'uuid';

export interface Garment {
  id: string;
  user_id: string;
  original_image_id: string;
  file_path: string;
  mask_path: string;
  metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
  data_version: number;
}

export interface CreateGarmentInput {
  user_id: string;
  original_image_id: string;
  file_path: string;
  mask_path: string;
  metadata?: Record<string, any>;
}

export interface UpdateGarmentMetadataInput {
  metadata: Record<string, any>;
}

export const garmentModel = {
  async create(data: CreateGarmentInput): Promise<Garment> {
    const { user_id, original_image_id, file_path, mask_path, metadata = {} } = data;
    const id = uuidv4();
    
    const result = await query(
      `INSERT INTO garment_items 
       (id, user_id, original_image_id, file_path, mask_path, metadata, created_at, updated_at, data_version) 
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), 1) 
       RETURNING *`,
      [id, user_id, original_image_id, file_path, mask_path, JSON.stringify(metadata)]
    );
    
    return result.rows[0];
  },
  
  async findById(id: string): Promise<Garment | null> {
    const result = await query(
      'SELECT * FROM garment_items WHERE id = $1',
      [id]
    );
    
    return result.rows[0] || null;
  },
  
  async findByUserId(userId: string): Promise<Garment[]> {
    const result = await query(
      'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    
    return result.rows;
  },
  
  async updateMetadata(id: string, data: UpdateGarmentMetadataInput): Promise<Garment | null> {
    const garment = await this.findById(id);
    if (!garment) return null;
    
    // Merge existing metadata with new metadata
    const updatedMetadata = {
      ...garment.metadata,
      ...data.metadata
    };
    
    const result = await query(
      `UPDATE garment_items 
       SET metadata = $1, updated_at = NOW(), data_version = data_version + 1 
       WHERE id = $2 
       RETURNING *`,
      [JSON.stringify(updatedMetadata), id]
    );
    
    return result.rows[0] || null;
  },
  
  async delete(id: string): Promise<boolean> {
    const result = await query(
      'DELETE FROM garment_items WHERE id = $1',
      [id]
    );
    
    return (result.rowCount ?? 0) > 0;
  }
};