// /backend/src/models/garmentModel.ts
import { v4 as uuidv4, validate as isUuid } from 'uuid';
import { getQueryFunction } from '../utils/modelUtils';

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
    
    const db = getQueryFunction();
    const result = await db(
      `INSERT INTO garment_items 
       (id, user_id, original_image_id, file_path, mask_path, metadata, created_at, updated_at, data_version) 
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), 1) 
       RETURNING *`,
      [id, user_id, original_image_id, file_path, mask_path, JSON.stringify(metadata)]
    );
    
    return result.rows[0];
  },
  
  async findById(id: string): Promise<Garment | null> {
    // Add UUID validation
    if (!isUuid(id)) {
      return null; // Early return for invalid UUID format
    }

    const db = getQueryFunction();
    const result = await db(
      'SELECT * FROM garment_items WHERE id = $1',
      [id]
    );
    
    return result.rows[0] || null;
  },
  
  async findByUserId(userId: string): Promise<Garment[]> {
    const db = getQueryFunction();
    const result = await db(
      'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );
    
    return result.rows;
  },
  
  async updateMetadata(
    id: string, 
    data: UpdateGarmentMetadataInput, 
    options = { replace: false }
  ): Promise<Garment | null> {
    // Add UUID validation
    if (!isUuid(id)) {
      return null; // Early return for invalid UUID
    }

    // Validate metadata format
    if (typeof data.metadata !== 'object' || data.metadata === null || Array.isArray(data.metadata)) {
      // Only log in non-test environments
      if (process.env.NODE_ENV !== 'test') {
        console.error('Invalid metadata format for update');
      }
      return null;
    }

    const garment = await this.findById(id);
    if (!garment) {
      return null;
    }
    
    // Either merge or replace based on options
    const updatedMetadata = options.replace 
      ? { ...data.metadata }
      : { ...garment.metadata, ...data.metadata };
    
    const db = getQueryFunction();
    const result = await db(
      `UPDATE garment_items 
      SET metadata = $1, updated_at = NOW(), data_version = data_version + 1 
      WHERE id = $2 
      RETURNING *`,
      [JSON.stringify(updatedMetadata), id]
    );
    
    return result.rows[0] || null;
  },
  
  async delete(id: string): Promise<boolean> {
    // Add UUID validation
    if (!isUuid(id)) {
      return false; // Early return for invalid UUID
    }

    const db = getQueryFunction();
    const result = await db(
      'DELETE FROM garment_items WHERE id = $1',
      [id]
    );
    
    return (result.rowCount ?? 0) > 0;
  }
};