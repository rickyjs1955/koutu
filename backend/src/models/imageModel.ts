// /backend/src/models/imageModel.ts
import { query } from './db';
import { v4 as uuidv4 } from 'uuid';

export interface Image {
  id: string;
  user_id: string;
  file_path: string;
  original_metadata: Record<string, any>;
  upload_date: Date;
  status: 'new' | 'processed' | 'labeled';
}

export interface CreateImageInput {
  user_id: string;
  file_path: string;
  original_metadata?: Record<string, any>;
}

export const imageModel = {
  async create(data: CreateImageInput): Promise<Image> {
    const { user_id, file_path, original_metadata = {} } = data;
    const id = uuidv4();
    
    const result = await query(
      `INSERT INTO original_images 
       (id, user_id, file_path, original_metadata, upload_date, status) 
       VALUES ($1, $2, $3, $4, NOW(), 'new') 
       RETURNING *`,
      [id, user_id, file_path, JSON.stringify(original_metadata)]
    );
    
    return result.rows[0];
  },
  
  async findById(id: string): Promise<Image | null> {
    const result = await query(
      'SELECT * FROM original_images WHERE id = $1',
      [id]
    );
    
    return result.rows[0] || null;
  },
  
  async findByUserId(userId: string): Promise<Image[]> {
    const result = await query(
      'SELECT * FROM original_images WHERE user_id = $1 ORDER BY upload_date DESC',
      [userId]
    );
    
    return result.rows;
  },
  
  async updateStatus(id: string, status: 'new' | 'processed' | 'labeled'): Promise<Image | null> {
    const result = await query(
      'UPDATE original_images SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    return result.rows[0] || null;
  },
  
  async delete(id: string): Promise<boolean> {
    const result = await query(
      'DELETE FROM original_images WHERE id = $1',
      [id]
    );
    
    return (result.rowCount ?? 0) > 0;
  }
};