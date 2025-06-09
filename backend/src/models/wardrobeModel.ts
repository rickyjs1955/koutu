// /backend/src/models/wardrobeModel.ts - FIXED with UUID validation
import { query } from './db';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

export interface Wardrobe {
  id: string;
  user_id: string;
  name: string;
  description: string;
  created_at: Date;
  updated_at: Date;
}

export interface CreateWardrobeInput {
  user_id: string;
  name: string;
  description?: string;
}

export interface UpdateWardrobeInput {
  name?: string;
  description?: string;
}

export const wardrobeModel = {
  async create(data: CreateWardrobeInput): Promise<Wardrobe> {
    const { user_id, name, description = '' } = data;
    const id = uuidv4();
    
    const result = await query(
      `INSERT INTO wardrobes 
       (id, user_id, name, description, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, NOW(), NOW()) 
       RETURNING *`,
      [id, user_id, name, description]
    );
    
    return result.rows[0];
  },
  
  async findById(id: string): Promise<Wardrobe | null> {
    // Add UUID validation - return null for invalid UUIDs without querying DB
    if (!id || !isUuid(id)) {
      return null;
    }
    
    const result = await query(
      'SELECT * FROM wardrobes WHERE id = $1',
      [id]
    );
    
    return result.rows[0] || null;
  },
  
  async findByUserId(userId: string): Promise<Wardrobe[]> {
    const result = await query(
      'SELECT * FROM wardrobes WHERE user_id = $1 ORDER BY name',
      [userId]
    );
    
    return result.rows;
  },
  
  async update(id: string, data: UpdateWardrobeInput): Promise<Wardrobe | null> {
    const { name, description } = data;
    
    // Start building the query
    let queryText = 'UPDATE wardrobes SET updated_at = NOW()';
    const queryParams: any[] = [];
    let paramIndex = 1;
    
    // Add fields to update
    if (name !== undefined) {
      queryText += `, name = $${paramIndex}`;
      queryParams.push(name);
      paramIndex++;
    }
    
    if (description !== undefined) {
      queryText += `, description = $${paramIndex}`;
      queryParams.push(description);
      paramIndex++;
    }
    
    // Add WHERE clause
    queryText += ` WHERE id = $${paramIndex} RETURNING *`;
    queryParams.push(id);
    
    const result = await query(queryText, queryParams);
    
    return result.rows[0] || null;
  },
  
  async delete(id: string): Promise<boolean> {
    // First, delete all associated wardrobe items
    await query('DELETE FROM wardrobe_items WHERE wardrobe_id = $1', [id]);
    
    // Then delete the wardrobe
    const result = await query(
      'DELETE FROM wardrobes WHERE id = $1',
      [id]
    );
    
    return (result.rowCount ?? 0) > 0;
  },
  
  async addGarment(wardrobeId: string, garmentId: string, position: number = 0): Promise<boolean> {
    // Check if the garment is already in the wardrobe
    const existingItem = await query(
      'SELECT * FROM wardrobe_items WHERE wardrobe_id = $1 AND garment_item_id = $2',
      [wardrobeId, garmentId]
    );
    
    if (existingItem.rows.length > 0) {
      // Update the position if the garment is already in the wardrobe
      await query(
        'UPDATE wardrobe_items SET position = $1 WHERE wardrobe_id = $2 AND garment_item_id = $3',
        [position, wardrobeId, garmentId]
      );
    } else {
      // Add the garment to the wardrobe
      await query(
        'INSERT INTO wardrobe_items (wardrobe_id, garment_item_id, position) VALUES ($1, $2, $3)',
        [wardrobeId, garmentId, position]
      );
    }
    
    return true;
  },
  
  async removeGarment(wardrobeId: string, garmentId: string): Promise<boolean> {
    const result = await query(
      'DELETE FROM wardrobe_items WHERE wardrobe_id = $1 AND garment_item_id = $2',
      [wardrobeId, garmentId]
    );
    
    return (result.rowCount ?? 0) > 0;
  },
  
  async getGarments(wardrobeId: string): Promise<any[]> {
    const result = await query(
      `SELECT g.*, wi.position 
       FROM garment_items g
       JOIN wardrobe_items wi ON g.id = wi.garment_item_id
       WHERE wi.wardrobe_id = $1
       ORDER BY wi.position`,
      [wardrobeId]
    );
    
    return result.rows;
  }
};