// /backend/src/models/wardrobeModel.ts - FIXED with UUID validation and error handling
import { query } from './db';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

export interface Wardrobe {
  id: string;
  user_id: string;
  name: string;
  description: string;
  is_default: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface CreateWardrobeInput {
  user_id: string;
  name: string;
  description?: string;
  is_default?: boolean;
}

export interface UpdateWardrobeInput {
  name?: string;
  description?: string;
  is_default?: boolean;
}

export const wardrobeModel = {
  async create(data: CreateWardrobeInput): Promise<Wardrobe> {
    const { user_id, name, description = '', is_default = false } = data;
    const id = uuidv4();
    
    const result = await query(
      `INSERT INTO wardrobes 
       (id, user_id, name, description, is_default, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) 
       RETURNING *`,
      [id, user_id, name, description, is_default]
    );
    
    return result.rows[0];
  },
  
  async findById(id: string): Promise<Wardrobe | null> {
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
    // Add UUID validation for update method
    if (!id || !isUuid(id)) {
      return null;
    }
    
    const { name, description, is_default } = data;
    
    let queryText = 'UPDATE wardrobes SET updated_at = NOW()';
    const queryParams: any[] = [];
    let paramIndex = 1;
    
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
    
    if (is_default !== undefined) {
      queryText += `, is_default = $${paramIndex}`;
      queryParams.push(is_default);
      paramIndex++;
    }
    
    queryText += ` WHERE id = $${paramIndex} RETURNING *`;
    queryParams.push(id);
    
    const result = await query(queryText, queryParams);
    
    return result.rows[0] || null;
  },
  
  async delete(id: string): Promise<boolean> {
    // Add UUID validation to prevent database errors
    if (!id || !isUuid(id)) {
      return false;
    }
    
    try {
      // First, delete all associated wardrobe items
      await query('DELETE FROM wardrobe_items WHERE wardrobe_id = $1', [id]);
    } catch (error) {
      // If the wardrobe_items table doesn't exist or there's another error, 
      // we should still try to delete the wardrobe
      console.warn('Error deleting wardrobe items:', error instanceof Error ? error.message : String(error));
    }
    
    try {
      const result = await query(
        'DELETE FROM wardrobes WHERE id = $1',
        [id]
      );
      
      return (result.rowCount ?? 0) > 0;
    } catch (error) {
      // Re-throw database errors for the wardrobe deletion
      throw error;
    }
  },
  
  async addGarment(
    wardrobeId: string, 
    garmentId: string, 
    position: number = 0,
    options: { allowUpdate?: boolean } = { allowUpdate: true }
  ): Promise<boolean> {
    try {
      // Check if the garment is already in the wardrobe
      const existingItem = await query(
        'SELECT * FROM wardrobe_items WHERE wardrobe_id = $1 AND garment_item_id = $2',
        [wardrobeId, garmentId]
      );
      
      if (existingItem.rows.length > 0) {
        if (options.allowUpdate) {
          // Update the position if the garment is already in the wardrobe (old behavior)
          await query(
            'UPDATE wardrobe_items SET position = $1, updated_at = NOW() WHERE wardrobe_id = $2 AND garment_item_id = $3',
            [position, wardrobeId, garmentId]
          );
          return true;
        } else {
          // Throw an error for strict duplicate prevention (new behavior)
          throw new Error('Garment already in wardrobe');
        }
      }
      
      // Add the garment to the wardrobe
      await query(
        'INSERT INTO wardrobe_items (wardrobe_id, garment_item_id, position, created_at, updated_at) VALUES ($1, $2, $3, NOW(), NOW())',
        [wardrobeId, garmentId, position]
      );
      
      return true;
    } catch (error) {
      if (error instanceof Error && error.message.includes('wardrobe_items') && error.message.includes('does not exist')) {
        throw new Error('wardrobe_items table not found - please create the table first');
      }
      // Re-throw the error (including our "Garment already in wardrobe" error)
      throw error;
    }
},
  
  async removeGarment(wardrobeId: string, garmentId: string): Promise<boolean> {
    try {
      const result = await query(
        'DELETE FROM wardrobe_items WHERE wardrobe_id = $1 AND garment_item_id = $2',
        [wardrobeId, garmentId]
      );
      
      return (result.rowCount ?? 0) > 0;
    } catch (error) {
      if (error instanceof Error && error.message.includes('wardrobe_items') && error.message.includes('does not exist')) {
        throw new Error('wardrobe_items table not found - please create the table first');
      }
      throw error;
    }
  },
  
  async getGarments(wardrobeId: string): Promise<any[]> {
    try {
      const result = await query(
        `SELECT g.*, wi.position 
         FROM garment_items g
         JOIN wardrobe_items wi ON g.id = wi.garment_item_id
         WHERE wi.wardrobe_id = $1
         ORDER BY wi.position`,
        [wardrobeId]
      );
      
      return result.rows;
    } catch (error) {
      if (error instanceof Error && error.message.includes('wardrobe_items') && error.message.includes('does not exist')) {
        throw new Error('wardrobe_items table not found - please create the table first');
      }
      throw error;
    }
  }
};