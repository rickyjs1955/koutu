// /backend/src/utils/testGarmentModel.ts
/**
 * Test Garment Model Utility
 * 
 * @description Provides simplified garment creation and management for integration tests.
 * This utility creates garments with minimal required data for testing wardrobe functionality.
 * 
 * @author Development Team
 * @version 1.0.0
 * @since June 10, 2025
 */

import { TestDatabaseConnection } from './testDatabaseConnection';
import { v4 as uuidv4 } from 'uuid';

export interface TestGarment {
  id: string;
  user_id: string;
  original_image_id?: string;
  metadata: {
    name: string;
    category?: string;
    color?: string;
    brand?: string;
    size?: string;
    price?: number;
    tags?: string[];
    [key: string]: any;
  };
  created_at: Date;
  updated_at: Date;
}

export interface CreateTestGarmentInput {
  user_id: string;
  original_image_id?: string;
  metadata: {
    name: string;
    category?: string;
    color?: string;
    brand?: string;
    size?: string;
    price?: number;
    tags?: string[];
    [key: string]: any;
  };
}

/**
 * Test Garment Model for integration testing
 * Provides simplified garment operations for testing wardrobe functionality
 */
export const testGarmentModel = {
  /**
   * Creates a test garment with minimal required data
   * @param data - Garment creation data
   * @returns Promise resolving to created garment
   */
  async create(data: CreateTestGarmentInput): Promise<TestGarment> {
    const {
      user_id,
      original_image_id = null,
      metadata
    } = data;
    
    const id = uuidv4();
    
    // Create a basic garment record
    const result = await TestDatabaseConnection.query(
      `INSERT INTO garment_items 
       (id, user_id, original_image_id, metadata, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, NOW(), NOW()) 
       RETURNING *`,
      [id, user_id, original_image_id, JSON.stringify(metadata)]
    );
    
    const garment = result.rows[0];
    
    return {
      id: garment.id,
      user_id: garment.user_id,
      original_image_id: garment.original_image_id,
      metadata: typeof garment.metadata === 'string' 
        ? JSON.parse(garment.metadata) 
        : garment.metadata,
      created_at: garment.created_at,
      updated_at: garment.updated_at
    };
  },

  /**
   * Finds a garment by ID
   * @param id - Garment ID
   * @returns Promise resolving to garment or null
   */
  async findById(id: string): Promise<TestGarment | null> {
    const result = await TestDatabaseConnection.query(
      'SELECT * FROM garment_items WHERE id = $1',
      [id]
    );
    
    if (result.rows.length === 0) {
      return null;
    }
    
    const garment = result.rows[0];
    return {
      id: garment.id,
      user_id: garment.user_id,
      original_image_id: garment.original_image_id,
      metadata: typeof garment.metadata === 'string' 
        ? JSON.parse(garment.metadata) 
        : garment.metadata,
      created_at: garment.created_at,
      updated_at: garment.updated_at
    };
  },

  /**
   * Finds all garments for a user
   * @param userId - User ID
   * @returns Promise resolving to array of garments
   */
  async findByUserId(userId: string): Promise<TestGarment[]> {
    const result = await TestDatabaseConnection.query(
      'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at',
      [userId]
    );
    
    return result.rows.map((garment: any) => ({
      id: garment.id,
      user_id: garment.user_id,
      original_image_id: garment.original_image_id,
      metadata: typeof garment.metadata === 'string' 
        ? JSON.parse(garment.metadata) 
        : garment.metadata,
      created_at: garment.created_at,
      updated_at: garment.updated_at
    }));
  },

  /**
   * Updates a garment's metadata
   * @param id - Garment ID
   * @param metadata - New metadata
   * @returns Promise resolving to updated garment or null
   */
  async updateMetadata(id: string, metadata: any): Promise<TestGarment | null> {
    const result = await TestDatabaseConnection.query(
      `UPDATE garment_items 
       SET metadata = $1, updated_at = NOW() 
       WHERE id = $2 
       RETURNING *`,
      [JSON.stringify(metadata), id]
    );
    
    if (result.rows.length === 0) {
      return null;
    }
    
    const garment = result.rows[0];
    return {
      id: garment.id,
      user_id: garment.user_id,
      original_image_id: garment.original_image_id,
      metadata: typeof garment.metadata === 'string' 
        ? JSON.parse(garment.metadata) 
        : garment.metadata,
      created_at: garment.created_at,
      updated_at: garment.updated_at
    };
  },

  /**
   * Deletes a garment
   * @param id - Garment ID
   * @returns Promise resolving to true if deleted, false otherwise
   */
  async delete(id: string): Promise<boolean> {
    // First, remove from any wardrobes
    await TestDatabaseConnection.query(
      'DELETE FROM wardrobe_items WHERE garment_item_id = $1',
      [id]
    );
    
    // Then delete the garment
    const result = await TestDatabaseConnection.query(
      'DELETE FROM garment_items WHERE id = $1',
      [id]
    );
    
    return (result.rowCount ?? 0) > 0;
  },

  /**
   * Creates multiple test garments for a user
   * @param userId - User ID
   * @param count - Number of garments to create
   * @param baseMetadata - Base metadata to use (will be varied)
   * @returns Promise resolving to array of created garments
   */
  async createMultiple(
    userId: string, 
    count: number, 
    baseMetadata: Partial<CreateTestGarmentInput['metadata']> = {}
  ): Promise<TestGarment[]> {
    const categories = ['shirt', 'pants', 'jacket', 'dress', 'shoes', 'accessories'];
    const colors = ['blue', 'red', 'green', 'black', 'white', 'gray', 'navy', 'brown'];
    const brands = ['TestBrand', 'BrandA', 'BrandB', 'BrandC', 'Premium', 'Casual'];
    const sizes = ['XS', 'S', 'M', 'L', 'XL', 'XXL'];
    
    const garments: TestGarment[] = [];
    
    for (let i = 0; i < count; i++) {
      const metadata = {
        name: `Test Garment ${i + 1}`,
        category: categories[i % categories.length],
        color: colors[i % colors.length],
        brand: brands[i % brands.length],
        size: sizes[i % sizes.length],
        price: parseFloat((19.99 + (i * 10)).toFixed(2)),
        tags: [`tag${i}`, `category-${categories[i % categories.length]}`],
        ...baseMetadata
      };
      
      const garment = await this.create({
        user_id: userId,
        metadata
      });
      
      garments.push(garment);
    }
    
    return garments;
  },

  /**
   * Cleans up all test garments for a user
   * @param userId - User ID
   * @returns Promise resolving to number of deleted garments
   */
  async cleanupByUserId(userId: string): Promise<number> {
    // First, remove all wardrobe associations
    await TestDatabaseConnection.query(
      `DELETE FROM wardrobe_items 
       WHERE garment_item_id IN (
         SELECT id FROM garment_items WHERE user_id = $1
       )`,
      [userId]
    );
    
    // Then delete the garments
    const result = await TestDatabaseConnection.query(
      'DELETE FROM garment_items WHERE user_id = $1',
      [userId]
    );
    
    return result.rowCount ?? 0;
  },

  /**
   * Creates garments with specific properties for testing
   * @param userId - User ID
   * @param specifications - Array of specific garment specifications
   * @returns Promise resolving to array of created garments
   */
  async createWithSpecifications(
    userId: string,
    specifications: Array<{
      name: string;
      category?: string;
      color?: string;
      metadata?: any;
    }>
  ): Promise<TestGarment[]> {
    const garments: TestGarment[] = [];
    
    for (const spec of specifications) {
      const metadata = {
        name: spec.name,
        category: spec.category || 'shirt',
        color: spec.color || 'blue',
        brand: 'TestBrand',
        size: 'M',
        price: 29.99,
        ...spec.metadata
      };
      
      const garment = await this.create({
        user_id: userId,
        metadata
      });
      
      garments.push(garment);
    }
    
    return garments;
  },

  /**
   * Gets garment count for a user
   * @param userId - User ID
   * @returns Promise resolving to garment count
   */
  async getCountByUserId(userId: string): Promise<number> {
    const result = await TestDatabaseConnection.query(
      'SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1',
      [userId]
    );
    
    return parseInt(result.rows[0].count);
  },

  /**
   * Verifies garment exists in database
   * @param garmentId - Garment ID
   * @returns Promise resolving to true if exists, false otherwise
   */
  async exists(garmentId: string): Promise<boolean> {
    const result = await TestDatabaseConnection.query(
      'SELECT 1 FROM garment_items WHERE id = $1',
      [garmentId]
    );
    
    return result.rows.length > 0;
  }
};