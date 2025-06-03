// /backend/src/models/polygonModel.ts
import { query } from './db';
import { v4 as uuidv4 } from 'uuid';
import { CreatePolygonInput, UpdatePolygonInput, Polygon } from '../../../shared/src/schemas/polygon';

// Helper function to safely parse JSON or return the value if already parsed
const safeJsonParse = (value: any): any => {
  if (typeof value === 'string') {
    try {
      return JSON.parse(value);
    } catch (e) {
      return value;
    }
  }
  // If it's already an object (as JSONB returns), return as-is
  return value;
};

export const polygonModel = {
    /**
     * Create a new polygon
     */
    async create(data: CreatePolygonInput & { user_id: string }): Promise<Polygon> {
        const { user_id, original_image_id, points, label, metadata = {} } = data;
        const id = uuidv4();
        
        const result = await query(
        `INSERT INTO polygons 
        (id, user_id, original_image_id, points, label, metadata, created_at, updated_at) 
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW()) 
        RETURNING *`,
        [
            id, 
            user_id, 
            original_image_id,
            JSON.stringify(points),
            label || null,
            JSON.stringify(metadata)
        ]
        );
        
        // Transform the database record to match the schema
        const polygon = result.rows[0];
        return {
        ...polygon,
        points: safeJsonParse(polygon.points),
        metadata: safeJsonParse(polygon.metadata)
        };
    },
    
    /**
     * Find a polygon by ID
     */
    async findById(id: string): Promise<Polygon | null> {
        const result = await query(
        'SELECT * FROM polygons WHERE id = $1',
        [id]
        );
        
        if (result.rows.length === 0) {
        return null;
        }
        
        // Transform the database record to match the schema
        const polygon = result.rows[0];
        return {
        ...polygon,
        points: safeJsonParse(polygon.points),
        metadata: safeJsonParse(polygon.metadata)
        };
    },
    
    /**
     * Find all polygons for an image
     */
    async findByImageId(imageId: string): Promise<Polygon[]> {
        const result = await query(
        'SELECT * FROM polygons WHERE original_image_id = $1 ORDER BY created_at ASC',
        [imageId]
        );
        
        // Transform the database records to match the schema
        return result.rows.map(polygon => ({
        ...polygon,
        points: safeJsonParse(polygon.points),
        metadata: safeJsonParse(polygon.metadata)
        }));
    },
    
    /**
     * Find all polygons for a user
     */
    async findByUserId(userId: string): Promise<Polygon[]> {
        const result = await query(
        'SELECT * FROM polygons WHERE user_id = $1 ORDER BY created_at DESC',
        [userId]
        );
        
        // Transform the database records to match the schema
        return result.rows.map(polygon => ({
        ...polygon,
        points: safeJsonParse(polygon.points),
        metadata: safeJsonParse(polygon.metadata)
        }));
    },
    
    /**
     * Update a polygon
     */
    async update(id: string, updates: UpdatePolygonInput): Promise<Polygon | null> {
        try {
            // Build the SET clause dynamically based on what's being updated
            const setClauses = [];
            const values = [];
            let paramIndex = 1;

            if (updates.points !== undefined) {
                setClauses.push(`points = $${paramIndex}`);
                values.push(JSON.stringify(updates.points));
                paramIndex++;
            }

            if (updates.label !== undefined) {
                setClauses.push(`label = $${paramIndex}`);
                values.push(updates.label);
                paramIndex++;
            }

            if (updates.metadata !== undefined) {
                setClauses.push(`metadata = $${paramIndex}`);
                values.push(JSON.stringify(updates.metadata));
                paramIndex++;
            }

            // Always update the updated_at timestamp
            setClauses.push(`updated_at = NOW()`);

            if (setClauses.length === 1) {
                // Only updated_at would be set, meaning no actual updates
                // Just return the current polygon
                return await this.findById(id);
            }

            // Add the id parameter for the WHERE clause
            values.push(id);

            const result = await query(
                `UPDATE polygons 
                 SET ${setClauses.join(', ')} 
                 WHERE id = $${paramIndex} 
                 RETURNING *`,
                values
            );

            if (result.rows.length === 0) {
                return null;
            }

            // Transform the database record to match the schema
            const polygon = result.rows[0];
            return {
                ...polygon,
                points: safeJsonParse(polygon.points),
                metadata: safeJsonParse(polygon.metadata)
            };
        } catch (error) {
            console.error('Error updating polygon:', error);
            throw error;
        }
    },
    
    /**
     * Delete a polygon
     */
    async delete(id: string): Promise<boolean> {
        const result = await query(
        'DELETE FROM polygons WHERE id = $1',
        [id]
        );
        
        return (result.rowCount ?? 0) > 0;
    },
    
    /**
     * Delete all polygons for an image
     */
    async deleteByImageId(imageId: string): Promise<number> {
        const result = await query(
        'DELETE FROM polygons WHERE original_image_id = $1',
        [imageId]
        );
        
        return result.rowCount ?? 0;
    }
};