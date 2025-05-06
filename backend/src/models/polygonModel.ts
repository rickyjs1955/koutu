// /backend/src/models/polygonModel.ts
import { query } from './db';
import { v4 as uuidv4 } from 'uuid';
import { CreatePolygonInput, UpdatePolygonInput, Polygon } from '../../../shared/src/schemas/polygon';

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
        points: JSON.parse(polygon.points),
        metadata: JSON.parse(polygon.metadata)
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
        points: JSON.parse(polygon.points),
        metadata: JSON.parse(polygon.metadata)
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
        points: JSON.parse(polygon.points),
        metadata: JSON.parse(polygon.metadata)
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
        points: JSON.parse(polygon.points),
        metadata: JSON.parse(polygon.metadata)
        }));
    },
    
    /**
     * Update a polygon
     */
    async update(id: string, data: UpdatePolygonInput): Promise<Polygon | null> {
        const updates: string[] = [];
        const values: any[] = [];
        let paramIndex = 1;
        
        // Build update query based on provided fields
        if (data.points !== undefined) {
        updates.push(`points = $${paramIndex}`);
        values.push(JSON.stringify(data.points));
        paramIndex++;
        }
        
        if (data.label !== undefined) {
        updates.push(`label = $${paramIndex}`);
        values.push(data.label);
        paramIndex++;
        }
        
        if (data.metadata !== undefined) {
        updates.push(`metadata = $${paramIndex}`);
        values.push(JSON.stringify(data.metadata));
        paramIndex++;
        }
        
        // Add updated_at
        updates.push(`updated_at = NOW()`);
        
        // If no updates, return existing polygon
        if (updates.length === 0) {
        return this.findById(id);
        }
        
        // Add id to values
        values.push(id);
        
        const result = await query(
        `UPDATE polygons 
        SET ${updates.join(', ')} 
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
        points: JSON.parse(polygon.points),
        metadata: JSON.parse(polygon.metadata)
        };
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