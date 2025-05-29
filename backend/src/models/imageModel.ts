// /backend/src/models/imageModel.ts
import { query } from './db';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

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

export interface ImageQueryOptions {
  status?: 'new' | 'processed' | 'labeled';
  limit?: number;
  offset?: number;
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
    // Validate UUID format
    if (!isUuid(id)) {
      return null;
    }
    
    const result = await query(
      'SELECT * FROM original_images WHERE id = $1',
      [id]
    );
    
    return result.rows[0] || null;
  },
  
  async findByUserId(userId: string, options: ImageQueryOptions = {}): Promise<Image[]> {
    let queryText = 'SELECT * FROM original_images WHERE user_id = $1';
    const queryParams: any[] = [userId];
    let paramIndex = 2;
    
    // Add status filter if provided
    if (options.status) {
      queryText += ` AND status = $${paramIndex}`;
      queryParams.push(options.status);
      paramIndex++;
    }
    
    // Add ordering
    queryText += ' ORDER BY upload_date DESC';
    
    // Add pagination
    if (options.limit) {
      queryText += ` LIMIT $${paramIndex}`;
      queryParams.push(options.limit);
      paramIndex++;
    }
    
    if (options.offset) {
      queryText += ` OFFSET $${paramIndex}`;
      queryParams.push(options.offset);
    }
    
    const result = await query(queryText, queryParams);
    return result.rows;
  },
  
  async updateStatus(id: string, status: 'new' | 'processed' | 'labeled'): Promise<Image | null> {
    // Validate UUID format
    if (!isUuid(id)) {
      return null;
    }
    
    const result = await query(
      'UPDATE original_images SET status = $1 WHERE id = $2 RETURNING *',
      [status, id]
    );
    
    return result.rows[0] || null;
  },
  
  async delete(id: string): Promise<boolean> {
    // Validate UUID format
    if (!isUuid(id)) {
      return false;
    }
    
    const result = await query(
      'DELETE FROM original_images WHERE id = $1',
      [id]
    );
    
    return (result.rowCount ?? 0) > 0;
  },
  
  /**
   * Find garments that depend on this image
   * Used to prevent deletion of images that are in use
   */
  async findDependentGarments(imageId: string): Promise<any[]> {
    // Validate UUID format
    if (!isUuid(imageId)) {
      return [];
    }
    
    const result = await query(
      'SELECT id, user_id FROM garment_items WHERE original_image_id = $1',
      [imageId]
    );
    
    return result.rows;
  },
  
  /**
   * Find polygons that depend on this image
   * Used to check image usage
   */
  async findDependentPolygons(imageId: string): Promise<any[]> {
    // Validate UUID format
    if (!isUuid(imageId)) {
      return [];
    }
    
    const result = await query(
      'SELECT id, user_id FROM polygons WHERE original_image_id = $1',
      [imageId]
    );
    
    return result.rows;
  },
  
  /**
   * Get image statistics for a user
   */
  async getUserImageStats(userId: string): Promise<{
    total: number;
    byStatus: Record<string, number>;
    totalSize: number;
    averageSize: number;
  }> {
    const result = await query(
      `SELECT 
        COUNT(*) as total,
        status,
        SUM((original_metadata->>'size')::bigint) as total_size,
        AVG((original_metadata->>'size')::bigint) as average_size
       FROM original_images 
       WHERE user_id = $1 
       GROUP BY status`,
      [userId]
    );
    
    const stats = {
      total: 0,
      byStatus: {} as Record<string, number>,
      totalSize: 0,
      averageSize: 0
    };
    
    let totalSizeSum = 0;
    let totalCount = 0;
    
    result.rows.forEach(row => {
      const count = parseInt(row.total, 10);
      stats.byStatus[row.status] = count;
      stats.total += count;
      
      if (row.total_size) {
        totalSizeSum += parseInt(row.total_size, 10);
        totalCount += count;
      }
    });
    
    stats.totalSize = totalSizeSum;
    stats.averageSize = totalCount > 0 ? Math.round(totalSizeSum / totalCount) : 0;
    
    return stats;
  },
  
  /**
   * Update image metadata
   */
  async updateMetadata(id: string, metadata: Record<string, any>): Promise<Image | null> {
    // Validate UUID format
    if (!isUuid(id)) {
      return null;
    }
        
    const result = await query(
      'UPDATE original_images SET original_metadata = $1 WHERE id = $2 RETURNING *',
      [JSON.stringify(metadata), id]
    );
    
    return result.rows[0] || null;
  },
  
  /**
   * Find images by file path (for cleanup operations)
   */
  async findByFilePath(filePath: string): Promise<Image[]> {
    const result = await query(
      'SELECT * FROM original_images WHERE file_path = $1',
      [filePath]
    );
    
    return result.rows;
  },
  
  /**
   * Batch update status for multiple images
   * FIXED: Added $ prefix to placeholders
   */
  async batchUpdateStatus(imageIds: string[], status: 'new' | 'processed' | 'labeled'): Promise<number> {
    // Validate all UUIDs
    const validIds = imageIds.filter(id => isUuid(id));
    
    if (validIds.length === 0) {
      return 0;
    }
    
    // FIXED: Add $ prefix to placeholders
    const placeholders = validIds.map((_, index) => `${index + 2}`).join(',');
    const result = await query(
      `UPDATE original_images SET status = $1 WHERE id IN (${placeholders})`,
      [status, ...validIds]
    );
    
    return result.rowCount ?? 0;
  }
};