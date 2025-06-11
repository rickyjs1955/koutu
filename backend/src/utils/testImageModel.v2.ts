// /backend/src/utils/testImageModel.v2.ts - DUAL-MODE VERSION
/**
 * Dual-Mode Test Image Model
 * 
 * This version automatically uses the correct database connection based on
 * the dual-mode infrastructure (Docker vs Manual).
 * 
 * Maintains identical API to original testImageModel.ts but uses the
 * dockerMigrationHelper to select the appropriate database connection.
 * 
 * @author Development Team
 * @version 2.0.0 - Dual-Mode Support
 * @since June 11, 2025
 */

import { getTestDatabaseConnection } from './dockerMigrationHelper';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

export interface TestImage {
    id: string;
    user_id: string;
    file_path: string;
    original_metadata: Record<string, any>;
    upload_date: Date;
    status: 'new' | 'processed' | 'labeled';
}

export interface CreateTestImageInput {
    user_id: string;
    file_path: string;
    original_metadata?: Record<string, any>;
}

export interface TestImageQueryOptions {
    status?: 'new' | 'processed' | 'labeled';
    limit?: number;
    offset?: number;
}

// Helper function to validate UUID format
const isValidUUID = (uuid: string): boolean => {
    if (!uuid || typeof uuid !== 'string') return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
};

/**
 * Get the appropriate database connection for current mode
 */
const getDB = () => {
    return getTestDatabaseConnection();
};

export const testImageModel = {
    async create(data: CreateTestImageInput): Promise<TestImage> {
        const DB = getDB();
        const { user_id, file_path, original_metadata = {} } = data;
        
        // Validate required fields
        if (!user_id || !file_path) {
            throw new Error('user_id and file_path are required');
        }
        
        // Validate UUID format
        if (!isValidUUID(user_id)) {
            throw new Error('Invalid user_id format');
        }
        
        const id = uuidv4();
        
        const result = await DB.query(
            `INSERT INTO original_images 
            (id, user_id, file_path, original_metadata, upload_date, status) 
            VALUES ($1, $2, $3, $4, NOW(), 'new') 
            RETURNING *`,
            [id, user_id, file_path, JSON.stringify(original_metadata)]
        );
        
        return result.rows[0];
    },
    
    async findById(id: string): Promise<TestImage | null> {
        const DB = getDB();
        
        // Validate UUID format
        if (!id || !isValidUUID(id)) {
            return null;
        }
        
        try {
            const result = await DB.query(
                'SELECT * FROM original_images WHERE id = $1',
                [id]
            );
            
            return result.rows[0] || null;
        } catch (error) {
            // If it's a UUID format error, return null instead of throwing
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return null;
            }
            throw error;
        }
    },

    async findByUserId(userId: string, options: TestImageQueryOptions = {}): Promise<TestImage[]> {
        const DB = getDB();
        
        // Validate UUID format first
        if (!userId || !isValidUUID(userId)) {
            return [];
        }
        
        try {
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
            
            const result = await DB.query(queryText, queryParams);
            return result.rows;
        } catch (error) {
            // If it's a UUID format error, return empty array instead of throwing
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return [];
            }
            throw error;
        }
    },

    async updateStatus(id: string, status: 'new' | 'processed' | 'labeled'): Promise<TestImage | null> {
        const DB = getDB();
        
        // Validate UUID format
        if (!id || !isValidUUID(id)) {
            return null;
        }
        
        // Validate status
        if (!['new', 'processed', 'labeled'].includes(status)) {
            throw new Error('Invalid status value');
        }
        
        try {
            const result = await DB.query(
                'UPDATE original_images SET status = $1 WHERE id = $2 RETURNING *',
                [status, id]
            );
            
            return result.rows[0] || null;
        } catch (error) {
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return null;
            }
            throw error;
        }
    },
    
    async delete(id: string): Promise<boolean> {
        const DB = getDB();
        
        // Validate UUID format
        if (!id || !isValidUUID(id)) {
            return false;
        }
        
        try {
            const result = await DB.query(
                'DELETE FROM original_images WHERE id = $1',
                [id]
            );
            
            return (result.rowCount ?? 0) > 0;
        } catch (error) {
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return false;
            }
            throw error;
        }
    },
    
    async findDependentGarments(imageId: string): Promise<any[]> {
        const DB = getDB();
        
        // Validate UUID format
        if (!imageId || !isValidUUID(imageId)) {
            return [];
        }
        
        try {
            const result = await DB.query(
                'SELECT id, user_id FROM garment_items WHERE original_image_id = $1',
                [imageId]
            );
            
            return result.rows;
        } catch (error) {
            // If table doesn't exist or other error, return empty array
            return [];
        }
    },
    
    async findDependentPolygons(imageId: string): Promise<any[]> {
        const DB = getDB();
        
        // Validate UUID format
        if (!imageId || !isValidUUID(imageId)) {
            return [];
        }
        
        try {
            const result = await DB.query(
                'SELECT id, user_id FROM polygons WHERE original_image_id = $1',
                [imageId]
            );
            
            return result.rows;
        } catch (error) {
            // If table doesn't exist or other error, return empty array
            return [];
        }
    },
    
    async getUserImageStats(userId: string): Promise<{
        total: number;
        byStatus: Record<string, number>;
        totalSize: number;
        averageSize: number;
    }> {
        const DB = getDB();
        
        if (!userId || !isValidUUID(userId)) {
            return {
                total: 0,
                byStatus: {},
                totalSize: 0,
                averageSize: 0
            };
        }
        
        try {
            const result = await DB.query(
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
            
            interface StatsRow {
                total: string;
                status: string;
                total_size: string | null;
                average_size: string | null;
            }

            result.rows.forEach((row: StatsRow) => {
                const count: number = parseInt(row.total, 10);
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
        } catch (error) {
            return {
                total: 0,
                byStatus: {},
                totalSize: 0,
                averageSize: 0
            };
        }
    },
    
    async updateMetadata(id: string, metadata: Record<string, any>): Promise<TestImage | null> {
        const DB = getDB();
        
        // Validate UUID format
        if (!id || !isValidUUID(id)) {
            return null;
        }
        
        try {
            const result = await DB.query(
                'UPDATE original_images SET original_metadata = $1 WHERE id = $2 RETURNING *',
                [JSON.stringify(metadata), id]
            );
            
            return result.rows[0] || null;
        } catch (error) {
            if (error instanceof Error && error.message.includes('invalid input syntax for type uuid')) {
                return null;
            }
            throw error;
        }
    },
    
    async findByFilePath(filePath: string): Promise<TestImage[]> {
        const DB = getDB();
        
        if (!filePath) {
            return [];
        }
        
        const result = await DB.query(
            'SELECT * FROM original_images WHERE file_path = $1',
            [filePath]
        );
        
        return result.rows;
    },
    
    async batchUpdateStatus(imageIds: string[], status: 'new' | 'processed' | 'labeled'): Promise<number> {
        const DB = getDB();
        
        // Validate all UUIDs
        const validIds = imageIds.filter(id => isValidUUID(id));
        
        if (validIds.length === 0) {
            return 0;
        }
        
        // Validate status
        if (!['new', 'processed', 'labeled'].includes(status)) {
            throw new Error('Invalid status value');
        }
        
        try {
            const placeholders = validIds.map((_, index) => `$${index + 2}`).join(',');
            const result = await DB.query(
                `UPDATE original_images SET status = $1 WHERE id IN (${placeholders})`,
                [status, ...validIds]
            );
            
            return result.rowCount ?? 0;
        } catch (error) {
            console.error('Batch update error:', error);
            return 0;
        }
    },
    
    async countByUserId(userId: string): Promise<number> {
        const DB = getDB();
        
        if (!userId || !isValidUUID(userId)) {
            return 0;
        }
        
        try {
            const result = await DB.query(
                'SELECT COUNT(*) as count FROM original_images WHERE user_id = $1',
                [userId]
            );
            
            return parseInt(result.rows[0].count, 10);
        } catch (error) {
            return 0;
        }
    },
    
    async findByDateRange(userId: string, startDate: Date, endDate: Date): Promise<TestImage[]> {
        const DB = getDB();
        
        if (!userId || !isValidUUID(userId)) {
            return [];
        }
        
        const result = await DB.query(
            'SELECT * FROM original_images WHERE user_id = $1 AND upload_date BETWEEN $2 AND $3 ORDER BY upload_date DESC',
            [userId, startDate, endDate]
        );
        
        return result.rows;
    },
    
    async existsByUserAndPath(userId: string, filePath: string): Promise<boolean> {
        const DB = getDB();
        
        if (!userId || !isValidUUID(userId) || !filePath) {
            return false;
        }
        
        try {
            const result = await DB.query(
                'SELECT 1 FROM original_images WHERE user_id = $1 AND file_path = $2 LIMIT 1',
                [userId, filePath]
            );
            
            return result.rows.length > 0;
        } catch (error) {
            return false;
        }
    },
    
    async findMostRecent(userId: string): Promise<TestImage | null> {
        const DB = getDB();
        
        if (!userId || !isValidUUID(userId)) {
            return null;
        }
        
        try {
            const result = await DB.query(
                'SELECT * FROM original_images WHERE user_id = $1 ORDER BY upload_date DESC LIMIT 1',
                [userId]
            );
            
            return result.rows[0] || null;
        } catch (error) {
            return null;
        }
    },
    
    async deleteAllByUserId(userId: string): Promise<number> {
        const DB = getDB();
        
        if (!userId || !isValidUUID(userId)) {
            return 0;
        }
        
        try {
            const result = await DB.query(
                'DELETE FROM original_images WHERE user_id = $1',
                [userId]
            );
            
            return result.rowCount ?? 0;
        } catch (error) {
            return 0;
        }
    }
};