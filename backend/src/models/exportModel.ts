// /backend/src/models/exportModel.ts - FIXED TypeScript Issues
import { query } from './db';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

export interface ExportBatchJob {
    id: string;
    user_id: string;
    status: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
    options: Record<string, any>;
    progress: number;
    total_items: number;
    processed_items: number;
    output_url?: string;
    error?: string;
    created_at: Date;
    updated_at: Date;
    completed_at?: Date;
    expires_at?: Date;
}

export interface CreateExportJobInput {
    user_id: string;
    status: 'pending' | 'processing';
    options: Record<string, any>;
    total_items?: number;
    expires_at?: Date;
}

export interface UpdateExportJobInput {
    status?: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
    progress?: number;
    total_items?: number;
    processed_items?: number;
    output_url?: string;
    error?: string;
    completed_at?: Date;
}

export interface ExportJobQueryOptions {
    status?: 'pending' | 'processing' | 'completed' | 'failed' | 'cancelled';
    limit?: number;
    offset?: number;
    includeExpired?: boolean;
}

export interface UserStats {
    total: number;
    byStatus: Record<string, number>;
    completedToday: number;
    totalProcessedItems: number;
    averageProcessingTime: number;
}

export const exportModel = {
    /**
     * Create a new export batch job
     */
    async create(data: CreateExportJobInput): Promise<ExportBatchJob> {
        const { user_id, status, options, total_items = 0, expires_at } = data;
        const id = uuidv4();
        
        // Default expiration: 7 days from creation
        const defaultExpiresAt = expires_at || new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        
        const result = await query(
        `INSERT INTO export_batch_jobs 
        (id, user_id, status, options, progress, total_items, processed_items, 
            created_at, updated_at, expires_at) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW(), $8) 
        RETURNING *`,
        [
            id, 
            user_id, 
            status, 
            JSON.stringify(options), 
            0, 
            total_items, 
            0,
            defaultExpiresAt
        ]
        );
        
        return this.transformDbRecord(result.rows[0]);
    },

    /**
     * Find export job by ID
     */
    async findById(id: string): Promise<ExportBatchJob | null> {
        if (!isUuid(id)) {
        return null;
        }

        const result = await query(
        'SELECT * FROM export_batch_jobs WHERE id = $1',
        [id]
        );
        
        if (result.rows.length === 0) {
        return null;
        }
        
        return this.transformDbRecord(result.rows[0]);
    },

    /**
     * Find export jobs by user ID
     */
    async findByUserId(userId: string, options: ExportJobQueryOptions = {}): Promise<ExportBatchJob[]> {
        let queryText = 'SELECT * FROM export_batch_jobs WHERE user_id = $1';
        const queryParams: any[] = [userId];
        let paramIndex = 2;

        // Add status filter
        if (options.status) {
        queryText += ` AND status = $${paramIndex}`;
        queryParams.push(options.status);
        paramIndex++;
        }

        // Filter expired jobs unless explicitly included
        if (!options.includeExpired) {
        queryText += ` AND (expires_at IS NULL OR expires_at > NOW())`;
        }

        // Add ordering
        queryText += ' ORDER BY created_at DESC';

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
        
        return result.rows.map(row => this.transformDbRecord(row));
    },

    /**
     * Update export job
     */
    async update(id: string, updateData: UpdateExportJobInput): Promise<ExportBatchJob | null> {
        // Validate UUID first - return early if invalid
        if (!isUuid(id)) {
            return null;
        }

        // Build dynamic update query only if we have valid data
        const updateFields = Object.entries(updateData).filter(([_, value]) => value !== undefined);
        
        if (updateFields.length === 0) {
            // No real updates, just return existing record
            return this.findById(id);
        }

        const setClause = updateFields.map(([key], index) => `${key} = $${index + 1}`).join(', ');
        const values = updateFields.map(([_, value]) => value);
        values.push(id); // Add id as last parameter

        const queryText = `
            UPDATE export_batch_jobs 
            SET ${setClause}, updated_at = NOW()
            WHERE id = $${values.length}
            RETURNING *
        `;

        const result = await query(queryText, values);
        
        // Now safely check result.rows
        if (!result || result.rows.length === 0) {
            return null;
        }

        return this.transformDbRecord(result.rows[0]);
    },

    /**
     * Delete export job
     */
    async delete(id: string): Promise<boolean> {
        if (!isUuid(id)) {
        return false;
        }

        const result = await query(
        'DELETE FROM export_batch_jobs WHERE id = $1',
        [id]
        );

        return (result.rowCount ?? 0) > 0;
    },

    /**
     * Find jobs by status
     */
    async findByStatus(status: string, limit?: number): Promise<ExportBatchJob[]> {
        let queryText = 'SELECT * FROM export_batch_jobs WHERE status = $1 ORDER BY created_at ASC';
        const queryParams: any[] = [status];

        if (limit) {
        queryText += ` LIMIT $2`;
        queryParams.push(limit);
        }

        const result = await query(queryText, queryParams);
        
        return result.rows.map(row => this.transformDbRecord(row));
    },

    /**
     * Find stale jobs (for cleanup)
     */
    async findStaleJobs(olderThanHours: number = 24): Promise<ExportBatchJob[]> {
        const cutoffTime = new Date(Date.now() - olderThanHours * 60 * 60 * 1000);

        const result = await query(
        `SELECT * FROM export_batch_jobs 
        WHERE status IN ('pending', 'processing') 
        AND created_at < $1 
        ORDER BY created_at ASC`,
        [cutoffTime]
        );

        return result.rows.map(row => this.transformDbRecord(row));
    },

    /**
     * Find expired jobs
     */
    async findExpiredJobs(): Promise<ExportBatchJob[]> {
        const result = await query(
        `SELECT * FROM export_batch_jobs 
        WHERE expires_at IS NOT NULL 
        AND expires_at < NOW() 
        AND status = 'completed'
        ORDER BY expires_at ASC`
        );

        return result.rows.map(row => this.transformDbRecord(row));
    },

    /**
     * Get user export statistics
     */
    async getUserStats(userId: string): Promise<UserStats> {
        // First query - get job statistics by status
        const statsQuery = `
            SELECT 
            COUNT(*) as total,
            status,
            COALESCE(SUM(processed_items), 0) as total_processed_items,
            AVG(CASE 
                WHEN status = 'completed' AND completed_at IS NOT NULL AND created_at IS NOT NULL 
                THEN EXTRACT(EPOCH FROM (completed_at - created_at))
                ELSE NULL 
            END) as avg_processing_seconds
            FROM export_batch_jobs 
            WHERE user_id = $1 
            GROUP BY status
        `;

        // Second query - get today's completed jobs
        const todayQuery = `
            SELECT COUNT(*) as completed_today
            FROM export_batch_jobs 
            WHERE user_id = $1 
            AND status = 'completed'
            AND DATE(completed_at) = CURRENT_DATE
        `;

        const [statsResult, todayResult] = await Promise.all([
            query(statsQuery, [userId]),
            query(todayQuery, [userId])
        ]);

        const statsRows = statsResult.rows;
        const todayRow = todayResult.rows[0];

        // Calculate totals with proper null handling
        const total = statsRows.reduce((sum, row) => {
            const count = parseInt(row.total) || 0; // Handle null/undefined
            return sum + count;
        }, 0);

        const totalProcessedItems = statsRows.reduce((sum, row) => {
            const items = parseInt(row.total_processed_items) || 0; // Handle null/undefined
            return sum + items;
        }, 0);

        // Calculate byStatus object
        const byStatus = statsRows.reduce((acc, row) => {
            const status = row.status;
            const count = parseInt(row.total) || 0; // Handle null/undefined
            acc[status] = count;
            return acc;
        }, {} as Record<string, number>);

        // Calculate average processing time (only for completed jobs)
        let averageProcessingTime = 0;
        const completedRows = statsRows.filter(row => row.status === 'completed');
        if (completedRows.length > 0) {
            const totalTime = completedRows.reduce((sum, row) => {
            const time = parseFloat(row.avg_processing_seconds) || 0; // Handle null/undefined
            const count = parseInt(row.total) || 0;
            return sum + (time * count);
            }, 0);
            
            const totalCompletedJobs = completedRows.reduce((sum, row) => {
            const count = parseInt(row.total) || 0;
            return sum + count;
            }, 0);
            
            if (totalCompletedJobs > 0) {
            averageProcessingTime = Math.round(totalTime / totalCompletedJobs);
            }
        }

        const completedToday = parseInt(todayRow?.completed_today) || 0; // Handle null/undefined

        return {
            total,
            byStatus,
            completedToday,
            totalProcessedItems,
            averageProcessingTime
        };
    },

    /**
     * Cleanup old jobs
     */
    async cleanupOldJobs(olderThanDays: number = 30): Promise<number> {
        const cutoffTime = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);

        const result = await query(
        `DELETE FROM export_batch_jobs 
        WHERE created_at < $1 
        AND status IN ('completed', 'failed', 'cancelled')`,
        [cutoffTime]
        );

        return result.rowCount ?? 0;
    },

    /**
     * Cancel all pending/processing jobs for a user
     */
    async cancelUserJobs(userId: string): Promise<number> {
        const result = await query(
        `UPDATE export_batch_jobs 
        SET status = 'cancelled', updated_at = NOW() 
        WHERE user_id = $1 
        AND status IN ('pending', 'processing')`,
        [userId]
        );

        return result.rowCount ?? 0;
    },

    /**
     * Get active job count for user (to enforce limits)
     */
    async getActiveJobCount(userId: string): Promise<number> {
        const result = await query(
        `SELECT COUNT(*) as active_count
        FROM export_batch_jobs 
        WHERE user_id = $1 
        AND status IN ('pending', 'processing')`,
        [userId]
        );

        return parseInt(result.rows[0]?.active_count || '0', 10);
    },

    /**
     * Transform database record to proper types
     * FIXED: Remove private modifier - not allowed in object literals
     */
    transformDbRecord(row: any): ExportBatchJob {
        return {
        id: row.id,
        user_id: row.user_id,
        status: row.status,
        options: typeof row.options === 'string' ? JSON.parse(row.options) : row.options,
        progress: row.progress,
        total_items: row.total_items,
        processed_items: row.processed_items,
        output_url: row.output_url,
        error: row.error,
        created_at: row.created_at,
        updated_at: row.updated_at,
        completed_at: row.completed_at,
        expires_at: row.expires_at
        };
    },

    /**
     * Batch update job progress (for efficient progress reporting)
     */
    async batchUpdateProgress(updates: Array<{id: string, progress: number, processed_items: number}>): Promise<number> {
        if (updates.length === 0) {
            return 0;
        }

        // Build the CASE statements for efficient batch update
        const progressCases = updates.map((_, index) => 
            `WHEN id = $${index * 3 + 1} THEN $${index * 3 + 2}`
        ).join(' ');
        
        const processedItemsCases = updates.map((_, index) => 
            `WHEN id = $${index * 3 + 1} THEN $${index * 3 + 3}`
        ).join(' ');

        const ids = updates.map(u => u.id);
        const idPlaceholders = ids.map((_, index) => `$${updates.length * 3 + 1 + index}`).join(', ');

        const queryText = `
            UPDATE export_batch_jobs 
            SET 
            progress = CASE ${progressCases} END,
            processed_items = CASE ${processedItemsCases} END,
            updated_at = NOW()
            WHERE id IN (${idPlaceholders})
        `;

        // Flatten parameters: [id1, progress1, processed_items1, id2, progress2, processed_items2, ..., id1, id2, ...]
        const params = [
            ...updates.flatMap(u => [u.id, u.progress, u.processed_items]),
            ...ids
        ];

        const result = await query(queryText, params);
        return result.rowCount || 0;
    }
};