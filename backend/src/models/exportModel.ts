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
    async update(id: string, data: UpdateExportJobInput): Promise<ExportBatchJob | null> {
        if (!isUuid(id)) {
        return null;
        }

        const updates: string[] = [];
        const values: any[] = [];
        let paramIndex = 1;

        // Build dynamic update query
        if (data.status !== undefined) {
        updates.push(`status = $${paramIndex}`);
        values.push(data.status);
        paramIndex++;
        }

        if (data.progress !== undefined) {
        updates.push(`progress = $${paramIndex}`);
        values.push(data.progress);
        paramIndex++;
        }

        if (data.total_items !== undefined) {
        updates.push(`total_items = $${paramIndex}`);
        values.push(data.total_items);
        paramIndex++;
        }

        if (data.processed_items !== undefined) {
        updates.push(`processed_items = $${paramIndex}`);
        values.push(data.processed_items);
        paramIndex++;
        }

        if (data.output_url !== undefined) {
        updates.push(`output_url = $${paramIndex}`);
        values.push(data.output_url);
        paramIndex++;
        }

        if (data.error !== undefined) {
        updates.push(`error = $${paramIndex}`);
        values.push(data.error);
        paramIndex++;
        }

        if (data.completed_at !== undefined) {
        updates.push(`completed_at = $${paramIndex}`);
        values.push(data.completed_at);
        paramIndex++;
        }

        // Always update updated_at
        updates.push(`updated_at = NOW()`);

        if (updates.length === 1) {
        // Only updated_at would be updated, so no real changes
        return this.findById(id);
        }

        // Add ID to values
        values.push(id);

        const result = await query(
        `UPDATE export_batch_jobs 
        SET ${updates.join(', ')} 
        WHERE id = $${paramIndex} 
        RETURNING *`,
        values
        );

        if (result.rows.length === 0) {
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
    async getUserStats(userId: string): Promise<{
        total: number;
        byStatus: Record<string, number>;
        completedToday: number;
        totalProcessedItems: number;
        averageProcessingTime: number;
    }> {
        const statsResult = await query(
        `SELECT 
            COUNT(*) as total,
            status,
            SUM(processed_items) as total_processed_items,
            AVG(EXTRACT(EPOCH FROM (completed_at - created_at))) as avg_processing_seconds
        FROM export_batch_jobs 
        WHERE user_id = $1 
        GROUP BY status`,
        [userId]
        );

        const todayResult = await query(
        `SELECT COUNT(*) as completed_today
        FROM export_batch_jobs 
        WHERE user_id = $1 
        AND status = 'completed'
        AND DATE(completed_at) = CURRENT_DATE`,
        [userId]
        );

        const stats = {
        total: 0,
        byStatus: {} as Record<string, number>,
        completedToday: parseInt(todayResult.rows[0]?.completed_today || '0', 10),
        totalProcessedItems: 0,
        averageProcessingTime: 0
        };

        let totalProcessingTime = 0;
        let completedJobs = 0;

        statsResult.rows.forEach(row => {
        const count = parseInt(row.total, 10);
        stats.byStatus[row.status] = count;
        stats.total += count;
        
        if (row.total_processed_items) {
            stats.totalProcessedItems += parseInt(row.total_processed_items, 10);
        }

        if (row.status === 'completed' && row.avg_processing_seconds) {
            totalProcessingTime += parseFloat(row.avg_processing_seconds) * count;
            completedJobs += count;
        }
        });

        if (completedJobs > 0) {
        stats.averageProcessingTime = Math.round(totalProcessingTime / completedJobs);
        }

        return stats;
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
    async batchUpdateProgress(updates: Array<{
        id: string;
        progress: number;
        processed_items: number;
    }>): Promise<number> {
        if (updates.length === 0) {
        return 0;
        }

        // Use a single query with CASE statements for efficiency
        const caseProgressStatements = updates.map((_, index) => 
        `WHEN id = ${3 * index + 1} THEN ${3 * index + 2}`
        ).join(' ');

        const caseProcessedItemsStatements = updates.map((_, index) => 
        `WHEN id = ${3 * index + 1} THEN ${3 * index + 3}`
        ).join(' ');

        const allIds = updates.map(update => update.id);
        const queryParams = updates.flatMap(update => [update.id, update.progress, update.processed_items]);
        const idPlaceholders = allIds.map((_, index) => `${updates.length * 3 + index + 1}`).join(',');

        const result = await query(
        `UPDATE export_batch_jobs 
        SET progress = CASE ${caseProgressStatements} END,
            processed_items = CASE ${caseProcessedItemsStatements} END,
            updated_at = NOW()
        WHERE id IN (${idPlaceholders})`,
        [...queryParams, ...allIds]
        );

        return result.rowCount ?? 0;
    }
};