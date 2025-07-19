// /backend/src/tests/fixtures/testDb.ts
import { Pool } from 'pg';
import { pool } from '../../models/db';

export class TestDb {
    private static instance: TestDb;
    private pool: Pool;
    private initialized = false;

    private constructor() {
        // Use the existing db pool from the app
        this.pool = pool;
    }

    static getInstance(): TestDb {
        if (!TestDb.instance) {
            TestDb.instance = new TestDb();
        }
        return TestDb.instance;
    }

    async initialize(): Promise<void> {
        if (this.initialized) return;
        
        try {
            // Test connection
            await this.pool.query('SELECT 1');
            this.initialized = true;
        } catch (error) {
            console.error('Failed to initialize test database:', error);
            throw error;
        }
    }

    async query(text: string, params?: any[]): Promise<any> {
        if (!this.initialized) {
            throw new Error('Test database not initialized. Call initialize() first.');
        }
        return await this.pool.query(text, params);
    }

    async clear(): Promise<void> {
        // Clear all test data in the correct order to avoid foreign key violations
        const tables = [
            'wardrobe_items',
            'wardrobes',
            'garment_items',
            'garments',
            'polygons',
            'original_images',
            'users'
        ];

        for (const table of tables) {
            try {
                await this.pool.query(`DELETE FROM ${table}`);
            } catch (error) {
                console.warn(`Failed to clear table ${table}:`, error);
            }
        }
    }

    async cleanup(): Promise<void> {
        // Don't close the pool as it's shared with the app
        // Just clear the data
        await this.clear();
    }

    // Transaction helper for tests
    async transaction<T>(callback: (client: any) => Promise<T>): Promise<T> {
        const client = await this.pool.connect();
        try {
            await client.query('BEGIN');
            const result = await callback(client);
            await client.query('COMMIT');
            return result;
        } catch (error) {
            await client.query('ROLLBACK');
            throw error;
        } finally {
            client.release();
        }
    }
}

// Export singleton instance
export const testDb = TestDb.getInstance();