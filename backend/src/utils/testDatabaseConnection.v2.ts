// /backend/src/utils/testDatabaseConnection.v2.ts - ENHANCED DOCKER MODE
/**
 * Enhanced Docker Database Connection (Docker Mode)
 * 
 * This version connects to Docker PostgreSQL containers for testing.
 * More reliable and isolated than manual setup for CI/CD environments.
 * Enhanced with all required schema elements for wardrobe tests.
 * 
 * @author Development Team
 * @version 2.1.0 - Enhanced Docker Mode
 * @since June 10, 2025
 */

import { Pool, PoolConfig, PoolClient } from 'pg';

export class TestDatabaseConnection {
    private static testPool: Pool | null = null;
    private static mainPool: Pool | null = null;
    private static isInitialized = false;
    private static isInitializing = false;
    private static initializationPromise: Promise<Pool> | null = null;
    private static activeConnections = new Set<PoolClient>();
    private static cleanupInProgress = false;

    /**
     * Initialize Docker-based test database connection
     */
    static async initialize(): Promise<Pool> {
        if (this.initializationPromise) {
            return this.initializationPromise;
        }

        if (this.isInitialized && this.testPool) {
            return this.testPool;
        }

        this.initializationPromise = this.performInitialization();
        
        try {
            const pool = await this.initializationPromise;
            return pool;
        } finally {
            this.initializationPromise = null;
        }
    }

    private static async performInitialization(): Promise<Pool> {
        try {
            this.isInitializing = true;

            // Wait for Docker PostgreSQL to be ready
            await this.waitForDockerPostgreSQL();

            // Connect to Docker postgres-test service
            this.testPool = new Pool({
                host: 'localhost',
                port: 5433, // Docker postgres-test service port
                user: 'postgres',
                password: 'postgres',
                database: 'koutu_test',
                max: 10,
                idleTimeoutMillis: 1000,
                connectionTimeoutMillis: 2000,
                allowExitOnIdle: true
            });

            // Add pool event handlers
            this.testPool.on('error', (err) => {
                console.warn('🐳 Docker database pool error:', err);
            });

            this.testPool.on('connect', () => {
                console.log('🐳 Docker database client connected');
            });

            this.testPool.on('remove', () => {
                console.log('🐳 Docker database client removed');
            });

            // Test connection
            const testClient = await this.testPool.connect();
            try {
                await testClient.query('SELECT 1');
                console.log('✅ Docker PostgreSQL test database ready');
            } finally {
                testClient.release();
            }

            // Set up database schema
            await this.setupDatabase();

            this.isInitialized = true;
            console.log('✅ Docker database setup completed');
            return this.testPool;
        } catch (error) {
            await this.cleanupPools();
            throw error;
        } finally {
            this.isInitializing = false;
        }
    }

    /**
     * Wait for Docker PostgreSQL container to be ready
     */
    private static async waitForDockerPostgreSQL(): Promise<void> {
        console.log('🐳 Waiting for Docker PostgreSQL container...');
        
        const maxAttempts = 30;
        const delay = 1000;

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                // Try connecting to ensure database exists
                const testPool = new Pool({
                    host: 'localhost',
                    port: 5433,
                    user: 'postgres',
                    password: 'postgres',
                    database: 'koutu_test', // Try the test database directly
                    max: 1,
                    connectionTimeoutMillis: 2000
                });
                
                try {
                    await testPool.query('SELECT 1');
                    await testPool.end();
                    console.log('✅ Docker PostgreSQL with koutu_test database is ready');
                    return;
                } catch (dbError: any) {
                    await testPool.end().catch(() => {});
                    
                    // If database doesn't exist, try to create it
                    if (dbError.message.includes('koutu_test') && dbError.message.includes('does not exist')) {
                        await this.createTestDatabaseInDocker();
                        // Try again on next iteration
                    }
                }
            } catch (error) {
                // Container not ready yet
                if (attempt % 5 === 0) {
                    console.log(`⏳ Still waiting for Docker PostgreSQL... (attempt ${attempt}/${maxAttempts})`);
                }
            }

            if (attempt === maxAttempts) {
                throw new Error(
                    `❌ Docker PostgreSQL not ready after ${maxAttempts} attempts.\n` +
                    `Please ensure PostgreSQL container is running on port 5433.\n` +
                    `Example: docker run --name test-postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=koutu_test -p 5433:5432 -d postgres:13`
                );
            }

            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    /**
     * Create test database in Docker container if it doesn't exist
     */
    private static async createTestDatabaseInDocker(): Promise<void> {
        try {
            const adminPool = new Pool({
                host: 'localhost',
                port: 5433,
                user: 'postgres',
                password: 'postgres',
                database: 'postgres', // Connect to default database
                max: 1,
                connectionTimeoutMillis: 2000
            });

            try {
                // Check if database exists
                const result = await adminPool.query(
                    'SELECT 1 FROM pg_database WHERE datname = $1',
                    ['koutu_test']
                );

                if (result.rows.length === 0) {
                    // Create test database
                    await adminPool.query('CREATE DATABASE koutu_test');
                    console.log('🐳 Created koutu_test database in Docker container');
                }
            } finally {
                await adminPool.end();
            }
        } catch (error) {
            console.warn('Warning: Could not create test database in Docker:', error);
        }
    }

    /**
     * Set up database schema in Docker container
     */
    private static async setupDatabase(): Promise<void> {
        if (!this.testPool) {
            throw new Error('Test pool not initialized');
        }

        const client = await this.testPool.connect();
        this.activeConnections.add(client);
        try {
            // Create extensions
            try {
                await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
            } catch (error: any) {
                if (!error.message?.includes('already exists')) {
                    throw error;
                }
            }

            // Create complete schema
            await this.createCompleteDockerSchema(client);
            
            console.log('✅ Docker database schema created successfully');
        } finally {
            this.activeConnections.delete(client);
            client.release();
        }
    }

    /**
     * Create complete database schema for Docker testing
     */
    private static async createCompleteDockerSchema(client: any): Promise<void> {
        // Create users table
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                display_name VARCHAR(255),
                profile_image_url TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        // Create user_oauth_providers table
        await client.query(`
            CREATE TABLE IF NOT EXISTS user_oauth_providers (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                provider VARCHAR(50) NOT NULL,
                provider_id VARCHAR(255) NOT NULL,
                provider_email VARCHAR(255),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(provider, provider_id)
            )
        `);

        // Create original_images table
        await client.query(`
            CREATE TABLE IF NOT EXISTS original_images (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                file_path TEXT NOT NULL,
                original_filename VARCHAR(255),
                mime_type VARCHAR(100),
                file_size INTEGER,
                original_metadata JSONB DEFAULT '{}',
                upload_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                status VARCHAR(20) DEFAULT 'new' CHECK (status IN ('new', 'processed', 'labeled')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        // Create garment_items table with all required columns
        await client.query(`
            CREATE TABLE IF NOT EXISTS garment_items (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                original_image_id UUID REFERENCES original_images(id) ON DELETE SET NULL,
                name VARCHAR(255),
                description TEXT,
                category VARCHAR(100),
                color VARCHAR(100),
                brand VARCHAR(255),
                size VARCHAR(50),
                price DECIMAL(10,2),
                purchase_date DATE,
                image_url TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                
                -- Additional columns for testGarmentModel compatibility
                file_path TEXT,
                mask_path TEXT,
                metadata JSONB DEFAULT '{}',
                data_version INTEGER DEFAULT 1
            )
        `);

        // Create wardrobes table with TEXT columns (no length limit) and is_default
        await client.query(`
            CREATE TABLE IF NOT EXISTS wardrobes (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                description TEXT,
                is_default BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        // Create wardrobe_items table (this was missing in original setup!)
        await client.query(`
            CREATE TABLE IF NOT EXISTS wardrobe_items (
                id SERIAL PRIMARY KEY,
                wardrobe_id UUID NOT NULL REFERENCES wardrobes(id) ON DELETE CASCADE,
                garment_item_id UUID NOT NULL REFERENCES garment_items(id) ON DELETE CASCADE,
                position INTEGER DEFAULT 0,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(wardrobe_id, garment_item_id)
            )
        `);

        // Create comprehensive performance indexes
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_original_images_user_id ON original_images(user_id);
            CREATE INDEX IF NOT EXISTS idx_original_images_status ON original_images(status);
            CREATE INDEX IF NOT EXISTS idx_original_images_upload_date ON original_images(upload_date DESC);
            CREATE INDEX IF NOT EXISTS idx_garment_items_user_id ON garment_items(user_id);
            CREATE INDEX IF NOT EXISTS idx_wardrobes_user_id ON wardrobes(user_id);
            CREATE INDEX IF NOT EXISTS idx_wardrobes_name ON wardrobes(name);
            CREATE INDEX IF NOT EXISTS idx_wardrobe_items_wardrobe_id ON wardrobe_items(wardrobe_id);
            CREATE INDEX IF NOT EXISTS idx_wardrobe_items_garment_id ON wardrobe_items(garment_item_id);
            CREATE INDEX IF NOT EXISTS idx_wardrobe_items_position ON wardrobe_items(wardrobe_id, position);
        `);

        console.log('✅ Docker database schema with all tables created');
    }

    /**
     * Ensure all required tables exist (for compatibility with manual mode)
     */
    static async ensureTablesExist(): Promise<void> {
        if (!this.testPool || !this.isInitialized) {
            throw new Error('Test database not initialized. Call initialize() first.');
        }

        const client = await this.testPool.connect();
        this.activeConnections.add(client);
        try {
            // Check if wardrobe_items table exists
            const result = await client.query(`
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'wardrobe_items'
                );
            `);

            if (!result.rows[0].exists) {
                console.log('🐳 Creating missing wardrobe_items table in Docker...');
                await client.query(`
                    CREATE TABLE wardrobe_items (
                        id SERIAL PRIMARY KEY,
                        wardrobe_id UUID NOT NULL REFERENCES wardrobes(id) ON DELETE CASCADE,
                        garment_item_id UUID NOT NULL REFERENCES garment_items(id) ON DELETE CASCADE,
                        position INTEGER DEFAULT 0,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        UNIQUE(wardrobe_id, garment_item_id)
                    )
                `);

                // Add indexes
                await client.query(`
                    CREATE INDEX idx_wardrobe_items_wardrobe_id ON wardrobe_items(wardrobe_id);
                    CREATE INDEX idx_wardrobe_items_garment_id ON wardrobe_items(garment_item_id);
                    CREATE INDEX idx_wardrobe_items_position ON wardrobe_items(wardrobe_id, position);
                `);
            }

            // Ensure wardrobes table has is_default column
            await client.query(`
                ALTER TABLE wardrobes 
                ADD COLUMN IF NOT EXISTS is_default BOOLEAN DEFAULT FALSE;
            `);

            // Ensure wardrobes columns are TEXT (not VARCHAR with limits)
            try {
                await client.query(`
                    ALTER TABLE wardrobes 
                    ALTER COLUMN name TYPE TEXT,
                    ALTER COLUMN description TYPE TEXT;
                `);
            } catch (error) {
                // Might already be TEXT, ignore error
                console.log('🐳 Columns already TEXT or conversion not needed');
            }

            console.log('✅ Docker database tables verified and updated');
        } catch (error) {
            console.warn('Warning: Error ensuring Docker tables exist:', error);
        } finally {
            this.activeConnections.delete(client);
            client.release();
        }
    }

    /**
     * Get the active pool instance
     */
    static getPool(): Pool {
        if (!this.testPool || !this.isInitialized) {
            throw new Error('Test database not initialized. Call initialize() first.');
        }
        return this.testPool;
    }

    /**
     * Execute a database query
     */
    static async query(text: string, params?: any[]): Promise<any> {
        if (this.cleanupInProgress) {
            throw new Error('Database cleanup in progress, cannot execute queries');
        }
        
        const pool = this.getPool();
        const client = await pool.connect();
        this.activeConnections.add(client);
        
        try {
            const result = await client.query(text, params);
            return result;
        } finally {
            this.activeConnections.delete(client);
            client.release();
        }
    }

    /**
     * Clear all data from test tables (Docker-safe)
     */
    static async clearAllTables(): Promise<void> {
        if (!this.testPool || !this.isInitialized) {
            throw new Error('Test database not initialized. Call initialize() first.');
        }

        const client = await this.testPool.connect();
        this.activeConnections.add(client);
        try {
            // Clear tables in reverse dependency order for Docker environment
            const tables = [
                'wardrobe_items',
                'user_oauth_providers',
                'garment_items',
                'wardrobes',
                'original_images', 
                'users'
            ];

            // Disable foreign key checks temporarily
            await client.query('SET session_replication_role = replica');
            
            try {
                for (const table of tables) {
                    await client.query(`TRUNCATE TABLE ${table} RESTART IDENTITY CASCADE`);
                }
                console.log('🐳 All Docker test tables cleared');
            } finally {
                // Re-enable foreign key checks
                await client.query('SET session_replication_role = DEFAULT');
            }
        } finally {
            this.activeConnections.delete(client);
            client.release();
        }
    }

    /**
     * Clean up Docker database connections (does not drop database)
     */
    static async cleanup(): Promise<void> {
        if (this.cleanupInProgress) {
            console.log('Docker cleanup already in progress, skipping...');
            return;
        }

        this.cleanupInProgress = true;
        console.log('🔄 Starting Docker database cleanup...');

        try {
            // Wait for active connections to finish
            if (this.activeConnections.size > 0) {
                console.log(`⏳ Waiting for ${this.activeConnections.size} Docker connections to finish...`);
                
                let attempts = 0;
                while (this.activeConnections.size > 0 && attempts < 10) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                    attempts++;
                }

                // Force release remaining connections
                if (this.activeConnections.size > 0) {
                    console.log(`⚠️ Force releasing ${this.activeConnections.size} remaining Docker connections`);
                    for (const client of this.activeConnections) {
                        try {
                            (client as any).release(true);
                        } catch (error) {
                            console.warn('Error force-releasing Docker client:', error);
                        }
                    }
                    this.activeConnections.clear();
                }
            }

            // Close pools (but don't drop database - Docker container persists)
            await this.cleanupPools();
            
            console.log('✅ Docker database cleanup completed (container persists)');
        } catch (error) {
            console.warn('⚠️ Docker cleanup had issues:', error);
        } finally {
            this.resetState();
            this.cleanupInProgress = false;
        }
    }

    /**
     * Close database pools
     */
    private static async cleanupPools(): Promise<void> {
        const promises: Promise<void>[] = [];

        if (this.testPool && !this.testPool.ended) {
            promises.push(
                this.testPool.end().catch(error => {
                    console.warn('Docker test pool cleanup error:', error);
                })
            );
        }

        if (this.mainPool && !this.mainPool.ended) {
            promises.push(
                this.mainPool.end().catch(error => {
                    console.warn('Docker main pool cleanup error:', error);
                })
            );
        }

        await Promise.allSettled(promises);
        
        this.testPool = null;
        this.mainPool = null;
    }

    /**
     * Reset internal state
     */
    private static resetState(): void {
        this.isInitialized = false;
        this.isInitializing = false;
        this.initializationPromise = null;
        this.testPool = null;
        this.mainPool = null;
        this.activeConnections.clear();
    }

    // Utility methods for debugging and compatibility
    static get initialized(): boolean {
        return this.isInitialized;
    }

    static get initializing(): boolean {
        return this.isInitializing;
    }

    static get activeConnectionCount(): number {
        return this.activeConnections.size;
    }
}