import { Pool, PoolConfig, PoolClient } from 'pg';

export class TestDatabaseConnection {
    private static testPool: Pool | null = null;
    private static mainPool: Pool | null = null;
    private static isInitialized = false;
    private static isInitializing = false;
    private static initializationPromise: Promise<Pool> | null = null;
    private static activeConnections = new Set<PoolClient>();
    private static cleanupInProgress = false;

    // SAME INTERFACE as your existing class, but Docker-backed implementation
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

            // FIXED: Only wait for PostgreSQL test database, not Firebase
            await this.waitForPostgreSQLTest();

            // Connect to Docker postgres-test service (port 5433)
            this.testPool = new Pool({
                host: 'localhost',
                port: 5433, // Docker postgres-test service
                user: 'postgres',
                password: 'postgres',
                database: 'koutu_test',
                max: 10,
                idleTimeoutMillis: 1000,
                connectionTimeoutMillis: 2000,
                allowExitOnIdle: true
            });

            // Same pool event handlers as before
            this.testPool.on('error', (err) => {
                console.warn('Database pool error:', err);
            });

            this.testPool.on('connect', (client) => {
                console.log('Database client connected');
            });

            this.testPool.on('remove', (client) => {
                console.log('Database client removed');
            });

            // Test connection
            const testClient = await this.testPool.connect();
            try {
                await testClient.query('SELECT 1');
                console.log('✅ Docker PostgreSQL test database ready');
            } finally {
                testClient.release();
            }

            // Set up schema
            await this.setupDatabase();

            this.isInitialized = true;
            return this.testPool;
        } catch (error) {
            await this.cleanupPools();
            throw error;
        } finally {
            this.isInitializing = false;
        }
    }

    // FIXED: Only wait for PostgreSQL, Firebase is handled separately
    private static async waitForPostgreSQLTest(): Promise<void> {
        console.log('🐳 Waiting for Docker PostgreSQL test service...');
        
        const maxAttempts = 15; // Reduced from 30
        const delay = 1000;

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                const testPool = new Pool({
                    host: 'localhost',
                    port: 5433,
                    user: 'postgres',
                    password: 'postgres',
                    database: 'postgres', // Connect to default db first
                    max: 1,
                    connectionTimeoutMillis: 2000
                });
                
                try {
                    await testPool.query('SELECT 1');
                    await testPool.end();
                    console.log('✅ Docker PostgreSQL test database is ready');
                    return;
                } catch (error) {
                    await testPool.end().catch(() => {});
                }
            } catch (error) {
                // Service not ready yet
            }

            if (attempt === maxAttempts) {
                throw new Error(`❌ Docker PostgreSQL test database not ready after ${maxAttempts} attempts. Is 'koutu-postgres-test' container running?`);
            }

            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }

    // KEEP ALL EXISTING METHODS - just the implementation changes
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

            await this.createSchema(client);
        } finally {
            this.activeConnections.delete(client);
            client.release();
        }
    }

    // Keep all your existing methods unchanged
    private static async createSchema(client: any): Promise<void> {
        await this.createBasicSchema(client);
    }

    private static async createBasicSchema(client: any): Promise<void> {
        // Create tables in dependency order
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
                
                -- Additional columns for compatibility
                file_path TEXT,
                mask_path TEXT,
                metadata JSONB DEFAULT '{}',
                data_version INTEGER DEFAULT 1
            )
        `);

        await client.query(`
            CREATE TABLE IF NOT EXISTS wardrobes (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                is_default BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        // Add indexes for better performance
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_original_images_user_id ON original_images(user_id);
            CREATE INDEX IF NOT EXISTS idx_original_images_status ON original_images(status);
            CREATE INDEX IF NOT EXISTS idx_original_images_upload_date ON original_images(upload_date DESC);
        `);
    }

    // KEEP ALL EXISTING PUBLIC METHODS - same interface!
    static getPool(): Pool {
        if (!this.testPool || !this.isInitialized) {
            throw new Error('Test database not initialized. Call initialize() first.');
        }
        return this.testPool;
    }

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

    static async clearAllTables(): Promise<void> {
        if (!this.testPool || !this.isInitialized) {
            throw new Error('Test database not initialized. Call initialize() first.');
        }

        const client = await this.testPool.connect();
        this.activeConnections.add(client);
        try {
            const tables = [
                'user_oauth_providers',
                'garment_items',
                'original_images', 
                'wardrobes',
                'users'
            ];

            await client.query('SET session_replication_role = replica');
            
            try {
                for (const table of tables) {
                    await client.query(`TRUNCATE TABLE ${table} RESTART IDENTITY CASCADE`);
                }
            } finally {
                await client.query('SET session_replication_role = DEFAULT');
            }
        } finally {
            this.activeConnections.delete(client);
            client.release();
        }
    }

    static async cleanup(): Promise<void> {
        if (this.cleanupInProgress) {
            console.log('Cleanup already in progress, skipping...');
            return;
        }

        this.cleanupInProgress = true;
        console.log('🔄 Starting Docker database cleanup...');

        try {
            if (this.activeConnections.size > 0) {
                console.log(`⏳ Waiting for ${this.activeConnections.size} active connections to finish...`);
                
                let attempts = 0;
                while (this.activeConnections.size > 0 && attempts < 10) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                    attempts++;
                }

                if (this.activeConnections.size > 0) {
                    console.log(`⚠️ Force releasing ${this.activeConnections.size} remaining connections`);
                    for (const client of this.activeConnections) {
                        try {
                            (client as any).release(true);
                        } catch (error) {
                            console.warn('Error force-releasing client:', error);
                        }
                    }
                    this.activeConnections.clear();
                }
            }

            await this.cleanupPools();
            
            console.log('✅ Docker database cleanup completed');
        } catch (error) {
            console.warn('⚠️ Cleanup had issues:', error);
        } finally {
            this.resetState();
            this.cleanupInProgress = false;
        }
    }

    private static async cleanupPools(): Promise<void> {
        const promises: Promise<void>[] = [];

        if (this.testPool && !this.testPool.ended) {
            promises.push(
                this.testPool.end().catch(error => {
                    console.warn('Test pool cleanup error:', error);
                })
            );
        }

        if (this.mainPool && !this.mainPool.ended) {
            promises.push(
                this.mainPool.end().catch(error => {
                    console.warn('Main pool cleanup error:', error);
                })
            );
        }

        await Promise.allSettled(promises);
        
        this.testPool = null;
        this.mainPool = null;
    }

    private static resetState(): void {
        this.isInitialized = false;
        this.isInitializing = false;
        this.initializationPromise = null;
        this.testPool = null;
        this.mainPool = null;
        this.activeConnections.clear();
    }

    // Keep all utility methods
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