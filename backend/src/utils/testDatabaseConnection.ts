// /backend/src/utils/testDatabaseConnection.ts - ENHANCED MANUAL MODE
/**
 * Enhanced Manual Database Connection (Original Mode)
 * 
 * This version creates/drops test databases dynamically.
 * Preserves the original approach that passed ~4000 tests.
 * Enhanced with missing schema elements for wardrobe tests.
 * 
 * @author Development Team
 * @version 1.1.0 - Enhanced
 * @since June 10, 2025
 */

import { Pool, Client, PoolConfig, PoolClient } from 'pg';
import { TEST_DB_CONFIG, MAIN_DB_CONFIG } from './testConfig';
import fs from 'fs';
import path from 'path';

export class TestDatabaseConnection {
  private static testPool: Pool | null = null;
  private static mainPool: Pool | null = null;
  private static isInitialized = false;
  private static isInitializing = false;
  private static initializationPromise: Promise<Pool> | null = null;
  private static activeConnections = new Set<PoolClient>();
  private static cleanupInProgress = false;

  static async initialize(): Promise<Pool> {
    // Return existing initialization promise if already initializing
    if (this.initializationPromise) {
      return this.initializationPromise;
    }

    // Return existing pool if already initialized
    if (this.isInitialized && this.testPool) {
      return this.testPool;
    }

    // Create new initialization promise
    this.initializationPromise = this.performInitialization();
    
    try {
      const pool = await this.initializationPromise;
      return pool;
    } finally {
      // Clear the promise after completion (success or failure)
      this.initializationPromise = null;
    }
  }

  private static async performInitialization(): Promise<Pool> {
    try {
      this.isInitializing = true;

      // Create main pool for administrative operations
      this.mainPool = new Pool({
        ...MAIN_DB_CONFIG,
        database: 'postgres' // Connect to postgres db for admin operations
      });

      // Check if test database exists, create if it doesn't
      await this.ensureTestDatabase();

      // Close main pool after database operations
      if (this.mainPool) {
        await this.mainPool.end();
        this.mainPool = null;
      }

      // Create test pool with enhanced configuration
      this.testPool = new Pool({
        ...TEST_DB_CONFIG,
        // Enhanced pool configuration for better cleanup
        max: 10, // Limit maximum connections
        idleTimeoutMillis: 1000, // Close idle connections faster
        connectionTimeoutMillis: 2000,
        allowExitOnIdle: true // Allow pool to close when idle
      });

      // Add error handlers to the pool
      this.testPool.on('error', (err) => {
        console.warn('Database pool error:', err);
      });

      this.testPool.on('connect', (client) => {
        console.log('Database client connected');
      });

      this.testPool.on('remove', (client) => {
        console.log('Database client removed');
      });

      // Test the connection
      const testClient = await this.testPool.connect();
      try {
        await testClient.query('SELECT 1');
      } finally {
        testClient.release();
      }

      // Create extensions and schema
      await this.setupDatabase();

      this.isInitialized = true;
      console.log('✅ Manual database setup completed');
      return this.testPool;
    } catch (error) {
      // Cleanup on failure
      await this.cleanupPools();
      throw error;
    } finally {
      this.isInitializing = false;
    }
  }

  private static async ensureTestDatabase(): Promise<void> {
    if (!this.mainPool) {
      throw new Error('Main pool not initialized');
    }

    try {
      // Check if test database exists
      const result = await this.mainPool.query(
        'SELECT 1 FROM pg_database WHERE datname = $1',
        ['koutu_test']
      );

      if (result.rows.length === 0) {
        // Terminate existing connections to test database (if any)
        try {
          await this.mainPool.query(`
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = 'koutu_test' AND pid <> pg_backend_pid()
          `);
        } catch (error) {
          // Ignore errors if database doesn't exist yet
        }

        // Create test database
        await this.mainPool.query('CREATE DATABASE koutu_test');
        console.log('Test database created successfully');
      }
    } catch (error) {
      console.error('Error ensuring test database:', error);
      throw error;
    }
  }

  private static async setupDatabase(): Promise<void> {
    if (!this.testPool) {
      throw new Error('Test pool not initialized');
    }

    const client = await this.testPool.connect();
    this.activeConnections.add(client);
    try {
      // Create extensions with error handling for concurrent access
      try {
        await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
      } catch (error: any) {
        // Ignore duplicate extension errors
        if (!error.message?.includes('already exists')) {
          throw error;
        }
      }

      // Create schema
      await this.createSchema(client);
    } finally {
      this.activeConnections.delete(client);
      client.release();
    }
  }

  private static async createSchema(client: any): Promise<void> {
    const schemaPath = path.join(__dirname, '../db/schema.sql');
    
    if (fs.existsSync(schemaPath)) {
      const schema = fs.readFileSync(schemaPath, 'utf8');
      await client.query(schema);
    } else {
      // Fallback: create enhanced schema manually
      await this.createEnhancedSchema(client);
    }
  }

  private static async createEnhancedSchema(client: any): Promise<void> {
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

    // Enhanced original_images table
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

    // ENHANCED: garment_items with all required columns
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

    // ENHANCED: wardrobes with TEXT columns and is_default
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

    // NEW: wardrobe_items table (was missing!)
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

    // Add comprehensive indexes for better performance
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

    console.log('✅ Enhanced database schema created');
  }

  // NEW: Method to ensure tables exist (for compatibility)
  static async ensureTablesExist(): Promise<void> {
    if (!this.testPool || !this.isInitialized) {
      throw new Error('Test database not initialized. Call initialize() first.');
    }

    const client = await this.testPool.connect();
    this.activeConnections.add(client);
    try {
      // Check if wardrobe_items table exists, create if missing
      const result = await client.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'wardrobe_items'
        );
      `);

      if (!result.rows[0].exists) {
        console.log('Creating missing wardrobe_items table...');
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
      await client.query(`
        ALTER TABLE wardrobes 
        ALTER COLUMN name TYPE TEXT,
        ALTER COLUMN description TYPE TEXT;
      `);

    } catch (error) {
      console.warn('Error ensuring tables exist:', error);
    } finally {
      this.activeConnections.delete(client);
      client.release();
    }
  }

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
      // Clear tables in reverse dependency order to avoid foreign key violations
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
      } finally {
        // Re-enable foreign key checks
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
    console.log('🔄 Starting enhanced database cleanup...');

    try {
      // Step 1: Wait for active connections to finish naturally
      if (this.activeConnections.size > 0) {
        console.log(`⏳ Waiting for ${this.activeConnections.size} active connections to finish...`);
        
        // Wait a short time for connections to finish naturally
        let attempts = 0;
        while (this.activeConnections.size > 0 && attempts < 10) {
          await new Promise(resolve => setTimeout(resolve, 100));
          attempts++;
        }

        // Force release any remaining connections
        if (this.activeConnections.size > 0) {
          console.log(`⚠️ Force releasing ${this.activeConnections.size} remaining connections`);
          for (const client of this.activeConnections) {
            try {
              (client as any).release(true); // Force release
            } catch (error) {
              console.warn('Error force-releasing client:', error);
            }
          }
          this.activeConnections.clear();
        }
      }

      // Step 2: Gracefully close pools
      await this.cleanupPools();
      
      // Step 3: Drop test database
      await this.dropTestDatabase();

      console.log('✅ Enhanced database cleanup completed');
    } catch (error) {
      console.warn('⚠️ Cleanup had issues:', error);
    } finally {
      this.resetState();
      this.cleanupInProgress = false;
    }
  }

  private static async cleanupPools(): Promise<void> {
    const promises: Promise<void>[] = [];

    // Close test pool
    if (this.testPool && !this.testPool.ended) {
      promises.push(
        this.testPool.end().catch(error => {
          console.warn('Test pool cleanup error:', error);
        })
      );
    }

    // Close main pool
    if (this.mainPool && !this.mainPool.ended) {
      promises.push(
        this.mainPool.end().catch(error => {
          console.warn('Main pool cleanup error:', error);
        })
      );
    }

    // Wait for all pools to close
    await Promise.allSettled(promises);
    
    this.testPool = null;
    this.mainPool = null;
  }

  private static async dropTestDatabase(): Promise<void> {
    // Create a new connection just for cleanup
    const cleanupPool = new Pool({
      ...MAIN_DB_CONFIG,
      database: 'postgres',
      max: 1, // Single connection for cleanup
      idleTimeoutMillis: 1000
    });

    try {
      // Terminate connections to test database
      await cleanupPool.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = 'koutu_test' AND pid <> pg_backend_pid()
      `);

      // Small delay to ensure connections are terminated
      await new Promise(resolve => setTimeout(resolve, 200));

      // Drop test database
      await cleanupPool.query('DROP DATABASE IF EXISTS koutu_test');
    } catch (error) {
      console.log('Error dropping test database:', error);
    } finally {
      try {
        await cleanupPool.end();
      } catch (error) {
        console.log('Error closing cleanup pool:', error);
      }
    }
  }

  private static resetState(): void {
    this.isInitialized = false;
    this.isInitializing = false;
    this.initializationPromise = null;
    this.testPool = null;
    this.mainPool = null;
    this.activeConnections.clear();
  }

  // Utility methods
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