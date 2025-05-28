// /backend/src/utils/testDatabaseConnection.ts

import { Pool, Client, PoolConfig } from 'pg';
import { TEST_DB_CONFIG, MAIN_DB_CONFIG } from './testConfig';
import fs from 'fs';
import path from 'path';

export class TestDatabaseConnection {
  private static testPool: Pool | null = null;
  private static mainPool: Pool | null = null;
  private static isInitialized = false;
  private static isInitializing = false;
  private static initializationPromise: Promise<Pool> | null = null;

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

      // Create test pool
      this.testPool = new Pool(TEST_DB_CONFIG);

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
      client.release();
    }
  }

  private static async createSchema(client: any): Promise<void> {
    const schemaPath = path.join(__dirname, '../db/schema.sql');
    
    if (fs.existsSync(schemaPath)) {
      const schema = fs.readFileSync(schemaPath, 'utf8');
      await client.query(schema);
    } else {
      // Fallback: create basic schema manually
      await this.createBasicSchema(client);
    }
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
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS garment_items (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        category VARCHAR(100),
        color VARCHAR(100),
        brand VARCHAR(255),
        size VARCHAR(50),
        price DECIMAL(10,2),
        purchase_date DATE,
        image_url TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
  }

  static getPool(): Pool {
    if (!this.testPool || !this.isInitialized) {
      throw new Error('Test database not initialized. Call initialize() first.');
    }
    return this.testPool;
  }

  static async query(text: string, params?: any[]): Promise<any> {
    const pool = this.getPool();
    return pool.query(text, params);
  }

  static async clearAllTables(): Promise<void> {
    if (!this.testPool || !this.isInitialized) {
      throw new Error('Test database not initialized. Call initialize() first.');
    }

    const client = await this.testPool.connect();
    try {
      // Clear tables in reverse dependency order to avoid foreign key violations
      const tables = [
        'user_oauth_providers',
        'original_images', 
        'garment_items',
        'wardrobes',
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
      client.release();
    }
  }

  static async cleanup(): Promise<void> {
    try {
      await this.cleanupPools();
      await this.dropTestDatabase();
    } catch (error) {
      console.log('Cleanup error (may be expected):', error);
    } finally {
      this.resetState();
    }
  }

  private static async cleanupPools(): Promise<void> {
    // Close test pool
    if (this.testPool && !this.testPool.ended) {
      try {
        await this.testPool.end();
      } catch (error) {
        console.log('Error closing test pool:', error);
      }
    }
    this.testPool = null;

    // Close main pool
    if (this.mainPool && !this.mainPool.ended) {
      try {
        await this.mainPool.end();
      } catch (error) {
        console.log('Error closing main pool:', error);
      }
    }
    this.mainPool = null;
  }

  private static async dropTestDatabase(): Promise<void> {
    // Create a new connection just for cleanup
    const cleanupPool = new Pool({
      ...MAIN_DB_CONFIG,
      database: 'postgres'
    });

    try {
      // Terminate connections to test database
      await cleanupPool.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = 'koutu_test' AND pid <> pg_backend_pid()
      `);

      // Small delay to ensure connections are terminated
      await new Promise(resolve => setTimeout(resolve, 100));

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
  }

  // Utility method to check if initialized (for testing)
  static get initialized(): boolean {
    return this.isInitialized;
  }

  // Utility method to check if initializing (for testing)  
  static get initializing(): boolean {
    return this.isInitializing;
  }
}