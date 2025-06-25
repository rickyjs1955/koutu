// /backend/src/utils/testDatabase.v2.ts - DOCKER MODE VERSION
/**
 * Docker Test Database Implementation
 * 
 * This version connects to Docker PostgreSQL containers for testing.
 * Compatible with the dual-mode infrastructure.
 * 
 * @author Development Team
 * @version 2.0.0 - Docker Mode
 * @since June 11, 2025
 */

import { Pool, Client } from 'pg';

const DOCKER_TEST_DB_CONFIG = {
  host: 'localhost',
  port: 5433, // Docker postgres-test service port
  user: 'postgres',
  password: 'postgres',
  database: 'koutu_test',
};

const DOCKER_MAIN_DB_CONFIG = {
  host: 'localhost',
  port: 5433, // Docker postgres-test service port
  user: 'postgres',
  password: 'postgres',
  database: 'postgres', // Connect to default postgres db for admin operations
};

export class TestDatabase {
  private static testPool: Pool | null = null;
  private static mainPool: Pool | null = null;
  private static isInitialized = false;

  static async initialize() {
    console.log('🐳 Setting up Docker test database...');
    
    // If already initialized, return existing pool
    if (this.isInitialized && this.testPool && !this.testPool.ended) {
      return this.testPool;
    }
    
    // Clean up any existing pools first
    if (this.testPool && !this.testPool.ended) {
      try {
        await this.testPool.end();
      } catch (error) {
        // Ignore errors when ending existing pools
      }
    }
    
    if (this.mainPool && !this.mainPool.ended) {
      try {
        await this.mainPool.end();
      } catch (error) {
        // Ignore errors when ending existing pools
      }
    }

    // Wait for Docker PostgreSQL to be ready
    await this.waitForDockerPostgreSQL();
    
    // Connect to main postgres database to create test database if needed
    this.mainPool = new Pool(DOCKER_MAIN_DB_CONFIG);
    
    try {
      // Terminate existing connections to the test database
      await this.mainPool.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = 'koutu_test' AND pid <> pg_backend_pid()
      `);
      
      // Check if database exists
      const dbCheck = await this.mainPool.query(
        'SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1) as exists',
        ['koutu_test']
      );
      console.log('DEBUG dbCheck:', dbCheck);
      if (dbCheck && Array.isArray(dbCheck.rows)) {
        console.log('DEBUG dbCheck.rows:', dbCheck.rows);
        if (dbCheck.rows[0]) {
          console.log('DEBUG dbCheck.rows[0].exists:', dbCheck.rows[0].exists);
        }
      }
      // Only create the database if it does not exist
      if (!dbCheck || !Array.isArray(dbCheck.rows) || dbCheck.rows.length === 0 || !dbCheck.rows[0].exists) {
        console.log('DEBUG: Creating database koutu_test');
        await this.mainPool.query('CREATE DATABASE koutu_test');
        console.log('🐳 Test database created in Docker container');
      } else {
        console.log('DEBUG: Database already exists, skipping creation');
      }
      
    } catch (error) {
      console.log('ℹ️ Docker test database setup:', error);
      // Re-throw the error to fail initialization if database creation fails
      throw error;
    }
    
    // Connect to test database
    this.testPool = new Pool(DOCKER_TEST_DB_CONFIG);
    
    // Create required extensions
    await this.testPool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    
    // Create complete schema
    await this.createDockerSchema();
    
    console.log('✅ Docker test database schema created');
    
    // Override the database connection for tests
    process.env.DATABASE_URL = `postgresql://postgres:postgres@localhost:5433/koutu_test`;
    process.env.TEST_DATABASE_URL = `postgresql://postgres:postgres@localhost:5433/koutu_test`;
    
    this.isInitialized = true;
    return this.testPool;
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
        const testPool = new Pool({
          host: 'localhost',
          port: 5433,
          user: 'postgres',
          password: 'postgres',
          database: 'postgres',
          max: 1,
          connectionTimeoutMillis: 2000
        });
        
        try {
          await testPool.query('SELECT 1');
          await testPool.end();
          console.log('✅ Docker PostgreSQL is ready');
          return;
        } catch (dbError) {
          await testPool.end().catch(() => {});
          throw dbError;
        }
      } catch (error) {
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
   * Create complete schema for Docker testing
   */
  private static async createDockerSchema(): Promise<void> {
    // Create users table with all necessary columns
    await this.testPool!.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        display_name VARCHAR(255),
        profile_image_url TEXT,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    // Create OAuth providers table
    await this.testPool!.query(`
      CREATE TABLE IF NOT EXISTS user_oauth_providers (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider VARCHAR(50) NOT NULL,
        provider_id VARCHAR(255) NOT NULL,
        provider_email VARCHAR(255),
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        UNIQUE(provider, provider_id)
      )
    `);

    // Create original_images table
    await this.testPool!.query(`
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
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    // Create garment_items table (removed SQL comments to avoid security test issues)
    await this.testPool!.query(`
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
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        file_path TEXT,
        mask_path TEXT,
        metadata JSONB DEFAULT '{}',
        data_version INTEGER DEFAULT 1
      )
    `);

    // Create wardrobes table
    await this.testPool!.query(`
      CREATE TABLE IF NOT EXISTS wardrobes (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT,
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    // Create wardrobe_items table
    await this.testPool!.query(`
      CREATE TABLE IF NOT EXISTS wardrobe_items (
        id SERIAL PRIMARY KEY,
        wardrobe_id UUID NOT NULL REFERENCES wardrobes(id) ON DELETE CASCADE,
        garment_item_id UUID NOT NULL REFERENCES garment_items(id) ON DELETE CASCADE,
        position INTEGER DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        UNIQUE(wardrobe_id, garment_item_id)
      )
    `);

    // Create indexes for performance (single query to reduce call count)
    await this.testPool!.query(`
      CREATE INDEX IF NOT EXISTS idx_original_images_user_id ON original_images(user_id);
      CREATE INDEX IF NOT EXISTS idx_garment_items_user_id ON garment_items(user_id);
      CREATE INDEX IF NOT EXISTS idx_wardrobes_user_id ON wardrobes(user_id);
      CREATE INDEX IF NOT EXISTS idx_wardrobe_items_wardrobe_id ON wardrobe_items(wardrobe_id);
      CREATE INDEX IF NOT EXISTS idx_wardrobe_items_garment_id ON wardrobe_items(garment_item_id);
    `);
  }

  static async cleanup() {
    console.log('🧹 Cleaning up Docker test database...');
    
    this.isInitialized = false;
    
    if (this.testPool && !this.testPool.ended) {
      try {
        await this.testPool.end();
      } catch (error) {
        console.log('⚠️ Error ending Docker test pool:', error);
      }
    }
    this.testPool = null;
    
    if (this.mainPool && !this.mainPool.ended) {
      try {
        // Don't drop the database in Docker mode - container persists
        // Just clear data instead
        await this.mainPool.end();
      } catch (error) {
        console.log('⚠️ Error ending Docker main pool:', error);
      }
    }
    this.mainPool = null;
    
    console.log('✅ Docker test database cleanup complete (container persists)');
  }

  static async clearAllTables() {
    if (!this.testPool || this.testPool.ended) return;
    
    try {
      // Clear tables in reverse dependency order
      await this.testPool.query(`
        DELETE FROM wardrobe_items;
        DELETE FROM user_oauth_providers;
        DELETE FROM garment_items;
        DELETE FROM wardrobes;
        DELETE FROM original_images;
        DELETE FROM users;
      `);
      console.log('🐳 All Docker test tables cleared');
    } catch (error) {
      console.log('⚠️ Error clearing Docker tables:', error);
    }
  }

  static getPool() {
    return this.testPool;
  }

  static async query(text: string, params?: any[]) {
    if (!this.testPool || this.testPool.ended) {
      throw new Error('Docker test database not initialized or has been closed. Call initialize() first.');
    }
    if (typeof params !== 'undefined') {
      return this.testPool.query(text, params);
    } else {
      return this.testPool.query(text);
    }
  }
}