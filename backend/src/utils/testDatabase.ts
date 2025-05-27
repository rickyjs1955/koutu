// /backend/src/utils/testDatabase.ts

import { Pool, Client } from 'pg';
import { config } from 'dotenv';

// Load test environment
config({ path: '.env.test' });

const TEST_DB_CONFIG = {
  host: 'localhost',
  port: 5432,
  user: 'postgres',
  password: 'postgres',
  database: 'koutu_test',
};

const MAIN_DB_CONFIG = {
  host: 'localhost',
  port: 5432,
  user: 'postgres',
  password: 'postgres',
  database: 'postgres', // Connect to default postgres db to create test db
};

export class TestDatabase {
  private static testPool: Pool;
  private static mainPool: Pool;

  static async initialize() {
    console.log('🔧 Setting up test database...');
    
    // Connect to main postgres database to create test database
    this.mainPool = new Pool(MAIN_DB_CONFIG);
    
    try {
      // Create test database if it doesn't exist
      await this.mainPool.query(`
        SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
        WHERE datname = 'koutu_test' AND pid <> pg_backend_pid()
      `);
      
      await this.mainPool.query('DROP DATABASE IF EXISTS koutu_test');
      await this.mainPool.query('CREATE DATABASE koutu_test');
      
      console.log('✅ Test database created');
    } catch (error) {
      console.log('ℹ️ Test database already exists or error creating:', error);
    }
    
    // Connect to test database
    this.testPool = new Pool(TEST_DB_CONFIG);
    
    // Create required extensions
    await this.testPool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    
    // Create users table with all necessary columns
    await this.testPool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        name TEXT,
        avatar_url TEXT,
        oauth_provider TEXT,
        oauth_id TEXT,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    // Create OAuth providers table
    await this.testPool.query(`
      CREATE TABLE IF NOT EXISTS user_oauth_providers (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        UNIQUE(provider, provider_id)
      )
    `);

    // Create statistics tables
    await this.testPool.query(`
      CREATE TABLE IF NOT EXISTS original_images (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    await this.testPool.query(`
      CREATE TABLE IF NOT EXISTS garment_items (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    await this.testPool.query(`
      CREATE TABLE IF NOT EXISTS wardrobes (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    console.log('✅ Test database schema created');
    
    // Override the database connection for tests
    process.env.DATABASE_URL = `postgresql://postgres:postgres@localhost:5432/koutu_test`;
    
    return this.testPool;
  }

  static async cleanup() {
    console.log('🧹 Cleaning up test database...');
    
    if (this.testPool) {
      await this.testPool.end();
    }
    
    if (this.mainPool) {
      try {
        // Drop test database
        await this.mainPool.query(`
          SELECT pg_terminate_backend(pid)
          FROM pg_stat_activity
          WHERE datname = 'koutu_test' AND pid <> pg_backend_pid()
        `);
        await this.mainPool.query('DROP DATABASE IF EXISTS koutu_test');
        console.log('✅ Test database dropped');
      } catch (error) {
        console.log('⚠️ Error dropping test database:', error);
      }
      
      await this.mainPool.end();
    }
  }

  static async clearAllTables() {
    if (!this.testPool) return;
    
    await this.testPool.query('TRUNCATE wardrobes, garment_items, original_images, user_oauth_providers, users RESTART IDENTITY CASCADE');
  }

  static getPool() {
    return this.testPool;
  }

  static async query(text: string, params?: any[]) {
    return this.testPool.query(text, params);
  }
}