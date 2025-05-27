// /backend/src/utils/testDatabaseConnection.ts

import { Pool } from 'pg';
import { TEST_DB_CONFIG, MAIN_DB_CONFIG } from './testConfig';

export class TestDatabaseConnection {
    private static testPool: Pool;
    private static mainPool: Pool;
    private static isInitialized = false;

    static async initialize() {
        if (this.isInitialized) {
        return this.testPool;
        }

        console.log('🔧 Setting up test database connection...');
        
        // Connect to main postgres database first
        this.mainPool = new Pool(MAIN_DB_CONFIG);
        
        try {
        // Terminate existing connections to test database
        await this.mainPool.query(`
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = 'koutu_test' AND pid <> pg_backend_pid()
        `);
        
        // Drop and recreate test database
        await this.mainPool.query('DROP DATABASE IF EXISTS koutu_test');
        await this.mainPool.query('CREATE DATABASE koutu_test');
        
        console.log('✅ Test database created');
        } catch (error) {
        console.log('ℹ️ Test database setup issue:', error);
        }
        
        // Connect to test database
        this.testPool = new Pool(TEST_DB_CONFIG);
        
        // Create required extensions
        await this.testPool.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
        
        // Create all required tables
        await this.createSchema();
        
        console.log('✅ Test database schema created');
        
        this.isInitialized = true;
        return this.testPool;
    }

    private static async createSchema() {
        // Create users table
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
    }

    static async cleanup() {
        console.log('🧹 Cleaning up test database...');
        
        if (this.testPool) {
        await this.testPool.end();
        }
        
        if (this.mainPool) {
        try {
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
        
        this.isInitialized = false;
    }

    static async clearAllTables() {
        if (!this.testPool) return;
        
        await this.testPool.query(`
        TRUNCATE wardrobes, garment_items, original_images, user_oauth_providers, users 
        RESTART IDENTITY CASCADE
        `);
    }

    static getPool() {
        return this.testPool;
    }

    static async query(text: string, params?: any[]) {
        if (!this.testPool) {
        throw new Error('Test database not initialized. Call initialize() first.');
        }
        return this.testPool.query(text, params);
    }
}