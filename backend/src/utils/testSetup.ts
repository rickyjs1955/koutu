// /backend/src/utils/testSetup.ts

import { cleanupTestFirebase, initializeTestFirebase, resetFirebaseEmulator } from '@/tests/__helpers__/firebase.helper';
import { Pool } from 'pg';

// Test database configuration - FIXED VERSION
const TEST_DB_CONFIG = {
  host: 'localhost',
  port: 5432,
  user: 'postgres',
  password: 'postgres',
  database: 'koutu_test',
  max: 20,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  ssl: false,
};

// Base config for connecting to postgres database (for database creation)
const BASE_DB_CONFIG = {
  ...TEST_DB_CONFIG,
  database: 'postgres' // Connect to default postgres database first
};

// Set environment variable for tests to use
process.env.TEST_DATABASE_URL = `postgresql://${TEST_DB_CONFIG.user}:${TEST_DB_CONFIG.password}@${TEST_DB_CONFIG.host}:${TEST_DB_CONFIG.port}/${TEST_DB_CONFIG.database}`;

// Create testPool for test queries
const testPool = new Pool(TEST_DB_CONFIG);

// Override the query function for tests
export const testQuery = async (text: string, params?: any[]) => {
  try {
    return await testPool.query(text, params);
  } catch (error) {
    console.error('Database query error:', error);
    console.error('Query:', text);
    console.error('Params:', params);
    throw error;
  }
};

/**
 * Wait for service to be available
 */
const waitForService = async (url: string, maxRetries = 30, interval = 1000): Promise<boolean> => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return true;
      }
    } catch (error) {
      // Service not ready yet
    }
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  return false;
};

/**
 * Create test database if it doesn't exist
 */
const ensureTestDatabase = async (): Promise<void> => {
  const basePool = new Pool(BASE_DB_CONFIG);
  
  try {
    // Check if test database exists
    const result = await basePool.query(
      "SELECT 1 FROM pg_database WHERE datname = $1",
      [TEST_DB_CONFIG.database]
    );
    
    if (result.rows.length === 0) {
      console.log(`Creating test database: ${TEST_DB_CONFIG.database}`);
      // Note: Database name cannot be parameterized, but we control this value
      await basePool.query(`CREATE DATABASE ${TEST_DB_CONFIG.database}`);
      console.log(`Test database ${TEST_DB_CONFIG.database} created successfully`);
    } else {
      console.log(`Test database ${TEST_DB_CONFIG.database} already exists`);
    }
  } catch (error) {
    console.error('Error ensuring test database exists:', error);
    throw error;
  } finally {
    await basePool.end();
  }
};

/**
 * Wait for PostgreSQL to be ready and ensure test database exists
 */
const waitForPostgreSQL = async (): Promise<boolean> => {
  const maxRetries = 30;
  
  // First, wait for PostgreSQL service to be available
  for (let i = 0; i < maxRetries; i++) {
    try {
      const basePool = new Pool(BASE_DB_CONFIG);
      const client = await basePool.connect();
      await client.query('SELECT 1');
      client.release();
      await basePool.end();
      console.log('PostgreSQL service is ready');
      break;
    } catch (error) {
      console.log(`Waiting for PostgreSQL service... (${i + 1}/${maxRetries})`);
      if (i === maxRetries - 1) {
        console.error('PostgreSQL service not ready after maximum retries');
        return false;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }

  // Ensure test database exists
  try {
    await ensureTestDatabase();
  } catch (error) {
    console.error('Failed to ensure test database exists:', error);
    return false;
  }

  // Now test connection to the test database
  for (let i = 0; i < maxRetries; i++) {
    try {
      const client = await testPool.connect();
      await client.query('SELECT 1');
      client.release();
      console.log(`Connected to test database: ${TEST_DB_CONFIG.database}`);
      return true;
    } catch (error) {
      console.log(`Waiting for test database connection... (${i + 1}/${maxRetries})`);
      if (i === maxRetries - 1) {
        console.error('Test database connection not ready after maximum retries');
        return false;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  return false;
};

/**
 * Initialize test database with required schema
 */
export const setupTestDatabase = async () => {
  try {
    console.log('Setting up test database...');
    
    // Wait for PostgreSQL to be ready and ensure test database exists
    const isReady = await waitForPostgreSQL();
    if (!isReady) {
      throw new Error('PostgreSQL test database is not ready after 30 seconds');
    }

    // Verify we're connected to the test database
    const dbResult = await testQuery('SELECT current_database()');
    const dbName = dbResult.rows[0].current_database;
    console.log(`Connected to database: ${dbName}`);
    
    if (!dbName.includes('test')) {
      throw new Error(`Tests must run against a database with "test" in the name! Current: ${dbName}`);
    }

    // Enable required extensions
    await testQuery(`CREATE EXTENSION IF NOT EXISTS btree_gist`);
    await testQuery(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);

    // Clean up existing tables (in correct order to handle foreign keys)
    await testQuery(`DROP TABLE IF EXISTS child_cleanup CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS parent_cleanup CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS exclude_test_table CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS test_table CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS test_items CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS garment_items CASCADE`);

    // Create garment_items table for garmentModel.int.test.ts
    await testQuery(`
      CREATE TABLE garment_items (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id TEXT NOT NULL,
        original_image_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        mask_path TEXT NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        data_version INTEGER NOT NULL DEFAULT 1
      )
    `);

    // Create test_items table for db.int.test.ts
    await testQuery(`
      CREATE TABLE test_items (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Create test_table for db.int.test.ts
    await testQuery(`
      CREATE TABLE test_table (
        id SERIAL PRIMARY KEY,
        value TEXT NOT NULL UNIQUE
      )
    `);

    // Create parent_cleanup and child_cleanup tables
    await testQuery(`
      CREATE TABLE parent_cleanup (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
      )
    `);
    
    await testQuery(`
      CREATE TABLE child_cleanup (
        id SERIAL PRIMARY KEY,
        parent_id INTEGER,
        description TEXT,
        CONSTRAINT fk_parent FOREIGN KEY (parent_id) REFERENCES parent_cleanup(id) ON DELETE RESTRICT
      )
    `);

    // Create exclude_test_table for EXCLUDE constraint tests
    await testQuery(`
      CREATE TABLE exclude_test_table (
        id SERIAL PRIMARY KEY,
        range INT4RANGE,
        EXCLUDE USING gist (range WITH &&)
      )
    `);

    // Verify table creation
    const tables = await testQuery(`
      SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' 
      ORDER BY table_name
    `);
    
    console.log('Tables created in test database:', tables.rows.map(row => row.table_name));
    console.log('Test database initialized successfully');
    
  } catch (error) {
    console.error('Test database setup failed:', error);
    throw error;
  }
};

/**
 * Setup Firebase emulator for tests
 */
export const setupFirebaseEmulator = async () => {
  try {
    console.log('Waiting for Firebase emulators to be ready...');
    
    // Wait for all emulators to be available
    const emulatorChecks = [
      waitForService('http://localhost:4001'), // UI
      waitForService('http://localhost:9099'), // Auth
      waitForService('http://localhost:9100'), // Firestore
      waitForService('http://localhost:9199')  // Storage
    ];

    const results = await Promise.all(emulatorChecks);
    const allReady = results.every(ready => ready);

    if (!allReady) {
      console.warn('Some Firebase emulators are not ready. Tests may fail if they require Firebase.');
      return;
    }

    // Initialize Firebase for testing
    initializeTestFirebase();
    
    // Reset emulator data
    await resetFirebaseEmulator();
    
    console.log('Firebase emulators initialized successfully');
    console.log('Firebase UI available at: http://localhost:4001');
  } catch (error) {
    console.error('Firebase emulator setup failed:', error);
    // Don't throw here - Firebase might not be needed for all tests
  }
};

/**
 * Clean up test database and Firebase resources
 */
export const teardownTestDatabase = async () => {
  try {
    // Clean up test data before closing connections
    await testQuery(`
      DELETE FROM child_cleanup;
      DELETE FROM parent_cleanup;
      DELETE FROM exclude_test_table;
      DELETE FROM test_table;
      DELETE FROM test_items;
      DELETE FROM garment_items;
    `);
    
    console.log('Test data cleaned up');
  } catch (error) {
    console.error('Failed to clean up test data:', error);
  }

  try {
    await testPool.end();
    console.log('Test database connections closed');
  } catch (error) {
    console.error('Failed to close testPool:', error);
  }

  try {
    await cleanupTestFirebase();
  } catch (error) {
    console.error('Failed to cleanup Firebase:', error);
  }
};

/**
 * Get test database configuration for other modules
 */
export const getTestDatabaseConfig = () => ({
  host: TEST_DB_CONFIG.host,
  port: TEST_DB_CONFIG.port,
  user: TEST_DB_CONFIG.user,
  password: TEST_DB_CONFIG.password,
  database: TEST_DB_CONFIG.database,
  connectionString: process.env.TEST_DATABASE_URL,
});

// Export pool for direct access if needed
export const getTestPool = () => testPool;