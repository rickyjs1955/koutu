// /backend/src/utils/testSetup.ts - RESTORED TO ORIGINAL

import { cleanupTestFirebase, initializeTestFirebase, resetFirebaseEmulator } from '@/tests/__helpers__/firebase.helper';
import { TestDatabaseConnection } from './testDatabaseConnection';

/**
 * Use TestDatabaseConnection for all queries - this ensures unified connection management
 */
export const testQuery = async (text: string, params?: any[]) => {
  try {
    return await TestDatabaseConnection.query(text, params);
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
 * Wait for PostgreSQL to be ready and ensure test database exists
 */
const waitForPostgreSQL = async (): Promise<boolean> => {
  try {
    // Initialize TestDatabaseConnection - this handles database creation
    await TestDatabaseConnection.initialize();
    console.log('PostgreSQL service is ready');
    
    // Test the connection
    const dbResult = await TestDatabaseConnection.query('SELECT current_database()');
    const dbName = dbResult.rows[0].current_database;
    console.log(`Connected to test database: ${dbName}`);
    
    return true;
  } catch (error) {
    console.error('PostgreSQL connection failed:', error);
    return false;
  }
};

/**
 * Initialize test database with required schema
 */
export const setupTestDatabase = async () => {
  try {
    console.log('Setting up test database...');
    
    // Wait for PostgreSQL to be ready
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

    // Clean up existing test-specific tables (preserve the main tables created by TestDatabaseConnection)
    await testQuery(`DROP TABLE IF EXISTS child_cleanup CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS parent_cleanup CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS exclude_test_table CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS test_table CASCADE`);
    await testQuery(`DROP TABLE IF EXISTS test_items CASCADE`);

    // Create additional test tables that aren't in the main schema
    await testQuery(`
      CREATE TABLE test_items (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    await testQuery(`
      CREATE TABLE test_table (
        id SERIAL PRIMARY KEY,
        value TEXT NOT NULL UNIQUE
      )
    `);

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
    
    console.log('Tables created in test database:', tables.rows.map((row: { table_name: string }) => row.table_name));
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

  console.log('Test database connections closed');

  try {
    await cleanupTestFirebase();
  } catch (error) {
    console.error('Failed to cleanup Firebase:', error);
  }
};

/**
 * Get test database configuration for other modules
 */
export const getTestDatabaseConfig = () => {
  const config = {
    host: 'localhost',
    port: 5433,
    user: 'postgres', 
    password: 'postgres',
    database: 'koutu_test'
  };
  
  return {
    ...config,
    connectionString: `postgresql://${config.user}:${config.password}@${config.host}:${config.port}/${config.database}`
  };
};

/**
 * Get the TestDatabaseConnection pool (unified access)
 */
export const getTestPool = () => TestDatabaseConnection.getPool();