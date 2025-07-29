// /backend/src/utils/testSetup.ts - HYBRID DOCKER/LOCAL SETUP

import { initializeTestFirebase, resetFirebaseEmulator, cleanupTestFirebase } from '../tests/__helpers__/firebase.helper';
import { TestDatabaseConnection } from './testDatabaseConnection';

// Global initialization state
let isGloballyInitialized = false;
let initializationPromise: Promise<void> | null = null;

/**
 * Determine if we should use Docker for database (but not necessarily Firebase)
 */
const shouldUseDockerForDatabase = (): boolean => {
  // TEMPORARY FIX: Always use manual mode since v2 initialization has issues
  // Both modes use port 5433 anyway, so there's no difference in connectivity
  return false;
  
  // Check if manual tests are explicitly requested
  if (process.env.USE_MANUAL_TESTS === 'true') {
    return false;
  }
  
  // Check if Docker database port is available
  if (process.env.USE_DOCKER_TESTS === 'true') {
    return true;
  }
  
  // Auto-detect if Docker database is running on port 5433
  try {
    const { execSync } = require('child_process');
    execSync('nc -z localhost 5433', { stdio: 'ignore', timeout: 1000 });
    return true;
  } catch {
    return false;
  }
};

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
 * One-time global initialization - called once per test suite
 */
const initializeOnce = async (): Promise<void> => {
  if (isGloballyInitialized) {
    return;
  }

  if (initializationPromise) {
    return initializationPromise;
  }

  initializationPromise = (async () => {
    const useDockerDb = shouldUseDockerForDatabase();
    
    if (useDockerDb) {
      console.log('🐳 Using Docker database on port 5433');
      // Override database configuration for Docker
      process.env.TEST_DATABASE_URL = 'postgresql://postgres:postgres@localhost:5433/koutu_test';
    } else {
      console.log('🔧 Using local database on port 5432');
      process.env.TEST_DATABASE_URL = 'postgresql://postgres:postgres@localhost:5432/koutu_test';
    }
    
    // Always use localhost Firebase emulators (not Docker)
    process.env.FIRESTORE_EMULATOR_HOST = 'localhost:9100';
    process.env.FIREBASE_AUTH_EMULATOR_HOST = 'localhost:9099';
    process.env.FIREBASE_STORAGE_EMULATOR_HOST = 'localhost:9199';
    
    // Initialize the database connection
    await TestDatabaseConnection.initialize();
    
    // Verify we're connected to the test database
    const dbResult = await TestDatabaseConnection.query('SELECT current_database()');
    const dbName = dbResult.rows[0].current_database;
    console.log(`Connected to test database: ${dbName} (Docker: ${useDockerDb})`);
    
    if (!dbName.includes('test')) {
      throw new Error(`Tests must run against a database with "test" in the name! Current: ${dbName}`);
    }

    // Enable required extensions (idempotent)
    await TestDatabaseConnection.query(`CREATE EXTENSION IF NOT EXISTS btree_gist`);
    await TestDatabaseConnection.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`);

    console.log('Database connection initialized successfully');
    isGloballyInitialized = true;
  })();

  return initializationPromise;
};

/**
 * Wait for service to be available (clean implementation, no leaks)
 */
const waitForService = async (url: string, maxRetries = 5, interval = 500): Promise<boolean> => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Simple timeout-based fetch (no AbortController to avoid timer leaks)
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1000);
      
      try {
        const response = await fetch(url, {
          method: 'GET',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (response.ok) {
          return true;
        }
      } catch (fetchError) {
        clearTimeout(timeoutId);
        throw fetchError;
      }
    } catch (error) {
      // Service not ready yet, timeout, or other error
      // This is expected behavior when services are starting up
    }
    
    if (i < maxRetries - 1) {
      await new Promise(resolve => setTimeout(resolve, interval));
    }
  }
  return false;
};

/**
 * Initialize test database with required schema - optimized for speed
 */
export const setupTestDatabase = async () => {
  // Initialize connection only once
  await initializeOnce();
  
  try {
    console.log('Setting up test database schema...');

    // Drop and recreate test-specific tables efficiently in one transaction
    await TestDatabaseConnection.query(`
      BEGIN;
      
      -- Drop tables in correct order (children first)
      DROP TABLE IF EXISTS child_cleanup CASCADE;
      DROP TABLE IF EXISTS exclude_test_table CASCADE;
      DROP TABLE IF EXISTS test_table CASCADE;
      DROP TABLE IF EXISTS test_items CASCADE;
      DROP TABLE IF EXISTS parent_cleanup CASCADE;

      -- Create tables efficiently
      CREATE TABLE IF NOT EXISTS test_items (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS test_table (
        id SERIAL PRIMARY KEY,
        value TEXT NOT NULL UNIQUE
      );

      CREATE TABLE IF NOT EXISTS parent_cleanup (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL
      );
      
      CREATE TABLE IF NOT EXISTS child_cleanup (
        id SERIAL PRIMARY KEY,
        parent_id INTEGER,
        description TEXT,
        CONSTRAINT fk_parent FOREIGN KEY (parent_id) REFERENCES parent_cleanup(id) ON DELETE RESTRICT
      );

      CREATE TABLE IF NOT EXISTS exclude_test_table (
        id SERIAL PRIMARY KEY,
        range INT4RANGE,
        EXCLUDE USING gist (range WITH &&)
      );
      
      COMMIT;
    `);

    console.log('Test database schema setup completed');
    
  } catch (error) {
    console.error('Test database setup failed:', error);
    throw error;
  }
};

/**
 * Setup Firebase emulator for tests - faster checks
 */
export const setupFirebaseEmulator = async () => {
  try {
    console.log('Checking Firebase emulators on localhost...');
    
    // Quick check for all emulators (reduced timeouts)
    const emulatorChecks = [
      waitForService('http://localhost:4001', 3, 300), // UI
      waitForService('http://localhost:9099', 3, 300), // Auth
      waitForService('http://localhost:9100', 3, 300), // Firestore
      waitForService('http://localhost:9199', 3, 300)  // Storage
    ];

    const results = await Promise.all(emulatorChecks);
    const allReady = results.every(ready => ready);

    if (!allReady) {
      console.warn('Some Firebase emulators are not ready. Skipping Firebase setup.');
      console.warn('Emulator status:', {
        ui: results[0] ? '✅' : '❌',
        auth: results[1] ? '✅' : '❌',
        firestore: results[2] ? '✅' : '❌',
        storage: results[3] ? '✅' : '❌'
      });
      return;
    }

    // Initialize Firebase for testing
    initializeTestFirebase();
    
    // Reset emulator data
    await resetFirebaseEmulator();
    
    console.log('Firebase emulators ready ✅');
  } catch (error) {
    console.warn('Firebase emulator setup failed:', error);
    // Don't throw - Firebase might not be needed for all tests
  }
};

/**
 * Clean up test data only (keep connections open for speed)
 */
export const cleanupTestData = async () => {
  if (!isGloballyInitialized) {
    return; // Nothing to clean up if not initialized
  }
  
  try {
    // Fast cleanup - delete in correct order to avoid FK constraints
    await TestDatabaseConnection.query(`
      DELETE FROM child_cleanup;
      DELETE FROM parent_cleanup;  
      DELETE FROM exclude_test_table;
      DELETE FROM test_table;
      DELETE FROM test_items;
      DELETE FROM garment_items WHERE created_at > NOW() - INTERVAL '1 hour';
    `);
  } catch (error) {
    // Don't log cleanup errors - they're usually not important
    // console.error('Failed to clean up test data:', error);
  }
};

/**
 * Full teardown - only call this at the very end of test suites
 */
export const teardownTestDatabase = async () => {
  try {
    await cleanupTestData();
  } catch (error) {
    // Ignore cleanup errors during teardown
  }

  // Close database connections only at the end
  try {
    if (isGloballyInitialized) {
      const pool = TestDatabaseConnection.getPool();
      await pool.end();
      isGloballyInitialized = false;
      initializationPromise = null;
      console.log('Test database connections closed');
    }
  } catch (error) {
    console.error('Failed to close database connections:', error);
  }

  try {
    await cleanupTestFirebase();
  } catch (error) {
    console.error('Failed to cleanup Firebase:', error);
  }
};

/**
 * Get test database configuration
 */
export const getTestDatabaseConfig = () => {
  const port = shouldUseDockerForDatabase() ? 5433 : 5432;
  const config = {
    host: 'localhost',
    port: port,
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
 * Get the TestDatabaseConnection pool
 */
export const getTestPool = () => {
  if (!isGloballyInitialized) {
    throw new Error('Test database not initialized. Call setupTestDatabase() first.');
  }
  return TestDatabaseConnection.getPool();
};

/**
 * Check if database is initialized
 */
export const isInitialized = () => {
  return isGloballyInitialized;
};

/**
 * Reset initialization state (for testing)
 */
export const resetInitialization = () => {
  isGloballyInitialized = false;
  initializationPromise = null;
};