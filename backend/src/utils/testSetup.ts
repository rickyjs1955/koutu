import { Pool } from 'pg';

// Create a pool for the default postgres database to initialize koutu-postgres-test
const initPool = new Pool({
  host: 'localhost',
  port: 5433,
  user: 'postgres',
  password: 'password',
  database: 'postgres',
  connectionTimeoutMillis: 5000,
  ssl: false, // Disable SSL
});

// Create testPool for test queries
const testPool = new Pool({
  host: 'localhost',
  port: 5433,
  user: 'postgres',
  password: 'password',
  database: 'koutu-postgres-test',
  max: 20,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 30000,
  ssl: false, // Disable SSL
});

// Override the query function for tests
export const testQuery = async (text: string, params?: any[]) => {
  return testPool.query(text, params);
};

/**
 * Initialize test database with required schema
 */
export const setupTestDatabase = async () => {
  try {
    // Create koutu-postgres-test database if it doesn't exist
    const dbCheck = await initPool.query('SELECT 1 FROM pg_database WHERE datname = $1', ['koutu-postgres-test']);
    if (dbCheck.rowCount === 0) {
      await initPool.query('CREATE DATABASE "koutu-postgres-test"');
      console.log('Created koutu-postgres-test database');
    }

    // Verify connection to koutu-postgres-test
    const dbResult = await testQuery('SELECT current_database()');
    const dbName = dbResult.rows[0].current_database;
    console.log(`Connected to database: ${dbName}`);
    if (!dbName.includes('test')) {
      throw new Error('Tests must run against a database with "test" in the name!');
    }

    // Enable btree_gist extension for EXCLUDE constraints
    await testQuery(`CREATE EXTENSION IF NOT EXISTS btree_gist`);

    // Create garment_items table for garmentModel.int.test.ts
    await testQuery(`
      CREATE TABLE IF NOT EXISTS garment_items (
        id UUID PRIMARY KEY,
        user_id TEXT NOT NULL,
        original_image_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        mask_path TEXT NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMP WITH TIME ZONE NOT NULL,
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
        data_version INTEGER NOT NULL DEFAULT 1
      )
    `);

    // Create test_items table for db.int.test.ts
    await testQuery(`
      CREATE TABLE IF NOT EXISTS test_items (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Create test_table for db.int.test.ts
    await testQuery(`DROP TABLE IF EXISTS test_table`);
    await testQuery(`
      CREATE TABLE test_table (
        id SERIAL PRIMARY KEY,
        value TEXT NOT NULL UNIQUE
      )
    `);

    // Drop and re-create parent_cleanup and child_cleanup
    await testQuery(`DROP TABLE IF EXISTS child_cleanup`);
    await testQuery(`DROP TABLE IF EXISTS parent_cleanup`);
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

    // Drop and re-create exclude_test_table for EXCLUDE constraint tests
    await testQuery(`DROP TABLE IF EXISTS exclude_test_table`);
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
        WHERE table_schema = 'public' AND table_name IN ('parent_cleanup', 'child_cleanup', 'exclude_test_table')
    `);
    console.log('Tables created in setup:', tables.rows.map(row => row.table_name));

    console.log('Test database initialized successfully');
  } catch (error) {
    console.error('Test database setup failed:', error);
    throw error;
  } finally {
    await initPool.end(); // Close initPool
  }
};

/**
 * Clean up test database resources
 */
export const teardownTestDatabase = async () => {
  try {
    await testPool.end();
  } catch (error) {
    console.error('Failed to close testPool:', error);
  }
};