import { Pool } from 'pg';

// Create a dedicated test pool that we KNOW works
const testPool = new Pool({
  host: 'localhost',
  port: 5433,
  user: 'postgres',
  password: 'password',
  database: 'koutu_test'
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
    // IMPORTANT: Use testQuery instead of query 
    const dbResult = await testQuery('SELECT current_database()');
    const dbName = dbResult.rows[0].current_database;
    
    if (!dbName.includes('test')) {
      throw new Error('Tests must run against a database with "test" in the name!');
    }
    
    // Create garment_items table for tests
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
    
    console.log('Test database initialized successfully');
  } catch (error) {
    console.error('Test database setup failed:', error);
    throw error;
  }
};

/**
 * Clean up test database resources
 */
export const teardownTestDatabase = async () => {
  await testPool.end();
};