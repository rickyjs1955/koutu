#!/usr/bin/env node

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

async function initTestDatabase() {
  console.log('Initializing test database...');
  
  // First, ensure the database exists
  const adminPool = new Pool({
    host: 'localhost',
    port: 5433,
    user: 'postgres',
    password: 'postgres',
    database: 'postgres' // Connect to default postgres database
  });

  try {
    // Check if koutu_test database exists
    const dbCheck = await adminPool.query(
      "SELECT 1 FROM pg_database WHERE datname = 'koutu_test'"
    );
    
    if (dbCheck.rows.length === 0) {
      console.log('Creating koutu_test database...');
      await adminPool.query('CREATE DATABASE koutu_test');
    }
  } catch (error) {
    console.error('Error checking/creating database:', error);
    throw error;
  } finally {
    await adminPool.end();
  }

  // Now connect to koutu_test and apply schema
  const testPool = new Pool({
    host: 'localhost',
    port: 5433,
    user: 'postgres',
    password: 'postgres',
    database: 'koutu_test'
  });

  try {
    console.log('Applying test schema...');
    
    // Read and execute the test schema
    const schemaPath = path.join(__dirname, 'migrations', 'test_schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    
    await testPool.query(schemaSql);
    
    console.log('✅ Test database initialized successfully');
    
    // Verify tables exist
    const tableCheck = await testPool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name IN ('users', 'original_images', 'polygons', 'garment_items', 'wardrobes', 'wardrobe_items')
      ORDER BY table_name
    `);
    
    console.log('Tables created:', tableCheck.rows.map(r => r.table_name).join(', '));
    
    // Also check if the TestDatabaseConnection uses the correct schema path
    const testDbConnPath = path.join(__dirname, 'src', 'utils', 'testDatabaseConnection.ts');
    console.log('\nChecking TestDatabaseConnection configuration...');
    console.log('Looking for schema at:', path.join(__dirname, 'src', 'db', 'schema.sql'));
    
    // Create the schema in the expected location
    const dbDir = path.join(__dirname, 'src', 'db');
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
    
    // Copy test schema to the expected location
    const targetSchemaPath = path.join(dbDir, 'schema.sql');
    fs.copyFileSync(schemaPath, targetSchemaPath);
    console.log('Schema copied to:', targetSchemaPath);
    
  } catch (error) {
    console.error('❌ Error applying test schema:', error.message);
    throw error;
  } finally {
    await testPool.end();
  }
}

// Run initialization
initTestDatabase().catch(error => {
  console.error('Failed to initialize test database:', error);
  process.exit(1);
});