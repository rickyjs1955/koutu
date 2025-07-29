#!/usr/bin/env node

const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

async function applyTestSchema() {
  // Use the test database on port 5433
  const pool = new Pool({
    connectionString: 'postgresql://postgres:postgres@localhost:5433/koutu_test'
  });

  try {
    console.log('Applying test schema...');
    
    // Read the test schema SQL file
    const schemaPath = path.join(__dirname, 'migrations', 'test_schema.sql');
    const schemaSql = fs.readFileSync(schemaPath, 'utf8');
    
    // Execute the schema
    await pool.query(schemaSql);
    
    console.log('✅ Test schema applied successfully');
    
    // Verify tables exist
    const result = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name IN ('users', 'original_images', 'polygons', 'garment_items', 'wardrobes', 'wardrobe_items')
      ORDER BY table_name
    `);
    
    console.log('Tables created:', result.rows.map(r => r.table_name).join(', '));
    
  } catch (error) {
    console.error('❌ Error applying test schema:', error.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

applyTestSchema();