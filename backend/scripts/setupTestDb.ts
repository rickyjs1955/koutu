// filepath: c:\Users\monmo\koutu\backend\scripts\setupTestDb.ts
import { Pool } from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const run = async () => {
  // Always use the test database URL
  const pool = new Pool({
    connectionString: 'postgresql://postgres:password@localhost:5433/koutu_test'
  });

  try {
    console.log('Setting up test database...');
    
    // Create migrations table
    await pool.query(\
      CREATE TABLE IF NOT EXISTS migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        applied_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    \);
    
    // Apply all migrations directly
    const migrationsDir = path.join(__dirname, '../migrations');
    const migrationFiles = fs.readdirSync(migrationsDir)
      .filter(file => file.endsWith('.sql'))
      .sort();
    
    for (const file of migrationFiles) {
      console.log(\Applying migration: \\);
      
      // Check if already applied
      const { rows } = await pool.query(
        'SELECT * FROM migrations WHERE name = ',
        [file]
      );
      
      if (rows.length > 0) {
        console.log(\Migration \ already applied, skipping\);
        continue;
      }
      
      // Read and execute the SQL file
      const filePath = path.join(migrationsDir, file);
      const sql = fs.readFileSync(filePath, 'utf8');
      
      // Execute the migration in a transaction
      await pool.query('BEGIN');
      try {
        await pool.query(sql);
        await pool.query(
          'INSERT INTO migrations (name) VALUES ()',
          [file]
        );
        await pool.query('COMMIT');
        console.log(\Successfully applied \\);
      } catch (error) {
        await pool.query('ROLLBACK');
        console.error(\Failed to apply \:\, error);
        throw error;
      }
    }
    
    console.log('Test database setup completed');
  } catch (error) {
    console.error('Test database setup failed:', error);
    throw error;
  } finally {
    await pool.end();
  }
};

run();
