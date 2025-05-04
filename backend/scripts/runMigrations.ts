// scripts/runMigrations.ts
import fs from 'fs';
import path from 'path';
import { Pool } from 'pg';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const run = async () => {
  // Create a database connection
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
  });

  try {
    // Create migrations table if it doesn't exist
    await pool.query(`
      CREATE TABLE IF NOT EXISTS migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        applied_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);

    // Get list of applied migrations
    const { rows: appliedMigrations } = await pool.query(
      'SELECT name FROM migrations ORDER BY id'
    );
    const appliedMigrationNames = appliedMigrations.map((m) => m.name);

    // Get list of migration files
    const migrationsDir = path.join(__dirname, '../migrations');
    const migrationFiles = fs
      .readdirSync(migrationsDir)
      .filter((file) => file.endsWith('.sql'))
      .sort(); // Ensures migrations run in the correct order

    // Run each migration that hasn't been applied yet
    for (const file of migrationFiles) {
      if (!appliedMigrationNames.includes(file)) {
        console.log(`Applying migration: ${file}`);
        
        // Read migration file
        const filePath = path.join(migrationsDir, file);
        const sql = fs.readFileSync(filePath, 'utf8');
        
        // Start a transaction
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          
          // Run the migration
          await client.query(sql);
          
          // Record the migration
          await client.query(
            'INSERT INTO migrations (name) VALUES ($1)',
            [file]
          );
          
          await client.query('COMMIT');
          console.log(`Successfully applied migration: ${file}`);
        } catch (err) {
          await client.query('ROLLBACK');
          console.error(`Failed to apply migration ${file}:`, err);
          throw err;
        } finally {
          client.release();
        }
      } else {
        console.log(`Migration already applied: ${file}`);
      }
    }

    console.log('All migrations have been applied successfully');
  } catch (err) {
    console.error('Error running migrations:', err);
    process.exit(1);
  } finally {
    await pool.end();
  }
};

// Run the migrations
run();
