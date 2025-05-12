// /backend/src/models/db.ts
import { Pool } from 'pg';
import { config } from '../config';

// Create database connection pool
export const pool = new Pool({
  connectionString: config.databaseUrl,
});

// Test the connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Database connected successfully');
  }
});

// Helper functions
export const query = async (text: string, params?: any[]) => {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  
  if (config.nodeEnv === 'development') {
    console.log('Executed query:', { text, params, duration, rows: res.rowCount });
  }
  
  return res;
};

export const getClient = () => {
  return pool.connect();
};