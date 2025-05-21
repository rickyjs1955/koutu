// /backend/src/models/db.ts
import { Pool } from 'pg';
import { config } from '../config';

let isPoolClosed = false;

// Create database connection pool
export const pool = new Pool({
  connectionString: config.databaseUrl,
});

// Only test connection in non-test environments
if (config.nodeEnv !== 'test') {
  pool.query('SELECT NOW()', (err, res) => {
    if (err) {
      console.error('Database connection error:', err.message);
    } else {
      console.log('Database connected successfully');
    }
  });
}

// Helper functions
export const query = async (text: string, params?: any[]) => {
    if (!text || text.trim().length === 0) {
        throw new Error('Query cannot be empty');
    }

    const start = Date.now();

    try {
        const res = await pool.query(text, params);
        const duration = Date.now() - start;

        if (config.nodeEnv === 'development') {
            console.log('Executed query:', { text, params, duration, rows: res.rowCount });
        }

        return res;
    } catch (error) {
        console.error(`Query failed: ${text}, Params: ${JSON.stringify(params)}, Error: ${(error as Error).message}`);
        if (error instanceof Error) {
            throw error;
        } else {
            // Wrap non-Error throwables in an Error object
            throw new Error(String(error));
        }
    }
};

export const getClient = async () => {
    try {
        return await pool.connect();
    } catch (error) {
        return Promise.reject(error);
    }
};

export const closePool = async () => {
  if (isPoolClosed) {
    console.log('Database pool already closed.');
    return;
  }
  
  try {
    await pool.end();
    isPoolClosed = true;
    console.log('Database pool closed successfully.');
  } catch (error) {
    console.error('Failed to close database pool:', error);
    throw error;
  }
};