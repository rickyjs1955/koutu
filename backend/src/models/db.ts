// /backend/src/models/db.ts
import { Pool, PoolConfig } from 'pg'; // Import PoolConfig
import { config } from '../config';

let isPoolClosed = false;

// Construct poolOptions object from config
const poolOptions: PoolConfig = {
  connectionString: config.databaseUrl,
};

if (config.dbPoolMax !== undefined) {
  poolOptions.max = config.dbPoolMax;
}
if (config.dbConnectionTimeout !== undefined && config.dbConnectionTimeout > 0) { // pg uses 0 for no timeout
  poolOptions.connectionTimeoutMillis = config.dbConnectionTimeout;
}
if (config.dbIdleTimeout !== undefined) {
  poolOptions.idleTimeoutMillis = config.dbIdleTimeout;
}
if (config.dbStatementTimeout !== undefined && config.dbStatementTimeout > 0) { // For client default statement_timeout
  poolOptions.statement_timeout = config.dbStatementTimeout;
}

// SSL Configuration
if (config.dbRequireSsl) {
  if (config.nodeEnv === 'production') {
    poolOptions.ssl = { rejectUnauthorized: true }; // Enforce verified SSL in prod
  } else {
    // For dev/test, you might allow self-signed or skip rejectUnauthorized
    // depending on your setup. For simplicity, if dbRequireSsl is true
    // but not prod, we'll assume a basic SSL requirement.
    poolOptions.ssl = { rejectUnauthorized: false }; // Example: allow self-signed for non-prod
  }
}


// Create database connection pool
export const pool = new Pool(poolOptions);

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