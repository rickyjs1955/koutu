// /backend/src/utils/testConfig.ts

import { PoolConfig } from 'pg';

// Determine the port based on USE_DOCKER_TESTS environment variable
const getDbPort = () => {
  if (process.env.USE_DOCKER_TESTS === 'true') {
    return 5433;
  }
  return parseInt(process.env.DB_PORT || '5432');
};

export const MAIN_DB_CONFIG: PoolConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: getDbPort(),
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: 'postgres', // Main database for administrative operations
  max: 5, // Lower max for admin operations
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  ssl: false
};

export const TEST_DB_CONFIG: PoolConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: getDbPort(),
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'postgres',
  database: 'koutu_test',
  max: 20,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 10000,
  ssl: false
};