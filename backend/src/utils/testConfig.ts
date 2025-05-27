// /backend/src/utils/testConfig.ts

import { config } from 'dotenv';

// Load test environment variables
config({ path: '.env.test' });

export const TEST_DB_CONFIG = {
    host: 'localhost',
    port: 5432, // Use same port as your Docker container
    user: 'postgres',
    password: 'postgres',
    database: 'koutu_test',
    max: 20,
    connectionTimeoutMillis: 10000,
    idleTimeoutMillis: 30000,
    ssl: false,
};

export const MAIN_DB_CONFIG = {
    ...TEST_DB_CONFIG,
    database: 'postgres', // Default postgres database
};