// backend/src/config/index.ts
import dotenv from 'dotenv';
import path from 'path';

// --- NEW DEBUG LOGS START ---
console.log(`[DOTENV_DEBUG] BEFORE dotenv.config() - NODE_ENV: ${process.env.NODE_ENV}`);
console.log(`[DOTENV_DEBUG] BEFORE dotenv.config() - TEST_DATABASE_URL: ${process.env.TEST_DATABASE_URL}`);
console.log(`[DOTENV_DEBUG] Current Working Directory (CWD): ${process.cwd()}`);
// --- NEW DEBUG LOGS END ---

// Conditional loading of environment variables based on NODE_ENV
if (process.env.NODE_ENV === 'test') {
    const pathToEnvTest = path.resolve(process.cwd(), '.env.test');
    console.log(`[DOTENV_DEBUG] Attempting to load .env.test from path: ${pathToEnvTest}`);
    dotenv.config({ path: pathToEnvTest });

    // Remove hardcoded override - let testSetup.ts handle the port selection based on USE_DOCKER_TESTS

} else {
    dotenv.config();
}

// --- NEW DEBUG LOGS START ---
console.log(`[DOTENV_DEBUG] AFTER dotenv.config() (and potential force) - TEST_DATABASE_URL: ${process.env.TEST_DATABASE_URL}`);
// --- NEW DEBUG LOGS END ---


// Test-specific configuration
const getJwtSecret = () => {
    const nodeEnv = process.env.NODE_ENV;

    // In test environment, use a dedicated test secret
    if (nodeEnv === 'test') {
        return process.env.JWT_SECRET_TEST || 'test-jwt-secret-never-use-in-production-12345';
    }

    // In production/development, require JWT_SECRET
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error(`JWT_SECRET environment variable is required for ${nodeEnv} environment`);
    }

    // Additional validation for production
    if (nodeEnv === 'production' && secret.length < 32) {
        throw new Error('JWT_SECRET must be at least 32 characters in production');
    }

    return secret;
};

export const config = {
    port: process.env.PORT || 3000,
    nodeEnv: process.env.NODE_ENV || 'development',

    // Database
    databaseUrl: process.env.NODE_ENV === 'test'
        ? process.env.TEST_DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/koutu_test'
        : process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/koutu',
    dbPoolMax: parseInt(process.env.DB_POOL_MAX || (process.env.NODE_ENV === 'test' ? '5' : '10'), 10),
    dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
    dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
    dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
    dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true' || false,

    // JWT configuration with environment-specific handling
    jwtSecret: getJwtSecret(),
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',

    // File storage
    uploadsDir: path.join(__dirname, '../../../uploads'),
    maxFileSize: parseInt(
        process.env.MAX_FILE_SIZE ||
        (process.env.NODE_ENV === 'test' ? '1048576' : '8388608'), // 1MB for tests, 8MB for others
        10
    ),

    // Firebase configuration
    firebase: {
        projectId: process.env.FIREBASE_PROJECT_ID,
        privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
    },

    // Application settings
    logLevel: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'test' ? 'error' : 'info'),

    // Storage mode
    storageMode: process.env.STORAGE_MODE || (process.env.NODE_ENV === 'test' ? 'local' : 'firebase'),

    // App URL
    appUrl: process.env.APP_URL ||
        (process.env.NODE_ENV === 'test' ? 'http://localhost:3001' : 'http://localhost:3000'),

    // OAuth (disabled in test environment for security)
    oauth: process.env.NODE_ENV === 'test' ? {
        googleClientId: 'test-google-client-id',
        googleClientSecret: 'test-google-client-secret',
        microsoftClientId: 'test-microsoft-client-id',
        microsoftClientSecret: 'test-microsoft-client-secret',
        githubClientId: 'test-github-client-id',
        githubClientSecret: 'test-github-client-secret',
        instagramClientId: 'test-instagram-client-id',
        instagramClientSecret: 'test-instagram-client-secret',
    } : {
        googleClientId: process.env.GOOGLE_CLIENT_ID,
        googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
        microsoftClientId: process.env.MICROSOFT_CLIENT_ID,
        microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET,
        githubClientId: process.env.GITHUB_CLIENT_ID,
        githubClientSecret: process.env.GITHUB_CLIENT_SECRET,
        instagramClientId: process.env.INSTAGRAM_CLIENT_ID,
        instagramClientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
    },

    // Test-specific configurations
    test: process.env.NODE_ENV === 'test' ? {
        jwtSecret: 'test-jwt-secret-never-use-in-production-12345',
        jwtExpiresIn: '1h',
        maxUploadSize: 1048576, // 1MB
        rateLimitWindow: 60000, // 1 minute
        rateLimitMax: 100,
        mockExternalServices: true,
        disableLogging: true,
    } : undefined,
};

// Helper functions
export const isProd = () => process.env.NODE_ENV === 'production';
export const isDev = () => process.env.NODE_ENV === 'development';
export const isTest = () => process.env.NODE_ENV === 'test';

// Validation function to ensure configuration is valid
export const validateConfig = () => {
    const errors: string[] = [];

    if (isProd()) {
        // Production-specific validations
        if (!process.env.JWT_SECRET) {
            errors.push('JWT_SECRET is required in production');
        }

        if (!process.env.DATABASE_URL) {
            errors.push('DATABASE_URL is required in production');
        }

        if (!config.firebase.projectId && config.storageMode === 'firebase') {
            errors.push('Firebase configuration is incomplete for firebase storage mode');
        }

        // Validate OAuth secrets in production
        if (config.oauth.googleClientId && !config.oauth.googleClientSecret) {
            errors.push('GOOGLE_CLIENT_SECRET is required when GOOGLE_CLIENT_ID is set');
        }
    }

    if (errors.length > 0) {
        throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
    }

    return true;
};

// Export test-specific config getter
export const getTestConfig = () => {
    if (!isTest()) {
        throw new Error('getTestConfig() can only be called in test environment');
    }

    return {
        jwtSecret: 'test-jwt-secret-never-use-in-production-12345',
        jwtExpiresIn: '1h',
        maxFileSize: 1048576, // 1MB
        databaseUrl: process.env.TEST_DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/koutu_test',
        storageMode: 'local',
        disableExternalServices: true,
    };
};

// Auto-validate config on import (except in test environment)
if (!isTest()) {
    validateConfig();
}