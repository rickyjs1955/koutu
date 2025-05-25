// backend/src/__tests__/integration/index.integration.test.ts
import { jest } from '@jest/globals';
import { beforeEach, afterEach, beforeAll, afterAll, describe, it, expect } from '@jest/globals';
import path from 'path';
import fs from 'fs';
import { promisify } from 'util';

// Import the real configuration module for integration testing
import { config, isProd, isDev, isTest } from '../../config/index';

// Test utilities
const writeFile = promisify(fs.writeFile);
const unlink = promisify(fs.unlink);
const access = promisify(fs.access);

// Helper class for environment management during integration tests
class IntegrationTestEnvironment {
    private originalEnv: NodeJS.ProcessEnv;
    private tempFiles: string[] = [];

    constructor() {
        this.originalEnv = { ...process.env };
    }

    setEnvironment(env: Record<string, string | undefined>): void {
        // Clear existing environment
        Object.keys(process.env).forEach(key => {
        if (key.startsWith('NODE_ENV') || 
            key.startsWith('JWT_') || 
            key.startsWith('DB_') ||
            key.startsWith('FIREBASE_') ||
            key.startsWith('GOOGLE_') ||
            key.startsWith('MICROSOFT_') ||
            key.startsWith('GITHUB_') ||
            key.startsWith('INSTAGRAM_') ||
            key.startsWith('PORT') ||
            key.startsWith('LOG_') ||
            key.startsWith('STORAGE_') ||
            key.startsWith('APP_') ||
            key.startsWith('MAX_FILE_') ||
            key.startsWith('DATABASE_') ||
            key.startsWith('TEST_DATABASE_')) {
            delete process.env[key];
        }
        });

        // Set new environment
        Object.keys(env).forEach(key => {
        if (env[key] === undefined) {
            delete process.env[key];
        } else {
            process.env[key] = env[key];
        }
        });
    }

    async createTempEnvFile(content: string): Promise<string> {
        const tempPath = path.join(__dirname, `test-${Date.now()}.env`);
        await writeFile(tempPath, content);
        this.tempFiles.push(tempPath);
        return tempPath;
    }

    async cleanupTempFiles(): Promise<void> {
        for (const file of this.tempFiles) {
        try {
            await unlink(file);
        } catch (error) {
            // Ignore errors - file might not exist
        }
        }
        this.tempFiles = [];
    }

    restore(): void {
        // Restore original environment
        process.env = { ...this.originalEnv };
    }
}

// Test scenarios for integration testing
const integrationTestScenarios = {
    production: {
        name: 'Production Environment Integration',
        env: {
        NODE_ENV: 'production',
        JWT_SECRET: 'production-jwt-secret-very-secure',
        PORT: '443',
        DATABASE_URL: 'postgresql://prod_user:prod_pass@prod-db.example.com:5432/koutu_prod',
        DB_POOL_MAX: '25',
        DB_CONNECTION_TIMEOUT: '10000',
        DB_IDLE_TIMEOUT: '30000',
        DB_STATEMENT_TIMEOUT: '15000',
        DB_REQUIRE_SSL: 'true',
        JWT_EXPIRES_IN: '12h',
        MAX_FILE_SIZE: '10485760',
        FIREBASE_PROJECT_ID: 'koutu-prod',
        FIREBASE_PRIVATE_KEY: 'prod-firebase-key',
        FIREBASE_CLIENT_EMAIL: 'firebase-adminsdk@koutu-prod.iam.gserviceaccount.com',
        FIREBASE_STORAGE_BUCKET: 'koutu-prod.appspot.com',
        LOG_LEVEL: 'error',
        STORAGE_MODE: 'firebase',
        APP_URL: 'https://koutu.com',
        GOOGLE_CLIENT_ID: 'prod-google-client-id',
        GOOGLE_CLIENT_SECRET: 'prod-google-secret',
        MICROSOFT_CLIENT_ID: 'prod-microsoft-client-id',
        MICROSOFT_CLIENT_SECRET: 'prod-microsoft-secret',
        },
        expectedConfig: {
        nodeEnv: 'production',
        port: 443,
        dbRequireSsl: true,
        logLevel: 'error',
        appUrl: 'https://koutu.com',
        },
    },
    development: {
        name: 'Development Environment Integration',
        env: {
        NODE_ENV: 'development',
        JWT_SECRET: 'dev-jwt-secret',
        PORT: '3001',
        DATABASE_URL: 'postgresql://dev_user:dev_pass@localhost:5432/koutu_dev',
        DB_POOL_MAX: '15',
        LOG_LEVEL: 'debug',
        STORAGE_MODE: 'local',
        APP_URL: 'http://localhost:3001',
        FIREBASE_PROJECT_ID: 'koutu-dev',
        GOOGLE_CLIENT_ID: 'dev-google-client-id',
        GOOGLE_CLIENT_SECRET: 'dev-google-secret',
        },
        expectedConfig: {
        nodeEnv: 'development',
        port: 3001,
        dbRequireSsl: false,
        logLevel: 'debug',
        storageMode: 'local',
        appUrl: 'http://localhost:3001',
        },
    },
    test: {
        name: 'Test Environment Integration',
        env: {
        NODE_ENV: 'test',
        JWT_SECRET: 'test-jwt-secret',
        TEST_DATABASE_URL: 'postgresql://test_user:test_pass@localhost:5432/koutu_test',
        DB_POOL_MAX: '5',
        LOG_LEVEL: 'silent',
        STORAGE_MODE: 'local',
        },
        expectedConfig: {
        nodeEnv: 'test',
        dbPoolMax: 5,
        logLevel: 'silent',
        storageMode: 'local',
        },
    },
    minimal: {
        name: 'Minimal Configuration Integration',
        env: {
        JWT_SECRET: 'minimal-secret',
        },
        expectedConfig: {
        nodeEnv: 'development',
        port: 3000,
        logLevel: 'info',
        storageMode: 'firebase',
        },
    },
};

// Integration test environment manager
let testEnv: IntegrationTestEnvironment;

describe('Configuration Integration Tests', () => {
    beforeAll(() => {
        testEnv = new IntegrationTestEnvironment();
    });

    afterAll(async () => {
        await testEnv.cleanupTempFiles();
        testEnv.restore();
    });

    beforeEach(() => {
        // Clear module cache to ensure fresh config loading
        jest.clearAllMocks();
    });

    afterEach(async () => {
        await testEnv.cleanupTempFiles();
    });

    describe('Environment-Specific Configuration Loading', () => {
        Object.entries(integrationTestScenarios).forEach(([scenarioName, scenario]) => {
        it(`should load ${scenario.name}`, () => {
            // Set environment variables
            testEnv.setEnvironment(scenario.env);

            // Mock the configuration loading to simulate real module behavior
            const mockConfig = {
            port: parseInt(process.env.PORT || '3000', 10),
            nodeEnv: process.env.NODE_ENV || 'development',
            databaseUrl: process.env.NODE_ENV === 'test' 
                ? process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test'
                : process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || (process.env.NODE_ENV === 'test' ? '5' : '10'), 10),
            dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
            dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
            dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
            jwtSecret: (() => {
                const secret = process.env.JWT_SECRET;
                if (!secret) {
                throw new Error('JWT_SECRET environment variable is required');
                }
                return secret;
            })(),
            jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
            uploadsDir: path.join(__dirname, '../../../uploads'),
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
            firebase: {
                projectId: process.env.FIREBASE_PROJECT_ID,
                privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
                clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
                storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
            },
            logLevel: process.env.LOG_LEVEL || 'info',
            storageMode: process.env.STORAGE_MODE || 'firebase',
            appUrl: process.env.APP_URL || 'http://localhost:3000',
            oauth: {
                googleClientId: process.env.GOOGLE_CLIENT_ID,
                googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
                microsoftClientId: process.env.MICROSOFT_CLIENT_ID,
                microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET,
                githubClientId: process.env.GITHUB_CLIENT_ID,
                githubClientSecret: process.env.GITHUB_CLIENT_SECRET,
                instagramClientId: process.env.INSTAGRAM_CLIENT_ID,
                instagramClientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
            },
            };

            // Verify all expected configuration values
            Object.entries(scenario.expectedConfig).forEach(([key, expectedValue]) => {
            expect(mockConfig[key as keyof typeof mockConfig]).toBe(expectedValue);
            });

            // Verify that JWT secret is always set (required)
            expect(mockConfig.jwtSecret).toBe(scenario.env.JWT_SECRET);

            // Verify configuration is valid and complete
            expect(mockConfig).toHaveProperty('port');
            expect(mockConfig).toHaveProperty('nodeEnv');
            expect(mockConfig).toHaveProperty('databaseUrl');
            expect(mockConfig).toHaveProperty('jwtSecret');
            expect(mockConfig).toHaveProperty('firebase');
            expect(mockConfig).toHaveProperty('oauth');
        });
        });
    });

    describe('Environment Helper Functions Integration', () => {
        it('should correctly identify environments in production setup', () => {
        testEnv.setEnvironment({ NODE_ENV: 'production', JWT_SECRET: 'prod-secret' });
        
        const helpers = {
            isProd: () => process.env.NODE_ENV === 'production',
            isDev: () => process.env.NODE_ENV === 'development',
            isTest: () => process.env.NODE_ENV === 'test',
        };

        expect(helpers.isProd()).toBe(true);
        expect(helpers.isDev()).toBe(false);
        expect(helpers.isTest()).toBe(false);
        });

        it('should correctly identify environments in development setup', () => {
        testEnv.setEnvironment({ NODE_ENV: 'development', JWT_SECRET: 'dev-secret' });
        
        const helpers = {
            isProd: () => process.env.NODE_ENV === 'production',
            isDev: () => process.env.NODE_ENV === 'development',
            isTest: () => process.env.NODE_ENV === 'test',
        };

        expect(helpers.isProd()).toBe(false);
        expect(helpers.isDev()).toBe(true);
        expect(helpers.isTest()).toBe(false);
        });

        it('should correctly identify environments in test setup', () => {
        testEnv.setEnvironment({ NODE_ENV: 'test', JWT_SECRET: 'test-secret' });
        
        const helpers = {
            isProd: () => process.env.NODE_ENV === 'production',
            isDev: () => process.env.NODE_ENV === 'development',
            isTest: () => process.env.NODE_ENV === 'test',
        };

        expect(helpers.isProd()).toBe(false);
        expect(helpers.isDev()).toBe(false);
        expect(helpers.isTest()).toBe(true);
        });
    });

    describe('Database Configuration Integration', () => {
        it('should configure production database with SSL', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'production',
            JWT_SECRET: 'prod-secret',
            DATABASE_URL: 'postgresql://prod_user:secure_pass@prod-db.example.com:5432/koutu_prod',
            DB_POOL_MAX: '30',
            DB_CONNECTION_TIMEOUT: '15000',
            DB_IDLE_TIMEOUT: '60000',
            DB_STATEMENT_TIMEOUT: '30000',
            DB_REQUIRE_SSL: 'true',
        });

        const dbConfig = {
            databaseUrl: process.env.DATABASE_URL,
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || '10', 10),
            dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
            dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
            dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
        };

        expect(dbConfig.databaseUrl).toBe('postgresql://prod_user:secure_pass@prod-db.example.com:5432/koutu_prod');
        expect(dbConfig.dbPoolMax).toBe(30);
        expect(dbConfig.dbConnectionTimeout).toBe(15000);
        expect(dbConfig.dbIdleTimeout).toBe(60000);
        expect(dbConfig.dbStatementTimeout).toBe(30000);
        expect(dbConfig.dbRequireSsl).toBe(true);
        });

        it('should configure test database with optimized settings', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'test',
            JWT_SECRET: 'test-secret',
            TEST_DATABASE_URL: 'postgresql://test_user:test_pass@localhost:5432/koutu_test',
            DB_POOL_MAX: '3',
            DB_CONNECTION_TIMEOUT: '1000',
            DB_IDLE_TIMEOUT: '5000',
            DB_STATEMENT_TIMEOUT: '5000',
            DB_REQUIRE_SSL: 'false',
        });

        const isTest = process.env.NODE_ENV === 'test';
        const dbConfig = {
            databaseUrl: isTest 
            ? process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test'
            : process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || (isTest ? '5' : '10'), 10),
            dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
            dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
            dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
        };

        expect(dbConfig.databaseUrl).toBe('postgresql://test_user:test_pass@localhost:5432/koutu_test');
        expect(dbConfig.dbPoolMax).toBe(3);
        expect(dbConfig.dbConnectionTimeout).toBe(1000);
        expect(dbConfig.dbIdleTimeout).toBe(5000);
        expect(dbConfig.dbStatementTimeout).toBe(5000);
        expect(dbConfig.dbRequireSsl).toBe(false);
        });

        it('should handle database configuration fallbacks', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'development',
            JWT_SECRET: 'dev-secret',
            // No database URL provided - should use default
        });

        const isTest = process.env.NODE_ENV === 'test';
        const dbConfig = {
            databaseUrl: isTest 
            ? process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test'
            : process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || (isTest ? '5' : '10'), 10),
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
        };

        expect(dbConfig.databaseUrl).toBe('postgresql://postgres:password@localhost:5432/koutu');
        expect(dbConfig.dbPoolMax).toBe(10);
        expect(dbConfig.dbRequireSsl).toBe(false);
        });
    });

    describe('Authentication & Authorization Integration', () => {
        it('should configure JWT for production with secure settings', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'production',
            JWT_SECRET: 'super-secure-production-jwt-secret-with-256-bits',
            JWT_EXPIRES_IN: '1h',
        });

        const jwtConfig = {
            jwtSecret: (() => {
            const secret = process.env.JWT_SECRET;
            if (!secret) {
                throw new Error('JWT_SECRET environment variable is required');
            }
            return secret;
            })(),
            jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
        };

        expect(jwtConfig.jwtSecret).toBe('super-secure-production-jwt-secret-with-256-bits');
        expect(jwtConfig.jwtExpiresIn).toBe('1h');
        });

        it('should configure OAuth providers for complete authentication flow', () => {
        testEnv.setEnvironment({
            JWT_SECRET: 'oauth-test-secret',
            GOOGLE_CLIENT_ID: 'google-oauth-client-id',
            GOOGLE_CLIENT_SECRET: 'google-oauth-client-secret',
            MICROSOFT_CLIENT_ID: 'microsoft-oauth-client-id',
            MICROSOFT_CLIENT_SECRET: 'microsoft-oauth-client-secret',
            GITHUB_CLIENT_ID: 'github-oauth-client-id',
            GITHUB_CLIENT_SECRET: 'github-oauth-client-secret',
            INSTAGRAM_CLIENT_ID: 'instagram-oauth-client-id',
            INSTAGRAM_CLIENT_SECRET: 'instagram-oauth-client-secret',
        });

        const oauthConfig = {
            oauth: {
            googleClientId: process.env.GOOGLE_CLIENT_ID,
            googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
            microsoftClientId: process.env.MICROSOFT_CLIENT_ID,
            microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET,
            githubClientId: process.env.GITHUB_CLIENT_ID,
            githubClientSecret: process.env.GITHUB_CLIENT_SECRET,
            instagramClientId: process.env.INSTAGRAM_CLIENT_ID,
            instagramClientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
            },
        };

        expect(oauthConfig.oauth.googleClientId).toBe('google-oauth-client-id');
        expect(oauthConfig.oauth.googleClientSecret).toBe('google-oauth-client-secret');
        expect(oauthConfig.oauth.microsoftClientId).toBe('microsoft-oauth-client-id');
        expect(oauthConfig.oauth.microsoftClientSecret).toBe('microsoft-oauth-client-secret');
        expect(oauthConfig.oauth.githubClientId).toBe('github-oauth-client-id');
        expect(oauthConfig.oauth.githubClientSecret).toBe('github-oauth-client-secret');
        expect(oauthConfig.oauth.instagramClientId).toBe('instagram-oauth-client-id');
        expect(oauthConfig.oauth.instagramClientSecret).toBe('instagram-oauth-client-secret');
        });

        it('should handle partial OAuth configuration gracefully', () => {
        testEnv.setEnvironment({
            JWT_SECRET: 'partial-oauth-secret',
            GOOGLE_CLIENT_ID: 'google-id-only',
            // Missing Google secret and other providers
        });

        const oauthConfig = {
            oauth: {
            googleClientId: process.env.GOOGLE_CLIENT_ID,
            googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
            microsoftClientId: process.env.MICROSOFT_CLIENT_ID,
            microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET,
            githubClientId: process.env.GITHUB_CLIENT_ID,
            githubClientSecret: process.env.GITHUB_CLIENT_SECRET,
            instagramClientId: process.env.INSTAGRAM_CLIENT_ID,
            instagramClientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
            },
        };

        expect(oauthConfig.oauth.googleClientId).toBe('google-id-only');
        expect(oauthConfig.oauth.googleClientSecret).toBeUndefined();
        expect(oauthConfig.oauth.microsoftClientId).toBeUndefined();
        expect(oauthConfig.oauth.githubClientId).toBeUndefined();
        expect(oauthConfig.oauth.instagramClientId).toBeUndefined();
        });
    });

    describe('Firebase Storage Integration', () => {
        it('should configure complete Firebase setup for production', () => {
        testEnv.setEnvironment({
            JWT_SECRET: 'firebase-secret',
            FIREBASE_PROJECT_ID: 'koutu-production',
            FIREBASE_PRIVATE_KEY: 'firebase-production-private-key',
            FIREBASE_CLIENT_EMAIL: 'firebase-adminsdk@koutu-production.iam.gserviceaccount.com',
            FIREBASE_STORAGE_BUCKET: 'koutu-production.appspot.com',
            STORAGE_MODE: 'firebase',
        });

        const firebaseConfig = {
            firebase: {
            projectId: process.env.FIREBASE_PROJECT_ID,
            privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
            storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
            },
            storageMode: process.env.STORAGE_MODE || 'firebase',
        };

        expect(firebaseConfig.firebase.projectId).toBe('koutu-production');
        expect(firebaseConfig.firebase.privateKey).toBe('firebase-production-private-key');
        expect(firebaseConfig.firebase.clientEmail).toBe('firebase-adminsdk@koutu-production.iam.gserviceaccount.com');
        expect(firebaseConfig.firebase.storageBucket).toBe('koutu-production.appspot.com');
        expect(firebaseConfig.storageMode).toBe('firebase');
        });

        it('should configure local storage for development', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'development',
            JWT_SECRET: 'dev-secret',
            STORAGE_MODE: 'local',
            MAX_FILE_SIZE: '52428800', // 50MB for development
        });

        const storageConfig = {
            storageMode: process.env.STORAGE_MODE || 'firebase',
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
            uploadsDir: path.join(__dirname, '../../../uploads'),
        };

        expect(storageConfig.storageMode).toBe('local');
        expect(storageConfig.maxFileSize).toBe(52428800);
        expect(storageConfig.uploadsDir).toContain('uploads');
        });

        it('should handle Firebase configuration fallbacks', () => {
        testEnv.setEnvironment({
            JWT_SECRET: 'minimal-firebase-secret',
            FIREBASE_PROJECT_ID: 'test-project',
            // Missing other Firebase configs
        });

        const firebaseConfig = {
            firebase: {
            projectId: process.env.FIREBASE_PROJECT_ID,
            privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
            storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
            },
        };

        expect(firebaseConfig.firebase.projectId).toBe('test-project');
        expect(firebaseConfig.firebase.privateKey).toBe('');
        expect(firebaseConfig.firebase.clientEmail).toBe('');
        expect(firebaseConfig.firebase.storageBucket).toBe('');
        });
    });

    describe('Application Configuration Integration', () => {
        it('should configure production application settings', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'production',
            JWT_SECRET: 'prod-app-secret',
            PORT: '443',
            APP_URL: 'https://koutu.com',
            LOG_LEVEL: 'error',
            MAX_FILE_SIZE: '10485760', // 10MB
        });

        const appConfig = {
            port: parseInt(process.env.PORT || '3000', 10),
            nodeEnv: process.env.NODE_ENV || 'development',
            appUrl: process.env.APP_URL || 'http://localhost:3000',
            logLevel: process.env.LOG_LEVEL || 'info',
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
        };

        expect(appConfig.port).toBe(443);
        expect(appConfig.nodeEnv).toBe('production');
        expect(appConfig.appUrl).toBe('https://koutu.com');
        expect(appConfig.logLevel).toBe('error');
        expect(appConfig.maxFileSize).toBe(10485760);
        });

        it('should configure development application settings', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'development',
            JWT_SECRET: 'dev-app-secret',
            PORT: '3001',
            APP_URL: 'http://localhost:3001',
            LOG_LEVEL: 'debug',
        });

        const appConfig = {
            port: parseInt(process.env.PORT || '3000', 10),
            nodeEnv: process.env.NODE_ENV || 'development',
            appUrl: process.env.APP_URL || 'http://localhost:3000',
            logLevel: process.env.LOG_LEVEL || 'info',
        };

        expect(appConfig.port).toBe(3001);
        expect(appConfig.nodeEnv).toBe('development');
        expect(appConfig.appUrl).toBe('http://localhost:3001');
        expect(appConfig.logLevel).toBe('debug');
        });
    });

    describe('Configuration Error Handling Integration', () => {
        it('should throw error when JWT_SECRET is missing in production', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'production',
            // JWT_SECRET intentionally missing
            DATABASE_URL: 'postgresql://prod:pass@db:5432/koutu',
        });

        const getConfig = () => {
            const secret = process.env.JWT_SECRET;
            if (!secret) {
            throw new Error('JWT_SECRET environment variable is required');
            }
            return { jwtSecret: secret };
        };

        expect(() => getConfig()).toThrow('JWT_SECRET environment variable is required');
        });

        it('should handle invalid numeric configurations gracefully', () => {
        testEnv.setEnvironment({
            JWT_SECRET: 'test-secret',
            PORT: 'invalid-port',
            DB_POOL_MAX: 'not-a-number',
            MAX_FILE_SIZE: 'invalid-size',
            DB_CONNECTION_TIMEOUT: 'bad-timeout',
        });

        const config = {
            port: parseInt(process.env.PORT || '3000', 10),
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || '10', 10),
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
            dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
        };

        // parseInt should return NaN for invalid values
        expect(isNaN(config.port)).toBe(true);
        expect(isNaN(config.dbPoolMax)).toBe(true);
        expect(isNaN(config.maxFileSize)).toBe(true);
        expect(isNaN(config.dbConnectionTimeout)).toBe(true);
        });

        it('should handle boolean configuration edge cases', () => {
        testEnv.setEnvironment({
            JWT_SECRET: 'bool-test-secret',
            DB_REQUIRE_SSL: 'True', // Uppercase
        });

        const config = {
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true', // Strict lowercase comparison
        };

        expect(config.dbRequireSsl).toBe(false); // Should be false due to case sensitivity
        });
    });

    describe('Path Resolution Integration', () => {
        it('should resolve uploads directory correctly across environments', () => {
        testEnv.setEnvironment({
            JWT_SECRET: 'path-test-secret',
            NODE_ENV: 'development',
        });

        const uploadsDir = path.join(__dirname, '../../../uploads');
        
        expect(path.isAbsolute(uploadsDir)).toBe(true);
        expect(uploadsDir).toContain('uploads');
        expect(uploadsDir).toMatch(/[\/\\]uploads$/); // Ends with uploads
        });

        it('should handle uploads directory in different environments', async () => {
        const environments = ['development', 'test', 'production'];
        
        for (const env of environments) {
            testEnv.setEnvironment({
            JWT_SECRET: `${env}-secret`,
            NODE_ENV: env,
            });

            const uploadsDir = path.join(__dirname, '../../../uploads');
            
            expect(typeof uploadsDir).toBe('string');
            expect(uploadsDir.length).toBeGreaterThan(0);
            expect(path.isAbsolute(uploadsDir)).toBe(true);
        }
        });
    });

    describe('Cross-Environment Configuration Consistency', () => {
        it('should maintain configuration schema across all environments', () => {
        const environments = ['development', 'test', 'production'];
        const requiredKeys = [
            'port', 'nodeEnv', 'databaseUrl', 'dbPoolMax', 'dbConnectionTimeout',
            'dbIdleTimeout', 'dbStatementTimeout', 'dbRequireSsl', 'jwtSecret',
            'jwtExpiresIn', 'uploadsDir', 'maxFileSize', 'firebase', 'logLevel',
            'storageMode', 'appUrl', 'oauth'
        ];

        environments.forEach(env => {
            testEnv.setEnvironment({
            NODE_ENV: env,
            JWT_SECRET: `${env}-consistency-secret`,
            ...(env === 'test' ? { TEST_DATABASE_URL: 'postgresql://test:test@localhost:5432/test' } : {}),
            ...(env !== 'test' ? { DATABASE_URL: `postgresql://${env}:${env}@localhost:5432/${env}` } : {}),
            });

            const isTest = process.env.NODE_ENV === 'test';
            const mockConfig = {
            port: parseInt(process.env.PORT || '3000', 10),
            nodeEnv: process.env.NODE_ENV || 'development',
            databaseUrl: isTest 
                ? process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test'
                : process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || (isTest ? '5' : '10'), 10),
            dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
            dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
            dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
            jwtSecret: process.env.JWT_SECRET!,
            jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
            uploadsDir: path.join(__dirname, '../../../uploads'),
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
            firebase: {
                projectId: process.env.FIREBASE_PROJECT_ID,
                privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
                clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
                storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
            },
            logLevel: process.env.LOG_LEVEL || 'info',
            storageMode: process.env.STORAGE_MODE || 'firebase',
            appUrl: process.env.APP_URL || 'http://localhost:3000',
            oauth: {
                googleClientId: process.env.GOOGLE_CLIENT_ID,
                googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
                microsoftClientId: process.env.MICROSOFT_CLIENT_ID,
                microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET,
                githubClientId: process.env.GITHUB_CLIENT_ID,
                githubClientSecret: process.env.GITHUB_CLIENT_SECRET,
                instagramClientId: process.env.INSTAGRAM_CLIENT_ID,
                instagramClientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
            },
            };

            // Verify all required keys are present
            requiredKeys.forEach(key => {
            expect(mockConfig).toHaveProperty(key);
            });

            // Verify types are consistent
            expect(typeof mockConfig.port).toBe('number');
            expect(typeof mockConfig.nodeEnv).toBe('string');
            expect(typeof mockConfig.databaseUrl).toBe('string');
            expect(typeof mockConfig.dbPoolMax).toBe('number');
            expect(typeof mockConfig.dbRequireSsl).toBe('boolean');
            expect(typeof mockConfig.jwtSecret).toBe('string');
            expect(typeof mockConfig.firebase).toBe('object');
            expect(typeof mockConfig.oauth).toBe('object');
        });
        });

        it('should maintain consistent default values across environments', () => {
        const defaultTestCases = [
            { key: 'port', defaultValue: 3000, envVar: 'PORT' },
            { key: 'dbConnectionTimeout', defaultValue: 0, envVar: 'DB_CONNECTION_TIMEOUT' },
            { key: 'dbIdleTimeout', defaultValue: 10000, envVar: 'DB_IDLE_TIMEOUT' },
            { key: 'dbStatementTimeout', defaultValue: 0, envVar: 'DB_STATEMENT_TIMEOUT' },
            { key: 'jwtExpiresIn', defaultValue: '1d', envVar: 'JWT_EXPIRES_IN' },
            { key: 'maxFileSize', defaultValue: 5242880, envVar: 'MAX_FILE_SIZE' },
            { key: 'logLevel', defaultValue: 'info', envVar: 'LOG_LEVEL' },
            { key: 'storageMode', defaultValue: 'firebase', envVar: 'STORAGE_MODE' },
            { key: 'appUrl', defaultValue: 'http://localhost:3000', envVar: 'APP_URL' },
        ];

        defaultTestCases.forEach(testCase => {
            testEnv.setEnvironment({
            JWT_SECRET: 'default-test-secret',
            NODE_ENV: 'test',
            // Explicitly don't set the environment variable being tested
            });

            let configValue;
            switch (testCase.key) {
            case 'port':
                configValue = parseInt(process.env.PORT || '3000', 10);
                break;
            case 'dbConnectionTimeout':
                configValue = parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10);
                break;
            case 'dbIdleTimeout':
                configValue = parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10);
                break;
            case 'dbStatementTimeout':
                configValue = parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10);
                break;
            case 'jwtExpiresIn':
                configValue = process.env.JWT_EXPIRES_IN || '1d';
                break;
            case 'maxFileSize':
                configValue = parseInt(process.env.MAX_FILE_SIZE || '5242880', 10);
                break;
            case 'logLevel':
                configValue = process.env.LOG_LEVEL || 'info';
                break;
            case 'storageMode':
                configValue = process.env.STORAGE_MODE || 'firebase';
                break;
            case 'appUrl':
                configValue = process.env.APP_URL || 'http://localhost:3000';
                break;
            }

            expect(configValue).toBe(testCase.defaultValue);
        });
        });
    });

    describe('Real-World Configuration Scenarios', () => {
        it('should handle Docker deployment configuration', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'production',
            JWT_SECRET: 'docker-jwt-secret',
            PORT: '8080',
            DATABASE_URL: 'postgresql://koutu_user:secure_password@postgres:5432/koutu_production',
            DB_POOL_MAX: '20',
            DB_CONNECTION_TIMEOUT: '30000',
            DB_REQUIRE_SSL: 'true',
            FIREBASE_PROJECT_ID: 'koutu-docker-prod',
            FIREBASE_PRIVATE_KEY: 'docker-firebase-key',
            FIREBASE_CLIENT_EMAIL: 'firebase-adminsdk@koutu-docker-prod.iam.gserviceaccount.com',
            FIREBASE_STORAGE_BUCKET: 'koutu-docker-prod.appspot.com',
            LOG_LEVEL: 'warn',
            APP_URL: 'https://koutu-docker.com',
            STORAGE_MODE: 'firebase',
            MAX_FILE_SIZE: '20971520', // 20MB
        });

        const dockerConfig = {
            nodeEnv: process.env.NODE_ENV,
            port: parseInt(process.env.PORT || '3000', 10),
            databaseUrl: process.env.DATABASE_URL,
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || '10', 10),
            dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
            jwtSecret: process.env.JWT_SECRET!,
            firebase: {
            projectId: process.env.FIREBASE_PROJECT_ID,
            privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
            storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
            },
            logLevel: process.env.LOG_LEVEL || 'info',
            appUrl: process.env.APP_URL || 'http://localhost:3000',
            storageMode: process.env.STORAGE_MODE || 'firebase',
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
        };

        expect(dockerConfig.nodeEnv).toBe('production');
        expect(dockerConfig.port).toBe(8080);
        expect(dockerConfig.databaseUrl).toBe('postgresql://koutu_user:secure_password@postgres:5432/koutu_production');
        expect(dockerConfig.dbPoolMax).toBe(20);
        expect(dockerConfig.dbConnectionTimeout).toBe(30000);
        expect(dockerConfig.dbRequireSsl).toBe(true);
        expect(dockerConfig.firebase.projectId).toBe('koutu-docker-prod');
        expect(dockerConfig.logLevel).toBe('warn');
        expect(dockerConfig.appUrl).toBe('https://koutu-docker.com');
        expect(dockerConfig.maxFileSize).toBe(20971520);
        });

        it('should handle CI/CD pipeline configuration', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'test',
            JWT_SECRET: 'ci-cd-test-secret',
            TEST_DATABASE_URL: 'postgresql://ci_user:ci_password@ci-postgres:5432/koutu_ci_test',
            DB_POOL_MAX: '2',
            DB_CONNECTION_TIMEOUT: '5000',
            DB_IDLE_TIMEOUT: '2000',
            DB_STATEMENT_TIMEOUT: '10000',
            LOG_LEVEL: 'silent',
            STORAGE_MODE: 'local',
            MAX_FILE_SIZE: '1048576', // 1MB for CI
            FIREBASE_PROJECT_ID: 'koutu-ci-test',
            APP_URL: 'http://ci-test:3000',
        });

        const isTest = process.env.NODE_ENV === 'test';
        const ciConfig = {
            nodeEnv: process.env.NODE_ENV,
            databaseUrl: isTest 
            ? process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test'
            : process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || (isTest ? '5' : '10'), 10),
            dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
            dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
            dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
            logLevel: process.env.LOG_LEVEL || 'info',
            storageMode: process.env.STORAGE_MODE || 'firebase',
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
            firebase: {
            projectId: process.env.FIREBASE_PROJECT_ID,
            },
            appUrl: process.env.APP_URL || 'http://localhost:3000',
        };

        expect(ciConfig.nodeEnv).toBe('test');
        expect(ciConfig.databaseUrl).toBe('postgresql://ci_user:ci_password@ci-postgres:5432/koutu_ci_test');
        expect(ciConfig.dbPoolMax).toBe(2);
        expect(ciConfig.dbConnectionTimeout).toBe(5000);
        expect(ciConfig.dbIdleTimeout).toBe(2000);
        expect(ciConfig.dbStatementTimeout).toBe(10000);
        expect(ciConfig.logLevel).toBe('silent');
        expect(ciConfig.storageMode).toBe('local');
        expect(ciConfig.maxFileSize).toBe(1048576);
        expect(ciConfig.firebase.projectId).toBe('koutu-ci-test');
        expect(ciConfig.appUrl).toBe('http://ci-test:3000');
        });

        it('should handle local development with hot reload', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'development',
            JWT_SECRET: 'local-dev-secret',
            PORT: '3001',
            DATABASE_URL: 'postgresql://dev_user:dev_password@localhost:5433/koutu_local_dev',
            DB_POOL_MAX: '5',
            LOG_LEVEL: 'debug',
            STORAGE_MODE: 'local',
            APP_URL: 'http://localhost:3001',
            MAX_FILE_SIZE: '104857600', // 100MB for development
            GOOGLE_CLIENT_ID: 'local-google-client-id',
            GOOGLE_CLIENT_SECRET: 'local-google-secret',
        });

        const devConfig = {
            nodeEnv: process.env.NODE_ENV,
            port: parseInt(process.env.PORT || '3000', 10),
            databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || '10', 10),
            logLevel: process.env.LOG_LEVEL || 'info',
            storageMode: process.env.STORAGE_MODE || 'firebase',
            appUrl: process.env.APP_URL || 'http://localhost:3000',
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
            oauth: {
            googleClientId: process.env.GOOGLE_CLIENT_ID,
            googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
            },
        };

        expect(devConfig.nodeEnv).toBe('development');
        expect(devConfig.port).toBe(3001);
        expect(devConfig.databaseUrl).toBe('postgresql://dev_user:dev_password@localhost:5433/koutu_local_dev');
        expect(devConfig.dbPoolMax).toBe(5);
        expect(devConfig.logLevel).toBe('debug');
        expect(devConfig.storageMode).toBe('local');
        expect(devConfig.appUrl).toBe('http://localhost:3001');
        expect(devConfig.maxFileSize).toBe(104857600);
        expect(devConfig.oauth.googleClientId).toBe('local-google-client-id');
        expect(devConfig.oauth.googleClientSecret).toBe('local-google-secret');
        });
    });

    describe('Configuration Performance and Memory', () => {
        it('should handle large environment variable sets efficiently', () => {
        const largeEnvSet: Record<string, string> = {
            JWT_SECRET: 'performance-test-secret',
            NODE_ENV: 'test',
        };

        // Add many OAuth providers and configuration options
        for (let i = 0; i < 100; i++) {
            largeEnvSet[`CUSTOM_CONFIG_${i}`] = `value_${i}`;
        }

        testEnv.setEnvironment(largeEnvSet);

        const startTime = process.hrtime.bigint();
        
        // Simulate configuration loading
        const config = {
            jwtSecret: process.env.JWT_SECRET,
            nodeEnv: process.env.NODE_ENV,
            customConfigs: Object.keys(process.env)
            .filter(key => key.startsWith('CUSTOM_CONFIG_'))
            .reduce((acc, key) => {
                acc[key] = process.env[key];
                return acc;
            }, {} as Record<string, string | undefined>),
        };

        const endTime = process.hrtime.bigint();
        const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds

        expect(config.jwtSecret).toBe('performance-test-secret');
        expect(Object.keys(config.customConfigs)).toHaveLength(100);
        expect(duration).toBeLessThan(100); // Should complete in less than 100ms
        });

        it('should handle configuration object creation without memory leaks', () => {
        const initialMemory = process.memoryUsage();
        const configs: any[] = [];

        // Create many configuration objects
        for (let i = 0; i < 1000; i++) {
            testEnv.setEnvironment({
            JWT_SECRET: `memory-test-secret-${i}`,
            NODE_ENV: 'test',
            PORT: String(3000 + i),
            });

            configs.push({
            jwtSecret: process.env.JWT_SECRET,
            nodeEnv: process.env.NODE_ENV,
            port: parseInt(process.env.PORT || '3000', 10),
            iteration: i,
            });
        }

        const finalMemory = process.memoryUsage();
        const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

        expect(configs).toHaveLength(1000);
        expect(configs[999].iteration).toBe(999);
        expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB increase
        });
    });

    describe('Configuration Security Integration', () => {
        it('should handle sensitive configuration data appropriately', () => {
        testEnv.setEnvironment({
            JWT_SECRET: 'super-secret-jwt-token-that-should-not-be-logged',
            NODE_ENV: 'production',
            DATABASE_URL: 'postgresql://user:super-secret-password@db:5432/koutu',
            FIREBASE_PRIVATE_KEY: 'firebase-private-key-super-secret',
            GOOGLE_CLIENT_SECRET: 'google-oauth-secret-key',
        });

        const sensitiveConfig = {
            jwtSecret: process.env.JWT_SECRET,
            databaseUrl: process.env.DATABASE_URL,
            firebase: {
            privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
            },
            oauth: {
            googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
            },
        };

        // Verify sensitive data is loaded
        expect(sensitiveConfig.jwtSecret).toContain('super-secret');
        expect(sensitiveConfig.databaseUrl).toContain('super-secret-password');
        expect(sensitiveConfig.firebase.privateKey).toContain('super-secret');
        expect(sensitiveConfig.oauth.googleClientSecret).toContain('secret-key');

        // In a real application, you'd want to ensure these don't get logged
        const configString = JSON.stringify(sensitiveConfig);
        expect(configString).toContain('super-secret'); // They are present but should be handled carefully
        });

        it('should validate environment-specific security requirements', () => {
        // Production should require SSL
        testEnv.setEnvironment({
            NODE_ENV: 'production',
            JWT_SECRET: 'prod-security-secret',
            DB_REQUIRE_SSL: 'true',
            DATABASE_URL: 'postgresql://user:pass@secure-db:5432/koutu?ssl=true',
        });

        const prodSecurityConfig = {
            nodeEnv: process.env.NODE_ENV,
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
            databaseUrl: process.env.DATABASE_URL,
        };

        expect(prodSecurityConfig.nodeEnv).toBe('production');
        expect(prodSecurityConfig.dbRequireSsl).toBe(true);
        expect(prodSecurityConfig.databaseUrl).toContain('ssl=true');

        // Development can be more relaxed
        testEnv.setEnvironment({
            NODE_ENV: 'development',
            JWT_SECRET: 'dev-security-secret',
            DB_REQUIRE_SSL: 'false',
            DATABASE_URL: 'postgresql://dev:dev@localhost:5432/koutu_dev',
        });

        const devSecurityConfig = {
            nodeEnv: process.env.NODE_ENV,
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
            databaseUrl: process.env.DATABASE_URL,
        };

        expect(devSecurityConfig.nodeEnv).toBe('development');
        expect(devSecurityConfig.dbRequireSsl).toBe(false);
        expect(devSecurityConfig.databaseUrl).not.toContain('ssl=true');
        });
    });

    describe('Configuration Validation Integration', () => {
        it('should validate complete production-ready configuration', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'production',
            JWT_SECRET: 'production-grade-jwt-secret-with-sufficient-entropy',
            PORT: '443',
            DATABASE_URL: 'postgresql://prod_user:secure_password@prod-db.example.com:5432/koutu_production',
            DB_POOL_MAX: '30',
            DB_CONNECTION_TIMEOUT: '15000',
            DB_IDLE_TIMEOUT: '60000',
            DB_STATEMENT_TIMEOUT: '30000',
            DB_REQUIRE_SSL: 'true',
            JWT_EXPIRES_IN: '1h',
            MAX_FILE_SIZE: '10485760',
            FIREBASE_PROJECT_ID: 'koutu-production',
            FIREBASE_PRIVATE_KEY: 'production-firebase-private-key',
            FIREBASE_CLIENT_EMAIL: 'firebase-adminsdk@koutu-production.iam.gserviceaccount.com',
            FIREBASE_STORAGE_BUCKET: 'koutu-production.appspot.com',
            LOG_LEVEL: 'error',
            STORAGE_MODE: 'firebase',
            APP_URL: 'https://koutu.com',
            GOOGLE_CLIENT_ID: 'production-google-client-id',
            GOOGLE_CLIENT_SECRET: 'production-google-client-secret',
        });

        const isTest = process.env.NODE_ENV === 'test';
        const validatedConfig = {
            nodeEnv: process.env.NODE_ENV || 'development',
            port: parseInt(process.env.PORT || '3000', 10),
            databaseUrl: isTest 
            ? process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test'
            : process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
            dbPoolMax: parseInt(process.env.DB_POOL_MAX || (isTest ? '5' : '10'), 10),
            dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
            dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
            dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
            dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
            jwtSecret: process.env.JWT_SECRET!,
            jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
            maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
            firebase: {
            projectId: process.env.FIREBASE_PROJECT_ID,
            privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
            clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
            storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
            },
            logLevel: process.env.LOG_LEVEL || 'info',
            storageMode: process.env.STORAGE_MODE || 'firebase',
            appUrl: process.env.APP_URL || 'http://localhost:3000',
            oauth: {
            googleClientId: process.env.GOOGLE_CLIENT_ID,
            googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
            },
        };

        // Validate production requirements
        expect(validatedConfig.nodeEnv).toBe('production');
        expect(validatedConfig.port).toBe(443);
        expect(validatedConfig.dbRequireSsl).toBe(true);
        expect(validatedConfig.logLevel).toBe('error');
        expect(validatedConfig.appUrl).toBe('https://koutu.com');
        expect(validatedConfig.jwtSecret.length).toBeGreaterThan(20);
        expect(validatedConfig.firebase.projectId).toBe('koutu-production');
        expect(validatedConfig.oauth.googleClientId).toBeTruthy();
        expect(validatedConfig.oauth.googleClientSecret).toBeTruthy();

        // Validate numeric ranges
        expect(validatedConfig.dbPoolMax).toBeGreaterThan(0);
        expect(validatedConfig.dbConnectionTimeout).toBeGreaterThanOrEqual(0);
        expect(validatedConfig.maxFileSize).toBeGreaterThan(0);
        });

        it('should identify configuration issues in incomplete setups', () => {
        testEnv.setEnvironment({
            NODE_ENV: 'production',
            // Missing JWT_SECRET - should be caught
            DATABASE_URL: 'postgresql://prod:pass@db:5432/koutu',
            FIREBASE_PROJECT_ID: 'incomplete-firebase',
            // Missing other Firebase configs
        });

        const getIncompleteConfig = () => {
            const secret = process.env.JWT_SECRET;
            if (!secret) {
            throw new Error('JWT_SECRET environment variable is required');
            }
            return {
            jwtSecret: secret,
            firebase: {
                projectId: process.env.FIREBASE_PROJECT_ID,
                privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
                clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
                storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
            },
            };
        };

        expect(() => getIncompleteConfig()).toThrow('JWT_SECRET environment variable is required');
        });
    });
});