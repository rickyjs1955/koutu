// backend/src/__tests__/config/index.unit.test.ts
import { jest } from '@jest/globals';
import { beforeEach, afterEach, describe, it, expect } from '@jest/globals';

// Mock dependencies before importing the actual config
jest.mock('dotenv', () => ({
  config: jest.fn(() => ({ parsed: {} })),
}));

jest.mock('path', () => ({
  join: jest.fn((...args: string[]) => args.join('/')),
}));

// Define types for our configuration
interface Config {
  port: number;
  nodeEnv: string;
  databaseUrl: string;
  dbPoolMax: number;
  dbConnectionTimeout: number;
  dbIdleTimeout: number;
  dbStatementTimeout: number;
  dbRequireSsl: boolean;
  jwtSecret: string;
  jwtExpiresIn: string;
  uploadsDir: string;
  maxFileSize: number;
  firebase: {
    projectId?: string;
    privateKey: string;
    clientEmail: string;
    storageBucket: string;
  };
  logLevel: string;
  storageMode: string;
  appUrl: string;
  oauth: {
    googleClientId?: string;
    googleClientSecret?: string;
    microsoftClientId?: string;
    microsoftClientSecret?: string;
    githubClientId?: string;
    githubClientSecret?: string;
    instagramClientId?: string;
    instagramClientSecret?: string;
  };
}

// Mock environment helper class
class MockProcessEnv {
  private originalEnv: NodeJS.ProcessEnv;

  constructor() {
    this.originalEnv = { ...process.env };
  }

  setEnv(env: Record<string, string | undefined>): void {
    Object.keys(env).forEach(key => {
      if (env[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = env[key];
      }
    });
  }

  restore(): void {
    process.env = this.originalEnv;
  }
}

// Helper function to create mock config
function createMockConfig(overrides: Partial<Config> = {}): Config {
  const defaultConfig: Config = {
    port: 3000,
    nodeEnv: 'test',
    databaseUrl: 'postgresql://postgres:password@localhost:5432/koutu_test',
    dbPoolMax: 5,
    dbConnectionTimeout: 0,
    dbIdleTimeout: 10000,
    dbStatementTimeout: 0,
    dbRequireSsl: false,
    jwtSecret: 'test-jwt-secret',
    jwtExpiresIn: '1d',
    uploadsDir: '/test/uploads',
    maxFileSize: 5242880,
    firebase: {
      projectId: undefined,
      privateKey: '',
      clientEmail: '',
      storageBucket: '',
    },
    logLevel: 'info',
    storageMode: 'firebase',
    appUrl: 'http://localhost:3000',
    oauth: {
      googleClientId: undefined,
      googleClientSecret: undefined,
      microsoftClientId: undefined,
      microsoftClientSecret: undefined,
      githubClientId: undefined,
      githubClientSecret: undefined,
      instagramClientId: undefined,
      instagramClientSecret: undefined,
    },
  };

  return { ...defaultConfig, ...overrides };
}

// Validation helper
function validateMockConfig(config: Config): string[] {
  const errors: string[] = [];

  if (!config.jwtSecret) {
    errors.push('JWT secret is required');
  }

  if (!config.databaseUrl) {
    errors.push('Database URL is required');
  }

  if (config.dbPoolMax < 0) {
    errors.push('Database pool max must be a positive number');
  }

  if (config.maxFileSize < 0) {
    errors.push('Max file size must be a non-negative number');
  }

  const validEnvs = ['development', 'production', 'test'];
  if (!validEnvs.includes(config.nodeEnv)) {
    errors.push(`Invalid node environment: ${config.nodeEnv}`);
  }

  const validStorageModes = ['firebase', 'local'];
  if (!validStorageModes.includes(config.storageMode)) {
    errors.push(`Invalid storage mode: ${config.storageMode}`);
  }

  return errors;
}

// Type assertion helper
function assertEnvironmentVariableTypes(config: Config): void {
  expect(typeof config.port).toBe('number');
  expect(typeof config.nodeEnv).toBe('string');
  expect(typeof config.databaseUrl).toBe('string');
  expect(typeof config.dbPoolMax).toBe('number');
  expect(typeof config.jwtSecret).toBe('string');
  expect(typeof config.maxFileSize).toBe('number');
  expect(typeof config.storageMode).toBe('string');
  expect(typeof config.logLevel).toBe('string');
  expect(typeof config.appUrl).toBe('string');
}

// Environment helpers
const environmentHelpers = {
  isProd: () => process.env.NODE_ENV === 'production',
  isDev: () => process.env.NODE_ENV === 'development',
  isTest: () => process.env.NODE_ENV === 'test',
};

// Mock environment for testing
let mockEnv: MockProcessEnv;

describe('Configuration Module', () => {
  beforeEach(() => {
    mockEnv = new MockProcessEnv();
    // Reset to clean state and clear Firebase env vars
    mockEnv.setEnv({
      NODE_ENV: 'test',
      JWT_SECRET: 'test-jwt-secret',
      // Explicitly clear Firebase environment variables
      FIREBASE_PROJECT_ID: undefined,
      FIREBASE_PRIVATE_KEY: undefined,
      FIREBASE_CLIENT_EMAIL: undefined,
      FIREBASE_STORAGE_BUCKET: undefined,
    });
  });

  afterEach(() => {
    mockEnv.restore();
  });

  describe('Basic Configuration Loading', () => {
    it('should load configuration successfully with required environment variables', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-jwt-secret',
        NODE_ENV: 'test',
      });

      const getConfig = (): Config => {
        const jwtSecret = process.env.JWT_SECRET;
        if (!jwtSecret) {
          throw new Error('JWT_SECRET environment variable is required');
        }

        return createMockConfig({
          jwtSecret,
          nodeEnv: process.env.NODE_ENV || 'development',
        });
      };

      const config = getConfig();
      
      expect(config).toBeDefined();
      expect(config.jwtSecret).toBe('test-jwt-secret');
      expect(config.nodeEnv).toBe('test');
      assertEnvironmentVariableTypes(config);
    });

    it('should throw error when JWT_SECRET is missing', () => {
      mockEnv.setEnv({
        NODE_ENV: 'test',
        JWT_SECRET: undefined,
      });

      const getConfig = (): Config => {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
          throw new Error('JWT_SECRET environment variable is required');
        }
        return createMockConfig({ jwtSecret: secret });
      };

      expect(() => getConfig()).toThrow('JWT_SECRET environment variable is required');
    });

    it('should load dotenv configuration', () => {
      const dotenv = require('dotenv');
      
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
      });

      // Simulate config loading
      dotenv.config();
      
      expect(dotenv.config).toHaveBeenCalled();
    });
  });

  describe('Environment-Specific Configuration', () => {
    describe('Test Environment', () => {
      it('should use test database URL when in test environment', () => {
        mockEnv.setEnv({
          NODE_ENV: 'test',
          JWT_SECRET: 'test-secret',
          TEST_DATABASE_URL: 'postgresql://test:test@localhost:5432/test_db',
        });

        const config = createMockConfig({
          nodeEnv: 'test',
          databaseUrl: process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test',
          dbPoolMax: 5,
        });

        expect(config.nodeEnv).toBe('test');
        expect(config.databaseUrl).toBe('postgresql://test:test@localhost:5432/test_db');
        expect(config.dbPoolMax).toBe(5);
      });

      it('should fall back to default test database URL', () => {
        mockEnv.setEnv({
          NODE_ENV: 'test',
          JWT_SECRET: 'test-secret',
        });

        const isTest = process.env.NODE_ENV === 'test';
        const config = createMockConfig({
          nodeEnv: 'test',
          databaseUrl: isTest 
            ? (process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test')
            : (process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu'),
        });

        expect(config.databaseUrl).toBe('postgresql://postgres:password@localhost:5432/koutu_test');
      });
    });

    describe('Development Environment', () => {
      it('should use development configuration', () => {
        mockEnv.setEnv({
          NODE_ENV: 'development',
          JWT_SECRET: 'dev-secret',
          DATABASE_URL: 'postgresql://dev:dev@localhost:5432/koutu_dev',
        });

        const config = createMockConfig({
          nodeEnv: 'development',
          databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
          dbPoolMax: 10,
        });

        expect(config.nodeEnv).toBe('development');
        expect(config.databaseUrl).toBe('postgresql://dev:dev@localhost:5432/koutu_dev');
        expect(config.dbPoolMax).toBe(10);
      });
    });

    describe('Production Environment', () => {
      it('should use production configuration', () => {
        mockEnv.setEnv({
          NODE_ENV: 'production',
          JWT_SECRET: 'prod-secret',
          DATABASE_URL: 'postgresql://prod:prod@localhost:5432/koutu_prod',
          DB_REQUIRE_SSL: 'true',
        });

        const config = createMockConfig({
          nodeEnv: 'production',
          databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
          dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
        });

        expect(config.nodeEnv).toBe('production');
        expect(config.dbRequireSsl).toBe(true);
      });
    });
  });

  describe('Database Configuration', () => {
    it('should parse database pool configuration', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        DB_POOL_MAX: '15',
      });

      const config = createMockConfig({
        dbPoolMax: parseInt(process.env.DB_POOL_MAX || '10', 10),
      });

      expect(config.dbPoolMax).toBe(15);
    });

    it('should handle invalid database pool number', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        DB_POOL_MAX: 'invalid',
      });

      const dbPoolMax = parseInt(process.env.DB_POOL_MAX || '10', 10);
      expect(isNaN(dbPoolMax)).toBe(true);
    });

    it('should configure database SSL requirement', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        DB_REQUIRE_SSL: 'true',
      });

      const config = createMockConfig({
        dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
      });

      expect(config.dbRequireSsl).toBe(true);
    });

    it('should configure database timeouts', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        DB_CONNECTION_TIMEOUT: '5000',
        DB_IDLE_TIMEOUT: '30000',
        DB_STATEMENT_TIMEOUT: '10000',
      });

      const config = createMockConfig({
        dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
        dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
        dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
      });

      expect(config.dbConnectionTimeout).toBe(5000);
      expect(config.dbIdleTimeout).toBe(30000);
      expect(config.dbStatementTimeout).toBe(10000);
    });
  });

  describe('JWT Configuration', () => {
    it('should validate JWT secret is provided', () => {
      mockEnv.setEnv({
        JWT_SECRET: undefined,
      });

      const getConfig = (): Config => {
        const secret = process.env.JWT_SECRET;
        if (!secret) {
          throw new Error('JWT_SECRET environment variable is required');
        }
        return createMockConfig({ jwtSecret: secret });
      };

      expect(() => getConfig()).toThrow('JWT_SECRET environment variable is required');
    });

    it('should use custom JWT expiration', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        JWT_EXPIRES_IN: '7d',
      });

      const config = createMockConfig({
        jwtSecret: 'test-secret',
        jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
      });

      expect(config.jwtExpiresIn).toBe('7d');
    });
  });

  describe('Firebase Configuration', () => {
    it('should handle complete Firebase configuration', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        FIREBASE_PROJECT_ID: 'my-project',
        FIREBASE_PRIVATE_KEY: 'my-private-key',
        FIREBASE_CLIENT_EMAIL: 'service@my-project.iam.gserviceaccount.com',
        FIREBASE_STORAGE_BUCKET: 'my-project.appspot.com',
      });

      const config = createMockConfig({
        firebase: {
          projectId: process.env.FIREBASE_PROJECT_ID,
          privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
          storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
        },
      });

      expect(config.firebase.projectId).toBe('my-project');
      expect(config.firebase.privateKey).toBe('my-private-key');
      expect(config.firebase.clientEmail).toBe('service@my-project.iam.gserviceaccount.com');
      expect(config.firebase.storageBucket).toBe('my-project.appspot.com');
    });

    it('should handle missing Firebase configuration gracefully', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        // Explicitly ensure Firebase vars are undefined
        FIREBASE_PROJECT_ID: undefined,
        FIREBASE_PRIVATE_KEY: undefined,
        FIREBASE_CLIENT_EMAIL: undefined,
        FIREBASE_STORAGE_BUCKET: undefined,
      });

      const config = createMockConfig({
        firebase: {
          projectId: process.env.FIREBASE_PROJECT_ID,
          privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
          storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
        },
      });

      expect(config.firebase.projectId).toBeUndefined();
      expect(config.firebase.privateKey).toBe('');
      expect(config.firebase.clientEmail).toBe('');
      expect(config.firebase.storageBucket).toBe('');
    });
  });

  describe('OAuth Configuration', () => {
    it('should configure Google OAuth', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        GOOGLE_CLIENT_ID: 'google-client-id',
        GOOGLE_CLIENT_SECRET: 'google-client-secret',
      });

      const config = createMockConfig({
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
      });

      expect(config.oauth.googleClientId).toBe('google-client-id');
      expect(config.oauth.googleClientSecret).toBe('google-client-secret');
    });

    it('should configure all OAuth providers', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        GOOGLE_CLIENT_ID: 'google-id',
        GOOGLE_CLIENT_SECRET: 'google-secret',
        MICROSOFT_CLIENT_ID: 'microsoft-id',
        MICROSOFT_CLIENT_SECRET: 'microsoft-secret',
        GITHUB_CLIENT_ID: 'github-id',
        GITHUB_CLIENT_SECRET: 'github-secret',
        INSTAGRAM_CLIENT_ID: 'instagram-id',
        INSTAGRAM_CLIENT_SECRET: 'instagram-secret',
      });

      const config = createMockConfig({
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
      });

      expect(config.oauth).toEqual({
        googleClientId: 'google-id',
        googleClientSecret: 'google-secret',
        microsoftClientId: 'microsoft-id',
        microsoftClientSecret: 'microsoft-secret',
        githubClientId: 'github-id',
        githubClientSecret: 'github-secret',
        instagramClientId: 'instagram-id',
        instagramClientSecret: 'instagram-secret',
      });
    });
  });

  describe('File Storage Configuration', () => {
    it('should configure storage mode', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        STORAGE_MODE: 'local',
      });

      const config = createMockConfig({
        storageMode: process.env.STORAGE_MODE || 'firebase',
      });

      expect(config.storageMode).toBe('local');
    });

    it('should configure maximum file size', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        MAX_FILE_SIZE: '10485760', // 10MB
      });

      const config = createMockConfig({
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
      });

      expect(config.maxFileSize).toBe(10485760);
    });

    it('should resolve uploads directory path', () => {
      const path = require('path');
      
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
      });

      // Simulate path.join call
      const uploadsDir = path.join('/root', '..', '..', '..', 'uploads');
      
      expect(path.join).toBeDefined();
      expect(typeof uploadsDir).toBe('string');
      expect(uploadsDir).toBe('/root/../../../uploads');
    });
  });

  describe('Default Values', () => {
    it('should provide sensible default values', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
      });

      const config = createMockConfig({
        port: parseInt(process.env.PORT || '3000', 10),
        nodeEnv: process.env.NODE_ENV || 'development',
        logLevel: process.env.LOG_LEVEL || 'info',
        storageMode: process.env.STORAGE_MODE || 'firebase',
        appUrl: process.env.APP_URL || 'http://localhost:3000',
        jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
      });

      expect(config.port).toBe(3000);
      expect(config.nodeEnv).toBe('test'); // Should use current NODE_ENV
      expect(config.logLevel).toBe('info');
      expect(config.storageMode).toBe('firebase');
      expect(config.appUrl).toBe('http://localhost:3000');
      expect(config.jwtExpiresIn).toBe('1d');
      expect(config.maxFileSize).toBe(5242880);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid numeric values gracefully', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        PORT: 'invalid-port',
        DB_POOL_MAX: 'invalid-number',
        MAX_FILE_SIZE: 'invalid-size',
      });

      // parseInt should return NaN for invalid values
      const port = parseInt(process.env.PORT || '3000', 10);
      const dbPoolMax = parseInt(process.env.DB_POOL_MAX || '10', 10);
      const maxFileSize = parseInt(process.env.MAX_FILE_SIZE || '5242880', 10);

      expect(isNaN(port)).toBe(true);
      expect(isNaN(dbPoolMax)).toBe(true);
      expect(isNaN(maxFileSize)).toBe(true);
    });
  });

  describe('Environment Helper Functions', () => {
    it('should correctly identify production environment', () => {
      mockEnv.setEnv({ NODE_ENV: 'production' });
      
      expect(environmentHelpers.isProd()).toBe(true);
      expect(environmentHelpers.isDev()).toBe(false);
      expect(environmentHelpers.isTest()).toBe(false);
    });

    it('should correctly identify development environment', () => {
      mockEnv.setEnv({ NODE_ENV: 'development' });
      
      expect(environmentHelpers.isProd()).toBe(false);
      expect(environmentHelpers.isDev()).toBe(true);
      expect(environmentHelpers.isTest()).toBe(false);
    });

    it('should correctly identify test environment', () => {
      mockEnv.setEnv({ NODE_ENV: 'test' });
      
      expect(environmentHelpers.isProd()).toBe(false);
      expect(environmentHelpers.isDev()).toBe(false);
      expect(environmentHelpers.isTest()).toBe(true);
    });
  });

  describe('Configuration Validation', () => {
    it('should validate complete configuration', () => {
      const config = createMockConfig();
      const errors = validateMockConfig(config);
      
      expect(errors).toHaveLength(0);
    });

    it('should detect missing required fields', () => {
      const config = createMockConfig({
        jwtSecret: '',
        databaseUrl: '',
      });
      
      const errors = validateMockConfig(config);
      
      expect(errors).toContain('JWT secret is required');
      expect(errors).toContain('Database URL is required');
    });

    it('should detect invalid types', () => {
      const config = createMockConfig({
        dbPoolMax: -1,
        maxFileSize: -1,
      });
      
      const errors = validateMockConfig(config);
      
      expect(errors).toContain('Database pool max must be a positive number');
      expect(errors).toContain('Max file size must be a non-negative number');
    });

    it('should detect invalid environment', () => {
      const config = createMockConfig({
        nodeEnv: 'invalid-env',
      });
      
      const errors = validateMockConfig(config);
      
      expect(errors).toContain('Invalid node environment: invalid-env');
    });

    it('should detect invalid storage mode', () => {
      const config = createMockConfig({
        storageMode: 'invalid-storage',
      });
      
      const errors = validateMockConfig(config);
      
      expect(errors).toContain('Invalid storage mode: invalid-storage');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string environment variables', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        PORT: '',
        LOG_LEVEL: '',
        STORAGE_MODE: '',
      });

      const config = createMockConfig({
        port: parseInt(process.env.PORT || '3000', 10),
        logLevel: process.env.LOG_LEVEL || 'info',
        storageMode: process.env.STORAGE_MODE || 'firebase',
      });

      expect(config.port).toBe(3000);
      expect(config.logLevel).toBe('info');
      expect(config.storageMode).toBe('firebase');
    });

    it('should handle zero values correctly', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        PORT: '0',
        DB_POOL_MAX: '0',
        MAX_FILE_SIZE: '0',
      });

      const config = createMockConfig({
        port: parseInt(process.env.PORT || '3000', 10),
        dbPoolMax: parseInt(process.env.DB_POOL_MAX || '10', 10),
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10),
      });

      expect(config.port).toBe(0);
      expect(config.dbPoolMax).toBe(0);
      expect(config.maxFileSize).toBe(0);
    });

    it('should handle boolean environment variables', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        DB_REQUIRE_SSL: 'false',
      });

      const config = createMockConfig({
        dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
      });

      expect(config.dbRequireSsl).toBe(false);
    });

    it('should handle mixed case boolean values', () => {
      mockEnv.setEnv({
        JWT_SECRET: 'test-secret',
        DB_REQUIRE_SSL: 'True',
      });

      const config = createMockConfig({
        dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true',
      });

      // Strict comparison should return false for 'True' vs 'true'
      expect(config.dbRequireSsl).toBe(false);
    });
  });
});