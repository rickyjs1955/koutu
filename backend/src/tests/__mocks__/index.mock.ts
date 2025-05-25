// backend/src/__tests__/__mocks__/index.mock.ts
import { jest } from '@jest/globals';

/**
 * Mock configuration object for testing
 */
export interface MockConfig {
  port: number | string;
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

/**
 * Default mock configuration values
 */
export const defaultMockConfig: MockConfig = {
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
    projectId: 'test-project',
    privateKey: 'test-private-key',
    clientEmail: 'test@test.com',
    storageBucket: 'test-bucket',
  },
  logLevel: 'info',
  storageMode: 'firebase',
  appUrl: 'http://localhost:3000',
  oauth: {
    googleClientId: 'test-google-client-id',
    googleClientSecret: 'test-google-client-secret',
    microsoftClientId: 'test-microsoft-client-id',
    microsoftClientSecret: 'test-microsoft-client-secret',
    githubClientId: 'test-github-client-id',
    githubClientSecret: 'test-github-client-secret',
    instagramClientId: 'test-instagram-client-id',
    instagramClientSecret: 'test-instagram-client-secret',
  },
};

/**
 * Development environment mock configuration
 */
export const developmentMockConfig: MockConfig = {
  ...defaultMockConfig,
  nodeEnv: 'development',
  databaseUrl: 'postgresql://postgres:password@localhost:5432/koutu',
  dbPoolMax: 10,
  logLevel: 'debug',
  storageMode: 'local',
};

/**
 * Production environment mock configuration
 */
export const productionMockConfig: MockConfig = {
  ...defaultMockConfig,
  nodeEnv: 'production',
  port: 80,
  databaseUrl: 'postgresql://user:pass@prod-db:5432/koutu_prod',
  dbPoolMax: 20,
  dbRequireSsl: true,
  logLevel: 'error',
  appUrl: 'https://app.example.com',
};

/**
 * Mock environment variables for testing
 */
export const mockEnvironmentVariables = {
  test: {
    NODE_ENV: 'test',
    PORT: '3000',
    TEST_DATABASE_URL: 'postgresql://postgres:password@localhost:5432/koutu_test',
    JWT_SECRET: 'test-jwt-secret',
    JWT_EXPIRES_IN: '1d',
    DB_POOL_MAX: '5',
    DB_CONNECTION_TIMEOUT: '0',
    DB_IDLE_TIMEOUT: '10000',
    DB_STATEMENT_TIMEOUT: '0',
    DB_REQUIRE_SSL: 'false',
    MAX_FILE_SIZE: '5242880',
    FIREBASE_PROJECT_ID: 'test-project',
    FIREBASE_PRIVATE_KEY: 'test-private-key',
    FIREBASE_CLIENT_EMAIL: 'test@test.com',
    FIREBASE_STORAGE_BUCKET: 'test-bucket',
    LOG_LEVEL: 'info',
    STORAGE_MODE: 'firebase',
    APP_URL: 'http://localhost:3000',
    GOOGLE_CLIENT_ID: 'test-google-client-id',
    GOOGLE_CLIENT_SECRET: 'test-google-client-secret',
    MICROSOFT_CLIENT_ID: 'test-microsoft-client-id',
    MICROSOFT_CLIENT_SECRET: 'test-microsoft-client-secret',
    GITHUB_CLIENT_ID: 'test-github-client-id',
    GITHUB_CLIENT_SECRET: 'test-github-client-secret',
    INSTAGRAM_CLIENT_ID: 'test-instagram-client-id',
    INSTAGRAM_CLIENT_SECRET: 'test-instagram-client-secret',
  },
  development: {
    NODE_ENV: 'development',
    PORT: '3001',
    DATABASE_URL: 'postgresql://postgres:password@localhost:5432/koutu',
    JWT_SECRET: 'dev-jwt-secret',
    JWT_EXPIRES_IN: '7d',
    DB_POOL_MAX: '10',
    LOG_LEVEL: 'debug',
    STORAGE_MODE: 'local',
    APP_URL: 'http://localhost:3001',
  },
  production: {
    NODE_ENV: 'production',
    PORT: '80',
    DATABASE_URL: 'postgresql://user:pass@prod-db:5432/koutu_prod',
    JWT_SECRET: 'super-secure-prod-secret',
    JWT_EXPIRES_IN: '1d',
    DB_POOL_MAX: '20',
    DB_REQUIRE_SSL: 'true',
    LOG_LEVEL: 'error',
    APP_URL: 'https://app.example.com',
    FIREBASE_PROJECT_ID: 'prod-project',
    FIREBASE_PRIVATE_KEY: 'prod-private-key',
    FIREBASE_CLIENT_EMAIL: 'prod@example.com',
    FIREBASE_STORAGE_BUCKET: 'prod-bucket',
  },
};

/**
 * Mock configuration scenarios for different testing contexts
 */
export const configScenarios = {
  validConfig: {
    name: 'Valid configuration',
    config: defaultMockConfig,
    shouldThrow: false,
  },
  missingJwtSecret: {
    name: 'Missing JWT secret',
    config: { ...defaultMockConfig, jwtSecret: '' },
    shouldThrow: true,
    expectedError: 'JWT_SECRET environment variable is required',
  },
  invalidPort: {
    name: 'Invalid port number',
    config: { ...defaultMockConfig, port: 'invalid' },
    shouldThrow: false, // Config allows string ports
  },
  invalidDbPoolMax: {
    name: 'Invalid database pool max',
    config: { ...defaultMockConfig, dbPoolMax: NaN },
    shouldThrow: false, // parseInt returns NaN, but doesn't throw
  },
  missingFirebaseConfig: {
    name: 'Missing Firebase configuration',
    config: {
      ...defaultMockConfig,
      firebase: {
        projectId: undefined,
        privateKey: '',
        clientEmail: '',
        storageBucket: '',
      },
    },
    shouldThrow: false, // Firebase config is optional
  },
  minimalConfig: {
    name: 'Minimal configuration with defaults',
    config: {
      port: 3000,
      nodeEnv: 'development',
      databaseUrl: 'postgresql://postgres:password@localhost:5432/koutu',
      dbPoolMax: 10,
      dbConnectionTimeout: 0,
      dbIdleTimeout: 10000,
      dbStatementTimeout: 0,
      dbRequireSsl: false,
      jwtSecret: 'minimal-secret',
      jwtExpiresIn: '1d',
      uploadsDir: expect.any(String),
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
    },
    shouldThrow: false,
  },
} as const;

/**
 * Database configuration scenarios
 */
export const databaseConfigScenarios = {
  testDatabase: {
    name: 'Test database configuration',
    config: {
      databaseUrl: 'postgresql://postgres:password@localhost:5432/koutu_test',
      dbPoolMax: 5,
      dbRequireSsl: false,
    },
    nodeEnv: 'test',
  },
  developmentDatabase: {
    name: 'Development database configuration',
    config: {
      databaseUrl: 'postgresql://postgres:password@localhost:5432/koutu',
      dbPoolMax: 10,
      dbRequireSsl: false,
    },
    nodeEnv: 'development',
  },
  productionDatabase: {
    name: 'Production database configuration',
    config: {
      databaseUrl: 'postgresql://user:pass@prod-db:5432/koutu_prod',
      dbPoolMax: 20,
      dbRequireSsl: true,
    },
    nodeEnv: 'production',
  },
} as const;

/**
 * OAuth configuration scenarios
 */
export const oauthConfigScenarios = {
  completeOAuth: {
    name: 'Complete OAuth configuration',
    config: {
      oauth: {
        googleClientId: 'google-client-id',
        googleClientSecret: 'google-client-secret',
        microsoftClientId: 'microsoft-client-id',
        microsoftClientSecret: 'microsoft-client-secret',
        githubClientId: 'github-client-id',
        githubClientSecret: 'github-client-secret',
        instagramClientId: 'instagram-client-id',
        instagramClientSecret: 'instagram-client-secret',
      },
    },
  },
  partialOAuth: {
    name: 'Partial OAuth configuration',
    config: {
      oauth: {
        googleClientId: 'google-client-id',
        googleClientSecret: 'google-client-secret',
        microsoftClientId: undefined,
        microsoftClientSecret: undefined,
        githubClientId: undefined,
        githubClientSecret: undefined,
        instagramClientId: undefined,
        instagramClientSecret: undefined,
      },
    },
  },
  emptyOAuth: {
    name: 'Empty OAuth configuration',
    config: {
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
    },
  },
} as const;

/**
 * Firebase configuration scenarios
 */
export const firebaseConfigScenarios = {
  completeFirebase: {
    name: 'Complete Firebase configuration',
    config: {
      firebase: {
        projectId: 'test-project',
        privateKey: 'test-private-key',
        clientEmail: 'test@test.com',
        storageBucket: 'test-bucket',
      },
    },
  },
  partialFirebase: {
    name: 'Partial Firebase configuration',
    config: {
      firebase: {
        projectId: 'test-project',
        privateKey: '',
        clientEmail: '',
        storageBucket: '',
      },
    },
  },
  emptyFirebase: {
    name: 'Empty Firebase configuration',
    config: {
      firebase: {
        projectId: undefined,
        privateKey: '',
        clientEmail: '',
        storageBucket: '',
      },
    },
  },
} as const;

/**
 * Mock dotenv module
 */
export const mockDotenv = {
  config: jest.fn(),
};

/**
 * Mock path module
 */
export const mockPath = {
  join: jest.fn((...args: string[]) => args.join('/')),
};

/**
 * Mock process.env for testing
 */
export class MockProcessEnv {
  private originalEnv: NodeJS.ProcessEnv;
  private currentEnv: Record<string, string | undefined>;

  constructor() {
    this.originalEnv = { ...process.env };
    this.currentEnv = {};
  }

  /**
   * Set environment variables for testing
   */
  setEnv(env: Record<string, string | undefined>): void {
    this.currentEnv = { ...env };
    Object.keys(env).forEach(key => {
      if (env[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = env[key];
      }
    });
  }

  /**
   * Clear specific environment variable
   */
  clearEnv(key: string): void {
    delete process.env[key];
    delete this.currentEnv[key];
  }

  /**
   * Clear all environment variables
   */
  clearAllEnv(): void {
    Object.keys(this.currentEnv).forEach(key => {
      delete process.env[key];
    });
    this.currentEnv = {};
  }

  /**
   * Restore original environment variables
   */
  restore(): void {
    // Clear current test env
    Object.keys(this.currentEnv).forEach(key => {
      delete process.env[key];
    });
    
    // Restore original env
    Object.keys(this.originalEnv).forEach(key => {
      const value = this.originalEnv[key];
      if (value !== undefined) {
        process.env[key] = value;
      }
    });
    
    this.currentEnv = {};
  }

  /**
   * Get current environment state
   */
  getCurrentEnv(): Record<string, string | undefined> {
    return { ...this.currentEnv };
  }
}

/**
 * Factory function to create mock config with overrides
 */
export const createMockConfig = (
  overrides: Partial<MockConfig> = {},
  baseConfig: MockConfig = defaultMockConfig
): MockConfig => {
  return {
    ...baseConfig,
    ...overrides,
    firebase: {
      ...baseConfig.firebase,
      ...overrides.firebase,
    },
    oauth: {
      ...baseConfig.oauth,
      ...overrides.oauth,
    },
  };
};

/**
 * Factory function to create mock environment variables
 */
export const createMockEnvVars = (
  environment: keyof typeof mockEnvironmentVariables,
  overrides: Record<string, string | undefined> = {}
): Record<string, string | undefined> => {
  return {
    ...mockEnvironmentVariables[environment],
    ...overrides,
  };
};

/**
 * Validation helper for config properties
 */
export const validateMockConfig = (config: MockConfig): string[] => {
  const errors: string[] = [];

  // Required fields validation
  if (!config.jwtSecret || config.jwtSecret === '') {
    errors.push('JWT secret is required');
  }

  if (!config.databaseUrl || config.databaseUrl === '') {
    errors.push('Database URL is required');
  }

  // Type validation
  if (typeof config.port !== 'number' && typeof config.port !== 'string') {
    errors.push('Port must be a number or string');
  }

  if (typeof config.dbPoolMax !== 'number' || config.dbPoolMax < 1) {
    errors.push('Database pool max must be a positive number');
  }

  if (typeof config.maxFileSize !== 'number' || config.maxFileSize < 0) {
    errors.push('Max file size must be a non-negative number');
  }

  // Environment validation
  const validEnvironments = ['development', 'production', 'test'];
  if (!validEnvironments.includes(config.nodeEnv)) {
    errors.push(`Invalid node environment: ${config.nodeEnv}`);
  }

  // Storage mode validation
  const validStorageModes = ['local', 'firebase'];
  if (!validStorageModes.includes(config.storageMode)) {
    errors.push(`Invalid storage mode: ${config.storageMode}`);
  }

  return errors;
};

/**
 * Helper to generate config test data
 */
export const generateConfigTestData = () => ({
  validConfigs: [
    defaultMockConfig,
    developmentMockConfig,
    productionMockConfig,
  ],
  invalidConfigs: [
    createMockConfig({ jwtSecret: '' }),
    createMockConfig({ databaseUrl: '' }),
    createMockConfig({ dbPoolMax: -1 }),
    createMockConfig({ maxFileSize: -1 }),
  ],
  edgeCaseConfigs: [
    createMockConfig({ port: '0' }),
    createMockConfig({ dbPoolMax: 0 }),
    createMockConfig({ maxFileSize: 0 }),
    createMockConfig({ 
      firebase: { 
        projectId: undefined, 
        privateKey: '', 
        clientEmail: '', 
        storageBucket: '' 
      } 
    }),
  ],
});

/**
 * Reset all mocks
 */
export const resetConfigMocks = (): void => {
  mockDotenv.config.mockClear();
  mockPath.join.mockClear();
};

/**
 * Setup mock implementations
 */
export const setupConfigMockImplementations = (): void => {
  mockDotenv.config.mockImplementation(() => ({ parsed: {} }));
  mockPath.join.mockImplementation((...args: string[]) => args.join('/'));
};

/**
 * Helper to create environment-specific test scenarios
 */
export const createEnvironmentTestScenarios = () => {
  const environments = ['test', 'development', 'production'] as const;
  
  return environments.map(env => ({
    name: `${env} environment configuration`,
    environment: env,
    envVars: mockEnvironmentVariables[env],
    expectedConfig: env === 'test' ? defaultMockConfig : 
                   env === 'development' ? developmentMockConfig : 
                   productionMockConfig,
  }));
};

/**
 * Helper functions for specific configuration aspects
 */
export const configHelpers = {
  /**
   * Create database config for testing
   */
  createDatabaseConfig: (nodeEnv: string = 'test') => {
    const isTest = nodeEnv === 'test';
    return {
      databaseUrl: isTest 
        ? 'postgresql://postgres:password@localhost:5432/koutu_test'
        : 'postgresql://postgres:password@localhost:5432/koutu',
      dbPoolMax: isTest ? 5 : 10,
      dbConnectionTimeout: 0,
      dbIdleTimeout: 10000,
      dbStatementTimeout: 0,
      dbRequireSsl: false,
    };
  },

  /**
   * Create JWT config for testing
   */
  createJwtConfig: (secret?: string) => ({
    jwtSecret: secret || 'test-jwt-secret',
    jwtExpiresIn: '1d',
  }),

  /**
   * Create Firebase config for testing
   */
  createFirebaseConfig: (complete: boolean = true) => ({
    firebase: {
      projectId: complete ? 'test-project' : undefined,
      privateKey: complete ? 'test-private-key' : '',
      clientEmail: complete ? 'test@test.com' : '',
      storageBucket: complete ? 'test-bucket' : '',
    },
  }),

  /**
   * Create OAuth config for testing
   */
  createOAuthConfig: (providers: string[] = []) => {
    const oauth: any = {
      googleClientId: undefined,
      googleClientSecret: undefined,
      microsoftClientId: undefined,
      microsoftClientSecret: undefined,
      githubClientId: undefined,
      githubClientSecret: undefined,
      instagramClientId: undefined,
      instagramClientSecret: undefined,
    };

    providers.forEach(provider => {
      oauth[`${provider}ClientId`] = `${provider}-client-id`;
      oauth[`${provider}ClientSecret`] = `${provider}-client-secret`;
    });

    return { oauth };
  },
};

/**
 * Export default mock for easy importing
 */
export default {
  defaultMockConfig,
  developmentMockConfig,
  productionMockConfig,
  mockEnvironmentVariables,
  configScenarios,
  createMockConfig,
  createMockEnvVars,
  validateMockConfig,
  MockProcessEnv,
  resetConfigMocks,
  setupConfigMockImplementations,
};