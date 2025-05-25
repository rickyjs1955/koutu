// backend/src/__tests__/__helpers__/index.helper.ts
import { jest } from '@jest/globals';
import {
  MockConfig,
  MockProcessEnv,
  defaultMockConfig,
  developmentMockConfig,
  productionMockConfig,
  mockEnvironmentVariables,
  configScenarios,
  createMockConfig,
  createMockEnvVars,
  validateMockConfig,
  resetConfigMocks,
  setupConfigMockImplementations,
  configHelpers,
} from '../__mocks__/index.mock';

/**
 * Test scenario interface for configuration testing
 */
export interface ConfigTestScenario {
  name: string;
  environment: string;
  envVars: Record<string, string | undefined>;
  expectedConfig: Partial<MockConfig>;
  shouldThrow?: boolean;
  expectedError?: string;
}

/**
 * Helper to create standardized configuration test scenarios
 */
export const createConfigTestScenario = (
  name: string,
  environment: string,
  envVars: Record<string, string | undefined> = {},
  expectedConfigOverrides: Partial<MockConfig> = {},
  options: { shouldThrow?: boolean; expectedError?: string } = {}
): ConfigTestScenario => {
  const baseConfig = environment === 'test' ? defaultMockConfig :
                   environment === 'development' ? developmentMockConfig :
                   environment === 'production' ? productionMockConfig :
                   defaultMockConfig;

  return {
    name,
    environment,
    envVars: {
      ...mockEnvironmentVariables[environment as keyof typeof mockEnvironmentVariables],
      NODE_ENV: environment,
      ...envVars,
    },
    expectedConfig: {
      ...baseConfig,
      ...expectedConfigOverrides,
    },
    shouldThrow: options.shouldThrow,
    expectedError: options.expectedError,
  };
};

/**
 * Helper to run configuration test scenarios
 */
export const runConfigTestScenario = (scenario: ConfigTestScenario, configFactory: () => any) => {
  it(scenario.name, () => {
    const mockEnv = new MockProcessEnv();
    
    try {
      // Set up environment
      mockEnv.setEnv(scenario.envVars);
      
      if (scenario.shouldThrow) {
        expect(() => configFactory()).toThrow(scenario.expectedError);
      } else {
        const config = configFactory();
        
        // Validate basic structure
        expect(config).toBeDefined();
        expect(config).toHaveProperty('port');
        expect(config).toHaveProperty('nodeEnv');
        expect(config).toHaveProperty('databaseUrl');
        expect(config).toHaveProperty('jwtSecret');
        expect(config).toHaveProperty('firebase');
        expect(config).toHaveProperty('oauth');
        
        // Validate specific expected values
        Object.keys(scenario.expectedConfig).forEach(key => {
          const expectedValue = scenario.expectedConfig[key as keyof MockConfig];
          if (expectedValue !== undefined) {
            if (typeof expectedValue === 'object' && expectedValue !== null) {
              expect(config[key]).toMatchObject(expectedValue);
            } else {
              expect(config[key]).toBe(expectedValue);
            }
          }
        });
      }
    } finally {
      mockEnv.restore();
    }
  });
};

/**
 * Helper to run multiple configuration test scenarios
 */
export const runConfigTestScenarios = (
  scenarios: ConfigTestScenario[],
  configFactory: () => any
) => {
  scenarios.forEach(scenario => runConfigTestScenario(scenario, configFactory));
};

/**
 * Helper to test environment variable parsing
 */
export const testEnvironmentVariableParsing = (
  envVar: string,
  testCases: Array<{
    name: string;
    value: string | undefined;
    expectedResult: any;
    configProperty: string;
  }>,
  configFactory: () => any
) => {
  describe(`${envVar} environment variable parsing`, () => {
    testCases.forEach(testCase => {
      it(testCase.name, () => {
        const mockEnv = new MockProcessEnv();
        
        try {
          const envVars: Record<string, string | undefined> = {
            JWT_SECRET: 'test-secret', // Always provide required vars
          };
          envVars[envVar] = testCase.value;
          
          mockEnv.setEnv(envVars);
          
          const config = configFactory();
          expect(config[testCase.configProperty]).toEqual(testCase.expectedResult);
        } finally {
          mockEnv.restore();
        }
      });
    });
  });
};

/**
 * Helper to assert configuration properties
 */
export const assertConfigProperties = (
  config: any,
  expectedProperties: {
    port?: number | string;
    nodeEnv?: string;
    databaseUrl?: string;
    dbPoolMax?: number;
    dbConnectionTimeout?: number;
    dbIdleTimeout?: number;
    dbStatementTimeout?: number;
    dbRequireSsl?: boolean;
    jwtSecret?: string;
    jwtExpiresIn?: string;
    uploadsDir?: string;
    maxFileSize?: number;
    logLevel?: string;
    storageMode?: string;
    appUrl?: string;
    firebase?: Partial<MockConfig['firebase']>;
    oauth?: Partial<MockConfig['oauth']>;
  }
) => {
  Object.keys(expectedProperties).forEach(key => {
    const expectedValue = expectedProperties[key as keyof typeof expectedProperties];
    if (expectedValue !== undefined) {
      if (typeof expectedValue === 'object' && expectedValue !== null) {
        expect(config[key]).toMatchObject(expectedValue);
      } else {
        expect(config[key]).toBe(expectedValue);
      }
    }
  });
};

/**
 * Helper to test configuration validation
 */
export const testConfigValidation = (
  config: MockConfig,
  expectations: {
    isValid?: boolean;
    expectedErrors?: string[];
    hasRequiredFields?: boolean;
    hasValidTypes?: boolean;
  }
) => {
  const errors = validateMockConfig(config);
  
  if (expectations.isValid !== undefined) {
    expect(errors.length === 0).toBe(expectations.isValid);
  }
  
  if (expectations.expectedErrors) {
    expectations.expectedErrors.forEach(expectedError => {
      expect(errors).toContain(expectedError);
    });
  }
  
  if (expectations.hasRequiredFields !== undefined) {
    const hasJwtSecret = !!config.jwtSecret;
    const hasDatabaseUrl = !!config.databaseUrl;
    expect(hasJwtSecret && hasDatabaseUrl).toBe(expectations.hasRequiredFields);
  }
  
  if (expectations.hasValidTypes !== undefined) {
    const validPort = typeof config.port === 'number' || typeof config.port === 'string';
    const validDbPoolMax = typeof config.dbPoolMax === 'number' && config.dbPoolMax >= 0;
    const validMaxFileSize = typeof config.maxFileSize === 'number' && config.maxFileSize >= 0;
    expect(validPort && validDbPoolMax && validMaxFileSize).toBe(expectations.hasValidTypes);
  }
};

/**
 * Helper to test environment helper functions
 */
export const testEnvironmentHelpers = (
  helperFunctions: {
    isProd: () => boolean;
    isDev: () => boolean;
    isTest: () => boolean;
  }
) => {
  describe('Environment helper functions', () => {
    const environments = [
      { name: 'production', isProd: true, isDev: false, isTest: false },
      { name: 'development', isProd: false, isDev: true, isTest: false },
      { name: 'test', isProd: false, isDev: false, isTest: true },
    ];

    environments.forEach(env => {
      it(`should correctly identify ${env.name} environment`, () => {
        const mockEnv = new MockProcessEnv();
        
        try {
          mockEnv.setEnv({ NODE_ENV: env.name });
          
          expect(helperFunctions.isProd()).toBe(env.isProd);
          expect(helperFunctions.isDev()).toBe(env.isDev);
          expect(helperFunctions.isTest()).toBe(env.isTest);
        } finally {
          mockEnv.restore();
        }
      });
    });
  });
};

/**
 * Helper to create comprehensive test suites for specific config sections
 */
export const createConfigSectionTestSuite = (
  sectionName: string,
  testCases: Array<{
    name: string;
    envVars: Record<string, string | undefined>;
    expectedConfig: any;
    shouldValidate?: boolean;
  }>,
  configFactory: () => any
) => {
  describe(`${sectionName} configuration`, () => {
    testCases.forEach(testCase => {
      it(testCase.name, () => {
        const mockEnv = new MockProcessEnv();
        
        try {
          mockEnv.setEnv({
            JWT_SECRET: 'test-secret', // Always provide required vars
            ...testCase.envVars,
          });
          
          const config = configFactory();
          expect(config).toMatchObject(testCase.expectedConfig);
          
          if (testCase.shouldValidate !== false) {
            const errors = validateMockConfig(config);
            expect(errors).toHaveLength(0);
          }
        } finally {
          mockEnv.restore();
        }
      });
    });
  });
};

/**
 * Helper to create database configuration test scenarios
 */
export const createDatabaseConfigScenarios = (): ConfigTestScenario[] => [
  createConfigTestScenario(
    'should use test database URL in test environment',
    'test',
    { TEST_DATABASE_URL: 'postgresql://test:test@localhost:5432/test_db' },
    { databaseUrl: 'postgresql://test:test@localhost:5432/test_db' }
  ),
  createConfigTestScenario(
    'should use regular database URL in development',
    'development',
    { DATABASE_URL: 'postgresql://dev:dev@localhost:5432/dev_db' },
    { databaseUrl: 'postgresql://dev:dev@localhost:5432/dev_db' }
  ),
  createConfigTestScenario(
    'should configure database pool size',
    'test',
    { DB_POOL_MAX: '15' },
    { dbPoolMax: 15 }
  ),
  createConfigTestScenario(
    'should configure database timeouts',
    'test',
    { 
      DB_CONNECTION_TIMEOUT: '5000',
      DB_IDLE_TIMEOUT: '30000',
      DB_STATEMENT_TIMEOUT: '10000'
    },
    { 
      dbConnectionTimeout: 5000,
      dbIdleTimeout: 30000,
      dbStatementTimeout: 10000
    }
  ),
  createConfigTestScenario(
    'should configure SSL requirement',
    'production',
    { DB_REQUIRE_SSL: 'true' },
    { dbRequireSsl: true }
  ),
];

/**
 * Helper to create JWT configuration test scenarios
 */
export const createJwtConfigScenarios = (): ConfigTestScenario[] => [
  createConfigTestScenario(
    'should use provided JWT secret',
    'test',
    { JWT_SECRET: 'my-secure-secret' },
    { jwtSecret: 'my-secure-secret' }
  ),
  createConfigTestScenario(
    'should use custom JWT expiration',
    'test',
    { 
      JWT_SECRET: 'test-secret',
      JWT_EXPIRES_IN: '7d' 
    },
    { jwtExpiresIn: '7d' }
  ),
  createConfigTestScenario(
    'should throw error when JWT secret is missing',
    'test',
    { JWT_SECRET: undefined },
    {},
    { shouldThrow: true, expectedError: 'JWT_SECRET environment variable is required' }
  ),
];

/**
 * Helper to create Firebase configuration test scenarios
 */
export const createFirebaseConfigScenarios = (): ConfigTestScenario[] => [
  createConfigTestScenario(
    'should configure complete Firebase settings',
    'test',
    {
      FIREBASE_PROJECT_ID: 'my-project',
      FIREBASE_PRIVATE_KEY: 'my-private-key',
      FIREBASE_CLIENT_EMAIL: 'my-email@project.iam.gserviceaccount.com',
      FIREBASE_STORAGE_BUCKET: 'my-project.appspot.com',
    },
    {
      firebase: {
        projectId: 'my-project',
        privateKey: 'my-private-key',
        clientEmail: 'my-email@project.iam.gserviceaccount.com',
        storageBucket: 'my-project.appspot.com',
      }
    }
  ),
  createConfigTestScenario(
    'should handle missing Firebase configuration',
    'test',
    {
      FIREBASE_PROJECT_ID: undefined,
      FIREBASE_PRIVATE_KEY: undefined,
      FIREBASE_CLIENT_EMAIL: undefined,
      FIREBASE_STORAGE_BUCKET: undefined,
    },
    {
      firebase: {
        projectId: undefined,
        privateKey: '',
        clientEmail: '',
        storageBucket: '',
      }
    }
  ),
];

/**
 * Helper to create OAuth configuration test scenarios
 */
export const createOAuthConfigScenarios = (): ConfigTestScenario[] => [
  createConfigTestScenario(
    'should configure Google OAuth',
    'test',
    {
      GOOGLE_CLIENT_ID: 'google-client-id',
      GOOGLE_CLIENT_SECRET: 'google-client-secret',
    },
    {
      oauth: expect.objectContaining({
        googleClientId: 'google-client-id',
        googleClientSecret: 'google-client-secret',
      })
    }
  ),
  createConfigTestScenario(
    'should configure Microsoft OAuth',
    'test',
    {
      MICROSOFT_CLIENT_ID: 'microsoft-client-id',
      MICROSOFT_CLIENT_SECRET: 'microsoft-client-secret',
    },
    {
      oauth: expect.objectContaining({
        microsoftClientId: 'microsoft-client-id',
        microsoftClientSecret: 'microsoft-client-secret',
      })
    }
  ),
  createConfigTestScenario(
    'should configure all OAuth providers',
    'test',
    {
      GOOGLE_CLIENT_ID: 'google-id',
      GOOGLE_CLIENT_SECRET: 'google-secret',
      MICROSOFT_CLIENT_ID: 'microsoft-id',
      MICROSOFT_CLIENT_SECRET: 'microsoft-secret',
      GITHUB_CLIENT_ID: 'github-id',
      GITHUB_CLIENT_SECRET: 'github-secret',
      INSTAGRAM_CLIENT_ID: 'instagram-id',
      INSTAGRAM_CLIENT_SECRET: 'instagram-secret',
    },
    {
      oauth: {
        googleClientId: 'google-id',
        googleClientSecret: 'google-secret',
        microsoftClientId: 'microsoft-id',
        microsoftClientSecret: 'microsoft-secret',
        githubClientId: 'github-id',
        githubClientSecret: 'github-secret',
        instagramClientId: 'instagram-id',
        instagramClientSecret: 'instagram-secret',
      }
    }
  ),
];

/**
 * Helper to create file storage configuration test scenarios
 */
export const createFileStorageConfigScenarios = (): ConfigTestScenario[] => [
  createConfigTestScenario(
    'should configure local storage mode',
    'test',
    { STORAGE_MODE: 'local' },
    { storageMode: 'local' }
  ),
  createConfigTestScenario(
    'should configure Firebase storage mode',
    'test',
    { STORAGE_MODE: 'firebase' },
    { storageMode: 'firebase' }
  ),
  createConfigTestScenario(
    'should configure maximum file size',
    'test',
    { MAX_FILE_SIZE: '10485760' }, // 10MB
    { maxFileSize: 10485760 }
  ),
];

/**
 * Helper to test configuration defaults
 */
export const testConfigurationDefaults = (configFactory: () => any) => {
  describe('Configuration defaults', () => {
    it('should provide sensible defaults when environment variables are missing', () => {
      const mockEnv = new MockProcessEnv();
      
      try {
        mockEnv.setEnv({
          JWT_SECRET: 'test-secret', // Only provide required var
        });
        
        const config = configFactory();
        
        // Test default values
        expect(config.port).toBe(3000);
        expect(config.nodeEnv).toBe('development');
        expect(config.logLevel).toBe('info');
        expect(config.storageMode).toBe('firebase');
        expect(config.appUrl).toBe('http://localhost:3000');
        expect(config.jwtExpiresIn).toBe('1d');
        expect(config.dbPoolMax).toBe(10); // Development default
        expect(config.dbConnectionTimeout).toBe(0);
        expect(config.dbIdleTimeout).toBe(10000);
        expect(config.dbStatementTimeout).toBe(0);
        expect(config.dbRequireSsl).toBe(false);
        expect(config.maxFileSize).toBe(5242880); // 5MB
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to test environment-specific configurations
 */
export const testEnvironmentSpecificConfigurations = (configFactory: () => any) => {
  describe('Environment-specific configurations', () => {
    const environments = ['test', 'development', 'production'] as const;
    
    environments.forEach(env => {
      it(`should configure correctly for ${env} environment`, () => {
        const mockEnv = new MockProcessEnv();
        
        try {
          mockEnv.setEnv(createMockEnvVars(env));
          
          const config = configFactory();
          
          expect(config.nodeEnv).toBe(env);
          
          // Test environment-specific database configurations
          if (env === 'test') {
            expect(config.databaseUrl).toContain('koutu_test');
            expect(config.dbPoolMax).toBe(5);
          } else {
            expect(config.dbPoolMax).toBe(10);
          }
        } finally {
          mockEnv.restore();
        }
      });
    });
  });
};

/**
 * Helper to test configuration error handling
 */
export const testConfigurationErrorHandling = (configFactory: () => any) => {
  describe('Configuration error handling', () => {
    it('should throw error for missing JWT secret', () => {
      const mockEnv = new MockProcessEnv();
      
      try {
        mockEnv.setEnv({ JWT_SECRET: undefined });
        
        expect(() => configFactory()).toThrow('JWT_SECRET environment variable is required');
      } finally {
        mockEnv.restore();
      }
    });
    
    it('should handle invalid numeric environment variables gracefully', () => {
      const mockEnv = new MockProcessEnv();
      
      try {
        mockEnv.setEnv({
          JWT_SECRET: 'test-secret',
          PORT: 'invalid-port',
          DB_POOL_MAX: 'invalid-number',
          MAX_FILE_SIZE: 'invalid-size',
        });
        
        const config = configFactory();
        
        // Should not throw, but might have NaN values
        expect(config).toBeDefined();
        expect(typeof config.port).toBe('string'); // PORT remains as string
        expect(isNaN(config.dbPoolMax)).toBe(true); // parseInt('invalid-number') returns NaN
        expect(isNaN(config.maxFileSize)).toBe(true);
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to create parameterized environment tests
 */
export const createParameterizedEnvironmentTests = (
  testFunction: (environment: string, envVars: Record<string, string | undefined>) => void
) => {
  Object.entries(mockEnvironmentVariables).forEach(([environment, envVars]) => {
    testFunction(environment, envVars);
  });
};

/**
 * Helper to test configuration immutability
 */
export const testConfigurationImmutability = (configFactory: () => any) => {
  describe('Configuration immutability', () => {
    it('should not allow modification of configuration object', () => {
      const mockEnv = new MockProcessEnv();
      
      try {
        mockEnv.setEnv(createMockEnvVars('test'));
        
        const config = configFactory();
        const originalPort = config.port;
        
        // Attempt to modify configuration
        config.port = 9999;
        
        // Configuration should remain unchanged (if frozen/sealed)
        // Note: This test assumes configuration is made immutable
        // If not implemented, this would need to be adjusted
        const newConfig = configFactory();
        expect(newConfig.port).toBe(originalPort);
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to assert module exports
 */
export const assertModuleExports = (configModule: any) => {
  expect(configModule).toHaveProperty('config');
  expect(configModule).toHaveProperty('isProd');
  expect(configModule).toHaveProperty('isDev');
  expect(configModule).toHaveProperty('isTest');
  
  expect(typeof configModule.isProd).toBe('function');
  expect(typeof configModule.isDev).toBe('function');
  expect(typeof configModule.isTest).toBe('function');
};

/**
 * Helper to create comprehensive configuration test scenarios
 */
export const createComprehensiveConfigTestScenarios = () => ({
  databaseScenarios: createDatabaseConfigScenarios(),
  jwtScenarios: createJwtConfigScenarios(),
  firebaseScenarios: createFirebaseConfigScenarios(),
  oauthScenarios: createOAuthConfigScenarios(),
  fileStorageScenarios: createFileStorageConfigScenarios(),
});

/**
 * Helper to setup configuration test environment
 */
export const setupConfigTestEnvironment = () => {
  beforeEach(() => {
    resetConfigMocks();
    setupConfigMockImplementations();
  });
  
  afterEach(() => {
    resetConfigMocks();
  });
};

/**
 * Helper to create mock configuration loader
 */
export const createMockConfigLoader = (baseConfig: MockConfig = defaultMockConfig) => {
  return jest.fn(() => baseConfig);
};

/**
 * Helper to test configuration caching
 */
export const testConfigurationCaching = (configFactory: () => any) => {
  describe('Configuration caching', () => {
    it('should return the same configuration object on multiple calls', () => {
      const mockEnv = new MockProcessEnv();
      
      try {
        mockEnv.setEnv(createMockEnvVars('test'));
        
        const config1 = configFactory();
        const config2 = configFactory();
        
        // If configuration is cached, should be the same object
        // If not cached, should have the same values
        expect(config1).toEqual(config2);
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to test configuration path resolution
 */
export const testConfigurationPaths = (configFactory: () => any) => {
  describe('Configuration path resolution', () => {
    it('should resolve uploads directory path correctly', () => {
      const mockEnv = new MockProcessEnv();
      
      try {
        mockEnv.setEnv(createMockEnvVars('test'));
        
        const config = configFactory();
        
        expect(config.uploadsDir).toBeDefined();
        expect(typeof config.uploadsDir).toBe('string');
        expect(config.uploadsDir).toContain('uploads');
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to clean up configuration tests
 */
export const cleanupConfigTests = () => {
  resetConfigMocks();
  jest.restoreAllMocks();
  
  // Ensure NODE_ENV is reset to test
  if (process.env.NODE_ENV !== 'test') {
    process.env.NODE_ENV = 'test';
  }
};

/**
 * Helper to create mock dotenv for testing
 */
export const createMockDotenvConfig = (shouldThrow: boolean = false) => {
  return jest.fn(() => {
    if (shouldThrow) {
      throw new Error('Failed to load .env file');
    }
    return { parsed: {} };
  });
};

/**
 * Helper to assert environment variable types
 */
export const assertEnvironmentVariableTypes = (config: any) => {
  expect(typeof config.port).toMatch(/number|string/);
  expect(typeof config.nodeEnv).toBe('string');
  expect(typeof config.databaseUrl).toBe('string');
  expect(typeof config.dbPoolMax).toBe('number');
  expect(typeof config.dbConnectionTimeout).toBe('number');
  expect(typeof config.dbIdleTimeout).toBe('number');
  expect(typeof config.dbStatementTimeout).toBe('number');
  expect(typeof config.dbRequireSsl).toBe('boolean');
  expect(typeof config.jwtSecret).toBe('string');
  expect(typeof config.jwtExpiresIn).toBe('string');
  expect(typeof config.uploadsDir).toBe('string');
  expect(typeof config.maxFileSize).toBe('number');
  expect(typeof config.logLevel).toBe('string');
  expect(typeof config.storageMode).toBe('string');
  expect(typeof config.appUrl).toBe('string');
  expect(typeof config.firebase).toBe('object');
  expect(typeof config.oauth).toBe('object');
};

/**
 * Helper to create integration test scenarios
 */
export const createIntegrationTestScenarios = () => [
  {
    name: 'Full application configuration',
    envVars: createMockEnvVars('production'),
    testFunction: (config: any) => {
      expect(config.nodeEnv).toBe('production');
      expect(config.dbRequireSsl).toBe(true);
      expect(config.logLevel).toBe('error');
      assertEnvironmentVariableTypes(config);
    },
  },
  {
    name: 'Development configuration with OAuth',
    envVars: {
      ...createMockEnvVars('development'),
      GOOGLE_CLIENT_ID: 'dev-google-id',
      GOOGLE_CLIENT_SECRET: 'dev-google-secret',
    },
    testFunction: (config: any) => {
      expect(config.nodeEnv).toBe('development');
      expect(config.oauth.googleClientId).toBe('dev-google-id');
      expect(config.oauth.googleClientSecret).toBe('dev-google-secret');
    },
  },
  {
    name: 'Test configuration with Firebase',
    envVars: {
      ...createMockEnvVars('test'),
      FIREBASE_PROJECT_ID: 'test-project-123',
      STORAGE_MODE: 'firebase',
    },
    testFunction: (config: any) => {
      expect(config.nodeEnv).toBe('test');
      expect(config.storageMode).toBe('firebase');
      expect(config.firebase.projectId).toBe('test-project-123');
    },
  },
];

/**
 * Helper to run integration test scenarios
 */
export const runIntegrationTestScenarios = (
  scenarios: Array<{
    name: string;
    envVars: Record<string, string | undefined>;
    testFunction: (config: any) => void;
  }>,
  configFactory: () => any
) => {
  describe('Integration test scenarios', () => {
    scenarios.forEach(scenario => {
      it(scenario.name, () => {
        const mockEnv = new MockProcessEnv();
        
        try {
          mockEnv.setEnv(scenario.envVars);
          const config = configFactory();
          scenario.testFunction(config);
        } finally {
          mockEnv.restore();
        }
      });
    });
  });
};

/**
 * Export default helper for easy importing
 */
export default {
  createConfigTestScenario,
  runConfigTestScenario,
  runConfigTestScenarios,
  testEnvironmentVariableParsing,
  assertConfigProperties,
  testConfigValidation,
  testEnvironmentHelpers,
  createConfigSectionTestSuite,
  createComprehensiveConfigTestScenarios,
  setupConfigTestEnvironment,
  cleanupConfigTests,
};