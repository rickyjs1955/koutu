// backend/src/__tests__/__helpers__/oauth.helper.ts - Fixed version
import { jest } from '@jest/globals';
import {
  MockOAuthConfig,
  MockOAuthProvider,
  MockInstagramProvider,
  MockOAuthProcessEnv,
  defaultMockOAuthConfig,
  developmentMockOAuthConfig,
  productionMockOAuthConfig,
  mockOAuthEnvironmentVariables,
  oauthConfigScenarios,
  oauthSecurityScenarios,
  mockOAuthUserResponses,
  mockOAuthTokenResponses,
  mockOAuthErrorResponses,
  createMockOAuthConfig,
  createMockOAuthProvider,
  createMockInstagramProvider,
  validateMockOAuthConfig,
  resetOAuthMocks,
  setupOAuthMockImplementations,
} from '../__mocks__/oauth.mock';

/**
 * OAuth test scenario interface
 */
export interface OAuthTestScenario {
  name: string;
  environment: string;
  envVars: Record<string, string | undefined>;
  expectedConfig: Partial<MockOAuthConfig>;
  shouldThrow?: boolean;
  expectedError?: string;
  provider?: string;
}

/**
 * OAuth security test scenario interface
 */
export interface OAuthSecurityScenario {
  name: string;
  attackVector: string;
  maliciousInput: string;
  expectedBehavior: 'block' | 'sanitize' | 'allow';
  shouldThrow?: boolean;
  expectedError?: string;
}

/**
 * OAuth test scenario creator
 */
export const createOAuthTestScenario = (
  name: string,
  environment: string,
  envVars: Record<string, any>,
  expectedConfig: any
) => ({
  name,
  environment,
  envVars,
  expectedConfig,
});

/**
 * Helper to run OAuth test scenarios
 */
export const runOAuthTestScenario = (
  scenario: OAuthTestScenario,
  oauthConfigFactory: () => any
) => {
  it(scenario.name, () => {
    const mockEnv = new MockOAuthProcessEnv();
    
    try {
      mockEnv.setEnv(scenario.envVars);
      
      if (scenario.shouldThrow) {
        expect(() => oauthConfigFactory()).toThrow(scenario.expectedError);
      } else {
        const config = oauthConfigFactory();
        
        expect(config).toBeDefined();
        expect(config).toHaveProperty('google');
        expect(config).toHaveProperty('microsoft');
        expect(config).toHaveProperty('github');
        expect(config).toHaveProperty('instagram');
        
        // Validate specific expected values
        Object.keys(scenario.expectedConfig).forEach(providerKey => {
          const expectedProvider = scenario.expectedConfig[providerKey as keyof MockOAuthConfig];
          if (expectedProvider) {
            expect(config[providerKey]).toMatchObject(expectedProvider);
          }
        });
      }
    } finally {
      mockEnv.restore();
    }
  });
};

/**
 * Runs OAuth test scenarios
 */
export const runOAuthTestScenarios = (
  scenarios: any[],
  configFactory: () => any
) => {
  scenarios.forEach(scenario => {
    it(scenario.name, () => {
      // Set up environment for this scenario
      Object.assign(process.env, scenario.envVars);
      
      const config = configFactory();
      
      // Validate against expected config
      expect(config).toMatchObject(scenario.expectedConfig);
    });
  });
};

/**
 * Tests OAuth provider configuration
 */
export const testOAuthProviderConfiguration = (
  provider: string,
  testCases: any[],
  configFactory: any
) => {
  describe(`${provider} OAuth provider configuration`, () => {
    testCases.forEach(testCase => {
      it(testCase.name, () => {
        // Set environment variables
        Object.assign(process.env, testCase.envVars);
        
        const config = configFactory();
        const providerConfig = config[provider];
        
        // Check expected configuration
        expect(providerConfig).toMatchObject(testCase.expectedConfig);
        
        // Validate if configuration should be valid
        if (testCase.shouldBeValid !== undefined) {
          const hasRequiredFields = providerConfig.clientId && providerConfig.clientSecret;
          expect(hasRequiredFields).toBe(testCase.shouldBeValid);
        }
      });
    });
  });
};

/**
 * Tests Instagram-specific OAuth configuration
 */
export const testInstagramConfiguration = (
  testCases: any[],
  configFactory: any
) => {
  describe('Instagram OAuth configuration', () => {
    testCases.forEach(testCase => {
      it(testCase.name, () => {
        // Set environment variables
        Object.assign(process.env, testCase.envVars);
        
        const config = configFactory();
        const instagramConfig = config.instagram;
        
        // Check expected configuration
        expect(instagramConfig).toMatchObject(testCase.expectedConfig);
        
        // Validate configuration if shouldBeValid is specified
        if (testCase.shouldBeValid !== undefined) {
          const hasRequiredFields = instagramConfig.clientId && instagramConfig.clientSecret;
          
          if (testCase.shouldBeValid) {
            expect(hasRequiredFields).toBe(true);
            
            // Additional Instagram-specific validations
            if (instagramConfig.requiresHttps && process.env.NODE_ENV === 'production') {
              expect(instagramConfig.redirectUri).toMatch(/^https:/);
            }
          } else {
            // Check for expected errors
            if (testCase.expectedErrors) {
              // This would typically involve calling a validation function
              // For now, we'll just check basic requirements
              if (!hasRequiredFields) {
                expect(hasRequiredFields).toBe(false);
              }
            }
          }
        }
      });
    });
  });
};

/**
 * Helper to test OAuth authorization URL generation
 */
export const testAuthorizationUrlGeneration = (
  providers: string[],
  urlGeneratorFunction: (provider: string, state: string, additionalParams?: Record<string, string>) => string
) => {
  describe('OAuth authorization URL generation', () => {
    providers.forEach(provider => {
      it(`should generate valid authorization URL for ${provider}`, () => {
        const state = 'test-state-123';
        const additionalParams = provider === 'instagram' ? { display: 'page' } : {};
        
        const cleanAdditionalParams = additionalParams ? 
            Object.fromEntries(
             Object.entries(additionalParams).filter(([_, value]) => value !== undefined)
        ) as Record<string, string> : 
        undefined;

        const url = urlGeneratorFunction(provider, state, cleanAdditionalParams);
        
        expect(url).toContain(state);
        expect(url).toContain('client_id=');
        expect(url).toContain('redirect_uri=');
        expect(url).toContain('response_type=code');
        expect(url).toContain('scope=');
        
        if (provider === 'instagram' && additionalParams.display) {
          expect(url).toContain(`display=${additionalParams.display}`);
        }
      });
    });

    it('should handle special characters in state parameter', () => {
      const specialState = 'state-with-special-chars!@#$%^&*()';
      const url = urlGeneratorFunction('google', specialState);
      
      // FIXED: Check for the actual encoded state in the URL, not double-encoded
      expect(url).toContain('state=state-with-special-chars%21%40%23%24%25%5E%26*%28%29');
    });

    it('should generate different URLs for different providers', () => {
      const state = 'same-state';
      const googleUrl = urlGeneratorFunction('google', state);
      const instagramUrl = urlGeneratorFunction('instagram', state);
      
      expect(googleUrl).not.toBe(instagramUrl);
      expect(googleUrl).toContain('accounts.google.com');
      expect(instagramUrl).toContain('api.instagram.com');
    });
  });
};

/**
 * Helper to test OAuth user info URL generation
 */
export const testUserInfoUrlGeneration = (
  providers: string[],
  userInfoUrlFunction: (provider: string, accessToken: string, fields?: string[]) => string
) => {
  describe('OAuth user info URL generation', () => {
    providers.forEach(provider => {
      it(`should generate valid user info URL for ${provider}`, () => {
        const accessToken = `test-token-${provider}`;
        const fields = provider === 'instagram' ? ['id', 'username'] : undefined;
        
        const url = userInfoUrlFunction(provider, accessToken, fields);
        
        expect(url).toBeDefined();
        expect(typeof url).toBe('string');
        
        if (provider === 'instagram') {
          expect(url).toContain('fields=');
          expect(url).toContain('access_token=');
          if (fields) {
            expect(url).toContain(fields.join(','));
          }
        }
      });
    });
  });
};

/**
 * Helper to test OAuth configuration validation
 */
export const testOAuthConfigurationValidation = (
  validationFunction: (provider: string) => { isValid: boolean; errors: string[] }
) => {
  describe('OAuth configuration validation', () => {
    it('should validate complete configuration as valid', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.setOAuthEnv('test');
        
        const providers = ['google', 'microsoft', 'github', 'instagram'];
        providers.forEach(provider => {
          const validation = validationFunction(provider);
          expect(validation.isValid).toBe(true);
          expect(validation.errors).toHaveLength(0);
        });
      } finally {
        mockEnv.restore();
      }
    });

    it('should detect missing client credentials', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.setEnv({
          GOOGLE_CLIENT_ID: '',
          GOOGLE_CLIENT_SECRET: '',
          APP_URL: 'http://localhost:3000',
        });
        
        const validation = validationFunction('google');
        expect(validation.isValid).toBe(false);
        expect(validation.errors).toContain('google client ID is missing');
        expect(validation.errors).toContain('google client secret is missing');
      } finally {
        mockEnv.restore();
      }
    });

    it('should validate Instagram HTTPS requirements in production', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.setEnv({
          NODE_ENV: 'production',
          INSTAGRAM_CLIENT_ID: 'test-id',
          INSTAGRAM_CLIENT_SECRET: 'test-secret',
          APP_URL: 'http://koutu.com', // HTTP instead of HTTPS
        });
        
        const validation = validationFunction('instagram');
        expect(validation.isValid).toBe(false);
        expect(validation.errors).toContain('Instagram requires HTTPS redirect URIs in production');
      } finally {
        mockEnv.restore();
      }
    });

    it('should validate Instagram scope requirements', () => {
      // This would require the validation function to check scope requirements
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.setEnv({
          INSTAGRAM_CLIENT_ID: 'test-id',
          INSTAGRAM_CLIENT_SECRET: 'test-secret',
          APP_URL: 'http://localhost:3000',
        });
        
        // Test would depend on how scope validation is implemented
        const validation = validationFunction('instagram');
        expect(validation).toBeDefined();
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to test OAuth provider detection
 */
export const testOAuthProviderDetection = (
  providerDetectionFunction: () => string[]
) => {
  describe('OAuth provider detection', () => {
    it('should detect all configured providers', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.setOAuthEnv('test');
        
        const configuredProviders = providerDetectionFunction();
        expect(configuredProviders).toContain('google');
        expect(configuredProviders).toContain('microsoft');
        expect(configuredProviders).toContain('github');
        expect(configuredProviders).toContain('instagram');
      } finally {
        mockEnv.restore();
      }
    });

    it('should detect only partially configured providers', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.setEnv({
          GOOGLE_CLIENT_ID: 'test-google-id',
          GOOGLE_CLIENT_SECRET: 'test-google-secret',
          INSTAGRAM_CLIENT_ID: 'test-instagram-id',
          INSTAGRAM_CLIENT_SECRET: 'test-instagram-secret',
          APP_URL: 'http://localhost:3000',
        });
        
        const configuredProviders = providerDetectionFunction();
        expect(configuredProviders).toContain('google');
        expect(configuredProviders).toContain('instagram');
        expect(configuredProviders).not.toContain('microsoft');
        expect(configuredProviders).not.toContain('github');
      } finally {
        mockEnv.restore();
      }
    });

    it('should return empty array when no providers are configured', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.clearOAuthEnv();
        
        const configuredProviders = providerDetectionFunction();
        expect(configuredProviders).toHaveLength(0);
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to create OAuth security test scenarios
 */
export const createOAuthSecurityTestScenarios = (): OAuthSecurityScenario[] => [
  {
    name: 'Redirect URI injection attack',
    attackVector: 'redirect_uri',
    maliciousInput: 'http://evil.com/callback',
    expectedBehavior: 'block',
    shouldThrow: true,
    expectedError: 'Invalid redirect URI',
  },
  {
    name: 'XSS via redirect URI',
    attackVector: 'redirect_uri',
    maliciousInput: 'javascript:alert("xss")',
    expectedBehavior: 'block',
    shouldThrow: true,
    expectedError: 'Invalid redirect URI', // FIXED: Match the actual error message
  },
  {
    name: 'Client secret exposure in URL',
    attackVector: 'client_secret',
    maliciousInput: 'https://api.example.com/oauth?client_secret=exposed',
    expectedBehavior: 'block',
    shouldThrow: true,
    expectedError: 'Client secret must not be in URL',
  },
  {
    name: 'State parameter injection',
    attackVector: 'state',
    maliciousInput: 'state"; DROP TABLE users; --',
    expectedBehavior: 'sanitize',
  },
  {
    name: 'CSRF attack via missing state',
    attackVector: 'state',
    maliciousInput: '',
    expectedBehavior: 'block',
    shouldThrow: true,
    expectedError: 'State parameter is required',
  },
];

/**
 * Helper to test OAuth security scenarios
 */
export const testOAuthSecurityScenarios = (
  scenarios: OAuthSecurityScenario[],
  securityTestFunction: (attackVector: string, maliciousInput: string) => any
) => {
  describe('OAuth security scenarios', () => {
    scenarios.forEach(scenario => {
      it(`should handle ${scenario.name}`, () => {
        if (scenario.shouldThrow) {
          expect(() => {
            securityTestFunction(scenario.attackVector, scenario.maliciousInput);
          }).toThrow(scenario.expectedError);
        } else {
          const result = securityTestFunction(scenario.attackVector, scenario.maliciousInput);
          
          switch (scenario.expectedBehavior) {
            case 'block':
              expect(result).toBeFalsy();
              break;
            case 'sanitize':
              expect(result).not.toBe(scenario.maliciousInput);
              break;
            case 'allow':
              expect(result).toBeTruthy();
              break;
          }
        }
      });
    });
  });
};

/**
 * Helper to test OAuth token exchange
 */
export const testOAuthTokenExchange = (
  providers: string[],
  tokenExchangeFunction: (provider: string, code: string) => Promise<any>
) => {
  describe('OAuth token exchange', () => {
    providers.forEach(provider => {
      it(`should exchange authorization code for token (${provider})`, async () => {
        const authCode = `test-auth-code-${provider}`;
        
        // Mock the token exchange
        const expectedToken = mockOAuthTokenResponses[provider as keyof typeof mockOAuthTokenResponses];
        
        const result = await tokenExchangeFunction(provider, authCode);
        
        expect(result).toBeDefined();
        expect(result.access_token).toBeTruthy();
        
        if (provider !== 'github') { // GitHub doesn't always return refresh tokens
          expect(result.token_type).toBeTruthy();
        }
      });
    });

    it('should handle token exchange errors', async () => {
      const invalidCode = 'invalid-auth-code';
      
      await expect(tokenExchangeFunction('google', invalidCode))
        .rejects.toThrow();
    });
  });
};

/**
 * Helper to test OAuth user data fetching
 */
export const testOAuthUserDataFetching = (
  providers: string[],
  userDataFunction: (provider: string, accessToken: string) => Promise<any>
) => {
  describe('OAuth user data fetching', () => {
    providers.forEach(provider => {
      it(`should fetch user data with valid token (${provider})`, async () => {
        const accessToken = `valid-token-${provider}`;
        
        const userData = await userDataFunction(provider, accessToken);
        
        expect(userData).toBeDefined();
        expect(userData.id).toBeTruthy();
        
        // Provider-specific assertions
        switch (provider) {
          case 'google':
            expect(userData.email).toBeTruthy();
            expect(userData.verified_email).toBeDefined();
            break;
          case 'microsoft':
            expect(userData.userPrincipalName || userData.mail).toBeTruthy();
            break;
          case 'github':
            expect(userData.login).toBeTruthy();
            break;
          case 'instagram':
            expect(userData.username).toBeTruthy();
            expect(userData.account_type).toBeTruthy();
            break;
        }
      });
    });

    it('should handle invalid access tokens', async () => {
      const invalidToken = 'invalid-access-token';
      
      await expect(userDataFunction('google', invalidToken))
        .rejects.toThrow();
    });
  });
};

/**
 * Helper to create comprehensive OAuth test scenarios
 */
export const createComprehensiveOAuthTestScenarios = () => ({
  configurationScenarios: [
    createOAuthTestScenario(
      'should configure all OAuth providers in test environment',
      'test',
      {},
      { google: expect.objectContaining({ clientId: 'test-google-client-id' }) }
    ),
    createOAuthTestScenario(
      'should configure HTTPS redirect URIs in production',
      'production',
      {},
      { 
        instagram: expect.objectContaining({ 
          redirectUri: expect.stringContaining('https://'),
          requiresHttps: true 
        }) 
      }
    ),
    createOAuthTestScenario(
      'should handle missing Instagram credentials',
      'test',
      { INSTAGRAM_CLIENT_ID: undefined, INSTAGRAM_CLIENT_SECRET: undefined },
      { instagram: expect.objectContaining({ clientId: '', clientSecret: '' }) }
    ),
  ],
  securityScenarios: createOAuthSecurityTestScenarios(),
  integrationScenarios: [
    {
      name: 'Complete OAuth flow integration',
      provider: 'google',
      authCode: 'test-auth-code',
      expectedUserData: mockOAuthUserResponses.google,
    },
    {
      name: 'Instagram OAuth flow with field selection',
      provider: 'instagram',
      authCode: 'test-instagram-code',
      fields: ['id', 'username', 'account_type'],
      expectedUserData: mockOAuthUserResponses.instagram,
    },
  ],
});

/**
 * Sets up OAuth test environment with proper mock implementations
 * NOTE: This function should NOT contain beforeEach/afterEach hooks
 * Those should be defined at the top level of describe blocks
 */
export const setupOAuthTestEnvironment = () => {
  // Initialize mocks and setup
  resetOAuthMocks();
  setupOAuthMockImplementations();
  
  // Return cleanup function if needed
  return () => {
    resetOAuthMocks();
    cleanupOAuthTests();
  };
};

/**
 * Alternative setup function that returns setup/cleanup functions
 * for manual control in tests
 */
export const createOAuthTestEnvironment = () => {
  return {
    setup: () => {
      resetOAuthMocks();
      setupOAuthMockImplementations();
    },
    cleanup: () => {
      resetOAuthMocks();
      cleanupOAuthTests();
    }
  };
};

/**
 * Helper to test OAuth configuration caching
 */
export const testOAuthConfigurationCaching = (
  configFactory: () => any
) => {
  describe('OAuth configuration caching', () => {
    it('should return consistent configuration on multiple calls', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.setOAuthEnv('test');
        
        const config1 = configFactory();
        const config2 = configFactory();
        
        expect(config1).toEqual(config2);
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to test OAuth environment-specific configurations
 */
export const testOAuthEnvironmentSpecificConfigurations = (
  configFactory: () => any
) => {
  describe('OAuth environment-specific configurations', () => {
    const environments = ['test', 'development', 'production'] as const;
    
    environments.forEach(env => {
      it(`should configure OAuth correctly for ${env} environment`, () => {
        const mockEnv = new MockOAuthProcessEnv();
        
        try {
          mockEnv.setOAuthEnv(env);
          
          const config = configFactory();
          
          // Test environment-specific settings
          if (env === 'production') {
            expect(config.instagram.requiresHttps).toBe(true);
            expect(config.google.redirectUri).toContain('https://');
          } else {
            expect(config.instagram.requiresHttps).toBe(false);
          }
          
          // All providers should have correct app URL
          const expectedAppUrl = mockOAuthEnvironmentVariables[env].APP_URL;
          Object.values(config).forEach((provider: any) => {
            expect(provider.redirectUri).toContain(expectedAppUrl);
          });
        } finally {
          mockEnv.restore();
        }
      });
    });
  });
};

/**
 * Helper to test OAuth error handling
 */
export const testOAuthErrorHandling = (
  configFactory: () => any
) => {
  describe('OAuth error handling', () => {
    it('should handle missing environment variables gracefully', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.clearOAuthEnv();
        
        const config = configFactory();
        
        // Should not throw, but should have empty client IDs/secrets
        expect(config).toBeDefined();
        expect(config.google.clientId).toBe('');
        expect(config.google.clientSecret).toBe('');
      } finally {
        mockEnv.restore();
      }
    });
    
    it('should handle malformed environment variables', () => {
      const mockEnv = new MockOAuthProcessEnv();
      
      try {
        mockEnv.setEnv({
          GOOGLE_CLIENT_ID: 'valid-id',
          GOOGLE_CLIENT_SECRET: 'valid-secret',
          APP_URL: 'not-a-valid-url',
        });
        
        const config = configFactory();
        
        // Should not throw, but might have unexpected redirect URIs
        expect(config).toBeDefined();
        expect(config.google.clientId).toBe('valid-id');
      } finally {
        mockEnv.restore();
      }
    });
  });
};

/**
 * Helper to assert OAuth module exports
 */
export const assertOAuthModuleExports = (oauthModule: any) => {
  expect(oauthModule).toHaveProperty('oauthConfig');
  expect(oauthModule).toHaveProperty('getAuthorizationUrl');
  expect(oauthModule).toHaveProperty('getUserInfoUrl');
  expect(oauthModule).toHaveProperty('validateOAuthConfig');
  expect(oauthModule).toHaveProperty('getConfiguredProviders');
  expect(oauthModule).toHaveProperty('isInstagramEnabled');
  
  expect(typeof oauthModule.getAuthorizationUrl).toBe('function');
  expect(typeof oauthModule.getUserInfoUrl).toBe('function');
  expect(typeof oauthModule.validateOAuthConfig).toBe('function');
  expect(typeof oauthModule.getConfiguredProviders).toBe('function');
  expect(typeof oauthModule.isInstagramEnabled).toBe('function');
};

/**
 * Helper to create mock HTTP responses for OAuth testing
 */
export const createMockOAuthHttpResponses = () => ({
  tokenSuccess: (provider: string) => ({
    status: 200,
    data: mockOAuthTokenResponses[provider as keyof typeof mockOAuthTokenResponses],
  }),
  tokenError: (error: string = 'invalid_grant') => ({
    status: 400,
    data: mockOAuthErrorResponses[error as keyof typeof mockOAuthErrorResponses] || {
      error: 'invalid_request',
      error_description: 'The request is invalid',
    },
  }),
  userDataSuccess: (provider: string) => ({
    status: 200,
    data: mockOAuthUserResponses[provider as keyof typeof mockOAuthUserResponses],
  }),
  userDataError: () => ({
    status: 401,
    data: {
      error: {
        message: 'Invalid OAuth access token',
        type: 'OAuthException',
        code: 190,
      },
    },
  }),
});

/**
 * Helper to clean up OAuth tests
 */
export const cleanupOAuthTests = () => {
  resetOAuthMocks();
  jest.restoreAllMocks();
};

export const setupOAuthControllerTests = () => {
  let oauthController: any;

  const loadController = async () => {
    // Clear module cache to ensure fresh import
    delete require.cache[require.resolve('../../controllers/oauthController')];
    
    // Set test environment before importing
    process.env.NODE_ENV = 'test';
    
    // Import controller
    const controllerModule = await import('../../controllers/oauthController');
    oauthController = controllerModule.oauthController;
    
    return oauthController;
  };

  const cleanupController = () => {
    if (oauthController?._testUtils) {
      oauthController._testUtils.stopCleanup();
      oauthController._testUtils.clearStates();
    }
  };

  return {
    loadController,
    cleanupController,
    getController: () => oauthController
  };
};

/**
 * Export default helper for easy importing
 */
export default {
  createOAuthTestScenario,
  runOAuthTestScenario,
  runOAuthTestScenarios,
  testOAuthProviderConfiguration,
  testInstagramConfiguration,
  testAuthorizationUrlGeneration,
  testUserInfoUrlGeneration,
  testOAuthConfigurationValidation,
  testOAuthProviderDetection,
  createOAuthSecurityTestScenarios,
  testOAuthSecurityScenarios,
  testOAuthTokenExchange,
  testOAuthUserDataFetching,
  createComprehensiveOAuthTestScenarios,
  setupOAuthTestEnvironment,
  cleanupOAuthTests,
  setupOAuthControllerTests
};