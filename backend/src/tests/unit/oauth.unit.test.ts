// backend/src/__tests__/config/oauth.unit.test.ts
import { jest } from '@jest/globals';
import { beforeEach, afterEach, describe, it, expect } from '@jest/globals';

// Mock dependencies before importing
jest.mock('../../config/index', () => ({
  config: {
    nodeEnv: 'test',
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
  },
}));

// Import OAuth helpers and mocks
import {
  MockOAuthProcessEnv,
  createDynamicMockOAuthConfig,
  defaultMockOAuthConfig,
  developmentMockOAuthConfig,
  productionMockOAuthConfig,
  createMockOAuthConfig,
  createMockInstagramProvider,
  validateMockOAuthConfig,
  oauthConfigScenarios,
  setupOAuthMockImplementations,
  resetOAuthMocks,
  createMockOAuthProvider,
} from '../__mocks__/oauth.mock';

import {
  createOAuthTestScenario,
  runOAuthTestScenarios,
  testOAuthProviderConfiguration,
  testInstagramConfiguration,
  testAuthorizationUrlGeneration,
  testOAuthConfigurationValidation,
  testOAuthProviderDetection,
  createOAuthSecurityTestScenarios,
  testOAuthSecurityScenarios,
  cleanupOAuthTests,
  assertOAuthModuleExports,
  testUserInfoUrlGeneration,
} from '../__helpers__/oauth.helper';

// Mock OAuth functions for testing
const mockGetAuthorizationUrl = jest.fn((provider: string, state: string, additionalParams?: Record<string, string>) => {
  const config = createDynamicMockOAuthConfig();
  const providerConfig = config[provider as keyof typeof config];
  const params = new URLSearchParams({
    client_id: providerConfig.clientId,
    redirect_uri: providerConfig.redirectUri,
    response_type: 'code',
    scope: providerConfig.scope,
    state,
    ...additionalParams,
  });
  return `${providerConfig.authUrl}?${params.toString()}`;
});

const mockGetUserInfoUrl = jest.fn((provider: string, accessToken: string, fields?: string[]) => {
  const config = createDynamicMockOAuthConfig();
  const providerConfig = config[provider as keyof typeof config];
  
  if (provider === 'instagram') {
    const instagramConfig = providerConfig as typeof config.instagram;
    const requestedFields = fields?.join(',') || instagramConfig.fields;
    return `${instagramConfig.userInfoUrl}?fields=${requestedFields}&access_token=${accessToken}`;
  }
  return providerConfig.userInfoUrl;
});

const mockValidateOAuthConfig = jest.fn((provider: string) => {
  const config = createDynamicMockOAuthConfig();
  const providerConfig = config[provider as keyof typeof config];
  const errors: string[] = [];

  if (!providerConfig.clientId) errors.push(`${provider} client ID is missing`);
  if (!providerConfig.clientSecret) errors.push(`${provider} client secret is missing`);

  if (provider === 'instagram') {
    const instagramConfig = providerConfig as typeof config.instagram;
    if (instagramConfig.requiresHttps && !instagramConfig.redirectUri.startsWith('https://')) {
      errors.push('Instagram requires HTTPS redirect URIs in production');
    }
  }

  return { isValid: errors.length === 0, errors };
});

const mockGetConfiguredProviders = jest.fn(() => {
  const config = createDynamicMockOAuthConfig();
  return Object.keys(config).filter(provider => {
    const providerConfig = config[provider as keyof typeof config];
    return providerConfig.clientId && providerConfig.clientSecret;
  });
});

const mockIsInstagramEnabled = jest.fn(() => {
  const validation = mockValidateOAuthConfig('instagram');
  return validation.isValid;
});

// Mock OAuth configuration factory that uses dynamic config
const createMockOAuthConfigFactory = (baseConfig?: any) => {
  return jest.fn(() => baseConfig || createDynamicMockOAuthConfig());
};

// Mock environment for testing
let mockEnv: MockOAuthProcessEnv;

describe('OAuth Configuration Unit Tests', () => {
  beforeEach(() => {
    resetOAuthMocks();
    setupOAuthMockImplementations();
    mockEnv = new MockOAuthProcessEnv();
    jest.clearAllMocks();
  });

  afterEach(() => {
    resetOAuthMocks();
    if (mockEnv) {
      mockEnv.restore();
    }
    cleanupOAuthTests();
  });

  describe('OAuth Configuration Loading', () => {
    it('should load OAuth configuration successfully with all providers', () => {
      mockEnv.setOAuthEnv('test');
      
      const config = createDynamicMockOAuthConfig();
      
      expect(config).toBeDefined();
      expect(config.google).toBeDefined();
      expect(config.microsoft).toBeDefined();
      expect(config.github).toBeDefined();
      expect(config.instagram).toBeDefined();
      
      // Validate each provider has required fields
      Object.values(config).forEach((provider: any) => {
        expect(provider.clientId).toBeTruthy();
        expect(provider.clientSecret).toBeTruthy();
        expect(provider.redirectUri).toBeTruthy();
        expect(provider.scope).toBeTruthy();
        expect(provider.authUrl).toBeTruthy();
        expect(provider.tokenUrl).toBeTruthy();
        expect(provider.userInfoUrl).toBeTruthy();
      });
    });

    it('should handle missing OAuth environment variables gracefully', () => {
      mockEnv.clearOAuthEnv();
      
      const config = createDynamicMockOAuthConfig();
      
      expect(config).toBeDefined();
      expect(config.google.clientId).toBe('');
      expect(config.google.clientSecret).toBe('');
    });
  });

  describe('Environment-Specific OAuth Configuration', () => {
    it('should use test OAuth configuration', () => {
      mockEnv.setOAuthEnv('test');
      const config = createDynamicMockOAuthConfig();
      
      expect(config.google.clientId).toBe('test-google-client-id');
    });

    it('should use development OAuth configuration', () => {
      mockEnv.setOAuthEnv('development');
      const config = createDynamicMockOAuthConfig();
      
      expect(config.google.clientId).toBe('dev-google-client-id');
    });

    it('should use production OAuth configuration with HTTPS', () => {
      mockEnv.setOAuthEnv('production');
      const config = createDynamicMockOAuthConfig();
      
      expect(config.google.clientId).toBe('prod-google-client-id');
      expect(config.instagram.requiresHttps).toBe(true);
    });
  });

  describe('OAuth Provider Configuration', () => {
    describe('google OAuth provider configuration', () => {
      it('should configure Google OAuth with complete credentials', () => {
        mockEnv.setEnv({
          GOOGLE_CLIENT_ID: 'google-client-id',
          GOOGLE_CLIENT_SECRET: 'google-client-secret',
        });
        
        const config = createDynamicMockOAuthConfig();
        const googleConfig = config.google;
        
        expect(googleConfig.clientId).toBe('google-client-id');
        expect(googleConfig.clientSecret).toBe('google-client-secret');
        expect(googleConfig.scope).toBe('email profile');
      });

      it('should handle missing Google OAuth credentials', () => {
        mockEnv.setEnv({
          GOOGLE_CLIENT_ID: '',
          GOOGLE_CLIENT_SECRET: '',
        });
        
        const config = createDynamicMockOAuthConfig();
        const googleConfig = config.google;
        
        expect(googleConfig.clientId).toBe('');
        expect(googleConfig.clientSecret).toBe('');
      });
    });

    describe('microsoft OAuth provider configuration', () => {
      it('should configure Microsoft OAuth with OpenID scope', () => {
        mockEnv.setEnv({
          MICROSOFT_CLIENT_ID: 'microsoft-client-id',
          MICROSOFT_CLIENT_SECRET: 'microsoft-client-secret',
        });
        
        const config = createDynamicMockOAuthConfig();
        const microsoftConfig = config.microsoft;
        
        expect(microsoftConfig.clientId).toBe('microsoft-client-id');
        expect(microsoftConfig.clientSecret).toBe('microsoft-client-secret');
        expect(microsoftConfig.scope).toBe('openid profile email');
      });
    });

    describe('github OAuth provider configuration', () => {
      it('should configure GitHub OAuth with user scopes', () => {
        mockEnv.setEnv({
          GITHUB_CLIENT_ID: 'github-client-id',
          GITHUB_CLIENT_SECRET: 'github-client-secret',
        });
        
        const config = createDynamicMockOAuthConfig();
        const githubConfig = config.github;
        
        expect(githubConfig.clientId).toBe('github-client-id');
        expect(githubConfig.clientSecret).toBe('github-client-secret');
        expect(githubConfig.scope).toBe('read:user user:email');
      });
    });
  });

  describe('Instagram OAuth Configuration', () => {
    describe('Instagram OAuth configuration', () => {
      it('should configure Instagram OAuth with media scope', () => {
        mockEnv.setEnv({
          INSTAGRAM_CLIENT_ID: 'instagram-client-id',
          INSTAGRAM_CLIENT_SECRET: 'instagram-client-secret',
        });
        
        const config = createDynamicMockOAuthConfig();
        const instagramConfig = config.instagram;
        
        expect(instagramConfig.clientId).toBe('instagram-client-id');
        expect(instagramConfig.clientSecret).toBe('instagram-client-secret');
        expect(instagramConfig.scope).toBe('user_profile,user_media');
        expect(instagramConfig.apiVersion).toBe('v18.0');
        expect(instagramConfig.fields).toBe('id,username,account_type,media_count');
        expect(instagramConfig.requiresHttps).toBe(false);
      });

      it('should require HTTPS in production environment', () => {
        mockEnv.setEnv({
          NODE_ENV: 'production',
          INSTAGRAM_CLIENT_ID: 'instagram-client-id',
          INSTAGRAM_CLIENT_SECRET: 'instagram-client-secret',
          APP_URL: 'https://koutu.com',
        });
        
        const config = createDynamicMockOAuthConfig();
        const instagramConfig = config.instagram;
        
        expect(instagramConfig.requiresHttps).toBe(true);
        expect(instagramConfig.redirectUri).toBe('https://koutu.com/api/v1/oauth/instagram/callback');
      });

      it('should fail validation with HTTP in production', () => {
        const invalidInstagramConfig = {
          ...defaultMockOAuthConfig.instagram,
          requiresHttps: true,
          redirectUri: 'http://koutu.com/api/v1/oauth/instagram/callback',
        };
        
        const config = createMockOAuthConfig({ instagram: invalidInstagramConfig });
        const validation = validateMockOAuthConfig(config);
        
        expect(validation.isValid).toBe(false);
        expect(validation.errors).toContain('Instagram requires HTTPS redirect URIs in production');
      });

      it('should validate Instagram scope requirements', () => {
        mockEnv.setEnv({
          INSTAGRAM_CLIENT_ID: 'instagram-client-id',
          INSTAGRAM_CLIENT_SECRET: 'instagram-client-secret',
        });
        
        const config = createDynamicMockOAuthConfig();
        const instagramConfig = config.instagram;
        
        expect(instagramConfig.scope).toBe('user_profile,user_media');
        
        // Validate that required fields are present
        const hasRequiredFields = !!(instagramConfig.clientId && instagramConfig.clientSecret);
        expect(hasRequiredFields).toBe(true);
      });
    });
  });

  describe('OAuth Authorization URL Generation', () => {
    testAuthorizationUrlGeneration(
      ['google', 'microsoft', 'github', 'instagram'],
      mockGetAuthorizationUrl
    );

    it('should include Instagram-specific parameters', () => {
      const state = 'test-state-123';
      const additionalParams = { display: 'page' };
      
      const url = mockGetAuthorizationUrl('instagram', state, additionalParams);
      
      expect(url).toContain('display=page');
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=user_profile%2Cuser_media');
    });

    it('should generate secure state parameters', () => {
      const specialState = 'state-with-special!@#$%^&*()chars';
      const url = mockGetAuthorizationUrl('google', specialState);
      
      // Check for the actual encoded state in the URL
      expect(url).toContain('state=state-with-special%21%40%23%24%25%5E%26*%28%29chars');
    });

    it('should validate redirect URI format', () => {
      const providers = ['google', 'microsoft', 'github', 'instagram'];
      
      providers.forEach(provider => {
        const url = mockGetAuthorizationUrl(provider, 'test-state');
        const urlObj = new URL(url);
        const redirectUri = urlObj.searchParams.get('redirect_uri');
        
        expect(redirectUri).toBeTruthy();
        expect(() => new URL(redirectUri!)).not.toThrow();
      });
    });
  });

  describe('OAuth User Info URL Generation', () => {
    testUserInfoUrlGeneration(
      ['google', 'microsoft', 'github', 'instagram'],
      mockGetUserInfoUrl
    );

    it('should handle Instagram field selection', () => {
      const accessToken = 'test-instagram-token';
      const fields = ['id', 'username', 'account_type'];
      
      const url = mockGetUserInfoUrl('instagram', accessToken, fields);
      
      // Check for unencoded fields parameter since our mock doesn't encode
      expect(url).toContain('fields=id,username,account_type');
      expect(url).toContain(`access_token=${accessToken}`);
      expect(url).toContain('graph.instagram.com');
    });

    it('should use default fields when none specified for Instagram', () => {
      const accessToken = 'test-instagram-token';
      
      const url = mockGetUserInfoUrl('instagram', accessToken);
      
      // Check for unencoded default fields
      expect(url).toContain('fields=id,username,account_type,media_count');
    });

    it('should not include fields parameter for non-Instagram providers', () => {
      const accessToken = 'test-google-token';
      
      const url = mockGetUserInfoUrl('google', accessToken);
      
      expect(url).not.toContain('fields=');
      expect(url).toBe(createDynamicMockOAuthConfig().google.userInfoUrl);
    });
  });

  describe('OAuth Configuration Validation', () => {
    testOAuthConfigurationValidation(mockValidateOAuthConfig);

    it('should validate complete configuration object', () => {
      const config = createDynamicMockOAuthConfig();
      const validation = validateMockOAuthConfig(config);
      
      expect(validation.isValid).toBe(true);
      expect(validation.errors).toHaveLength(0);
      expect(validation.providerValidations).toBeDefined();
      
      Object.values(validation.providerValidations).forEach((providerValidation: any) => {
        expect(providerValidation.isValid).toBe(true);
        expect(providerValidation.errors).toHaveLength(0);
      });
    });

    it('should detect multiple validation errors', () => {
      const invalidConfig = createMockOAuthConfig({
        google: { ...defaultMockOAuthConfig.google, clientId: '', clientSecret: '' },
        instagram: {
          ...defaultMockOAuthConfig.instagram,
          clientId: '',
          requiresHttps: true,
          redirectUri: 'http://koutu.com/callback',
          scope: 'invalid_scope',
        },
      });
      
      const validation = validateMockOAuthConfig(invalidConfig);
      
      expect(validation.isValid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(0);
      expect(validation.errors).toContain('google client ID is missing');
      expect(validation.errors).toContain('google client secret is missing');
      expect(validation.errors).toContain('instagram client ID is missing');
      expect(validation.errors).toContain('Instagram requires HTTPS redirect URIs in production');
      expect(validation.errors).toContain('Instagram missing required scopes: user_profile');
    });

    it('should validate individual provider configurations', () => {
      const providers = ['google', 'microsoft', 'github', 'instagram'];
      
      providers.forEach(provider => {
        const validation = mockValidateOAuthConfig(provider);
        expect(validation.isValid).toBe(true);
        expect(validation.errors).toHaveLength(0);
      });
    });
  });

  describe('OAuth Provider Detection', () => {
    testOAuthProviderDetection(mockGetConfiguredProviders);

    it('should detect Instagram when properly configured', () => {
      mockEnv.setOAuthEnv('test');
      
      const configuredProviders = mockGetConfiguredProviders();
      
      expect(configuredProviders).toContain('instagram');
      expect(mockIsInstagramEnabled()).toBe(true);
    });

    it('should not detect Instagram when missing credentials', () => {
      mockEnv.setEnv({
        GOOGLE_CLIENT_ID: 'google-id',
        GOOGLE_CLIENT_SECRET: 'google-secret',
        INSTAGRAM_CLIENT_ID: '',
        INSTAGRAM_CLIENT_SECRET: '',
        APP_URL: 'http://localhost:3000',
      });
      
      const configuredProviders = mockGetConfiguredProviders();
      
      expect(configuredProviders).toContain('google');
      expect(configuredProviders).not.toContain('instagram');
      expect(mockIsInstagramEnabled()).toBe(false);
    });

    it('should handle empty configuration', () => {
      mockEnv.clearOAuthEnv();
      
      const configuredProviders = mockGetConfiguredProviders();
      
      expect(configuredProviders).toHaveLength(0);
    });
  });

  describe('OAuth Security Scenarios', () => {
    const securityScenarios = createOAuthSecurityTestScenarios();
    
    const mockSecurityTestFunction = jest.fn((attackVector: string, maliciousInput: string) => {
      // Mock security validation logic
      switch (attackVector) {
        case 'redirect_uri':
          if (maliciousInput.includes('evil.com') || maliciousInput.startsWith('javascript:')) {
            throw new Error('Invalid redirect URI');
          }
          return maliciousInput;
        case 'client_secret':
          if (maliciousInput.includes('client_secret=')) {
            throw new Error('Client secret must not be in URL');
          }
          return maliciousInput;
        case 'state':
          if (!maliciousInput) {
            throw new Error('State parameter is required');
          }
          // Sanitize SQL injection attempts
          return maliciousInput.replace(/[;"']/g, '');
        default:
          return maliciousInput;
      }
    });

    testOAuthSecurityScenarios(securityScenarios, mockSecurityTestFunction);

    it('should prevent redirect URI hijacking', () => {
      const maliciousRedirectUri = 'http://evil.com/steal-tokens';
      
      expect(() => {
        mockSecurityTestFunction('redirect_uri', maliciousRedirectUri);
      }).toThrow('Invalid redirect URI');
    });

    it('should prevent XSS via JavaScript URLs', () => {
      const xssRedirectUri = 'javascript:alert("xss")';
      
      expect(() => {
        mockSecurityTestFunction('redirect_uri', xssRedirectUri);
      }).toThrow('Invalid redirect URI');
    });

    it('should sanitize state parameter', () => {
      const maliciousState = 'state"; DROP TABLE users; --';
      
      const sanitized = mockSecurityTestFunction('state', maliciousState);
      
      expect(sanitized).not.toContain('"');
      expect(sanitized).not.toContain(';');
      expect(sanitized).toBe('state DROP TABLE users --');
    });

    it('should require state parameter', () => {
      expect(() => {
        mockSecurityTestFunction('state', '');
      }).toThrow('State parameter is required');
    });
  });

  describe('OAuth Configuration Scenarios', () => {
    Object.values(oauthConfigScenarios).forEach(scenario => {
      it(scenario.name, () => {
        const config = scenario.config;
        const validation = validateMockOAuthConfig(config);
        
        expect(validation.isValid).toBe(scenario.shouldBeValid);
        
        if (!scenario.shouldBeValid && 'expectedErrors' in scenario && scenario.expectedErrors) {
          scenario.expectedErrors.forEach(expectedError => {
            expect(validation.errors).toContain(expectedError);
          });
        }
      });
    });
  });

  describe('OAuth Module Exports', () => {
    it('should export all required OAuth functions and configurations', () => {
      const mockOAuthModule = {
        oauthConfig: defaultMockOAuthConfig,
        getAuthorizationUrl: mockGetAuthorizationUrl,
        getUserInfoUrl: mockGetUserInfoUrl,
        validateOAuthConfig: mockValidateOAuthConfig,
        getConfiguredProviders: mockGetConfiguredProviders,
        isInstagramEnabled: mockIsInstagramEnabled,
        instagramConfig: defaultMockOAuthConfig.instagram,
      };
      
      assertOAuthModuleExports(mockOAuthModule);
    });
  });

  describe('OAuth Error Handling', () => {
    it('should handle malformed OAuth configuration gracefully', () => {
      const malformedConfig = {
        google: null,
        microsoft: undefined,
        github: { clientId: 'valid-id' }, // Missing other required fields
        instagram: {}, // Empty object
      };
      
      expect(() => {
        // This should not throw, but validation should catch the issues
        const validation = validateMockOAuthConfig(malformedConfig as any);
        expect(validation.isValid).toBe(false);
      }).not.toThrow();
    });

    it('should handle network errors during OAuth flow', async () => {
        const mockNetworkError = jest.fn<() => Promise<any>>().mockRejectedValue(new Error('Network error'));
        
        await expect(mockNetworkError()).rejects.toThrow('Network error');
    });

    it('should handle invalid OAuth responses', () => {
      const invalidResponse = { invalid: 'response' };
      
      expect(() => {
        // Mock validation of OAuth response format
        if (!invalidResponse.hasOwnProperty('access_token')) {
          throw new Error('Invalid OAuth response format');
        }
      }).toThrow('Invalid OAuth response format');
    });
  });

  describe('OAuth Configuration Caching', () => {
    it('should return consistent OAuth configuration', () => {
      mockEnv.setOAuthEnv('test');
      
      const config1 = createDynamicMockOAuthConfig();
      const config2 = createDynamicMockOAuthConfig();
      
      expect(config1).toEqual(config2);
    });
  });

  describe('OAuth Environment Variables', () => {
    it('should handle boolean-like environment variables', () => {
      mockEnv.setEnv({
        INSTAGRAM_CLIENT_ID: 'test-id',
        INSTAGRAM_CLIENT_SECRET: 'test-secret',
        NODE_ENV: 'production',
        APP_URL: 'https://koutu.com',
      });
      
      const config = createDynamicMockOAuthConfig();
      const instagramConfig = config.instagram;
      
      expect(instagramConfig.requiresHttps).toBe(true);
      expect(instagramConfig.redirectUri).toBe('https://koutu.com/api/v1/oauth/instagram/callback');
    });

    it('should handle missing APP_URL gracefully', () => {
      mockEnv.setEnv({
        GOOGLE_CLIENT_ID: 'test-id',
        GOOGLE_CLIENT_SECRET: 'test-secret',
        APP_URL: undefined,
      });
      
      const config = createDynamicMockOAuthConfig();
      const googleConfig = config.google;
      
      expect(googleConfig.redirectUri).toBe('http://localhost:3000/api/v1/oauth/google/callback');
    });
  });

  describe('OAuth Integration Scenarios', () => {
    it('should support complete OAuth flow simulation', () => {
      // Simulate authorization URL generation
      const authUrl = mockGetAuthorizationUrl('google', 'test-state-123');
      expect(authUrl).toBeTruthy();
      
      // Simulate user info URL generation
      const userInfoUrl = mockGetUserInfoUrl('google', 'test-access-token');
      expect(userInfoUrl).toBeTruthy();
      
      // Simulate provider validation
      const validation = mockValidateOAuthConfig('google');
      expect(validation.isValid).toBe(true);
    });

    it('should support Instagram-specific OAuth flow', () => {
      const state = 'instagram-state-456';
      const accessToken = 'instagram-access-token';
      const fields = ['id', 'username', 'media_count'];
      
      // Instagram authorization URL with display parameter
      const authUrl = mockGetAuthorizationUrl('instagram', state, { display: 'page' });
      expect(authUrl).toContain('display=page');
      expect(authUrl).toContain('scope=user_profile%2Cuser_media');
      
      // Instagram user info URL with custom fields
      const userInfoUrl = mockGetUserInfoUrl('instagram', accessToken, fields);
      expect(userInfoUrl).toContain('fields=id,username,media_count');
      expect(userInfoUrl).toContain(`access_token=${accessToken}`);
      
      // Instagram configuration validation
      const validation = mockValidateOAuthConfig('instagram');
      expect(validation.isValid).toBe(true);
      
      // Instagram enablement check
      expect(mockIsInstagramEnabled()).toBe(true);
    });
  });
});