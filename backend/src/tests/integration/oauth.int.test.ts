// backend/src/__tests__/integration/oauth.int.test.ts
import { jest } from '@jest/globals';
import { beforeEach, afterEach, beforeAll, afterAll, describe, it, expect } from '@jest/globals';
import { promisify } from 'util';
import path from 'path';
import fs from 'fs';

// Import OAuth configuration and helpers
import {
  MockOAuthProcessEnv,
  defaultMockOAuthConfig,
  developmentMockOAuthConfig,
  productionMockOAuthConfig,
  mockOAuthEnvironmentVariables,
  mockOAuthUserResponses,
  mockOAuthTokenResponses,
  mockOAuthErrorResponses,
  createMockOAuthConfig,
  validateMockOAuthConfig,
} from '../__mocks__/oauth.mock';

import {
  createOAuthTestScenario,
  runOAuthTestScenarios,
  testOAuthEnvironmentSpecificConfigurations,
  testOAuthConfigurationCaching,
  testOAuthErrorHandling,
  setupOAuthTestEnvironment,
  cleanupOAuthTests,
  createMockOAuthHttpResponses,
} from '../__helpers__/oauth.helper';

// Test utilities
const writeFile = promisify(fs.writeFile);
const unlink = promisify(fs.unlink);

/**
 * Integration Test Environment Manager for OAuth
 */
class OAuthIntegrationTestEnvironment {
  private originalEnv: NodeJS.ProcessEnv;
  private tempFiles: string[] = [];

  constructor() {
    this.originalEnv = { ...process.env };
  }

  setEnvironment(env: Record<string, string | undefined>): void {
    // Clear existing OAuth environment
    this.clearOAuthEnvironment();

    // Set new environment
    Object.keys(env).forEach(key => {
      if (env[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = env[key];
      }
    });
  }

  clearOAuthEnvironment(): void {
    const oauthKeys = [
      'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET',
      'MICROSOFT_CLIENT_ID', 'MICROSOFT_CLIENT_SECRET',
      'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
      'INSTAGRAM_CLIENT_ID', 'INSTAGRAM_CLIENT_SECRET',
      'APP_URL', 'NODE_ENV'
    ];

    oauthKeys.forEach(key => {
      delete process.env[key];
    });
  }

  async createTempOAuthConfigFile(content: string): Promise<string> {
    const tempPath = path.join(__dirname, `oauth-test-${Date.now()}.env`);
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
    process.env = { ...this.originalEnv };
  }
}

/**
 * Mock OAuth Service for integration testing
 */
class MockOAuthService {
  private config: any;

  constructor(config: any) {
    this.config = config;
  }

  getAuthorizationUrl(provider: string, state: string, additionalParams?: Record<string, string>): string {
    const providerConfig = this.config[provider];
    if (!providerConfig) {
      throw new Error(`Unsupported OAuth provider: ${provider}`);
    }

    const params = new URLSearchParams({
      client_id: providerConfig.clientId,
      redirect_uri: providerConfig.redirectUri,
      response_type: 'code',
      scope: providerConfig.scope,
      state,
    });

    // Add Instagram-specific parameters
    if (provider === 'instagram' && additionalParams) {
      Object.entries(additionalParams).forEach(([key, value]) => {
        params.set(key, value);
      });
    }

    return `${providerConfig.authUrl}?${params.toString()}`;
  }

  async exchangeCodeForToken(provider: string, code: string): Promise<any> {
    const providerConfig = this.config[provider];
    if (!providerConfig) {
      throw new Error(`Unsupported OAuth provider: ${provider}`);
    }

    if (!code || code === 'invalid-code') {
      throw new Error('Invalid authorization code');
    }

    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 100));

    // FIXED: Return proper mock token responses with token_type for all providers
    const tokenResponses = {
      google: {
        access_token: 'google-access-token-123',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'google-refresh-token-123',
        scope: 'email profile'
      },
      microsoft: {
        access_token: 'microsoft-access-token-456',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'microsoft-refresh-token-456',
        scope: 'openid profile email'
      },
      github: {
        access_token: 'github-access-token-789',
        scope: 'read:user,user:email',
        token_type: 'bearer'
      },
      instagram: {
        access_token: 'instagram-access-token-101112',
        token_type: 'Bearer', // FIXED: Added token_type for Instagram
        user_id: 'instagram-user-101112'
      }
    };

    return tokenResponses[provider as keyof typeof tokenResponses];
  }

  async getUserInfo(provider: string, accessToken: string, fields?: string[]): Promise<any> {
    const providerConfig = this.config[provider];
    if (!providerConfig) {
      throw new Error(`Unsupported OAuth provider: ${provider}`);
    }

    if (!accessToken || accessToken === 'invalid-token') {
      throw new Error('Invalid access token');
    }

    // Simulate network delay
    await new Promise(resolve => setTimeout(resolve, 150));

    // Return proper mock user responses
    const userResponses = {
      google: {
        id: 'google-user-123',
        email: 'user@gmail.com',
        verified_email: true,
        name: 'Google User',
        given_name: 'Google',
        family_name: 'User',
        picture: 'https://example.com/picture.jpg',
        locale: 'en'
      },
      microsoft: {
        id: 'microsoft-user-456',
        userPrincipalName: 'user@outlook.com',
        displayName: 'Microsoft User',
        givenName: 'Microsoft',
        surname: 'User',
        mail: 'user@outlook.com'
      },
      github: {
        id: 789,
        login: 'githubuser',
        name: 'GitHub User',
        email: 'user@github.com',
        avatar_url: 'https://github.com/avatar.jpg',
        bio: 'Developer'
      },
      instagram: {
        id: 'instagram-user-101112',
        username: 'instagramuser',
        account_type: 'PERSONAL',
        media_count: 42
      }
    };

    return userResponses[provider as keyof typeof userResponses];
  }

  validateOAuthConfig(provider: string): { isValid: boolean; errors: string[] } {
    const providerConfig = this.config[provider];
    const errors: string[] = [];

    if (!providerConfig) {
      errors.push(`Provider ${provider} not configured`);
      return { isValid: false, errors };
    }

    if (!providerConfig.clientId) {
      errors.push(`${provider} client ID is missing`);
    }

    if (!providerConfig.clientSecret) {
      errors.push(`${provider} client secret is missing`);
    }

    // Instagram-specific validations
    if (provider === 'instagram') {
      if (providerConfig.requiresHttps && !providerConfig.redirectUri.startsWith('https://')) {
        errors.push('Instagram requires HTTPS redirect URIs in production');
      }

      const requiredScopes = ['user_profile'];
      const configuredScopes = providerConfig.scope.split(',').map((s: string) => s.trim());
      
      const missingScopes = requiredScopes.filter(scope => !configuredScopes.includes(scope));
      if (missingScopes.length > 0) {
        errors.push(`Instagram missing required scopes: ${missingScopes.join(', ')}`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  getConfiguredProviders(): string[] {
    return Object.keys(this.config).filter(provider => {
      const config = this.config[provider];
      return config.clientId && config.clientSecret;
    });
  }
}

/**
 * OAuth integration test scenarios
 */
const oauthIntegrationTestScenarios = {
  production: {
    name: 'Production OAuth Environment Integration',
    env: {
      NODE_ENV: 'production',
      APP_URL: 'https://koutu.com',
      GOOGLE_CLIENT_ID: 'prod-google-client-id-abc123',
      GOOGLE_CLIENT_SECRET: 'prod-google-client-secret-xyz789',
      MICROSOFT_CLIENT_ID: 'prod-microsoft-client-id-def456',
      MICROSOFT_CLIENT_SECRET: 'prod-microsoft-client-secret-uvw012',
      GITHUB_CLIENT_ID: 'prod-github-client-id-ghi789',
      GITHUB_CLIENT_SECRET: 'prod-github-client-secret-rst345',
      INSTAGRAM_CLIENT_ID: 'prod-instagram-client-id-jkl012',
      INSTAGRAM_CLIENT_SECRET: 'prod-instagram-client-secret-mno678',
    },
    expectedConfig: {
      appUrl: 'https://koutu.com',
      httpsRequired: true,
      allProvidersConfigured: true,
    },
  },
  development: {
    name: 'Development OAuth Environment Integration',
    env: {
      NODE_ENV: 'development',
      APP_URL: 'http://localhost:3001', // FIXED: Use different port for development
      GOOGLE_CLIENT_ID: 'dev-google-client-id',
      GOOGLE_CLIENT_SECRET: 'dev-google-client-secret',
      INSTAGRAM_CLIENT_ID: 'dev-instagram-client-id',
      INSTAGRAM_CLIENT_SECRET: 'dev-instagram-client-secret',
    },
    expectedConfig: {
      appUrl: 'http://localhost:3001',
      httpsRequired: false,
      partialConfiguration: true,
    },
  },
  test: {
    name: 'Test OAuth Environment Integration',
    env: {
      NODE_ENV: 'test',
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
    expectedConfig: {
      appUrl: 'http://localhost:3000',
      httpsRequired: false,
      allProvidersConfigured: true,
    },
  },
  minimal: {
    name: 'Minimal OAuth Configuration Integration',
    env: {
      NODE_ENV: 'development',
      GOOGLE_CLIENT_ID: 'minimal-google-client-id',
      GOOGLE_CLIENT_SECRET: 'minimal-google-client-secret',
    },
    expectedConfig: {
      appUrl: 'http://localhost:3000',
      httpsRequired: false,
      onlyGoogleConfigured: true,
    },
  },
};

// Test environment manager
let testEnv: OAuthIntegrationTestEnvironment;

describe('OAuth Configuration Integration Tests', () => {
  beforeAll(() => {
    testEnv = new OAuthIntegrationTestEnvironment();
  });

  afterAll(async () => {
    await testEnv.cleanupTempFiles();
    testEnv.restore();
  });

  beforeEach(() => {
    setupOAuthTestEnvironment();
  });

  afterEach(async () => {
    await testEnv.cleanupTempFiles();
    cleanupOAuthTests();
  });

  describe('Environment-Specific OAuth Configuration Loading', () => {
    Object.entries(oauthIntegrationTestScenarios).forEach(([scenarioName, scenario]) => {
      it(`should load ${scenario.name}`, () => {
        testEnv.setEnvironment(scenario.env);

        const mockOAuthConfig = {
          google: {
            clientId: process.env.GOOGLE_CLIENT_ID || '',
            clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
            redirectUri: `${process.env.APP_URL || 'http://localhost:3000'}/api/v1/oauth/google/callback`,
            scope: 'email profile',
            authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenUrl: 'https://oauth2.googleapis.com/token',
            userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
          },
          microsoft: {
            clientId: process.env.MICROSOFT_CLIENT_ID || '',
            clientSecret: process.env.MICROSOFT_CLIENT_SECRET || '',
            redirectUri: `${process.env.APP_URL || 'http://localhost:3000'}/api/v1/oauth/microsoft/callback`,
            scope: 'openid profile email',
            authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
            tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
            userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
          },
          github: {
            clientId: process.env.GITHUB_CLIENT_ID || '',
            clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
            redirectUri: `${process.env.APP_URL || 'http://localhost:3000'}/api/v1/oauth/github/callback`,
            scope: 'read:user user:email',
            authUrl: 'https://github.com/login/oauth/authorize',
            tokenUrl: 'https://github.com/login/oauth/access_token',
            userInfoUrl: 'https://api.github.com/user',
          },
          instagram: {
            clientId: process.env.INSTAGRAM_CLIENT_ID || '',
            clientSecret: process.env.INSTAGRAM_CLIENT_SECRET || '',
            redirectUri: `${process.env.APP_URL || 'http://localhost:3000'}/api/v1/oauth/instagram/callback`,
            scope: 'user_profile,user_media',
            authUrl: 'https://api.instagram.com/oauth/authorize',
            tokenUrl: 'https://api.instagram.com/oauth/access_token',
            userInfoUrl: 'https://graph.instagram.com/me',
            apiVersion: 'v18.0',
            fields: 'id,username,account_type,media_count',
            requiresHttps: process.env.NODE_ENV === 'production',
          },
        };

        // Verify all expected configuration values
        if (scenario.expectedConfig.appUrl) {
          expect(mockOAuthConfig.google.redirectUri).toContain(scenario.expectedConfig.appUrl);
          expect(mockOAuthConfig.instagram.redirectUri).toContain(scenario.expectedConfig.appUrl);
        }

        if (scenario.expectedConfig.httpsRequired !== undefined) {
          expect(mockOAuthConfig.instagram.requiresHttps).toBe(scenario.expectedConfig.httpsRequired);
        }

        if ('allProvidersConfigured' in scenario.expectedConfig && scenario.expectedConfig.allProvidersConfigured) {
          expect(mockOAuthConfig.google.clientId).toBeTruthy();
          expect(mockOAuthConfig.microsoft.clientId).toBeTruthy();
          expect(mockOAuthConfig.github.clientId).toBeTruthy();
          expect(mockOAuthConfig.instagram.clientId).toBeTruthy();
        }

        if ('onlyGoogleConfigured' in scenario.expectedConfig && scenario.expectedConfig.onlyGoogleConfigured) {
          expect(mockOAuthConfig.google.clientId).toBeTruthy();
          expect(mockOAuthConfig.microsoft.clientId).toBe('');
          expect(mockOAuthConfig.github.clientId).toBe('');
          expect(mockOAuthConfig.instagram.clientId).toBe('');
        }

        // Verify configuration is valid and complete
        expect(mockOAuthConfig).toHaveProperty('google');
        expect(mockOAuthConfig).toHaveProperty('microsoft');
        expect(mockOAuthConfig).toHaveProperty('github');
        expect(mockOAuthConfig).toHaveProperty('instagram');
      });
    });
  });

  describe('OAuth Service Integration', () => {
    it('should integrate OAuth service with complete configuration', () => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.test.env);

      const oauthConfig = createMockOAuthConfig({}, defaultMockOAuthConfig);
      const oauthService = new MockOAuthService(oauthConfig);

      // Test service initialization
      expect(oauthService).toBeDefined();

      // Test provider detection
      const configuredProviders = oauthService.getConfiguredProviders();
      expect(configuredProviders).toContain('google');
      expect(configuredProviders).toContain('microsoft');
      expect(configuredProviders).toContain('github');
      expect(configuredProviders).toContain('instagram');

      // Test configuration validation
      configuredProviders.forEach(provider => {
        const validation = oauthService.validateOAuthConfig(provider);
        expect(validation.isValid).toBe(true);
        expect(validation.errors).toHaveLength(0);
      });
    });

    it('should integrate OAuth service with partial configuration', () => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.minimal.env);

      const minimalConfig = createMockOAuthConfig({
        microsoft: { ...defaultMockOAuthConfig.microsoft, clientId: '', clientSecret: '' },
        github: { ...defaultMockOAuthConfig.github, clientId: '', clientSecret: '' },
        instagram: { ...defaultMockOAuthConfig.instagram, clientId: '', clientSecret: '' },
      });

      const oauthService = new MockOAuthService(minimalConfig);
      const configuredProviders = oauthService.getConfiguredProviders();

      expect(configuredProviders).toContain('google');
      expect(configuredProviders).not.toContain('microsoft');
      expect(configuredProviders).not.toContain('github');
      expect(configuredProviders).not.toContain('instagram');
    });
  });

  describe('OAuth Authorization Flow Integration', () => {
    let oauthService: MockOAuthService;

    beforeEach(() => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.test.env);
      const oauthConfig = createMockOAuthConfig({}, defaultMockOAuthConfig);
      oauthService = new MockOAuthService(oauthConfig);
    });

    it('should generate authorization URLs for all providers', () => {
      const providers = ['google', 'microsoft', 'github', 'instagram'];
      const state = 'integration-test-state-123';

      providers.forEach(provider => {
        const authUrl = oauthService.getAuthorizationUrl(provider, state);

        expect(authUrl).toBeTruthy();
        expect(authUrl).toContain('client_id=');
        expect(authUrl).toContain('redirect_uri=');
        expect(authUrl).toContain('response_type=code');
        expect(authUrl).toContain('scope=');
        expect(authUrl).toContain(`state=${state}`);

        // Validate URL format
        expect(() => new URL(authUrl)).not.toThrow();
      });
    });

    it('should generate Instagram authorization URL with display parameter', () => {
      const state = 'instagram-integration-test';
      const additionalParams = { display: 'page' };

      const authUrl = oauthService.getAuthorizationUrl('instagram', state, additionalParams);

      expect(authUrl).toContain('display=page');
      expect(authUrl).toContain('scope=user_profile%2Cuser_media');
      expect(authUrl).toContain('api.instagram.com');
    });

    it('should handle authorization URL generation errors', () => {
      const state = 'test-state';

      expect(() => {
        oauthService.getAuthorizationUrl('unsupported-provider', state);
      }).toThrow('Unsupported OAuth provider: unsupported-provider');
    });
  });

  describe('OAuth Token Exchange Integration', () => {
    let oauthService: MockOAuthService;

    beforeEach(() => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.test.env);
      const oauthConfig = createMockOAuthConfig({}, defaultMockOAuthConfig);
      oauthService = new MockOAuthService(oauthConfig);
    });

    it('should exchange authorization codes for tokens', async () => {
      const providers = ['google', 'microsoft', 'github', 'instagram'];

      for (const provider of providers) {
        const authCode = `valid-auth-code-${provider}`;
        const tokenResponse = await oauthService.exchangeCodeForToken(provider, authCode);

        expect(tokenResponse).toBeDefined();
        expect(tokenResponse.access_token).toBeTruthy();

        // Provider-specific token validations - FIXED: All providers now have token_type
        expect(tokenResponse.token_type).toBeTruthy();

        if (provider === 'instagram') {
          expect(tokenResponse.user_id).toBeTruthy();
        } else {
          expect(tokenResponse.expires_in || tokenResponse.scope).toBeTruthy();
        }
      }
    });

    it('should handle token exchange errors', async () => {
      const providers = ['google', 'microsoft', 'github', 'instagram'];

      for (const provider of providers) {
        await expect(
          oauthService.exchangeCodeForToken(provider, 'invalid-code')
        ).rejects.toThrow('Invalid authorization code');

        await expect(
          oauthService.exchangeCodeForToken(provider, '')
        ).rejects.toThrow('Invalid authorization code');
      }
    });

    it('should handle unsupported provider token exchange', async () => {
      await expect(
        oauthService.exchangeCodeForToken('unsupported-provider', 'valid-code')
      ).rejects.toThrow('Unsupported OAuth provider: unsupported-provider');
    });
  });

  describe('OAuth User Data Integration', () => {
    let oauthService: MockOAuthService;

    beforeEach(() => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.test.env);
      const oauthConfig = createMockOAuthConfig({}, defaultMockOAuthConfig);
      oauthService = new MockOAuthService(oauthConfig);
    });

    it('should fetch user data for all providers', async () => {
      const testCases = [
        {
          provider: 'google',
          accessToken: 'google-access-token-123',
          expectedFields: ['id', 'email', 'name', 'verified_email'],
        },
        {
          provider: 'microsoft',
          accessToken: 'microsoft-access-token-456',
          expectedFields: ['id', 'userPrincipalName', 'displayName'],
        },
        {
          provider: 'github',
          accessToken: 'github-access-token-789',
          expectedFields: ['id', 'login', 'name', 'email'],
        },
        {
          provider: 'instagram',
          accessToken: 'instagram-access-token-101112',
          expectedFields: ['id', 'username', 'account_type'],
        },
      ];

      for (const testCase of testCases) {
        const userData = await oauthService.getUserInfo(testCase.provider, testCase.accessToken);

        expect(userData).toBeDefined();
        expect(userData.id).toBeTruthy();

        testCase.expectedFields.forEach(field => {
          expect(userData).toHaveProperty(field);
        });
      }
    });

    it('should handle Instagram user data with custom fields', async () => {
      const accessToken = 'instagram-access-token-custom';
      const customFields = ['id', 'username', 'media_count'];

      const userData = await oauthService.getUserInfo('instagram', accessToken, customFields);

      expect(userData).toBeDefined();
      expect(userData.id).toBeTruthy();
      expect(userData.username).toBeTruthy();
      expect(userData.media_count).toBeDefined();
    });

    it('should handle user data fetch errors', async () => {
      const providers = ['google', 'microsoft', 'github', 'instagram'];

      for (const provider of providers) {
        await expect(
          oauthService.getUserInfo(provider, 'invalid-token')
        ).rejects.toThrow('Invalid access token');

        await expect(
          oauthService.getUserInfo(provider, '')
        ).rejects.toThrow('Invalid access token');
      }
    });
  });

  describe('OAuth Production Environment Integration', () => {
    it('should configure OAuth for production deployment', () => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.production.env);

      const productionConfig = createMockOAuthConfig({}, productionMockOAuthConfig);
      const oauthService = new MockOAuthService(productionConfig);

      // Validate production-specific configurations
      expect(productionConfig.instagram.requiresHttps).toBe(true);
      expect(productionConfig.google.redirectUri).toContain('https://koutu.com');
      expect(productionConfig.instagram.redirectUri).toContain('https://koutu.com');

      // Validate Instagram HTTPS requirement
      const instagramValidation = oauthService.validateOAuthConfig('instagram');
      expect(instagramValidation.isValid).toBe(true);

      // Validate all providers are configured
      const configuredProviders = oauthService.getConfiguredProviders();
      expect(configuredProviders).toHaveLength(4);
      expect(configuredProviders).toEqual(['google', 'microsoft', 'github', 'instagram']);
    });

    it('should detect Instagram HTTPS requirement violation in production', () => {
      testEnv.setEnvironment({
        ...oauthIntegrationTestScenarios.production.env,
        APP_URL: 'http://koutu.com', // HTTP instead of HTTPS
      });

      const productionConfigWithHttp = createMockOAuthConfig({
        instagram: {
          ...productionMockOAuthConfig.instagram,
          redirectUri: 'http://koutu.com/api/v1/oauth/instagram/callback',
          requiresHttps: true,
        },
      });

      const oauthService = new MockOAuthService(productionConfigWithHttp);
      const instagramValidation = oauthService.validateOAuthConfig('instagram');

      expect(instagramValidation.isValid).toBe(false);
      expect(instagramValidation.errors).toContain('Instagram requires HTTPS redirect URIs in production');
    });
  });

  describe('OAuth Configuration File Integration', () => {
    it('should load OAuth configuration from environment file', async () => {
      const envContent = `
NODE_ENV=test
APP_URL=http://localhost:3000
GOOGLE_CLIENT_ID=file-google-client-id
GOOGLE_CLIENT_SECRET=file-google-client-secret
INSTAGRAM_CLIENT_ID=file-instagram-client-id
INSTAGRAM_CLIENT_SECRET=file-instagram-client-secret
`.trim();

      const tempEnvFile = await testEnv.createTempOAuthConfigFile(envContent);

      // Simulate loading from .env file
      testEnv.setEnvironment({
        NODE_ENV: 'test',
        APP_URL: 'http://localhost:3000',
        GOOGLE_CLIENT_ID: 'file-google-client-id',
        GOOGLE_CLIENT_SECRET: 'file-google-client-secret',
        INSTAGRAM_CLIENT_ID: 'file-instagram-client-id',
        INSTAGRAM_CLIENT_SECRET: 'file-instagram-client-secret',
      });

      const fileConfig = createMockOAuthConfig({
        google: {
          ...defaultMockOAuthConfig.google,
          clientId: 'file-google-client-id',
          clientSecret: 'file-google-client-secret',
        },
        instagram: {
          ...defaultMockOAuthConfig.instagram,
          clientId: 'file-instagram-client-id',
          clientSecret: 'file-instagram-client-secret',
        },
        // FIXED: Ensure other providers have empty credentials for this test
        microsoft: { ...defaultMockOAuthConfig.microsoft, clientId: '', clientSecret: '' },
        github: { ...defaultMockOAuthConfig.github, clientId: '', clientSecret: '' },
      });

      expect(fileConfig.google.clientId).toBe('file-google-client-id');
      expect(fileConfig.instagram.clientId).toBe('file-instagram-client-id');

      const validation = validateMockOAuthConfig(fileConfig);
      expect(validation.isValid).toBe(false); // FIXED: Will be false due to missing microsoft/github creds
      expect(validation.errors).toContain('microsoft client ID is missing');
      expect(validation.errors).toContain('github client ID is missing');
    });
  });

  describe('OAuth Error Handling Integration', () => {
    it('should handle missing OAuth environment variables in production', () => {
      testEnv.setEnvironment({
        NODE_ENV: 'production',
        APP_URL: 'https://koutu.com',
        // Missing all OAuth credentials
      });

      const emptyConfig = createMockOAuthConfig({
        google: { ...defaultMockOAuthConfig.google, clientId: '', clientSecret: '' },
        microsoft: { ...defaultMockOAuthConfig.microsoft, clientId: '', clientSecret: '' },
        github: { ...defaultMockOAuthConfig.github, clientId: '', clientSecret: '' },
        instagram: { ...defaultMockOAuthConfig.instagram, clientId: '', clientSecret: '' },
      });

      const oauthService = new MockOAuthService(emptyConfig);
      const configuredProviders = oauthService.getConfiguredProviders();

      expect(configuredProviders).toHaveLength(0);

      // Should fail validation for all providers
      ['google', 'microsoft', 'github', 'instagram'].forEach(provider => {
        const validation = oauthService.validateOAuthConfig(provider);
        expect(validation.isValid).toBe(false);
        expect(validation.errors.length).toBeGreaterThan(0);
      });
    });

    it('should handle invalid OAuth environment variable formats', () => {
      testEnv.setEnvironment({
        NODE_ENV: 'test',
        APP_URL: 'not-a-valid-url',
        GOOGLE_CLIENT_ID: 'valid-google-id',
        GOOGLE_CLIENT_SECRET: 'valid-google-secret',
      });

      // Even with invalid APP_URL, OAuth service should handle gracefully
      const configWithInvalidUrl = createMockOAuthConfig({
        google: {
          ...defaultMockOAuthConfig.google,
          clientId: 'valid-google-id',
          clientSecret: 'valid-google-secret',
          redirectUri: 'not-a-valid-url/api/v1/oauth/google/callback',
        },
      });

      const oauthService = new MockOAuthService(configWithInvalidUrl);

      // Service should initialize without throwing
      expect(oauthService).toBeDefined();

      // Configuration should have correct client credentials
      const validation = oauthService.validateOAuthConfig('google');
      expect(validation.isValid).toBe(true); // Only checks client ID/secret, not redirect URI format
    });
  });

  describe('OAuth Cross-Environment Configuration Consistency', () => {
    it('should maintain OAuth configuration schema across all environments', () => {
      const environments = ['test', 'development', 'production'];
      const requiredOAuthKeys = [
        'clientId', 'clientSecret', 'redirectUri', 'scope',
        'authUrl', 'tokenUrl', 'userInfoUrl'
      ];
      const requiredProviders = ['google', 'microsoft', 'github', 'instagram'];

      environments.forEach(env => {
        const scenario = oauthIntegrationTestScenarios[env as keyof typeof oauthIntegrationTestScenarios];
        testEnv.setEnvironment(scenario.env);

        const envConfig = env === 'production' ? productionMockOAuthConfig :
                          env === 'development' ? developmentMockOAuthConfig :
                          defaultMockOAuthConfig;

        // Verify all required providers are present
        requiredProviders.forEach(provider => {
          expect(envConfig).toHaveProperty(provider);

          const providerConfig = envConfig[provider as keyof typeof envConfig];

          // Verify all required keys are present
          requiredOAuthKeys.forEach(key => {
            expect(providerConfig).toHaveProperty(key);
          });

          // Verify types are consistent
          expect(typeof providerConfig.clientId).toBe('string');
          expect(typeof providerConfig.clientSecret).toBe('string');
          expect(typeof providerConfig.redirectUri).toBe('string');
          expect(typeof providerConfig.scope).toBe('string');
          expect(typeof providerConfig.authUrl).toBe('string');
          expect(typeof providerConfig.tokenUrl).toBe('string');
          expect(typeof providerConfig.userInfoUrl).toBe('string');

          // Instagram-specific type checks
          if (provider === 'instagram') {
            const instagramConfig = providerConfig as typeof defaultMockOAuthConfig.instagram;
            expect(typeof instagramConfig.apiVersion).toBe('string');
            expect(typeof instagramConfig.fields).toBe('string');
            expect(typeof instagramConfig.requiresHttps).toBe('boolean');
          }
        });
      });
    });

    it('should maintain consistent OAuth default values across environments', () => {
      const defaultTestCases = [
        { key: 'scope', provider: 'google', defaultValue: 'email profile' },
        { key: 'scope', provider: 'microsoft', defaultValue: 'openid profile email' },
        { key: 'scope', provider: 'github', defaultValue: 'read:user user:email' },
        { key: 'scope', provider: 'instagram', defaultValue: 'user_profile,user_media' },
        { key: 'apiVersion', provider: 'instagram', defaultValue: 'v18.0' },
        { key: 'fields', provider: 'instagram', defaultValue: 'id,username,account_type,media_count' },
      ];

      defaultTestCases.forEach(testCase => {
        testEnv.setEnvironment({
          NODE_ENV: 'test',
          APP_URL: 'http://localhost:3000',
          // Don't set provider-specific environment variables
        });

        const config = defaultMockOAuthConfig[testCase.provider as keyof typeof defaultMockOAuthConfig];
        const configValue = (config as any)[testCase.key];

        expect(configValue).toBe(testCase.defaultValue);
      });
    });
  });

  describe('OAuth Performance and Memory Integration', () => {
    it('should handle large OAuth configuration sets efficiently', () => {
      const largeEnvSet: Record<string, string> = {
        NODE_ENV: 'test',
        APP_URL: 'http://localhost:3000',
      };

      // Add many OAuth providers and configurations
      for (let i = 0; i < 100; i++) {
        largeEnvSet[`CUSTOM_OAUTH_PROVIDER_${i}_CLIENT_ID`] = `client_id_${i}`;
        largeEnvSet[`CUSTOM_OAUTH_PROVIDER_${i}_CLIENT_SECRET`] = `client_secret_${i}`;
      }

      testEnv.setEnvironment(largeEnvSet);

      const startTime = process.hrtime.bigint();

      // Simulate OAuth configuration loading with many providers
      const extendedConfig = {
        ...defaultMockOAuthConfig,
        customProviders: Object.keys(process.env)
          .filter(key => key.startsWith('CUSTOM_OAUTH_PROVIDER_') && key.endsWith('_CLIENT_ID'))
          .reduce((acc, key) => {
            const providerName = key.replace('CUSTOM_OAUTH_PROVIDER_', '').replace('_CLIENT_ID', '');
            acc[providerName] = {
              clientId: process.env[key],
              clientSecret: process.env[`CUSTOM_OAUTH_PROVIDER_${providerName}_CLIENT_SECRET`],
            };
            return acc;
          }, {} as Record<string, any>),
      };

      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds

      expect(Object.keys(extendedConfig.customProviders)).toHaveLength(100);
      expect(duration).toBeLessThan(100); // Should complete in less than 100ms
    });

    it('should handle OAuth configuration object creation without memory leaks', () => {
      const initialMemory = process.memoryUsage();
      const configs: any[] = [];

      // Create many OAuth configuration objects
      for (let i = 0; i < 1000; i++) {
        testEnv.setEnvironment({
          NODE_ENV: 'test',
          APP_URL: `http://localhost:${3000 + i}`,
          GOOGLE_CLIENT_ID: `google-client-id-${i}`,
          GOOGLE_CLIENT_SECRET: `google-client-secret-${i}`,
        });

        configs.push(createMockOAuthConfig({
          google: {
            ...defaultMockOAuthConfig.google,
            clientId: `google-client-id-${i}`,
            clientSecret: `google-client-secret-${i}`,
          },
        }));
      }

      const finalMemory = process.memoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      expect(configs).toHaveLength(1000);
      expect(configs[999].google.clientId).toBe('google-client-id-999');
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB increase
    });
  });

  describe('OAuth Concurrent Access Integration', () => {
    it('should handle concurrent OAuth configuration access safely', async () => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.test.env);

      // Simulate concurrent OAuth operations
      const concurrentPromises = Array.from({ length: 10 }, (_, i) =>
        Promise.resolve().then(async () => {
          const oauthService = new MockOAuthService(defaultMockOAuthConfig);
          
          // Concurrent authorization URL generation
          const authUrl = oauthService.getAuthorizationUrl('google', `state-${i}`);
          
          // Concurrent token exchange simulation
          const tokenResponse = await oauthService.exchangeCodeForToken('google', `code-${i}`);
          
          // Concurrent user data fetch simulation
          const userData = await oauthService.getUserInfo('google', `token-${i}`);
          
          return {
            iteration: i,
            authUrl,
            tokenResponse,
            userData,
          };
        })
      );

      const results = await Promise.all(concurrentPromises);

      // All results should be consistent and complete
      results.forEach((result, index) => {
        expect(result.iteration).toBe(index);
        expect(result.authUrl).toContain(`state-${index}`);
        expect(result.tokenResponse.access_token).toBeTruthy();
        expect(result.userData.id).toBeTruthy();
      });
    });

    it('should handle concurrent OAuth provider validation', async () => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.test.env);
      const oauthService = new MockOAuthService(defaultMockOAuthConfig);

      const providers = ['google', 'microsoft', 'github', 'instagram'];
      
      // Concurrent validation of all providers
      const validationPromises = providers.map(provider =>
        Promise.resolve().then(() => {
          const validation = oauthService.validateOAuthConfig(provider);
          return { provider, validation };
        })
      );

      const validationResults = await Promise.all(validationPromises);

      validationResults.forEach(({ provider, validation }) => {
        expect(validation.isValid).toBe(true);
        expect(validation.errors).toHaveLength(0);
      });
    });
  });

  describe('OAuth Real-World Deployment Scenarios', () => {
    it('should handle Docker deployment OAuth configuration', () => {
      testEnv.setEnvironment({
        NODE_ENV: 'production',
        APP_URL: 'https://koutu-docker.com',
        GOOGLE_CLIENT_ID: 'docker-google-client-id',
        GOOGLE_CLIENT_SECRET: 'docker-google-client-secret',
        INSTAGRAM_CLIENT_ID: 'docker-instagram-client-id',
        INSTAGRAM_CLIENT_SECRET: 'docker-instagram-client-secret',
      });

      const dockerConfig = createMockOAuthConfig({
        google: {
          ...productionMockOAuthConfig.google,
          clientId: 'docker-google-client-id',
          clientSecret: 'docker-google-client-secret',
          redirectUri: 'https://koutu-docker.com/api/v1/oauth/google/callback',
        },
        instagram: {
          ...productionMockOAuthConfig.instagram,
          clientId: 'docker-instagram-client-id',
          clientSecret: 'docker-instagram-client-secret',
          redirectUri: 'https://koutu-docker.com/api/v1/oauth/instagram/callback',
          requiresHttps: true,
        },
      });

      const oauthService = new MockOAuthService(dockerConfig);

      expect(dockerConfig.google.redirectUri).toBe('https://koutu-docker.com/api/v1/oauth/google/callback');
      expect(dockerConfig.instagram.requiresHttps).toBe(true);
      
      const configuredProviders = oauthService.getConfiguredProviders();
      expect(configuredProviders).toContain('google');
      expect(configuredProviders).toContain('instagram');

      // Validate production security requirements
      const instagramValidation = oauthService.validateOAuthConfig('instagram');
      expect(instagramValidation.isValid).toBe(true);
    });

    it('should handle CI/CD pipeline OAuth configuration', () => {
      testEnv.setEnvironment({
        NODE_ENV: 'test',
        APP_URL: 'http://ci-test:3000',
        GOOGLE_CLIENT_ID: 'ci-google-client-id',
        GOOGLE_CLIENT_SECRET: 'ci-google-client-secret',
      });

      const ciConfig = createMockOAuthConfig({
        google: {
          ...defaultMockOAuthConfig.google,
          clientId: 'ci-google-client-id',
          clientSecret: 'ci-google-client-secret',
          redirectUri: 'http://ci-test:3000/api/v1/oauth/google/callback',
        },
        // Other providers empty for CI
        microsoft: { ...defaultMockOAuthConfig.microsoft, clientId: '', clientSecret: '' },
        github: { ...defaultMockOAuthConfig.github, clientId: '', clientSecret: '' },
        instagram: { ...defaultMockOAuthConfig.instagram, clientId: '', clientSecret: '' },
      });

      const oauthService = new MockOAuthService(ciConfig);
      const configuredProviders = oauthService.getConfiguredProviders();

      expect(configuredProviders).toHaveLength(1);
      expect(configuredProviders).toContain('google');
      expect(ciConfig.google.redirectUri).toBe('http://ci-test:3000/api/v1/oauth/google/callback');
    });

    it('should handle local development with hot reload OAuth configuration', () => {
      testEnv.setEnvironment({
        NODE_ENV: 'development',
        APP_URL: 'http://localhost:3001',
        GOOGLE_CLIENT_ID: 'local-dev-google-client-id',
        GOOGLE_CLIENT_SECRET: 'local-dev-google-client-secret',
        INSTAGRAM_CLIENT_ID: 'local-dev-instagram-client-id',
        INSTAGRAM_CLIENT_SECRET: 'local-dev-instagram-client-secret',
      });

      const devConfig = createMockOAuthConfig({}, developmentMockOAuthConfig);
      const oauthService = new MockOAuthService(devConfig);

      expect(devConfig.google.redirectUri).toContain('localhost:3001');
      expect(devConfig.instagram.requiresHttps).toBe(false);
      
      // Test hot reload simulation - configuration should be consistent
      const configSnapshot1 = JSON.stringify(devConfig);
      const configSnapshot2 = JSON.stringify(createMockOAuthConfig({}, developmentMockOAuthConfig));
      
      expect(configSnapshot1).toBe(configSnapshot2);
    });
  });

  describe('OAuth Security Integration', () => {
    it('should integrate OAuth with security validation', () => {
      testEnv.setEnvironment(oauthIntegrationTestScenarios.production.env);
      const oauthService = new MockOAuthService(productionMockOAuthConfig);

      // Test secure redirect URI validation
      const secureState = 'cryptographically-secure-state-' + Math.random().toString(36);
      const authUrl = oauthService.getAuthorizationUrl('google', secureState);
      
      expect(authUrl).toContain(encodeURIComponent(secureState));
      expect(authUrl).toContain('https://accounts.google.com');

      // Test Instagram HTTPS enforcement
      const instagramValidation = oauthService.validateOAuthConfig('instagram');
      expect(instagramValidation.isValid).toBe(true);
      
      // Verify all redirect URIs use HTTPS in production
      Object.values(productionMockOAuthConfig).forEach((provider: any) => {
        expect(provider.redirectUri).toMatch(/^https:\/\//);
      });
    });

    it('should handle OAuth configuration security compliance', () => {
      testEnv.setEnvironment({
        NODE_ENV: 'production',
        APP_URL: 'https://koutu.com',
        GOOGLE_CLIENT_ID: 'compliance-google-client-id-with-long-secure-identifier',
        GOOGLE_CLIENT_SECRET: 'compliance-google-client-secret-with-256-bit-entropy',
        INSTAGRAM_CLIENT_ID: 'compliance-instagram-client-id-secure',
        INSTAGRAM_CLIENT_SECRET: 'compliance-instagram-client-secret-secure',
      });

      const complianceConfig = createMockOAuthConfig({
        google: {
          ...productionMockOAuthConfig.google,
          clientId: 'compliance-google-client-id-with-long-secure-identifier',
          clientSecret: 'compliance-google-client-secret-with-256-bit-entropy',
        },
        instagram: {
          ...productionMockOAuthConfig.instagram,
          clientId: 'compliance-instagram-client-id-secure',
          clientSecret: 'compliance-instagram-client-secret-secure',
          requiresHttps: true,
        },
      });

      const oauthService = new MockOAuthService(complianceConfig);

      // Validate compliance requirements
      expect(complianceConfig.google.clientSecret.length).toBeGreaterThan(32);
      expect(complianceConfig.instagram.requiresHttps).toBe(true);
      
      const configuredProviders = oauthService.getConfiguredProviders();
      expect(configuredProviders).toContain('google');
      expect(configuredProviders).toContain('instagram');

      // Validate all providers meet security requirements
      configuredProviders.forEach(provider => {
        const validation = oauthService.validateOAuthConfig(provider);
        expect(validation.isValid).toBe(true);
        expect(validation.errors).toHaveLength(0);
      });
    });
  });

  describe('OAuth Configuration Monitoring and Alerting Integration', () => {
    it('should detect OAuth configuration changes', () => {
      // Initial secure configuration
      testEnv.setEnvironment(oauthIntegrationTestScenarios.production.env);
      const initialConfig = createMockOAuthConfig({}, productionMockOAuthConfig);
      const initialValidation = validateMockOAuthConfig(initialConfig);
      
      expect(initialValidation.isValid).toBe(true);

      // Simulate configuration change with security degradation
      testEnv.setEnvironment({
        NODE_ENV: 'production',
        APP_URL: 'http://koutu.com', // Changed from HTTPS to HTTP
        INSTAGRAM_CLIENT_ID: 'changed-instagram-client-id',
        INSTAGRAM_CLIENT_SECRET: 'weak-secret', // Weakened secret
      });

      const changedConfig = createMockOAuthConfig({
        instagram: {
          ...productionMockOAuthConfig.instagram,
          clientId: 'changed-instagram-client-id',
          clientSecret: 'weak-secret',
          redirectUri: 'http://koutu.com/api/v1/oauth/instagram/callback',
          requiresHttps: true, // Still requires HTTPS but URI is HTTP
        },
      });

      const changedValidation = validateMockOAuthConfig(changedConfig);
      
      // Should detect security issue
      expect(changedValidation.isValid).toBe(false);
      expect(changedValidation.errors).toContain('Instagram requires HTTPS redirect URIs in production');
    });

    it('should track OAuth configuration security metrics', () => {
      const configurations = [
        {
          name: 'Secure Production OAuth',
          env: oauthIntegrationTestScenarios.production.env,
          config: productionMockOAuthConfig,
        },
        {
          name: 'Insecure Production OAuth',
          env: {
            ...oauthIntegrationTestScenarios.production.env,
            APP_URL: 'http://koutu.com',
          },
          config: createMockOAuthConfig({
            instagram: {
              ...productionMockOAuthConfig.instagram,
              redirectUri: 'http://koutu.com/api/v1/oauth/instagram/callback',
              requiresHttps: true,
            },
          }),
        },
        {
          name: 'Development OAuth',
          env: oauthIntegrationTestScenarios.development.env,
          config: developmentMockOAuthConfig,
        },
      ];

      const securityMetrics = configurations.map(config => {
        testEnv.setEnvironment(config.env);
        const oauthService = new MockOAuthService(config.config);
        const validation = validateMockOAuthConfig(config.config);

        const configuredProviders = oauthService.getConfiguredProviders();
        const providerValidations = configuredProviders.map(provider => 
          oauthService.validateOAuthConfig(provider)
        );

        return {
          name: config.name,
          environment: config.env.NODE_ENV,
          isSecure: validation.isValid,
          totalErrors: validation.errors.length,
          configuredProviders: configuredProviders.length,
          secureProviders: providerValidations.filter(v => v.isValid).length,
          overallSecurityScore: validation.isValid ? 100 : 
            Math.max(0, 100 - (validation.errors.length * 25)),
        };
      });

      // Verify security metrics
      expect(securityMetrics[0].isSecure).toBe(true); // Secure Production
      expect(securityMetrics[1].isSecure).toBe(false); // Insecure Production
      expect(securityMetrics[1].totalErrors).toBeGreaterThan(0);
      expect(securityMetrics[0].overallSecurityScore).toBe(100);
      expect(securityMetrics[1].overallSecurityScore).toBeLessThan(100);
    });
  });
});