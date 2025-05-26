// backend/src/__tests__/__mocks__/oauth.mock.ts
import { jest } from '@jest/globals';

/**
 * Mock OAuth configuration interface
 */
export interface MockOAuthConfig {
  google: MockOAuthProvider;
  microsoft: MockOAuthProvider;
  github: MockOAuthProvider;
  instagram: MockInstagramProvider;
}

/**
 * Standard OAuth provider mock interface
 */
export interface MockOAuthProvider {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
  authUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
}

/**
 * Instagram-specific OAuth provider mock interface
 */
export interface MockInstagramProvider extends MockOAuthProvider {
  apiVersion: string;
  fields: string;
  requiresHttps: boolean;
}

/**
 * Default mock OAuth configuration
 */
export const defaultMockOAuthConfig: MockOAuthConfig = {
  google: {
    clientId: 'test-google-client-id',
    clientSecret: 'test-google-client-secret',
    redirectUri: 'http://localhost:3000/api/v1/oauth/google/callback',
    scope: 'email profile',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
  },
  microsoft: {
    clientId: 'test-microsoft-client-id',
    clientSecret: 'test-microsoft-client-secret',
    redirectUri: 'http://localhost:3000/api/v1/oauth/microsoft/callback',
    scope: 'openid profile email',
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
  },
  github: {
    clientId: 'test-github-client-id',
    clientSecret: 'test-github-client-secret',
    redirectUri: 'http://localhost:3000/api/v1/oauth/github/callback',
    scope: 'read:user user:email',
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
  },
  instagram: {
    clientId: 'test-instagram-client-id',
    clientSecret: 'test-instagram-client-secret',
    redirectUri: 'http://localhost:3000/api/v1/oauth/instagram/callback',
    scope: 'user_profile,user_media',
    authUrl: 'https://api.instagram.com/oauth/authorize',
    tokenUrl: 'https://api.instagram.com/oauth/access_token',
    userInfoUrl: 'https://graph.instagram.com/me',
    apiVersion: 'v18.0',
    fields: 'id,username,account_type,media_count',
    requiresHttps: false,
  },
};

/**
 * Production mock OAuth configuration (with HTTPS)
 */
export const productionMockOAuthConfig: MockOAuthConfig = {
  ...defaultMockOAuthConfig,
  google: {
    ...defaultMockOAuthConfig.google,
    clientId: 'prod-google-client-id',
    clientSecret: 'prod-google-client-secret',
    redirectUri: 'https://koutu.com/api/v1/oauth/google/callback',
  },
  microsoft: {
    ...defaultMockOAuthConfig.microsoft,
    clientId: 'prod-microsoft-client-id',
    clientSecret: 'prod-microsoft-client-secret',
    redirectUri: 'https://koutu.com/api/v1/oauth/microsoft/callback',
  },
  github: {
    ...defaultMockOAuthConfig.github,
    clientId: 'prod-github-client-id',
    clientSecret: 'prod-github-client-secret',
    redirectUri: 'https://koutu.com/api/v1/oauth/github/callback',
  },
  instagram: {
    ...defaultMockOAuthConfig.instagram,
    clientId: 'prod-instagram-client-id',
    clientSecret: 'prod-instagram-client-secret',
    redirectUri: 'https://koutu.com/api/v1/oauth/instagram/callback',
    requiresHttps: true,
  },
};

/**
 * Development mock OAuth configuration
 */
export const developmentMockOAuthConfig: MockOAuthConfig = {
  ...defaultMockOAuthConfig,
  google: {
    ...defaultMockOAuthConfig.google,
    clientId: 'dev-google-client-id',
    clientSecret: 'dev-google-client-secret',
    redirectUri: 'http://localhost:3001/api/v1/oauth/google/callback',
  },
  microsoft: {
    ...defaultMockOAuthConfig.microsoft,
    clientId: 'dev-microsoft-client-id',
    clientSecret: 'dev-microsoft-client-secret',
    redirectUri: 'http://localhost:3001/api/v1/oauth/microsoft/callback',
  },
  github: {
    ...defaultMockOAuthConfig.github,
    clientId: 'dev-github-client-id',
    clientSecret: 'dev-github-client-secret',
    redirectUri: 'http://localhost:3001/api/v1/oauth/github/callback',
  },
  instagram: {
    ...defaultMockOAuthConfig.instagram,
    clientId: 'dev-instagram-client-id',
    clientSecret: 'dev-instagram-client-secret',
    redirectUri: 'http://localhost:3001/api/v1/oauth/instagram/callback',
  },
};

/**
 * Mock OAuth environment variables for different environments
 */
export const mockOAuthEnvironmentVariables = {
  test: {
    GOOGLE_CLIENT_ID: 'test-google-client-id',
    GOOGLE_CLIENT_SECRET: 'test-google-client-secret',
    MICROSOFT_CLIENT_ID: 'test-microsoft-client-id',
    MICROSOFT_CLIENT_SECRET: 'test-microsoft-client-secret',
    GITHUB_CLIENT_ID: 'test-github-client-id',
    GITHUB_CLIENT_SECRET: 'test-github-client-secret',
    INSTAGRAM_CLIENT_ID: 'test-instagram-client-id',
    INSTAGRAM_CLIENT_SECRET: 'test-instagram-client-secret',
    APP_URL: 'http://localhost:3000',
  },
  development: {
    GOOGLE_CLIENT_ID: 'dev-google-client-id',
    GOOGLE_CLIENT_SECRET: 'dev-google-client-secret',
    MICROSOFT_CLIENT_ID: 'dev-microsoft-client-id',
    MICROSOFT_CLIENT_SECRET: 'dev-microsoft-client-secret',
    GITHUB_CLIENT_ID: 'dev-github-client-id',
    GITHUB_CLIENT_SECRET: 'dev-github-client-secret',
    INSTAGRAM_CLIENT_ID: 'dev-instagram-client-id',
    INSTAGRAM_CLIENT_SECRET: 'dev-instagram-client-secret',
    APP_URL: 'http://localhost:3001',
  },
  production: {
    GOOGLE_CLIENT_ID: 'prod-google-client-id',
    GOOGLE_CLIENT_SECRET: 'prod-google-client-secret',
    MICROSOFT_CLIENT_ID: 'prod-microsoft-client-id',
    MICROSOFT_CLIENT_SECRET: 'prod-microsoft-client-secret',
    GITHUB_CLIENT_ID: 'prod-github-client-id',
    GITHUB_CLIENT_SECRET: 'prod-github-client-secret',
    INSTAGRAM_CLIENT_ID: 'prod-instagram-client-id',
    INSTAGRAM_CLIENT_SECRET: 'prod-instagram-client-secret',
    APP_URL: 'https://koutu.com',
  },
};

/**
 * OAuth configuration test scenarios
 */
export const oauthConfigScenarios = {
  completeConfiguration: {
    name: 'Complete OAuth configuration',
    config: defaultMockOAuthConfig,
    shouldBeValid: true,
  },
  missingGoogleCredentials: {
    name: 'Missing Google OAuth credentials',
    config: {
      ...defaultMockOAuthConfig,
      google: {
        ...defaultMockOAuthConfig.google,
        clientId: '',
        clientSecret: '',
      },
    },
    shouldBeValid: false,
    expectedErrors: ['google client ID is missing', 'google client secret is missing'],
  },
  missingInstagramCredentials: {
    name: 'Missing Instagram OAuth credentials',
    config: {
      ...defaultMockOAuthConfig,
      instagram: {
        ...defaultMockOAuthConfig.instagram,
        clientId: '',
        clientSecret: '',
      },
    },
    shouldBeValid: false,
    expectedErrors: ['instagram client ID is missing', 'instagram client secret is missing'],
  },
  invalidInstagramHttps: {
    name: 'Instagram with HTTP redirect in production',
    config: {
      ...defaultMockOAuthConfig,
      instagram: {
        ...defaultMockOAuthConfig.instagram,
        requiresHttps: true,
        redirectUri: 'http://koutu.com/api/v1/oauth/instagram/callback',
      },
    },
    shouldBeValid: false,
    expectedErrors: ['Instagram requires HTTPS redirect URIs in production'],
  },
  invalidInstagramScope: {
    name: 'Instagram with invalid scope',
    config: {
      ...defaultMockOAuthConfig,
      instagram: {
        ...defaultMockOAuthConfig.instagram,
        scope: 'invalid_scope',
      },
    },
    shouldBeValid: false,
    expectedErrors: ['Instagram missing required scopes: user_profile'],
  },
  partialConfiguration: {
    name: 'Partial OAuth configuration (only Google)',
    config: {
      ...defaultMockOAuthConfig,
      microsoft: {
        ...defaultMockOAuthConfig.microsoft,
        clientId: '',
        clientSecret: '',
      },
      github: {
        ...defaultMockOAuthConfig.github,
        clientId: '',
        clientSecret: '',
      },
      instagram: {
        ...defaultMockOAuthConfig.instagram,
        clientId: '',
        clientSecret: '',
      },
    },
    shouldBeValid: true, // Only Google is configured, which is valid
  },
  emptyConfiguration: {
    name: 'Empty OAuth configuration',
    config: {
      google: { ...defaultMockOAuthConfig.google, clientId: '', clientSecret: '' },
      microsoft: { ...defaultMockOAuthConfig.microsoft, clientId: '', clientSecret: '' },
      github: { ...defaultMockOAuthConfig.github, clientId: '', clientSecret: '' },
      instagram: { ...defaultMockOAuthConfig.instagram, clientId: '', clientSecret: '' },
    },
    shouldBeValid: false,
    expectedErrors: [
      'google client ID is missing',
      'google client secret is missing',
      'microsoft client ID is missing',
      'microsoft client secret is missing',
      'github client ID is missing',
      'github client secret is missing',
      'instagram client ID is missing',
      'instagram client secret is missing',
    ],
  },
} as const;

/**
 * Mock OAuth provider user data responses
 */
export const mockOAuthUserResponses = {
  google: {
    id: 'google-user-123',
    email: 'user@gmail.com',
    name: 'John Doe',
    picture: 'https://lh3.googleusercontent.com/a/default-user',
    verified_email: true,
  },
  microsoft: {
    id: 'microsoft-user-456',
    userPrincipalName: 'user@outlook.com',
    displayName: 'Jane Smith',
    givenName: 'Jane',
    surname: 'Smith',
    mail: 'user@outlook.com',
  },
  github: {
    id: 789,
    login: 'github-user',
    name: 'GitHub User',
    email: 'user@github.com',
    avatar_url: 'https://avatars.githubusercontent.com/u/789',
    html_url: 'https://github.com/github-user',
  },
  instagram: {
    id: 'instagram-user-101112',
    username: 'instagram_user',
    account_type: 'PERSONAL',
    media_count: 42,
  },
};

/**
 * Mock OAuth token responses
 */
export const mockOAuthTokenResponses = {
  google: {
    access_token: 'google-access-token-123',
    refresh_token: 'google-refresh-token-123',
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'email profile',
  },
  microsoft: {
    access_token: 'microsoft-access-token-456',
    refresh_token: 'microsoft-refresh-token-456',
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'openid profile email',
  },
  github: {
    access_token: 'github-access-token-789',
    token_type: 'bearer',
    scope: 'read:user,user:email',
  },
  instagram: {
    access_token: 'instagram-access-token-101112',
    user_id: 'instagram-user-101112',
  },
};

/**
 * Mock OAuth error responses
 */
export const mockOAuthErrorResponses = {
  invalidRequest: {
    error: 'invalid_request',
    error_description: 'The request is missing a required parameter',
  },
  unauthorizedClient: {
    error: 'unauthorized_client',
    error_description: 'The client is not authorized to request a token using this method',
  },
  accessDenied: {
    error: 'access_denied',
    error_description: 'The resource owner or authorization server denied the request',
  },
  invalidGrant: {
    error: 'invalid_grant',
    error_description: 'The provided authorization grant is invalid',
  },
  unsupportedGrantType: {
    error: 'unsupported_grant_type',
    error_description: 'The authorization grant type is not supported',
  },
};

/**
 * Security test scenarios for OAuth
 */
export const oauthSecurityScenarios = {
  maliciousRedirectUri: {
    name: 'Malicious redirect URI injection',
    redirectUri: 'http://evil.com/callback',
    shouldBeBlocked: true,
  },
  javascriptInjection: {
    name: 'JavaScript injection in redirect URI',
    redirectUri: 'javascript:alert("xss")',
    shouldBeBlocked: true,
  },
  dataUriInjection: {
    name: 'Data URI injection',
    redirectUri: 'data:text/html,<script>alert("xss")</script>',
    shouldBeBlocked: true,
  },
  pathTraversal: {
    name: 'Path traversal in redirect URI',
    redirectUri: 'http://localhost:3000/../../../evil',
    shouldBeBlocked: true,
  },
  weakClientSecret: {
    name: 'Weak client secret',
    clientSecret: '123456',
    shouldBeBlocked: true,
  },
  exposedClientSecret: {
    name: 'Client secret in URL',
    authUrl: 'https://example.com/oauth?client_secret=exposed-secret',
    shouldBeBlocked: true,
  },
  stateFixation: {
    name: 'Missing or predictable state parameter',
    state: 'predictable-state-123',
    shouldBeBlocked: true,
  },
  csrfAttack: {
    name: 'CSRF attack via missing state validation',
    state: '',
    shouldBeBlocked: true,
  },
};

/**
 * Mock process environment for OAuth testing
 */
export class MockOAuthProcessEnv {
  private originalEnv: NodeJS.ProcessEnv;
  private currentEnv: Record<string, string | undefined>;

  constructor() {
    this.originalEnv = { ...process.env };
    this.currentEnv = {};
  }

  setOAuthEnv(environment: keyof typeof mockOAuthEnvironmentVariables): void {
    const envVars = mockOAuthEnvironmentVariables[environment];
    this.setEnv(envVars);
  }

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

  clearOAuthEnv(): void {
    const oauthKeys = [
      'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET',
      'MICROSOFT_CLIENT_ID', 'MICROSOFT_CLIENT_SECRET',
      'GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
      'INSTAGRAM_CLIENT_ID', 'INSTAGRAM_CLIENT_SECRET',
      'APP_URL'
    ];

    oauthKeys.forEach(key => {
      delete process.env[key];
      delete this.currentEnv[key];
    });
  }

  restore(): void {
    Object.keys(this.currentEnv).forEach(key => {
      delete process.env[key];
    });

    Object.keys(this.originalEnv).forEach(key => {
      const value = this.originalEnv[key];
      if (value !== undefined) {
        process.env[key] = value;
      }
    });

    this.currentEnv = {};
  }

  getCurrentEnv(): Record<string, string | undefined> {
    return { ...this.currentEnv };
  }
}

/**
 * Factory functions for creating mock configurations
 */
export const createMockOAuthConfig = (
  overrides: Partial<MockOAuthConfig> = {},
  baseConfig: MockOAuthConfig = defaultMockOAuthConfig
): MockOAuthConfig => {
  return {
    google: { ...baseConfig.google, ...overrides.google },
    microsoft: { ...baseConfig.microsoft, ...overrides.microsoft },
    github: { ...baseConfig.github, ...overrides.github },
    instagram: { ...baseConfig.instagram, ...overrides.instagram },
  };
};

export const createMockOAuthProvider = (
  providerName: string,
  overrides: Partial<MockOAuthProvider> = {}
): MockOAuthProvider => {
  return {
    clientId: `test-${providerName}-client-id`,
    clientSecret: `test-${providerName}-client-secret`,
    redirectUri: `http://localhost:3000/api/v1/oauth/${providerName}/callback`,
    scope: 'email profile',
    authUrl: `https://${providerName}.com/oauth/authorize`,
    tokenUrl: `https://${providerName}.com/oauth/token`,
    userInfoUrl: `https://api.${providerName}.com/user`,
    ...overrides,
  };
};

export const createMockInstagramProvider = (
  overrides: Partial<MockInstagramProvider> = {}
): MockInstagramProvider => {
  return {
    ...createMockOAuthProvider('instagram', {
      scope: 'user_profile,user_media',
      authUrl: 'https://api.instagram.com/oauth/authorize',
      tokenUrl: 'https://api.instagram.com/oauth/access_token',
      userInfoUrl: 'https://graph.instagram.com/me',
    }),
    apiVersion: 'v18.0',
    fields: 'id,username,account_type,media_count',
    requiresHttps: false,
    ...overrides,
  };
};

/**
 * Validation helper for OAuth configuration
 */
export const validateMockOAuthConfig = (config: MockOAuthConfig): {
  isValid: boolean;
  errors: string[];
  providerValidations: Record<string, { isValid: boolean; errors: string[] }>;
} => {
  const allErrors: string[] = [];
  const providerValidations: Record<string, { isValid: boolean; errors: string[] }> = {};

  Object.entries(config).forEach(([providerName, providerConfig]) => {
    const errors: string[] = [];

    if (!providerConfig.clientId) {
      errors.push(`${providerName} client ID is missing`);
    }

    if (!providerConfig.clientSecret) {
      errors.push(`${providerName} client secret is missing`);
    }

    if (!providerConfig.redirectUri) {
      errors.push(`${providerName} redirect URI is missing`);
    }

    // Instagram-specific validations
    if (providerName === 'instagram') {
      const instagramConfig = providerConfig as MockInstagramProvider;
      
      if (instagramConfig.requiresHttps && !instagramConfig.redirectUri.startsWith('https://')) {
        errors.push('Instagram requires HTTPS redirect URIs in production');
      }

      const requiredScopes = ['user_profile'];
      const configuredScopes = instagramConfig.scope.split(',').map(s => s.trim());
      const missingScopes = requiredScopes.filter(scope => !configuredScopes.includes(scope));
      
      if (missingScopes.length > 0) {
        errors.push(`Instagram missing required scopes: ${missingScopes.join(', ')}`);
      }
    }

    providerValidations[providerName] = {
      isValid: errors.length === 0,
      errors,
    };

    allErrors.push(...errors);
  });

  return {
    isValid: allErrors.length === 0,
    errors: allErrors,
    providerValidations,
  };
};

/**
 * Helper to generate OAuth test data
 */
export const generateOAuthTestData = () => ({
  validConfigs: [
    defaultMockOAuthConfig,
    developmentMockOAuthConfig,
    productionMockOAuthConfig,
  ],
  invalidConfigs: [
    createMockOAuthConfig({
      google: { ...defaultMockOAuthConfig.google, clientId: '', clientSecret: '' },
    }),
    createMockOAuthConfig({
      instagram: {
        ...defaultMockOAuthConfig.instagram,
        requiresHttps: true,
        redirectUri: 'http://koutu.com/callback',
      },
    }),
  ],
  securityTestCases: Object.values(oauthSecurityScenarios),
  userResponses: mockOAuthUserResponses,
  tokenResponses: mockOAuthTokenResponses,
  errorResponses: mockOAuthErrorResponses,
});

/**
 * Reset all OAuth mocks
 */
export const resetOAuthMocks = (): void => {
  // Clear any mock implementations that might have been set
  jest.clearAllMocks();
};

/**
 * Setup OAuth mock implementations
 */
export const setupOAuthMockImplementations = (): void => {
  // Setup any default mock implementations here
  resetOAuthMocks();
};

/**
 * Export default mock for easy importing
 */
export default {
  defaultMockOAuthConfig,
  developmentMockOAuthConfig,
  productionMockOAuthConfig,
  mockOAuthEnvironmentVariables,
  oauthConfigScenarios,
  createMockOAuthConfig,
  createMockOAuthProvider,
  createMockInstagramProvider,
  validateMockOAuthConfig,
  MockOAuthProcessEnv,
  resetOAuthMocks,
  setupOAuthMockImplementations,
};