// backend/src/__tests__/__mocks__/oauth.mock.ts - Fixed version with all issues resolved

import { NextFunction } from "express";

export class MockOAuthProcessEnv {
  private originalEnv: NodeJS.ProcessEnv;

  constructor() {
    this.originalEnv = { ...process.env };
  }

  setOAuthEnv(environment: string) {
    const envConfigs = {
      test: {
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
      development: {
        NODE_ENV: 'development',
        APP_URL: 'http://localhost:3000',
        GOOGLE_CLIENT_ID: 'dev-google-client-id',
        GOOGLE_CLIENT_SECRET: 'dev-google-client-secret',
        MICROSOFT_CLIENT_ID: 'dev-microsoft-client-id',
        MICROSOFT_CLIENT_SECRET: 'dev-microsoft-client-secret',
        GITHUB_CLIENT_ID: 'dev-github-client-id',
        GITHUB_CLIENT_SECRET: 'dev-github-client-secret',
        INSTAGRAM_CLIENT_ID: 'dev-instagram-client-id',
        INSTAGRAM_CLIENT_SECRET: 'dev-instagram-client-secret',
      },
      production: {
        NODE_ENV: 'production',
        APP_URL: 'https://koutu.com',
        GOOGLE_CLIENT_ID: 'prod-google-client-id',
        GOOGLE_CLIENT_SECRET: 'prod-google-client-secret',
        MICROSOFT_CLIENT_ID: 'prod-microsoft-client-id',
        MICROSOFT_CLIENT_SECRET: 'prod-microsoft-client-secret',
        GITHUB_CLIENT_ID: 'prod-github-client-id',
        GITHUB_CLIENT_SECRET: 'prod-github-client-secret',
        INSTAGRAM_CLIENT_ID: 'prod-instagram-client-id',
        INSTAGRAM_CLIENT_SECRET: 'prod-instagram-client-secret',
      }
    };

    this.setEnv(envConfigs[environment as keyof typeof envConfigs] || envConfigs.test);
  }

  setEnv(envVars: Record<string, any>) {
    Object.assign(process.env, envVars);
  }

  clearOAuthEnv() {
    delete process.env.GOOGLE_CLIENT_ID;
    delete process.env.GOOGLE_CLIENT_SECRET;
    delete process.env.MICROSOFT_CLIENT_ID;
    delete process.env.MICROSOFT_CLIENT_SECRET;
    delete process.env.GITHUB_CLIENT_ID;
    delete process.env.GITHUB_CLIENT_SECRET;
    delete process.env.INSTAGRAM_CLIENT_ID;
    delete process.env.INSTAGRAM_CLIENT_SECRET;
  }

  restore() {
    process.env = { ...this.originalEnv };
  }
}

// Mock OAuth environment variables for different environments
export const mockOAuthEnvironmentVariables = {
  test: {
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
  development: {
    NODE_ENV: 'development',
    APP_URL: 'http://localhost:3000',
    GOOGLE_CLIENT_ID: 'dev-google-client-id',
    GOOGLE_CLIENT_SECRET: 'dev-google-client-secret',
    MICROSOFT_CLIENT_ID: 'dev-microsoft-client-id',
    MICROSOFT_CLIENT_SECRET: 'dev-microsoft-client-secret',
    GITHUB_CLIENT_ID: 'dev-github-client-id',
    GITHUB_CLIENT_SECRET: 'dev-github-client-secret',
    INSTAGRAM_CLIENT_ID: 'dev-instagram-client-id',
    INSTAGRAM_CLIENT_SECRET: 'dev-instagram-client-secret',
  },
  production: {
    NODE_ENV: 'production',
    APP_URL: 'https://koutu.com',
    GOOGLE_CLIENT_ID: 'prod-google-client-id',
    GOOGLE_CLIENT_SECRET: 'prod-google-client-secret',
    MICROSOFT_CLIENT_ID: 'prod-microsoft-client-id',
    MICROSOFT_CLIENT_SECRET: 'prod-microsoft-client-secret',
    GITHUB_CLIENT_ID: 'prod-github-client-id',
    GITHUB_CLIENT_SECRET: 'prod-github-client-secret',
    INSTAGRAM_CLIENT_ID: 'prod-instagram-client-id',
    INSTAGRAM_CLIENT_SECRET: 'prod-instagram-client-secret',
  }
};

// Mock OAuth user responses for different providers
export const mockOAuthUserResponses = {
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

// Mock OAuth token responses for different providers
export const mockOAuthTokenResponses = {
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

// Mock OAuth error responses
export const mockOAuthErrorResponses = {
  invalid_grant: {
    error: 'invalid_grant',
    error_description: 'The provided authorization grant is invalid'
  },
  invalid_client: {
    error: 'invalid_client',
    error_description: 'Client authentication failed'
  },
  invalid_request: {
    error: 'invalid_request',
    error_description: 'The request is invalid'
  }
};

// Create dynamic config that responds to environment variables
export const createDynamicMockOAuthConfig = () => {
  const appUrl = process.env.APP_URL || 'http://localhost:3000';
  const isProduction = process.env.NODE_ENV === 'production';

  return {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      redirectUri: `${appUrl}/api/v1/oauth/google/callback`,
      scope: 'email profile',
      authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    microsoft: {
      clientId: process.env.MICROSOFT_CLIENT_ID || '',
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET || '',
      redirectUri: `${appUrl}/api/v1/oauth/microsoft/callback`,
      scope: 'openid profile email',
      authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
    },
    github: {
      clientId: process.env.GITHUB_CLIENT_ID || '',
      clientSecret: process.env.GITHUB_CLIENT_SECRET || '',
      redirectUri: `${appUrl}/api/v1/oauth/github/callback`,
      scope: 'read:user user:email',
      authUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      userInfoUrl: 'https://api.github.com/user',
    },
    instagram: {
      clientId: process.env.INSTAGRAM_CLIENT_ID || '',
      clientSecret: process.env.INSTAGRAM_CLIENT_SECRET || '',
      redirectUri: `${appUrl}/api/v1/oauth/instagram/callback`,
      scope: 'user_profile,user_media',
      authUrl: 'https://api.instagram.com/oauth/authorize',
      tokenUrl: 'https://api.instagram.com/oauth/access_token',
      userInfoUrl: 'https://graph.instagram.com/me',
      apiVersion: 'v18.0',
      fields: 'id,username,account_type,media_count',
      requiresHttps: isProduction,
    },
  };
};

// Static configs for reference
export const defaultMockOAuthConfig = {
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

export const developmentMockOAuthConfig = {
  ...defaultMockOAuthConfig,
  google: { 
    ...defaultMockOAuthConfig.google, 
    clientId: 'dev-google-client-id', 
    clientSecret: 'dev-google-client-secret' 
  },
  microsoft: { 
    ...defaultMockOAuthConfig.microsoft, 
    clientId: 'dev-microsoft-client-id', 
    clientSecret: 'dev-microsoft-client-secret' 
  },
  github: { 
    ...defaultMockOAuthConfig.github, 
    clientId: 'dev-github-client-id', 
    clientSecret: 'dev-github-client-secret' 
  },
  instagram: { 
    ...defaultMockOAuthConfig.instagram, 
    clientId: 'dev-instagram-client-id', 
    clientSecret: 'dev-instagram-client-secret' 
  },
};

export const productionMockOAuthConfig = {
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

export const createMockOAuthConfig = (overrides: any = {}, baseConfig = createDynamicMockOAuthConfig()) => {
  return {
    google: { ...baseConfig.google, ...overrides.google },
    microsoft: { ...baseConfig.microsoft, ...overrides.microsoft },
    github: { ...baseConfig.github, ...overrides.github },
    instagram: { ...baseConfig.instagram, ...overrides.instagram },
  };
};

export const createMockOAuthProvider = (provider: string, overrides: any = {}) => {
  const base = createDynamicMockOAuthConfig();
  return { ...base[provider as keyof typeof base], ...overrides };
};

export const createMockInstagramProvider = (overrides: any = {}) => {
  const base = createDynamicMockOAuthConfig();
  return { ...base.instagram, ...overrides };
};

// Type definitions
export interface MockOAuthConfig {
  google: typeof defaultMockOAuthConfig.google;
  microsoft: typeof defaultMockOAuthConfig.microsoft;
  github: typeof defaultMockOAuthConfig.github;
  instagram: typeof defaultMockOAuthConfig.instagram;
}

export interface MockOAuthProvider {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
  authUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
}

export interface MockInstagramProvider extends MockOAuthProvider {
  apiVersion: string;
  fields: string;
  requiresHttps: boolean;
}

// FIXED: Enhanced validation function with proper validation logic
export const validateMockOAuthConfig = (config: any) => {
  const errors: string[] = [];
  const providerValidations: any = {};

  const providers = ['google', 'microsoft', 'github', 'instagram'];
  
  providers.forEach(providerName => {
    const providerConfig = config[providerName];
    const providerErrors: string[] = [];

    // Handle null/undefined providers gracefully
    if (!providerConfig || typeof providerConfig !== 'object') {
      providerErrors.push(`${providerName} configuration is missing or invalid`);
      providerValidations[providerName] = { isValid: false, errors: providerErrors };
      errors.push(...providerErrors);
      return;
    }

    if (!providerConfig.clientId) {
      providerErrors.push(`${providerName} client ID is missing`);
    }
    if (!providerConfig.clientSecret) {
      providerErrors.push(`${providerName} client secret is missing`);
    }

    // Instagram-specific validations
    if (providerName === 'instagram') {
      if (providerConfig.requiresHttps && providerConfig.redirectUri && !providerConfig.redirectUri.startsWith('https://')) {
        providerErrors.push('Instagram requires HTTPS redirect URIs in production');
      }
      
      if (providerConfig.scope) {
        const requiredScopes = ['user_profile'];
        const providedScopes = providerConfig.scope.split(',').map((s: string) => s.trim());
        const missingScopes = requiredScopes.filter(scope => !providedScopes.includes(scope));
        if (missingScopes.length > 0) {
          providerErrors.push(`Instagram missing required scopes: ${missingScopes.join(', ')}`);
        }
      }
    }

    providerValidations[providerName] = {
      isValid: providerErrors.length === 0,
      errors: providerErrors
    };
    errors.push(...providerErrors);
  });

  return {
    isValid: errors.length === 0,
    errors,
    providerValidations
  };
};

export const oauthConfigScenarios = {
  complete: {
    name: 'Complete OAuth configuration',
    config: defaultMockOAuthConfig,
    shouldBeValid: true,
  },
  missingGoogle: {
    name: 'Missing Google OAuth credentials',
    config: createMockOAuthConfig({
      google: { ...defaultMockOAuthConfig.google, clientId: '', clientSecret: '' }
    }),
    shouldBeValid: false,
    expectedErrors: ['google client ID is missing', 'google client secret is missing'],
  },
  missingInstagram: {
    name: 'Missing Instagram OAuth credentials',
    config: createMockOAuthConfig({
      instagram: { ...defaultMockOAuthConfig.instagram, clientId: '', clientSecret: '' }
    }),
    shouldBeValid: false,
    expectedErrors: ['instagram client ID is missing', 'instagram client secret is missing'],
  },
  instagramHttpProduction: {
    name: 'Instagram with HTTP redirect in production',
    config: createMockOAuthConfig({
      instagram: {
        ...defaultMockOAuthConfig.instagram,
        requiresHttps: true,
        redirectUri: 'http://koutu.com/callback'
      }
    }),
    shouldBeValid: false,
    expectedErrors: ['Instagram requires HTTPS redirect URIs in production'],
  },
  instagramInvalidScope: {
    name: 'Instagram with invalid scope',
    config: createMockOAuthConfig({
      instagram: {
        ...defaultMockOAuthConfig.instagram,
        scope: 'invalid_scope'
      }
    }),
    shouldBeValid: false,
    expectedErrors: ['Instagram missing required scopes: user_profile'],
  },
  partialGoogle: {
    name: 'Partial OAuth configuration (only Google)',
    config: createMockOAuthConfig({
      microsoft: { ...defaultMockOAuthConfig.microsoft, clientId: '', clientSecret: '' },
      github: { ...defaultMockOAuthConfig.github, clientId: '', clientSecret: '' },
      instagram: { ...defaultMockOAuthConfig.instagram, clientId: '', clientSecret: '' },
    }),
    shouldBeValid: false,
    expectedErrors: [
      'microsoft client ID is missing',
      'microsoft client secret is missing',
      'github client ID is missing',
      'github client secret is missing',
      'instagram client ID is missing',
      'instagram client secret is missing'
    ],
  },
  empty: {
    name: 'Empty OAuth configuration',
    config: createMockOAuthConfig({
      google: { ...defaultMockOAuthConfig.google, clientId: '', clientSecret: '' },
      microsoft: { ...defaultMockOAuthConfig.microsoft, clientId: '', clientSecret: '' },
      github: { ...defaultMockOAuthConfig.github, clientId: '', clientSecret: '' },
      instagram: { ...defaultMockOAuthConfig.instagram, clientId: '', clientSecret: '' },
    }),
    shouldBeValid: false,
  },
};

export const oauthSecurityScenarios = [
  {
    name: 'Redirect URI injection attack',
    attackVector: 'redirect_uri',
    maliciousInput: 'http://evil.com/steal-tokens',
    expectedBehavior: 'block' as const,
    shouldThrow: true
  },
  {
    name: 'XSS via redirect URI',
    attackVector: 'redirect_uri',
    maliciousInput: 'javascript:alert("xss")',
    expectedBehavior: 'block' as const,
    shouldThrow: true
  },
  {
    name: 'Client secret exposure in URL',
    attackVector: 'client_secret',
    maliciousInput: 'some-url?client_secret=secret123',
    expectedBehavior: 'block' as const,
    shouldThrow: true
  },
  {
    name: 'State parameter injection',
    attackVector: 'state',
    maliciousInput: 'state"; DROP TABLE users; --',
    expectedBehavior: 'sanitize' as const,
    shouldThrow: false
  },
  {
    name: 'CSRF attack via missing state',
    attackVector: 'state',
    maliciousInput: '',
    expectedBehavior: 'block' as const,
    shouldThrow: true
  }
];

// Mock the state management without the setInterval
const mockOAuthStates: Record<string, { createdAt: number; redirectUrl?: string }> = {};

// Mock controller implementation that matches the real interface
export const oauthController = {
  authorize: jest.fn(async (req: Request, res: Response, next: NextFunction) => {
    // Mock implementation - tests will override this behavior
  }),

  callback: jest.fn(async (req: Request, res: Response, next: NextFunction) => {
    // Mock implementation - tests will override this behavior
  }),

  getOAuthStatus: jest.fn(async (req: Request, res: Response, next: NextFunction) => {
    // Mock implementation - tests will override this behavior
  }),

  unlinkProvider: jest.fn(async (req: Request, res: Response, next: NextFunction) => {
    // Mock implementation - tests will override this behavior
  }),

  // Export the states for test manipulation
  __getOAuthStates: () => mockOAuthStates,
  __clearOAuthStates: () => {
    Object.keys(mockOAuthStates).forEach(key => delete mockOAuthStates[key]);
  }
};

export const setupOAuthMockImplementations = () => {
  // Setup any additional mock implementations if needed
};

export const resetOAuthMocks = () => {
  // Reset any mocks if needed
};

// For backward compatibility
export default oauthController;