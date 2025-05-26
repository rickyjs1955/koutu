// /backend/src/config/oauth.ts
import { config } from './index';

export const oauthConfig = {
  google: {
    clientId: config.oauth?.googleClientId || '',
    clientSecret: config.oauth?.googleClientSecret || '',
    redirectUri: `${config.appUrl}/api/v1/oauth/google/callback`,
    scope: 'email profile',
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
  },
  microsoft: {
    clientId: config.oauth?.microsoftClientId || '',
    clientSecret: config.oauth?.microsoftClientSecret || '',
    redirectUri: `${config.appUrl}/api/v1/oauth/microsoft/callback`,
    scope: 'openid profile email',
    authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
  },
  github: {
    clientId: config.oauth?.githubClientId || '',
    clientSecret: config.oauth?.githubClientSecret || '',
    redirectUri: `${config.appUrl}/api/v1/oauth/github/callback`,
    scope: 'read:user user:email',
    authUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
  },
  instagram: {
    clientId: config.oauth?.instagramClientId || '',
    clientSecret: config.oauth?.instagramClientSecret || '',
    redirectUri: `${config.appUrl}/api/v1/oauth/instagram/callback`,
    // Updated scope for Instagram Basic Display API (current standard)
    scope: 'user_profile,user_media',
    // Updated to use Instagram Basic Display API endpoints
    authUrl: 'https://api.instagram.com/oauth/authorize',
    tokenUrl: 'https://api.instagram.com/oauth/access_token',
    // Updated to use Graph API endpoint for user info
    userInfoUrl: 'https://graph.instagram.com/me',
    // Additional Instagram-specific configurations
    apiVersion: 'v18.0', // Current stable version
    fields: 'id,username,account_type,media_count', // Default fields to request
    // Instagram requires HTTPS for redirect URIs in production
    requiresHttps: config.nodeEnv === 'production',
  }
};

// Enhanced authorization URL generator with Instagram-specific handling
export const getAuthorizationUrl = (
  provider: 'google' | 'microsoft' | 'github' | 'instagram', 
  state: string,
  additionalParams?: Record<string, string>
): string => {
  const providerConfig = oauthConfig[provider];
  
  const baseParams = new URLSearchParams({
    client_id: providerConfig.clientId,
    redirect_uri: providerConfig.redirectUri,
    response_type: 'code',
    scope: providerConfig.scope,
    state,
  });

  // Add Instagram-specific parameters
  if (provider === 'instagram') {
    // Instagram requires response_type to be 'code'
    baseParams.set('response_type', 'code');
    
    // Add any additional Instagram-specific parameters
    if (additionalParams?.display) {
      baseParams.set('display', additionalParams.display); // 'page' or 'popup'
    }
  }

  // Add any additional parameters for other providers
  if (additionalParams) {
    Object.entries(additionalParams).forEach(([key, value]) => {
      if (key !== 'display' || provider !== 'instagram') {
        baseParams.set(key, value);
      }
    });
  }

  return `${providerConfig.authUrl}?${baseParams.toString()}`;
};

// Helper function to get user info URL with Instagram-specific field handling
export const getUserInfoUrl = (
  provider: 'google' | 'microsoft' | 'github' | 'instagram',
  accessToken: string,
  fields?: string[]
): string => {
  const providerConfig = oauthConfig[provider];
  
  if (provider === 'instagram') {
    const instagramConfig = providerConfig as typeof oauthConfig.instagram;
    const requestedFields = fields?.join(',') || instagramConfig.fields;
    
    return `${instagramConfig.userInfoUrl}?fields=${requestedFields}&access_token=${accessToken}`;
  }
  
  // For other providers, return the standard user info URL
  return providerConfig.userInfoUrl;
};

// Helper function to validate OAuth configuration
export const validateOAuthConfig = (provider: keyof typeof oauthConfig): {
  isValid: boolean;
  errors: string[];
} => {
  const config = oauthConfig[provider];
  const errors: string[] = [];

  if (!config.clientId) {
    errors.push(`${provider} client ID is missing`);
  }

  if (!config.clientSecret) {
    errors.push(`${provider} client secret is missing`);
  }

  if (!config.redirectUri) {
    errors.push(`${provider} redirect URI is missing`);
  }

  // Instagram-specific validations
  if (provider === 'instagram') {
    const instagramConfig = config as typeof oauthConfig.instagram;
    
    // Check if redirect URI uses HTTPS in production
    if (instagramConfig.requiresHttps && !instagramConfig.redirectUri.startsWith('https://')) {
      errors.push('Instagram requires HTTPS redirect URIs in production');
    }

    // Validate scope contains required permissions
    const requiredScopes = ['user_profile'];
    const configuredScopes = instagramConfig.scope.split(',').map(s => s.trim());
    
    const missingScopes = requiredScopes.filter(scope => !configuredScopes.includes(scope));
    if (missingScopes.length > 0) {
      errors.push(`Instagram missing required scopes: ${missingScopes.join(', ')}`);
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
};

// Helper function to get all configured providers
export const getConfiguredProviders = (): string[] => {
  return Object.keys(oauthConfig).filter(provider => {
    const config = oauthConfig[provider as keyof typeof oauthConfig];
    return config.clientId && config.clientSecret;
  });
};

// Helper function to check if Instagram is properly configured
export const isInstagramEnabled = (): boolean => {
  const validation = validateOAuthConfig('instagram');
  return validation.isValid;
};

// Export Instagram-specific configuration for easy access
export const instagramConfig = oauthConfig.instagram;

// Export types for TypeScript support
export type OAuthProvider = keyof typeof oauthConfig;
export type OAuthConfig = typeof oauthConfig;
export type InstagramConfig = typeof oauthConfig.instagram;