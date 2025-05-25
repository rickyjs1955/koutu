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
    scope: 'user_profile,user_media',
    authUrl: 'https://api.instagram.com/oauth/authorize',
    tokenUrl: 'https://api.instagram.com/oauth/access_token',
    userInfoUrl: 'https://graph.instagram.com/me',
  }
};

// Generate OAuth provider authorization URLs
export const getAuthorizationUrl = (provider: 'google' | 'microsoft' | 'github' | 'instagram', state: string): string => {
  const config = oauthConfig[provider];
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: config.scope,
    state,
  });

  return `${config.authUrl}?${params.toString()}`;
};