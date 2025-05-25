// /backend/src/services/oauthService.ts
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { oauthConfig } from '../config/oauth';
import { userModel } from '../models/userModel';
import { query } from '../models/db';
import { ApiError } from '../utils/ApiError';
import jwt, { SignOptions } from 'jsonwebtoken';
import { config } from '../config';

type OAuthProvider = 'google' | 'microsoft' | 'github' | 'instagram';

interface OAuthTokenResponse {
  access_token: string;
  id_token?: string;
  expires_in: number;
  refresh_token?: string;
  token_type: string;
}

interface OAuthUserInfo {
  id: string;
  email: string;
  name?: string;
  picture?: string;
  [key: string]: any;
}

export const oauthService = {
  /**
   * Exchange authorization code for tokens
   */
  async exchangeCodeForTokens(
    provider: OAuthProvider,
    code: string
  ): Promise<OAuthTokenResponse> {
    const providerConfig = oauthConfig[provider];
    
    try {
      // Instagram uses different token exchange format
      if (provider === 'instagram') {
        const formData = new URLSearchParams();
        formData.append('client_id', providerConfig.clientId);
        formData.append('client_secret', providerConfig.clientSecret);
        formData.append('grant_type', 'authorization_code');
        formData.append('redirect_uri', providerConfig.redirectUri);
        formData.append('code', code);

        const tokenResponse = await axios.post(
          providerConfig.tokenUrl,
          formData,
          {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              Accept: 'application/json'
            }
          }
        );

        return tokenResponse.data;
      }

      const tokenResponse = await axios.post(
        providerConfig.tokenUrl,
        {
          client_id: providerConfig.clientId,
          client_secret: providerConfig.clientSecret,
          code,
          grant_type: 'authorization_code',
          redirect_uri: providerConfig.redirectUri
        },
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json'
          }
        }
      );

      return tokenResponse.data;
    } catch (error) {
      console.error('OAuth token exchange error:', error);
      throw new ApiError('Failed to exchange code for tokens', 500, 'OAUTH_TOKEN_ERROR');
    }
  },

  /**
   * Get user information from OAuth provider
   */
  async getUserInfo(
    provider: OAuthProvider,
    accessToken: string
  ): Promise<OAuthUserInfo> {
    const providerConfig = oauthConfig[provider];
    
    try {
      let userInfoUrl = providerConfig.userInfoUrl;
      
      // Instagram requires specific fields parameter
      if (provider === 'instagram') {
        userInfoUrl = `${providerConfig.userInfoUrl}?fields=id,username,account_type`;
      }

      const userInfoResponse = await axios.get(userInfoUrl, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      });

      // Normalize user info based on provider
      const userData = userInfoResponse.data;

      switch (provider) {
        case 'google':
          return {
            id: userData.sub,
            email: userData.email,
            name: userData.name,
            picture: userData.picture
          };
        case 'microsoft':
          return {
            id: userData.sub,
            email: userData.email,
            name: userData.name,
            picture: userData.picture
          };
        case 'github':
          // GitHub doesn't return email in user info endpoint
          const emailsResponse = await axios.get('https://api.github.com/user/emails', {
            headers: {
              Authorization: `Bearer ${accessToken}`
            }
          });
          
          const primaryEmail = emailsResponse.data.find((email: any) => email.primary)?.email;
          
          return {
            id: userData.id.toString(),
            email: primaryEmail || userData.email,
            name: userData.name,
            picture: userData.avatar_url
          };
        case 'instagram':
          // Instagram Basic Display API doesn't provide email
          // You might need to request it separately or use a placeholder
          return {
            id: userData.id.toString(),
            email: `${userData.username}@instagram.local`, // Placeholder email
            name: userData.username,
            picture: userData.profile_picture_url || ''
          };
        default:
          throw new Error(`Unsupported provider: ${provider}`);
      }
    } catch (error) {
      console.error('OAuth user info error:', error);
      throw new ApiError('Failed to get user info', 500, 'OAUTH_USER_INFO_ERROR');
    }
  },

  /**
   * Find or create user based on OAuth user info
   */
  async findOrCreateUser(
    provider: OAuthProvider,
    userInfo: OAuthUserInfo
  ): Promise<any> {
    // Check if user already exists with this OAuth provider and ID
    const existingUser = await userModel.findByOAuth(provider, userInfo.id);
    
    if (existingUser) {
      return existingUser;
    }
    
    // For Instagram, since we don't get real email, check by OAuth ID only
    if (provider !== 'instagram') {
      // Check if user exists with the same email
      const userByEmail = await userModel.findByEmail(userInfo.email);
      
      if (userByEmail) {
        // Link this OAuth account to the existing user
        await this.linkOAuthProviderToUser(userByEmail.id, provider, userInfo);
        return userByEmail;
      }
    }
    
    // Create a new user
    const newUser = await userModel.createOAuthUser({
      email: userInfo.email,
      name: userInfo.name,
      avatar_url: userInfo.picture,
      oauth_provider: provider,
      oauth_id: userInfo.id
    });
    
    return newUser;
  },
  
  /**
   * Link OAuth provider to existing user
   */
  async linkOAuthProviderToUser(
    userId: string,
    provider: OAuthProvider,
    userInfo: OAuthUserInfo
  ): Promise<void> {
    const id = uuidv4();
    
    await query(
      `INSERT INTO user_oauth_providers 
       (id, user_id, provider, provider_id, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       ON CONFLICT (provider, provider_id) DO NOTHING`,
      [id, userId, provider, userInfo.id]
    );
  },
  
  /**
   * Generate JWT token for authenticated user
   */
  generateToken(user: any): string {
    // Assert the entire expression to the target type
    const expiresInValue: SignOptions['expiresIn'] = (config.jwtExpiresIn || '1d') as SignOptions['expiresIn'];

    return jwt.sign(
        {
            id: user.id,
            email: user.email
        },
        config.jwtSecret || 'fallback_secret',
        {
            expiresIn: expiresInValue
        }
    );
  }
};