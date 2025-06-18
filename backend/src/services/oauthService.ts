// /backend/src/services/oauthService.ts
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { oauthConfig } from '../config/oauth';
import { userModel } from '../models/userModel';
import { query } from '../models/db';
import { ApiError } from '../utils/ApiError';
import jwt, { SignOptions } from 'jsonwebtoken';
import { config } from '../config';
import { sanitization } from '../utils/sanitize';

export type OAuthProvider = 'google' | 'microsoft' | 'github' | 'instagram';

// Rate limiting for OAuth operations - separated by provider
const oauthRateLimit = new Map<string, { count: number; resetTime: number }>();

export interface OAuthTokenResponse {
  access_token: string;
  id_token?: string;
  expires_in: number;
  refresh_token?: string;
  token_type: string;
}

export interface OAuthUserInfo {
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
  async exchangeCodeForTokens(provider: OAuthProvider, code: string): Promise<OAuthTokenResponse> {
    const startTime = Date.now();
    
    // Validate input
    if (!code || typeof code !== 'string' || code.trim().length === 0) {
      await this.ensureMinimumResponseTime(startTime, 100);
      throw ApiError.badRequest('Invalid authorization code');
    }

    // Rate limiting by provider to prevent abuse
    await this.checkOAuthRateLimit(provider);

    try {
      const providerConfig = oauthConfig[provider];
      
      // Enhanced request configuration with security headers
      const requestConfig = {
        timeout: 10000, // 10 second timeout
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/json',
          'User-Agent': 'YourApp/1.0',
          // Add security headers
          'X-Requested-With': 'XMLHttpRequest'
        }
      };

      let tokenResponse;
      
      if (provider === 'instagram') {
        const formData = new URLSearchParams();
        formData.append('client_id', providerConfig.clientId);
        formData.append('client_secret', providerConfig.clientSecret);
        formData.append('grant_type', 'authorization_code');
        formData.append('redirect_uri', providerConfig.redirectUri);
        formData.append('code', code);

        tokenResponse = await axios.post(providerConfig.tokenUrl, formData, requestConfig);
      } else {
        tokenResponse = await axios.post(providerConfig.tokenUrl, {
          client_id: providerConfig.clientId,
          client_secret: providerConfig.clientSecret,
          code,
          grant_type: 'authorization_code',
          redirect_uri: providerConfig.redirectUri
        }, requestConfig);
      }

      // Validate token response structure
      const tokens = tokenResponse.data;
      if (!tokens.access_token || typeof tokens.access_token !== 'string') {
        throw new Error('Invalid token response format');
      }

      // Ensure minimum response time
      await this.ensureMinimumResponseTime(startTime, 100);
      
      return tokens;
    } catch (error: any) {
      await this.ensureMinimumResponseTime(startTime, 100);
      
      // Track failed attempt
      await this.trackFailedOAuthAttempt(provider, 'token_exchange_failed');
      
      // Log error without sensitive information
      this.logErrorSafely('OAuth token exchange error', error, ['client_secret', 'access_token', 'refresh_token']);
      
      // Return generic error to prevent information disclosure
      throw ApiError.internal('Failed to exchange code for tokens', 'OAUTH_TOKEN_ERROR');
    }
  },

  /**
   * Get user information from OAuth provider
   */
  async getUserInfo(provider: OAuthProvider, accessToken: string): Promise<OAuthUserInfo> {
    const startTime = Date.now();
    
    // Validate access token
    if (!accessToken || typeof accessToken !== 'string' || accessToken.trim().length === 0) {
      await this.ensureMinimumResponseTime(startTime, 100);
      throw ApiError.badRequest('Invalid access token');
    }

    try {
      const providerConfig = oauthConfig[provider];
      let userInfoUrl = providerConfig.userInfoUrl;
      
      if (provider === 'instagram') {
        userInfoUrl = `${providerConfig.userInfoUrl}?fields=id,username,account_type`;
      }

      const requestConfig = {
        timeout: 10000,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'User-Agent': 'YourApp/1.0',
          'Accept': 'application/json'
        }
      };

      const userInfoResponse = await axios.get(userInfoUrl, requestConfig);
      const userData = userInfoResponse.data;

      // Handle null or empty responses
      if (!userData) {
        throw new Error('Invalid user info response');
      }

      // Sanitize user data to prevent XSS
      const sanitizedUserInfo = this.sanitizeUserInfo(provider, userData);
      
      await this.ensureMinimumResponseTime(startTime, 100);
      return sanitizedUserInfo;
    } catch (error: any) {
      await this.ensureMinimumResponseTime(startTime, 100);
      
      // Log error without sensitive information (like access tokens)
      this.logErrorSafely('OAuth user info error', error, ['access_token', 'bearer', 'token']);
      
      // Return generic error to prevent information disclosure
      throw ApiError.internal('Failed to get user info', 'OAUTH_USER_INFO_ERROR');
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
    
    // Create a new user with only necessary data (GDPR compliance)
    const userData = {
      email: userInfo.email,
      name: userInfo.name,
      avatar_url: userInfo.picture,
      oauth_provider: provider,
      oauth_id: userInfo.id
    };
    
    const newUser = await userModel.createOAuthUser(userData);
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
  },
  
  /**
   * Check OAuth rate limit per provider
   */
  async checkOAuthRateLimit(provider: string): Promise<void> {
    const key = `oauth_${provider}`;
    const now = Date.now();
    const limit = oauthRateLimit.get(key);
    
    if (!limit || now > limit.resetTime) {
      // Reset or initialize rate limit for this provider
      oauthRateLimit.set(key, { count: 1, resetTime: now + 60000 }); // 1 minute window
      return;
    }
    
    if (limit.count >= 10) { // 10 attempts per minute per provider
      throw ApiError.rateLimited('OAuth rate limit exceeded', 10, 60000);
    }
    
    limit.count++;
    oauthRateLimit.set(key, limit);
  },

  /**
   * Track failed OAuth attempts for monitoring
   */
  async trackFailedOAuthAttempt(provider: string, reason: string): Promise<void> {
    try {
      // Log without sensitive information
      console.warn(`Failed OAuth attempt for provider: ${provider}, reason: ${reason}`);
      // In production, store in database for monitoring
      // You could add database logging here if needed
    } catch (error) {
      console.error('Error tracking failed OAuth attempt');
    }
  },

  /**
   * Ensure minimum response time to prevent timing attacks
   */
  async ensureMinimumResponseTime(startTime: number, minimumMs: number): Promise<void> {
    const elapsed = Date.now() - startTime;
    if (elapsed < minimumMs) {
      await new Promise(resolve => setTimeout(resolve, minimumMs - elapsed));
    }
  },

  /**
   * Safely log errors without exposing sensitive information
   */
  logErrorSafely(message: string, error: any, sensitivePatterns: string[] = []): void {
    let errorMessage = error?.message || 'Unknown error';
    
    // Remove sensitive information from error messages
    const allSensitivePatterns = [
      ...sensitivePatterns,
      'password',
      'secret',
      'key',
      'token',
      'bearer',
      /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, // IP addresses
      /:\d{4,5}\b/g, // Port numbers
      /\/[a-zA-Z]+\/[a-zA-Z]+\/[^\/\s]+/g, // File paths
      'database',
      'connection',
      'ECONNREFUSED',
      'client_secret',
      'access_token',
      'refresh_token'
    ];
    
    allSensitivePatterns.forEach(pattern => {
      if (typeof pattern === 'string') {
        const regex = new RegExp(pattern, 'gi');
        errorMessage = errorMessage.replace(regex, '[REDACTED]');
      } else {
        errorMessage = errorMessage.replace(pattern, '[REDACTED]');
      }
    });
    
    console.error(`${message}: ${errorMessage}`);
  },

  /**
   * Sanitize user information from OAuth providers
   */
  sanitizeUserInfo(provider: OAuthProvider, userData: any): OAuthUserInfo {
    // Handle null or undefined userData
    if (!userData) {
      throw new Error('Invalid user data received from OAuth provider');
    }

    switch (provider) {
      case 'google':
        return {
          id: sanitization.sanitizeUserInput(userData.sub || userData.id),
          email: sanitization.sanitizeEmail(userData.email),
          name: sanitization.sanitizeUserInput(userData.name),
          picture: sanitization.sanitizeUrl(userData.picture)
        };
      case 'microsoft':
        return {
          id: sanitization.sanitizeUserInput(userData.sub || userData.id),
          email: sanitization.sanitizeEmail(userData.email),
          name: sanitization.sanitizeUserInput(userData.name),
          picture: sanitization.sanitizeUrl(userData.picture)
        };
      case 'github':
        return {
          id: sanitization.sanitizeUserInput(userData.id?.toString()),
          email: sanitization.sanitizeEmail(userData.email || ''), // Handle null email
          name: sanitization.sanitizeUserInput(userData.name || userData.login),
          picture: sanitization.sanitizeUrl(userData.avatar_url)
        };
      case 'instagram':
        const username = sanitization.sanitizeUserInput(userData.username) || '';
        return {
          id: sanitization.sanitizeUserInput(userData.id?.toString()),
          email: `${username}@instagram.local`,
          name: username,
          picture: sanitization.sanitizeUrl(userData.profile_picture_url || '')
        };
      default:
        throw new Error(`Unsupported provider: ${provider}`);
    }
  },

  /**
   * Reset rate limits for a specific provider (useful for testing)
   */
  resetRateLimit(provider?: string): void {
    if (provider) {
      oauthRateLimit.delete(`oauth_${provider}`);
    } else {
      oauthRateLimit.clear();
    }
  },

  /**
   * Get current rate limit status for a provider
   */
  getRateLimitStatus(provider: string): { count: number; resetTime: number } | null {
    return oauthRateLimit.get(`oauth_${provider}`) || null;
  }
};

export const __testExports = {
  oauthRateLimit
};