// /backend/src/controllers/oauthController.ts
import { Request, Response, NextFunction } from 'express';
import { oauthService } from '../services/oauthService';
import { getAuthorizationUrl } from '../config/oauth';
import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '../utils/ApiError';

// Track OAuth state parameters to prevent CSRF attacks
const oauthStates: Record<string, { createdAt: number, redirectUrl?: string }> = {};

// Clean up expired states every hour
setInterval(() => {
  const now = Date.now();
  Object.keys(oauthStates).forEach(state => {
    if (now - oauthStates[state].createdAt > 3600000) { // 1 hour
      delete oauthStates[state];
    }
  });
}, 3600000);

export const oauthController = {
  /**
   * Initiate OAuth flow by redirecting to provider's authorization page
   */
  async authorize(req: Request, res: Response, next: NextFunction) {
    try {
      const { provider } = req.params;
      const { redirect } = req.query;
      
      // Validate provider
      if (!['google', 'microsoft', 'github'].includes(provider)) {
        return next(ApiError.badRequest(`Unsupported provider: ${provider}`));
      }
      
      // Generate and store state parameter
      const state = uuidv4();
      oauthStates[state] = { 
        createdAt: Date.now(),
        redirectUrl: redirect as string | undefined
      };
      
      // Generate authorization URL
      const authUrl = getAuthorizationUrl(
        provider as 'google' | 'microsoft' | 'github',
        state
      );
      
      // Redirect to provider's authorization page
      res.redirect(authUrl);
    } catch (error) {
      next(error);
    }
  },
  
  /**
   * Handle OAuth callback from provider
   */
  async callback(req: Request, res: Response, next: NextFunction) {
    try {
      const { provider } = req.params;
      const { code, state, error } = req.query;
      
      // Validate provider
      if (!['google', 'microsoft', 'github'].includes(provider)) {
        return next(ApiError.badRequest(`Unsupported provider: ${provider}`));
      }
      
      // Check for OAuth error
      if (error) {
        return next(ApiError.badRequest(`Provider error: ${error}`));
      }
      
      // Validate required parameters
      if (!code || !state) {
        return next(ApiError.badRequest('Missing required parameters'));
      }
      
      // Validate state parameter
      if (!oauthStates[state as string]) {
        return next(ApiError.badRequest('Invalid state parameter'));
      }
      
      // Get redirect URL from stored state
      const { redirectUrl } = oauthStates[state as string];
      
      // Remove used state
      delete oauthStates[state as string];
      
      // Exchange code for tokens
      const tokens = await oauthService.exchangeCodeForTokens(
        provider as 'google' | 'microsoft' | 'github',
        code as string
      );
      
      // Get user info from provider
      const userInfo = await oauthService.getUserInfo(
        provider as 'google' | 'microsoft' | 'github',
        tokens.access_token
      );
      
      // Find or create user
      const user = await oauthService.findOrCreateUser(
        provider as 'google' | 'microsoft' | 'github',
        userInfo
      );
      
      // Generate JWT token
      const token = oauthService.generateToken(user);
      
      // Determine redirect URL
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      const callbackUrl = `${frontendUrl}/oauth/callback`;
      const finalRedirect = redirectUrl || '/';
      
      // Redirect to frontend with token
      res.redirect(`${callbackUrl}?token=${token}&redirect=${encodeURIComponent(finalRedirect)}`);
    } catch (error) {
      next(error);
    }
  }
};