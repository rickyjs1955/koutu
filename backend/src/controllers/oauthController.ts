// /backend/src/controllers/oauthController.ts
import { Request, Response, NextFunction } from 'express';
import { oauthService } from '../services/oauthService';
import { getAuthorizationUrl, OAuthProvider } from '../config/oauth';
import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '../utils/ApiError';
import { sanitization } from '@/utils/sanitize';

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

const validateOAuthInput = (provider: any, state: any, code: any) => {
  // Handle type confusion attacks
  if (Array.isArray(provider) || Array.isArray(state) || Array.isArray(code)) {
    throw ApiError.badRequest('Invalid input format');
  }
  
  if (provider !== null && typeof provider === 'object') {
    throw ApiError.badRequest('Invalid provider format');
  }

  // Validate provider
  const validProviders = ['google', 'microsoft', 'github', 'instagram'];
  if (!validProviders.includes(String(provider))) {
    throw ApiError.badRequest(`Unsupported provider: ${provider}`);
  }

  return {
    provider: String(provider),
    state: state ? String(state) : null,
    code: code ? String(code) : null
  };
};

// Timing attack prevention helper
const ensureMinimumResponseTime = async (startTime: number, minimumMs: number): Promise<void> => {
  const elapsed = Date.now() - startTime;
  if (elapsed < minimumMs) {
    await new Promise(resolve => setTimeout(resolve, minimumMs - elapsed));
  }
};

// Enhanced state validation with timing safety
const validateOAuthState = (state: string) => {
  const dummyValidation = () => {
    // Perform dummy operations to maintain consistent timing
    const dummyState = 'dummy-state-for-timing-consistency';
    const dummyTime = Date.now() - 1000;
    return dummyState.length > 0 && dummyTime < Date.now();
  };

  if (!state || !oauthStates[state]) {
    dummyValidation(); // Maintain timing consistency
    return { isValid: false, error: 'Invalid state parameter' };
  }

  const stateData = oauthStates[state];
  delete oauthStates[state]; // Remove used state

  // Check state expiration (30 minutes max)
  if (Date.now() - stateData.createdAt > 30 * 60 * 1000) {
    return { isValid: false, error: 'State parameter expired' };
  }

  return { 
    isValid: true, 
    redirectUrl: stateData.redirectUrl 
  };
};

export const oauthController = {
  /**
   * Initiate OAuth flow by redirecting to provider's authorization page
   */
  async authorize(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      const { provider } = validateOAuthInput(req.params.provider, null, null);
      const { redirect } = req.query;
      
      // Validate redirect parameter to prevent open redirects
      if (redirect && typeof redirect === 'string') {
        const allowedRedirectDomains = process.env.ALLOWED_REDIRECT_DOMAINS?.split(',') || [];
        const redirectUrl = new URL(redirect, process.env.FRONTEND_URL);
        
        if (allowedRedirectDomains.length > 0 && !allowedRedirectDomains.includes(redirectUrl.hostname)) {
          return next(ApiError.badRequest('Invalid redirect URL'));
        }
      }
      
      // Generate cryptographically secure state parameter
      const state = uuidv4();
      oauthStates[state] = { 
        createdAt: Date.now(),
        redirectUrl: redirect as string | undefined
      };

      // Type guard to validate if a string is a supported OAuth provider
      const isValidOAuthProvider = (provider: string): provider is OAuthProvider => {
        return ['google', 'microsoft', 'github', 'instagram'].includes(provider);
      };

      // Usage:
      if (!isValidOAuthProvider(provider)) {
        throw new Error(`Invalid OAuth provider: ${provider}`);
      }
      
      // Generate authorization URL with additional security
      const authUrl = getAuthorizationUrl(
        provider,
        state,
        { 
          // Add additional security parameters
          ...(provider === 'instagram' && { display: 'page' }),
        }
      );
      
      // Ensure minimum response time to prevent timing attacks
      await ensureMinimumResponseTime(startTime, 50);
      
      // Sanitize the redirect URL to prevent XSS
      const sanitizedAuthUrl = sanitization.sanitizeUrl(authUrl);
      res.redirect(sanitizedAuthUrl);
      
    } catch (error) {
      await ensureMinimumResponseTime(startTime, 50);
      next(error);
    }
  },
  
  /**
   * Handle OAuth callback from provider
   */
  async callback(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      const { provider } = validateOAuthInput(req.params.provider, null, null);
      const { code, state, error } = req.query;
      
      // Validate input types
      const { state: validatedState, code: validatedCode } = validateOAuthInput(
        provider, state, code
      );
      
      // Check for OAuth provider error
      if (error) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(ApiError.badRequest(`Provider error: ${sanitization.sanitizeUserInput(String(error))}`));
      }
      
      // Validate required parameters
      if (!validatedCode || !validatedState) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(ApiError.badRequest('Missing required parameters'));
      }
      
      // Validate state parameter with timing safety
      const stateValidation = validateOAuthState(validatedState);
      if (!stateValidation.isValid) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(ApiError.badRequest(stateValidation.error));
      }
      
      // Type guard to validate if a string is a supported OAuth provider
      const isValidOAuthProvider = (provider: string): provider is OAuthProvider => {
        return ['google', 'microsoft', 'github', 'instagram'].includes(provider);
      };

      // Validate OAuth provider before proceeding
      if (!isValidOAuthProvider(provider)) {
        throw new Error(`Invalid OAuth provider: ${provider}`);
      }

      // OAuth token exchange and user authentication
      const tokens = await oauthService.exchangeCodeForTokens(provider, validatedCode);
      const userInfo = await oauthService.getUserInfo(provider, tokens.access_token);
      const user = await oauthService.findOrCreateUser(provider, userInfo);
      const token = oauthService.generateToken(user);
      
      // Ensure minimum response time
      await ensureMinimumResponseTime(startTime, 100);
      
      // Sanitize redirect parameters
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      const callbackUrl = `${frontendUrl}/oauth/callback`;
      const finalRedirect = stateValidation.redirectUrl || '/';
      
      const sanitizedRedirect = sanitization.sanitizeUrl(`${callbackUrl}?token=${token}&redirect=${encodeURIComponent(finalRedirect)}`);
      res.redirect(sanitizedRedirect);
      
    } catch (error) {
      await ensureMinimumResponseTime(startTime, 100);
      next(error);
    }
  }
};