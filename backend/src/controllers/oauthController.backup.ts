// /backend/src/controllers/oauthController.ts - Enhanced with proper cleanup
import { Request, Response, NextFunction } from 'express';
import { oauthService } from '../services/oauthService';
import { authService } from '../services/authService';
import { getAuthorizationUrl, OAuthProvider } from '../config/oauth';
import { v4 as uuidv4 } from 'uuid';
import { ApiError } from '../utils/ApiError';
import { sanitization } from '../utils/sanitize';
import * as db from '../models/db';

// Track OAuth state parameters to prevent CSRF attacks
const oauthStates: Record<string, { createdAt: number, redirectUrl?: string }> = {};

// Store interval reference for cleanup
let cleanupInterval: NodeJS.Timeout | null = null;

// Helper to check if we're in test environment
const isTestEnvironment = () => process.env.NODE_ENV === 'test';

// Start cleanup interval (only in non-test environments)
const startCleanupInterval = () => {
  if (!isTestEnvironment() && !cleanupInterval) {
    cleanupInterval = setInterval(() => {
      const now = Date.now();
      Object.keys(oauthStates).forEach(state => {
        if (now - oauthStates[state].createdAt > 3600000) { // 1 hour
          delete oauthStates[state];
        }
      });
    }, 3600000);

    // Ensure interval doesn't prevent process exit
    if (cleanupInterval.unref) {
      cleanupInterval.unref();
    }
  }
};

// Stop cleanup interval
const stopCleanupInterval = () => {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
  }
};

// Initialize cleanup on module load (non-test only)
if (!isTestEnvironment()) {
  startCleanupInterval();
}

// ENHANCED: Aligned with auth system validation patterns
const validateOAuthInput = (provider: any, state: any, code: any) => {
  // Handle type confusion attacks (aligned with authController)
  if (Array.isArray(provider) || Array.isArray(state) || Array.isArray(code)) {
    throw ApiError.badRequest('Invalid input format');
  }
  
  if (provider !== null && typeof provider === 'object') {
    throw ApiError.badRequest('Invalid provider format');
  }

  // Validate provider using auth system validation pattern
  const validProviders = ['google', 'microsoft', 'github', 'instagram'];
  if (!validProviders.includes(String(provider))) {
    throw ApiError.badRequest(`Unsupported provider: ${provider}`);
  }

  // ENHANCED: Use auth system input validation approach
  const providerStr = String(provider).trim();
  const stateStr = state ? String(state).trim() : null;
  const codeStr = code ? String(code).trim() : null;

  // Additional validation following auth system patterns
  if (stateStr && (stateStr.length === 0 || stateStr.length > 255)) {
    throw ApiError.badRequest('Invalid state parameter');
  }

  if (codeStr && (codeStr.length === 0 || codeStr.length > 1000)) {
    throw ApiError.badRequest('Invalid authorization code');
  }

  return {
    provider: providerStr,
    state: stateStr,
    code: codeStr
  };
};

// ENHANCED: Use auth service timing function for consistency
const ensureMinimumResponseTime = authService.ensureMinimumResponseTime.bind(authService);

// Enhanced state validation with timing safety (aligned with auth system)
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
  
  // Check state expiration BEFORE deleting (30 minutes max)
  const isExpired = Date.now() - stateData.createdAt > 30 * 60 * 1000;
  
  // Always delete used state to prevent reuse
  delete oauthStates[state];
  
  if (isExpired) {
    return { isValid: false, error: 'State parameter expired' };
  }

  return { 
    isValid: true, 
    redirectUrl: stateData.redirectUrl 
  };
};

// ENHANCED: Email validation for OAuth users (aligned with auth system)
const validateOAuthEmail = (email: string): void => {
  try {
    // Use auth system email validation for consistency
    authService.validateEmailFormat(email);
  } catch (error) {
    // Re-throw with OAuth context
    throw ApiError.businessLogic(
      'Invalid email from OAuth provider',
      'oauth_invalid_email',
      'email'
    );
  }
};

export const oauthController = {
  /**
   * Initiate OAuth flow by redirecting to provider's authorization page
   * ENHANCED: Aligned with auth system patterns
   */
  async authorize(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      const { provider } = validateOAuthInput(req.params.provider, null, null);
      const { redirect } = req.query;
      
      // ENHANCED: Validate redirect parameter using auth system validation patterns
      if (redirect && typeof redirect === 'string') {
        const allowedRedirectDomains = process.env.ALLOWED_REDIRECT_DOMAINS?.split(',') || [];
        
        try {
          const redirectUrl = new URL(redirect, process.env.FRONTEND_URL);
          
          if (allowedRedirectDomains.length > 0 && !allowedRedirectDomains.includes(redirectUrl.hostname)) {
            await ensureMinimumResponseTime(startTime, 50);
            return next(ApiError.badRequest('Invalid redirect URL'));
          }
        } catch (urlError) {
          await ensureMinimumResponseTime(startTime, 50);
          return next(ApiError.badRequest('Invalid redirect URL format'));
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

      if (!isValidOAuthProvider(provider)) {
        await ensureMinimumResponseTime(startTime, 50);
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
      
      // ENHANCED: Use auth service timing function for consistency
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
   * ENHANCED: Aligned with auth system response patterns
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
        await ensureMinimumResponseTime(startTime, 100);
        throw new Error(`Invalid OAuth provider: ${provider}`);
      }

      // OAuth token exchange and user authentication
      const tokens = await oauthService.exchangeCodeForTokens(provider, validatedCode);
      const userInfo = await oauthService.getUserInfo(provider, tokens.access_token);
      
      // ENHANCED: Validate email using auth system validation if available
      if (userInfo.email && !userInfo.email.includes('@instagram.local') && !userInfo.email.includes('@github.local')) {
        validateOAuthEmail(userInfo.email);
      }
      
      const user = await oauthService.findOrCreateUser(provider, userInfo);
      const token = oauthService.generateToken(user);
      
      // ENHANCED: Use auth service timing function for consistency
      await ensureMinimumResponseTime(startTime, 100);
      
      // ENHANCED: Response format aligned with auth system
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      const callbackUrl = `${frontendUrl}/oauth/callback`;
      const finalRedirect = stateValidation.redirectUrl || '/';
      
      const sanitizedRedirect = sanitization.sanitizeUrl(
        `${callbackUrl}?token=${token}&redirect=${encodeURIComponent(finalRedirect)}`
      );
      
      // ENHANCED: Add success logging like auth system
      console.log(`OAuth login successful: ${user.email} via ${provider}`);
      
      res.redirect(sanitizedRedirect);
      
    } catch (error) {
      await ensureMinimumResponseTime(startTime, 100);
      
      // ENHANCED: Error logging aligned with auth system
      if (error instanceof ApiError) {
        console.warn(`OAuth callback error: ${error.message}`);
      } else {
        console.error('OAuth callback error:', error);
      }
      
      next(error);
    }
  },

  /**
   * ADDED: Get OAuth status for user (aligned with auth system stats endpoint)
   */
  async getOAuthStatus(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('Authentication required'));
      }

      // Get user's OAuth providers using auth service pattern
      const stats = await authService.getUserAuthStats(req.user.id);
      
      res.status(200).json({
        status: 'success',
        data: {
          linkedProviders: stats.linkedProviders,
          authenticationMethods: stats.authenticationMethods
        }
      });
    } catch (error) {
      if (error instanceof ApiError) {
        return next(error);
      }
      console.error('OAuth status error:', error);
      next(ApiError.internal('Failed to retrieve OAuth status'));
    }
  },

  /**
   * ADDED: Unlink OAuth provider (aligned with auth system patterns)
   */
  async unlinkProvider(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      if (!req.user) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(ApiError.unauthorized('Authentication required'));
      }

      const { provider } = validateOAuthInput(req.params.provider, null, null);
      
      // Type guard for OAuth provider
      const isValidOAuthProvider = (provider: string): provider is OAuthProvider => {
        return ['google', 'microsoft', 'github', 'instagram'].includes(provider);
      };

      if (!isValidOAuthProvider(provider)) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(ApiError.badRequest(`Invalid OAuth provider: ${provider}`));
      }
      
      // Ensure user has password before unlinking OAuth
      const stats = await authService.getUserAuthStats(req.user.id);
      
      // Check if user has a password and other auth methods
      const hasPassword = stats.hasPassword || false;
      const linkedProviders = stats.linkedProviders || [];
      
      if (!hasPassword && linkedProviders.length <= 1) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(ApiError.businessLogic(
          'Cannot unlink the only authentication method. Please set a password first.',
          'last_auth_method',
          'oauth'
        ));
      }

      // Check if provider is actually linked
      if (linkedProviders.length > 0 && !linkedProviders.includes(provider)) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(ApiError.notFound(`${provider} account not linked to your profile`));
      }

      // Implement unlink logic
      try {
        // Check if oauthService has unlinkProvider method
        if (typeof oauthService.unlinkProvider === 'function') {
          await oauthService.unlinkProvider(req.user.id, provider);
        } else {
          // Fallback: Direct database operation if service method doesn't exist
          const result = await db.query(
            'DELETE FROM user_oauth_providers WHERE user_id = $1 AND provider = $2 RETURNING id',
            [req.user.id, provider]
          );

          if (result.rowCount === 0) {
            await ensureMinimumResponseTime(startTime, 100);
            return next(ApiError.notFound(`${provider} account not linked to your profile`));
          }
        }

        await ensureMinimumResponseTime(startTime, 100);
        
        res.status(200).json({
          status: 'success',
          message: `Successfully unlinked ${provider} account`
        });
        
      } catch (unlinkError) {
        console.error('OAuth unlink error:', unlinkError);
        await ensureMinimumResponseTime(startTime, 100);
        next(ApiError.internal('Failed to unlink OAuth provider'));
      }
      
    } catch (error) {
      await ensureMinimumResponseTime(startTime, 100);
      next(error);
    }
  },

  // Test utilities - only exposed in test environment
  _testUtils: isTestEnvironment() ? {
    clearStates: () => {
      Object.keys(oauthStates).forEach(key => delete oauthStates[key]);
    },
    stopCleanup: () => {
      stopCleanupInterval();
    },
    getStateCount: () => Object.keys(oauthStates).length,
    // Add state for testing
    addState: (state: string, data: { createdAt: number, redirectUrl?: string }) => {
      oauthStates[state] = data;
    },
    // Get states for debugging
    getStates: () => ({ ...oauthStates })
  } : undefined
};

// Cleanup on process termination
if (!isTestEnvironment()) {
  process.on('SIGTERM', stopCleanupInterval);
  process.on('SIGINT', stopCleanupInterval);
  process.on('exit', stopCleanupInterval);
}