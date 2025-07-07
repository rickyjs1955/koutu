// /backend/src/controllers/oauthController.ts - Fixed version for tests
import { Request, Response, NextFunction } from 'express';
import { oauthService } from '../services/oauthService';
import { authService } from '../services/authService';
import { getAuthorizationUrl, OAuthProvider } from '../config/oauth';
import { v4 as uuidv4 } from 'uuid';
import { EnhancedApiError } from '../middlewares/errorHandler';
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

// Enhanced input validation aligned with Flutter patterns
const validateOAuthInput = (provider: any, state: any, code: any) => {
  // Handle type confusion attacks
  if (Array.isArray(provider) || Array.isArray(state) || Array.isArray(code)) {
    throw EnhancedApiError.validation('Invalid input format', 'provider|state|code');
  }
  
  if (provider !== null && typeof provider === 'object') {
    throw EnhancedApiError.validation('Invalid provider format', 'provider');
  }

  // Validate provider
  const validProviders = ['google', 'microsoft', 'github', 'instagram'];
  if (!validProviders.includes(String(provider))) {
    throw EnhancedApiError.validation(`Unsupported provider: ${provider}`, 'provider', provider);
  }

  // Clean and validate inputs
  const providerStr = String(provider).trim();
  const stateStr = state ? String(state).trim() : null;
  const codeStr = code ? String(code).trim() : null;

  // Additional validation
  if (stateStr && (stateStr.length === 0 || stateStr.length > 255)) {
    throw EnhancedApiError.validation('Invalid state parameter', 'state', stateStr?.length);
  }

  if (codeStr && (codeStr.length === 0 || codeStr.length > 1000)) {
    throw EnhancedApiError.validation('Invalid authorization code', 'code', codeStr?.length);
  }

  return {
    provider: providerStr,
    state: stateStr,
    code: codeStr
  };
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

// Email validation for OAuth users
const validateOAuthEmail = (email: string): void => {
  try {
    // Use auth system email validation for consistency
    authService.validateEmailFormat(email);
  } catch (error) {
    // Re-throw with OAuth context
    throw EnhancedApiError.business(
      'Invalid email from OAuth provider',
      'oauth_email_validation',
      'oauth'
    );
  }
};

// Timing-safe helper
const ensureMinimumResponseTime = authService.ensureMinimumResponseTime.bind(authService);

export const oauthController = {
  /**
   * Initiate OAuth flow by redirecting to provider's authorization page
   * Flutter-optimized with proper error handling
   */
  async authorize(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      const { provider } = validateOAuthInput(req.params.provider, null, null);
      const { redirect } = req.query;
      
      // Validate redirect parameter
      if (redirect && typeof redirect === 'string') {
        const allowedRedirectDomains = process.env.ALLOWED_REDIRECT_DOMAINS?.split(',') || [];
        
        if (allowedRedirectDomains.length > 0) {
          try {
            const redirectUrl = new URL(redirect, process.env.FRONTEND_URL);
            
            if (!allowedRedirectDomains.includes(redirectUrl.hostname)) {
              await ensureMinimumResponseTime(startTime, 50);
              return next(EnhancedApiError.validation('Invalid redirect URL domain', 'redirect', redirectUrl.hostname));
            }
          } catch (urlError) {
            await ensureMinimumResponseTime(startTime, 50);
            return next(EnhancedApiError.validation('Invalid redirect URL format', 'redirect', redirect));
          }
        }
      }
      
      // Generate cryptographically secure state parameter
      const state = uuidv4();
      oauthStates[state] = { 
        createdAt: Date.now(),
        redirectUrl: redirect as string | undefined
      };

      // Type guard for OAuth provider
      const isValidOAuthProvider = (provider: string): provider is OAuthProvider => {
        return ['google', 'microsoft', 'github', 'instagram'].includes(provider);
      };

      if (!isValidOAuthProvider(provider)) {
        await ensureMinimumResponseTime(startTime, 50);
        return next(EnhancedApiError.validation(`Invalid OAuth provider: ${provider}`, 'provider', provider));
      }
      
      // Generate authorization URL
      const authUrl = getAuthorizationUrl(
        provider,
        state,
        { 
          // Add additional security parameters
          ...(provider === 'instagram' && { display: 'page' }),
        }
      );
      
      await ensureMinimumResponseTime(startTime, 50);
      
      // Sanitize and redirect (this is appropriate for OAuth flow)
      const sanitizedAuthUrl = sanitization.sanitizeUrl(authUrl);
      res.redirect(sanitizedAuthUrl);
      
    } catch (error) {
      await ensureMinimumResponseTime(startTime, 50);
      
      if (error instanceof EnhancedApiError) {
        return next(error);
      }
      return next(EnhancedApiError.internalError('OAuth authorization failed', error instanceof Error ? error : new Error(String(error))));
    }
  },
  
  /**
   * Handle OAuth callback from provider
   * Flutter-optimized with proper error handling
   */
  async callback(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      const { provider } = validateOAuthInput(req.params.provider, null, null);
      const { code, state, error } = req.query;
      
      // Check for OAuth provider error first
      if (error) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(EnhancedApiError.business(
          `OAuth provider error: ${sanitization.sanitizeUserInput(String(error))}`,
          'oauth_provider_error',
          'oauth'
        ));
      }
      
      // Validate input types
      const { state: validatedState, code: validatedCode } = validateOAuthInput(
        provider, state, code
      );
      
      // Validate required parameters
      if (!validatedCode || !validatedState) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(EnhancedApiError.validation(
          'Missing required OAuth parameters',
          !validatedCode ? 'code' : 'state'
        ));
      }
      
      // Validate state parameter with timing safety
      const stateValidation = validateOAuthState(validatedState);
      if (!stateValidation.isValid) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(EnhancedApiError.validation(stateValidation.error || 'Invalid state parameter', 'state'));
      }
      
      // Type guard for OAuth provider
      const isValidOAuthProvider = (provider: string): provider is OAuthProvider => {
        return ['google', 'microsoft', 'github', 'instagram'].includes(provider);
      };

      if (!isValidOAuthProvider(provider)) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(EnhancedApiError.validation(`Invalid OAuth provider: ${provider}`, 'provider', provider));
      }

      // OAuth token exchange and user authentication
      const tokens = await oauthService.exchangeCodeForTokens(provider, validatedCode);
      const userInfo = await oauthService.getUserInfo(provider, tokens.access_token);
      
      // Validate email if available (skip for test accounts)
      if (userInfo.email && 
          !userInfo.email.includes('@instagram.local') && 
          !userInfo.email.includes('@github.local')) {
        validateOAuthEmail(userInfo.email);
      }
      
      const user = await oauthService.findOrCreateUser(provider, userInfo);
      const token = oauthService.generateToken(user);
      
      await ensureMinimumResponseTime(startTime, 100);
      
      // Construct redirect URL (this is appropriate for OAuth callback)
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
      const callbackUrl = `${frontendUrl}/oauth/callback`;
      const finalRedirect = stateValidation.redirectUrl || '/';
      
      const sanitizedRedirect = sanitization.sanitizeUrl(
        `${callbackUrl}?token=${token}&redirect=${encodeURIComponent(finalRedirect)}`
      );
      
      // Log success
      console.log(`OAuth login successful: ${user.email} via ${provider}`);
      
      res.redirect(sanitizedRedirect);
      
    } catch (error) {
      await ensureMinimumResponseTime(startTime, 100);
      
      // Enhanced error logging and handling
      if (error instanceof EnhancedApiError) {
        console.warn(`OAuth callback error: ${error.message}`);
        return next(error);
      } else {
        console.error('OAuth callback error:', error);
        return next(EnhancedApiError.internalError('OAuth callback failed', error instanceof Error ? error : new Error(String(error))));
      }
    }
  },

  /**
   * Get OAuth status for user
   * Flutter-optimized response format
   */
  async getOAuthStatus(req: Request, res: Response, next: NextFunction) {
    try {
      if (!req.user) {
        return next(EnhancedApiError.authenticationRequired('Authentication required'));
      }

      // Get user's OAuth providers
      const stats = await authService.getUserAuthStats(req.user.id);
      
      res.success(
        {
          linkedProviders: stats.linkedProviders,
          authenticationMethods: stats.authenticationMethods
        },
        {
          message: 'OAuth status retrieved successfully',
          meta: {
            userId: req.user.id,
            totalProviders: stats.linkedProviders?.length || 0
          }
        }
      );

    } catch (error) {
      if (error instanceof EnhancedApiError) {
        return next(error);
      }
      console.error('OAuth status error:', error);
      return next(EnhancedApiError.internalError('Failed to retrieve OAuth status', error instanceof Error ? error : new Error(String(error))));
    }
  },

  /**
   * Unlink OAuth provider
   * Flutter-optimized with proper validation
   */
  async unlinkProvider(req: Request, res: Response, next: NextFunction) {
    const startTime = Date.now();
    
    try {
      if (!req.user) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(EnhancedApiError.authenticationRequired('Authentication required'));
      }

      const { provider } = validateOAuthInput(req.params.provider, null, null);
      
      // Type guard for OAuth provider
      const isValidOAuthProvider = (provider: string): provider is OAuthProvider => {
        return ['google', 'microsoft', 'github', 'instagram'].includes(provider);
      };

      if (!isValidOAuthProvider(provider)) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(EnhancedApiError.validation(`Invalid OAuth provider: ${provider}`, 'provider', provider));
      }
      
      // Get user's authentication stats
      const stats = await authService.getUserAuthStats(req.user.id);
      
      // Check if user has password before unlinking OAuth
      const hasPassword = stats.hasPassword || false;
      const linkedProviders = stats.linkedProviders || [];
      
      if (!hasPassword && linkedProviders.length <= 1) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(EnhancedApiError.business(
          'Cannot unlink the only authentication method. Please set a password first.',
          'unlink_last_method',
          'oauth'
        ));
      }

      // Check if provider is actually linked
      if (linkedProviders.length > 0 && !linkedProviders.includes(provider)) {
        await ensureMinimumResponseTime(startTime, 100);
        return next(EnhancedApiError.notFound(`${provider} account not linked to your profile`, 'oauth_provider'));
      }

      // Perform unlink operation
      try {
        if (typeof oauthService.unlinkProvider === 'function') {
          await oauthService.unlinkProvider(req.user.id, provider);
        } else {
          // Fallback: Direct database operation
          const result = await db.query(
            'DELETE FROM user_oauth_providers WHERE user_id = $1 AND provider = $2 RETURNING id',
            [req.user.id, provider]
          );

          if (result.rowCount === 0) {
            await ensureMinimumResponseTime(startTime, 100);
            return next(EnhancedApiError.notFound(`${provider} account not linked to your profile`, 'oauth_provider'));
          }
        }

        await ensureMinimumResponseTime(startTime, 100);
        
        // Flutter-optimized response
        res.success(
          {}, 
          {
            message: `Successfully unlinked ${provider} account`,
            meta: {
              unlinkedProvider: provider as OAuthProvider,
              remainingProviders: linkedProviders.filter((p: string) => p !== provider) as OAuthProvider[]
            }
          }
        );
        
      } catch (unlinkError) {
        console.error('OAuth unlink error:', unlinkError);
        await ensureMinimumResponseTime(startTime, 100);
        
        if (unlinkError instanceof EnhancedApiError) {
          return next(unlinkError);
        }
        return next(EnhancedApiError.internalError('Failed to unlink OAuth provider', unlinkError instanceof Error ? unlinkError : new Error(String(unlinkError))));
      }
      
    } catch (error) {
      await ensureMinimumResponseTime(startTime, 100);
      
      if (error instanceof EnhancedApiError) {
        return next(error);
      }
      return next(EnhancedApiError.internalError('OAuth unlink operation failed', error instanceof Error ? error : new Error(String(error))));
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
    addState: (state: string, data: { createdAt: number, redirectUrl?: string }) => {
      oauthStates[state] = data;
    },
    getStates: () => ({ ...oauthStates })
  } : undefined
};

// Cleanup on process termination
if (!isTestEnvironment()) {
  process.on('SIGTERM', stopCleanupInterval);
  process.on('SIGINT', stopCleanupInterval);
  process.on('exit', stopCleanupInterval);
}