// /backend/src/middlewares/oauthValidate.ts - OAuth-specific validation middleware
import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';

/**
 * Validate OAuth provider parameter
 */
export const validateOAuthProvider = (req: Request, res: Response, next: NextFunction) => {
  const provider = req.params.provider;
  const validProviders = ['google', 'microsoft', 'github', 'instagram'];
  
  // Handle missing provider
  if (!provider) {
    return next(ApiError.badRequest('OAuth provider is required'));
  }
  
  // Handle array injection
  if (Array.isArray(provider)) {
    return next(ApiError.badRequest('Invalid provider format'));
  }
  
  // Handle object injection
  if (typeof provider === 'object') {
    return next(ApiError.badRequest('Invalid provider format'));
  }
  
  // Convert to string and validate
  const providerStr = String(provider).toLowerCase().trim();
  
  if (!validProviders.includes(providerStr)) {
    return next(ApiError.badRequest(`Invalid OAuth provider: ${providerStr}`));
  }
  
  // Normalize the provider in params
  req.params.provider = providerStr;
  
  next();
};

/**
 * Validate OAuth callback query parameters
 */
export const validateOAuthCallbackParams = (req: Request, res: Response, next: NextFunction) => {
  const { code, state, error } = req.query;
  
  // If there's an OAuth error, allow it through for proper handling
  if (error) {
    return next();
  }
  
  // Validate required parameters for successful callback
  if (!code || !state) {
    return next(ApiError.badRequest('Missing required OAuth callback parameters'));
  }
  
  // Validate parameter types
  if (Array.isArray(code) || Array.isArray(state)) {
    return next(ApiError.badRequest('Invalid parameter format'));
  }
  
  if (typeof code === 'object' || typeof state === 'object') {
    return next(ApiError.badRequest('Invalid parameter format'));
  }
  
  // Validate parameter lengths
  const codeStr = String(code);
  const stateStr = String(state);
  
  if (codeStr.length === 0 || codeStr.length > 1000) {
    return next(ApiError.badRequest('Invalid authorization code'));
  }
  
  if (stateStr.length === 0 || stateStr.length > 255) {
    return next(ApiError.badRequest('Invalid state parameter'));
  }
  
  next();
};

/**
 * Validate OAuth redirect parameter
 */
export const validateOAuthRedirect = (req: Request, res: Response, next: NextFunction) => {
  const { redirect } = req.query;
  
  // Redirect is optional
  if (!redirect) {
    return next();
  }
  
  // Validate type
  if (Array.isArray(redirect) || typeof redirect === 'object') {
    return next(ApiError.badRequest('Invalid redirect format'));
  }
  
  const redirectStr = String(redirect);
  
  // Basic validation - more thorough validation happens in controller
  if (redirectStr.length > 2000) {
    return next(ApiError.badRequest('Redirect URL too long'));
  }
  
  // Check for obvious XSS attempts
  if (redirectStr.includes('<script>') || redirectStr.includes('javascript:')) {
    return next(ApiError.badRequest('Invalid redirect URL'));
  }
  
  next();
};