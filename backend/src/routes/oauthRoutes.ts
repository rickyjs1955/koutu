// backend/src/routes/oauthRoutes.ts - Enhanced with DELETE support and proper middleware
import express from 'express';
import { oauthController } from '../controllers/oauthController';
import { securityMiddleware } from '../middlewares/security';
import { authenticate, requireAuth, rateLimitByUser } from '../middlewares/auth';
import { validateOAuthTypes, validateOAuthProvider } from '../middlewares/validate';
import { ApiError } from '../utils/ApiError';
import { config } from '../config'; // Import your config to check NODE_ENV

const router = express.Router();

// ==================== ENHANCED SECURITY MIDDLEWARE INTEGRATION ====================

// Apply OAuth-specific security middleware (aligned with auth system)
securityMiddleware.auth.forEach(middleware => {
  router.use(middleware as express.RequestHandler);
});

// ==================== ENHANCED OAUTH ROUTES ====================

// Public OAuth routes (initiation and callback)
router.get('/:provider/authorize', 
  validateOAuthProvider,                // Validate provider parameter
  rateLimitByUser(10, 15 * 60 * 1000),  // 10 OAuth attempts per 15 minutes (aligned with auth)
  oauthController.authorize
);

router.get('/:provider/callback', 
  validateOAuthProvider,                 // Validate provider parameter
  validateOAuthTypes,                    // Validate query parameters 
  rateLimitByUser(20, 15 * 60 * 1000),   // 20 callbacks per 15 minutes
  oauthController.callback
);

// ==================== PROTECTED OAUTH MANAGEMENT ROUTES ====================
// These routes require authentication and follow auth system patterns

// Get OAuth status for authenticated user (aligned with auth system's /stats endpoint)
router.get('/status',
  authenticate,                          // Authentication middleware
  requireAuth,                           // Ensure user is authenticated
  rateLimitByUser(30, 15 * 60 * 1000),   // 30 status checks per 15 minutes
  oauthController.getOAuthStatus
);

// IMPORTANT: DELETE method for unlinking OAuth providers
const unlinkMiddleware = [
  authenticate,                           // Authentication middleware
  requireAuth,                            // Ensure user is authenticated
  validateOAuthProvider,                  // Validate provider parameter
  // Conditionally apply CSRF protection:
  ...(config.nodeEnv !== 'test' ? [securityMiddleware.csrf as express.RequestHandler] : []), 
  rateLimitByUser(5, 60 * 60 * 1000),     // 5 unlink attempts per hour (aligned with auth)
];

router.delete('/:provider/unlink',
  ...unlinkMiddleware,
  oauthController.unlinkProvider
);

// Alternative: Also support POST for environments that don't support DELETE
router.post('/:provider/unlink',
  ...unlinkMiddleware, // Use the same middleware array
  oauthController.unlinkProvider
);

// ==================== ADDITIONAL SECURITY ENHANCEMENTS ====================

// Add route-specific security headers
router.use((req, res, next) => {
  // OAuth-specific security headers
  res.setHeader('X-OAuth-Version', '2.0');
  
  // Prevent caching of OAuth responses
  if (req.path.includes('/callback') || req.path.includes('/status') || req.path.includes('/unlink')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
  }
  
  // Add OAuth-specific permissions policy
  res.setHeader('Permissions-Policy', 
    'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
  );
  
  next();
});

// ==================== ERROR HANDLING ALIGNMENT ====================

// Add OAuth-specific error handling that aligns with auth system
router.use((error: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  // Log OAuth-specific errors with context
  if (error.message?.includes('oauth') || error.message?.includes('OAuth')) {
    console.warn(`OAuth route error on ${req.path}:`, {
      provider: req.params.provider,
      method: req.method,
      error: error.message,
      userAgent: req.get('User-Agent'),
      ip: req.ip
    });
  }
  
  // Pass to main error handler
  next(error);
});

router.get(['/authorize', '//authorize'], (req, res, next) => {
  // The provider is missing or empty, handle as bad request
  return next(ApiError.badRequest('OAuth provider is required in the URL.'));
});

// Existing route for specific providers (duplicate, can be removed if the first one is used)
router.get('/:provider/authorize',
  validateOAuthProvider,
  rateLimitByUser(10, 15 * 60 * 1000),
  oauthController.authorize
);

export { router as oauthRoutes };