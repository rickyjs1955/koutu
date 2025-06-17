// /backend/src/routes/oauthRoutes.ts - Enhanced Version
import express from 'express';
import { oauthController } from '../controllers/oauthController';
import { securityMiddleware } from '../middlewares/security';
import { rateLimitByUser } from '../middlewares/auth';
import { validateOAuthTypes, validateOAuthProvider } from '../middlewares/validate';

const router = express.Router();

// Apply OAuth-specific security middleware
securityMiddleware.auth.forEach(middleware => {
  router.use(middleware as express.RequestHandler);
});

// Enhanced OAuth routes with validation and rate limiting
router.get('/:provider/authorize', 
  validateOAuthProvider,           // Validate provider parameter
  rateLimitByUser(10, 15 * 60 * 1000), // 10 OAuth attempts per 15 minutes
  oauthController.authorize
);

router.get('/:provider/callback', 
  validateOAuthProvider,           // Validate provider parameter
  validateOAuthTypes,              // Validate query parameters
  rateLimitByUser(20, 15 * 60 * 1000), // 20 callbacks per 15 minutes
  oauthController.callback
);

export { router as oauthRoutes };