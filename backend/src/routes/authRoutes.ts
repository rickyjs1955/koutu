// /backend/src/routes/authRoutes.ts - Updated with security middleware
import express from 'express';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { authController } from '../controllers/authController';
import { authService } from '../services/authService';
import { authenticate, requireAuth, rateLimitByUser } from '../middlewares/auth';
import { validateAuthTypes, validateBody, validateRequestTypes } from '../middlewares/validate';
import { securityMiddleware } from '../middlewares/security';

import { ApiError } from '../utils/ApiError';

const router = express.Router();

// ==================== APPLY SECURITY MIDDLEWARE ====================

// Apply authentication-specific security to all routes
securityMiddleware.auth.forEach(middleware => {
  router.use(middleware as express.RequestHandler);
});

// ==================== UPDATED VALIDATION SCHEMAS ====================

// Registration validation schema - REMOVED password validation (controller handles it)
const RegisterSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .regex(/^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/, 'Invalid email format')
    .max(254, 'Email address is too long')
    .transform(email => email.toLowerCase().trim()),
  password: z.string()
    .min(1, 'Password is required')
});

// Login validation schema - REMOVED password validation (controller handles it)  
const LoginSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .regex(/^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/, 'Invalid email format')
    .transform(email => email.toLowerCase().trim()),
  password: z.string()
    .min(1, 'Password is required')
});

// Password update validation schema - REMOVED password validation (controller handles it)
const UpdatePasswordSchema = z.object({
  currentPassword: z.string()
    .min(1, 'Current password is required'),
  newPassword: z.string()
    .min(1, 'New password is required')
});

// Email update validation schema - KEPT as-is (no password complexity here)
const UpdateEmailSchema = z.object({
  newEmail: z.string()
    .min(1, 'New email is required')
    .regex(/^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/, 'Invalid email format')
    .max(254, 'Email address is too long')
    .transform(email => email.toLowerCase().trim()),
  password: z.string()
    .min(1, 'Password is required for email changes')
    // REMOVED: Password complexity validation - controller handles this
});

// ==================== ENHANCED CONTROLLERS (UNCHANGED) ====================

// Enhanced register controller using authService
const enhancedRegister = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;
    
    const result = await authService.register({ email, password });
    
    res.status(201).json({
      status: 'success',
      message: 'User registered successfully',
      data: result
    });
  } catch (error) {
    next(error);
  }
};

// Enhanced login controller using authService
const enhancedLogin = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password } = req.body;
    
    const result = await authService.login({ email, password });
    
    res.status(200).json({
      status: 'success',
      message: 'Login successful',
      data: result
    });
  } catch (error) {
    next(error);
  }
};

// Get user profile controller
const getUserProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    const user = await authService.getUserProfile(req.user.id);
    
    res.status(200).json({
      status: 'success',
      data: { user }
    });
  } catch (error) {
    next(error);
  }
};

// Update password controller
const updatePassword = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    const { currentPassword, newPassword } = req.body;
    
    const result = await authService.updatePassword({
      userId: req.user.id,
      currentPassword,
      newPassword,
      requestingUserId: req.user.id // Ensure authorization
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Password updated successfully',
      data: result
    });
  } catch (error) {
    next(error);
  }
};

// Update email controller
const updateEmail = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    const { newEmail, password } = req.body;
    
    const updatedUser = await authService.updateEmail({
      userId: req.user.id,
      newEmail,
      password
    });
    
    res.status(200).json({
      status: 'success',
      message: 'Email updated successfully',
      data: { user: updatedUser }
    });
  } catch (error) {
    next(error);
  }
};

// Get authentication statistics controller
const getAuthStats = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    const stats = await authService.getUserAuthStats(req.user.id);
    
    res.status(200).json({
      status: 'success',
      data: { stats }
    });
  } catch (error) {
    next(error);
  }
};

// Deactivate account controller
const deactivateAccount = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    const { password } = req.body;
    
    const result = await authService.deactivateAccount(req.user.id, password);
    
    res.status(200).json({
      status: 'success',
      message: 'Account deactivated successfully',
      data: result
    });
  } catch (error) {
    next(error);
  }
};

// Validate token controller
const validateToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(ApiError.authentication('Authentication token required'));
    }

    const token = authHeader.substring(7);
    const result = await authService.validateToken(token);
    
    if (result.isValid) {
      res.status(200).json({
        status: 'success',
        message: 'Token is valid',
        data: {
          valid: true,
          user: result.user
        }
      });
    } else {
      res.status(401).json({
        status: 'error',
        message: result.error || 'Invalid token',
        data: {
          valid: false
        }
      });
    }
  } catch (error) {
    next(error);
  }
};

// ==================== ROUTES WITH UPDATED VALIDATION ====================

// Public routes with enhanced validation but NO password complexity checks
router.post('/register', 
  rateLimitByUser(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  validateAuthTypes,                   // Type validation first
  validateBody(RegisterSchema),        // Basic schema validation (no password complexity)
  enhancedRegister                     // Controller handles ALL password validation
);

router.post('/login', 
  rateLimitByUser(10, 15 * 60 * 1000), // 10 attempts per 15 minutes
  validateAuthTypes,                    // Type validation first
  validateBody(LoginSchema),            // Basic schema validation (no password complexity)
  enhancedLogin                         // Controller handles ALL password validation
);

// Token validation endpoint (public but rate limited)
router.post('/validate-token',
  rateLimitByUser(20, 15 * 60 * 1000), // 20 attempts per 15 minutes
  validateToken
);

// Protected routes (require authentication)
router.use(authenticate, requireAuth);

// Profile management
router.get('/me', getUserProfile);
router.get('/profile', getUserProfile); // Alias for /me

// Account management with additional rate limiting and type validation
router.patch('/password', 
  rateLimitByUser(3, 60 * 60 * 1000), // 3 password changes per hour
  validateRequestTypes,                 // General type validation
  validateBody(UpdatePasswordSchema),   // Basic schema validation (no password complexity)
  updatePassword                        // Controller handles ALL password validation
);

router.patch('/email', 
  rateLimitByUser(2, 60 * 60 * 1000), // 2 email changes per hour
  validateRequestTypes,                 // General type validation  
  validateBody(UpdateEmailSchema),      // Basic schema validation (no password complexity)
  updateEmail                           // Controller handles password validation
);

// Authentication statistics
router.get('/stats', getAuthStats);

// Account deactivation (highly restricted)
router.delete('/account', 
  rateLimitByUser(1, 24 * 60 * 60 * 1000), // 1 attempt per day
  validateRequestTypes,                      // Type validation for body
  deactivateAccount                          // Controller handles password validation
);

// ==================== BACKWARD COMPATIBILITY (UNCHANGED) ====================

// Keep original controller endpoints with type validation for legacy support
router.post('/register-legacy', 
  validateAuthTypes,                    // Add type validation
  validateBody(RegisterSchema),         // Basic validation (no password complexity)
  authController.register               // Original controller handles password validation
);

router.post('/login-legacy', 
  validateAuthTypes,                    // Add type validation
  validateBody(LoginSchema),            // Basic validation (no password complexity)
  authController.login                  // Original controller handles password validation
);

router.get('/me-legacy', 
  authenticate, 
  authController.me
);

export { router as authRoutes };