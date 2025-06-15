// /backend/src/routes/authRoutes.ts - Updated with proper validators and service integration
import express from 'express';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { authController } from '../controllers/authController';
import { authService } from '../services/authService';
import { authenticate, requireAuth, rateLimitByUser } from '../middlewares/auth';
import { validateBody } from '../middlewares/validate';
import { ApiError } from '../utils/ApiError';


const router = express.Router();

// ==================== VALIDATION SCHEMAS ====================

// Registration validation schema
const RegisterSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .email('Invalid email format')
    .max(254, 'Email address is too long')
    .transform(email => email.toLowerCase().trim()),
  password: z.string()
    .min(8, 'Password must be at least 8 characters long')
    .max(128, 'Password cannot exceed 128 characters')
});

// Login validation schema
const LoginSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .email('Invalid email format')
    .transform(email => email.toLowerCase().trim()),
  password: z.string()
    .min(1, 'Password is required')
});

// Password update validation schema
const UpdatePasswordSchema = z.object({
  currentPassword: z.string()
    .min(1, 'Current password is required'),
  newPassword: z.string()
    .min(8, 'New password must be at least 8 characters long')
    .max(128, 'New password cannot exceed 128 characters')
});

// Email update validation schema
const UpdateEmailSchema = z.object({
  newEmail: z.string()
    .min(1, 'New email is required')
    .email('Invalid email format')
    .max(254, 'Email address is too long')
    .transform(email => email.toLowerCase().trim()),
  password: z.string()
    .min(1, 'Password is required for email changes')
});

// ==================== ENHANCED CONTROLLERS ====================

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

// ==================== ROUTES ====================

// Public routes with rate limiting
router.post('/register', 
  rateLimitByUser(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  validateBody(RegisterSchema), 
  enhancedRegister
);

router.post('/login', 
  rateLimitByUser(10, 15 * 60 * 1000), // 10 attempts per 15 minutes
  validateBody(LoginSchema), 
  enhancedLogin
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

// Account management with additional rate limiting
router.patch('/password', 
  rateLimitByUser(3, 60 * 60 * 1000), // 3 password changes per hour
  validateBody(UpdatePasswordSchema), 
  updatePassword
);

router.patch('/email', 
  rateLimitByUser(2, 60 * 60 * 1000), // 2 email changes per hour
  validateBody(UpdateEmailSchema), 
  updateEmail
);

// Authentication statistics
router.get('/stats', getAuthStats);

// Account deactivation (highly restricted)
router.delete('/account', 
  rateLimitByUser(1, 24 * 60 * 60 * 1000), // 1 attempt per day
  deactivateAccount
);

// ==================== BACKWARD COMPATIBILITY ====================

// Keep original controller endpoints for backward compatibility
router.post('/register-legacy', 
  validateBody(RegisterSchema), 
  authController.register
);

router.post('/login-legacy', 
  validateBody(LoginSchema), 
  authController.login
);

router.get('/me-legacy', 
  authenticate, 
  authController.me
);

export { router as authRoutes };