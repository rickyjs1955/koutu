// /backend/src/routes/authRoutes.ts - Updated with security middleware and mobile support
import express from 'express';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { authController } from '../controllers/authController';
import { authService } from '../services/authService';
import { authenticate, requireAuth, rateLimitByUser } from '../middlewares/auth';
import { validateAuthTypes, validateBody, validateRequestTypes } from '../middlewares/validate';
import { securityMiddleware } from '../middlewares/security';
import { ApiError } from '../utils/ApiError';
import { 
  BiometricLoginSchema, 
  DeviceRegistrationSchema,
  MobileValidation 
} from '../../../shared/src/schemas';

declare global {
  namespace Express {
    interface Request {
      user?: any;
      device?: {
        id: string;
        type: 'ios' | 'android' | 'web';
        name?: string;
      };
    }
  }
}

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

// ==================== MOBILE-SPECIFIC VALIDATION SCHEMAS ====================

// Define safe fallback patterns for testing
const DEVICE_ID_PATTERN = MobileValidation?.MOBILE_PATTERNS?.deviceId || /^[a-zA-Z0-9\-_]{16,128}$/;
const PUSH_TOKEN_PATTERN = MobileValidation?.MOBILE_PATTERNS?.pushToken || /^[a-zA-Z0-9\-_:]{32,512}$/;

// Mobile registration schema with device info
const MobileRegisterSchema = RegisterSchema.extend({
  device_id: z.string().regex(DEVICE_ID_PATTERN),
  device_type: z.enum(['ios', 'android']),
  device_name: z.string().max(100).optional(),
  push_token: z.string().regex(PUSH_TOKEN_PATTERN).optional()
});

// Mobile login schema with device tracking
const MobileLoginSchema = LoginSchema.extend({
  device_id: z.string().regex(DEVICE_ID_PATTERN),
  device_type: z.enum(['ios', 'android']),
  remember_device: z.boolean().default(false)
});

// Biometric registration schema
const BiometricRegistrationSchema = z.object({
  biometric_type: z.enum(['fingerprint', 'face_id', 'touch_id']),
  device_id: z.string().regex(DEVICE_ID_PATTERN),
  public_key: z.string() // For secure key exchange
});

// Refresh token schema
const RefreshTokenSchema = z.object({
  refresh_token: z.string(),
  device_id: z.string().regex(DEVICE_ID_PATTERN).optional()
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

// ==================== MOBILE-SPECIFIC CONTROLLERS ====================

// Mobile register controller with device registration
const mobileRegister = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, device_id, device_type, device_name, push_token } = req.body;
    
    // Register user first
    const authResult = await authService.register({ email, password });
    
    // Register device (mock implementation - would call device service)
    const deviceRegistered = true; // Mock success
    
    res.status(201).json({
      status: 'success',
      message: 'User registered successfully',
      data: {
        ...authResult,
        device_registered: deviceRegistered,
        sync_required: false,
        server_time: new Date().toISOString(),
        features: {
          biometric_available: true,
          offline_mode_available: true,
          push_notifications_available: Boolean(push_token)
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Mobile login controller with device tracking
const mobileLogin = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { email, password, device_id, device_type, remember_device } = req.body;
    
    const result = await authService.login({ email, password });
    
    // Track device login (mock implementation)
    const deviceTracked = true; // Mock success
    
    res.status(200).json({
      status: 'success',
      message: 'Login successful',
      data: {
        ...result,
        refresh_token: remember_device ? `refresh_${result.token}_${device_id}` : undefined,
        expires_in: 3600, // 1 hour
        device_registered: deviceTracked,
        sync_required: true,
        server_time: new Date().toISOString(),
        features: {
          biometric_available: true,
          offline_mode_available: true,
          push_notifications_available: true
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Biometric registration controller
const registerBiometric = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    const { biometric_type, device_id, public_key } = req.body;
    
    // Mock biometric registration
    const biometricId = `bio_${req.user.id}_${device_id}`;
    const challenge = Buffer.from(Math.random().toString()).toString('base64');
    
    res.status(200).json({
      status: 'success',
      message: 'Biometric registration successful',
      data: {
        biometric_id: biometricId,
        biometric_type,
        challenge,
        expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() // 30 days
      }
    });
  } catch (error) {
    next(error);
  }
};

// Biometric login controller
const biometricLogin = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { user_id, biometric_id, device_id, challenge } = req.body;
    
    // Mock biometric verification
    const isValid = biometric_id.includes(user_id) && biometric_id.includes(device_id);
    
    if (!isValid) {
      return next(ApiError.authentication('Biometric authentication failed'));
    }
    
    // Generate token for user (mock implementation)
    const token = `token_bio_${user_id}_${Date.now()}`;
    
    res.status(200).json({
      status: 'success',
      message: 'Biometric login successful',
      data: {
        token,
        refresh_token: `refresh_bio_${token}`,
        expires_in: 3600,
        user: {
          id: user_id,
          email: 'user@example.com' // Mock data
        }
      }
    });
  } catch (error) {
    next(error);
  }
};

// Device registration controller
const registerDevice = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.user) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    const { device_id, device_type, device_name, push_token, app_version, os_version } = req.body;
    
    // Mock device registration
    const registered = true;
    
    res.status(200).json({
      status: 'success',
      message: 'Device registered successfully',
      data: {
        device_id,
        device_type,
        device_name,
        registered,
        push_notifications_enabled: Boolean(push_token),
        biometric_available: ['ios', 'android'].includes(device_type),
        app_version,
        os_version
      }
    });
  } catch (error) {
    console.error('Device registration error:', error);
    next(error);
  }
};

// Refresh token controller
const refreshToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refresh_token, device_id } = req.body;
    
    // Mock refresh token validation
    if (!refresh_token.startsWith('refresh_')) {
      return next(ApiError.authentication('Invalid refresh token'));
    }
    
    // Generate new tokens
    const newToken = `token_refreshed_${Date.now()}`;
    const newRefreshToken = `refresh_${newToken}`;
    
    res.status(200).json({
      status: 'success',
      message: 'Token refreshed successfully',
      data: {
        token: newToken,
        refresh_token: newRefreshToken,
        expires_in: 3600
      }
    });
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

// ==================== MOBILE-SPECIFIC ROUTES ====================

// Mobile authentication endpoints
router.post('/mobile/register',
  rateLimitByUser(5, 15 * 60 * 1000), // 5 attempts per 15 minutes
  validateBody(MobileRegisterSchema),
  mobileRegister
);

router.post('/mobile/login',
  rateLimitByUser(10, 15 * 60 * 1000), // 10 attempts per 15 minutes
  validateBody(MobileLoginSchema),
  mobileLogin
);

// Biometric authentication endpoints
router.post('/biometric/register',
  authenticate,
  requireAuth,
  rateLimitByUser(3, 60 * 60 * 1000), // 3 attempts per hour
  validateBody(BiometricRegistrationSchema),
  registerBiometric
);

router.post('/biometric/login',
  rateLimitByUser(20, 15 * 60 * 1000), // 20 attempts per 15 minutes
  validateBody(BiometricLoginSchema),
  biometricLogin
);

// Device management endpoints
router.post('/device/register',
  authenticate,
  requireAuth,
  rateLimitByUser(5, 60 * 60 * 1000), // 5 attempts per hour
  validateBody(z.object({
    device_id: z.string(),
    device_type: z.enum(['ios', 'android']),
    device_name: z.string(),
    push_token: z.string().optional(),
    app_version: z.string(),
    os_version: z.string()
  })),
  registerDevice
);

// Token refresh endpoint
router.post('/refresh',
  rateLimitByUser(30, 60 * 60 * 1000), // 30 attempts per hour
  validateBody(RefreshTokenSchema),
  refreshToken
);

// Mobile-specific profile endpoint with minimal data
router.get('/mobile/profile',
  authenticate,
  requireAuth,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const user = await authService.getUserProfile(req.user.id);
      
      // Return minimal mobile-optimized response
      res.status(200).json({
        status: 'success',
        data: {
          user: {
            id: user.id,
            email: user.email,
            // Additional fields would come from an extended user service
            // For now, return minimal data
            preferences: {
              notifications_enabled: true,
              theme: 'system'
            }
          }
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

export { router as authRoutes };