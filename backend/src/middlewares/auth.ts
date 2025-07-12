// src/middlewares/auth.ts

import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import { ApiError } from '../utils/ApiError';
import { userModel } from '../models/userModel';
import { imageModel } from '../models/imageModel';
import { garmentModel } from '../models/garmentModel';
import { polygonModel } from '../models/polygonModel';
import { wardrobeModel } from '../models/wardrobeModel';
import { TestDatabaseConnection } from '../utils/testDatabaseConnection';

// Mobile device tracking
interface DeviceInfo {
  platform: 'android' | 'ios' | 'web';
  version?: string;
  deviceId?: string;
}

// Enhanced user interface for mobile
interface AuthenticatedUser {
  id: string;
  email: string;
  deviceInfo?: DeviceInfo;
  lastRefresh?: number;
}

// Refresh token storage
export const refreshTokenCache = new Map<string, { 
  userId: string; 
  deviceId?: string; 
  expiresAt: number; 
  isRevoked: boolean;
}>();

// Rate limiting cache
export const rateLimitCache = new Map<string, { count: number; resetTime: number }>();

// Store the interval ID for proper cleanup
let cleanupIntervalId: NodeJS.Timeout | null = null;

/**
 * Extract device info from user agent and headers (Flutter compatible)
 */
const extractDeviceInfo = (req: Request): DeviceInfo | undefined => {
  const userAgent = req.headers['user-agent'] || '';
  const platform = req.headers['x-platform'] as string;
  const version = req.headers['x-app-version'] as string;
  const deviceId = req.headers['x-device-id'] as string;

  // Flutter app identification
  if (platform === 'flutter' || userAgent.includes('Dart/')) {
    const isAndroid = userAgent.includes('Android') || platform === 'android';
    const isIOS = userAgent.includes('iOS') || platform === 'ios';
    
    return {
      platform: isAndroid ? 'android' : isIOS ? 'ios' : 'web',
      version,
      deviceId
    };
  }
  
  return undefined;
};

/**
 * Authentication middleware - validates JWT token and sets user info (Flutter compatible)
 */
export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(ApiError.authentication('Authentication token required', 'missing_token'));
    }

    const token = authHeader.substring(7);
    if (!token) {
      return next(ApiError.authentication('Authentication token required', 'missing_token'));
    }

    try {
      // Enhanced JWT verification with Flutter-specific claims
      const decoded = jwt.verify(token, config.jwtSecret) as any;
      
      const user = await userModel.findById(decoded.id);
      if (!user) {
        return next(ApiError.authentication('User not found', 'user_not_found'));
      }

      // Extract device information for mobile tracking
      const deviceInfo = extractDeviceInfo(req);
      
      // Enhanced user object with mobile support
      (req.user as AuthenticatedUser) = {
        id: user.id,
        email: user.email,
        deviceInfo,
        lastRefresh: decoded.lastRefresh
      };
      
      next();
    } catch (jwtError: any) {
      if (jwtError.name === 'TokenExpiredError') {
        // Return additional info for mobile refresh logic
        return next(ApiError.authentication('Authentication token has expired', 'expired_token'));
      } else if (jwtError.name === 'NotBeforeError') {
        return next(ApiError.authentication('Authentication token not yet valid', 'premature_token'));
      } else if (jwtError.name === 'JsonWebTokenError') {
        return next(ApiError.authentication('Invalid authentication token', 'invalid_token'));
      }
      // For unexpected JWT errors, log but still throw a generic error
      console.error('Authentication middleware error:', jwtError);
      return next(ApiError.internal('Authentication error'));
    }
  } catch (error: any) {
    console.error('Authentication middleware error:', error);
    return next(ApiError.internal('Authentication error'));
  }
};

/**
 * Require authentication middleware - ensures user is authenticated
 */
export const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  if (!req.user) {
    return next(ApiError.unauthorized('Authentication required', 'AUTH_REQUIRED'));
  }
  next();
};

/**
 * Generic resource authorization middleware
 */
export const authorizeResource = (
  resourceType: 'image' | 'garment' | 'polygon' | 'wardrobe',
  paramName: string = 'id'
) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('Authentication required for resource access'));
      }

      const resourceId = req.params[paramName];
      if (!resourceId) {
        return next(ApiError.badRequest(`Missing ${paramName} parameter`));
      }

      // Handle array parameters (parameter pollution)
      if (Array.isArray(resourceId)) {
        return next(ApiError.badRequest(`Invalid ${resourceType} ID format`, 'INVALID_UUID'));
      }

      // Validate UUID format
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(resourceId)) {
        return next(ApiError.badRequest(`Invalid ${resourceType} ID format`, 'INVALID_UUID'));
      }

      let resource;
      let ownerId: string;

      switch (resourceType) {
        case 'image':
          resource = await imageModel.findById(resourceId);
          if (!resource) {
            return next(ApiError.notFound('Image not found'));
          }
          ownerId = resource.user_id;
          break;

        case 'garment':
          resource = await garmentModel.findById(resourceId);
          if (!resource) {
            return next(ApiError.notFound('Garment not found'));
          }
          ownerId = resource.user_id;
          break;

        case 'polygon':
          resource = await polygonModel.findById(resourceId);
          if (!resource) {
            return next(ApiError.notFound('Polygon not found'));
          }
          
          // For polygons, check ownership through the associated image
          const associatedImage = await imageModel.findById(resource.original_image_id);
          if (!associatedImage) {
            return next(ApiError.notFound('Associated image not found'));
          }
          ownerId = associatedImage.user_id;
          break;

        case 'wardrobe':
          resource = await wardrobeModel.findById(resourceId);
          if (!resource) {
            return next(ApiError.notFound('Wardrobe not found'));
          }
          ownerId = resource.user_id;
          break;

        default:
          return next(ApiError.internal('Unknown resource type'));
      }

      // Check if user owns the resource
      if (ownerId !== req.user.id) {
        return next(ApiError.authorization(
          `You do not have permission to access this ${resourceType}`,
          resourceType,
          'access'
        ));
      }

      // Add resource context to request for potential use in handlers
      (req as any).resourceContext = {
        resourceType,
        resourceId,
        ownerId
      };

      next();
    } catch (error) {
      console.error('Resource authorization error:', error);
      next(ApiError.internal('Authorization error'));
    }
  };
};

// Convenience middleware functions for specific resource types
export const authorizeImage = authorizeResource('image');
export const authorizeGarment = authorizeResource('garment');
export const authorizePolygon = authorizeResource('polygon');
export const authorizeWardrobe = authorizeResource('wardrobe');

/**
 * Optional authentication middleware - sets user info if token is valid, continues otherwise
 */
export const optionalAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next();
    }

    const token = authHeader.substring(7);
    if (!token) {
      return next();
    }

    try {
      const decoded = jwt.verify(token, config.jwtSecret) as any;
      
      const user = await userModel.findById(decoded.id);
      if (user) {
        req.user = {
          id: user.id,
          email: user.email
        };
      }
    } catch (jwtError: any) {
      // Log the error but continue without authentication
      console.log('Optional auth failed:', jwtError.message);
    }
    
    next();
  } catch (error: any) {
    // Log the error but continue without authentication
    console.log('Optional auth failed:', error.message);
    next();
  }
};

/**
 * Mobile-aware rate limiting middleware by user ID
 */
export const rateLimitByUser = (maxRequests: number = 100, windowMs: number = 15 * 60 * 1000) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Skip rate limiting for unauthenticated requests
    if (!req.user) {
      return next();
    }

    const authUser = req.user as AuthenticatedUser;
    const userId = authUser.id;
    const deviceInfo = authUser.deviceInfo;
    const now = Date.now();
    
    // Create device-specific cache key for mobile apps
    const cacheKey = deviceInfo?.deviceId ? `${userId}:${deviceInfo.deviceId}` : userId;
    const userRateLimit = rateLimitCache.get(cacheKey);

    // Adjust limits for mobile platforms (more lenient for mobile apps)
    let adjustedMaxRequests = maxRequests;
    if (deviceInfo?.platform === 'android' || deviceInfo?.platform === 'ios') {
      adjustedMaxRequests = Math.floor(maxRequests * 1.5); // 50% higher limit for mobile
    }

    if (!userRateLimit || now > userRateLimit.resetTime) {
      // Initialize or reset the rate limit for this user/device
      rateLimitCache.set(cacheKey, { count: 1, resetTime: now + windowMs });
      return next();
    }

    if (userRateLimit.count >= adjustedMaxRequests) {
      const retryAfter = Math.ceil((userRateLimit.resetTime - now) / 1000);
      return next(ApiError.rateLimited(
        `Rate limit exceeded. Try again in ${retryAfter} seconds.`,
        adjustedMaxRequests,
        windowMs,
        retryAfter
      ));
    }

    // Increment the count
    userRateLimit.count++;
    rateLimitCache.set(cacheKey, userRateLimit);
    next();
  };
};

/**
 * Generate refresh token for mobile apps
 */
export const generateRefreshToken = (userId: string, deviceId?: string): string => {
  const refreshToken = jwt.sign(
    { 
      userId, 
      deviceId, 
      type: 'refresh',
      iat: Math.floor(Date.now() / 1000)
    },
    config.jwtSecret,
    { expiresIn: '30d' } // Long-lived refresh token
  );
  
  // Store refresh token with expiration
  refreshTokenCache.set(refreshToken, {
    userId,
    deviceId,
    expiresAt: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
    isRevoked: false
  });
  
  return refreshToken;
};

/**
 * Validate and refresh access token (mobile-specific)
 */
export const refreshAccessToken = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return next(ApiError.authentication('Refresh token required', 'missing_refresh_token'));
    }

    // Check if refresh token exists and is valid
    const tokenData = refreshTokenCache.get(refreshToken);
    if (!tokenData || tokenData.isRevoked || Date.now() > tokenData.expiresAt) {
      return next(ApiError.authentication('Invalid or expired refresh token', 'invalid_refresh_token'));
    }

    try {
      // Verify refresh token signature
      const decoded = jwt.verify(refreshToken, config.jwtSecret) as any;
      
      if (decoded.type !== 'refresh' || decoded.userId !== tokenData.userId) {
        return next(ApiError.authentication('Invalid refresh token', 'invalid_refresh_token'));
      }

      // Get user and generate new access token
      const user = await userModel.findById(decoded.userId);
      if (!user) {
        return next(ApiError.authentication('User not found', 'user_not_found'));
      }

      // Generate new access token with mobile-specific claims
      const deviceInfo = extractDeviceInfo(req);
      const newAccessToken = jwt.sign(
        {
          id: user.id,
          email: user.email,
          deviceId: tokenData.deviceId,
          lastRefresh: Math.floor(Date.now() / 1000)
        },
        config.jwtSecret,
        { expiresIn: '1h' }
      );

      // Optionally rotate refresh token for security
      const shouldRotateRefresh = deviceInfo?.platform === 'android' || deviceInfo?.platform === 'ios';
      let newRefreshToken = refreshToken;
      
      if (shouldRotateRefresh) {
        // Revoke old refresh token
        tokenData.isRevoked = true;
        // Generate new refresh token
        newRefreshToken = generateRefreshToken(user.id, tokenData.deviceId);
      }

      res.json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: 3600, // 1 hour
        tokenType: 'Bearer'
      });
      
    } catch (jwtError: any) {
      console.error('Refresh token verification error:', jwtError);
      return next(ApiError.authentication('Invalid refresh token', 'invalid_refresh_token'));
    }
    
  } catch (error: any) {
    console.error('Token refresh error:', error);
    return next(ApiError.internal('Token refresh failed'));
  }
};

/**
 * Revoke refresh token (logout for mobile)
 */
export const revokeRefreshToken = (req: Request, res: Response, next: NextFunction) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken && refreshTokenCache.has(refreshToken)) {
      const tokenData = refreshTokenCache.get(refreshToken)!;
      tokenData.isRevoked = true;
    }
    
    res.json({ message: 'Token revoked successfully' });
    
  } catch (error: any) {
    console.error('Token revocation error:', error);
    return next(ApiError.internal('Token revocation failed'));
  }
};

/**
 * Clean up expired rate limit and refresh token entries
 */
export const cleanupRateLimitCache = () => {
  const now = Date.now();
  for (const [key, rateLimit] of rateLimitCache.entries()) {
    if (now > rateLimit.resetTime) {
      rateLimitCache.delete(key);
    }
  }
};

/**
 * Clean up expired refresh tokens
 */
export const cleanupRefreshTokens = () => {
  const now = Date.now();
  for (const [token, data] of refreshTokenCache.entries()) {
    if (data.isRevoked || now > data.expiresAt) {
      refreshTokenCache.delete(token);
    }
  }
};

/**
 * Initialize cleanup interval (only in production)
 */
export const initializeCleanup = () => {
  if (process.env.NODE_ENV !== 'test' && !cleanupIntervalId) {
    cleanupIntervalId = setInterval(() => {
      cleanupRateLimitCache();
      cleanupRefreshTokens();
    }, 5 * 60 * 1000); // Clean up every 5 minutes
  }
};

/**
 * Stop cleanup interval and clear cache (for testing and shutdown)
 */
export const stopCleanup = () => {
  if (cleanupIntervalId) {
    clearInterval(cleanupIntervalId);
    cleanupIntervalId = null;
  }
  if (process.env.NODE_ENV === 'test') {
    rateLimitCache.clear();
    refreshTokenCache.clear();
  }
};

// Initialize cleanup only in non-test environments
if (process.env.NODE_ENV !== 'test') {
  initializeCleanup();
}

/**
 * Authorize polygon ownership middleware
 */
export const authorizePolygonOwnership = async (req: Request, res: Response, next: NextFunction) => {
    try {
        if (!req.user) {
            return next(ApiError.unauthorized('Authentication required', 'AUTH_REQUIRED'));
        }

        const polygonId = req.params.id;
        if (!polygonId) {
            return next(ApiError.badRequest('Polygon ID is required'));
        }

        // Query to check if polygon belongs to the authenticated user
        const result = await TestDatabaseConnection.query(
            'SELECT user_id FROM polygons WHERE id = $1 AND status != $2',
            [polygonId, 'deleted']
        );

        if (result.rows.length === 0) {
            return next(ApiError.notFound('Polygon not found'));
        }

        const polygon = result.rows[0];
        if (polygon.user_id !== req.user.id) {
            return next(ApiError.forbidden('You do not have permission to access this polygon', 'INSUFFICIENT_PERMISSIONS'));
        }

        next();
    } catch (error: any) {
        console.error('Polygon authorization error:', error);
        return next(ApiError.internal('Authorization check failed'));
    }
};