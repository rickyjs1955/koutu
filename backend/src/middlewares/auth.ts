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

// Rate limiting cache
export const rateLimitCache = new Map<string, { count: number; resetTime: number }>();

// Store the interval ID for proper cleanup
let cleanupIntervalId: NodeJS.Timeout | null = null;

/**
 * Authentication middleware - validates JWT token and sets user info
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
      const decoded = jwt.verify(token, config.jwtSecret) as any;
      
      const user = await userModel.findById(decoded.id);
      if (!user) {
        return next(ApiError.authentication('User not found', 'user_not_found'));
      }

      req.user = {
        id: user.id,
        email: user.email
      };
      
      next();
    } catch (jwtError: any) {
      if (jwtError.name === 'TokenExpiredError') {
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
      req.resourceContext = {
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
 * Rate limiting middleware by user ID
 */
export const rateLimitByUser = (maxRequests: number = 100, windowMs: number = 15 * 60 * 1000) => {
  return (req: Request, res: Response, next: NextFunction) => {
    // Skip rate limiting for unauthenticated requests
    if (!req.user) {
      return next();
    }

    const userId = req.user.id;
    const now = Date.now();
    const userRateLimit = rateLimitCache.get(userId);

    if (!userRateLimit || now > userRateLimit.resetTime) {
      // Initialize or reset the rate limit for this user
      rateLimitCache.set(userId, { count: 1, resetTime: now + windowMs });
      return next();
    }

    if (userRateLimit.count >= maxRequests) {
      const retryAfter = Math.ceil((userRateLimit.resetTime - now) / 1000);
      return next(ApiError.rateLimited(
        `Rate limit exceeded. Try again in ${retryAfter} seconds.`,
        maxRequests,
        windowMs,
        retryAfter
      ));
    }

    // Increment the count
    userRateLimit.count++;
    rateLimitCache.set(userId, userRateLimit);
    next();
  };
};

/**
 * Clean up expired rate limit entries
 */
export const cleanupRateLimitCache = () => {
  const now = Date.now();
  for (const [userId, rateLimit] of rateLimitCache.entries()) {
    if (now > rateLimit.resetTime) {
      rateLimitCache.delete(userId);
    }
  }
};

/**
 * Initialize cleanup interval (only in production)
 */
export const initializeCleanup = () => {
  if (process.env.NODE_ENV !== 'test' && !cleanupIntervalId) {
    cleanupIntervalId = setInterval(cleanupRateLimitCache, 5 * 60 * 1000);
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
  }
};

// Initialize cleanup only in non-test environments
if (process.env.NODE_ENV !== 'test') {
  initializeCleanup();
}