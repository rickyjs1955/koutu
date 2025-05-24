// /backend/src/middlewares/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { ApiError } from '../utils/ApiError';
import { userModel } from '../models/userModel';
import { imageModel } from '../models/imageModel';
import { garmentModel } from '../models/garmentModel';
import { polygonModel } from '../models/polygonModel';
import { wardrobeModel } from '../models/wardrobeModel';

// Extend Express Request type to include user and resource context
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
      };
      resourceContext?: {
        resourceType: string;
        resourceId: string;
        ownerId?: string;
      };
    }
  }
}

/**
 * Middleware to authenticate users using JWT
 * This middleware checks for a valid JWT in the Authorization header
 * and attaches the user information to the request object.
 */
export const authenticate = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    // Get the token from the Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(ApiError.authentication('Authentication token required', 'missing_token'));
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return next(ApiError.authentication('Authentication token required', 'missing_token'));
    }

    // Verify JWT token
    let decoded;
    
    try {
      decoded = jwt.verify(token, config.jwtSecret as string) as {
        id: string;
        email: string;
      };
    } catch (error: any) {
      if (error.name === 'JsonWebTokenError') {
        return next(ApiError.authentication('Invalid authentication token', 'invalid_token'));
      }
      if (error.name === 'TokenExpiredError') {
        return next(ApiError.authentication('Authentication token has expired', 'expired_token'));
      }
      if (error.name === 'NotBeforeError') {
        return next(ApiError.authentication('Authentication token not yet valid', 'premature_token'));
      }
      return next(ApiError.internal('Authentication error'));
    }

    // Find the user
    const user = await userModel.findById(decoded.id);
    if (!user) {
      return next(ApiError.authentication('User not found', 'user_not_found'));
    }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email
    };

    next();
  } catch (error: any) {
    console.error('Authentication middleware error:', error);
    return next(ApiError.internal('Authentication error'));
  }
};

/**
 * Middleware that requires an authenticated user
 * This can be used on routes that should only be accessible to authenticated users
 */
export const requireAuth = (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  if (!req.user) {
    return next(ApiError.unauthorized('Authentication required', 'AUTH_REQUIRED'));
  }
  next();
};

/**
 * Resource authorization middleware factory
 * Checks if the authenticated user owns/can access the specified resource
 */
export const authorizeResource = (
  resourceType: 'image' | 'garment' | 'polygon' | 'wardrobe',
  paramName: string = 'id'
) => {
  return async (req: Request, _res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return next(ApiError.unauthorized('Authentication required for resource access'));
      }

      const resourceId = req.params[paramName];
      if (!resourceId) {
        return next(ApiError.badRequest(`Missing ${paramName} parameter`));
      }

      // Validate UUID format
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      if (!uuidRegex.test(resourceId)) {
        return next(ApiError.badRequest(`Invalid ${resourceType} ID format`, 'INVALID_UUID'));
      }

      let resource;
      let ownerId;

      // Check resource ownership based on type
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
          // For polygons, we need to check the image ownership
          const image = await imageModel.findById(resource.original_image_id);
          if (!image) {
            return next(ApiError.notFound('Associated image not found'));
          }
          ownerId = image.user_id;
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

      // Check ownership
      if (ownerId !== req.user.id) {
        return next(ApiError.authorization(
          `You do not have permission to access this ${resourceType}`,
          resourceType,
          'access'
        ));
      }

      // Add resource context to request for use in controllers
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

/**
 * Middleware to authorize image access
 */
export const authorizeImage = authorizeResource('image');

/**
 * Middleware to authorize garment access
 */
export const authorizeGarment = authorizeResource('garment');

/**
 * Middleware to authorize polygon access
 */
export const authorizePolygon = authorizeResource('polygon');

/**
 * Middleware to authorize wardrobe access
 */
export const authorizeWardrobe = authorizeResource('wardrobe');

/**
 * Middleware to authorize access to image by imageId parameter
 */
export const authorizeImageByImageId = authorizeResource('image', 'imageId');

/**
 * Middleware to authorize access to wardrobe item
 */
export const authorizeWardrobeItem = authorizeResource('garment', 'itemId');

/**
 * Optional authentication middleware - doesn't fail if no token provided
 * Useful for endpoints that work differently for authenticated vs anonymous users
 */
export const optionalAuth = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      // No token provided, continue without authentication
      return next();
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return next();
    }

    try {
      const decoded = jwt.verify(token, config.jwtSecret as string) as {
        id: string;
        email: string;
      };

      const user = await userModel.findById(decoded.id);
      if (user) {
        req.user = {
          id: user.id,
          email: user.email
        };
      }
    } catch (error) {
      // Invalid token, but we don't fail - just continue without user
      console.log('Optional auth failed:', error);
    }

    next();
  } catch (error) {
    // Don't fail on optional auth errors
    next();
  }
};

/**
 * Rate limiting by user ID
 * Simple implementation - could be enhanced with Redis for production
 */
const userRequestCounts = new Map<string, { count: number; resetTime: number }>();

export const rateLimitByUser = (
  maxRequests: number = 100,
  windowMs: number = 15 * 60 * 1000 // 15 minutes
) => {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(); // Skip rate limiting for unauthenticated requests
    }

    const userId = req.user.id;
    const now = Date.now();
    const userLimit = userRequestCounts.get(userId);

    if (!userLimit || now > userLimit.resetTime) {
      // First request or window expired
      userRequestCounts.set(userId, {
        count: 1,
        resetTime: now + windowMs
      });
      return next();
    }

    if (userLimit.count >= maxRequests) {
      const retryAfter = Math.ceil((userLimit.resetTime - now) / 1000);
      return next(ApiError.rateLimited(
        `Rate limit exceeded. Try again in ${retryAfter} seconds.`,
        maxRequests,
        windowMs,
        retryAfter
      ));
    }

    // Increment count
    userLimit.count++;
    userRequestCounts.set(userId, userLimit);
    next();
  };
};

/**
 * Cleanup expired rate limit entries (call periodically)
 */
export const cleanupRateLimitCache = () => {
  const now = Date.now();
  for (const [userId, userLimit] of userRequestCounts.entries()) {
    if (now > userLimit.resetTime) {
      userRequestCounts.delete(userId);
    }
  }
};

// Clean up every 5 minutes
setInterval(cleanupRateLimitCache, 5 * 60 * 1000);