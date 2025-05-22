// /backend/src/middlewares/auth.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { ApiError } from '../utils/ApiError';
import { userModel } from '../models/userModel';

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
      };
    }
  }
}

export const authenticate = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    // Get the token from the Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return next(ApiError.unauthorized('Authentication required'));
    }

    // Verify JWT token
    let decoded;
    
    // Handle JWT verification errors - no try/catch to let outer catch handle it
    try {
      decoded = jwt.verify(token, config.jwtSecret as string) as {
        id: string;
        email: string;
      };
    } catch (error: any) {
      // Differentiate between JWT-specific errors and other unexpected errors
      if (error.name === 'JsonWebTokenError' || 
          error.name === 'TokenExpiredError' || 
          error.name === 'NotBeforeError') {
        // These are standard JWT validation errors
        return next(ApiError.unauthorized('Invalid token'));
      }
      // Any other error during token verification is unexpected
      return next(ApiError.internal('Authentication error')); 
    }

    // Find the user
    const user = await userModel.findById(decoded.id);
    if (!user) {
      return next(ApiError.unauthorized('Invalid token'));
    }

    // Attach user to request
    req.user = {
      id: user.id,
      email: user.email
    };

    next();
  } catch (error: any) {
    // This outer catch block handles errors from other parts of the try block,
    // like userModel.findById or other unexpected issues.
    // The JWT-specific checks here are a fallback, though errors from jwt.verify
    // should now be fully handled by the inner try-catch.
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError' || error.name === 'NotBeforeError') {
      return next(ApiError.unauthorized('Invalid token'));
    }
    
    return next(ApiError.internal('Authentication error'));
  }
};