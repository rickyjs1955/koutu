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
  res: Response,
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

    // Verify the token
    try {
      const decoded = jwt.verify(token, config.jwtSecret as string) as {
        id: string;
        email: string;
      };

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
    } catch (error) {
      return next(ApiError.unauthorized('Invalid token'));
    }
  } catch (error) {
    return next(ApiError.internal('Authentication error'));
  }
};