// src/controllers/authController.ts
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { userModel, CreateUserInput } from '../models/userModel';
import { ApiError } from '../utils/ApiError';

export const authController = {
  async register(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password } = req.body;

      // Validate input
      if (!email || !password) {
        return next(ApiError.badRequest('Email and password are required'));
      }

      // Simple email validation
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return next(ApiError.badRequest('Invalid email format'));
      }

      // Password strength validation
      if (password.length < 8) {
        return next(ApiError.badRequest('Password must be at least 8 characters long'));
      }

      // Create user
      const userData: CreateUserInput = { email, password };
      const newUser = await userModel.create(userData);

      // Generate JWT token with proper typing
      // Using a string literal for expiresIn, which matches the expected type
      const token = jwt.sign(
        {
          id: newUser.id,
          email: newUser.email
        },
        config.jwtSecret || 'fallback_secret',
        { 
          expiresIn: '1d' // Use a literal string that matches the required pattern
        }
      );

      res.status(201).json({
        status: 'success',
        data: {
          user: {
            id: newUser.id,
            email: newUser.email
          },
          token
        }
      });
    } catch (error) {
      // Pass the error to the error handler middleware
      next(error);
    }
  },

  async login(req: Request, res: Response, next: NextFunction) {
    try {
      const { email, password } = req.body;

      // Validate input
      if (!email || !password) {
        return next(ApiError.badRequest('Email and password are required'));
      }

      // Find user by email
      const user = await userModel.findByEmail(email);
      if (!user) {
        return next(ApiError.unauthorized('Invalid credentials'));
      }

      // Validate password
      const isPasswordValid = await userModel.validatePassword(user, password);
      if (!isPasswordValid) {
        return next(ApiError.unauthorized('Invalid credentials'));
      }

      // Generate JWT token with proper typing
      // Using a string literal for expiresIn, which matches the expected type
      const token = jwt.sign(
        {
          id: user.id,
          email: user.email
        },
        config.jwtSecret || 'fallback_secret',
        { 
          expiresIn: '1d' // Use a literal string that matches the required pattern
        }
      );

      res.status(200).json({
        status: 'success',
        data: {
          user: {
            id: user.id,
            email: user.email
          },
          token
        }
      });
    } catch (error) {
      next(error);
    }
  },

  async me(req: Request, res: Response, next: NextFunction) {
    try {
      // The user is attached to the request by the authenticate middleware
      if (!req.user) {
        return next(ApiError.unauthorized('Not authenticated'));
      }

      res.status(200).json({
        status: 'success',
        data: {
          user: req.user
        }
      });
    } catch (error) {
      next(error);
    }
  }
};