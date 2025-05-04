// src/routes/authRoutes.ts - Updated with validators
import express from 'express';
import { authController } from '../controllers/authController';
import { authenticate } from '../middlewares/auth';
import { registerValidator, loginValidator } from '../validators';

const router = express.Router();

// Public routes
router.post('/register', registerValidator, authController.register);
router.post('/login', loginValidator, authController.login);

// Protected routes
router.get('/me', authenticate, authController.me);

export { router as authRoutes };