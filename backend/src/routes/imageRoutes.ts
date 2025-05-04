// src/routes/imageRoutes.ts
import express from 'express';
import { imageController } from '../controllers/imageController';
import { authenticate } from '../middlewares/auth';

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// Upload image
router.post('/upload', imageController.uploadMiddleware, imageController.uploadImage);

// Get all images
router.get('/', imageController.getImages);

// Get a specific image
router.get('/:id', imageController.getImage);

// Delete an image
router.delete('/:id', imageController.deleteImage);

export { router as imageRoutes };