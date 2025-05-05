// /backend/src/routes/fileRoutes.ts
import express from 'express';
import path from 'path';
import { config } from '../config';
import { storageService } from '../services/storageService';
import { authenticate } from '../middlewares/auth';
import { ApiError } from '../utils/ApiError';

const router = express.Router();

/**
 * @route GET /api/v1/files/:filepath*
 * @desc Serve a file from storage (either Firebase or local)
 * @access Public (but could be restricted based on requirements)
 */
router.get('/:filepath(*)', async (req, res, next) => {
  try {
    const filepath = req.params.filepath;
    
    if (config.storageMode === 'firebase') {
      // For Firebase storage, redirect to a signed URL
      const signedUrl = await storageService.getSignedUrl(filepath);
      return res.redirect(signedUrl);
    } else {
      // For local storage, serve the file directly
      const absolutePath = storageService.getAbsolutePath(filepath);
      return res.sendFile(absolutePath);
    }
  } catch (error) {
    return next(ApiError.notFound('File not found'));
  }
});

/**
 * @route GET /api/v1/files/secure/:filepath*
 * @desc Serve a file from storage with authentication required
 * @access Private
 */
router.get('/secure/:filepath(*)', authenticate, async (req, res, next) => {
  try {
    const filepath = req.params.filepath;
    
    if (config.storageMode === 'firebase') {
      // For Firebase storage, redirect to a signed URL
      const signedUrl = await storageService.getSignedUrl(filepath, 5); // 5 minutes expiration
      return res.redirect(signedUrl);
    } else {
      // For local storage, serve the file directly
      const absolutePath = storageService.getAbsolutePath(filepath);
      return res.sendFile(absolutePath);
    }
  } catch (error) {
    return next(ApiError.notFound('File not found'));
  }
});

export { router as fileRoutes };