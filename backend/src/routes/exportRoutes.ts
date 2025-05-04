// /backend/src/routes/exportRoutes.ts
import express from 'express';
import { exportController } from '../controllers/exportController';
import { authenticate } from '../middlewares/auth';

const router = express.Router();

// All routes require authentication
router.use(authenticate);

// Export user data as JSON response
router.get('/data', exportController.exportData);

// Export user data to file and return file path
router.get('/file', exportController.exportDataToFile);

export { router as exportRoutes };