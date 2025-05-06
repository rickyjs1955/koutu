// backend/src/routes/exportRoutes.ts
import express from 'express';
import { exportController } from '../controllers/exportController';
import { auth } from '../middlewares/auth';
import { validate } from '../middlewares/validate';
import { mlExportRequestSchema } from '@koutu/shared/schemas/export';

const router = express.Router();

// Protected routes - require authentication
router.use(auth);

// Existing export routes
// GET /api/v1/export/data
// GET /api/v1/export/file

// New ML export routes
router.post(
  '/ml',
  validate(mlExportRequestSchema),
  exportController.createMLExport
);

router.get(
  '/ml/jobs',
  exportController.getUserExportJobs
);

router.get(
  '/ml/jobs/:jobId',
  exportController.getExportJob
);

router.delete(
  '/ml/jobs/:jobId',
  exportController.cancelExportJob
);

router.get(
  '/ml/download/:jobId',
  exportController.downloadExport
);

router.get(
  '/ml/stats',
  exportController.getDatasetStats
);

export default router;