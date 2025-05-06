// backend/src/controllers/exportController.ts
import { Request, Response, NextFunction } from 'express';
import { exportService } from '../services/exportService';
import { MLExportOptions } from '@koutu/shared/schemas/export';
import { ApiError } from '../utils/ApiError';

// No need to define our own interface since Express has already been extended
// in the auth.ts file with the proper user type

export const exportController = {
  /**
   * Create a new ML export job
   * POST /api/v1/export/ml
   */
  createMLExport: async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Use optional chaining to safely access user (although middleware should guarantee it exists)
      const userId = req.user?.id;
      if (!userId) {
        return next(ApiError.unauthorized('User authentication required'));
      }
      
      const options: MLExportOptions = req.body.options;

      const batchJobId = await exportService.exportMLData(userId, options);
      
      res.status(202).json({
        success: true,
        message: 'ML export job created successfully',
        data: {
          jobId: batchJobId
        }
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * Get ML export job status
   * GET /api/v1/export/ml/jobs/:jobId
   */
  getExportJob: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return next(ApiError.unauthorized('User authentication required'));
      }
      
      const { jobId } = req.params;
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        return next(ApiError.notFound('Export job not found'));
      }
      
      // Check if user owns this job
      if (job.userId !== userId) {
        return next(ApiError.forbidden('You do not have permission to access this export job'));
      }
      
      res.status(200).json({
        success: true,
        data: job
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * Get all ML export jobs for the user
   * GET /api/v1/export/ml/jobs
   */
  getUserExportJobs: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return next(ApiError.unauthorized('User authentication required'));
      }
      
      const jobs = await exportService.getUserBatchJobs(userId);
      
      res.status(200).json({
        success: true,
        data: jobs
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * Download ML export file
   * GET /api/v1/export/ml/download/:jobId
   */
  downloadExport: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return next(ApiError.unauthorized('User authentication required'));
      }
      
      const { jobId } = req.params;
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        return next(ApiError.notFound('Export job not found'));
      }
      
      // Check if user owns this job
      if (job.userId !== userId) {
        return next(ApiError.forbidden('You do not have permission to access this export'));
      }
      
      // Check if job is completed
      if (job.status !== 'completed') {
        return next(ApiError.badRequest(`Export job is not ready for download (status: ${job.status})`));
      }
      
      const { path, filename } = await exportService.downloadExport(jobId);
      
      res.download(path, filename);
    } catch (error) {
      next(error);
    }
  },

  /**
   * Get dataset statistics for ML
   * GET /api/v1/export/ml/stats
   */
  getDatasetStats: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return next(ApiError.unauthorized('User authentication required'));
      }
      
      const stats = await exportService.getDatasetStats(userId);
      
      res.status(200).json({
        success: true,
        data: stats
      });
    } catch (error) {
      next(error);
    }
  },

  /**
   * Cancel ML export job
   * DELETE /api/v1/export/ml/jobs/:jobId
   */
  cancelExportJob: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        return next(ApiError.unauthorized('User authentication required'));
      }
      
      const { jobId } = req.params;
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        return next(ApiError.notFound('Export job not found'));
      }
      
      // Check if user owns this job
      if (job.userId !== userId) {
        return next(ApiError.forbidden('You do not have permission to cancel this export job'));
      }
      
      // Check if job is already completed or failed
      if (job.status === 'completed' || job.status === 'failed') {
        return next(ApiError.badRequest(`Cannot cancel job with status: ${job.status}`));
      }
      
      // Call the public cancelExportJob method instead of the private updateBatchJobStatus
      await exportService.cancelExportJob(jobId);
      
      res.status(200).json({
        success: true,
        message: 'Export job canceled successfully'
      });
    } catch (error) {
      next(error);
    }
  }
};