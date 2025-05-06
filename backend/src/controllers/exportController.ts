// backend/src/controllers/exportController.ts
import { Request, Response, NextFunction } from 'express';
import { exportService } from '../services/exportService';
import { MLExportOptions } from '@koutu/shared/schemas/export';
import { ApiError } from '../utils/ApiError';

export const exportController = {
  /**
   * Create a new ML export job
   * POST /api/v1/export/ml
   */
  createMLExport: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user.id;
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
      const { jobId } = req.params;
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        throw new ApiError(404, 'Export job not found');
      }
      
      // Check if user owns this job
      if (job.userId !== req.user.id) {
        throw new ApiError(403, 'You do not have permission to access this export job');
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
      const userId = req.user.id;
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
      const { jobId } = req.params;
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        throw new ApiError(404, 'Export job not found');
      }
      
      // Check if user owns this job
      if (job.userId !== req.user.id) {
        throw new ApiError(403, 'You do not have permission to access this export');
      }
      
      // Check if job is completed
      if (job.status !== 'completed') {
        throw new ApiError(400, `Export job is not ready for download (status: ${job.status})`);
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
      const userId = req.user.id;
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
      const { jobId } = req.params;
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        throw new ApiError(404, 'Export job not found');
      }
      
      // Check if user owns this job
      if (job.userId !== req.user.id) {
        throw new ApiError(403, 'You do not have permission to cancel this export job');
      }
      
      // Check if job is already completed or failed
      if (job.status === 'completed' || job.status === 'failed') {
        throw new ApiError(400, `Cannot cancel job with status: ${job.status}`);
      }
      
      // Update job status to canceled
      await exportService.updateBatchJobStatus(jobId, 'failed', 'Job canceled by user');
      
      res.status(200).json({
        success: true,
        message: 'Export job canceled successfully'
      });
    } catch (error) {
      next(error);
    }
  }
};