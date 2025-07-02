// backend/src/controllers/exportController.ts - Fully Flutter-compatible version
import { Request, Response, NextFunction } from 'express';
import { exportService } from '../services/exportService';
import { MLExportOptions } from '@koutu/shared/schemas/export';
import { EnhancedApiError } from '../middlewares/errorHandler';

export const exportController = {
  /**
   * Create a new ML export job
   * POST /api/v1/export/ml
   * Flutter-optimized response format
   */
  createMLExport: async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Use optional chaining to safely access user (although middleware should guarantee it exists)
      const userId = req.user?.id;
      if (!userId) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }
      
      const options: MLExportOptions = req.body.options;

      // Validate export options
      if (!options || typeof options !== 'object') {
        throw EnhancedApiError.validation('Export options are required', 'options');
      }

      const batchJobId = await exportService.exportMLData(userId, options);
      
      // Flutter-optimized response (202 Accepted for async operations)
      res.accepted(
        { jobId: batchJobId },
        {
          message: 'ML export job created successfully',
          meta: {
            jobId: batchJobId,
            userId,
            jobType: 'ml_export',
            status: 'queued',
            createdAt: new Date().toISOString()
          }
        }
      );

    } catch (error) {
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      throw EnhancedApiError.internalError('Failed to create ML export job', error instanceof Error ? error : new Error(String(error)));
    }
  },

  /**
   * Get ML export job status
   * GET /api/v1/export/ml/jobs/:jobId
   * Flutter-optimized response format
   */
  getExportJob: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }
      
      const { jobId } = req.params;
      
      if (!jobId || typeof jobId !== 'string') {
        throw EnhancedApiError.validation('Valid job ID is required', 'jobId');
      }
      
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        throw EnhancedApiError.notFound('Export job not found', 'export_job');
      }
      
      // Check if user owns this job
      if (job.userId !== userId) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to access this export job', 'export_job');
      }
      
      // Flutter-optimized response
      res.success(
        job,
        {
          message: 'Export job retrieved successfully',
          meta: {
            jobId,
            userId,
            status: job.status,
            retrievedAt: new Date().toISOString()
          }
        }
      );

    } catch (error) {
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      throw EnhancedApiError.internalError('Failed to retrieve export job', error instanceof Error ? error : new Error(String(error)));
    }
  },

  /**
   * Get all ML export jobs for the user
   * GET /api/v1/export/ml/jobs
   * Flutter-optimized response format
   */
  getUserExportJobs: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }
      
      const jobs = await exportService.getUserBatchJobs(userId);
      
      // Flutter-optimized response
      res.success(
        jobs,
        {
          message: 'Export jobs retrieved successfully',
          meta: {
            userId,
            jobCount: jobs.length,
            retrievedAt: new Date().toISOString()
          }
        }
      );

    } catch (error) {
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      throw EnhancedApiError.internalError('Failed to retrieve user export jobs', error instanceof Error ? error : new Error(String(error)));
    }
  },

  /**
   * Download ML export file
   * GET /api/v1/export/ml/download/:jobId
   * Special handling for file downloads (not JSON response)
   */
  downloadExport: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }
      
      const { jobId } = req.params;
      
      if (!jobId || typeof jobId !== 'string') {
        throw EnhancedApiError.validation('Valid job ID is required', 'jobId');
      }
      
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        throw EnhancedApiError.notFound('Export job not found', 'export_job');
      }
      
      // Check if user owns this job
      if (job.userId !== userId) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to access this export', 'export_job');
      }
      
      // Check if job is completed
      if (job.status !== 'completed') {
        throw EnhancedApiError.validation(
          `Export job is not ready for download (status: ${job.status})`,
          'job_status',
          { currentStatus: job.status, requiredStatus: 'completed' }
        );
      }
      
      const { path, filename } = await exportService.downloadExport(jobId);
      
      // For file downloads, we use res.download() which handles the response differently
      // This is not a JSON response, so we don't use our Flutter format here
      res.download(path, filename, (err) => {
        if (err) {
          console.error('Download error:', err);
          throw EnhancedApiError.internalError('Failed to download export file', err);
        }
      });

    } catch (error) {
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      throw EnhancedApiError.internalError('Failed to download export', error instanceof Error ? error : new Error(String(error)));
    }
  },

  /**
   * Get dataset statistics for ML
   * GET /api/v1/export/ml/stats
   * Flutter-optimized response format
   */
  getDatasetStats: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }
      
      const stats = await exportService.getDatasetStats(userId);
      
      // Flutter-optimized response
      res.success(
        stats,
        {
          message: 'Dataset statistics retrieved successfully',
          meta: {
            userId,
            statsType: 'ml_dataset',
            generatedAt: new Date().toISOString()
          }
        }
      );

    } catch (error) {
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      throw EnhancedApiError.internalError('Failed to retrieve dataset statistics', error instanceof Error ? error : new Error(String(error)));
    }
  },

  /**
   * Cancel ML export job
   * DELETE /api/v1/export/ml/jobs/:jobId
   * Flutter-optimized response format
   */
  cancelExportJob: async (req: Request, res: Response, next: NextFunction) => {
    try {
      const userId = req.user?.id;
      if (!userId) {
        throw EnhancedApiError.authenticationRequired('User authentication required');
      }
      
      const { jobId } = req.params;
      
      if (!jobId || typeof jobId !== 'string') {
        throw EnhancedApiError.validation('Valid job ID is required', 'jobId');
      }
      
      const job = await exportService.getBatchJob(jobId);
      
      if (!job) {
        throw EnhancedApiError.notFound('Export job not found', 'export_job');
      }
      
      // Check if user owns this job
      if (job.userId !== userId) {
        throw EnhancedApiError.authorizationDenied('You do not have permission to cancel this export job', 'export_job');
      }
      
      // Check if job is already completed or failed
      if (job.status === 'completed' || job.status === 'failed') {
        throw EnhancedApiError.validation(
          `Cannot cancel job with status: ${job.status}`,
          'job_status',
          { currentStatus: job.status, cancellableStatuses: ['queued', 'running', 'pending'] }
        );
      }
      
      // Call the public cancelExportJob method
      await exportService.cancelExportJob(jobId);
      
      // Flutter-optimized response
      res.success(
        {},
        {
          message: 'Export job canceled successfully',
          meta: {
            jobId,
            userId,
            previousStatus: job.status,
            newStatus: 'canceled',
            canceledAt: new Date().toISOString()
          }
        }
      );

    } catch (error) {
      if (error instanceof EnhancedApiError) {
        throw error;
      }
      throw EnhancedApiError.internalError('Failed to cancel export job', error instanceof Error ? error : new Error(String(error)));
    }
  }
};