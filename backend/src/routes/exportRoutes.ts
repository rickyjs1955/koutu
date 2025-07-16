// backend/src/routes/exportRoutes.ts - Enhanced with mobile-friendly formats and progressive download
import express from 'express';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { exportController } from '../controllers/exportController';
import { authenticate } from '../middlewares/auth';
import { validate, validateBody } from '../middlewares/validate';
import { mlExportRequestSchema } from '../../../shared/src/schemas/export';
import { ApiError } from '../utils/ApiError';
import { MobileExportFormats } from '../../../shared/src/schemas';

const router = express.Router();

// ==================== MOBILE-SPECIFIC SCHEMAS ====================

// Mobile export request with size optimization
const MobileExportRequestSchema = mlExportRequestSchema.extend({
  format: z.enum(['zip', 'tar', 'json', 'sqlite']).default('zip'),
  compression_level: z.enum(['low', 'medium', 'high']).default('medium'),
  include_thumbnails: z.boolean().default(true),
  max_image_dimension: z.number().min(100).max(2000).default(1200),
  split_size_mb: z.number().min(10).max(100).optional(), // For chunked downloads
  exclude_masks: z.boolean().default(false) // Save bandwidth
});

// Progressive download schema
const ProgressiveDownloadSchema = z.object({
  job_id: z.string().uuid(),
  chunk_index: z.number().int().min(0),
  chunk_size: z.number().int().min(1024).max(MobileExportFormats.CHUNK_SIZE).default(MobileExportFormats.CHUNK_SIZE)
});

// Export preview schema
const ExportPreviewSchema = z.object({
  wardrobe_ids: z.array(z.string().uuid()).optional(),
  garment_ids: z.array(z.string().uuid()).optional(),
  include_stats: z.boolean().default(true)
});

// Resume download schema
const ResumeDownloadSchema = z.object({
  job_id: z.string().uuid(),
  last_chunk_index: z.number().int().min(0),
  checksum: z.string() // To verify last chunk
});

// Protected routes - require authentication
router.use(authenticate);

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

// ==================== MOBILE-SPECIFIC ENDPOINTS ====================

// Mobile-optimized export creation
router.post(
  '/mobile/create',
  validateBody(MobileExportRequestSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { 
        format, 
        compression_level, 
        include_thumbnails,
        max_image_dimension,
        split_size_mb,
        exclude_masks,
        ...exportData 
      } = req.body;
      
      // Create mobile-optimized export job (mock implementation)
      const jobId = `export_mobile_${Date.now()}`;
      const estimatedSize = 50 * 1024 * 1024; // 50MB mock
      const chunks = split_size_mb ? Math.ceil(estimatedSize / (split_size_mb * 1024 * 1024)) : 1;
      
      res.status(202).json({
        status: 'success',
        message: 'Export job created',
        data: {
          job_id: jobId,
          status: 'processing',
          format,
          compression_level,
          estimated_size: estimatedSize,
          total_chunks: chunks,
          estimated_completion: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
          mobile_optimized: true
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

// Get export preview before downloading
router.post(
  '/mobile/preview',
  validateBody(ExportPreviewSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { wardrobe_ids, garment_ids, include_stats } = req.body;
      
      // Generate preview (mock implementation)
      const preview: any = {
        total_items: (wardrobe_ids?.length || 0) + (garment_ids?.length || 0),
        estimated_size: {
          full: 100 * 1024 * 1024, // 100MB
          thumbnails_only: 10 * 1024 * 1024, // 10MB
          without_masks: 80 * 1024 * 1024 // 80MB
        },
        file_count: {
          images: 50,
          masks: 50,
          metadata: 10
        },
        export_time_estimate: '2-5 minutes'
      };
      
      if (include_stats) {
        preview.stats = {
          garment_types: { shirt: 20, pants: 15, dress: 10, other: 5 },
          total_wardrobes: wardrobe_ids?.length || 0,
          date_range: {
            oldest: '2023-01-01',
            newest: '2024-01-15'
          }
        };
      }
      
      res.status(200).json({
        status: 'success',
        data: preview
      });
    } catch (error) {
      next(error);
    }
  }
);

// Progressive download endpoint
router.get(
  '/mobile/download/chunk',
  validateBody(ProgressiveDownloadSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { job_id, chunk_index, chunk_size } = req.body;
      
      // Generate mock chunk data
      const chunkData = Buffer.alloc(chunk_size);
      const isLastChunk = chunk_index >= 4; // Mock 5 chunks total
      
      res.set({
        'Content-Type': 'application/octet-stream',
        'Content-Length': chunkData.length.toString(),
        'X-Chunk-Index': chunk_index.toString(),
        'X-Total-Chunks': '5',
        'X-Is-Last-Chunk': isLastChunk.toString(),
        'X-Chunk-Checksum': Buffer.from(`checksum_${chunk_index}`).toString('base64')
      });
      
      res.status(206).send(chunkData); // 206 Partial Content
    } catch (error) {
      next(error);
    }
  }
);

// Resume interrupted download
router.post(
  '/mobile/download/resume',
  validateBody(ResumeDownloadSchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { job_id, last_chunk_index, checksum } = req.body;
      
      // Verify checksum and resume (mock implementation)
      const isValid = checksum === Buffer.from(`checksum_${last_chunk_index}`).toString('base64');
      
      if (!isValid) {
        return next(ApiError.badRequest('Invalid checksum, cannot resume download'));
      }
      
      res.status(200).json({
        status: 'success',
        message: 'Download can be resumed',
        data: {
          job_id,
          next_chunk_index: last_chunk_index + 1,
          remaining_chunks: 5 - last_chunk_index - 1,
          resume_token: `resume_${job_id}_${last_chunk_index + 1}`
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

// Get mobile-friendly export formats
router.get(
  '/mobile/formats',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const formats = [
        {
          format: 'zip',
          description: 'Compressed archive with folder structure',
          compression_ratio: 0.7,
          supports_resume: true,
          recommended_for: ['offline_viewing', 'backup']
        },
        {
          format: 'sqlite',
          description: 'Single database file with all data',
          compression_ratio: 0.5,
          supports_resume: false,
          recommended_for: ['offline_app', 'quick_access']
        },
        {
          format: 'json',
          description: 'Structured data without images',
          compression_ratio: 0.1,
          supports_resume: true,
          recommended_for: ['metadata_only', 'third_party_apps']
        }
      ];
      
      res.status(200).json({
        status: 'success',
        data: {
          formats,
          default_format: 'zip',
          max_export_size: 500 * 1024 * 1024, // 500MB
          chunk_sizes_available: [10, 25, 50, 100] // MB
        }
      });
    } catch (error) {
      next(error);
    }
  }
);

// Check export progress with mobile-specific info
router.get(
  '/mobile/jobs/:jobId/progress',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { jobId } = req.params;
      
      // Mock progress data
      const progress = {
        job_id: jobId,
        status: 'processing',
        progress_percentage: 45,
        current_step: 'Optimizing images for mobile',
        steps_completed: ['Collecting data', 'Generating thumbnails'],
        steps_remaining: ['Compressing files', 'Creating archive'],
        estimated_time_remaining: 180, // seconds
        current_size: 23 * 1024 * 1024, // 23MB
        can_download_partial: true,
        mobile_optimizations: {
          images_resized: 25,
          thumbnails_generated: 25,
          compression_applied: true
        }
      };
      
      res.status(200).json({
        status: 'success',
        data: progress
      });
    } catch (error) {
      next(error);
    }
  }
);

export default router;