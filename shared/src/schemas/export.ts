// shared/src/schemas/export.ts
import { z } from 'zod';
import { GarmentSchema } from './garment';
import { ImageSchema } from './image';

// Polygon point schema
export const pointSchema = z.object({
  x: z.number(),
  y: z.number(),
});

// ML-ready garment data schema
export const mlGarmentSchema = z.object({
  id: z.string().uuid(),
  imageId: z.string().uuid(),
  // The polygon points that define the garment boundary
  polygonPoints: z.array(pointSchema),
  // Mask representation as base64 string (optional for smaller payloads)
  maskBase64: z.string().optional(),
  // Bounding box for quick reference
  boundingBox: z.object({
    x: z.number(),
    y: z.number(),
    width: z.number(),
    height: z.number(),
  }),
  // Garment category and attributes
  category: z.string(),
  attributes: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])),
  // Original creation metadata
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

// ML export format options
export const exportFormatSchema = z.enum([
  'coco', // COCO dataset format
  'yolo', // YOLO format
  'pascal_voc', // Pascal VOC format
  'raw_json', // Custom raw JSON format
  'csv', // CSV format for tabular data
]);

// ML export options schema
export const mlExportOptionsSchema = z.object({
  format: exportFormatSchema,
  includeImages: z.boolean().default(true),
  includeRawPolygons: z.boolean().default(true),
  includeMasks: z.boolean().default(false),
  imageFormat: z.enum(['jpg', 'png']).default('jpg'),
  compressionQuality: z.number().min(0).max(100).default(90),
  garmentIds: z.array(z.string()).optional(),
  categoryFilter: z.array(z.string()).optional(),
  dateRange: z.object({
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
  }).optional(),
});

// ML export request schema
export const mlExportRequestSchema = z.object({
  options: mlExportOptionsSchema,
});

// ML export batch job schema
export const mlExportBatchJobSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
  status: z.enum(['pending', 'processing', 'completed', 'failed']),
  options: mlExportOptionsSchema,
  progress: z.number().min(0).max(100).default(0),
  totalItems: z.number().default(0),
  processedItems: z.number().default(0),
  outputUrl: z.string().url().optional(),
  error: z.string().optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  completedAt: z.string().datetime().optional(),
});

// Dataset statistics for ML
export const datasetStatsSchema = z.object({
  totalImages: z.number(),
  totalGarments: z.number(),
  categoryCounts: z.record(z.string(), z.number()),
  attributeCounts: z.record(z.string(), z.record(z.string(), z.number())),
  averagePolygonPoints: z.number(),
});

// Export the schemas and types
export type Point = z.infer<typeof pointSchema>;
export type MLGarment = z.infer<typeof mlGarmentSchema>;
export type ExportFormat = z.infer<typeof exportFormatSchema>;
export type MLExportOptions = z.infer<typeof mlExportOptionsSchema>;
export type MLExportRequest = z.infer<typeof mlExportRequestSchema>;
export type MLExportBatchJob = z.infer<typeof mlExportBatchJobSchema>;
export type DatasetStats = z.infer<typeof datasetStatsSchema>;