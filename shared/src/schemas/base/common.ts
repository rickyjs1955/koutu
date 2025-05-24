// /shared/src/schemas/base/common.ts
import { z } from 'zod';

// ==================== PRIMITIVE SCHEMAS ====================

export const UUIDSchema = z.string().uuid('Invalid UUID format');

export const EmailSchema = z.string().email('Invalid email format').max(255, 'Email too long');

export const PasswordSchema = z.string().min(8, 'Password must be at least 8 characters').max(128, 'Password too long');

export const TimestampSchema = z.string().datetime().or(z.date());

export const PaginationSchema = z.object({
  page: z.coerce.number().int().min(1, 'Page must be at least 1').optional(),
  limit: z.coerce.number().int().min(1, 'Limit must be at least 1').max(100, 'Limit cannot exceed 100').optional(),
  offset: z.coerce.number().int().min(0, 'Offset must be non-negative').optional()
});

// ==================== GEOMETRY SCHEMAS ====================

export const PointSchema = z.object({
  x: z.number().min(0, 'X coordinate must be non-negative'),
  y: z.number().min(0, 'Y coordinate must be non-negative')
});

export const BoundingBoxSchema = z.object({
  x: z.number().min(0),
  y: z.number().min(0),
  width: z.number().min(0),
  height: z.number().min(0)
});

export const DimensionsSchema = z.object({
  width: z.number().int().min(1, 'Width must be positive').max(10000, 'Width too large'),
  height: z.number().int().min(1, 'Height must be positive').max(10000, 'Height too large')
});

// ==================== ENUM SCHEMAS ====================

export const ImageStatusSchema = z.enum(['new', 'processed', 'labeled']);

export const ExportFormatSchema = z.enum(['coco', 'yolo', 'pascal_voc', 'csv', 'raw_json']);

export const ImageFormatSchema = z.enum(['jpg', 'png', 'webp']);

export const GarmentTypeSchema = z.enum(['shirt', 'pants', 'dress', 'jacket', 'skirt', 'other']);

export const GarmentPatternSchema = z.enum(['solid', 'striped', 'plaid', 'floral', 'geometric', 'other']);

export const SeasonSchema = z.enum(['spring', 'summer', 'fall', 'winter', 'all']);

export const JobStatusSchema = z.enum(['pending', 'processing', 'completed', 'failed', 'cancelled']);

// ==================== VALIDATION UTILITIES ====================

export const createOptionalSchema = <T extends z.ZodTypeAny>(schema: T) => schema.optional();

export const createArraySchema = <T extends z.ZodTypeAny>(schema: T, min = 0, max = 1000) => 
  z.array(schema).min(min).max(max);

export const createRecordSchema = <T extends z.ZodTypeAny>(valueSchema: T) => 
  z.record(z.string(), valueSchema);

// ==================== FILE SCHEMAS ====================

export const FileMetadataSchema = z.object({
  filename: z.string().max(255, 'Filename too long'),
  mimetype: z.string().max(100, 'MIME type too long'),
  size: z.number().int().min(1, 'File size must be positive'),
  uploadedAt: TimestampSchema.optional()
});

export const ImageMetadataSchema = FileMetadataSchema.extend({
  width: z.number().int().min(1).optional(),
  height: z.number().int().min(1).optional(),
  format: z.string().max(10).optional(),
  density: z.number().optional(),
  hasProfile: z.boolean().optional(),
  hasAlpha: z.boolean().optional(),
  channels: z.number().int().min(1).max(4).optional(),
  space: z.string().optional()
});

// ==================== ERROR SCHEMAS ====================

export const ValidationErrorSchema = z.object({
  field: z.string(),
  message: z.string(),
  code: z.string().optional(),
  value: z.any().optional()
});

export const ApiErrorSchema = z.object({
  status: z.literal('error'),
  code: z.string(),
  message: z.string(),
  errors: z.array(ValidationErrorSchema).optional(),
  requestId: z.string().optional(),
  timestamp: TimestampSchema.optional()
});

export const ApiSuccessSchema = <T extends z.ZodTypeAny>(dataSchema: T) => 
  z.object({
    status: z.literal('success'),
    data: dataSchema,
    message: z.string().optional(),
    requestId: z.string().optional(),
    timestamp: TimestampSchema.optional()
  });

// ==================== EXPORTED TYPES ====================

export type UUID = z.infer<typeof UUIDSchema>;
export type Email = z.infer<typeof EmailSchema>;
export type Password = z.infer<typeof PasswordSchema>;
export type Timestamp = z.infer<typeof TimestampSchema>;
export type Pagination = z.infer<typeof PaginationSchema>;
export type Point = z.infer<typeof PointSchema>;
export type BoundingBox = z.infer<typeof BoundingBoxSchema>;
export type Dimensions = z.infer<typeof DimensionsSchema>;
export type ImageStatus = z.infer<typeof ImageStatusSchema>;
export type ExportFormat = z.infer<typeof ExportFormatSchema>;
export type ImageFormat = z.infer<typeof ImageFormatSchema>;
export type GarmentType = z.infer<typeof GarmentTypeSchema>;
export type GarmentPattern = z.infer<typeof GarmentPatternSchema>;
export type Season = z.infer<typeof SeasonSchema>;
export type JobStatus = z.infer<typeof JobStatusSchema>;
export type FileMetadata = z.infer<typeof FileMetadataSchema>;
export type ImageMetadata = z.infer<typeof ImageMetadataSchema>;
export type ValidationError = z.infer<typeof ValidationErrorSchema>;
export type ApiError = z.infer<typeof ApiErrorSchema>;
export type ApiSuccess<T> = {
  status: 'success';
  data: T;
  message?: string;
  requestId?: string;
  timestamp?: Timestamp;
};