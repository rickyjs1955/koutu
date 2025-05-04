// /shared/src/schemas/image.ts
import { z } from 'zod';

// Image schema
export const ImageSchema = z.object({
  id: z.string().uuid().optional(),
  user_id: z.string().uuid(),
  file_path: z.string(),
  original_metadata: z.record(z.any()).optional(), // JSON metadata from upload
  upload_date: z.date().optional(),
  status: z.enum(['new', 'processed', 'labeled']).optional()
});

// Schema for image response
export const ImageResponseSchema = ImageSchema;

// Image list response schema
export const ImageListResponseSchema = z.array(ImageResponseSchema);

// Schema for image metadata
export const ImageMetadataSchema = z.object({
  filename: z.string().optional(),
  mimetype: z.string().optional(),
  size: z.number().optional(),
  width: z.number().optional(),
  height: z.number().optional(),
  format: z.string().optional()
});

// Derived TypeScript types
export type Image = z.infer<typeof ImageSchema>;
export type ImageResponse = z.infer<typeof ImageResponseSchema>;
export type ImageListResponse = z.infer<typeof ImageListResponseSchema>;
export type ImageMetadata = z.infer<typeof ImageMetadataSchema>;