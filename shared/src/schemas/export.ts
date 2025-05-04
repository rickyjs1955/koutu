// /shared/src/schemas/export.ts
import { z } from 'zod';
import { ImageSchema } from './image';
import { GarmentSchema } from './garment';
import { WardrobeSchema } from './wardrobe';

// Export data schema
export const ExportDataSchema = z.object({
  version: z.string(),
  exportDate: z.string().or(z.date()),
  userId: z.string().uuid(),
  images: z.array(ImageSchema),
  garments: z.array(GarmentSchema),
  wardrobes: z.array(WardrobeSchema),
  wardrobeItems: z.record(z.string().uuid(), z.array(z.any()))
});

// Export response schema
export const ExportResponseSchema = z.object({
  message: z.string().optional(),
  filePath: z.string().optional(),
  data: ExportDataSchema.optional()
});

// Export file schema
export const ExportFileSchema = z.object({
  filePath: z.string(),
  fileName: z.string()
});

// Derived TypeScript types
export type ExportData = z.infer<typeof ExportDataSchema>;
export type ExportResponse = z.infer<typeof ExportResponseSchema>;
export type ExportFile = z.infer<typeof ExportFileSchema>;