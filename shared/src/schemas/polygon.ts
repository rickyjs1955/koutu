// /shared/src/schemas/polygon.ts
import { z } from 'zod';

// Define a point in a polygon
export const PointSchema = z.object({
  x: z.number(),
  y: z.number()
});

// Define the polygon schema
export const PolygonSchema = z.object({
  id: z.string().uuid().optional(), // Will be generated on the server
  original_image_id: z.string().uuid(), // Link to parent image
  points: z.array(PointSchema), // Array of points that make up the polygon
  label: z.string().optional(), // Optional label for the polygon (e.g., "shirt", "pants")
  metadata: z.record(z.any()).optional(), // Additional metadata
  created_at: z.date().optional(),
  updated_at: z.date().optional()
});

// Schema for creating a new polygon
export const CreatePolygonSchema = z.object({
  original_image_id: z.string().uuid(),
  points: z.array(PointSchema),
  label: z.string().optional(),
  metadata: z.record(z.any()).optional()
});

// Schema for updating a polygon
export const UpdatePolygonSchema = z.object({
  points: z.array(PointSchema).optional(),
  label: z.string().optional(),
  metadata: z.record(z.any()).optional()
});

// Polygon response schema
export const PolygonResponseSchema = PolygonSchema;

// Derived TypeScript types
export type Point = z.infer<typeof PointSchema>;
export type Polygon = z.infer<typeof PolygonSchema>;
export type CreatePolygonInput = z.infer<typeof CreatePolygonSchema>;
export type UpdatePolygonInput = z.infer<typeof UpdatePolygonSchema>;
export type PolygonResponse = z.infer<typeof PolygonResponseSchema>;