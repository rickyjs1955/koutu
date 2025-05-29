// backend/src/validators/schemas.ts - Added Missing Schema
import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';

// ==================== CORE SCHEMAS ====================

// Base garment schema
const BaseGarmentSchema = z.object({
  mask_data: z.object({
    width: z.number().positive('Width must be positive'),
    height: z.number().positive('Height must be positive'),
    data: z.array(z.number()).min(1, 'Mask data must be an array of numbers')
  }),
  metadata: z.object({
    type: z.string().min(1, 'Type is required'),
    color: z.string().min(1, 'Color is required'),
    brand: z.string().min(1, 'Brand is required'),
    tags: z.array(z.string()).optional(),
    season: z.string().optional(),
    size: z.string().optional(),
    material: z.string().optional()
  }).optional(),
  original_image_id: z.string().optional(),
  processing_notes: z.string().optional(),
  source_polygon_id: z.string().optional(),
  created_by: z.string().optional()
});

// Extended garment schema with business rules
export const CreateGarmentWithBusinessRulesSchema = BaseGarmentSchema.refine(
  (data) => {
    // Ensure mask data length matches dimensions
    const expectedLength = data.mask_data.width * data.mask_data.height;
    return data.mask_data.data.length === expectedLength;
  },
  {
    message: 'Mask data length must match width * height',
    path: ['mask_data', 'data']
  }
).refine(
  (data) => {
    // Ensure mask has actual content (not all zeros)
    const nonZeroCount = data.mask_data.data.filter(val => val > 0).length;
    return nonZeroCount > 0;
  },
  {
    message: 'Mask must contain actual selection data (cannot be all zeros)',
    path: ['mask_data', 'data']
  }
);

// Base polygon schema
const BasePolygonSchema = z.object({
  points: z.array(z.object({
    x: z.number(),
    y: z.number()
  })).min(3, 'Polygon must have at least 3 points'),
  metadata: z.object({
    label: z.string().min(1, 'Label is required'),
    confidence: z.number().min(0).max(1).optional(),
    source: z.string().optional(),
    notes: z.string().optional(),
    annotator_id: z.string().optional()
  }).optional(),
  original_image_id: z.string().optional(),
  created_by: z.string().optional()
});

// Extended polygon schema with geometry validation
export const CreatePolygonWithGeometryValidationSchema = BasePolygonSchema.refine(
  (data) => {
    // Validate polygon area is sufficient (minimum 100 square pixels)
    const area = calculatePolygonArea(data.points);
    return area >= 100;
  },
  {
    message: 'Polygon area too small for processing (minimum 100 square pixels)',
    path: ['points']
  }
).refine(
  (data) => {
    // Check for self-intersection (simplified check)
    return !hasSelfIntersection(data.points);
  },
  {
    message: 'Polygon cannot have self-intersecting edges',
    path: ['points']
  }
);

// File upload schema
export const FileUploadSchema = z.object({
  fieldname: z.string(),
  originalname: z.string().max(255, 'Filename too long (max 255 characters)'),
  encoding: z.string(),
  mimetype: z.string().regex(
    /^image\/(jpeg|jpg|png|webp)$/i, 
    'Invalid image type. Only JPEG, PNG, and WebP are allowed'
  ),
  size: z.number().max(5242880, 'File too large (max 5MB)'),
  buffer: z.instanceof(Buffer)
});

// Enhanced file upload schema with additional business rules
export const EnhancedFileUploadSchema = FileUploadSchema.refine(
  (data) => {
    // Prevent path traversal
    return !data.originalname.includes('..') && 
           !data.originalname.includes('\\') &&
           !data.originalname.includes('/');
  },
  {
    message: 'Filename cannot contain path traversal characters',
    path: ['originalname']
  }
).refine(
  (data) => {
    // Prevent empty files
    return data.size > 0;
  },
  {
    message: 'File cannot be empty',
    path: ['size']
  }
);

// UUID parameter schema
export const UUIDParamSchema = z.object({
  id: z.string().uuid('Invalid UUID format')
});

// Image query schema
export const ImageQuerySchema = z.object({
  limit: z.string().optional().transform(val => val ? parseInt(val, 10) : undefined),
  offset: z.string().optional().transform(val => val ? parseInt(val, 10) : undefined),
  sort: z.enum(['created_at', 'updated_at', 'name']).optional(),
  order: z.enum(['asc', 'desc']).optional(),
  search: z.string().optional()
});

// ==================== MISSING SCHEMA - ADDED ==================== 

// Update image status schema - ADDED
export const UpdateImageStatusSchema = z.object({
  status: z.enum(['new', 'processed', 'labeled'], {
    errorMap: () => ({ message: 'Status must be one of: new, processed, labeled' })
  })
});

// ==================== ADDITIONAL SCHEMAS ====================

// Update garment metadata schema
export const UpdateGarmentMetadataSchema = z.object({
  metadata: z.object({
    type: z.string().optional(),
    color: z.string().optional(),
    brand: z.string().optional(),
    tags: z.array(z.string()).optional(),
    season: z.string().optional(),
    size: z.string().optional(),
    material: z.string().optional()
  }),
  processing_notes: z.string().optional()
});

// Create polygon schema (alias for consistency)
export const CreatePolygonSchema = BasePolygonSchema;

// Update polygon schema
export const UpdatePolygonSchema = z.object({
  points: z.array(z.object({
    x: z.number(),
    y: z.number()
  })).min(3).optional(),
  metadata: z.object({
    label: z.string().optional(),
    confidence: z.number().min(0).max(1).optional(),
    source: z.string().optional(),
    notes: z.string().optional()
  }).optional()
});

// ==================== HELPER FUNCTIONS ====================

function calculatePolygonArea(points: Array<{ x: number; y: number }>): number {
  if (points.length < 3) return 0;
  
  let area = 0;
  for (let i = 0; i < points.length; i++) {
    const j = (i + 1) % points.length;
    area += points[i].x * points[j].y;
    area -= points[j].x * points[i].y;
  }
  
  return Math.abs(area / 2);
}

function hasSelfIntersection(points: Array<{ x: number; y: number }>): boolean {
  // Simplified self-intersection check
  if (points.length < 4) return false;
  
  for (let i = 0; i < points.length; i++) {
    for (let j = i + 2; j < points.length; j++) {
      // Skip adjacent segments and last-to-first segment
      if (j === points.length - 1 && i === 0) continue;
      
      const line1 = {
        start: points[i],
        end: points[(i + 1) % points.length]
      };
      
      const line2 = {
        start: points[j],
        end: points[(j + 1) % points.length]
      };
      
      if (linesIntersect(line1.start, line1.end, line2.start, line2.end)) {
        return true;
      }
    }
  }
  
  return false;
}

function linesIntersect(
  p1: { x: number; y: number },
  p2: { x: number; y: number },
  p3: { x: number; y: number },
  p4: { x: number; y: number }
): boolean {
  const det = (p2.x - p1.x) * (p4.y - p3.y) - (p4.x - p3.x) * (p2.y - p1.y);
  if (det === 0) return false; // Lines are parallel
  
  const lambda = ((p4.y - p3.y) * (p4.x - p1.x) + (p3.x - p4.x) * (p4.y - p1.y)) / det;
  const gamma = ((p1.y - p2.y) * (p4.x - p1.x) + (p2.x - p1.x) * (p4.y - p1.y)) / det;
  
  return (0 < lambda && lambda < 1) && (0 < gamma && gamma < 1);
}

// ==================== EXPORTS ====================

// Re-export core schemas for compatibility
export const CreateGarmentSchema = BaseGarmentSchema;

// Export all schemas and validators
export {
  BaseGarmentSchema,
  BasePolygonSchema
};