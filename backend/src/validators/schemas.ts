// /backend/src/validators/schemas.ts (UPDATED - Using Shared Schemas)
import { 
  // Import from shared API schemas
  CreateGarmentSchema,
  UpdateGarmentMetadataSchema,
  CreatePolygonSchema,
  UpdatePolygonSchema,
  ImageQuerySchema,
  UUIDParamSchema,
  ImageIdParamSchema,
  JobIdParamSchema,
  WardrobeItemParamSchema,
  CreateWardrobeSchema,
  UpdateWardrobeSchema,
  AddGarmentToWardrobeSchema,
  MLExportOptionsSchema,
  CreateMLExportSchema,
  BatchUpdateImageStatusSchema,
  UpdateImageStatusSchema
} from '@koutu/shared/schemas/api';

import { 
  // Import validation utilities
  BackendValidator,
  createValidationMiddleware
} from '../../../shared/src/schemas/validator';

import { z } from 'zod';

// ==================== RE-EXPORT SHARED SCHEMAS ====================
// These are the main schemas used in routes - directly from shared
export {
  CreateGarmentSchema,
  UpdateGarmentMetadataSchema,
  CreatePolygonSchema,
  UpdatePolygonSchema,
  ImageQuerySchema,
  UUIDParamSchema,
  ImageIdParamSchema,
  JobIdParamSchema,
  WardrobeItemParamSchema,
  CreateWardrobeSchema,
  UpdateWardrobeSchema,
  AddGarmentToWardrobeSchema,
  MLExportOptionsSchema,
  CreateMLExportSchema,
  BatchUpdateImageStatusSchema,
  UpdateImageStatusSchema
};

// ==================== BACKEND-SPECIFIC EXTENSIONS ====================

// Extended garment schema with backend-specific business rules
export const CreateGarmentWithBusinessRulesSchema = CreateGarmentSchema.extend({
  // Add server-side validations
  mask_data: CreateGarmentSchema.shape.mask_data.refine(
    (data) => {
      // Ensure mask data is properly formatted for processing
      const expectedLength = data.width * data.height;
      if (data.data.length !== expectedLength) {
        return false;
      }
      
      // Ensure mask has some actual content (not all zeros)
      const nonZeroCount = data.data.filter(val => val > 0).length;
      return nonZeroCount > 0;
    },
    'Mask must contain actual selection data'
  )
});

// Extended polygon schema with geometry validation
export const CreatePolygonWithGeometryValidationSchema = CreatePolygonSchema.extend({
  points: CreatePolygonSchema.shape.points.refine(
    (points) => {
      // Validate polygon area is sufficient
      const area = calculatePolygonArea(points);
      return area >= 100; // minimum 100 square pixels
    },
    'Polygon area too small for processing'
  ).refine(
    (points) => {
      // Check for self-intersection (simplified check)
      return !hasSelfIntersection(points);
    },
    'Polygon cannot have self-intersecting edges'
  )
});

// File upload validation schema (backend-specific)
export const FileUploadSchema = z.object({
  fieldname: z.string(),
  originalname: z.string().max(255, 'Filename too long'),
  encoding: z.string(),
  mimetype: z.string().regex(/^image\/(jpeg|png|webp)$/, 'Invalid image type'),
  size: z.number().max(5242880, 'File too large (max 5MB)'),
  buffer: z.instanceof(Buffer)
});

// ==================== VALIDATION MIDDLEWARE FACTORIES ====================

export const validateBody = createValidationMiddleware.forExpress;
export const validateQuery = createValidationMiddleware.forExpress;
export const validateParams = createValidationMiddleware.forExpress;

// Specific validation middleware for common use cases
export const validateUUIDParam = validateParams(UUIDParamSchema, 'params');
export const validateImageQuery = validateQuery(ImageQuerySchema, 'query');

// File validation middleware
export const validateFile = (req: any, res: any, next: any) => {
  const result = BackendValidator.validateWithContext(
    FileUploadSchema,
    req.file,
    {
      operation: 'file_upload',
      userId: req.user?.id
    }
  );

  if (result.success) {
    req.file = result.data;
    next();
  } else {
    const error = new Error('Invalid file upload');
    (error as any).statusCode = 400;
    (error as any).code = 'INVALID_FILE';
    (error as any).details = result.errors;
    next(error);
  }
};

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
  if (det === 0) return false;
  
  const lambda = ((p4.y - p3.y) * (p4.x - p1.x) + (p3.x - p4.x) * (p4.y - p1.y)) / det;
  const gamma = ((p1.y - p2.y) * (p4.x - p1.x) + (p2.x - p1.x) * (p4.y - p1.y)) / det;
  
  return (0 < lambda && lambda < 1) && (0 < gamma && gamma < 1);
}