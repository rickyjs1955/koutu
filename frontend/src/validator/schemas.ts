import { z } from 'zod';
import { 
  CreateGarmentSchema,
  CreateWardrobeSchema,
  RegisterUserSchema,
  LoginUserSchema
} from '@koutu/shared/schemas';

import { 
  UniversalValidator,
  transformErrors,
  type ValidationResult,
  type ValidationError
} from '@koutu/shared/schemas/validator';
import { CreatePolygonSchema } from '@koutu/shared/schemas/polygon';

// ==================== FRONTEND-OPTIMIZED SCHEMAS ====================

/**
 * Frontend garment creation schema with additional UI validations
 */
export const FrontendCreateGarmentSchema = CreateGarmentSchema.extend({
  // Add frontend-specific validations
  preview_url: z.string().url().optional(),
  upload_progress: z.number().min(0).max(100).optional()
});

/**
 * Polygon creation with canvas-specific validations
 */
export const FrontendCreatePolygonSchema = CreatePolygonSchema.extend({
  canvas_dimensions: z.object({
    width: z.number().positive(),
    height: z.number().positive()
  }).optional(),
  normalized_points: z.array(z.object({
    x: z.number().min(0).max(1), // Normalized 0-1 coordinates
    y: z.number().min(0).max(1)
  })).min(3).optional()
});

/**
 * Form validation schemas for common UI inputs
 */
export const FormValidationSchemas = {
  email: z.string().email('Please enter a valid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase, and number'),
  wardrobeName: z.string()
    .min(1, 'Wardrobe name is required')
    .max(50, 'Wardrobe name is too long')
    .regex(/^[a-zA-Z0-9\s-_]+$/, 'Only letters, numbers, spaces, hyphens, and underscores allowed'),
  garmentName: z.string()
    .min(1, 'Garment name is required')
    .max(100, 'Garment name is too long'),
  garmentColor: z.string()
    .min(1, 'Color is required')
    .max(30, 'Color name is too long'),
  garmentType: z.enum(['shirt', 'pants', 'dress', 'jacket', 'skirt', 'shorts', 'sweater', 'other'], {
    errorMap: () => ({ message: 'Please select a valid garment type' })
  }),
  imageFile: z.instanceof(File)
    .refine(file => file.size <= 10 * 1024 * 1024, 'File size must be less than 10MB')
    .refine(file => ['image/jpeg', 'image/png', 'image/webp'].includes(file.type), 
      'Only JPEG, PNG, and WebP images are allowed')
};

/**
 * Multi-step form schemas
 */
export const MultiStepSchemas = {
  // Step 1: Basic garment info
  garmentBasicInfo: z.object({
    name: FormValidationSchemas.garmentName,
    type: FormValidationSchemas.garmentType,
    color: FormValidationSchemas.garmentColor,
    brand: z.string().max(50).optional(),
    size: z.string().max(20).optional()
  }),

  // Step 2: Image upload
  garmentImageUpload: z.object({
    original_image: FormValidationSchemas.imageFile,
    description: z.string().max(500).optional()
  }),

  // Step 3: Polygon selection
  garmentPolygonSelection: z.object({
    polygon_points: z.array(z.object({
      x: z.number(),
      y: z.number()
    })).min(3, 'Please select at least 3 points to define the garment area'),
    confidence: z.number().min(0).max(1).optional()
  })
};

// ==================== VALIDATION UTILITIES ====================

/**
 * Frontend-specific validation wrapper with UI-friendly error handling
 */
class FrontendValidator {
  /**
   * Validate form data with user-friendly error messages
   */
  static validateForm<T>(
    schema: z.ZodSchema<T>,
    data: unknown
  ): ValidationResult<T> & { fieldErrors?: Record<string, string> } {
    const result = UniversalValidator.validate(schema, data);
    
    if (!result.success && result.errors) {
      const fieldErrors = transformErrors.toFieldErrors(result.errors);
      const friendlyFieldErrors: Record<string, string> = {};
      
      // Convert to user-friendly messages
      Object.entries(fieldErrors).forEach(([field, error]) => {
        friendlyFieldErrors[field] = this.formatErrorForUser(error);
      });
      
      return { ...result, fieldErrors: friendlyFieldErrors };
    }
    
    return result;
  }

  /**
   * Validate single field for real-time feedback
   */
  static validateField<T>(
    schema: z.ZodSchema<T>,
    fieldName: string,
    value: unknown
  ): { isValid: boolean; error?: string } {
    try {
      // Extract field schema if it's an object schema
      if ('shape' in schema && schema.shape && typeof schema.shape === 'object') {
        const fieldSchema = (schema.shape as any)[fieldName];
        if (fieldSchema) {
          const result = fieldSchema.safeParse(value);
          return {
            isValid: result.success,
            error: result.success ? undefined : this.formatErrorForUser(result.error.issues[0]?.message || 'Invalid')
          };
        }
      }
      
      // Fallback: validate entire object with single field
      const testData = { [fieldName]: value };
      const result = schema.safeParse(testData);
      
      return {
        isValid: result.success,
        error: result.success ? undefined : 'Invalid value'
      };
    } catch (error) {
      return {
        isValid: false,
        error: 'Validation error'
      };
    }
  }

  /**
   * Convert technical error messages to user-friendly ones
   */
  private static formatErrorForUser(error: string): string {
    const errorMappings: Record<string, string> = {
      'Invalid email format': 'Please enter a valid email address',
      'String must contain at least 8 character(s)': 'Password must be at least 8 characters',
      'String must contain at most 50 character(s)': 'This field is too long',
      'Required': 'This field is required',
      'Expected string, received undefined': 'This field is required',
      'Invalid enum value': 'Please select a valid option',
      'Invalid UUID format': 'Invalid selection',
      'File size too large': 'File size must be less than 10MB',
      'Invalid file type': 'Please select a valid image file'
    };

    // Check for partial matches
    for (const [key, value] of Object.entries(errorMappings)) {
      if (error.includes(key)) {
        return value;
      }
    }

    return error;
  }
}

/**
 * Async validation for expensive operations (like duplicate checking)
 */
class AsyncValidator {
  /**
   * Check if wardrobe name is unique (example async validation)
   */
  static async validateUniqueWardrobeName(
    name: string,
    excludeId?: string
  ): Promise<{ isValid: boolean; error?: string }> {
    try {
      // This would call your API
      const response = await fetch(`/api/wardrobes/check-name?name=${encodeURIComponent(name)}&exclude=${excludeId || ''}`);
      const { isUnique } = await response.json();
      
      return {
        isValid: isUnique,
        error: isUnique ? undefined : 'A wardrobe with this name already exists'
      };
    } catch (error) {
      return {
        isValid: false,
        error: 'Unable to validate name uniqueness'
      };
    }
  }

  /**
   * Validate image file integrity
   */
  static async validateImageFile(file: File): Promise<{ isValid: boolean; error?: string; metadata?: any }> {
    return new Promise((resolve) => {
      const img = new Image();
      
      img.onload = () => {
        const metadata = {
          width: img.width,
          height: img.height,
          aspectRatio: img.width / img.height
        };
        
        // Check dimensions
        if (img.width < 100 || img.height < 100) {
          resolve({
            isValid: false,
            error: 'Image must be at least 100x100 pixels'
          });
          return;
        }
        
        if (img.width > 4096 || img.height > 4096) {
          resolve({
            isValid: false,
            error: 'Image must be smaller than 4096x4096 pixels'
          });
          return;
        }
        
        resolve({
          isValid: true,
          metadata
        });
      };
      
      img.onerror = () => {
        resolve({
          isValid: false,
          error: 'Invalid image file'
        });
      };
      
      img.src = URL.createObjectURL(file);
    });
  }
}

/**
 * Validation helpers for specific use cases
 */
const ValidationHelpers = {
  /**
   * Quick validation for common form fields
   */
  quick: {
    email: (value: string) => FrontendValidator.validateField(z.object({ email: FormValidationSchemas.email }), 'email', value),
    password: (value: string) => FrontendValidator.validateField(z.object({ password: FormValidationSchemas.password }), 'password', value),
    wardrobeName: (value: string) => FrontendValidator.validateField(z.object({ name: FormValidationSchemas.wardrobeName }), 'name', value),
    garmentName: (value: string) => FrontendValidator.validateField(z.object({ name: FormValidationSchemas.garmentName }), 'name', value)
  },

  /**
   * Validate file uploads
   */
  file: {
    image: async (file: File) => {
      // First validate with schema
      const schemaResult = FrontendValidator.validateField(
        z.object({ file: FormValidationSchemas.imageFile }), 
        'file', 
        file
      );
      
      if (!schemaResult.isValid) {
        return schemaResult;
      }
      
      // Then validate image integrity
      return await AsyncValidator.validateImageFile(file);
    }
  },

  /**
   * Validate polygon data
   */
  polygon: {
    points: (points: Array<{ x: number; y: number }>) => {
      const result = FrontendValidator.validateField(
        FrontendCreatePolygonSchema,
        'points',
        points
      );
      
      // Additional polygon-specific validations
      if (result.isValid && points.length >= 3) {
        // Check if polygon is self-intersecting (basic check)
        const isSimple = ValidationHelpers.isSimplePolygon(points);
        if (!isSimple) {
          return {
            isValid: false,
            error: 'Polygon lines cannot cross each other'
          };
        }
      }
      
      return result;
    }
  },

  // Helper method for polygon validation
  isSimplePolygon(points: Array<{ x: number; y: number }>): boolean {
    // Simplified self-intersection check
    // In a real app, you'd use a more robust algorithm
    return true; // Placeholder
  }
};

// ==================== EXPORTS ====================

export {
  FrontendValidator,
  AsyncValidator,
  ValidationHelpers,
  // Re-export commonly used schemas
  CreateGarmentSchema,
  CreatePolygonSchema,
  CreateWardrobeSchema,
  RegisterUserSchema,
  LoginUserSchema
};

export type {
  ValidationResult,
  ValidationError
};