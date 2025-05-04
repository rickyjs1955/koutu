// /backend/src/validators/index.ts
import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../utils/ApiError';

// Type for validation rules - explicit interface
export interface ValidationRule {
  field: string;
  required?: boolean;
  type?: 'string' | 'number' | 'boolean' | 'object' | 'array';
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  pattern?: RegExp;
  message?: string;
  custom?: (value: any) => boolean | Promise<boolean>;
}

/**
 * Create a validation middleware from a set of validation rules
 */
export const createValidator = (rules: ValidationRule[], source: 'body' | 'query' | 'params' = 'body') => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const data = req[source];
      const errors: string[] = [];

      // Check each rule
      for (const rule of rules) {
        const value = data[rule.field];

        // Required check
        if (rule.required && (value === undefined || value === null || value === '')) {
          errors.push(rule.message || `${rule.field} is required`);
          continue;
        }

        // Skip other validations if value is not provided and not required
        if ((value === undefined || value === null || value === '') && !rule.required) {
          continue;
        }

        // Type check
        if (rule.type) {
          let typeValid = true;

          switch (rule.type) {
            case 'string':
              typeValid = typeof value === 'string';
              break;
            case 'number':
              typeValid = typeof value === 'number' || (typeof value === 'string' && !isNaN(Number(value)));
              break;
            case 'boolean':
              typeValid = typeof value === 'boolean' || value === 'true' || value === 'false';
              break;
            case 'object':
              typeValid = typeof value === 'object' && !Array.isArray(value);
              break;
            case 'array':
              typeValid = Array.isArray(value);
              break;
          }

          if (!typeValid) {
            errors.push(rule.message || `${rule.field} must be a ${rule.type}`);
            continue;
          }
        }

        // String-specific validations
        if (typeof value === 'string') {
          // Min length
          if (rule.minLength !== undefined && value.length < rule.minLength) {
            errors.push(rule.message || `${rule.field} must be at least ${rule.minLength} characters long`);
          }

          // Max length
          if (rule.maxLength !== undefined && value.length > rule.maxLength) {
            errors.push(rule.message || `${rule.field} must be at most ${rule.maxLength} characters long`);
          }

          // Pattern
          if (rule.pattern && !rule.pattern.test(value)) {
            errors.push(rule.message || `${rule.field} has an invalid format`);
          }
        }

        // Number-specific validations
        if (typeof value === 'number' || (typeof value === 'string' && !isNaN(Number(value)))) {
          const numValue = Number(value);

          // Min
          if (rule.min !== undefined && numValue < rule.min) {
            errors.push(rule.message || `${rule.field} must be at least ${rule.min}`);
          }

          // Max
          if (rule.max !== undefined && numValue > rule.max) {
            errors.push(rule.message || `${rule.field} must be at most ${rule.max}`);
          }
        }

        // Custom validator
        if (rule.custom && !(await Promise.resolve(rule.custom(value)))) {
          errors.push(rule.message || `${rule.field} is invalid`);
        }
      }

      // Return errors if any
      if (errors.length > 0) {
        return next(ApiError.badRequest(errors.join(', ')));
      }

      // All validations passed
      next();
    } catch (error) {
      next(error);
    }
  };
};

// Common validators

// Fix: Explicitly type the return value to match ValidationRule interface
export const emailValidator: ValidationRule = {
  field: 'email',
  required: true,
  type: 'string',
  pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  message: 'Please provide a valid email address'
};

// Fix: Explicitly type the return value to match ValidationRule interface
export const passwordValidator: ValidationRule = {
  field: 'password',
  required: true,
  type: 'string',
  minLength: 8,
  message: 'Password must be at least 8 characters long'
};

// Fix: Ensure the uuidValidator returns a ValidationRule object
export const uuidValidator = (field: string = 'id'): ValidationRule => ({
  field,
  required: true,
  type: 'string',
  pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  message: `${field} must be a valid UUID`
});

// Specific validator examples

// Auth validators
export const registerValidator = createValidator([
  emailValidator,
  passwordValidator
]);

export const loginValidator = createValidator([
  emailValidator,
  passwordValidator
]);

// Wardrobe validators
export const createWardrobeValidator = createValidator([
  {
    field: 'name',
    required: true,
    type: 'string',
    minLength: 1,
    maxLength: 100,
    message: 'Wardrobe name is required and must be between 1 and 100 characters'
  },
  {
    field: 'description',
    required: false,
    type: 'string',
    maxLength: 1000,
    message: 'Wardrobe description must be at most 1000 characters'
  }
]);

// Garment validators
export const garmentMetadataValidator = createValidator([
  {
    field: 'metadata',
    required: true,
    type: 'object',
    message: 'Metadata must be a valid object'
  }
]);

// Add garment to wardrobe validator
export const addGarmentToWardrobeValidator = createValidator([
  uuidValidator('garmentId'),
  {
    field: 'position',
    required: false,
    type: 'number',
    min: 0,
    message: 'Position must be a non-negative number'
  }
]);