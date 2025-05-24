import { z } from 'zod';

// ==================== VALIDATION RESULT TYPES ====================

interface ValidationResult<T = any> {
  success: boolean;
  data?: T;
  errors?: ValidationError[];
}

interface ValidationError {
  field: string;
  message: string;
  code?: string;
  value?: any;
  context?: Record<string, any>;
}

interface ValidationOptions {
  stripUnknown?: boolean;
  abortEarly?: boolean;
  allowUnknown?: boolean;
}

// ==================== UNIVERSAL VALIDATOR CLASS ====================

class UniversalValidator {
  /**
   * Validate data against a Zod schema with consistent error formatting
   */
  static validate<T>(
    schema: z.ZodSchema<T>, 
    data: unknown, 
    options: ValidationOptions = {}
  ): ValidationResult<T> {
    try {
      const result = schema.safeParse(data);
      
      if (result.success) {
        return {
          success: true,
          data: result.data
        };
      } else {
        return {
          success: false,
          errors: this.formatZodErrors(result.error)
        };
      }
    } catch (error) {
      return {
        success: false,
        errors: [{
          field: 'unknown',
          message: error instanceof Error ? error.message : 'Validation failed',
          code: 'VALIDATION_ERROR'
        }]
      };
    }
  }

  /**
   * Async validation for schemas with async refinements
   */
  static async validateAsync<T>(
    schema: z.ZodSchema<T>, 
    data: unknown, 
    options: ValidationOptions = {}
  ): Promise<ValidationResult<T>> {
    try {
      const result = await schema.safeParseAsync(data);
      
      if (result.success) {
        return {
          success: true,
          data: result.data
        };
      } else {
        return {
          success: false,
          errors: this.formatZodErrors(result.error)
        };
      }
    } catch (error) {
      return {
        success: false,
        errors: [{
          field: 'unknown',
          message: error instanceof Error ? error.message : 'Async validation failed',
          code: 'ASYNC_VALIDATION_ERROR'
        }]
      };
    }
  }

  /**
   * Format Zod errors into consistent ValidationError format
   */
  private static formatZodErrors(zodError: z.ZodError): ValidationError[] {
    return zodError.issues.map(issue => ({
      field: issue.path.join('.') || 'root',
      message: issue.message,
      code: issue.code,
      value: undefined // Simplified - we don't have access to original data here
    }));
  }

  /**
   * Validate partial data (useful for updates)
   */
  static validatePartial<T>(
    schema: z.ZodSchema<T>, 
    data: unknown, 
    options: ValidationOptions = {}
  ): ValidationResult<Partial<T>> {
    // Use partial() instead of deepPartial() for better compatibility
    if ('partial' in schema) {
      const partialSchema = (schema as any).partial();
      return this.validate(partialSchema, data, options);
    }
    // Fallback for non-object schemas
    return this.validate(schema.optional(), data, options) as ValidationResult<Partial<T>>;
  }

  /**
   * Validate array of items
   */
  static validateArray<T>(
    itemSchema: z.ZodSchema<T>, 
    data: unknown[], 
    options: ValidationOptions = {}
  ): ValidationResult<T[]> {
    const arraySchema = z.array(itemSchema);
    return this.validate(arraySchema, data, options);
  }

  /**
   * Create a validator function for a specific schema
   */
  static createValidator<T>(schema: z.ZodSchema<T>) {
    return (data: unknown, options: ValidationOptions = {}) => 
      this.validate(schema, data, options);
  }
}

// ==================== PLATFORM-SPECIFIC VALIDATORS ====================

/**
 * Backend-specific validator with enhanced error context
 */
class BackendValidator extends UniversalValidator {
  /**
   * Validate with business context for better error reporting
   */
  static validateWithContext<T>(
    schema: z.ZodSchema<T>,
    data: unknown,
    context: {
      operation?: string;
      resource?: string;
      userId?: string;
    }
  ): ValidationResult<T> & { context?: typeof context } {
    const result = this.validate(schema, data);
    
    if (!result.success && result.errors) {
      // Enhance errors with business context
      result.errors = result.errors.map(error => ({
        ...error,
        context: {
          operation: context.operation,
          resource: context.resource,
          userId: context.userId
        }
      }));
    }
    
    return { ...result, context };
  }

  /**
   * Validate with performance monitoring
   */
  static validateWithMetrics<T>(
    schema: z.ZodSchema<T>,
    data: unknown,
    options: ValidationOptions = {}
  ): ValidationResult<T> & { metrics: { duration: number; complexity: number } } {
    const startTime = Date.now();
    const result = this.validate(schema, data, options);
    const duration = Date.now() - startTime;
    
    // Simple complexity calculation based on schema depth
    const complexity = this.calculateSchemaComplexity(schema);
    
    return {
      ...result,
      metrics: { duration, complexity }
    };
  }

  private static calculateSchemaComplexity(schema: z.ZodSchema): number {
    // Simplified complexity calculation
    try {
      return JSON.stringify(schema).length / 1000;
    } catch {
      return 1; // Fallback for non-serializable schemas
    }
  }
}

/**
 * Mobile-specific validator optimized for performance
 */
class MobileValidator extends UniversalValidator {
  /**
   * Lightweight validation for mobile with reduced error details
   */
  static validateLightweight<T>(
    schema: z.ZodSchema<T>,
    data: unknown
  ): { success: boolean; data?: T; error?: string } {
    const result = this.validate(schema, data);
    
    if (result.success) {
      return { success: true, data: result.data };
    } else {
      // Return simplified error for mobile
      const firstError = result.errors?.[0];
      return { 
        success: false, 
        error: firstError ? `${firstError.field}: ${firstError.message}` : 'Validation failed'
      };
    }
  }

  /**
   * Validate only required fields for mobile forms
   */
  static validateRequired<T extends Record<string, any>>(
    schema: z.ZodSchema<T>,
    data: unknown,
    requiredFields: (keyof T)[]
  ): ValidationResult<Pick<T, keyof T & string>> {
    try {
      // This is a simplified implementation
      // In practice, you'd need to extract the shape from the schema
      const result = this.validate(schema, data);
        if (result.success && result.data) {
          // Filter to only required fields
          const filteredData: any = {};
          const validData = result.data; // Create a non-nullable reference
          requiredFields.forEach(field => {
            if (field in validData) {
              filteredData[field] = validData[field];
            }
          });
          return { success: true, data: filteredData };
        }
      return result as ValidationResult<Pick<T, keyof T & string>>;
    } catch (error) {
      return {
        success: false,
        errors: [{
          field: 'schema',
          message: 'Failed to validate required fields',
          code: 'SCHEMA_ERROR'
        }]
      };
    }
  }

  /**
   * Batch validation for offline sync
   */
  static validateBatch<T>(
    schema: z.ZodSchema<T>,
    dataArray: unknown[]
  ): { success: boolean; validItems: T[]; invalidItems: { index: number; errors: ValidationError[] }[] } {
    const validItems: T[] = [];
    const invalidItems: { index: number; errors: ValidationError[] }[] = [];

    dataArray.forEach((item, index) => {
      const result = this.validate(schema, item);
      if (result.success && result.data) {
        validItems.push(result.data);
      } else {
        invalidItems.push({
          index,
          errors: result.errors || []
        });
      }
    });

    return {
      success: invalidItems.length === 0,
      validItems,
      invalidItems
    };
  }
}

// ==================== VALIDATION MIDDLEWARE FACTORIES ====================

/**
 * Create validation middleware for different platforms
 */
const createValidationMiddleware = {
  /**
   * Express middleware factory for backend
   */
  forExpress: <T>(schema: z.ZodSchema<T>, source: 'body' | 'query' | 'params' = 'body') => {
    return (req: any, res: any, next: any) => {
      const result = BackendValidator.validateWithContext(
        schema, 
        req[source],
        {
          operation: `validate_${source}`,
          resource: req.route?.path,
          userId: req.user?.id
        }
      );

      if (result.success) {
        req[source] = result.data;
        next();
      } else {
        const error = new Error('Validation failed');
        (error as any).statusCode = 400;
        (error as any).code = 'VALIDATION_ERROR';
        (error as any).details = result.errors;
        next(error);
      }
    };
  },

  /**
   * React Native form validation factory
   */
  forReactNative: <T>(schema: z.ZodSchema<T>) => {
    return (data: unknown) => MobileValidator.validateLightweight(schema, data);
  },

  /**
   * Real-time validation for forms
   */
  forRealTime: <T>(schema: z.ZodSchema<T>, debounceMs: number = 300) => {
    let timeoutId: NodeJS.Timeout;
    let lastValidation: ValidationResult<T> | null = null;

    return (data: unknown, callback: (result: ValidationResult<T>) => void) => {
      clearTimeout(timeoutId);
      
      timeoutId = setTimeout(() => {
        const result = UniversalValidator.validate(schema, data); // Fixed: use UniversalValidator
        lastValidation = result;
        callback(result);
      }, debounceMs);

      // Return last validation immediately for better UX
      return lastValidation;
    };
  }
};

// ==================== UTILITY FUNCTIONS ====================

/**
 * Check if a value matches a schema without throwing
 */
const isValid = <T>(schema: z.ZodSchema<T>, data: unknown): data is T => {
  const result = schema.safeParse(data);
  return result.success;
};

/**
 * Transform validation errors to different formats
 */
const transformErrors = {
  /**
   * Convert to field-error object for forms
   */
  toFieldErrors: (errors: ValidationError[]): Record<string, string> => {
    const fieldErrors: Record<string, string> = {};
    errors.forEach(error => {
      fieldErrors[error.field] = error.message;
    });
    return fieldErrors;
  },

  /**
   * Convert to flat array of error messages
   */
  toMessages: (errors: ValidationError[]): string[] => {
    return errors.map(error => `${error.field}: ${error.message}`);
  },

  /**
   * Convert to API error format
   */
  toApiError: (errors: ValidationError[]) => ({
    status: 'error' as const,
    code: 'VALIDATION_ERROR',
    message: 'Validation failed',
    errors
  })
};

/**
 * Schema composition utilities
 */
const schemaUtils = {
  /**
   * Merge multiple schemas
   */
  merge: <T extends Record<string, z.ZodSchema>>(schemas: T) => {
    return z.object(schemas);
  },

  /**
   * Make all fields optional
   */
  makeOptional: <T>(schema: z.ZodSchema<T>) => {
    if ('partial' in schema) {
      return (schema as any).partial();
    }
    return schema.optional();
  },

  /**
   * Pick specific fields from a schema
   */
  pick: <T, K extends keyof T>(schema: z.ZodSchema<T>, keys: K[]) => {
    if ('pick' in schema) {
      const pickObject = keys.reduce((acc, key) => ({ ...acc, [key]: true }), {} as Record<K, true>);
      return (schema as any).pick(pickObject);
    }
    throw new Error('Schema does not support pick operation');
  },

  /**
   * Omit specific fields from a schema
   */
  omit: <T, K extends keyof T>(schema: z.ZodSchema<T>, keys: K[]) => {
    if ('omit' in schema) {
      const omitObject = keys.reduce((acc, key) => ({ ...acc, [key]: true }), {} as Record<K, true>);
      return (schema as any).omit(omitObject);
    }
    throw new Error('Schema does not support omit operation');
  }
};

/**
 * Performance optimization utilities
 */
const performanceUtils = {
  /**
   * Memoize schema validation results
   */
  memoizeValidator: <T>(schema: z.ZodSchema<T>, maxCacheSize: number = 100) => {
    const cache = new Map<string, ValidationResult<T>>();

    return (data: unknown): ValidationResult<T> => {
      const key = JSON.stringify(data);
      
      if (cache.has(key)) {
        return cache.get(key)!;
      }

      const result = UniversalValidator.validate(schema, data);
      
      // Simple LRU cache
      if (cache.size >= maxCacheSize) {
        const firstKey = cache.keys().next().value;
        if (firstKey !== undefined) {
          cache.delete(firstKey);
        }
      }
      
      cache.set(key, result);
      return result;
    };
  },

  /**
   * Lazy schema compilation
   */
  lazySchema: <T>(schemaFactory: () => z.ZodSchema<T>) => {
    let compiled: z.ZodSchema<T> | null = null;
    
    return {
      validate: (data: unknown) => {
        if (!compiled) {
          compiled = schemaFactory();
        }
        return UniversalValidator.validate(compiled, data);
      }
    };
  }
};

// ==================== EXPORTS ====================

// Export all types
export type {
  ValidationResult,
  ValidationError,
  ValidationOptions
};

// Export all classes
export {
  UniversalValidator,
  BackendValidator,
  MobileValidator
};

// Export all utilities
export {
  createValidationMiddleware,
  isValid,
  transformErrors,
  schemaUtils,
  performanceUtils
};