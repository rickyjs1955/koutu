import { z } from 'zod';
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
declare class UniversalValidator {
    /**
     * Validate data against a Zod schema with consistent error formatting
     */
    static validate<T>(schema: z.ZodSchema<T>, data: unknown, options?: ValidationOptions): ValidationResult<T>;
    /**
     * Async validation for schemas with async refinements
     */
    static validateAsync<T>(schema: z.ZodSchema<T>, data: unknown, options?: ValidationOptions): Promise<ValidationResult<T>>;
    /**
     * Format Zod errors into consistent ValidationError format
     */
    private static formatZodErrors;
    /**
     * Validate partial data (useful for updates)
     */
    static validatePartial<T>(schema: z.ZodSchema<T>, data: unknown, options?: ValidationOptions): ValidationResult<Partial<T>>;
    /**
     * Validate array of items
     */
    static validateArray<T>(itemSchema: z.ZodSchema<T>, data: unknown[], options?: ValidationOptions): ValidationResult<T[]>;
    /**
     * Create a validator function for a specific schema
     */
    static createValidator<T>(schema: z.ZodSchema<T>): (data: unknown, options?: ValidationOptions) => ValidationResult<T>;
}
/**
 * Backend-specific validator with enhanced error context
 */
declare class BackendValidator extends UniversalValidator {
    /**
     * Validate with business context for better error reporting
     */
    static validateWithContext<T>(schema: z.ZodSchema<T>, data: unknown, context: {
        operation?: string;
        resource?: string;
        userId?: string;
    }): ValidationResult<T> & {
        context?: typeof context;
    };
    /**
     * Validate with performance monitoring
     */
    static validateWithMetrics<T>(schema: z.ZodSchema<T>, data: unknown, options?: ValidationOptions): ValidationResult<T> & {
        metrics: {
            duration: number;
            complexity: number;
        };
    };
    private static calculateSchemaComplexity;
}
/**
 * Mobile-specific validator optimized for performance
 */
declare class MobileValidator extends UniversalValidator {
    /**
     * Lightweight validation for mobile with reduced error details
     */
    static validateLightweight<T>(schema: z.ZodSchema<T>, data: unknown): {
        success: boolean;
        data?: T;
        error?: string;
    };
    /**
     * Validate only required fields for mobile forms
     */
    static validateRequired<T extends Record<string, any>>(schema: z.ZodSchema<T>, data: unknown, requiredFields: (keyof T)[]): ValidationResult<Pick<T, keyof T & string>>;
    /**
     * Batch validation for offline sync
     */
    static validateBatch<T>(schema: z.ZodSchema<T>, dataArray: unknown[]): {
        success: boolean;
        validItems: T[];
        invalidItems: {
            index: number;
            errors: ValidationError[];
        }[];
    };
}
/**
 * Create validation middleware for different platforms
 */
declare const createValidationMiddleware: {
    /**
     * Express middleware factory for backend
     */
    forExpress: <T>(schema: z.ZodSchema<T>, source?: "body" | "query" | "params") => (req: any, res: any, next: any) => void;
    /**
     * React Native form validation factory
     */
    forReactNative: <T>(schema: z.ZodSchema<T>) => (data: unknown) => {
        success: boolean;
        data?: T | undefined;
        error?: string;
    };
    /**
     * Real-time validation for forms
     */
    forRealTime: <T>(schema: z.ZodSchema<T>, debounceMs?: number) => (data: unknown, callback: (result: ValidationResult<T>) => void) => ValidationResult<T> | null;
};
/**
 * Check if a value matches a schema without throwing
 */
declare const isValid: <T>(schema: z.ZodSchema<T>, data: unknown) => data is T;
/**
 * Transform validation errors to different formats
 */
declare const transformErrors: {
    /**
     * Convert to field-error object for forms
     */
    toFieldErrors: (errors: ValidationError[]) => Record<string, string>;
    /**
     * Convert to flat array of error messages
     */
    toMessages: (errors: ValidationError[]) => string[];
    /**
     * Convert to API error format
     */
    toApiError: (errors: ValidationError[]) => {
        status: "error";
        code: string;
        message: string;
        errors: ValidationError[];
    };
};
/**
 * Schema composition utilities
 */
declare const schemaUtils: {
    /**
     * Merge multiple schemas
     */
    merge: <T extends Record<string, z.ZodSchema>>(schemas: T) => z.ZodObject<T, "strip", z.ZodTypeAny, z.objectUtil.addQuestionMarks<z.baseObjectOutputType<T>, any> extends infer T_1 ? { [k in keyof T_1]: z.objectUtil.addQuestionMarks<z.baseObjectOutputType<T>, any>[k]; } : never, z.baseObjectInputType<T> extends infer T_2 ? { [k_1 in keyof T_2]: z.baseObjectInputType<T>[k_1]; } : never>;
    /**
     * Make all fields optional
     */
    makeOptional: <T>(schema: z.ZodSchema<T>) => any;
    /**
     * Pick specific fields from a schema
     */
    pick: <T, K extends keyof T>(schema: z.ZodSchema<T>, keys: K[]) => any;
    /**
     * Omit specific fields from a schema
     */
    omit: <T, K extends keyof T>(schema: z.ZodSchema<T>, keys: K[]) => any;
};
/**
 * Performance optimization utilities
 */
declare const performanceUtils: {
    /**
     * Memoize schema validation results
     */
    memoizeValidator: <T>(schema: z.ZodSchema<T>, maxCacheSize?: number) => (data: unknown) => ValidationResult<T>;
    /**
     * Lazy schema compilation
     */
    lazySchema: <T>(schemaFactory: () => z.ZodSchema<T>) => {
        validate: (data: unknown) => ValidationResult<T>;
    };
};
export type { ValidationResult, ValidationError, ValidationOptions };
export { UniversalValidator, BackendValidator, MobileValidator };
export { createValidationMiddleware, isValid, transformErrors, schemaUtils, performanceUtils };
//# sourceMappingURL=index.d.ts.map