"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.performanceUtils = exports.schemaUtils = exports.transformErrors = exports.isValid = exports.createValidationMiddleware = exports.MobileValidator = exports.BackendValidator = exports.UniversalValidator = void 0;
const zod_1 = require("zod");
// ==================== UNIVERSAL VALIDATOR CLASS ====================
class UniversalValidator {
    /**
     * Validate data against a Zod schema with consistent error formatting
     */
    static validate(schema, data, options = {}) {
        try {
            const result = schema.safeParse(data);
            if (result.success) {
                return {
                    success: true,
                    data: result.data
                };
            }
            else {
                return {
                    success: false,
                    errors: this.formatZodErrors(result.error)
                };
            }
        }
        catch (error) {
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
    static async validateAsync(schema, data, options = {}) {
        try {
            const result = await schema.safeParseAsync(data);
            if (result.success) {
                return {
                    success: true,
                    data: result.data
                };
            }
            else {
                return {
                    success: false,
                    errors: this.formatZodErrors(result.error)
                };
            }
        }
        catch (error) {
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
    static formatZodErrors(zodError) {
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
    static validatePartial(schema, data, options = {}) {
        // Use partial() instead of deepPartial() for better compatibility
        if ('partial' in schema) {
            const partialSchema = schema.partial();
            return this.validate(partialSchema, data, options);
        }
        // Fallback for non-object schemas
        return this.validate(schema.optional(), data, options);
    }
    /**
     * Validate array of items
     */
    static validateArray(itemSchema, data, options = {}) {
        const arraySchema = zod_1.z.array(itemSchema);
        return this.validate(arraySchema, data, options);
    }
    /**
     * Create a validator function for a specific schema
     */
    static createValidator(schema) {
        return (data, options = {}) => this.validate(schema, data, options);
    }
}
exports.UniversalValidator = UniversalValidator;
// ==================== PLATFORM-SPECIFIC VALIDATORS ====================
/**
 * Backend-specific validator with enhanced error context
 */
class BackendValidator extends UniversalValidator {
    /**
     * Validate with business context for better error reporting
     */
    static validateWithContext(schema, data, context) {
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
    static validateWithMetrics(schema, data, options = {}) {
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
    static calculateSchemaComplexity(schema) {
        // Simplified complexity calculation
        try {
            return JSON.stringify(schema).length / 1000;
        }
        catch {
            return 1; // Fallback for non-serializable schemas
        }
    }
}
exports.BackendValidator = BackendValidator;
/**
 * Mobile-specific validator optimized for performance
 */
class MobileValidator extends UniversalValidator {
    /**
     * Lightweight validation for mobile with reduced error details
     */
    static validateLightweight(schema, data) {
        const result = this.validate(schema, data);
        if (result.success) {
            return { success: true, data: result.data };
        }
        else {
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
    static validateRequired(schema, data, requiredFields) {
        try {
            // This is a simplified implementation
            // In practice, you'd need to extract the shape from the schema
            const result = this.validate(schema, data);
            if (result.success && result.data) {
                // Filter to only required fields
                const filteredData = {};
                const validData = result.data; // Create a non-nullable reference
                requiredFields.forEach(field => {
                    if (field in validData) {
                        filteredData[field] = validData[field];
                    }
                });
                return { success: true, data: filteredData };
            }
            return result;
        }
        catch (error) {
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
    static validateBatch(schema, dataArray) {
        const validItems = [];
        const invalidItems = [];
        dataArray.forEach((item, index) => {
            const result = this.validate(schema, item);
            if (result.success && result.data) {
                validItems.push(result.data);
            }
            else {
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
exports.MobileValidator = MobileValidator;
// ==================== VALIDATION MIDDLEWARE FACTORIES ====================
/**
 * Create validation middleware for different platforms
 */
const createValidationMiddleware = {
    /**
     * Express middleware factory for backend
     */
    forExpress: (schema, source = 'body') => {
        return (req, res, next) => {
            const result = BackendValidator.validateWithContext(schema, req[source], {
                operation: `validate_${source}`,
                resource: req.route?.path,
                userId: req.user?.id
            });
            if (result.success) {
                req[source] = result.data;
                next();
            }
            else {
                const error = new Error('Validation failed');
                error.statusCode = 400;
                error.code = 'VALIDATION_ERROR';
                error.details = result.errors;
                next(error);
            }
        };
    },
    /**
     * React Native form validation factory
     */
    forReactNative: (schema) => {
        return (data) => MobileValidator.validateLightweight(schema, data);
    },
    /**
     * Real-time validation for forms
     */
    forRealTime: (schema, debounceMs = 300) => {
        let timeoutId;
        let lastValidation = null;
        return (data, callback) => {
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
exports.createValidationMiddleware = createValidationMiddleware;
// ==================== UTILITY FUNCTIONS ====================
/**
 * Check if a value matches a schema without throwing
 */
const isValid = (schema, data) => {
    const result = schema.safeParse(data);
    return result.success;
};
exports.isValid = isValid;
/**
 * Transform validation errors to different formats
 */
const transformErrors = {
    /**
     * Convert to field-error object for forms
     */
    toFieldErrors: (errors) => {
        const fieldErrors = {};
        errors.forEach(error => {
            fieldErrors[error.field] = error.message;
        });
        return fieldErrors;
    },
    /**
     * Convert to flat array of error messages
     */
    toMessages: (errors) => {
        return errors.map(error => `${error.field}: ${error.message}`);
    },
    /**
     * Convert to API error format
     */
    toApiError: (errors) => ({
        status: 'error',
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        errors
    })
};
exports.transformErrors = transformErrors;
/**
 * Schema composition utilities
 */
const schemaUtils = {
    /**
     * Merge multiple schemas
     */
    merge: (schemas) => {
        return zod_1.z.object(schemas);
    },
    /**
     * Make all fields optional
     */
    makeOptional: (schema) => {
        if ('partial' in schema) {
            return schema.partial();
        }
        return schema.optional();
    },
    /**
     * Pick specific fields from a schema
     */
    pick: (schema, keys) => {
        if ('pick' in schema) {
            const pickObject = keys.reduce((acc, key) => ({ ...acc, [key]: true }), {});
            return schema.pick(pickObject);
        }
        throw new Error('Schema does not support pick operation');
    },
    /**
     * Omit specific fields from a schema
     */
    omit: (schema, keys) => {
        if ('omit' in schema) {
            const omitObject = keys.reduce((acc, key) => ({ ...acc, [key]: true }), {});
            return schema.omit(omitObject);
        }
        throw new Error('Schema does not support omit operation');
    }
};
exports.schemaUtils = schemaUtils;
/**
 * Performance optimization utilities
 */
const performanceUtils = {
    /**
     * Memoize schema validation results
     */
    memoizeValidator: (schema, maxCacheSize = 100) => {
        const cache = new Map();
        return (data) => {
            const key = JSON.stringify(data);
            if (cache.has(key)) {
                return cache.get(key);
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
    lazySchema: (schemaFactory) => {
        let compiled = null;
        return {
            validate: (data) => {
                if (!compiled) {
                    compiled = schemaFactory();
                }
                return UniversalValidator.validate(compiled, data);
            }
        };
    }
};
exports.performanceUtils = performanceUtils;
//# sourceMappingURL=index.js.map