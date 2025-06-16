// backend/src/tests/unit/validate.unit.test.ts

import { describe, it, expect } from '@jest/globals';
import { Request, Response } from 'express';
import { z } from 'zod';

// Import validation middleware
import {
  validate,
  validateBody,
  validateQuery,
  validateParams,
  validateFile,
  validateUUIDParam,
  validateImageQuery,
  createValidationMiddleware,
  validateAuthTypes,
  validateRequestTypes
} from '../../middlewares/validate';

// Import test utilities
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  TestSchema,
  TestParamsSchema,
  mockValidData,
  mockInvalidData,
  mockValidFile,
  mockInvalidFile,
  mockOversizedFile,
  expectNoError,
  edgeCaseData
} from '../__mocks__/validate.mock';

import {
  setupValidationTestEnvironment,
  testMiddlewareWithData,
  expectMiddlewareSuccess,
  expectMiddlewareError,
  testSchemaValidation,
  createTestDataFactory
} from '../__helpers__/validate.helper';

// Import schemas for testing
import { ApiError } from '../../utils/ApiError';

/**
 * Create a test schema that properly validates input and rejects malicious content
 */
export const createSecureTestSchema = () => {
  return z.object({
    publicField: z.string().min(1, 'Public field is required'),
    // Optional fields that should not be revealed in errors
    apiKey: z.string().optional(),
    internalSecret: z.string().optional(),
    databasePassword: z.string().optional()
  }).strict(); // Use strict to reject unknown fields
};

/**
 * Helper to test validation with timing consistency
 */
export const testValidationTiming = async (validator: any, testData: any[], iterations: number = 10) => {
  const timings: number[] = [];
  
  for (let i = 0; i < iterations; i++) {
    const promises = testData.map(async (data) => {
      const start = performance.now();
      const result = await testMiddlewareWithData(validator, data, 'body');
      const end = performance.now();
      return end - start;
    });
    
    const batchTimings = await Promise.all(promises);
    timings.push(...batchTimings);
  }
  
  return timings;
};

/**
 * Enhanced schema that properly rejects malicious input patterns
 */
export const createMaliciousInputTestSchema = () => {
  return z.object({
    name: z.string()
      .min(1, 'Name is required')
      .refine(val => !/<script/i.test(val), 'XSS content not allowed')
      .refine(val => !/DROP\s+TABLE/i.test(val), 'SQL injection not allowed')
      .refine(val => !val.includes('..'), 'Path traversal not allowed'),
    email: z.string()
      .email('Invalid email format')
      .refine(val => !val.includes(';'), 'Invalid email format'),
    age: z.number()
      .min(18, 'Must be at least 18')
      .max(120, 'Age too high')
      .optional()
  });
};

/**
 * Test data generator that creates mixed valid/invalid data for load testing
 */
export const generateMixedValidationData = (batchSize: number) => {
  return Array(batchSize).fill(0).map((_, i) => {
    // Create alternating valid/invalid data
    if (i % 2 === 0) {
      return {
        name: `Valid User ${i}`,
        email: `user${i}@example.com`,
        age: 25
      };
    } else {
      return {
        name: '', // Invalid - empty string
        email: `user${i}@example.com`,
        age: 25
      };
    }
  });
};

/**
 * Helper to run security validation tests with proper error handling
 */
export const runSecurityValidationTest = async (
  validatorFactory: (schema: z.ZodSchema) => any,
  schema: z.ZodSchema,
  maliciousInputs: any[]
) => {
  const results = [];
  
  for (const maliciousInput of maliciousInputs) {
    const middleware = validatorFactory(schema);
    const result = await testMiddlewareWithData(middleware, maliciousInput, 'body');
    
    // Check if validation properly rejected the malicious input
    const wasRejected = result.next.mock.calls.length > 0 && result.next.mock.calls[0][0];
    
    results.push({
      input: maliciousInput,
      rejected: wasRejected,
      error: wasRejected ? result.next.mock.calls[0][0] : null
    });
  }
  
  return results;
};

/**
 * Test helper for concurrent validation that ensures proper load distribution
 */
export const testConcurrentValidationLoad = async (
  validator: any,
  testDataGenerator: (count: number) => any[],
  concurrency: number = 50
) => {
  const testData = testDataGenerator(concurrency);
  
  const startTime = performance.now();
  
  const results = await Promise.all(
    testData.map(async (data, index) => {
      try {
        const result = await testMiddlewareWithData(validator, data, 'body');
        return {
          index,
          success: result.next.mock.calls.length === 0,
          error: result.next.mock.calls.length > 0 ? result.next.mock.calls[0][0] : null
        };
      } catch (error) {
        return {
          index,
          success: false,
          error
        };
      }
    })
  );
  
  const endTime = performance.now();
  
  return {
    results,
    executionTime: endTime - startTime,
    successCount: results.filter(r => r.success).length,
    errorCount: results.filter(r => !r.success).length
  };
};

describe('Validation Middleware Unit Tests', () => {
  setupValidationTestEnvironment();
  
  const testDataFactory = createTestDataFactory();

  describe('validate() function', () => {
    it('should validate body data successfully with valid input', async () => {
      const middleware = validate(TestSchema, 'body');
      const result = await testMiddlewareWithData(middleware, mockValidData.body, 'body');
      
      expectMiddlewareSuccess(result.req, result.next, mockValidData.body, 'body');
    });

    it('should validate query data successfully with valid input', async () => {
      const querySchema = z.object({
        search: z.string().optional(),
        limit: z.string().optional()
      });
      
      const middleware = validate(querySchema, 'query');
      const testQuery = { search: 'test', limit: '10' };
      const result = await testMiddlewareWithData(middleware, testQuery, 'query');
      
      expectMiddlewareSuccess(result.req, result.next, testQuery, 'query');
    });

    it('should validate params data successfully with valid input', async () => {
      const middleware = validate(TestParamsSchema, 'params');
      const result = await testMiddlewareWithData(middleware, mockValidData.params, 'params');
      
      expectMiddlewareSuccess(result.req, result.next, mockValidData.params, 'params');
    });

    it('should reject invalid body data and return ApiError', async () => {
      const middleware = validate(TestSchema, 'body');
      const result = await testMiddlewareWithData(middleware, mockInvalidData.body, 'body');
      
      const error = expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      expect(error).toBeInstanceOf(ApiError);
      expect(error.context).toBeDefined();
      expect(error.context.validationErrors).toBeDefined();
      expect(error.context.source).toBe('body');
    });

    it('should handle async validation with parseAsync', async () => {
      const asyncSchema = z.object({
        name: z.string().refine(async (val) => {
          // Simulate async validation
          await new Promise(resolve => setTimeout(resolve, 10));
          return val.length > 0;
        }, 'Name cannot be empty')
      });

      const middleware = validate(asyncSchema, 'body');
      const result = await testMiddlewareWithData(middleware, { name: 'Valid Name' }, 'body');
      
      expectMiddlewareSuccess(result.req, result.next, { name: 'Valid Name' }, 'body');
    });

    it('should handle non-ZodError exceptions gracefully', async () => {
      const faultySchema = z.object({
        name: z.string().transform(() => {
          throw new Error('Unexpected transform error');
        })
      });

      const middleware = validate(faultySchema, 'body');
      const result = await testMiddlewareWithData(middleware, { name: 'test' }, 'body');
      
      expect(result.next).toHaveBeenCalledWith(expect.any(Error));
      const error = result.next.mock.calls[0][0] as unknown as Error;
      expect(error.message).toBe('Unexpected transform error');
    });
  });

  describe('createValidationMiddleware() function', () => {
    it('should validate data successfully with valid input', async () => {
      const middleware = createValidationMiddleware(TestSchema, 'body');
      const result = await testMiddlewareWithData(middleware, mockValidData.body, 'body');
      
      expectMiddlewareSuccess(result.req, result.next, mockValidData.body, 'body');
    });

    it('should reject invalid data with custom error format', async () => {
      const middleware = createValidationMiddleware(TestSchema, 'body');
      const result = await testMiddlewareWithData(middleware, mockInvalidData.body, 'body');
      
      const error = expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      expect(error.message).toBe('Validation failed');
      expect(error.details).toBeDefined();
      expect(Array.isArray(error.details)).toBe(true);
    });

    it('should handle middleware errors with proper error codes', async () => {
      // Force an error by passing invalid schema
      const middleware = createValidationMiddleware(null as any, 'body');
      const result = await testMiddlewareWithData(middleware, mockValidData.body, 'body');
      
      const error = expectMiddlewareError(result.next, 'MIDDLEWARE_ERROR', 500);
      expect(error.originalError).toBeDefined();
    });

    it('should transform data correctly', async () => {
      const transformSchema = z.object({
        name: z.string().transform(s => s.toUpperCase()),
        age: z.string().transform(s => parseInt(s, 10))
      });

      const middleware = createValidationMiddleware(transformSchema, 'body');
      const inputData = { name: 'john', age: '25' };
      const expectedData = { name: 'JOHN', age: 25 };
      
      const result = await testMiddlewareWithData(middleware, inputData, 'body');
      
      expectMiddlewareSuccess(result.req, result.next, expectedData, 'body');
    });
  });

  describe('validateBody() function', () => {
    it('should create body validation middleware', async () => {
      const middleware = validateBody(TestSchema);
      const result = await testMiddlewareWithData(middleware, mockValidData.body, 'body');
      
      expectMiddlewareSuccess(result.req, result.next, mockValidData.body, 'body');
    });

    it('should reject invalid body data', async () => {
      const middleware = validateBody(TestSchema);
      const result = await testMiddlewareWithData(middleware, mockInvalidData.body, 'body');
      
      expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
    });
  });

  describe('validateQuery() function', () => {
    it('should create query validation middleware', async () => {
      const querySchema = z.object({
        search: z.string().optional(),
        limit: z.string().transform(s => parseInt(s, 10)).optional()
      });
      
      const middleware = validateQuery(querySchema);
      const queryData = { search: 'test', limit: '10' };
      const expectedData = { search: 'test', limit: 10 };
      
      const result = await testMiddlewareWithData(middleware, queryData, 'query');
      
      expectMiddlewareSuccess(result.req, result.next, expectedData, 'query');
    });

    it('should handle empty query parameters', async () => {
      const querySchema = z.object({
        search: z.string().optional(),
        active: z.string().optional()
      });
      
      const middleware = validateQuery(querySchema);
      const result = await testMiddlewareWithData(middleware, {}, 'query');
      
      expectMiddlewareSuccess(result.req, result.next, {}, 'query');
    });
  });

  describe('validateParams() function', () => {
    it('should create params validation middleware', async () => {
      const middleware = validateParams(TestParamsSchema);
      const result = await testMiddlewareWithData(middleware, mockValidData.params, 'params');
      
      expectMiddlewareSuccess(result.req, result.next, mockValidData.params, 'params');
    });

    it('should reject invalid UUID in params', async () => {
      const middleware = validateParams(TestParamsSchema);
      const invalidParams = { id: 'not-a-uuid' };
      const result = await testMiddlewareWithData(middleware, invalidParams, 'params');
      
      expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
    });
  });

  describe('validateUUIDParam middleware', () => {
    it('should validate valid UUID parameter', async () => {
      const validParams = { id: '123e4567-e89b-12d3-a456-426614174000' };
      const result = await testMiddlewareWithData(validateUUIDParam, validParams, 'params');
      
      expectMiddlewareSuccess(result.req, result.next, validParams, 'params');
    });

    it('should reject invalid UUID parameter', async () => {
      const invalidParams = { id: 'invalid-uuid' };
      const result = await testMiddlewareWithData(validateUUIDParam, invalidParams, 'params');
      
      expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
    });

    it('should reject SQL injection attempts', async () => {
      const maliciousParams = { id: "'; DROP TABLE users; --" };
      const result = await testMiddlewareWithData(validateUUIDParam, maliciousParams, 'params');
      
      expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
    });
  });

  describe('validateImageQuery middleware', () => {
    it('should validate valid image query parameters', async () => {
      const validQuery = {
        limit: '10',
        offset: '0',
        sort: 'created_at',
        order: 'desc',
        search: 'test'
      };
      const expectedQuery = {
        limit: 10,
        offset: 0,
        sort: 'created_at',
        order: 'desc',
        search: 'test'
      };
      
      const result = await testMiddlewareWithData(validateImageQuery, validQuery, 'query');
      
      expectMiddlewareSuccess(result.req, result.next, expectedQuery, 'query');
    });

    it('should handle optional query parameters', async () => {
      const minimalQuery = {};
      const result = await testMiddlewareWithData(validateImageQuery, minimalQuery, 'query');
      
      expectMiddlewareSuccess(result.req, result.next, {}, 'query');
    });

    it('should reject invalid enum values', async () => {
      const invalidQuery = { sort: 'invalid_sort', order: 'invalid_order' };
      const result = await testMiddlewareWithData(validateImageQuery, invalidQuery, 'query');
      
      expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
    });
  });

  describe('validateFile middleware', () => {
    it('should validate valid file upload', async () => {
      const validFile = {
        ...mockValidFile,
        stream: {} as any,
        destination: '/tmp',
        filename: 'test-file.jpg',
        path: '/tmp/test-file.jpg',
        mimetype: 'image/jpeg', // Ensure valid mimetype
        size: 1024 * 500 // 500KB - under limit
      };

      const req = createMockRequest({ file: validFile }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      validateFile(req, res, next);

      expectNoError(next);
      expect(req.file).toBeDefined();
    });

    it('should reject missing file', async () => {
      const req = createMockRequest({ file: undefined }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      validateFile(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      const error = next.mock.calls[0][0] as unknown as ApiError;
      expect(error.code).toBe('NO_FILE');
      expect(error.statusCode).toBe(400);
    });

    it('should reject invalid file type', async () => {
      const invalidFile = {
        fieldname: 'file',
        originalname: 'document.txt',
        encoding: '7bit',
        mimetype: 'text/plain',  // Invalid - not an image
        size: 1024 * 100, // 100KB - valid size
        buffer: Buffer.alloc(100),
        stream: {} as any,
        destination: '/tmp',
        filename: 'document.txt',
        path: '/tmp/document.txt'
      };

      const req = createMockRequest({ file: invalidFile }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      validateFile(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      const error = next.mock.calls[0][0] as unknown as ApiError;
      expect(error.code).toBe('INVALID_FILE');
      expect(error.statusCode).toBe(400);
      expect(error.message).toContain('Only JPEG, PNG, and BMP images are allowed');
    });

    it('should reject oversized file', async () => {
      // The middleware has MAX_FILE_SIZE = 8388608 (8MB)
      // So we need a file LARGER than 8MB to trigger the error
      const oversizedFile = {
        fieldname: 'file',
        originalname: 'huge-image.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',  // Valid mimetype
        size: 10 * 1024 * 1024,  // 10MB - exceeds 8MB limit
        buffer: Buffer.alloc(100), // Small buffer for testing
        stream: {} as any,
        destination: '/tmp',
        filename: 'huge-image.jpg',
        path: '/tmp/huge-image.jpg'
      };

      const req = createMockRequest({ file: oversizedFile }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      validateFile(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      const error = next.mock.calls[0][0] as unknown as ApiError;
      expect(error.code).toBe('INVALID_FILE');
      expect(error.statusCode).toBe(400);
      expect(error.message).toContain('File too large');
    });

    it('should handle file validation errors gracefully', async () => {
      // Create a file that will cause validation to throw
      const problematicFile = null as any;
      const req = createMockRequest({ file: problematicFile }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      validateFile(req, res, next);

      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      const error = next.mock.calls[0][0] as unknown as ApiError;
      expect(error.code).toBe('NO_FILE');
    });
  });

  describe('Schema Validation Logic', () => {
    const schemaValidator = testSchemaValidation(TestSchema);

    it('should validate complete valid data', () => {
      const result = schemaValidator.expectValid(mockValidData.body);
      
      if (result.success) {
        expect(result.data.name).toBe(mockValidData.body.name);
        expect(result.data.email).toBe(mockValidData.body.email);
        expect(result.data.age).toBe(mockValidData.body.age);
      }
    });

    it('should reject data with missing required fields', () => {
      const incompleteData = { name: 'John' }; // Missing email
      schemaValidator.expectInvalid(incompleteData, 1);
    });

    it('should handle optional fields correctly', () => {
      const minimalData = { name: 'John', email: 'john@example.com' }; // No age
      const result = schemaValidator.expectValid(minimalData);
      
      if (result.success) {
        expect(result.data.age).toBeUndefined();
      }
    });

    it('should validate array fields', () => {
      const dataWithTags = {
        ...mockValidData.body,
        tags: ['developer', 'nodejs', 'javascript']
      };
      
      schemaValidator.expectValid(dataWithTags);
    });

    it('should reject invalid email formats', () => {
      const invalidEmailData = {
        name: 'John',
        email: 'not-an-email'
      };
      
      schemaValidator.expectInvalid(invalidEmailData, 1);
    });

    it('should reject age below minimum', () => {
      const underageData = {
        name: 'Young User',
        email: 'young@example.com',
        age: 15 // Below 18
      };
      
      schemaValidator.expectInvalid(underageData, 1);
    });
  });

  describe('Edge Cases', () => {
    it('should handle unicode characters in validation', async () => {
      const middleware = validateBody(TestSchema);
      const result = await testMiddlewareWithData(middleware, edgeCaseData.unicode, 'body');
      
      // Should either pass or fail gracefully
      if (result.next.mock.calls.length === 0) {
        // Validation passed
        expect(result.req.body.name).toBe(edgeCaseData.unicode.name);
      } else {
        // Validation failed - should be handled gracefully
        const error = result.next.mock.calls[0][0];
        expect(error).toBeDefined();
      }
    });

    it('should handle boundary values', async () => {
      const middleware = validateBody(TestSchema);
      const result = await testMiddlewareWithData(middleware, edgeCaseData.boundaries, 'body');
      
      expectMiddlewareSuccess(result.req, result.next, edgeCaseData.boundaries, 'body');
    });

    it('should handle very long strings', async () => {
      const middleware = validateBody(TestSchema);
      const result = await testMiddlewareWithData(middleware, edgeCaseData.maximum, 'body');
      
      // Should handle without crashing
      expect(result.next).toHaveBeenCalled();
    });

    it('should handle special characters', async () => {
      const middleware = validateBody(TestSchema);
      const result = await testMiddlewareWithData(middleware, edgeCaseData.special, 'body');
      
      // Should handle gracefully
      expect(result.next).toHaveBeenCalled();
    });

    it('should handle null and undefined values', async () => {
      const middleware = validateBody(TestSchema);
      
      // Test null data
      const nullResult = await testMiddlewareWithData(middleware, null, 'body');
      expectMiddlewareError(nullResult.next);
      
      // Test undefined data
      const undefinedResult = await testMiddlewareWithData(middleware, undefined, 'body');
      expectMiddlewareError(undefinedResult.next);
    });
  });

  describe('Data Transformation', () => {
    it('should transform string numbers to integers', async () => {
      const transformSchema = z.object({
        count: z.string().transform(s => parseInt(s, 10))
      });
      
      const middleware = validateBody(transformSchema);
      const inputData = { count: '42' };
      const expectedData = { count: 42 };
      
      const result = await testMiddlewareWithData(middleware, inputData, 'body');
      
      expectMiddlewareSuccess(result.req, result.next, expectedData, 'body');
    });

    it('should transform and validate complex data structures', async () => {
      const complexSchema = z.object({
        user: z.object({
          name: z.string().transform(s => s.trim().toLowerCase()),
          settings: z.object({
            notifications: z.string().transform(s => s === 'true')
          })
        })
      });
      
      const middleware = validateBody(complexSchema);
      const inputData = {
        user: {
          name: '  JOHN DOE  ',
          settings: {
            notifications: 'true'
          }
        }
      };
      const expectedData = {
        user: {
          name: 'john doe',
          settings: {
            notifications: true
          }
        }
      };
      
      const result = await testMiddlewareWithData(middleware, inputData, 'body');
      
      expectMiddlewareSuccess(result.req, result.next, expectedData, 'body');
    });
  });

  describe('Error Message Quality', () => {
    it('should provide detailed error messages for validation failures', async () => {
      const middleware = validate(TestSchema, 'body');
      const result = await testMiddlewareWithData(middleware, mockInvalidData.body, 'body');
      
      const error = expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      expect(error.message).toContain('Validation error:');
      expect(error.message.length).toBeGreaterThan(20); // Should be descriptive
    });

    it('should include field paths in error messages', async () => {
      const nestedSchema = z.object({
        user: z.object({
          profile: z.object({
            email: z.string().email()
          })
        })
      });
      
      const middleware = validate(nestedSchema, 'body');
      const invalidNestedData = {
        user: {
          profile: {
            email: 'invalid-email'
          }
        }
      };
      
      const result = await testMiddlewareWithData(middleware, invalidNestedData, 'body');
      
      const error = expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      expect(error.message).toContain('user.profile.email');
    });
  });

  describe('Performance Considerations', () => {
    it('should validate simple data quickly', async () => {
      const middleware = validateBody(TestSchema);
      
      const startTime = performance.now();
      const result = await testMiddlewareWithData(middleware, mockValidData.body, 'body');
      const endTime = performance.now();
      
      const executionTime = endTime - startTime;
      expect(executionTime).toBeLessThan(50); // Should be very fast for simple validation
      expectNoError(result.next);
    });

    it('should handle multiple validation calls efficiently', async () => {
      const middleware = validateBody(TestSchema);
      const iterations = 100;
      
      const startTime = performance.now();
      
      for (let i = 0; i < iterations; i++) {
        const testData = testDataFactory.validUser({ name: `User ${i}` });
        const result = await testMiddlewareWithData(middleware, testData, 'body');
        expectNoError(result.next);
      }
      
      const endTime = performance.now();
      const executionTime = endTime - startTime;
      const avgTime = executionTime / iterations;
      
      expect(avgTime).toBeLessThan(5); // Average under 5ms per validation
    });
  });

  describe('Type Validation Middleware', () => {
  describe('validateRequestTypes', () => {
    it('should allow valid object with primitive values', async () => {
      const validData = {
        name: 'John Doe',
        age: 25,
        active: true,
        score: 95.5
      };
      
      const result = await testMiddlewareWithData(validateRequestTypes, validData, 'body');
      expectMiddlewareSuccess(result.req, result.next, validData, 'body');
    });

    it('should allow nested objects for allowed fields', async () => {
      const validNestedData = {
        name: 'Test User',
        metadata: {
          type: 'garment',
          color: 'blue'
        },
        mask_data: {
          width: 100,
          height: 100,
          data: [1, 2, 3]
        },
        points: [
          { x: 10, y: 20 },
          { x: 30, y: 40 }
        ]
      };
      
      const result = await testMiddlewareWithData(validateRequestTypes, validNestedData, 'body');
      expectMiddlewareSuccess(result.req, result.next, validNestedData, 'body');
    });

    it('should reject array injection where string expected', async () => {
      const maliciousData = {
        name: ['array', 'instead', 'of', 'string'],
        email: 'test@example.com'
      };
      
      const result = await testMiddlewareWithData(validateRequestTypes, maliciousData, 'body');
      expectMiddlewareError(result.next, 'TYPE_VALIDATION_ERROR', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toContain("Field 'name' should be a string, received array");
    });

    it('should reject object injection where primitive expected', async () => {
      const maliciousData = {
        name: 'Valid Name',
        email: { malicious: 'object' },
        age: 25
      };
      
      const result = await testMiddlewareWithData(validateRequestTypes, maliciousData, 'body');
      expectMiddlewareError(result.next, 'TYPE_VALIDATION_ERROR', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toContain("Field 'email' should be a primitive value, received object");
    });

    it('should reject function injection', async () => {
      const maliciousData = {
        name: 'Test User',
        callback: function() { return 'malicious'; }
      };
      
      const result = await testMiddlewareWithData(validateRequestTypes, maliciousData, 'body');
      expectMiddlewareError(result.next, 'TYPE_VALIDATION_ERROR', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toContain("Field 'callback' contains function, which is not allowed");
    });

    it('should reject explicit undefined values', async () => {
      const maliciousData = {
        name: 'Test User',
        email: undefined
      };
      
      const result = await testMiddlewareWithData(validateRequestTypes, maliciousData, 'body');
      expectMiddlewareError(result.next, 'TYPE_VALIDATION_ERROR', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toContain("Field 'email' is explicitly undefined");
    });

    it('should handle empty body gracefully', async () => {
      const result = await testMiddlewareWithData(validateRequestTypes, {}, 'body');
      expectMiddlewareSuccess(result.req, result.next, {}, 'body');
    });

    it('should handle null body gracefully', async () => {
      const result = await testMiddlewareWithData(validateRequestTypes, null, 'body');
      expectNoError(result.next);
    });

    it('should handle non-object body gracefully', async () => {
      const result = await testMiddlewareWithData(validateRequestTypes, 'string body', 'body');
      expectNoError(result.next);
    });

    it('should handle validation errors gracefully', async () => {
      // Force an error by mocking the validation logic
      const originalEntries = Object.entries;
      Object.entries = jest.fn().mockImplementation(() => {
        throw new Error('Forced validation error');
      });

      const result = await testMiddlewareWithData(validateRequestTypes, { name: 'test' }, 'body');
      expectMiddlewareError(result.next, 'TYPE_VALIDATION_ERROR', 500);

      // Restore original
      Object.entries = originalEntries;
    });
  });

  describe('validateAuthTypes', () => {
    it('should allow valid string email and password', async () => {
      const validAuthData = {
        email: 'test@example.com',
        password: 'validPassword123!'
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, validAuthData, 'body');
      expectMiddlewareSuccess(result.req, result.next, validAuthData, 'body');
    });

    it('should allow missing email and password (handled by other validation)', async () => {
      const emptyData = {};
      
      const result = await testMiddlewareWithData(validateAuthTypes, emptyData, 'body');
      expectNoError(result.next);
    });

    it('should allow undefined email and password', async () => {
      const undefinedData = {
        email: undefined,
        password: undefined
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, undefinedData, 'body');
      expectNoError(result.next);
    });

    it('should reject non-string email', async () => {
      const invalidData = {
        email: 123,
        password: 'validPassword123!'
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, invalidData, 'body');
      expectMiddlewareError(result.next, 'INVALID_EMAIL_TYPE', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toBe('Email must be a string');
    });

    it('should reject non-string password', async () => {
      const invalidData = {
        email: 'test@example.com',
        password: 12345
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, invalidData, 'body');
      expectMiddlewareError(result.next, 'INVALID_PASSWORD_TYPE', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toBe('Password must be a string');
    });

    it('should reject array email', async () => {
      const maliciousData = {
        email: ['malicious@array.com'],
        password: 'validPassword123!'
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, maliciousData, 'body');
      expectMiddlewareError(result.next, 'INVALID_EMAIL_TYPE', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toBe('Email cannot be an array');
    });

    it('should reject array password', async () => {
      const maliciousData = {
        email: 'test@example.com',
        password: ['malicious', 'array']
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, maliciousData, 'body');
      expectMiddlewareError(result.next, 'INVALID_PASSWORD_TYPE', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toBe('Password cannot be an array');
    });

    it('should reject object email', async () => {
      const maliciousData = {
        email: { malicious: 'object' },
        password: 'validPassword123!'
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, maliciousData, 'body');
      expectMiddlewareError(result.next, 'INVALID_EMAIL_TYPE', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toBe('Email cannot be an object');
    });

    it('should reject object password', async () => {
      const maliciousData = {
        email: 'test@example.com',
        password: { malicious: 'object' }
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, maliciousData, 'body');
      expectMiddlewareError(result.next, 'INVALID_PASSWORD_TYPE', 400);
      
      const error = result.next.mock.calls[0][0];
      expect(error.message).toBe('Password cannot be an object');
    });

    it('should allow null email and password', async () => {
      const nullData = {
        email: null,
        password: null
      };
      
      const result = await testMiddlewareWithData(validateAuthTypes, nullData, 'body');
      expectNoError(result.next);
    });

    it('should handle validation errors gracefully', async () => {
      // Force an error by mocking req.body access
      const originalBody = { email: 'test@example.com', password: 'valid' };
      Object.defineProperty(originalBody, 'email', {
        get() { throw new Error('Forced access error'); }
      });

      const result = await testMiddlewareWithData(validateAuthTypes, originalBody, 'body');
      expectMiddlewareError(result.next, 'AUTH_TYPE_VALIDATION_ERROR', 500);
    });

    it('should handle missing body gracefully', async () => {
      const req = createMockRequest({}) as Request; // No body
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateAuthTypes(req, res, next);
      expectNoError(next);
    });
  });
});
});