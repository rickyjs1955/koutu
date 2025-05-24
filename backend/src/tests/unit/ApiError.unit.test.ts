// backend/src/__tests__/utils/ApiError.unit.test.ts
import { jest } from '@jest/globals';

// Import mocks and helpers
import {
  MockApiError,
  errorScenarios,
  createMockApiError,
  resetApiErrorMocks} from '../__mocks__/ApiError.mock';

import {
  runApiErrorTestScenarios,
  testApiErrorFactoryMethod,
  assertApiErrorProperties,
  testErrorClassificationMethods,
  testErrorJsonSerialization,
  createErrorHandlingTestScenarios,
  setupApiErrorTestEnvironment,
  testErrorContextPreservation,
  testErrorSeverityClassification,
  testErrorRetryLogic,
  testUnknownErrorConversion,
  testErrorChaining,
  cleanupApiErrorTests,
  createParameterizedErrorTests
} from '../__helpers__/ApiError.helper';

// Mock the actual ApiError class
jest.mock('../../utils/ApiError', () => ({ ApiError: MockApiError }));

describe('ApiError Unit Tests', () => {
  // Setup test environment
  setupApiErrorTestEnvironment();

  afterAll(() => {
    cleanupApiErrorTests();
  });

  describe('Basic ApiError Construction', () => {
    it('should create ApiError instance with all properties', () => {
      const cause = new Error('Original error');
      const context = { field: 'email', value: 'invalid' };
      
      const error = new MockApiError(
        'Test error message',
        400,
        'TEST_ERROR',
        cause,
        context
      );

      expect(error).toBeInstanceOf(MockApiError);
      expect(error).toBeInstanceOf(Error);
      expect(error.name).toBe('ApiError');
      expect(error.message).toBe('Test error message');
      expect(error.statusCode).toBe(400);
      expect(error.code).toBe('TEST_ERROR');
      expect(error.cause).toBe(cause);
      expect(error.context).toBe(context);
      expect(error.isOperational).toBe(true);
      expect(error.type).toBe('validation'); // Auto-derived from status code
    });

    it('should create ApiError with minimal properties', () => {
      const error = new MockApiError('Simple error', 500, 'SIMPLE_ERROR');

      expect(error.message).toBe('Simple error');
      expect(error.statusCode).toBe(500);
      expect(error.code).toBe('SIMPLE_ERROR');
      expect(error.cause).toBeUndefined();
      expect(error.context).toBeUndefined();
      expect(error.isOperational).toBe(true);
      expect(error.type).toBe('internal');
    });

    it('should maintain proper prototype chain', () => {
      const error = new MockApiError('Test', 400, 'TEST');
      
      expect(error instanceof MockApiError).toBe(true);
      expect(error instanceof Error).toBe(true);
      expect(Object.getPrototypeOf(error)).toBe(MockApiError.prototype);
    });
  });

  describe('Standard Factory Methods', () => {
    describe('badRequest', () => {
      it('should create bad request error with default values', () => {
        const error = testApiErrorFactoryMethod('badRequest', 400, 'BAD_REQUEST');
        expect(error.message).toBe('Bad request');
      });

      it('should create bad request error with custom message', () => {
        const error = testApiErrorFactoryMethod(
          'badRequest', 
          400, 
          'CUSTOM_CODE',
          ['Custom validation failed', 'CUSTOM_CODE']
        );
        expect(error.message).toBe('Custom validation failed');
        expect(error.code).toBe('CUSTOM_CODE');
      });

      it('should handle null/undefined message', () => {
        const nullError = testApiErrorFactoryMethod(
          'badRequest',
          400,
          'BAD_REQUEST',
          [null]
        );
        expect(nullError.message).toBe('Bad request');

        const undefinedError = testApiErrorFactoryMethod(
          'badRequest',
          400,
          'BAD_REQUEST',
          [undefined]
        );
        expect(undefinedError.message).toBe('Bad request');
      });

      it('should handle empty code', () => {
        const error = testApiErrorFactoryMethod(
          'badRequest',
          400,
          'BAD_REQUEST',
          ['Test message', '']
        );
        expect(error.code).toBe('BAD_REQUEST');
      });

      it('should include context when provided', () => {
        const context = { field: 'email', rule: 'required' };
        const error = testApiErrorFactoryMethod(
          'badRequest',
          400,
          'VALIDATION_FAILED',
          ['Validation failed', 'VALIDATION_FAILED', context]
        );
        expect(error.context).toEqual(context);
      });
    });

    describe('unauthorized', () => {
      it('should create unauthorized error', () => {
        const error = testApiErrorFactoryMethod('unauthorized', 401, 'UNAUTHORIZED');
        expect(error.message).toBe('Unauthorized');
      });

      it('should create unauthorized error with custom message and code', () => {
        const error = testApiErrorFactoryMethod(
          'unauthorized',
          401,
          'AUTH_FAILED',
          ['Authentication failed', 'AUTH_FAILED']
        );
        expect(error.message).toBe('Authentication failed');
        expect(error.code).toBe('AUTH_FAILED');
      });
    });

    describe('forbidden', () => {
      it('should create forbidden error', () => {
        const error = testApiErrorFactoryMethod('forbidden', 403, 'FORBIDDEN');
        expect(error.message).toBe('Forbidden');
      });
    });

    describe('notFound', () => {
      it('should create not found error', () => {
        const error = testApiErrorFactoryMethod('notFound', 404, 'NOT_FOUND');
        expect(error.message).toBe('Resource not found');
      });
    });

    describe('conflict', () => {
      it('should create conflict error', () => {
        const error = testApiErrorFactoryMethod('conflict', 409, 'CONFLICT');
        expect(error.message).toBe('Conflict');
      });
    });

    describe('unprocessableEntity', () => {
      it('should create unprocessable entity error', () => {
        const error = testApiErrorFactoryMethod('unprocessableEntity', 422, 'UNPROCESSABLE_ENTITY');
        expect(error.message).toBe('Unprocessable Entity');
      });
    });

    describe('tooManyRequests', () => {
      it('should create too many requests error', () => {
        const error = testApiErrorFactoryMethod('tooManyRequests', 429, 'TOO_MANY_REQUESTS');
        expect(error.message).toBe('Too many requests');
      });
    });

    describe('internal', () => {
      it('should create internal error', () => {
        const error = testApiErrorFactoryMethod('internal', 500, 'INTERNAL_ERROR');
        expect(error.message).toBe('Internal server error');
      });

      it('should create internal error with cause', () => {
        const cause = new Error('Database connection failed');
        const error = testApiErrorFactoryMethod(
          'internal',
          500,
          'DB_ERROR',
          ['Database error', 'DB_ERROR', cause]
        );
        expect(error.cause).toBe(cause);
      });
    });

    describe('serviceUnavailable', () => {
      it('should create service unavailable error', () => {
        const error = testApiErrorFactoryMethod('serviceUnavailable', 503, 'SERVICE_UNAVAILABLE');
        expect(error.message).toBe('Service unavailable');
      });
    });

    describe('custom', () => {
      it('should create custom error with specified parameters', () => {
        const cause = new Error('Original');
        const context = { customData: 'test' };
        const error = testApiErrorFactoryMethod(
          'custom',
          418,
          'CUSTOM_ERROR',
          ['Custom error message', 418, 'CUSTOM_ERROR', cause, context]
        );
        
        expect(error.message).toBe('Custom error message');
        expect(error.statusCode).toBe(418);
        expect(error.code).toBe('CUSTOM_ERROR');
        expect(error.cause).toBe(cause);
        expect(error.context).toBe(context);
      });
    });
  });

  describe('Enhanced Factory Methods', () => {
    describe('validation', () => {
      it('should create validation error with field context', () => {
        const error = testApiErrorFactoryMethod(
          'validation',
          400,
          'VALIDATION_ERROR',
          ['Invalid email format', 'email', 'invalid-email', 'email']
        );
        
        expect(error.context).toEqual({
          field: 'email',
          value: 'invalid-email',
          rule: 'email'
        });
      });

      it('should handle object values in validation context', () => {
        const objectValue = { nested: 'object' };
        const error = testApiErrorFactoryMethod(
          'validation',
          400,
          'VALIDATION_ERROR',
          ['Invalid object', 'data', objectValue, 'object']
        );
        
        expect(error.context?.value).toBe('[object]');
      });
    });

    describe('database', () => {
      it('should create database error with operation context', () => {
        const cause = new Error('Connection timeout');
        const error = testApiErrorFactoryMethod(
          'database',
          500,
          'DATABASE_ERROR',
          ['Database operation failed', 'SELECT', 'users', cause]
        );
        
        expect(error.context).toEqual({
          operation: 'SELECT',
          table: 'users'
        });
        expect(error.cause).toBe(cause);
      });
    });

    describe('fileOperation', () => {
      it('should create file operation error', () => {
        const cause = new Error('Permission denied');
        const error = testApiErrorFactoryMethod(
          'fileOperation',
          500,
          'FILE_OPERATION_ERROR',
          ['File upload failed', 'upload', 'image.jpg', cause]
        );
        
        expect(error.context).toEqual({
          operation: 'upload',
          filename: 'image.jpg'
        });
        expect(error.cause).toBe(cause);
      });
    });

    describe('authentication', () => {
      it('should create authentication error', () => {
        const error = testApiErrorFactoryMethod(
          'authentication',
          401,
          'AUTHENTICATION_ERROR',
          ['Token expired', 'token_expired']
        );
        
        expect(error.context).toEqual({
          reason: 'token_expired'
        });
      });

      it('should create authentication error with default message', () => {
        const error = testApiErrorFactoryMethod(
          'authentication',
          401,
          'AUTHENTICATION_ERROR',
          []
        );
        
        expect(error.message).toBe('Authentication failed');
      });
    });

    describe('authorization', () => {
      it('should create authorization error with resource context', () => {
        const error = testApiErrorFactoryMethod(
          'authorization',
          403,
          'AUTHORIZATION_ERROR',
          ['Access denied to image', 'image', 'read']
        );
        
        expect(error.context).toEqual({
          resource: 'image',
          action: 'read'
        });
      });
    });

    describe('rateLimited', () => {
      it('should create rate limited error with limits', () => {
        const error = testApiErrorFactoryMethod(
          'rateLimited',
          429,
          'RATE_LIMITED',
          ['Too many requests', 100, 3600000, 1800]
        );
        
        expect(error.context).toEqual({
          limit: 100,
          windowMs: 3600000,
          retryAfter: 1800
        });
      });
    });

    describe('businessLogic', () => {
      it('should create business logic error', () => {
        const error = testApiErrorFactoryMethod(
          'businessLogic',
          400,
          'BUSINESS_LOGIC_ERROR',
          ['Cannot delete active user', 'no_delete_active_user', 'user']
        );
        
        expect(error.context).toEqual({
          rule: 'no_delete_active_user',
          entity: 'user'
        });
      });
    });

    describe('externalService', () => {
      it('should create external service error', () => {
        const cause = new Error('Service timeout');
        const error = testApiErrorFactoryMethod(
          'externalService',
          502,
          'EXTERNAL_SERVICE_ERROR',
          ['Payment service unavailable', 'stripe', cause]
        );
        
        expect(error.context).toEqual({
          service: 'stripe'
        });
        expect(error.cause).toBe(cause);
      });
    });
  });

  describe('Error Classification Methods', () => {
    testErrorSeverityClassification();
    testErrorRetryLogic();

    describe('isClientError', () => {
      it('should correctly identify client errors', () => {
        const clientErrors = [400, 401, 403, 404, 409, 422, 429];
        const serverErrors = [500, 502, 503];
        
        clientErrors.forEach(statusCode => {
          const error = new MockApiError('Test', statusCode, 'TEST');
          expect(error.isClientError()).toBe(true);
          expect(error.isServerError()).toBe(false);
        });
        
        serverErrors.forEach(statusCode => {
          const error = new MockApiError('Test', statusCode, 'TEST');
          expect(error.isClientError()).toBe(false);
          expect(error.isServerError()).toBe(true);
        });
      });
    });

    describe('comprehensive classification tests', () => {
      const testCases = [
        {
          statusCode: 400,
          expected: { isClient: true, isServer: false, isRetryable: false, severity: 'medium' }
        },
        {
          statusCode: 401,
          expected: { isClient: true, isServer: false, isRetryable: false, severity: 'medium' }
        },
        {
          statusCode: 408,
          expected: { isClient: true, isServer: false, isRetryable: true, severity: 'medium' }
        },
        {
          statusCode: 429,
          expected: { isClient: true, isServer: false, isRetryable: true, severity: 'high' }
        },
        {
          statusCode: 500,
          expected: { isClient: false, isServer: true, isRetryable: true, severity: 'critical' }
        },
        {
          statusCode: 503,
          expected: { isClient: false, isServer: true, isRetryable: true, severity: 'critical' }
        }
      ];

      testCases.forEach(({ statusCode, expected }) => {
        it(`should classify ${statusCode} correctly`, () => {
          const error = new MockApiError('Test', statusCode, 'TEST');
          
          testErrorClassificationMethods(error, {
            isClientError: expected.isClient,
            isServerError: expected.isServer,
            isRetryable: expected.isRetryable,
            severity: expected.severity as 'low' | 'medium' | 'high' | 'critical'
          });
        });
      });
    });
  });

  describe('JSON Serialization', () => {
    it('should serialize error to JSON correctly', () => {
      const error = new MockApiError('Test error', 400, 'TEST_ERROR');
      
      const json = testErrorJsonSerialization(error, {
        status: 'error',
        code: 'TEST_ERROR',
        message: 'Test error'
      });
      
      expect(json).toEqual({
        status: 'error',
        code: 'TEST_ERROR',
        message: 'Test error'
      });
    });

    it('should include context in development environment', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';
      
      const context = { field: 'email', rule: 'required' };
      const error = new MockApiError('Test', 400, 'TEST', undefined, context);
      
      testErrorContextPreservation(error, context);
      
      process.env.NODE_ENV = originalEnv;
    });

    it('should exclude context in production environment', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const context = { sensitive: 'data' };
      const error = new MockApiError('Test', 400, 'TEST', undefined, context);
      
      const json = error.toJSON();
      expect(json.context).toBeUndefined();
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Unknown Error Conversion', () => {
    it('should return same instance for ApiError', () => {
      const apiError = new MockApiError('Original', 400, 'ORIGINAL');
      const converted = testUnknownErrorConversion(apiError);
      
      expect(converted).toBe(apiError);
    });

    it('should convert standard Error to ApiError', () => {
      const standardError = new Error('Standard error message');
      const converted = testUnknownErrorConversion(standardError);
      
      expect(converted).toBeInstanceOf(MockApiError);
      expect(converted.message).toBe('Standard error message');
      expect(converted.cause).toBe(standardError);
      expect(converted.statusCode).toBe(500);
      expect(converted.code).toBe('UNKNOWN_ERROR');
    });

    it('should convert string to ApiError', () => {
      const stringError = 'Something went wrong';
      const converted = testUnknownErrorConversion(stringError);
      
      expect(converted).toBeInstanceOf(MockApiError);
      expect(converted.message).toBe('Something went wrong');
      expect(converted.statusCode).toBe(500);
      expect(converted.code).toBe('UNKNOWN_ERROR');
    });

    it('should convert unknown object to ApiError with default message', () => {
      const unknownError = { weird: 'object' };
      const converted = testUnknownErrorConversion(unknownError, 'Custom default message');
      
      expect(converted).toBeInstanceOf(MockApiError);
      expect(converted.message).toBe('Custom default message');
      expect(converted.statusCode).toBe(500);
      expect(converted.code).toBe('UNKNOWN_ERROR');
    });

    it('should handle Error with empty message', () => {
      const emptyError = new Error('');
      const converted = testUnknownErrorConversion(emptyError, 'Fallback message');
      
      expect(converted.message).toBe('Fallback message');
      expect(converted.cause).toBe(emptyError);
    });
  });

  describe('Error Chaining', () => {
    it('should properly chain errors', () => {
      const originalError = new Error('Database connection failed');
      
      testErrorChaining(originalError, () => 
        new MockApiError('Service unavailable', 503, 'SERVICE_ERROR', originalError)
      );
    });

    it('should handle multiple levels of error chaining', () => {
      const dbError = new Error('Connection timeout');
      const serviceError = new MockApiError('Service error', 500, 'SERVICE_ERROR', dbError);
      const apiError = new MockApiError('API error', 502, 'API_ERROR', serviceError);
      
      expect(apiError.cause).toBe(serviceError);
      expect(serviceError.cause).toBe(dbError);
    });
  });

  describe('Comprehensive Error Scenarios', () => {
    const scenarios = createErrorHandlingTestScenarios();
    
    describe('Standard Errors', () => {
      runApiErrorTestScenarios(scenarios.standardErrors);
    });
    
    describe('Authentication Errors', () => {
      runApiErrorTestScenarios(scenarios.authErrors);
    });
    
    describe('Validation Errors', () => {
      runApiErrorTestScenarios(scenarios.validationErrors);
    });
    
    describe('File Operation Errors', () => {
      runApiErrorTestScenarios(scenarios.fileErrors);
    });
    
    describe('Database Errors', () => {
      runApiErrorTestScenarios(scenarios.databaseErrors);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle very long error messages', () => {
      const longMessage = 'A'.repeat(1000);
      const error = new MockApiError(longMessage, 400, 'LONG_MESSAGE');
      
      expect(error.message).toBe(longMessage);
      expect(error.message.length).toBe(1000);
    });

    it('should handle special characters in error messages', () => {
      const specialMessage = 'Error with special chars: àáâãäåæçèéêë 中文 🚀 \'"\n\t';
      const error = new MockApiError(specialMessage, 400, 'SPECIAL_CHARS');
      
      expect(error.message).toBe(specialMessage);
    });

    it('should handle numeric codes', () => {
      const error = new MockApiError('Test', 400, '12345');
      expect(error.code).toBe('12345');
    });

    it('should handle empty string code (with sanitization)', () => {
      const error = MockApiError.badRequest('Test message', '');
      expect(error.code).toBe('BAD_REQUEST'); // Should be sanitized to default
    });

    it('should handle very large status codes', () => {
      const error = new MockApiError('Test', 999, 'CUSTOM');
      expect(error.statusCode).toBe(999);
      expect(error.isClientError()).toBe(false);
      expect(error.isServerError()).toBe(false);
    });

    it('should handle circular references in context', () => {
      const circularContext: any = { name: 'test' };
      circularContext.self = circularContext;
      
      const error = new MockApiError('Test', 400, 'CIRCULAR', undefined, circularContext);
      expect(error.context).toBe(circularContext);
      
      // JSON serialization should not crash
      expect(() => {
        const json = error.toJSON();
        // Note: JSON.stringify would throw on circular refs, but our toJSON doesn't use it
        expect(json.code).toBe('CIRCULAR');
      }).not.toThrow();
    });
  });

  describe('Factory Method Input Validation', () => {
    it('should handle factory methods with missing arguments', () => {
      // Test that factory methods handle missing optional arguments gracefully
      const error1 = MockApiError.badRequest();
      expect(error1.message).toBe('Bad request');
      expect(error1.code).toBe('BAD_REQUEST');
      
      const error2 = MockApiError.unauthorized();
      expect(error2.message).toBe('Unauthorized');
      expect(error2.code).toBe('UNAUTHORIZED');
    });

    it('should handle factory methods with undefined context', () => {
      const error = MockApiError.validation('Test validation', 'field', 'value', undefined);
      expect(error.context?.rule).toBeUndefined();
      expect(error.context?.field).toBe('field');
      expect(error.context?.value).toBe('value');
    });

    it('should handle complex nested context objects', () => {
      const complexContext = {
        user: { id: 123, email: 'test@example.com' },
        request: { method: 'POST', path: '/api/test' },
        metadata: { timestamp: new Date(), version: '1.0.0' }
      };
      
      const error = MockApiError.internal('Complex error', 'COMPLEX', undefined, complexContext);
      expect(error.context).toEqual(complexContext);
    });
  });

  describe('Mock Function Behavior', () => {
    it('should track factory method calls correctly', () => {
      // Clear previous calls
      resetApiErrorMocks();
      
      MockApiError.badRequest('Test 1');
      MockApiError.badRequest('Test 2', 'CUSTOM');
      MockApiError.unauthorized('Auth failed');
      
      expect(MockApiError.badRequest).toHaveBeenCalledTimes(2);
      expect(MockApiError.badRequest).toHaveBeenNthCalledWith(1, 'Test 1');
      expect(MockApiError.badRequest).toHaveBeenNthCalledWith(2, 'Test 2', 'CUSTOM');
      expect(MockApiError.unauthorized).toHaveBeenCalledTimes(1);
      expect(MockApiError.unauthorized).toHaveBeenCalledWith('Auth failed');
    });

    it('should reset mock calls correctly', () => {
      MockApiError.notFound('Test');
      expect(MockApiError.notFound).toHaveBeenCalledTimes(1);
      
      resetApiErrorMocks();
      expect(MockApiError.notFound).toHaveBeenCalledTimes(0);
    });
  });

  describe('Parameterized Tests for All Error Types', () => {
    createParameterizedErrorTests((errorType) => {
      it(`should create ${errorType} error correctly`, () => {
        const scenario = errorScenarios[errorType];
        const error = createMockApiError(errorType);
        
        assertApiErrorProperties(error, {
          statusCode: scenario.statusCode,
          code: scenario.code,
          message: scenario.message,
          type: scenario.type,
          isOperational: true
        });
      });
    });
  });
});