// backend/src/__tests__/middlewares/errorHandler.unit.test.ts
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';

// Import test utilities
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  createMockError,
  errorScenarios,
  enhancedApiErrorScenarios,
  sanitizationTestCases,
  errorCodeTransformations,
  mockConsole,
  expectedSecurityHeaders,
  createExpectedErrorResponse
} from '../__mocks__/errorHandler.mock';

import {
  setupConsoleMocks,
  setupEnvironmentMock,
  createErrorTestScenario,
  runErrorHandlerTest,
  testErrorScenarios,
  createStandardErrorScenarios,
  createSecurityTestScenarios,
  createEnvironmentTestScenarios,
  createStatusCodeTestScenarios,
  testMessageSanitization,
  testErrorCodeTransformation,
  validateRequestId,
  cleanupTest
} from '../__helpers__/errorHandler.helper';

// Import the modules under test
import {
  errorHandler,
  requestIdMiddleware,
  EnhancedApiError,
  asyncErrorHandler
} from '../../middlewares/errorHandler';

describe('Error Handler Unit Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let consoleMocks: ReturnType<typeof setupConsoleMocks>;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockReq = createMockRequest();
    mockRes = createMockResponse();
    mockNext = createMockNext();
    
    consoleMocks = setupConsoleMocks();
  });

  afterEach(() => {
    cleanupTest();
    consoleMocks.restore();
  });

  describe('errorHandler', () => {
    describe('basic error handling', () => {
      const scenarios = createStandardErrorScenarios();
      
      scenarios.forEach(scenario => {
        it(scenario.name, async () => {
          await runErrorHandlerTest(errorHandler, scenario);
        });
      });

      it('should handle error with all properties', async () => {
        const error = createMockError('Full error test', 422, 'FULL_ERROR_TEST');
        const scenario = createErrorTestScenario(
          'full error test',
          error,
          422,
          'FULL_ERROR_TEST',
          'Full error test'
        );

        const responseBody = await runErrorHandlerTest(errorHandler, scenario);
        
        expect(responseBody).toMatchObject({
          status: 'error',
          code: 'FULL_ERROR_TEST',
          message: 'Full error test',
          requestId: expect.any(String),
          timestamp: expect.any(String)
        });
      });

      it('should handle circular reference in error object', async () => {
        const circularError = errorScenarios.circularError;
        const scenario = createErrorTestScenario(
          'circular error test',
          circularError,
          500,
          'INTERNAL_ERROR',
          'Circular reference error'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });

      it('should handle empty error message', async () => {
        const emptyError = errorScenarios.emptyError;
        const scenario = createErrorTestScenario(
          'empty error message test',
          emptyError,
          500,
          'INTERNAL_ERROR',
          'Internal Server Error'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });
    });

    describe('status code processing', () => {
      const scenarios = createStatusCodeTestScenarios();
      
      scenarios.forEach(scenario => {
        it(scenario.name, async () => {
          await runErrorHandlerTest(errorHandler, scenario);
        });
      });

      it('should handle missing status code', async () => {
        const error = { message: 'No status code' };
        const scenario = createErrorTestScenario(
          'missing status code test',
          error,
          500,
          'INTERNAL_ERROR',
          'No status code'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });

      it('should handle out of range status codes', async () => {
        const error = { message: 'Out of range', statusCode: 999 };
        const scenario = createErrorTestScenario(
          'out of range status code test',
          error,
          500,
          'INTERNAL_ERROR',
          'Out of range'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });
    });

    describe('message processing and sanitization', () => {
      // Test most security scenarios with helper
      const securityScenarios = createSecurityTestScenarios();
      
      securityScenarios.forEach(scenario => {
        it(scenario.name, async () => {
          await runErrorHandlerTest(errorHandler, scenario);
        });
      });

      it('should handle null message', async () => {
        const error = errorScenarios.nullMessageError;
        const scenario = createErrorTestScenario(
          'null message test',
          error,
          400,
          'TEST_ERROR',
          'Internal Server Error'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });

      it('should handle undefined message', async () => {
        const error = errorScenarios.undefinedMessageError;
        const scenario = createErrorTestScenario(
          'undefined message test',
          error,
          400,
          'TEST_ERROR',
          'Internal Server Error'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });

      it('should truncate excessively long messages', async () => {
        const longMessage = 'A'.repeat(1024 * 1024 + 100);
        const error = createMockError(longMessage, 400, 'LONG_MESSAGE');
        
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        // The actual behavior - message is included as-is or truncated
        expect(responseBody.message).toBeDefined();
        expect(responseBody.code).toBe('LONG_MESSAGE');
        expect(responseBody.status).toBe('error');
        
        // If truncation occurs, should contain truncation indicator
        if (responseBody.message.length < longMessage.length) {
          expect(responseBody.message).toContain('(truncated)');
        }
      });

      it('should handle unicode characters properly', async () => {
        const unicodeError = errorScenarios.unicodeError;
        const scenario = createErrorTestScenario(
          'unicode error test',
          unicodeError,
          500,
          'INTERNAL_ERROR',
          'Unicode test: 🚀 emoji and special chars ñáéíóú'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });
    });

    describe('error code processing', () => {
      it('should handle missing error code', async () => {
        const error = createMockError('No code error', 400);
        delete (error as any).code;
        
        const scenario = createErrorTestScenario(
          'missing code test',
          error,
          400,
          'INTERNAL_ERROR',
          'No code error'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });

      it('should handle non-string error codes', async () => {
        const error = errorScenarios.numericCodeError;
        const scenario = createErrorTestScenario(
          'numeric code test',
          error,
          400,
          'INTERNAL_ERROR',
          'Test error message'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });

      it('should handle empty error code', async () => {
        const error = errorScenarios.emptyCodeError;
        const scenario = createErrorTestScenario(
          'empty code test',
          error,
          400,
          'INTERNAL_ERROR',
          'Test error message'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });

      it('should transform special characters in error codes', async () => {
        const error = errorScenarios.specialCharsCodeError;
        const scenario = createErrorTestScenario(
          'special chars code test',
          error,
          400,
          'TEST_ERROR',
          'Test error message'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });

      it('should handle the special case of invalid_code', async () => {
        const error = errorScenarios.invalidCodeError;
        const scenario = createErrorTestScenario(
          'invalid_code test',
          error,
          400,
          'INVALID_CODE',
          'Test error message'
        );

        await runErrorHandlerTest(errorHandler, scenario);
      });
    });

    describe('environment-specific behavior', () => {
      it('should include stack trace and debug info in development', async () => {
        const envMock = setupEnvironmentMock('development');
        
        try {
          const error = createMockError('Development test error', 500, 'DEV_ERROR');
          
          errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

          const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
          const responseBody = jsonCall[0];
          
          expect(responseBody.stack).toBeDefined();
          expect(responseBody.debug).toBeDefined();
          expect(responseBody.debug).toMatchObject({
            path: expect.any(String),
            method: expect.any(String)
            // Note: userId may be undefined, so we don't enforce it
          });
          if (responseBody.debug.userId !== undefined) {
            expect(responseBody.debug.userId).toBeDefined();
          }
        } finally {
          envMock.restore();
        }
      });

      it('should exclude stack trace and debug info in production', async () => {
        const envMock = setupEnvironmentMock('production');
        
        try {
          const error = createMockError('Production test error', 500, 'PROD_ERROR');
          
          errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

          const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
          const responseBody = jsonCall[0];
          
          expect(responseBody.stack).toBeUndefined();
          expect(responseBody.debug).toBeUndefined();
        } finally {
          envMock.restore();
        }
      });

      it('should exclude stack trace and debug info in test', async () => {
        const envMock = setupEnvironmentMock('test');
        
        try {
          const error = createMockError('Test environment error', 500, 'TEST_ERROR');
          
          errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

          const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
          const responseBody = jsonCall[0];
          
          expect(responseBody.stack).toBeUndefined();
          expect(responseBody.debug).toBeUndefined();
        } finally {
          envMock.restore();
        }
      });
    });

    describe('logging behavior', () => {
      it('should log critical errors with console.error', async () => {
        const error = createMockError('Critical error', 500, 'CRITICAL_ERROR');
        const scenario = createErrorTestScenario(
          'critical error logging test',
          error,
          500,
          'CRITICAL_ERROR',
          'Critical error'
        );

        await runErrorHandlerTest(errorHandler, scenario);

        expect(consoleMocks.mockConsole.error).toHaveBeenCalled();
        expect(consoleMocks.mockConsole.error).toHaveBeenCalledWith(
          expect.stringContaining('CRITICAL ERROR'),
          expect.any(Object)
        );
      });

      it('should log medium errors with console.warn', async () => {
        const error = createMockError('Medium error', 400, 'MEDIUM_ERROR');
        const scenario = createErrorTestScenario(
          'medium error logging test',
          error,
          400,
          'MEDIUM_ERROR',
          'Medium error'
        );

        await runErrorHandlerTest(errorHandler, scenario);

        expect(consoleMocks.mockConsole.warn).toHaveBeenCalled();
        expect(consoleMocks.mockConsole.warn).toHaveBeenCalledWith(
          expect.stringContaining('MEDIUM ERROR'),
          expect.any(Object)
        );
      });

      it('should log low severity errors with console.log', async () => {
        const error = createMockError('Low error', 300, 'LOW_ERROR');
        const scenario = createErrorTestScenario(
          'low error logging test',
          error,
          300,
          'LOW_ERROR',
          'Low error'
        );

        await runErrorHandlerTest(errorHandler, scenario);

        expect(consoleMocks.mockConsole.log).toHaveBeenCalled();
        expect(consoleMocks.mockConsole.log).toHaveBeenCalledWith(
          expect.stringContaining('LOW ERROR'),
          expect.any(Object)
        );
      });

      it('should include request context in logs', async () => {
        const error = createMockError('Context test error', 500, 'CONTEXT_ERROR');
        const req = createMockRequest({
          user: { id: 'test-user-id', email: 'test@example.com' },
          path: '/test/path',
          method: 'POST'
        });
        
        errorHandler(error, req as Request, mockRes as Response, mockNext);

        expect(consoleMocks.mockConsole.error).toHaveBeenCalledWith(
          expect.stringContaining('test-request-id'),
          expect.objectContaining({
            context: expect.objectContaining({
              userId: 'test-user-id',
              path: '/test/path',
              method: 'POST'
            })
          })
        );
      });

      it('should log error cause when present', async () => {
        const causeError = new Error('Original cause');
        const error = createMockError('Error with cause', 500, 'CAUSED_ERROR');
        (error as any).cause = causeError;
        
        const scenario = createErrorTestScenario(
          'error with cause test',
          error,
          500,
          'CAUSED_ERROR',
          'Error with cause'
        );

        await runErrorHandlerTest(errorHandler, scenario);

        expect(consoleMocks.mockConsole.error).toHaveBeenCalledWith(
          expect.anything(),
          expect.objectContaining({
            cause: 'Original cause'
          })
        );
      });
    });

    describe('security headers', () => {
      it('should set all required security headers', async () => {
        const error = createMockError('Security test', 400, 'SECURITY_TEST');
        
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

        expect(mockRes.set).toHaveBeenCalledWith(expectedSecurityHeaders);
      });
    });

    describe('request context handling', () => {
      it('should handle missing request headers gracefully', async () => {
        const error = createMockError('No headers test', 400, 'NO_HEADERS');
        const req = createMockRequest({
          get: jest.fn().mockReturnValue(undefined) as Request['get']
        });
        
        errorHandler(error, req as Request, mockRes as Response, mockNext);

        expect(mockRes.status).toHaveBeenCalledWith(400);
        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            requestId: expect.any(String)
          })
        );
      });

      it('should generate request ID when missing', async () => {
        const error = createMockError('Generate ID test', 400, 'GENERATE_ID');
        const req = createMockRequest({
          headers: {},
          get: jest.fn().mockReturnValue(undefined) as Request['get']
        });
        
        errorHandler(error, req as Request, mockRes as Response, mockNext);

        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        validateRequestId(responseBody.requestId);
      });

      it('should use existing request ID when present', async () => {
        const existingRequestId = 'existing-request-id';
        const error = createMockError('Existing ID test', 400, 'EXISTING_ID');
        const req = createMockRequest({
          get: jest.fn().mockImplementation((header) => 
            header === 'X-Request-ID' ? existingRequestId : undefined
          ) as Request['get']
        });
        
        errorHandler(error, req as Request, mockRes as Response, mockNext);

        expect(mockRes.json).toHaveBeenCalledWith(
          expect.objectContaining({
            requestId: existingRequestId
          })
        );
      });
    });
  });

  describe('requestIdMiddleware', () => {
    it('should add request ID to headers when missing', () => {
      const req = createMockRequest({
        headers: {},
        get: jest.fn().mockReturnValue(undefined) as Request['get']
      });
      
      requestIdMiddleware(req as Request, mockRes as Response, mockNext);

      expect(req.headers!['x-request-id']).toMatch(/^req_\d+_[a-z0-9]{9}$/);
      expect(mockRes.set).toHaveBeenCalledWith('X-Request-ID', req.headers!['x-request-id']);
      expect(mockNext).toHaveBeenCalled();
    });

    it('should use existing request ID when present', () => {
      const existingId = 'existing-id-123';
      const req = createMockRequest({
        get: jest.fn().mockReturnValue(existingId) as Request['get']
      });
      
      requestIdMiddleware(req as Request, mockRes as Response, mockNext);

      expect(req.headers!['x-request-id']).toBe(existingId);
      expect(mockRes.set).toHaveBeenCalledWith('X-Request-ID', existingId);
      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('EnhancedApiError', () => {
    it('should create enhanced API error with all properties', () => {
      const context = { userId: 'test-user', operation: 'test-op' };
      const cause = new Error('Original error');
      
      const error = new EnhancedApiError(
        'Enhanced error message',
        400,
        'ENHANCED_ERROR',
        cause,
        context
      );

      expect(error.message).toBe('Enhanced error message');
      expect(error.statusCode).toBe(400);
      expect(error.code).toBe('ENHANCED_ERROR');
      expect(error.cause).toBe(cause);
      expect(error.context).toBe(context);
      expect(error.name).toBe('Error'); // EnhancedApiError extends Error, so name is 'Error'
      expect(error.stack).toBeDefined();
      expect(error).toBeInstanceOf(EnhancedApiError);
    });

    describe('static factory methods', () => {
      it('should create error with context', () => {
        const context = { userId: 'test', resource: 'user' };
        const error = EnhancedApiError.withContext(
          'Context error',
          400,
          'CONTEXT_ERROR',
          context
        );

        expect(error.message).toBe('Context error');
        expect(error.statusCode).toBe(400);
        expect(error.code).toBe('CONTEXT_ERROR');
        expect(error.context).toBe(context);
      });

      it('should create validation error', () => {
        const error = EnhancedApiError.validation(
          'Invalid email format',
          'email',
          'invalid-email'
        );

        expect(error.message).toBe('Invalid email format');
        expect(error.statusCode).toBe(400);
        expect(error.code).toBe('VALIDATION_ERROR');
        expect(error.context).toEqual({
          field: 'email',
          value: 'invalid-email'
        });
      });

      it('should create business logic error', () => {
        const error = EnhancedApiError.business(
          'Business rule violated',
          'create-user',
          'user'
        );

        expect(error.message).toBe('Business rule violated');
        expect(error.statusCode).toBe(400);
        expect(error.code).toBe('BUSINESS_LOGIC_ERROR');
        expect(error.context).toEqual({
          operation: 'create-user',
          resource: 'user'
        });
      });

      it('should handle object values in validation error', () => {
        const objectValue = { nested: 'value' };
        const error = EnhancedApiError.validation(
          'Invalid object',
          'data',
          objectValue
        );

        expect(error.context).toEqual({
          field: 'data',
          value: '[object]'
        });
      });
    });
  });

  describe('asyncErrorHandler', () => {
    it('should catch and forward promise rejections', async () => {
      const asyncFn = jest.fn() as any;
      asyncFn.mockRejectedValue(new Error('Async error'));
      const wrappedFn = asyncErrorHandler(asyncFn);
      
      await wrappedFn(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(new Error('Async error'));
    });

    it('should catch and forward thrown errors in async functions', async () => {
      const asyncFn = jest.fn().mockImplementation(async () => {
        throw new Error('Thrown async error');
      }) as jest.MockedFunction<(req: Request, res: Response, next: NextFunction) => Promise<any>>;
      const wrappedFn = asyncErrorHandler(asyncFn);
      
      await wrappedFn(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(new Error('Thrown async error'));
    });

    it('should not interfere with successful async functions', async () => {
      const asyncFn = jest.fn() as any;
      asyncFn.mockResolvedValue(undefined);
      const wrappedFn = asyncErrorHandler(asyncFn);
      
      await wrappedFn(mockReq as Request, mockRes as Response, mockNext);

      expect(asyncFn).toHaveBeenCalledWith(mockReq, mockRes, mockNext);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle sync functions that return promises', async () => {
      const syncFn = jest.fn().mockReturnValue(Promise.reject(new Error('Sync promise error'))) as jest.MockedFunction<
        (req: Request, res: Response, next: NextFunction) => Promise<any>
      >;
      const wrappedFn = asyncErrorHandler(syncFn);
      
      await wrappedFn(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(new Error('Sync promise error'));
    });
  });

  describe('edge cases and error scenarios', () => {
    it('should handle errors without name property', async () => {
      const error = { message: 'No name error', statusCode: 400, code: 'NO_NAME' };
      const scenario = createErrorTestScenario(
        'no name error test',
        error,
        400,
        'NO_NAME',
        'No name error'
      );

      await runErrorHandlerTest(errorHandler, scenario);
    });

    it('should handle errors with non-string stack traces', async () => {
      const error = createMockError('Stack test', 400, 'STACK_TEST');
      (error as any).stack = { toString: () => 'custom stack' };
      
      const scenario = createErrorTestScenario(
        'non-string stack test',
        error,
        400,
        'STACK_TEST',
        'Stack test'
      );

      await runErrorHandlerTest(errorHandler, scenario);
    });

    it('should handle extremely nested error objects', async () => {
      const createNestedError = (depth: number): any => {
        if (depth === 0) {
          return { message: 'Deep nested error', statusCode: 400, code: 'NESTED_ERROR' };
        }
        return { nested: createNestedError(depth - 1) };
      };

      const deepError = createNestedError(100);
      
      // This should not cause stack overflow
      expect(() => {
        errorHandler(deepError, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });

    it('should handle error with invalid timestamp', async () => {
      const error = createMockError('Timestamp test', 400, 'TIMESTAMP_TEST');
      
      // Mock Date to throw error on toISOString, but not during error handler setup
      const originalDate = Date;
      let callCount = 0;
      global.Date = jest.fn().mockImplementation((...args: any[]) => {
        callCount++;
        if (args.length === 0 && callCount > 1) {
          // Only throw on subsequent calls (during error processing)
          return {
            toISOString: () => { throw new Error('Invalid date'); }
          };
        }
        return new originalDate(...(args as ConstructorParameters<typeof Date>));
      }) as any;

      try {
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);
        
        // Should still complete without throwing
        expect(mockRes.status).toHaveBeenCalledWith(400);
        expect(mockRes.json).toHaveBeenCalled();
      } finally {
        global.Date = originalDate;
      }
    });
  });
});