// backend/src/__tests__/helpers/errorHandler.helper.ts
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  createMockError,
  mockConsole,
  mockEnvironments,
  errorSeverityScenarios,
  sanitizationTestCases,
  expectedSecurityHeaders,
  createExpectedErrorResponse
} from '../__mocks__/errorHandler.mock';

/**
 * Helper to set up console mocks for testing logging
 */
export const setupConsoleMocks = () => {
  const originalConsole = { ...console };
  
  console.log = mockConsole.log;
  console.warn = mockConsole.warn;
  console.error = mockConsole.error;
  console.info = mockConsole.info;
  console.debug = mockConsole.debug;

  return {
    mockConsole,
    restore: () => {
      Object.assign(console, originalConsole);
    }
  };
};

/**
 * Helper to set up environment mocks
 */
export const setupEnvironmentMock = (env: string = 'test') => {
  const originalEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = env;

  return {
    restore: () => {
      if (originalEnv !== undefined) {
        process.env.NODE_ENV = originalEnv;
      } else {
        delete process.env.NODE_ENV;
      }
    }
  };
};

/**
 * Helper to create test scenarios for error handling
 */
export interface ErrorTestScenario {
  name: string;
  error: any;
  request: Partial<Request>;
  response: Partial<Response>;
  next: NextFunction;
  expectedStatusCode: number;
  expectedErrorCode: string;
  expectedMessage: string;
  shouldIncludeStack?: boolean;
  shouldIncludeDebug?: boolean;
  customValidation?: (res: Partial<Response>) => void;
}

export const createErrorTestScenario = (
  name: string,
  error: any,
  expectedStatusCode: number = 500,
  expectedErrorCode: string = 'INTERNAL_ERROR',
  expectedMessage: string = 'Internal Server Error',
  requestOverrides: Partial<Request> = {},
  options: {
    shouldIncludeStack?: boolean;
    shouldIncludeDebug?: boolean;
    customValidation?: (res: Partial<Response>) => void;
  } = {}
): ErrorTestScenario => ({
  name,
  error,
  request: createMockRequest(requestOverrides),
  response: createMockResponse(),
  next: createMockNext(),
  expectedStatusCode,
  expectedErrorCode,
  expectedMessage,
  ...options
});

/**
 * Helper to run error handler test and assert common behaviors
 */
export const runErrorHandlerTest = async (
  errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void,
  scenario: ErrorTestScenario
) => {
  errorHandler(
    scenario.error,
    scenario.request as Request,
    scenario.response as Response,
    scenario.next
  );

  // Check status code was set correctly
  expect(scenario.response.status).toHaveBeenCalledWith(scenario.expectedStatusCode);

  // Check response JSON structure
  const jsonCall = (scenario.response.json as jest.MockedFunction<any>).mock.calls[0];
  expect(jsonCall).toBeDefined();
  
  const responseBody = jsonCall[0];
  expect(responseBody).toMatchObject({
    status: 'error',
    code: scenario.expectedErrorCode,
    message: scenario.expectedMessage,
    requestId: expect.any(String),
    timestamp: expect.any(String)
  });

  // Only check security headers if not explicitly disabled
  if (!scenario.customValidation || scenario.expectedErrorCode !== 'SKIP_SECURITY_HEADERS') {
    expect(scenario.response.set).toHaveBeenCalledWith(expectedSecurityHeaders);
  }

  // Run custom validation if provided
  if (scenario.customValidation) {
    scenario.customValidation(scenario.response);
  }

  return responseBody;
};

/**
 * Helper to test multiple error scenarios
 * Note: This should be used inside describe blocks, not inside it blocks
 */
export const testErrorScenarios = (
  errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void,
  scenarios: ErrorTestScenario[]
) => {
  scenarios.forEach(scenario => {
    it(scenario.name, async () => {
      await runErrorHandlerTest(errorHandler, scenario);
    });
  });
};

/**
 * Helper to create standard error scenarios
 */
export const createStandardErrorScenarios = (): ErrorTestScenario[] => [
  createErrorTestScenario(
    'should handle null error',
    null,
    500,
    'INTERNAL_ERROR',
    'Internal Server Error'
  ),
  createErrorTestScenario(
    'should handle undefined error',
    undefined,
    500,
    'INTERNAL_ERROR',
    'Internal Server Error'
  ),
  createErrorTestScenario(
    'should handle string error',
    'Simple string error',
    500,
    'INTERNAL_ERROR',
    'Internal Server Error' // String errors default to generic message
  ),
  createErrorTestScenario(
    'should handle number error',
    404,
    500,
    'INTERNAL_ERROR',
    'Internal Server Error' // Number errors default to generic message
  ),
  createErrorTestScenario(
    'should handle basic Error object',
    new Error('Basic error'),
    500,
    'INTERNAL_ERROR',
    'Basic error'
  ),
  createErrorTestScenario(
    'should handle error with status code',
    createMockError('Custom error', 400, 'CUSTOM_ERROR'),
    400,
    'CUSTOM_ERROR',
    'Custom error'
  )
];

/**
 * Helper to create security test scenarios
 */
export const createSecurityTestScenarios = (): ErrorTestScenario[] => [
  createErrorTestScenario(
    'should sanitize XSS attempts in error messages',
    createMockError('<script>alert("xss")</script>', 400, 'XSS_TEST'),
    400,
    'XSS_TEST',
    'alert("xss")'
  ),
  createErrorTestScenario(
    'should sanitize SQL injection attempts',
    createMockError('SELECT * FROM users; DROP TABLE users;', 400, 'SQL_TEST'),
    400,
    'SQL_TEST',
    '[SQL] * FROM users; [SQL] TABLE users;'
  ),
  createErrorTestScenario(
    'should sanitize error codes',
    createMockError('Test error', 400, 'invalid-code!@#'),
    400,
    'INVALID_CODE',
    'Test error'
  )
];

/**
 * Helper to create environment-specific test scenarios
 */
export const createEnvironmentTestScenarios = (env: string): ErrorTestScenario[] => {
  const includeStack = env === 'development';
  const includeDebug = env === 'development';

  return [
    createErrorTestScenario(
      `should ${includeStack ? 'include' : 'exclude'} stack trace in ${env}`,
      createMockError('Test error with stack', 500, 'STACK_TEST'),
      500,
      'STACK_TEST',
      'Test error with stack',
      {},
      { 
        shouldIncludeStack: includeStack,
        shouldIncludeDebug: includeDebug,
        customValidation: (res) => {
          const jsonCall = (res.json as jest.MockedFunction<any>).mock.calls[0];
          const responseBody = jsonCall[0];
          
          if (includeStack) {
            expect(responseBody.stack).toBeDefined();
          } else {
            expect(responseBody.stack).toBeUndefined();
          }
          
          if (includeDebug) {
            expect(responseBody.debug).toBeDefined();
            expect(responseBody.debug).toMatchObject({
              path: expect.any(String),
              method: expect.any(String),
              userId: expect.anything()
            });
          } else {
            expect(responseBody.debug).toBeUndefined();
          }
        }
      }
    )
  ];
};

/**
 * Helper to test status code processing
 */
export const createStatusCodeTestScenarios = (): ErrorTestScenario[] => [
  createErrorTestScenario(
    'should default invalid status codes to 500',
    { message: 'Test', statusCode: 'invalid' },
    500,
    'INTERNAL_ERROR',
    'Test'
  ),
  createErrorTestScenario(
    'should default negative status codes to 500',
    { message: 'Test', statusCode: -1 },
    500,
    'INTERNAL_ERROR',
    'Test'
  ),
  createErrorTestScenario(
    'should convert success status codes to 500',
    { message: 'Test', statusCode: 200 },
    500,
    'INTERNAL_ERROR',
    'Test'
  ),
  createErrorTestScenario(
    'should preserve valid error status codes',
    { message: 'Test', statusCode: 404 },
    404,
    'INTERNAL_ERROR',
    'Test'
  )
];

/**
 * Helper to test message sanitization
 */
export const testMessageSanitization = (
  processFn: (message: any) => string,
  testCases: typeof sanitizationTestCases
) => {
  Object.entries(testCases).forEach(([key, value]) => {
    if (key.endsWith('Expected')) return;
    
    const expectedKey = `${key}Expected`;
    const expected = testCases[expectedKey as keyof typeof testCases];
    
    it(`should sanitize ${key}`, () => {
      expect(processFn(value)).toBe(expected);
    });
  });
};

/**
 * Helper to test error code validation and transformation
 */
export const testErrorCodeTransformation = (
  processFn: (code: any) => string,
  transformations: Record<string, string>
) => {
  Object.entries(transformations).forEach(([input, expected]) => {
    it(`should transform "${input}" to "${expected}"`, () => {
      expect(processFn(input)).toBe(expected);
    });
  });
};

/**
 * Helper to test logging behavior
 */
export const testLoggingBehavior = (
  logFn: (...args: any[]) => void,
  severity: string,
  expectedConsoleMethod: keyof typeof mockConsole
) => {
  const consoleMocks = setupConsoleMocks();
  
  logFn();
  
  expect(consoleMocks.mockConsole[expectedConsoleMethod]).toHaveBeenCalled();
  
  consoleMocks.restore();
};

/**
 * Helper to test security headers
 */
export const testSecurityHeaders = (response: Partial<Response>) => {
  expect(response.set).toHaveBeenCalledWith(expectedSecurityHeaders);
};

/**
 * Helper to validate request ID generation
 */
export const validateRequestId = (requestId: string) => {
  expect(requestId).toMatch(/^req_\d+_[a-z0-9]{9}$/);
  expect(requestId.length).toBeGreaterThan(10);
};

/**
 * Helper to test timing attack resistance
 */
export const testTimingAttackResistance = async (
  operations: Array<() => Promise<void> | void>,
  tolerance: number = 100
) => {
  const times: number[] = [];
  
  for (const operation of operations) {
    const start = Date.now();
    await operation();
    times.push(Date.now() - start);
  }
  
  // Check that all operations complete within similar timeframes
  const maxTime = Math.max(...times);
  const minTime = Math.min(...times);
  
  expect(maxTime - minTime).toBeLessThan(tolerance);
};

/**
 * Helper to test DoS protection
 */
export const testDosProtection = (
  processFn: (input: any) => string,
  maxLength: number
) => {
  const longInput = 'A'.repeat(maxLength + 1000);
  const result = processFn(longInput);
  
  expect(result.length).toBeLessThanOrEqual(maxLength + 20); // Allow for truncation message
  expect(result).toContain('(truncated)');
};

/**
 * Helper to create enhanced API error test scenarios
 */
export const createEnhancedApiErrorScenarios = () => [
  {
    name: 'should handle enhanced API error with context',
    create: () => ({
      message: 'Enhanced error',
      statusCode: 400,
      code: 'ENHANCED_ERROR',
      context: { userId: 'test-user', operation: 'test-op' }
    })
  },
  {
    name: 'should handle validation error',
    create: () => ({
      message: 'Validation failed',
      statusCode: 400,
      code: 'VALIDATION_ERROR',
      context: { field: 'email', value: 'invalid-email' }
    })
  },
  {
    name: 'should handle business logic error',
    create: () => ({
      message: 'Business rule violated',
      statusCode: 400,
      code: 'BUSINESS_LOGIC_ERROR',
      context: { operation: 'create-user', resource: 'user' }
    })
  }
];

/**
 * Helper to validate error context
 */
export const validateErrorContext = (context: any, expectedKeys: string[]) => {
  expect(context).toBeDefined();
  expectedKeys.forEach(key => {
    expect(context).toHaveProperty(key);
  });
};

/**
 * Helper to test async error wrapper
 */
export const testAsyncErrorWrapper = async (
  wrapper: (fn: any) => any,
  asyncFn: () => Promise<any>,
  expectedError: Error
) => {
  const wrappedFn = wrapper(asyncFn);
  const mockNext = jest.fn();
  
  await wrappedFn({}, {}, mockNext);
  
  expect(mockNext).toHaveBeenCalledWith(expectedError);
};

/**
 * Helper to clean up test environment
 */
export const cleanupTest = () => {
  jest.clearAllMocks();
  
  // Reset console methods
  if (jest.isMockFunction(console.log)) {
    jest.restoreAllMocks();
  }
  
  // Reset environment
  if (process.env.NODE_ENV === undefined) {
    delete process.env.NODE_ENV;
  }
};

/**
 * Helper to wait for async operations
 */
export const waitForAsync = () => new Promise(resolve => setImmediate(resolve));

/**
 * Helper to create memory usage test
 */
export const testMemoryUsage = (operation: () => void, maxIncrease: number = 10 * 1024 * 1024) => {
  const initialMemory = process.memoryUsage().heapUsed;
  
  operation();
  
  // Force garbage collection if available
  if (global.gc) {
    global.gc();
  }
  
  const finalMemory = process.memoryUsage().heapUsed;
  const increase = finalMemory - initialMemory;
  
  expect(increase).toBeLessThan(maxIncrease);
};

/**
 * Helper to test error handler performance
 */
export const testErrorHandlerPerformance = (
  errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void,
  maxExecutionTime: number = 100
) => {
  const error = createMockError('Performance test error');
  const req = createMockRequest();
  const res = createMockResponse();
  const next = createMockNext();
  
  const start = Date.now();
  errorHandler(error, req as Request, res as Response, next);
  const executionTime = Date.now() - start;
  
  expect(executionTime).toBeLessThan(maxExecutionTime);
};