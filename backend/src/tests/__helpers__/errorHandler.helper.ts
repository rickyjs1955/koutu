// backend/src/__tests__/__helpers__/errorHandler.helper.ts
import { expect, jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  createMockError,
  FlutterErrorResponse,
  validateFlutterErrorResponse,
  assertFlutterErrorStructure,
  measurePerformance,
  measureMemoryUsage,
  performanceTestConfig,
  timingAttackTestConfig
} from '../__mocks__/errorHandler.mock';
import { FLUTTER_ERROR_CODES } from '../../middlewares/errorHandler';

// Console mocking utilities
export const setupConsoleMocks = () => {
  const originalConsole = {
    log: console.log,
    warn: console.warn,
    error: console.error,
    info: console.info,
    debug: console.debug
  };

  const mockConsole = {
    log: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
    debug: jest.fn()
  };

  console.log = mockConsole.log;
  console.warn = mockConsole.warn;
  console.error = mockConsole.error;
  console.info = mockConsole.info;
  console.debug = mockConsole.debug;

  return {
    mockConsole,
    restore: () => {
      console.log = originalConsole.log;
      console.warn = originalConsole.warn;
      console.error = originalConsole.error;
      console.info = originalConsole.info;
      console.debug = originalConsole.debug;
    }
  };
};

// Environment mocking utilities
export const setupEnvironmentMock = (env: string) => {
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

// Test scenario creation helpers
export interface ErrorTestScenario {
  name: string;
  error: any;
  expectedStatusCode: number;
  expectedCode: string;
  expectedMessage: string;
  expectedDetails?: any;
}

export const createErrorTestScenario = (
  name: string,
  error: any,
  expectedStatusCode: number,
  expectedCode: string,
  expectedMessage: string,
  expectedDetails?: any
): ErrorTestScenario => ({
  name,
  error,
  expectedStatusCode,
  expectedCode,
  expectedMessage,
  expectedDetails
});

// Enhanced test runner for Flutter-compatible error handler
export const runErrorHandlerTest = async (
  errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void,
  scenario: ErrorTestScenario
): Promise<FlutterErrorResponse> => {
  const mockReq = createMockRequest();
  const mockRes = createMockResponse();
  const mockNext = createMockNext();

  errorHandler(scenario.error, mockReq as Request, mockRes as Response, mockNext);

  // Verify response structure
  expect(mockRes.status).toHaveBeenCalledWith(scenario.expectedStatusCode);
  expect(mockRes.json).toHaveBeenCalled();

  const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
  const responseBody = jsonCall[0] as FlutterErrorResponse;

  // Validate Flutter response structure
  expect(validateFlutterErrorResponse(responseBody)).toBe(true);

  // Assert specific values
  assertFlutterErrorStructure(responseBody, scenario.expectedCode, scenario.expectedStatusCode);
  expect(responseBody.error.message).toBe(scenario.expectedMessage);

  if (scenario.expectedDetails) {
    expect(responseBody.error.details).toEqual(scenario.expectedDetails);
  }

  return responseBody;
};

// Legacy test runner for backward compatibility
export const runLegacyErrorHandlerTest = async (
  errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void,
  scenario: ErrorTestScenario
): Promise<any> => {
  const mockReq = createMockRequest();
  const mockRes = createMockResponse();
  const mockNext = createMockNext();

  errorHandler(scenario.error, mockReq as Request, mockRes as Response, mockNext);

  const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
  return jsonCall[0];
};

// Test scenario generators
export const createStandardErrorScenarios = (): ErrorTestScenario[] => [
  createErrorTestScenario(
    'should handle null error',
    null,
    500,
    FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR,
    'Internal Server Error'
  ),
  createErrorTestScenario(
    'should handle undefined error',
    undefined,
    500,
    FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR,
    'Internal Server Error'
  ),
  createErrorTestScenario(
    'should handle basic Error object',
    new Error('Basic error message'),
    500,
    FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR,
    'Basic error message'
  ),
  createErrorTestScenario(
    'should handle string error',
    'String error message',
    500,
    FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR,
    'Internal Server Error' // String errors are sanitized
  ),
  createErrorTestScenario(
    'should handle error with custom status and code',
    createMockError('Custom error', 400, FLUTTER_ERROR_CODES.VALIDATION_ERROR),
    400,
    FLUTTER_ERROR_CODES.VALIDATION_ERROR,
    'Custom error'
  )
];

export const createSecurityTestScenarios = (): ErrorTestScenario[] => [
  createErrorTestScenario(
    'should sanitize XSS script tags',
    createMockError('<script>alert("xss")</script>', 400, FLUTTER_ERROR_CODES.BAD_REQUEST),
    400,
    FLUTTER_ERROR_CODES.BAD_REQUEST,
    'alert("xss")'
  ),
  createErrorTestScenario(
    'should sanitize SQL injection patterns',
    createMockError('Error: SELECT * FROM users; DROP TABLE users;', 400, FLUTTER_ERROR_CODES.BAD_REQUEST),
    400,
    FLUTTER_ERROR_CODES.BAD_REQUEST,
    'Error: [SQL] * FROM users; [SQL] TABLE users;'
  ),
  createErrorTestScenario(
    'should remove HTML tags',
    createMockError('<div>Error content</div>', 400, FLUTTER_ERROR_CODES.BAD_REQUEST),
    400,
    FLUTTER_ERROR_CODES.BAD_REQUEST,
    'Error content'
  ),
  createErrorTestScenario(
    'should remove JavaScript protocol',
    createMockError('javascript:alert("xss")', 400, FLUTTER_ERROR_CODES.BAD_REQUEST),
    400,
    FLUTTER_ERROR_CODES.BAD_REQUEST,
    'alert("xss")'
  )
];

export const createEnvironmentTestScenarios = (): ErrorTestScenario[] => [
  createErrorTestScenario(
    'should handle development environment error',
    createMockError('Development error', 500, FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR),
    500,
    FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR,
    'Development error'
  ),
  createErrorTestScenario(
    'should handle production environment error',
    createMockError('Production error', 500, FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR),
    500,
    FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR,
    'Production error'
  )
];

export const createStatusCodeTestScenarios = (): ErrorTestScenario[] => [
  createErrorTestScenario(
    'should handle 400 bad request',
    createMockError('Bad request', 400),
    400,
    FLUTTER_ERROR_CODES.BAD_REQUEST,
    'Bad request'
  ),
  createErrorTestScenario(
    'should handle 401 authentication required',
    createMockError('Authentication required', 401),
    401,
    FLUTTER_ERROR_CODES.AUTHENTICATION_REQUIRED,
    'Authentication required'
  ),
  createErrorTestScenario(
    'should handle 403 authorization denied',
    createMockError('Access denied', 403),
    403,
    FLUTTER_ERROR_CODES.AUTHORIZATION_DENIED,
    'Access denied'
  ),
  createErrorTestScenario(
    'should handle 404 not found',
    createMockError('Resource not found', 404),
    404,
    FLUTTER_ERROR_CODES.RESOURCE_NOT_FOUND,
    'Resource not found'
  ),
  createErrorTestScenario(
    'should handle 409 conflict',
    createMockError('Resource conflict', 409),
    409,
    FLUTTER_ERROR_CODES.CONFLICT,
    'Resource conflict'
  ),
  createErrorTestScenario(
    'should handle 413 payload too large',
    createMockError('Payload too large', 413),
    413,
    FLUTTER_ERROR_CODES.PAYLOAD_TOO_LARGE,
    'Payload too large'
  ),
  createErrorTestScenario(
    'should handle 429 rate limit exceeded',
    createMockError('Rate limit exceeded', 429),
    429,
    FLUTTER_ERROR_CODES.RATE_LIMIT_EXCEEDED,
    'Rate limit exceeded'
  ),
  createErrorTestScenario(
    'should handle 500 internal server error',
    createMockError('Internal server error', 500),
    500,
    FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR,
    'Internal server error'
  ),
  createErrorTestScenario(
    'should convert success status code (200) to 500',
    createMockError('Success status error', 200, FLUTTER_ERROR_CODES.BAD_REQUEST),
    500, // Should be converted to 500
    FLUTTER_ERROR_CODES.BAD_REQUEST,
    'Success status error'
  )
];

// Test execution helpers
export const testErrorScenarios = async (
  errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void,
  scenarios: ErrorTestScenario[]
): Promise<void> => {
  for (const scenario of scenarios) {
    await runErrorHandlerTest(errorHandler, scenario);
  }
};

// Message sanitization testing
export const testMessageSanitization = (
  sanitizeFunction: (message: string) => string,
  testCases: Array<{ input: string; expected: string }>
): void => {
  testCases.forEach(({ input, expected }) => {
    const result = sanitizeFunction(input);
    expect(result).toBe(expected);
  });
};

// Error code transformation testing
export const testErrorCodeTransformation = (
  transformFunction: (code: any, statusCode: number) => string,
  testCases: Array<{ input: any; statusCode: number; expected: string }>
): void => {
  testCases.forEach(({ input, statusCode, expected }) => {
    const result = transformFunction(input, statusCode);
    expect(result).toBe(expected);
  });
};

// Request ID validation
export const validateRequestId = (requestId: string): void => {
  expect(requestId).toMatch(/^req_\d+_[a-z0-9]{9}$/);
};

// Timing attack resistance testing
export const testTimingAttackResistance = async (
  operations: Array<() => void | Promise<void>>,
  toleranceMs: number = timingAttackTestConfig.toleranceMs
): Promise<void> => {
  const times: number[] = [];

  // Run each operation multiple times and measure timing
  for (const operation of operations) {
    const operationTimes: number[] = [];
    
    for (let i = 0; i < timingAttackTestConfig.iterations; i++) {
      const duration = await measurePerformance(operation);
      operationTimes.push(duration);
    }
    
    // Use median to reduce outlier impact
    operationTimes.sort((a, b) => a - b);
    const median = operationTimes[Math.floor(operationTimes.length / 2)];
    times.push(median);
  }

  // Check that timing differences are within acceptable tolerance
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const timeDifference = maxTime - minTime;

  expect(timeDifference).toBeLessThan(toleranceMs);
};

// Performance testing helper
export const testPerformanceRequirements = async (
  operation: () => void | Promise<void>,
  requirements: {
    maxExecutionTime?: number;
    maxMemoryIncrease?: number;
    iterations?: number;
  }
): Promise<void> => {
  const {
    maxExecutionTime = performanceTestConfig.singleErrorMaxTime,
    maxMemoryIncrease = performanceTestConfig.memoryLeakThreshold,
    iterations = 1
  } = requirements;

  const initialMemory = measureMemoryUsage();
  
  // Test execution time
  const executionTime = await measurePerformance(async () => {
    for (let i = 0; i < iterations; i++) {
      await operation();
    }
  });

  expect(executionTime).toBeLessThan(maxExecutionTime);

  // Test memory usage (force garbage collection if available)
  if ((global as any).gc) {
    (global as any).gc();
  }
  
  const finalMemory = measureMemoryUsage();
  const memoryIncrease = finalMemory - initialMemory;
  
  expect(memoryIncrease).toBeLessThan(maxMemoryIncrease);
};

// Cleanup helper
export const cleanupTest = (): void => {
  jest.clearAllMocks();
  
  // Clear any global state if needed
  if ((global as any).gc) {
    (global as any).gc();
  }
};

// Flutter-specific validation helpers
export const validateFlutterErrorStructure = (response: any): void => {
  expect(response).toMatchObject({
    success: false,
    error: {
      code: expect.any(String),
      message: expect.any(String),
      timestamp: expect.any(String),
      requestId: expect.any(String),
      statusCode: expect.any(Number)
    }
  });

  // Validate that error code is a known Flutter error code
  const validCodes = Object.values(FLUTTER_ERROR_CODES);
  expect(validCodes).toContain(response.error.code);

  // Validate timestamp format (ISO string)
  expect(() => new Date(response.error.timestamp)).not.toThrow();
  
  // Validate request ID format
  validateRequestId(response.error.requestId);
  
  // Validate status code range
  expect(response.error.statusCode).toBeGreaterThanOrEqual(100);
  expect(response.error.statusCode).toBeLessThan(600);
};

// Flutter success response validation
export const validateFlutterSuccessStructure = (response: any): void => {
  expect(response).toMatchObject({
    success: true,
    data: expect.anything(),
    message: expect.any(String),
    timestamp: expect.any(String)
  });

  // Validate timestamp format
  expect(() => new Date(response.timestamp)).not.toThrow();
};

// Concurrency testing helper
export const testConcurrentErrorHandling = async (
  errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void,
  concurrentCount: number = performanceTestConfig.concurrentErrorCount
): Promise<void> => {
  const errors = Array.from({ length: concurrentCount }, (_, i) =>
    createMockError(`Concurrent error ${i}`, 400, FLUTTER_ERROR_CODES.BAD_REQUEST)
  );

  const promises = errors.map(error =>
    new Promise<void>((resolve) => {
      const mockReq = createMockRequest();
      const mockRes = createMockResponse();
      const mockNext = createMockNext();
      
      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);
      resolve();
    })
  );

  const executionTime = await measurePerformance(async () => {
    await Promise.all(promises);
  });

  expect(executionTime).toBeLessThan(performanceTestConfig.concurrentMaxTime);
};

// Error context extraction helper
export const extractErrorContext = (error: any): Record<string, any> => {
  const context: Record<string, any> = {};
  
  if (error.context) {
    Object.assign(context, error.context);
  }
  
  if (error.cause) {
    context.cause = error.cause.message || error.cause.toString();
  }
  
  return context;
};

// Enhanced API Error factory for testing
export const createEnhancedApiError = (
  message: string,
  statusCode: number,
  code: string,
  context?: Record<string, any>,
  cause?: Error
) => {
  const error = createMockError(message, statusCode, code, context);
  if (cause) {
    (error as any).cause = cause;
  }
  return error;
};

// Integration test helper for full error flow
export const testFullErrorFlow = async (
  errorHandler: (err: any, req: Request, res: Response, next: NextFunction) => void,
  error: any,
  expectedResponse: Partial<FlutterErrorResponse>
): Promise<void> => {
  const mockReq = createMockRequest();
  const mockRes = createMockResponse();
  const mockNext = createMockNext();

  errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

  const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
  const responseBody = jsonCall[0] as FlutterErrorResponse;

  // Validate complete structure
  validateFlutterErrorStructure(responseBody);
  
  // Check specific expectations
  if (expectedResponse.error?.code) {
    expect(responseBody.error.code).toBe(expectedResponse.error.code);
  }
  
  if (expectedResponse.error?.message) {
    expect(responseBody.error.message).toBe(expectedResponse.error.message);
  }
  
  if (expectedResponse.error?.statusCode) {
    expect(responseBody.error.statusCode).toBe(expectedResponse.error.statusCode);
  }
  
  if (expectedResponse.error?.details) {
    expect(responseBody.error.details).toEqual(expectedResponse.error.details);
  }
};

// Export all utilities as default
export default {
  setupConsoleMocks,
  setupEnvironmentMock,
  createErrorTestScenario,
  runErrorHandlerTest,
  runLegacyErrorHandlerTest,
  createStandardErrorScenarios,
  createSecurityTestScenarios,
  createEnvironmentTestScenarios,
  createStatusCodeTestScenarios,
  testErrorScenarios,
  testMessageSanitization,
  testErrorCodeTransformation,
  validateRequestId,
  testTimingAttackResistance,
  testPerformanceRequirements,
  cleanupTest,
  validateFlutterErrorStructure,
  validateFlutterSuccessStructure,
  testConcurrentErrorHandling,
  extractErrorContext,
  createEnhancedApiError,
  testFullErrorFlow
};