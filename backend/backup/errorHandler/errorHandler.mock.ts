// backend/src/__tests__/mocks/errorHandler.mock.ts
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';

// Extend Request interface to include custom properties
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
      };
    }
  }
}

// Mock error types
export const mockAppError = {
  name: 'AppError',
  message: 'Test error message',
  statusCode: 400,
  code: 'TEST_ERROR',
  stack: 'Error: Test error message\n    at test (/path/to/test.js:1:1)',
  cause: undefined as Error | undefined
};

export const mockApiError = {
  name: 'ApiError',
  message: 'API test error',
  statusCode: 422,
  code: 'API_TEST_ERROR',
  stack: 'Error: API test error\n    at apiTest (/path/to/api.js:1:1)',
  isOperational: true
};

export const mockInternalError = {
  name: 'Error',
  message: 'Internal server error',
  statusCode: 500,
  code: 'INTERNAL_SERVER_ERROR',
  stack: 'Error: Internal server error\n    at internal (/path/to/internal.js:1:1)'
};

export const mockValidationError = {
  name: 'ValidationError',
  message: 'Validation failed',
  statusCode: 400,
  code: 'VALIDATION_FAILED',
  stack: 'ValidationError: Validation failed\n    at validate (/path/to/validation.js:1:1)',
  field: 'email',
  value: 'invalid-email'
};

// Mock different error scenarios
export const errorScenarios = {
  nullError: null,
  undefinedError: undefined,
  stringError: 'Simple string error',
  numberError: 404,
  objectError: { message: 'Object error', custom: 'data' },
  arrayError: ['error', 'array'],
  circularError: (() => {
    const obj: any = { message: 'Circular reference error' };
    obj.self = obj;
    return obj;
  })(),
  emptyError: new Error(''),
  longMessageError: new Error('A'.repeat(2000)),
  specialCharsError: new Error('<script>alert("xss")</script>'),
  sqlInjectionError: new Error('SELECT * FROM users WHERE id = 1; DROP TABLE users;'),
  unicodeError: new Error('Unicode test: 🚀 emoji and special chars ñáéíóú'),
  nullMessageError: { ...mockAppError, message: null },
  undefinedMessageError: { ...mockAppError, message: undefined },
  invalidStatusCodeError: { ...mockAppError, statusCode: 'invalid' },
  negativeStatusCodeError: { ...mockAppError, statusCode: -1 },
  successStatusCodeError: { ...mockAppError, statusCode: 200 },
  invalidCodeError: { ...mockAppError, code: 'invalid_code!' },
  numericCodeError: { ...mockAppError, code: 123 },
  emptyCodeError: { ...mockAppError, code: '' },
  specialCharsCodeError: { ...mockAppError, code: 'TEST-ERROR@#$' }
};

// Mock request objects with different scenarios
export const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
  headers: {
    'user-agent': 'test-user-agent',
    'x-request-id': 'test-request-id'
  },
  path: '/test/path',
  method: 'GET',
  get: ((jest.fn().mockImplementation((...args: unknown[]) => {
    const header = args[0] as string;
    if (typeof header === 'string' && header.toLowerCase() === 'set-cookie') {
      // Simulate no cookies by default
      return undefined as string[] | undefined;
    }
    const headers: Record<string, string | string[]> = {
      'user-agent': 'test-user-agent',
      'x-request-id': 'test-request-id',
      ...overrides.headers
    };
    return typeof header === 'string' ? headers[header.toLowerCase()] : undefined;
  })) as unknown) as Request['get'],
  user: undefined,
  ...overrides
});

// Mock response objects
export const createMockResponse = (): Partial<Response> => {
  const mockResponse = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis(),
    locals: {}
  } as any;
  
  return mockResponse;
};

// Mock next function
export const createMockNext = (): NextFunction => 
  jest.fn() as NextFunction;

// Mock authenticated request
export const createAuthenticatedRequest = (userId?: string): Partial<Request> => 
  createMockRequest({
    user: {
      id: userId || 'test-user-id',
      email: 'test@example.com'
    }
  });

// Mock unauthenticated request
export const createUnauthenticatedRequest = (): Partial<Request> => 
  createMockRequest({
    user: undefined
  });

// Mock request without headers
export const createRequestWithoutHeaders = (): Partial<Request> => 
  createMockRequest({
    headers: {},
    get: ((header: string) => {
      if (header.toLowerCase() === 'set-cookie') {
        return undefined as string[] | undefined;
      }
      return undefined as string | undefined;
    }) as Request['get']
  });

// Mock request with custom headers
export const createRequestWithHeaders = (headers: Record<string, string>): Partial<Request> => 
  createMockRequest({
    headers,
    get: ((header: string) => {
      if (header.toLowerCase() === 'set-cookie') {
        // Simulate no cookies by default
        return undefined as string[] | undefined;
      }
      return headers[header.toLowerCase()];
    }) as Request['get']
  });

// Mock console methods for logging tests
export const mockConsole = {
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
  debug: jest.fn()
};

// Environment mocks
export const mockEnvironments = {
  development: 'development',
  production: 'production',
  test: 'test'
};

// Mock error with cause
export const createErrorWithCause = (message: string, cause: Error): Error => {
  const error = new Error(message);
  (error as any).cause = cause;
  return error;
};

// Mock enhanced API error scenarios
export const enhancedApiErrorScenarios = {
  withContext: {
    message: 'Enhanced error with context',
    statusCode: 400,
    code: 'ENHANCED_ERROR',
    context: { userId: 'test-user', operation: 'test-operation' }
  },
  validation: {
    message: 'Validation error',
    field: 'email',
    value: 'invalid-email'
  },
  business: {
    message: 'Business logic error',
    operation: 'create-user',
    resource: 'user'
  }
};

// Mock request ID generation
const mockRequestIds = [
  'req_1234567890_abc123def',
  'req_1234567891_def456ghi',
  'req_1234567892_ghi789jkl'
];

// Mock security headers
const expectedSecurityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block'
};

// Mock response body structure
export const createExpectedErrorResponse = (
  code: string,
  message: string,
  requestId: string,
  timestamp?: string,
  includeDebug: boolean = false,
  includeStack: boolean = false
) => {
  const response: any = {
    status: 'error',
    code,
    message,
    requestId,
    timestamp: timestamp || expect.any(String)
  };

  if (includeDebug) {
    response.debug = {
      path: expect.any(String),
      method: expect.any(String),
      userId: expect.anything()
    };
  }

  if (includeStack) {
    response.stack = expect.any(String);
  }

  return response;
};

// Mock error severity levels
const errorSeverityScenarios = {
  critical: { statusCode: 500, severity: 'critical' },
  high: { statusCode: 501, severity: 'critical' },
  medium: { statusCode: 400, severity: 'medium' },
  low: { statusCode: 300, severity: 'low' },
  unknown: { statusCode: 200, severity: 'low' }
};

// Mock sanitization test cases
const sanitizationTestCases = {
  htmlTags: '<script>alert("xss")</script>',
  htmlTagsExpected: 'alert("xss")',
  javascript: 'javascript:alert("xss")',
  javascriptExpected: 'alert("xss")',
  dataUri: 'data:text/html,<script>alert("xss")</script>',
  dataUriExpected: ',alert("xss")',
  sqlInjection: 'SELECT * FROM users; DROP TABLE users;',
  sqlInjectionExpected: '[SQL] * FROM users; [SQL] TABLE users;',
  excessiveWhitespace: 'Error   with    lots     of      spaces',
  excessiveWhitespaceExpected: 'Error with lots of spaces',
  mixedThreats: '<script>SELECT * FROM users</script> javascript:alert(1)',
  mixedThreatsExpected: '[SQL] * FROM users alert(1)'
};

// Mock process.env scenarios
const processEnvScenarios = {
  development: { NODE_ENV: 'development' },
  production: { NODE_ENV: 'production' },
  test: { NODE_ENV: 'test' },
  undefined: { NODE_ENV: undefined }
};

// Mock timing attack prevention data
const timingAttackScenarios = {
  scenario1: { delay: 0, expectedRange: 50 },
  scenario2: { delay: 10, expectedRange: 50 },
  scenario3: { delay: 20, expectedRange: 50 }
};

// Mock large payload scenarios for DoS testing
const dosTestScenarios = {
  maxLength: 1024 * 1024,
  overMaxLength: 1024 * 1024 + 1,
  normalLength: 100,
  emptyLength: 0
};

// Mock error code transformation test cases
const errorCodeTransformations = {
  'invalid-code': 'INVALID_CODE',
  'test error': 'TEST_ERROR',
  '123invalid': 'E23INVALID',
  'special@#$chars': 'SPECIAL_CHARS',
  '___multiple___underscores___': 'MULTIPLE_UNDERSCORES',
  '': 'INTERNAL_ERROR',
  'normal_code': 'NORMAL_CODE',
  'ALREADY_VALID': 'ALREADY_VALID'
};

// Mock async error scenarios
const asyncErrorScenarios = {
  promiseRejection: () => Promise.reject(new Error('Promise rejection')),
  asyncThrow: async () => { throw new Error('Async throw'); },
  asyncTimeout: () => new Promise((_, reject) => {
    setTimeout(() => reject(new Error('Timeout error')), 10);
  }),
  nestedAsyncError: async () => {
    await Promise.resolve();
    throw new Error('Nested async error');
  }
};

// Export utility functions
export const createMockError = (
  message: string,
  statusCode: number = 500,
  code: string = 'TEST_ERROR'
) => ({
  name: 'MockError',
  message,
  statusCode,
  code,
  stack: `Error: ${message}\n    at test (/path/to/test.js:1:1)`
});

export const createMockEnhancedApiError = (
  message: string,
  statusCode: number,
  code: string,
  context?: Record<string, any>,
  cause?: Error
) => ({
  name: 'EnhancedApiError',
  message,
  statusCode,
  code,
  context,
  cause,
  stack: `EnhancedApiError: ${message}\n    at test (/path/to/test.js:1:1)`
});

// Export mock data for reuse
export {
  mockRequestIds,
  expectedSecurityHeaders,
  errorSeverityScenarios,
  sanitizationTestCases,
  processEnvScenarios,
  timingAttackScenarios,
  dosTestScenarios,
  errorCodeTransformations,
  asyncErrorScenarios
};