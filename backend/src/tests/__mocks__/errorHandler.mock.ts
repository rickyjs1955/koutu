// backend/src/__tests__/__mocks__/errorHandler.mock.ts
import { expect, jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import { FLUTTER_ERROR_CODES } from '../../middlewares/errorHandler';

export interface MockError {
  name?: string;
  message?: string;
  statusCode?: number;
  code?: string;
  stack?: string;
  cause?: Error;
  type?: string;
  context?: Record<string, any>;
}

// Flutter-compatible response structure for testing
export interface FlutterErrorResponse {
  success: boolean;
  error: {
    code: string;
    message: string;
    details?: {
      field?: string;
      value?: any;
      operation?: string;
      resource?: string;
    };
    timestamp: string;
    requestId: string;
    statusCode: number;
  };
  debug?: {
    path: string;
    method: string;
    userId?: string;
    stack?: string;
  };
}

export const createMockError = (
  message?: string,
  statusCode?: number,
  code?: string,
  context?: Record<string, any>
): MockError => ({
  name: 'Error',
  message: message || 'Test error message',
  statusCode: statusCode || 500,
  code: code || 'TEST_ERROR',
  stack: 'Error: Test error\n    at test.js:1:1',
  context
});

export const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
  path: '/test/path',
  method: 'GET',
  headers: {
    'x-request-id': 'test-request-id',
    'user-agent': 'Test Agent'
  },
  get: jest.fn().mockImplementation((header: any) => {
    const headers: Record<string, string> = {
      'X-Request-ID': 'test-request-id',
      'User-Agent': 'Test Agent'
    };
    return headers[header];
  }) as Request['get'],
  user: undefined,
  ...overrides
});

export const createMockResponse = (): Partial<Response> & Response => (
  {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis()
  } as unknown as Partial<Response> & Response
);

export const createMockNext = (): NextFunction => jest.fn();

// Error scenarios for testing
export const errorScenarios = {
  basicError: new Error('Basic error'),
  nullError: null,
  undefinedError: undefined,
  stringError: 'String error message',
  emptyError: createMockError('', 400, 'EMPTY_ERROR'),
  nullMessageError: createMockError(null as any, 400, 'TEST_ERROR'),
  undefinedMessageError: createMockError(undefined as any, 400, 'TEST_ERROR'),
  numericCodeError: createMockError('Test error message', 400, 123 as any),
  emptyCodeError: createMockError('Test error message', 400, ''),
  specialCharsCodeError: createMockError('Test error message', 400, 'test-error!@#'),
  invalidCodeError: createMockError('Test error message', 400, 'invalid_code'),
  unicodeError: createMockError('Unicode test: 🚀 emoji and special chars ñáéíóú', 500),
  circularError: (() => {
    const error: any = createMockError('Circular reference error', 500, 'CIRCULAR_ERROR');
    error.self = error;
    error.nested = { parent: error };
    return error;
  })()
};

// Enhanced API Error scenarios for testing
export const enhancedApiErrorScenarios = {
  validationError: createMockError(
    'Validation failed',
    400,
    FLUTTER_ERROR_CODES.VALIDATION_ERROR,
    { field: 'email', value: 'invalid-email' }
  ),
  businessError: createMockError(
    'Business rule violation',
    400,
    FLUTTER_ERROR_CODES.BUSINESS_RULE_VIOLATION,
    { operation: 'create-user', resource: 'user' }
  ),
  authError: createMockError(
    'Authentication required',
    401,
    FLUTTER_ERROR_CODES.AUTHENTICATION_REQUIRED
  ),
  notFoundError: createMockError(
    'Resource not found',
    404,
    FLUTTER_ERROR_CODES.RESOURCE_NOT_FOUND,
    { resource: 'user' }
  )
};

// Sanitization test cases
export const sanitizationTestCases = [
  {
    name: 'XSS script tags',
    input: '<script>alert("xss")</script>',
    expectedSanitized: 'alert("xss")'
  },
  {
    name: 'HTML tags',
    input: '<div>Safe content</div>',
    expectedSanitized: 'Safe content'
  },
  {
    name: 'JavaScript protocol',
    input: 'javascript:alert("xss")',
    expectedSanitized: 'alert("xss")'
  },
  {
    name: 'Data protocol',
    input: 'data:text/html,<script>alert("xss")</script>',
    expectedSanitized: 'text/html,alert("xss")'
  },
  {
    name: 'SQL injection',
    input: 'Error: SELECT * FROM users; DROP TABLE users;',
    expectedSanitized: 'Error: [SQL] * FROM users; [SQL] TABLE users;'
  },
  {
    name: 'Multiple whitespace',
    input: 'Error    with   multiple   spaces',
    expectedSanitized: 'Error with multiple spaces'
  }
];

// Error code transformations for testing
export const errorCodeTransformations = [
  {
    name: 'lowercase to uppercase',
    input: 'test_error',
    expected: 'TEST_ERROR'
  },
  {
    name: 'special characters to underscores',
    input: 'test-error!@#',
    expected: 'TEST_ERROR'
  },
  {
    name: 'leading number to E prefix',
    input: '123_error',
    expected: 'E123_ERROR'
  },
  {
    name: 'multiple underscores collapsed',
    input: 'test___error',
    expected: 'TEST_ERROR'
  },
  {
    name: 'special case invalid_code',
    input: 'invalid_code',
    expected: FLUTTER_ERROR_CODES.BAD_REQUEST
  }
];

// Console mock utilities
export const mockConsole = {
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn(),
  debug: jest.fn()
};

// Expected security headers for Flutter compatibility
export const expectedSecurityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block'
};

// Create expected Flutter error response for testing
export const createExpectedFlutterErrorResponse = (
  code: string,
  message: string,
  statusCode: number,
  details?: any,
  requestId: string = 'test-request-id'
): FlutterErrorResponse => ({
  success: false,
  error: {
    code,
    message,
    timestamp: expect.any(String),
    requestId,
    statusCode,
    ...(details && { details })
  }
});

// Legacy compatibility - create expected error response in old format for existing tests
export const createExpectedErrorResponse = (
  code: string,
  message: string,
  statusCode: number,
  requestId: string = 'test-request-id'
) => ({
  status: 'error',
  code,
  message,
  requestId,
  timestamp: expect.any(String)
});

// Status code to Flutter error code mapping for tests
export const statusCodeToFlutterErrorCode = {
  400: FLUTTER_ERROR_CODES.BAD_REQUEST,
  401: FLUTTER_ERROR_CODES.AUTHENTICATION_REQUIRED,
  403: FLUTTER_ERROR_CODES.AUTHORIZATION_DENIED,
  404: FLUTTER_ERROR_CODES.RESOURCE_NOT_FOUND,
  409: FLUTTER_ERROR_CODES.CONFLICT,
  413: FLUTTER_ERROR_CODES.PAYLOAD_TOO_LARGE,
  429: FLUTTER_ERROR_CODES.RATE_LIMIT_EXCEEDED,
  500: FLUTTER_ERROR_CODES.INTERNAL_SERVER_ERROR,
  503: FLUTTER_ERROR_CODES.SERVICE_UNAVAILABLE
};

// Helper to validate Flutter error response structure
export const validateFlutterErrorResponse = (response: any): response is FlutterErrorResponse => {
  return (
    response &&
    typeof response === 'object' &&
    response.success === false &&
    response.error &&
    typeof response.error.code === 'string' &&
    typeof response.error.message === 'string' &&
    typeof response.error.timestamp === 'string' &&
    typeof response.error.requestId === 'string' &&
    typeof response.error.statusCode === 'number'
  );
};

// Helper to create error with Flutter error codes
export const createFlutterMockError = (
  message: string,
  statusCode: number,
  flutterCode: keyof typeof FLUTTER_ERROR_CODES,
  context?: Record<string, any>
): MockError => ({
  name: 'Error',
  message,
  statusCode,
  code: FLUTTER_ERROR_CODES[flutterCode],
  stack: 'Error: Test error\n    at test.js:1:1',
  context
});

// Test data for different error severity levels
export const errorSeverityTestCases = [
  {
    name: 'critical error (500+)',
    statusCode: 500,
    expectedSeverity: 'critical',
    expectedLogMethod: 'error'
  },
  {
    name: 'high error (not used in current implementation)',
    statusCode: 400,
    expectedSeverity: 'medium',
    expectedLogMethod: 'warn'
  },
  {
    name: 'medium error (400-499)',
    statusCode: 400,
    expectedSeverity: 'medium',
    expectedLogMethod: 'warn'
  },
  {
    name: 'low error (300-399)',
    statusCode: 300,
    expectedSeverity: 'low',
    expectedLogMethod: 'log'
  }
];

// Helper to create body parser errors
export const createBodyParserError = (type: 'malformed-json' | 'too-large') => {
  if (type === 'malformed-json') {
    const error = new SyntaxError('Unexpected token } in JSON');
    (error as any).body = '{"invalid": json}';
    (error as any).stack = 'SyntaxError: Unexpected token } in JSON\n    at body-parser\n    at parse';
    return error;
  } else {
    const error = new Error('Request entity too large');
    (error as any).type = 'entity.too.large';
    (error as any).statusCode = 413;
    return error;
  }
};

// Environment-specific test scenarios
export const environmentTestScenarios = {
  development: {
    env: 'development',
    expectStack: true,
    expectDebug: true
  },
  production: {
    env: 'production',
    expectStack: false,
    expectDebug: false
  },
  test: {
    env: 'test',
    expectStack: false,
    expectDebug: false
  }
};

// Request ID validation pattern
export const REQUEST_ID_PATTERN = /^req_\d+_[a-z0-9]{9}$/;

// Helper to validate request ID format
export const isValidRequestId = (requestId: string): boolean => {
  return REQUEST_ID_PATTERN.test(requestId);
};

// Mock user data for testing authenticated requests
export const mockUserData = {
  id: 'test-user-123',
  email: 'test@example.com',
  role: 'user'
};

// Helper to create authenticated mock request
export const createAuthenticatedMockRequest = (user = mockUserData): Partial<Request> => ({
  ...createMockRequest(),
  user
});

// Performance test helpers
export const performanceTestConfig = {
  singleErrorMaxTime: 100, // milliseconds
  bulkErrorMaxTime: 5000,  // milliseconds for 1000 errors
  memoryLeakThreshold: 100 * 1024 * 1024, // 100MB
  concurrentErrorCount: 50,
  concurrentMaxTime: 5000 // milliseconds
};

// Large data test helpers
export const largeDataTestConfig = {
  maxMessageLength: 1024 * 1024, // 1MB
  largeMessageSize: 1024 * 1024 + 100, // Slightly over limit
  largeContextSize: 10000, // Large context object
  deepNestingLevel: 1000 // Deep object nesting
};

// Security test patterns
export const securityTestPatterns = {
  xssPatterns: [
    '<script>alert("xss")</script>',
    '<img src="x" onerror="alert(1)">',
    'javascript:alert("xss")',
    '<svg onload="alert(1)">',
    '"><script>alert("xss")</script>'
  ],
  sqlInjectionPatterns: [
    "'; DROP TABLE users; --",
    'SELECT * FROM users WHERE id = 1 OR 1=1',
    'UNION SELECT password FROM users',
    'INSERT INTO users (admin) VALUES (true)',
    'UPDATE users SET admin = true'
  ],
  pathTraversalPatterns: [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '/proc/self/environ',
    '../../../app/config/database.yml'
  ],
  prototypepollution: [
    '{"__proto__": {"polluted": true}}',
    '{"constructor": {"prototype": {"polluted": true}}}',
    '{"__proto__.polluted": true}'
  ]
};

// Unicode and special character test cases
export const unicodeTestCases = [
  {
    name: 'emoji characters',
    input: '🚀 Error with emoji 🔥',
    shouldPreserve: true
  },
  {
    name: 'accented characters',
    input: 'Erreur avec accents: àáâãäåæçèéêë',
    shouldPreserve: true
  },
  {
    name: 'chinese characters',
    input: '错误消息：中文字符',
    shouldPreserve: true
  },
  {
    name: 'arabic characters',
    input: 'رسالة خطأ بالعربية',
    shouldPreserve: true
  },
  {
    name: 'null bytes',
    input: 'Error with null\x00byte',
    shouldPreserve: false
  },
  {
    name: 'control characters',
    input: 'Error with\t\n\rcontrol chars',
    shouldPreserve: true // but may be normalized
  }
];

// Timing attack test configuration
export const timingAttackTestConfig = {
  iterations: 20,
  toleranceMs: 200,
  operations: [
    'normal_processing',
    'sanitization_heavy',
    'validation_complex'
  ]
};

// Helper functions for test assertions
export const assertFlutterErrorStructure = (response: any, expectedCode: string, expectedStatusCode: number) => {
  expect(response).toMatchObject({
    success: false,
    error: {
      code: expectedCode,
      message: expect.any(String),
      timestamp: expect.any(String),
      requestId: expect.any(String),
      statusCode: expectedStatusCode
    }
  });
};

export const assertSecurityHeaders = (mockRes: Partial<Response>) => {
  expect(mockRes.set).toHaveBeenCalledWith(expectedSecurityHeaders);
};

export const assertLoggingCall = (
  mockConsoleMethod: jest.MockedFunction<any>,
  expectedLevel: string,
  expectedCode: string
) => {
  expect(mockConsoleMethod).toHaveBeenCalledWith(
    expect.stringContaining(`${expectedLevel.toUpperCase()} ERROR [${expectedCode}]`),
    expect.any(Object)
  );
};

// Performance measurement helper
export const measurePerformance = async (operation: () => Promise<void> | void): Promise<number> => {
  const start = Date.now();
  await operation();
  return Date.now() - start;
};

// Memory usage helper
export const measureMemoryUsage = (): number => {
  return process.memoryUsage().heapUsed;
};

// Helper to create circular reference object
export const createCircularReference = () => {
  const obj: any = { name: 'circular' };
  obj.self = obj;
  obj.nested = { parent: obj };
  return obj;
};

// Helper to create deep nested object
export const createDeepNestedObject = (depth: number): any => {
  if (depth === 0) {
    return { value: 'deep_value' };
  }
  return { level: depth, nested: createDeepNestedObject(depth - 1) };
};

// Export default mock setup function
export const setupDefaultMocks = () => {
  const originalConsole = { ...console };
  
  // Mock console methods
  console.log = mockConsole.log;
  console.warn = mockConsole.warn;
  console.error = mockConsole.error;
  console.info = mockConsole.info;
  console.debug = mockConsole.debug;
  
  return {
    restore: () => {
      Object.assign(console, originalConsole);
    },
    mocks: mockConsole
  };
};

// Integration test helper for Express app setup
export const createTestExpressApp = () => {
  const express = require('express');
  const app = express();
  
  app.use(express.json());
  // Request ID middleware would be added by the test
  
  return app;
};

// Flutter-specific error response validation
export const validateFlutterSuccessResponse = (response: any) => {
  expect(response).toMatchObject({
    success: true,
    data: expect.anything(),
    message: expect.any(String),
    timestamp: expect.any(String)
  });
};

// Helper to create Flutter validation error
export const createFlutterValidationError = (field: string, value: any, message?: string) => {
  return createMockError(
    message || `Validation failed for field: ${field}`,
    400,
    FLUTTER_ERROR_CODES.VALIDATION_ERROR,
    { field, value: typeof value === 'object' ? '[object]' : value }
  );
};

// Helper to create Flutter business error
export const createFlutterBusinessError = (operation: string, resource?: string, message?: string) => {
  return createMockError(
    message || `Business rule violation in operation: ${operation}`,
    400,
    FLUTTER_ERROR_CODES.BUSINESS_RULE_VIOLATION,
    { operation, resource }
  );
};

// Default test timeout for async operations
export const DEFAULT_TEST_TIMEOUT = 10000; // 10 seconds

// Helper to wait for a specified time (for timing tests)
export const sleep = (ms: number): Promise<void> => {
  return new Promise(resolve => setTimeout(resolve, ms));
};