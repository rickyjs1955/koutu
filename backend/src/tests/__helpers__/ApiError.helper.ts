// backend/src/__tests__/__helpers__/ApiError.helper.ts
import { jest } from '@jest/globals';
import {
  MockApiError,
  errorScenarios,
  authErrorScenarios,
  createMockApiError,
  createMockAuthError,
  createMockValidationError,
  createMockFileError,
  createMockDatabaseError,
  resetApiErrorMocks,
  setupMockApiErrorImplementations
} from '../__mocks__/ApiError.mock';

/**
 * Test scenario interface for ApiError testing
 */
export interface ApiErrorTestScenario {
  name: string;
  error: MockApiError;
  expectedStatusCode: number;
  expectedCode: string;
  expectedMessage: string;
  expectedType?: string;
  expectedContext?: Record<string, any>;
}

/**
 * Helper to create standardized ApiError test scenarios
 */
export const createApiErrorTestScenario = (
  name: string,
  errorType: keyof typeof errorScenarios,
  overrides?: Partial<MockApiError>
): ApiErrorTestScenario => {
  const error = createMockApiError(errorType, overrides);
  const scenario = errorScenarios[errorType];
  
  return {
    name,
    error,
    expectedStatusCode: scenario.statusCode,
    expectedCode: scenario.code,
    expectedMessage: overrides?.message || scenario.message,
    expectedType: scenario.type,
    expectedContext: overrides?.context
  };
};

/**
 * Helper to create auth-specific error test scenarios
 */
export const createAuthErrorTestScenario = (
  name: string,
  errorType: keyof typeof authErrorScenarios,
  overrides?: Partial<MockApiError>
): ApiErrorTestScenario => {
  const error = createMockAuthError(errorType, overrides);
  const scenario = authErrorScenarios[errorType];
  
  return {
    name,
    error,
    expectedStatusCode: scenario.statusCode,
    expectedCode: scenario.code,
    expectedMessage: overrides?.message || scenario.message,
    expectedType: scenario.type,
    expectedContext: overrides?.context
  };
};

/**
 * Helper to run ApiError test scenarios
 */
export const runApiErrorTestScenario = (scenario: ApiErrorTestScenario) => {
  it(scenario.name, () => {
    expect(scenario.error).toBeInstanceOf(MockApiError);
    expect(scenario.error.statusCode).toBe(scenario.expectedStatusCode);
    expect(scenario.error.code).toBe(scenario.expectedCode);
    expect(scenario.error.message).toBe(scenario.expectedMessage);
    expect(scenario.error.isOperational).toBe(true);
    
    if (scenario.expectedType) {
      expect(scenario.error.type).toBe(scenario.expectedType);
    }
    
    if (scenario.expectedContext) {
      expect(scenario.error.context).toEqual(scenario.expectedContext);
    }
  });
};

/**
 * Helper to run multiple ApiError test scenarios
 */
export const runApiErrorTestScenarios = (scenarios: ApiErrorTestScenario[]) => {
  scenarios.forEach(runApiErrorTestScenario);
};

/**
 * Helper to test ApiError factory methods
 */
export const testApiErrorFactoryMethod = (
  methodName: keyof typeof MockApiError,
  expectedStatusCode: number,
  expectedCode: string,
  args: any[] = []
): MockApiError => {
  const method = MockApiError[methodName] as jest.MockedFunction<(...args: any[]) => MockApiError>;
  
  if (!jest.isMockFunction(method)) {
    throw new Error(`${String(methodName)} is not a mocked function`);
  }
  
  const error = method(...args);
  
  expect(method).toHaveBeenCalledWith(...args);
  expect(error).toBeInstanceOf(MockApiError);
  expect(error.statusCode).toBe(expectedStatusCode);
  expect(error.code).toBe(expectedCode);
  expect(error.isOperational).toBe(true);
  
  return error;
};

/**
 * Helper to assert error properties
 */
export const assertApiErrorProperties = (
  error: MockApiError,
  expectedProperties: {
    statusCode?: number;
    code?: string;
    message?: string;
    type?: string;
    cause?: Error;
    context?: Record<string, any>;
    isOperational?: boolean;
  }
) => {
  if (expectedProperties.statusCode !== undefined) {
    expect(error.statusCode).toBe(expectedProperties.statusCode);
  }
  
  if (expectedProperties.code !== undefined) {
    expect(error.code).toBe(expectedProperties.code);
  }
  
  if (expectedProperties.message !== undefined) {
    expect(error.message).toBe(expectedProperties.message);
  }
  
  if (expectedProperties.type !== undefined) {
    expect(error.type).toBe(expectedProperties.type);
  }
  
  if (expectedProperties.cause !== undefined) {
    expect(error.cause).toBe(expectedProperties.cause);
  }
  
  if (expectedProperties.context !== undefined) {
    expect(error.context).toEqual(expectedProperties.context);
  }
  
  if (expectedProperties.isOperational !== undefined) {
    expect(error.isOperational).toBe(expectedProperties.isOperational);
  }
};

/**
 * Helper to test error classification methods
 */
export const testErrorClassificationMethods = (
  error: MockApiError,
  expectations: {
    isClientError?: boolean;
    isServerError?: boolean;
    isRetryable?: boolean;
    severity?: 'low' | 'medium' | 'high' | 'critical';
  }
) => {
  if (expectations.isClientError !== undefined) {
    expect(error.isClientError()).toBe(expectations.isClientError);
  }
  
  if (expectations.isServerError !== undefined) {
    expect(error.isServerError()).toBe(expectations.isServerError);
  }
  
  if (expectations.isRetryable !== undefined) {
    expect(error.isRetryable()).toBe(expectations.isRetryable);
  }
  
  if (expectations.severity !== undefined) {
    expect(error.getSeverity()).toBe(expectations.severity);
  }
};

/**
 * Helper to test error JSON serialization
 */
export const testErrorJsonSerialization = (
  error: MockApiError,
  expectedJson?: Partial<{
    status: string;
    code: string;
    message: string;
    context: Record<string, any>;
  }>
): any => {
  const json = error.toJSON();
  
  expect(json.status).toBe('error');
  expect(json.code).toBe(error.code);
  expect(json.message).toBe(error.message);
  
  if (expectedJson) {
    Object.keys(expectedJson).forEach(key => {
      expect(json[key]).toEqual(expectedJson[key as keyof typeof expectedJson]);
    });
  }
  
  return json;
};

/**
 * Helper to create comprehensive test suites for specific error types
 */
export const createErrorTypeTestSuite = (
  errorType: keyof typeof errorScenarios,
  factoryMethod: keyof typeof MockApiError,
  testCases: Array<{
    name: string;
    args: any[];
    expectedOverrides?: Partial<MockApiError>;
  }>
) => {
  describe(`${String(factoryMethod)} factory method`, () => {
    const baseScenario = errorScenarios[errorType];
    
    testCases.forEach(testCase => {
      it(testCase.name, () => {
        const method = MockApiError[factoryMethod] as jest.MockedFunction<any>;
        const error = method(...testCase.args);
        
        expect(method).toHaveBeenCalledWith(...testCase.args);
        expect(error).toBeInstanceOf(MockApiError);
        expect(error.statusCode).toBe(baseScenario.statusCode);
        expect(error.isOperational).toBe(true);
        
        if (testCase.expectedOverrides) {
          Object.keys(testCase.expectedOverrides).forEach(key => {
            const expectedValue = testCase.expectedOverrides![key as keyof MockApiError];
            expect(error[key as keyof MockApiError]).toEqual(expectedValue);
          });
        }
      });
    });
  });
};

/**
 * Helper to create validation error test scenarios
 */
export const createValidationErrorScenarios = (): ApiErrorTestScenario[] => [
  {
    name: 'should create validation error for missing field',
    error: createMockValidationError('missingField', 'email'),
    expectedStatusCode: 400,
    expectedCode: 'VALIDATION_ERROR',
    expectedMessage: 'Required field is missing',
    expectedType: 'validation',
    expectedContext: { field: 'email', value: undefined, rule: undefined }
  },
  {
    name: 'should create validation error for invalid format',
    error: createMockValidationError('invalidFormat', 'email', 'invalid-email', 'email'),
    expectedStatusCode: 400,
    expectedCode: 'VALIDATION_ERROR',
    expectedMessage: 'Invalid format',
    expectedType: 'validation',
    expectedContext: { field: 'email', value: 'invalid-email', rule: 'email' }
  },
  {
    name: 'should create validation error for invalid UUID',
    error: createMockValidationError('invalidUUID', 'id', 'not-a-uuid', 'uuid'),
    expectedStatusCode: 400,
    expectedCode: 'VALIDATION_ERROR',
    expectedMessage: 'Invalid UUID format',
    expectedType: 'validation',
    expectedContext: { field: 'id', value: 'not-a-uuid', rule: 'uuid' }
  }
];

/**
 * Helper to create file operation error test scenarios
 */
export const createFileErrorScenarios = (): ApiErrorTestScenario[] => [
  {
    name: 'should create file upload error',
    error: createMockFileError('uploadFailed', 'upload', 'image.jpg'),
    expectedStatusCode: 500,
    expectedCode: 'FILE_OPERATION_ERROR',
    expectedMessage: 'File upload failed',
    expectedType: 'internal',
    expectedContext: { operation: 'upload', filename: 'image.jpg' }
  },
  {
    name: 'should create file deletion error',
    error: createMockFileError('deleteFailed', 'delete', 'old-file.jpg'),
    expectedStatusCode: 500,
    expectedCode: 'FILE_OPERATION_ERROR',
    expectedMessage: 'File deletion failed',
    expectedType: 'internal',
    expectedContext: { operation: 'delete', filename: 'old-file.jpg' }
  }
];

/**
 * Helper to create database error test scenarios
 */
export const createDatabaseErrorScenarios = (): ApiErrorTestScenario[] => [
  {
    name: 'should create database connection error',
    error: createMockDatabaseError('connectionFailed', 'connect', 'users'),
    expectedStatusCode: 500,
    expectedCode: 'DATABASE_ERROR',
    expectedMessage: 'Database connection failed',
    expectedType: 'internal',
    expectedContext: { operation: 'connect', table: 'users' }
  },
  {
    name: 'should create database query error',
    error: createMockDatabaseError('queryFailed', 'SELECT', 'images'),
    expectedStatusCode: 500,
    expectedCode: 'DATABASE_ERROR',
    expectedMessage: 'Database query failed',
    expectedType: 'internal',
    expectedContext: { operation: 'SELECT', table: 'images' }
  },
  {
    name: 'should create database constraint violation error',
    error: createMockDatabaseError('constraintViolation', 'INSERT', 'users'),
    expectedStatusCode: 409,
    expectedCode: 'DATABASE_ERROR',
    expectedMessage: 'Database constraint violation',
    expectedType: 'conflict',
    expectedContext: { operation: 'INSERT', table: 'users' }
  }
];

/**
 * Helper to test error inheritance and chaining
 */
export const testErrorChaining = (
  parentError: Error,
  childErrorFactory: () => MockApiError
) => {
  const childError = childErrorFactory();
  
  expect(childError.cause).toBe(parentError);
  expect(childError).toBeInstanceOf(MockApiError);
  expect(childError).toBeInstanceOf(Error);
};

/**
 * Helper to test unknown error conversion
 */
export const testUnknownErrorConversion = (
  unknownError: unknown,
  expectedMessage?: string
): MockApiError => {
  const convertedError = MockApiError.fromUnknown(unknownError, expectedMessage);
  
  expect(convertedError).toBeInstanceOf(MockApiError);
  
  if (unknownError instanceof MockApiError) {
    // Should return the same instance
    expect(convertedError).toBe(unknownError);
    // Don't check status code or code since it should preserve original
  } else {
    // Should create new error with 500 status
    expect(convertedError.statusCode).toBe(500);
    expect(convertedError.code).toBe('UNKNOWN_ERROR');
    
    if (unknownError instanceof Error) {
      expect(convertedError.message).toBe(unknownError.message || expectedMessage || 'An unexpected error occurred');
      expect(convertedError.cause).toBe(unknownError);
    } else {
      const expectedMsg = typeof unknownError === 'string' 
        ? unknownError 
        : expectedMessage || 'An unexpected error occurred';
      expect(convertedError.message).toBe(expectedMsg);
    }
  }
  
  return convertedError;
};

/**
 * Helper to create comprehensive error handling test scenarios
 */
export const createErrorHandlingTestScenarios = () => ({
  standardErrors: [
    createApiErrorTestScenario('should handle bad request', 'badRequest'),
    createApiErrorTestScenario('should handle unauthorized', 'unauthorized'),
    createApiErrorTestScenario('should handle forbidden', 'forbidden'),
    createApiErrorTestScenario('should handle not found', 'notFound'),
    createApiErrorTestScenario('should handle conflict', 'conflict'),
    createApiErrorTestScenario('should handle unprocessable entity', 'unprocessableEntity'),
    createApiErrorTestScenario('should handle too many requests', 'tooManyRequests'),
    createApiErrorTestScenario('should handle internal error', 'internalError'),
    createApiErrorTestScenario('should handle service unavailable', 'serviceUnavailable')
  ],
  
  authErrors: [
    createAuthErrorTestScenario('should handle missing token', 'missingToken'),
    createAuthErrorTestScenario('should handle invalid token', 'invalidToken'),
    createAuthErrorTestScenario('should handle expired token', 'expiredToken'),
    createAuthErrorTestScenario('should handle user not found', 'userNotFound'),
    createAuthErrorTestScenario('should handle access denied', 'accessDenied'),
    createAuthErrorTestScenario('should handle rate limit exceeded', 'rateLimitExceeded')
  ],
  
  validationErrors: createValidationErrorScenarios(),
  fileErrors: createFileErrorScenarios(),
  databaseErrors: createDatabaseErrorScenarios()
});

/**
 * Helper to setup mock environment for ApiError testing
 */
export const setupApiErrorTestEnvironment = () => {
  beforeEach(() => {
    resetApiErrorMocks();
    setupMockApiErrorImplementations();
  });
  
  afterEach(() => {
    resetApiErrorMocks();
  });
};

/**
 * Helper to assert error response format for API endpoints
 */
export const assertErrorResponse = (
  response: any,
  expectedStatusCode: number,
  expectedErrorCode: string,
  expectedMessage?: string
) => {
  expect(response.status).toBe(expectedStatusCode);
  expect(response.body).toHaveProperty('error');
  expect(response.body.error).toHaveProperty('code', expectedErrorCode);
  
  if (expectedMessage) {
    expect(response.body.error).toHaveProperty('message', expectedMessage);
  }
  
  expect(response.body.error).toHaveProperty('type');
};

/**
 * Helper to create error middleware test scenarios
 */
export const createErrorMiddlewareTestScenarios = () => [
  {
    name: 'should handle ApiError properly',
    error: createMockApiError('badRequest', { message: 'Test validation error' }),
    expectedResponse: {
      statusCode: 400,
      body: {
        error: {
          code: 'BAD_REQUEST',
          message: 'Test validation error',
          type: 'validation'
        }
      }
    }
  },
  {
    name: 'should handle unknown errors',
    error: new Error('Unexpected system error'),
    expectedResponse: {
      statusCode: 500,
      body: {
        error: {
          message: 'Internal server error',
          type: 'internal'
        }
      }
    }
  },
  {
    name: 'should handle non-error objects',
    error: 'String error',
    expectedResponse: {
      statusCode: 500,
      body: {
        error: {
          message: 'Internal server error',
          type: 'internal'
        }
      }
    }
  }
];

/**
 * Helper to test error context preservation
 */
export const testErrorContextPreservation = (
  error: MockApiError,
  expectedContext: Record<string, any>
): void => {
  expect(error.context).toBeDefined();
  expect(error.context).toEqual(expectedContext);
  
  // Test JSON serialization includes context in development
  const originalEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';
  
  const json = error.toJSON();
  expect(json.context).toEqual(expectedContext);
  
  // Test JSON serialization excludes context in production
  process.env.NODE_ENV = 'production';
  const prodJson = error.toJSON();
  expect(prodJson.context).toBeUndefined();
  
  process.env.NODE_ENV = originalEnv;
};

/**
 * Helper to test error severity classification
 */
export const testErrorSeverityClassification = () => {
  const testCases = [
    { statusCode: 400, expectedSeverity: 'medium' as const },
    { statusCode: 401, expectedSeverity: 'medium' as const },
    { statusCode: 403, expectedSeverity: 'medium' as const },
    { statusCode: 404, expectedSeverity: 'medium' as const },
    { statusCode: 429, expectedSeverity: 'high' as const },
    { statusCode: 500, expectedSeverity: 'critical' as const },
    { statusCode: 502, expectedSeverity: 'critical' as const },
    { statusCode: 503, expectedSeverity: 'critical' as const }
  ];
  
  testCases.forEach(({ statusCode, expectedSeverity }) => {
    it(`should classify ${statusCode} status as ${expectedSeverity} severity`, () => {
      const error = new MockApiError('Test error', statusCode, 'TEST_ERROR');
      expect(error.getSeverity()).toBe(expectedSeverity);
    });
  });
};

/**
 * Helper to test error retry logic
 */
export const testErrorRetryLogic = () => {
  const testCases = [
    { statusCode: 400, shouldRetry: false },
    { statusCode: 401, shouldRetry: false },
    { statusCode: 403, shouldRetry: false },
    { statusCode: 404, shouldRetry: false },
    { statusCode: 408, shouldRetry: true }, // Request Timeout
    { statusCode: 429, shouldRetry: true }, // Too Many Requests
    { statusCode: 500, shouldRetry: true },
    { statusCode: 502, shouldRetry: true },
    { statusCode: 503, shouldRetry: true }
  ];
  
  testCases.forEach(({ statusCode, shouldRetry }) => {
    it(`should ${shouldRetry ? '' : 'not '}mark ${statusCode} status as retryable`, () => {
      const error = new MockApiError('Test error', statusCode, 'TEST_ERROR');
      expect(error.isRetryable()).toBe(shouldRetry);
    });
  });
};

/**
 * Helper to clean up ApiError test environment
 */
export const cleanupApiErrorTests = () => {
  resetApiErrorMocks();
  jest.restoreAllMocks();
  
  // Reset NODE_ENV if it was modified during tests
  if (process.env.NODE_ENV !== 'test') {
    process.env.NODE_ENV = 'test';
  }
};

/**
 * Helper to create mock Express error handler for testing
 */
export const createMockErrorHandler = () => {
  return jest.fn((error: any, req: any, res: any, next: any) => {
    if (error instanceof MockApiError) {
      return res.status(error.statusCode).json({
        error: {
          code: error.code,
          message: error.message,
          type: error.type
        }
      });
    }
    
    // Handle non-ApiError instances
    return res.status(500).json({
      error: {
        message: 'Internal server error',
        type: 'internal'
      }
    });
  });
};

/**
 * Helper to assert mock function calls for error creation
 */
export const assertErrorFactoryCall = (
  factoryMethod: jest.MockedFunction<(...args: any[]) => MockApiError>,
  expectedArgs: any[],
  callIndex = 0
): void => {
  expect(factoryMethod).toHaveBeenCalled();
  expect(factoryMethod).toHaveBeenNthCalledWith(callIndex + 1, ...expectedArgs);
};

/**
 * Helper to create parameterized tests for all error types
 */
export const createParameterizedErrorTests = (
  testFunction: (errorType: keyof typeof errorScenarios) => void
) => {
  Object.keys(errorScenarios).forEach(errorType => {
    testFunction(errorType as keyof typeof errorScenarios);
  });
};