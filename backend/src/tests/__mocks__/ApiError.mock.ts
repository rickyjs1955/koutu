// backend/src/__tests__/__mocks__/ApiError.mock.ts
import { jest } from '@jest/globals';

/**
 * Mock ApiError class for testing
 */
export class MockApiError extends Error {
  statusCode: number;
  code: string;
  cause?: Error;
  context?: Record<string, any>;
  isOperational: boolean;
  type?: string; // For backwards compatibility with existing tests

  constructor(
    message: string,
    statusCode: number,
    code: string,
    cause?: Error,
    context?: Record<string, any>
  ) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.cause = cause;
    this.context = context;
    this.isOperational = true;
    this.name = 'ApiError';
    
    // Set type for backwards compatibility
    this.type = this.getTypeFromStatusCode(statusCode);
    
    Object.setPrototypeOf(this, MockApiError.prototype);
  }

  private getTypeFromStatusCode(statusCode: number): string {
    if (statusCode === 400) return 'validation';
    if (statusCode === 401) return 'authentication';
    if (statusCode === 403) return 'authorization';
    if (statusCode === 404) return 'notFound';
    if (statusCode === 409) return 'conflict';
    if (statusCode === 422) return 'unprocessableEntity';
    if (statusCode === 429) return 'rateLimited';
    if (statusCode >= 500) return 'internal';
    return 'unknown';
  }

  static badRequest = jest.fn((
    message: string | null | undefined = 'Bad request',
    code: string = 'BAD_REQUEST',
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedMessage = message === null || message === undefined ? 'Bad request' : String(message);
    const sanitizedCode = code === '' ? 'BAD_REQUEST' : code;
    return new MockApiError(sanitizedMessage, 400, sanitizedCode, undefined, context);
  });

  static unauthorized = jest.fn((
    message: string = 'Unauthorized',
    code: string = 'UNAUTHORIZED',
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedCode = code === '' ? 'UNAUTHORIZED' : code;
    return new MockApiError(message, 401, sanitizedCode, undefined, context);
  });

  static forbidden = jest.fn((
    message: string = 'Forbidden',
    code: string = 'FORBIDDEN',
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedCode = code === '' ? 'FORBIDDEN' : code;
    return new MockApiError(message, 403, sanitizedCode, undefined, context);
  });

  static notFound = jest.fn((
    message: string = 'Resource not found',
    code: string = 'NOT_FOUND',
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedCode = code === '' ? 'NOT_FOUND' : code;
    return new MockApiError(message, 404, sanitizedCode, undefined, context);
  });

  static conflict = jest.fn((
    message: string = 'Conflict',
    code: string = 'CONFLICT',
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedCode = code === '' ? 'CONFLICT' : code;
    return new MockApiError(message, 409, sanitizedCode, undefined, context);
  });

  static unprocessableEntity = jest.fn((
    message: string = 'Unprocessable Entity',
    code: string = 'UNPROCESSABLE_ENTITY',
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedCode = code === '' ? 'UNPROCESSABLE_ENTITY' : code;
    return new MockApiError(message, 422, sanitizedCode, undefined, context);
  });

  static tooManyRequests = jest.fn((
    message: string = 'Too many requests',
    code: string = 'TOO_MANY_REQUESTS',
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedCode = code === '' ? 'TOO_MANY_REQUESTS' : code;
    return new MockApiError(message, 429, sanitizedCode, undefined, context);
  });

  static internal = jest.fn((
    message: string = 'Internal server error',
    code: string = 'INTERNAL_ERROR',
    cause?: Error,
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedCode = code === '' ? 'INTERNAL_ERROR' : code;
    return new MockApiError(message, 500, sanitizedCode, cause, context);
  });

  static serviceUnavailable = jest.fn((
    message: string = 'Service unavailable',
    code: string = 'SERVICE_UNAVAILABLE',
    context?: Record<string, any>
  ): MockApiError => {
    const sanitizedCode = code === '' ? 'SERVICE_UNAVAILABLE' : code;
    return new MockApiError(message, 503, sanitizedCode, undefined, context);
  });

  static custom = jest.fn((
    message: string,
    statusCode: number,
    code: string,
    cause?: Error,
    context?: Record<string, any>
  ): MockApiError => {
    return new MockApiError(message, statusCode, code, cause, context);
  });

  // Enhanced factory methods
  static validation = jest.fn((
    message: string,
    field?: string,
    value?: any,
    rule?: string
  ): MockApiError => {
    return new MockApiError(
      message,
      400,
      'VALIDATION_ERROR',
      undefined,
      {
        field,
        value: typeof value === 'object' && value !== null ? '[object]' : value,
        rule
      }
    );
  });

  static database = jest.fn((
    message: string,
    operation: string,
    table?: string,
    cause?: Error
  ): MockApiError => {
    return new MockApiError(
      message,
      500,
      'DATABASE_ERROR',
      cause,
      { operation, table }
    );
  });

  static fileOperation = jest.fn((
    message: string,
    operation: 'upload' | 'delete' | 'read' | 'write',
    filename?: string,
    cause?: Error
  ): MockApiError => {
    return new MockApiError(
      message,
      500,
      'FILE_OPERATION_ERROR',
      cause,
      { operation, filename }
    );
  });

  static authentication = jest.fn((
    message: string = 'Authentication failed',
    reason?: string
  ): MockApiError => {
    return new MockApiError(
      message,
      401,
      'AUTHENTICATION_ERROR',
      undefined,
      { reason }
    );
  });

  static authorization = jest.fn((
    message: string = 'Access denied',
    resource?: string,
    action?: string
  ): MockApiError => {
    return new MockApiError(
      message,
      403,
      'AUTHORIZATION_ERROR',
      undefined,
      { resource, action }
    );
  });

  static rateLimited = jest.fn((
    message: string = 'Rate limit exceeded',
    limit?: number,
    windowMs?: number,
    retryAfter?: number
  ): MockApiError => {
    return new MockApiError(
      message,
      429,
      'RATE_LIMITED',
      undefined,
      { limit, windowMs, retryAfter }
    );
  });

  static businessLogic = jest.fn((
    message: string,
    rule: string,
    entity?: string
  ): MockApiError => {
    return new MockApiError(
      message,
      400,
      'BUSINESS_LOGIC_ERROR',
      undefined,
      { rule, entity }
    );
  });

  static externalService = jest.fn((
    message: string,
    service: string,
    cause?: Error
  ): MockApiError => {
    return new MockApiError(
      message,
      502,
      'EXTERNAL_SERVICE_ERROR',
      cause,
      { service }
    );
  });

  static fromUnknown = jest.fn((
    error: unknown,
    defaultMessage: string = 'An unexpected error occurred'
  ): MockApiError => {
    if (error instanceof MockApiError) {
      return error; // Return the same instance
    }

    if (error instanceof Error) {
      return new MockApiError(
        error.message || defaultMessage,
        500,
        'UNKNOWN_ERROR',
        error
      );
    }

    const message = typeof error === 'string' ? error : defaultMessage;
    return new MockApiError(message, 500, 'UNKNOWN_ERROR');
  });

  toJSON(): Record<string, any> {
    const json: Record<string, any> = {
      status: 'error',
      code: this.code,
      message: this.message
    };

    if (process.env.NODE_ENV === 'development' && this.context) {
      json.context = this.context;
    }

    return json;
  }

  isClientError(): boolean {
    return this.statusCode >= 400 && this.statusCode < 500;
  }

  isServerError(): boolean {
    return this.statusCode >= 500 && this.statusCode < 600;
  }

  isRetryable(): boolean {
    return this.statusCode >= 500 ||
           this.statusCode === 408 ||
           this.statusCode === 429;
  }

  getSeverity(): 'low' | 'medium' | 'high' | 'critical' {
    if (this.statusCode >= 500) return 'critical';
    if (this.statusCode === 429) return 'high';
    if (this.statusCode >= 400) return 'medium';
    return 'low';
  }
}

// Common error scenarios for testing
export const errorScenarios = {
  badRequest: {
    statusCode: 400,
    code: 'BAD_REQUEST',
    message: 'Bad request',
    type: 'validation'
  },
  unauthorized: {
    statusCode: 401,
    code: 'UNAUTHORIZED',
    message: 'Unauthorized',
    type: 'authentication'
  },
  forbidden: {
    statusCode: 403,
    code: 'FORBIDDEN',
    message: 'Forbidden',
    type: 'authorization'
  },
  notFound: {
    statusCode: 404,
    code: 'NOT_FOUND',
    message: 'Resource not found',
    type: 'notFound'
  },
  conflict: {
    statusCode: 409,
    code: 'CONFLICT',
    message: 'Conflict',
    type: 'conflict'
  },
  unprocessableEntity: {
    statusCode: 422,
    code: 'UNPROCESSABLE_ENTITY',
    message: 'Unprocessable Entity',
    type: 'unprocessableEntity'
  },
  tooManyRequests: {
    statusCode: 429,
    code: 'TOO_MANY_REQUESTS',
    message: 'Too many requests',
    type: 'rateLimited'
  },
  internalError: {
    statusCode: 500,
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
    type: 'internal'
  },
  serviceUnavailable: {
    statusCode: 503,
    code: 'SERVICE_UNAVAILABLE',
    message: 'Service unavailable',
    type: 'internal'
  }
} as const;

// Specific auth-related error scenarios
export const authErrorScenarios = {
  missingToken: {
    statusCode: 401,
    code: 'AUTHENTICATION_ERROR',
    message: 'Authentication token required',
    type: 'authentication'
  },
  invalidToken: {
    statusCode: 401,
    code: 'AUTHENTICATION_ERROR',
    message: 'Invalid authentication token',
    type: 'authentication'
  },
  expiredToken: {
    statusCode: 401,
    code: 'AUTHENTICATION_ERROR',
    message: 'Authentication token has expired',
    type: 'authentication'
  },
  userNotFound: {
    statusCode: 401,
    code: 'AUTHENTICATION_ERROR',
    message: 'User not found',
    type: 'authentication'
  },
  accessDenied: {
    statusCode: 403,
    code: 'AUTHORIZATION_ERROR',
    message: 'Access denied',
    type: 'authorization'
  },
  rateLimitExceeded: {
    statusCode: 429,
    code: 'RATE_LIMITED',
    message: 'Rate limit exceeded',
    type: 'rateLimited'
  }
} as const;

// Validation error scenarios
export const validationErrorScenarios = {
  missingField: {
    statusCode: 400,
    code: 'VALIDATION_ERROR',
    message: 'Required field is missing',
    type: 'validation'
  },
  invalidFormat: {
    statusCode: 400,
    code: 'VALIDATION_ERROR',
    message: 'Invalid format',
    type: 'validation'
  },
  invalidValue: {
    statusCode: 400,
    code: 'VALIDATION_ERROR',
    message: 'Invalid value',
    type: 'validation'
  },
  invalidUUID: {
    statusCode: 400,
    code: 'VALIDATION_ERROR',
    message: 'Invalid UUID format',
    type: 'validation'
  }
} as const;

// File operation error scenarios
export const fileErrorScenarios = {
  uploadFailed: {
    statusCode: 500,
    code: 'FILE_OPERATION_ERROR',
    message: 'File upload failed',
    type: 'internal'
  },
  deleteFailed: {
    statusCode: 500,
    code: 'FILE_OPERATION_ERROR',
    message: 'File deletion failed',
    type: 'internal'
  },
  readFailed: {
    statusCode: 500,
    code: 'FILE_OPERATION_ERROR',
    message: 'File read failed',
    type: 'internal'
  },
  writeFailed: {
    statusCode: 500,
    code: 'FILE_OPERATION_ERROR',
    message: 'File write failed',
    type: 'internal'
  }
} as const;

// Database error scenarios
export const databaseErrorScenarios = {
  connectionFailed: {
    statusCode: 500,
    code: 'DATABASE_ERROR',
    message: 'Database connection failed',
    type: 'internal'
  },
  queryFailed: {
    statusCode: 500,
    code: 'DATABASE_ERROR',
    message: 'Database query failed',
    type: 'internal'
  },
  transactionFailed: {
    statusCode: 500,
    code: 'DATABASE_ERROR',
    message: 'Database transaction failed',
    type: 'internal'
  },
  constraintViolation: {
    statusCode: 409,
    code: 'DATABASE_ERROR',
    message: 'Database constraint violation',
    type: 'conflict'
  }
} as const;

// Factory functions for creating mock errors
export const createMockApiError = (
  type: keyof typeof errorScenarios,
  overrides?: Partial<MockApiError>
): MockApiError => {
  const scenario = errorScenarios[type];
  const error = new MockApiError(
    scenario.message,
    scenario.statusCode,
    scenario.code
  );
  
  return Object.assign(error, overrides);
};

export const createMockAuthError = (
  type: keyof typeof authErrorScenarios,
  overrides?: Partial<MockApiError>
): MockApiError => {
  const scenario = authErrorScenarios[type];
  const error = new MockApiError(
    scenario.message,
    scenario.statusCode,
    scenario.code
  );
  
  return Object.assign(error, overrides);
};

export const createMockValidationError = (
  type: keyof typeof validationErrorScenarios,
  field?: string,
  value?: any,
  rule?: string
): MockApiError => {
  const scenario = validationErrorScenarios[type];
  return new MockApiError(
    scenario.message,
    scenario.statusCode,
    scenario.code,
    undefined,
    { field, value, rule }
  );
};

export const createMockFileError = (
  type: keyof typeof fileErrorScenarios,
  operation: 'upload' | 'delete' | 'read' | 'write',
  filename?: string,
  cause?: Error
): MockApiError => {
  const scenario = fileErrorScenarios[type];
  return new MockApiError(
    scenario.message,
    scenario.statusCode,
    scenario.code,
    cause,
    { operation, filename }
  );
};

export const createMockDatabaseError = (
  type: keyof typeof databaseErrorScenarios,
  operation: string,
  table?: string,
  cause?: Error
): MockApiError => {
  const scenario = databaseErrorScenarios[type];
  return new MockApiError(
    scenario.message,
    scenario.statusCode,
    scenario.code,
    cause,
    { operation, table }
  );
};

// Reset all mock functions
export const resetApiErrorMocks = (): void => {
  const mockMethods = [
    MockApiError.badRequest,
    MockApiError.unauthorized,
    MockApiError.forbidden,
    MockApiError.notFound,
    MockApiError.conflict,
    MockApiError.unprocessableEntity,
    MockApiError.tooManyRequests,
    MockApiError.internal,
    MockApiError.serviceUnavailable,
    MockApiError.custom,
    MockApiError.validation,
    MockApiError.database,
    MockApiError.fileOperation,
    MockApiError.authentication,
    MockApiError.authorization,
    MockApiError.rateLimited,
    MockApiError.businessLogic,
    MockApiError.externalService,
    MockApiError.fromUnknown
  ];

  mockMethods.forEach(method => {
    if (jest.isMockFunction(method)) {
      method.mockClear();
    }
  });
};

// Setup mock implementations for specific test scenarios
export const setupMockApiErrorImplementations = (): void => {
  // Setup default implementations that return proper MockApiError instances
  MockApiError.badRequest.mockImplementation((message, code, context) => 
    new MockApiError(message || 'Bad request', 400, code || 'BAD_REQUEST', undefined, context)
  );
  
  MockApiError.unauthorized.mockImplementation((message, code, context) => 
    new MockApiError(message || 'Unauthorized', 401, code || 'UNAUTHORIZED', undefined, context)
  );
  
  MockApiError.forbidden.mockImplementation((message, code, context) => 
    new MockApiError(message || 'Forbidden', 403, code || 'FORBIDDEN', undefined, context)
  );
  
  MockApiError.notFound.mockImplementation((message, code, context) => 
    new MockApiError(message || 'Resource not found', 404, code || 'NOT_FOUND', undefined, context)
  );
  
  MockApiError.internal.mockImplementation((message, code, cause, context) => 
    new MockApiError(message || 'Internal server error', 500, code || 'INTERNAL_ERROR', cause, context)
  );
  
  MockApiError.authentication.mockImplementation((message, reason) => 
    new MockApiError(message || 'Authentication failed', 401, 'AUTHENTICATION_ERROR', undefined, { reason })
  );
  
  MockApiError.authorization.mockImplementation((message, resource, action) => 
    new MockApiError(message || 'Access denied', 403, 'AUTHORIZATION_ERROR', undefined, { resource, action })
  );
  
  MockApiError.rateLimited.mockImplementation((message, limit, windowMs, retryAfter) => 
    new MockApiError(message || 'Rate limit exceeded', 429, 'RATE_LIMITED', undefined, { limit, windowMs, retryAfter })
  );
  
  MockApiError.validation.mockImplementation((message, field, value, rule) => 
    new MockApiError(message, 400, 'VALIDATION_ERROR', undefined, { 
      field, 
      value: typeof value === 'object' && value !== null ? '[object]' : value, 
      rule 
    })
  );
};