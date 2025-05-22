// /backend/src/utils/ApiError.ts

/**
 * Custom error class for API errors
 * Includes status code and error code for better error handling
 */
export class ApiError extends Error {
  statusCode: number;
  code: string;
  cause?: Error;
  
  constructor(message: string, statusCode: number, code: string, cause?: Error) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.cause = cause;
    
    // Set the prototype explicitly.
    // See: https://github.com/Microsoft/TypeScript/wiki/Breaking-Changes#extending-built-ins-like-error-array-and-map-may-no-longer-work
    Object.setPrototypeOf(this, ApiError.prototype);
    
    // Maintains proper stack trace for where our error was thrown
    Error.captureStackTrace(this, this.constructor);
  }
  
  /**
   * Create a 400 Bad Request error
   */
  static badRequest(message: string | null | undefined = 'Bad request', code = 'BAD_REQUEST'): ApiError {
    if (message === null || message === undefined) {
      message = 'Bad request';
    }
    if (code === '') {
      code = 'BAD_REQUEST';
    }
    return new ApiError(message, 400, code);
  }
  
  /**
   * Create a 401 Unauthorized error
   */
  static unauthorized(message = 'Unauthorized', code = 'UNAUTHORIZED'): ApiError {
    if (code === '') {
      code = 'UNAUTHORIZED';
    }
    return new ApiError(message, 401, code);
  }
  
  /**
   * Create a 403 Forbidden error
   */
  static forbidden(message = 'Forbidden', code = 'FORBIDDEN'): ApiError {
    if (code === '') {
      code = 'FORBIDDEN';
    }
    return new ApiError(message, 403, code);
  }
  
  /**
   * Create a 404 Not Found error
   */
  static notFound(message = 'Resource not found', code = 'NOT_FOUND'): ApiError {
    if (code === '') {
      code = 'NOT_FOUND';
    }
    return new ApiError(message, 404, code);
  }
  
  /**
   * Create a 409 Conflict error
   */
  static conflict(message = 'Conflict', code = 'CONFLICT'): ApiError {
    if (code === '') {
      code = 'CONFLICT';
    }
    return new ApiError(message, 409, code);
  }
  
  /**
   * Create a 422 Unprocessable Entity error
   */
  static unprocessableEntity(message = 'Unprocessable Entity', code = 'UNPROCESSABLE_ENTITY'): ApiError {
    if (code === '') {
      code = 'UNPROCESSABLE_ENTITY';
    }
    return new ApiError(message, 422, code);
  }
  
  /**
   * Create a 429 Too Many Requests error
   */
  static tooManyRequests(message = 'Too many requests', code = 'TOO_MANY_REQUESTS'): ApiError {
    if (code === '') {
      code = 'TOO_MANY_REQUESTS';
    }
    return new ApiError(message, 429, code);
  }
  
  /**
   * Create a 500 Internal Server Error
   */
  static internal(message = 'Internal server error', code = 'INTERNAL_ERROR', cause?: Error): ApiError {
    if (code === '') {
      code = 'INTERNAL_ERROR';
    }
    return new ApiError(message, 500, code, cause);
  }
  
  /**
   * Create a 503 Service Unavailable error
   */
  static serviceUnavailable(message = 'Service unavailable', code = 'SERVICE_UNAVAILABLE'): ApiError {
    if (code === '') {
      code = 'SERVICE_UNAVAILABLE';
    }
    return new ApiError(message, 503, code);
  }
  
  /**
   * Create a generic API error with custom status code
   */
  static custom(message: string, statusCode: number, code: string, cause?: Error): ApiError {
    return new ApiError(message, statusCode, code, cause);
  }
  
  /**
   * Convert error to JSON response
   */
  toJSON() {
    return {
      status: 'error',
      code: this.code,
      message: this.message
    };
  }
}