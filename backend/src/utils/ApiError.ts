// /backend/src/utils/ApiError.ts

/**
 * Custom error class for API errors
 * Includes status code and error code for better error handling
 */
export class ApiError extends Error {
  statusCode: number;
  code: string;
  
  constructor(message: string, statusCode: number, code: string) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    
    // Set the prototype explicitly.
    // See: https://github.com/Microsoft/TypeScript/wiki/Breaking-Changes#extending-built-ins-like-error-array-and-map-may-no-longer-work
    Object.setPrototypeOf(this, ApiError.prototype);
    
    // Maintains proper stack trace for where our error was thrown
    Error.captureStackTrace(this, this.constructor);
  }
  
  /**
   * Create a 400 Bad Request error
   */
  static badRequest(message: string, code = 'BAD_REQUEST'): ApiError {
    return new ApiError(message, 400, code);
  }
  
  /**
   * Create a 401 Unauthorized error
   */
  static unauthorized(message = 'Unauthorized', code = 'UNAUTHORIZED'): ApiError {
    return new ApiError(message, 401, code);
  }
  
  /**
   * Create a 403 Forbidden error
   */
  static forbidden(message = 'Forbidden', code = 'FORBIDDEN'): ApiError {
    return new ApiError(message, 403, code);
  }
  
  /**
   * Create a 404 Not Found error
   */
  static notFound(message = 'Resource not found', code = 'NOT_FOUND'): ApiError {
    return new ApiError(message, 404, code);
  }
  
  /**
   * Create a 409 Conflict error
   */
  static conflict(message: string, code = 'CONFLICT'): ApiError {
    return new ApiError(message, 409, code);
  }
  
  /**
   * Create a 422 Unprocessable Entity error
   */
  static unprocessableEntity(message: string, code = 'UNPROCESSABLE_ENTITY'): ApiError {
    return new ApiError(message, 422, code);
  }
  
  /**
   * Create a 429 Too Many Requests error
   */
  static tooManyRequests(message = 'Too many requests', code = 'TOO_MANY_REQUESTS'): ApiError {
    return new ApiError(message, 429, code);
  }
  
  /**
   * Create a 500 Internal Server Error
   */
  static internal(message = 'Internal server error', code = 'INTERNAL_ERROR'): ApiError {
    return new ApiError(message, 500, code);
  }
  
  /**
   * Create a 503 Service Unavailable error
   */
  static serviceUnavailable(message = 'Service unavailable', code = 'SERVICE_UNAVAILABLE'): ApiError {
    return new ApiError(message, 503, code);
  }
  
  /**
   * Create a generic API error with custom status code
   */
  static custom(message: string, statusCode: number, code: string): ApiError {
    return new ApiError(message, statusCode, code);
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