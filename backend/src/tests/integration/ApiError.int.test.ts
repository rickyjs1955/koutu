// filepath: /backend/src/tests/int/ApiError.int.test.ts
/**
 * @file ApiError.int.test.ts
 * @summary Integration tests for ApiError class with error handler
 * 
 * @description
 * This test suite verifies the integration between ApiError class and error handler middleware,
 * covering:
 * - Proper error response formatting for different error types
 * - Default values handling for missing parameters
 * - Error propagation in async contexts
 * - Chained error handling
 * - Compatibility with standard Error instances
 * - Custom error cases and error causes
 * 
 * The tests simulate how ApiError instances are processed by a typical error handling middleware.
 */

import { ApiError } from '../../utils/ApiError';

// #region Mock Definitions
/**
 * Mock response object to capture error handler output
 */
interface MockResponse {
  statusCode?: number;
  body?: any;
  headers?: Record<string, string>;
  send: (data: any) => void;
  status: (code: number) => MockResponse;
  json: (data: any) => MockResponse;
}

/**
 * Simulates error handler middleware processing
 * @param err Error instance to handle
 * @param res Mock response object
 */
const mockErrorHandler = (err: Error | ApiError, res: MockResponse) => {
  if (err instanceof ApiError) {
    res.status(err.statusCode).json(err.toJSON());
  } else {
    // Default handling for non-ApiError instances
    res.status(500).json({
      status: 'error',
      code: 'INTERNAL_ERROR',
      message: 'An unexpected internal server error occurred.',
    });
  }
};
// #endregion

// #region Test Suite
describe('ApiError Integration with Error Handler', () => {
  let mockResponse: MockResponse;

  beforeEach(() => {
    mockResponse = {
      send: jest.fn(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      headers: {},
    };
  });

  // #region Standard Error Cases
  test('should correctly process an ApiError.badRequest through the error handler', () => {
    const apiErr = ApiError.badRequest('Test bad request');
    mockErrorHandler(apiErr, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(400);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'BAD_REQUEST',
      message: 'Test bad request',
    });
  });

  test('should correctly process an ApiError.notFound through the error handler', () => {
    const apiErr = ApiError.notFound('Resource X not found');
    mockErrorHandler(apiErr, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(404);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'NOT_FOUND',
      message: 'Resource X not found',
    });
  });

  test('should correctly process an ApiError.internal with a cause through the error handler', () => {
    const causeError = new Error('Database connection failed');
    const apiErr = ApiError.internal('Internal system failure', 'SYS_FAILURE', causeError);
    mockErrorHandler(apiErr, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(500);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'SYS_FAILURE',
      message: 'Internal system failure',
    });
  });

  test('should correctly process a custom ApiError through the error handler', () => {
    const apiErr = ApiError.custom('A very custom error', 418, 'TEAPOT_EMPTY');
    mockErrorHandler(apiErr, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(418);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'TEAPOT_EMPTY',
      message: 'A very custom error',
    });
  });
  // #endregion

  // #region Edge Cases
  test('should handle a standard Error instance by defaulting to 500', () => {
    const standardError = new Error('A generic error occurred');
    mockErrorHandler(standardError, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(500);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'INTERNAL_ERROR',
      message: 'An unexpected internal server error occurred.',
    });
  });

  test('should handle ApiError with default message and code if not provided', () => {
    const apiErr = ApiError.unauthorized(); // Uses default message and code
    mockErrorHandler(apiErr, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'UNAUTHORIZED',
      message: 'Unauthorized',
    });
  });
  // #endregion

  // #region Null/Empty Handling
  test('should handle ApiError.badRequest with null message, defaulting appropriately', () => {
    const apiErr = ApiError.badRequest(null);
    mockErrorHandler(apiErr, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(400);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'BAD_REQUEST',
      message: 'Bad request', // Default message
    });
  });

  test('should handle ApiError.badRequest with empty string code, defaulting appropriately', () => {
    const apiErr = ApiError.badRequest("Message", "");
    mockErrorHandler(apiErr, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(400);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'BAD_REQUEST', // Default code
      message: 'Message',
    });
  });
  // #endregion

  // #region Advanced Scenarios
  test('should handle asynchronous ApiError thrown in async context', async () => {
    const asyncFunction = async () => {
      throw ApiError.forbidden('Async forbidden error');
    };

    await expect(asyncFunction()).rejects.toThrow(ApiError);

    try {
      await asyncFunction();
    } catch (err) {
      mockErrorHandler(err as ApiError, mockResponse);
      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'error',
        code: 'FORBIDDEN',
        message: 'Async forbidden error'
      });
    }
  });

  test('should handle chained ApiErrors', () => {
    const innerError = ApiError.unauthorized('Inner unauthorized error');
    const chainedError = ApiError.internal('Chained error', 'CHAINED_INTERNAL', innerError);
    mockErrorHandler(chainedError, mockResponse);

    expect(mockResponse.status).toHaveBeenCalledWith(500);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'error',
      code: 'CHAINED_INTERNAL',
      message: 'Chained error'
    });
  });
  // #endregion
});
// #endregion