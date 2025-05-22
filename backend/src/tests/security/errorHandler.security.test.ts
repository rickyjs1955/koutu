/**
 * @file errorHandler.security.test.ts
 * @summary Security-focused test suite for the errorHandler middleware.
 * 
 * @description
 * This test suite verifies the security aspects of the errorHandler middleware, ensuring:
 * - Sensitive information is not leaked in production environments
 * - Error responses are properly sanitized
 * - Error handling is robust against malformed inputs
 * - Secure logging practices are followed
 * 
 * The tests cover environment-specific behaviors, input validation, error code formatting,
 * and protection against information disclosure through error messages.
 */

import { errorHandler, AppError } from '../../middlewares/errorHandler';
import { Request, Response, NextFunction } from 'express';

// #region Test Setup
describe('errorHandler Middleware - Security Tests', () => {
  let req: Request;
  let res: Response;
  let next: NextFunction;
  let consoleErrorSpy: jest.SpyInstance;

  beforeEach(() => {
    req = {} as Request;
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    } as unknown as Response;
    next = jest.fn();
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.clearAllMocks();
    consoleErrorSpy.mockRestore();
  });
// #endregion

// #region Environment-Specific Behavior
  it('should not include stack trace in production environment', () => {
    process.env.NODE_ENV = 'production';
    const error: AppError = {
      name: 'Error',
      message: 'Test error',
      statusCode: 500,
      code: 'TEST_ERROR',
    };

    errorHandler(error, req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith(
      expect.not.objectContaining({ stack: expect.any(String) })
    );
  });

  it('should include stack trace in development environment', () => {
    process.env.NODE_ENV = 'development';
    const error: AppError = {
      name: 'Error',
      message: 'Test error',
      statusCode: 500,
      code: 'TEST_ERROR',
      stack: 'Error stack trace',
    };

    errorHandler(error, req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ stack: 'Error stack trace' })
    );
  });
// #endregion

// #region Information Disclosure Protection
  it('should not expose sensitive server details in error response', () => {
    const error: AppError = {
      name: 'Error',
      message: 'Sensitive error',
      statusCode: 500,
      code: 'SENSITIVE_ERROR',
    };

    errorHandler(error, req, res, next);

    expect(res.json).not.toHaveBeenCalledWith(
      expect.objectContaining({ sensitiveData: expect.anything() })
    );
  });

  it('should log errors securely without sensitive data', () => {
    const error: AppError = {
      name: 'Error',
      message: 'Sensitive error',
      statusCode: 500,
      code: 'SENSITIVE_ERROR',
      stack: 'Sensitive stack trace',
    };

    errorHandler(error, req, res, next);

    expect(consoleErrorSpy).toHaveBeenCalledWith(
      expect.stringContaining('Error [SENSITIVE_ERROR]: Sensitive error')
    );
    expect(consoleErrorSpy).not.toHaveBeenCalledWith(
      expect.stringContaining('Sensitive stack trace')
    );
  });
// #endregion

// #region Input Validation and Sanitization
  it('should validate error code format', () => {
    const error: AppError = {
      name: 'Error',
      message: 'Invalid error code',
      statusCode: 400,
      code: 'invalid_code',
    };

    errorHandler(error, req, res, next);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        code: 'invalid_code',
      })
    );
  });

  it('should enforce error code format and sanitize invalid codes', () => {
    const error: AppError = {
      name: 'Error',
      message: 'Test error',
      statusCode: 400,
      code: 'invalid-code-format@123'
    };

    errorHandler(error, req, res, next);

    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        code: expect.stringMatching(/^[A-Z_]+$/)
      })
    );
  });

  it('should handle excessively large error messages securely', () => {
    const largeMsgSize = 1024 * 1024 + 1; // 1MB + 1 byte
    const error: AppError = {
      name: 'Error',
      message: 'x'.repeat(largeMsgSize),
      statusCode: 500,
      code: 'LARGE_MESSAGE_ERROR'
    };

    errorHandler(error, req, res, next);

    const responseJson = (res.json as jest.Mock).mock.calls[0][0];
    expect(responseJson.message.length).toBeLessThan(largeMsgSize);
    expect(res.status).toHaveBeenCalledWith(500);
  });
// #endregion

// #region Error Handling Robustness
  it('should handle non-error inputs gracefully', () => {
    const nonErrorInput = 'This is not an error';

    errorHandler(nonErrorInput as unknown as Error, req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        code: 'INTERNAL_ERROR',
        message: 'Internal Server Error',
      })
    );
  });

  it('should handle null or undefined error objects securely', () => {
    errorHandler(null, req, res, next);

    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        code: 'INTERNAL_ERROR',
        message: 'Internal Server Error',
      })
    );
  });

  it('should handle invalid status codes by defaulting to 500', () => {
    const invalidStatusCases = [
      { statusCode: -1 },
      { statusCode: 'invalid' as any },
      { statusCode: 1000 },
      { statusCode: undefined },
      {}  // missing statusCode
    ];

    invalidStatusCases.forEach(statusCase => {
      const error: AppError = {
        name: 'Error',
        message: 'Test error',
        ...statusCase,
        code: 'TEST_ERROR'
      };

      errorHandler(error, req, res, next);

      expect(res.status).toHaveBeenCalledWith(500);
    });
  });
// #endregion
});