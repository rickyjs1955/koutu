// filepath: /backend/src/tests/unit/ApiError.unit.test.ts

/**
 * ApiError Unit Test Suite
 * --------------------------
 * This suite tests the functionality of the ApiError class, a custom error type designed
 * to standardize error handling in the API by providing HTTP status codes, error codes, and messages.
 * 
 * Coverage includes:
 * - Static factory methods for all major HTTP error types
 * - Default value handling for messages and codes
 * - Customization and error chaining
 * - Standard Error behavior and serialization
 */

import { ApiError } from '../../utils/ApiError';

// #region Error Creation Tests
describe('ApiError - Static Factory Methods', () => {
  test('should create a BadRequest error', () => {
    const error = ApiError.badRequest('Bad request error');
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(ApiError);
    expect(error.statusCode).toBe(400);
    expect(error.code).toBe('BAD_REQUEST');
    expect(error.message).toBe('Bad request error');
  });

  test('should create an Unauthorized error', () => {
    const error = ApiError.unauthorized('Unauthorized error');
    expect(error.statusCode).toBe(401);
    expect(error.code).toBe('UNAUTHORIZED');
    expect(error.message).toBe('Unauthorized error');
  });

  test('should create a Forbidden error', () => {
    const error = ApiError.forbidden('Forbidden error');
    expect(error.statusCode).toBe(403);
    expect(error.code).toBe('FORBIDDEN');
    expect(error.message).toBe('Forbidden error');
  });

  test('should create a NotFound error', () => {
    const error = ApiError.notFound('Resource not found');
    expect(error.statusCode).toBe(404);
    expect(error.code).toBe('NOT_FOUND');
    expect(error.message).toBe('Resource not found');
  });

  test('should create a Conflict error', () => {
    const error = ApiError.conflict('Resource already exists');
    expect(error.statusCode).toBe(409);
    expect(error.code).toBe('CONFLICT');
    expect(error.message).toBe('Resource already exists');
  });

  test('should create an Internal error', () => {
    const error = ApiError.internal('Internal server error');
    expect(error.statusCode).toBe(500);
    expect(error.code).toBe('INTERNAL_ERROR');
    expect(error.message).toBe('Internal server error');
  });

  test('should create an Unprocessable Entity error', () => {
    const error = ApiError.unprocessableEntity('Invalid data format');
    expect(error.statusCode).toBe(422);
    expect(error.code).toBe('UNPROCESSABLE_ENTITY');
    expect(error.message).toBe('Invalid data format');
  });

  test('should create a Too Many Requests error', () => {
    const error = ApiError.tooManyRequests();
    expect(error.statusCode).toBe(429);
    expect(error.code).toBe('TOO_MANY_REQUESTS');
    expect(error.message).toBe('Too many requests');
  });

  test('should create a Service Unavailable error', () => {
    const error = ApiError.serviceUnavailable();
    expect(error.statusCode).toBe(503);
    expect(error.code).toBe('SERVICE_UNAVAILABLE');
    expect(error.message).toBe('Service unavailable');
  });

  test('should create a custom error with specified status code and code', () => {
    const error = ApiError.custom('Custom error message', 418, 'IM_A_TEAPOT');
    expect(error.statusCode).toBe(418);
    expect(error.code).toBe('IM_A_TEAPOT');
    expect(error.message).toBe('Custom error message');
  });
});
// #endregion

// #region Default Values & Customization
describe('ApiError - Default Values & Customization', () => {
  test('should allow custom error codes', () => {
    const error = ApiError.badRequest('Invalid input', 'INVALID_INPUT');
    expect(error.statusCode).toBe(400);
    expect(error.code).toBe('INVALID_INPUT');
    expect(error.message).toBe('Invalid input');
  });

  test('should use default message when none provided', () => {
    const error = ApiError.unauthorized();
    expect(error.statusCode).toBe(401);
    expect(error.message).toBe('Unauthorized');
  });

  test('should use default message for forbidden error when none provided', () => {
    const error = ApiError.forbidden();
    expect(error.statusCode).toBe(403);
    expect(error.message).toBe('Forbidden');
    expect(error.code).toBe('FORBIDDEN');
  });

  test('should use default message for notFound error when none provided', () => {
    const error = ApiError.notFound();
    expect(error.statusCode).toBe(404);
    expect(error.message).toBe('Resource not found');
    expect(error.code).toBe('NOT_FOUND');
  });

  test('should use default message for internal error when none provided', () => {
    const error = ApiError.internal();
    expect(error.statusCode).toBe(500);
    expect(error.message).toBe('Internal server error');
    expect(error.code).toBe('INTERNAL_ERROR');
  });

  test('should use default message for conflict error when none provided', () => {
    const error = ApiError.conflict();
    expect(error.statusCode).toBe(409);
    expect(error.message).toBe('Conflict');
    expect(error.code).toBe('CONFLICT');
  });

  test('should use default message for unprocessableEntity when none provided', () => {
    const error = ApiError.unprocessableEntity();
    expect(error.statusCode).toBe(422);
    expect(error.message).toBe('Unprocessable Entity');
    expect(error.code).toBe('UNPROCESSABLE_ENTITY');
  });

  test('should use default error code when provided code is empty string', () => {
    const error = ApiError.badRequest('Bad request', '');
    expect(error.code).toBe('BAD_REQUEST');
  });

  test('should handle null or undefined messages', () => {
    const error1 = ApiError.badRequest(null as any);
    const error2 = ApiError.badRequest(undefined as any);
    expect(error1.message).toBe('Bad request');
    expect(error2.message).toBe('Bad request');
  });

  test('should handle empty string messages', () => {
    const error = ApiError.badRequest('');
    expect(error.message).toBe('');
  });
});
// #endregion

// #region Standard Error Behavior & Serialization
describe('ApiError - Standard Error Behavior & Serialization', () => {
  test('should behave like a standard Error', () => {
    const error = ApiError.internal();
    expect(error instanceof Error).toBe(true);
    expect(error.stack).toBeDefined();
    expect(typeof error.stack).toBe('string');
  });

  test('should preserve the error name property', () => {
    const error = ApiError.badRequest('Bad data');
    expect(error.name).toBe('Error');
  });

  test('should throw and be catchable like standard errors', () => {
    const throwError = () => {
      throw ApiError.badRequest('Bad data');
    };
    expect(throwError).toThrow();
    expect(throwError).toThrow(Error);
    expect(throwError).toThrow(ApiError);
    expect(throwError).toThrow('Bad data');
    try {
      throwError();
    } catch (error) {
      expect(error instanceof ApiError).toBe(true);
      if (error instanceof ApiError) {
        expect(error.statusCode).toBe(400);
      } else {
        // This path should not be taken if the first expect passes.
        fail('Expected error to be an instance of ApiError');
      }
    }
  });

  test('should handle error with additional properties', () => {
    const error = ApiError.badRequest('Bad request');
    (error as any).details = { field: 'email', issue: 'invalid format' };
    expect((error as any).details).toEqual({ field: 'email', issue: 'invalid format' });
    expect(error.toJSON()).toEqual({
      status: 'error',
      code: 'BAD_REQUEST',
      message: 'Bad request'
    });
  });

  test('should convert error to JSON response', () => {
    const error = ApiError.badRequest('Bad request');
    const jsonResponse = error.toJSON();

    expect(jsonResponse).toEqual({
      status: 'error',
      code: 'BAD_REQUEST',
      message: 'Bad request'
    });
  });

  test('should have consistent status and code across serialization', () => {
    const error = ApiError.notFound('User not found');
    const json = error.toJSON();
    expect(json.code).toBe(error.code);
    expect(json.message).toBe(error.message);
    expect(json.status).toBe('error');
  });

  test('should create multiple instances with different properties', () => {
    const error1 = ApiError.badRequest('First error');
    const error2 = ApiError.badRequest('Second error');
    expect(error1.message).not.toBe(error2.message);
    expect(error1).not.toBe(error2);
  });

  test('should support error chaining with cause property', () => {
    const originalError = new Error('Original error');
    const error = ApiError.internal('Something went wrong', 'INTERNAL_ERROR', originalError);
    expect(error.cause).toBe(originalError);
  });
});
// #endregion