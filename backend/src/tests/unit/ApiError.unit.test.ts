// backend/src/utils/ApiError.test.ts
import { ApiError } from '../../utils/ApiError';

/**
 * ApiError Unit Test Suite
 * --------------------------
 * This suite tests the functionality of the ApiError class, a custom error type designed
 * to standardize error handling in the API by providing HTTP status codes, error codes, and messages.
 *
 * Testing Approach:
 * - Black Box Testing: Each test validates the inputs and expected outputs without exposing internal implementation details.
 * 
 * Key Focus Areas:
 * 1. Error Creation Tests:
 *    - Verify that each static factory method (e.g., badRequest, unauthorized, forbidden, etc.) creates an instance of ApiError
 *      with the correct status code, error code, and message.
 * 2. Default Values:
 *    - Confirm that default messages and error codes are set when no parameters are provided.
 * 3. Customization:
 *    - Ensure that providing custom messages and error codes overrides the defaults as expected.
 * 4. Standard Error Behavior:
 *    - Check that the created errors are instances of both Error and ApiError.
 *    - Validate that typical Error properties, such as the stack trace and name, are present and accurate.
 * 5. JSON Serialization:
 *    - Test the toJSON() method to ensure it returns an object with the proper structure: { status, code, message }.
 *
 * The suite covers all modes of error generation provided by the ApiError class:
 * - BadRequest (400)
 * - Unauthorized (401)
 * - Forbidden (403)
 * - NotFound (404)
 * - Conflict (409)
 * - Internal (500)
 * - Unprocessable Entity (422)
 * - Too Many Requests (429)
 * - Service Unavailable (503)
 * - Custom Errors (custom status code and message)
 */

describe('ApiError', () => {
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

  test('should convert error to JSON response', () => {
    const error = ApiError.badRequest('Bad request');
    const jsonResponse = error.toJSON();
    
    expect(jsonResponse).toEqual({
      status: 'error',
      code: 'BAD_REQUEST',
      message: 'Bad request'
    });
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
    // This is already partially covered by 'should behave like a standard Error'
    // but explicitly checking message and code for the default case is good.
    expect(error.statusCode).toBe(500);
    expect(error.message).toBe('Internal server error');
    expect(error.code).toBe('INTERNAL_ERROR');
  });
});