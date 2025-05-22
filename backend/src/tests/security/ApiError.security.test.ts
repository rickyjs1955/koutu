// filepath: c:\Users\monmo\koutu\backend\src\tests\security\ApiError.security.test.ts
/**
 * @file ApiError.security.test.ts
 * @summary Security tests for the ApiError class
 * 
 * @description
 * This test suite focuses on security aspects of the ApiError class, specifically:
 * - Prevention of sensitive information leakage in serialized output
 * - Handling of potentially malicious inputs (injection attempts, oversized data)
 * - Safe serialization behavior with problematic error causes
 * - Validation that stack traces and internal details aren't exposed
 * 
 * The tests verify that the ApiError class maintains proper security boundaries
 * when handling error information that might contain sensitive data.
 */

import { ApiError } from '../../utils/ApiError';

describe('ApiError Security Tests', () => {
  // #region Sensitive Information Leakage
  test('toJSON should not expose the cause property', () => {
    const causeError = new Error('Sensitive database error');
    const apiError = ApiError.internal('Internal server error', 'INTERNAL_ERROR', causeError);

    const jsonOutput = apiError.toJSON();
    expect(jsonOutput).not.toHaveProperty('cause');
    expect(jsonOutput).toEqual({
      status: 'error',
      code: 'INTERNAL_ERROR',
      message: 'Internal server error',
    });
  });
  // #endregion

  // #region Malicious Input Handling
  test('should handle long strings gracefully', () => {
    const longMessage = 'A'.repeat(10000); // 10,000 characters
    const apiError = ApiError.badRequest(longMessage);

    expect(apiError.message).toBe(longMessage);
    expect(apiError.toJSON()).toEqual({
      status: 'error',
      code: 'BAD_REQUEST',
      message: longMessage,
    });
  });

  test('should handle special characters in message and code', () => {
    // Testing with typical XSS payload
    const specialMessage = '<script>alert("XSS")</script>';
    const specialCode = 'BAD_REQUEST<script>';
    const apiError = ApiError.badRequest(specialMessage, specialCode);

    expect(apiError.message).toBe(specialMessage);
    expect(apiError.code).toBe(specialCode);
    expect(apiError.toJSON()).toEqual({
      status: 'error',
      code: specialCode,
      message: specialMessage,
    });
  });
  // #endregion

  // #region Error Serialization Security
  test('should not allow error serialization to expose stack traces', () => {
    const apiError = ApiError.internal('Internal server error');
    const jsonOutput = JSON.stringify(apiError);

    // Ensure internal details aren't leaked during JSON serialization
    expect(jsonOutput).not.toContain('stack');
    expect(jsonOutput).toContain('"status":"error"');
    expect(jsonOutput).toContain('"code":"INTERNAL_ERROR"');
    expect(jsonOutput).toContain('"message":"Internal server error"');
  });
  // #endregion

  // #region Cause Property Security
  test('should handle undefined cause property securely', () => {
    const apiError = ApiError.internal('Internal server error', 'INTERNAL_ERROR');
    expect(apiError.cause).toBeUndefined();

    const jsonOutput = apiError.toJSON();
    expect(jsonOutput).not.toHaveProperty('cause');
  });

  test('should handle circular references in cause property gracefully', () => {
    // Creating a circular reference which could potentially cause serialization issues
    const circularError: any = new Error('Circular reference');
    circularError.cause = circularError; // Create circular reference

    const apiError = ApiError.internal('Internal server error', 'INTERNAL_ERROR', circularError);
    expect(() => apiError.toJSON()).not.toThrow();
    expect(apiError.toJSON()).toEqual({
      status: 'error',
      code: 'INTERNAL_ERROR',
      message: 'Internal server error',
    });
  });
  // #endregion
});