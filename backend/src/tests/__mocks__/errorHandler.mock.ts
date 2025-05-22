// filepath: c:\Users\monmo\koutu\backend\src\tests\__mocks__\errorHandler.mock.ts
// This file contains mock implementations related to the error handling functionality.

export const mockError = {
  statusCode: 400,
  message: 'Bad Request',
  code: 'BAD_REQUEST',
  stack: 'Error: Bad Request at Object.<anonymous> (path/to/file.js:10:5)',
};

export const createMockError = (overrides = {}) => {
  return {
    statusCode: 500,
    message: 'Internal Server Error',
    code: 'INTERNAL_ERROR',
    stack: 'Error: Internal Server Error at Object.<anonymous> (path/to/file.js:10:5)',
    ...overrides,
  };
};