/**
 * @summary Unit test suite for the errorHandler middleware.
 * @description This suite tests the behavior of the errorHandler middleware under various scenarios,
 * including handling of default values, custom error properties, environment-based stack traces,
 * and edge cases such as null, undefined, or plain JavaScript Error objects.
 */

import { Request, Response, NextFunction } from 'express';
import { errorHandler, AppError } from '../../middlewares/errorHandler';
import { mockRequest, mockResponse, mockNext } from '../../tests/__helpers__/errorHandler.helper';
import { createMockError } from '../../tests/__mocks__/errorHandler.mock';

describe('errorHandler Middleware', () => {
    let req: Request;
    let res: Response;
    let next: NextFunction;
    let consoleErrorSpy: jest.SpyInstance;

    beforeEach(() => {
        req = mockRequest;
        res = mockResponse();
        next = mockNext;
        consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    afterEach(() => {
        consoleErrorSpy.mockRestore();
        jest.clearAllMocks();
    });

    // #region Default Behavior Tests
    it('should handle errors with default values if not provided', () => {
        const err = new Error('Test error') as AppError;
        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Test error', // Error.message is used if err.message is not set on AppError
            stack: undefined, // Assuming NODE_ENV is not 'development' by default for tests
        });
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: Test error');
    });

    it('should use statusCode, message, and code from the error object', () => {
        const err = createMockError({
            statusCode: 404,
            message: 'Not Found',
            code: 'NOT_FOUND',
        }) as AppError;
        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(404);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            status: 'error',
            code: 'NOT_FOUND',
            message: 'Not Found',
        }));
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [NOT_FOUND]: Not Found');
    });
    // #endregion

    // #region Environment-Specific Behavior Tests
    it('should include stack trace in development environment', () => {
        process.env.NODE_ENV = 'development';
        const err = createMockError({
            message: 'Dev error',
            stack: 'Error: Dev error at test.js:1:1',
        }) as AppError;
        errorHandler(err, req, res, next);

        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            stack: 'Error: Dev error at test.js:1:1',
        }));
        process.env.NODE_ENV = 'test'; // Reset NODE_ENV
    });

    it('should not include stack trace in non-development environment', () => {
        process.env.NODE_ENV = 'production';
        const err = createMockError({
            message: 'Prod error',
            stack: 'Error: Prod error at test.js:1:1',
        }) as AppError;
        errorHandler(err, req, res, next);

        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            stack: undefined,
        }));
        process.env.NODE_ENV = 'test'; // Reset NODE_ENV
    });
    // #endregion

    // #region Partial Error Object Tests
    it('should handle an error with only a message', () => {
        const err = { message: 'Just a message' } as AppError;
        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Just a message',
            stack: undefined,
        });
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: Just a message');
    });

    it('should handle an error with only a statusCode', () => {
        const err = { statusCode: 403 } as AppError;
        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalledWith({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Internal Server Error',
            stack: undefined,
        });
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: Internal Server Error');
    });

    it('should handle an error with only a code', () => {
        const err = { code: 'CUSTOM_CODE' } as AppError;
        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({
            status: 'error',
            code: 'CUSTOM_CODE',
            message: 'Internal Server Error',
            stack: undefined,
        });
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [CUSTOM_CODE]: Internal Server Error');
    });

    it('should use err.message if err.message is an empty string', () => {
        const err = { message: '' } as AppError;
        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            message: '', // Explicitly testing empty string behavior
        }));
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: ');
    });
    // #endregion

    // #region Edge Case Tests
    it('should handle plain JavaScript Error objects', () => {
        const err = new Error('Plain error');
        errorHandler(err, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Plain error',
            stack: undefined,
        });
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: Plain error');
    });

    it('should handle null or undefined error objects', () => {
        errorHandler(null as any, req, res, next);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Internal Server Error',
            stack: undefined,
        });
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: Internal Server Error');
    });
    // #endregion
});