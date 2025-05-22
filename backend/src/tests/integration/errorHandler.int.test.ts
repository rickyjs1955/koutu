// filepath: /backend/src/tests/int/errorHandler.int.test.ts

import express, { Request, Response, NextFunction } from 'express';
import supertest from 'supertest';
import { errorHandler, AppError } from '../../middlewares/errorHandler';
import { createError } from '../__helpers__/errorHandler.helper';

/**
 * @summary Integration tests for the errorHandler middleware.
 * @description This test suite verifies the behavior of the errorHandler middleware in an Express application.
 * It covers various scenarios, including handling custom AppError objects, standard Error objects, null/undefined errors,
 * non-Error object types, empty error messages, and concurrent error handling. The suite also tests environment-specific
 * behavior (e.g., stack traces in development vs production) and ensures proper logging of errors.
 */

describe('Error Handler Integration Tests', () => {
    let app: express.Application;
    let server: any;
    const originalNodeEnv = process.env.NODE_ENV;
    let consoleErrorSpy: jest.SpyInstance;

    // #region Setup and Teardown
    beforeAll(() => {
        // Spy on console.error to verify logging behavior
        consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    beforeEach(() => {
        // Create a fresh Express app for each test
        app = express();

        // Define routes for various error scenarios
        app.get('/custom-error', (req: Request, res: Response, next: NextFunction) => {
            const error = createError('Custom error message', 400, 'CUSTOM_ERROR');
            next(error);
        });

        app.get('/standard-error', (req: Request, res: Response, next: NextFunction) => {
            next(new Error('Standard error message'));
        });

        app.get('/null-error', (req: Request, res: Response) => {
            errorHandler(null, req, res, {} as NextFunction);
        });

        app.get('/undefined-error', (req: Request, res: Response) => {
            errorHandler(undefined, req, res, {} as NextFunction);
        });

        app.get('/empty-message', (req: Request, res: Response, next: NextFunction) => {
            const err = new Error('') as AppError;
            next(err);
        });

        app.get('/invalid-error', (req: Request, res: Response, next: NextFunction) => {
            next({ message: 'Invalid object' }); // Pass plain object to next()
        });

        // Add error handler middleware
        app.use(errorHandler as express.ErrorRequestHandler);
    });

    afterEach(() => {
        // Close the server and clear mocks after each test
        if (server) {
            server.close();
        }
        jest.clearAllMocks();
    });

    afterAll(() => {
        // Restore the original NODE_ENV and console.error
        process.env.NODE_ENV = originalNodeEnv;
        consoleErrorSpy.mockRestore();
    });
    // #endregion

    // #region Tests for Specific Error Scenarios
    it('should return correct status code and error details for custom AppError', async () => {
        const response = await supertest(app).get('/custom-error');

        expect(response.status).toBe(400);
        expect(response.body).toEqual({
            status: 'error',
            code: 'CUSTOM_ERROR',
            message: 'Custom error message',
            stack: process.env.NODE_ENV === 'development' ? expect.any(String) : undefined,
        });
    });

    it('should handle standard Error objects with default status code and error code', async () => {
        const response = await supertest(app).get('/standard-error');

        expect(response.status).toBe(500);
        expect(response.body).toEqual({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Standard error message',
            stack: process.env.NODE_ENV === 'development' ? expect.any(String) : undefined,
        });
    });

    it('should handle null errors with 500 status and default message', async () => {
        const response = await supertest(app).get('/null-error');

        expect(response.status).toBe(500);
        expect(response.body).toEqual({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Internal Server Error',
            stack: process.env.NODE_ENV === 'development' ? undefined : undefined,
        });
    });

    it('should handle undefined errors with 500 status and default message', async () => {
        const response = await supertest(app).get('/undefined-error');

        expect(response.status).toBe(500);
        expect(response.body).toEqual({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Internal Server Error',
            stack: process.env.NODE_ENV === 'development' ? undefined : undefined,
        });
    });

    it('should handle errors with empty message strings', async () => {
        const response = await supertest(app).get('/empty-message');

        expect(response.status).toBe(500);
        expect(response.body).toEqual({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: '',
            stack: process.env.NODE_ENV === 'development' ? expect.any(String) : undefined,
        });
    });

    it('should handle non-Error object types', async () => {
        const response = await supertest(app).get('/invalid-error');

        expect(response.status).toBe(500);
        expect(response.body).toEqual({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Invalid object', // Matches the behavior of errorHandler
            stack: process.env.NODE_ENV === 'development' ? undefined : undefined,
        });
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: Invalid object');
    });
    // #endregion

    // #region Environment-Specific Behavior
    it('should include stack trace in development environment', async () => {
        process.env.NODE_ENV = 'development';

        const response = await supertest(app).get('/standard-error');

        expect(response.body).toHaveProperty('stack');
        expect(response.body.stack).toBeTruthy();
    });

    it('should not include stack trace in production environment', async () => {
        process.env.NODE_ENV = 'production';

        const response = await supertest(app).get('/standard-error');

        expect(response.body.stack).toBeUndefined();
    });
    // #endregion

    // #region Logging Behavior
    it('should log errors to console', async () => {
        await supertest(app).get('/custom-error');

        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [CUSTOM_ERROR]: Custom error message');
    });

    it('should log default error message for null errors', async () => {
        await supertest(app).get('/null-error');

        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: Internal Server Error');
    });
    // #endregion

    // #region Concurrent Error Handling
    it('should handle concurrent error requests correctly', async () => {
        consoleErrorSpy.mockClear();

        const [customErrorResponse, standardErrorResponse] = await Promise.all([
            supertest(app).get('/custom-error'),
            supertest(app).get('/standard-error'),
        ]);

        expect(customErrorResponse.status).toBe(400);
        expect(customErrorResponse.body).toEqual({
            status: 'error',
            code: 'CUSTOM_ERROR',
            message: 'Custom error message',
            stack: process.env.NODE_ENV === 'development' ? expect.any(String) : undefined,
        });

        expect(standardErrorResponse.status).toBe(500);
        expect(standardErrorResponse.body).toEqual({
            status: 'error',
            code: 'INTERNAL_ERROR',
            message: 'Standard error message',
            stack: process.env.NODE_ENV === 'development' ? expect.any(String) : undefined,
        });

        expect(consoleErrorSpy).toHaveBeenCalledTimes(2);
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [CUSTOM_ERROR]: Custom error message');
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error [INTERNAL_ERROR]: Standard error message');
    });
    // #endregion
});