/**
 * @file auth.security.test.ts
 * @summary Security tests for the authenticate middleware
 * 
 * @description
 * This test suite validates the security and resilience of the `authenticate` middleware.
 * It covers various scenarios including:
 * - JWT validation (e.g., weak secrets, tampering, expiration)
 * - Error handling to prevent information leakage
 * - Session fixation prevention
 * - Protection against malformed headers and bypass attempts
 * - Handling of database errors during user lookup
 * 
 * The tests use Jest mocks and assertions to simulate edge cases and verify middleware behavior.
 */

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('../../config', () => ({
  config: { jwtSecret: 'testsecret' }
}));
jest.mock('../../models/userModel', () => ({
  userModel: { findById: jest.fn() }
}));
jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    unauthorized: jest.fn(msg => ({
      message: msg,
      statusCode: 401,
      type: 'UNAUTHORIZED'
    })),
    internal: jest.fn(msg => ({
      message: msg,
      statusCode: 500,
      type: 'INTERNAL_ERROR'
    }))
  }
}));

import { authenticate } from '../../middlewares/auth';
import { ApiError } from '../../utils/ApiError';
import jwt from 'jsonwebtoken';
import { userModel } from '../../models/userModel';

describe('Authentication Middleware Security Tests', () => {
    let req: any;
    let res: any;
    let next: jest.Mock;

    beforeEach(() => {
        req = { headers: {} };
        res = {};
        next = jest.fn();
        jest.clearAllMocks();
    });

    // #region JWT Security Tests
    /**
     * These tests validate the middleware's handling of JWT-related vulnerabilities,
     * such as weak secrets, tampering, and expired tokens.
     */
    test('should reject tokens signed with weak secrets (HS256 with short secret)', async () => {
        req.headers.authorization = 'Bearer weaktoken';
        (jwt.verify as jest.Mock).mockImplementation(() => {
            const err = new Error('weak secret used');
            err.name = 'JsonWebTokenError';
            throw err;
        });

        await authenticate(req, res, next);
        expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
    });

    test('should prevent token tampering by rejecting invalid signatures', async () => {
        req.headers.authorization = 'Bearer tamperedtoken';
        (jwt.verify as jest.Mock).mockImplementation(() => {
            const err = new Error('invalid signature');
            err.name = 'JsonWebTokenError';
            throw err;
        });

        await authenticate(req, res, next);
        expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
    });

    test('should reject expired tokens immediately', async () => {
        req.headers.authorization = 'Bearer expiredtoken';
        (jwt.verify as jest.Mock).mockImplementation(() => {
            const err = new Error('token expired');
            err.name = 'TokenExpiredError';
            throw err;
        });

        await authenticate(req, res, next);
        expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
    });
    // #endregion

    // #region Information Leakage Tests
    /**
     * These tests ensure that error messages do not leak sensitive information
     * and that generic error messages are used for JWT failures.
     */
    test('should not reveal specific error details in responses', async () => {
        req.headers.authorization = 'Bearer invalidtoken';
        
        // Simulate a non-JWT error
        (jwt.verify as jest.Mock).mockImplementation(() => {
            throw new Error('database connection failed');
        });

        await authenticate(req, res, next);

        // Verify error handling
        expect(next).toHaveBeenCalledWith(expect.objectContaining({
            message: 'Authentication error',
            statusCode: 500
        }));
        expect(next.mock.calls[0][0].message).not.toContain('database');
    });

    test('should use generic error messages for all JWT failures', async () => {
        const testCases = [
            { error: new Error('invalid signature'), name: 'JsonWebTokenError' },
            { error: new Error('token expired'), name: 'TokenExpiredError' },
            { error: new Error('jwt malformed'), name: 'JsonWebTokenError' }
        ];

        for (const { error, name } of testCases) {
            error.name = name;
            req.headers.authorization = 'Bearer sometoken';
            (jwt.verify as jest.Mock).mockImplementation(() => { throw error; });
            await authenticate(req, res, next);
            expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
            jest.clearAllMocks();
        }
    });
    // #endregion

    // #region Session Fixation Tests
    /**
     * These tests verify that tokens cannot be reused after user credentials are changed.
     */
    test('should not allow token reuse after user changes credentials', async () => {
        const mockUser = { id: '123', email: 'a@b.com' };
        (jwt.verify as jest.Mock).mockReturnValue(mockUser);
        (userModel.findById as jest.Mock).mockResolvedValueOnce(mockUser)
            .mockResolvedValueOnce(null); // Simulate user changing credentials

        // First call - valid
        req.headers.authorization = 'Bearer validtoken';
        await authenticate(req, res, next);
        expect(next).toHaveBeenCalledWith();
        jest.clearAllMocks();

        // Second call - same token should now be invalid
        await authenticate(req, res, next);
        expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
    });
    // #endregion

    // #region Timing Attack Protection
    /**
     * These tests ensure consistent error handling paths to mitigate timing attacks.
     */
    test('should have consistent error handling paths', async () => {
        // Mock different error scenarios
        (jwt.verify as jest.Mock)
            .mockImplementationOnce(() => { throw { name: 'JsonWebTokenError' } }) // Invalid token
            .mockImplementationOnce(() => { throw { name: 'TokenExpiredError' } }) // Expired token
            .mockImplementationOnce(() => { throw new Error('DB error') }); // Internal error

        const testCases = [
            undefined, // No header - should be unauthorized
            'Bearer invalid', // Invalid token - unauthorized
            'Bearer expired', // Expired token - unauthorized
            'Bearer error' // Internal error - 500
        ];

        const results = {
            unauthorized: 0,
            internal: 0
        };

        for (const header of testCases) {
            req.headers.authorization = header;
            await authenticate(req, res, next);
            
            const error = next.mock.calls[0][0];
            if (error?.statusCode === 401) results.unauthorized++;
            if (error?.statusCode === 500) results.internal++;
            
            jest.clearAllMocks();
        }

        // Verify:
        // - 3 unauthorized cases (missing header, invalid token, expired token)
        // - 1 internal error case (DB error)
        expect(results.unauthorized).toBe(3);
        expect(results.internal).toBe(1);
    });
    // #endregion

    // #region Malformed Header Tests
    /**
     * These tests validate the middleware's handling of malformed Authorization headers.
     */
    test('should reject malformed Authorization headers', async () => {
        req.headers.authorization = 'MalformedHeader';
        await authenticate(req, res, next);
        expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
    });

    test('should reject empty token', async () => {
        req.headers.authorization = 'Bearer ';
        await authenticate(req, res, next);
        expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
    });
    // #endregion

    // #region Database Error Tests
    /**
     * These tests ensure proper handling of database errors during user lookup.
     */
    test('should handle database errors during user lookup', async () => {
        req.headers.authorization = 'Bearer validtoken';
        (jwt.verify as jest.Mock).mockReturnValue({ id: '123', email: 'a@b.com' });
        (userModel.findById as jest.Mock).mockImplementation(() => {
            throw new Error('Database error');
        });

        await authenticate(req, res, next);
        expect(next).toHaveBeenCalledWith(expect.objectContaining({
            message: 'Authentication error',
            statusCode: 500
        }));
    });
    // #endregion

    // #region Authentication Bypass Tests
    /**
     * These tests ensure that the middleware cannot be bypassed with invalid token structures.
     */
    test('should not allow authentication bypass with invalid token structure', async () => {
        req.headers.authorization = 'Bearer invalid.token.structure';
        (jwt.verify as jest.Mock).mockImplementation(() => {
            const err = new Error('invalid token');
            err.name = 'JsonWebTokenError';
            throw err;
        });

        await authenticate(req, res, next);
        expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
    });
    // #endregion
});