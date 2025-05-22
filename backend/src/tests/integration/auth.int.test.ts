// filepath: /backend/src/tests/integration/auth.int.test.ts
/**
 * @file auth.int.test.ts
 * @summary Integration tests for the authenticate middleware.
 *
 * @description
 * This test suite verifies the behavior of the authentication middleware in an
 * integrated Express application setup. It covers various scenarios including:
 * - Missing or malformed Authorization headers.
 * - Invalid JWT tokens or non-existent users.
 * - Successful authentication and user attachment to the request.
 * - Handling of unexpected errors during the authentication process.
 *
 * The tests use `supertest` to make HTTP requests to a minimal Express app
 * that incorporates the `authenticate` middleware and a global `errorHandler`.
 * Dependencies like `jsonwebtoken`, `userModel`, and `ApiError` are mocked to
 * control their behavior and isolate the middleware's integration logic.
 */

// Mock dependencies
jest.mock('jsonwebtoken');
jest.mock('../../models/userModel', () => ({
  userModel: { findById: jest.fn() },
}));
jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    unauthorized: jest.fn((msg) => ({
      message: msg,
      statusCode: 401,
      code: 'UNAUTHORIZED',
      stack: '',
    })),
    internal: jest.fn((msg) => ({
      message: msg,
      statusCode: 500,
      code: 'INTERNAL_ERROR',
      stack: '',
    })),
  },
}));

import request from 'supertest';
import express from 'express';
import jwt from 'jsonwebtoken';
import { authenticate } from '../../middlewares/auth';
import { userModel } from '../../models/userModel';
import { ApiError } from '../../utils/ApiError';
import { errorHandler } from '../../middlewares/errorHandler';

const app = express();
app.use(express.json());
app.use(authenticate);

app.get('/protected', (req, res) => {
  res.status(200).json({ message: 'Access granted', user: req.user });
});

app.use(errorHandler);

describe('Authenticate Middleware Integration Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  // #region Authorization Header Tests
  test('should return 401 if Authorization header is missing', async () => {
    const response = await request(app).get('/protected');
    expect(response.status).toBe(401);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
  });

  test('should return 401 if Authorization header is malformed (does not start with Bearer)', async () => {
    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Token abcdef'); // Using "Token" instead of "Bearer"
    expect(response.status).toBe(401);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
  });
  // #endregion

  // #region Token and User Validation Tests
  test('should return 401 if token is invalid (jwt.verify throws "Invalid token")', async () => {
    (jwt.verify as jest.Mock).mockImplementation(() => {
      // Simulate a JWT-specific error that the middleware handles as unauthorized
      const err = new Error('Invalid token');
      err.name = 'JsonWebTokenError';
      throw err;
    });

    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer invalidtoken');
    expect(response.status).toBe(401);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
  });

  test('should return 401 if user does not exist (valid token, but userModel.findById returns null)', async () => {
    (jwt.verify as jest.Mock).mockReturnValue({ id: '123', email: 'a@b.com' });
    (userModel.findById as jest.Mock).mockResolvedValue(null); // Simulate user not found

    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer validtoken');
    expect(response.status).toBe(401);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
  });

  test('should return 200 and attach user to request if token and user are valid', async () => {
    const mockUser = { id: '123', email: 'a@b.com' };
    (jwt.verify as jest.Mock).mockReturnValue(mockUser);
    (userModel.findById as jest.Mock).mockResolvedValue(mockUser);

    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer validtoken');
    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      message: 'Access granted',
      user: mockUser,
    });
  });
  // #endregion

  // #region Error Handling Tests
  test('should return 500 if an unexpected error occurs during jwt.verify', async () => {
    (jwt.verify as jest.Mock).mockImplementation(() => {
      // Simulate a generic error, not a JWT-specific one
      throw new Error('Unexpected database connection error');
    });

    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer sometoken');
    expect(response.status).toBe(500);
    expect(ApiError.internal).toHaveBeenCalledWith('Authentication error');
  });
  // #endregion
});