// filepath: /backend/src/tests/unit/auth.unit.test.ts
/**
 * @file auth.unit.test.ts
 * @summary Unit tests for the authenticate middleware
 * 
 * @description
 * This test suite verifies the behavior of the authentication middleware under various scenarios:
 * - Missing or malformed Authorization headers
 * - Invalid JWT tokens
 * - User lookup failures
 * - Successful authentication flow
 * - Error handling for unexpected issues
 * 
 * The tests use Jest mocks for jwt, userModel, and ApiError to isolate the middleware's behavior.
 */

import { authenticate } from '../../middlewares/auth';
import { ApiError } from '../../utils/ApiError';
import jwt from 'jsonwebtoken';
import { userModel } from '../../models/userModel';

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
    unauthorized: jest.fn((msg) => ({ type: 'unauthorized', message: msg })),
    internal: jest.fn((msg) => ({ type: 'internal', message: msg }))
  }
}));

describe('authenticate middleware', () => {
  let req: any;
  let res: any;
  let next: jest.Mock;

  beforeEach(() => {
    req = { headers: {} };
    res = {};
    next = jest.fn();
    jest.clearAllMocks();
  });

  // #region Authorization header tests
  test('should call next with unauthorized if no Authorization header', async () => {
    await authenticate(req, res, next);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ type: 'unauthorized' }));
  });

  test('should call next with unauthorized if Authorization header does not start with Bearer', async () => {
    req.headers.authorization = 'Token abcdef';
    await authenticate(req, res, next);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ type: 'unauthorized' }));
  });

  test('should call next with unauthorized if token is missing after Bearer', async () => {
    req.headers.authorization = 'Bearer ';
    await authenticate(req, res, next);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ type: 'unauthorized' }));
  });
  // #endregion

  // #region Token verification tests
  test('should call next with unauthorized if jwt.verify throws', async () => {
    req.headers.authorization = 'Bearer sometoken';
    (jwt.verify as jest.Mock).mockImplementation(() => { throw new Error('bad token'); });
    await authenticate(req, res, next);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ type: 'unauthorized' }));
  });

  test('should call next with unauthorized if user not found', async () => {
    req.headers.authorization = 'Bearer validtoken';
    (jwt.verify as jest.Mock).mockReturnValue({ id: '123', email: 'a@b.com' });
    (userModel.findById as jest.Mock).mockResolvedValue(null);
    await authenticate(req, res, next);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ type: 'unauthorized' }));
  });
  // #endregion

  // #region Success path
  test('should attach user to req and call next if token and user are valid', async () => {
    req.headers.authorization = 'Bearer validtoken';
    (jwt.verify as jest.Mock).mockReturnValue({ id: '123', email: 'a@b.com' });
    (userModel.findById as jest.Mock).mockResolvedValue({ id: '123', email: 'a@b.com' });
    await authenticate(req, res, next);
    expect(req.user).toEqual({ id: '123', email: 'a@b.com' });
    expect(next).toHaveBeenCalledWith();
  });
  // #endregion

  // #region Error handling
  test('should call next with internal error if unexpected error occurs', async () => {
    // Simulate error in outer try/catch
    req.headers = null as any;
    await authenticate(req, res, next);
    expect(ApiError.internal).toHaveBeenCalledWith('Authentication error');
    expect(next).toHaveBeenCalledWith(expect.objectContaining({ type: 'internal' }));
  });
  // #endregion
});