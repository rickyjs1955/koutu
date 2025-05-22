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

  test('should return 401 if Authorization header is missing', async () => {
    const response = await request(app).get('/protected');
    expect(response.status).toBe(401);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
  });

  test('should return 401 if Authorization header is malformed', async () => {
    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Token abcdef');
    expect(response.status).toBe(401);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Authentication required');
  });

  test('should return 401 if token is invalid', async () => {
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new Error('Invalid token');
    });

    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer invalidtoken');
    expect(response.status).toBe(401);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
  });

  test('should return 401 if user does not exist', async () => {
    (jwt.verify as jest.Mock).mockReturnValue({ id: '123', email: 'a@b.com' });
    (userModel.findById as jest.Mock).mockResolvedValue(null);

    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer validtoken');
    expect(response.status).toBe(401);
    expect(ApiError.unauthorized).toHaveBeenCalledWith('Invalid token');
  });

  test('should return 200 and attach user to request if token and user are valid', async () => {
    (jwt.verify as jest.Mock).mockReturnValue({ id: '123', email: 'a@b.com' });
    (userModel.findById as jest.Mock).mockResolvedValue({ id: '123', email: 'a@b.com' });

    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer validtoken');
    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      message: 'Access granted',
      user: { id: '123', email: 'a@b.com' },
    });
  });

  test('should return 500 if an unexpected error occurs', async () => {
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new Error('Unexpected error');
    });

    const response = await request(app)
      .get('/protected')
      .set('Authorization', 'Bearer sometoken');
    expect(response.status).toBe(500);
    expect(ApiError.internal).toHaveBeenCalledWith('Authentication error');
  });
});