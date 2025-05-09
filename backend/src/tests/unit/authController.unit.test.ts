// backend/src/controllers/authController.test.ts
import { v4 as uuidv4 } from 'uuid';
import { Request, Response, NextFunction } from 'express';
import { userModel, User } from '../../models/userModel';
import { ApiError } from '../../utils/ApiError';

/**
 * Auth Controller Unit Test Suite
 * ------------------------------
 * This suite tests the functionality of the Auth Controller, which handles user 
 * authentication operations like registration, login, and user profile retrieval.
 *
 * Testing Approach:
 * - Unit Testing with Mocks: We isolate the controller from external dependencies
 *   through mocking to test its behavior independently.
 *
 * Key Focus Areas:
 * 1. Registration Validation: Verify that the controller properly validates user input
 *    for registration requests.
 * 2. Login Authentication: Test that the controller correctly authenticates users and
 *    handles invalid credentials.
 * 3. User Profile Retrieval: Confirm that authenticated users can access their profile
 *    information.
 * 4. Error Handling: Ensure that appropriate error responses are returned for invalid
 *    inputs or server errors.
 * 5. Response Format: Validate that successful responses follow the expected structure.
 *
 * The suite covers all main authentication flows:
 * - User registration with validation
 * - User login with credential verification
 * - User profile access with authentication checks
 */

// Define proper mock types
interface MockRequest {
  body: Record<string, any>;
  user?: {
    id: string;
    email: string;
  } | null;
}

interface MockResponse extends Partial<Response> {
  status: jest.Mock;
  json: jest.Mock;
}

// Mock dependencies with proper types
jest.mock('../../models/userModel', () => ({
  userModel: {
    create: jest.fn(),
    findByEmail: jest.fn(),
    validatePassword: jest.fn(),
    findById: jest.fn()
  }
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn().mockReturnValue('test-token')
}));

jest.mock('firebase-admin', () => require('../../__mocks__/firebase-admin'), { virtual: true });

jest.mock('../../models/db', () => ({
  query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
  getClient: jest.fn().mockResolvedValue({
    query: jest.fn(),
    release: jest.fn()
  })
}));

// Import controller after mocks are set up
const { authController } = require('../../controllers/authController');

describe('Auth Controller Unit Tests', () => {
  let mockUser: User;
  let req: MockRequest;
  let res: MockResponse;
  let next: jest.Mock;
  
  beforeEach(() => {
    jest.clearAllMocks();
    
    mockUser = {
      id: uuidv4(),
      email: 'test@example.com',
      created_at: new Date(),
      password_hash: 'hashed_password',
      updated_at: new Date()
    };
    
    req = {
      body: {
        email: 'test@example.com',
        password: 'password123'
      },
      user: null
    };
    
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    
    next = jest.fn();
  });
  
  describe('register method', () => {
    test('userModel.create should be called with correct parameters', async () => {
      const localMockUser: User = {
        id: uuidv4(),
        email: 'test@example.com',
        created_at: new Date(),
        password_hash: 'hashed_password',
        updated_at: new Date()
      };
      
      (userModel.create as jest.Mock).mockResolvedValue(localMockUser);
      
      const localReq: MockRequest = {
        body: {
          email: 'test@example.com',
          password: 'password123'
        }
      };
      
      const localRes: MockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      
      const localNext: jest.Mock = jest.fn();
      
      await authController.register(localReq, localRes, localNext);
      
      expect(userModel.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'password123'
      });
    });

    test('should create a user and return success with token when provided valid data', async () => {
      (userModel.create as jest.Mock).mockResolvedValue(mockUser);
      
      await authController.register(req, res, next);
      
      expect(userModel.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'password123'
      });
      expect(res.status).toHaveBeenCalledWith(201);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          user: {
            id: mockUser.id,
            email: mockUser.email
          },
          token: 'test-token'
        }
      });
    });

    test('should return 400 when email is missing', async () => {
      req.body = { password: 'password123' };
      
      await authController.register(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(400);
      expect(next.mock.calls[0][0].message).toBe('Email and password are required');
      expect(userModel.create).not.toHaveBeenCalled();
    });

    test('should return 400 when password is missing', async () => {
      req.body = { email: 'test@example.com' };
      
      await authController.register(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(400);
      expect(next.mock.calls[0][0].message).toBe('Email and password are required');
      expect(userModel.create).not.toHaveBeenCalled();
    });

    test('should return 400 when email format is invalid', async () => {
      req.body.email = 'invalid-email';
      
      await authController.register(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(400);
      expect(next.mock.calls[0][0].message).toBe('Invalid email format');
      expect(userModel.create).not.toHaveBeenCalled();
    });

    test('should return 400 when password is too short', async () => {
      req.body.password = 'short';
      
      await authController.register(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(400);
      expect(next.mock.calls[0][0].message).toBe('Password must be at least 8 characters long');
      expect(userModel.create).not.toHaveBeenCalled();
    });

    test('should pass errors from userModel.create to next middleware', async () => {
      const error = new Error('Database error');
      (userModel.create as jest.Mock).mockRejectedValue(error);
      
      await authController.register(req, res, next);
      
      expect(next).toHaveBeenCalledWith(error);
    });

    test('should return 409 when email already exists', async () => {
      (userModel.findByEmail as jest.Mock).mockResolvedValue(mockUser); // Simulate email found
      const specificError = new ApiError('Email already registered', 409, 'CONFLICT');
      (userModel.create as jest.Mock).mockRejectedValue(specificError);

      await authController.register(req, res, next);

      expect(userModel.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'password123'
      });
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(409);
      expect(next.mock.calls[0][0].message).toMatch(/email already registered/i); 
  });
  });

  describe('login method', () => {
    test('should return user data and token when credentials are valid', async () => {
      (userModel.findByEmail as jest.Mock).mockResolvedValue(mockUser);
      (userModel.validatePassword as jest.Mock).mockResolvedValue(true);
      
      await authController.login(req, res, next);
      
      expect(userModel.findByEmail).toHaveBeenCalledWith('test@example.com');
      expect(userModel.validatePassword).toHaveBeenCalledWith(mockUser, 'password123');
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          user: {
            id: mockUser.id,
            email: mockUser.email
          },
          token: 'test-token'
        }
      });
    });

    test('should return 400 when email is missing', async () => {
      req.body = { password: 'password123' };
      
      await authController.login(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(400);
      expect(next.mock.calls[0][0].message).toBe('Email and password are required');
    });

    test('should return 400 when password is missing', async () => {
      req.body = { email: 'test@example.com' };
      
      await authController.login(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(400);
      expect(next.mock.calls[0][0].message).toBe('Email and password are required');
    });

    test('should return 401 when user is not found', async () => {
      (userModel.findByEmail as jest.Mock).mockResolvedValue(null);
      
      await authController.login(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(401);
      expect(next.mock.calls[0][0].message).toBe('Invalid credentials');
    });

    test('should return 401 when password is invalid', async () => {
      (userModel.findByEmail as jest.Mock).mockResolvedValue(mockUser);
      (userModel.validatePassword as jest.Mock).mockResolvedValue(false);
      
      await authController.login(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(401);
      expect(next.mock.calls[0][0].message).toBe('Invalid credentials');
    });

    test('should pass errors from userModel to next middleware', async () => {
      const error = new Error('Database error');
      (userModel.findByEmail as jest.Mock).mockRejectedValue(error);
      
      await authController.login(req, res, next);
      
      expect(next).toHaveBeenCalledWith(error);
    });
  });

  describe('me method', () => {
    test('should return user data when authenticated', async () => {
      req.user = {
        id: mockUser.id,
        email: mockUser.email
      };
      
      await authController.me(req, res, next);
      
      expect(res.status).toHaveBeenCalledWith(200);
      expect(res.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          user: req.user
        }
      });
    });

    test('should return 401 when not authenticated', async () => {
      req.user = null;
      
      await authController.me(req, res, next);
      
      expect(next).toHaveBeenCalledWith(expect.any(ApiError));
      expect(next.mock.calls[0][0].statusCode).toBe(401);
      expect(next.mock.calls[0][0].message).toBe('Not authenticated');
    });

    test('should pass errors to next middleware', async () => {
      req.user = { id: mockUser.id, email: mockUser.email };
      const error = new Error('Unexpected error');
      res.status = jest.fn().mockImplementation(() => { throw error; });
      
      await authController.me(req, res, next);
      
      expect(next).toHaveBeenCalledWith(error);
    });
  });
});