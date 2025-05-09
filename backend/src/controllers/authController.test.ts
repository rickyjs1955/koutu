// backend/src/controllers/authController.test.ts
import { v4 as uuidv4 } from 'uuid';
import { userModel } from '../models/userModel';

// Mock dependencies
jest.mock('../models/userModel', () => ({
  userModel: {
    create: jest.fn(),
    findByEmail: jest.fn(),
    validatePassword: jest.fn(),
    findById: jest.fn()
  }
}));

// Mock JWT generation to return a consistent token for testing
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn().mockReturnValue('test-token')
}));

// Mock firebase-admin
jest.mock('firebase-admin', () => require('../__mocks__/firebase-admin'), { virtual: true });

// Mock database
jest.mock('../models/db', () => ({
  query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
  getClient: jest.fn().mockResolvedValue({
    query: jest.fn(),
    release: jest.fn()
  })
}));

// Mock simple test without app dependency
describe('Auth Controller Simple Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('userModel.create should be called with correct parameters', async () => {
    const mockUser = {
      id: uuidv4(),
      email: 'test@example.com',
      created_at: new Date()
    };
    
    (userModel.create as jest.Mock).mockResolvedValue(mockUser);
    
    // Create a simple mock request, response, and next function
    const req = {
      body: {
        email: 'test@example.com',
        password: 'password123'
      }
    };
    
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    
    const next = jest.fn();
    
    // Directly import the controller
    const { authController } = require('../controllers/authController');
    
    // Call the register method
    await authController.register(req, res, next);
    
    // Verify userModel.create was called with the correct parameters
    expect(userModel.create).toHaveBeenCalledWith({
      email: 'test@example.com',
      password: 'password123'
    });
  });
});