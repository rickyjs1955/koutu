// Mock only external dependencies that can't be included in tests
jest.mock('../../services/labelingService');
jest.mock('../../config/firebase', () => ({
  // Mock firebase configuration
  admin: {
    initializeApp: jest.fn(),
    storage: jest.fn(),
    auth: jest.fn()
  }
}));

import { Request, Response, NextFunction } from 'express';
import { garmentController } from '../../controllers/garmentController';
import { garmentModel } from '../../models/garmentModel';
import { pool } from '../../models/db';
import { ApiError } from '../../utils/ApiError';

describe('Garment Controller Integration Tests', () => {
  // Setup test database connection before all tests
  beforeAll(async () => {
    // Connect to test database - should be configured in env
    // Ideally, this would be a separate database used for testing
  });

  // Clean up after all tests
  afterAll(async () => {
    // Close database connection
    await pool.end();
  });

  // Reset test database between tests
  beforeEach(async () => {
    // Clear and seed test data
    // For example: await pool.query('DELETE FROM garments WHERE user_id = $1', ['test-user-id']);
  });

  describe('getGarments', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;
    
    beforeEach(() => {
      // Reset HTTP mocks before each test
      jest.clearAllMocks();
      
      mockRequest = {
        user: { 
            id: 'test-user-id',
            email: 'test@example.com'
        }
      };
      
      mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      
      mockNext = jest.fn();
    });
    
    it('should return all garments for authenticated user', async () => {
      // Mock data
      const mockGarments = [
        { id: 'garment-1', user_id: 'test-user-id' },
        { id: 'garment-2', user_id: 'test-user-id' }
      ];
      
      // Setup the model mock to return garments
      (garmentModel.findByUserId as jest.Mock).mockResolvedValue(mockGarments);
      
      // Call the controller method
      await garmentController.getGarments(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );
      
      // Assertions
      expect(garmentModel.findByUserId).toHaveBeenCalledWith('test-user-id');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          garments: mockGarments,
          count: 2
        }
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
    
    it('should return error when user is not authenticated', async () => {
      // Setup request without user (unauthenticated)
      mockRequest.user = undefined;
      
      // Call the controller method
      await garmentController.getGarments(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );
      
      // Assertions
      expect(garmentModel.findByUserId).not.toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'User not authenticated',
          statusCode: 401
        })
      );
    });
    
    it('should pass database errors to error handler', async () => {
      // Setup model to throw an error
      const mockError = new Error('Database connection failed');
      (garmentModel.findByUserId as jest.Mock).mockRejectedValue(mockError);
      
      // Call the controller method
      await garmentController.getGarments(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );
      
      // Assertions
      expect(garmentModel.findByUserId).toHaveBeenCalledWith('test-user-id');
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(mockError);
    });
    
    it('should handle empty garment list correctly', async () => {
      // Setup model to return empty array
      (garmentModel.findByUserId as jest.Mock).mockResolvedValue([]);
      
      // Call the controller method
      await garmentController.getGarments(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );
      
      // Assertions
      expect(garmentModel.findByUserId).toHaveBeenCalledWith('test-user-id');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'success',
        data: {
          garments: [],
          count: 0
        }
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});