import { Request, Response, NextFunction } from 'express';
import { validate } from '../../middlewares/validate';
import { z } from 'zod';
import { ApiError } from '../../utils/ApiError';

// Mock ApiError
jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    badRequest: jest.fn((message, code) => ({
      message,
      code,
      statusCode: 400
    }))
  }
}));

describe('validate middleware', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: NextFunction;
    
    beforeEach(() => {
      mockRequest = {
        body: {},
        query: {},
        params: {}
      };
      mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      mockNext = jest.fn();
      jest.clearAllMocks();
    });
    
    test('should pass validation with valid data', async () => {
      // Define a test schema
      const testSchema = z.object({
        name: z.string(),
        age: z.number()
      });
      
      // Set up valid request data
      mockRequest.body = { name: 'John', age: 30 };
      
      // Create middleware instance
      const middleware = validate(testSchema);
      
      // Execute middleware
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);
      
      // Check that next was called without errors
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockNext).not.toHaveBeenCalledWith(expect.objectContaining({ statusCode: 400 }));
    });
    
    test('should reject invalid data with proper error formatting', async () => {
      // Define a test schema
      const testSchema = z.object({
        name: z.string(),
        age: z.number()
      });
      
      // Set up invalid request data
      mockRequest.body = { name: 123, age: 'thirty' };
      
      // Create middleware instance
      const middleware = validate(testSchema);
      
      // Execute middleware
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);
      
      // Check that ApiError.badRequest was called with appropriate error message
      expect(ApiError.badRequest).toHaveBeenCalledWith(
        expect.stringContaining('Validation error'),
        'VALIDATION_ERROR'
      );
      
      // Check that next was called with the error
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ 
        statusCode: 400,
        code: 'VALIDATION_ERROR'
      }));
    });
    
    test('should handle multiple validation errors', async () => {
      // Define a test schema with multiple requirements
      const testSchema = z.object({
        email: z.string().email(),
        password: z.string().min(8),
        age: z.number().min(18)
      });
      
      // Set up invalid request data with multiple issues
      mockRequest.body = { email: 'not-an-email', password: 'short', age: 16 };
      
      // Create middleware instance
      const middleware = validate(testSchema);
      
      // Execute middleware
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);
      
      // Check that ApiError.badRequest was called with error message containing all validation issues
      expect(ApiError.badRequest).toHaveBeenCalledWith(
        expect.stringMatching(/email.*password.*age/s),
        'VALIDATION_ERROR'
      );
    });
    
    test('should validate query parameters when source is set to "query"', async () => {
      // Define a test schema
      const testSchema = z.object({
        search: z.string(),
        limit: z.coerce.number().optional()
      });
      
      // Set up valid query parameters
      mockRequest.query = { search: 'test', limit: '10' };
      
      // Create middleware instance with query source
      const middleware = validate(testSchema, 'query');
      
      // Execute middleware
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);
      
      // The middleware should coerce the limit string to a number
      expect(mockRequest.query).toEqual({ search: 'test', limit: 10 });
      expect(mockNext).toHaveBeenCalledWith();
    });
    
    test('should pass non-Zod errors to next without formatting', async () => {
      // Define a test schema
      const testSchema = z.object({
        name: z.string()
      });
      
      // Create middleware instance
      const middleware = validate(testSchema);
      
      // Mock schema.parseAsync to throw a non-Zod error
      jest.spyOn(testSchema, 'parseAsync').mockImplementation(() => {
        throw new Error('Unexpected error');
      });
      
      // Execute middleware
      await middleware(mockRequest as Request, mockResponse as Response, mockNext);
      
      // Check that next was called with the original error
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ 
        message: 'Unexpected error'
      }));
      
      // Check that ApiError.badRequest was not called
      expect(ApiError.badRequest).not.toHaveBeenCalled();
    });
});