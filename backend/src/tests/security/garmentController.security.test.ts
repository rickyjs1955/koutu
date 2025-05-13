/**
 * Security Test Suite for Garment Controller
 *
 * This test suite validates the security measures implemented in the garmentController,
 * ensuring proper authentication, authorization, data protection, and error handling.
 */

// Update the ApiError mock to include all methods we use
jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    unauthorized: jest.fn().mockReturnValue(new Error('Unauthorized')),
    notFound: jest.fn().mockReturnValue(new Error('Not Found')),
    forbidden: jest.fn().mockReturnValue(new Error('Forbidden')),
    badRequest: jest.fn().mockReturnValue(new Error('Bad Request')),
    internal: jest.fn().mockReturnValue(new Error('Internal Server Error'))
  }
}));

// Other mocks remain the same
jest.mock('../../models/garmentModel', () => ({
  garmentModel: {
    findByUserId: jest.fn(),
    findById: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    updateMetadata: jest.fn()
  }
}));

jest.mock('../../models/imageModel', () => ({
  imageModel: {
    findById: jest.fn(),
    updateStatus: jest.fn()
  }
}));

jest.mock('../../services/labelingService', () => ({
  labelingService: {
    applyMaskToImage: jest.fn()
  }
}));

import { Request, Response, NextFunction } from 'express';
import { garmentController } from '../../controllers/garmentController';
import { ApiError } from '../../utils/ApiError';
import { garmentModel } from '../../models/garmentModel';

type TestGarment = {
  id: string;
  user_id: string;
  file_path?: string;
  mask_path?: string;
  metadata: Record<string, any>;
  created_at?: Date;
  updated_at?: Date;
  data_version?: number;
};

describe('Garment Controller Security Tests', () => {
    let mockRequest: Partial<Request> & { params: Record<string, string> };
    let mockResponse: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;
    
    beforeEach(() => {
        // Reset all mocks before each test
        jest.clearAllMocks();
        
        // Setup request, response and next function mocks
        mockRequest = {
        user: undefined, // Will be set in individual tests
        params: {},
        query: {},
        headers: {},
        body: {}
        };
        
        mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn()
        };
        
        mockNext = jest.fn();
    });
    
    describe('Authentication Security', () => {
        test('should reject requests with missing authentication', async () => {
        // Authentication is null/undefined
        mockRequest.user = undefined;
        
        await garmentController.getGarments(
            mockRequest as Request,
            mockResponse as Response,
            mockNext
        );
        
        // Verify security behavior
        expect(ApiError.unauthorized).toHaveBeenCalledWith('User not authenticated');
        expect(mockNext).toHaveBeenCalled();
        expect(garmentModel.findByUserId).not.toHaveBeenCalled();
        expect(mockResponse.status).not.toHaveBeenCalled();
        expect(mockResponse.json).not.toHaveBeenCalled();
        });
        
        test('should reject requests with empty authentication object', async () => {
        // Authentication exists but has no id
        mockRequest.user = {} as any;
        
        await garmentController.getGarments(
            mockRequest as Request,
            mockResponse as Response,
            mockNext
        );
        
        // Verify security behavior
        expect(ApiError.unauthorized).toHaveBeenCalledWith('User not authenticated');
        expect(mockNext).toHaveBeenCalled();
        expect(garmentModel.findByUserId).not.toHaveBeenCalled();
        });

        test('should accept properly authenticated requests', async () => {
        // Valid user authentication
        mockRequest.user = { id: 'valid-user-id', email: 'user@example.com' } as any;
        (garmentModel.findByUserId as jest.Mock).mockResolvedValue([]);
        
        await garmentController.getGarments(
            mockRequest as Request,
            mockResponse as Response,
            mockNext
        );
        
        // Verify proper behavior for authenticated requests
        expect(ApiError.unauthorized).not.toHaveBeenCalled();
        expect(garmentModel.findByUserId).toHaveBeenCalledWith('valid-user-id');
        expect(mockResponse.status).toHaveBeenCalledWith(200);
        expect(mockResponse.json).toHaveBeenCalled();
        });
    });
    
    describe('Data Isolation Security', () => {
        test('should filter out garments not owned by the current user', async () => {
            // Setup user and mixed ownership data
            const userId = 'user-123';
            const otherUserId = 'other-user-456';
            mockRequest.user = { id: userId, email: 'user@example.com' } as any;
            
            // Simulate a compromised model that returns mixed ownership data
            const mockGarments = [
                { 
                id: 'garment1', 
                user_id: userId,
                metadata: {}
                },
                { 
                id: 'garment2', 
                user_id: otherUserId, // Different user's garment
                metadata: {}
                },
                { 
                id: 'garment3', 
                user_id: userId,
                metadata: {}
                }
            ];
            
            (garmentModel.findByUserId as jest.Mock).mockResolvedValue(mockGarments);
            
            await garmentController.getGarments(
                mockRequest as Request,
                mockResponse as Response,
                mockNext
            );
            
            // Get the garments from the response
            const responseData = (mockResponse.json as jest.Mock).mock.calls[0][0].data.garments;
            
            // Verify only user's garments are returned
            expect(responseData.length).toBe(2); // Only two garments should remain
            expect(responseData.some((g: TestGarment) => g.user_id === otherUserId)).toBe(false);
            expect(responseData.every((g: TestGarment) => g.user_id === userId)).toBe(true);
        });
    });
    
    describe('Error Handling Security', () => {
        test('should sanitize database errors to prevent information leakage', async () => {
        // Setup authenticated user
        mockRequest.user = { id: 'user-123', email: 'user@example.com' } as any;
        
        // Simulate database error with sensitive information
        const dbError = new Error('FATAL ERROR: connection to postgres@internal-db:5432 failed - password: "secret123"');
        (garmentModel.findByUserId as jest.Mock).mockRejectedValue(dbError);
        
        await garmentController.getGarments(
            mockRequest as Request,
            mockResponse as Response,
            mockNext
        );
        
        // Verify error is sanitized
        expect(ApiError.internal).toHaveBeenCalledWith('An error occurred while retrieving garments');
        expect(mockNext).toHaveBeenCalled();
        
        // Verify the raw error with sensitive details is not passed to next()
        const sanitizedError = mockNext.mock.calls[0][0] as unknown as Error;
        expect(sanitizedError.message).not.toContain('postgres');
        expect(sanitizedError.message).not.toContain('password');
        expect(sanitizedError.message).not.toContain('secret123');
        });
    });
    
    describe('Path Sanitization Security', () => {
        test('should sanitize file paths to prevent server path disclosure', async () => {
        // Setup authenticated user
        mockRequest.user = { id: 'user-123', email: 'user@example.com' } as any;
        
        // Mock garments with file system paths
        const mockGarments = [{
            id: 'garment1',
            user_id: 'user-123',
            file_path: '/var/www/app/storage/user-123/images/garment1.jpg',
            mask_path: '/var/www/app/storage/user-123/masks/mask1.png',
            metadata: {}
        }];
        
        (garmentModel.findByUserId as jest.Mock).mockResolvedValue(mockGarments);
        
        await garmentController.getGarments(
            mockRequest as Request,
            mockResponse as Response,
            mockNext
        );
        
        // Get garment from response
        const responseData = (mockResponse.json as jest.Mock).mock.calls[0][0].data.garments[0];
        
        // Verify paths are converted to API routes
        expect(responseData.file_path).toBe('/api/garments/garment1/image');
        expect(responseData.mask_path).toBe('/api/garments/garment1/mask');
        expect(responseData.file_path).not.toContain('/var/www/');
        expect(responseData.mask_path).not.toContain('/var/www/');
        });
    });
    
    describe('Metadata Filtering Security', () => {
        test('should filter sensitive metadata fields', async () => {
        // Setup authenticated user
        mockRequest.user = { id: 'user-123', email: 'user@example.com' } as any;
        
        // Mock garment with sensitive metadata
        const mockGarments = [{
            id: 'garment1',
            user_id: 'user-123',
            file_path: '/path/to/file.jpg',
            mask_path: '/path/to/mask.png',
            metadata: {
            type: 'shirt',
            color: 'blue',
            pattern: 'striped',
            season: 'summer',
            brand: 'example',
            tags: ['casual'],
            // Sensitive fields that should be filtered
            internalNotes: 'Customer has payment issues',
            systemTags: ['vip-customer'],
            purchaseInfo: { price: 499.99 }
            }
        }];
        
        (garmentModel.findByUserId as jest.Mock).mockResolvedValue(mockGarments);
        
        await garmentController.getGarments(
            mockRequest as Request,
            mockResponse as Response,
            mockNext
        );
        
        // Get metadata from response
        const responseMetadata = (mockResponse.json as jest.Mock).mock.calls[0][0].data.garments[0].metadata;
        
        // Verify allowed fields are included
        expect(responseMetadata).toHaveProperty('type');
        expect(responseMetadata).toHaveProperty('color');
        expect(responseMetadata).toHaveProperty('pattern');
        expect(responseMetadata).toHaveProperty('season');
        expect(responseMetadata).toHaveProperty('brand');
        expect(responseMetadata).toHaveProperty('tags');
        
        // Verify sensitive fields are excluded
        expect(responseMetadata).not.toHaveProperty('internalNotes');
        expect(responseMetadata).not.toHaveProperty('systemTags');
        expect(responseMetadata).not.toHaveProperty('purchaseInfo');
        });
    });
    
    describe('Authorization Security', () => {
        test('should prevent access to garments owned by other users', async () => {
        // Setup request for accessing another user's garment
        const userId = 'user-123';
        const otherUserId = 'other-user-456';
        mockRequest.user = { id: userId, email: 'user@example.com' } as any;
        mockRequest.params.id = 'garment-1';
        
        // Mock garment belonging to another user
        const otherUserGarment = {
            id: 'garment-1',
            user_id: otherUserId,
            metadata: {}
        };
        
        (garmentModel.findById as jest.Mock).mockResolvedValue(otherUserGarment);
        
        await garmentController.getGarment(
            mockRequest as Request,
            mockResponse as Response,
            mockNext
        );
        
        // Verify proper access control
        expect(ApiError.forbidden).toHaveBeenCalledWith('You do not have permission to access this garment');
        expect(mockNext).toHaveBeenCalled();
        expect(mockResponse.status).not.toHaveBeenCalled();
        expect(mockResponse.json).not.toHaveBeenCalled();
        });
    });
});