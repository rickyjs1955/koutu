// filepath: /backend/src/tests/unit/garmentController.unit.test.ts

// Mock external dependencies
jest.mock('firebase-admin', () => ({
  initializeApp: jest.fn(),
  credential: {
    cert: jest.fn().mockReturnValue({}), // Mock the return of cert to avoid issues
  },
  apps: [], // Add this line to mock the apps array
  storage: jest.fn(() => ({ // Mock the storage service
    bucket: jest.fn(() => ({ // Mock the bucket() method
      // Add mocks for any bucket methods your code uses, e.g., file(), upload()
      // Example:
      // file: jest.fn().mockReturnThis(),
      // upload: jest.fn().mockResolvedValue([{ name: 'mocked-file-name.jpg' }]), 
      // getSignedUrl: jest.fn().mockResolvedValue(['http://mocked-url.com/image.jpg']),
    })),
  })),
  // If your code (or unmocked dependencies) directly uses other firebase-admin services
  // like firestore(), you might need to mock them here as well.
  // For example:
  // firestore: jest.fn(() => ({ /* mock Firestore methods */ })),
}));

jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    unauthorized: jest.fn(),
    notFound: jest.fn(),
    forbidden: jest.fn(),
    badRequest: jest.fn(),
  },
}));
jest.mock('../../models/db', () => ({ // Add this mock for the db module
  query: jest.fn(), // Mock the 'query' export if your models use it directly
  // Add mocks for any other exports from db.ts that might be used during import
}));
jest.mock('../../models/garmentModel');
jest.mock('../../models/imageModel');
jest.mock('../../services/labelingService');

import { Request, Response, NextFunction } from 'express';
import { garmentController } from '../../controllers/garmentController';
import { ApiError } from '../../utils/ApiError';
import { garmentModel } from '../../models/garmentModel';
import { imageModel } from '../../models/imageModel';
import { labelingService } from '../../services/labelingService';
import { CreateGarmentInput, GarmentResponse, GarmentMetadata } from '../../../../shared/src/schemas/garment';

describe('garmentController', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: NextFunction;

    beforeEach(() => {
        mockRequest = {
        body: {},
        user: { id: 'user123', email: 'test@example.com' } as any, // Mock user object
        };
        mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        };
        mockNext = jest.fn();
        jest.clearAllMocks(); // Clear all mocks before each test
    });

    describe('createGarment', () => {
        const mockCreateGarmentInput: CreateGarmentInput = {
        original_image_id: 'imageABC',
        mask_data: { // Corrected: Align with CreateGarmentSchema
            width: 100,
            height: 100,
            data: Array(100 * 100).fill(0).map((_, i) => i % 2) // Example numeric array
        },
        metadata: { // Corrected: Align with GarmentMetadata
            type: 'shirt', // Was 'Top'
            color: 'blue', // Was ['blue']
            pattern: 'striped',
            season: 'spring', // Was ['spring', 'summer']
            brand: 'FashionBrand',
            tags: ['casual', 'cotton']
        } as GarmentMetadata, // This assertion should now be accurate
        };

        const mockOriginalImage = {
        id: 'imageABC',
        user_id: 'user123',
        file_path: 'uploads/user123/original_image.jpg',
        status: 'new',
        created_at: new Date(),
        updated_at: new Date(),
        };

        const mockLabelingServiceResponse = {
        maskedImagePath: 'uploads/user123/masked_garment.png',
        maskPath: 'uploads/user123/mask_garment.png',
        };

        const mockDate = new Date();
        const mockCreatedGarment = { // Ensure this reflects corrected metadata
        id: 'garmentXYZ',
        user_id: 'user123',
        original_image_id: 'imageABC',
        file_path: mockLabelingServiceResponse.maskedImagePath,
        mask_path: mockLabelingServiceResponse.maskPath,
        metadata: { // Ensure this metadata matches the corrected structure
            type: 'shirt',
            color: 'blue',
            pattern: 'striped',
            season: 'spring',
            brand: 'FashionBrand',
            tags: ['casual', 'cotton']
        } as GarmentMetadata, // Add type assertion here
        created_at: mockDate,
        updated_at: mockDate,
        data_version: 1,
        };

        const expectedGarmentResponse: GarmentResponse = { // Ensure this reflects corrected metadata
        id: mockCreatedGarment.id,
        original_image_id: mockCreatedGarment.original_image_id,
        file_path: mockCreatedGarment.file_path,
        mask_path: mockCreatedGarment.mask_path,
        metadata: { // Ensure this metadata matches the corrected structure
            type: mockCreatedGarment.metadata.type, // This is 'shirt'
            color: mockCreatedGarment.metadata.color, // This is 'blue'
            pattern: mockCreatedGarment.metadata.pattern, // This is 'striped'
            season: mockCreatedGarment.metadata.season, // This is 'spring'
            brand: mockCreatedGarment.metadata.brand, // This is 'FashionBrand'
            tags: mockCreatedGarment.metadata.tags // This is ['casual', 'cotton']
        },
        created_at: mockCreatedGarment.created_at,
        updated_at: mockCreatedGarment.updated_at,
        data_version: mockCreatedGarment.data_version
        };

        test('should create a garment successfully and return 201 status', async () => {
            mockRequest.body = mockCreateGarmentInput;
            (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
            (labelingService.applyMaskToImage as jest.Mock).mockResolvedValue(mockLabelingServiceResponse);
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(undefined);
            (garmentModel.create as jest.Mock).mockResolvedValue(mockCreatedGarment);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            expect(imageModel.findById).toHaveBeenCalledWith(mockCreateGarmentInput.original_image_id);
            expect(labelingService.applyMaskToImage).toHaveBeenCalledWith(
                mockOriginalImage.file_path,
                mockCreateGarmentInput.mask_data
            );
            expect(imageModel.updateStatus).toHaveBeenCalledWith(mockCreateGarmentInput.original_image_id, 'labeled');
            expect(garmentModel.create).toHaveBeenCalledWith({
                user_id: 'user123',
                original_image_id: mockCreateGarmentInput.original_image_id,
                file_path: mockLabelingServiceResponse.maskedImagePath,
                mask_path: mockLabelingServiceResponse.maskPath,
                metadata: mockCreateGarmentInput.metadata,
            });
            expect(mockResponse.status).toHaveBeenCalledWith(201);
            expect(mockResponse.json).toHaveBeenCalledWith({
                status: 'success',
                data: { garment: expectedGarmentResponse },
            });
            expect(mockNext).not.toHaveBeenCalled();
        });

        test('should call next with ApiError.unauthorized if user is not authenticated', async () => {
            mockRequest.user = undefined;
            mockRequest.body = mockCreateGarmentInput;
            const unauthorizedError = new Error('User not authenticated');
            (ApiError.unauthorized as jest.Mock).mockReturnValue(unauthorizedError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            expect(ApiError.unauthorized).toHaveBeenCalledWith('User not authenticated');
            expect(mockNext).toHaveBeenCalledWith(unauthorizedError);
            expect(imageModel.findById).not.toHaveBeenCalled();
            expect(mockResponse.status).not.toHaveBeenCalled();
            expect(mockResponse.json).not.toHaveBeenCalled();
        });

        test('should call next with ApiError.notFound if original image is not found', async () => {
            mockRequest.body = mockCreateGarmentInput;
            (imageModel.findById as jest.Mock).mockResolvedValue(null);
            const notFoundError = new Error('Original image not found');
            (ApiError.notFound as jest.Mock).mockReturnValue(notFoundError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            expect(imageModel.findById).toHaveBeenCalledWith(mockCreateGarmentInput.original_image_id);
            expect(ApiError.notFound).toHaveBeenCalledWith('Original image not found');
            expect(mockNext).toHaveBeenCalledWith(notFoundError);
            expect(labelingService.applyMaskToImage).not.toHaveBeenCalled();
        });

        test('should call next with ApiError.forbidden if user does not own the original image', async () => {
            mockRequest.body = mockCreateGarmentInput;
            const imageOwnedByAnotherUser = { ...mockOriginalImage, user_id: 'anotherUser456' };
            (imageModel.findById as jest.Mock).mockResolvedValue(imageOwnedByAnotherUser);
            const forbiddenError = new Error('You do not have permission to use this image');
            (ApiError.forbidden as jest.Mock).mockReturnValue(forbiddenError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            expect(imageModel.findById).toHaveBeenCalledWith(mockCreateGarmentInput.original_image_id);
            expect(ApiError.forbidden).toHaveBeenCalledWith('You do not have permission to use this image');
            expect(mockNext).toHaveBeenCalledWith(forbiddenError);
            expect(labelingService.applyMaskToImage).not.toHaveBeenCalled();
        });

        test('should call next with error if labelingService.applyMaskToImage throws an error', async () => {
            mockRequest.body = mockCreateGarmentInput;
            (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
            const labelingError = new Error('Labeling service processing failed');
            (labelingService.applyMaskToImage as jest.Mock).mockRejectedValue(labelingError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            expect(labelingService.applyMaskToImage).toHaveBeenCalledWith(
                mockOriginalImage.file_path,
                mockCreateGarmentInput.mask_data
            );
            expect(mockNext).toHaveBeenCalledWith(labelingError);
            expect(imageModel.updateStatus).not.toHaveBeenCalled();
            expect(garmentModel.create).not.toHaveBeenCalled();
        });

        test('should call next with error if imageModel.updateStatus throws an error', async () => {
            mockRequest.body = mockCreateGarmentInput;
            (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
            (labelingService.applyMaskToImage as jest.Mock).mockResolvedValue(mockLabelingServiceResponse);
            const updateStatusError = new Error('Database error updating image status');
            (imageModel.updateStatus as jest.Mock).mockRejectedValue(updateStatusError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            expect(imageModel.updateStatus).toHaveBeenCalledWith(mockCreateGarmentInput.original_image_id, 'labeled');
            expect(mockNext).toHaveBeenCalledWith(updateStatusError);
            expect(garmentModel.create).not.toHaveBeenCalled();
        });

        test('should call next with error if garmentModel.create throws an error', async () => {
            mockRequest.body = mockCreateGarmentInput;
            (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
            (labelingService.applyMaskToImage as jest.Mock).mockResolvedValue(mockLabelingServiceResponse);
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(undefined);
            const createGarmentError = new Error('Database error creating garment');
            (garmentModel.create as jest.Mock).mockRejectedValue(createGarmentError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            expect(garmentModel.create).toHaveBeenCalledWith({
                user_id: 'user123',
                original_image_id: mockCreateGarmentInput.original_image_id,
                file_path: mockLabelingServiceResponse.maskedImagePath,
                mask_path: mockLabelingServiceResponse.maskPath,
                metadata: mockCreateGarmentInput.metadata,
            });
            expect(mockNext).toHaveBeenCalledWith(createGarmentError);
            expect(mockResponse.status).not.toHaveBeenCalled();
            expect(mockResponse.json).not.toHaveBeenCalled();
        });

        test('should handle invalid image status (not "new")', async () => {
            mockRequest.body = mockCreateGarmentInput;
            const processingImage = { 
                ...mockOriginalImage, 
                status: 'processing' 
            };
            (imageModel.findById as jest.Mock).mockResolvedValue(processingImage);
            
            const badRequestError = new Error('Image must be in "new" status before creating a garment');
            (ApiError.badRequest as jest.Mock).mockReturnValue(badRequestError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            // Verify the ApiError.badRequest is called with correct message
            expect(ApiError.badRequest).toHaveBeenCalledWith('Image must be in "new" status before creating a garment');
            // Verify the error is passed to next()
            expect(mockNext).toHaveBeenCalledWith(badRequestError);
            // Verify that processing stopped before reaching these methods
            expect(labelingService.applyMaskToImage).not.toHaveBeenCalled();
            expect(imageModel.updateStatus).not.toHaveBeenCalled();
            expect(garmentModel.create).not.toHaveBeenCalled();
        });

        test('should handle already processed images (status is already "labeled")', async () => {
            mockRequest.body = mockCreateGarmentInput;
            const alreadyLabeledImage = { 
                ...mockOriginalImage, 
                status: 'labeled'
            };
            (imageModel.findById as jest.Mock).mockResolvedValue(alreadyLabeledImage);
            
            const badRequestError = new Error('This image has already been used to create a garment');
            (ApiError.badRequest as jest.Mock).mockReturnValue(badRequestError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            // Verify the ApiError.badRequest is called with correct message
            expect(ApiError.badRequest).toHaveBeenCalledWith('This image has already been used to create a garment');
            // Verify the error is passed to next()
            expect(mockNext).toHaveBeenCalledWith(badRequestError);
            // Verify that processing stopped before reaching these methods
            expect(labelingService.applyMaskToImage).not.toHaveBeenCalled();
            expect(imageModel.updateStatus).not.toHaveBeenCalled();
            expect(garmentModel.create).not.toHaveBeenCalled();
        });
        
        /* Should be moved to the validation middleware
        test('should handle invalid mask_data (empty data array)', async () => {
            const invalidInput = {
                ...mockCreateGarmentInput,
                mask_data: {
                    width: 100,
                    height: 100,
                    data: [] // Empty data array
                }
            };
            mockRequest.body = invalidInput;
            (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
            
            const badRequestError = new Error('Invalid mask data: data array cannot be empty');
            (ApiError.badRequest as jest.Mock).mockReturnValue(badRequestError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            // Verify the ApiError.badRequest is called with correct message
            expect(ApiError.badRequest).toHaveBeenCalledWith('Invalid mask data: data array cannot be empty');
            // Verify the error is passed to next()
            expect(mockNext).toHaveBeenCalledWith(badRequestError);
            // Verify that processing stopped before reaching these methods
            expect(labelingService.applyMaskToImage).not.toHaveBeenCalled();
            expect(imageModel.updateStatus).not.toHaveBeenCalled();
            expect(garmentModel.create).not.toHaveBeenCalled();
        });

        test('should handle mask_data with mismatched dimensions', async () => {
            const invalidInput = {
                ...mockCreateGarmentInput,
                mask_data: {
                    width: 100,
                    height: 100,
                    data: Array(50).fill(0) // Data array length doesn't match width*height
                }
            };
            mockRequest.body = invalidInput;
            (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
            
            const badRequestError = new Error('Invalid mask data: data array length does not match width*height');
            (ApiError.badRequest as jest.Mock).mockReturnValue(badRequestError);

            await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

            // Verify the ApiError.badRequest is called with correct message
            expect(ApiError.badRequest).toHaveBeenCalledWith('Invalid mask data: data array length does not match width*height');
            // Verify the error is passed to next()
            expect(mockNext).toHaveBeenCalledWith(badRequestError);
            // Verify that processing stopped before reaching these methods
            expect(labelingService.applyMaskToImage).not.toHaveBeenCalled();
            expect(imageModel.updateStatus).not.toHaveBeenCalled();
            expect(garmentModel.create).not.toHaveBeenCalled();
        });
        */
    });
});