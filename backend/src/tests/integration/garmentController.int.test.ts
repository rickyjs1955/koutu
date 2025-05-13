// Mock dependencies before importing
jest.mock('../../models/garmentModel', () => ({
  garmentModel: {
    findByUserId: jest.fn(),
    findById: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    updateStatus: jest.fn(),
    delete: jest.fn(),
    updateMetadata: jest.fn()
  }
}));

jest.mock('../../config/firebase', () => ({
  admin: {
    initializeApp: jest.fn(),
    storage: jest.fn(),
    auth: jest.fn()
  }
}));

// Don't interact with the actual database 
jest.mock('../../models/db', () => ({
  pool: {
    query: jest.fn(),
    end: jest.fn()
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
import { garmentModel } from '../../models/garmentModel';
import { ApiError } from '../../utils/ApiError';
import { imageModel } from '../../models/imageModel';
import { labelingService } from '../../services/labelingService';
import { CreateGarmentInput } from '../../../../shared/src/schemas/garment';


describe('Garment Controller Integration Tests', () => {
  // No need for database setup/teardown with mocks
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getGarments', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;
    
    beforeEach(() => {
      mockRequest = {
        user: { 
            id: 'test-user-id',
            email: 'test@example.com'
        },
        params: { id: 'garment-1' },
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

    it('should return garment for owner', async () => {
    const garment = { id: 'garment-1', user_id: 'test-user-id' };
    (garmentModel.findById as jest.Mock).mockResolvedValue(garment);

    await garmentController.getGarment(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(garmentModel.findById).toHaveBeenCalledWith('garment-1');
    expect(mockResponse.status).toHaveBeenCalledWith(200);
    expect(mockResponse.json).toHaveBeenCalledWith({
      status: 'success',
      data: { garment }
    });
    expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 404 if garment not found', async () => {
    (garmentModel.findById as jest.Mock).mockResolvedValue(null);

    await garmentController.getGarment(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalledWith(
      expect.objectContaining({ message: 'Garment not found', statusCode: 404 })
    );
    });

    it('should return 403 if user does not own garment', async () => {
      const garment = { id: 'garment-1', user_id: 'other-user' };
      (garmentModel.findById as jest.Mock).mockResolvedValue(garment);

      await garmentController.getGarment(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'You do not have permission to access this garment', statusCode: 403 })
      );
    });

    it('should return 401 if unauthenticated', async () => {
      mockRequest.user = undefined;

      await garmentController.getGarment(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'User not authenticated', statusCode: 401 })
      );
    });
  });  

  describe('createGarment', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;
    const userId = 'test-user-id';
    const imageId = 'original-image-id-1';
    const mockMaskData = { width: 100, height: 100, data: [0, 1, 0, 1] }; // Proper mask data format
    const mockMetadata = { type: 'shirt' as const, color: 'blue', season: 'summer' as const };

    beforeEach(() => {
      mockRequest = {
        user: { id: userId, email: 'test@example.com' },
        body: {
          original_image_id: imageId,
          mask_data: mockMaskData,
          metadata: mockMetadata,
        } as CreateGarmentInput,
      };
      mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      mockNext = jest.fn();
    });

    it('should create a garment successfully', async () => {
      const mockOriginalImage = { id: imageId, user_id: userId, file_path: '/path/to/original.jpg', status: 'new' };
      const mockProcessedPaths = { maskedImagePath: '/path/to/masked.jpg', maskPath: '/path/to/mask.png' };
      
      // This is the metadata from the request body
      const requestBodyMetadata = mockRequest.body.metadata;

      // This is what we expect the garmentModel.create to be called with (relevant parts)
      const expectedPayloadToCreateModel = {
        user_id: userId,
        original_image_id: imageId,
        file_path: mockProcessedPaths.maskedImagePath,
        mask_path: mockProcessedPaths.maskPath,
        metadata: requestBodyMetadata, // The metadata from the request
      };

      // This is what the garmentModel.create mock will return.
      // It should reflect the structure that ends up in the response.
      // Note: No user_id here if GarmentResponseSchema omits it.
      // Metadata includes optional fields as undefined if that's the behavior.
      const garmentReturnedByModelMock = {
        id: 'new-garment-id',
        original_image_id: imageId, // No user_id if not in GarmentResponseSchema
        file_path: mockProcessedPaths.maskedImagePath,
        mask_path: mockProcessedPaths.maskPath,
        metadata: {
          type: requestBodyMetadata.type,
          color: requestBodyMetadata.color,
          season: requestBodyMetadata.season,
          pattern: requestBodyMetadata.pattern || undefined, // Ensure undefined if not present
          brand: requestBodyMetadata.brand || undefined,   // Ensure undefined if not present
          tags: requestBodyMetadata.tags || [],          // Ensure tags is an array
        },
        created_at: new Date(), // Actual date object
        updated_at: new Date(), // Actual date object
        data_version: 1,
      };

      (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
      (labelingService.applyMaskToImage as jest.Mock).mockResolvedValue(mockProcessedPaths);
      (imageModel.updateStatus as jest.Mock).mockResolvedValue(undefined);
      (garmentModel.create as jest.Mock).mockResolvedValue(garmentReturnedByModelMock);

      await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);

      expect(imageModel.findById).toHaveBeenCalledWith(imageId);
      expect(labelingService.applyMaskToImage).toHaveBeenCalledWith(mockOriginalImage.file_path, mockMaskData);
      expect(imageModel.updateStatus).toHaveBeenCalledWith(imageId, 'labeled');
      expect(garmentModel.create).toHaveBeenCalledWith(expectedPayloadToCreateModel);
      
      // This is what we expect the final JSON response's garment object to look like.
      const expectedGarmentInJsonResponse = {
        id: 'new-garment-id',
        original_image_id: imageId, // No user_id
        file_path: mockProcessedPaths.maskedImagePath,
        mask_path: mockProcessedPaths.maskPath,
        metadata: {
          type: requestBodyMetadata.type,
          color: requestBodyMetadata.color,
          season: requestBodyMetadata.season,
          pattern: requestBodyMetadata.pattern || undefined,
          brand: requestBodyMetadata.brand || undefined,
          tags: requestBodyMetadata.tags || [],
        },
        created_at: expect.any(Date), // Use matcher for dates
        updated_at: expect.any(Date), // Use matcher for dates
        data_version: 1,
      };

      expect(mockResponse.status).toHaveBeenCalledWith(201);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'success',
        data: { garment: expectedGarmentInJsonResponse },
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 if user is not authenticated', async () => {
      mockRequest.user = undefined;
      await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 401, message: 'User not authenticated' }));
    });

    it('should return 404 if original image not found', async () => {
      (imageModel.findById as jest.Mock).mockResolvedValue(null);
      await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 404, message: 'Original image not found' }));
    });

    it('should return 403 if user does not own the image', async () => {
      const mockOriginalImage = { id: imageId, user_id: 'another-user-id', file_path: '/path/to/original.jpg', status: 'new' };
      (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
      await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 403, message: 'You do not have permission to use this image' }));
    });

    it('should return 400 if image has already been used (status labeled)', async () => {
      const mockOriginalImage = { id: imageId, user_id: userId, file_path: '/path/to/original.jpg', status: 'labeled' };
      (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
      await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 400, message: 'This image has already been used to create a garment' }));
    });

    it('should return 400 if image is not in "new" status (e.g., processing)', async () => {
      const mockOriginalImage = { id: imageId, user_id: userId, file_path: '/path/to/original.jpg', status: 'processing' };
      (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
      await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 400, message: 'Image must be in "new" status before creating a garment' }));
    });

    it('should pass error to next if labelingService fails', async () => {
      const mockOriginalImage = { id: imageId, user_id: userId, file_path: '/path/to/original.jpg', status: 'new' };
      const serviceError = new Error('Labeling service failed');
      (imageModel.findById as jest.Mock).mockResolvedValue(mockOriginalImage);
      (labelingService.applyMaskToImage as jest.Mock).mockRejectedValue(serviceError);
      await garmentController.createGarment(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(serviceError);
    });
  });

  describe('updateGarmentMetadata', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;
    const userId = 'test-user-id';
    const garmentId = 'garment-to-update-id';
    const initialMetadata = { type: 'shirt', color: 'blue', season: 'summer', brand: 'OldBrand', tags: ['casual'] };
    const updatedMetadataPayload = { type: 'shirt', color: 'red', season: 'autumn', brand: 'NewBrand', tags: ['formal', 'office'] };

    beforeEach(() => {
      mockRequest = {
        user: { id: userId, email: 'test@example.com' },
        params: { id: garmentId },
        body: updatedMetadataPayload,
      };
      mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      mockNext = jest.fn();
    });

    it('should update garment metadata successfully', async () => {
      const mockExistingGarment = { id: garmentId, user_id: userId, metadata: initialMetadata };
      const mockUpdatedGarment = { ...mockExistingGarment, metadata: updatedMetadataPayload, updated_at: new Date() };

      (garmentModel.findById as jest.Mock).mockResolvedValue(mockExistingGarment);
      (garmentModel.updateMetadata as jest.Mock).mockResolvedValue(mockUpdatedGarment);

      await garmentController.updateGarmentMetadata(mockRequest as Request, mockResponse as Response, mockNext);

      expect(garmentModel.findById).toHaveBeenCalledWith(garmentId);
      expect(garmentModel.updateMetadata).toHaveBeenCalledWith(garmentId, updatedMetadataPayload);
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'success',
        data: { garment: mockUpdatedGarment },
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 401 if user is not authenticated', async () => {
      mockRequest.user = undefined;
      await garmentController.updateGarmentMetadata(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 401, message: 'User not authenticated' }));
    });

    it('should return 404 if garment not found', async () => {
      (garmentModel.findById as jest.Mock).mockResolvedValue(null);
      await garmentController.updateGarmentMetadata(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 404, message: 'Garment not found' }));
    });

    it('should return 403 if user does not own the garment', async () => {
      const mockExistingGarment = { id: garmentId, user_id: 'another-user-id', metadata: initialMetadata };
      (garmentModel.findById as jest.Mock).mockResolvedValue(mockExistingGarment);
      await garmentController.updateGarmentMetadata(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 403, message: 'You do not have permission to update this garment' }));
    });

    it('should pass error to next if garmentModel.updateMetadata fails', async () => {
      const mockExistingGarment = { id: garmentId, user_id: userId, metadata: initialMetadata };
      const dbError = new Error('Database update failed');
      (garmentModel.findById as jest.Mock).mockResolvedValue(mockExistingGarment);
      (garmentModel.updateMetadata as jest.Mock).mockRejectedValue(dbError);
      await garmentController.updateGarmentMetadata(mockRequest as Request, mockResponse as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(dbError);
    });
  });

  describe('deleteGarment', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;

    beforeEach(() => {
      mockRequest = {
        user: { id: 'test-user-id', email: 'test@example.com' },
        params: { id: 'garment-1' }
      };
      mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      };
      mockNext = jest.fn();
    });

    it('should delete garment for owner', async () => {
      const garment = { id: 'garment-1', user_id: 'test-user-id' };
      (garmentModel.findById as jest.Mock).mockResolvedValue(garment);
      (garmentModel.delete as jest.Mock).mockResolvedValue(undefined);

      await garmentController.deleteGarment(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(garmentModel.findById).toHaveBeenCalledWith('garment-1');
      expect(garmentModel.delete).toHaveBeenCalledWith('garment-1');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'success',
        message: 'Garment deleted successfully'
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 404 if garment not found', async () => {
      (garmentModel.findById as jest.Mock).mockResolvedValue(null);

      await garmentController.deleteGarment(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'Garment not found', statusCode: 404 })
      );
    });

    it('should return 403 if user does not own garment', async () => {
      const garment = { id: 'garment-1', user_id: 'other-user' };
      (garmentModel.findById as jest.Mock).mockResolvedValue(garment);

      await garmentController.deleteGarment(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'You do not have permission to delete this garment', statusCode: 403 })
      );
    });

    it('should return 401 if unauthenticated', async () => {
      mockRequest.user = undefined;

      await garmentController.deleteGarment(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({ message: 'User not authenticated', statusCode: 401 })
      );
    });
  });
});