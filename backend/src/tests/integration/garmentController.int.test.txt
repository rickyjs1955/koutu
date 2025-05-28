// filepath: /backend/src/tests/integration/garmentController.int.test.ts
/**
 * Integration Test Suite for Garment Controller
 *
 * This test suite validates the behavior of the garmentController methods
 * using a hybrid approach. The database and external services are mocked,
 * allowing us to focus on the controller logic, including:
 *
 * 1. Authentication and authorization checks
 * 2. Business rule enforcement
 * 3. Proper interaction with mocked models and services
 * 4. Error handling and response formatting
 *
 * Covered Methods:
 * - getGarments: Retrieves all garments for an authenticated user.
 * - getGarment: Fetches a specific garment with ownership validation.
 * - createGarment: Handles garment creation, including image processing and metadata validation.
 * - updateGarmentMetadata: Updates garment metadata with ownership checks.
 * - deleteGarment: Deletes a garment with proper ownership validation.
 *
 * This suite is designed to be adaptable for future true integration tests
 * with a real database, ensuring comprehensive test coverage.
 */

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
        { 
          id: 'garment-1', 
          user_id: 'test-user-id',
          original_image_id: 'image-1',
          file_path: '/actual/file/path1.jpg',
          mask_path: '/actual/mask/path1.png',
          metadata: { type: 'shirt', color: 'blue' },
          created_at: new Date(),
          updated_at: new Date(),
          data_version: 1
        },
        { 
          id: 'garment-2', 
          user_id: 'test-user-id',
          original_image_id: 'image-2',
          file_path: '/actual/file/path2.jpg',
          mask_path: '/actual/mask/path2.png',
          metadata: { 
            type: 'pants', 
            color: 'black',
            pattern: undefined,  
            season: undefined,
            brand: undefined,
            tags: [] 
           },
          created_at: new Date(),
          updated_at: new Date(),
          data_version: 1
        }
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
          garments: mockGarments.map(g => ({
            id: g.id,
            original_image_id: g.original_image_id,
            file_path: `/api/garments/${g.id}/image`,
            mask_path: `/api/garments/${g.id}/mask`,
            metadata: {
              type: g.metadata?.type,
              color: g.metadata?.color,
              pattern: g.metadata?.pattern,
              season: g.metadata?.season,
              brand: g.metadata?.brand,
              tags: Array.isArray(g.metadata?.tags) ? g.metadata.tags : []
            },
            created_at: g.created_at,
            updated_at: g.updated_at,
            data_version: g.data_version
          })),
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
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'An error occurred while retrieving garments',
          statusCode: 500
        })
      );
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
      const garment = { 
        id: 'garment-1', 
        user_id: 'test-user-id',
        original_image_id: 'image-1',
        file_path: '/actual/file/path.jpg',
        mask_path: '/actual/mask/path.png',
        metadata: { 
          type: 'shirt', 
          color: 'blue',
          pattern: undefined,  
          season: undefined,
          brand: undefined, 
          tags: [] 
        },
        created_at: new Date(),
        updated_at: new Date(),
        data_version: 1
      };
      (garmentModel.findById as jest.Mock).mockResolvedValue(garment);
      (imageModel.findById as jest.Mock).mockResolvedValue({
        id: 'image-1',
        user_id: 'test-user-id'
      });

      await garmentController.getGarment(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(garmentModel.findById).toHaveBeenCalledWith('garment-1');
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'success',
        data: { 
          garment: {
            id: garment.id,
            // user_id: garment.user_id, // DTO omits user_id, so remove from expectation
            original_image_id: garment.original_image_id,
            file_path: `/api/garments/${garment.id}/image`,
            mask_path: `/api/garments/${garment.id}/mask`,
            metadata: {
              type: garment.metadata?.type,
              color: garment.metadata?.color,
              pattern: garment.metadata?.pattern,
              season: garment.metadata?.season,
              brand: garment.metadata?.brand,
              tags: Array.isArray(garment.metadata?.tags) ? garment.metadata.tags : []
            },
            created_at: garment.created_at,
            updated_at: garment.updated_at,
            data_version: garment.data_version
          }
        }
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
        metadata: {
          type: requestBodyMetadata.type,
          color: requestBodyMetadata.color,
          pattern: requestBodyMetadata.pattern,
          season: requestBodyMetadata.season,
          brand: requestBodyMetadata.brand,
          tags: Array.isArray(requestBodyMetadata.tags) ? requestBodyMetadata.tags : []
        }
      };

      // This is what the garmentModel.create mock will return.
      // It should reflect the structure that ends up in the response.
      // Note: No user_id here if GarmentResponseSchema omits it.
      // Metadata includes optional fields as undefined if that's the behavior.
      const garmentReturnedByModelMock = {
        id: 'new-garment-id',
        user_id: userId,
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
        original_image_id: imageId,
        // Change to API routes format
        file_path: `/api/garments/new-garment-id/image`,
        mask_path: `/api/garments/new-garment-id/mask`,
        metadata: {
          type: requestBodyMetadata.type,
          color: requestBodyMetadata.color,
          season: requestBodyMetadata.season,
          pattern: requestBodyMetadata.pattern || undefined,
          brand: requestBodyMetadata.brand || undefined,
          tags: requestBodyMetadata.tags || [],
        },
        created_at: expect.any(Date),
        updated_at: expect.any(Date),
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
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'An error occurred while creating the garment',
          statusCode: 500
        })
      );
    });
  });

  describe('updateGarmentMetadata', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;
    const userId = 'test-user-id';
    const garmentId = 'garment-to-update-id';
    const initialMetadata = { type: 'shirt', color: 'blue', season: 'summer', brand: 'OldBrand', tags: ['casual'] };
    const updatedMetadataPayload = { 
      type: 'shirt', 
      color: 'red', 
      pattern: 'striped',
      season: 'autumn', 
      brand: 'NewBrand', 
      tags: ['formal', 'office'] };

    beforeEach(() => {
      mockRequest = {
        user: { id: userId, email: 'test@example.com' },
        params: { id: garmentId },
        body: { metadata: updatedMetadataPayload },
      };
      mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      mockNext = jest.fn();
    });

    it('should update garment metadata successfully', async () => {
      const mockExistingGarment = { id: garmentId, user_id: userId, metadata: initialMetadata };
      const mockUpdatedGarment = { 
        ...mockExistingGarment, 
        metadata: updatedMetadataPayload, 
        original_image_id: 'image-1',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png',
        created_at: new Date(),
        updated_at: new Date(),
        data_version: 1
      };

      (garmentModel.findById as jest.Mock).mockResolvedValue(mockExistingGarment);
      (garmentModel.updateMetadata as jest.Mock).mockResolvedValue(mockUpdatedGarment);

      await garmentController.updateGarmentMetadata(mockRequest as Request, mockResponse as Response, mockNext);

      expect(garmentModel.findById).toHaveBeenCalledWith(garmentId);
      expect(garmentModel.updateMetadata).toHaveBeenCalledWith(
        garmentId, 
        { 
          metadata: {
            type: updatedMetadataPayload.type,
            color: updatedMetadataPayload.color,
            pattern: updatedMetadataPayload.pattern,
            season: updatedMetadataPayload.season,
            brand: updatedMetadataPayload.brand,
            tags: Array.isArray(updatedMetadataPayload.tags) ? updatedMetadataPayload.tags : []
          }
        }
      );
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        status: 'success',
        data: { 
          garment: {
            id: mockUpdatedGarment.id,
            original_image_id: mockUpdatedGarment.original_image_id,
            file_path: `/api/garments/${mockUpdatedGarment.id}/image`,
            mask_path: `/api/garments/${mockUpdatedGarment.id}/mask`,
            metadata: {
              type: mockUpdatedGarment.metadata?.type,
              color: mockUpdatedGarment.metadata?.color,
              pattern: mockUpdatedGarment.metadata?.pattern,
              season: mockUpdatedGarment.metadata?.season,
              brand: mockUpdatedGarment.metadata?.brand,
              tags: Array.isArray(mockUpdatedGarment.metadata?.tags) ? mockUpdatedGarment.metadata.tags : []
            },
            created_at: mockUpdatedGarment.created_at,
            updated_at: mockUpdatedGarment.updated_at,
            data_version: mockUpdatedGarment.data_version
          }
        }
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
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'An error occurred while updating the garment metadata',
          statusCode: 500
        })
      );
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
      (garmentModel.delete as jest.Mock).mockResolvedValue(true);

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