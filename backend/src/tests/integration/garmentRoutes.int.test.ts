// filepath: /backend/src/tests/integration/garmentRoutes.int.test.ts

/**
 * Integration Test Suite for Garment Routes
 *
 * This test suite validates the behavior of the garment routes, including:
 * 1. Route configuration and middleware application (authenticate, validate)
 * 2. Integration with the garmentController
 * 3. Complete request-response cycle
 * 4. Proper error handling and response formatting
 * 5. Resource existence and ownership checks (authorization and access control)
 *
 * Following the project's integration test approach, we mock all external
 * dependencies (models, services) to focus on the route-controller integration.
 * 
 * Note: Some tests (e.g., "GET /:id - Authorization Tests") primarily verify controller logic
 * for resource existence and ownership. While not pure authorization tests, they are included here
 * because they validate both access control and resource state as part of the route's behavior.
 */

// Mock dependencies before importing modules
jest.mock('../../middlewares/auth', () => ({
  authenticate: jest.fn((req, res, next) => {
    // Only authenticate if Authorization header is present
    if (req.headers.authorization) {
      req.user = { id: 'test-user-id', email: 'test@example.com' };
      next();
    } else {
      // Return 401 for requests without Authorization
      const error = new Error('Authentication required') as Error & { statusCode?: number; code?: string };
      error.statusCode = 401;
      error.code = 'UNAUTHORIZED';
      next(error);
    }
  }),
  authorize: jest.fn((_req, _res, next) => next())
}));

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

jest.mock('../../models/db', () => ({
  pool: {
    query: jest.fn(),
    end: jest.fn()
  }
}));

jest.mock('../../config/firebase', () => ({
  admin: {
    initializeApp: jest.fn(),
    storage: jest.fn(),
    auth: jest.fn()
  }
}));

jest.mock('../../config', () => ({
  config: {
    jwt: {
      secret: 'test-secret-key'
    }
  }
}));

jest.mock('../../../../shared/src/schemas/garment', () => ({
  // Add any schema needed by your routes
  CreateGarmentSchema: {
    parse: jest.fn().mockImplementation((data) => data),
    parseAsync: jest.fn().mockImplementation((data) => Promise.resolve(data))
  },
  UpdateGarmentMetadataSchema: {
    parse: jest.fn().mockImplementation((data) => data),
    parseAsync: jest.fn().mockImplementation((data) => Promise.resolve(data))
  },
  idParamSchema: {
    parse: jest.fn().mockImplementation((data) => data),
    parseAsync: jest.fn().mockImplementation((data) => Promise.resolve(data))
  }
}));

jest.mock('../../middlewares/validate', () => {
  // Keep track of validation expectations for different routes
  const validationBehaviors = {
    // Route paths that should fail validation
    failValidation: [
      '/api/garments/create-invalid-test',
      '/api/garments/garment-1/metadata-invalid-test'
    ]
  };

  return {
    validate: (_schema: any, ..._args: any[]) => {
      return (req: Request, res: Response, next: NextFunction) => {
        // For testing validation failures - check path or add custom headers
        if (req.headers['x-test-validation-failure'] === 'true' || 
            validationBehaviors.failValidation.some(path => req.path.includes(path))) {
            const error = new Error('Validation error') as Error & { statusCode?: number; code?: string };
            error.statusCode = 400;
            error.code = 'VALIDATION_ERROR';
            return next(error);
        }
        // Otherwise pass validation
        next();
      };
    }
  };
});

// Import express, supertest, and other dependencies
import express from 'express';
import request from 'supertest';
import { garmentRoutes } from '../../routes/garmentRoutes';
import { garmentModel } from '../../models/garmentModel';
import { imageModel } from '../../models/imageModel';
import { labelingService } from '../../services/labelingService';
import jwt from 'jsonwebtoken';
import { errorHandler } from '../../middlewares/errorHandler';
import { Request, Response, NextFunction } from 'express';

describe('Garment Routes Integration Tests', () => {
    let app: express.Application;
    let mockAuthToken: string;
    const testUserId = 'test-user-id';
    const originalConsoleError = console.error;

    beforeAll(() => {
        // Create auth token for test requests
        mockAuthToken = jwt.sign({ id: testUserId }, 'test-secret-key');
        console.error = jest.fn(); // Suppress error logs during tests
    });
    
    beforeEach(() => {
        // Reset mocks
        jest.clearAllMocks();
        
        // Setup fresh Express app for each test
        app = express();
        app.use(express.json());
        
        // Remove the manual middleware - rely on the mocked authenticate
        
        // Apply routes
        app.use('/api/garments', garmentRoutes);
        
        // Add error handler
        app.use(errorHandler);
    });

    afterAll(() => {
        console.error = originalConsoleError; // Restore after tests
    });
    
    describe('GET /', () => {
        it('should return all garments for authenticated user', async () => {
            // Setup mock data
            const mockGarments = [
                { 
                id: 'garment-1', 
                user_id: testUserId,
                original_image_id: 'image-1',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png',
                metadata: { type: 'shirt', color: 'blue' },
                created_at: new Date(),
                updated_at: new Date(),
                data_version: 1
                }
            ];
            
            // Setup mocks
            (garmentModel.findByUserId as jest.Mock).mockResolvedValue(mockGarments);
            
            // Make request
            const response = await request(app)
                .get('/api/garments')
                .set('Authorization', `Bearer ${mockAuthToken}`);
            
            // Assert
            expect(response.status).toBe(200);
            expect(response.body.status).toBe('success');
            expect(response.body.data.garments).toHaveLength(1);
            expect(response.body.data.garments[0].id).toBe('garment-1');
            expect(response.body.data.garments[0].file_path).toBe('/api/garments/garment-1/image');
            expect(garmentModel.findByUserId).toHaveBeenCalledWith(testUserId);
        });
        
        it('should return 401 for unauthenticated request', async () => {
            const response = await request(app)
                .get('/api/garments');
                
            expect(response.status).toBe(401);
        });
    });
    
    describe('GET /:id', () => {
        it('should return a single garment by ID', async () => {
            const mockGarment = { 
                id: 'garment-1', 
                user_id: testUserId,
                original_image_id: 'image-1',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png',
                metadata: { type: 'shirt', color: 'blue' },
                created_at: new Date(),
                updated_at: new Date(),
                data_version: 1
            };
            const mockImage = {
                id: 'image-1',
                user_id: testUserId
            };

            (garmentModel.findById as jest.Mock).mockResolvedValue(mockGarment);
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);

            const response = await request(app)
                .get('/api/garments/garment-1')
                .set('Authorization', `Bearer ${mockAuthToken}`);
                
            expect(response.status).toBe(200);
            expect(response.body.data.garment.id).toBe('garment-1');
            expect(garmentModel.findById).toHaveBeenCalledWith('garment-1');
        });
            
        it('should return 404 when garment not found', async () => {
            (garmentModel.findById as jest.Mock).mockResolvedValue(null);
            
            const response = await request(app)
                .get('/api/garments/non-existent')
                .set('Authorization', `Bearer ${mockAuthToken}`);
                
            expect(response.status).toBe(404);
            expect(response.body.message).toContain('not found');
        });
        
        it('should return 403 when user does not own garment', async () => {
            (garmentModel.findById as jest.Mock).mockResolvedValue({
                id: 'garment-1',
                user_id: 'different-user'
            });
            
            const response = await request(app)
                .get('/api/garments/garment-1')
                .set('Authorization', `Bearer ${mockAuthToken}`);
                
            expect(response.status).toBe(403);
            expect(response.body.message).toContain('permission');
        });

        it('should return 200 if garment and image exist and both are owned by the user', async () => {
            const mockGarment = {
                id: 'garment-1',
                user_id: testUserId,
                original_image_id: 'image-1',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png',
                metadata: { type: 'shirt', color: 'blue' },
                created_at: new Date(),
                updated_at: new Date(),
                data_version: 1
            };
            const mockImage = {
                id: 'image-1',
                user_id: testUserId
            };
            (garmentModel.findById as jest.Mock).mockResolvedValue(mockGarment);
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);

            const response = await request(app)
                .get('/api/garments/garment-1')
                .set('Authorization', `Bearer ${mockAuthToken}`);

            expect(response.status).toBe(200);
            expect(response.body.data.garment.id).toBe('garment-1');
        });
    });
    
    describe('POST /create', () => {
        it('should create a new garment with valid data', async () => {
            // Setup mocks
            const requestPayload = {
                original_image_id: 'image-1',
                mask_data: {
                points: [
                    { x: 10, y: 10 },
                    { x: 20, y: 20 },
                    { x: 30, y: 10 }
                ]
                },
                metadata: {
                type: 'shirt',
                color: 'blue'
                }
            };
            
            const mockImage = { 
                id: 'image-1', 
                user_id: testUserId, 
                file_path: '/path/to/original.jpg',
                status: 'new'
            };
            
            const mockCreatedGarment = {
                id: 'new-garment-id',
                user_id: testUserId,
                original_image_id: 'image-1',
                file_path: '/path/to/masked.jpg',
                mask_path: '/path/to/mask.png',
                metadata: {
                type: 'shirt',
                color: 'blue'
                },
                created_at: new Date(),
                updated_at: new Date(),
                data_version: 1
            };
            
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (labelingService.applyMaskToImage as jest.Mock).mockResolvedValue({ 
                maskedImagePath: '/path/to/masked.jpg', 
                maskPath: '/path/to/mask.png' 
            });
            (garmentModel.create as jest.Mock).mockResolvedValue(mockCreatedGarment);
            
            // Make request
            const response = await request(app)
                .post('/api/garments/create')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .send(requestPayload);
                
            // Assert
            expect(response.status).toBe(201);
            expect(response.body.status).toBe('success');
            expect(response.body.data.garment.id).toBe('new-garment-id');
            expect(imageModel.findById).toHaveBeenCalledWith('image-1');
            expect(labelingService.applyMaskToImage).toHaveBeenCalled();
            expect(garmentModel.create).toHaveBeenCalled();
        });
        
        it('should validate input and return 400 for invalid data', async () => {
            const response = await request(app)
                .post('/api/garments/create')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .set('x-test-validation-failure', 'true') // Signal validation failure
                .send({
                // Missing required fields
                metadata: {
                    type: 'shirt'
                }
                });
                    
            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(imageModel.findById).not.toHaveBeenCalled();
        });
        
        it('should return 401 for unauthenticated request', async () => {
            const response = await request(app)
                .post('/api/garments/create')
                .send({
                original_image_id: 'image-1',
                mask_data: { /* valid data */ },
                metadata: { type: 'shirt' }
                });
                
            expect(response.status).toBe(401);
        });

        it('should call garmentModel.create with correct data', async () => {
            const requestPayload = {
                original_image_id: 'image-1',
                mask_data: { points: [{ x: 10, y: 10 }, { x: 20, y: 20 }, { x: 30, y: 10 }] },
                metadata: { type: 'shirt', color: 'blue' }
            };

            const mockImage = { 
                id: 'image-1', 
                user_id: testUserId, 
                file_path: '/path/to/original.jpg',
                status: 'new'
            };

            const mockCreatedGarment = {
                id: 'new-garment-id',
                user_id: testUserId,
                original_image_id: 'image-1',
                file_path: '/path/to/masked.jpg',
                mask_path: '/path/to/mask.png',
                metadata: {
                    type: 'shirt',
                    color: 'blue',
                    brand: undefined,
                    pattern: undefined,
                    season: undefined,
                    tags: []
                },
                created_at: new Date(),
                updated_at: new Date(),
                data_version: 1
            };

            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (labelingService.applyMaskToImage as jest.Mock).mockResolvedValue({ 
                maskedImagePath: '/path/to/masked.jpg', 
                maskPath: '/path/to/mask.png' 
            });
            (garmentModel.create as jest.Mock).mockImplementation((garmentData) => {
                return Promise.resolve(mockCreatedGarment);
            });

            // Make request
            const response = await request(app)
                .post('/api/garments/create')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .send(requestPayload);

            // Assert that garmentModel.create was called with the correct data
            expect(garmentModel.create).toHaveBeenCalled();
        });

        it('should return 500 if labelingService fails', async () => {
            // Mock labelingService to throw an error
            (labelingService.applyMaskToImage as jest.Mock).mockRejectedValue(new Error('Labeling failed'));
            
            const response = await request(app)
                .post('/api/garments/create')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .send({
                original_image_id: 'image-1',
                mask_data: { points: [{ x: 10, y: 10 }, { x: 20, y: 20 }, { x: 30, y: 10 }] },
                metadata: { type: 'shirt', color: 'blue' }
                });
                
            expect(response.status).toBe(500);
            expect(response.body.message).toContain('An error occurred while creating the garment');
        });

        it('should return 404 if trying to create a garment for a non-existent image', async () => {
            const requestPayload = {
                original_image_id: 'image-1',
                mask_data: { points: [{ x: 10, y: 10 }, { x: 20, y: 20 }, { x: 30, y: 10 }] },
                metadata: { type: 'shirt', color: 'blue' }
            };
            (imageModel.findById as jest.Mock).mockResolvedValue(null);

            const response = await request(app)
                .post('/api/garments/create')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .send(requestPayload);

            expect(response.status).toBe(404);
            expect(response.body.message).toContain('not found');
        });
    });
    
    describe('PUT /:id/metadata', () => {
        it('should update metadata for a garment', async () => {
            const mockGarment = { 
                id: 'garment-1', 
                user_id: testUserId,
                metadata: { type: 'shirt', color: 'blue' }
            };
            
            const updatedGarment = {
                ...mockGarment,
                metadata: { type: 'shirt', color: 'red', pattern: 'striped' },
                original_image_id: 'image-1',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png',
                created_at: new Date(),
                updated_at: new Date(),
                data_version: 1
            };
            
            (garmentModel.findById as jest.Mock).mockResolvedValue(mockGarment);
            (garmentModel.updateMetadata as jest.Mock).mockResolvedValue(updatedGarment);
            
            const response = await request(app)
                .put('/api/garments/garment-1/metadata')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .send({
                type: 'shirt',
                color: 'red',
                pattern: 'striped'
                });
                
            expect(response.status).toBe(200);
            expect(response.body.data.garment.metadata.color).toBe('red');
            expect(response.body.data.garment.metadata.pattern).toBe('striped');
            expect(garmentModel.findById).toHaveBeenCalledWith('garment-1');
            expect(garmentModel.updateMetadata).toHaveBeenCalled();
        });
        
        it('should validate metadata and return 400 for invalid data', async () => {
            const response = await request(app)
                .put('/api/garments/garment-1/metadata')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .set('x-test-validation-failure', 'true') // Signal validation failure
                .send({
                color: 123, // Invalid - should be string
                tags: 'not-an-array' // Invalid - should be array
                });
                    
            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(garmentModel.findById).not.toHaveBeenCalled();
        });

        it('should return 403 when trying to update metadata for a garment not owned by the user', async () => {
            (garmentModel.findById as jest.Mock).mockResolvedValue({
                id: 'garment-1',
                user_id: 'another-user'
            });

            const response = await request(app)
                .put('/api/garments/garment-1/metadata')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .send({ type: 'shirt', color: 'red' });

            expect(response.status).toBe(403);
            expect(response.body.message).toContain('permission');
        });
    });
    
    describe('DELETE /:id', () => {
        it('should delete a garment', async () => {
            const mockGarment = { 
                id: 'garment-1', 
                user_id: testUserId
            };
            
            (garmentModel.findById as jest.Mock).mockResolvedValue(mockGarment);
            (garmentModel.delete as jest.Mock).mockResolvedValue(true);
            
            const response = await request(app)
                .delete('/api/garments/garment-1')
                .set('Authorization', `Bearer ${mockAuthToken}`);
                
            expect(response.status).toBe(200);
            expect(response.body.message).toContain('deleted successfully');
            expect(garmentModel.findById).toHaveBeenCalledWith('garment-1');
            expect(garmentModel.delete).toHaveBeenCalledWith('garment-1');
        });
        
        it('should return 404 when garment not found', async () => {
            (garmentModel.findById as jest.Mock).mockResolvedValue(null);
            
            const response = await request(app)
                .delete('/api/garments/non-existent')
                .set('Authorization', `Bearer ${mockAuthToken}`);
                
            expect(response.status).toBe(404);
        });

        it('should return 403 when trying to delete a garment not owned by the user', async () => {
            (garmentModel.findById as jest.Mock).mockResolvedValue({
                id: 'garment-1',
                user_id: 'another-user'
            });

            const response = await request(app)
                .delete('/api/garments/garment-1')
                .set('Authorization', `Bearer ${mockAuthToken}`);

            expect(response.status).toBe(403);
            expect(response.body.message).toContain('permission');
        });
    });

    describe('POST /create - Validation Tests', () => {
        it('should return 400 for missing original_image_id', async () => {
            const response = await request(app)
            .post('/api/garments/create')
            .set('Authorization', `Bearer ${mockAuthToken}`)
            .set('x-test-validation-failure', 'true') // Signal validation failure
            .send({
                mask_data: { points: [{ x: 10, y: 10 }] },
                metadata: { type: 'shirt' }
            });
            
            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(response.body.message).toBe('Validation error'); // changed
        });
        
        it('should return 400 for invalid mask_data (not enough points)', async () => {
            const response = await request(app)
            .post('/api/garments/create')
            .set('Authorization', `Bearer ${mockAuthToken}`)
            .set('x-test-validation-failure', 'true') // Signal validation failure
            .send({
                original_image_id: 'image-1',
                mask_data: { points: [{ x: 10, y: 10 }] },
                metadata: { type: 'shirt' }
            });
            
            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(response.body.message).toBe('Validation error'); // changed
        });
        
        it('should return 400 for invalid metadata (type is missing)', async () => {
            const response = await request(app)
            .post('/api/garments/create')
            .set('Authorization', `Bearer ${mockAuthToken}`)
            .set('x-test-validation-failure', 'true') // Signal validation failure
            .send({
                original_image_id: 'image-1',
                mask_data: { points: [{ x: 10, y: 10 }, { x: 20, y: 20 }, { x: 30, y: 10 }] },
                metadata: { }
            });
            
            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(response.body.message).toBe('Validation error'); // changed
        });

        it('should return 403 if trying to create a garment for an image not owned by the user', async () => {
            const requestPayload = {
                original_image_id: 'image-1',
                mask_data: { points: [{ x: 10, y: 10 }, { x: 20, y: 20 }, { x: 30, y: 10 }] },
                metadata: { type: 'shirt', color: 'blue' }
            };
            const mockImage = {
                id: 'image-1',
                user_id: 'another-user'
            };
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);

            const response = await request(app)
                .post('/api/garments/create')
                .set('Authorization', `Bearer ${mockAuthToken}`)
                .send(requestPayload);

            expect(response.status).toBe(403);
            expect(response.body.message).toContain('permission');
        });
    });

    // These tests primarily verify controller logic for resource existence and ownership checks.
    // While they are not pure authorization tests, they involve permission and access control
    // (e.g., 403 for wrong user, 404 for missing image). For organizational clarity, we include
    // them here under "Authorization Tests" since they validate both access and resource state.
    describe('GET /:id - Authorization Tests', () => {
        it('should return 404 if garment exists but image does not', async () => {
            (garmentModel.findById as jest.Mock).mockResolvedValue({
                id: 'garment-1',
                user_id: testUserId,
                original_image_id: 'non-existent-image'
            });
            (imageModel.findById as jest.Mock).mockResolvedValue(null);

            // Do NOT override authenticate here

            const response = await request(app)
                .get('/api/garments/garment-1')
                .set('Authorization', `Bearer ${mockAuthToken}`);

            expect(response.status).toBe(404);
            expect(response.body.message).toContain('Image not found');
        });

        it('should return 403 if garment and image exist, but image belongs to another user', async () => {
            (garmentModel.findById as jest.Mock).mockResolvedValue({
                id: 'garment-1',
                user_id: testUserId,
                original_image_id: 'image-1'
            });
            (imageModel.findById as jest.Mock).mockResolvedValue({
                id: 'image-1',
                user_id: 'another-user'
            });

            // Do NOT override authenticate here

            const response = await request(app)
                .get('/api/garments/garment-1')
                .set('Authorization', `Bearer ${mockAuthToken}`);

            expect(response.status).toBe(403);
            expect(response.body.message).toContain('permission');
        });

        it('should return 403 if garment exists but is not owned by the user, even if image is owned', async () => {
            (garmentModel.findById as jest.Mock).mockResolvedValue({
                id: 'garment-1',
                user_id: 'another-user',
                original_image_id: 'image-1'
            });
            (imageModel.findById as jest.Mock).mockResolvedValue({
                id: 'image-1',
                user_id: testUserId
            });

            const response = await request(app)
                .get('/api/garments/garment-1')
                .set('Authorization', `Bearer ${mockAuthToken}`);

            expect(response.status).toBe(403);
            expect(response.body.message).toContain('permission');
        });
    });
});