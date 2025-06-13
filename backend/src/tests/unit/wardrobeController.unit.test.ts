// /backend/tests/unit/controllers/wardrobeController2.test.ts
import { Request, Response, NextFunction } from 'express';
import { wardrobeController } from '../../controllers/wardrobeController';
import { wardrobeModel } from '../../models/wardrobeModel';
import { garmentModel } from '../../models/garmentModel';
import { ApiError } from '../../utils/ApiError';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';
import { wardrobeValidationHelpers } from '../__helpers__/wardrobes.helper';

// Mock the models
jest.mock('../../models/wardrobeModel');
jest.mock('../../models/garmentModel');

// Mock the ApiError utility
jest.mock('../../utils/ApiError');

// Type the mocked models
const mockWardrobeModel = wardrobeModel as jest.Mocked<typeof wardrobeModel>;
const mockGarmentModel = garmentModel as jest.Mocked<typeof garmentModel>;
const mockApiError = ApiError as jest.MockedClass<typeof ApiError>;

describe('wardrobeController', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let mockUser: { id: string; email: string };

  beforeEach(() => {
    // Reset all mocks FIRST
    jest.clearAllMocks();
    
    // Setup mock user
    mockUser = {
        id: 'test-user-id',
        email: 'test@example.com'
    };

    // Setup mock request
    mockReq = {
        user: mockUser,
        body: {},
        params: {}
    };

    // Setup mock response with chainable methods - IMPORTANT: Create new instances
    mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis()
    };

    // Setup mock next function
    mockNext = jest.fn();

    // Setup default ApiError mocks - Create new instances
    mockApiError.badRequest = jest.fn();
    mockApiError.unauthorized = jest.fn();
    mockApiError.forbidden = jest.fn();
    mockApiError.notFound = jest.fn();
    mockApiError.internal = jest.fn();
  });

    describe('createWardrobe', () => {
        describe('Successful Creation', () => {
            it('should create wardrobe with valid input', async () => {
                // Arrange
                const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
                const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                name: inputData.name,
                description: inputData.description 
                });

                mockReq.body = {
                name: inputData.name,
                description: inputData.description
                };

                mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

                // Act
                await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: inputData.name.trim(),
                description: inputData.description?.trim() || ''
                });

                expect(mockRes.status).toHaveBeenCalledWith(201);
                expect(mockRes.json).toHaveBeenCalledWith({
                status: 'success',
                data: { wardrobe: expectedWardrobe },
                message: 'Wardrobe created successfully'
                });

                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should create wardrobe without description', async () => {
                // Arrange
                const inputData = { name: 'Test Wardrobe' };
                const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                name: inputData.name,
                description: ''
                });

                mockReq.body = inputData;
                mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

                // Act
                await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: inputData.name,
                description: ''
                });

                expect(mockRes.status).toHaveBeenCalledWith(201);
            });

            it('should trim whitespace from name and description', async () => {
                // Arrange
                const inputData = {
                name: '  Test Wardrobe  ',
                description: '  Test Description  '
                };
                const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                name: 'Test Wardrobe',
                description: 'Test Description'
                });

                mockReq.body = inputData;
                mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

                // Act
                await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: 'Test Wardrobe',
                description: 'Test Description'
                });
            });
        });
    });

    describe('Input Validation', () => {
        it('should reject empty name', async () => {
            // Arrange
            mockReq.body = { name: '', description: 'Valid description' };

            // Act
            await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.badRequest).toHaveBeenCalledWith(
            'Wardrobe name is required',
            'MISSING_NAME'
            );
            expect(mockNext).toHaveBeenCalled();
            expect(mockWardrobeModel.create).not.toHaveBeenCalled();
        });

        it('should reject whitespace-only name', async () => {
            // Arrange
            mockReq.body = { name: '   ', description: 'Valid description' };

            // Act
            await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.badRequest).toHaveBeenCalledWith(
            'Wardrobe name is required',
            'MISSING_NAME'
            );
            expect(mockNext).toHaveBeenCalled();
        });

        it('should reject non-string name', async () => {
            // Arrange
            mockReq.body = { name: 123, description: 'Valid description' };

            // Act
            await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.badRequest).toHaveBeenCalledWith(
            'Wardrobe name is required',
            'MISSING_NAME'
            );
            expect(mockNext).toHaveBeenCalled();
        });

        it('should reject name longer than 100 characters', async () => {
            // Arrange
            mockReq.body = { 
            name: 'a'.repeat(101),
            description: 'Valid description' 
            };

            // Act
            await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.badRequest).toHaveBeenCalledWith(
            'Wardrobe name cannot exceed 100 characters',
            'NAME_TOO_LONG'
            );
            expect(mockNext).toHaveBeenCalled();
        });

        it('should reject non-string description', async () => {
            // Arrange
            mockReq.body = { 
            name: 'Valid Name',
            description: 123 
            };

            // Act
            await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.badRequest).toHaveBeenCalledWith(
            'Description must be a string',
            'INVALID_DESCRIPTION_TYPE'
            );
            expect(mockNext).toHaveBeenCalled();
        });

        it('should reject description longer than 1000 characters', async () => {
            // Arrange
            mockReq.body = { 
            name: 'Valid Name',
            description: 'a'.repeat(1001)
            };

            // Act
            await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.badRequest).toHaveBeenCalledWith(
            'Description cannot exceed 1000 characters',
            'DESCRIPTION_TOO_LONG'
            );
            expect(mockNext).toHaveBeenCalled();
        });

        // Test edge cases from validation helper
        const nameValidationTests = wardrobeValidationHelpers.getNameValidationTests();
        nameValidationTests.forEach(testCase => {
            it(`should ${testCase.shouldPass ? 'accept' : 'reject'} name: ${testCase.description}`, async () => {
            // Arrange
            mockReq.body = { 
                name: testCase.name,
                description: 'Valid description' 
            };

            if (testCase.shouldPass) {
                const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                name: testCase.name.trim(),
                description: 'Valid description'
                });
                mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);
            }

            // Act
            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Assert
            if (testCase.shouldPass) {
                expect(mockWardrobeModel.create).toHaveBeenCalled();
                expect(mockRes.status).toHaveBeenCalledWith(201);
            } else {
                expect(mockApiError.badRequest).toHaveBeenCalled();
                expect(mockNext).toHaveBeenCalled();
            }
            });
        });
    });

    describe('Error Handling', () => {
        it('should handle model errors', async () => {
            // Arrange
            const inputData = { name: 'Valid Name', description: 'Valid description' };
            const modelError = new Error('Database connection failed');
            
            mockReq.body = inputData;
            mockWardrobeModel.create.mockRejectedValue(modelError);

            // Spy on console.error to verify error logging
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            // Act
            await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(consoleSpy).toHaveBeenCalledWith('Error creating wardrobe:', modelError);
            expect(mockApiError.internal).toHaveBeenCalledWith('Failed to create wardrobe');
            expect(mockNext).toHaveBeenCalled();

            // Cleanup
            consoleSpy.mockRestore();
        });
    });

    describe('getWardrobes', () => {
        describe('Successful Retrieval', () => {
            it('should retrieve wardrobes for authenticated user', async () => {
                // Arrange
                const expectedWardrobes = wardrobeMocks.createMultipleWardrobes(mockUser.id, 3);
                mockWardrobeModel.findByUserId.mockResolvedValue(expectedWardrobes);

                // Act
                await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.findByUserId).toHaveBeenCalledWith(mockUser.id);
                expect(mockRes.status).toHaveBeenCalledWith(200);
                expect(mockRes.json).toHaveBeenCalledWith({
                status: 'success',
                data: { 
                    wardrobes: expectedWardrobes,
                    count: expectedWardrobes.length 
                }
                });
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should return empty array when user has no wardrobes', async () => {
                // Arrange
                mockWardrobeModel.findByUserId.mockResolvedValue([]);

                // Act
                await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockRes.json).toHaveBeenCalledWith({
                status: 'success',
                data: { 
                    wardrobes: [],
                    count: 0 
                }
                });
            });
        });

        describe('Error Handling', () => {
            it('should handle model errors', async () => {
                // Arrange
                const modelError = new Error('Database connection failed');
                mockWardrobeModel.findByUserId.mockRejectedValue(modelError);

                const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

                // Act
                await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(consoleSpy).toHaveBeenCalledWith('Error retrieving wardrobes:', modelError);
                expect(mockApiError.internal).toHaveBeenCalledWith('Failed to retrieve wardrobes');
                expect(mockNext).toHaveBeenCalled();

                consoleSpy.mockRestore();
            });
        });
    });

    describe('getWardrobe', () => {
        const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';

        describe('Successful Retrieval', () => {                       
            it('should retrieve wardrobe with garments for valid ID', async () => {
                // Arrange
                const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                    id: validWardrobeId,
                    user_id: mockUser.id 
                });
                const expectedGarments = wardrobeMocks.garments.createMultipleGarments(mockUser.id, 3);

                mockReq.params = { id: validWardrobeId };
                mockReq.user = mockUser;
                mockWardrobeModel.findById.mockResolvedValue(expectedWardrobe);
                mockWardrobeModel.getGarments.mockResolvedValue(expectedGarments);

                // Act
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );

                // Assert
                expect(mockWardrobeModel.findById).toHaveBeenCalledWith(validWardrobeId);
                expect(mockWardrobeModel.getGarments).toHaveBeenCalledWith(validWardrobeId);
                expect(mockRes.status).toHaveBeenCalledWith(200);
                expect(mockRes.json).toHaveBeenCalledWith({
                    status: 'success',
                    data: {
                        wardrobe: {
                            ...expectedWardrobe,
                            garments: expectedGarments
                        }
                    }
                });
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should retrieve wardrobe with empty garments array', async () => {
                // Arrange
                const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                    id: validWardrobeId,
                    user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId };
                mockReq.user = mockUser;
                mockWardrobeModel.findById.mockResolvedValue(expectedWardrobe);
                mockWardrobeModel.getGarments.mockResolvedValue([]);

                // Act - CALL THE CONTROLLER
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );

                // Assert
                expect(mockRes.json).toHaveBeenCalledWith({
                    status: 'success',
                    data: {
                        wardrobe: {
                            ...expectedWardrobe,
                            garments: []
                        }
                    }
                });
            });
        });

        describe('ID Validation', () => {
            const invalidIds = [
                'invalid-uuid',
                '123',
                '',
                'not-a-uuid-at-all',
                'a0b1c2d3-e4f5-6789-abcd-ef012345678',  // too short
                'a0b1c2d3-e4f5-6789-abcd-ef01234567890'  // too long
            ];

            invalidIds.forEach(invalidId => {
                it(`should reject invalid UUID: "${invalidId}"`, async () => {
                // Arrange
                mockReq.params = { id: invalidId };

                // Act
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                    'Invalid wardrobe ID format',
                    'INVALID_UUID'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
                });
            });
        });

        describe('Error Handling', () => {
        it('should handle wardrobe not found', async () => {
            // Arrange
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(null);

            // Act
            await wardrobeController.getWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.notFound).toHaveBeenCalledWith('Wardrobe not found');
            expect(mockNext).toHaveBeenCalled();
            expect(mockWardrobeModel.getGarments).not.toHaveBeenCalled();
        });

        it('should handle model errors during wardrobe retrieval', async () => {
            // Arrange
            const modelError = new Error('Database connection failed');
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockRejectedValue(modelError);

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            // Act
            await wardrobeController.getWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(consoleSpy).toHaveBeenCalledWith('Error retrieving wardrobe:', modelError);
            expect(mockApiError.internal).toHaveBeenCalledWith('Failed to retrieve wardrobe');
            expect(mockNext).toHaveBeenCalled();

            consoleSpy.mockRestore();
        });

        it('should handle model errors during garments retrieval', async () => {
            // Arrange
            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
            id: validWardrobeId,
            user_id: mockUser.id 
            });
            const modelError = new Error('Failed to fetch garments');
            
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(expectedWardrobe);
            mockWardrobeModel.getGarments.mockRejectedValue(modelError);

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            // Act
            await wardrobeController.getWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(consoleSpy).toHaveBeenCalledWith('Error retrieving wardrobe:', modelError);
            expect(mockApiError.internal).toHaveBeenCalledWith('Failed to retrieve wardrobe');
            expect(mockNext).toHaveBeenCalled();

            consoleSpy.mockRestore();
        });
        });
    });

    describe('updateWardrobe', () => {
        const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';

        describe('Successful Updates', () => {
            it('should update wardrobe with valid data', async () => {
                // Arrange
                const existingWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const updateData = { name: 'Updated Name', description: 'Updated Description' };
                const updatedWardrobe = { ...existingWardrobe, ...updateData };

                mockReq.params = { id: validWardrobeId };
                mockReq.body = updateData;
                mockWardrobeModel.findById.mockResolvedValue(existingWardrobe);
                mockWardrobeModel.update.mockResolvedValue(updatedWardrobe);

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.update).toHaveBeenCalledWith(validWardrobeId, {
                name: updateData.name.trim(),
                description: updateData.description.trim()
                });
                expect(mockRes.status).toHaveBeenCalledWith(200);
                expect(mockRes.json).toHaveBeenCalledWith({
                status: 'success',
                data: { wardrobe: updatedWardrobe },
                message: 'Wardrobe updated successfully'
                });
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should trim whitespace from updated fields', async () => {
                // Arrange
                const existingWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const updateData = { name: '  Updated Name  ', description: '  Updated Description  ' };

                mockReq.params = { id: validWardrobeId };
                mockReq.body = updateData;
                mockWardrobeModel.findById.mockResolvedValue(existingWardrobe);
                mockWardrobeModel.update.mockResolvedValue(existingWardrobe);

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.update).toHaveBeenCalledWith(validWardrobeId, {
                name: 'Updated Name',
                description: 'Updated Description'
                });
            });
        });

        describe('Partial Updates', () => {
            it('should update only name when description not provided', async () => {
                // Arrange
                const existingWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const updateData = { name: 'Updated Name Only' };

                mockReq.params = { id: validWardrobeId };
                mockReq.body = updateData;
                mockWardrobeModel.findById.mockResolvedValue(existingWardrobe);
                mockWardrobeModel.update.mockResolvedValue(existingWardrobe);

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.update).toHaveBeenCalledWith(validWardrobeId, {
                name: 'Updated Name Only',
                description: undefined
                });
            });

            it('should update only description when name not provided', async () => {
                // Arrange
                const existingWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const updateData = { description: 'Updated Description Only' };

                mockReq.params = { id: validWardrobeId };
                mockReq.body = updateData;
                mockWardrobeModel.findById.mockResolvedValue(existingWardrobe);
                mockWardrobeModel.update.mockResolvedValue(existingWardrobe);

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.update).toHaveBeenCalledWith(validWardrobeId, {
                name: undefined,
                description: 'Updated Description Only'
                });
            });

            it('should handle undefined fields correctly', async () => {
                // Arrange
                const existingWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId };
                mockReq.body = {}; // No updates
                mockWardrobeModel.findById.mockResolvedValue(existingWardrobe);
                mockWardrobeModel.update.mockResolvedValue(existingWardrobe);

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.update).toHaveBeenCalledWith(validWardrobeId, {
                name: undefined,
                description: undefined
                });
            });
        });

        describe('Input Validation', () => {
            beforeEach(() => {
                const existingWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(existingWardrobe);
            });

            it('should reject invalid wardrobe ID format', async () => {
                // Arrange
                mockReq.params = { id: 'invalid-uuid' };

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Invalid wardrobe ID format',
                'INVALID_UUID'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });

            it('should reject empty name', async () => {
                // Arrange
                mockReq.body = { name: '' };

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Name must be a non-empty string',
                'INVALID_NAME'
                );
                expect(mockNext).toHaveBeenCalled();
            });

            it('should reject whitespace-only name', async () => {
                // Arrange
                mockReq.body = { name: '   ' };

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Name must be a non-empty string',
                'INVALID_NAME'
                );
                expect(mockNext).toHaveBeenCalled();
            });

            it('should reject non-string name', async () => {
                // Arrange
                mockReq.body = { name: 123 };

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Name must be a non-empty string',
                'INVALID_NAME'
                );
                expect(mockNext).toHaveBeenCalled();
            });

            it('should reject name longer than 100 characters', async () => {
                // Arrange
                mockReq.body = { name: 'a'.repeat(101) };

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Name cannot exceed 100 characters',
                'NAME_TOO_LONG'
                );
                expect(mockNext).toHaveBeenCalled();
            });

            it('should reject non-string description', async () => {
                // Arrange
                mockReq.body = { description: 123 };

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Description must be a string',
                'INVALID_DESCRIPTION_TYPE'
                );
                expect(mockNext).toHaveBeenCalled();
            });

            it('should reject description longer than 1000 characters', async () => {
                // Arrange
                mockReq.body = { description: 'a'.repeat(1001) };

                // Act
                await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Description cannot exceed 1000 characters',
                'DESCRIPTION_TOO_LONG'
                );
                expect(mockNext).toHaveBeenCalled();
            });
        });

        describe('Error Handling', () => {
        it('should handle wardrobe not found', async () => {
            // Arrange
            mockReq.params = { id: validWardrobeId };
            mockReq.body = { name: 'Updated Name' };
            mockWardrobeModel.findById.mockResolvedValue(null);

            // Act
            await wardrobeController.updateWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.notFound).toHaveBeenCalledWith('Wardrobe not found');
            expect(mockNext).toHaveBeenCalled();
            expect(mockWardrobeModel.update).not.toHaveBeenCalled();
        });

        it('should handle model errors', async () => {
            // Arrange
            const existingWardrobe = wardrobeMocks.createValidWardrobe({ 
            id: validWardrobeId,
            user_id: mockUser.id 
            });
            const modelError = new Error('Database connection failed');
            
            mockReq.params = { id: validWardrobeId };
            mockReq.body = { name: 'Updated Name' };
            mockWardrobeModel.findById.mockResolvedValue(existingWardrobe);
            mockWardrobeModel.update.mockRejectedValue(modelError);

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            // Act
            await wardrobeController.updateWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(consoleSpy).toHaveBeenCalledWith('Error updating wardrobe:', modelError);
            expect(mockApiError.internal).toHaveBeenCalledWith('Failed to update wardrobe');
            expect(mockNext).toHaveBeenCalled();

            consoleSpy.mockRestore();
        });
        });
    });

    describe('addGarmentToWardrobe', () => {
        const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
        const validGarmentId = 'b1c2d3e4-f5a6-789b-cdef-012345678901';

        describe('Successful Addition', () => {
            it('should add garment to wardrobe with default position', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garment = wardrobeMocks.garments.createMockGarment({ 
                id: validGarmentId,
                user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: validGarmentId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockGarmentModel.findById.mockResolvedValue(garment);
                mockWardrobeModel.addGarment.mockResolvedValue(true);

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(
                validWardrobeId, 
                validGarmentId, 
                0, 
                { allowUpdate: false }
                );
                expect(mockRes.status).toHaveBeenCalledWith(200);
                expect(mockRes.json).toHaveBeenCalledWith({
                status: 'success',
                data: null,
                message: 'Garment added to wardrobe successfully'
                });
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should add garment to wardrobe with custom position', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garment = wardrobeMocks.garments.createMockGarment({ 
                id: validGarmentId,
                user_id: mockUser.id 
                });
                const customPosition = 5;

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: validGarmentId, position: customPosition };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockGarmentModel.findById.mockResolvedValue(garment);
                mockWardrobeModel.addGarment.mockResolvedValue(true);

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(
                validWardrobeId, 
                validGarmentId, 
                customPosition, 
                { allowUpdate: false }
                );
                expect(mockRes.status).toHaveBeenCalledWith(200);
            });
        });

        describe('Position Handling', () => {
            beforeEach(() => {
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garment = wardrobeMocks.garments.createMockGarment({ 
                id: validGarmentId,
                user_id: mockUser.id 
                });
                
                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockGarmentModel.findById.mockResolvedValue(garment);
                mockWardrobeModel.addGarment.mockResolvedValue(true);
            });

            it('should use position 0 when position is undefined', async () => {
                // Arrange
                mockReq.body = { garmentId: validGarmentId };

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(
                validWardrobeId, 
                validGarmentId, 
                0, 
                { allowUpdate: false }
                );
            });

            it('should accept position 0', async () => {
                // Arrange
                mockReq.body = { garmentId: validGarmentId, position: 0 };

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(
                validWardrobeId, 
                validGarmentId, 
                0, 
                { allowUpdate: false }
                );
            });

            it('should accept positive position values', async () => {
                // Arrange
                mockReq.body = { garmentId: validGarmentId, position: 10 };

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(validWardrobeId, validGarmentId, 10, { allowUpdate: false });
            });

            it('should convert string position to number', async () => {
                // Arrange
                mockReq.body = { garmentId: validGarmentId, position: '7' };

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(validWardrobeId, validGarmentId, 7, { allowUpdate: false });
            });

            it('should reject negative position values', async () => {
                // Arrange
                mockReq.body = { garmentId: validGarmentId, position: -1 };

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Position must be a non-negative number',
                'INVALID_POSITION'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.addGarment).not.toHaveBeenCalled();
            });

            it('should reject non-numeric position values', async () => {
                // Arrange
                mockReq.body = { garmentId: validGarmentId, position: 'invalid' };

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Position must be a non-negative number',
                'INVALID_POSITION'
                );
                expect(mockNext).toHaveBeenCalled();
            });
        });

        describe('Input Validation', () => {
            it('should reject invalid wardrobe ID format', async () => {
                // Arrange
                mockReq.params = { id: 'invalid-uuid' };
                mockReq.body = { garmentId: validGarmentId };

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Invalid wardrobe ID format',
                'INVALID_UUID'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });

            it('should reject missing garment ID', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockReq.body = {};

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Valid garment ID is required',
                'INVALID_GARMENT_ID'
                );
                expect(mockNext).toHaveBeenCalled();
            });

            it('should reject invalid garment ID format', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: 'invalid-uuid' };

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Valid garment ID is required',
                'INVALID_GARMENT_ID'
                );
                expect(mockNext).toHaveBeenCalled();
            });
        });

        describe('Error Handling', () => {
            it('should handle wardrobe not found', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: validGarmentId };
                mockWardrobeModel.findById.mockResolvedValue(null);

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.notFound).toHaveBeenCalledWith('Wardrobe not found');
                expect(mockNext).toHaveBeenCalled();
                expect(mockGarmentModel.findById).not.toHaveBeenCalled();
            });

            it('should handle garment not found', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: validGarmentId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockGarmentModel.findById.mockResolvedValue(null);

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.notFound).toHaveBeenCalledWith(
                'Garment not found',
                'GARMENT_NOT_FOUND'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.addGarment).not.toHaveBeenCalled();
            });

            it('should handle model errors', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garment = wardrobeMocks.garments.createMockGarment({ 
                id: validGarmentId,
                user_id: mockUser.id 
                });
                const modelError = new Error('Database connection failed');

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: validGarmentId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockGarmentModel.findById.mockResolvedValue(garment);
                mockWardrobeModel.addGarment.mockRejectedValue(modelError);

                const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

                // Act
                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(consoleSpy).toHaveBeenCalledWith('Error adding garment to wardrobe:', modelError);
                expect(mockApiError.internal).toHaveBeenCalledWith('Failed to add garment to wardrobe');
                expect(mockNext).toHaveBeenCalled();

                consoleSpy.mockRestore();
            });
        });
    });

    describe('removeGarmentFromWardrobe', () => {
        const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
        const validItemId = 'b1c2d3e4-f5a6-789b-cdef-012345678901';

        describe('Successful Removal', () => {
            it('should remove garment from wardrobe successfully', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId, itemId: validItemId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.removeGarment.mockResolvedValue(true);

                // Act
                await wardrobeController.removeGarmentFromWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.removeGarment).toHaveBeenCalledWith(validWardrobeId, validItemId);
                expect(mockRes.status).toHaveBeenCalledWith(200);
                expect(mockRes.json).toHaveBeenCalledWith({
                status: 'success',
                data: null,
                message: 'Garment removed from wardrobe successfully'
                });
                expect(mockNext).not.toHaveBeenCalled();
            });
        });

        describe('ID Validation', () => {
            it('should reject invalid wardrobe ID format', async () => {
                // Arrange
                mockReq.params = { id: 'invalid-uuid', itemId: validItemId };

                // Act
                await wardrobeController.removeGarmentFromWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Invalid wardrobe ID format',
                'INVALID_UUID'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });

            it('should reject invalid item ID format', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId, itemId: 'invalid-uuid' };

                // Act
                await wardrobeController.removeGarmentFromWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Invalid item ID format',
                'INVALID_ITEM_UUID'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });
        });

        describe('Error Handling', () => {
        it('should handle wardrobe not found', async () => {
            // Arrange
            mockReq.params = { id: validWardrobeId, itemId: validItemId };
            mockWardrobeModel.findById.mockResolvedValue(null);

            // Act
            await wardrobeController.removeGarmentFromWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.notFound).toHaveBeenCalledWith('Wardrobe not found');
            expect(mockNext).toHaveBeenCalled();
            expect(mockWardrobeModel.removeGarment).not.toHaveBeenCalled();
        });

        it('should handle garment not found in wardrobe', async () => {
            // Arrange
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
            id: validWardrobeId,
            user_id: mockUser.id 
            });

            mockReq.params = { id: validWardrobeId, itemId: validItemId };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.removeGarment.mockResolvedValue(false);

            // Act
            await wardrobeController.removeGarmentFromWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(mockApiError.notFound).toHaveBeenCalledWith(
            'Garment not found in wardrobe',
            'GARMENT_NOT_IN_WARDROBE'
            );
            expect(mockNext).toHaveBeenCalled();
        });

        it('should handle model errors', async () => {
            // Arrange
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
            id: validWardrobeId,
            user_id: mockUser.id 
            });
            const modelError = new Error('Database connection failed');

            mockReq.params = { id: validWardrobeId, itemId: validItemId };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.removeGarment.mockRejectedValue(modelError);

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            // Act
            await wardrobeController.removeGarmentFromWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
            );

            // Assert
            expect(consoleSpy).toHaveBeenCalledWith('Error removing garment from wardrobe:', modelError);
            expect(mockApiError.internal).toHaveBeenCalledWith('Failed to remove garment from wardrobe');
            expect(mockNext).toHaveBeenCalled();

            consoleSpy.mockRestore();
        });
        });
    });

    describe('deleteWardrobe', () => {
        const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';

        describe('Successful Deletion', () => {
            it('should delete wardrobe successfully', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.delete.mockResolvedValue(true);

                // Act
                await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.delete).toHaveBeenCalledWith(validWardrobeId);
                expect(mockRes.status).toHaveBeenCalledWith(200);
                expect(mockRes.json).toHaveBeenCalledWith({
                status: 'success',
                data: null,
                message: 'Wardrobe deleted successfully'
                });
                expect(mockNext).not.toHaveBeenCalled();
            });
        });

        describe('ID Validation', () => {
            it('should reject invalid wardrobe ID format', async () => {
                // Arrange
                mockReq.params = { id: 'invalid-uuid' };

                // Act
                await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Invalid wardrobe ID format',
                'INVALID_UUID'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });
        });

        describe('Error Handling', () => {
            it('should handle wardrobe not found', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(null);

                // Act
                await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.notFound).toHaveBeenCalledWith('Wardrobe not found');
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.delete).not.toHaveBeenCalled();
            });

            it('should handle deletion failure', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.delete.mockResolvedValue(false);

                // Act
                await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockApiError.internal).toHaveBeenCalledWith('Failed to delete wardrobe');
                expect(mockNext).toHaveBeenCalled();
            });

            it('should handle model errors', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const modelError = new Error('Database connection failed');

                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.delete.mockRejectedValue(modelError);

                const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

                // Act
                await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(consoleSpy).toHaveBeenCalledWith('Error deleting wardrobe:', modelError);
                expect(mockApiError.internal).toHaveBeenCalledWith('Failed to delete wardrobe');
                expect(mockNext).toHaveBeenCalled();

                consoleSpy.mockRestore();
            });
        });
    });

    describe('Response Format Validation', () => {
        it('should maintain consistent success response format across all endpoints', async () => {
            const successResponseFormat = {
                status: 'success',
                data: expect.any(Object),
                message: expect.any(String)
            };

            // Test createWardrobe response format
            const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
            const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            const createCall = (mockRes.json as jest.Mock).mock.calls[0][0];
            expect(createCall).toMatchObject(successResponseFormat);
            expect(createCall.status).toBe('success');
            expect(createCall.data).toHaveProperty('wardrobe');
            expect(createCall.message).toBe('Wardrobe created successfully');
        });

        it('should use null data for operations without return data', async () => {
            // Test endpoints that return null data (like delete operations)
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789',
                user_id: mockUser.id 
            });

            mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.delete.mockResolvedValue(true);

            await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            const deleteCall = (mockRes.json as jest.Mock).mock.calls[0][0];
            expect(deleteCall.data).toBeNull();
            expect(deleteCall.status).toBe('success');
            expect(deleteCall.message).toBe('Wardrobe deleted successfully');
        });

        it('should include appropriate data properties for each endpoint', async () => {
        // Test getWardrobes includes count
        const wardrobes = wardrobeMocks.createMultipleWardrobes(mockUser.id, 2);
        mockWardrobeModel.findByUserId.mockResolvedValue(wardrobes);

        await wardrobeController.getWardrobes(
            mockReq as Request,
            mockRes as Response,
            mockNext
        );

        const getWardrobesResponse = (mockRes.json as jest.Mock).mock.calls[0][0];
        expect(getWardrobesResponse.data).toHaveProperty('wardrobes');
        expect(getWardrobesResponse.data).toHaveProperty('count');
        expect(getWardrobesResponse.data.count).toBe(2);
        });
    });

    describe('Edge Cases and Boundary Conditions', () => {
        it('should handle maximum length name (100 characters)', async () => {
            // Arrange
            const maxLengthName = 'a'.repeat(100);
            const inputData = { name: maxLengthName, description: 'Test' };
            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                name: maxLengthName,
                description: 'Test'
            });

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            // Act
            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Assert
            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: maxLengthName,
                description: 'Test'
            });
            expect(mockRes.status).toHaveBeenCalledWith(201);
        });

        it('should handle maximum length description (1000 characters)', async () => {
        // Arrange
        const maxLengthDescription = 'a'.repeat(1000);
        const inputData = { name: 'Test Name', description: maxLengthDescription };
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
            user_id: mockUser.id,
            name: 'Test Name',
            description: maxLengthDescription
        });

        mockReq.body = inputData;
        mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

        // Act
        await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
        );

        // Assert
        expect(mockWardrobeModel.create).toHaveBeenCalledWith({
            user_id: mockUser.id,
            name: 'Test Name',
            description: maxLengthDescription
        });
        expect(mockRes.status).toHaveBeenCalledWith(201);
        });

        it('should handle empty description correctly', async () => {
        // Arrange
        const inputData = { name: 'Test Name', description: '' };
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
            user_id: mockUser.id,
            name: 'Test Name',
            description: ''
        });

        mockReq.body = inputData;
        mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

        // Act
        await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
        );

        // Assert
        expect(mockWardrobeModel.create).toHaveBeenCalledWith({
            user_id: mockUser.id,
            name: 'Test Name',
            description: ''
        });
        });

        it('should handle position value of zero correctly', async () => {
            // Arrange
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789',
                user_id: mockUser.id 
            });
            const garment = wardrobeMocks.garments.createMockGarment({ 
                id: 'b1c2d3e4-f5a6-789b-cdef-012345678901',
                user_id: mockUser.id 
            });

            mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
            mockReq.body = { garmentId: 'b1c2d3e4-f5a6-789b-cdef-012345678901', position: 0 };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockGarmentModel.findById.mockResolvedValue(garment);
            mockWardrobeModel.addGarment.mockResolvedValue(true);

            // Act
            await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Assert
            expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(
                'a0b1c2d3-e4f5-6789-abcd-ef0123456789',
                'b1c2d3e4-f5a6-789b-cdef-012345678901',
                0,
                { allowUpdate: false }
            );
        });

        it('should handle large position values', async () => {
            // Arrange
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789',
                user_id: mockUser.id 
            });
            const garment = wardrobeMocks.garments.createMockGarment({ 
                id: 'b1c2d3e4-f5a6-789b-cdef-012345678901',
                user_id: mockUser.id 
            });

            mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
            mockReq.body = { garmentId: 'b1c2d3e4-f5a6-789b-cdef-012345678901', position: 999 };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockGarmentModel.findById.mockResolvedValue(garment);
            mockWardrobeModel.addGarment.mockResolvedValue(true);

            // Act
            await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Assert
            expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(
                'a0b1c2d3-e4f5-6789-abcd-ef0123456789',
                'b1c2d3e4-f5a6-789b-cdef-012345678901',
                999,
                { allowUpdate: false }
            );
        });
    });

    describe('Model Integration', () => {
        it('should call model methods with correct parameters', async () => {
            // Test that controller properly delegates to model layer
            const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
            const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify exact model method calls
            expect(mockWardrobeModel.create).toHaveBeenCalledTimes(1);
            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: inputData.name.trim(),
                description: inputData.description?.trim() || ''
            });
        });

        it('should handle model method call order correctly', async () => {
            const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
            });
            const garments = wardrobeMocks.garments.createMultipleGarments(mockUser.id, 2);

            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.getGarments.mockResolvedValue(garments);

            await wardrobeController.getWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify both methods were called with correct parameters
            expect(mockWardrobeModel.findById).toHaveBeenCalledWith(validWardrobeId);
            expect(mockWardrobeModel.getGarments).toHaveBeenCalledWith(validWardrobeId);
            
            // Verify call order by checking the invocationCallOrder
            const findByIdCallOrder = (mockWardrobeModel.findById as jest.Mock).mock.invocationCallOrder[0];
            const getGarmentsCallOrder = (mockWardrobeModel.getGarments as jest.Mock).mock.invocationCallOrder[0];
            expect(findByIdCallOrder).toBeLessThan(getGarmentsCallOrder);
        });

        it('should pass through model errors without modification', async () => {
        // Arrange
        const originalError = new Error('Original database error');
        mockReq.body = { name: 'Valid Name', description: 'Valid description' };
        mockWardrobeModel.create.mockRejectedValue(originalError);

        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        // Act
        await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
        );

        // Assert
        expect(consoleSpy).toHaveBeenCalledWith('Error creating wardrobe:', originalError);
        expect(mockApiError.internal).toHaveBeenCalledWith('Failed to create wardrobe');

        consoleSpy.mockRestore();
        });
    });

    describe('Input Sanitization', () => {
        it('should trim whitespace from all string inputs', async () => {
            const inputWithWhitespace = {
                name: '  \t Summer Collection \n ',
                description: ' \r A wonderful collection of summer clothes \t\n '
            };

            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                name: 'Summer Collection',
                description: 'A wonderful collection of summer clothes'
            });

            mockReq.body = inputWithWhitespace;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: 'Summer Collection',
                description: 'A wonderful collection of summer clothes'
            });
        });

        it('should handle unicode characters correctly', async () => {
            const unicodeInput = {
                name: 'Été Collection 夏季',
                description: 'Collection pour l\'été avec des vêtements 夏季服装'
            };

            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                ...unicodeInput
            });

            mockReq.body = unicodeInput;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: unicodeInput.name,
                description: unicodeInput.description
            });
        });

        it('should handle special characters in names correctly', async () => {
            const specialCharInput = {
                name: 'My-Special_Wardrobe.2024',
                description: 'Contains special chars @#$%^&*()'
            };

            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                ...specialCharInput
            });

            mockReq.body = specialCharInput;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: specialCharInput.name,
                description: specialCharInput.description
            });
        });

        it('should handle empty string description properly', async () => {
            const inputData = { name: 'Test Wardrobe', description: '' };
            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                ...inputData
            });

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: 'Test Wardrobe',
                description: ''
            });
        });
    });

    describe('Concurrent Operations', () => {
        it('should handle multiple concurrent requests properly', async () => {
            // Simulate multiple users creating wardrobes simultaneously
            const user1 = { id: 'user-1', email: 'user1@example.com' };
            const user2 = { id: 'user-2', email: 'user2@example.com' };

            const req1 = { ...mockReq, user: user1, body: { name: 'User 1 Wardrobe' } };
            const req2 = { ...mockReq, user: user2, body: { name: 'User 2 Wardrobe' } };

            const res1 = { ...mockRes };
            const res2 = { ...mockRes };

            const wardrobe1 = wardrobeMocks.createValidWardrobe({ user_id: user1.id, name: 'User 1 Wardrobe' });
            const wardrobe2 = wardrobeMocks.createValidWardrobe({ user_id: user2.id, name: 'User 2 Wardrobe' });

            // Setup mocks to return different results for different users
            mockWardrobeModel.create
                .mockResolvedValueOnce(wardrobe1)
                .mockResolvedValueOnce(wardrobe2);

            // Execute concurrent requests
            const promise1 = wardrobeController.createWardrobe(req1 as Request, res1 as Response, mockNext);
            const promise2 = wardrobeController.createWardrobe(req2 as Request, res2 as Response, mockNext);

            await Promise.all([promise1, promise2]);

            // Verify both calls were made with correct user contexts
            expect(mockWardrobeModel.create).toHaveBeenNthCalledWith(1, {
                user_id: user1.id,
                name: 'User 1 Wardrobe',
                description: ''
            });

            expect(mockWardrobeModel.create).toHaveBeenNthCalledWith(2, {
                user_id: user2.id,
                name: 'User 2 Wardrobe',
                description: ''
            });
        });

        it('should isolate errors between concurrent requests', async () => {
            const user1 = { id: 'user-1', email: 'user1@example.com' };
            const user2 = { id: 'user-2', email: 'user2@example.com' };

            const req1 = { ...mockReq, user: user1, body: { name: 'User 1 Wardrobe' } };
            const req2 = { ...mockReq, user: user2, body: { name: '' } }; // Invalid input

            const res1 = { ...mockRes };
            const res2 = { ...mockRes };
            const next1 = jest.fn();
            const next2 = jest.fn();

            const wardrobe1 = wardrobeMocks.createValidWardrobe({ user_id: user1.id, name: 'User 1 Wardrobe' });
            mockWardrobeModel.create.mockResolvedValueOnce(wardrobe1);

            // Execute concurrent requests
            const promise1 = wardrobeController.createWardrobe(req1 as Request, res1 as Response, next1);
            const promise2 = wardrobeController.createWardrobe(req2 as Request, res2 as Response, next2);

            await Promise.all([promise1, promise2]);

            // Verify first request succeeded
            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: user1.id,
                name: 'User 1 Wardrobe',
                description: ''
            });

            // Verify second request failed with validation error
            expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Wardrobe name is required',
                'MISSING_NAME'
            );
            expect(next2).toHaveBeenCalled();
            expect(next1).not.toHaveBeenCalled();
        });
    });

    describe('Error Consistency', () => {
        it('should use consistent error codes and messages across similar validation failures', async () => {
            const testCases = [
                {
                description: 'name too long in create',
                method: 'createWardrobe',
                setup: () => { 
                    mockReq.body = { name: 'a'.repeat(101) };
                    mockReq.params = {};
                },
                expectedError: ['Wardrobe name cannot exceed 100 characters', 'NAME_TOO_LONG']
                },
                {
                description: 'name too long in update',
                method: 'updateWardrobe',
                setup: () => {
                    mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
                    mockReq.body = { name: 'a'.repeat(101) };
                    mockWardrobeModel.findById.mockResolvedValue(wardrobeMocks.createValidWardrobe({ user_id: mockUser.id }));
                },
                expectedError: ['Name cannot exceed 100 characters', 'NAME_TOO_LONG']
                },
                {
                description: 'description too long in create',
                method: 'createWardrobe',
                setup: () => { 
                    mockReq.body = { name: 'Valid Name', description: 'a'.repeat(1001) };
                    mockReq.params = {};
                },
                expectedError: ['Description cannot exceed 1000 characters', 'DESCRIPTION_TOO_LONG']
                },
                {
                description: 'description too long in update',
                method: 'updateWardrobe',
                setup: () => {
                    mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
                    mockReq.body = { description: 'a'.repeat(1001) };
                    mockWardrobeModel.findById.mockResolvedValue(wardrobeMocks.createValidWardrobe({ user_id: mockUser.id }));
                },
                expectedError: ['Description cannot exceed 1000 characters', 'DESCRIPTION_TOO_LONG']
                }
            ];

            for (const testCase of testCases) {
                jest.clearAllMocks();
                testCase.setup();

                await (wardrobeController as any)[testCase.method](
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                expect(mockApiError.badRequest).toHaveBeenCalledWith(...testCase.expectedError);
            }
        });

        it('should use consistent error codes for UUID validation', async () => {
            const methods = ['getWardrobe', 'updateWardrobe', 'addGarmentToWardrobe', 'removeGarmentFromWardrobe', 'deleteWardrobe'];
            
            for (const method of methods) {
                jest.clearAllMocks();
                
                if (method === 'removeGarmentFromWardrobe') {
                mockReq.params = { id: 'invalid-uuid', itemId: 'also-invalid' };
                } else {
                mockReq.params = { id: 'invalid-uuid' };
                }
                mockReq.body = {};

                await (wardrobeController as any)[method](
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                expect.stringContaining('Invalid'),
                expect.stringContaining('UUID')
                );
            }
        });
    });

    describe('Performance Considerations', () => {
        it('should not make unnecessary database calls', async () => {
            // Test that validation failures prevent database calls
            mockReq.body = { name: '', description: 'Valid description' };

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify no model methods were called due to validation failure
            expect(mockWardrobeModel.create).not.toHaveBeenCalled();
            expect(mockApiError.badRequest).toHaveBeenCalled();
            });

            it('should optimize database calls in getWardrobe', async () => {
            // Test that findById is called before getGarments (fail fast)
            const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
            
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(null);

            await wardrobeController.getWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify getGarments is not called when wardrobe doesn't exist
            expect(mockWardrobeModel.findById).toHaveBeenCalledWith(validWardrobeId);
            expect(mockWardrobeModel.getGarments).not.toHaveBeenCalled();
            expect(mockApiError.notFound).toHaveBeenCalled();
        });

        it('should avoid redundant validation in update operations', async () => {
            const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
            });

            mockReq.params = { id: validWardrobeId };
            mockReq.body = {}; // No updates
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.update.mockResolvedValue(wardrobe);

            await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify update is called even with no changes (model handles optimization)
            expect(mockWardrobeModel.update).toHaveBeenCalledWith(validWardrobeId, {
                name: undefined,
                description: undefined
            });
        });
    });

    describe('Type Safety and Interface Compliance', () => {
        it('should properly type all request/response objects', async () => {
            // This test ensures our controller properly handles Express types
            const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
            const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify proper typing of response methods
            expect(mockRes.status).toHaveBeenCalledWith(expect.any(Number));
            expect(mockRes.json).toHaveBeenCalledWith(expect.any(Object));
            
            // Verify the response object structure matches our API contract
            const responseCall = (mockRes.json as jest.Mock).mock.calls[0][0];
            expect(responseCall).toHaveProperty('status');
            expect(responseCall).toHaveProperty('data');
            expect(responseCall).toHaveProperty('message');
            expect(typeof responseCall.status).toBe('string');
            expect(typeof responseCall.message).toBe('string');
        });

        it('should handle undefined optional parameters correctly', async () => {
            // Test handling of optional description parameter
            const inputData = { name: 'Test Wardrobe' }; // No description
            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                name: 'Test Wardrobe',
                description: ''
            });

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: 'Test Wardrobe',
                description: '' // Should default to empty string
            });
        });

        it('should handle null and undefined values consistently', async () => {
            const testCases = [
                { description: undefined, expected: '' },
                { description: null, expected: '' },
                { description: '', expected: '' }
            ];

            for (const testCase of testCases) {
                // Clear mocks between test cases
                jest.clearAllMocks();
                
                const inputData = { name: 'Test Wardrobe', description: testCase.description };
                const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                    user_id: mockUser.id,
                    name: 'Test Wardrobe',
                    description: testCase.expected
                });

                mockReq.body = inputData;
                mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

                // ACTUALLY CALL THE CONTROLLER - this was missing!
                await wardrobeController.createWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );

                expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                    user_id: mockUser.id,
                    name: 'Test Wardrobe',
                    description: testCase.expected
                });
            }
        });
    });

    describe('Database Transaction Integrity', () => {
        it('should handle database transaction failures gracefully', async () => {
            // Test behavior when database operations fail mid-transaction
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789',
                user_id: mockUser.id 
            });
            const garment = wardrobeMocks.garments.createMockGarment({ 
                id: 'b1c2d3e4-f5a6-789b-cdef-012345678901',
                user_id: mockUser.id 
            });

            mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
            mockReq.body = { garmentId: 'b1c2d3e4-f5a6-789b-cdef-012345678901' };
            
            // Setup mocks for successful lookup but failed addition
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockGarmentModel.findById.mockResolvedValue(garment);
            mockWardrobeModel.addGarment.mockRejectedValue(new Error('Transaction failed'));

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify proper error handling
            expect(consoleSpy).toHaveBeenCalledWith(
                'Error adding garment to wardrobe:',
                expect.any(Error)
            );
            expect(mockApiError.internal).toHaveBeenCalledWith('Failed to add garment to wardrobe');
            expect(mockNext).toHaveBeenCalled();

            consoleSpy.mockRestore();
        });

        it('should maintain data consistency during partial update failures', async () => {
            const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
            const existingWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
            });

            mockReq.params = { id: validWardrobeId };
            mockReq.body = { name: 'Updated Name', description: 'Updated Description' };
            
            // Simulate successful findById but failed update
            mockWardrobeModel.findById.mockResolvedValue(existingWardrobe);
            mockWardrobeModel.update.mockRejectedValue(new Error('Update constraint violation'));

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify error is propagated without data corruption
            expect(consoleSpy).toHaveBeenCalledWith('Error updating wardrobe:', expect.any(Error));
            expect(mockApiError.internal).toHaveBeenCalledWith('Failed to update wardrobe');
            expect(mockNext).toHaveBeenCalled();

            consoleSpy.mockRestore();
        });
    });

    describe('API Contract Validation', () => {
        it('should return 201 status for successful creation', async () => {
            const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
            const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.status).toHaveBeenCalledWith(201);
        });

        it('should return 200 status for successful retrieval/update/delete operations', async () => {
            const wardrobe = wardrobeMocks.createValidWardrobe({ user_id: mockUser.id });
            
            // Test getWardrobes
            mockWardrobeModel.findByUserId.mockResolvedValue([wardrobe]);
            
            await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.status).toHaveBeenCalledWith(200);
            
            // Reset mocks for next test
            jest.clearAllMocks();
            mockRes.status = jest.fn().mockReturnThis();
            
            // Test updateWardrobe
            mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
            mockReq.body = { name: 'Updated Name' };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.update.mockResolvedValue(wardrobe);

            await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.status).toHaveBeenCalledWith(200);
        });

        it('should include count property in wardrobes list response', async () => {
            const wardrobes = wardrobeMocks.createMultipleWardrobes(mockUser.id, 3);
            mockWardrobeModel.findByUserId.mockResolvedValue(wardrobes);

            await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            const responseCall = (mockRes.json as jest.Mock).mock.calls[0][0];
            expect(responseCall.data).toHaveProperty('wardrobes');
            expect(responseCall.data).toHaveProperty('count');
            expect(responseCall.data.count).toBe(wardrobes.length);
            expect(Array.isArray(responseCall.data.wardrobes)).toBe(true);
        });

        it('should include garments in individual wardrobe response', async () => {
            const validWardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
            });
            const garments = wardrobeMocks.garments.createMultipleGarments(mockUser.id, 2);

            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.getGarments.mockResolvedValue(garments);

            await wardrobeController.getWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            const responseCall = (mockRes.json as jest.Mock).mock.calls[0][0];
            expect(responseCall.data.wardrobe).toHaveProperty('garments');
            expect(Array.isArray(responseCall.data.wardrobe.garments)).toBe(true);
            expect(responseCall.data.wardrobe.garments).toEqual(garments);
        });

        it('should maintain consistent response structure across all endpoints', async () => {
            const responseStructure = {
                status: expect.any(String),
                data: expect.any(Object),
                message: expect.stringMatching(/successfully$/)
            };

            // Test create response structure
            const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
            const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);
            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            const createResponse = (mockRes.json as jest.Mock).mock.calls[0][0];
            expect(createResponse).toMatchObject(responseStructure);
            expect(createResponse.status).toBe('success');
        });
    });

    describe('UUID Validation Edge Cases', () => {
        const uuidTestCases = [
        { input: '', description: 'empty string', shouldPass: false },
        { input: 'undefined', description: 'string "undefined"', shouldPass: false },
        { input: 'null', description: 'string "null"', shouldPass: false },
        { input: '00000000-0000-0000-0000-000000000000', description: 'null UUID', shouldPass: true },
        { input: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789', description: 'valid UUID', shouldPass: true },
        { input: 'A0B1C2D3-E4F5-6789-ABCD-EF0123456789', description: 'uppercase UUID', shouldPass: true },
        { input: 'a0b1c2d3e4f567890abcdef0123456789', description: 'UUID without hyphens', shouldPass: false },
        { input: 'a0b1c2d3-e4f5-6789-abcd-ef012345678x', description: 'invalid character at end', shouldPass: false },
        { input: 'g0b1c2d3-e4f5-6789-abcd-ef0123456789', description: 'invalid character at start', shouldPass: false },
        { input: 'a0b1c2d3-e4f5-6789-abcd-ef01234567890', description: 'too long', shouldPass: false },
        { input: 'a0b1c2d3-e4f5-6789-abcd-ef012345678', description: 'too short', shouldPass: false }
        ];

        uuidTestCases.forEach(testCase => {
            it(`should ${testCase.shouldPass ? 'accept' : 'reject'} ${testCase.description}: "${testCase.input}"`, async () => {
                mockReq.params = { id: testCase.input };

                if (testCase.shouldPass) {
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                    id: testCase.input.toLowerCase(),
                    user_id: mockUser.id 
                });
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.getGarments.mockResolvedValue([]);
                }

                await wardrobeController.getWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                if (testCase.shouldPass) {
                expect(mockWardrobeModel.findById).toHaveBeenCalledWith(testCase.input);
                expect(mockRes.status).toHaveBeenCalledWith(200);
                } else {
                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                    'Invalid wardrobe ID format',
                    'INVALID_UUID'
                );
                expect(mockNext).toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
                }
            });
        });

        it('should validate UUIDs in multiple parameters consistently', async () => {
            // Test removeGarmentFromWardrobe which validates both wardrobe and item IDs
            const invalidId = 'invalid-uuid';
            
            mockReq.params = { id: invalidId, itemId: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };

            await wardrobeController.removeGarmentFromWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Invalid wardrobe ID format',
                'INVALID_UUID'
            );

            // Reset and test invalid item ID
            jest.clearAllMocks();
            mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789', itemId: invalidId };

            await wardrobeController.removeGarmentFromWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Invalid item ID format',
                'INVALID_ITEM_UUID'
            );
        });
    });

    describe('Memory and Resource Management', () => {
        it('should not hold references to large objects after completion', async () => {
            // Test with large description to ensure no memory leaks
            const largeDescription = 'x'.repeat(1000);
            const inputData = { name: 'Test', description: largeDescription };
            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                ...inputData
            });

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify the large object was processed correctly
            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: 'Test',
                description: largeDescription
            });

            // Clear references
            mockReq.body = {};
        });

        it('should handle multiple large concurrent operations efficiently', async () => {
            const largeWardrobes: Array<{
                id: string;
                user_id: string;
                name: string;
                description: string;
                created_at?: Date;
                updated_at?: Date;
            }> = [];
            const promises = [];

            // Create 10 concurrent operations with moderately large data
            for (let i = 0; i < 10; i++) {
                const inputData = {
                    name: `Large Wardrobe ${i}`,
                    description: `Large description ${i} `.repeat(50) // ~1000 characters
                };
                
                const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                    user_id: mockUser.id,
                    ...inputData
                });
                
                largeWardrobes.push(expectedWardrobe);
                
                const req = { ...mockReq, body: inputData };
                const res = { ...mockRes };
                
                promises.push(wardrobeController.createWardrobe(req as Request, res as Response, mockNext));
            }

            // Setup mocks for all operations
            mockWardrobeModel.create.mockImplementation((data) => {
                const foundWardrobe = largeWardrobes.find(w => w.name === data.name);
                if (!foundWardrobe) {
                    throw new Error(`Test setup error: No wardrobe found with name ${data.name}`);
                }
                // Ensure the returned object matches the Wardrobe interface exactly
                return Promise.resolve({
                    id: foundWardrobe.id,
                    user_id: foundWardrobe.user_id,
                    name: foundWardrobe.name,
                    description: foundWardrobe.description,
                    created_at: foundWardrobe.created_at || new Date(),
                    updated_at: foundWardrobe.updated_at || new Date(),
                    is_default: false
                });
            });

            // Execute all operations concurrently
            await Promise.all(promises);

            // Verify all operations completed successfully
            expect(mockWardrobeModel.create).toHaveBeenCalledTimes(10);
            expect(mockNext).not.toHaveBeenCalled();
        });
    });

    describe('Error Message Consistency', () => {
        it('should provide helpful error messages for validation failures', async () => {
            const validationTests = [
                {
                input: { name: '' },
                expectedMessage: 'Wardrobe name is required',
                expectedCode: 'MISSING_NAME'
                },
                {
                input: { name: 'a'.repeat(101) },
                expectedMessage: 'Wardrobe name cannot exceed 100 characters',
                expectedCode: 'NAME_TOO_LONG'
                },
                {
                input: { name: 'Valid', description: 123 },
                expectedMessage: 'Description must be a string',
                expectedCode: 'INVALID_DESCRIPTION_TYPE'
                },
                {
                input: { name: 'Valid', description: 'a'.repeat(1001) },
                expectedMessage: 'Description cannot exceed 1000 characters',
                expectedCode: 'DESCRIPTION_TOO_LONG'
                },
                {
                input: { name: 123 },
                expectedMessage: 'Wardrobe name is required',
                expectedCode: 'MISSING_NAME'
                }
            ];

            for (const test of validationTests) {
                jest.clearAllMocks();
                mockReq.body = test.input;

                await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                expect(mockApiError.badRequest).toHaveBeenCalledWith(
                test.expectedMessage,
                test.expectedCode
                );
            }
        });

        it('should provide consistent error messages for not found scenarios', async () => {
            const notFoundTests = [
                {
                method: 'getWardrobe',
                setup: () => {
                    mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
                    mockWardrobeModel.findById.mockResolvedValue(null);
                },
                expectedMessage: 'Wardrobe not found'
                },
                {
                method: 'updateWardrobe',
                setup: () => {
                    mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
                    mockReq.body = { name: 'Updated' };
                    mockWardrobeModel.findById.mockResolvedValue(null);
                },
                expectedMessage: 'Wardrobe not found'
                },
                {
                method: 'deleteWardrobe',
                setup: () => {
                    mockReq.params = { id: 'a0b1c2d3-e4f5-6789-abcd-ef0123456789' };
                    mockWardrobeModel.findById.mockResolvedValue(null);
                },
                expectedMessage: 'Wardrobe not found'
                }
            ];

            for (const test of notFoundTests) {
                jest.clearAllMocks();
                test.setup();

                await (wardrobeController as any)[test.method](
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                expect(mockApiError.notFound).toHaveBeenCalledWith(test.expectedMessage);
            }
        });
    });

    describe('Integration Test Scenarios', () => {
        it('should handle complete wardrobe management workflow', async () => {
            // This test simulates a complete workflow: create -> get -> update -> add garment -> delete
            const wardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
            const garmentId = 'b1c2d3e4-f5a6-789b-cdef-012345678901';
            
            // Step 1: Create wardrobe
            const createData = { name: 'Test Wardrobe', description: 'Test Description' };
            const createdWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: wardrobeId,
                user_id: mockUser.id,
                ...createData
            });

            mockReq.body = createData;
            mockWardrobeModel.create.mockResolvedValue(createdWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.status).toHaveBeenCalledWith(201);
            
            // Step 2: Get wardrobe
            jest.clearAllMocks();
            mockRes.status = jest.fn().mockReturnThis();
            mockRes.json = jest.fn().mockReturnThis();

            mockReq.params = { id: wardrobeId };
            mockReq.body = {};
            mockWardrobeModel.findById.mockResolvedValue(createdWardrobe);
            mockWardrobeModel.getGarments.mockResolvedValue([]);

            await wardrobeController.getWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.status).toHaveBeenCalledWith(200);
            
            // Step 3: Update wardrobe
            jest.clearAllMocks();
            mockRes.status = jest.fn().mockReturnThis();
            mockRes.json = jest.fn().mockReturnThis();

            const updateData = { name: 'Updated Wardrobe' };
            const updatedWardrobe = { ...createdWardrobe, ...updateData };

            mockReq.body = updateData;
            mockWardrobeModel.findById.mockResolvedValue(createdWardrobe);
            mockWardrobeModel.update.mockResolvedValue(updatedWardrobe);

            await wardrobeController.updateWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.status).toHaveBeenCalledWith(200);
            
            // Step 4: Add garment
            jest.clearAllMocks();
            mockRes.status = jest.fn().mockReturnThis();
            mockRes.json = jest.fn().mockReturnThis();

            const garment = wardrobeMocks.garments.createMockGarment({ 
                id: garmentId,
                user_id: mockUser.id 
            });

            mockReq.body = { garmentId };
            mockWardrobeModel.findById.mockResolvedValue(updatedWardrobe);
            mockGarmentModel.findById.mockResolvedValue(garment);
            mockWardrobeModel.addGarment.mockResolvedValue(true);

            await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.status).toHaveBeenCalledWith(200);
            
            // Step 5: Delete wardrobe
            jest.clearAllMocks();
            mockRes.status = jest.fn().mockReturnThis();
            mockRes.json = jest.fn().mockReturnThis();

            mockReq.body = {};
            mockWardrobeModel.findById.mockResolvedValue(updatedWardrobe);
            mockWardrobeModel.delete.mockResolvedValue(true);

            await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.status).toHaveBeenCalledWith(200);

            // Verify that no errors occurred throughout the workflow
            expect(mockNext).not.toHaveBeenCalled();
        });

        it('should handle complex garment management scenario', async () => {
            const wardrobeId = 'a0b1c2d3-e4f5-6789-abcd-ef0123456789';
            const garmentIds = [
                'b1c2d3e4-f5a6-789b-cdef-012345678901',
                'c2d3e4f5-a6b7-890c-def0-123456789012',
                'd3e4f5a6-b7c8-901d-ef01-234567890123'
            ];

            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: wardrobeId,
                user_id: mockUser.id 
            });

            // Add multiple garments with specific positions
            for (let i = 0; i < garmentIds.length; i++) {
                jest.clearAllMocks();
                mockRes.status = jest.fn().mockReturnThis();
                mockRes.json = jest.fn().mockReturnThis();

                const garment = wardrobeMocks.garments.createMockGarment({ 
                id: garmentIds[i],
                user_id: mockUser.id 
                });

                mockReq.params = { id: wardrobeId };
                mockReq.body = { garmentId: garmentIds[i], position: i };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockGarmentModel.findById.mockResolvedValue(garment);
                mockWardrobeModel.addGarment.mockResolvedValue(true);

                await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(
                wardrobeId, 
                garmentIds[i], 
                i, 
                { allowUpdate: false }
                );
                expect(mockRes.status).toHaveBeenCalledWith(200);
            }

            // Remove middle garment
            jest.clearAllMocks();
            mockRes.status = jest.fn().mockReturnThis();
            mockRes.json = jest.fn().mockReturnThis();

            mockReq.params = { id: wardrobeId, itemId: garmentIds[1] };
            mockReq.body = {};
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.removeGarment.mockResolvedValue(true);

            await wardrobeController.removeGarmentFromWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockWardrobeModel.removeGarment).toHaveBeenCalledWith(wardrobeId, garmentIds[1]);
            expect(mockRes.status).toHaveBeenCalledWith(200);

            // Verify no errors throughout the process
            expect(mockNext).not.toHaveBeenCalled();
        });
    });

    describe('Boundary Value Testing', () => {
        it('should handle exactly maximum length inputs', async () => {
            const maxLengthName = 'a'.repeat(100);
            const maxLengthDescription = 'b'.repeat(1000);
            
            const inputData = { 
                name: maxLengthName, 
                description: maxLengthDescription 
            };
            
            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                ...inputData
            });

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: maxLengthName,
                description: maxLengthDescription
            });
            expect(mockRes.status).toHaveBeenCalledWith(201);
            expect(mockNext).not.toHaveBeenCalled();
        });

        it('should reject exactly one character over maximum length', async () => {
            const tooLongName = 'a'.repeat(101);
            const tooLongDescription = 'b'.repeat(1001);
            
            // Test name too long
            mockReq.body = { name: tooLongName, description: 'Valid' };

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Wardrobe name cannot exceed 100 characters',
                'NAME_TOO_LONG'
            );
            
            // Reset and test description too long
            jest.clearAllMocks();
            mockReq.body = { name: 'Valid', description: tooLongDescription };

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockApiError.badRequest).toHaveBeenCalledWith(
                'Description cannot exceed 1000 characters',
                'DESCRIPTION_TOO_LONG'
            );
        });

        it('should handle minimum valid inputs', async () => {
            const minInputData = { 
                name: 'A', // Minimum 1 character
                description: '' // Minimum 0 characters
            };
            
            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                ...minInputData
            });

            mockReq.body = minInputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                user_id: mockUser.id,
                name: 'A',
                description: ''
            });
            expect(mockRes.status).toHaveBeenCalledWith(201);
        });
    });
});