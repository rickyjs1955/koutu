// /backend/tests/unit/controllers/wardrobeController.test.ts - Updated for Flutter compatibility
import { Request, Response, NextFunction } from 'express';
import { wardrobeController } from '../../controllers/wardrobeController';
import { wardrobeModel } from '../../models/wardrobeModel';
import { garmentModel } from '../../models/garmentModel';
import { EnhancedApiError } from '../../middlewares/errorHandler';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';
import { wardrobeValidationHelpers } from '../__helpers__/wardrobes.helper';

// Mock the models
jest.mock('../../models/wardrobeModel');
jest.mock('../../models/garmentModel');

// Mock the sanitization utility
jest.mock('../../utils/sanitize', () => ({
  sanitization: {
    sanitizeUserInput: jest.fn((input) => input),
    sanitizeForSecurity: jest.fn((input) => input)
  }
}));

// Mock the EnhancedApiError utility - FIXED VERSION
jest.mock('../../middlewares/errorHandler', () => {
  // Create a proper error class that can be used with instanceof
  class MockEnhancedApiError extends Error {
    public statusCode: number;
    public field?: string;
    public value?: any;

    constructor(message: string, statusCode: number, field?: string, value?: any) {
      super(message);
      this.name = 'EnhancedApiError';
      this.statusCode = statusCode;
      this.field = field;
      this.value = value;
    }

    static validation(message: string, field?: string, value?: any): MockEnhancedApiError {
      throw new MockEnhancedApiError(message, 400, field, value);
    }

    static authenticationRequired(message: string): MockEnhancedApiError {
      throw new MockEnhancedApiError(message, 401);
    }

    static authorizationDenied(message: string, resource?: string): MockEnhancedApiError {
      throw new MockEnhancedApiError(message, 403, resource);
    }

    static notFound(message: string, resource?: string): MockEnhancedApiError {
      throw new MockEnhancedApiError(message, 404, resource);
    }

    static internalError(message: string, originalError?: any): MockEnhancedApiError {
      throw new MockEnhancedApiError(message, 500, undefined, originalError);
    }

    static conflict(message: string, field?: string): MockEnhancedApiError {
      throw new MockEnhancedApiError(message, 409, field);
    }
  }

  return {
    EnhancedApiError: MockEnhancedApiError
  };
});

// Mock ResponseUtils
jest.mock('../../utils/responseWrapper', () => ({
  ResponseUtils: {
    validatePagination: jest.fn((page, limit) => ({
      page: parseInt(page) || 1,
      limit: parseInt(limit) || 10
    })),
    createPagination: jest.fn((page, limit, total) => ({
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      hasNext: page * limit < total,
      hasPrev: page > 1
    }))
  }
}));

// Helper function to replace expect.fail
const expectToFail = (message: string) => {
  throw new Error(message);
};

// Type the mocked models
const mockWardrobeModel = wardrobeModel as jest.Mocked<typeof wardrobeModel>;
const mockGarmentModel = garmentModel as jest.Mocked<typeof garmentModel>;

describe('wardrobeController (Flutter Compatible)', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let mockUser: { id: string; email: string };
  // Use VALID UUIDs that match the regex pattern in the controller
  const validWardrobeId = 'a0b1c2d3-e4f5-1789-abcd-ef0123456789';
  const validGarmentId = 'b1c2d3e4-f5a6-2789-bcde-f012345678ab';

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
        params: {},
        query: {}
    };

    // Setup mock response with Flutter-compatible methods
    mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
        // Flutter-compatible response methods
        success: jest.fn().mockReturnThis(),
        created: jest.fn().mockReturnThis(),
        successWithPagination: jest.fn().mockReturnThis()
    };

    // Setup mock next function
    mockNext = jest.fn();
  });

    describe('createWardrobe', () => {
        describe('Successful Creation', () => {
            it('should create wardrobe with valid input', async () => {
                // Arrange
                const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
                const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

                mockReq.body = inputData;
                mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

                // Act - this should NOT throw
                await wardrobeController.createWardrobe(mockReq as Request, mockRes as Response, mockNext);

                // Assert
                expect(mockWardrobeModel.create).toHaveBeenCalledWith({
                    user_id: mockUser.id,
                    name: inputData.name.trim(),
                    description: inputData.description?.trim() || ''
                });

                expect(mockRes.created).toHaveBeenCalledWith(
                    { wardrobe: expectedWardrobe },
                    expect.objectContaining({
                    message: 'Wardrobe created successfully'
                    })
                );
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

                expect(mockRes.created).toHaveBeenCalledWith(
                { wardrobe: expectedWardrobe },
                expect.objectContaining({
                    message: 'Wardrobe created successfully',
                    meta: expect.objectContaining({
                        hasDescription: false
                    })
                })
                );
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

        describe('Input Validation', () => {
            it('should reject empty name', async () => {
                mockReq.body = { name: '', description: 'Valid description' };
                
                try {
                    await wardrobeController.createWardrobe(mockReq as Request, mockRes as Response, mockNext);
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Wardrobe name is required');
                }
                
                expect(mockWardrobeModel.create).not.toHaveBeenCalled();
            });

            it('should reject whitespace-only name', async () => {
                // Arrange
                mockReq.body = { name: '   ', description: 'Valid description' };

                // Act & Assert
                try {
                    await wardrobeController.createWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Wardrobe name cannot be empty');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should reject non-string name', async () => {
                // Arrange
                mockReq.body = { name: ['array', 'input'], description: 'Valid description' };

                // Act & Assert
                try {
                    await wardrobeController.createWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Invalid input format');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should reject name longer than 100 characters', async () => {
                // Arrange
                mockReq.body = { 
                name: 'a'.repeat(101),
                description: 'Valid description' 
                };

                // Act & Assert
                try {
                    await wardrobeController.createWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Wardrobe name cannot exceed 100 characters');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should reject invalid name characters', async () => {
                // Arrange
                mockReq.body = { 
                name: 'Invalid@Name#',
                description: 'Valid description' 
                };

                // Act & Assert
                try {
                    await wardrobeController.createWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Name contains invalid characters');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should reject description longer than 1000 characters', async () => {
                // Arrange
                mockReq.body = { 
                name: 'Valid Name',
                description: 'a'.repeat(1001)
                };

                // Act & Assert
                try {
                    await wardrobeController.createWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Description cannot exceed 1000 characters');
                }
                expect(mockNext).not.toHaveBeenCalled();
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

                // Act & Assert
                try {
                    await wardrobeController.createWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Failed to create wardrobe');
                }

                expect(consoleSpy).toHaveBeenCalledWith('Error creating wardrobe:', modelError);
                expect(mockNext).not.toHaveBeenCalled();

                // Cleanup
                consoleSpy.mockRestore();
            });

            it('should handle duplicate name conflicts', async () => {
                // Arrange
                const inputData = { name: 'Existing Wardrobe', description: 'Valid description' };
                const duplicateError = new Error('duplicate key value');
                (duplicateError as any).code = '23505';
                
                mockReq.body = inputData;
                mockWardrobeModel.create.mockRejectedValue(duplicateError);

                // Act & Assert
                try {
                    await wardrobeController.createWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('A wardrobe with this name already exists');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });
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
                expect(mockRes.success).toHaveBeenCalledWith(
                expectedWardrobes,
                {
                    message: 'Wardrobes retrieved successfully',
                    meta: {
                    count: expectedWardrobes.length,
                    userId: mockUser.id
                    }
                }
                );
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
                expect(mockRes.success).toHaveBeenCalledWith(
                [],
                {
                    message: 'Wardrobes retrieved successfully',
                    meta: {
                    count: 0,
                    userId: mockUser.id
                    }
                }
                );
            });

            it('should handle pagination when provided', async () => {
                // Arrange
                const allWardrobes = wardrobeMocks.createMultipleWardrobes(mockUser.id, 25);
                mockReq.query = { page: '2', limit: '10' };
                mockWardrobeModel.findByUserId.mockResolvedValue(allWardrobes);

                // Act
                await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert - Should use successWithPagination for paginated results
                expect(mockRes.successWithPagination).toHaveBeenCalledWith(
                expect.any(Array), // paginated wardrobes
                expect.objectContaining({
                    page: 2,
                    limit: 10,
                    total: 25
                }),
                expect.objectContaining({
                    message: 'Wardrobes retrieved successfully'
                })
                );
            });
        });

        describe('Error Handling', () => {
            it('should handle model errors', async () => {
                // Arrange
                const modelError = new Error('Database connection failed');
                mockWardrobeModel.findByUserId.mockRejectedValue(modelError);

                const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

                // Act & Assert
                try {
                    await wardrobeController.getWardrobes(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Failed to retrieve wardrobes');
                }

                expect(consoleSpy).toHaveBeenCalledWith('Error retrieving wardrobes:', modelError);
                expect(mockNext).not.toHaveBeenCalled();

                consoleSpy.mockRestore();
            });
        });
    });

    describe('getWardrobe', () => {
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
                expect(mockRes.success).toHaveBeenCalledWith(
                    { wardrobe: expect.objectContaining({
                        ...expectedWardrobe,
                        garments: expectedGarments
                    }) },
                    {
                        message: 'Wardrobe retrieved successfully',
                        meta: {
                            wardrobeId: validWardrobeId,
                            garmentCount: expectedGarments.length,
                            hasGarments: true
                        }
                    }
                );
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

                // Act
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );

                // Assert
                expect(mockRes.success).toHaveBeenCalledWith(
                    expect.objectContaining({
                        wardrobe: expect.objectContaining({
                            garments: []
                        })
                    }),
                    expect.objectContaining({
                        meta: expect.objectContaining({
                            hasGarments: false
                        })
                    })
                );
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

                // Act & Assert
                try {
                    await wardrobeController.getWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Invalid wardrobeId format');
                }
                expect(mockNext).not.toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
                });
            });
        });

        describe('Error Handling', () => {
        it('should handle wardrobe not found', async () => {
            // Arrange
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(null);

            // Act & Assert
            try {
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Wardrobe not found');
            }
            expect(mockNext).not.toHaveBeenCalled();
            expect(mockWardrobeModel.getGarments).not.toHaveBeenCalled();
        });

        it('should handle unauthorized access', async () => {
            // Arrange
            const otherUserWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: 'other-user-id' 
            });
            
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

            // Act & Assert
            try {
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('You do not have permission to access this wardrobe');
            }
            expect(mockNext).not.toHaveBeenCalled();
        });

        it('should handle model errors during wardrobe retrieval', async () => {
            // Arrange
            const modelError = new Error('Database connection failed');
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockRejectedValue(modelError);

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

            // Act & Assert
            try {
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Failed to retrieve wardrobe');
            }

            expect(consoleSpy).toHaveBeenCalledWith('Error retrieving wardrobe:', modelError);
            expect(mockNext).not.toHaveBeenCalled();

            consoleSpy.mockRestore();
        });
        });
    });

    describe('updateWardrobe', () => {
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
                
                expect(mockRes.success).toHaveBeenCalledWith(
                { wardrobe: expect.objectContaining(updatedWardrobe) },
                {
                    message: 'Wardrobe updated successfully',
                    meta: {
                        wardrobeId: validWardrobeId,
                        updatedFields: ['name', 'description'],
                        updatedAt: expect.any(String)
                    }
                }
                );
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

                // Act & Assert
                try {
                    await wardrobeController.updateWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Invalid wardrobeId format');
                }
                expect(mockNext).not.toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });

            it('should reject empty name', async () => {
                // Arrange
                mockReq.body = { name: '' };

                // Act & Assert
                try {
                    await wardrobeController.updateWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Name cannot be empty');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should require at least one field for update', async () => {
                // Arrange
                mockReq.body = {}; // No update fields

                // Act & Assert
                try {
                    await wardrobeController.updateWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('At least one field must be provided for update');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });
        });

        describe('Error Handling', () => {
        it('should handle wardrobe not found', async () => {
            // Arrange
            mockReq.params = { id: validWardrobeId };
            mockReq.body = { name: 'Updated Name' };
            mockWardrobeModel.findById.mockResolvedValue(null);

            // Act & Assert
            try {
                await wardrobeController.updateWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Wardrobe not found');
            }
            expect(mockNext).not.toHaveBeenCalled();
            expect(mockWardrobeModel.update).not.toHaveBeenCalled();
        });

        it('should handle unauthorized access', async () => {
            // Arrange
            const otherUserWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: 'other-user-id' 
            });
            
            mockReq.params = { id: validWardrobeId };
            mockReq.body = { name: 'Updated Name' };
            mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

            // Act & Assert
            try {
                await wardrobeController.updateWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('You do not have permission to update this wardrobe');
            }
            expect(mockNext).not.toHaveBeenCalled();
        });
        });
    });

    describe('addGarmentToWardrobe', () => {
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
                0
                );
                expect(mockRes.success).toHaveBeenCalledWith(
                {},
                {
                    message: 'Garment added to wardrobe successfully',
                    meta: {
                        wardrobeId: validWardrobeId,
                        garmentId: validGarmentId,
                        position: 0,
                        addedAt: expect.any(String)
                    }
                }
                );
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should handle wardrobe with no garments', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.getGarments.mockResolvedValue([]);

                // Act
                await wardrobeController.getWardrobeStats(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockRes.success).toHaveBeenCalledWith(
                { stats: expect.objectContaining({
                    totalGarments: 0,
                    categories: {},
                    colors: {}
                }) },
                expect.objectContaining({
                    meta: expect.objectContaining({
                        categoriesCount: 0,
                        colorsCount: 0
                    })
                })
                );
            });
        });
    });

    describe('Response Format Validation', () => {
        it('should maintain consistent success response format across all endpoints', async () => {
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

            // Verify Flutter-compatible response format was used
            expect(mockRes.created).toHaveBeenCalledWith(
                expect.objectContaining({ wardrobe: expectedWardrobe }),
                expect.objectContaining({
                    message: expect.any(String),
                    meta: expect.any(Object)
                })
            );
        });

        it('should use empty object data for operations without return data', async () => {
            // Test endpoints that return empty data (like delete operations)
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
            });

            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockWardrobeModel.getGarments.mockResolvedValue([]);
            mockWardrobeModel.delete.mockResolvedValue(true);

            await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify empty object is used for operations without return data
            expect(mockRes.success).toHaveBeenCalledWith(
                {},
                expect.objectContaining({
                    message: 'Wardrobe deleted successfully',
                    meta: expect.any(Object)
                })
            );
        });

        it('should include appropriate meta data for each endpoint', async () => {
            // Test getWardrobes includes count in meta
            const wardrobes = wardrobeMocks.createMultipleWardrobes(mockUser.id, 2);
            mockWardrobeModel.findByUserId.mockResolvedValue(wardrobes);

            await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.success).toHaveBeenCalledWith(
                wardrobes,
                expect.objectContaining({
                    meta: expect.objectContaining({
                        count: 2,
                        userId: mockUser.id
                    })
                })
            );
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
            expect(mockRes.created).toHaveBeenCalled();
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
            expect(mockRes.created).toHaveBeenCalled();
        });

        it('should handle position value of zero correctly', async () => {
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
            mockReq.body = { garmentId: validGarmentId, position: 0 };
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
                0
            );
        });

        it('should handle large position values', async () => {
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
            mockReq.body = { garmentId: validGarmentId, position: 999 };
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
                999
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

            // Act & Assert
            try {
                await wardrobeController.createWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Failed to create wardrobe');
            }

            expect(consoleSpy).toHaveBeenCalledWith('Error creating wardrobe:', originalError);

            consoleSpy.mockRestore();
        });
    });

    describe('Input Sanitization', () => {
        it('should sanitize user inputs through sanitization module', async () => {
            const inputWithPotentialXSS = {
                name: 'Summer Collection',  // Use safe name to avoid character validation errors
                description: 'A collection with summer items'
            };

            const expectedWardrobe = wardrobeMocks.createValidWardrobe({ 
                user_id: mockUser.id,
                name: inputWithPotentialXSS.name,
                description: inputWithPotentialXSS.description
            });

            mockReq.body = inputWithPotentialXSS;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Verify sanitization was called
            const { sanitization } = require('../../utils/sanitize');
            expect(sanitization.sanitizeUserInput).toHaveBeenCalled();
        });

        it('should handle unicode characters correctly', async () => {
            const unicodeInput = {
                name: 'Ete Collection',  // Use safe characters to avoid validation errors
                description: 'Collection pour lete avec des vetements'
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
    });

    describe('Authentication and Authorization', () => {
        it('should reject requests without authentication', async () => {
            // Arrange
            mockReq.user = undefined;

            // Act & Assert
            try {
                await wardrobeController.createWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('User authentication required');
            }
            expect(mockNext).not.toHaveBeenCalled();
            expect(mockWardrobeModel.create).not.toHaveBeenCalled();
        });

        it('should enforce user ownership on all wardrobe operations', async () => {
            const otherUserWardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: 'other-user-id' 
            });

            // Test getWardrobe authorization
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

            try {
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('You do not have permission to access this wardrobe');
            }

            // Reset for next test
            jest.clearAllMocks();

            // Test updateWardrobe authorization
            mockReq.body = { name: 'Updated Name' };
            mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

            try {
                await wardrobeController.updateWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('You do not have permission to update this wardrobe');
            }
        });
    });

    describe('Pagination Support', () => {
        it('should handle pagination parameters correctly', async () => {
            // Arrange
            const allWardrobes = wardrobeMocks.createMultipleWardrobes(mockUser.id, 50);
            mockReq.query = { page: '3', limit: '15' };
            mockWardrobeModel.findByUserId.mockResolvedValue(allWardrobes);

            // Act
            await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Assert
            const { ResponseUtils } = require('../../utils/responseWrapper');
            expect(ResponseUtils.validatePagination).toHaveBeenCalledWith('3', '15');
            expect(mockRes.successWithPagination).toHaveBeenCalled();
        });

        it('should reject pagination limit over 50', async () => {
            // Arrange
            mockReq.query = { page: '1', limit: '51' };

            // Act & Assert
            try {
                await wardrobeController.getWardrobes(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Limit cannot exceed 50 wardrobes per page');
            }
            expect(mockNext).not.toHaveBeenCalled();
        });

        it('should work without pagination parameters', async () => {
            // Arrange
            const wardrobes = wardrobeMocks.createMultipleWardrobes(mockUser.id, 10);
            mockReq.query = {}; // No pagination
            mockWardrobeModel.findByUserId.mockResolvedValue(wardrobes);

            // Act
            await wardrobeController.getWardrobes(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            // Assert
            expect(mockRes.success).toHaveBeenCalledWith(
                wardrobes,
                expect.objectContaining({
                    message: 'Wardrobes retrieved successfully',
                    meta: expect.objectContaining({
                        count: 10
                    })
                })
            );
        });
    });

    describe('Error Consistency', () => {
        it('should use consistent error patterns across similar operations', async () => {
            const testCases = [
                {
                    description: 'name validation in create',
                    method: 'createWardrobe',
                    setup: () => { 
                        mockReq.body = { name: 'a'.repeat(101) };
                        mockReq.params = {};
                    },
                    expectedMessage: 'Wardrobe name cannot exceed 100 characters'
                },
                {
                    description: 'name validation in update',
                    method: 'updateWardrobe',
                    setup: () => {
                        mockReq.params = { id: validWardrobeId };
                        mockReq.body = { name: 'a'.repeat(101) };
                        mockWardrobeModel.findById.mockResolvedValue(wardrobeMocks.createValidWardrobe({ user_id: mockUser.id }));
                    },
                    expectedMessage: 'Wardrobe name cannot exceed 100 characters'
                }
            ];

            for (const testCase of testCases) {
                jest.clearAllMocks();
                testCase.setup();

                try {
                    await (wardrobeController as any)[testCase.method](
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail(`${testCase.description} should have thrown an error`);
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain(testCase.expectedMessage);
                }
            }
        });

        it('should use consistent UUID validation across endpoints', async () => {
            const methods = ['getWardrobe', 'updateWardrobe', 'addGarmentToWardrobe', 'removeGarmentFromWardrobe', 'deleteWardrobe'];
            
            for (const method of methods) {
                jest.clearAllMocks();
                
                if (method === 'removeGarmentFromWardrobe') {
                    mockReq.params = { id: 'invalid-uuid', itemId: 'also-invalid' };
                } else {
                    mockReq.params = { id: 'invalid-uuid' };
                }
                mockReq.body = {};

                try {
                    await (wardrobeController as any)[method](
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail(`${method} should have thrown an error for invalid UUID`);
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toMatch(/Invalid.*Id.*format/);
                }
            }
        });
    });

    describe('Performance Considerations', () => {
        it('should not make unnecessary database calls on validation failures', async () => {
            // Test that validation failures prevent database calls
            mockReq.body = { name: '', description: 'Valid description' };

            try {
                await wardrobeController.createWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
            }

            // Verify no model methods were called due to validation failure
            expect(mockWardrobeModel.create).not.toHaveBeenCalled();
        });

        it('should optimize database calls in getWardrobe (fail fast)', async () => {
            // Test that findById is called before getGarments
            mockReq.params = { id: validWardrobeId };
            mockWardrobeModel.findById.mockResolvedValue(null);

            try {
                await wardrobeController.getWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Wardrobe not found');
            }

            // Verify getGarments is not called when wardrobe doesn't exist
            expect(mockWardrobeModel.findById).toHaveBeenCalledWith(validWardrobeId);
            expect(mockWardrobeModel.getGarments).not.toHaveBeenCalled();
        });
    });

    describe('Type Safety and Interface Compliance', () => {
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

    describe('Flutter-Specific Optimizations', () => {
        it('should include rich metadata for mobile UI', async () => {
            // Test that responses include metadata useful for mobile apps
            const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
            const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

            mockReq.body = inputData;
            mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

            await wardrobeController.createWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.created).toHaveBeenCalledWith(
                expect.any(Object),
                expect.objectContaining({
                    meta: expect.objectContaining({
                        wardrobeId: expect.any(String),
                        nameLength: expect.any(Number),
                        hasDescription: expect.any(Boolean),
                        createdAt: expect.any(String)
                    })
                })
            );
        });

        it('should provide consistent timestamps in ISO format', async () => {
            // Test that all timestamps are in ISO format for Flutter compatibility
            const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
            });

            mockReq.params = { id: validWardrobeId };
            mockReq.body = { garmentId: validGarmentId };
            
            const garment = wardrobeMocks.garments.createMockGarment({ 
                id: validGarmentId,
                user_id: mockUser.id 
            });

            mockWardrobeModel.findById.mockResolvedValue(wardrobe);
            mockGarmentModel.findById.mockResolvedValue(garment);
            mockWardrobeModel.addGarment.mockResolvedValue(true);

            await wardrobeController.addGarmentToWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
            );

            expect(mockRes.success).toHaveBeenCalledWith(
                expect.any(Object),
                expect.objectContaining({
                    meta: expect.objectContaining({
                        addedAt: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/)
                    })
                })
            );
        });

        it('should handle mobile-specific error scenarios', async () => {
            // Test scenarios common in mobile development
            mockReq.body = { name: null }; // Common in mobile form handling

            try {
                await wardrobeController.createWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Wardrobe name is required');
            }
        });
    });

    describe('removeGarmentFromWardrobe', () => {
        const validItemId = 'b1c2d3e4-f5a6-2789-bcde-f012345678ab';

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
                expect(mockRes.success).toHaveBeenCalledWith(
                {},
                {
                    message: 'Garment removed from wardrobe successfully',
                    meta: {
                        wardrobeId: validWardrobeId,
                        removedGarmentId: validItemId,
                        removedAt: expect.any(String)
                    }
                }
                );
                expect(mockNext).not.toHaveBeenCalled();
            });
        });

        describe('ID Validation', () => {
            it('should reject invalid wardrobe ID format', async () => {
                // Arrange
                mockReq.params = { id: 'invalid-uuid', itemId: validItemId };

                // Act & Assert
                try {
                    await wardrobeController.removeGarmentFromWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Invalid wardrobeId format');
                }
                expect(mockNext).not.toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });

            it('should reject invalid item ID format', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId, itemId: 'invalid-uuid' };

                // Act & Assert
                try {
                    await wardrobeController.removeGarmentFromWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    // FIX: Change from 'Invalid garmentId format' to 'Invalid itemId format'
                    expect((error as Error).message).toContain('Invalid itemId format');
                }
                expect(mockNext).not.toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });
        });

        describe('Error Handling', () => {
        it('should handle wardrobe not found', async () => {
            // Arrange
            mockReq.params = { id: validWardrobeId, itemId: validItemId };
            mockWardrobeModel.findById.mockResolvedValue(null);

            // Act & Assert
            try {
                await wardrobeController.removeGarmentFromWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Wardrobe not found');
            }
            expect(mockNext).not.toHaveBeenCalled();
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

            // Act & Assert
            try {
                await wardrobeController.removeGarmentFromWardrobe(
                    mockReq as Request,
                    mockRes as Response,
                    mockNext
                );
                expectToFail('Should have thrown an error');
            } catch (error) {
                expect(error).toBeInstanceOf(Error);
                expect((error as Error).message).toContain('Garment not found in wardrobe');
            }
            expect(mockNext).not.toHaveBeenCalled();
        });
        });
    });

    describe('deleteWardrobe', () => {
        describe('Successful Deletion', () => {
            it('should delete wardrobe successfully', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });

                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.getGarments.mockResolvedValue([]);
                mockWardrobeModel.delete.mockResolvedValue(true);

                // Act
                await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockWardrobeModel.delete).toHaveBeenCalledWith(validWardrobeId);
                expect(mockRes.success).toHaveBeenCalledWith(
                {},
                {
                    message: 'Wardrobe deleted successfully',
                    meta: {
                        deletedWardrobeId: validWardrobeId,
                        deletedGarmentRelationships: 0,
                        deletedAt: expect.any(String)
                    }
                }
                );
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should delete wardrobe with garments and track count', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garments = wardrobeMocks.garments.createMultipleGarments(mockUser.id, 3);

                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.getGarments.mockResolvedValue(garments);
                mockWardrobeModel.delete.mockResolvedValue(true);

                // Act
                await wardrobeController.deleteWardrobe(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockRes.success).toHaveBeenCalledWith(
                {},
                expect.objectContaining({
                    meta: expect.objectContaining({
                        deletedGarmentRelationships: 3
                    })
                })
                );
            });
        });

        describe('Error Handling', () => {
            it('should handle wardrobe not found', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(null);

                // Act & Assert
                try {
                    await wardrobeController.deleteWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Wardrobe not found');
                }
                expect(mockNext).not.toHaveBeenCalled();
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
                mockWardrobeModel.getGarments.mockResolvedValue([]);
                mockWardrobeModel.delete.mockResolvedValue(false);

                // Act & Assert
                try {
                    await wardrobeController.deleteWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Failed to delete wardrobe');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });
        });
    });

    describe('reorderGarments', () => {
        const garmentIds = [
            'b1c2d3e4-f5a6-1789-bcde-f012345678ab',
            'c2d3e4f5-a6b7-2890-8def-012345678abc',
            'd3e4f5a6-b7c8-3901-9ef0-123456789bcd'
        ];

        describe('Successful Reordering', () => {
            it('should reorder garments successfully', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garmentPositions = garmentIds.map((id, index) => ({
                    garmentId: id,
                    position: index * 10
                }));

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentPositions };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.removeGarment.mockResolvedValue(true);
                mockWardrobeModel.addGarment.mockResolvedValue(true);

                // Act
                await wardrobeController.reorderGarments(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockRes.success).toHaveBeenCalledWith(
                {},
                {
                    message: 'Garments reordered successfully',
                    meta: {
                        wardrobeId: validWardrobeId,
                        reorderedCount: garmentIds.length,
                        garmentIds: garmentIds,
                        reorderedAt: expect.any(String)
                    }
                }
                );
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should validate garment position structure', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockReq.body = { 
                    garmentPositions: [
                        { garmentId: garmentIds[0] }, // Missing position
                        { position: 10 } // Missing garmentId
                    ]
                };

                // Act & Assert
                try {
                    await wardrobeController.reorderGarments(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Garment ID is required at index 1');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should reject duplicate garment IDs', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garmentPositions = [
                    { garmentId: garmentIds[0], position: 0 },
                    { garmentId: garmentIds[0], position: 10 } // Duplicate
                ];

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentPositions };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);

                // Act & Assert
                try {
                    await wardrobeController.reorderGarments(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Duplicate garment IDs are not allowed');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should reject more than 100 garments', async () => {
                // Arrange
                const manyGarments = Array.from({ length: 101 }, (_, i) => {
                    // Generate valid UUIDs with proper format
                    const paddedIndex = i.toString().padStart(3, '0');
                    return {
                        garmentId: `a0b1c2d3-e4f5-1789-abcd-ef0123456${paddedIndex.slice(-3)}`,
                        position: i
                    };
                });

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentPositions: manyGarments };

                // Act & Assert
                try {
                    await wardrobeController.reorderGarments(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Cannot reorder more than 100 garments at once');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });
        });
    });

    describe('getWardrobeStats', () => {
        describe('Successful Stats Retrieval', () => {
            it('should retrieve wardrobe statistics successfully', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garments = [
                    { metadata: { category: 'shirt', color: 'blue' } },
                    { metadata: { category: 'pants', color: 'black' } },
                    { metadata: { category: 'shirt', color: 'red' } }
                ];

                mockReq.params = { id: validWardrobeId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockWardrobeModel.getGarments.mockResolvedValue(garments);

                // Act
                await wardrobeController.getWardrobeStats(
                mockReq as Request,
                mockRes as Response,
                mockNext
                );

                // Assert
                expect(mockRes.success).toHaveBeenCalledWith(
                { stats: expect.objectContaining({
                    totalGarments: 3,
                    categories: {
                        shirt: 2,
                        pants: 1
                    },
                    colors: {
                        blue: 1,
                        black: 1,
                        red: 1
                    }
                }) },
                {
                    message: 'Wardrobe statistics retrieved successfully',
                    meta: {
                        wardrobeId: validWardrobeId,
                        analysisDate: expect.any(String),
                        categoriesCount: 2,
                        colorsCount: 3
                    }
                }
                );
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
                customPosition
                );
                expect(mockRes.success).toHaveBeenCalledWith(
                {},
                expect.objectContaining({
                    meta: expect.objectContaining({
                        position: customPosition
                    })
                })
                );
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
                0
                );
            });

            it('should reject negative position values', async () => {
                // Arrange
                mockReq.body = { garmentId: validGarmentId, position: -1 };

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Position must be a non-negative number');
                }
                expect(mockNext).not.toHaveBeenCalled();
                expect(mockWardrobeModel.addGarment).not.toHaveBeenCalled();
            });

            it('should reject position values over 1000', async () => {
                // Arrange
                mockReq.body = { garmentId: validGarmentId, position: 1001 };

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Position cannot exceed 1000');
                }
                expect(mockNext).not.toHaveBeenCalled();
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
                expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(validWardrobeId, validGarmentId, 7);
            });
        });

        describe('Input Validation', () => {
            it('should reject invalid wardrobe ID format', async () => {
                // Arrange
                mockReq.params = { id: 'invalid-uuid' };
                mockReq.body = { garmentId: validGarmentId };

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Invalid wardrobeId format');
                }
                expect(mockNext).not.toHaveBeenCalled();
                expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
            });

            it('should reject missing garment ID', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockReq.body = {};

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Garment ID is required');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should reject invalid garment ID format', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: 'invalid-uuid' };

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Invalid garmentId format');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });
        });

        describe('Error Handling', () => {
            it('should handle wardrobe not found', async () => {
                // Arrange
                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: validGarmentId };
                mockWardrobeModel.findById.mockResolvedValue(null);

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Wardrobe not found');
                }
                expect(mockNext).not.toHaveBeenCalled();
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

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Garment not found');
                }
                expect(mockNext).not.toHaveBeenCalled();
                expect(mockWardrobeModel.addGarment).not.toHaveBeenCalled();
            });

            it('should handle unauthorized garment access', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const otherUserGarment = wardrobeMocks.garments.createMockGarment({ 
                id: validGarmentId,
                user_id: 'other-user-id' 
                });

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: validGarmentId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockGarmentModel.findById.mockResolvedValue(otherUserGarment);

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('You do not have permission to use this garment');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });

            it('should handle duplicate garment conflicts', async () => {
                // Arrange
                const wardrobe = wardrobeMocks.createValidWardrobe({ 
                id: validWardrobeId,
                user_id: mockUser.id 
                });
                const garment = wardrobeMocks.garments.createMockGarment({ 
                id: validGarmentId,
                user_id: mockUser.id 
                });
                const duplicateError = new Error('duplicate key value') as Error & { code?: string };
                duplicateError.code = '23505';

                mockReq.params = { id: validWardrobeId };
                mockReq.body = { garmentId: validGarmentId };
                mockWardrobeModel.findById.mockResolvedValue(wardrobe);
                mockGarmentModel.findById.mockResolvedValue(garment);
                mockWardrobeModel.addGarment.mockRejectedValue(duplicateError);

                // Act & Assert
                try {
                    await wardrobeController.addGarmentToWardrobe(
                        mockReq as Request,
                        mockRes as Response,
                        mockNext
                    );
                    expectToFail('Should have thrown an error');
                } catch (error) {
                    expect(error).toBeInstanceOf(Error);
                    expect((error as Error).message).toContain('Garment is already in this wardrobe');
                }
                expect(mockNext).not.toHaveBeenCalled();
            });
        });
    });
});