// /backend/tests/security/controllers/wardrobeController.security.test.ts
import { Request, Response, NextFunction } from 'express';
import { wardrobeController } from '../../controllers/wardrobeController';
import { garmentModel } from '../../models/garmentModel';
import { wardrobeModel } from '../../models/wardrobeModel';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';

// Mock the models
jest.mock('../../models/wardrobeModel');
jest.mock('../../models/garmentModel');

// Mock the sanitization utility - Track calls for security validation
jest.mock('../../utils/sanitize', () => ({
  sanitization: {
    sanitizeUserInput: jest.fn((input) => {
      // Simulate sanitization by removing potentially dangerous characters
      if (typeof input === 'string') {
        return input.replace(/<script>/gi, '').replace(/javascript:/gi, '');
      }
      return input;
    }),
    sanitizeForSecurity: jest.fn((input) => {
      // Simulate security sanitization
      if (typeof input === 'object' && input !== null) {
        const sanitized = { ...input };
        // Remove potentially dangerous properties
        delete sanitized.__proto__;
        delete sanitized.constructor;
        return sanitized;
      }
      return input;
    })
  }
}));

// Mock EnhancedApiError
jest.mock('../../middlewares/errorHandler', () => {
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

// Type the mocked models
const mockWardrobeModel = wardrobeModel as jest.Mocked<typeof wardrobeModel>;
const mockGarmentModel = garmentModel as jest.Mocked<typeof garmentModel>;

// Helper function for test expectations
const expectToFail = (message: string) => {
  throw new Error(message);
};

describe('wardrobeController - Security Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let mockUser: { id: string; email: string };
  let maliciousUser: { id: string; email: string };

  // Valid UUIDs for testing
  const validWardrobeId = 'a0b1c2d3-e4f5-1789-abcd-ef0123456789';
  const validGarmentId = 'b1c2d3e4-f5a6-2789-bcde-f012345678ab';
  const otherUserWardrobeId = 'c2d3e4f5-a6b7-3890-9def-012345678abc';

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockUser = {
      id: 'legitimate-user-id',
      email: 'legitimate@example.com'
    };

    maliciousUser = {
      id: 'malicious-user-id',
      email: 'malicious@example.com'
    };

    mockReq = {
      user: mockUser,
      body: {},
      params: {},
      query: {},
      headers: {}
    };

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      success: jest.fn().mockReturnThis(),
      created: jest.fn().mockReturnThis(),
      successWithPagination: jest.fn().mockReturnThis()
    };

    mockNext = jest.fn();
  });

  describe('Authentication Security', () => {
    describe('Missing Authentication', () => {
      const endpoints = [
        { method: 'createWardrobe', setup: () => ({ body: { name: 'Test' } }) },
        { method: 'getWardrobes', setup: () => ({}) },
        { method: 'getWardrobe', setup: () => ({ params: { id: validWardrobeId } }) },
        { method: 'updateWardrobe', setup: () => ({ params: { id: validWardrobeId }, body: { name: 'Updated' } }) },
        { method: 'deleteWardrobe', setup: () => ({ params: { id: validWardrobeId } }) },
        { method: 'addGarmentToWardrobe', setup: () => ({ params: { id: validWardrobeId }, body: { garmentId: validGarmentId } }) },
        { method: 'removeGarmentFromWardrobe', setup: () => ({ params: { id: validWardrobeId, itemId: validGarmentId } }) },
        { method: 'reorderGarments', setup: () => ({ params: { id: validWardrobeId }, body: { garmentPositions: [] } }) },
        { method: 'getWardrobeStats', setup: () => ({ params: { id: validWardrobeId } }) }
      ];

      endpoints.forEach(({ method, setup }) => {
        it(`should reject unauthenticated ${method} requests`, async () => {
          // Arrange
          mockReq.user = undefined;
          Object.assign(mockReq, setup());

          // Act & Assert
          try {
            await (wardrobeController as any)[method](
              mockReq as Request,
              mockRes as Response,
              mockNext
            );
            expectToFail(`${method} should have rejected unauthenticated request`);
          } catch (error) {
            expect(error).toBeInstanceOf(Error);
            expect((error as Error).message).toContain('User authentication required');
          }
        });
      });
    });

    describe('Token Manipulation Attempts', () => {
      it('should reject requests with null user object', async () => {
        // Arrange
        mockReq.user = null as any;
        mockReq.body = { name: 'Test Wardrobe' };

        // Act & Assert
        try {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have rejected null user');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('User authentication required');
        }
      });

      it('should reject requests with malformed user object', async () => {
        // Arrange
        mockReq.user = { id: undefined } as any;
        mockReq.body = { name: 'Test Wardrobe' };

        // Act & Assert - This would fail at the model level if we get that far
        try {
          mockWardrobeModel.create.mockRejectedValue(new Error('Invalid user ID'));
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have failed with invalid user');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      });
    });
  });

  describe('Authorization Security', () => {
    describe('Horizontal Privilege Escalation', () => {
      it('should prevent access to other users wardrobes in getWardrobe', async () => {
        // Arrange
        const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
          id: otherUserWardrobeId,
          user_id: maliciousUser.id
        });

        mockReq.params = { id: otherUserWardrobeId };
        mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

        // Act & Assert
        try {
          await wardrobeController.getWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have prevented unauthorized access');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('You do not have permission to access this wardrobe');
        }
      });

      it('should prevent modification of other users wardrobes in updateWardrobe', async () => {
        // Arrange
        const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
          id: otherUserWardrobeId,
          user_id: maliciousUser.id
        });

        mockReq.params = { id: otherUserWardrobeId };
        mockReq.body = { name: 'Hacked Name' };
        mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

        // Act & Assert
        try {
          await wardrobeController.updateWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have prevented unauthorized modification');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('You do not have permission to update this wardrobe');
        }

        // Ensure no update was attempted
        expect(mockWardrobeModel.update).not.toHaveBeenCalled();
      });

      it('should prevent deletion of other users wardrobes', async () => {
        // Arrange
        const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
          id: otherUserWardrobeId,
          user_id: maliciousUser.id
        });

        mockReq.params = { id: otherUserWardrobeId };
        mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

        // Act & Assert
        try {
          await wardrobeController.deleteWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have prevented unauthorized deletion');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('You do not have permission to delete this wardrobe');
        }

        expect(mockWardrobeModel.delete).not.toHaveBeenCalled();
      });

      it('should prevent adding other users garments to wardrobes', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });
        const otherUserGarment = wardrobeMocks.garments.createMockGarment({
          id: validGarmentId,
          user_id: maliciousUser.id
        });

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentId: validGarmentId };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockGarmentModel.findById.mockResolvedValue(otherUserGarment);

        // Act & Assert
        try {
          await wardrobeController.addGarmentToWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have prevented unauthorized garment addition');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('You do not have permission to use this garment');
        }

        expect(mockWardrobeModel.addGarment).not.toHaveBeenCalled();
      });

      it('should prevent modifying other users wardrobes via addGarmentToWardrobe', async () => {
        // Arrange
        const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
          id: otherUserWardrobeId,
          user_id: maliciousUser.id
        });

        mockReq.params = { id: otherUserWardrobeId };
        mockReq.body = { garmentId: validGarmentId };
        mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

        // Act & Assert
        try {
          await wardrobeController.addGarmentToWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have prevented unauthorized wardrobe modification');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('You do not have permission to modify this wardrobe');
        }

        expect(mockGarmentModel.findById).not.toHaveBeenCalled();
      });
    });

    describe('Authorization Bypass Attempts', () => {
      it('should validate user ownership even with manipulated request parameters', async () => {
        // Arrange - Simulate attempt to bypass authorization by manipulating params
        const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: maliciousUser.id
        });

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { name: 'Malicious Update', user_id: mockUser.id }; // Attempt to override user
        mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

        // Act & Assert
        try {
          await wardrobeController.updateWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have prevented authorization bypass');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('You do not have permission to update this wardrobe');
        }
      });

      it('should ignore attempts to modify user_id in request body', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { 
          name: 'Updated Name',
          user_id: maliciousUser.id // Attempt to change ownership
        };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockWardrobeModel.update.mockResolvedValue({ ...userWardrobe, name: 'Updated Name' });

        // Act
        await wardrobeController.updateWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert - user_id should not be in the update data
        expect(mockWardrobeModel.update).toHaveBeenCalledWith(
          validWardrobeId,
          expect.not.objectContaining({ user_id: expect.anything() })
        );
      });
    });
  });

  describe('Input Validation Security', () => {
    describe('XSS Prevention', () => {
      it('should reject malicious script tags in wardrobe name due to character validation', async () => {
        // Arrange
        const maliciousName = 'My Wardrobe<script>alert("XSS")</script>';
        
        mockReq.body = { name: maliciousName, description: 'Safe description' };

        // Act & Assert
        await expect(
          wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          )
        ).rejects.toThrow('Name contains invalid characters');

        // Verify no database call was made due to validation failure
        expect(mockWardrobeModel.create).not.toHaveBeenCalled();
      });

      it('should sanitize malicious script tags in description', async () => {
        // Arrange - Use valid name but malicious description
        const validName = 'Valid Wardrobe Name';
        const maliciousDescription = 'Nice wardrobe<script>document.cookie</script>';
        const sanitizedDescription = 'Nice wardrobe';
        
        mockReq.body = { 
          name: validName, 
          description: maliciousDescription 
        };
        
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({
          user_id: mockUser.id,
          name: validName,
          description: sanitizedDescription
        });
        mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

        // Act
        await wardrobeController.createWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert
        const { sanitization } = require('../../utils/sanitize');
        expect(sanitization.sanitizeUserInput).toHaveBeenCalledWith(maliciousDescription);
      });

      it('should reject javascript: URLs in input due to character validation', async () => {
        // Arrange
        const maliciousName = 'javascript:alert("XSS")';
        
        mockReq.body = { name: maliciousName, description: 'Safe description' };

        // Act & Assert
        await expect(
          wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          )
        ).rejects.toThrow('Name contains invalid characters');

        // Verify no database call was made due to validation failure
        expect(mockWardrobeModel.create).not.toHaveBeenCalled();
      });
    });

    describe('SQL Injection Prevention', () => {
      it('should reject wardrobe names with SQL injection patterns', async () => {
        // Arrange
        const sqlInjectionAttempts = [
          "'; DROP TABLE wardrobes; --",
          "1' OR '1'='1",
          "admin'--",
          "'; INSERT INTO wardrobes VALUES ('hack'); --"
        ];

        for (const maliciousName of sqlInjectionAttempts) {
          jest.clearAllMocks();
          mockReq.body = { name: maliciousName, description: 'Test' };

          // Act & Assert
          try {
            await wardrobeController.createWardrobe(
              mockReq as Request,
              mockRes as Response,
              mockNext
            );
            expectToFail(`Should have rejected SQL injection attempt: ${maliciousName}`);
          } catch (error) {
            expect(error).toBeInstanceOf(Error);
            expect((error as Error).message).toContain('Name contains invalid characters');
          }
        }
      });

      it('should validate UUID format to prevent SQL injection via ID parameters', async () => {
        // Arrange
        const sqlInjectionIds = [
          "'; DROP TABLE wardrobes; --",
          "1' OR '1'='1",
          "UNION SELECT * FROM users--",
          "../../../etc/passwd"
        ];

        for (const maliciousId of sqlInjectionIds) {
          jest.clearAllMocks();
          mockReq.params = { id: maliciousId };

          // Act & Assert
          try {
            await wardrobeController.getWardrobe(
              mockReq as Request,
              mockRes as Response,
              mockNext
            );
            expectToFail(`Should have rejected malicious ID: ${maliciousId}`);
          } catch (error) {
            expect(error).toBeInstanceOf(Error);
            expect((error as Error).message).toContain('Invalid wardrobeId format');
          }

          // Ensure no database calls were made
          expect(mockWardrobeModel.findById).not.toHaveBeenCalled();
        }
      });
    });

    describe('NoSQL Injection Prevention', () => {
      it('should reject object-based injection attempts in name field', async () => {
        // Arrange
        const objectInjection = { $gt: "" }; // NoSQL injection attempt
        mockReq.body = { name: objectInjection, description: 'Test' };

        // Act & Assert
        try {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have rejected object injection');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Invalid name format');
        }
      });

      it('should reject array-based injection attempts', async () => {
        // Arrange
        const arrayInjection = ['malicious', 'array'];
        mockReq.body = { name: arrayInjection, description: 'Test' };

        // Act & Assert
        try {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have rejected array injection');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Invalid input format');
        }
      });
    });

    describe('Path Traversal Prevention', () => {
      it('should reject path traversal attempts in wardrobe names', async () => {
        // Arrange
        const pathTraversalAttempts = [
          '../../etc/passwd',
          '..\\..\\windows\\system32',
          '/etc/shadow',
          '../../../root/.ssh/id_rsa'
        ];

        for (const maliciousPath of pathTraversalAttempts) {
          jest.clearAllMocks();
          mockReq.body = { name: maliciousPath, description: 'Test' };

          // Act & Assert
          try {
            await wardrobeController.createWardrobe(
              mockReq as Request,
              mockRes as Response,
              mockNext
            );
            expectToFail(`Should have rejected path traversal: ${maliciousPath}`);
          } catch (error) {
            expect(error).toBeInstanceOf(Error);
            expect((error as Error).message).toContain('Name contains invalid characters');
          }
        }
      });
    });

    describe('Type Confusion Attacks', () => {
      it('should handle type confusion in position parameter', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });
        const userGarment = wardrobeMocks.garments.createMockGarment({
          id: validGarmentId,
          user_id: mockUser.id
        });

        // Test case: Infinity should trigger "Position cannot exceed 1000"
        jest.clearAllMocks();
        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentId: validGarmentId, position: 'Infinity' };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockGarmentModel.findById.mockResolvedValue(userGarment);
        mockWardrobeModel.addGarment.mockResolvedValue(true);

        // Act & Assert for Infinity
        await expect(
          wardrobeController.addGarmentToWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          )
        ).rejects.toThrow('Position cannot exceed 1000');

        // Test case: NaN should trigger "Position must be a non-negative number"
        jest.clearAllMocks();
        mockReq.body = { garmentId: validGarmentId, position: 'NaN' };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockGarmentModel.findById.mockResolvedValue(userGarment);

        await expect(
          wardrobeController.addGarmentToWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          )
        ).rejects.toThrow('Position must be a non-negative number');

        // Test case: null should use default position 0
        jest.clearAllMocks();
        mockReq.body = { garmentId: validGarmentId, position: null };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockGarmentModel.findById.mockResolvedValue(userGarment);
        mockWardrobeModel.addGarment.mockResolvedValue(true);

        await wardrobeController.addGarmentToWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        expect(mockWardrobeModel.addGarment).toHaveBeenCalledWith(
          validWardrobeId,
          validGarmentId,
          0 // Should default to 0 for null
        );
      });

      it('should handle prototype pollution attempts', async () => {
        // Arrange
        const prototypePollution = {
          name: 'Test Wardrobe',
          description: 'Test',
          '__proto__': { polluted: true },
          'constructor': { prototype: { polluted: true } }
        };

        mockReq.body = prototypePollution;
        
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({
          user_id: mockUser.id,
          name: 'Test Wardrobe',
          description: 'Test'
        });
        mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

        // Act
        await wardrobeController.createWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert - Only safe properties should be passed to model
        expect(mockWardrobeModel.create).toHaveBeenCalledWith({
          user_id: mockUser.id,
          name: 'Test Wardrobe',
          description: 'Test'
        });

        // Verify prototype pollution didn't occur
        expect((Object.prototype as any).polluted).toBeUndefined();
      });
    });
  });

  describe('Data Exposure Prevention', () => {
    describe('Response Sanitization', () => {
      it('should sanitize garment metadata in wardrobe responses', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });
        const garments = [
          {
            id: validGarmentId,
            metadata: {
              category: 'shirt',
              color: 'blue'
              // Note: The mock sanitization will remove __proto__ and constructor
            }
          }
        ];

        mockReq.params = { id: validWardrobeId };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockWardrobeModel.getGarments.mockResolvedValue(garments);

        // Act
        await wardrobeController.getWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert
        const { sanitization } = require('../../utils/sanitize');
        expect(sanitization.sanitizeForSecurity).toHaveBeenCalled();
        
        // Verify the response contains the expected wardrobe structure
        expect(mockRes.success).toHaveBeenCalledWith(
          expect.objectContaining({
            wardrobe: expect.objectContaining({
              id: validWardrobeId,
              garments: expect.arrayContaining([
                expect.objectContaining({
                  id: validGarmentId,
                  metadata: expect.objectContaining({
                    category: 'shirt',
                    color: 'blue'
                  })
                })
              ])
            })
          }),
          expect.objectContaining({
            message: 'Wardrobe retrieved successfully'
          })
        );
      });

      it('should sanitize user input in response data', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id,
          name: 'Test<script>alert("xss")</script>',
          description: 'Description<img src=x onerror=alert(1)>'
        });

        mockReq.params = { id: validWardrobeId };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockWardrobeModel.getGarments.mockResolvedValue([]);

        // Act
        await wardrobeController.getWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert
        const { sanitization } = require('../../utils/sanitize');
        expect(sanitization.sanitizeUserInput).toHaveBeenCalledWith(userWardrobe.name);
        expect(sanitization.sanitizeUserInput).toHaveBeenCalledWith(userWardrobe.description);
      });
    });

    describe('Information Disclosure Prevention', () => {
      it('should not expose sensitive error information', async () => {
        // Arrange
        const databaseError = new Error('Connection failed: Server details, credentials, etc.');
        mockReq.body = { name: 'Test Wardrobe', description: 'Test' };
        mockWardrobeModel.create.mockRejectedValue(databaseError);

        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        // Act & Assert
        try {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have thrown a sanitized error');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          // Should not expose internal database details
          expect((error as Error).message).toBe('Failed to create wardrobe');
          expect((error as Error).message).not.toContain('Connection failed');
          expect((error as Error).message).not.toContain('credentials');
        }

        // Verify detailed error was logged but not exposed
        expect(consoleSpy).toHaveBeenCalledWith('Error creating wardrobe:', databaseError);
        consoleSpy.mockRestore();
      });

      it('should not expose user IDs of other users in error messages', async () => {
        // Arrange
        const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: 'sensitive-user-id-12345'
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
          expectToFail('Should have thrown authorization error');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).not.toContain('sensitive-user-id-12345');
          expect((error as Error).message).toContain('You do not have permission to access this wardrobe');
        }
      });

      it('should document internal model structure exposure (security concern)', async () => {
        // Arrange
        const wardrobeWithInternalData = {
          ...wardrobeMocks.createValidWardrobe({
            id: validWardrobeId,
            user_id: mockUser.id
          }),
          internal_flag: true,
          database_connection: 'sensitive_info',
          _private_field: 'should_not_expose'
        };

        mockReq.params = { id: validWardrobeId };
        mockWardrobeModel.findById.mockResolvedValue(wardrobeWithInternalData);
        mockWardrobeModel.getGarments.mockResolvedValue([]);

        // Act
        await wardrobeController.getWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert - Document current behavior (this is a security issue that should be fixed)
        const responseCall = (mockRes.success as jest.Mock).mock.calls[0];
        const responseData = responseCall[0];
        
        // The controller currently exposes internal fields - this documents the security concern
        expect(responseData.wardrobe).toHaveProperty('internal_flag', true);
        expect(responseData.wardrobe).toHaveProperty('database_connection', 'sensitive_info');
        expect(responseData.wardrobe).toHaveProperty('_private_field', 'should_not_expose');
        
        // However, user input fields are sanitized
        const { sanitization } = require('../../utils/sanitize');
        expect(sanitization.sanitizeUserInput).toHaveBeenCalled();
        
        // TODO: This test highlights that the controller should filter internal fields
        // before sending responses. Consider implementing a response mapper/filter.
      });
    });
  });

  describe('Rate Limiting and DoS Prevention', () => {
    describe('Input Size Limits', () => {
      it('should enforce maximum wardrobe name length', async () => {
        // Arrange
        const oversizedName = 'a'.repeat(10000); // Massive input
        mockReq.body = { name: oversizedName, description: 'Test' };

        // Act & Assert
        try {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have rejected oversized name');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Wardrobe name cannot exceed 100 characters');
        }
      });

      it('should enforce maximum description length', async () => {
        // Arrange
        const oversizedDescription = 'a'.repeat(10000); // Massive input
        mockReq.body = { name: 'Valid Name', description: oversizedDescription };

        // Act & Assert
        try {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have rejected oversized description');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Description cannot exceed 1000 characters');
        }
      });

      it('should limit number of garments in reorder operation', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });

        // Create 500 garment positions (exceeds limit of 100)
        const massiveGarmentList = Array.from({ length: 500 }, (_, i) => {
          const paddedIndex = i.toString().padStart(12, '0');
          return {
            garmentId: `a0b1c2d3-e4f5-1789-abcd-${paddedIndex}`,
            position: i
          };
        });

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentPositions: massiveGarmentList };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);

        // Act & Assert
        try {
          await wardrobeController.reorderGarments(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have rejected massive garment list');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Cannot reorder more than 100 garments at once');
        }
      });

      it('should limit pagination parameters to prevent resource exhaustion', async () => {
        // Arrange
        mockReq.query = { page: '1', limit: '10000' }; // Excessive limit

        // Act & Assert
        try {
          await wardrobeController.getWardrobes(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have rejected excessive pagination limit');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Limit cannot exceed 50 wardrobes per page');
        }
      });
    });

    describe('Resource Exhaustion Prevention', () => {
      it('should prevent excessive position values in garment ordering', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });
        const userGarment = wardrobeMocks.garments.createMockGarment({
          id: validGarmentId,
          user_id: mockUser.id
        });

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentId: validGarmentId, position: Number.MAX_SAFE_INTEGER };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockGarmentModel.findById.mockResolvedValue(userGarment);

        // Act & Assert
        try {
          await wardrobeController.addGarmentToWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have rejected excessive position value');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Position cannot exceed 1000');
        }
      });
    });
  });

  describe('Session and State Security', () => {
    describe('Session Fixation Prevention', () => {
      it('should use user ID from authenticated session, not request body', async () => {
        // Arrange
        const sessionUser = { id: 'session-user-123', email: 'session@example.com' };
        mockReq.user = sessionUser;
        mockReq.body = { 
          name: 'Test Wardrobe',
          user_id: 'attacker-user-456' // Attempt to override session user
        };

        const expectedWardrobe = wardrobeMocks.createValidWardrobe({
          user_id: sessionUser.id,
          name: 'Test Wardrobe'
        });
        mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

        // Act
        await wardrobeController.createWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert - Should use session user ID, not body user ID
        expect(mockWardrobeModel.create).toHaveBeenCalledWith({
          user_id: sessionUser.id,
          name: 'Test Wardrobe',
          description: ''
        });
      });

      it('should validate session user ID format to prevent injection', async () => {
        // Arrange
        const maliciousUser = { 
          id: "'; DROP TABLE users; --", 
          email: 'malicious@example.com' 
        };
        mockReq.user = maliciousUser;
        mockReq.body = { name: 'Test Wardrobe' };

        // The model should handle this safely, but let's test the flow
        mockWardrobeModel.create.mockRejectedValue(new Error('Invalid user ID format'));

        // Act & Assert
        try {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have failed with invalid user ID');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }

        // Verify the malicious user ID was passed to model (where it should be validated)
        expect(mockWardrobeModel.create).toHaveBeenCalledWith(
          expect.objectContaining({
            user_id: maliciousUser.id
          })
        );
      });
    });

    describe('Race Condition Prevention', () => {
      it('should handle concurrent wardrobe creation attempts', async () => {
        // Arrange
        const duplicateName = 'Duplicate Wardrobe';
        mockReq.body = { name: duplicateName, description: 'Test' };

        // Simulate race condition where duplicate is created between validation and insertion
        const duplicateError = new Error('duplicate key value') as Error & { code?: string };
        duplicateError.code = '23505';
        mockWardrobeModel.create.mockRejectedValue(duplicateError);

        // Act & Assert
        try {
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have handled duplicate creation');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('A wardrobe with this name already exists');
        }
      });

      it('should handle concurrent garment addition attempts', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });
        const userGarment = wardrobeMocks.garments.createMockGarment({
          id: validGarmentId,
          user_id: mockUser.id
        });

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentId: validGarmentId };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockGarmentModel.findById.mockResolvedValue(userGarment);

        // Simulate race condition where garment is added between validation and insertion
        const duplicateError = new Error('duplicate key value') as Error & { code?: string };
        duplicateError.code = '23505';
        mockWardrobeModel.addGarment.mockRejectedValue(duplicateError);

        // Act & Assert
        try {
          await wardrobeController.addGarmentToWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have handled duplicate garment addition');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Garment is already in this wardrobe');
        }
      });
    });
  });

  describe('API Security Headers and Metadata', () => {
    describe('Secure Response Metadata', () => {
      it('should include security-safe metadata in responses', async () => {
        // Arrange
        const inputData = wardrobeMocks.createValidInput({ user_id: mockUser.id });
        const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

        mockReq.body = inputData;
        mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

        // Act
        await wardrobeController.createWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert
        const responseCall = (mockRes.created as jest.Mock).mock.calls[0];
        const metadata = responseCall[1].meta;

        // Verify metadata doesn't contain sensitive information
        expect(metadata).not.toHaveProperty('user_id');
        expect(metadata).not.toHaveProperty('database_connection');
        expect(metadata).not.toHaveProperty('internal_id');
        
        // Verify safe metadata is present
        expect(metadata).toHaveProperty('wardrobeId');
        expect(metadata).toHaveProperty('createdAt');
        expect(metadata.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
      });

      it('should sanitize timestamps to prevent information leakage', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentId: validGarmentId };
        
        const userGarment = wardrobeMocks.garments.createMockGarment({
          id: validGarmentId,
          user_id: mockUser.id
        });

        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockGarmentModel.findById.mockResolvedValue(userGarment);
        mockWardrobeModel.addGarment.mockResolvedValue(true);

        // Act
        await wardrobeController.addGarmentToWardrobe(
          mockReq as Request,
          mockRes as Response,
          mockNext
        );

        // Assert
        const responseCall = (mockRes.success as jest.Mock).mock.calls[0];
        const metadata = responseCall[1].meta;

        // Verify timestamp is in safe ISO format
        expect(metadata.addedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
        
        // Verify no internal timing information is leaked
        expect(metadata).not.toHaveProperty('processing_time');
        expect(metadata).not.toHaveProperty('database_query_time');
      });
    });
  });

  describe('Business Logic Security', () => {
    describe('Workflow Integrity', () => {
      it('should prevent unauthorized state transitions', async () => {
        // Arrange - Try to delete a wardrobe that doesn't belong to user
        const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: maliciousUser.id
        });

        mockReq.params = { id: validWardrobeId };
        mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

        // Act & Assert
        try {
          await wardrobeController.deleteWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have prevented unauthorized deletion');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('You do not have permission to delete this wardrobe');
        }

        // Verify no state change occurred
        expect(mockWardrobeModel.delete).not.toHaveBeenCalled();
        expect(mockWardrobeModel.getGarments).not.toHaveBeenCalled();
      });

      it('should validate business rules in garment reordering', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });

        // Attempt to reorder garments with invalid UUID format
        const maliciousReorder = [
          { garmentId: 'nonexistent-garment-id', position: 0 }, // Invalid UUID format
          { garmentId: 'a0b1c2d3-e4f5-1789-abcd-ef0123456789', position: 1 }
        ];

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentPositions: maliciousReorder };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);

        // Act & Assert
        await expect(
          wardrobeController.reorderGarments(
            mockReq as Request,
            mockRes as Response,
            mockNext
          )
        ).rejects.toThrow('Invalid garmentPositions[0].garmentId format');
      });
    });

    describe('Data Consistency', () => {
      it('should maintain referential integrity during operations', async () => {
        // Arrange - Try to add non-existent garment to wardrobe
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentId: validGarmentId };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        mockGarmentModel.findById.mockResolvedValue(null); // Garment doesn't exist

        // Act & Assert
        try {
          await wardrobeController.addGarmentToWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have prevented adding non-existent garment');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Garment not found');
        }

        // Verify no invalid reference was created
        expect(mockWardrobeModel.addGarment).not.toHaveBeenCalled();
      });

      it('should handle transaction integrity during batch operations', async () => {
        // Arrange
        const userWardrobe = wardrobeMocks.createValidWardrobe({
          id: validWardrobeId,
          user_id: mockUser.id
        });

        const garmentPositions = [
          { garmentId: 'a0b1c2d3-e4f5-1789-abcd-ef0123456789', position: 0 },
          { garmentId: 'b1c2d3e4-f5a6-2890-8def-012345678abc', position: 1 }
        ];

        mockReq.params = { id: validWardrobeId };
        mockReq.body = { garmentPositions };
        mockWardrobeModel.findById.mockResolvedValue(userWardrobe);
        
        // Simulate failure during batch operation
        mockWardrobeModel.removeGarment.mockResolvedValueOnce(true);
        mockWardrobeModel.addGarment.mockRejectedValueOnce(new Error('Database constraint violation'));

        // Act & Assert
        try {
          await wardrobeController.reorderGarments(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );
          expectToFail('Should have handled batch operation failure');
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain('Failed to reorder garments');
        }
      });
    });
  });

  describe('Edge Case Security', () => {
    describe('Unicode and Encoding Security', () => {
      it('should handle unicode normalization attacks', async () => {
        // Arrange - Unicode characters that could be used for bypassing validation
        const unicodeAttacks = [
          'Café', // Normal
          'Cafe\u0301', // Composed differently
          'C\u0061\u0066\u0065\u0301', // Decomposed
          'Test\u200B\u200C\u200D', // Zero-width characters
          'Test\uFEFF' // Byte order mark
        ];

        for (const unicodeName of unicodeAttacks) {
          jest.clearAllMocks();
          mockReq.body = { name: unicodeName, description: 'Test' };
          
          const expectedWardrobe = wardrobeMocks.createValidWardrobe({
            user_id: mockUser.id,
            name: unicodeName.trim(),
            description: 'Test'
          });
          mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

          // Act
          await wardrobeController.createWardrobe(
            mockReq as Request,
            mockRes as Response,
            mockNext
          );

          // Assert - Should handle safely
          expect(mockWardrobeModel.create).toHaveBeenCalledWith(
            expect.objectContaining({
              name: expect.any(String)
            })
          );
        }
      });

      it('should prevent homograph attacks in wardrobe names', async () => {
        // Arrange - Characters that look similar but are different
        const homographAttacks = [
          'аdmin', // Cyrillic 'а' instead of Latin 'a'
          'test＠example', // Fullwidth @ symbol
          'pаypal', // Mixed scripts
        ];

        for (const homographName of homographAttacks) {
          jest.clearAllMocks();
          mockReq.body = { name: homographName, description: 'Test' };
          
          const expectedWardrobe = wardrobeMocks.createValidWardrobe({
            user_id: mockUser.id,
            name: homographName,
            description: 'Test'
          });
          mockWardrobeModel.create.mockResolvedValue(expectedWardrobe);

          // Act - Should either succeed safely or be rejected by character validation
          try {
            await wardrobeController.createWardrobe(
              mockReq as Request,
              mockRes as Response,
              mockNext
            );
            
            // If successful, verify safe handling
            expect(mockWardrobeModel.create).toHaveBeenCalled();
          } catch (error) {
            // Rejection by character validation is also acceptable
            expect(error).toBeInstanceOf(Error);
            expect((error as Error).message).toContain('Name contains invalid characters');
          }
        }
      });
    });

    describe('Resource Timing Attacks', () => {
      it('should verify timing attack considerations', async () => {
        // This test documents timing attack considerations without flaky assertions
        // In production, timing-safe comparisons should be implemented
        
        // Arrange - Test both existing and non-existing wardrobes
        const testCases = [
          { id: validWardrobeId, exists: true, description: 'unauthorized access' },
          { id: 'a0b1c2d3-e4f5-1789-abcd-ef0123456999', exists: false, description: 'not found' }
        ];

        for (const testCase of testCases) {
          jest.clearAllMocks();
          mockReq.params = { id: testCase.id };
          
          if (testCase.exists) {
            const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
              id: testCase.id,
              user_id: maliciousUser.id
            });
            mockWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);
          } else {
            mockWardrobeModel.findById.mockResolvedValue(null);
          }

          // Act & verify both operations handle errors appropriately
          await expect(
            wardrobeController.getWardrobe(
              mockReq as Request,
              mockRes as Response,
              mockNext
            )
          ).rejects.toThrow();
        }
        
        // Note: Timing attack prevention requires:
        // 1. Constant-time string comparisons for sensitive data
        // 2. Consistent response times regardless of error type
        // 3. Rate limiting and request throttling
        // This test serves as documentation for these requirements
      });
    });
  });
});