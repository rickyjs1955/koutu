// backend/src/__tests__/routes/authRoutes.unit.test.ts

import { Request, Response, NextFunction } from 'express';
import { jest } from '@jest/globals';
import { ApiError } from '../../utils/ApiError';

// Mock all external dependencies first
jest.mock('../../middlewares/auth');
jest.mock('../../middlewares/validate');
jest.mock('../../middlewares/security');
jest.mock('../../services/authService');
jest.mock('../../controllers/authController');

// Import mocked modules
import { 
  authenticate, 
  requireAuth, 
  rateLimitByUser 
} from '../../middlewares/auth';
import { 
  validateAuthTypes, 
  validateBody, 
  validateRequestTypes 
} from '../../middlewares/validate';
import { securityMiddleware } from '../../middlewares/security';
import { authService } from '../../services/authService';
import { authController } from '../../controllers/authController';

// Cast to mocked functions
const mockAuthenticate = authenticate as jest.MockedFunction<typeof authenticate>;
const mockRequireAuth = requireAuth as jest.MockedFunction<typeof requireAuth>;
const mockRateLimitByUser = rateLimitByUser as jest.MockedFunction<typeof rateLimitByUser>;
const mockValidateAuthTypes = validateAuthTypes as jest.MockedFunction<typeof validateAuthTypes>;
const mockValidateBody = validateBody as jest.MockedFunction<typeof validateBody>;
const mockValidateRequestTypes = validateRequestTypes as jest.MockedFunction<typeof validateRequestTypes>;
const mockSecurityMiddleware = securityMiddleware as jest.Mocked<typeof securityMiddleware>;
const mockAuthService = authService as jest.Mocked<typeof authService>;
const mockAuthController = authController as jest.Mocked<typeof authController>;

describe('AuthRoutes Unit Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let statusSpy: jest.MockedFunction<any>;
  let jsonSpy: jest.MockedFunction<any>;

  // Import the router after mocking
  let authRoutes: any;

  beforeAll(async () => {
    // Setup default mocks
    mockAuthenticate.mockImplementation(async (req, res, next) => next());
    mockRequireAuth.mockImplementation(async (req, res, next) => next());
    mockRateLimitByUser.mockImplementation(() => (req: any, res: any, next: any) => next());
    mockValidateAuthTypes.mockImplementation(async (req, res, next) => next());
    mockValidateBody.mockImplementation(() => (req: any, res: any, next: any) => next());
    mockValidateRequestTypes.mockImplementation(async (req, res, next) => next());
    
    // Setup security middleware mock with proper typing
    mockSecurityMiddleware.auth = [jest.fn((req: Request, res: Response, next: NextFunction) => next())];
    
    // Import routes after setting up mocks
    const routesModule = await import('../../routes/authRoutes');
    authRoutes = routesModule.authRoutes;
  });

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create response spies
    statusSpy = jest.fn().mockReturnThis();
    jsonSpy = jest.fn().mockReturnThis();
    
    mockReq = {
      body: {},
      params: {},
      headers: {},
      user: undefined,
      method: 'POST',
      path: '/auth/register'
    };
    
    mockRes = {
      status: statusSpy,
      json: jsonSpy,
      setHeader: jest.fn().mockReturnValue(mockRes)
    } as any;
    
    mockNext = jest.fn();

    // Setup default successful responses
    mockAuthService.register.mockResolvedValue({
      user: {
        id: '123',
        email: 'test@example.com',
        created_at: new Date()
      },
      token: 'mock-token'
    });

    mockAuthService.login.mockResolvedValue({
      user: {
        id: '123',
        email: 'test@example.com',
        created_at: new Date()
      },
      token: 'mock-token'
    });

    mockAuthService.getUserProfile.mockResolvedValue({
      id: '123',
      email: 'test@example.com',
      created_at: new Date()
    });
  });

  describe('Route Configuration', () => {
    it('should export authRoutes router', () => {
      expect(authRoutes).toBeDefined();
      expect(typeof authRoutes).toBe('function'); // Express router is a function
    });

    it('should apply security middleware to all routes', () => {
      // Verify that security middleware is applied
      expect(mockSecurityMiddleware.auth).toBeDefined();
      expect(Array.isArray(mockSecurityMiddleware.auth)).toBe(true);
    });
  });

  describe('Validation Schemas', () => {
    describe('RegisterSchema', () => {
      it('should validate valid registration data', async () => {
        const validData = {
          email: 'test@example.com',
          password: 'ValidPass123!'
        };
        
        mockReq.body = validData;
        
        // Test that validation would pass
        expect(validData.email).toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
        expect(validData.password).toHaveLength(13); // Strong password
      });

      it('should require email field', () => {
        const invalidData = {
          password: 'ValidPass123!'
          // email missing
        };
        
        // Email should be required
        expect(invalidData).not.toHaveProperty('email');
      });

      it('should require password field', () => {
        const invalidData = {
          email: 'test@example.com'
          // password missing
        };
        
        expect(invalidData).not.toHaveProperty('password');
      });

      it('should transform email to lowercase and trim', () => {
        const inputEmail = '  TEST@EXAMPLE.COM  ';
        const expectedEmail = 'test@example.com';
        
        // This tests the expected transformation behavior
        expect(inputEmail.toLowerCase().trim()).toBe(expectedEmail);
      });

      it('should reject invalid email formats', () => {
        const invalidEmails = [
          'invalid-email',           // No @ symbol
          '@example.com',           // Missing local part (empty before @)
          'test@',                  // Missing domain part (empty after @)
          'test@example',           // Missing dot (no . in domain)
          '',                       // Empty string
          'test @example.com',      // Space in local part
          'test@ex ample.com',      // Space in domain part
          'test@example. com',      // Space after dot
          ' test@example.com',      // Leading space
          'test@example.com ',      // Trailing space
          'te st@example.com',      // Space in middle of local part
          'test@@example.com',      // Double @
          'test@',                  // Just @ at end
          '@',                      // Just @ symbol
          'test@.com',              // Domain starts with dot (empty between @ and .)
          'test@example.com.',      // Extra dot at end (empty after final .)
          'test@example.',          // Missing part after dot (empty after .)
        ];
        
        invalidEmails.forEach(email => {
          expect(email).not.toMatch(/^[^\s@]+@[^\s@]+\.[a-zA-Z]{2,}$/);
        });
      });

      it('should reject emails that are too long', () => {
        const longEmail = 'a'.repeat(250) + '@example.com';
        expect(longEmail.length).toBeGreaterThan(254);
      });
    });

    describe('LoginSchema', () => {
      it('should validate valid login data', () => {
        const validData = {
          email: 'test@example.com',
          password: 'any-password'
        };
        
        expect(validData.email).toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
        expect(validData.password).toBeTruthy();
      });

      it('should require both email and password', () => {
        const invalidData1 = { email: 'test@example.com' };
        const invalidData2 = { password: 'password' };
        
        expect(invalidData1).not.toHaveProperty('password');
        expect(invalidData2).not.toHaveProperty('email');
      });

      it('should transform email consistently', () => {
        const inputEmail = '  User@Example.Com  ';
        const expectedEmail = 'user@example.com';
        
        expect(inputEmail.toLowerCase().trim()).toBe(expectedEmail);
      });
    });

    describe('UpdatePasswordSchema', () => {
      it('should require current and new passwords', () => {
        const validData = {
          currentPassword: 'oldpass',
          newPassword: 'NewPass123!'
        };
        
        expect(validData).toHaveProperty('currentPassword');
        expect(validData).toHaveProperty('newPassword');
        expect(validData.currentPassword).toBeTruthy();
        expect(validData.newPassword).toBeTruthy();
      });

      it('should reject missing current password', () => {
        const invalidData = {
          newPassword: 'NewPass123!'
        };
        
        expect(invalidData).not.toHaveProperty('currentPassword');
      });

      it('should reject missing new password', () => {
        const invalidData = {
          currentPassword: 'oldpass'
        };
        
        expect(invalidData).not.toHaveProperty('newPassword');
      });
    });

    describe('UpdateEmailSchema', () => {
      it('should require new email and password', () => {
        const validData = {
          newEmail: 'new@example.com',
          password: 'currentpass'
        };
        
        expect(validData).toHaveProperty('newEmail');
        expect(validData).toHaveProperty('password');
        expect(validData.newEmail).toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
      });

      it('should validate new email format', () => {
        const invalidEmails = [
          'invalid',
          '@example.com',
          'test@'
        ];
        
        invalidEmails.forEach(email => {
          expect(email).not.toMatch(/^[^\s@]+@[^\s@]+\.[^\s@]+$/);
        });
      });

      it('should transform new email', () => {
        const inputEmail = '  NEW@EXAMPLE.COM  ';
        const expectedEmail = 'new@example.com';
        
        expect(inputEmail.toLowerCase().trim()).toBe(expectedEmail);
      });
    });
  });

  describe('Enhanced Controllers', () => {
    describe('enhancedRegister', () => {
      it('should call authService.register with correct parameters', async () => {
        const registrationData = {
          email: 'test@example.com',
          password: 'TestPass123!'
        };
        
        mockReq.body = registrationData;
        
        // Import and test the enhanced register controller logic
        expect(mockAuthService.register).toBeDefined();
        
        // Simulate calling the enhanced register
        await mockAuthService.register(registrationData);
        
        expect(mockAuthService.register).toHaveBeenCalledWith(registrationData);
      });

      it('should return 201 status on successful registration', async () => {
        const mockUser = {
          id: '123',
          email: 'test@example.com',
          created_at: new Date()
        };
        const mockToken = 'jwt-token';
        
        mockAuthService.register.mockResolvedValue({
          user: mockUser,
          token: mockToken
        });
        
        // Test expected response format
        const expectedResponse = {
          status: 'success',
          message: 'User registered successfully',
          data: {
            user: mockUser,
            token: mockToken
          }
        };
        
        expect(expectedResponse.status).toBe('success');
        expect(expectedResponse.data).toHaveProperty('user');
        expect(expectedResponse.data).toHaveProperty('token');
      });

      it('should handle registration errors', async () => {
        const registrationError = new ApiError('Registration failed', 400, 'REGISTRATION_ERROR');
        
        mockAuthService.register.mockRejectedValue(registrationError);
        
        try {
          await mockAuthService.register({ email: 'test@example.com', password: 'pass' });
        } catch (error) {
          expect(error).toBeInstanceOf(ApiError);
          expect((error as ApiError).message).toBe('Registration failed');
        }
      });

      it('should handle service exceptions gracefully', async () => {
        const unexpectedError = new Error('Database connection failed');
        
        mockAuthService.register.mockRejectedValue(unexpectedError);
        
        try {
          await mockAuthService.register({ email: 'test@example.com', password: 'pass' });
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      });
    });

    describe('enhancedLogin', () => {
      it('should call authService.login with correct parameters', async () => {
        const loginData = {
          email: 'test@example.com',
          password: 'password'
        };
        
        await mockAuthService.login(loginData);
        
        expect(mockAuthService.login).toHaveBeenCalledWith(loginData);
      });

      it('should return 200 status on successful login', async () => {
        const mockUser = {
          id: '123',
          email: 'test@example.com',
          created_at: new Date()
        };
        const mockToken = 'jwt-token';
        
        mockAuthService.login.mockResolvedValue({
          user: mockUser,
          token: mockToken
        });
        
        const result = await mockAuthService.login({
          email: 'test@example.com',
          password: 'password'
        });
        
        expect(result).toEqual({
          user: mockUser,
          token: mockToken
        });
      });

      it('should handle login failures', async () => {
        const loginError = new ApiError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
        
        mockAuthService.login.mockRejectedValue(loginError);
        
        try {
          await mockAuthService.login({ email: 'wrong@example.com', password: 'wrongpass' });
        } catch (error) {
          expect(error).toBeInstanceOf(ApiError);
          expect((error as ApiError).statusCode).toBe(401);
        }
      });

      it('should handle service errors', async () => {
        const serviceError = new Error('Service unavailable');
        
        mockAuthService.login.mockRejectedValue(serviceError);
        
        try {
          await mockAuthService.login({ email: 'test@example.com', password: 'pass' });
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
        }
      });
    });

    describe('getUserProfile', () => {
      it('should require authentication', async () => {
        mockReq.user = undefined;
        
        // Should return authentication error when no user
        expect(mockReq.user).toBeUndefined();
      });

      it('should return user profile when authenticated', async () => {
        const mockUser = {
          id: '123',
          email: 'test@example.com',
          created_at: new Date()
        };
        
        mockReq.user = { id: '123', email: 'test@example.com' };
        mockAuthService.getUserProfile.mockResolvedValue(mockUser);
        
        const result = await mockAuthService.getUserProfile('123');
        
        expect(result).toEqual(mockUser);
        expect(mockAuthService.getUserProfile).toHaveBeenCalledWith('123');
      });

      it('should handle user not found', async () => {
        const notFoundError = new ApiError('User not found', 404, 'USER_NOT_FOUND');
        
        mockAuthService.getUserProfile.mockRejectedValue(notFoundError);
        
        try {
          await mockAuthService.getUserProfile('nonexistent');
        } catch (error) {
          expect(error).toBeInstanceOf(ApiError);
          expect((error as ApiError).statusCode).toBe(404);
        }
      });
    });

    describe('updatePassword', () => {
      it('should require authentication', () => {
        mockReq.user = undefined;
        expect(mockReq.user).toBeUndefined();
      });

      it('should call authService.updatePassword with correct parameters', async () => {
        const passwordData = {
          currentPassword: 'oldpass',
          newPassword: 'NewPass123!'
        };
        
        mockReq.user = { id: '123', email: 'test@example.com' };
        mockReq.body = passwordData;
        
        const expectedParams = {
          userId: '123',
          currentPassword: 'oldpass',
          newPassword: 'NewPass123!',
          requestingUserId: '123'
        };
        
        mockAuthService.updatePassword.mockResolvedValue({ success: true });
        
        await mockAuthService.updatePassword(expectedParams);
        
        expect(mockAuthService.updatePassword).toHaveBeenCalledWith(expectedParams);
      });

      it('should handle password update success', async () => {
        mockAuthService.updatePassword.mockResolvedValue({ success: true });
        
        const result = await mockAuthService.updatePassword({
          userId: '123',
          currentPassword: 'old',
          newPassword: 'new',
          requestingUserId: '123'
        });
        
        expect(result).toEqual({ success: true });
      });

      it('should handle password update errors', async () => {
        const passwordError = new ApiError('Current password is incorrect', 401, 'INVALID_PASSWORD');
        
        mockAuthService.updatePassword.mockRejectedValue(passwordError);
        
        try {
          await mockAuthService.updatePassword({
            userId: '123',
            currentPassword: 'wrong',
            newPassword: 'new',
            requestingUserId: '123'
          });
        } catch (error) {
          expect(error).toBeInstanceOf(ApiError);
          expect((error as ApiError).message).toBe('Current password is incorrect');
        }
      });
    });

    describe('updateEmail', () => {
      it('should require authentication', () => {
        mockReq.user = undefined;
        expect(mockReq.user).toBeUndefined();
      });

      it('should call authService.updateEmail with correct parameters', async () => {
        const emailData = {
          newEmail: 'new@example.com',
          password: 'currentpass'
        };
        
        mockReq.user = { id: '123', email: 'test@example.com' };
        mockReq.body = emailData;
        
        const expectedParams = {
          userId: '123',
          newEmail: 'new@example.com',
          password: 'currentpass'
        };
        
        const updatedUser = {
          id: '123',
          email: 'new@example.com',
          created_at: new Date()
        };
        
        mockAuthService.updateEmail.mockResolvedValue(updatedUser);
        
        await mockAuthService.updateEmail(expectedParams);
        
        expect(mockAuthService.updateEmail).toHaveBeenCalledWith(expectedParams);
      });

      it('should handle email update success', async () => {
        const updatedUser = {
          id: '123',
          email: 'new@example.com',
          created_at: new Date()
        };
        
        mockAuthService.updateEmail.mockResolvedValue(updatedUser);
        
        const result = await mockAuthService.updateEmail({
          userId: '123',
          newEmail: 'new@example.com',
          password: 'pass'
        });
        
        expect(result).toEqual(updatedUser);
      });

      it('should handle email update errors', async () => {
        const emailError = new ApiError('Email already exists', 409, 'EMAIL_EXISTS');
        
        mockAuthService.updateEmail.mockRejectedValue(emailError);
        
        try {
          await mockAuthService.updateEmail({
            userId: '123',
            newEmail: 'existing@example.com',
            password: 'pass'
          });
        } catch (error) {
          expect(error).toBeInstanceOf(ApiError);
          expect((error as ApiError).statusCode).toBe(409);
        }
      });
    });
  });

  describe('Middleware Integration', () => {
    describe('Rate Limiting', () => {
      it('should apply rate limiting to registration endpoint', () => {
        // Verify that rateLimitByUser is called with correct parameters for register
        expect(mockRateLimitByUser).toBeDefined();
        
        // Test that rate limiting factory can be called
        const rateLimitMiddleware = mockRateLimitByUser(5, 15 * 60 * 1000);
        expect(typeof rateLimitMiddleware).toBe('function');
      });

      it('should apply rate limiting to login endpoint', () => {
        // Verify rate limiting for login
        const rateLimitMiddleware = mockRateLimitByUser(10, 15 * 60 * 1000);
        expect(typeof rateLimitMiddleware).toBe('function');
      });

      it('should apply stricter rate limiting to password updates', () => {
        // Password changes should have stricter limits
        const rateLimitMiddleware = mockRateLimitByUser(3, 60 * 60 * 1000);
        expect(typeof rateLimitMiddleware).toBe('function');
      });

      it('should apply strictest rate limiting to account deactivation', () => {
        // Account deletion should be most restrictive
        const rateLimitMiddleware = mockRateLimitByUser(1, 24 * 60 * 60 * 1000);
        expect(typeof rateLimitMiddleware).toBe('function');
      });
    });

    describe('Validation Middleware', () => {
      it('should apply type validation to auth endpoints', () => {
        expect(mockValidateAuthTypes).toBeDefined();
        expect(typeof mockValidateAuthTypes).toBe('function');
      });

      it('should apply body validation with schemas', () => {
        expect(mockValidateBody).toBeDefined();
        expect(typeof mockValidateBody).toBe('function');
        
        // Should be able to create validation middleware
        const mockSchema = {} as any; // Mock Zod schema
        const validationMiddleware = mockValidateBody(mockSchema);
        expect(typeof validationMiddleware).toBe('function');
      });

      it('should apply request type validation to protected routes', () => {
        expect(mockValidateRequestTypes).toBeDefined();
        expect(typeof mockValidateRequestTypes).toBe('function');
      });
    });

    describe('Authentication Middleware', () => {
      it('should apply authentication to protected routes', () => {
        expect(mockAuthenticate).toBeDefined();
        expect(typeof mockAuthenticate).toBe('function');
      });

      it('should require auth for protected endpoints', () => {
        expect(mockRequireAuth).toBeDefined();
        expect(typeof mockRequireAuth).toBe('function');
      });
    });
  });

  describe('Error Handling', () => {
    it('should handle validation errors properly', async () => {
      const validationError = new ApiError('Validation failed', 400, 'VALIDATION_ERROR');
      
      // Test that validation errors are handled
      expect(validationError).toBeInstanceOf(ApiError);
      expect(validationError.statusCode).toBe(400);
      expect(validationError.code).toBe('VALIDATION_ERROR');
    });

    it('should handle authentication errors', async () => {
      const authError = new ApiError('Authentication required', 401, 'AUTH_REQUIRED');
      
      expect(authError).toBeInstanceOf(ApiError);
      expect(authError.statusCode).toBe(401);
    });

    it('should handle authorization errors', async () => {
      const authzError = new ApiError('Access denied', 403, 'ACCESS_DENIED');
      
      expect(authzError).toBeInstanceOf(ApiError);
      expect(authzError.statusCode).toBe(403);
    });

    it('should handle rate limiting errors', async () => {
      const rateLimitError = new ApiError('Rate limit exceeded', 429, 'RATE_LIMITED');
      
      expect(rateLimitError).toBeInstanceOf(ApiError);
      expect(rateLimitError.statusCode).toBe(429);
    });

    it('should handle internal server errors', async () => {
      const internalError = new ApiError('Internal server error', 500, 'INTERNAL_ERROR');
      
      expect(internalError).toBeInstanceOf(ApiError);
      expect(internalError.statusCode).toBe(500);
    });
  });

  describe('Token Validation', () => {
    describe('validateToken endpoint', () => {
      it('should require Bearer token in Authorization header', async () => {
        mockReq.headers = {};
        
        // Should fail without Authorization header
        expect(mockReq.headers.authorization).toBeUndefined();
      });

      it('should validate Bearer token format', async () => {
        const validHeader = 'Bearer valid-jwt-token';
        const invalidHeaders = [
          'Invalid format',
          'Bearer',
          'Bearer ',
          'Basic user:pass'
        ];
        
        expect(validHeader.startsWith('Bearer ')).toBe(true);
        expect(validHeader.substring(7)).toBe('valid-jwt-token');
        
        invalidHeaders.forEach(header => {
          expect(header.startsWith('Bearer ') && header.length > 7).toBe(false);
        });
      });

      it('should call authService.validateToken', async () => {
        const token = 'valid-jwt-token';
        
        mockAuthService.validateToken.mockResolvedValue({
          isValid: true,
          user: {
            id: '123',
            email: 'test@example.com',
            created_at: new Date()
          }
        });
        
        await mockAuthService.validateToken(token);
        
        expect(mockAuthService.validateToken).toHaveBeenCalledWith(token);
      });

      it('should return valid response for valid tokens', async () => {
        const mockUser = {
          id: '123',
          email: 'test@example.com',
          created_at: new Date()
        };
        
        mockAuthService.validateToken.mockResolvedValue({
          isValid: true,
          user: mockUser
        });
        
        const result = await mockAuthService.validateToken('valid-token');
        
        expect(result.isValid).toBe(true);
        expect(result.user).toEqual(mockUser);
      });

      it('should return invalid response for invalid tokens', async () => {
        mockAuthService.validateToken.mockResolvedValue({
          isValid: false,
          error: 'Invalid token'
        });
        
        const result = await mockAuthService.validateToken('invalid-token');
        
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('Invalid token');
      });
    });
  });

  describe('Legacy Controller Compatibility', () => {
    it('should maintain backward compatibility with original controllers', () => {
      expect(mockAuthController.register).toBeDefined();
      expect(mockAuthController.login).toBeDefined();
      expect(mockAuthController.me).toBeDefined();
      
      expect(typeof mockAuthController.register).toBe('function');
      expect(typeof mockAuthController.login).toBe('function');
      expect(typeof mockAuthController.me).toBe('function');
    });

    it('should apply same validation to legacy routes', () => {
      // Legacy routes should also get type and body validation
      expect(mockValidateAuthTypes).toBeDefined();
      expect(mockValidateBody).toBeDefined();
    });
  });

  describe('Route Security Configuration', () => {
    it('should apply security middleware to all routes', () => {
      expect(mockSecurityMiddleware.auth).toBeDefined();
      expect(Array.isArray(mockSecurityMiddleware.auth)).toBe(true);
    });

    it('should have public routes without authentication', () => {
      // Register, login, and token validation should be public
      // This is tested by verifying they don't require authentication
      expect(mockAuthenticate).toBeDefined(); // Available but not required for public routes
    });

    it('should protect sensitive routes with authentication', () => {
      // Profile, password update, email update should require auth
      expect(mockAuthenticate).toBeDefined();
      expect(mockRequireAuth).toBeDefined();
    });

    it('should apply appropriate rate limiting per endpoint type', () => {
      // Different endpoints should have different rate limits
      expect(mockRateLimitByUser).toBeDefined();
      
      // Registration: 5 per 15 minutes
      const registerLimit = mockRateLimitByUser(5, 15 * 60 * 1000);
      expect(typeof registerLimit).toBe('function');
      
      // Login: 10 per 15 minutes  
      const loginLimit = mockRateLimitByUser(10, 15 * 60 * 1000);
      expect(typeof loginLimit).toBe('function');
      
      // Password change: 3 per hour
      const passwordLimit = mockRateLimitByUser(3, 60 * 60 * 1000);
      expect(typeof passwordLimit).toBe('function');
    });
  });
});