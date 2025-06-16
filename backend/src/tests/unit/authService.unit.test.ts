// /backend/src/services/__tests__/authService.unit.test.ts

import { authService } from '../../services/authService';
import { ApiError } from '../../utils/ApiError';
import jwt from 'jsonwebtoken';
import { config } from '../../config';

// Mock dependencies BEFORE importing userModel to prevent DB connection
jest.mock('../../models/userModel', () => ({
  userModel: {
    create: jest.fn(),
    findByEmail: jest.fn(),
    findById: jest.fn(),
    validatePassword: jest.fn(),
    hasPassword: jest.fn(),
    updatePassword: jest.fn(),
    updateEmail: jest.fn(),
    getUserWithOAuthProviders: jest.fn(),
    getUserStats: jest.fn(),
    delete: jest.fn()
  }
}));

jest.mock('jsonwebtoken');
jest.mock('../../config', () => ({
  config: {
    jwtSecret: 'test-secret',
    jwtExpiresIn: '1d'
  }
}));

// Mock the database connection to prevent open handles
jest.mock('../../models/db', () => ({
  pool: {
    query: jest.fn(),
    end: jest.fn()
  }
}));

// Import userModel AFTER mocking
import { userModel } from '../../models/userModel';

const mockUserModel = userModel as jest.Mocked<typeof userModel>;
const mockJwt = jwt as jest.Mocked<typeof jwt>;

describe('authService', () => {
    beforeAll(() => {
        // Ensure NODE_ENV is set to test to prevent any real DB connections
        process.env.NODE_ENV = 'test';
        process.env.SKIP_DB_CONNECTION_TEST = 'true';
    });

    beforeEach(() => {
        jest.clearAllMocks();
        // Mock console methods to avoid noise in tests
        jest.spyOn(console, 'log').mockImplementation();
        jest.spyOn(console, 'warn').mockImplementation();
        jest.spyOn(console, 'error').mockImplementation();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    afterAll(() => {
        // Clean up any remaining timers or handles
        jest.clearAllTimers();
        jest.useRealTimers();
    });

    describe('register', () => {
        const validRegisterParams = {
        email: 'test@example.com',
        password: 'ValidPass123!'
        };

        const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        it('should successfully register a new user', async () => {
            // Arrange
            mockUserModel.create.mockResolvedValue(mockUser);
            mockJwt.sign.mockReturnValue('mock-token' as any);

            // Act
            const result = await authService.register(validRegisterParams);

            // Assert
            expect(result).toEqual({
                user: mockUser,
                token: 'mock-token'
            });
            expect(mockUserModel.create).toHaveBeenCalledWith({
                email: 'test@example.com',
                password: 'ValidPass123!'
            });
            expect(mockJwt.sign).toHaveBeenCalledWith(
                { id: mockUser.id, email: mockUser.email },
                'test-secret',
                { expiresIn: '1d' }
            );
        });

        it('should validate email format', async () => {
            // Test invalid emails
            const invalidEmails = [
                '',
                '   ',
                'invalid-email',
                '@example.com',
                'test@',
                'test..test@example.com',
                'a'.repeat(250) + '@example.com'
            ];

            for (const email of invalidEmails) {
                await expect(
                authService.register({ email, password: 'ValidPass123!' })
                ).rejects.toThrow(ApiError);
            }
        });

        it('should validate password strength', async () => {
            // Test weak passwords
            const weakPasswords = [
                '',
                '1234567',          // Too short
                'password',         // Common password
                'Password',         // Missing numbers and special chars
                '12345678',         // Missing letters and special chars
                'Password123',      // Missing special chars
                'a'.repeat(130)     // Too long
            ];

            for (const password of weakPasswords) {
                await expect(
                authService.register({ email: 'test@example.com', password })
                ).rejects.toThrow(ApiError);
            }
        });

        it('should reject disposable email domains', async () => {
            const disposableEmails = [
                'test@10minutemail.com',
                'test@tempmail.org',
                'test@guerrillamail.com'
            ];

            for (const email of disposableEmails) {
                await expect(
                authService.register({ email, password: 'ValidPass123!' })
                ).rejects.toThrow(ApiError);
            }
        });

        it('should handle database errors gracefully', async () => {
            // Arrange
            mockUserModel.create.mockRejectedValue(new Error('Database error'));

            // Act & Assert
            await expect(
                authService.register(validRegisterParams)
            ).rejects.toThrow(ApiError);
        });

        it('should normalize email to lowercase', async () => {
            // Arrange
            mockUserModel.create.mockResolvedValue(mockUser);
            mockJwt.sign.mockReturnValue('mock-token' as any);

            // Act
            await authService.register({
                email: 'TEST@EXAMPLE.COM',
                password: 'ValidPass123!'
            });

            // Assert
            expect(mockUserModel.create).toHaveBeenCalledWith({
                email: 'test@example.com',
                password: 'ValidPass123!'
            });
        });
    });

    describe('login', () => {
        const validLoginParams = {
        email: 'test@example.com',
        password: 'ValidPass123!'
        };

        const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date(),
        updated_at: new Date(),
        password_hash: 'hashed-password'
        };

        const mockSafeUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        it('should successfully login with valid credentials', async () => {
            // Arrange
            mockUserModel.findByEmail.mockResolvedValue(mockUser);
            mockUserModel.validatePassword.mockResolvedValue(true);
            mockJwt.sign.mockReturnValue('mock-token' as any);

            // Act
            const result = await authService.login(validLoginParams);

            // Assert
            expect(result).toEqual({
                user: mockSafeUser,
                token: 'mock-token'
            });
            expect(mockUserModel.findByEmail).toHaveBeenCalledWith('test@example.com');
            expect(mockUserModel.validatePassword).toHaveBeenCalledWith(mockUser, 'ValidPass123!');
        });

        it('should fail login with non-existent user', async () => {
            // Arrange
            mockUserModel.findByEmail.mockResolvedValue(null);

            // Act & Assert
            await expect(
                authService.login(validLoginParams)
            ).rejects.toThrow(ApiError);
            
            expect(mockUserModel.validatePassword).not.toHaveBeenCalled();
        });

        it('should fail login with invalid password', async () => {
            // Arrange
            mockUserModel.findByEmail.mockResolvedValue(mockUser);
            mockUserModel.validatePassword.mockResolvedValue(false);

            // Act & Assert
            await expect(
                authService.login(validLoginParams)
            ).rejects.toThrow(ApiError);
        });

        it('should validate email format for login', async () => {
            const invalidEmails = ['', '   ', 'invalid-email'];

            for (const email of invalidEmails) {
                await expect(
                authService.login({ email, password: 'ValidPass123!' })
                ).rejects.toThrow(ApiError);
            }
        });

        it('should validate password input for login', async () => {
            const invalidPasswords = ['', '   '];

            for (const password of invalidPasswords) {
                await expect(
                authService.login({ email: 'test@example.com', password })
                ).rejects.toThrow(ApiError);
            }
        });

        it('should normalize email to lowercase for login', async () => {
            // Arrange
            mockUserModel.findByEmail.mockResolvedValue(mockUser);
            mockUserModel.validatePassword.mockResolvedValue(true);
            mockJwt.sign.mockReturnValue('mock-token' as any);

            // Act
            await authService.login({
                email: 'TEST@EXAMPLE.COM',
                password: 'ValidPass123!'
            });

            // Assert
            expect(mockUserModel.findByEmail).toHaveBeenCalledWith('test@example.com');
        });
    });

    describe('getUserProfile', () => {
        const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        it('should return user profile successfully', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockUser);

            // Act
            const result = await authService.getUserProfile('user-123');

            // Assert
            expect(result).toEqual(mockUser);
            expect(mockUserModel.findById).toHaveBeenCalledWith('user-123');
            });

            it('should throw error when user not found', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(null);

            // Act & Assert
            await expect(
                authService.getUserProfile('non-existent-user')
            ).rejects.toThrow(ApiError);
        });
    });

    describe('updatePassword', () => {
        const updatePasswordParams = {
        userId: 'user-123',
        currentPassword: 'OldPass123!',
        newPassword: 'NewPass456!'
        };

        const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        const mockUserWithPassword = {
        id: 'user-123',
        email: 'test@example.com',
        password_hash: 'hashed-password',
        created_at: new Date(),
        updated_at: new Date()
        };

        it('should successfully update password', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(mockUserWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(true);
            mockUserModel.updatePassword.mockResolvedValue(true);

            // Act
            const result = await authService.updatePassword(updatePasswordParams);

            // Assert
            expect(result).toEqual({ success: true });
            expect(mockUserModel.updatePassword).toHaveBeenCalledWith('user-123', 'NewPass456!');
        });

        it('should validate new password strength', async () => {
            await expect(
                authService.updatePassword({
                ...updatePasswordParams,
                newPassword: 'weak'
                })
            ).rejects.toThrow(ApiError);
        });

        it('should prevent password reuse', async () => {
            await expect(
                authService.updatePassword({
                ...updatePasswordParams,
                newPassword: updatePasswordParams.currentPassword
                })
            ).rejects.toThrow(ApiError);
        });

        it('should fail for OAuth-only users', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.hasPassword.mockResolvedValue(false);

            // Act & Assert
            await expect(
                authService.updatePassword(updatePasswordParams)
            ).rejects.toThrow(ApiError);
        });

        it('should verify current password', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(mockUserWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(false);

            // Act & Assert
            await expect(
                authService.updatePassword(updatePasswordParams)
            ).rejects.toThrow(ApiError);
        });
    });

    describe('updateEmail', () => {
        const updateEmailParams = {
        userId: 'user-123',
        newEmail: 'newemail@example.com',
        password: 'ValidPass123!'
        };

        const mockCurrentUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        const mockUpdatedUser = {
        id: 'user-123',
        email: 'newemail@example.com',
        created_at: new Date()
        };

        const mockUserWithPassword = {
        id: 'user-123',
        email: 'test@example.com',
        password_hash: 'hashed-password',
        created_at: new Date(),
        updated_at: new Date()
        };

        it('should successfully update email', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockCurrentUser);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(mockUserWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(true);
            mockUserModel.updateEmail.mockResolvedValue(mockUpdatedUser);

            // Act
            const result = await authService.updateEmail(updateEmailParams);

            // Assert
            expect(result).toEqual(mockUpdatedUser);
            expect(mockUserModel.updateEmail).toHaveBeenCalledWith('user-123', 'newemail@example.com');
            });

            it('should validate new email format', async () => {
            await expect(
                authService.updateEmail({
                ...updateEmailParams,
                newEmail: 'invalid-email'
                })
            ).rejects.toThrow(ApiError);
        });

        it('should prevent email change to same email', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockCurrentUser);

            // Act & Assert
            await expect(
                authService.updateEmail({
                ...updateEmailParams,
                newEmail: 'test@example.com'
                })
            ).rejects.toThrow(ApiError);
        });

        it('should verify password for users with password', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockCurrentUser);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(mockUserWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(false);

            // Act & Assert
            await expect(
                authService.updateEmail(updateEmailParams)
            ).rejects.toThrow(ApiError);
        });

        it('should work for OAuth users without password verification', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockCurrentUser);
            mockUserModel.hasPassword.mockResolvedValue(false);
            mockUserModel.updateEmail.mockResolvedValue(mockUpdatedUser);

            // Act
            const result = await authService.updateEmail(updateEmailParams);

            // Assert
            expect(result).toEqual(mockUpdatedUser);
            expect(mockUserModel.validatePassword).not.toHaveBeenCalled();
        });
    });

    describe('validateToken', () => {
        const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        it('should validate a valid token successfully', async () => {
            // Arrange
            const decodedToken = { id: 'user-123', email: 'test@example.com' };
            mockJwt.verify.mockReturnValue(decodedToken as any);
            mockUserModel.findById.mockResolvedValue(mockUser);

            // Act
            const result = await authService.validateToken('valid-token');

            // Assert
            expect(result).toEqual({ isValid: true, user: mockUser });
            expect(mockJwt.verify).toHaveBeenCalledWith('valid-token', 'test-secret');
            });

            it('should return invalid for missing token', async () => {
            // Act
            const result = await authService.validateToken('');

            // Assert
            expect(result).toEqual({ isValid: false, error: 'Token is required' });
        });

        it('should return invalid for expired token', async () => {
            // Arrange
            const expiredError = new Error('Token expired');
            expiredError.name = 'TokenExpiredError';
            mockJwt.verify.mockImplementation(() => { throw expiredError; });

            // Act
            const result = await authService.validateToken('expired-token');

            // Assert
            expect(result).toEqual({ isValid: false, error: 'Token has expired' });
        });

        it('should return invalid for malformed token', async () => {
            // Arrange
            const malformedError = new Error('Malformed token');
            malformedError.name = 'JsonWebTokenError';
            mockJwt.verify.mockImplementation(() => { throw malformedError; });

            // Act
            const result = await authService.validateToken('malformed-token');

            // Assert
            expect(result).toEqual({ isValid: false, error: 'Token is malformed' });
        });

        it('should return invalid for non-existent user', async () => {
            // Arrange
            const decodedToken = { id: 'user-123', email: 'test@example.com' };
            mockJwt.verify.mockReturnValue(decodedToken as any);
            mockUserModel.findById.mockResolvedValue(null);

            // Act
            const result = await authService.validateToken('valid-token');

            // Assert
            expect(result).toEqual({ isValid: false, error: 'User not found' });
        });
    });

    describe('getUserAuthStats', () => {
        const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        const mockUserWithProviders = {
        ...mockUser,
        linkedProviders: ['google', 'github']
        };

        it('should return authentication statistics', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.getUserWithOAuthProviders.mockResolvedValue(mockUserWithProviders);
            mockUserModel.hasPassword.mockResolvedValue(true);

            // Act
            const result = await authService.getUserAuthStats('user-123');

            // Assert
            expect(result).toEqual({
                userId: 'user-123',
                email: 'test@example.com',
                hasPassword: true,
                linkedProviders: ['google', 'github'],
                accountCreated: mockUser.created_at,
                authenticationMethods: {
                password: true,
                oauth: true
                }
            });
        });

        it('should handle user with no OAuth providers', async () => {
            // Arrange
            const userWithoutOAuth = { ...mockUser, linkedProviders: [] };
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.getUserWithOAuthProviders.mockResolvedValue(userWithoutOAuth);
            mockUserModel.hasPassword.mockResolvedValue(true);

            // Act
            const result = await authService.getUserAuthStats('user-123');

            // Assert
            expect(result.authenticationMethods).toEqual({
                password: true,
                oauth: false
            });
            });

            it('should throw error for non-existent user', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(null);

            // Act & Assert
            await expect(
                authService.getUserAuthStats('non-existent-user')
            ).rejects.toThrow(ApiError);
        });
    });

    describe('deactivateAccount', () => {
        const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        const mockUserWithPassword = {
        id: 'user-123',
        email: 'test@example.com',
        password_hash: 'hashed-password',
        created_at: new Date(),
        updated_at: new Date()
        };

        const mockStats = {
        imageCount: 0,
        garmentCount: 0,
        wardrobeCount: 0
        };

        it('should successfully deactivate account', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(mockUserWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(true);
            mockUserModel.getUserStats.mockResolvedValue(mockStats);
            mockUserModel.delete.mockResolvedValue(true);

            // Act
            const result = await authService.deactivateAccount('user-123', 'ValidPass123!');

            // Assert
            expect(result).toEqual({ success: true });
            expect(mockUserModel.delete).toHaveBeenCalledWith('user-123');
        });

        it('should prevent deactivation with active data', async () => {
            // Arrange
            const statsWithData = { imageCount: 5, garmentCount: 0, wardrobeCount: 0 };
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(mockUserWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(true);
            mockUserModel.getUserStats.mockResolvedValue(statsWithData);

            // Act & Assert
            await expect(
                authService.deactivateAccount('user-123', 'ValidPass123!')
            ).rejects.toThrow(ApiError);
        });

        it('should verify password if user has one', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(mockUserWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(false);

            // Act & Assert
            await expect(
                authService.deactivateAccount('user-123', 'WrongPassword!')
            ).rejects.toThrow(ApiError);
        });

        it('should work without password for OAuth users', async () => {
            // Arrange
            mockUserModel.findById.mockResolvedValue(mockUser);
            mockUserModel.hasPassword.mockResolvedValue(false);
            mockUserModel.getUserStats.mockResolvedValue(mockStats);
            mockUserModel.delete.mockResolvedValue(true);

            // Act
            const result = await authService.deactivateAccount('user-123');

            // Assert
            expect(result).toEqual({ success: true });
            expect(mockUserModel.validatePassword).not.toHaveBeenCalled();
        });
    });

    describe('generateAuthToken', () => {
        const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        created_at: new Date()
        };

        it('should generate a valid token', () => {
            // Arrange
            mockJwt.sign.mockReturnValue('generated-token' as any);

            // Act
            const token = authService.generateAuthToken(mockUser);

            // Assert
            expect(token).toBe('generated-token');
            expect(mockJwt.sign).toHaveBeenCalledWith(
                { id: mockUser.id, email: mockUser.email },
                'test-secret',
                { expiresIn: '1d' }
            );
            });

            it('should handle token generation errors', () => {
            // Arrange
            mockJwt.sign.mockImplementation(() => { throw new Error('JWT error'); });

            // Act & Assert
            expect(() => authService.generateAuthToken(mockUser)).toThrow(ApiError);
        });
    });

    describe('validation methods', () => {
        describe('validateEmailFormat', () => {
            it('should validate correct email formats', () => {
                const validEmails = [
                'test@example.com',
                'user.name@domain.co.uk',
                'user+tag@example.org'
                ];

                validEmails.forEach(email => {
                expect(() => authService.validateEmailFormat(email)).not.toThrow();
                });
            });

            it('should reject invalid email formats', () => {
                const invalidEmails = [
                '',
                '   ',
                'invalid',
                '@example.com',
                'test@',
                'test..test@example.com',
                'a'.repeat(250) + '@example.com'
                ];

                invalidEmails.forEach(email => {
                expect(() => authService.validateEmailFormat(email)).toThrow(ApiError);
                });
            });
        });

        describe('validatePasswordStrength', () => {
            it('should validate strong passwords', () => {
                const strongPasswords = [
                'StrongPass123!',
                'MyP@ssw0rd',
                'C0mplex!Password'
                ];

                strongPasswords.forEach(password => {
                expect(() => authService.validatePasswordStrength(password)).not.toThrow();
                });
            });

            it('should reject weak passwords', () => {
                const weakPasswords = [
                '',
                '1234567',           // Too short
                'password',          // Common password
                'Password',          // Missing numbers and special chars
                '12345678',          // Missing letters and special chars
                'a'.repeat(130)      // Too long
                ];

                weakPasswords.forEach(password => {
                expect(() => authService.validatePasswordStrength(password)).toThrow(ApiError);
                });
            });
        });

        describe('validatePasswordInput', () => {
            it('should validate non-empty passwords', () => {
                expect(() => authService.validatePasswordInput('password')).not.toThrow();
            });

            it('should reject empty passwords', () => {
                const emptyPasswords = ['', '   '];

                emptyPasswords.forEach(password => {
                expect(() => authService.validatePasswordInput(password)).toThrow(ApiError);
                });
            });
        });
    });

    describe('security helper methods', () => {
        describe('checkEmailDomainRestrictions', () => {
            it('should allow regular email domains', async () => {
                await expect(
                authService.checkEmailDomainRestrictions('test@gmail.com')
                ).resolves.not.toThrow();
            });

            it('should block disposable email domains', async () => {
                const disposableEmails = [
                'test@10minutemail.com',
                'test@tempmail.org',
                'test@guerrillamail.com'
                ];

                for (const email of disposableEmails) {
                await expect(
                    authService.checkEmailDomainRestrictions(email)
                ).rejects.toThrow(ApiError);
                }
            });
        });

        describe('rate limiting methods', () => {
            it('should handle rate limiting gracefully', async () => {
                // These are placeholder implementations, so they should not throw
                await expect(
                authService.checkRegistrationRateLimits('test@example.com')
                ).resolves.not.toThrow();

                await expect(
                authService.checkLoginRateLimits('test@example.com')
                ).resolves.not.toThrow();
            });
        });

        describe('security tracking methods', () => {
            it('should track failed attempts without throwing', async () => {
                await expect(
                authService.trackFailedLoginAttempt('test@example.com', 'test_reason')
                ).resolves.not.toThrow();

                await expect(
                authService.clearFailedLoginAttempts('test@example.com')
                ).resolves.not.toThrow();
            });
        });
    });

    describe('Enhanced Security Features', () => {
        describe('Enhanced Password Validation', () => {
            it('should reject specific weak password patterns', () => {
            const weakPatterns = [
                'weakpass',        // Exact match in weak patterns
                'simple123',       // Exact match in weak patterns  
                'nosymbols123',    // Exact match in weak patterns
                'uppercase123',    // Exact match in weak patterns
                'lowercase',       // Exact match in weak patterns
                'nonumbers'        // Exact match in weak patterns
            ];

            for (const password of weakPatterns) {
                expect(() => authService.validatePasswordStrength(password))
                .toThrow(expect.objectContaining({
                    message: 'Password must be at least 8 characters long'
                }));
            }
            });

            it('should reject repetitive character patterns', () => {
            const repetitivePasswords = [
                'AAA12345!',     // 3+ consecutive same chars
                'password111',   // repetitive numbers
                'TestTTT1!'      // repetitive letters
            ];

            for (const password of repetitivePasswords) {
                expect(() => authService.validatePasswordStrength(password))
                .toThrow(expect.objectContaining({
                    message: expect.stringContaining('repeating characters')
                }));
            }
            });

            it('should reject keyboard walking patterns', () => {
            const keyboardPasswords = [
                'qwerty123!',
                'asdf1234!', 
                '1234abcd!'
            ];

            for (const password of keyboardPasswords) {
                expect(() => authService.validatePasswordStrength(password))
                .toThrow(expect.objectContaining({
                    message: expect.stringContaining('keyboard patterns')
                }));
            }
            });

            it('should reject all-letters passwords regardless of length', () => {
            const allLetterPasswords = [
                'abcdefgh',        // 8 chars, all lowercase
                'ABCDEFGH',        // 8 chars, all uppercase
                'AbCdEfGh',        // 8 chars, mixed case but all letters
                'abcdefghijklmn'   // longer, all letters
            ];

            for (const password of allLetterPasswords) {
                expect(() => authService.validatePasswordStrength(password))
                .toThrow(expect.objectContaining({
                    message: 'Password must be at least 8 characters long'
                }));
            }
            });

            it('should reject all-numbers passwords regardless of length', () => {
            const allNumberPasswords = [
                '12345678',        // 8 digits
                '123456789',       // 9 digits
                '1234567890123'    // longer numbers
            ];

            for (const password of allNumberPasswords) {
                expect(() => authService.validatePasswordStrength(password))
                .toThrow(expect.objectContaining({
                    message: 'Password must be at least 8 characters long'
                }));
            }
            });

            it('should allow strong passwords that pass all checks', () => {
            const strongPasswords = [
                'StrongP@ss123!',   // Mixed case, numbers, special chars
                'MySecure#2024',    // Different pattern
                'C0mplex!Pass'      // Another strong pattern
            ];

            for (const password of strongPasswords) {
                expect(() => authService.validatePasswordStrength(password))
                .not.toThrow();
            }
            });
        });

        describe('Timing Attack Prevention Methods', () => {
            beforeEach(() => {
            jest.clearAllMocks();
            });

            it('should have performDummyPasswordValidation method', async () => {
            // Test that the method exists and runs without error
            await expect(authService.performDummyPasswordValidation())
                .resolves.not.toThrow();
            });

            it('should have ensureMinimumResponseTime method', async () => {
            const startTime = Date.now();
            
            // Test with time that needs padding
            await authService.ensureMinimumResponseTime(startTime, 100);
            
            const elapsed = Date.now() - startTime;
            expect(elapsed).toBeGreaterThanOrEqual(95); // Allow small variance
            });

            it('should not add delay if minimum time already elapsed', async () => {
            const pastTime = Date.now() - 200; // 200ms ago
            const start = Date.now();
            
            await authService.ensureMinimumResponseTime(pastTime, 100);
            
            const elapsed = Date.now() - start;
            expect(elapsed).toBeLessThan(50); // Should be very quick
            });
        });

        describe('Enhanced Input Type Validation', () => {
            it('should handle non-string email inputs in validateEmailFormat', () => {
            const invalidInputs = [
                123,
                [],
                {},
                null,
                undefined,
                true,
                false,
                Symbol('email')
            ];

            for (const input of invalidInputs) {
                expect(() => authService.validateEmailFormat(input as any))
                .toThrow(expect.objectContaining({
                    message: 'Email is required'
                }));
            }
            });

            it('should handle non-string password inputs in validatePasswordStrength', () => {
            const invalidInputs = [
                123,
                [],
                {},
                null,
                undefined,
                true,
                false,
                Symbol('password')
            ];

            for (const input of invalidInputs) {
                expect(() => authService.validatePasswordStrength(input as any))
                .toThrow(expect.objectContaining({
                    message: 'Password is required'
                }));
            }
            });

            it('should handle empty strings properly', () => {
            // Empty email
            expect(() => authService.validateEmailFormat(''))
                .toThrow(expect.objectContaining({
                message: 'Email cannot be empty'
                }));

            // Whitespace-only email
            expect(() => authService.validateEmailFormat('   '))
                .toThrow(expect.objectContaining({
                message: 'Email cannot be empty'
                }));
            });
        });

        describe('Authorization Security Enhancement', () => {
            it('should prevent cross-user password updates with requestingUserId', async () => {
            const user1 = { 
                id: 'user-1', 
                email: 'user1@example.com', 
                created_at: new Date() 
            };
            const user2 = { 
                id: 'user-2', 
                email: 'user2@example.com',
                created_at: new Date() 
            };

            mockUserModel.findById.mockResolvedValue(user2);

            // User 1 trying to update User 2's password
            await expect(
                authService.updatePassword({
                userId: user2.id,
                currentPassword: 'SomePassword123!',
                newPassword: 'NewPassword123!',
                requestingUserId: user1.id  // Different user!
                })
            ).rejects.toThrow(expect.objectContaining({
                message: 'Users can only update their own passwords'
            }));
            });

            it('should allow password updates when requestingUserId matches userId', async () => {
            const user = { 
                id: 'user-1', 
                email: 'user1@example.com', 
                created_at: new Date() 
            };
            const userWithPassword = {
                ...user,
                password_hash: 'hashed-password',
                updated_at: new Date()
            };

            mockUserModel.findById.mockResolvedValue(user);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(userWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(true);
            mockUserModel.updatePassword.mockResolvedValue(true);

            const result = await authService.updatePassword({
                userId: user.id,
                currentPassword: 'CurrentPass123!',
                newPassword: 'NewPassword123!',
                requestingUserId: user.id  // Same user
            });

            expect(result).toEqual({ success: true });
            });

            it('should work without requestingUserId for backward compatibility', async () => {
            const user = { 
                id: 'user-1', 
                email: 'user1@example.com', 
                created_at: new Date() 
            };
            const userWithPassword = {
                ...user,
                password_hash: 'hashed-password',
                updated_at: new Date()
            };

            mockUserModel.findById.mockResolvedValue(user);
            mockUserModel.hasPassword.mockResolvedValue(true);
            mockUserModel.findByEmail.mockResolvedValue(userWithPassword);
            mockUserModel.validatePassword.mockResolvedValue(true);
            mockUserModel.updatePassword.mockResolvedValue(true);

            const result = await authService.updatePassword({
                userId: user.id,
                currentPassword: 'CurrentPass123!',
                newPassword: 'NewPassword123!'
                // No requestingUserId - should work for backward compatibility
            });

            expect(result).toEqual({ success: true });
            });
        });
    });
});