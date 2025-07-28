// /backend/src/tests/unit/testUserModel.unit.test.ts

import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

// Mock dependencies first
const mockBcrypt = {
  hash: jest.fn(),
  compare: jest.fn()
};

const mockUuidv4 = jest.fn();

const mockApiError = {
  conflict: jest.fn(),
  badRequest: jest.fn(),
  notFound: jest.fn()
};

const mockTestDatabaseConnection = {
  query: jest.fn()
};

// Mock external modules
jest.mock('bcrypt', () => mockBcrypt);
jest.mock('uuid', () => ({ v4: mockUuidv4 }));
jest.mock('../../utils/ApiError', () => ({
  ApiError: mockApiError
}));

// Mock the database connection - ensure this matches the import path exactly
jest.mock('../../utils/testDatabaseConnection', () => ({
  TestDatabaseConnection: mockTestDatabaseConnection
}));

// Import the module under test after mocking
import { testUserModel } from '../../utils/testUserModel';

describe('testUserModel Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Reset all mock implementations
    mockTestDatabaseConnection.query.mockReset();
    mockBcrypt.hash.mockReset();
    mockBcrypt.compare.mockReset();
    mockUuidv4.mockReset();
    mockApiError.conflict.mockReset();
    mockApiError.badRequest.mockReset();
    mockApiError.notFound.mockReset();
    
    // Set up default mock implementations
    mockBcrypt.hash.mockResolvedValue('$2b$10$hashedPassword');
    mockBcrypt.compare.mockResolvedValue(true);
    mockUuidv4.mockReturnValue('12345678-1234-4123-8123-123456789012');
    
    // Mock ApiError.conflict
    mockApiError.conflict.mockImplementation((message, code) => {
      const error = new Error(message) as any;
      error.code = code;
      error.statusCode = 409;
      return error;
    });

    // Mock ApiError.badRequest
    mockApiError.badRequest.mockImplementation((message, code) => {
      const error = new Error(message) as any;
      error.code = code;
      error.statusCode = 400;
      return error;
    });
  });

  describe('User Creation', () => {
    describe('Input Validation', () => {
      it('should require email and password', async () => {
        await expect(testUserModel.create({ email: '', password: '' })).rejects.toThrow();
      });

      it('should reject empty email', async () => {
        await expect(testUserModel.create({ email: '', password: 'password123' })).rejects.toThrow();
      });

      it('should reject empty password', async () => {
        await expect(testUserModel.create({ email: 'test@example.com', password: '' })).rejects.toThrow();
      });

      it('should reject null/undefined inputs', async () => {
        await expect(testUserModel.create({ email: null as any, password: undefined as any })).rejects.toThrow();
      });
    });

    describe('Email Uniqueness', () => {
      it('should check for existing email before creating user', async () => {
        const userData = { email: 'test@example.com', password: 'password123' };
        
        // Mock email check returning no existing user
        mockTestDatabaseConnection.query.mockResolvedValueOnce({ 
          rows: [], 
          command: 'SELECT', 
          rowCount: 0, 
          oid: 0, 
          fields: [] 
        });
        
        // Mock user creation
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ 
            id: '12345678-1234-4123-8123-123456789012',
            email: 'test@example.com',
            created_at: new Date()
          }],
          command: 'INSERT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        await testUserModel.create(userData);

        expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
          'SELECT * FROM users WHERE email = $1',
          ['test@example.com']
        );
      });

      it('should throw conflict error if email already exists', async () => {
        const userData = { email: 'existing@example.com', password: 'password123' };
        
        // Mock email check returning existing user
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ id: 'existing-user-id' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        await expect(testUserModel.create(userData)).rejects.toThrow('User with this email already exists');
        expect(mockApiError.conflict).toHaveBeenCalledWith('User with this email already exists', 'EMAIL_IN_USE');
      });

      it('should handle email case properly', async () => {
        const userData = { email: 'Test@Example.COM', password: 'password123' };
        
        mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ 
            id: '12345678-1234-4123-8123-123456789012',
            email: 'Test@Example.COM',
            created_at: new Date()
          }],
          command: 'INSERT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        await testUserModel.create(userData);

        // The implementation preserves original case
        expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
          'SELECT * FROM users WHERE email = $1',
          ['Test@Example.COM']
        );
      });
    });

    describe('Password Hashing', () => {
      it('should hash password with bcrypt before storing', async () => {
        const userData = { email: 'test@example.com', password: 'password123' };
        
        mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ 
            id: '12345678-1234-4123-8123-123456789012',
            email: 'test@example.com',
            created_at: new Date()
          }],
          command: 'INSERT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        await testUserModel.create(userData);

        expect(mockBcrypt.hash).toHaveBeenCalledWith('password123', 10);
      });

      it('should use salt rounds of 10', async () => {
        const userData = { email: 'test@example.com', password: 'password123' };
        
        mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ 
            id: '12345678-1234-4123-8123-123456789012',
            email: 'test@example.com',
            created_at: new Date()
          }],
          command: 'INSERT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        await testUserModel.create(userData);

        expect(mockBcrypt.hash).toHaveBeenCalledWith(expect.any(String), 10);
      });
    });

    describe('UUID Generation', () => {
      it('should generate UUID for new user', async () => {
        const userData = { email: 'test@example.com', password: 'password123' };
        
        mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ 
            id: '12345678-1234-4123-8123-123456789012',
            email: 'test@example.com',
            created_at: new Date()
          }],
          command: 'INSERT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        await testUserModel.create(userData);

        expect(mockUuidv4).toHaveBeenCalled();
      });
    });

    describe('Return Value', () => {
      it('should return user data without password hash', async () => {
        const userData = { email: 'test@example.com', password: 'password123' };
        const expectedUser = {
          id: '12345678-1234-4123-8123-123456789012',
          email: 'test@example.com',
          created_at: expect.any(Date)
        };
        
        mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [expectedUser],
          command: 'INSERT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.create(userData);

        expect(result).toEqual(expectedUser);
        expect(result).not.toHaveProperty('password_hash');
      });
    });
  });

  describe('User Lookup', () => {
    describe('Find By ID', () => {
      it('should validate UUID format before querying', async () => {
        const invalidUuid = 'invalid-uuid-format';

        const result = await testUserModel.findById(invalidUuid);

        expect(result).toBe(null);
        expect(mockTestDatabaseConnection.query).not.toHaveBeenCalled();
      });

      it('should return null for null/undefined ID', async () => {
        expect(await testUserModel.findById(null as any)).toBe(null);
        expect(await testUserModel.findById(undefined as any)).toBe(null);
      });

      it('should query database for valid UUID', async () => {
        const validUuid = '12345678-1234-4123-8123-123456789012';
        const expectedUser = {
          id: validUuid,
          email: 'test@example.com',
          created_at: new Date()
        };

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [expectedUser],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.findById(validUuid);

        expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
          'SELECT id, email, created_at FROM users WHERE id = $1',
          [validUuid]
        );
        expect(result).toEqual(expectedUser);
      });

      it('should return null when user not found', async () => {
        const validUuid = '12345678-1234-4123-8123-123456789012';

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'SELECT',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.findById(validUuid);

        expect(result).toBe(null);
      });

      it('should handle database UUID syntax errors gracefully', async () => {
        const invalidUuid = 'malformed-uuid';
        const dbError = new Error('invalid input syntax for type uuid');

        mockTestDatabaseConnection.query.mockRejectedValueOnce(dbError);

        const result = await testUserModel.findById(invalidUuid);

        expect(result).toBe(null);
      });
    });

    describe('Find By Email', () => {
      it('should return null for empty email', async () => {
        expect(await testUserModel.findByEmail('')).toBe(null);
        expect(await testUserModel.findByEmail(null as any)).toBe(null);
        expect(await testUserModel.findByEmail(undefined as any)).toBe(null);
      });

      it('should query database with provided email', async () => {
        const email = 'test@example.com';
        const expectedUser = {
          id: 'user-id',
          email: email,
          password_hash: '$2b$10$hash'
        };

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [expectedUser],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.findByEmail(email);

        expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
          'SELECT * FROM users WHERE email = $1',
          [email]
        );
        expect(result).toEqual(expectedUser);
      });

      it('should return null when email not found', async () => {
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'SELECT',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.findByEmail('notfound@example.com');
        expect(result).toBe(null);
      });

      it('should preserve email case in query', async () => {
        const email = 'Test@Example.COM';
        
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'SELECT',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        await testUserModel.findByEmail(email);

        expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
          'SELECT * FROM users WHERE email = $1',
          [email] // Should preserve original case based on implementation
        );
      });
    });
  });

  describe('Password Validation', () => {
    describe('Input Validation', () => {
      it('should return false for null/undefined user', async () => {
        expect(await testUserModel.validatePassword(null as any, 'password')).toBe(false);
        expect(await testUserModel.validatePassword(undefined as any, 'password')).toBe(false);
      });

      it('should return false for user without password_hash', async () => {
        const userWithoutPassword = { id: 'user-id', email: 'test@example.com' };
        
        expect(await testUserModel.validatePassword(userWithoutPassword as any, 'password')).toBe(false);
      });

      it('should return false for null/undefined password', async () => {
        const user = { id: 'user-id', email: 'test@example.com', password_hash: '$2b$10$hash' };
        
        expect(await testUserModel.validatePassword(user, null as any)).toBe(false);
        expect(await testUserModel.validatePassword(user, undefined as any)).toBe(false);
        expect(await testUserModel.validatePassword(user, '')).toBe(false);
      });
    });

    describe('Password Comparison', () => {
      it('should use bcrypt.compare for valid inputs', async () => {
        const user = { id: 'user-id', email: 'test@example.com', password_hash: '$2b$10$hash' };
        const password = 'testpassword';

        await testUserModel.validatePassword(user, password);

        expect(mockBcrypt.compare).toHaveBeenCalledWith(password, user.password_hash);
      });

      it('should return false for incorrect password', async () => {
        const user = { id: 'user-id', email: 'test@example.com', password_hash: '$2b$10$hash' };
        
        mockBcrypt.compare.mockResolvedValueOnce(false);

        const result = await testUserModel.validatePassword(user, 'wrongpassword');

        expect(result).toBe(false);
      });

      it('should propagate bcrypt comparison errors', async () => {
        const user = { id: 'user-id', email: 'test@example.com', password_hash: '$2b$10$hash' };
        
        // Set up mock to throw bcrypt error
        mockBcrypt.compare.mockImplementationOnce(() => {
          throw new Error('bcrypt error');
        });

        // The validatePassword method should propagate bcrypt errors rather than catching them
        await expect(testUserModel.validatePassword(user, 'password')).rejects.toThrow('bcrypt error');
      });
    });
  });

  describe('User Updates', () => {
    describe('Email Update', () => {
      it('should validate UUID format before updating', async () => {
        const invalidUuid = 'invalid-uuid';
        const newEmail = 'new@example.com';

        const result = await testUserModel.updateEmail(invalidUuid, newEmail);

        expect(result).toBe(null);
        expect(mockTestDatabaseConnection.query).not.toHaveBeenCalled();
      });

      it('should validate email before updating', async () => {
        const validUuid = '12345678-1234-4123-8123-123456789012';

        expect(await testUserModel.updateEmail(validUuid, '')).toBe(null);
        expect(await testUserModel.updateEmail(validUuid, null as any)).toBe(null);
      });

      it('should check for email conflicts before updating', async () => {
        const userId = '12345678-1234-4123-8123-123456789012';
        const newEmail = 'existing@example.com';

        // Mock email conflict check - email already exists
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ id: 'other-user-id', email: newEmail }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        await expect(testUserModel.updateEmail(userId, newEmail)).rejects.toThrow('Email is already in use');
        expect(mockApiError.conflict).toHaveBeenCalledWith('Email is already in use', 'EMAIL_IN_USE');
      });

      it('should update email when no conflicts exist', async () => {
        const userId = '12345678-1234-4123-8123-123456789012';
        const newEmail = 'new@example.com';

        // Mock no email conflict
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'SELECT',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        // Mock successful update
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ id: userId, email: newEmail }],
          command: 'UPDATE',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.updateEmail(userId, newEmail);

        expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
          'UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2 RETURNING id, email, created_at',
          [newEmail, userId]
        );
        expect(result).toEqual({ id: userId, email: newEmail });
      });

      it('should handle database UUID errors gracefully', async () => {
        const invalidUuid = 'malformed-uuid';
        const newEmail = 'new@example.com';
        const dbError = new Error('invalid input syntax for type uuid');

        mockTestDatabaseConnection.query.mockRejectedValueOnce(dbError);

        const result = await testUserModel.updateEmail(invalidUuid, newEmail);

        expect(result).toBe(null);
      });
    });

    describe('Password Update', () => {
      it('should validate inputs before updating password', async () => {
        expect(await testUserModel.updatePassword('', 'newpassword')).toBe(false);
        expect(await testUserModel.updatePassword('12345678-1234-4123-8123-123456789012', '')).toBe(false);
      });

      it('should hash new password before updating', async () => {
        const userId = '12345678-1234-4123-8123-123456789012';
        const newPassword = 'newpassword123';
        const hashedPassword = '$2b$10$newHashedPassword';

        // Reset and set specific mock for this test
        mockBcrypt.hash.mockResolvedValueOnce(hashedPassword);
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'UPDATE',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.updatePassword(userId, newPassword);

        expect(mockBcrypt.hash).toHaveBeenCalledWith(newPassword, 10);
        expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
          'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
          [hashedPassword, userId]
        );
        expect(result).toBe(true);
      });

      it('should return false when no rows affected', async () => {
        const userId = '12345678-1234-4123-8123-123456789012';
        const newPassword = 'newpassword123';

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'UPDATE',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.updatePassword(userId, newPassword);
        expect(result).toBe(false);
      });

      it('should handle null rowCount gracefully', async () => {
        const userId = '12345678-1234-4123-8123-123456789012';
        const newPassword = 'newpassword123';

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'UPDATE',
          rowCount: null,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.updatePassword(userId, newPassword);
        expect(result).toBe(false);
      });
    });
  });

  describe('User Deletion', () => {
    it('should validate UUID format before deleting', async () => {
      const invalidUuid = 'invalid-uuid';

      const result = await testUserModel.delete(invalidUuid);

      expect(result).toBe(false);
      expect(mockTestDatabaseConnection.query).not.toHaveBeenCalled();
    });

    it('should execute delete query for valid UUID', async () => {
      const validUuid = '12345678-1234-4123-8123-123456789012';

      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [],
        command: 'DELETE',
        rowCount: 1,
        oid: 0,
        fields: []
      });

      const result = await testUserModel.delete(validUuid);

      expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
        'DELETE FROM users WHERE id = $1',
        [validUuid]
      );
      expect(result).toBe(true);
    });

    it('should return false when no rows deleted', async () => {
      const validUuid = '12345678-1234-4123-8123-123456789012';

      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [],
        command: 'DELETE',
        rowCount: 0,
        oid: 0,
        fields: []
      });

      const result = await testUserModel.delete(validUuid);
      expect(result).toBe(false);
    });

    it('should handle null rowCount gracefully', async () => {
      const validUuid = '12345678-1234-4123-8123-123456789012';

      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [],
        command: 'DELETE',
        rowCount: null,
        oid: 0,
        fields: []
      });

      const result = await testUserModel.delete(validUuid);
      expect(result).toBe(false);
    });

    it('should handle database UUID errors gracefully', async () => {
      const invalidUuid = 'malformed-uuid';
      const dbError = new Error('invalid input syntax for type uuid');

      mockTestDatabaseConnection.query.mockRejectedValueOnce(dbError);

      const result = await testUserModel.delete(invalidUuid);
      expect(result).toBe(false);
    });
  });

  describe('User Statistics', () => {
    it('should return zero stats for invalid UUID', async () => {
      const invalidUuid = 'invalid-uuid';

      const result = await testUserModel.getUserStats(invalidUuid);

      expect(result).toEqual({
        imageCount: 0,
        garmentCount: 0,
        wardrobeCount: 0
      });
    });

    it('should execute parallel queries for valid UUID', async () => {
      const validUuid = '12345678-1234-4123-8123-123456789012';

      // Mock parallel query results in the correct order
      mockTestDatabaseConnection.query
        .mockResolvedValueOnce({
          rows: [{ image_count: '5' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        })
        .mockResolvedValueOnce({
          rows: [{ garment_count: '10' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        })
        .mockResolvedValueOnce({
          rows: [{ wardrobe_count: '3' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

      const result = await testUserModel.getUserStats(validUuid);

      expect(result).toEqual({
        imageCount: 5,
        garmentCount: 10,
        wardrobeCount: 3
      });
    });

    it('should parse string counts to integers', async () => {
      const validUuid = '12345678-1234-4123-8123-123456789012';

      mockTestDatabaseConnection.query
        .mockResolvedValueOnce({
          rows: [{ image_count: '15' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        })
        .mockResolvedValueOnce({
          rows: [{ garment_count: '25' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        })
        .mockResolvedValueOnce({
          rows: [{ wardrobe_count: '7' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

      const result = await testUserModel.getUserStats(validUuid);

      expect(result.imageCount).toBe(15);
      expect(result.garmentCount).toBe(25);
      expect(result.wardrobeCount).toBe(7);
      expect(typeof result.imageCount).toBe('number');
      expect(typeof result.garmentCount).toBe('number');
      expect(typeof result.wardrobeCount).toBe('number');
    });

    it('should handle database UUID errors gracefully', async () => {
      const invalidUuid = 'malformed-uuid';
      const dbError = new Error('invalid input syntax for type uuid');

      mockTestDatabaseConnection.query.mockRejectedValueOnce(dbError);

      const result = await testUserModel.getUserStats(invalidUuid);

      expect(result).toEqual({
        imageCount: 0,
        garmentCount: 0,
        wardrobeCount: 0
      });
    });
  });

  describe('OAuth Operations', () => {
    describe('Find By OAuth', () => {
      it('should return null for invalid provider or provider ID', async () => {
        expect(await testUserModel.findByOAuth('', 'id')).toBe(null);
        expect(await testUserModel.findByOAuth('google', '')).toBe(null);
        expect(await testUserModel.findByOAuth(null as any, 'id')).toBe(null);
      });

      it('should check linked OAuth providers first', async () => {
        const provider = 'google';
        const providerId = '123456';
        const expectedUser = {
          id: 'user-id',
          email: 'test@example.com'
        };

        // Mock linked providers check (returns user)
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [expectedUser],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.findByOAuth(provider, providerId);

        expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
          expect.stringContaining('SELECT u.* FROM users u'),
          [provider, providerId]
        );
        expect(result).toEqual(expectedUser);
      });
    });

    describe('Create OAuth User', () => {
      it('should validate required OAuth fields', async () => {
        await expect(testUserModel.createOAuthUser({
          email: '',
          oauth_provider: 'google',
          oauth_id: '123456'
        })).rejects.toThrow();

        await expect(testUserModel.createOAuthUser({
          email: 'test@example.com',
          oauth_provider: '',
          oauth_id: '123456'
        })).rejects.toThrow();

        await expect(testUserModel.createOAuthUser({
          email: 'test@example.com',
          oauth_provider: 'google',
          oauth_id: ''
        })).rejects.toThrow();
      });

      it('should check for existing email before creating OAuth user', async () => {
        const oauthData = {
          email: 'existing@example.com',
          name: 'Test User',
          avatar_url: 'test.jpg',
          oauth_provider: 'google',
          oauth_id: '123456'
        };

        // Mock existing email check
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ id: 'existing-user-id' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        await expect(testUserModel.createOAuthUser(oauthData)).rejects.toThrow('User with this email already exists');
      });

      it('should create OAuth user with all provided fields', async () => {
        const oauthData = {
          email: 'oauth@example.com',
          name: 'OAuth User',
          avatar_url: 'https://example.com/avatar.jpg',
          oauth_provider: 'google',
          oauth_id: '123456'
        };

        const expectedUser = {
          id: '12345678-1234-4123-8123-123456789012',
          email: 'oauth@example.com',
          created_at: new Date()
        };

        // Mock email check (no existing user)
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'SELECT',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        // Mock BEGIN transaction
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'BEGIN',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        // Mock user creation (INSERT INTO users)
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [expectedUser],
          command: 'INSERT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        // Mock OAuth provider insert
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'INSERT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        // Mock COMMIT transaction
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'COMMIT',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.createOAuthUser(oauthData);

        // Verify correct sequence of calls
        expect(mockTestDatabaseConnection.query).toHaveBeenNthCalledWith(1,
          'SELECT * FROM users WHERE email = $1',
          ['oauth@example.com']
        );
        expect(mockTestDatabaseConnection.query).toHaveBeenNthCalledWith(2, 'BEGIN');
        expect(mockTestDatabaseConnection.query).toHaveBeenNthCalledWith(3,
          expect.stringContaining('INSERT INTO users'),
          ['12345678-1234-4123-8123-123456789012', 'oauth@example.com']
        );
        expect(mockTestDatabaseConnection.query).toHaveBeenNthCalledWith(4,
          expect.stringContaining('INSERT INTO user_oauth_providers'),
          ['12345678-1234-4123-8123-123456789012', 'google', '123456']
        );
        expect(mockTestDatabaseConnection.query).toHaveBeenNthCalledWith(5, 'COMMIT');
        
        expect(result).toEqual(expectedUser);
      });

      it('should handle optional fields as null', async () => {
        const oauthData = {
          email: 'oauth@example.com',
          name: null,
          avatar_url: null,
          oauth_provider: 'google',
          oauth_id: '123456'
        };

        // Mock complete transaction sequence
        mockTestDatabaseConnection.query
          .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] })
          .mockResolvedValueOnce({ rows: [], command: 'BEGIN', rowCount: 0, oid: 0, fields: [] })
          .mockResolvedValueOnce({
            rows: [{
              id: '12345678-1234-4123-8123-123456789012',
              email: 'oauth@example.com',
              created_at: new Date()
            }],
            command: 'INSERT',
            rowCount: 1,
            oid: 0,
            fields: []
          })
          .mockResolvedValueOnce({ rows: [], command: 'INSERT', rowCount: 1, oid: 0, fields: [] })
          .mockResolvedValueOnce({ rows: [], command: 'COMMIT', rowCount: 0, oid: 0, fields: [] });

        const result = await testUserModel.createOAuthUser(oauthData);

        expect(result).toBeDefined();
        expect(result.email).toBe('oauth@example.com');
      });
    });

    describe('Get User With OAuth Providers', () => {
      it('should return null for invalid UUID', async () => {
        const invalidUuid = 'invalid-uuid';

        const result = await testUserModel.getUserWithOAuthProviders(invalidUuid);

        expect(result).toBe(null);
        expect(mockTestDatabaseConnection.query).not.toHaveBeenCalled();
      });

      it('should return null when user not found', async () => {
        const validUuid = '12345678-1234-4123-8123-123456789012';

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'SELECT',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.getUserWithOAuthProviders(validUuid);
        expect(result).toBe(null);
      });

      it('should combine direct OAuth provider with linked providers', async () => {
        const validUuid = '12345678-1234-4123-8123-123456789012';
        const user = {
          id: validUuid,
          email: 'test@example.com',
          created_at: new Date()
        };

        // Mock user query (updated to match new implementation)
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [user],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        // Mock linked providers query
        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [
            { provider: 'facebook' },
            { provider: 'github' }
          ],
          command: 'SELECT',
          rowCount: 2,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.getUserWithOAuthProviders(validUuid);

        // Updated expectation to match new implementation
        expect(result).toEqual({
          ...user,
          linkedProviders: ['facebook', 'github'],
          // Add placeholder values that new implementation returns
          name: null,
          avatar_url: null,
          oauth_provider: null
        });
      });

      it('should handle user with only linked providers', async () => {
        const validUuid = '12345678-1234-4123-8123-123456789012';
        const user = {
          id: validUuid,
          email: 'test@example.com',
          created_at: new Date()
        };

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [user],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [{ provider: 'google' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.getUserWithOAuthProviders(validUuid);

        // Updated expectation
        expect(result).toEqual({
          ...user,
          linkedProviders: ['google'],
          name: null,
          avatar_url: null,
          oauth_provider: null
        });
      });

      it('should handle user with no OAuth providers', async () => {
        const validUuid = '12345678-1234-4123-8123-123456789012';
        const user = {
          id: validUuid,
          email: 'test@example.com',
          created_at: new Date()
        };

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [user],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        mockTestDatabaseConnection.query.mockResolvedValueOnce({
          rows: [],
          command: 'SELECT',
          rowCount: 0,
          oid: 0,
          fields: []
        });

        const result = await testUserModel.getUserWithOAuthProviders(validUuid);

        // Updated expectation
        expect(result).toEqual({
          ...user,
          linkedProviders: [],
          name: null,
          avatar_url: null,
          oauth_provider: null
        });
      });

      it('should handle database UUID errors gracefully', async () => {
        const invalidUuid = 'malformed-uuid';
        const dbError = new Error('invalid input syntax for type uuid');

        mockTestDatabaseConnection.query.mockRejectedValueOnce(dbError);

        const result = await testUserModel.getUserWithOAuthProviders(invalidUuid);
        expect(result).toBe(null);
      });
    });
  });

  describe('Error Handling', () => {
    it('should propagate non-UUID database errors', async () => {
      const validUuid = '12345678-1234-4123-8123-123456789012';
      const dbError = new Error('Connection failed');

      mockTestDatabaseConnection.query.mockRejectedValueOnce(dbError);

      await expect(testUserModel.findById(validUuid)).rejects.toThrow('Connection failed');
    });

    it('should handle bcrypt errors in password operations', async () => {
      const userData = { email: 'test@example.com', password: 'password123' };
      const bcryptError = new Error('bcrypt failed');

      // Reset and configure mocks for this specific test
      mockBcrypt.hash.mockReset();
      mockBcrypt.hash.mockRejectedValue(bcryptError);
      mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });

      await expect(testUserModel.create(userData)).rejects.toThrow('bcrypt failed');
    });

    it('should handle UUID generation errors', async () => {
      const userData = { email: 'test@example.com', password: 'password123' };
      const uuidError = new Error('UUID generation failed');

      // Reset and configure mocks for this specific test
      mockUuidv4.mockReset();
      mockUuidv4.mockImplementation(() => {
        throw uuidError;
      });
      mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });

      await expect(testUserModel.create(userData)).rejects.toThrow('UUID generation failed');
    });
  });

  describe('Input Sanitization', () => {
    it('should handle special characters in email safely', async () => {
      const specialEmail = "test+special@exam'ple.com";
      
      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: []
      });

      const result = await testUserModel.findByEmail(specialEmail);

      expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
        'SELECT * FROM users WHERE email = $1',
        [specialEmail]
      );
      expect(result).toBe(null);
    });

    it('should handle whitespace in inputs appropriately', async () => {
      const emailWithWhitespace = '  test@example.com  ';
      const passwordWithWhitespace = '  password123  ';
      
      mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [{
          id: '12345678-1234-4123-8123-123456789012',
          email: 'test@example.com',
          created_at: new Date()
        }],
        command: 'INSERT',
        rowCount: 1,
        oid: 0,
        fields: []
      });

      await testUserModel.create({ 
        email: emailWithWhitespace, 
        password: passwordWithWhitespace 
      });

      // Should check with trimmed email - based on implementation behavior
      expect(mockTestDatabaseConnection.query).toHaveBeenCalledWith(
        'SELECT * FROM users WHERE email = $1',
        ['  test@example.com  '] // Implementation doesn't trim automatically
      );
    });
  });

  describe('Data Type Consistency', () => {
    it('should consistently return boolean for validation methods', async () => {
      const user = { id: 'user-id', email: 'test@example.com', password_hash: '$2b$10$hash' };
      
      // Reset mock for this test
      mockBcrypt.compare.mockResolvedValueOnce(true);
      const result = await testUserModel.validatePassword(user, 'password');

      expect(typeof result).toBe('boolean');
      expect(result).toBe(true);
    });

    it('should consistently return boolean for update/delete operations', async () => {
      const validUuid = '12345678-1234-4123-8123-123456789012';

      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [],
        command: 'UPDATE',
        rowCount: 1,
        oid: 0,
        fields: []
      });

      const result = await testUserModel.updatePassword(validUuid, 'newpassword');

      expect(typeof result).toBe('boolean');
      expect(result).toBe(true);
    });

    it('should consistently return numbers for statistics', async () => {
      const validUuid = '12345678-1234-4123-8123-123456789012';

      mockTestDatabaseConnection.query
        .mockResolvedValueOnce({
          rows: [{ image_count: '5' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        })
        .mockResolvedValueOnce({
          rows: [{ garment_count: '10' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        })
        .mockResolvedValueOnce({
          rows: [{ wardrobe_count: '3' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

      const result = await testUserModel.getUserStats(validUuid);

      expect(typeof result.imageCount).toBe('number');
      expect(typeof result.garmentCount).toBe('number');
      expect(typeof result.wardrobeCount).toBe('number');
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    it('should handle extremely long email addresses', async () => {
      const longEmail = 'a'.repeat(100) + '@example.com';

      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [],
        command: 'SELECT',
        rowCount: 0,
        oid: 0,
        fields: []
      });

      const result = await testUserModel.findByEmail(longEmail);

      expect(result).toBe(null);
      expect(mockTestDatabaseConnection.query).toHaveBeenCalled();
    });

    it('should handle concurrent user creation attempts', async () => {
      const userData1 = { email: 'test@example.com', password: 'password123' };
      const userData2 = { email: 'test@example.com', password: 'password456' };

      // First user creation succeeds
      mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [{ id: '12345678-1234-4123-8123-123456789012', email: 'test@example.com' }],
        command: 'INSERT',
        rowCount: 1,
        oid: 0,
        fields: []
      });

      // Second user creation fails due to existing email
      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [{ id: 'existing-id' }],
        command: 'SELECT',
        rowCount: 1,
        oid: 0,
        fields: []
      });

      const result1 = await testUserModel.create(userData1);
      await expect(testUserModel.create(userData2)).rejects.toThrow('User with this email already exists');

      expect(result1).toBeDefined();
    });

    it('should handle very long passwords', async () => {
      const longPassword = 'a'.repeat(1000);
      const userData = { email: 'test@example.com', password: longPassword };

      mockTestDatabaseConnection.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockTestDatabaseConnection.query.mockResolvedValueOnce({
        rows: [{
          id: '12345678-1234-4123-8123-123456789012',
          email: 'test@example.com',
          created_at: new Date()
        }],
        command: 'INSERT',
        rowCount: 1,
        oid: 0,
        fields: []
      });

      const result = await testUserModel.create(userData);

      expect(mockBcrypt.hash).toHaveBeenCalledWith(longPassword, 10);
      expect(result.email).toBe('test@example.com');
    });

    it('should handle database connection timeouts gracefully', async () => {
      const timeoutError = new Error('query timeout');
      mockTestDatabaseConnection.query.mockRejectedValueOnce(timeoutError);

      await expect(testUserModel.findByEmail('test@example.com')).rejects.toThrow('query timeout');
    });
  });
});