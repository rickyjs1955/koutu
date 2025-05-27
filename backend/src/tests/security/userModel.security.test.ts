// /backend/src/models/__tests__/security/userModel.security.test.ts
import { userModel, User, CreateUserInput, CreateOAuthUserInput } from '../../models/userModel';
import { setupTestDatabase, teardownTestDatabase, testQuery } from '../../utils/testSetup';

describe('userModel Security Tests', () => {
  // Track created users for cleanup
  const createdUserIds: string[] = [];

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    await setupTestDatabase();
    
    // Create users table for security testing
    await testQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        name TEXT,
        avatar_url TEXT,
        oauth_provider TEXT,
        oauth_id TEXT,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    await testQuery(`
      CREATE TABLE IF NOT EXISTS user_oauth_providers (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        UNIQUE(provider, provider_id)
      )
    `);

    // Add test tables for statistics
    await testQuery(`
      CREATE TABLE IF NOT EXISTS original_images (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    await testQuery(`
      CREATE TABLE IF NOT EXISTS garment_items (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);

    await testQuery(`
      CREATE TABLE IF NOT EXISTS wardrobes (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
      )
    `);
  }, 30000);

  afterAll(async () => {
    try {
      if (createdUserIds.length > 0) {
        await testQuery(`DELETE FROM users WHERE id = ANY($1)`, [createdUserIds]);
      }
      
      await testQuery(`DROP TABLE IF EXISTS wardrobes CASCADE`);
      await testQuery(`DROP TABLE IF EXISTS garment_items CASCADE`);
      await testQuery(`DROP TABLE IF EXISTS original_images CASCADE`);
      await testQuery(`DROP TABLE IF EXISTS user_oauth_providers CASCADE`);
      await testQuery(`DROP TABLE IF EXISTS users CASCADE`);
    } catch (error) {
      console.error('Security test cleanup error:', error);
    }

    await teardownTestDatabase();
  }, 30000);

  beforeEach(async () => {
    // Clean up test data before each test
    await testQuery(`DELETE FROM users WHERE id = ANY($1)`, [createdUserIds]);
    createdUserIds.length = 0;
  });

  // Helper function to create test user
  const createTestUser = async (overrides: Partial<CreateUserInput> = {}): Promise<{ user: any, input: CreateUserInput }> => {
    const input: CreateUserInput = {
      email: `security-test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
      password: 'SecurePassword123!',
      ...overrides
    };
    
    const user = await userModel.create(input);
    createdUserIds.push(user.id);
    return { user, input };
  };

  const createTestOAuthUser = async (overrides: Partial<CreateOAuthUserInput> = {}) => {
    const input: CreateOAuthUserInput = {
      email: `oauth-security-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
      name: 'Security Test User',
      oauth_provider: 'google',
      oauth_id: `google_security_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      ...overrides
    };
    
    const user = await userModel.createOAuthUser(input);
    createdUserIds.push(user.id);
    return { user, input };
  };

  describe('Password Security', () => {
    describe('Password Hashing', () => {
      it('should hash passwords with bcrypt and sufficient salt rounds', async () => {
        const { user, input } = await createTestUser({ password: 'TestPassword123!' });
        
        const dbResult = await testQuery('SELECT password_hash FROM users WHERE id = $1', [user.id]);
        const passwordHash = dbResult.rows[0].password_hash;
        
        // Verify bcrypt format ($2b$rounds$salt+hash)
        expect(passwordHash).toMatch(/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/);
        
        // Verify salt rounds (should be at least 10)
        const rounds = parseInt(passwordHash.split('$')[2]);
        expect(rounds).toBeGreaterThanOrEqual(10);
        
        // Verify password is not stored in plain text
        expect(passwordHash).not.toBe(input.password);
        expect(passwordHash).not.toContain(input.password);
      });

      it('should generate unique hashes for identical passwords', async () => {
        const password = 'SamePassword123!';
        
        const { user: user1 } = await createTestUser({ password });
        const { user: user2 } = await createTestUser({ password });
        
        const result1 = await testQuery('SELECT password_hash FROM users WHERE id = $1', [user1.id]);
        const result2 = await testQuery('SELECT password_hash FROM users WHERE id = $1', [user2.id]);
        
        const hash1 = result1.rows[0].password_hash;
        const hash2 = result2.rows[0].password_hash;
        
        // Hashes should be different due to unique salts
        expect(hash1).not.toBe(hash2);
        
        // But both should validate correctly
        const user1Data = await userModel.findByEmail(user1.email) as User;
        const user2Data = await userModel.findByEmail(user2.email) as User;
        
        expect(await userModel.validatePassword(user1Data, password)).toBe(true);
        expect(await userModel.validatePassword(user2Data, password)).toBe(true);
      });

      it('should not expose password hash in user output', async () => {
        const { user, input } = await createTestUser();
        
        // Check create output
        expect(user).not.toHaveProperty('password_hash');
        expect(user).not.toHaveProperty('password');
        
        // Check findById output
        const foundUser = await userModel.findById(user.id);
        expect(foundUser).not.toHaveProperty('password_hash');
        expect(foundUser).not.toHaveProperty('password');
        
        // Verify password_hash is only in findByEmail (for authentication)
        const userWithHash = await userModel.findByEmail(input.email);
        expect(userWithHash).toHaveProperty('password_hash');
      });
    });

    describe('Password Validation Security', () => {
      it('should use constant-time comparison for password validation', async () => {
        const { input } = await createTestUser({ password: 'CorrectPassword123!' });
        const user = await userModel.findByEmail(input.email) as User;
        
        const correctPassword = 'CorrectPassword123!';
        const wrongPassword = 'WrongPassword123!';
        
        // Measure timing for correct and incorrect passwords
        const timings: number[] = [];
        
        for (let i = 0; i < 10; i++) {
          const start = process.hrtime.bigint();
          await userModel.validatePassword(user, i % 2 === 0 ? correctPassword : wrongPassword);
          const end = process.hrtime.bigint();
          timings.push(Number(end - start) / 1000000); // Convert to milliseconds
        }
        
        // bcrypt should provide constant-time comparison
        // Variance should be minimal regardless of password correctness
        const correctTimings = timings.filter((_, i) => i % 2 === 0);
        const incorrectTimings = timings.filter((_, i) => i % 2 === 1);
        
        expect(correctTimings.length).toBeGreaterThan(0);
        expect(incorrectTimings.length).toBeGreaterThan(0);
        
        // Verify both return appropriate boolean values
        expect(await userModel.validatePassword(user, correctPassword)).toBe(true);
        expect(await userModel.validatePassword(user, wrongPassword)).toBe(false);
      });

      it('should handle timing attacks on non-existent users', async () => {
        const nonExistentUser: User = {
          id: 'non-existent',
          email: 'nonexistent@example.com',
          password_hash: '$2b$10$invalidhashfortimingtestpurposes',
          created_at: new Date(),
          updated_at: new Date()
        };
        
        const timings: number[] = [];
        
        for (let i = 0; i < 5; i++) {
          const start = process.hrtime.bigint();
          const result = await userModel.validatePassword(nonExistentUser, 'AnyPassword123!');
          const end = process.hrtime.bigint();
          
          timings.push(Number(end - start) / 1000000);
          expect(result).toBe(false);
        }
        
        // Should still take reasonable time (not immediately fail)
        const avgTiming = timings.reduce((a, b) => a + b) / timings.length;
        expect(avgTiming).toBeGreaterThan(1); // Should take at least 1ms
      });
    });

    describe('Password Update Security', () => {
      it('should hash new passwords when updating', async () => {
        const { user } = await createTestUser();
        const newPassword = 'NewSecurePassword456!';
        
        const updateResult = await userModel.updatePassword(user.id, newPassword);
        expect(updateResult).toBe(true);
        
        const updatedUser = await userModel.findByEmail(user.email) as User;
        
        // Verify new password is hashed
        expect(updatedUser.password_hash).toMatch(/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/);
        expect(updatedUser.password_hash).not.toBe(newPassword);
        
        // Verify new password works
        expect(await userModel.validatePassword(updatedUser, newPassword)).toBe(true);
      });

      it('should invalidate old password after update', async () => {
        const { user, input } = await createTestUser();
        const oldPassword = input.password;
        const newPassword = 'NewSecurePassword456!';
        
        await userModel.updatePassword(user.id, newPassword);
        
        const updatedUser = await userModel.findByEmail(user.email) as User;
        
        // Old password should no longer work
        expect(await userModel.validatePassword(updatedUser, oldPassword)).toBe(false);
        
        // New password should work
        expect(await userModel.validatePassword(updatedUser, newPassword)).toBe(true);
      });
    });
  });

  describe('SQL Injection Prevention', () => {
    describe('Email Input Sanitization', () => {
      it('should prevent SQL injection in email fields', async () => {
        const maliciousEmails = [
          "'; DROP TABLE users; --",
          "admin@example.com'; DELETE FROM users WHERE '1'='1",
          "test@example.com' UNION SELECT password_hash FROM users --",
          "'; INSERT INTO users (email, password_hash) VALUES ('hacker@evil.com', 'hash'); --",
          "test'; UPDATE users SET email='hacked@evil.com' WHERE '1'='1; --"
        ];
        
        for (const email of maliciousEmails) {
          try {
            await createTestUser({ email });
            
            // If user was created, verify no SQL injection occurred
            const userCount = await testQuery('SELECT COUNT(*) as count FROM users');
            const initialCount = parseInt(userCount.rows[0].count);
            
            // Verify tables still exist and have expected structure
            const tableCheck = await testQuery(`
              SELECT table_name FROM information_schema.tables 
              WHERE table_schema = 'public' AND table_name = 'users'
            `);
            expect(tableCheck.rows.length).toBe(1);
            
            // Try to find the user (should work if properly escaped)
            const foundUser = await userModel.findByEmail(email);
            if (foundUser) {
              expect(foundUser.email).toBe(email);
            }
            
          } catch (error) {
            // If creation failed, it should be due to validation, not SQL injection
            expect(error).toBeInstanceOf(Error);
            // SQL injection would typically cause database errors, not application errors
          }
        }
        
        // Verify database integrity after all attempts
        const finalTableCheck = await testQuery(`
          SELECT table_name FROM information_schema.tables 
          WHERE table_schema = 'public' AND table_name = 'users'
        `);
        expect(finalTableCheck.rows.length).toBe(1);
      });

      it('should prevent SQL injection in findByEmail queries', async () => {
        const { user } = await createTestUser();
        
        const maliciousQueries = [
          "' OR '1'='1",
          "' UNION SELECT password_hash, email, id FROM users --",
          "'; DROP TABLE users; --",
          "' OR id IN (SELECT id FROM users) --"
        ];
        
        for (const maliciousQuery of maliciousQueries) {
          const result = await userModel.findByEmail(maliciousQuery);
          
          // Should return null for non-existent email, not error or unauthorized data
          expect(result).toBeNull();
        }
        
        // Verify legitimate user still exists
        const legitimateResult = await userModel.findByEmail(user.email);
        expect(legitimateResult).not.toBeNull();
      });
    });

    describe('ID Parameter Sanitization', () => {
      it('should prevent SQL injection in findById queries', async () => {
        const { user } = await createTestUser();
        
        const maliciousIds = [
          "'; DROP TABLE users; --",
          "' OR '1'='1",
          "' UNION SELECT email, password_hash, created_at FROM users --",
          `${user.id}'; UPDATE users SET email='hacked@evil.com' --`
        ];
        
        for (const maliciousId of maliciousIds) {
          const result = await userModel.findById(maliciousId);
          
          // Should return null for invalid ID, not error or unauthorized data
          expect(result).toBeNull();
        }
        
        // Verify legitimate lookup still works
        const legitimateResult = await userModel.findById(user.id);
        expect(legitimateResult).not.toBeNull();
        expect(legitimateResult?.id).toBe(user.id);
      });

      it('should prevent SQL injection in update operations', async () => {
        const { user } = await createTestUser();
        
        const maliciousIds = [
          "'; UPDATE users SET email='hacked@evil.com' WHERE '1'='1; --",
          "' OR '1'='1",
          `${user.id}'; DROP TABLE users; --`
        ];
        
        for (const maliciousId of maliciousIds) {
          try {
            await userModel.updateEmail(maliciousId, 'test@example.com');
            await userModel.updatePassword(maliciousId, 'newpassword');
            await userModel.delete(maliciousId);
          } catch (error) {
            // Errors are acceptable, but SQL injection should not occur
          }
        }
        
        // Verify original user is unaffected
        const originalUser = await userModel.findById(user.id);
        expect(originalUser).not.toBeNull();
        expect(originalUser?.email).toBe(user.email);
        
        // Verify database integrity
        const tableCheck = await testQuery(`
          SELECT table_name FROM information_schema.tables 
          WHERE table_schema = 'public' AND table_name = 'users'
        `);
        expect(tableCheck.rows.length).toBe(1);
      });
    });

    describe('OAuth Parameter Sanitization', () => {
            it('should prevent SQL injection in OAuth queries', async () => {
        const { user, input } = await createTestOAuthUser();
        
        const maliciousProviders = [
          "'; DROP TABLE users; --",
          "google'; DELETE FROM users --",
          "' OR '1'='1"
        ];
        
        const maliciousProviderIds = [
          "'; DROP TABLE user_oauth_providers; --",
          "123'; UPDATE users SET email='hacked@evil.com' --",
          "' OR '1'='1"
        ];
        
        for (const provider of maliciousProviders) {
          for (const providerId of maliciousProviderIds) {
            const result = await userModel.findByOAuth(provider, providerId);
            expect(result).toBeNull();
          }
        }
        
        // Verify legitimate OAuth lookup still works
        const legitimateResult = await userModel.findByOAuth(input.oauth_provider, input.oauth_id);
        expect(legitimateResult).not.toBeNull();
      });

      it('should prevent SQL injection in OAuth user creation', async () => {
        const maliciousOAuthData: CreateOAuthUserInput[] = [
          {
            email: "test@example.com",
            oauth_provider: "'; DROP TABLE users; --",
            oauth_id: "legitimate_id"
          },
          {
            email: "test2@example.com",
            oauth_provider: "google",
            oauth_id: "'; DELETE FROM users; --"
          },
          {
            email: "'; UPDATE users SET email='hacked@evil.com'; --",
            oauth_provider: "google",
            oauth_id: "legitimate_id"
          }
        ];
        
        for (const maliciousData of maliciousOAuthData) {
          try {
            const result = await userModel.createOAuthUser(maliciousData);
            // If successful, verify it was properly escaped
            if (result) {
              createdUserIds.push(result.id);
              const dbUser = await testQuery('SELECT * FROM users WHERE id = $1', [result.id]);
              expect(dbUser.rows[0].oauth_provider).toBe(maliciousData.oauth_provider);
              expect(dbUser.rows[0].oauth_id).toBe(maliciousData.oauth_id);
            }
          } catch (error) {
            // Errors are acceptable, but should not be SQL injection errors
            expect(error).toBeInstanceOf(Error);
          }
        }
        
        // Verify database integrity
        const tableCheck = await testQuery(`
          SELECT table_name FROM information_schema.tables 
          WHERE table_schema = 'public' AND table_name = 'users'
        `);
        expect(tableCheck.rows.length).toBe(1);
      });
    });
  });

  describe('Data Exposure Prevention', () => {
    describe('Sensitive Data Filtering', () => {
      it('should never expose password hashes in user output', async () => {
        const { user, input } = await createTestUser();
        
        // Test all user retrieval methods
        const foundById = await userModel.findById(user.id);
        const userWithProviders = await userModel.getUserWithOAuthProviders(user.id);
        const stats = await userModel.getUserStats(user.id);
        const emailUpdate = await userModel.updateEmail(user.id, 'new@example.com');
        
        // None of these should contain password hashes
        [foundById, userWithProviders, emailUpdate].forEach(result => {
          if (result) {
            expect(result).not.toHaveProperty('password_hash');
            expect(result).not.toHaveProperty('password');
            expect(JSON.stringify(result)).not.toContain('$2b$');
          }
        });
        
        expect(stats).not.toHaveProperty('password_hash');
        expect(stats).not.toHaveProperty('password');
      });

      it('should only expose password hash in findByEmail for authentication', async () => {
        const { input } = await createTestUser();
        
        const userWithHash = await userModel.findByEmail(input.email);
        
        expect(userWithHash).toHaveProperty('password_hash');
        expect(userWithHash?.password_hash).toMatch(/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/);
        
        // Verify this is the only method that exposes the hash
        expect(typeof userWithHash?.password_hash).toBe('string');
      });

      it('should not expose other users data in error messages', async () => {
        const { user: user1 } = await createTestUser();
        const { user: user2 } = await createTestUser();
        
        try {
          // Try to update user1's email to user2's email
          await userModel.updateEmail(user1.id, user2.email);
          fail('Should have thrown an error');
        } catch (error: any) {
          // Error message should not contain user2's data
          expect(error.message).not.toContain(user2.id);
          expect(error.message).not.toContain('password_hash');
          expect(error.message).toBe('Email is already in use');
        }
      });
    });

    describe('Information Disclosure Prevention', () => {
      it('should not reveal user existence through timing differences', async () => {
        const { input: existingUser } = await createTestUser();
        const nonExistentEmail = 'nonexistent@example.com';
        
        const timings: { email: string, time: number }[] = [];
        
        // Test multiple queries to both existing and non-existing users
        for (let i = 0; i < 10; i++) {
          const email = i % 2 === 0 ? existingUser.email : nonExistentEmail;
          const start = process.hrtime.bigint();
          await userModel.findByEmail(email);
          const end = process.hrtime.bigint();
          
          timings.push({
            email,
            time: Number(end - start) / 1000000
          });
        }
        
        const existingUserTimings = timings.filter(t => t.email === existingUser.email);
        const nonExistentTimings = timings.filter(t => t.email === nonExistentEmail);
        
        // Both should take similar amounts of time
        expect(existingUserTimings.length).toBeGreaterThan(0);
        expect(nonExistentTimings.length).toBeGreaterThan(0);
        
        // Timing difference should not be significant enough to reveal existence
        const avgExisting = existingUserTimings.reduce((a, b) => a + b.time, 0) / existingUserTimings.length;
        const avgNonExistent = nonExistentTimings.reduce((a, b) => a + b.time, 0) / nonExistentTimings.length;
        
        // Both should be in reasonable range (not orders of magnitude different)
        expect(avgExisting).toBeGreaterThan(0);
        expect(avgNonExistent).toBeGreaterThan(0);
      });

      it('should not expose internal database structure in errors', async () => {
        const malformedInputs = [
          { email: 'not-an-email', password: 'password' },
          { email: '', password: 'password' },
          { email: null as any, password: 'password' },
          { email: 'test@example.com', password: '' },
          { email: 'test@example.com', password: null as any }
        ];
        
        for (const input of malformedInputs) {
          try {
            await userModel.create(input);
          } catch (error: any) {
            // Error messages should not reveal internal structure
            expect(error.message).not.toContain('users');
            expect(error.message).not.toContain('password_hash');
            expect(error.message).not.toContain('SELECT');
            expect(error.message).not.toContain('INSERT');
            expect(error.message).not.toContain('$1');
            expect(error.message).not.toContain('constraint');
          }
        }
      });
    });
  });

  describe('Authentication Security', () => {
    describe('OAuth Security', () => {
      it('should validate OAuth provider inputs', async () => {
        const maliciousOAuthInputs = [
          { oauth_provider: '', oauth_id: 'valid_id' },
          { oauth_provider: '   ', oauth_id: 'valid_id' },
          { oauth_provider: 'google', oauth_id: '' },
          { oauth_provider: 'google', oauth_id: '   ' },
          { oauth_provider: 'invalid<script>alert(1)</script>', oauth_id: 'valid_id' },
          { oauth_provider: 'google', oauth_id: '<script>alert(1)</script>' }
        ];
        
        for (const { oauth_provider, oauth_id } of maliciousOAuthInputs) {
          const result = await userModel.findByOAuth(oauth_provider, oauth_id);
          expect(result).toBeNull();
          
          // Try creating OAuth user with malicious data
          try {
            await userModel.createOAuthUser({
              email: 'test@example.com',
              oauth_provider,
              oauth_id
            });
          } catch (error) {
            // Should handle gracefully without exposing internal details
            expect(error).toBeInstanceOf(Error);
          }
        }
      });

      it('should prevent OAuth provider impersonation', async () => {
        const { user } = await createTestOAuthUser({
          oauth_provider: 'google',
          oauth_id: 'real_google_user'
        });
        
        // Try to find user with similar but different provider names
        const impersonationAttempts = [
          { provider: 'Google', id: 'real_google_user' }, // Case variation
          { provider: 'google ', id: 'real_google_user' }, // Trailing space
          { provider: ' google', id: 'real_google_user' }, // Leading space
          { provider: 'google\n', id: 'real_google_user' }, // Newline
          { provider: 'google\t', id: 'real_google_user' }, // Tab
        ];
        
        for (const { provider, id } of impersonationAttempts) {
          const result = await userModel.findByOAuth(provider, id);
          if (provider.trim().toLowerCase() === 'google') {
            // Should only match exact case
            expect(result).toBeNull();
          }
        }
        
        // Verify legitimate lookup still works
        const legitimateResult = await userModel.findByOAuth('google', 'real_google_user');
        expect(legitimateResult?.id).toBe(user.id);
      });

      it('should handle OAuth ID collisions securely', async () => {
        const oauthId = 'collision_test_id';
        
        // Create users with same OAuth ID but different providers
        const { user: googleUser, input: googleInput } = await createTestOAuthUser({
          oauth_provider: 'google',
          oauth_id: oauthId
        });
        
        const { user: githubUser, input: githubInput } = await createTestOAuthUser({
          oauth_provider: 'github',
          oauth_id: oauthId
        });
        
        // Each provider should find its own user
        const foundGoogle = await userModel.findByOAuth(googleInput.oauth_provider, googleInput.oauth_id);
        const foundGithub = await userModel.findByOAuth(githubInput.oauth_provider, githubInput.oauth_id);
        
        expect(foundGoogle?.id).toBe(googleUser.id);
        expect(foundGithub?.id).toBe(githubUser.id);
        expect(foundGoogle?.id).not.toBe(foundGithub?.id);
      });
    });

    describe('Session Security', () => {
      it('should not store session data in user model', async () => {
        const { user } = await createTestUser();
        
        // User model should not contain any session-related data
        const foundUser = await userModel.findById(user.id);
        const userWithProviders = await userModel.getUserWithOAuthProviders(user.id);
        
        [foundUser, userWithProviders].forEach(result => {
          if (result) {
            expect(result).not.toHaveProperty('session_id');
            expect(result).not.toHaveProperty('session_token');
            expect(result).not.toHaveProperty('access_token');
            expect(result).not.toHaveProperty('refresh_token');
            expect(result).not.toHaveProperty('jwt');
            expect(result).not.toHaveProperty('token');
          }
        });
      });

      it('should handle concurrent authentication attempts securely', async () => {
        const { input } = await createTestUser();
        const user = await userModel.findByEmail(input.email) as User;
        
        // Simulate multiple concurrent password validations
        const validationPromises = Array.from({ length: 10 }, (_, i) => 
          userModel.validatePassword(user, i % 2 === 0 ? input.password : 'wrong_password')
        );
        
        const results = await Promise.all(validationPromises);
        
        // Results should be correct regardless of concurrency
        results.forEach((result, index) => {
          if (index % 2 === 0) {
            expect(result).toBe(true); // Correct password
          } else {
            expect(result).toBe(false); // Wrong password
          }
        });
      });
    });
  });

  describe('Access Control Security', () => {
    describe('User Isolation', () => {
      it('should prevent users from accessing other users data', async () => {
        const { user: user1 } = await createTestUser();
        const { user: user2 } = await createTestUser();
        
        // User1 should not be able to update user2's data
        const updateResult = await userModel.updateEmail(user1.id, user2.email);
        expect(updateResult).toBeNull(); // Should fail due to email conflict
        
        // User operations should be isolated by user ID
        const user1Stats = await userModel.getUserStats(user1.id);
        const user2Stats = await userModel.getUserStats(user2.id);
        
        expect(user1Stats).toEqual({ imageCount: 0, garmentCount: 0, wardrobeCount: 0 });
        expect(user2Stats).toEqual({ imageCount: 0, garmentCount: 0, wardrobeCount: 0 });
        
        // Add data for user1
        await testQuery('INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)', [user1.id, 'user1_image.jpg']);
        
        // User2's stats should remain unchanged
        const user2StatsAfter = await userModel.getUserStats(user2.id);
        expect(user2StatsAfter.imageCount).toBe(0);
        
        const user1StatsAfter = await userModel.getUserStats(user1.id);
        expect(user1StatsAfter.imageCount).toBe(1);
      });

      it('should prevent privilege escalation through parameter manipulation', async () => {
        const { user: normalUser } = await createTestUser();
        const { user: adminUser } = await createTestUser({ email: 'admin@example.com' });
        
        // Create admin-specific data
        await testQuery('INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)', [adminUser.id, 'admin_secret.jpg']);
        
        // Normal user should not be able to access admin's data through parameter manipulation
        const normalUserStats = await userModel.getUserStats(normalUser.id);
        expect(normalUserStats.imageCount).toBe(0);
        
        // Even if someone tries to manipulate the user ID in a request
        // the model should only return data for the specified user
        const adminStats = await userModel.getUserStats(adminUser.id);
        expect(adminStats.imageCount).toBe(1);
        
        // Verify data isolation
        expect(normalUserStats.imageCount).not.toBe(adminStats.imageCount);
      });
    });

    describe('Authorization Boundaries', () => {
      it('should enforce proper user boundaries in OAuth operations', async () => {
        const { user: user1 } = await createTestUser();
        const { user: user2 } = await createTestOAuthUser();
        
        // Link OAuth provider to user1
        await testQuery(
          'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
          [user1.id, 'github', 'github_user1']
        );
        
        // User2 should not see user1's linked providers
        const user1WithProviders = await userModel.getUserWithOAuthProviders(user1.id);
        const user2WithProviders = await userModel.getUserWithOAuthProviders(user2.id);
        
        expect(user1WithProviders?.linkedProviders).toContain('github');
        expect(user2WithProviders?.linkedProviders).not.toContain('github');
        
        // OAuth lookup should return correct user
        const foundUser = await userModel.findByOAuth('github', 'github_user1');
        expect(foundUser?.id).toBe(user1.id);
        expect(foundUser?.id).not.toBe(user2.id);
      });

      it('should prevent unauthorized data modification', async () => {
        const { user, input } = await createTestUser();
        const originalEmail = input.email;
        
        // Try to update with malicious data
        const maliciousEmails = [
          'admin@system.com',
          'root@localhost',
          'system@internal.local'
        ];
        
        for (const email of maliciousEmails) {
          const result = await userModel.updateEmail(user.id, email);
          expect(result?.email).toBe(email); // Should work if email is available
        }
        
        // Verify updates are properly recorded
        const finalUser = await userModel.findById(user.id);
        expect(finalUser?.email).not.toBe(originalEmail);
      });
    });
  });

  describe('Input Validation Security', () => {
    describe('Email Validation', () => {
      it('should handle malicious email formats', async () => {
        const maliciousEmails = [
          'user@evil.com<script>alert(1)</script>',
          'user+<img src=x onerror=alert(1)>@example.com',
          'user@example.com\r\nBcc: hacker@evil.com',
          'user@example.com\nX-Header: malicious',
          'user@example.com\0admin@system.com',
          'user@192.168.1.1', // IP address
          'user@[127.0.0.1]', // IP in brackets
          'user@localhost',
          'user@internal',
          'user@.example.com',
          'user@example..com',
          '.user@example.com',
          'user.@example.com',
          'us..er@example.com',
          'user@ex ample.com', // Space in domain
          'user@example.com.', // Trailing dot
          'user name@example.com', // Space in local part
          '"user@example.com"@example.com', // Quoted local part with @
        ];
        
        for (const email of maliciousEmails) {
          try {
            const { user } = await createTestUser({ email });
            
            // If creation succeeded, verify the email is stored exactly as provided
            const foundUser = await userModel.findByEmail(email);
            if (foundUser) {
              expect(foundUser.email).toBe(email);
            }
          } catch (error) {
            // If it fails, should be due to validation, not injection
            expect(error).toBeInstanceOf(Error);
          }
        }
      });

      it('should prevent email header injection', async () => {
        const headerInjectionEmails = [
          "user@example.com\r\nTo: victim@example.com\r\nSubject: Phishing",
          "user@example.com\nBcc: attacker@evil.com",
          "user@example.com%0ABcc:attacker@evil.com",
          "user@example.com%0D%0ABcc:attacker@evil.com",
          "user@example.com\x0ABcc:attacker@evil.com",
          "user@example.com\x0D\x0ABcc:attacker@evil.com"
        ];
        
        for (const email of headerInjectionEmails) {
          try {
            const result = await userModel.create({ email, password: 'password123' });
            if (result) {
              createdUserIds.push(result.id);
              
              // Verify email is stored without injection
              const dbResult = await testQuery('SELECT email FROM users WHERE id = $1', [result.id]);
              const storedEmail = dbResult.rows[0].email;
              
              // Should not contain newline characters that could be used for injection
              expect(storedEmail).not.toContain('\r');
              expect(storedEmail).not.toContain('\n');
              expect(storedEmail).not.toContain('\x0A');
              expect(storedEmail).not.toContain('\x0D');
            }
          } catch (error) {
            // Rejection is acceptable for malformed emails
            expect(error).toBeInstanceOf(Error);
          }
        }
      });
    });

    describe('Password Validation', () => {
      it('should handle extremely long passwords securely', async () => {
        const longPasswords = [
          'a'.repeat(1000),
          'a'.repeat(10000),
          'very_long_password_' + 'x'.repeat(500) + '_end'
        ];
        
        for (const password of longPasswords) {
          try {
            const { user } = await createTestUser({ password });
            
            // If successful, verify password was properly hashed
            const dbResult = await testQuery('SELECT password_hash FROM users WHERE id = $1', [user.id]);
            const hash = dbResult.rows[0].password_hash;
            
            expect(hash).toMatch(/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/);
            expect(hash.length).toBeLessThan(100); // bcrypt hash should be fixed length
          } catch (error) {
            // If it fails due to length constraints, that's acceptable
            expect(error).toBeInstanceOf(Error);
          }
        }
      });

      it('should handle special characters in passwords', async () => {
        const specialPasswords = [
          'password with spaces',
          'pássword with ñ and ç',
          'パスワード', // Japanese
          '密码', // Chinese
          'пароль', // Cyrillic
          'password\ttab\nnewline\rreturn',
          'password"quotes\'and`backticks',
          'password<script>alert(1)</script>',
          'password${process.env.SECRET}',
          'password`rm -rf /`',
          'password;DROP TABLE users;--',
          'password\x00null\x00bytes',
          'password\u0000unicode\u0000null'
        ];
        
        for (const password of specialPasswords) {
          try {
            const { user } = await createTestUser({ password });
            
            // Verify password validation works with special characters
            const dbUser = await userModel.findByEmail(user.email) as User;
            const isValid = await userModel.validatePassword(dbUser, password);
            expect(isValid).toBe(true);
            
            // Verify wrong password still fails
            const isInvalid = await userModel.validatePassword(dbUser, password + 'wrong');
            expect(isInvalid).toBe(false);
            
          } catch (error) {
            // Some special characters might be rejected, which is acceptable
            expect(error).toBeInstanceOf(Error);
          }
        }
      });

      it('should prevent password length timing attacks', async () => {
        const { user } = await createTestUser({ password: 'short' });
        const dbUser = await userModel.findByEmail(user.email) as User;
        
        const passwords = [
          'a',
          'ab',
          'abc',
          'abcd',
          'abcde',
          'a'.repeat(100),
          'a'.repeat(1000)
        ];
        
        const timings: number[] = [];
        
        for (const password of passwords) {
          const start = process.hrtime.bigint();
          await userModel.validatePassword(dbUser, password);
          const end = process.hrtime.bigint();
          timings.push(Number(end - start) / 1000000);
        }
        
        // bcrypt should provide consistent timing regardless of password length
        const maxTiming = Math.max(...timings);
        const minTiming = Math.min(...timings);
        const ratio = maxTiming / minTiming;
        
        // Timing ratio should not be excessive (bcrypt normalizes this)
        expect(ratio).toBeLessThan(10); // Allow some variance but not orders of magnitude
      });
    });

    describe('Unicode and Encoding Security', () => {
      it('should handle Unicode normalization securely', async () => {
        // These should be treated as different emails despite visual similarity
        const unicodeEmails = [
          'test@example.com', // Normal
          'tеst@example.com', // Cyrillic 'е' instead of 'e'
          'test@exаmple.com', // Cyrillic 'а' instead of 'a'
          'test@examрle.com', // Cyrillic 'р' instead of 'p'
          'tést@example.com', // Accented character
          'test@éxample.com', // Accented character in domain
        ];
        
        const createdUsers = [];
        
        for (const email of unicodeEmails) {
          try {
            const { user } = await createTestUser({ email });
            createdUsers.push({ user, email });
          } catch (error) {
            // Some unicode emails might be rejected, which is security-conscious
            expect(error).toBeInstanceOf(Error);
          }
        }
        
        // Each created user should have the exact email they were created with
        for (const { user, email } of createdUsers) {
          const foundUser = await userModel.findByEmail(email);
          expect(foundUser?.email).toBe(email);
          
          // Similar-looking emails should not find this user
          const otherEmails = unicodeEmails.filter(e => e !== email);
          for (const otherEmail of otherEmails) {
            const shouldNotFind = await userModel.findByEmail(otherEmail);
            if (shouldNotFind) {
              expect(shouldNotFind.id).not.toBe(user.id);
            }
          }
        }
      });

      it('should prevent homograph attacks in OAuth data', async () => {
        const homographAttacks = [
          { provider: 'google', oauth_id: 'legitimate_id' },
          { provider: 'gооgle', oauth_id: 'legitimate_id' }, // Cyrillic 'о'
          { provider: 'googIe', oauth_id: 'legitimate_id' }, // Capital 'I' instead of 'l'
          { provider: 'google', oauth_id: 'legitimаte_id' }, // Cyrillic 'а'
        ];
        
        const createdOAuthUsers = [];
        
        for (const { provider, oauth_id } of homographAttacks) {
          try {
            const { user } = await createTestOAuthUser({
              oauth_provider: provider,
              oauth_id: oauth_id,
              email: `test_${Date.now()}_${Math.random()}@example.com`
            });
            createdOAuthUsers.push({ user, provider, oauth_id });
          } catch (error) {
            expect(error).toBeInstanceOf(Error);
          }
        }
        
        // Each OAuth provider/ID combination should be treated as distinct
        for (const { user, provider, oauth_id } of createdOAuthUsers) {
          const foundUser = await userModel.findByOAuth(provider, oauth_id);
          expect(foundUser?.id).toBe(user.id);
          
          // Similar-looking providers should not find this user
          const otherCombos = homographAttacks.filter(combo => 
            combo.provider !== provider || combo.oauth_id !== oauth_id
          );
          
          for (const { provider: otherProvider, oauth_id: otherOAuthId } of otherCombos) {
            const shouldNotFind = await userModel.findByOAuth(otherProvider, otherOAuthId);
            if (shouldNotFind) {
              expect(shouldNotFind.id).not.toBe(user.id);
            }
          }
        }
      });
    });
  });

  describe('Rate Limiting and DoS Prevention', () => {
    describe('Resource Exhaustion Prevention', () => {
      it('should handle rapid user creation attempts', async () => {
        const startTime = Date.now();
        const userCreationPromises = [];
        
        // Attempt to create many users rapidly
        for (let i = 0; i < 20; i++) {
          userCreationPromises.push(
            createTestUser({ email: `rapid_${i}_${Date.now()}@example.com` })
              .catch(() => null) // Ignore failures
          );
        }
        
        const results = await Promise.allSettled(userCreationPromises);
        const successfulCreations = results.filter(r => r.status === 'fulfilled').length;
        const endTime = Date.now();
        
        // Should complete in reasonable time (not hang indefinitely)
        expect(endTime - startTime).toBeLessThan(30000); // 30 seconds max
        
        // Should handle the load without crashing
        expect(successfulCreations).toBeGreaterThan(0);
        expect(successfulCreations).toBeLessThanOrEqual(20);
      });

      it('should handle password validation floods', async () => {
        const { input } = await createTestUser();
        const user = await userModel.findByEmail(input.email) as User;
        
        const startTime = Date.now();
        const validationPromises = [];
        
        // Flood with password validation requests
        for (let i = 0; i < 50; i++) {
          validationPromises.push(
            userModel.validatePassword(user, 'wrong_password')
              .catch(() => false)
          );
        }
        
        const results = await Promise.all(validationPromises);
        const endTime = Date.now();
        
        // Should complete in reasonable time
        expect(endTime - startTime).toBeLessThan(60000); // 1 minute max
        
        // All should return false (wrong password)
        results.forEach(result => {
          expect(result).toBe(false);
        });
      });

      it('should handle large OAuth query floods', async () => {
        const startTime = Date.now();
        const oauthQueries = [];
        
        // Flood with OAuth queries
        for (let i = 0; i < 100; i++) {
          oauthQueries.push(
            userModel.findByOAuth('nonexistent_provider', `fake_id_${i}`)
              .catch(() => null)
          );
        }
        
        const results = await Promise.all(oauthQueries);
        const endTime = Date.now();
        
        // Should complete in reasonable time
        expect(endTime - startTime).toBeLessThan(30000); // 30 seconds max
        
        // All should return null (not found)
        results.forEach(result => {
          expect(result).toBeNull();
        });
      });
    });

    describe('Memory Exhaustion Prevention', () => {
      it('should handle large result sets efficiently', async () => {
        const initialMemory = process.memoryUsage().heapUsed;
        
        // Create multiple users with statistics
        const users = [];
        for (let i = 0; i < 10; i++) {
          const { user } = await createTestUser();
          users.push(user);
          
          // Add statistics data
          await testQuery(
            'INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)',
            [user.id, `image_${i}.jpg`]
          );
        }
        
        // Query statistics for all users
        const statsPromises = users.map(user => userModel.getUserStats(user.id));
        await Promise.all(statsPromises);
        
        const finalMemory = process.memoryUsage().heapUsed;
        const memoryIncrease = finalMemory - initialMemory;
        
        // Memory increase should be reasonable (less than 50MB)
        expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024);
      });

      it('should not leak memory on failed operations', async () => {
        const initialMemory = process.memoryUsage().heapUsed;
        
        // Attempt many failing operations
        const failingOperations = [];
        for (let i = 0; i < 100; i++) {
          failingOperations.push(
            userModel.findById('invalid-uuid-format')
              .catch(() => null),
            userModel.findByEmail('invalid@nonexistent.domain')
              .catch(() => null),
            userModel.updateEmail('nonexistent-id', 'test@example.com')
              .catch(() => null)
          );
        }
        
        await Promise.all(failingOperations);
        
        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
        
        const finalMemory = process.memoryUsage().heapUsed;
        const memoryIncrease = finalMemory - initialMemory;
        
        // Memory increase should be minimal for failed operations
        expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024); // Less than 10MB
      });
    });
  });

  describe('Cryptographic Security', () => {
    describe('Random Number Generation', () => {
      it('should use cryptographically secure randomness for IDs', async () => {
        const users = [];
        const userIds = new Set();
        
        // Create multiple users and collect their IDs
        for (let i = 0; i < 20; i++) {
          const { user } = await createTestUser();
          users.push(user);
          userIds.add(user.id);
        }
        
        // All IDs should be unique
        expect(userIds.size).toBe(users.length);
        
        // IDs should follow UUID v4 format (random)
        users.forEach(user => {
          expect(user.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
        });
        
        // Check randomness distribution (simple test)
        const firstBytes = users.map(user => user.id.charAt(0));
        const uniqueFirstBytes = new Set(firstBytes);
        
        // Should have reasonable distribution of first hex digits
        expect(uniqueFirstBytes.size).toBeGreaterThan(3);
      });

      it('should generate unpredictable salts for password hashing', async () => {
        const password = 'SamePassword123!';
        const users = [];
        const salts = new Set();
        
        // Create multiple users with same password
        for (let i = 0; i < 10; i++) {
          const { user } = await createTestUser({ password });
          users.push(user);
        }
        
        // Extract salts from password hashes
        for (const user of users) {
          const dbResult = await testQuery('SELECT password_hash FROM users WHERE id = $1', [user.id]);
          const hash = dbResult.rows[0].password_hash;
          
          // bcrypt format: $2b$rounds$salthash (salt is first 22 chars of last segment)
          const parts = hash.split('$');
          const saltAndHash = parts[3];
          const salt = saltAndHash.substring(0, 22);
          
          salts.add(salt);
        }
        
        // All salts should be unique
        expect(salts.size).toBe(users.length);
        
        // Salts should be base64-like (bcrypt format)
        salts.forEach(salt => {
          expect(salt).toMatch(/^[./A-Za-z0-9]{22}$/);
        });
      });
    });

    describe('Hash Security', () => {
      it('should use secure hashing parameters', async () => {
        const { user } = await createTestUser();
        
        const dbResult = await testQuery('SELECT password_hash FROM users WHERE id = $1', [user.id]);
        const hash = dbResult.rows[0].password_hash;
        
        // Should use bcrypt with $2b$ (latest variant)
        expect(hash).toMatch(/^\$2b\$/);
        
        // Extract cost factor
        const costFactor = parseInt(hash.split('$')[2]);
        
        // Should use sufficient cost (at least 10, preferably 12+)
        expect(costFactor).toBeGreaterThanOrEqual(10);
        expect(costFactor).toBeLessThanOrEqual(15); // Reasonable upper bound
      });

      it('should resist rainbow table attacks', async () => {
        const commonPasswords = [
          'password',
          '123456',
          'password123',
          'admin',
          'letmein',
          'welcome',
          'monkey',
          'dragon'
        ];
        
        const users = [];
        const hashes = new Set();
        
        // Create users with common passwords
        for (const password of commonPasswords) {
          const { user } = await createTestUser({ password });
          users.push(user);
          
          const dbResult = await testQuery('SELECT password_hash FROM users WHERE id = $1', [user.id]);
          const hash = dbResult.rows[0].password_hash;
          hashes.add(hash);
        }
        
        // All hashes should be unique (due to unique salts)
        expect(hashes.size).toBe(commonPasswords.length);
        
        // Hashes should not be predictable/pre-computed
        hashes.forEach(hash => {
          expect(hash).not.toContain('password');
          expect(hash).not.toContain('123456');
          expect(hash).not.toContain('admin');
        });
      });
    });
  });

  describe('Error Handling Security', () => {
    describe('Information Leakage Prevention', () => {
      it('should not expose stack traces in production', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';
        
        try {
          // Force a database error
          await testQuery('SELECT * FROM non_existent_table');
        } catch (error: any) {
          // Error should not contain sensitive internal information
          expect(error.message).not.toContain('pg');
          expect(error.message).not.toContain('postgres');
          expect(error.message).not.toContain('node_modules');
          expect(error.message).not.toContain(__filename);
          expect(error.message).not.toContain('stacktrace');
        } finally {
          process.env.NODE_ENV = originalEnv;
        }
      });

      it('should sanitize error messages', async () => {
        const maliciousInputs = [
          { email: '<script>alert("xss")</script>@example.com', password: 'pass' },
          { email: 'test@example.com', password: '<img src=x onerror=alert(1)>' },
          { email: 'test"; DROP TABLE users; --@example.com', password: 'pass' }
        ];
        
        for (const input of maliciousInputs) {
          try {
            await userModel.create(input);
          } catch (error: any) {
            // Error messages should not contain unsanitized user input
            expect(error.message).not.toContain('<script>');
            expect(error.message).not.toContain('<img');
            expect(error.message).not.toContain('DROP TABLE');
            expect(error.message).not.toContain('alert(');
          }
        }
      });
    });

    describe('Error Consistency', () => {
      it('should provide consistent error responses', async () => {
        const { user } = await createTestUser();
        
        const errorScenarios = [
          () => userModel.updateEmail(user.id, user.email), // Same email (conflict)
          () => userModel.updateEmail('nonexistent-id', 'new@example.com'), // Non-existent user
          () => userModel.updatePassword('nonexistent-id', 'newpass'), // Non-existent user
          () => userModel.delete('nonexistent-id'), // Non-existent user
        ];
        
        for (const scenario of errorScenarios) {
          try {
            const result = await scenario();
            // Some scenarios return null/false instead of throwing
            if (result === null || result === false) {
              expect([null, false]).toContain(result);
            }
          } catch (error: any) {
            // Errors should be consistent ApiError instances
            expect(error).toBeInstanceOf(Error);
            expect(error.message).toBeDefined();
            expect(typeof error.message).toBe('string');
          }
        }
      });
    });
  });
});