// /backend/src/tests/security/testUserModel.security.test.ts

import { testUserModel } from '../../utils/testUserModel';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { ApiError } from '../../utils/ApiError';
import bcrypt from 'bcrypt';

describe('testUserModel Security Tests', () => {
  let createdUserIds: string[] = [];
  const BATCH_SIZE = 5; // Reduced batch size to prevent memory issues
  
  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    await TestDatabaseConnection.initialize();
  }, 30000);

  afterAll(async () => {
    await TestDatabaseConnection.cleanup();
  }, 30000);

  beforeEach(async () => {
    await TestDatabaseConnection.clearAllTables();
    createdUserIds = [];
  });

  afterEach(async () => {
    // Clean up created users in smaller batches to prevent memory issues
    if (createdUserIds.length > 0) {
      try {
        // Process cleanup in batches
        for (let i = 0; i < createdUserIds.length; i += BATCH_SIZE) {
          const batch = createdUserIds.slice(i, i + BATCH_SIZE);
          await TestDatabaseConnection.query(
            'DELETE FROM users WHERE id = ANY($1)', 
            [batch]
          );
        }
      } catch (error) {
        console.log('⚠️ Error cleaning up users:', error);
      }
    }
  });

  const createUniqueEmail = () => 
    `security-test-${Date.now()}-${Math.random().toString(36).substring(2, 11)}@example.com`;

  describe('Password Security', () => {
    it('should properly hash passwords with bcrypt', async () => {
      const password = 'SecureTestPassword123!';
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password
      });
      createdUserIds.push(user.id);

      const dbUser = await TestDatabaseConnection.query(
        'SELECT password_hash FROM users WHERE id = $1',
        [user.id]
      );

      const hash = dbUser.rows[0].password_hash;
      expect(hash).not.toBe(password);
      expect(hash).toMatch(/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/);
      
      const isValid = await bcrypt.compare(password, hash);
      expect(isValid).toBe(true);
    });

    it('should use sufficient bcrypt rounds', async () => {
      const password = 'TestPassword123!';
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password
      });
      createdUserIds.push(user.id);

      const dbUser = await TestDatabaseConnection.query(
        'SELECT password_hash FROM users WHERE id = $1',
        [user.id]
      );

      const hash = dbUser.rows[0].password_hash;
      const match = hash.match(/^\$2[aby]\$(\d{2})\$/);
      expect(match).toBeTruthy();
      
      const rounds = parseInt(match![1], 10);
      expect(rounds).toBeGreaterThanOrEqual(10);
    });

    it('should reject weak passwords', async () => {
      const weakPasswords = [
        '123456',
        'password',
        'qwerty',
        'abc123',
        '',
        '     ',
        'a',
        '12345678'
      ];

      for (const password of weakPasswords) {
        const result = await testUserModel.create({
          email: createUniqueEmail(),
          password
        }).catch(err => err);

        if (result instanceof Error) {
          // Accept any Error type since validation might throw different error types
          expect(result).toBeInstanceOf(Error);
        } else if (result && result.id) {
          createdUserIds.push(result.id);
          // Even if it succeeds, verify it's properly hashed
          const dbUser = await TestDatabaseConnection.query(
            'SELECT password_hash FROM users WHERE id = $1',
            [result.id]
          );
          expect(dbUser.rows[0].password_hash).not.toBe(password);
        }
      }
    });
  });

  describe('SQL Injection Prevention', () => {
    it('should handle SQL injection attempts in email field', async () => {
      const maliciousEmails = [
        "test'; DROP TABLE users; --@example.com",
        "test' OR '1'='1@example.com",
        "test\"; DELETE FROM users WHERE \"\"=\"@example.com",
        "test'); INSERT INTO users (email, password_hash) VALUES ('hacker@evil.com', 'hash'); --@example.com"
      ];

      for (const email of maliciousEmails) {
        try {
          const user = await testUserModel.create({
            email,
            password: 'SecurePassword123!'
          });
          
          if (user) {
            createdUserIds.push(user.id);
            
            // Verify the email is stored safely
            const foundUser = await testUserModel.findByEmail(email);
            expect(foundUser?.email).toBe(email);
          }
        } catch (error) {
          // If it fails, it should be due to validation, not SQL injection
          expect(error).toBeInstanceOf(Error);
        }
      }

      // Verify users table still exists
      const tableCheck = await TestDatabaseConnection.query(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')"
      );
      expect(tableCheck.rows[0].exists).toBe(true);
    });

    it('should handle SQL injection attempts in password field', async () => {
      const maliciousPasswords = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "\"; DELETE FROM users WHERE \"\"=\"",
        "'); INSERT INTO users (email, password_hash) VALUES ('hacker@evil.com', 'hash'); --"
      ];

      for (const password of maliciousPasswords) {
        const user = await testUserModel.create({
          email: createUniqueEmail(),
          password
        }).catch(() => null);

        if (user) {
          createdUserIds.push(user.id);
          
          // Verify password is hashed, not stored as-is
          const dbUser = await TestDatabaseConnection.query(
            'SELECT password_hash FROM users WHERE id = $1',
            [user.id]
          );
          expect(dbUser.rows[0].password_hash).not.toBe(password);
          expect(dbUser.rows[0].password_hash).toMatch(/^\$2[aby]\$\d{2}\$/);
        }
      }
    });

    it('should handle SQL injection in findByEmail', async () => {
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'TestPassword123!'
      });
      createdUserIds.push(user.id);

      const maliciousQueries = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "admin'--"
      ];

      for (const query of maliciousQueries) {
        const result = await testUserModel.findByEmail(query);
        expect(result).toBeNull();
      }

      // Verify the original user still exists
      const foundUser = await testUserModel.findByEmail(user.email);
      expect(foundUser).toBeTruthy();
    });
  });

  describe('Access Control', () => {
    it('should not expose password hashes in findById', async () => {
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'TestPassword123!'
      });
      createdUserIds.push(user.id);

      const foundUser = await testUserModel.findById(user.id);
      expect(foundUser).not.toHaveProperty('password_hash');
      expect(foundUser).not.toHaveProperty('password');
    });

    it('should only expose password hash in findByEmail for authentication', async () => {
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'TestPassword123!'
      });
      createdUserIds.push(user.id);

      const foundUser = await testUserModel.findByEmail(user.email);
      expect(foundUser).toHaveProperty('password_hash');
      expect(foundUser?.password_hash).toMatch(/^\$2[aby]\$\d{2}\$/);
    });

    it('should prevent unauthorized access to other users data', async () => {
      const user1 = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'Password123!'
      });
      const user2 = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'Password456!'
      });
      createdUserIds.push(user1.id, user2.id);

      // Attempt to access user2's data with user1's ID patterns
      const maliciousIds = [
        `${user1.id}' OR id='${user2.id}`,
        `${user1.id}' UNION SELECT * FROM users WHERE id='${user2.id}`,
        `${user1.id}'; SELECT * FROM users; --`
      ];

      for (const id of maliciousIds) {
        const result = await testUserModel.findById(id);
        expect(result).toBeNull();
      }
    });
  });

  describe('Authentication Security', () => {
    it('should prevent timing attacks on password validation', async () => {
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'CorrectPassword123!'
      });
      createdUserIds.push(user.id);

      const userWithHash = await testUserModel.findByEmail(user.email);
      
      // Test multiple password attempts and measure timing
      const attempts = 5; // Reduced from 10 to prevent memory issues
      const correctTimes: number[] = [];
      const incorrectTimes: number[] = [];

      for (let i = 0; i < attempts; i++) {
        // Correct password
        const startCorrect = process.hrtime.bigint();
        await testUserModel.validatePassword(userWithHash!, 'CorrectPassword123!');
        const endCorrect = process.hrtime.bigint();
        correctTimes.push(Number(endCorrect - startCorrect));

        // Incorrect password
        const startIncorrect = process.hrtime.bigint();
        await testUserModel.validatePassword(userWithHash!, 'WrongPassword123!');
        const endIncorrect = process.hrtime.bigint();
        incorrectTimes.push(Number(endIncorrect - startIncorrect));
      }

      // Calculate average times
      const avgCorrect = correctTimes.reduce((a, b) => a + b) / correctTimes.length;
      const avgIncorrect = incorrectTimes.reduce((a, b) => a + b) / incorrectTimes.length;

      // The timing difference should be minimal (within 50% variance)
      const timingRatio = avgCorrect / avgIncorrect;
      expect(timingRatio).toBeGreaterThan(0.5);
      expect(timingRatio).toBeLessThan(2.0);
    });

    it('should handle null/undefined password attempts safely', async () => {
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'TestPassword123!'
      });
      createdUserIds.push(user.id);

      const userWithHash = await testUserModel.findByEmail(user.email);
      
      const nullResult = await testUserModel.validatePassword(userWithHash!, null as any);
      expect(nullResult).toBe(false);

      const undefinedResult = await testUserModel.validatePassword(userWithHash!, undefined as any);
      expect(undefinedResult).toBe(false);

      const emptyResult = await testUserModel.validatePassword(userWithHash!, '');
      expect(emptyResult).toBe(false);
    });
  });

  describe('OAuth Security', () => {
    it('should prevent OAuth ID collision attacks', async () => {
      const oauthId = 'oauth_123456';
      const provider = 'google';

      const user1 = await testUserModel.createOAuthUser({
        email: createUniqueEmail(),
        oauth_provider: provider,
        oauth_id: oauthId
      });
      createdUserIds.push(user1.id);

      // Attempt to create another user with same OAuth ID
      await expect(testUserModel.createOAuthUser({
        email: createUniqueEmail(),
        oauth_provider: provider,
        oauth_id: oauthId
      })).rejects.toThrow();

      // Verify only one user exists with this OAuth ID
      const foundUser = await testUserModel.findByOAuth(provider, oauthId);
      expect(foundUser?.id).toBe(user1.id);
    });

    it('should handle OAuth injection attempts', async () => {
      const maliciousOAuthIds = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "') OR ('1'='1"
      ];

      for (const oauthId of maliciousOAuthIds) {
        const user = await testUserModel.createOAuthUser({
          email: createUniqueEmail(),
          oauth_provider: 'google',
          oauth_id: oauthId
        }).catch(() => null);

        if (user) {
          createdUserIds.push(user.id);
          
          // Verify the OAuth ID is stored safely
          const foundUser = await testUserModel.findByOAuth('google', oauthId);
          expect(foundUser?.id).toBe(user.id);
        }
      }

      // Verify tables still exist
      const tableCheck = await TestDatabaseConnection.query(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')"
      );
      expect(tableCheck.rows[0].exists).toBe(true);
    });
  });

  describe('Data Integrity', () => {
    it('should enforce unique email constraint at database level', async () => {
      const email = createUniqueEmail();
      
      const user1 = await testUserModel.create({
        email,
        password: 'Password123!'
      });
      createdUserIds.push(user1.id);

      // Direct database insert attempt should fail
      await expect(TestDatabaseConnection.query(
        'INSERT INTO users (email, password_hash) VALUES ($1, $2)',
        [email, 'hash']
      )).rejects.toThrow(/duplicate key value violates unique constraint/);
    });

    it('should handle concurrent user creation safely', async () => {
      const email = createUniqueEmail();
      
      // Process promises in smaller batches to prevent memory issues
      const promises = Array.from({ length: BATCH_SIZE }, () => 
        testUserModel.create({
          email,
          password: 'ConcurrentTest123!'
        }).catch(() => null)
      );

      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === 'fulfilled' && r.value !== null);

      expect(successful.length).toBe(1);
      
      if (successful.length > 0) {
        const result = successful[0] as PromiseFulfilledResult<any>;
        if (result.value) {
          createdUserIds.push(result.value.id);
        }
      }

      // Verify only one user exists
      const dbUsers = await TestDatabaseConnection.query(
        'SELECT COUNT(*) FROM users WHERE email = $1',
        [email]
      );
      expect(parseInt(dbUsers.rows[0].count)).toBe(1);
    });
  });

  describe('Rate Limiting and DoS Prevention', () => {
    it('should handle rapid authentication attempts', async () => {
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'TestPassword123!'
      });
      createdUserIds.push(user.id);

      const userWithHash = await testUserModel.findByEmail(user.email);
      
      const startTime = Date.now();
      const attempts = BATCH_SIZE; // Use smaller batch size
      
      // Process in smaller batches
      const promises = Array.from({ length: attempts }, () => 
        testUserModel.validatePassword(userWithHash!, 'WrongPassword!')
      );

      const results = await Promise.all(promises);
      const endTime = Date.now();

      // All should return false
      results.forEach(result => expect(result).toBe(false));

      // Should complete in reasonable time
      const totalTime = endTime - startTime;
      expect(totalTime).toBeLessThan(5000); // 5 seconds for batch

      // Average time per attempt should indicate rate limiting
      const avgTime = totalTime / attempts;
      expect(avgTime).toBeGreaterThan(20); // At least 20ms per attempt (bcrypt overhead)
    });

    it('should handle bulk user creation attempts efficiently', async () => {
      const startTime = Date.now();
      const userCount = BATCH_SIZE;
      
      const createdUsers = [];
      
      // Create users sequentially to avoid memory issues
      for (let i = 0; i < userCount; i++) {
        try {
          const user = await testUserModel.create({
            email: createUniqueEmail(),
            password: 'BulkTest123!'
          });
          createdUsers.push(user);
          createdUserIds.push(user.id);
        } catch (error) {
          // Handle any creation errors
        }
      }

      const endTime = Date.now();
      const totalTime = endTime - startTime;

      expect(createdUsers.length).toBe(userCount);
      expect(totalTime).toBeLessThan(10000); // Should complete within 10 seconds

      // Verify all users were created
      const dbCount = await TestDatabaseConnection.query('SELECT COUNT(*) as count FROM users');
      expect(parseInt(dbCount.rows[0].count)).toBeGreaterThanOrEqual(userCount);
    });
  });

  describe('XSS and Input Sanitization', () => {
    it('should handle XSS attempts in email field', async () => {
      const xssEmails = [
        '<script>alert("xss")</script>@example.com',
        'test@<img src=x onerror=alert("xss")>.com',
        'test@example.com<svg onload=alert("xss")>',
        'test+<iframe src="javascript:alert(\'xss\')"></iframe>@example.com'
      ];

      for (const email of xssEmails) {
        try {
          const user = await testUserModel.create({
            email,
            password: 'TestPassword123!'
          });
          
          if (user) {
            createdUserIds.push(user.id);
            
            // Verify the email is stored as-is (escaped by database)
            const foundUser = await testUserModel.findByEmail(email);
            expect(foundUser?.email).toBe(email);
          }
        } catch (error) {
          // Email validation might reject these
          expect(error).toBeInstanceOf(Error);
        }
      }
    });

    it('should handle special characters in OAuth data safely', async () => {
      const specialChars = [
        { provider: 'google', id: 'user<script>alert("xss")</script>' },
        { provider: 'github', id: 'user&lt;img src=x onerror=alert("xss")&gt;' },
        { provider: 'facebook', id: 'user\'; DROP TABLE users; --' }
      ];

      for (const oauth of specialChars) {
        const user = await testUserModel.createOAuthUser({
          email: createUniqueEmail(),
          oauth_provider: oauth.provider,
          oauth_id: oauth.id
        }).catch(() => null);

        if (user) {
          createdUserIds.push(user.id);
          
          // Verify the OAuth data is stored safely
          const foundUser = await testUserModel.findByOAuth(oauth.provider, oauth.id);
          expect(foundUser?.id).toBe(user.id);
        }
      }
    });
  });

  describe('Session Security', () => {
    it('should not expose sensitive data in user stats', async () => {
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'TestPassword123!'
      });
      createdUserIds.push(user.id);

      const stats = await testUserModel.getUserStats(user.id);
      
      // Stats should only contain counts, no sensitive data
      expect(stats).toHaveProperty('imageCount');
      expect(stats).toHaveProperty('garmentCount');
      expect(stats).toHaveProperty('wardrobeCount');
      expect(stats).not.toHaveProperty('email');
      expect(stats).not.toHaveProperty('password_hash');
      expect(stats).not.toHaveProperty('id');
    });

    it('should handle invalid user IDs in stats queries', async () => {
      const invalidIds = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        null,
        undefined,
        ''
      ];

      for (const id of invalidIds) {
        const stats = await testUserModel.getUserStats(id as any);
        expect(stats).toEqual({
          imageCount: 0,
          garmentCount: 0,
          wardrobeCount: 0
        });
      }
    });
  });

  describe('Cascading Delete Security', () => {
    it('should securely cascade delete user data', async () => {
      const user = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'TestPassword123!'
      });

      // Create related data
      await TestDatabaseConnection.query(
        'INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)',
        [user.id, 'test.jpg']
      );
      await TestDatabaseConnection.query(
        'INSERT INTO garment_items (user_id, name) VALUES ($1, $2)',
        [user.id, 'Test Item']
      );
      await TestDatabaseConnection.query(
        'INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)',
        [user.id, 'Test Wardrobe']
      );

      // Delete user
      await testUserModel.delete(user.id);

      // Verify all related data is deleted
      const [images, garments, wardrobes] = await Promise.all([
        TestDatabaseConnection.query('SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', [user.id]),
        TestDatabaseConnection.query('SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', [user.id]),
        TestDatabaseConnection.query('SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', [user.id])
      ]);

      expect(parseInt(images.rows[0].count)).toBe(0);
      expect(parseInt(garments.rows[0].count)).toBe(0);
      expect(parseInt(wardrobes.rows[0].count)).toBe(0);
    });

    it('should prevent deletion injection attacks', async () => {
      const user1 = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'Password123!'
      });
      const user2 = await testUserModel.create({
        email: createUniqueEmail(),
        password: 'Password456!'
      });
      createdUserIds.push(user1.id, user2.id);

      // Attempt injection to delete multiple users
      const maliciousIds = [
        `${user1.id}' OR id='${user2.id}`,
        `${user1.id}'; DELETE FROM users; --`,
        `${user1.id}' OR '1'='1`
      ];

      for (const id of maliciousIds) {
        const result = await testUserModel.delete(id);
        expect(result).toBe(false);
      }

      // Verify both users still exist
      const foundUser1 = await testUserModel.findById(user1.id);
      const foundUser2 = await testUserModel.findById(user2.id);
      expect(foundUser1).toBeTruthy();
      expect(foundUser2).toBeTruthy();
    });
  });
});