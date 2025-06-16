// /backend/src/services/__tests__/authService.integration.test.ts

import { authService } from '../../services/authService';
import { setupTestDatabase, cleanupTestData, teardownTestDatabase } from '../../utils/testSetup';
import { ApiError } from '../../utils/ApiError';
import jwt from 'jsonwebtoken';
import { config } from '../../config';

// Helper to generate unique emails - SAME AS SECURITY TESTS
const generateUniqueEmail = (prefix: string = 'test') => {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(7);
  return `${prefix}-${timestamp}-${random}@example.com`;
};

describe('authService Integration Tests', () => {
  beforeAll(async () => {
    await setupTestDatabase();
  });

  beforeEach(async () => {
    await cleanupTestData();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  describe('complete authentication flow', () => {
    it('should handle complete user registration and login flow', async () => {
      const testUser = {
        email: generateUniqueEmail('integration'),
        password: 'TestPass123!'
      };

      // Step 1: Register user
      const registerResult = await authService.register(testUser);
      
      expect(registerResult.user.email).toBe(testUser.email);
      expect(registerResult.token).toBeDefined();
      expect(typeof registerResult.token).toBe('string');
      
      // Verify token can be decoded
      const decodedToken = jwt.verify(registerResult.token, config.jwtSecret) as any;
      expect(decodedToken.id).toBe(registerResult.user.id);
      expect(decodedToken.email).toBe(testUser.email);

      // Step 2: Login with same credentials
      const loginResult = await authService.login(testUser);
      
      expect(loginResult.user.email).toBe(testUser.email);
      expect(loginResult.user.id).toBe(registerResult.user.id);
      expect(loginResult.token).toBeDefined();

      // Step 3: Validate token
      const tokenValidation = await authService.validateToken(loginResult.token);
      
      expect(tokenValidation.isValid).toBe(true);
      expect(tokenValidation.user?.id).toBe(registerResult.user.id);

      // Step 4: Get user profile
      const profile = await authService.getUserProfile(registerResult.user.id);
      
      expect(profile.id).toBe(registerResult.user.id);
      expect(profile.email).toBe(testUser.email);
    });

    it('should prevent duplicate email registration', async () => {
      const testUser = {
        email: generateUniqueEmail('duplicate'),
        password: 'TestPass123!'
      };

      // Register first user
      await authService.register(testUser);

      // Attempt to register with same email
      await expect(
        authService.register(testUser)
      ).rejects.toThrow(ApiError);
    });

    it('should maintain authentication state across operations', async () => {
      const testUser = {
        email: generateUniqueEmail('state'),
        password: 'TestPass123!'
      };

      // Register user
      const { user, token } = await authService.register(testUser);

      // Validate initial token
      let validation = await authService.validateToken(token);
      expect(validation.isValid).toBe(true);

      // Get auth stats
      const stats = await authService.getUserAuthStats(user.id);
      expect(stats.hasPassword).toBe(true);
      expect(stats.linkedProviders).toEqual([]);

      // Update password
      const updateResult = await authService.updatePassword({
        userId: user.id,
        currentPassword: testUser.password,
        newPassword: 'NewPassword123!'
      });
      expect(updateResult.success).toBe(true);

      // Original token should still be valid (password change doesn't invalidate tokens)
      validation = await authService.validateToken(token);
      expect(validation.isValid).toBe(true);

      // Login with new password should work
      const newLoginResult = await authService.login({
        email: testUser.email,
        password: 'NewPassword123!'
      });
      expect(newLoginResult.user.id).toBe(user.id);

      // Login with old password should fail
      await expect(
        authService.login(testUser)
      ).rejects.toThrow(ApiError);
    });
  });

  describe('email management', () => {
    it('should handle email updates correctly', async () => {
      const testUser = {
        email: generateUniqueEmail('emailtest'),
        password: 'TestPass123!'
      };

      // Register user
      const { user } = await authService.register(testUser);

      // Update email
      const newEmail = generateUniqueEmail('newemail');
      const updatedUser = await authService.updateEmail({
        userId: user.id,
        newEmail,
        password: testUser.password
      });

      expect(updatedUser.email).toBe(newEmail);

      // Verify login works with new email
      const loginResult = await authService.login({
        email: newEmail,
        password: testUser.password
      });
      expect(loginResult.user.id).toBe(user.id);

      // Verify login fails with old email
      await expect(
        authService.login(testUser)
      ).rejects.toThrow(ApiError);
    });

    it('should prevent email conflicts', async () => {
      // Register two users
      const user1 = { email: generateUniqueEmail('user1'), password: 'Pass123!' };
      const user2 = { email: generateUniqueEmail('user2'), password: 'Pass123!' };

      const { user: registeredUser1 } = await authService.register(user1);
      const { user: registeredUser2 } = await authService.register(user2);

      // Try to update user2's email to user1's email
      await expect(
        authService.updateEmail({
          userId: registeredUser2.id,
          newEmail: user1.email,
          password: user2.password
        })
      ).rejects.toThrow(ApiError);
    });
  });

  describe('token lifecycle', () => {
    it('should handle token expiration properly', async () => {
      // Create an already expired token manually (same approach as security tests)
      const expiredPayload = {
        id: 'test-user-id',
        email: generateUniqueEmail('expired'),
        exp: Math.floor(Date.now() / 1000) - 3600 // Expired 1 hour ago
      };

      const expiredToken = jwt.sign(expiredPayload, config.jwtSecret);
      
      // Token should be expired
      const validation = await authService.validateToken(expiredToken);
      expect(validation.isValid).toBe(false);
      expect(validation.error).toContain('expired');
    });

    it('should reject invalid token formats', async () => {
      const invalidTokens = [
        'invalid-token',
        'not.a.jwt',
        '',
        'Bearer token',
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature'
      ];

      for (const token of invalidTokens) {
        const validation = await authService.validateToken(token);
        expect(validation.isValid).toBe(false);
      }
    });
  });

  describe('account management', () => {
    it('should provide comprehensive authentication statistics', async () => {
      const testUser = {
        email: generateUniqueEmail('accounttest'),
        password: 'TestPass123!'
      };

      // Register user
      const { user } = await authService.register(testUser);

      // Get initial stats
      const stats = await authService.getUserAuthStats(user.id);
      
      expect(stats).toMatchObject({
        userId: user.id,
        email: testUser.email,
        hasPassword: true,
        linkedProviders: [],
        authenticationMethods: {
          password: true,
          oauth: false
        }
      });
      expect(stats.accountCreated).toBeInstanceOf(Date);
    });

    it('should handle account deactivation workflow', async () => {
      const testUser = {
        email: generateUniqueEmail('deactivation'),
        password: 'TestPass123!'
      };

      // Register user
      const { user } = await authService.register(testUser);

      // Verify user exists
      const profile = await authService.getUserProfile(user.id);
      expect(profile.id).toBe(user.id);

      // Deactivate account
      const deactivationResult = await authService.deactivateAccount(
        user.id,
        testUser.password
      );
      expect(deactivationResult.success).toBe(true);

      // Verify user no longer exists
      await expect(
        authService.getUserProfile(user.id)
      ).rejects.toThrow(ApiError);

      // Verify login no longer works
      await expect(
        authService.login(testUser)
      ).rejects.toThrow(ApiError);
    });
  });

  describe('security validations', () => {
    it('should enforce password complexity in real scenarios', async () => {
      const weakPasswords = [
        { email: generateUniqueEmail('weak1'), password: '123456' },
        { email: generateUniqueEmail('weak2'), password: 'password' },
        { email: generateUniqueEmail('weak3'), password: 'Password' },
        { email: generateUniqueEmail('weak4'), password: 'PASSWORD123' }
      ];

      for (const credentials of weakPasswords) {
        await expect(
          authService.register(credentials)
        ).rejects.toThrow(ApiError);
      }
    });

    it('should enforce email format validations', async () => {
      const invalidEmails = [
        'notanemail',
        '@invalid.com',
        'user@',
        'user..name@domain.com',
        'user@domain..com'
      ];

      for (const email of invalidEmails) {
        await expect(
          authService.register({ email, password: 'ValidPass123!' })
        ).rejects.toThrow(ApiError);
      }
    });

    it('should block disposable email domains', async () => {
      const disposableEmails = [
        'test@10minutemail.com',
        'test@tempmail.org',
        'test@guerrillamail.com',
        'test@mailinator.com'
      ];

      for (const email of disposableEmails) {
        await expect(
          authService.register({ email, password: 'ValidPass123!' })
        ).rejects.toThrow(ApiError);
      }
    });

    it('should handle case-insensitive email operations', async () => {
      const baseEmail = generateUniqueEmail('CaseTest');
      const normalizedEmail = baseEmail.toLowerCase();

      // Register with mixed case
      const { user } = await authService.register({
        email: baseEmail,
        password: 'TestPass123!'
      });

      // User should be stored with normalized email
      expect(user.email).toBe(normalizedEmail);

      // Login should work with any case variation
      const loginVariations = [
        baseEmail.toLowerCase(),
        baseEmail.toUpperCase(),
        baseEmail.charAt(0).toUpperCase() + baseEmail.slice(1).toLowerCase()
      ];

      for (const emailVariation of loginVariations) {
        const loginResult = await authService.login({
          email: emailVariation,
          password: 'TestPass123!'
        });
        expect(loginResult.user.id).toBe(user.id);
      }
    });
  });

  describe('error handling and edge cases', () => {
    it('should handle database connection issues gracefully', async () => {
      // This would require mocking database connection failures
      // For now, we test that the service properly wraps database errors
      await expect(
        authService.getUserProfile('non-existent-uuid')
      ).rejects.toThrow(ApiError);
    });

    it('should handle malformed user IDs', async () => {
      const invalidUserIds = [
        'not-a-uuid',
        '123',
        '',
        'null',
        'undefined'
      ];

      for (const userId of invalidUserIds) {
        // These should either throw validation errors or not-found errors
        try {
          await authService.getUserProfile(userId);
          // If it doesn't throw, that's unexpected for invalid UUIDs
          fail(`Expected error for invalid user ID: ${userId}`);
        } catch (error) {
          expect(error).toBeInstanceOf(ApiError);
        }
      }
    });

    it('should handle concurrent registration attempts', async () => {
      const email = generateUniqueEmail('concurrent');
      const password = 'TestPass123!';

      // Attempt concurrent registrations with same email
      const registrationPromises = Array(3).fill(null).map(() =>
        authService.register({ email, password })
      );

      const results = await Promise.allSettled(registrationPromises);
      
      // Only one should succeed
      const successful = results.filter(r => r.status === 'fulfilled');
      const failed = results.filter(r => r.status === 'rejected');

      expect(successful).toHaveLength(1);
      expect(failed).toHaveLength(2);

      // Failed attempts should be due to conflict errors
      failed.forEach(result => {
        if (result.status === 'rejected') {
          expect(result.reason).toBeInstanceOf(Error);
        }
      });
    });

    it('should handle password update edge cases', async () => {
      const testUser = {
        email: generateUniqueEmail('passwordupdate'),
        password: 'OriginalPass123!'
      };

      const { user } = await authService.register(testUser);

      // Test password update with wrong current password
      await expect(
        authService.updatePassword({
          userId: user.id,
          currentPassword: 'WrongPassword!',
          newPassword: 'NewPass123!'
        })
      ).rejects.toThrow(ApiError);

      // Test password update with same password
      await expect(
        authService.updatePassword({
          userId: user.id,
          currentPassword: 'OriginalPass123!',
          newPassword: 'OriginalPass123!'
        })
      ).rejects.toThrow(ApiError);
    });
  });

  describe('performance and scalability', () => {
    it('should handle multiple users efficiently', async () => {
      const startTime = Date.now();
      const userCount = 10;

      // Register multiple users
      const registrationPromises = Array(userCount).fill(null).map((_, index) =>
        authService.register({
          email: generateUniqueEmail(`perfuser${index}`),
          password: 'TestPass123!'
        })
      );

      const registrationResults = await Promise.all(registrationPromises);
      
      // All registrations should succeed
      expect(registrationResults).toHaveLength(userCount);
      registrationResults.forEach(result => {
        expect(result.user.id).toBeDefined();
        expect(result.token).toBeDefined();
      });

      // Login with all users
      const loginPromises = registrationResults.map(result =>
        authService.login({
          email: result.user.email,
          password: 'TestPass123!'
        })
      );

      const loginResults = await Promise.all(loginPromises);
      expect(loginResults).toHaveLength(userCount);

      const endTime = Date.now();
      const totalTime = endTime - startTime;
      
      // Performance assertion - should complete within reasonable time
      expect(totalTime).toBeLessThan(5000); // 5 seconds for 10 users
      
      console.log(`Processed ${userCount} users in ${totalTime}ms`);
    });

    it('should handle token validation at scale', async () => {
      // Register users and collect tokens
      const userCount = 20;
      const tokens: string[] = [];

      for (let i = 0; i < userCount; i++) {
        const { token } = await authService.register({
          email: generateUniqueEmail(`scaleuser${i}`),
          password: 'TestPass123!'
        });
        tokens.push(token);
      }

      const startTime = Date.now();

      // Validate all tokens concurrently
      const validationPromises = tokens.map(token =>
        authService.validateToken(token)
      );

      const validationResults = await Promise.all(validationPromises);
      
      const endTime = Date.now();
      const totalTime = endTime - startTime;

      // All validations should succeed
      validationResults.forEach(result => {
        expect(result.isValid).toBe(true);
        expect(result.user).toBeDefined();
      });

      // Performance assertion
      expect(totalTime).toBeLessThan(2000); // 2 seconds for 20 validations
      
      console.log(`Validated ${userCount} tokens in ${totalTime}ms`);
    });
  });

  describe('data consistency', () => {
    it('should maintain data consistency across operations', async () => {
      const { user: user1 } = await authService.register({
        email: generateUniqueEmail('consistency1'),
        password: 'TestPass123!'
      });

      const { user: user2 } = await authService.register({
        email: generateUniqueEmail('consistency2'),
        password: 'TestPass123!'
      });

      // Get initial stats
      const stats1Initial = await authService.getUserAuthStats(user1.id);
      const stats2Initial = await authService.getUserAuthStats(user2.id);

      expect(stats1Initial.userId).toBe(user1.id);
      expect(stats2Initial.userId).toBe(user2.id);

      // Update user1's password
      await authService.updatePassword({
        userId: user1.id,
        currentPassword: 'TestPass123!',
        newPassword: 'NewPass123!'
      });

      // Update user2's email
      await authService.updateEmail({
        userId: user2.id,
        newEmail: generateUniqueEmail('newconsistency2'),
        password: 'TestPass123!'
      });

      // Verify stats are still consistent
      const stats1Updated = await authService.getUserAuthStats(user1.id);
      const stats2Updated = await authService.getUserAuthStats(user2.id);

      expect(stats1Updated.userId).toBe(user1.id);
      expect(stats1Updated.email).toBe(user1.email); // Email unchanged
      expect(stats1Updated.hasPassword).toBe(true); // Still has password

      expect(stats2Updated.userId).toBe(user2.id);
      expect(stats2Updated.email).toContain('newconsistency2'); // Email updated
      expect(stats2Updated.hasPassword).toBe(true); // Still has password

      // Verify cross-user operations don't interfere
      await expect(
        authService.updatePassword({
          userId: user2.id,
          currentPassword: 'TestPass123!', // User2's original password
          newPassword: 'AnotherPass123!'
        })
      ).resolves.toMatchObject({ success: true });

      // User1 should still be able to login with new password
      const user1Login = await authService.login({
        email: user1.email,
        password: 'NewPass123!'
      });
      expect(user1Login.user.id).toBe(user1.id);

      // User2 should be able to login with updated email and new password
      const user2Login = await authService.login({
        email: stats2Updated.email,
        password: 'AnotherPass123!'
      });
      expect(user2Login.user.id).toBe(user2.id);
    });
  });

  describe('real-world scenarios', () => {
    it('should handle typical user onboarding flow', async () => {
      const userEmail = generateUniqueEmail('onboarding');
      const initialPassword = 'InitialPass123!';

      // Step 1: User registers
      const { user, token } = await authService.register({
        email: userEmail,
        password: initialPassword
      });

      expect(user.email).toBe(userEmail);
      expect(token).toBeDefined();

      // Step 2: User immediately checks their profile
      const profile = await authService.getUserProfile(user.id);
      expect(profile.id).toBe(user.id);

      // Step 3: User checks their auth status
      const initialStats = await authService.getUserAuthStats(user.id);
      expect(initialStats.hasPassword).toBe(true);
      expect(initialStats.linkedProviders).toEqual([]);

      // Step 4: User decides to change password for security
      await authService.updatePassword({
        userId: user.id,
        currentPassword: initialPassword,
        newPassword: 'SecurePass456!'
      });

      // Step 5: User logs out and logs back in with new password
      const loginResult = await authService.login({
        email: userEmail,
        password: 'SecurePass456!'
      });

      expect(loginResult.user.id).toBe(user.id);

      // Step 6: User updates their email
      const newEmail = generateUniqueEmail('newemail');
      const updatedUser = await authService.updateEmail({
        userId: user.id,
        newEmail,
        password: 'SecurePass456!'
      });

      expect(updatedUser.email).toBe(newEmail);

      // Step 7: Verify final state
      const finalStats = await authService.getUserAuthStats(user.id);
      expect(finalStats.email).toBe(newEmail);
      expect(finalStats.hasPassword).toBe(true);

      // Step 8: Final login with new credentials
      const finalLogin = await authService.login({
        email: newEmail,
        password: 'SecurePass456!'
      });

      expect(finalLogin.user.id).toBe(user.id);
      expect(finalLogin.user.email).toBe(newEmail);
    });

    it('should handle account recovery scenario', async () => {
      // Simulate a user who forgot their password and needs to verify identity
      const { user } = await authService.register({
        email: generateUniqueEmail('recovery'),
        password: 'OriginalPass123!'
      });

      // Verify user exists and can be found
      const profile = await authService.getUserProfile(user.id);
      expect(profile.email).toBe(user.email);

      // In a real scenario, this would involve email verification
      // For this test, we'll simulate successful identity verification
      // by showing the user can update their password with current credentials

      const recoveryResult = await authService.updatePassword({
        userId: user.id,
        currentPassword: 'OriginalPass123!',
        newPassword: 'RecoveredPass456!'
      });

      expect(recoveryResult.success).toBe(true);

      // Verify user can login with new password
      const loginResult = await authService.login({
        email: user.email,
        password: 'RecoveredPass456!'
      });

      expect(loginResult.user.id).toBe(user.id);
    });

    it('should handle account migration scenario', async () => {
      // User wants to change from old email to new email
      const oldEmail = generateUniqueEmail('oldaccount');
      const newEmail = generateUniqueEmail('newaccount');

      const { user } = await authService.register({
        email: oldEmail,
        password: 'MigrationPass123!'
      });

      // Update to new email
      const updatedUser = await authService.updateEmail({
        userId: user.id,
        newEmail,
        password: 'MigrationPass123!'
      });

      expect(updatedUser.email).toBe(newEmail);

      // Verify old email no longer works
      await expect(
        authService.login({
          email: oldEmail,
          password: 'MigrationPass123!'
        })
      ).rejects.toThrow(ApiError);

      // Verify new email works
      const loginResult = await authService.login({
        email: newEmail,
        password: 'MigrationPass123!'
      });

      expect(loginResult.user.id).toBe(user.id);
      expect(loginResult.user.email).toBe(newEmail);

      // Verify account data integrity
      const stats = await authService.getUserAuthStats(user.id);
      expect(stats.email).toBe(newEmail);
      expect(stats.userId).toBe(user.id);
    });

    it('should handle security audit scenario', async () => {
      // Create multiple users for audit
      const users = await Promise.all([
        authService.register({ email: generateUniqueEmail('audit1'), password: 'AuditPass123!' }),
        authService.register({ email: generateUniqueEmail('audit2'), password: 'AuditPass123!' }),
        authService.register({ email: generateUniqueEmail('audit3'), password: 'AuditPass123!' })
      ]);

      // Audit each user's authentication status
      for (const { user } of users) {
        const stats = await authService.getUserAuthStats(user.id);
        
        expect(stats).toMatchObject({
          userId: user.id,
          hasPassword: true,
          linkedProviders: [],
          authenticationMethods: {
            password: true,
            oauth: false
          }
        });

        expect(stats.accountCreated).toBeInstanceOf(Date);
        expect(stats.email).toContain('@example.com');
      }

      // Verify all users can authenticate
      const loginResults = await Promise.all(
        users.map(({ user }) =>
          authService.login({
            email: user.email,
            password: 'AuditPass123!'
          })
        )
      );

      expect(loginResults).toHaveLength(3);
      loginResults.forEach((result, index) => {
        expect(result.user.id).toBe(users[index].user.id);
      });
    });
  });

  describe('Enhanced Security Integration', () => {
    describe('Timing Attack Prevention Integration', () => {
      it('should maintain consistent response times in login flow', async () => {
        const validUser = {
          email: generateUniqueEmail('timing'),
          password: 'ValidPass123!'
        };

        // Register a valid user
        await authService.register(validUser);

        const timings: number[] = [];

        // Test login with non-existent user
        for (let i = 0; i < 3; i++) {
          const start = Date.now();
          try {
            await authService.login({
              email: generateUniqueEmail('nonexistent'),
              password: 'SomePassword123!'
            });
          } catch (error) {
            // Expected to fail
          }
          timings.push(Date.now() - start);
        }

        // Test login with valid user but wrong password
        for (let i = 0; i < 3; i++) {
          const start = Date.now();
          try {
            await authService.login({
              email: validUser.email,
              password: 'WrongPassword123!'
            });
          } catch (error) {
            // Expected to fail
          }
          timings.push(Date.now() - start);
        }

        // Check timing consistency
        const avgTime = timings.reduce((a, b) => a + b, 0) / timings.length;
        const maxDeviation = Math.max(...timings.map(t => Math.abs(t - avgTime)));
        
        // Should be reasonably consistent (within 100% of average)
        expect(maxDeviation).toBeLessThan(avgTime);
        
        // All should meet minimum response time
        timings.forEach(timing => {
          expect(timing).toBeGreaterThanOrEqual(95); // Allow 5ms variance from 100ms
        });
      });
    });

    describe('Enhanced Password Validation Integration', () => {
      it('should reject enhanced weak patterns in real registration flow', async () => {
        const enhancedWeakPatterns = [
          'qwerty123!',      // Keyboard pattern
          'AAA12345!',       // Repetitive characters
          'abcdefghijk',     // All letters, long
          '123456789012'     // All numbers, long
        ];

        for (const password of enhancedWeakPatterns) {
          await expect(
            authService.register({
              email: generateUniqueEmail('weakpattern'),
              password
            })
          ).rejects.toThrow(ApiError);
        }
      });

      it('should accept strong passwords in real registration flow', async () => {
        const strongPasswords = [
          'MyStr0ng!P@ssw0rd',
          'C0mplex#Security2024',
          'Un1que$Safe&Sound'
        ];

        for (const password of strongPasswords) {
          const result = await authService.register({
            email: generateUniqueEmail('strongpass'),
            password
          });
          
          expect(result.user.id).toBeDefined();
          expect(result.token).toBeDefined();
        }
      });
    });
  });
});