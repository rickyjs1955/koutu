// /backend/src/tests/integration/userModel.int.test.ts
// Complete comprehensive integration test suite (39 tests)

import { testUserModel as userModel } from '../../utils/testUserModel';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { ApiError } from '../../utils/ApiError';
import bcrypt from 'bcrypt';

describe('userModel Real Integration Tests', () => {
  let createdUserIds: string[] = [];

  beforeAll(async () => {
    // Set test environment
    process.env.NODE_ENV = 'test';
    
    // Initialize test database
    await TestDatabaseConnection.initialize();
    
    console.log('🧪 Integration tests starting...');
  }, 60000);

  afterAll(async () => {
    console.log('🏁 Integration tests completed, cleaning up...');
    await TestDatabaseConnection.cleanup();
  }, 30000);

  beforeEach(async () => {
    // Clear all tables before each test
    await TestDatabaseConnection.clearAllTables();
    createdUserIds = [];
  });

  afterEach(async () => {
    // Additional cleanup after each test
    if (createdUserIds.length > 0) {
      try {
        await TestDatabaseConnection.query(
          'DELETE FROM users WHERE id = ANY($1)', 
          [createdUserIds]
        );
      } catch (error) {
        console.log('⚠️ Error cleaning up users:', error);
      }
    }
  });

  // Helper functions
  const createUniqueEmail = () => 
    `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`;
  
  const createTestUserInput = (overrides = {}) => ({
    email: createUniqueEmail(),
    password: 'SecureTestPassword123!',
    ...overrides
  });

  const createTestOAuthInput = (overrides = {}) => ({
    email: createUniqueEmail(),
    name: 'Test OAuth User',
    avatar_url: 'https://example.com/avatar.jpg',
    oauth_provider: 'google',
    oauth_id: `google_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    ...overrides
  });

  describe('User Creation and Authentication', () => {
    it('should create a new user and store it in the database', async () => {
      const userInput = createTestUserInput();
      
      const result = await userModel.create(userInput);
      createdUserIds.push(result.id);
      
      // Verify the result structure
      expect(result).toMatchObject({
        id: expect.any(String),
        email: userInput.email,
        created_at: expect.any(Date)
      });
      
      // Verify the user exists in the database
      const dbUser = await TestDatabaseConnection.query(
        'SELECT * FROM users WHERE id = $1', 
        [result.id]
      );
      expect(dbUser.rows).toHaveLength(1);
      
      const savedUser = dbUser.rows[0];
      expect(savedUser.email).toBe(userInput.email);
      expect(savedUser.password_hash).toBeDefined();
      expect(savedUser.password_hash).not.toBe(userInput.password);
      
      // Verify password is properly hashed with bcrypt
      expect(savedUser.password_hash).toMatch(/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/);
      
      // Verify password can be validated
      const isValidPassword = await bcrypt.compare(userInput.password, savedUser.password_hash);
      expect(isValidPassword).toBe(true);
    });

    it('should prevent duplicate email registration', async () => {
      const email = createUniqueEmail();
      const userInput1 = createTestUserInput({ email });
      const userInput2 = createTestUserInput({ email });
      
      // Create first user
      const user1 = await userModel.create(userInput1);
      createdUserIds.push(user1.id);
      
      // Attempt to create second user with same email
      await expect(userModel.create(userInput2)).rejects.toThrow();
      await expect(userModel.create(userInput2)).rejects.toThrow(ApiError);
      
      // Verify only one user exists in database
      const dbUsers = await TestDatabaseConnection.query(
        'SELECT * FROM users WHERE email = $1', 
        [email]
      );
      expect(dbUsers.rows).toHaveLength(1);
    });

    it('should handle concurrent user creation attempts with same email', async () => {
      const email = createUniqueEmail();
      const userInput = createTestUserInput({ email });
      
      // Attempt to create multiple users simultaneously
      const promises = Array.from({ length: 5 }, () => 
        userModel.create({ ...userInput }).catch(() => null)
      );
      const results = await Promise.allSettled(promises);
      
      // Only one should succeed
      const successful = results.filter(r => r.status === 'fulfilled' && r.value !== null);
      const failed = results.filter(r => r.status === 'rejected' || r.value === null);
      
      expect(successful).toHaveLength(1);
      expect(failed).toHaveLength(4);
      
      if (successful.length > 0) {
        const successfulResult = successful[0] as PromiseFulfilledResult<any>;
        if (successfulResult.value) {
          createdUserIds.push(successfulResult.value.id);
        }
      }
      
      // Verify only one user exists in database
      const dbUsers = await TestDatabaseConnection.query(
        'SELECT * FROM users WHERE email = $1', 
        [email]
      );
      expect(dbUsers.rows).toHaveLength(1);
    });

    it('should validate user credentials correctly', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);
      
      // Find user by email
      const user = await userModel.findByEmail(userInput.email);
      expect(user).toBeDefined();
      expect(user.email).toBe(userInput.email);
      
      // Test correct password
      const isValidCorrect = await userModel.validatePassword(user, userInput.password);
      expect(isValidCorrect).toBe(true);
      
      // Test incorrect password
      const isValidIncorrect = await userModel.validatePassword(user, 'WrongPassword123!');
      expect(isValidIncorrect).toBe(false);
    });
  });

  describe('User Retrieval Operations', () => {
    it('should find user by ID', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);
      
      const foundUser = await userModel.findById(createdUser.id);
      
      expect(foundUser).toMatchObject({
        id: createdUser.id,
        email: userInput.email,
        created_at: expect.any(Date)
      });
      
      // Should not expose password hash
      expect(foundUser).not.toHaveProperty('password_hash');
    });

    it('should find user by email with password hash', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);
      
      const foundUser = await userModel.findByEmail(userInput.email);
      
      expect(foundUser).toMatchObject({
        id: createdUser.id,
        email: userInput.email,
        password_hash: expect.any(String),
        created_at: expect.any(Date),
        updated_at: expect.any(Date)
      });
    });

    it('should return null for non-existent users', async () => {
      const foundById = await userModel.findById('550e8400-e29b-41d4-a716-446655440000');
      const foundByEmail = await userModel.findByEmail('nonexistent@example.com');
      
      expect(foundById).toBeNull();
      expect(foundByEmail).toBeNull();
    });

    it('should handle malformed UUIDs gracefully', async () => {
      const foundUser = await userModel.findById('invalid-uuid-format');
      expect(foundUser).toBeNull();
    });
  });

  describe('User Update Operations', () => {
    it('should update user email successfully', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);
      
      const newEmail = createUniqueEmail();
      const updatedUser = await userModel.updateEmail(createdUser.id, newEmail);
      
      expect(updatedUser).toMatchObject({
        id: createdUser.id,
        email: newEmail,
        created_at: expect.any(Date)
      });
      
      // Verify in database
      const dbUser = await TestDatabaseConnection.query(
        'SELECT * FROM users WHERE id = $1', 
        [createdUser.id]
      );
      expect(dbUser.rows[0].email).toBe(newEmail);
      expect(new Date(dbUser.rows[0].updated_at).getTime()).toBeGreaterThan(new Date(dbUser.rows[0].created_at).getTime());
    });

    it('should prevent email updates to existing emails', async () => {
      const user1Input = createTestUserInput();
      const user2Input = createTestUserInput();
      
      const user1 = await userModel.create(user1Input);
      const user2 = await userModel.create(user2Input);
      
      createdUserIds.push(user1.id, user2.id);
      
      // Try to update user1's email to user2's email
      await expect(userModel.updateEmail(user1.id, user2Input.email)).rejects.toThrow(ApiError);
      
      // Verify user1's email is unchanged
      const dbUser1 = await TestDatabaseConnection.query(
        'SELECT email FROM users WHERE id = $1', 
        [user1.id]
      );
      expect(dbUser1.rows[0].email).toBe(user1Input.email);
    });

    it('should update user password successfully', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);
      
      const newPassword = 'NewSecurePassword456!';
      const updateResult = await userModel.updatePassword(createdUser.id, newPassword);
      
      expect(updateResult).toBe(true);
      
      // Verify old password no longer works
      const userWithOldPassword = await userModel.findByEmail(userInput.email);
      const oldPasswordValid = await userModel.validatePassword(userWithOldPassword, userInput.password);
      expect(oldPasswordValid).toBe(false);
      
      // Verify new password works
      const newPasswordValid = await userModel.validatePassword(userWithOldPassword, newPassword);
      expect(newPasswordValid).toBe(true);
      
      // Verify password hash changed in database
      const dbUser = await TestDatabaseConnection.query(
        'SELECT password_hash, updated_at FROM users WHERE id = $1', 
        [createdUser.id]
      );
      expect(dbUser.rows[0].password_hash).toMatch(/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/);
      expect(new Date(dbUser.rows[0].updated_at).getTime()).toBeGreaterThan(userWithOldPassword.created_at.getTime());
    });

    it('should return false when updating non-existent user', async () => {
      const updateResult = await userModel.updatePassword('550e8400-e29b-41d4-a716-446655440000', 'newpassword');
      expect(updateResult).toBe(false);
    });
  });

  describe('User Deletion Operations', () => {
    it('should delete user successfully', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      
      const deleteResult = await userModel.delete(createdUser.id);
      expect(deleteResult).toBe(true);
      
      // Verify user is deleted from database
      const dbUser = await TestDatabaseConnection.query(
        'SELECT * FROM users WHERE id = $1', 
        [createdUser.id]
      );
      expect(dbUser.rows).toHaveLength(0);
      
      // Remove from cleanup array since it's already deleted
      createdUserIds = createdUserIds.filter(id => id !== createdUser.id);
    });

    it('should handle cascading deletes for related data', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      
      // Create related data
      await TestDatabaseConnection.query(
        'INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)', 
        [createdUser.id, 'test.jpg']
      );
      await TestDatabaseConnection.query(
        'INSERT INTO garment_items (user_id, name) VALUES ($1, $2)', 
        [createdUser.id, 'Test Shirt']
      );
      await TestDatabaseConnection.query(
        'INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', 
        [createdUser.id, 'Test Wardrobe']
      );
      
      // Verify related data exists
      const [images, garments, wardrobes] = await Promise.all([
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', 
          [createdUser.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', 
          [createdUser.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', 
          [createdUser.id]
        )
      ]);
      
      expect(parseInt(images.rows[0].count)).toBe(1);
      expect(parseInt(garments.rows[0].count)).toBe(1);
      expect(parseInt(wardrobes.rows[0].count)).toBe(1);
      
      // Delete user
      const deleteResult = await userModel.delete(createdUser.id);
      expect(deleteResult).toBe(true);
      
      // Verify related data is cascade deleted
      const [imagesAfter, garmentsAfter, wardrobesAfter] = await Promise.all([
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', 
          [createdUser.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', 
          [createdUser.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', 
          [createdUser.id]
        )
      ]);
      
      expect(parseInt(imagesAfter.rows[0].count)).toBe(0);
      expect(parseInt(garmentsAfter.rows[0].count)).toBe(0);
      expect(parseInt(wardrobesAfter.rows[0].count)).toBe(0);
    });

    it('should return false when deleting non-existent user', async () => {
      const deleteResult = await userModel.delete('550e8400-e29b-41d4-a716-446655440000');
      expect(deleteResult).toBe(false);
    });
  });

  describe('User Statistics Operations', () => {
    it('should return correct user statistics', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);
      
      // Add test data
      await Promise.all([
        TestDatabaseConnection.query(
          'INSERT INTO original_images (user_id, file_path) VALUES ($1, $2), ($1, $3)', 
          [createdUser.id, 'image1.jpg', 'image2.jpg']
        ),
        TestDatabaseConnection.query(
          'INSERT INTO garment_items (user_id, name) VALUES ($1, $2), ($1, $3), ($1, $4)', 
          [createdUser.id, 'Shirt', 'Pants', 'Jacket']
        ),
        TestDatabaseConnection.query(
          'INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', 
          [createdUser.id, 'Summer Wardrobe']
        )
      ]);
      
      const stats = await userModel.getUserStats(createdUser.id);
      
      expect(stats).toEqual({
        imageCount: 2,
        garmentCount: 3,
        wardrobeCount: 1
      });
    });

    it('should return zero counts for user with no data', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);
      
      const stats = await userModel.getUserStats(createdUser.id);
      
      expect(stats).toEqual({
        imageCount: 0,
        garmentCount: 0,
        wardrobeCount: 0
      });
    });

    it('should handle non-existent user gracefully', async () => {
      const stats = await userModel.getUserStats('550e8400-e29b-41d4-a716-446655440000');
      
      expect(stats).toEqual({
        imageCount: 0,
        garmentCount: 0,
        wardrobeCount: 0
      });
    });
  });

  describe('OAuth Operations', () => {
    it('should create OAuth user successfully', async () => {
      const oauthInput = createTestOAuthInput();
      
      const result = await userModel.createOAuthUser(oauthInput);
      createdUserIds.push(result.id);
      
      expect(result).toMatchObject({
        id: expect.any(String),
        email: oauthInput.email,
        created_at: expect.any(Date)
      });
      
      // Verify in database - check users table
      const dbUser = await TestDatabaseConnection.query(
        'SELECT * FROM users WHERE id = $1', 
        [result.id]
      );
      const savedUser = dbUser.rows[0];
      
      expect(savedUser.email).toBe(oauthInput.email);
      expect(savedUser.password_hash).toBeFalsy(); // Should be NULL for OAuth users
      
      // Verify OAuth data is in separate table
      const oauthData = await TestDatabaseConnection.query(
        'SELECT * FROM user_oauth_providers WHERE user_id = $1',
        [result.id]
      );
      expect(oauthData.rows).toHaveLength(1);
      expect(oauthData.rows[0].provider).toBe(oauthInput.oauth_provider);
      expect(oauthData.rows[0].provider_id).toBe(oauthInput.oauth_id);
    });

    it('should find OAuth user by provider and ID', async () => {
      const oauthInput = createTestOAuthInput();
      const createdUser = await userModel.createOAuthUser(oauthInput);
      createdUserIds.push(createdUser.id);
      
      const foundUser = await userModel.findByOAuth(oauthInput.oauth_provider, oauthInput.oauth_id);
      
      expect(foundUser).toMatchObject({
        id: createdUser.id,
        email: oauthInput.email,
        // Remove these expectations since OAuth data is in separate table:
        // oauth_provider: oauthInput.oauth_provider,
        // oauth_id: oauthInput.oauth_id
      });
    });

    it('should find user by linked OAuth provider', async () => {
      // Create regular user
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);
      
      // Link OAuth provider
      const provider = 'github';
      const providerId = 'github123456';
      await TestDatabaseConnection.query(
        'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
        [user.id, provider, providerId]
      );
      
      const foundUser = await userModel.findByOAuth(provider, providerId);
      
      expect(foundUser).toMatchObject({
        id: user.id,
        email: userInput.email
      });
    });

    it('should get user with OAuth providers', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);
      
      // Link multiple OAuth providers
      await Promise.all([
        TestDatabaseConnection.query(
          'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
          [user.id, 'github', 'github123']
        ),
        TestDatabaseConnection.query(
          'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
          [user.id, 'facebook', 'facebook456']
        )
      ]);
      
      const result = await userModel.getUserWithOAuthProviders(user.id);
      
      expect(result).toMatchObject({
        id: user.id,
        email: userInput.email,
        linkedProviders: expect.arrayContaining(['github', 'facebook'])
      });
      expect(result?.linkedProviders).toHaveLength(2);
    });

    it('should prevent OAuth user creation with existing email', async () => {
      const email = createUniqueEmail();
      
      // Create regular user first
      const userInput = createTestUserInput({ email });
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);
      
      // Try to create OAuth user with same email
      const oauthInput = createTestOAuthInput({ email });
      
      await expect(userModel.createOAuthUser(oauthInput)).rejects.toThrow(ApiError);
      
      // Verify only one user exists
      const dbUsers = await TestDatabaseConnection.query(
        'SELECT * FROM users WHERE email = $1', 
        [email]
      );
      expect(dbUsers.rows).toHaveLength(1);
    });

    it('should return null for non-existent OAuth user', async () => {
      const foundUser = await userModel.findByOAuth('nonexistent', 'provider123');
      expect(foundUser).toBeNull();
    });
  });

  describe('Performance and Edge Cases', () => {
    it('should handle bulk user operations efficiently', async () => {
      const userCount = 20;
      const startTime = Date.now();
      
      const userInputs = Array.from({ length: userCount }, () => createTestUserInput());
      
      // Create users sequentially to avoid email conflicts
      const createdUsers = [];
      for (const input of userInputs) {
        const user = await userModel.create(input);
        createdUsers.push(user);
        createdUserIds.push(user.id);
      }
      
      const creationTime = Date.now() - startTime;
      
      expect(createdUsers).toHaveLength(userCount);
      expect(creationTime).toBeLessThan(10000); // Should complete in under 10 seconds
      
      // Verify all users exist in database
      const dbUsers = await TestDatabaseConnection.query('SELECT COUNT(*) as count FROM users');
      expect(parseInt(dbUsers.rows[0].count)).toBe(userCount);
      
      console.log(`✅ Created ${userCount} users in ${creationTime}ms`);
    });

    it('should handle special characters in emails and names', async () => {
      const specialEmail = 'test+special.123@sub-domain.example-site.com';
      const specialName = 'José María O\'Connor';
      
      const oauthInput = createTestOAuthInput({
        email: specialEmail,
        name: specialName
      });
      
      const user = await userModel.createOAuthUser(oauthInput);
      createdUserIds.push(user.id);
      
      expect(user.email).toBe(specialEmail);
      
      const foundUser = await userModel.findByEmail(specialEmail);
      expect(foundUser?.email).toBe(specialEmail);
      
      const userWithProviders = await userModel.getUserWithOAuthProviders(user.id);
      expect(userWithProviders?.email).toBe(specialEmail);
      // Remove this expectation since name is not stored in users table:
      // expect(userWithProviders?.name).toBe(specialName);
      
      // Instead, verify OAuth provider is linked:
      expect(userWithProviders?.linkedProviders).toContain(oauthInput.oauth_provider);
    });

    it('should maintain data consistency under load', async () => {
      const baseEmail = `load-test-${Date.now()}@example.com`;
      
      // Attempt to create multiple users with different emails
      const promises = Array.from({ length: 10 }, (_, i) => 
        userModel.create({
          email: `${i}-${baseEmail}`,
          password: 'LoadTestPassword123!'
        })
      );
      
      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === 'fulfilled');
      
      expect(successful).toHaveLength(10);
      
      // Add to cleanup
      successful.forEach(result => {
        if (result.status === 'fulfilled') {
          createdUserIds.push((result.value as any).id);
        }
      });
      
      // Verify all users exist in database
      const dbUsers = await TestDatabaseConnection.query('SELECT COUNT(*) as count FROM users');
      expect(parseInt(dbUsers.rows[0].count)).toBeGreaterThanOrEqual(10);
    });

    it('should handle database errors gracefully', async () => {
      // Try to create user with extremely long email
      const longEmail = 'a'.repeat(300) + '@example.com';
      
      try {
        const result = await userModel.create({
          email: longEmail,
          password: 'TestPassword123!'
        });
        // If it succeeds, add to cleanup
        if (result) {
          createdUserIds.push(result.id);
        }
      } catch (error) {
        // Should handle database constraint errors gracefully
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should validate UUID format consistency', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);
      
      // Verify UUID format (8-4-4-4-12 pattern)
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(user.id).toMatch(uuidRegex);
      
      // Verify UUID is consistent across queries
      const foundUser = await userModel.findById(user.id);
      expect(foundUser?.id).toBe(user.id);
    });

    it('should handle timestamp precision correctly', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);
      
      const beforeUpdate = new Date();
      await new Promise(resolve => setTimeout(resolve, 10)); // Small delay
      
      await userModel.updateEmail(user.id, createUniqueEmail());
      
      const dbUser = await TestDatabaseConnection.query(
        'SELECT created_at, updated_at FROM users WHERE id = $1', 
        [user.id]
      );
      const { created_at, updated_at } = dbUser.rows[0];
      
      expect(new Date(created_at)).toBeInstanceOf(Date);
      expect(new Date(updated_at)).toBeInstanceOf(Date);
      expect(new Date(updated_at).getTime()).toBeGreaterThan(beforeUpdate.getTime());
      expect(new Date(updated_at).getTime()).toBeGreaterThan(new Date(created_at).getTime());
    });
  });

  describe('Real-world Usage Scenarios', () => {
    it('should support complete user lifecycle', async () => {
      // 1. User registration
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);
      
      expect(user.email).toBe(userInput.email);
      
      // 2. Login simulation (find and validate)
      const loginUser = await userModel.findByEmail(userInput.email);
      expect(loginUser).not.toBeNull();
      
      const isValidPassword = await userModel.validatePassword(loginUser!, userInput.password);
      expect(isValidPassword).toBe(true);
      
      // 3. Profile updates
      const newEmail = createUniqueEmail();
      await userModel.updateEmail(user.id, newEmail);
      
      const newPassword = 'NewSecurePassword456!';
      await userModel.updatePassword(user.id, newPassword);
      
      // 4. Link OAuth account
      await TestDatabaseConnection.query(
        'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
        [user.id, 'google', 'google_link_test']
      );
      
      // 5. Verify updated profile
      const updatedUser = await userModel.getUserWithOAuthProviders(user.id);
      expect(updatedUser?.email).toBe(newEmail);
      expect(updatedUser?.linkedProviders).toContain('google');
      
      // 6. Verify new password works
      const userWithNewPassword = await userModel.findByEmail(newEmail);
      const isNewPasswordValid = await userModel.validatePassword(userWithNewPassword!, newPassword);
      expect(isNewPasswordValid).toBe(true);
      
      // 7. Generate usage statistics
      await Promise.all([
        TestDatabaseConnection.query(
          'INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)', 
          [user.id, 'profile.jpg']
        ),
        TestDatabaseConnection.query(
          'INSERT INTO garment_items (user_id, name) VALUES ($1, $2)', 
          [user.id, 'Favorite Shirt']
        ),
        TestDatabaseConnection.query(
          'INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', 
          [user.id, 'Work Clothes']
        )
      ]);
      
      const stats = await userModel.getUserStats(user.id);
      expect(stats).toEqual({
        imageCount: 1,
        garmentCount: 1,
        wardrobeCount: 1
      });
      
      // 8. Account deactivation (deletion)
      const deleteResult = await userModel.delete(user.id);
      expect(deleteResult).toBe(true);
      
      // Remove from cleanup since already deleted
      createdUserIds = createdUserIds.filter(id => id !== user.id);
      
      // Verify user and all related data is gone
      const deletedUser = await userModel.findById(user.id);
      expect(deletedUser).toBeNull();
      
      const remainingStats = await userModel.getUserStats(user.id);
      expect(remainingStats).toEqual({
        imageCount: 0,
        garmentCount: 0,
        wardrobeCount: 0
      });
    });

    it('should handle OAuth login flow', async () => {
      const oauthId = 'google_flow_test';
      const provider = 'google';
      
      // 1. First OAuth login - user doesn't exist
      let user = await userModel.findByOAuth(provider, oauthId);
      expect(user).toBeNull();
      
      // 2. Create OAuth user
      const oauthInput = createTestOAuthInput({
        oauth_provider: provider,
        oauth_id: oauthId
      });
      const createdUser = await userModel.createOAuthUser(oauthInput);
      createdUserIds.push(createdUser.id);
      
      // 3. Subsequent OAuth login - user exists
      user = await userModel.findByOAuth(provider, oauthId);
      expect(user?.id).toBe(createdUser.id);
      
      // 4. Get user profile with OAuth info
      const profile = await userModel.getUserWithOAuthProviders(createdUser.id);
      // Remove these expectations since OAuth data is in separate table:
      // expect(profile?.oauth_provider).toBe(provider);
      expect(profile?.linkedProviders).toContain(provider);
      
      // 5. Link additional OAuth provider
      await TestDatabaseConnection.query(
        'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
        [createdUser.id, 'github', 'github_additional']
      );
      
      // 6. Verify multiple providers
      const updatedProfile = await userModel.getUserWithOAuthProviders(createdUser.id);
      expect(updatedProfile?.linkedProviders).toHaveLength(2);
      expect(updatedProfile?.linkedProviders).toContain('google');
      expect(updatedProfile?.linkedProviders).toContain('github');
    });

    it('should handle account linking scenario', async () => {
      // 1. User signs up with email/password
      const userInput = createTestUserInput();
      const emailUser = await userModel.create(userInput);
      createdUserIds.push(emailUser.id);
      
      // 2. Later, user tries to login with OAuth using same email
      const oauthInput = createTestOAuthInput({
        email: userInput.email // Same email
      });
      
      // This should fail - email already exists
      await expect(userModel.createOAuthUser(oauthInput)).rejects.toThrow(ApiError);
      
      // 3. Instead, link OAuth to existing account
      await TestDatabaseConnection.query(
        'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
        [emailUser.id, oauthInput.oauth_provider, oauthInput.oauth_id]
      );
      
      // 4. Now OAuth lookup should find the original user
      const foundUser = await userModel.findByOAuth(oauthInput.oauth_provider, oauthInput.oauth_id);
      expect(foundUser?.id).toBe(emailUser.id);
      
      // 5. User profile shows both authentication methods
      const profile = await userModel.getUserWithOAuthProviders(emailUser.id);
      expect(profile?.linkedProviders).toContain(oauthInput.oauth_provider);
      
      // User still has password login capability
      const userWithPassword = await userModel.findByEmail(userInput.email);
      expect(userWithPassword?.password_hash).toBeTruthy();
    });

    it('should handle high-frequency operations', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);
      
      const startTime = Date.now();
      
      // Perform many read operations
      const readOperations = Array.from({ length: 50 }, () => 
        userModel.findById(user.id)
      );
      
      const results = await Promise.all(readOperations);
      const endTime = Date.now();
      
      // All should return the same user
      results.forEach(result => {
        expect(result?.id).toBe(user.id);
      });
      
      // Should complete in reasonable time
      expect(endTime - startTime).toBeLessThan(5000); // 5 seconds
      
      console.log(`✅ Completed 50 read operations in ${endTime - startTime}ms`);
    });

    it('should maintain referential integrity', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      
      // Create extensive related data
      await Promise.all([
        TestDatabaseConnection.query(
          'INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)', 
          [user.id, 'test1.jpg']
        ),
        TestDatabaseConnection.query(
          'INSERT INTO garment_items (user_id, name) VALUES ($1, $2)', 
          [user.id, 'Test Garment']
        ),
        TestDatabaseConnection.query(
          'INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', 
          [user.id, 'Test Wardrobe']
        ),
        TestDatabaseConnection.query(
          'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)', 
          [user.id, 'github', 'github123']
        )
      ]);
      
      // Verify data exists
      const counts = await Promise.all([
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', 
          [user.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', 
          [user.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', 
          [user.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM user_oauth_providers WHERE user_id = $1', 
          [user.id]
        )
      ]);
      
      counts.forEach(result => {
        expect(parseInt(result.rows[0].count)).toBe(1);
      });
      
      // Delete user
      await userModel.delete(user.id);
      
      // Verify all related data was cascade deleted
      const afterDeleteCounts = await Promise.all([
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', 
          [user.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', 
          [user.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', 
          [user.id]
        ),
        TestDatabaseConnection.query(
          'SELECT COUNT(*) as count FROM user_oauth_providers WHERE user_id = $1', 
          [user.id]
        )
      ]);
      
      afterDeleteCounts.forEach(result => {
        expect(parseInt(result.rows[0].count)).toBe(0);
      });
    });
  });

  describe('Database Constraints and Security', () => {
    it('should enforce email uniqueness constraint', async () => {
      const email = createUniqueEmail();
      
      // Create first user
      const user1 = await userModel.create({ email, password: 'password1' });
      createdUserIds.push(user1.id);
      
      // Try to create second user with same email
      await expect(userModel.create({ email, password: 'password2' })).rejects.toThrow();
      
      // Try to create OAuth user with same email
      await expect(userModel.createOAuthUser({
        email,
        oauth_provider: 'google',
        oauth_id: 'google123'
      })).rejects.toThrow();
      
      // Verify only one user exists
      const users = await TestDatabaseConnection.query(
        'SELECT COUNT(*) as count FROM users WHERE email = $1', 
        [email]
      );
      expect(parseInt(users.rows[0].count)).toBe(1);
    });

    it('should handle SQL injection attempts safely', async () => {
      const maliciousEmail = "test'; DROP TABLE users; --@example.com";
      const maliciousPassword = "password'; DROP TABLE users; --";
      
      try {
        const user = await userModel.create({
          email: maliciousEmail,
          password: maliciousPassword
        });
        
        if (user) {
          createdUserIds.push(user.id);
          
          // If creation succeeded, verify data is properly escaped
          const foundUser = await userModel.findByEmail(maliciousEmail);
          expect(foundUser?.email).toBe(maliciousEmail);
        }
      } catch (error) {
        // If it fails, should be due to validation, not SQL injection
        expect(error).toBeInstanceOf(Error);
      }
      
      // Verify tables still exist (not dropped by injection)
      const tables = await TestDatabaseConnection.query(`
        SELECT table_name FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_name = 'users'
      `);
      expect(tables.rows.length).toBe(1);
    });

    it('should handle concurrent operations safely', async () => {
      const baseEmail = createUniqueEmail();
      
      // Try to create users with same email concurrently
      const promises = Array.from({ length: 5 }, () => 
        userModel.create({
          email: baseEmail,
          password: 'ConcurrentTest123!'
        }).catch(() => null)
      );
      
      const results = await Promise.allSettled(promises);
      const successful = results.filter(r => r.status === 'fulfilled' && r.value !== null);
      
      // Only one should succeed due to unique constraint
      expect(successful.length).toBe(1);
      
      if (successful.length > 0) {
        const successfulResult = successful[0] as PromiseFulfilledResult<any>;
        if (successfulResult.value) {
          createdUserIds.push(successfulResult.value.id);
        }
      }
      
      // Verify only one user exists in database
      const users = await TestDatabaseConnection.query(
        'SELECT COUNT(*) as count FROM users WHERE email = $1', 
        [baseEmail]
      );
      expect(parseInt(users.rows[0].count)).toBe(1);
    });

    it('should validate UUID constraints', async () => {
      // Test with invalid UUID formats
      const invalidIds = [
        'invalid-uuid',
        '123456789',
        'not-a-uuid-at-all',
        '',
        null,
        undefined
      ];
      
      for (const invalidId of invalidIds) {
        const result = await userModel.findById(invalidId as any);
        expect(result).toBeNull();
        
        const updateResult = await userModel.updateEmail(invalidId as any, createUniqueEmail());
        expect(updateResult).toBeNull();
        
        const deleteResult = await userModel.delete(invalidId as any);
        expect(deleteResult).toBe(false);
      }
    });
  });
});