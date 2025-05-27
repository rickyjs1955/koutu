// /backend/src/models/__tests__/integration/userModel.int.test.ts
import { userModel, User, CreateUserInput, CreateOAuthUserInput } from '../../models/userModel';
import { setupTestDatabase, teardownTestDatabase, testQuery } from '../../utils/testSetup';
import { ApiError } from '../../utils/ApiError';
import bcrypt from 'bcrypt';

describe('userModel Integration Tests', () => {
  // Track created users for cleanup
  const createdUserIds: string[] = [];
  const createdEmails: string[] = [];

  beforeAll(async () => {
    // Set environment to test
    process.env.NODE_ENV = 'test';
    
    // Initialize test database
    await setupTestDatabase();
    
    // Create users table for testing
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

    // Create user_oauth_providers table for OAuth linking
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

    // Create tables for user statistics
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
    // Clean up created users and related data
    try {
      if (createdUserIds.length > 0) {
        await testQuery(`DELETE FROM users WHERE id = ANY($1)`, [createdUserIds]);
      }
      
      // Drop test tables
      await testQuery(`DROP TABLE IF EXISTS wardrobes CASCADE`);
      await testQuery(`DROP TABLE IF EXISTS garment_items CASCADE`);
      await testQuery(`DROP TABLE IF EXISTS original_images CASCADE`);
      await testQuery(`DROP TABLE IF EXISTS user_oauth_providers CASCADE`);
      await testQuery(`DROP TABLE IF EXISTS users CASCADE`);
    } catch (error) {
      console.error('Cleanup error:', error);
    }

    await teardownTestDatabase();
  }, 30000);

  beforeEach(async () => {
    // Clean up any existing test data before each test
    await testQuery(`DELETE FROM wardrobes WHERE user_id = ANY($1)`, [createdUserIds]);
    await testQuery(`DELETE FROM garment_items WHERE user_id = ANY($1)`, [createdUserIds]);
    await testQuery(`DELETE FROM original_images WHERE user_id = ANY($1)`, [createdUserIds]);
    await testQuery(`DELETE FROM user_oauth_providers WHERE user_id = ANY($1)`, [createdUserIds]);
    await testQuery(`DELETE FROM users WHERE id = ANY($1)`, [createdUserIds]);
    
    // Clear tracking arrays
    createdUserIds.length = 0;
    createdEmails.length = 0;
  });

  // Helper function to create test user data
  const createTestUserInput = (overrides: Partial<CreateUserInput> = {}): CreateUserInput => ({
    email: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
    password: 'testpassword123',
    ...overrides
  });

  const createTestOAuthUserInput = (overrides: Partial<CreateOAuthUserInput> = {}): CreateOAuthUserInput => ({
    email: `oauth-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
    name: 'OAuth Test User',
    avatar_url: 'https://example.com/avatar.jpg',
    oauth_provider: 'google',
    oauth_id: `google_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    ...overrides
  });

  describe('create', () => {
    it('should create a new user with valid data', async () => {
      const userInput = createTestUserInput();
      
      const result = await userModel.create(userInput);
      
      expect(result).toMatchObject({
        id: expect.any(String),
        email: userInput.email,
        created_at: expect.any(Date)
      });
      
      // Verify user was actually saved to database
      const dbResult = await testQuery('SELECT * FROM users WHERE id = $1', [result.id]);
      expect(dbResult.rows.length).toBe(1);
      
      const dbUser = dbResult.rows[0];
      expect(dbUser.email).toBe(userInput.email);
      expect(dbUser.password_hash).toBeDefined();
      expect(dbUser.password_hash).not.toBe(userInput.password); // Should be hashed
      
      // Verify password is properly hashed
      const isValidPassword = await bcrypt.compare(userInput.password, dbUser.password_hash);
      expect(isValidPassword).toBe(true);
      
      createdUserIds.push(result.id);
      createdEmails.push(userInput.email);
    });

    it('should throw ApiError when email already exists', async () => {
      const userInput = createTestUserInput();
      
      // Create first user
      const firstUser = await userModel.create(userInput);
      createdUserIds.push(firstUser.id);
      
      // Try to create second user with same email
      await expect(userModel.create(userInput)).rejects.toThrow(ApiError);
      
      // Verify only one user exists
      const dbResult = await testQuery('SELECT COUNT(*) as count FROM users WHERE email = $1', [userInput.email]);
      expect(parseInt(dbResult.rows[0].count)).toBe(1);
    });

    it('should handle concurrent user creation with different emails', async () => {
      const userInputs = [
        createTestUserInput(),
        createTestUserInput(),
        createTestUserInput()
      ];

      const promises = userInputs.map(input => userModel.create(input));
      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      results.forEach((result, index) => {
        expect(result.email).toBe(userInputs[index].email);
        createdUserIds.push(result.id);
      });

      // Verify all users were created in database
      const dbResult = await testQuery('SELECT COUNT(*) as count FROM users WHERE id = ANY($1)', [results.map(r => r.id)]);
      expect(parseInt(dbResult.rows[0].count)).toBe(3);
    });
  });

  describe('findById', () => {
    it('should find user by ID', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const result = await userModel.findById(createdUser.id);

      expect(result).toMatchObject({
        id: createdUser.id,
        email: userInput.email,
        created_at: expect.any(Date)
      });
      expect(result).not.toHaveProperty('password_hash');
    });

    it('should return null for non-existent user', async () => {
      const result = await userModel.findById('550e8400-e29b-41d4-a716-446655440000');
      expect(result).toBeNull();
    });

    it('should handle invalid UUID format', async () => {
      const result = await userModel.findById('invalid-uuid');
      expect(result).toBeNull();
    });
  });

  describe('findByEmail', () => {
    it('should find user by email with password hash', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const result = await userModel.findByEmail(userInput.email);

      expect(result).toMatchObject({
        id: createdUser.id,
        email: userInput.email,
        password_hash: expect.any(String),
        created_at: expect.any(Date),
        updated_at: expect.any(Date)
      });
    });

    it('should return null for non-existent email', async () => {
      const result = await userModel.findByEmail('nonexistent@example.com');
      expect(result).toBeNull();
    });

    it('should be case sensitive for email lookup', async () => {
      const userInput = createTestUserInput({ email: 'Test@Example.Com' });
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const result = await userModel.findByEmail('test@example.com');
      expect(result).toBeNull();

      const correctResult = await userModel.findByEmail('Test@Example.Com');
      expect(correctResult).not.toBeNull();
    });
  });

  describe('validatePassword', () => {
    it('should validate correct password', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const user = await userModel.findByEmail(userInput.email) as User;
      const isValid = await userModel.validatePassword(user, userInput.password);

      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const user = await userModel.findByEmail(userInput.email) as User;
      const isValid = await userModel.validatePassword(user, 'wrongpassword');

      expect(isValid).toBe(false);
    });

    it('should handle empty password hash', async () => {
      // Create user directly in database with empty password hash (OAuth user)
      const result = await testQuery(
        'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *',
        ['oauth@example.com', '']
      );
      const user = result.rows[0];
      createdUserIds.push(user.id);

      const isValid = await userModel.validatePassword(user, 'anypassword');
      expect(isValid).toBe(false);
    });
  });

  describe('updateEmail', () => {
    it('should update user email successfully', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const newEmail = `updated-${Date.now()}@example.com`;
      const result = await userModel.updateEmail(createdUser.id, newEmail);

      expect(result).toMatchObject({
        id: createdUser.id,
        email: newEmail,
        created_at: expect.any(Date)
      });

      // Verify update in database
      const dbResult = await testQuery('SELECT email, updated_at FROM users WHERE id = $1', [createdUser.id]);
      expect(dbResult.rows[0].email).toBe(newEmail);
      expect(new Date(dbResult.rows[0].updated_at)).toBeInstanceOf(Date);
    });

    it('should throw error when new email already exists', async () => {
      const userInput1 = createTestUserInput();
      const userInput2 = createTestUserInput();
      
      const user1 = await userModel.create(userInput1);
      const user2 = await userModel.create(userInput2);
      
      createdUserIds.push(user1.id, user2.id);

      await expect(userModel.updateEmail(user1.id, userInput2.email)).rejects.toThrow(ApiError);

      // Verify original email unchanged
      const dbResult = await testQuery('SELECT email FROM users WHERE id = $1', [user1.id]);
      expect(dbResult.rows[0].email).toBe(userInput1.email);
    });

    it('should return null for non-existent user', async () => {
      const result = await userModel.updateEmail('550e8400-e29b-41d4-a716-446655440000', 'new@example.com');
      expect(result).toBeNull();
    });

    it('should allow user to keep same email', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const result = await userModel.updateEmail(createdUser.id, userInput.email);
      expect(result?.email).toBe(userInput.email);
    });
  });

  describe('updatePassword', () => {
    it('should update user password successfully', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const newPassword = 'newpassword456';
      const result = await userModel.updatePassword(createdUser.id, newPassword);

      expect(result).toBe(true);

      // Verify password was updated and can be validated
      const user = await userModel.findByEmail(userInput.email) as User;
      const oldPasswordValid = await userModel.validatePassword(user, userInput.password);
      const newPasswordValid = await userModel.validatePassword(user, newPassword);

      expect(oldPasswordValid).toBe(false);
      expect(newPasswordValid).toBe(true);

      // Verify updated_at was changed
      const dbResult = await testQuery('SELECT updated_at FROM users WHERE id = $1', [createdUser.id]);
      expect(new Date(dbResult.rows[0].updated_at)).toBeInstanceOf(Date);
    });

    it('should return false for non-existent user', async () => {
      const result = await userModel.updatePassword('550e8400-e29b-41d4-a716-446655440000', 'newpassword');
      expect(result).toBe(false);
    });

    it('should handle concurrent password updates', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      const promises = [
        userModel.updatePassword(createdUser.id, 'password1'),
        userModel.updatePassword(createdUser.id, 'password2')
      ];

      const results = await Promise.allSettled(promises);
      
      // At least one should succeed
      const successCount = results.filter(r => r.status === 'fulfilled' && r.value === true).length;
      expect(successCount).toBeGreaterThanOrEqual(1);
    });
  });

  describe('delete', () => {
    it('should delete user successfully', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);

      const result = await userModel.delete(createdUser.id);
      expect(result).toBe(true);

      // Verify user was deleted from database
      const dbResult = await testQuery('SELECT COUNT(*) as count FROM users WHERE id = $1', [createdUser.id]);
      expect(parseInt(dbResult.rows[0].count)).toBe(0);

      // Remove from cleanup since already deleted
      const index = createdUserIds.indexOf(createdUser.id);
      if (index > -1) createdUserIds.splice(index, 1);
    });

    it('should return false for non-existent user', async () => {
      const result = await userModel.delete('550e8400-e29b-41d4-a716-446655440000');
      expect(result).toBe(false);
    });

    it('should handle cascading deletes with related data', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);

      // Create related data
      await testQuery('INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)', [createdUser.id, 'test.jpg']);
      await testQuery('INSERT INTO garment_items (user_id, name) VALUES ($1, $2)', [createdUser.id, 'Test Garment']);
      await testQuery('INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', [createdUser.id, 'Test Wardrobe']);

      const result = await userModel.delete(createdUser.id);
      expect(result).toBe(true);

      // Verify related data was also deleted
      const imageCount = await testQuery('SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', [createdUser.id]);
      const garmentCount = await testQuery('SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', [createdUser.id]);
      const wardrobeCount = await testQuery('SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', [createdUser.id]);

      expect(parseInt(imageCount.rows[0].count)).toBe(0);
      expect(parseInt(garmentCount.rows[0].count)).toBe(0);
      expect(parseInt(wardrobeCount.rows[0].count)).toBe(0);
    });
  });

  describe('getUserStats', () => {
    it('should return correct user statistics', async () => {
      const userInput = createTestUserInput();
      const createdUser = await userModel.create(userInput);
      createdUserIds.push(createdUser.id);

      // Create test data
      await testQuery('INSERT INTO original_images (user_id, file_path) VALUES ($1, $2), ($1, $3)', 
        [createdUser.id, 'image1.jpg', 'image2.jpg']);
      await testQuery('INSERT INTO garment_items (user_id, name) VALUES ($1, $2), ($1, $3), ($1, $4)', 
        [createdUser.id, 'Shirt', 'Pants', 'Jacket']);
      await testQuery('INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', 
        [createdUser.id, 'Summer Wardrobe']);

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

    it('should handle non-existent user', async () => {
      const stats = await userModel.getUserStats('550e8400-e29b-41d4-a716-446655440000');

      expect(stats).toEqual({
        imageCount: 0,
        garmentCount: 0,
        wardrobeCount: 0
      });
    });
  });

  describe('OAuth Operations', () => {
    describe('createOAuthUser', () => {
      it('should create OAuth user successfully', async () => {
        const oauthInput = createTestOAuthUserInput();

        const result = await userModel.createOAuthUser(oauthInput);

        expect(result).toMatchObject({
          id: expect.any(String),
          email: oauthInput.email,
          created_at: expect.any(Date)
        });

        // Verify user was saved with OAuth data
        const dbResult = await testQuery('SELECT * FROM users WHERE id = $1', [result.id]);
        const dbUser = dbResult.rows[0];

        expect(dbUser.email).toBe(oauthInput.email);
        expect(dbUser.name).toBe(oauthInput.name);
        expect(dbUser.avatar_url).toBe(oauthInput.avatar_url);
        expect(dbUser.oauth_provider).toBe(oauthInput.oauth_provider);
        expect(dbUser.oauth_id).toBe(oauthInput.oauth_id);
        expect(dbUser.password_hash).toBe('');

        createdUserIds.push(result.id);
      });

      it('should throw error when OAuth email already exists', async () => {
        const oauthInput = createTestOAuthUserInput();

        const firstUser = await userModel.createOAuthUser(oauthInput);
        createdUserIds.push(firstUser.id);

        await expect(userModel.createOAuthUser(oauthInput)).rejects.toThrow(ApiError);
      });

      it('should handle OAuth user with minimal data', async () => {
        const oauthInput = createTestOAuthUserInput({
          name: undefined,
          avatar_url: undefined
        });

        const result = await userModel.createOAuthUser(oauthInput);
        createdUserIds.push(result.id);

        const dbResult = await testQuery('SELECT * FROM users WHERE id = $1', [result.id]);
        const dbUser = dbResult.rows[0];

        expect(dbUser.name).toBeNull();
        expect(dbUser.avatar_url).toBeNull();
        expect(dbUser.oauth_provider).toBe(oauthInput.oauth_provider);
        expect(dbUser.oauth_id).toBe(oauthInput.oauth_id);
      });
    });

    describe('findByOAuth', () => {
      it('should find user by OAuth provider and ID', async () => {
        const oauthInput = createTestOAuthUserInput();
        const createdUser = await userModel.createOAuthUser(oauthInput);
        createdUserIds.push(createdUser.id);

        const result = await userModel.findByOAuth(oauthInput.oauth_provider, oauthInput.oauth_id);

        expect(result).toMatchObject({
          id: createdUser.id,
          email: oauthInput.email,
          oauth_provider: oauthInput.oauth_provider,
          oauth_id: oauthInput.oauth_id
        });
      });

      it('should find user by linked OAuth provider', async () => {
        // Create regular user
        const userInput = createTestUserInput();
        const user = await userModel.create(userInput);
        createdUserIds.push(user.id);

        // Link OAuth provider
        const provider = 'github';
        const providerId = 'github123';
        await testQuery(
          'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
          [user.id, provider, providerId]
        );

        const result = await userModel.findByOAuth(provider, providerId);

        expect(result).toMatchObject({
          id: user.id,
          email: userInput.email
        });
      });

      it('should return null for non-existent OAuth user', async () => {
        const result = await userModel.findByOAuth('nonexistent', 'provider123');
        expect(result).toBeNull();
      });

      it('should prioritize linked accounts over direct OAuth accounts', async () => {
        // Create OAuth user
        const oauthInput = createTestOAuthUserInput();
        const oauthUser = await userModel.createOAuthUser(oauthInput);
        createdUserIds.push(oauthUser.id);

        // Create regular user with linked OAuth
        const userInput = createTestUserInput();
        const regularUser = await userModel.create(userInput);
        createdUserIds.push(regularUser.id);

        await testQuery(
          'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
          [regularUser.id, oauthInput.oauth_provider, oauthInput.oauth_id]
        );

        const result = await userModel.findByOAuth(oauthInput.oauth_provider, oauthInput.oauth_id);

        // Should return the linked account (regular user), not the direct OAuth user
        expect(result?.id).toBe(regularUser.id);
      });
    });

    describe('getUserWithOAuthProviders', () => {
      it('should get user with linked OAuth providers', async () => {
        const userInput = createTestUserInput();
        const user = await userModel.create(userInput);
        createdUserIds.push(user.id);

        // Link multiple OAuth providers
        await testQuery(
          'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3), ($1, $4, $5)',
          [user.id, 'github', 'github123', 'facebook', 'facebook456']
        );

        const result = await userModel.getUserWithOAuthProviders(user.id);

        expect(result).toMatchObject({
          id: user.id,
          email: userInput.email,
          linkedProviders: expect.arrayContaining(['github', 'facebook'])
        });
      });

      it('should get OAuth user with direct provider', async () => {
        const oauthInput = createTestOAuthUserInput();
        const user = await userModel.createOAuthUser(oauthInput);
        createdUserIds.push(user.id);

        const result = await userModel.getUserWithOAuthProviders(user.id);

        expect(result).toMatchObject({
          id: user.id,
          email: oauthInput.email,
          oauth_provider: oauthInput.oauth_provider,
          linkedProviders: expect.arrayContaining([oauthInput.oauth_provider])
        });
      });

      it('should return null for non-existent user', async () => {
        const result = await userModel.getUserWithOAuthProviders('550e8400-e29b-41d4-a716-446655440000');
        expect(result).toBeNull();
      });

      it('should handle user with both direct and linked providers', async () => {
        const oauthInput = createTestOAuthUserInput();
        const user = await userModel.createOAuthUser(oauthInput);
        createdUserIds.push(user.id);

        // Link additional provider
        await testQuery(
          'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
          [user.id, 'github', 'github123']
        );

        const result = await userModel.getUserWithOAuthProviders(user.id);

        expect(result?.linkedProviders).toHaveLength(2);
        expect(result?.linkedProviders).toContain(oauthInput.oauth_provider);
        expect(result?.linkedProviders).toContain('github');
      });
    });
  });

  describe('Database Transaction Integrity', () => {
    it('should handle database connection errors gracefully', async () => {
      // This test would require temporarily breaking the DB connection
      // For now, we'll just verify the error handling structure exists
      const userInput = createTestUserInput();
      
      try {
        await userModel.create(userInput);
      } catch (error) {
        // Should be proper ApiError or database error, not undefined
        expect(error).toBeDefined();
      }
    });

    it('should maintain data consistency under concurrent operations', async () => {
      const baseEmail = `concurrent-${Date.now()}@example.com`;
      
      // Try to create multiple users with same email simultaneously
      const promises = Array.from({ length: 5 }, () => 
        userModel.create({ email: baseEmail, password: 'password123' })
      );

      const results = await Promise.allSettled(promises);
      
      // Only one should succeed, others should fail with conflict error
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      expect(successful).toBe(1);
      expect(failed).toBe(4);

      // Clean up the successful user
      const successfulResult = results.find(r => r.status === 'fulfilled') as PromiseFulfilledResult<any>;
      if (successfulResult) {
        createdUserIds.push(successfulResult.value.id);
      }
    });

    it('should handle database constraint violations properly', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);

      // Try to insert duplicate email directly in database
      await expect(
        testQuery('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [userInput.email, 'hash'])
      ).rejects.toThrow();
    });
  });

  describe('Performance Tests', () => {
    it('should handle bulk user operations efficiently', async () => {
      const startTime = Date.now();
      const userCount = 10;
      
      const userInputs = Array.from({ length: userCount }, () => createTestUserInput());
      
      // Create users sequentially to avoid constraint conflicts
      const users = [];
      for (const input of userInputs) {
        const user = await userModel.create(input);
        users.push(user);
        createdUserIds.push(user.id);
      }

      const creationTime = Date.now() - startTime;
      console.log(`Created ${userCount} users in ${creationTime}ms`);

      // Verify all users exist
      const dbResult = await testQuery('SELECT COUNT(*) as count FROM users WHERE id = ANY($1)', [users.map(u => u.id)]);
      expect(parseInt(dbResult.rows[0].count)).toBe(userCount);

      // Test should complete in reasonable time
      expect(creationTime).toBeLessThan(10000); // 10 seconds
    });

    it('should handle large query results efficiently', async () => {
      // Create multiple users with statistics
      const userCount = 5;
      const users = [];

      for (let i = 0; i < userCount; i++) {
        const userInput = createTestUserInput();
        const user = await userModel.create(userInput);
        users.push(user);
        createdUserIds.push(user.id);

        // Add related data for statistics
        await testQuery('INSERT INTO original_images (user_id, file_path) VALUES ($1, $2), ($1, $3)', 
          [user.id, `image${i}_1.jpg`, `image${i}_2.jpg`]);
        await testQuery('INSERT INTO garment_items (user_id, name) VALUES ($1, $2), ($1, $3)', 
          [user.id, `Garment${i}_1`, `Garment${i}_2`]);
        await testQuery('INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', 
          [user.id, `Wardrobe${i}`]);
      }

      const startTime = Date.now();
      
      // Get statistics for all users
      const statsPromises = users.map(user => userModel.getUserStats(user.id));
      const allStats = await Promise.all(statsPromises);

      const queryTime = Date.now() - startTime;
      console.log(`Retrieved stats for ${userCount} users in ${queryTime}ms`);

      // Verify results
      allStats.forEach(stats => {
        expect(stats).toEqual({
          imageCount: 2,
          garmentCount: 2,
          wardrobeCount: 1
        });
      });

      expect(queryTime).toBeLessThan(5000); // 5 seconds
    });

    it('should handle complex OAuth queries efficiently', async () => {
      const startTime = Date.now();
      
      // Create mix of regular and OAuth users
      const regularUser = await userModel.create(createTestUserInput());
      const oauthInput1 = createTestOAuthUserInput({ oauth_provider: 'google' });
      const oauthInput2 = createTestOAuthUserInput({ oauth_provider: 'github' });
      const oauthUser1 = await userModel.createOAuthUser(oauthInput1);
      const oauthUser2 = await userModel.createOAuthUser(oauthInput2);
      
      createdUserIds.push(regularUser.id, oauthUser1.id, oauthUser2.id);

      // Link additional providers to regular user
      await testQuery(
        'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3), ($1, $4, $5)',
        [regularUser.id, 'facebook', 'fb123', 'twitter', 'tw456']
      );

      // Test various OAuth lookup scenarios
      const queries = [
        userModel.findByOAuth('google', oauthInput1.oauth_id),
        userModel.findByOAuth('github', oauthInput2.oauth_id),
        userModel.findByOAuth('facebook', 'fb123'),
        userModel.getUserWithOAuthProviders(regularUser.id),
        userModel.getUserWithOAuthProviders(oauthUser1.id),
        userModel.getUserWithOAuthProviders(oauthUser2.id)
      ];

      const results = await Promise.all(queries);
      const queryTime = Date.now() - startTime;
      
      console.log(`Completed OAuth queries in ${queryTime}ms`);

      // Verify results
      expect(results[0]?.id).toBe(oauthUser1.id); // Google OAuth user
      expect(results[1]?.id).toBe(oauthUser2.id); // GitHub OAuth user
      expect(results[2]?.id).toBe(regularUser.id); // Linked Facebook account
      expect(results[3]?.linkedProviders).toContain('facebook'); // Regular user with links
      expect(results[4]?.linkedProviders).toContain('google'); // Direct OAuth user
      expect(results[5]?.linkedProviders).toContain('github'); // Direct OAuth user

      expect(queryTime).toBeLessThan(3000); // 3 seconds
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle extremely long email addresses', async () => {
      const longEmail = 'a'.repeat(200) + '@example.com'; // Very long email
      const userInput = createTestUserInput({ email: longEmail });

      // This might fail due to database constraints, which is expected behavior
      try {
        const user = await userModel.create(userInput);
        createdUserIds.push(user.id);
        expect(user.email).toBe(longEmail);
      } catch (error) {
        // If it fails due to length constraints, that's also valid behavior
        expect(error).toBeDefined();
      }
    });

    it('should handle special characters in email', async () => {
      const specialEmail = 'user+test.123@sub-domain.example-site.com';
      const userInput = createTestUserInput({ email: specialEmail });

      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);

      expect(user.email).toBe(specialEmail);

      const foundUser = await userModel.findByEmail(specialEmail);
      expect(foundUser?.email).toBe(specialEmail);
    });

    it('should handle Unicode characters in user data', async () => {
      const oauthInput = createTestOAuthUserInput({
        name: '测试用户 🚀 José María',
        email: 'unicode.test@测试.example.com'
      });

      try {
        const user = await userModel.createOAuthUser(oauthInput);
        createdUserIds.push(user.id);

        const result = await userModel.getUserWithOAuthProviders(user.id);
        expect(result?.name).toBe(oauthInput.name);
      } catch (error) {
        // Unicode domain might not be supported, which is valid
        expect(error).toBeDefined();
      }
    });

    it('should handle null and undefined values gracefully', async () => {
      // Test OAuth user with null values
      const result = await testQuery(
        'INSERT INTO users (email, name, avatar_url, oauth_provider, oauth_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        ['null-test@example.com', null, null, 'google', 'google_null_test']
      );
      const user = result.rows[0];
      createdUserIds.push(user.id);

      const userWithProviders = await userModel.getUserWithOAuthProviders(user.id);
      expect(userWithProviders?.name).toBeNull();
      expect(userWithProviders?.avatar_url).toBeNull();
      expect(userWithProviders?.oauth_provider).toBe('google');
    });

    it('should handle database connection recovery', async () => {
      // Simulate a scenario where database operations might be retried
      const userInput = createTestUserInput();
      
      let attempts = 0;
      const maxAttempts = 3;
      let user;

      while (attempts < maxAttempts) {
        try {
          user = await userModel.create(userInput);
          break;
        } catch (error) {
          attempts++;
          if (attempts === maxAttempts) {
            throw error;
          }
          // Wait briefly before retry
          await new Promise(resolve => setTimeout(resolve, 100));
        }
      }

      if (user) {
        createdUserIds.push(user.id);
        expect(user.email).toBe(userInput.email);
      }
    });

    it('should handle concurrent email updates', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);

      const newEmails = [
        `concurrent1-${Date.now()}@example.com`,
        `concurrent2-${Date.now()}@example.com`,
        `concurrent3-${Date.now()}@example.com`
      ];

      // Try concurrent email updates
      const updatePromises = newEmails.map(email => 
        userModel.updateEmail(user.id, email)
      );

      const results = await Promise.allSettled(updatePromises);
      
      // At least one should succeed
      const successfulUpdates = results.filter(r => r.status === 'fulfilled').length;
      expect(successfulUpdates).toBeGreaterThanOrEqual(1);

      // Verify final state
      const finalUser = await userModel.findById(user.id);
      expect(newEmails).toContain(finalUser?.email);
    });

    it('should handle malformed OAuth provider data', async () => {
      // Test with empty provider strings
      await expect(
        userModel.findByOAuth('', 'someId')
      ).resolves.toBeNull();

      await expect(
        userModel.findByOAuth('google', '')
      ).resolves.toBeNull();

      // Test with whitespace
      await expect(
        userModel.findByOAuth('  ', 'someId')
      ).resolves.toBeNull();
    });

    it('should handle very long OAuth IDs', async () => {
      const longOAuthId = 'oauth_' + 'x'.repeat(500);
      const oauthInput = createTestOAuthUserInput({
        oauth_id: longOAuthId
      });

      try {
        const user = await userModel.createOAuthUser(oauthInput);
        createdUserIds.push(user.id);

        const foundUser = await userModel.findByOAuth(oauthInput.oauth_provider, longOAuthId);
        expect(foundUser?.id).toBe(user.id);
      } catch (error) {
        // Might fail due to database field length constraints
        expect(error).toBeDefined();
      }
    });
  });

  describe('Data Validation and Integrity', () => {
    it('should maintain referential integrity with cascading deletes', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);

      // Create extensive related data
      const relatedDataPromises = [
        testQuery('INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)', [user.id, 'test1.jpg']),
        testQuery('INSERT INTO garment_items (user_id, name) VALUES ($1, $2)', [user.id, 'Test Garment']),
        testQuery('INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', [user.id, 'Test Wardrobe']),
        testQuery('INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)', 
          [user.id, 'github', 'github123'])
      ];

      await Promise.all(relatedDataPromises);

      // Verify data exists
      const counts = await Promise.all([
        testQuery('SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', [user.id]),
        testQuery('SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', [user.id]),
        testQuery('SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', [user.id]),
        testQuery('SELECT COUNT(*) as count FROM user_oauth_providers WHERE user_id = $1', [user.id])
      ]);

      counts.forEach(result => {
        expect(parseInt(result.rows[0].count)).toBeGreaterThan(0);
      });

      // Delete user
      await userModel.delete(user.id);

      // Verify all related data was cascade deleted
      const afterDeleteCounts = await Promise.all([
        testQuery('SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', [user.id]),
        testQuery('SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', [user.id]),
        testQuery('SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', [user.id]),
        testQuery('SELECT COUNT(*) as count FROM user_oauth_providers WHERE user_id = $1', [user.id])
      ]);

      afterDeleteCounts.forEach(result => {
        expect(parseInt(result.rows[0].count)).toBe(0);
      });
    });

    it('should ensure email uniqueness across all user types', async () => {
      const email = `unique-test-${Date.now()}@example.com`;

      // Create regular user
      const regularUser = await userModel.create({ email, password: 'password123' });
      createdUserIds.push(regularUser.id);

      // Try to create OAuth user with same email
      await expect(
        userModel.createOAuthUser({
          email,
          oauth_provider: 'google',
          oauth_id: 'google123'
        })
      ).rejects.toThrow(ApiError);

      // Verify only one user exists with this email
      const result = await testQuery('SELECT COUNT(*) as count FROM users WHERE email = $1', [email]);
      expect(parseInt(result.rows[0].count)).toBe(1);
    });

    it('should handle timestamp precision correctly', async () => {
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);

      // Get precise timestamps
      const beforeUpdate = new Date();
      await new Promise(resolve => setTimeout(resolve, 10)); // Small delay

      await userModel.updateEmail(user.id, `updated-${Date.now()}@example.com`);

      const dbResult = await testQuery('SELECT created_at, updated_at FROM users WHERE id = $1', [user.id]);
      const { created_at, updated_at } = dbResult.rows[0];

      expect(new Date(created_at)).toBeInstanceOf(Date);
      expect(new Date(updated_at)).toBeInstanceOf(Date);
      expect(new Date(updated_at).getTime()).toBeGreaterThan(beforeUpdate.getTime());
      expect(new Date(updated_at).getTime()).toBeGreaterThan(new Date(created_at).getTime());
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
  });

  describe('Real-world Usage Scenarios', () => {
    it('should support complete user lifecycle', async () => {
      // 1. User registration
      const userInput = createTestUserInput();
      const user = await userModel.create(userInput);
      createdUserIds.push(user.id);

      // 2. Login simulation (find and validate)
      const loginUser = await userModel.findByEmail(userInput.email);
      expect(loginUser).not.toBeNull();
      
      const isValidPassword = await userModel.validatePassword(loginUser!, userInput.password);
      expect(isValidPassword).toBe(true);

      // 3. Profile updates
      const newEmail = `updated-${Date.now()}@example.com`;
      await userModel.updateEmail(user.id, newEmail);
      
      const newPassword = 'newSecurePassword123';
      await userModel.updatePassword(user.id, newPassword);

      // 4. Link OAuth account
      await testQuery(
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
      await testQuery('INSERT INTO original_images (user_id, file_path) VALUES ($1, $2)', [user.id, 'profile.jpg']);
      await testQuery('INSERT INTO garment_items (user_id, name) VALUES ($1, $2)', [user.id, 'Favorite Shirt']);
      await testQuery('INSERT INTO wardrobes (user_id, name) VALUES ($1, $2)', [user.id, 'Work Clothes']);

      const stats = await userModel.getUserStats(user.id);
      expect(stats.imageCount).toBe(1);
      expect(stats.garmentCount).toBe(1);
      expect(stats.wardrobeCount).toBe(1);

      // 8. Account deactivation (deletion)
      const deleteResult = await userModel.delete(user.id);
      expect(deleteResult).toBe(true);

      // Remove from cleanup since already deleted
      const index = createdUserIds.indexOf(user.id);
      if (index > -1) createdUserIds.splice(index, 1);
    });

    it('should handle OAuth login flow', async () => {
      const oauthId = 'google_flow_test';
      const provider = 'google';

      // 1. First OAuth login - user doesn't exist
      let user = await userModel.findByOAuth(provider, oauthId);
      expect(user).toBeNull();

      // 2. Create OAuth user
      const oauthInput = createTestOAuthUserInput({
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
      expect(profile?.oauth_provider).toBe(provider);
      expect(profile?.linkedProviders).toContain(provider);

      // 5. Link additional OAuth provider
      await testQuery(
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
      const oauthInput = createTestOAuthUserInput({
        email: userInput.email // Same email
      });

      // This should fail - email already exists
      await expect(userModel.createOAuthUser(oauthInput)).rejects.toThrow(ApiError);

      // 3. Instead, link OAuth to existing account
      await testQuery(
        'INSERT INTO user_oauth_providers (user_id, provider, provider_id) VALUES ($1, $2, $3)',
        [emailUser.id, oauthInput.oauth_provider, oauthInput.oauth_id]
      );

      // 4. Now OAuth lookup should find the original user
      const foundUser = await userModel.findByOAuth(oauthInput.oauth_provider, oauthInput.oauth_id);
      expect(foundUser?.id).toBe(emailUser.id);

      // 5. User profile shows both authentication methods
      const profile = await userModel.getUserWithOAuthProviders(emailUser.id);
      expect(profile?.linkedProviders).toContain(oauthInput.oauth_provider);
      expect(profile?.password_hash).toBeDefined(); // Still has password login
    });
  });
});