// /backend/src/models/__tests__/helpers/userModel.helper.ts
import { User, UserOutput, CreateUserInput, CreateOAuthUserInput } from '../../models/userModel';
import { mockQuery, mockBcrypt, mockUuidv4, mockQueryResults } from '../../tests/__mocks__/userModel.mock';

/**
 * Helper functions for userModel testing
 */
export class UserModelTestHelper {
  /**
   * Setup mock for successful user creation
   */
  static setupCreateUserSuccess() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUserNotFound); // No existing user
    mockQuery.mockResolvedValueOnce(mockQueryResults.insertUser); // Insert new user
    mockBcrypt.hash.mockResolvedValueOnce('$2b$10$mockedHashValue');
    mockUuidv4.mockReturnValueOnce('550e8400-e29b-41d4-a716-446655440000');
  }

  /**
   * Setup mock for user creation failure (email already exists)
   */
  static setupCreateUserEmailExists() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUser); // Existing user found
  }

  /**
   * Setup mock for successful user lookup by ID
   */
  static setupFindByIdSuccess() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUser);
  }

  /**
   * Setup mock for user not found by ID
   */
  static setupFindByIdNotFound() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUserNotFound);
  }

  /**
   * Setup mock for successful user lookup by email
   */
  static setupFindByEmailSuccess() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUser);
  }

  /**
   * Setup mock for user not found by email
   */
  static setupFindByEmailNotFound() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUserNotFound);
  }

  /**
   * Setup mock for successful password validation
   */
  static setupValidatePasswordSuccess() {
    mockBcrypt.compare.mockResolvedValueOnce(true);
  }

  /**
   * Setup mock for failed password validation
   */
  static setupValidatePasswordFailure() {
    mockBcrypt.compare.mockResolvedValueOnce(false);
  }

  /**
   * Setup mock for successful email update
   */
  static setupUpdateEmailSuccess() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUserNotFound); // Email not in use
    mockQuery.mockResolvedValueOnce(mockQueryResults.updateUser); // Update successful
  }

  /**
   * Setup mock for email update failure (email already in use)
   */
  static setupUpdateEmailExists() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUser); // Email already in use
  }

  /**
   * Setup mock for successful password update
   */
  static setupUpdatePasswordSuccess() {
    mockBcrypt.hash.mockResolvedValueOnce('$2b$10$newMockedHashValue');
    mockQuery.mockResolvedValueOnce(mockQueryResults.updateUser);
  }

  /**
   * Setup mock for failed password update
   */
  static setupUpdatePasswordFailure() {
    mockBcrypt.hash.mockResolvedValueOnce('$2b$10$newMockedHashValue');
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
  }

  /**
   * Setup mock for successful user deletion
   */
  static setupDeleteUserSuccess() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.deleteUser);
  }

  /**
   * Setup mock for failed user deletion
   */
  static setupDeleteUserFailure() {
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
  }

  /**
   * Setup mock for getting user statistics
   */
  static setupGetUserStats() {
    mockQuery
      .mockResolvedValueOnce(mockQueryResults.userStats.imageCount)
      .mockResolvedValueOnce(mockQueryResults.userStats.garmentCount)
      .mockResolvedValueOnce(mockQueryResults.userStats.wardrobeCount);
  }

  /**
   * Setup mock for successful OAuth user lookup
   */
  static setupFindByOAuthSuccess() {
    // Only return from linked accounts now, not direct OAuth
    mockQuery.mockResolvedValueOnce({ rows: [] }); // No linked account
  }

  /**
   * Setup mock for OAuth user lookup with linked account
   */
  static setupFindByOAuthLinkedSuccess() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUser); // Linked account found
  }

  /**
   * Setup mock for OAuth user not found
   */
  static setupFindByOAuthNotFound() {
    mockQuery.mockResolvedValueOnce({ rows: [] }); // No linked account
  }

  /**
   * Setup mock for successful OAuth user creation
   */
  static setupCreateOAuthUserSuccess() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUserNotFound); // No existing user
    mockQuery.mockResolvedValueOnce(mockQueryResults.insertUser); // Insert new user
    mockUuidv4.mockReturnValueOnce('550e8400-e29b-41d4-a716-446655440000');
  }

  /**
   * Setup mock for OAuth user creation failure (email already exists)
   */
  static setupCreateOAuthUserEmailExists() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUser); // Existing user found
  }

  /**
   * Setup mock for getting user with OAuth providers
   */
  static setupGetUserWithOAuthProviders() {
    mockQuery
      .mockResolvedValueOnce(mockQueryResults.userWithProviders.user) // User data
      .mockResolvedValueOnce(mockQueryResults.userWithProviders.providers); // Linked providers
  }

  /**
   * Setup mock for user not found when getting OAuth providers
   */
  static setupGetUserWithOAuthProvidersNotFound() {
    mockQuery.mockResolvedValueOnce(mockQueryResults.selectUserNotFound);
  }

  /**
   * Expect query to be called with normalized whitespace
   */
  static expectQueryCalledWith(query: string, params?: any[]) {
    if (params) {
      // Normalize whitespace for comparison
      const normalizedQuery = query.replace(/\s+/g, ' ').trim();
      
      // Check if any call matches the normalized query
      const calls = mockQuery.mock.calls;
      const matchingCall = calls.find(call => {
        const normalizedCall = call[0].replace(/\s+/g, ' ').trim();
        return normalizedCall === normalizedQuery && 
               JSON.stringify(call[1]) === JSON.stringify(params);
      });
      
      expect(matchingCall).toBeDefined();
    } else {
      expect(mockQuery).toHaveBeenCalledWith(query);
    }
  }

  /**
   * Expect specific call number with exact parameters
   */
  static expectNthQueryCalledWith(callNumber: number, query: string, params?: any[]) {
    if (params) {
      expect(mockQuery).toHaveBeenNthCalledWith(callNumber, query, params);
    } else {
      expect(mockQuery).toHaveBeenNthCalledWith(callNumber, query);
    }
  }

  /**
   * Verify that bcrypt.hash was called with expected parameters
   */
  static expectBcryptHashCalledWith(password: string, rounds: number) {
    expect(mockBcrypt.hash).toHaveBeenCalledWith(password, rounds);
  }

  /**
   * Verify that bcrypt.compare was called with expected parameters
   */
  static expectBcryptCompareCalledWith(password: string, hash: string) {
    expect(mockBcrypt.compare).toHaveBeenCalledWith(password, hash);
  }

  /**
   * Verify that UUID was generated
   */
  static expectUuidGenerated() {
    expect(mockUuidv4).toHaveBeenCalled();
  }

  /**
   * Create a test user input
   */
  static createTestUserInput(overrides: Partial<CreateUserInput> = {}): CreateUserInput {
    return {
      email: 'test@example.com',
      password: 'testpassword123',
      ...overrides
    };
  }

  /**
   * Create a test OAuth user input
   */
  static createTestOAuthUserInput(overrides: Partial<CreateOAuthUserInput> = {}): CreateOAuthUserInput {
    return {
      email: 'oauth@example.com',
      name: 'OAuth Test User',
      avatar_url: 'https://example.com/avatar.jpg',
      oauth_provider: 'google',
      oauth_id: 'google_123456',
      ...overrides
    };
  }

  /**
   * Create a test user object
   */
  static createTestUser(overrides: Partial<User> = {}): User {
    return {
      id: '550e8400-e29b-41d4-a716-446655440000',
      email: 'test@example.com',
      password_hash: '$2b$10$mockedHashValue',
      created_at: new Date('2024-01-01T10:00:00Z'),
      updated_at: new Date('2024-01-01T10:00:00Z'),
      ...overrides
    };
  }

  /**
   * Create a test user output object
   */
  static createTestUserOutput(overrides: Partial<UserOutput> = {}): UserOutput {
    return {
      id: '550e8400-e29b-41d4-a716-446655440000',
      email: 'test@example.com',
      created_at: new Date('2024-01-01T10:00:00Z'),
      ...overrides
    };
  }

  /**
   * Setup for new transaction-based OAuth user creation
   */
  static setupCreateOAuthUserSuccessNew() {
    // First query: check if email exists
    mockQuery
      .mockResolvedValueOnce({ rows: [] }) // Email doesn't exist
      .mockResolvedValueOnce({ rows: [] }) // BEGIN transaction
      .mockResolvedValueOnce({ // INSERT user
        rows: [{
          id: '550e8400-e29b-41d4-a716-446655440000',
          email: 'john.doe@example.com',
          created_at: new Date('2024-01-01T10:00:00Z')
        }]
      })
      .mockResolvedValueOnce({ rows: [] }) // INSERT oauth provider
      .mockResolvedValueOnce({ rows: [] }); // COMMIT transaction
  }

  /**
   * Setup for new getUserWithOAuthProviders (without OAuth columns)
   */
  static setupGetUserWithOAuthProvidersNew() {
    mockQuery
      .mockResolvedValueOnce({ // User query
        rows: [{
          id: '550e8400-e29b-41d4-a716-446655440000',
          email: 'john.doe@example.com',
          created_at: new Date('2024-01-01T10:00:00Z')
        }]
      })
      .mockResolvedValueOnce({ // OAuth providers query
        rows: [
          { provider: 'github' }
        ]
      });
  }

  /**
   * Setup findByOAuth to return null (no direct OAuth accounts)
   */
  static setupFindByOAuthNotFoundNew() {
    mockQuery.mockResolvedValueOnce({ rows: [] }); // No linked account found
  }
}