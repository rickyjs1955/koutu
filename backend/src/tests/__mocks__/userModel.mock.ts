// /backend/src/models/__mocks__/userModel.mock.ts
import { User, UserOutput, CreateUserInput, CreateOAuthUserInput } from '../../models/userModel';

/**
 * Mock data for testing userModel
 */
export const mockUsers: User[] = [
  {
    id: '550e8400-e29b-41d4-a716-446655440000',
    email: 'john.doe@example.com',
    password_hash: '$2b$10$N9qo8uLOickgx2ZMRZoMye.IjdZsZdN6T3VqOkn4xGc8IZjyHl2Q6', // "password123"
    created_at: new Date('2024-01-01T10:00:00Z'),
    updated_at: new Date('2024-01-01T10:00:00Z')
  },
  {
    id: '550e8400-e29b-41d4-a716-446655440001',
    email: 'jane.smith@example.com',
    password_hash: '$2b$10$N9qo8uLOickgx2ZMRZoMye.IjdZsZdN6T3VqOkn4xGc8IZjyHl2Q6',
    created_at: new Date('2024-01-02T10:00:00Z'),
    updated_at: new Date('2024-01-02T10:00:00Z')
  },
  {
    id: '550e8400-e29b-41d4-a716-446655440002',
    email: 'oauth.user@example.com',
    password_hash: '',
    created_at: new Date('2024-01-03T10:00:00Z'),
    updated_at: new Date('2024-01-03T10:00:00Z')
  }
];

export const mockUserOutputs: UserOutput[] = mockUsers.map(user => ({
  id: user.id,
  email: user.email,
  created_at: user.created_at
}));

export const mockCreateUserInput: CreateUserInput = {
  email: 'new.user@example.com',
  password: 'newpassword123'
};

export const mockCreateOAuthUserInput: CreateOAuthUserInput = {
  email: 'oauth.new@example.com',
  name: 'OAuth User',
  avatar_url: 'https://example.com/avatar.jpg',
  oauth_provider: 'google',
  oauth_id: 'google_123456789'
};

export const mockUserStats = {
  imageCount: 25,
  garmentCount: 150,
  wardrobeCount: 5
};

export const mockUserWithOAuthProviders = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  email: 'john.doe@example.com',
  name: 'John Doe',
  avatar_url: 'https://example.com/john-avatar.jpg',
  oauth_provider: 'google',
  created_at: new Date('2024-01-01T10:00:00Z'),
  linkedProviders: ['google', 'github']
};

/**
 * Mock database query results
 */
export const mockQueryResults = {
  selectUser: {
    rows: [mockUsers[0]],
    rowCount: 1
  },
  selectUserNotFound: {
    rows: [],
    rowCount: 0
  },
  insertUser: {
    rows: [mockUserOutputs[0]],
    rowCount: 1
  },
  updateUser: {
    rows: [mockUserOutputs[0]],
    rowCount: 1
  },
  deleteUser: {
    rows: [],
    rowCount: 1
  },
  userStats: {
    imageCount: { rows: [{ image_count: '25' }] },
    garmentCount: { rows: [{ garment_count: '150' }] },
    wardrobeCount: { rows: [{ wardrobe_count: '5' }] }
  },
  oauthUser: {
    rows: [mockUsers[2]],
    rowCount: 1
  },
  userWithProviders: {
    user: { rows: [mockUserWithOAuthProviders], rowCount: 1 },
    providers: { rows: [{ provider: 'github' }], rowCount: 1 }
  }
};

/**
 * Mock bcrypt functions
 */
export const mockBcrypt = {
  hash: jest.fn().mockResolvedValue('$2b$10$mockedHashValue'),
  compare: jest.fn().mockResolvedValue(true)
};

/**
 * Mock UUID function
 */
export const mockUuidv4 = jest.fn().mockReturnValue('550e8400-e29b-41d4-a716-446655440000');

/**
 * Mock database query function
 */
export const mockQuery = jest.fn();

/**
 * Reset all mocks
 */
export const resetMocks = () => {
  mockBcrypt.hash.mockClear();
  mockBcrypt.compare.mockClear();
  mockUuidv4.mockClear();
  mockQuery.mockClear();
  
  // Reset default implementations
  mockBcrypt.hash.mockResolvedValue('$2b$10$mockedHashValue');
  mockBcrypt.compare.mockResolvedValue(true);
  mockUuidv4.mockReturnValue('550e8400-e29b-41d4-a716-446655440000');
};

/**
 * Mock ApiError for testing
 */
export const mockApiError = {
  conflict: jest.fn().mockImplementation((message: string, code?: string) => {
    const error = new Error(message);
    (error as any).statusCode = 409;
    (error as any).code = code;
    return error;
  })
};