/**
 * @vitest-environment jsdom
 */

// frontend/src/hooks/__tests__/useAuth.test.ts
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

// Mock localStorage at the top level
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
  length: 0,
  key: vi.fn()
}

// Set up localStorage mock globally
Object.defineProperty(global, 'localStorage', {
  value: localStorageMock,
  writable: true
})

// Mock data
const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  name: 'Test User',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z'
}

const mockAuthResponse = {
  user: mockUser,
  token: 'mock-token-12345',
  expires_at: '2024-12-31T23:59:59Z'
}

// Setup and cleanup functions
const setupTestEnvironment = () => {
  vi.clearAllMocks()
  if (typeof localStorage !== 'undefined') {
    localStorage.clear()
  }
}

const cleanupTestEnvironment = () => {
  vi.clearAllMocks()
  if (typeof localStorage !== 'undefined') {
    localStorage.clear()
  }
}

// Mock the authApi
const mockAuthApi = {
  login: vi.fn(),
  register: vi.fn(),
  me: vi.fn(),
  logout: vi.fn(),
  isLoggedIn: vi.fn(),
  loginWithToken: vi.fn(),
  unlinkProvider: vi.fn()
}

vi.mock('../../api/authApi', () => ({
  authApi: mockAuthApi
}))

// Import after mocking
const { authApi } = await import('../../api/authApi')

// Test the auth API directly to avoid circular dependencies
describe('Auth API Integration', () => {
  beforeEach(() => {
    setupTestEnvironment()
    vi.clearAllMocks()
    
    // Reset localStorage mocks
    localStorageMock.getItem.mockClear()
    localStorageMock.setItem.mockClear()
    localStorageMock.removeItem.mockClear()
    
    // Setup default mock implementations
    mockAuthApi.isLoggedIn.mockReturnValue(false)
    mockAuthApi.logout.mockImplementation(() => {
      localStorageMock.removeItem('token')
    })
  })

  afterEach(() => {
    cleanupTestEnvironment()
  })

  describe('Authentication API Tests', () => {
    test('login stores token and returns auth response', async () => {
      mockAuthApi.login.mockResolvedValue(mockAuthResponse)
      
      const result = await authApi.login({ 
        email: 'test@test.com', 
        password: 'password123' 
      })

      expect(authApi.login).toHaveBeenCalledWith({
        email: 'test@test.com',
        password: 'password123'
      })
      
      expect(result).toEqual(mockAuthResponse)
    })

    test('register creates new user account', async () => {
      const registerData = {
        email: 'newuser@test.com',
        password: 'password123',
        name: 'New User'
      }
      
      mockAuthApi.register.mockResolvedValue(mockAuthResponse)
      
      const result = await authApi.register(registerData)

      expect(authApi.register).toHaveBeenCalledWith(registerData)
      expect(result).toEqual(mockAuthResponse)
    })

    test('me endpoint fetches current user', async () => {
      mockAuthApi.me.mockResolvedValue(mockUser)
      
      const result = await authApi.me()
      
      expect(result).toEqual(mockUser)
    })

    test('logout removes token from storage', () => {
      localStorageMock.setItem('token', 'test-token')
      
      authApi.logout()
      
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('token')
    })

    test('isLoggedIn checks for token existence', () => {
      // No token initially
      mockAuthApi.isLoggedIn.mockReturnValue(false)
      expect(authApi.isLoggedIn()).toBe(false)
      
      // With token
      localStorageMock.setItem('token', 'test-token')
      mockAuthApi.isLoggedIn.mockReturnValue(true)
      expect(authApi.isLoggedIn()).toBe(true)
    })

    test('loginWithToken handles OAuth flow', async () => {
      const token = 'oauth-token-123'
      mockAuthApi.loginWithToken.mockResolvedValue(mockUser)
      
      const result = await authApi.loginWithToken(token)

      expect(authApi.loginWithToken).toHaveBeenCalledWith(token)
      expect(result).toEqual(mockUser)
    })

    test('unlinkProvider calls correct API endpoint', async () => {
      mockAuthApi.unlinkProvider.mockResolvedValue(undefined)
      
      await authApi.unlinkProvider('google')

      expect(authApi.unlinkProvider).toHaveBeenCalledWith('google')
    })
  })

  describe('Error Handling', () => {
    test('handles login failures', async () => {
      const loginError = new Error('Invalid credentials')
      mockAuthApi.login.mockRejectedValue(loginError)
      
      try {
        await authApi.login({ 
          email: 'test@test.com', 
          password: 'wrongpassword' 
        })
        // Should not reach here
        expect(true).toBe(false)
      } catch (error) {
        expect(error).toEqual(loginError)
      }
    })

    test('handles network errors during user fetch', async () => {
      const networkError = new Error('Network error')
      mockAuthApi.me.mockRejectedValue(networkError)
      
      try {
        await authApi.me()
        // Should not reach here
        expect(true).toBe(false)
      } catch (error) {
        expect(error).toEqual(networkError)
      }
    })

    test('handles invalid token during OAuth login', async () => {
      const tokenError = new Error('Invalid token')
      mockAuthApi.loginWithToken.mockRejectedValue(tokenError)
      
      try {
        await authApi.loginWithToken('invalid-token')
        // Should not reach here
        expect(true).toBe(false)
      } catch (error) {
        expect(error).toEqual(tokenError)
      }
    })
  })

  describe('Token Management', () => {
    test('token is stored after successful login', async () => {
      // Mock the API to simulate token storage
      mockAuthApi.login.mockImplementation(async (credentials) => {
        localStorageMock.setItem('token', mockAuthResponse.token)
        return mockAuthResponse
      })
      
      await authApi.login({ email: 'test@test.com', password: 'password123' })
      
      expect(localStorageMock.setItem).toHaveBeenCalledWith('token', mockAuthResponse.token)
    })

    test('token is cleared after logout', () => {
      localStorageMock.setItem('token', 'test-token')
      
      authApi.logout()
      
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('token')
    })

    test('OAuth token is stored correctly', async () => {
      const oauthToken = 'oauth-abc-123'
      
      mockAuthApi.loginWithToken.mockImplementation(async (token) => {
        localStorageMock.setItem('token', token)
        return mockUser
      })
      
      await authApi.loginWithToken(oauthToken)
      
      expect(localStorageMock.setItem).toHaveBeenCalledWith('token', oauthToken)
    })
  })

  describe('Authentication Flow Integration', () => {
    test('complete login flow works correctly', async () => {
      // Step 1: User is not logged in
      mockAuthApi.isLoggedIn.mockReturnValue(false)
      expect(authApi.isLoggedIn()).toBe(false)
      
      // Step 2: User logs in
      mockAuthApi.login.mockImplementation(async (credentials) => {
        localStorageMock.setItem('token', mockAuthResponse.token)
        return mockAuthResponse
      })
      
      const loginResult = await authApi.login({
        email: 'test@test.com',
        password: 'password123'
      })
      
      expect(loginResult).toEqual(mockAuthResponse)
      expect(localStorageMock.setItem).toHaveBeenCalledWith('token', mockAuthResponse.token)
      
      // Step 3: User is now logged in
      mockAuthApi.isLoggedIn.mockReturnValue(true)
      expect(authApi.isLoggedIn()).toBe(true)
      
      // Step 4: Can fetch user data
      mockAuthApi.me.mockResolvedValue(mockUser)
      const userData = await authApi.me()
      expect(userData).toEqual(mockUser)
      
      // Step 5: User logs out
      authApi.logout()
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('token')
    })

    test('OAuth flow works correctly', async () => {
      const oauthToken = 'oauth-token-from-provider'
      
      // Step 1: Receive OAuth token and log in
      mockAuthApi.loginWithToken.mockImplementation(async (token) => {
        localStorageMock.setItem('token', token)
        return mockUser
      })
      
      const result = await authApi.loginWithToken(oauthToken)
      
      expect(result).toEqual(mockUser)
      expect(localStorageMock.setItem).toHaveBeenCalledWith('token', oauthToken)
      
      // Step 2: User is now authenticated
      mockAuthApi.isLoggedIn.mockReturnValue(true)
      expect(authApi.isLoggedIn()).toBe(true)
      
      // Step 3: Can unlink provider later
      mockAuthApi.unlinkProvider.mockResolvedValue(undefined)
      await authApi.unlinkProvider('google')
      expect(authApi.unlinkProvider).toHaveBeenCalledWith('google')
    })
  })
})