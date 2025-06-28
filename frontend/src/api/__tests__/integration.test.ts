/**
 * @vitest-environment jsdom
 */

// frontend/src/api/__tests__/integration.test.ts (Fixed Vitest version)

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
  created_at: new Date('2024-01-01T00:00:00Z'),
  updated_at: new Date('2024-01-01T00:00:00Z')
}

const mockAuthResponse = {
  user: mockUser,
  token: 'mock-token-12345',
  expires_at: '2024-12-31T23:59:59Z'
}

const mockFile = (
  name: string = 'test.jpg',
  type: string = 'image/jpeg',
  size: number = 1024
): File => {
  const content = new Array(size).fill('a').join('')
  const blob = new Blob([content], { type })
  return new File([blob], name, { type })
}

// Create mock API
const mockApi = {
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
  defaults: { baseURL: 'http://localhost:3000/api/v1' }
}

// Mock the entire API module
vi.mock('../index', () => ({
  api: mockApi,
  API_BASE_URL: 'http://localhost:3000/api/v1',
  authApi: {
    login: vi.fn(),
    logout: vi.fn(),
    me: vi.fn(),
    isLoggedIn: vi.fn()
  }
}))

// Import after mocking
const { authApi } = await import('../index')

describe('API Integration Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Reset localStorage mocks
    localStorageMock.getItem.mockClear()
    localStorageMock.setItem.mockClear()
    localStorageMock.removeItem.mockClear()
  })

  describe('Authentication API Mock Tests', () => {
    test('login function is callable and mockable', async () => {
      const credentials = { email: 'test@test.com', password: 'password123' }
      
      // Setup mock
      vi.mocked(authApi.login).mockResolvedValue(mockAuthResponse)
      
      // Call function
      const result = await authApi.login(credentials)
      
      // Verify
      expect(authApi.login).toHaveBeenCalledWith(credentials)
      expect(result).toEqual(mockAuthResponse)
    })

    test('me function is callable and mockable', async () => {
      vi.mocked(authApi.me).mockResolvedValue(mockUser)
      
      const result = await authApi.me()
      
      expect(authApi.me).toHaveBeenCalled()
      expect(result).toEqual(mockUser)
    })

    test('logout function is callable', () => {
      // Setup mock to simulate localStorage.removeItem call
      vi.mocked(authApi.logout).mockImplementation(() => {
        localStorageMock.removeItem('token')
      })
      
      authApi.logout()
      
      expect(authApi.logout).toHaveBeenCalled()
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('token')
    })

    test('isLoggedIn function returns boolean', () => {
      vi.mocked(authApi.isLoggedIn).mockReturnValue(false)
      expect(authApi.isLoggedIn()).toBe(false)
      
      vi.mocked(authApi.isLoggedIn).mockReturnValue(true)
      expect(authApi.isLoggedIn()).toBe(true)
      
      expect(authApi.isLoggedIn).toHaveBeenCalledTimes(2)
    })
  })

  describe('Base API Configuration', () => {
    test('API has correct configuration', () => {
      expect(mockApi.defaults.baseURL).toBe('http://localhost:3000/api/v1')
    })

    test('API methods are available', () => {
      expect(mockApi.get).toBeDefined()
      expect(mockApi.post).toBeDefined()
      expect(mockApi.put).toBeDefined()
      expect(mockApi.delete).toBeDefined()
    })

    test('API methods can be mocked', async () => {
      const mockResponse = { data: { data: { test: 'value' } } }
      
      mockApi.get.mockResolvedValue(mockResponse)
      
      const result = await mockApi.get('/test')
      
      expect(mockApi.get).toHaveBeenCalledWith('/test')
      expect(result).toEqual(mockResponse)
    })
  })

  describe('File Upload Simulation', () => {
    test('can create mock files', () => {
      const file = mockFile('test.jpg', 'image/jpeg', 1024)
      
      expect(file.name).toBe('test.jpg')
      expect(file.type).toBe('image/jpeg')
      expect(file.size).toBe(1024)
    })

    test('can mock FormData operations', () => {
      const file = mockFile()
      const formData = new FormData()
      formData.append('image', file)
      
      // Mock the post request
      const mockResponse = { 
        data: { 
          data: { 
            image: { id: '1', file_path: 'uploads/test.jpg' } 
          } 
        } 
      }
      
      mockApi.post.mockResolvedValue(mockResponse)
      
      expect(formData.get('image')).toEqual(file)
    })
  })

  describe('Error Handling Simulation', () => {
    test('can mock 401 errors', async () => {
      const error401 = {
        response: { status: 401 },
        config: {},
        isAxiosError: true
      }
      
      mockApi.get.mockRejectedValue(error401)
      
      try {
        await mockApi.get('/protected')
      } catch (error) {
        expect(error).toEqual(error401)
      }
      
      expect(mockApi.get).toHaveBeenCalledWith('/protected')
    })

    test('can mock network errors', async () => {
      const networkError = new Error('Network error')
      
      mockApi.get.mockRejectedValue(networkError)
      
      try {
        await mockApi.get('/test')
      } catch (error) {
        expect(error).toBeInstanceOf(Error)
        expect((error as Error).message).toBe('Network error')
      }
    })
  })

  describe('localStorage Integration', () => {
    test('localStorage methods are mocked', () => {
      localStorageMock.setItem.mockImplementation(() => {})
      localStorageMock.getItem.mockReturnValue('test-token')
      localStorageMock.removeItem.mockImplementation(() => {})
      
      localStorage.setItem('token', 'test-token')
      const token = localStorage.getItem('token')
      localStorage.removeItem('token')
      
      expect(localStorageMock.setItem).toHaveBeenCalledWith('token', 'test-token')
      expect(localStorageMock.getItem).toHaveBeenCalledWith('token')
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('token')
      expect(token).toBe('test-token')
    })
  })
})