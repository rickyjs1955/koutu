// src/__tests__/testUtils.ts
import { vi } from 'vitest'

export const setupTestEnvironment = () => {
  // Clear all mocks before each test
  vi.clearAllMocks()
  
  // Reset localStorage
  if (typeof localStorage !== 'undefined') {
    localStorage.clear()
  }
  
  // Reset any global state if needed
}

export const cleanupTestEnvironment = () => {
  // Clean up after each test
  vi.clearAllMocks()
  if (typeof localStorage !== 'undefined') {
    localStorage.clear()
  }
}

export const mockFile = (
  name: string = 'test.jpg',
  type: string = 'image/jpeg',
  size: number = 1024
): File => {
  const content = new Array(size).fill('a').join('')
  const blob = new Blob([content], { type })
  return new File([blob], name, { type })
}

export const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  name: 'Test User',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z'
}

export const mockAuthResponse = {
  user: mockUser,
  token: 'mock-token-12345',
  expires_at: '2024-12-31T23:59:59Z'
}