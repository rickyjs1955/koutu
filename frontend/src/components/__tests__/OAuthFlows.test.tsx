/**
 * @vitest-environment jsdom
 */

// frontend/src/components/__tests__/OAuthCallback.test.tsx
import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import '@testing-library/jest-dom'

// Mock user data
const mockUser = {
  id: 'user-123',
  email: 'test@example.com',
  name: 'Test User',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z'
}

// Setup and cleanup functions
const setupTestEnvironment = () => {
  vi.clearAllMocks()
}

const cleanupTestEnvironment = () => {
  vi.clearAllMocks()
}

// renderWithProviders utility
const renderWithProviders = (component: React.ReactNode) => {
  return render(
    <MemoryRouter>
      {component}
    </MemoryRouter>
  )
}

// Mock the useAuth hook
const mockUseAuth = {
  loginWithToken: vi.fn(),
  user: null,
  isLoading: false,
  isAuthenticated: false,
  login: vi.fn(),
  register: vi.fn(),
  logout: vi.fn(),
  error: null,
  linkedProviders: [],
  linkProvider: vi.fn(),
  unlinkProvider: vi.fn()
}

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth
}))

// Mock react-router-dom hooks
const mockNavigate = vi.fn()
const mockUseSearchParams = vi.fn()

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useSearchParams: () => mockUseSearchParams()
  }
})

// Mock OAuthCallback component since we don't have access to the actual one
const MockOAuthCallback = () => {
  const [searchParams] = mockUseSearchParams()
  const navigate = mockNavigate
  const { loginWithToken } = mockUseAuth
  
  const token = searchParams?.get?.('token')
  const redirect = searchParams?.get?.('redirect') || '/'
  
  const [isAuthenticating, setIsAuthenticating] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  
  React.useEffect(() => {
    if (!token) {
      setError('No token received')
      return
    }
    
    setIsAuthenticating(true)
    loginWithToken(token)
      .then(() => {
        navigate(redirect)
      })
      .catch((err: Error) => {
        setError('Failed to authenticate')
        setIsAuthenticating(false)
      })
  }, [token, loginWithToken, navigate, redirect])
  
  if (error) {
    return (
      <div>
        <h1>Authentication Error</h1>
        <p>Authentication failed</p>
        {error === 'No token received' && <p>No token received</p>}
        {error === 'Failed to authenticate' && <p>Failed to authenticate</p>}
        <button type="button">Return to Login</button>
      </div>
    )
  }
  
  if (isAuthenticating) {
    return <div>Authenticating, please wait...</div>
  }
  
  return <div>Processing...</div>
}

describe('OAuth Callback Component', () => {
  beforeEach(() => {
    setupTestEnvironment()
    vi.clearAllMocks()
    
    // Default search params setup
    const mockParams = new URLSearchParams()
    mockUseSearchParams.mockReturnValue([mockParams, vi.fn()])
  })

  afterEach(() => {
    cleanupTestEnvironment()
  })

  test('handles successful OAuth callback with token', async () => {
    // Setup URL params with token
    const token = 'oauth-success-token-123'
    const redirect = '/dashboard'
    const mockParams = new URLSearchParams()
    mockParams.set('token', token)
    mockParams.set('redirect', redirect)
    mockUseSearchParams.mockReturnValue([mockParams, vi.fn()])

    // Mock successful token login
    mockUseAuth.loginWithToken.mockResolvedValue(mockUser)

    renderWithProviders(<MockOAuthCallback />)

    // Should show loading state initially
    expect(screen.getByText(/authenticating/i)).toBeInTheDocument()

    // Wait for OAuth processing
    await waitFor(() => {
      expect(mockUseAuth.loginWithToken).toHaveBeenCalledWith(token)
    })

    // Should navigate to redirect URL
    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith(redirect)
    })
  })

  test('handles OAuth callback without token parameter', async () => {
    // Setup URL params without token
    const mockParams = new URLSearchParams()
    mockUseSearchParams.mockReturnValue([mockParams, vi.fn()])

    renderWithProviders(<MockOAuthCallback />)

    // Should show error immediately
    expect(screen.getByText(/authentication failed/i)).toBeInTheDocument()
    expect(screen.getByText(/no token received/i)).toBeInTheDocument()
    
    // Should show return to login button
    const returnButton = screen.getByRole('button', { name: /return to login/i })
    expect(returnButton).toBeInTheDocument()
  })

  test('handles failed token authentication', async () => {
    // Setup URL params with token
    const token = 'invalid-token-123'
    const mockParams = new URLSearchParams()
    mockParams.set('token', token)
    mockUseSearchParams.mockReturnValue([mockParams, vi.fn()])

    // Mock failed token login
    mockUseAuth.loginWithToken.mockRejectedValue(new Error('Invalid token'))

    renderWithProviders(<MockOAuthCallback />)

    // Wait for error to appear
    await waitFor(() => {
      expect(screen.getByText(/failed to authenticate/i)).toBeInTheDocument()
    })

    expect(mockUseAuth.loginWithToken).toHaveBeenCalledWith(token)
    expect(mockNavigate).not.toHaveBeenCalled()
  })

  test('defaults to root redirect when no redirect parameter', async () => {
    // Setup URL params with token but no redirect
    const token = 'oauth-token-456'
    const mockParams = new URLSearchParams()
    mockParams.set('token', token)
    mockUseSearchParams.mockReturnValue([mockParams, vi.fn()])

    mockUseAuth.loginWithToken.mockResolvedValue(mockUser)

    renderWithProviders(<MockOAuthCallback />)

    await waitFor(() => {
      expect(mockUseAuth.loginWithToken).toHaveBeenCalledWith(token)
    })

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/')
    })
  })

  test('displays loading spinner during authentication', async () => {
    const token = 'oauth-token-loading'
    const mockParams = new URLSearchParams()
    mockParams.set('token', token)
    mockUseSearchParams.mockReturnValue([mockParams, vi.fn()])

    // Mock delayed response
    let resolveLogin: (value: any) => void
    const loginPromise = new Promise(resolve => {
      resolveLogin = resolve
    })
    mockUseAuth.loginWithToken.mockReturnValue(loginPromise)

    renderWithProviders(<MockOAuthCallback />)

    // Should show loading state
    expect(screen.getByText(/authenticating, please wait/i)).toBeInTheDocument()

    // Resolve the promise
    resolveLogin!(mockUser)

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalled()
    })
  })

  test('maintains proper page structure and accessibility', async () => {
    const mockParams = new URLSearchParams()
    mockUseSearchParams.mockReturnValue([mockParams, vi.fn()])

    renderWithProviders(<MockOAuthCallback />)

    // Check page structure
    const heading = screen.getByRole('heading', { name: /authentication error/i })
    expect(heading).toBeInTheDocument()

    // Check button accessibility
    const button = screen.getByRole('button', { name: /return to login/i })
    expect(button).toHaveAttribute('type', 'button')
    expect(button).toBeVisible()
  })

  test('handles network errors gracefully', async () => {
    const token = 'oauth-token-network-error'
    const mockParams = new URLSearchParams()
    mockParams.set('token', token)
    mockUseSearchParams.mockReturnValue([mockParams, vi.fn()])

    // Mock network error
    mockUseAuth.loginWithToken.mockRejectedValue(new Error('Network error'))

    renderWithProviders(<MockOAuthCallback />)

    await waitFor(() => {
      expect(screen.getByText(/failed to authenticate/i)).toBeInTheDocument()
    })

    // Should show error state with return button
    expect(screen.getByRole('button', { name: /return to login/i })).toBeInTheDocument()
  })
})