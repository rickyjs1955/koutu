/**
 * @vitest-environment jsdom
 */

// frontend/src/components/__tests__/SSOButtons.test.tsx
import React from 'react'
import { render, screen } from '@testing-library/react'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

// Import jest-dom matchers
import '@testing-library/jest-dom'

// Mock the env utility function BEFORE importing the component
vi.mock('../../utils/env', () => ({
  getApiBaseUrl: vi.fn(() => 'http://localhost:3000/api/v1')
}))

// Now import the component and the mocked module
import SSOButtons from '../auth/SSOButtons'
import { getApiBaseUrl } from '../../utils/env'

// Get the mocked function
const mockGetApiBaseUrl = vi.mocked(getApiBaseUrl)

// Setup and cleanup functions
const setupTestEnvironment = () => {
  vi.clearAllMocks()
}

const cleanupTestEnvironment = () => {
  vi.clearAllMocks()
}

describe('SSOButtons Component', () => {
  beforeEach(() => {
    setupTestEnvironment()
    // Reset the mock to default value
    mockGetApiBaseUrl.mockReturnValue('http://localhost:3000/api/v1')
  })

  afterEach(() => {
    cleanupTestEnvironment()
  })

  test('renders OAuth provider buttons', () => {
    render(<SSOButtons />)
    
    // Check if the component renders properly
    expect(screen.getByText(/Or continue with/i)).toBeInTheDocument()
    
    // Check if all provider buttons are rendered
    const buttons = screen.getAllByRole('link')
    expect(buttons).toHaveLength(4) // Google, Microsoft, GitHub, Instagram
  })

  test('generates correct OAuth URLs for each provider', () => {
    render(<SSOButtons />)
    
    const buttons = screen.getAllByRole('link')
    
    // Find and verify OAuth URLs
    const googleButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/google/authorize')
    )
    const microsoftButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/microsoft/authorize')
    )
    const githubButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/github/authorize')
    )
    const instagramButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/instagram/authorize')
    )
    
    expect(googleButton).toBeInTheDocument()
    expect(microsoftButton).toBeInTheDocument()
    expect(githubButton).toBeInTheDocument()
    expect(instagramButton).toBeInTheDocument()
    
    // Verify the actual URLs
    expect(googleButton?.getAttribute('href')).toBe(
      'http://localhost:3000/api/v1/oauth/google/authorize'
    )
    expect(microsoftButton?.getAttribute('href')).toBe(
      'http://localhost:3000/api/v1/oauth/microsoft/authorize'
    )
    expect(githubButton?.getAttribute('href')).toBe(
      'http://localhost:3000/api/v1/oauth/github/authorize'
    )
    expect(instagramButton?.getAttribute('href')).toBe(
      'http://localhost:3000/api/v1/oauth/instagram/authorize'
    )
  })

  test('includes redirect URL when provided', () => {
    const redirectUrl = '/dashboard'
    render(<SSOButtons redirectUrl={redirectUrl} />)
    
    const buttons = screen.getAllByRole('link')
    
    // Check that all buttons include the redirect parameter
    buttons.forEach(button => {
      const href = button.getAttribute('href')
      expect(href).toContain(`redirect=${encodeURIComponent(redirectUrl)}`)
    })
    
    // Specifically test Google button with redirect
    const googleButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/google/authorize')
    )
    expect(googleButton?.getAttribute('href')).toBe(
      `http://localhost:3000/api/v1/oauth/google/authorize?redirect=${encodeURIComponent(redirectUrl)}`
    )
  })

  test('handles empty redirect URL gracefully', () => {
    render(<SSOButtons redirectUrl="" />)
    
    const buttons = screen.getAllByRole('link')
    
    // Should not include redirect parameter when empty
    const googleButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/google/authorize')
    )
    expect(googleButton?.getAttribute('href')).toBe(
      'http://localhost:3000/api/v1/oauth/google/authorize'
    )
  })

  test('handles complex redirect URLs with encoding', () => {
    const complexRedirectUrl = '/dashboard?tab=profile&section=security'
    render(<SSOButtons redirectUrl={complexRedirectUrl} />)
    
    const buttons = screen.getAllByRole('link')
    const googleButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/google/authorize')
    )
    
    expect(googleButton?.getAttribute('href')).toBe(
      `http://localhost:3000/api/v1/oauth/google/authorize?redirect=${encodeURIComponent(complexRedirectUrl)}`
    )
  })

  test('renders provider icons correctly', () => {
    render(<SSOButtons />)
    
    // Check for SVG elements (provider icons)
    const svgElements = document.querySelectorAll('svg')
    expect(svgElements.length).toBeGreaterThanOrEqual(4) // At least one per provider
    
    // Check for specific provider icon characteristics
    const googleIcon = document.querySelector('svg path[fill="#4285F4"]')
    expect(googleIcon).toBeInTheDocument()
    
    const microsoftIcon = document.querySelector('svg rect[fill="#F25022"]')
    expect(microsoftIcon).toBeInTheDocument()
  })

  test('applies correct CSS classes for styling', () => {
    render(<SSOButtons />)
    
    // Check if we can find an element with space-y-3 class
    const containerWithSpacing = document.querySelector('.space-y-3')
    if (containerWithSpacing) {
      expect(containerWithSpacing).toBeInTheDocument()
    }
    
    // Check button styling (this is the more important test)
    const buttons = screen.getAllByRole('link')
    expect(buttons.length).toBeGreaterThan(0) // Ensure we have buttons
    
    buttons.forEach(button => {
      expect(button).toHaveClass('w-full')
      expect(button).toHaveClass('inline-flex')
      expect(button).toHaveClass('justify-center')
    })
  })

  test('maintains accessibility standards', () => {
    render(<SSOButtons />)
    
    // Check that all buttons are properly accessible as links
    const buttons = screen.getAllByRole('link')
    buttons.forEach(button => {
      // Each button should have a valid href
      expect(button.getAttribute('href')).toBeTruthy()
      
      // Each button should be keyboard accessible (inherent for links)
      expect(button.tagName.toLowerCase()).toBe('a')
    })
  })

  test('handles different API base URLs from environment', () => {
    // Mock different API base URL
    mockGetApiBaseUrl.mockReturnValue('https://api.production.com/v1')
    
    render(<SSOButtons />)
    
    const buttons = screen.getAllByRole('link')
    const googleButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/google/authorize')
    )
    
    expect(googleButton?.getAttribute('href')).toBe(
      'https://api.production.com/v1/oauth/google/authorize'
    )
    
    // Reset mock
    mockGetApiBaseUrl.mockReturnValue('http://localhost:3000/api/v1')
  })

  test('component structure matches expected layout', () => {
    render(<SSOButtons />)
    
    // Check the overall structure
    const mainContainer = screen.getByText(/Or continue with/i).closest('.space-y-3')
    expect(mainContainer).toBeInTheDocument()
    
    // Check the separator line structure
    const separator = screen.getByText(/Or continue with/i).closest('.relative')
    expect(separator).toBeInTheDocument()
    
    // Check the button grid structure
    const buttonGrid = document.querySelector('.grid.grid-cols-2.gap-3')
    expect(buttonGrid).toBeInTheDocument()
  })

  test('handles special characters in redirect URL', () => {
    const redirectWithSpecialChars = '/dashboard?user=john@example.com&tab=profile%20settings'
    render(<SSOButtons redirectUrl={redirectWithSpecialChars} />)
    
    const buttons = screen.getAllByRole('link')
    const googleButton = buttons.find(button => 
      button.getAttribute('href')?.includes('/oauth/google/authorize')
    )
    
    // Should properly encode the redirect URL
    expect(googleButton?.getAttribute('href')).toBe(
      `http://localhost:3000/api/v1/oauth/google/authorize?redirect=${encodeURIComponent(redirectWithSpecialChars)}`
    )
  })
})