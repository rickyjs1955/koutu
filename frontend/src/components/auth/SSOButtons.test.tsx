// frontend/src/components/auth/SSOButtons.test.tsx
import React from 'react';
import { render, screen } from '@testing-library/react';
import SSOButtons from './SSOButtons';

// Mock the env utility function
jest.mock('../../utils/env', () => ({
  getApiBaseUrl: jest.fn().mockReturnValue('http://localhost:3000/api/v1')
}));

describe('SSOButtons', () => {
  test('renders OAuth provider buttons', () => {
    render(<SSOButtons />);
    
    // Check if the component renders properly
    expect(screen.getByText(/Or continue with/i)).toBeInTheDocument();
    
    // Check if all provider buttons are rendered
    const buttons = screen.getAllByRole('link');
    expect(buttons).toHaveLength(3); // Google, Microsoft, GitHub
    
    // Check if the buttons have the correct hrefs
    const googleButton = buttons[0];
    const microsoftButton = buttons[1];
    const githubButton = buttons[2];
    
    expect(googleButton.getAttribute('href')).toContain('/oauth/google/authorize');
    expect(microsoftButton.getAttribute('href')).toContain('/oauth/microsoft/authorize');
    expect(githubButton.getAttribute('href')).toContain('/oauth/github/authorize');
  });

  test('includes redirect URL when provided', () => {
    const redirectUrl = '/dashboard';
    render(<SSOButtons redirectUrl={redirectUrl} />);
    
    const googleButton = screen.getAllByRole('link')[0];
    expect(googleButton.getAttribute('href')).toContain(`redirect=${encodeURIComponent(redirectUrl)}`);
  });
});