/**
 * Utility functions for environment variables that work in both browser and test environments
 */

/**
 * Get the API base URL from environment variables
 * This function is test-friendly as it doesn't directly use import.meta.env
 */
export function getApiBaseUrl(): string {
    // For the browser environment using Vite
    if (typeof import.meta !== 'undefined' && import.meta.env) {
      return import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000/api/v1';
    }
    
    // For test environment
    return process.env.VITE_API_BASE_URL || 'http://localhost:3000/api/v1';
  }