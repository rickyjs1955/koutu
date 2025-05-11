// filepath: /backend/src/tests/security/oauth.security.test.ts

/**
 * OAuth Security Test Suite
 *
 * This test suite focuses on security aspects of the OAuth configuration:
 * - Ensures that sensitive parameters like client secrets are not exposed in authorization URLs.
 * - Validates that all required URL parameters are present and properly encoded.
 * - Checks that malicious inputs in the state parameter are safely handled to prevent injection attacks.
 */

import { oauthConfig, getAuthorizationUrl } from '../../config/oauth';

describe('OAuth Security Tests', () => {
    const providers: Array<'google' | 'microsoft' | 'github'> = ['google', 'microsoft', 'github'];

    test('should not expose client secret in authorization URL', () => {
        providers.forEach((provider) => {
        const state = 'secure-state';
        const url = getAuthorizationUrl(provider, state);
        // Ensure URL does not include "client_secret" as a parameter
        expect(url).not.toMatch(/client_secret=/);
        // Also check that essential parameters are in place
        expect(url).toContain(oauthConfig[provider].authUrl);
        expect(url).toContain(`client_id=${oauthConfig[provider].clientId}`);
        expect(url).toContain(`redirect_uri=${encodeURIComponent(oauthConfig[provider].redirectUri)}`);
        expect(url).toContain('response_type=code');
        expect(url).toContain(`state=${state}`);
        });
    });

    test('should properly encode malicious state to prevent injection attacks', () => {
        const maliciousState = "malicious?state=<script>alert('xss')</script>";
        const url = getAuthorizationUrl('google', maliciousState);
        // Parse the URL to extract search parameters
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);
        expect(params.get('state')).toBe(maliciousState);
        // Ensure the raw malicious string is not present in the URL (it should be encoded)
        expect(url).not.toContain(maliciousState);
    });

    test('should only include expected query parameters in the authorization URL', () => {
        providers.forEach((provider) => {
        const state = 'test-state-for-params';
        const url = getAuthorizationUrl(provider, state);
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);

        const actualParamKeys = Array.from(params.keys()).sort();
        const expectedParamKeys = ['client_id', 'redirect_uri', 'response_type', 'scope', 'state'].sort();

        expect(actualParamKeys).toEqual(expectedParamKeys);
        });
    });

    test('should handle empty state parameter gracefully', () => {
        providers.forEach((provider) => {
        const url = getAuthorizationUrl(provider, '');
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);
        
        // State should be present but empty
        expect(params.has('state')).toBe(true);
        expect(params.get('state')).toBe('');
        });
    });

    test('should handle extremely long state parameters', () => {
        // Create a very long state string (e.g., 2KB)
        const longState = 'A'.repeat(2048);
        
        providers.forEach((provider) => {
        const url = getAuthorizationUrl(provider, longState);
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);
        
        // State should be preserved completely
        expect(params.get('state')).toBe(longState);
        
        // URL should still be valid (not truncated)
        expect(url.length).toBeGreaterThan(2048);
        });
    });

    test('should use the exact scopes defined in config', () => {
        providers.forEach((provider) => {
        const url = getAuthorizationUrl(provider, 'test-state');
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);
        
        // Verify that the scope in the URL exactly matches the configured scope
        expect(params.get('scope')).toBe(oauthConfig[provider].scope);
        });
    });

    test('should properly encode redirect_uri parameter to prevent open redirects', () => {
        providers.forEach((provider) => {
        const url = getAuthorizationUrl(provider, 'test-state');
        const urlObj = new URL(url);
        const params = new URLSearchParams(urlObj.search);
        
        // Get the redirect_uri from the URL
        const redirectUri = params.get('redirect_uri');
        
        // Ensure redirect_uri exists
        expect(redirectUri).not.toBeNull();
        
        if (redirectUri) {
            // The redirect_uri should match the configured value
            expect(decodeURIComponent(redirectUri)).toBe(oauthConfig[provider].redirectUri);
            
            // Ensure the redirect_uri doesn't contain any unencoded special characters
            expect(redirectUri).not.toMatch(/[&?=#]/);
        }
        });
    });
});