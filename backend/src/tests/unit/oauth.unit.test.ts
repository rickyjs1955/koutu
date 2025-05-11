// /backend/src/tests/unit/oauth.unit.test.ts

import { jest } from '@jest/globals';

// Mock the config before importing the module under test
jest.mock('../../../src/config/index', () => ({
    config: {
        appUrl: 'http://localhost:3000',
        oauth: {
        googleClientId: 'google-client-id',
        googleClientSecret: 'google-client-secret',
        microsoftClientId: 'microsoft-client-id',
        microsoftClientSecret: 'microsoft-client-secret',
        githubClientId: 'github-client-id',
        githubClientSecret: 'github-client-secret',
        }
    }
}));

// Import the module after mocking its dependencies
import { oauthConfig, getAuthorizationUrl } from '../../../src/config/oauth';

/**
 * OAuth Configuration Unit Tests
 * 
 * This test suite verifies the OAuth configuration module functionality:
 * - Validates the structure and content of OAuth provider configurations
 * - Tests URL generation for authorization endpoints
 * - Ensures proper parameter encoding in authorization URLs
 * - Verifies graceful handling of missing configurations
 * 
 * The tests use Jest's mocking capabilities to simulate different configuration scenarios.
 * Dependencies are mocked to isolate the module under test and provide controlled test conditions.
 */

describe('OAuth Configuration', () => {
    describe('oauthConfig object', () => {
        test('should contain configurations for all providers', () => {
            expect(oauthConfig).toHaveProperty('google');
            expect(oauthConfig).toHaveProperty('microsoft');
            expect(oauthConfig).toHaveProperty('github');
        });

        test('should have correct Google OAuth configuration', () => {
            expect(oauthConfig.google).toMatchObject({
                clientId: 'google-client-id',
                clientSecret: 'google-client-secret',
                redirectUri: 'http://localhost:3000/api/v1/oauth/google/callback',
                scope: 'email profile',
                authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
                tokenUrl: 'https://oauth2.googleapis.com/token',
                userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
            });
        });

        test('should have correct Microsoft OAuth configuration', () => {
            expect(oauthConfig.microsoft).toMatchObject({
                clientId: 'microsoft-client-id',
                clientSecret: 'microsoft-client-secret',
                redirectUri: 'http://localhost:3000/api/v1/oauth/microsoft/callback',
                scope: 'openid profile email',
                authUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
                userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
            });
        });

        test('should have correct GitHub OAuth configuration', () => {
            expect(oauthConfig.github).toMatchObject({
                clientId: 'github-client-id',
                clientSecret: 'github-client-secret',
                redirectUri: 'http://localhost:3000/api/v1/oauth/github/callback',
                scope: 'read:user user:email',
                authUrl: 'https://github.com/login/oauth/authorize',
                tokenUrl: 'https://github.com/login/oauth/access_token',
                userInfoUrl: 'https://api.github.com/user',
            });
        });

        test('should handle missing OAuth configuration gracefully', () => {
            // Save the original module and reset mocks
            jest.resetModules();
            
            // Mock with empty OAuth config
            jest.mock('../../../src/config/index', () => ({
                config: {
                appUrl: 'http://localhost:3000',
                oauth: undefined
                }
            }));
            
            // Re-import to get the updated module
            const { oauthConfig: emptyOauthConfig } = require('../../../src/config/oauth');
            
            expect(emptyOauthConfig.google.clientId).toBe('');
            expect(emptyOauthConfig.microsoft.clientId).toBe('');
            expect(emptyOauthConfig.github.clientId).toBe('');
            
            // Clean up
            jest.resetModules();
        });
    });

    describe('getAuthorizationUrl function', () => {
        test('should generate correct authorization URL for Google', () => {
            const state = 'random-state-value';
            const url = getAuthorizationUrl('google', state);
            
            expect(url).toContain('https://accounts.google.com/o/oauth2/v2/auth');
            expect(url).toContain('client_id=google-client-id');
            expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fv1%2Foauth%2Fgoogle%2Fcallback');
            expect(url).toContain('response_type=code');
            expect(url).toContain('scope=email+profile');
            expect(url).toContain(`state=${state}`);
        });

        test('should generate correct authorization URL for Microsoft', () => {
            const state = 'random-state-value';
            const url = getAuthorizationUrl('microsoft', state);
            
            expect(url).toContain('https://login.microsoftonline.com/common/oauth2/v2.0/authorize');
            expect(url).toContain('client_id=microsoft-client-id');
            expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fv1%2Foauth%2Fmicrosoft%2Fcallback');
            expect(url).toContain('response_type=code');
            expect(url).toContain('scope=openid+profile+email');
            expect(url).toContain(`state=${state}`);
        });

        test('should generate correct authorization URL for GitHub', () => {
            const state = 'random-state-value';
            const url = getAuthorizationUrl('github', state);
            
            expect(url).toContain('https://github.com/login/oauth/authorize');
            expect(url).toContain('client_id=github-client-id');
            expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fv1%2Foauth%2Fgithub%2Fcallback');
            expect(url).toContain('response_type=code');
            expect(url).toContain('scope=read%3Auser+user%3Aemail');
            expect(url).toContain(`state=${state}`);
        });

        test('should encode parameters correctly in the URL', () => {
            const state = 'state with spaces & special chars';
            const url = getAuthorizationUrl('google', state);
            
            // Instead of checking for exact encoding, verify the state parameter exists
            // and can be properly decoded
            const urlObj = new URL(url);
            const params = new URLSearchParams(urlObj.search);
            expect(params.get('state')).toBe(state);
            
            // Alternatively, check with the correct encoding for URLSearchParams
            const encodedStateForUrlParams = state.replace(/ /g, '+').replace(/&/g, '%26');
            expect(url).toContain(`state=${encodedStateForUrlParams}`);
        });
    });
});