// /backend/src/tests/unit/oauth.unit.test.ts

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
            
            // Alternatively, check with the encoding replacement used by URLSearchParams
            const encodedStateForUrlParams = state.replace(/ /g, '+').replace(/&/g, '%26');
            expect(url).toContain(`state=${encodedStateForUrlParams}`);
        });

        test('should generate correct authorization URL for Microsoft with empty state', () => {
            const state = '';
            const url = getAuthorizationUrl('microsoft', state);
            
            const urlObj = new URL(url);
            const params = new URLSearchParams(urlObj.search);
            expect(params.get('state')).toBe(state);
        });

        test('should throw an error or handle invalid provider gracefully', () => {
            const state = 'test-state';
            // Use @ts-expect-error to acknowledge the deliberate type error for testing purposes
            // @ts-expect-error
            expect(() => getAuthorizationUrl('unknownprovider', state)).toThrow();
            // Depending on desired behavior, you might expect a specific error type or message.
            // For example: .toThrow(TypeError); or .toThrow("Cannot read properties of undefined (reading 'clientId')");
        });

        test('should handle missing appUrl in config for redirectUri generation', () => {
            jest.isolateModules(() => {
                // This mock is scoped to this isolateModules block
                jest.mock('../../../src/config/index', () => ({
                    config: {
                        // appUrl is intentionally missing
                        oauth: {
                            googleClientId: 'google-client-id', // You can use distinct values to be extra sure
                            googleClientSecret: 'google-client-secret',
                            // Ensure other providers are also defined if getAuthorizationUrl is called with them
                            microsoftClientId: 'microsoft-client-id',
                            microsoftClientSecret: 'microsoft-client-secret',
                            githubClientId: 'github-client-id',
                            githubClientSecret: 'github-client-secret',
                        }
                    }
                }));

                // Requiring the module inside isolateModules ensures it gets the above mock
                const { oauthConfig: updatedOauthConfig, getAuthorizationUrl: updatedGetAuthorizationUrl } = require('../../../src/config/oauth');

                // Check how redirectUri is formed in oauthConfig when appUrl is missing
                // For `${undefined}/path` it becomes "undefined/path"
                expect(updatedOauthConfig.google.redirectUri).toBe('undefined/api/v1/oauth/google/callback');

                const state = 'test-state-no-app-url';
                const url = updatedGetAuthorizationUrl('google', state);
                
                // The redirect_uri parameter in the URL should reflect the malformed redirectUri
                const expectedRedirectUri = encodeURIComponent('undefined/api/v1/oauth/google/callback');
                expect(url).toContain(`redirect_uri=${expectedRedirectUri}`);
            });
            // Note: jest.isolateModules handles the reset.
            // The top-level mock for '../../../src/config/index' will apply to other tests outside this block.
        });
    });
});