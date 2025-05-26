// filepath: /backend/src/tests/integration/oauth.int.test.ts

import { URL } from 'url';

/**
 * Integration Test Suite for OAuth Configuration
 *
 * This suite verifies the integration of OAuth configuration and authorization URL generation.
 * It ensures that environment variables are respected, default values are used when needed,
 * and all supported providers generate correct, distinct, and robust authorization URLs.
 * The tests also check for proper parameter encoding, error handling, and edge case handling.
 */

// Note: Actual imports of oauthConfig and getAuthorizationUrl will be done
// within jest.isolateModules to ensure fresh state based on process.env changes.

describe('OAuth Integration Tests', () => {
    let originalEnv: NodeJS.ProcessEnv;

    beforeAll(() => {
        originalEnv = { ...process.env };
    });

    beforeEach(() => {
        process.env = { ...originalEnv };
    });

    afterEach(() => {
        process.env = { ...originalEnv };
        jest.resetModules();
    });

    describe('oauthConfig object - Integration', () => {
        test('should use default client IDs and redirect URIs based on default appUrl when relevant environment variables are not set', () => {
            // Clear relevant OAuth and App URL environment variables
            delete process.env.APP_URL;
            delete process.env.PORT; // To ensure default port 3000 is used in appUrl from config/index
            delete process.env.GOOGLE_CLIENT_ID;
            delete process.env.GOOGLE_CLIENT_SECRET;
            delete process.env.MICROSOFT_CLIENT_ID;
            delete process.env.MICROSOFT_CLIENT_SECRET;
            delete process.env.GITHUB_CLIENT_ID;
            delete process.env.GITHUB_CLIENT_SECRET;

            jest.isolateModules(() => {
                const { config: appConfig } = require('../../config/index');
                const { oauthConfig } = require('../../config/oauth');
                // The config/index module will provide the default appUrl.
                // Assuming default PORT is 3000 if not set.
                const expectedDefaultAppUrl = appConfig.appUrl; // This will be 'http://localhost:3000' or similar by default

                // Assert Google config
                expect(oauthConfig.google.clientId).toBe('');
                expect(oauthConfig.google.clientSecret).toBe('');
                expect(oauthConfig.google.redirectUri).toBe(`${expectedDefaultAppUrl}/api/v1/oauth/google/callback`);

                // Assert Microsoft config
                expect(oauthConfig.microsoft.clientId).toBe('');
                expect(oauthConfig.microsoft.clientSecret).toBe('');
                expect(oauthConfig.microsoft.redirectUri).toBe(`${expectedDefaultAppUrl}/api/v1/oauth/microsoft/callback`);

                // Assert GitHub config
                expect(oauthConfig.github.clientId).toBe('');
                expect(oauthConfig.github.clientSecret).toBe('');
                expect(oauthConfig.github.redirectUri).toBe(`${expectedDefaultAppUrl}/api/v1/oauth/github/callback`);
            });
        });

        test('should use values from environment variables for client IDs, secrets, and redirect URIs when set', () => {
            // Set mock environment variables
            const testAppUrl = 'https://test-app.example.com';
            process.env.APP_URL = testAppUrl;
            process.env.GOOGLE_CLIENT_ID = 'env-google-id-123';
            process.env.GOOGLE_CLIENT_SECRET = 'env-google-secret-xyz';
            process.env.MICROSOFT_CLIENT_ID = 'env-microsoft-id-456';
            process.env.MICROSOFT_CLIENT_SECRET = 'env-microsoft-secret-abc';
            process.env.GITHUB_CLIENT_ID = 'env-github-id-789';
            process.env.GITHUB_CLIENT_SECRET = 'env-github-secret-def';

            jest.isolateModules(() => {
                const { oauthConfig } = require('../../config/oauth');

                // Assert Google config
                expect(oauthConfig.google.clientId).toBe('env-google-id-123');
                expect(oauthConfig.google.clientSecret).toBe('env-google-secret-xyz');
                expect(oauthConfig.google.redirectUri).toBe(`${testAppUrl}/api/v1/oauth/google/callback`);

                // Assert Microsoft config
                expect(oauthConfig.microsoft.clientId).toBe('env-microsoft-id-456');
                expect(oauthConfig.microsoft.clientSecret).toBe('env-microsoft-secret-abc');
                expect(oauthConfig.microsoft.redirectUri).toBe(`${testAppUrl}/api/v1/oauth/microsoft/callback`);

                // Assert GitHub config
                expect(oauthConfig.github.clientId).toBe('env-github-id-789');
                expect(oauthConfig.github.clientSecret).toBe('env-github-secret-def');
                expect(oauthConfig.github.redirectUri).toBe(`${testAppUrl}/api/v1/oauth/github/callback`);
            });
        });
    });

    describe('getAuthorizationUrl function - Integration', () => {
        test('should generate URLs with empty client_id and redirect_uri based on default appUrl when env vars are not set', () => {
            delete process.env.APP_URL;
            delete process.env.PORT;
            delete process.env.GOOGLE_CLIENT_ID;
            delete process.env.MICROSOFT_CLIENT_ID;
            delete process.env.GITHUB_CLIENT_ID;

            jest.isolateModules(() => {
                const { config: appConfig } = require('../../config/index');
                const { getAuthorizationUrl } = require('../../config/oauth');
                const expectedDefaultAppUrl = appConfig.appUrl;
                const state = 'default-state-123';

                const googleUrl = getAuthorizationUrl('google', state);
                expect(googleUrl).toContain('client_id='); // Empty client_id becomes client_id=
                expect(googleUrl).toContain(`redirect_uri=${encodeURIComponent(`${expectedDefaultAppUrl}/api/v1/oauth/google/callback`)}`);
                expect(googleUrl).toContain(`state=${state}`);

                const microsoftUrl = getAuthorizationUrl('microsoft', state);
                expect(microsoftUrl).toContain('client_id=');
                expect(microsoftUrl).toContain(`redirect_uri=${encodeURIComponent(`${expectedDefaultAppUrl}/api/v1/oauth/microsoft/callback`)}`);
                expect(microsoftUrl).toContain(`state=${state}`);

                const githubUrl = getAuthorizationUrl('github', state);
                expect(githubUrl).toContain('client_id=');
                expect(githubUrl).toContain(`redirect_uri=${encodeURIComponent(`${expectedDefaultAppUrl}/api/v1/oauth/github/callback`)}`);
                expect(githubUrl).toContain(`state=${state}`);
            });
        });

        test('should generate correct URLs using client IDs and redirect URIs from environment variables', () => {
            const envAppUrl = 'https://my-live-app.com';
            const envGoogleId = 'live-google-id';
            const envMicrosoftId = 'live-microsoft-id';
            const envGithubId = 'live-github-id';

            process.env.APP_URL = envAppUrl;
            process.env.GOOGLE_CLIENT_ID = envGoogleId;
            process.env.MICROSOFT_CLIENT_ID = envMicrosoftId;
            process.env.GITHUB_CLIENT_ID = envGithubId;

            jest.isolateModules(() => {
                const { oauthConfig, getAuthorizationUrl } = require('../../config/oauth');
                const state = 'live-state-456';

                // Google
                const googleUrl = getAuthorizationUrl('google', state);
                expect(googleUrl).toContain(oauthConfig.google.authUrl);
                expect(googleUrl).toContain(`client_id=${envGoogleId}`);
                expect(googleUrl).toContain(`redirect_uri=${encodeURIComponent(`${envAppUrl}/api/v1/oauth/google/callback`)}`);
                expect(googleUrl).toContain('response_type=code');
                expect(googleUrl).toContain('scope=email+profile'); // scope 'email profile' encoded
                expect(googleUrl).toContain(`state=${state}`);

                // Microsoft
                const microsoftUrl = getAuthorizationUrl('microsoft', state);
                expect(microsoftUrl).toContain(oauthConfig.microsoft.authUrl);
                expect(microsoftUrl).toContain(`client_id=${envMicrosoftId}`);
                expect(microsoftUrl).toContain(`redirect_uri=${encodeURIComponent(`${envAppUrl}/api/v1/oauth/microsoft/callback`)}`);
                expect(microsoftUrl).toContain('response_type=code');
                expect(microsoftUrl).toContain('scope=openid+profile+email'); // scope 'openid profile email' encoded
                expect(microsoftUrl).toContain(`state=${state}`);

                // GitHub
                const githubUrl = getAuthorizationUrl('github', state);
                expect(githubUrl).toContain(oauthConfig.github.authUrl);
                expect(githubUrl).toContain(`client_id=${envGithubId}`);
                expect(githubUrl).toContain(`redirect_uri=${encodeURIComponent(`${envAppUrl}/api/v1/oauth/github/callback`)}`);
                expect(githubUrl).toContain('response_type=code');
                expect(githubUrl).toContain('scope=read%3Auser+user%3Aemail'); // scope 'read:user user:email' encoded
                expect(githubUrl).toContain(`state=${state}`);
            });
        });

        test('should throw a TypeError if an invalid provider is specified', () => {
            jest.isolateModules(() => {
                const { getAuthorizationUrl } = require('../../config/oauth');
                const state = 'test-state-invalid-provider';
                expect(() => getAuthorizationUrl('unknownprovider', state)).toThrow(TypeError);
                // Specifically, it should throw "Cannot read properties of undefined (reading 'clientId')" or similar
                expect(() => getAuthorizationUrl('unknownprovider', state)).toThrow(/Cannot read properties of undefined/);
            });
        });

        test('should correctly URL-encode special characters in the state parameter', () => {
            jest.isolateModules(() => {
                const { getAuthorizationUrl } = require('../../config/oauth');
                // Set APP_URL and a client_id to ensure URL generation doesn't fail early for other reasons
                process.env.APP_URL = "http://dummyurl.com";
                process.env.GOOGLE_CLIENT_ID = "dummy-google-id";
                process.env.MICROSOFT_CLIENT_ID = "dummy-microsoft-id";
                process.env.GITHUB_CLIENT_ID = "dummy-github-id";

                const stateWithSpecialChars = 'complex state /w spaces & symbols like +?#=!';
                
                const providers: Array<'google' | 'microsoft' | 'github'> = ['google', 'microsoft', 'github'];

                providers.forEach(provider => {
                    const url = getAuthorizationUrl(provider, stateWithSpecialChars);
                    const parsedUrl = new URL(url);
                    expect(parsedUrl.searchParams.get('state')).toBe(stateWithSpecialChars);
                });
            });
        });

        test('should generate unique URLs for each provider with the same state', () => {
            jest.isolateModules(() => {
                const { getAuthorizationUrl } = require('../../config/oauth');
                process.env.APP_URL = "http://uniqueurl.com";
                process.env.GOOGLE_CLIENT_ID = "google-id";
                process.env.MICROSOFT_CLIENT_ID = "microsoft-id";
                process.env.GITHUB_CLIENT_ID = "github-id";
                const state = 'same-state';

                const googleUrl = getAuthorizationUrl('google', state);
                const microsoftUrl = getAuthorizationUrl('microsoft', state);
                const githubUrl = getAuthorizationUrl('github', state);

                expect(googleUrl).not.toBe(microsoftUrl);
                expect(googleUrl).not.toBe(githubUrl);
                expect(microsoftUrl).not.toBe(githubUrl);
            });
        });

        test('should include all required query parameters in the generated URL', () => {
            process.env.APP_URL = "http://paramtest.com";
            process.env.GOOGLE_CLIENT_ID = "google-id";
            jest.isolateModules(() => {
                const { getAuthorizationUrl } = require('../../config/oauth');
                const state = 'param-state';

                const url = getAuthorizationUrl('google', state);
                const parsedUrl = new URL(url);

                expect(parsedUrl.searchParams.get('client_id')).toBe('google-id');
                expect(parsedUrl.searchParams.get('redirect_uri')).toBe('http://paramtest.com/api/v1/oauth/google/callback');
                expect(parsedUrl.searchParams.get('response_type')).toBe('code');
                expect(parsedUrl.searchParams.get('scope')).toBe('email profile');
                expect(parsedUrl.searchParams.get('state')).toBe(state);
            });
        });

        test('should handle empty state parameter gracefully', () => {
            jest.isolateModules(() => {
                const { getAuthorizationUrl } = require('../../config/oauth');
                process.env.APP_URL = "http://emptystate.com";
                process.env.GOOGLE_CLIENT_ID = "google-id";

                const url = getAuthorizationUrl('google', '');
                const parsedUrl = new URL(url);

                expect(parsedUrl.searchParams.get('state')).toBe('');
            });
        });

        test('should handle very long state parameters', () => {
            jest.isolateModules(() => {
                const { getAuthorizationUrl } = require('../../config/oauth');
                process.env.GOOGLE_CLIENT_ID = "test-id";
                
                const longState = 'a'.repeat(1000); // Create a 1000-character string
                const url = getAuthorizationUrl('google', longState);
                const parsedUrl = new URL(url);
                
                expect(parsedUrl.searchParams.get('state')).toBe(longState);
                expect(url.length).toBeGreaterThan(1000); // Basic sanity check
            });
        });

        test('should handle partial environment configuration', () => {
            // Set only client ID but not secrets
            process.env.GOOGLE_CLIENT_ID = 'partial-config-id';
            delete process.env.GOOGLE_CLIENT_SECRET;
            
            jest.isolateModules(() => {
                const { oauthConfig } = require('../../config/oauth');
                
                expect(oauthConfig.google.clientId).toBe('partial-config-id');
                expect(oauthConfig.google.clientSecret).toBe('');
            });
        });

        test('should handle non-ASCII characters in configuration', () => {
            process.env.APP_URL = "http://international-app.com";
            process.env.GOOGLE_CLIENT_ID = "测试-id-😊";
            
            jest.isolateModules(() => {
                const { getAuthorizationUrl } = require('../../config/oauth');
                const url = getAuthorizationUrl('google', 'test-state');
                
                expect(url).toContain(`client_id=${encodeURIComponent("测试-id-😊")}`);
            });
        });
    });
});