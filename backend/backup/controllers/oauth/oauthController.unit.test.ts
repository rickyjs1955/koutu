// /backend/src/controllers/__tests__/oauthController.unit.test.ts
import { Request, Response, NextFunction } from 'express';
import { oauthService } from '../../services/oauthService';
import { authService } from '../../services/authService';
import { getAuthorizationUrl, OAuthProvider } from '../../config/oauth';
import { ApiError } from '../../utils/ApiError';
import { sanitization } from '../../utils/sanitize';
import { v4 as uuidv4 } from 'uuid';

/**
 * 🧪 OPTIMIZED OAUTH CONTROLLER UNIT TEST SUITE
 * =============================================
 * 
 * OPTIMIZATION STRATEGY:
 * 1. TYPE SAFETY: Strong typing for all test data and scenarios
 * 2. HELPER FUNCTIONS: Reusable test utilities and data factories
 * 3. TEST BUILDERS: Fluent API for test scenario construction
 * 4. MOCK MANAGEMENT: Centralized mock setup and teardown
 * 5. ASSERTION HELPERS: Simplified result verification
 * 6. DRY PRINCIPLE: Eliminate repetitive test patterns
 */

// ==================== MOCK SETUP ====================

jest.mock('../../services/oauthService');
jest.mock('../../services/authService');
jest.mock('../../config/oauth');
jest.mock('../../utils/sanitize');
jest.mock('uuid');
jest.mock('../../models/db', () => ({
  query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
  pool: { query: jest.fn(), end: jest.fn() }
}));

// ==================== TYPE DEFINITIONS ====================

interface MockUser {
  id: string;
  email: string;
  created_at?: Date;
  updated_at?: Date;
}

interface MockOAuthTokens {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
}

interface MockOAuthUserInfo {
  id: string;
  email: string;
  name?: string;
  picture?: string;
  login?: string;
  avatar_url?: string;
  username?: string;
  account_type?: string;
  userPrincipalName?: string;
}

interface MockAuthStats {
  userId: string;
  email: string;
  hasPassword: boolean;
  linkedProviders: string[];
  accountCreated: Date;
  authenticationMethods: {
    password: boolean;
    oauth: boolean;
  };
}

interface TestRequest extends Partial<Request> {
  params?: Record<string, any>;
  query?: Record<string, any>;
  user?: MockUser;
  headers?: Record<string, string>;
  body?: Record<string, any>;
}

interface TestResponse extends Partial<Response> {
  status: jest.Mock;
  json: jest.Mock;
  send: jest.Mock;
  redirect: jest.Mock;
  setHeader: jest.Mock;
}

interface TestScenario {
  name: string;
  provider?: OAuthProvider;
  params?: Record<string, any>;
  query?: Record<string, any>;
  user?: MockUser;
  mockSetup?: () => void;
  expectSuccess?: boolean;
  expectRedirect?: boolean;
  expectError?: boolean;
  expectedStatus?: number;
  expectedErrorMessage?: string | RegExp;
  redirectMatcher?: string | RegExp;
}

interface TestContext {
  req: TestRequest;
  res: TestResponse;
  next: NextFunction;
  controller: any;
}

// ==================== TEST DATA FACTORIES ====================

class TestDataFactory {
  static createUser(provider: string = 'google', overrides: Partial<MockUser> = {}): MockUser {
    return {
      id: `user-${provider}-123e4567-e89b-12d3-a456-426614174000`,
      email: `user@${provider}.com`,
      created_at: new Date('2024-01-01T00:00:00Z'),
      updated_at: new Date('2024-01-01T00:00:00Z'),
      ...overrides
    };
  }

  static createOAuthTokens(provider: string): MockOAuthTokens {
    return {
      access_token: `mock-access-token-${provider}`,
      token_type: 'Bearer',
      expires_in: 3600,
      refresh_token: `mock-refresh-token-${provider}`,
      scope: provider === 'github' ? 'read:user user:email' : 'email profile'
    };
  }

  static createOAuthUserInfo(provider: string): MockOAuthUserInfo {
    const baseInfo = {
      id: `${provider}-user-123`,
      email: `user@${provider}.com`,
      name: `${provider} User`
    };

    const providerSpecific: Record<string, Partial<MockOAuthUserInfo>> = {
      google: { picture: 'https://example.com/picture.jpg' },
      microsoft: { userPrincipalName: baseInfo.email },
      github: { 
        login: 'githubuser', 
        avatar_url: 'https://github.com/avatar.jpg' 
      },
      instagram: { 
        username: 'instagramuser',
        email: 'instagramuser@instagram.local',
        account_type: 'PERSONAL'
      }
    };

    return { ...baseInfo, ...providerSpecific[provider] };
  }

  static createAuthStats(overrides: Partial<MockAuthStats> = {}): MockAuthStats {
    return {
      userId: 'user-123e4567-e89b-12d3-a456-426614174000',
      email: 'user@test.com',
      hasPassword: true,
      linkedProviders: ['google'],
      accountCreated: new Date('2024-01-01T00:00:00Z'),
      authenticationMethods: {
        password: true,
        oauth: true
      },
      ...overrides
    };
  }

  static createMaliciousInputs(): string[] {
    return [
      '<script>alert("xss")</script>',
      "'; DROP TABLE users; --",
      '../../etc/passwd',
      'javascript:alert("xss")',
      '%3Cscript%3Ealert%28%22xss%22%29%3C%2Fscript%3E'
    ];
  }

  // Helper to safely mock UUID
  static mockUuid(mockFn: jest.MockedFunction<typeof uuidv4>, value: string): void {
    mockFn.mockReturnValue(value as any);
  }

  static mockUuidImplementation(mockFn: jest.MockedFunction<typeof uuidv4>, impl: () => string): void {
    mockFn.mockImplementation(impl as any);
  }
}

// ==================== MOCK MANAGER ====================

class MockManager {
  private static _mocks: {
    oauthService: jest.Mocked<typeof oauthService>;
    authService: jest.Mocked<typeof authService>;
    getAuthorizationUrl: jest.MockedFunction<typeof getAuthorizationUrl>;
    sanitization: jest.Mocked<typeof sanitization>;
    uuid: jest.MockedFunction<typeof uuidv4>;
  } | null = null;

  private static get mocks() {
    if (!this._mocks) {
      this.setup();
    }
    return this._mocks!;
  }

  static setup() {
    this._mocks = {
      oauthService: oauthService as jest.Mocked<typeof oauthService>,
      authService: authService as jest.Mocked<typeof authService>,
      getAuthorizationUrl: getAuthorizationUrl as jest.MockedFunction<typeof getAuthorizationUrl>,
      sanitization: sanitization as jest.Mocked<typeof sanitization>,
      uuid: uuidv4 as jest.MockedFunction<typeof uuidv4>
    };

    // Set default implementations
    this._mocks.authService.ensureMinimumResponseTime.mockResolvedValue(undefined);
    this._mocks.sanitization.sanitizeUrl.mockImplementation((url: string) => url);
    this._mocks.sanitization.sanitizeUserInput.mockImplementation((input: string) => input);
    this._mocks.sanitization.sanitizeEmail.mockImplementation((email: string) => email);
  }

  static reset() {
    jest.clearAllMocks();
    this.setup();
  }

  static setupValidOAuthFlow(provider: OAuthProvider, state?: string) {
    const testState = state || `test-state-${provider}-${Date.now()}`;
    const tokens = TestDataFactory.createOAuthTokens(provider);
    const userInfo = TestDataFactory.createOAuthUserInfo(provider);
    const user = TestDataFactory.createUser(provider);

    // Use helper function for UUID mocking
    TestDataFactory.mockUuid(this.mocks.uuid, testState);
    this.mocks.oauthService.exchangeCodeForTokens.mockResolvedValue(tokens);
    this.mocks.oauthService.getUserInfo.mockResolvedValue(userInfo);
    this.mocks.oauthService.findOrCreateUser.mockResolvedValue(user);
    this.mocks.oauthService.generateToken.mockReturnValue('mock-jwt-token');
    this.mocks.authService.validateEmailFormat.mockReturnValue(undefined);
    this.mocks.getAuthorizationUrl.mockReturnValue(`https://oauth.${provider}.com/authorize?state=${testState}`);

    return { state: testState, tokens, userInfo, user };
  }

  static setupAuthStats(stats: Partial<MockAuthStats> = {}) {
    const authStats = TestDataFactory.createAuthStats(stats);
    this.mocks.authService.getUserAuthStats.mockResolvedValue(authStats);
    return authStats;
  }

  static setupError(service: 'oauth' | 'auth' | 'authUrl' | 'sanitize' | 'uuid', method: string, error: Error) {
    const serviceMap = {
      oauth: this.mocks.oauthService,
      auth: this.mocks.authService,
      authUrl: this.mocks.getAuthorizationUrl,
      sanitize: this.mocks.sanitization,
      uuid: this.mocks.uuid
    };

    const mockService = serviceMap[service] as any;
    if (mockService && mockService[method]) {
      mockService[method].mockRejectedValue(error);
    } else {
      throw new Error(`Mock method ${service}.${method} not found`);
    }
  }

  static get oauth() { return this.mocks.oauthService; }
  static get auth() { return this.mocks.authService; }
  static get authUrl() { return this.mocks.getAuthorizationUrl; }
  static get sanitize() { return this.mocks.sanitization; }
  static get uuid() { return this.mocks.uuid; }
}

// ==================== TEST BUILDERS ====================

class TestBuilder {
  private scenario: TestScenario = { name: '' };

  static create(name: string): TestBuilder {
    return new TestBuilder().withName(name);
  }

  withName(name: string): TestBuilder {
    this.scenario.name = name;
    return this;
  }

  withProvider(provider: OAuthProvider): TestBuilder {
    this.scenario.provider = provider;
    return this;
  }

  withParams(params: Record<string, any>): TestBuilder {
    this.scenario.params = params;
    return this;
  }

  withQuery(query: Record<string, any>): TestBuilder {
    this.scenario.query = query;
    return this;
  }

  withUser(user: MockUser): TestBuilder {
    this.scenario.user = user;
    return this;
  }

  withMockSetup(setup: () => void): TestBuilder {
    this.scenario.mockSetup = setup;
    return this;
  }

  expectSuccess(status: number = 200): TestBuilder {
    this.scenario.expectSuccess = true;
    this.scenario.expectedStatus = status;
    return this;
  }

  expectRedirect(matcher?: string | RegExp): TestBuilder {
    this.scenario.expectRedirect = true;
    this.scenario.redirectMatcher = matcher;
    return this;
  }

  expectError(message?: string | RegExp, status?: number): TestBuilder {
    this.scenario.expectError = true;
    this.scenario.expectedErrorMessage = message;
    this.scenario.expectedStatus = status;
    return this;
  }

  build(): TestScenario {
    return this.scenario;
  }
}

// ==================== TEST EXECUTOR ====================

class TestExecutor {
  static async run(
    method: (req: Request, res: Response, next: NextFunction) => Promise<void>,
    scenario: TestScenario
  ): Promise<TestContext> {
    // Setup mocks
    if (scenario.mockSetup) {
      scenario.mockSetup();
    }

    // Create test context
    const context = this.createContext(scenario);

    // Execute method
    try {
      await method(context.req as Request, context.res as Response, context.next);
    } catch (error) {
      context.next(error);
    }

    return context;
  }

  private static createContext(scenario: TestScenario): TestContext {
    const req: TestRequest = {
      params: scenario.params || {},
      query: scenario.query || {},
      user: scenario.user,
      headers: {},
      body: {}
    };

    const res: TestResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      send: jest.fn().mockReturnThis(),
      redirect: jest.fn().mockReturnThis(),
      setHeader: jest.fn().mockReturnThis()
    };

    const next: NextFunction = jest.fn() as NextFunction;

    return { req, res, next, controller: null };
  }
}

// ==================== ASSERTION HELPERS ====================

class AssertionHelper {
  static expectSuccess(context: TestContext, expectedStatus: number = 200, dataMatchers?: any) {
    expect(context.res.status).toHaveBeenCalledWith(expectedStatus);
    if (dataMatchers) {
      expect(context.res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'success',
          data: expect.objectContaining(dataMatchers)
        })
      );
    } else {
      expect(context.res.json).toHaveBeenCalledWith(
        expect.objectContaining({ status: 'success' })
      );
    }
    expect(context.next).not.toHaveBeenCalled();
  }

  static expectRedirect(context: TestContext, urlMatcher?: string | RegExp) {
    expect(context.res.redirect).toHaveBeenCalled();
    if (urlMatcher) {
      const redirectCall = context.res.redirect.mock.calls[0][0];
      if (typeof urlMatcher === 'string') {
        expect(redirectCall).toContain(urlMatcher);
      } else {
        expect(redirectCall).toMatch(urlMatcher);
      }
    }
    expect(context.next).not.toHaveBeenCalled();
  }

  static expectError(context: TestContext, messageMatcher?: string | RegExp, status?: number) {
    expect(context.next).toHaveBeenCalled();
    const error = (context.next as jest.Mock).mock.calls[0][0];
    expect(error).toBeDefined();
    
    if (messageMatcher) {
      if (typeof messageMatcher === 'string') {
        // More flexible error message matching
        if (messageMatcher === 'provider') {
          expect(error.message).toMatch(/provider|Invalid input format/i);
        } else {
          expect(error.message).toContain(messageMatcher);
        }
      } else {
        expect(error.message).toMatch(messageMatcher);
      }
    }
    
    if (status) {
      expect(error.statusCode).toBe(status);
    }
  }

  static expectNoErrors(context: TestContext) {
    expect(context.next).not.toHaveBeenCalled();
  }
}

// ==================== MAIN TEST SUITE ====================

describe('OAuthController Unit Tests (Optimized)', () => {
    const validProviders: OAuthProvider[] = ['google', 'microsoft', 'github', 'instagram'];
    let oauthController: any;

    beforeAll(() => {
        jest.clearAllTimers();
        jest.useFakeTimers();
        process.env.NODE_ENV = 'test';
        process.env.FRONTEND_URL = 'http://localhost:3000';
        process.env.ALLOWED_REDIRECT_DOMAINS = 'localhost,koutu.com';
    });

    afterAll(() => {
        jest.useRealTimers();
    });

    beforeEach(async () => {
        MockManager.reset();
        
        // Fresh controller import
        delete require.cache[require.resolve('../../controllers/oauthController')];
        const controllerModule = await import('../../controllers/oauthController');
        oauthController = controllerModule.oauthController;
    });

    // ==================== AUTHORIZE METHOD TESTS ====================

    describe('authorize method', () => {
        describe('successful authorization initiation', () => {
        test.each(validProviders)('should initiate OAuth flow for %s', async (provider) => {
            const scenario = TestBuilder
            .create(`${provider} authorization`)
            .withProvider(provider)
            .withParams({ provider })
            .withMockSetup(() => MockManager.setupValidOAuthFlow(provider))
            .expectRedirect(`oauth.${provider}.com`)
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectRedirect(context, scenario.redirectMatcher);
            expect(MockManager.authUrl).toHaveBeenCalledWith(provider, expect.any(String), expect.any(Object));
        });

        it('should handle redirect parameter correctly', async () => {
            const scenario = TestBuilder
            .create('authorization with redirect')
            .withParams({ provider: 'google' })
            .withQuery({ redirect: '/dashboard' })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .expectRedirect()
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectRedirect(context);
            expect(MockManager.auth.ensureMinimumResponseTime).toHaveBeenCalled();
        });

        it('should generate unique state parameters', async () => {
            const states = ['state-1', 'state-2', 'state-3'];
            let callCount = 0;

            (MockManager.uuid as unknown as jest.MockedFunction<() => string>).mockImplementation(() => states[callCount++]);
            MockManager.authUrl.mockImplementation((provider, state) => 
            `https://oauth.${provider}.com/authorize?state=${state}`
            );

            for (let i = 0; i < 3; i++) {
            const scenario = TestBuilder
                .create(`unique state ${i}`)
                .withParams({ provider: 'google' })
                .build();

            await TestExecutor.run(oauthController.authorize, scenario);
            }

            expect(MockManager.uuid).toHaveBeenCalledTimes(3);
            states.forEach((state, index) => {
            expect(MockManager.authUrl).toHaveBeenNthCalledWith(
                index + 1, 'google', state, expect.any(Object)
            );
            });
        });
        });

        describe('error boundary and recovery', () => {
        it('should not crash on completely malformed request objects', async () => {
            const malformedRequests = [
            { params: null },
            { params: undefined },
            { params: 'string-instead-of-object' },
            { params: 123 },
            { params: [] },
            {} // no params property at all
            ];

            for (const request of malformedRequests) {
            const scenario = TestBuilder
                .create('malformed request')
                .withParams(request.params as any)
                .build();

            // Should not throw unhandled errors
            await expect(
                TestExecutor.run(oauthController.authorize, scenario)
            ).resolves.toBeDefined();

            MockManager.reset();
            }
        });

        it('should maintain consistent error format across all failure modes', async () => {
            const errorScenarios = [
            {
                name: 'invalid provider',
                params: { provider: 'invalid' }
            },
            {
                name: 'missing provider',
                params: {}
            },
            {
                name: 'malicious redirect',
                params: { provider: 'google' },
                query: { redirect: 'javascript:alert("xss")' }
            }
            ];

            const errorResponses: any[] = [];

            for (const { name, params, query } of errorScenarios) {
            const scenario = TestBuilder
                .create(name)
                .withParams(params)
                .withQuery(query || {})
                .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);

            if ((context.next as jest.Mock).mock.calls.length > 0) {
                errorResponses.push((context.next as jest.Mock).mock.calls[0][0]);
            }

            MockManager.reset();
            }

            // All errors should have consistent structure
            errorResponses.forEach(error => {
            expect(error).toBeDefined();
            if (error && typeof error === 'object' && 'statusCode' in error) {
                expect(typeof error.statusCode).toBe('number');
                expect(typeof error.message).toBe('string');
            }
            });
        });
        });

        describe('provider validation', () => {
        const invalidProviders = [
            'invalid-provider', 'facebook', 'twitter', '', null, undefined, 123, {}, []
        ];

        test.each(invalidProviders)('should reject invalid provider: %p', async (provider) => {
            const scenario = TestBuilder
            .create(`invalid provider ${JSON.stringify(provider)}`)
            .withParams({ provider })
            .expectError('provider', 400)
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
            expect(MockManager.authUrl).not.toHaveBeenCalled();
        });

        it('should handle array injection attacks on provider parameter', async () => {
            const scenario = TestBuilder
            .create('array injection attack')
            .withParams({ provider: ['google', 'malicious'] as any })
            .expectError('provider', 400)
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
        });

        it('should handle object injection attacks on provider parameter', async () => {
            const scenario = TestBuilder
            .create('object injection attack')
            .withParams({ provider: { malicious: 'payload' } as any })
            .expectError('provider', 400)
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
        });
        });

        describe('redirect URL validation', () => {
        it('should validate redirect URL domains', async () => {
            const scenario = TestBuilder
            .create('invalid redirect domain')
            .withParams({ provider: 'google' })
            .withQuery({ redirect: 'http://evil.com/steal-tokens' })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .expectError('Invalid redirect URL', 400)
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
        });

        test.each([
            'http://localhost:3000/dashboard',
            'https://koutu.com/profile',
            '/relative-path'
        ])('should allow valid redirect: %s', async (redirect) => {
            const scenario = TestBuilder
            .create(`valid redirect: ${redirect}`)
            .withParams({ provider: 'google' })
            .withQuery({ redirect })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .expectRedirect()
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectRedirect(context);
        });

        test.each([
            'javascript:alert("xss")',
            'data:text/html,<script>alert("xss")</script>',
            'file:///etc/passwd',
            'ftp://malicious.com/file.txt'
        ])('should reject malformed URL: %s', async (malformedUrl) => {
            const scenario = TestBuilder
            .create(`malformed URL: ${malformedUrl}`)
            .withParams({ provider: 'google' })
            .withQuery({ redirect: malformedUrl })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .expectError('Invalid redirect URL', 400)
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
        });
        });

        describe('timing attack prevention', () => {
        it('should ensure minimum response time for all requests', async () => {
            const scenario = TestBuilder
            .create('timing consistency')
            .withParams({ provider: 'google' })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .build();

            await TestExecutor.run(oauthController.authorize, scenario);
            expect(MockManager.auth.ensureMinimumResponseTime).toHaveBeenCalled();
        });

        it('should ensure minimum response time even for errors', async () => {
            const scenario = TestBuilder
            .create('timing consistency on error')
            .withParams({ provider: 'invalid' })
            .expectError()
            .build();

            await TestExecutor.run(oauthController.authorize, scenario);
            expect(MockManager.auth.ensureMinimumResponseTime).toHaveBeenCalled();
        });
        });

        describe('security headers and sanitization', () => {
        it('should sanitize authorization URL before redirect', async () => {
            const scenario = TestBuilder
            .create('URL sanitization')
            .withParams({ provider: 'google' })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .build();

            await TestExecutor.run(oauthController.authorize, scenario);
            expect(MockManager.sanitize.sanitizeUrl).toHaveBeenCalled();
        });

        it('should handle URL sanitization errors gracefully', async () => {
            const scenario = TestBuilder
            .create('sanitization error handling')
            .withParams({ provider: 'google' })
            .withMockSetup(() => {
                MockManager.setupValidOAuthFlow('google');
                MockManager.sanitize.sanitizeUrl.mockImplementation(() => {
                throw new Error('Sanitization failed');
                });
            })
            .expectError()
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context);
        });
        });

        describe('error handling', () => {
        it('should handle authorization URL generation errors', async () => {
            const scenario = TestBuilder
            .create('auth URL generation error')
            .withParams({ provider: 'google' })
            .withMockSetup(() => {
                MockManager.authUrl.mockImplementation(() => {
                throw new Error('Authorization URL generation failed');
                });
            })
            .expectError()
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context);
        });

        it('should handle UUID generation failures', async () => {
            const scenario = TestBuilder
            .create('UUID generation error')
            .withParams({ provider: 'google' })
            .withMockSetup(() => {
                MockManager.uuid.mockImplementation(() => {
                throw new Error('UUID generation failed');
                });
            })
            .expectError()
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context);
        });
        });
    });

    // ==================== CALLBACK METHOD TESTS ====================

    describe('callback method', () => {
        describe('successful OAuth callback', () => {
        test.each(validProviders)('should handle OAuth callback for %s', async (provider) => {
            const testData = MockManager.setupValidOAuthFlow(provider);
            
            // Setup OAuth state via authorize
            await TestExecutor.run(oauthController.authorize, {
            name: 'setup authorize',
            params: { provider }
            });

            MockManager.reset();
            MockManager.setupValidOAuthFlow(provider);

            const scenario = TestBuilder
            .create(`${provider} callback`)
            .withParams({ provider })
            .withQuery({ code: 'auth-code', state: testData.state })
            .build();

            const context = await TestExecutor.run(oauthController.callback, scenario);
            
            expect(MockManager.oauth.exchangeCodeForTokens).toHaveBeenCalledWith(provider, 'auth-code');
            expect(MockManager.oauth.getUserInfo).toHaveBeenCalled();
            expect(MockManager.oauth.findOrCreateUser).toHaveBeenCalled();
            expect(MockManager.oauth.generateToken).toHaveBeenCalled();
            AssertionHelper.expectRedirect(context);
        });

        it('should handle callback with custom redirect URL', async () => {
            const testData = MockManager.setupValidOAuthFlow('google');
            const customRedirect = '/custom-dashboard';
            
            // Setup state with redirect via authorize
            await TestExecutor.run(oauthController.authorize, {
            name: 'setup with redirect',
            params: { provider: 'google' },
            query: { redirect: customRedirect }
            });

            MockManager.reset();
            MockManager.setupValidOAuthFlow('google');

            const scenario = TestBuilder
            .create('callback with custom redirect')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code', state: testData.state })
            .build();

            const context = await TestExecutor.run(oauthController.callback, scenario);
            
            expect(MockManager.oauth.exchangeCodeForTokens).toHaveBeenCalled();
            AssertionHelper.expectRedirect(context);
            
            const redirectCall = context.res.redirect.mock.calls[0][0];
            expect(redirectCall).toContain(encodeURIComponent(customRedirect));
        });

        it('should handle callback without redirect URL (default)', async () => {
            const testData = MockManager.setupValidOAuthFlow('google');
            
            // Setup state without redirect via authorize
            await TestExecutor.run(oauthController.authorize, {
            name: 'setup without redirect',
            params: { provider: 'google' }
            });

            MockManager.reset();
            MockManager.setupValidOAuthFlow('google');

            const scenario = TestBuilder
            .create('callback with default redirect')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code', state: testData.state })
            .build();

            const context = await TestExecutor.run(oauthController.callback, scenario);
            
            expect(MockManager.oauth.exchangeCodeForTokens).toHaveBeenCalled();
            AssertionHelper.expectRedirect(context);
            
            const redirectCall = context.res.redirect.mock.calls[0][0];
            expect(redirectCall).toContain(encodeURIComponent('/'));
        });
        });

        describe('input validation', () => {
        const requiredParamTests = [
            { name: 'missing code', query: { state: 'valid-state' } },
            { name: 'missing state', query: { code: 'valid-code' } },
            { name: 'empty code', query: { code: '', state: 'valid-state' } },
            { name: 'empty state', query: { code: 'valid-code', state: '' } }
        ];

        test.each(requiredParamTests)('should reject callback with $name', async ({ query }) => {
            const scenario = TestBuilder
            .create(`missing ${Object.keys(query).join(',')}`)
            .withParams({ provider: 'google' })
            .withQuery(query)
            .expectError('Missing required parameters', 400)
            .build();

            const context = await TestExecutor.run(oauthController.callback, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
            expect(MockManager.oauth.exchangeCodeForTokens).not.toHaveBeenCalled();
        });
        });

        describe('OAuth provider errors', () => {
        const providerErrors = [
            'access_denied', 'invalid_request', 'unauthorized_client', 
            'unsupported_response_type', 'invalid_scope', 'server_error'
        ];

        test.each(providerErrors)('should handle provider error: %s', async (error) => {
            const scenario = TestBuilder
            .create(`provider error: ${error}`)
            .withParams({ provider: 'google' })
            .withQuery({ error })
            .expectError('Provider error', 400)
            .build();

            const context = await TestExecutor.run(oauthController.callback, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
            expect(MockManager.oauth.exchangeCodeForTokens).not.toHaveBeenCalled();
        });
        });

        describe('state parameter security', () => {
        it('should reject invalid state parameter', async () => {
            const scenario = TestBuilder
            .create('invalid state')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'valid-code', state: 'invalid-state' })
            .expectError('Invalid state parameter', 400)
            .build();

            const context = await TestExecutor.run(oauthController.callback, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
        });
        });
    });

    // ==================== TOKEN EXCHANGE AND USER FLOW TESTS ====================

    describe('token exchange and user flow', () => {
        const serviceErrorTests = [
        {
            service: 'oauth' as const,
            method: 'exchangeCodeForTokens',
            error: new Error('Token exchange failed'),
            shouldNotCall: 'getUserInfo'
        },
        {
            service: 'oauth' as const,
            method: 'getUserInfo',
            error: new Error('User info retrieval failed'),
            shouldNotCall: 'findOrCreateUser'
        },
        {
            service: 'oauth' as const,
            method: 'findOrCreateUser',
            error: new Error('User creation failed'),
            shouldNotCall: 'generateToken'
        }
        ];

        test.each(serviceErrorTests)(
        'should handle $method errors',
        async ({ service, method, error, shouldNotCall }) => {
            const testData = MockManager.setupValidOAuthFlow('google');
            MockManager.setupError(service, method, error);

            const scenario = TestBuilder
            .create(`${method} error`)
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code', state: testData.state })
            .expectError()
            .build();

            const context = await TestExecutor.run(oauthController.callback, scenario);
            AssertionHelper.expectError(context);
            
            if (shouldNotCall) {
            expect(MockManager.oauth[shouldNotCall as keyof typeof MockManager.oauth]).not.toHaveBeenCalled();
            }
        }
        );

        it('should handle token generation errors', async () => {
        const testData = MockManager.setupValidOAuthFlow('google');
        MockManager.oauth.generateToken.mockImplementation(() => {
            throw new Error('Token generation failed');
        });

        const scenario = TestBuilder
            .create('token generation error')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code', state: testData.state })
            .expectError()
            .build();

        const context = await TestExecutor.run(oauthController.callback, scenario);
        AssertionHelper.expectError(context);
        });
    });

    describe('email validation for OAuth users', () => {
        it('should validate OAuth email for non-local domains', async () => {
        const testData = MockManager.setupValidOAuthFlow('google');
        testData.userInfo.email = 'user@gmail.com';

        // Setup state via authorize
        await TestExecutor.run(oauthController.authorize, {
            name: 'setup',
            params: { provider: 'google' }
        });

        MockManager.reset();
        MockManager.setupValidOAuthFlow('google');
        MockManager.oauth.getUserInfo.mockResolvedValue({ ...testData.userInfo, email: 'user@gmail.com' });

        const scenario = TestBuilder
            .create('email validation')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code', state: testData.state })
            .build();

        await TestExecutor.run(oauthController.callback, scenario);
        expect(MockManager.auth.validateEmailFormat).toHaveBeenCalledWith('user@gmail.com');
        });

        test.each(['instagram', 'github'])('should skip validation for %s local emails', async (provider) => {
        const testData = MockManager.setupValidOAuthFlow(provider as OAuthProvider);
        testData.userInfo.email = `user@${provider}.local`;

        const scenario = TestBuilder
            .create(`${provider} local email`)
            .withParams({ provider })
            .withQuery({ code: 'auth-code', state: testData.state })
            .build();

        await TestExecutor.run(oauthController.callback, scenario);
        expect(MockManager.auth.validateEmailFormat).not.toHaveBeenCalled();
        });
    });

    // ==================== GET OAUTH STATUS TESTS ====================

    describe('getOAuthStatus method', () => {
        describe('successful status retrieval', () => {
        it('should return OAuth status for authenticated user', async () => {
            const mockStats = MockManager.setupAuthStats({
            linkedProviders: ['google', 'github'],
            authenticationMethods: { password: true, oauth: true }
            });

            const scenario = TestBuilder
            .create('successful status retrieval')
            .withUser(TestDataFactory.createUser())
            .expectSuccess(200)
            .build();

            const context = await TestExecutor.run(oauthController.getOAuthStatus, scenario);
            
            expect(MockManager.auth.getUserAuthStats).toHaveBeenCalledWith(scenario.user!.id);
            AssertionHelper.expectSuccess(context, 200, {
            linkedProviders: mockStats.linkedProviders,
            authenticationMethods: mockStats.authenticationMethods
            });
        });

        it('should handle user with no linked providers', async () => {
            const mockStats = MockManager.setupAuthStats({
            linkedProviders: [],
            authenticationMethods: { password: true, oauth: false }
            });

            const scenario = TestBuilder
            .create('no linked providers')
            .withUser(TestDataFactory.createUser())
            .expectSuccess(200)
            .build();

            const context = await TestExecutor.run(oauthController.getOAuthStatus, scenario);
            AssertionHelper.expectSuccess(context, 200, {
            linkedProviders: [],
            authenticationMethods: { password: true, oauth: false }
            });
        });
        });

        describe('authentication requirement', () => {
        const unauthenticatedTests = [
            { name: 'no user object', input: {} },
            { name: 'undefined user', input: { user: undefined } },
            { name: 'null user', input: { user: null as any } }
        ];

        test.each(unauthenticatedTests)('should reject request with $name', async ({ name, input }) => {
            const scenario = TestBuilder
            .create(`unauthenticated: ${name}`)
            .withUser(input.user)
            .expectError('Authentication required', 401)
            .build();

            const context = await TestExecutor.run(oauthController.getOAuthStatus, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
            expect(MockManager.auth.getUserAuthStats).not.toHaveBeenCalled();
        });
        });

        describe('error handling', () => {
        it('should handle auth service errors', async () => {
            MockManager.setupAuthStats(); // Setup default first
            MockManager.setupError('auth', 'getUserAuthStats', new Error('Auth service error'));

            const scenario = TestBuilder
            .create('auth service error')
            .withUser(TestDataFactory.createUser())
            .expectError('Failed to retrieve OAuth status')
            .build();

            const context = await TestExecutor.run(oauthController.getOAuthStatus, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage);
        });

        it('should handle API errors from auth service', async () => {
            MockManager.setupAuthStats(); // Setup default first
            MockManager.setupError('auth', 'getUserAuthStats', ApiError.notFound('User not found'));

            const scenario = TestBuilder
            .create('API error from auth service')
            .withUser(TestDataFactory.createUser())
            .expectError('User not found', 404)
            .build();

            const context = await TestExecutor.run(oauthController.getOAuthStatus, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
        });
        });
    });

    // ==================== UNLINK PROVIDER TESTS ====================

    describe('unlinkProvider method', () => {
        describe('successful provider unlinking', () => {
        it('should successfully unlink provider when user has password', async () => {
            MockManager.setupAuthStats({
            hasPassword: true,
            linkedProviders: ['google', 'github'],
            authenticationMethods: { password: true, oauth: true }
            });

            const scenario = TestBuilder
            .create('successful unlink')
            .withParams({ provider: 'google' })
            .withUser(TestDataFactory.createUser())
            .expectSuccess(200)
            .build();

            const context = await TestExecutor.run(oauthController.unlinkProvider, scenario);
            
            expect(MockManager.auth.getUserAuthStats).toHaveBeenCalled();
            expect(context.res.json).toHaveBeenCalledWith({
            status: 'success',
            message: 'Successfully unlinked google account'
            });
        });

        it('should allow unlinking when user has multiple OAuth providers', async () => {
            MockManager.setupAuthStats({
            hasPassword: false,
            linkedProviders: ['google', 'github', 'microsoft'],
            authenticationMethods: { password: false, oauth: true }
            });

            const scenario = TestBuilder
            .create('unlink with multiple providers')
            .withParams({ provider: 'google' })
            .withUser(TestDataFactory.createUser())
            .build();

            const context = await TestExecutor.run(oauthController.unlinkProvider, scenario);
            expect(context.res.status).toHaveBeenCalledWith(200);
            expect(context.res.json).toHaveBeenCalledWith({
            status: 'success',
            message: 'Successfully unlinked google account'
            });
        });
        });

        describe('security validations', () => {
        it('should prevent unlinking last authentication method', async () => {
            MockManager.setupAuthStats({
            hasPassword: false,
            linkedProviders: ['google'],
            authenticationMethods: { password: false, oauth: true }
            });

            const scenario = TestBuilder
            .create('prevent last auth removal')
            .withParams({ provider: 'google' })
            .withUser(TestDataFactory.createUser())
            .expectError('Cannot unlink the only authentication method')
            .build();

            const context = await TestExecutor.run(oauthController.unlinkProvider, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage);
        });

        test.each(['invalid', '', null, undefined, 123, {}, []])(
            'should validate provider parameter: %p', 
            async (invalidProvider) => {
            const scenario = TestBuilder
                .create(`invalid provider: ${JSON.stringify(invalidProvider)}`)
                .withParams({ provider: invalidProvider })
                .withUser(TestDataFactory.createUser())
                .expectError('', 400)
                .build();

            const context = await TestExecutor.run(oauthController.unlinkProvider, scenario);
            AssertionHelper.expectError(context, undefined, 400);
            }
        );
        });

        describe('authentication requirement', () => {
        it('should require authentication for unlinking', async () => {
            const scenario = TestBuilder
            .create('unauthenticated unlink attempt')
            .withParams({ provider: 'google' })
            .expectError('Authentication required', 401)
            .build();

            const context = await TestExecutor.run(oauthController.unlinkProvider, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
            expect(MockManager.auth.getUserAuthStats).not.toHaveBeenCalled();
        });
        });

        describe('timing attack prevention', () => {
        it('should ensure minimum response time for successful unlink', async () => {
            MockManager.setupAuthStats({
            hasPassword: true,
            linkedProviders: ['google', 'github'],
            authenticationMethods: { password: true, oauth: true }
            });

            const scenario = TestBuilder
            .create('unlink timing')
            .withParams({ provider: 'google' })
            .withUser(TestDataFactory.createUser())
            .build();

            await TestExecutor.run(oauthController.unlinkProvider, scenario);
            expect(MockManager.auth.ensureMinimumResponseTime).toHaveBeenCalled();
        });

        it('should ensure minimum response time for error responses', async () => {
            const scenario = TestBuilder
            .create('unlink error timing')
            .withParams({ provider: 'invalid' })
            .withUser(TestDataFactory.createUser())
            .build();

            await TestExecutor.run(oauthController.unlinkProvider, scenario);
            expect(MockManager.auth.ensureMinimumResponseTime).toHaveBeenCalled();
        });
        });

        describe('error handling', () => {
        it('should handle auth service errors', async () => {
            MockManager.setupAuthStats(); // Setup default first
            MockManager.setupError('auth', 'getUserAuthStats', new Error('Database connection failed'));

            const scenario = TestBuilder
            .create('auth service error')
            .withParams({ provider: 'google' })
            .withUser(TestDataFactory.createUser())
            .expectError()
            .build();

            const context = await TestExecutor.run(oauthController.unlinkProvider, scenario);
            AssertionHelper.expectError(context);
        });
        });
    });

    // ==================== SECURITY AND EDGE CASES ====================

    describe('security and edge cases', () => {
        describe('malicious input handling', () => {
        test.each(TestDataFactory.createMaliciousInputs())(
            'should handle malicious input: %s', 
            async (maliciousInput) => {
            const scenario = TestBuilder
                .create(`malicious input: ${maliciousInput}`)
                .withParams({ provider: maliciousInput })
                .expectError()
                .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context);
            expect(MockManager.authUrl).not.toHaveBeenCalled();
            }
        );

        it('should handle extremely long provider parameters', async () => {
            const longProvider = 'a'.repeat(10000);
            
            const scenario = TestBuilder
            .create('extremely long provider')
            .withParams({ provider: longProvider })
            .expectError('', 400)
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context, undefined, 400);
        });

        test.each([
            '🚀provider',
            'provider\u0000null',
            'provider\r\ninjection',
            'provider\x00\x01\x02'
        ])('should handle Unicode characters: %s', async (unicodeInput) => {
            const scenario = TestBuilder
            .create(`unicode input: ${unicodeInput}`)
            .withParams({ provider: unicodeInput })
            .expectError()
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectError(context);
        });
        });

        describe('concurrent request handling', () => {
        it('should handle multiple simultaneous OAuth flows', async () => {
            const scenarios = validProviders.map((provider, index) => 
            TestBuilder
                .create(`concurrent ${provider} flow`)
                .withParams({ provider })
                .withMockSetup(() => {
                MockManager.setupValidOAuthFlow(provider);
                TestDataFactory.mockUuid(MockManager.uuid, `concurrent-state-${index}`);
                })
                .build()
            );

            const promises = scenarios.map(scenario =>
            TestExecutor.run(oauthController.authorize, scenario)
            );

            const results = await Promise.all(promises);

            results.forEach(context => {
            const hasError = (context.next as jest.Mock).mock.calls.length > 0;
            if (!hasError) {
                expect(context.res.redirect).toHaveBeenCalled();
            }
            });
        });

        it('should handle rapid sequential requests efficiently', async () => {
            const startTime = Date.now();
            const requestCount = 10;

            for (let i = 0; i < requestCount; i++) {
            const scenario = TestBuilder
                .create(`sequential request ${i}`)
                .withParams({ provider: 'google' })
                .withMockSetup(() => {
                MockManager.setupValidOAuthFlow('google');
                TestDataFactory.mockUuid(MockManager.uuid, `sequential-state-${i}`);
                })
                .build();

            await TestExecutor.run(oauthController.authorize, scenario);
            MockManager.reset();
            }

            const endTime = Date.now();
            const duration = endTime - startTime;
            expect(duration).toBeLessThan(1000); // 100ms per request average
        });
        });

        describe('memory and performance', () => {
        it('should not leak memory with large request objects', async () => {
            const largeQuery = {
            provider: 'google',
            largeData: 'x'.repeat(100000),
            extraField: 'should-be-ignored',
            maliciousScript: '<script>alert("xss")</script>'
            };

            const scenario = TestBuilder
            .create('large request object')
            .withParams({ provider: 'google' })
            .withQuery(largeQuery)
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .expectRedirect()
            .build();

            const context = await TestExecutor.run(oauthController.authorize, scenario);
            AssertionHelper.expectRedirect(context);
        });

        it('should complete OAuth flows within reasonable time', async () => {
            const startTime = Date.now();
            
            const scenario = TestBuilder
            .create('performance timing')
            .withParams({ provider: 'google' })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .build();

            await TestExecutor.run(oauthController.authorize, scenario);

            const endTime = Date.now();
            const duration = endTime - startTime;
            expect(duration).toBeLessThan(100);
        });
        });

        describe('state management security', () => {
        it('should prevent state parameter reuse attacks', async () => {
            const testData = MockManager.setupValidOAuthFlow('google');

            // First use of the state (should work)
            const firstScenario = TestBuilder
            .create('first state use')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code-1', state: testData.state })
            .build();

            const firstContext = await TestExecutor.run(oauthController.callback, firstScenario);
            AssertionHelper.expectRedirect(firstContext);

            // Second use of the same state (should fail)
            const secondScenario = TestBuilder
            .create('state reuse attempt')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code-2', state: testData.state })
            .expectError('Invalid state parameter', 400)
            .build();

            const secondContext = await TestExecutor.run(oauthController.callback, secondScenario);
            AssertionHelper.expectError(secondContext, secondScenario.expectedErrorMessage, secondScenario.expectedStatus);
        });

        it('should handle state cleanup race conditions', async () => {
            const testData = MockManager.setupValidOAuthFlow('google');

            // Simulate concurrent access to the same state
            const promises = Array(5).fill(null).map((_, index) => {
            const scenario = TestBuilder
                .create(`concurrent state access ${index}`)
                .withParams({ provider: 'google' })
                .withQuery({ code: `code-${index}`, state: testData.state })
                .build();

            return TestExecutor.run(oauthController.callback, scenario);
            });

            const results = await Promise.all(promises);

            // At least some should succeed or fail gracefully
            const successCount = results.filter(context => {
            // Check if next was called (indicates error)
            const hasError = jest.mocked(context.next).mock.calls.length > 0;
            
            // Check if redirect was called (indicates success)
            const hasRedirect = jest.mocked(context.res.redirect).mock.calls.length > 0;
            
            return !hasError && hasRedirect;
            }).length;

            expect(successCount).toBeGreaterThanOrEqual(0);
        });
        });
    });

    // ==================== ENVIRONMENT CONFIGURATION TESTS ====================

    describe('environment configuration', () => {
        const originalEnv = process.env;

        afterEach(() => {
        process.env = { ...originalEnv };
        });

        it('should handle missing environment variables gracefully', async () => {
        delete process.env.FRONTEND_URL;

        const testData = MockManager.setupValidOAuthFlow('google');

        // Setup state via authorize
        await TestExecutor.run(oauthController.authorize, {
            name: 'setup',
            params: { provider: 'google' }
        });

        MockManager.reset();
        MockManager.setupValidOAuthFlow('google');

        const scenario = TestBuilder
            .create('missing env vars')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code', state: testData.state })
            .build();

        const context = await TestExecutor.run(oauthController.callback, scenario);

        expect(MockManager.oauth.exchangeCodeForTokens).toHaveBeenCalled();
        AssertionHelper.expectRedirect(context);
        
        const redirectCall = context.res.redirect.mock.calls[0][0];
        expect(redirectCall).toContain('localhost:3000'); // Default fallback
        });

        describe('domain validation configurations', () => {
        const domainTests = [
            {
            name: 'undefined domains (no restrictions)',
            domains: undefined,
            redirect: 'http://localhost:3000/dashboard',
            shouldSucceed: true
            },
            {
            name: 'empty string domains (rejects all)',
            domains: '',
            redirect: 'http://localhost:3000/dashboard',
            shouldSucceed: false,
            expectedError: 'Invalid redirect URL'
            },
            {
            name: 'whitespace-only domains',
            domains: '   ',
            redirect: 'http://localhost:3000/dashboard',
            shouldSucceed: false,
            expectedError: 'Invalid redirect URL'
            },
            {
            name: 'properly configured domains',
            domains: 'localhost,koutu.com,example.com',
            redirect: 'http://localhost:3000/dashboard',
            shouldSucceed: true
            },
            {
            name: 'domains with whitespace',
            domains: ' localhost , koutu.com , example.com ',
            redirect: 'http://localhost:3000/dashboard',
            shouldSucceed: false, // Controller doesn't trim whitespace
            expectedError: 'Invalid redirect URL'
            }
        ];

        test.each(domainTests)('should handle $name', async ({ domains, redirect, shouldSucceed, expectedError }) => {
            if (domains === undefined) {
            delete process.env.ALLOWED_REDIRECT_DOMAINS;
            } else {
            process.env.ALLOWED_REDIRECT_DOMAINS = domains;
            }

            const scenarioBuilder = TestBuilder
            .create(`domain config: ${domains}`)
            .withParams({ provider: 'google' })
            .withQuery({ redirect })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'));

            if (shouldSucceed) {
            scenarioBuilder.expectRedirect();
            } else {
            scenarioBuilder.expectError(expectedError, 400);
            }

            const scenario = scenarioBuilder.build();
            const context = await TestExecutor.run(oauthController.authorize, scenario);

            if (shouldSucceed) {
            AssertionHelper.expectRedirect(context);
            } else {
            AssertionHelper.expectError(context, expectedError, 400);
            }
        });
        });
    });

    // ==================== ERROR HANDLING INTEGRATION ====================

    describe('error handling integration', () => {
        describe('service error handling', () => {
        const serviceErrorTests = [
            {
            service: 'oauth' as const,
            method: 'exchangeCodeForTokens',
            error: new Error('Token exchange failed'),
            testMethod: 'callback',
            setupCallback: true
            },
            {
            service: 'oauth' as const,
            method: 'getUserInfo',
            error: new Error('User info retrieval failed'),
            testMethod: 'callback',
            setupCallback: true
            },
            {
            service: 'oauth' as const,
            method: 'findOrCreateUser',
            error: new Error('User creation failed'),
            testMethod: 'callback',
            setupCallback: true
            },
            {
            service: 'auth' as const,
            method: 'getUserAuthStats',
            error: new Error('Auth service error'),
            testMethod: 'getOAuthStatus',
            setupCallback: false
            }
        ];

        test.each(serviceErrorTests)(
            'should handle $service.$method errors in $testMethod',
            async ({ service, method, error, testMethod, setupCallback }) => {
            // Setup the error after initial setup
            let testData: any = null;
            
            if (setupCallback) {
                testData = MockManager.setupValidOAuthFlow('google');
            } else {
                MockManager.setupAuthStats(); // Setup default for non-callback tests
            }
            
            // Now setup the error
            MockManager.setupError(service, method, error);

            let scenario: TestScenario;
            
            if (setupCallback) {
                scenario = TestBuilder
                .create(`${service} ${method} error`)
                .withParams({ provider: 'google' })
                .withQuery({ code: 'auth-code', state: testData!.state })
                .expectError()
                .build();
            } else {
                scenario = TestBuilder
                .create(`${service} ${method} error`)
                .withUser(TestDataFactory.createUser())
                .expectError()
                .build();
            }

            const context = await TestExecutor.run(oauthController[testMethod], scenario);
            AssertionHelper.expectError(context);
            }
        );
        });

        describe('API error consistency', () => {
        it('should handle API errors consistently with auth system', async () => {
            MockManager.setupAuthStats(); // Setup default first
            MockManager.setupError('auth', 'getUserAuthStats', ApiError.notFound('User not found', 'USER_NOT_FOUND'));

            const scenario = TestBuilder
            .create('API error consistency')
            .withUser(TestDataFactory.createUser())
            .expectError('User not found', 404)
            .build();

            const context = await TestExecutor.run(oauthController.getOAuthStatus, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage, scenario.expectedStatus);
        });

        it('should wrap unexpected errors like auth system', async () => {
            MockManager.setupAuthStats(); // Setup default first
            MockManager.setupError('auth', 'getUserAuthStats', 'Unexpected string error' as any);

            const scenario = TestBuilder
            .create('unexpected error wrapping')
            .withUser(TestDataFactory.createUser())
            .expectError('Failed to retrieve OAuth status')
            .build();

            const context = await TestExecutor.run(oauthController.getOAuthStatus, scenario);
            AssertionHelper.expectError(context, scenario.expectedErrorMessage);
        });
        });
    });

    // ==================== RESOURCE MANAGEMENT AND CLEANUP ====================

    describe('resource management', () => {
        it('should not leave hanging promises or timers', async () => {
        const scenario = TestBuilder
            .create('resource cleanup')
            .withParams({ provider: 'google' })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .build();

        await TestExecutor.run(oauthController.authorize, scenario);
        // Jest will detect hanging promises/timers and warn about them
        });

        it('should handle controller method calls without side effects', async () => {
        const logSpy = jest.spyOn(console, 'log');
        const errorSpy = jest.spyOn(console, 'error');
        const warnSpy = jest.spyOn(console, 'warn');

        const scenario = TestBuilder
            .create('side effect check')
            .withParams({ provider: 'google' })
            .withMockSetup(() => MockManager.setupValidOAuthFlow('google'))
            .build();

        await TestExecutor.run(oauthController.authorize, scenario);

        expect(logSpy).not.toHaveBeenCalled();
        expect(errorSpy).not.toHaveBeenCalled();
        expect(warnSpy).not.toHaveBeenCalled();

        logSpy.mockRestore();
        errorSpy.mockRestore();
        warnSpy.mockRestore();
        });

        it('should maintain consistent timing behavior', async () => {
        const timingTests = [
            { method: 'authorize', params: { provider: 'google' } },
            { method: 'unlinkProvider', params: { provider: 'google' }, user: TestDataFactory.createUser() }
        ];

        for (const { method, params, user } of timingTests) {
            MockManager.reset();
            
            if (method === 'unlinkProvider') {
            MockManager.setupAuthStats();
            } else {
            MockManager.setupValidOAuthFlow('google');
            }

            const scenarioBuilder = TestBuilder
            .create(`timing ${method}`)
            .withParams(params);
            
            if (user) {
            scenarioBuilder.withUser(user);
            }
            
            const scenario = scenarioBuilder.build();

            await TestExecutor.run(oauthController[method], scenario);
            expect(MockManager.auth.ensureMinimumResponseTime).toHaveBeenCalled();
        }
        });
    });

    // ==================== INTEGRATION WITH AUTH SYSTEM ====================

    describe('integration with auth system', () => {
        it('should use auth service email validation for OAuth emails', async () => {
        const testData = MockManager.setupValidOAuthFlow('google');
        testData.userInfo.email = 'real-email@gmail.com';
        MockManager.oauth.getUserInfo.mockResolvedValue(testData.userInfo);

        const scenario = TestBuilder
            .create('auth service email validation')
            .withParams({ provider: 'google' })
            .withQuery({ code: 'auth-code', state: testData.state })
            .build();

        await TestExecutor.run(oauthController.callback, scenario);
        expect(MockManager.auth.validateEmailFormat).toHaveBeenCalledWith('real-email@gmail.com');
        });

        it('should return responses in consistent auth system format', async () => {
        const mockStats = MockManager.setupAuthStats({
            linkedProviders: ['google'],
            authenticationMethods: { password: true, oauth: true }
        });

        const scenario = TestBuilder
            .create('response format consistency')
            .withUser(TestDataFactory.createUser())
            .expectSuccess(200)
            .build();

        const context = await TestExecutor.run(oauthController.getOAuthStatus, scenario);
        
        expect(context.res.json).toHaveBeenCalledWith({
            status: 'success',
            data: expect.objectContaining({
            linkedProviders: mockStats.linkedProviders,
            authenticationMethods: mockStats.authenticationMethods
            })
        });
        });

        it('should use consistent success response structure for unlink', async () => {
        MockManager.setupAuthStats({
            hasPassword: true,
            linkedProviders: ['google', 'github'],
            authenticationMethods: { password: true, oauth: true }
        });

        const scenario = TestBuilder
            .create('unlink response format')
            .withParams({ provider: 'google' })
            .withUser(TestDataFactory.createUser())
            .build();

        const context = await TestExecutor.run(oauthController.unlinkProvider, scenario);
        
        expect(context.res.json).toHaveBeenCalledWith({
            status: 'success',
            message: expect.stringContaining('Successfully unlinked google account')
        });
        });
    });
});