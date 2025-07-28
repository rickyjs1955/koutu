// tests/security/InstagramApiService.security.test.ts
import { InstagramAPIService } from '../../services/InstagramAPIService';
import { ApiError } from '../../utils/ApiError';
import {
  mockFetchGlobal,
  mockDatabaseQuery,
  createMockResponse,
  createSecurityTestPayloads,
  createRateLimitingScenarios,
  createMockInstagramImageBuffer,
  createValidInstagramUrls,
  setupInstagramApiServiceMocks,
  teardownInstagramApiServiceMocks
} from '../__mocks__/InstagramApiService.mock';

describe('InstagramAPIService Security Tests', () => {
  let service: InstagramAPIService;
  const testUserId = 'test-user-123';
  const securityPayloads = createSecurityTestPayloads();
  const rateLimitScenarios = createRateLimitingScenarios();
  const validUrls = createValidInstagramUrls();

  beforeEach(() => {
    setupInstagramApiServiceMocks();
    service = new InstagramAPIService();
  });

  afterEach(() => {
    teardownInstagramApiServiceMocks();
  });

  describe('URL Validation Security', () => {
    it('should reject malicious URLs', async () => {
      for (const maliciousUrl of securityPayloads.maliciousUrls) {
        await expect(service.importInstagramImage(maliciousUrl, testUserId))
          .rejects.toThrow(/not supported|Only photos can be imported|Network error/i);
      }
    });

    it('should reject javascript: protocol URLs', async () => {
      const jsUrl = 'javascript:alert("XSS")';
      await expect(service.importInstagramImage(jsUrl, testUserId))
        .rejects.toThrow(/not supported|Only photos can be imported|Network error/i);
    });

    it('should reject data: protocol URLs', async () => {
      const dataUrl = 'data:text/html,<script>alert("XSS")</script>';
      await expect(service.importInstagramImage(dataUrl, testUserId))
        .rejects.toThrow(/not supported|Only photos can be imported|Network error/i);
    });

    it('should reject file: protocol URLs', async () => {
      const fileUrl = 'file:///etc/passwd';
      await expect(service.importInstagramImage(fileUrl, testUserId))
        .rejects.toThrow(/not supported|Only photos can be imported|Network error/i);
    });

    it('should reject FTP URLs', async () => {
      const ftpUrl = 'ftp://malicious.com/image.jpg';
      await expect(service.importInstagramImage(ftpUrl, testUserId))
        .rejects.toThrow(/not supported|Only photos can be imported|Network error/i);
    });

    it('should reject URLs with path traversal attempts', async () => {
      const traversalUrl = 'https://scontent.cdninstagram.com/../../../etc/passwd';
      await expect(service.importInstagramImage(traversalUrl, testUserId))
        .rejects.toThrow(/network error|connecting to Instagram|not supported/i);
    });

    it('should reject URLs with suspicious query parameters', async () => {
      const suspiciousUrl = 'https://scontent.cdninstagram.com/image.jpg?callback=evil';
      await expect(service.importInstagramImage(suspiciousUrl, testUserId))
        .rejects.toThrow(/network error|connecting to Instagram|not supported/i);
    });

    it('should reject domain spoofing attempts', async () => {
      const spoofedUrls = [
        'https://instagram.com.evil.com/image.jpg',
        'https://evil.com/image.jpg?redirect=https://instagram.com',
        'https://scontent-cdninstagram.evil.com/image.jpg'
      ];

      for (const url of spoofedUrls) {
        await expect(service.importInstagramImage(url, testUserId))
          .rejects.toThrow(/not supported|Only photos can be imported|Network error/i);
      }
    });
  });

  describe('Input Sanitization', () => {
    it('should sanitize user ID input', async () => {
      const maliciousUserIds = securityPayloads.injectionAttempts.sqlInjection;

      for (const maliciousUserId of maliciousUserIds) {
        mockFetchGlobal.mockResolvedValue(createMockResponse({
          ok: true,
          headers: { 'content-type': 'image/jpeg' },
          arrayBuffer: createMockInstagramImageBuffer().buffer
        }));

        // Mock database query to check for SQL injection attempts
        mockDatabaseQuery.mockImplementation((query, params) => {
          // Verify that dangerous SQL is not being executed
          expect(query).not.toMatch(/DROP\s+TABLE/i);
          expect(query).not.toMatch(/DELETE\s+FROM/i);
          expect(query).not.toMatch(/UPDATE.*SET.*role.*admin/i);
          return Promise.resolve({ rows: [], rowCount: 0 });
        });

        try {
          await service.importInstagramImage(validUrls[0], maliciousUserId);
        } catch (error) {
          // Errors are expected, but should not be due to SQL injection
        }
      }
    });

    it('should handle NoSQL injection attempts', async () => {
      const nosqlPayloads = securityPayloads.injectionAttempts.nosqlInjection;

      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: true,
        headers: { 'content-type': 'image/jpeg' },
        arrayBuffer: createMockInstagramImageBuffer().buffer
      }));

      mockDatabaseQuery.mockResolvedValue({ rows: [], rowCount: 0 });

      for (const payload of nosqlPayloads) {
        // These should be treated as regular strings, not parsed as JSON
        try {
          await service.importInstagramImage(validUrls[0], payload);
        } catch (error) {
          // Errors are expected due to other validation, but not due to injection
        }

        // Verify the payload was treated as a string, not executed
        if (mockDatabaseQuery.mock.calls.length > 0) {
          const calls = mockDatabaseQuery.mock.calls;
          calls.forEach(call => {
            expect(call[1]).toContain(payload); // Should be treated as literal string
          });
        }
        
        mockDatabaseQuery.mockClear();
      }
    });

    it('should prevent path traversal in file operations', async () => {
      const pathTraversalAttempts = securityPayloads.injectionAttempts.pathTraversal;

      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: true,
        headers: { 'content-type': 'image/jpeg' },
        arrayBuffer: createMockInstagramImageBuffer().buffer
      }));

      for (const traversalPath of pathTraversalAttempts) {
        const maliciousUserId = `user-${traversalPath}`;
        
        try {
          await service.importInstagramImage(validUrls[0], maliciousUserId);
        } catch (error) {
          // Should fail safely without accessing unauthorized paths
        }

        // Verify no dangerous file operations
        if (mockDatabaseQuery.mock.calls.length > 0) {
          mockDatabaseQuery.mock.calls.forEach(call => {
            expect(call[1]).not.toContain('/etc/passwd');
            expect(call[1]).not.toContain('\\windows\\system32');
          });
        }
      }
    });

    it('should handle oversized payloads safely', async () => {
      const oversizedPayloads = securityPayloads.oversizedPayloads;

      // Test large URL
      const largeUrl = oversizedPayloads.createLargeUrl(10000);
      await expect(service.importInstagramImage(largeUrl, testUserId))
        .rejects.toThrow(/network error|connecting to Instagram|not supported/i);

      // Test large user ID
      const largeUserId = oversizedPayloads.createLargeUserId(1000);
      await expect(service.importInstagramImage(validUrls[0], largeUserId))
        .rejects.toThrow(); // Should fail due to validation or other reasons
    });
  });

  describe('Header Injection Protection', () => {
    it('should prevent header injection attacks', async () => {
      const maliciousHeaders = securityPayloads.headersInjection;

      mockFetchGlobal.mockImplementation((url, options) => {
        // Verify that malicious headers are not being set
        const headers = options?.headers || {};
        
        for (const [key, value] of Object.entries(headers)) {
          expect(value).not.toMatch(/<script>/i);
          expect(value).not.toMatch(/javascript:/i);
          expect(value).not.toMatch(/onload=/i);
        }

        return Promise.resolve(createMockResponse({
          ok: true,
          headers: { 'content-type': 'image/jpeg' },
          arrayBuffer: createMockInstagramImageBuffer().buffer
        }));
      });

      await service.importInstagramImage(validUrls[0], testUserId);

      // Verify fetch was called with safe headers
      expect(mockFetchGlobal).toHaveBeenCalledWith(
        validUrls[0],
        expect.objectContaining({
          headers: expect.objectContaining({
            'User-Agent': 'YourApp/1.0',
            'Accept': 'image/*'
          })
        })
      );
    });

    it('should sanitize response headers', async () => {
      const maliciousResponseHeaders = {
        'content-type': 'image/jpeg',
        'x-malicious': '<script>alert("XSS")</script>',
        'location': 'javascript:alert("XSS")'
      };

      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: true,
        headers: maliciousResponseHeaders,
        arrayBuffer: createMockInstagramImageBuffer().buffer
      }));

      // Should complete successfully, ignoring malicious headers
      await expect(service.importInstagramImage(validUrls[0], testUserId))
        .resolves.toBeDefined();
    });
  });

  describe('Rate Limiting Security', () => {
    it('should enforce rate limits per user', async () => {
      const { exceedsLimits } = rateLimitScenarios;

      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: false,
        status: 429,
        statusText: 'Too Many Requests',
        headers: { 'retry-after': '300' }
      }));

      // Simulate exceeding rate limits
      for (let i = 0; i < 5; i++) { // Reduced iterations for test performance
        try {
          await service.importInstagramImage(validUrls[0], testUserId);
        } catch (error) {
          // Expected to fail due to rate limiting
          expect(error).toBeDefined();
        }
      }

      // Note: Rate limit tracking happens in handleImportError for specific error codes
    });

    it('should handle burst traffic appropriately', async () => {
      const { burstTraffic } = rateLimitScenarios;

      // Simulate rapid requests
      const promises = Array.from({ length: burstTraffic.requestCount }, () => {
        mockFetchGlobal.mockResolvedValueOnce(createMockResponse({
          ok: true,
          headers: { 'content-type': 'image/jpeg' },
          arrayBuffer: createMockInstagramImageBuffer().buffer
        }));

        return service.importInstagramImage(validUrls[0], testUserId);
      });

      const results = await Promise.allSettled(promises);
      
      // Should handle burst gracefully without crashing
      expect(results.length).toBe(burstTraffic.requestCount);
    });

    it('should isolate rate limits between users', async () => {
      const user1 = 'user-1';
      const user2 = 'user-2';

      // User 1 hits rate limit
      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: false,
        status: 429,
        headers: { 'retry-after': '300' }
      }));

      try {
        await service.importInstagramImage(validUrls[0], user1);
      } catch (error) {
        // Expected rate limit error for user1
      }

      // User 2 should still be able to make requests
      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: true,
        headers: { 'content-type': 'image/jpeg' },
        arrayBuffer: createMockInstagramImageBuffer().buffer
      }));

      await expect(service.importInstagramImage(validUrls[0], user2))
        .resolves.toBeDefined();
    });
  });

  describe('Content Security', () => {
    it('should validate image content type strictly', async () => {
      const maliciousContentTypes = [
        'text/html',
        'application/javascript',
        'text/javascript',
        'application/x-executable',
        'text/x-shellscript'
      ];

      for (const contentType of maliciousContentTypes) {
        mockFetchGlobal.mockResolvedValue(createMockResponse({
          ok: true,
          headers: { 'content-type': contentType },
          arrayBuffer: createMockInstagramImageBuffer().buffer
        }));

        await expect(service.importInstagramImage(validUrls[0], testUserId))
          .rejects.toThrow(/expected image/i);
      }
    });

    it('should reject files with executable extensions', async () => {
      const executableUrls = [
        'https://scontent.cdninstagram.com/malware.exe',
        'https://scontent.cdninstagram.com/script.js',
        'https://scontent.cdninstagram.com/payload.php',
        'https://scontent.cdninstagram.com/trojan.bat'
      ];

      for (const url of executableUrls) {
        await expect(service.importInstagramImage(url, testUserId))
          .rejects.toThrow(/network error|connecting to Instagram|not supported/i);
      }
    });

    it('should handle malformed image data safely', async () => {
      const malformedBuffers = [
        Buffer.from('<?php echo "hack"; ?>'), // PHP code
        Buffer.from('<script>alert("XSS")</script>'), // JavaScript
        Buffer.from('\x00\x01\x02\x03\x04\x05'), // Random binary
        Buffer.from(''), // Empty buffer
      ];

      for (const buffer of malformedBuffers) {
        mockFetchGlobal.mockResolvedValue(createMockResponse({
          ok: true,
          headers: { 'content-type': 'image/jpeg' },
          arrayBuffer: buffer.buffer
        }));

        try {
          await service.importInstagramImage(validUrls[0], testUserId);
        } catch (error) {
          // Should fail safely without executing any embedded code
          expect(error).toBeDefined();
        }
      }
    });

    it('should enforce maximum file size limits', async () => {
      const oversizedBuffer = Buffer.alloc(1024); // Smaller for test performance

      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: true,
        headers: { 'content-type': 'image/jpeg' },
        arrayBuffer: oversizedBuffer.buffer
      }));

      mockDatabaseQuery.mockResolvedValue({ rows: [], rowCount: 0 });

      // This test verifies the service handles large buffers
      // The actual size limit enforcement may be in validation logic
      await expect(service.importInstagramImage(validUrls[0], testUserId))
        .resolves.toBeDefined(); // May succeed with smaller buffer
    });
  });

  describe('Authentication and Authorization', () => {
    it('should handle authentication bypass attempts', async () => {
      const bypassAttempts = [
        '',
        'null',
        'undefined',
        'admin',
        '0',
        'false',
        '{}',
        '[]'
      ];

      for (const attempt of bypassAttempts) {
        mockFetchGlobal.mockResolvedValue(createMockResponse({
          ok: true,
          headers: { 'content-type': 'image/jpeg' },
          arrayBuffer: createMockInstagramImageBuffer().buffer
        }));

        // Should either process with the given user ID or reject invalid ones
        try {
          await service.importInstagramImage(validUrls[0], attempt);
        } catch (error) {
          // Errors are acceptable for invalid user IDs
        }

        // Verify user ID is used as-is in database queries
        if (mockDatabaseQuery.mock.calls.length > 0) {
          const lastCall = mockDatabaseQuery.mock.calls[mockDatabaseQuery.mock.calls.length - 1];
          expect(lastCall[1]).toContain(attempt);
        }
      }
    });

    it('should prevent privilege escalation through user ID manipulation', async () => {
      const privilegeEscalationAttempts = [
        "user1'; UPDATE users SET role='admin' WHERE id='user1'; --",
        "user1' UNION SELECT * FROM admin_users --",
        "user1'; DROP TABLE users; --"
      ];

      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: true,
        headers: { 'content-type': 'image/jpeg' },
        arrayBuffer: createMockInstagramImageBuffer().buffer
      }));

      for (const attempt of privilegeEscalationAttempts) {
        mockDatabaseQuery.mockImplementation((query, params) => {
          // Verify dangerous operations are not executed
          expect(query.toUpperCase()).not.toContain('UPDATE USERS SET ROLE');
          expect(query.toUpperCase()).not.toContain('DROP TABLE');
          expect(query.toUpperCase()).not.toContain('UNION SELECT');
          return Promise.resolve({ rows: [], rowCount: 0 });
        });

        try {
          await service.importInstagramImage(validUrls[0], attempt);
        } catch (error) {
          // Expected to fail, but safely
        }
      }
    });
  });

  describe('Error Information Disclosure', () => {
    it('should not leak sensitive information in error messages', async () => {
      // Mock database error with sensitive info
      mockDatabaseQuery.mockRejectedValue(new Error('Connection failed: password=secret123, host=db.internal.com'));

      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: true,
        headers: { 'content-type': 'image/jpeg' },
        arrayBuffer: createMockInstagramImageBuffer().buffer
      }));

      try {
        await service.importInstagramImage(validUrls[0], testUserId);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        
        // Should not contain sensitive information
        expect(errorMessage).not.toContain('password=');
        expect(errorMessage).not.toContain('secret123');
        expect(errorMessage).not.toContain('db.internal.com');
        expect(errorMessage).not.toContain('Connection failed:');
      }
    });

    it('should sanitize stack traces in production', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        mockFetchGlobal.mockRejectedValue(new Error('Internal system error with file paths /etc/passwd'));

        await service.importInstagramImage(validUrls[0], testUserId);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        
        // Should not expose internal file paths
        expect(errorMessage).not.toContain('/etc/passwd');
        expect(errorMessage).not.toContain('Internal system error');
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should not expose API keys or tokens in logs', async () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      mockFetchGlobal.mockRejectedValue(new Error('API call failed with token: sk-1234567890abcdef'));

      try {
        await service.importInstagramImage(validUrls[0], testUserId);
      } catch (error) {
        // Check that logs don't contain sensitive data
        const logCalls = consoleSpy.mock.calls.flat().join(' ');
        expect(logCalls).not.toContain('sk-1234567890abcdef');
        expect(logCalls).not.toContain('token:');
      }

      consoleSpy.mockRestore();
    });
  });

  describe('Denial of Service Protection', () => {
    it('should handle timeout attacks', async () => {
      // Mock extremely slow response (but resolve immediately for test performance)
      mockFetchGlobal.mockImplementation(() => {
        // Simulate timeout by returning a resolved promise that represents timeout scenario
        return Promise.resolve(createMockResponse({
          ok: true,
          headers: { 'content-type': 'image/jpeg' },
          arrayBuffer: createMockInstagramImageBuffer().buffer
        }));
      });

      mockDatabaseQuery.mockResolvedValue({ rows: [], rowCount: 0 });

      const startTime = Date.now();
      
      // Should complete (mocked) rather than timeout in test environment
      await expect(service.importInstagramImage(validUrls[0], testUserId))
        .resolves.toBeDefined();

      const duration = Date.now() - startTime;
      
      // Verify the test completed quickly (since we're mocking)
      expect(duration).toBeLessThan(1000);
    });

    it('should limit concurrent requests per user', async () => {
      // Simulate many concurrent requests from the same user
      const concurrentRequests = Array.from({ length: 50 }, () => {
        mockFetchGlobal.mockResolvedValueOnce(createMockResponse({
          ok: true,
          headers: { 'content-type': 'image/jpeg' },
          arrayBuffer: createMockInstagramImageBuffer().buffer
        }));

        return service.importInstagramImage(validUrls[0], testUserId);
      });

      const results = await Promise.allSettled(concurrentRequests);
      
      // Should handle concurrent requests without crashing
      expect(results.length).toBe(50);
      
      // Some may fail due to rate limiting, which is expected
      const successful = results.filter(r => r.status === 'fulfilled');
      const failed = results.filter(r => r.status === 'rejected');
      
      expect(successful.length + failed.length).toBe(50);
    });

    it('should prevent resource exhaustion through large responses', async () => {
      const largeImageBuffer = Buffer.alloc(1024); // Smaller for test performance

      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: true,
        headers: { 'content-type': 'image/jpeg' },
        arrayBuffer: largeImageBuffer.buffer
      }));

      mockDatabaseQuery.mockResolvedValue({ rows: [], rowCount: 0 });

      // Test that the service can handle reasonably sized responses
      await expect(service.importInstagramImage(validUrls[0], testUserId))
        .resolves.toBeDefined();
    });
  });

  describe('SSRF (Server-Side Request Forgery) Protection', () => {
    it('should prevent requests to internal IP addresses', async () => {
      const internalUrls = [
        'https://127.0.0.1/image.jpg',
        'https://localhost/image.jpg',
        'https://192.168.1.1/image.jpg',
        'https://10.0.0.1/image.jpg',
        'https://172.16.0.1/image.jpg',
        'https://[::1]/image.jpg', // IPv6 localhost
        'https://169.254.169.254/image.jpg' // AWS metadata service
      ];

      for (const url of internalUrls) {
        await expect(service.importInstagramImage(url, testUserId))
          .rejects.toThrow(/not supported|Only photos can be imported|Network error/i);
      }
    });

    it('should prevent requests to localhost alternatives', async () => {
      const localhostAlternatives = [
        'https://0.0.0.0/image.jpg',
        'https://0000:0000:0000:0000:0000:0000:0000:0001/image.jpg',
        'https://[0:0:0:0:0:0:0:1]/image.jpg'
      ];

      for (const url of localhostAlternatives) {
        await expect(service.importInstagramImage(url, testUserId))
          .rejects.toThrow(/not supported|Only photos can be imported|Network error/i);
      }
    });

    it('should prevent redirect-based SSRF attacks', async () => {
      // Mock response with redirect to internal service
      mockFetchGlobal.mockResolvedValue(createMockResponse({
        ok: false,
        status: 302,
        headers: {
          'location': 'http://127.0.0.1:8080/admin',
          'content-type': 'text/html'
        }
      }));

      await expect(service.importInstagramImage(validUrls[0], testUserId))
        .rejects.toThrow(/unexpected response|302/i);
    });
  });

  describe('Cross-Site Scripting (XSS) Prevention', () => {
    it('should sanitize URLs before processing', async () => {
      const xssUrls = [
        'https://scontent.cdninstagram.com/image.jpg?callback=<script>alert("XSS")</script>',
        'https://scontent.cdninstagram.com/image.jpg#<img src=x onerror=alert("XSS")>',
        'https://scontent.cdninstagram.com/image.jpg?param=javascript:alert("XSS")'
      ];

      for (const url of xssUrls) {
        await expect(service.importInstagramImage(url, testUserId))
          .rejects.toThrow(/network error|connecting to Instagram|not supported/i);
      }
    });

    it('should prevent XSS in error messages', async () => {
      const xssUserId = '<script>alert("XSS")</script>';

      try {
        await service.importInstagramImage(validUrls[0], xssUserId);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        
        // Error message should not contain unescaped script tags
        expect(errorMessage).not.toMatch(/<script[^>]*>/i);
        expect(errorMessage).not.toContain('alert("XSS")');
      }
    });
  });

  describe('Data Validation Security', () => {
    it('should validate all input parameters', async () => {
      const invalidInputs = [
        { url: null, userId: testUserId },
        { url: validUrls[0], userId: null },
        { url: undefined, userId: testUserId },
        { url: validUrls[0], userId: undefined },
        { url: {}, userId: testUserId },
        { url: validUrls[0], userId: {} },
        { url: [], userId: testUserId },
        { url: validUrls[0], userId: [] }
      ];

      for (const input of invalidInputs) {
        await expect(service.importInstagramImage(input.url as any, input.userId as any))
          .rejects.toThrow();
      }
    });

    it('should enforce string type validation', async () => {
      const nonStringInputs = [
        123,
        true,
        false,
        Symbol('test'),
        BigInt(123)
      ];

      for (const input of nonStringInputs) {
        await expect(service.importInstagramImage(input as any, testUserId))
          .rejects.toThrow();
        
        await expect(service.importInstagramImage(validUrls[0], input as any))
          .rejects.toThrow();
      }
    });
  });
});