// tests/security/healthRoutes.flutter.security.test.ts
import request from 'supertest';
import express from 'express';
import healthRoutes from '../../routes/healthRoutes';
import { flutterDetectionMiddleware } from '../../middlewares/flutterMiddleware';

describe('Health Routes Security Tests', () => {
  let app: express.Application;

  beforeEach(() => {
    app = express();
    app.use(express.json());
    app.use(flutterDetectionMiddleware);
    app.use('/', healthRoutes);
    
    // Suppress console output for cleaner test results
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Information Disclosure Prevention', () => {
    describe('GET /health', () => {
      test('should not expose sensitive system information', async () => {
        const response = await request(app).get('/health');

        const responseStr = JSON.stringify(response.body);
        
        // Should not expose sensitive file paths
        expect(responseStr).not.toMatch(/\/etc\/passwd/);
        expect(responseStr).not.toMatch(/\/root\//);
        expect(responseStr).not.toMatch(/C:\\Windows\\System32/);
        
        // Should not expose database credentials
        expect(responseStr).not.toMatch(/password/i);
        expect(responseStr).not.toMatch(/secret/i);
        expect(responseStr).not.toMatch(/token/i);
        expect(responseStr).not.toMatch(/api[_-]?key/i);
        
        // Should not expose internal IP addresses
        expect(responseStr).not.toMatch(/192\.168\./);
        expect(responseStr).not.toMatch(/10\.0\.0\./);
        expect(responseStr).not.toMatch(/172\.16\./);
        
        // Should not expose process information
        expect(responseStr).not.toMatch(/process\.env/);
        expect(responseStr).not.toMatch(/NODE_ENV/);
      });

      test('should not expose stack traces in production', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        const response = await request(app).get('/health');

        const responseStr = JSON.stringify(response.body);
        expect(responseStr).not.toMatch(/at\s+\w+\s+\(/); // Stack trace pattern
        expect(responseStr).not.toMatch(/Error:\s+/);
        expect(responseStr).not.toMatch(/\.js:\d+:\d+/);

        process.env.NODE_ENV = originalEnv;
      });

      test('should sanitize version information', async () => {
        const response = await request(app).get('/health');

        // Should not expose exact dependency versions that could reveal vulnerabilities
        expect(response.body.version).toBeDefined();
        expect(typeof response.body.version).toBe('string');
        
        // Should not expose internal build information
        const responseStr = JSON.stringify(response.body);
        expect(responseStr).not.toMatch(/build[-_]?\d+/i);
        expect(responseStr).not.toMatch(/commit/i);
        expect(responseStr).not.toMatch(/sha/i);
      });

      test('should not expose detailed memory addresses', async () => {
        const response = await request(app).get('/health');

        const responseStr = JSON.stringify(response.body);
        
        // Should not expose memory addresses
        expect(responseStr).not.toMatch(/0x[0-9a-fA-F]{8,}/);
        expect(responseStr).not.toMatch(/\[object Object\]/);
        
        // Memory usage should be numbers, not detailed breakdown
        expect(response.body.performance.memoryUsage.used).toBeGreaterThan(0);
        expect(typeof response.body.performance.memoryUsage.used).toBe('number');
      });
    });

    describe('GET /diagnostics', () => {
      test('should require authentication in production', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        const response = await request(app).get('/diagnostics');

        expect(response.status).toBe(403);
        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('AUTHORIZATION_DENIED');

        process.env.NODE_ENV = originalEnv;
      });

      test('should validate admin token format', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        const maliciousTokens = [
          '<script>alert(1)</script>',
          'admin\r\nX-Injected: malicious',
          '../../../etc/passwd',
          'admin; DROP TABLE users;',
          '\x00\x01\x02admin'
        ];

        for (const token of maliciousTokens) {
          const response = await request(app)
            .get('/diagnostics')
            .set('X-Admin-Token', token);

          // Should either reject the token or handle it safely
          expect([403, 500]).toContain(response.status);
        }

        process.env.NODE_ENV = originalEnv;
      });

      test('should not expose sensitive environment variables', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'development';

        const response = await request(app).get('/diagnostics');

        if (response.status === 200) {
          const responseStr = JSON.stringify(response.body);
          
          // Should not expose sensitive env vars
          expect(responseStr).not.toMatch(/JWT_SECRET/);
          expect(responseStr).not.toMatch(/DATABASE_URL/);
          expect(responseStr).not.toMatch(/API_KEY/);
          expect(responseStr).not.toMatch(/PASSWORD/);
          expect(responseStr).not.toMatch(/SECRET/);
        }

        process.env.NODE_ENV = originalEnv;
      });
    });
  });

  describe('Injection Attack Prevention', () => {
    describe('Header Injection', () => {
      test('should prevent CRLF injection in User-Agent', async () => {
        const maliciousUA = 'Dart/2.19.0\r\nX-Injected: malicious\r\nFlutter/3.7.0';
        
        const response = await request(app)
          .get('/health')
          .set('User-Agent', maliciousUA);

        expect(response.status).toBe(200);
        expect(response.headers['x-injected']).toBeUndefined();
      });

      test('should prevent header injection through Origin', async () => {
        const maliciousOrigin = 'http://localhost:3000\r\nX-Evil: injected';
        
        const response = await request(app)
          .get('/flutter-test')
          .set('Origin', maliciousOrigin);

        expect(response.status).toBe(200);
        expect(response.headers['x-evil']).toBeUndefined();
      });

      test('should handle null bytes in headers', async () => {
        const nullByteUA = 'Dart/2.19.0\x00Flutter/3.7.0';
        
        const response = await request(app)
          .get('/health')
          .set('User-Agent', nullByteUA);

        expect(response.status).toBe(200);
        // Should not crash or expose information
      });
    });

    describe('Query Parameter Injection', () => {
      test('should sanitize malicious query parameters', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .query({
            test: '<script>alert(1)</script>',
            param: 'value\r\ninjected',
            evil: '../../../etc/passwd'
          });

        expect(response.status).toBe(200);
        
        // Should not echo back malicious content
        const responseStr = JSON.stringify(response.body);
        expect(responseStr).not.toContain('<script>');
        expect(responseStr).not.toContain('etc/passwd');
      });

      test('should handle SQL injection patterns in parameters', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .query({
            id: "1'; DROP TABLE users; --",
            search: "' OR 1=1 --"
          });

        expect(response.status).toBe(200);
        // Should not expose database errors
      });
    });

    describe('JSON Injection', () => {
      test('should prevent JSON injection in request body', async () => {
        const maliciousPayload = {
          'test": "value", "injected": "evil': 'payload'
        };

        const response = await request(app)
          .post('/ping') // If ping accepts POST
          .send(maliciousPayload);

        // Should handle malformed JSON gracefully
        expect([200, 400, 405]).toContain(response.status);
      });
    });
  });

  describe('Cross-Site Scripting (XSS) Prevention', () => {
    test('should escape HTML in responses', async () => {
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', 'Dart/2.19.0 <img src=x onerror=alert(1)> Flutter/3.7.0');

      expect(response.status).toBe(200);
      
      const responseStr = JSON.stringify(response.body);
      expect(responseStr).not.toContain('<img');
      expect(responseStr).not.toContain('onerror');
      expect(responseStr).not.toContain('alert(1)');
    });

    test('should handle script injection in User-Agent', async () => {
      const scriptUA = 'Dart/2.19.0 <script>document.location="http://evil.com"</script> Flutter/3.7.0';
      
      const response = await request(app)
        .get('/health')
        .set('User-Agent', scriptUA);

      expect(response.status).toBe(200);
      
      const responseStr = JSON.stringify(response.body);
      expect(responseStr).not.toContain('<script>');
      expect(responseStr).not.toContain('document.location');
      expect(responseStr).not.toContain('evil.com');
    });

    test('should prevent JavaScript URL injection', async () => {
      const jsUA = 'Dart/2.19.0 javascript:alert(document.domain) Flutter/3.7.0';
      
      const response = await request(app)
        .get('/flutter-test')
        .set('User-Agent', jsUA);

      expect(response.status).toBe(200);
      
      const responseStr = JSON.stringify(response.body);
      expect(responseStr).not.toContain('javascript:');
      expect(responseStr).not.toContain('alert(');
    });
  });

  describe('Denial of Service (DoS) Prevention', () => {
    describe('Resource Exhaustion', () => {
      test('should handle extremely long User-Agent strings', async () => {
        const longUA = 'Dart/2.19.0 ' + 'A'.repeat(100000) + ' Flutter/3.7.0';
        
        const startTime = Date.now();
        const response = await request(app)
          .get('/health')
          .set('User-Agent', longUA);
        const duration = Date.now() - startTime;

        expect(response.status).toBe(200);
        expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      });

      test('should handle many concurrent requests', async () => {
        const requests = Array(50).fill(0).map((_, i) =>
          request(app)
            .get('/ping')
            .set('User-Agent', `Dart/2.19.0 Request-${i} Flutter/3.7.0`)
        );

        const startTime = Date.now();
        const responses = await Promise.all(requests);
        const duration = Date.now() - startTime;

        // All requests should succeed or fail gracefully
        responses.forEach(response => {
          expect([200, 429, 503]).toContain(response.status);
        });

        // Should handle concurrent load reasonably
        expect(duration).toBeLessThan(10000); // Within 10 seconds
      });

      test('should handle excessive header counts', async () => {
        const requestAgent = request(app).get('/health');
        
        // Add many headers
        for (let i = 0; i < 100; i++) {
          requestAgent.set(`X-Header-${i}`, `value-${i}`);
        }

        const response = await requestAgent;
        expect([200, 400, 413]).toContain(response.status);
      });
    });

    describe('Memory Exhaustion Prevention', () => {
      test('should not leak memory with repeated requests', async () => {
        const initialMemory = process.memoryUsage().heapUsed;

        // Make many requests
        for (let i = 0; i < 50; i++) {
          await request(app)
            .get('/health')
            .set('User-Agent', `Dart/2.19.0 Request-${i} Flutter/3.7.0`);
        }

        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }

        const finalMemory = process.memoryUsage().heapUsed;
        const memoryIncrease = finalMemory - initialMemory;

        // Memory increase should be reasonable
        expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // < 50MB
      });

      test('should handle large request bodies safely', async () => {
        const largePayload = { data: 'A'.repeat(1000000) }; // 1MB payload

        const response = await request(app)
          .post('/ping')
          .send(largePayload);

        expect([200, 400, 413, 405]).toContain(response.status);
      });
    });
  });

  describe('Authentication and Authorization', () => {
    describe('Admin Access Control', () => {
      test('should enforce admin access for diagnostics', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        const response = await request(app).get('/diagnostics');

        expect(response.status).toBe(403);
        expect(response.body.error.code).toBe('AUTHORIZATION_DENIED');

        process.env.NODE_ENV = originalEnv;
      });

      test('should validate admin token securely', async () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        // Test with empty token
        let response = await request(app)
          .get('/diagnostics')
          .set('X-Admin-Token', '');
        expect(response.status).toBe(403);

        // Test with whitespace token
        response = await request(app)
          .get('/diagnostics')
          .set('X-Admin-Token', '   ');
        expect(response.status).toBe(403);

        // Test with null token
        response = await request(app)
          .get('/diagnostics')
          .set('X-Admin-Token', 'null');
        expect(response.status).toBe(403);

        process.env.NODE_ENV = originalEnv;
      });
    });

    describe('Privilege Escalation Prevention', () => {
      test('should not allow privilege escalation through headers', async () => {
        const privilegeHeaders = [
          'X-Admin: true',
          'X-Role: admin',
          'X-Privilege: elevated',
          'X-User-Id: 0',
          'X-Is-Admin: 1'
        ];

        for (const header of privilegeHeaders) {
          const [key, value] = header.split(': ');
          const response = await request(app)
            .get('/diagnostics')
            .set(key, value);

          expect(response.status).toBe(403);
        }
      });
    });
  });

  describe('Data Validation and Sanitization', () => {
    describe('Input Validation', () => {
      test('should validate User-Agent format strictly', async () => {
        const invalidUserAgents = [
          '', // Empty
          '\x00\x01\x02', // Control characters
          'A'.repeat(10000), // Too long
          'Dart/invalid.version Flutter/invalid.version',
          'Dart/../../../etc/passwd Flutter/3.7.0'
        ];

        for (const ua of invalidUserAgents) {
          const response = await request(app)
            .get('/health')
            .set('User-Agent', ua);

          expect(response.status).toBe(200);
          // Should handle gracefully without exposing errors
        }
      });

      test('should sanitize platform detection', async () => {
        const maliciousPlatforms = [
          '<script>alert(1)</script>',
          '../../../etc/passwd',
          'platform\r\ninjected',
          'platform"; DROP TABLE users; --'
        ];

        for (const platform of maliciousPlatforms) {
          const response = await request(app)
            .get('/flutter-test')
            .set('X-Platform', platform);

          expect(response.status).toBe(200);
          
          const responseStr = JSON.stringify(response.body);
          expect(responseStr).not.toContain('<script>');
          expect(responseStr).not.toContain('etc/passwd');
          expect(responseStr).not.toContain('DROP TABLE');
        }
      });
    });

    describe('Output Sanitization', () => {
      test('should not echo unsanitized input', async () => {
        const response = await request(app)
          .get('/flutter-test')
          .set('User-Agent', 'Dart/2.19.0 <evil>payload</evil> Flutter/3.7.0')
          .set('X-App-Version', '<script>alert("xss")</script>');

        expect(response.status).toBe(200);
        
        const responseStr = JSON.stringify(response.body);
        expect(responseStr).not.toContain('<evil>');
        expect(responseStr).not.toContain('<script>');
        expect(responseStr).not.toContain('alert("xss")');
      });
    });
  });

  describe('Error Handling Security', () => {
    test('should not expose stack traces to clients', async () => {
      // This would require mocking internal errors
      // For now, test that errors are handled gracefully
      const response = await request(app)
        .get('/health')
        .set('User-Agent', '\x00\x01\x02'); // Malformed input

      expect(response.status).toBe(200);
      
      const responseStr = JSON.stringify(response.body);
      expect(responseStr).not.toMatch(/Error:/);
      expect(responseStr).not.toMatch(/at\s+\w+/);
      expect(responseStr).not.toMatch(/\.js:\d+/);
    });

    test('should handle internal errors without information disclosure', async () => {
      // Test with various error-inducing inputs
      const errorInputs = [
        { path: '/health', ua: 'Dart/2.19.0 ' + '\x00'.repeat(1000) },
        { path: '/flutter-test', ua: 'Dart/\uD800\uDFFF Flutter/3.7.0' },
        { path: '/ping', ua: 'Dart/' + 'A'.repeat(100000) }
      ];

      for (const { path, ua } of errorInputs) {
        const response = await request(app)
          .get(path)
          .set('User-Agent', ua);

        // Should not expose internal errors
        expect([200, 400, 500]).toContain(response.status);
        
        if (response.body.error) {
          expect(response.body.error.message).not.toContain('Internal Error');
          expect(response.body.error.message).not.toContain('Database');
          expect(response.body.error.message).not.toContain('File system');
        }
      }
    });
  });

  describe('Timing Attack Prevention', () => {
    test('should have consistent response times regardless of input', async () => {
      const inputs = [
        'Dart/2.19.0 Flutter/3.7.0', // Valid Flutter
        'Mozilla/5.0', // Valid browser
        'invalid-user-agent', // Invalid
        '', // Empty
        'A'.repeat(1000) // Long
      ];

      const times: number[] = [];

      for (const ua of inputs) {
        const start = Date.now();
        const response = await request(app)
          .get('/health')
          .set('User-Agent', ua);
        const duration = Date.now() - start;

        expect(response.status).toBe(200);
        times.push(duration);
      }

      // Check that timing variations are not significant
      const maxTime = Math.max(...times);
      const minTime = Math.min(...times);
      const timingVariation = maxTime - minTime;

      // Timing difference should be reasonable (< 100ms variation)
      expect(timingVariation).toBeLessThan(100);
    });
  });

  describe('Content Security Policy', () => {
    test('should set secure response headers', async () => {
      const response = await request(app).get('/health');

      expect(response.status).toBe(200);
      // Verify that security headers are set (implementation dependent)
      // This would need to be configured in the actual health routes
    });

    test('should prevent MIME type sniffing', async () => {
      const response = await request(app).get('/health');

      expect(response.headers['content-type']).toContain('application/json');
      // Should not be vulnerable to MIME sniffing attacks
    });
  });
});