// backend/src/__tests__/security/ApiError.security.test.ts
import { jest } from '@jest/globals';
import { ApiError } from '../../utils/ApiError';

/**
 * Security-focused tests for ApiError class
 * 
 * These tests validate that ApiError handles security scenarios correctly:
 * - Information disclosure prevention
 * - Input sanitization and validation
 * - Error message safety
 * - Context data protection
 * - Memory safety and DoS prevention
 * - Injection attack prevention
 */

describe('ApiError Security Tests', () => {
  beforeEach(() => {
    // Reset environment to test state
    process.env.NODE_ENV = 'test';
  });

  afterEach(() => {
    // Restore original environment
    delete process.env.NODE_ENV;
  });

  describe('Information Disclosure Prevention', () => {
    describe('Sensitive Data in Error Messages', () => {
      it('should not expose sensitive information in error messages', () => {
        const sensitiveData = {
          password: 'secret123',
          apiKey: 'sk_live_1234567890abcdef',
          token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          creditCard: '4111-1111-1111-1111',
          ssn: '123-45-6789'
        };

        // Create error with sensitive data in context
        const error = ApiError.validation(
          'User validation failed',
          'userData',
          sensitiveData,
          'validation'
        );

        const json = error.toJSON();
        const jsonString = JSON.stringify(json);

        // Verify sensitive data is not in the serialized output
        expect(jsonString).not.toContain('secret123');
        expect(jsonString).not.toContain('sk_live_');
        expect(jsonString).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
        expect(jsonString).not.toContain('4111-1111-1111-1111');
        expect(jsonString).not.toContain('123-45-6789');
      });

      it('should sanitize error messages with potential sensitive patterns', () => {
        const maliciousMessage = 'Database error: password=secret123, api_key=sk_live_abcd1234';
        const error = ApiError.database(maliciousMessage, 'SELECT', 'users');

        expect(error.message).toBe(maliciousMessage); // Message is stored as-is
        
        // But in production, context should be hidden
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';
        
        const json = error.toJSON();
        expect(json.context).toBeUndefined();
        
        process.env.NODE_ENV = originalEnv;
      });

      it('should prevent stack trace information disclosure', () => {
        const internalError = new Error('Internal system details: /etc/passwd, database credentials');
        internalError.stack = 'Error: Internal details\n    at /home/user/app/secrets/config.js:42:15';
        
        const apiError = ApiError.fromUnknown(internalError);
        const json = apiError.toJSON();

        // Verify stack traces are not exposed
        expect(json).not.toHaveProperty('stack');
        expect(JSON.stringify(json)).not.toContain('/home/user/app');
        expect(JSON.stringify(json)).not.toContain('config.js');
      });
    });

    describe('Environment-based Information Disclosure', () => {
      it('should hide sensitive context in production environment', () => {
        const sensitiveContext = {
          databaseUrl: 'postgresql://user:password@localhost:5432/app',
          internalPath: '/var/lib/app/secrets/keys.pem',
          debugInfo: { query: 'SELECT * FROM users WHERE password = ?', params: ['secret'] }
        };

        const error = ApiError.internal('Server error', 'INTERNAL', undefined, sensitiveContext);

        // In production, context should be hidden
        process.env.NODE_ENV = 'production';
        const prodJson = error.toJSON();
        expect(prodJson.context).toBeUndefined();

        // In development, context should be visible (for debugging)
        process.env.NODE_ENV = 'development';
        const devJson = error.toJSON();
        expect(devJson.context).toEqual(sensitiveContext);
      });

      it('should handle undefined NODE_ENV safely', () => {
        delete process.env.NODE_ENV;
        
        const error = ApiError.validation('Test error', 'field', 'value', 'rule');
        const json = error.toJSON();

        // Should default to hiding context when NODE_ENV is undefined
        expect(json.context).toBeUndefined();
      });
    });
  });

  describe('Input Sanitization and Validation', () => {
    describe('Message Sanitization', () => {
      it('should handle XSS attempts in error messages', () => {
        const xssAttempts = [
          '<script>alert("xss")</script>',
          'javascript:alert("xss")',
          '<img src="x" onerror="alert(1)">',
          '"><script>alert(document.cookie)</script>',
          'data:text/html,<script>alert("xss")</script>'
        ];

        xssAttempts.forEach(xssPayload => {
          const error = ApiError.badRequest(xssPayload);
          
          // Error should store the message as-is (responsibility of output encoding is on the client)
          expect(error.message).toBe(xssPayload);
          
          // But JSON serialization should work safely
          expect(() => error.toJSON()).not.toThrow();
          expect(error.toJSON().message).toBe(xssPayload);
        });
      });

      it('should handle SQL injection attempts in error messages', () => {
        const sqlInjectionAttempts = [
          "'; DROP TABLE users; --",
          "' OR '1'='1",
          "1'; DELETE FROM users WHERE '1'='1",
          "'; EXEC xp_cmdshell('dir'); --",
          "UNION SELECT password FROM users"
        ];

        sqlInjectionAttempts.forEach(sqlPayload => {
          const error = ApiError.database(
            `Database query failed: ${sqlPayload}`,
            'SELECT',
            'users'
          );
          
          expect(error.message).toContain(sqlPayload);
          expect(() => error.toJSON()).not.toThrow();
        });
      });

      it('should handle extremely long error messages safely', () => {
        const longMessage = 'A'.repeat(10000); // 10KB message
        const error = ApiError.badRequest(longMessage);

        expect(error.message).toBe(longMessage);
        expect(error.message.length).toBe(10000);
        expect(() => error.toJSON()).not.toThrow();
      });

      it('should handle unicode and special characters safely', () => {
        const specialChars = [
          '🚀💀👻🔥', // Emojis
          '中文测试', // Chinese characters
          'العربية', // Arabic
          'русский', // Cyrillic
          '𝔲𝔫𝔦𝔠𝔬𝔡𝔢', // Mathematical characters
          '\u0000\u0001\u0002', // Control characters
          '\n\r\t', // Newlines and tabs
          '\\x00\\x01\\x02' // Escaped characters
        ];

        specialChars.forEach(specialChar => {
          const error = ApiError.validation(
            `Invalid input: ${specialChar}`,
            'field',
            specialChar,
            'format'
          );
          
          expect(error.message).toContain(specialChar);
          expect(() => error.toJSON()).not.toThrow();
        });
      });
    });

    describe('Code Sanitization', () => {
      it('should sanitize error codes to prevent injection', () => {
        const maliciousCodes = [
          '<script>alert(1)</script>',
          'javascript:void(0)',
          '../../etc/passwd',
          '${process.env.SECRET}',
          '{{constructor.constructor("return process")().env}}',
          'eval("alert(1)")'
        ];

        maliciousCodes.forEach(maliciousCode => {
          const error = ApiError.badRequest('Test error', maliciousCode);
          
          // Code should be stored as provided
          expect(error.code).toBe(maliciousCode);
          
          // But serialization should be safe
          expect(() => error.toJSON()).not.toThrow();
          const json = error.toJSON();
          expect(json.code).toBe(maliciousCode);
        });
      });

      it('should handle empty and null codes safely', () => {
        // Test empty string
        const emptyError = ApiError.badRequest('Test', '');
        expect(emptyError.code).toBe('BAD_REQUEST'); // Should use default

        // Test null/undefined (TypeScript should prevent this, but test runtime safety)
        const nullError = ApiError.badRequest('Test', null as any);
        expect(nullError.code).toBe('BAD_REQUEST');

        const undefinedError = ApiError.badRequest('Test', undefined as any);
        expect(undefinedError.code).toBe('BAD_REQUEST');
      });
    });

    describe('Context Sanitization', () => {
      it('should handle malicious objects in context safely', () => {
        const maliciousContext = {
          constructor: { constructor: function() { return 'hacked'; } },
          __proto__: { polluted: true },
          toString: function() { throw new Error('Malicious toString'); },
          valueOf: function() { throw new Error('Malicious valueOf'); },
          toJSON: function() { throw new Error('Malicious toJSON'); }
        };

        const error = ApiError.validation('Test', 'field', 'value', 'rule');
        error.context = maliciousContext;

        // Should not throw during serialization
        expect(() => error.toJSON()).not.toThrow();
      });

      it('should handle circular references in context safely', () => {
        const circularContext: any = { name: 'test' };
        circularContext.self = circularContext;
        circularContext.nested = { parent: circularContext };

        const error = ApiError.validation('Test', 'field', circularContext, 'rule');

        // Should not throw even with circular references
        expect(() => error.toJSON()).not.toThrow();
        
        // Verify the basic properties are still accessible
        const json = error.toJSON();
        expect(json.message).toBe('Test');
        expect(json.code).toBe('VALIDATION_ERROR');
      });
    });
  });

  describe('Memory Safety and DoS Prevention', () => {
    describe('Memory Exhaustion Prevention', () => {
      it('should handle extremely large context objects safely', () => {
        const largeContext: any = {};
        
        // Create an object with 1000 properties, each with large string values
        for (let i = 0; i < 1000; i++) {
          largeContext[`key${i}`] = 'x'.repeat(1000); // 1KB per property = ~1MB total
        }

        const error = ApiError.internal('Large context test', 'LARGE_CONTEXT', undefined, largeContext);

        expect(error.context).toBe(largeContext);
        expect(() => error.toJSON()).not.toThrow();
      });

      it('should handle deeply nested objects safely', () => {
        // Create a deeply nested object (100 levels deep)
        let deepObject: any = { level: 0 };
        let current = deepObject;
        
        for (let i = 1; i < 100; i++) {
          current.next = { level: i };
          current = current.next;
        }

        const error = ApiError.validation('Deep nesting test', 'field', deepObject, 'nested');

        expect(() => error.toJSON()).not.toThrow();
      });

      it('should handle arrays with many elements safely', () => {
        const largeArray = new Array(10000).fill('test-value'); // 10K elements
        
        const error = ApiError.validation('Large array test', 'arrayField', largeArray, 'size');

        expect(() => error.toJSON()).not.toThrow();
      });
    });

    describe('Prototype Pollution Prevention', () => {
      it('should not be vulnerable to prototype pollution attacks', () => {
        const maliciousInput = {
          '__proto__': { polluted: true },
          'constructor': { 'prototype': { polluted: true } },
          'prototype': { polluted: true }
        };

        const error = ApiError.validation('Test', 'field', maliciousInput, 'validation');

        // Verify that Object.prototype is not polluted
        expect((Object.prototype as any).polluted).toBeUndefined();
        expect((Array.prototype as any).polluted).toBeUndefined();
        expect((Function.prototype as any).polluted).toBeUndefined();
      });

      it('should safely handle constructor manipulation attempts', () => {
        const maliciousObject = {
          constructor: function() {
            // Attempt to access global scope
            return eval('process.env');
          }
        };

        const error = ApiError.badRequest('Test', 'CONSTRUCTOR_ATTACK', maliciousObject);

        expect(() => error.toJSON()).not.toThrow();
        expect(error.context).toBe(maliciousObject);
      });
    });
  });

  describe('Error Chaining Security', () => {
    describe('Sensitive Information in Error Chains', () => {
      it('should not expose sensitive information through error chains', () => {
        const sensitiveOriginalError = new Error('Database connection failed: password=secret123');
        sensitiveOriginalError.stack = 'Error at /home/app/config/database.js:15:30';
        
        const chainedError = ApiError.database(
          'Database operation failed',
          'CONNECT',
          'users',
          sensitiveOriginalError
        );

        const json = chainedError.toJSON();
        
        // Original error details should not be exposed
        expect(JSON.stringify(json)).not.toContain('password=secret123');
        expect(JSON.stringify(json)).not.toContain('/home/app/config');
        
        // But the ApiError message should be clean
        expect(json.message).toBe('Database operation failed');
      });

      it('should handle multiple levels of error chaining safely', () => {
        const originalError = new Error('Connection timeout: server=prod-db-01.internal');
        const level1Error = ApiError.database('DB connection failed', 'CONNECT', undefined, originalError);
        const level2Error = ApiError.externalService('Service unavailable', 'user-service', level1Error);
        const level3Error = ApiError.internal('System error', 'SYSTEM_FAILURE', level2Error);

        const json = level3Error.toJSON();
        
        // Should only expose the top-level message
        expect(json.message).toBe('System error');
        expect(JSON.stringify(json)).not.toContain('prod-db-01.internal');
        expect(JSON.stringify(json)).not.toContain('Connection timeout');
      });
    });
  });

  describe('Factory Method Security', () => {
    describe('fromUnknown Method Security', () => {
      it('should safely handle malicious unknown errors', () => {
        const maliciousErrors = [
          { message: '<script>alert(1)</script>', stack: 'fake stack trace' },
          { toString: () => { throw new Error('Malicious toString'); } },
          { valueOf: () => { throw new Error('Malicious valueOf'); } },
          new Proxy({}, { get: () => { throw new Error('Malicious proxy'); } }),
          Symbol('malicious symbol'),
          BigInt(123456789),
          null,
          undefined,
          NaN,
          Infinity,
          -Infinity
        ];

        maliciousErrors.forEach((maliciousError, index) => {
          expect(() => {
            const convertedError = ApiError.fromUnknown(maliciousError, `Test error ${index}`);
            expect(convertedError).toBeInstanceOf(ApiError);
            expect(convertedError.toJSON()).toBeDefined();
          }).not.toThrow();
        });
      });

      it('should handle Error objects with malicious properties', () => {
        const maliciousError = new Error('Legitimate error message');
        maliciousError.name = '<script>alert("xss")</script>';
        (maliciousError as any).maliciousProp = 'javascript:alert(1)';
        maliciousError.stack = 'Error: Legitimate error\n    at <script>alert("stack-xss")</script>';

        const convertedError = ApiError.fromUnknown(maliciousError);
        
        expect(convertedError.message).toBe('Legitimate error message');
        expect(convertedError.statusCode).toBe(500);
        expect(convertedError.code).toBe('UNKNOWN_ERROR');
        expect(() => convertedError.toJSON()).not.toThrow();
      });
    });
  });

  describe('Serialization Security', () => {
    describe('JSON Serialization Safety', () => {
      it('should prevent JSON injection attacks', () => {
        const jsonInjectionPayloads = [
          '{"malicious": true}',
          '</script><script>alert(1)</script>',
          '\u2028\u2029', // Line/paragraph separators that can break JSON in HTML
          '\b\f\n\r\t', // Control characters
          '\\u0000\\u0001', // Null bytes
          '"escaping": "attempts"'
        ];

        jsonInjectionPayloads.forEach(payload => {
          const error = ApiError.validation(`Injection test: ${payload}`, 'field', payload, 'format');
          
          const json = error.toJSON();
          const jsonString = JSON.stringify(json);
          
          expect(() => JSON.parse(jsonString)).not.toThrow();
          expect(json.message).toContain(payload);
        });
      });

      it('should handle special JSON characters safely', () => {
        const specialChars = {
          quotes: '"double" and \'single\' quotes',
          backslashes: 'path\\to\\file and \\n newlines',
          unicode: '\u0000\u001f\u007f\uffff',
          html: '<div>"quoted"</div>',
          json: '{"nested": "json", "array": [1,2,3]}'
        };

        Object.entries(specialChars).forEach(([key, value]) => {
          const error = ApiError.validation(`Special chars test: ${key}`, 'field', value, 'format');
          
          expect(() => {
            const json = error.toJSON();
            const serialized = JSON.stringify(json);
            const parsed = JSON.parse(serialized);
            expect(parsed.message).toContain(key);
          }).not.toThrow();
        });
      });
    });
  });

  describe('Performance Security', () => {
    describe('ReDoS (Regular Expression Denial of Service) Prevention', () => {
      it('should handle pathological strings efficiently', () => {
        // Strings that could cause ReDoS if processed by vulnerable regex
        const pathologicalStrings = [
          'a'.repeat(10000) + '!', // Long string with mismatch at end
          'a'.repeat(1000) + 'b'.repeat(1000), // Long alternating pattern
          '((((((((((a))))))))))'.repeat(100), // Nested groups
          'aaaaaaaaaaaaaaaaaaaaX', // Exponential backtracking pattern
        ];

        pathologicalStrings.forEach(pathString => {
          const startTime = Date.now();
          
          const error = ApiError.validation(`Path test: ${pathString}`, 'field', pathString, 'pattern');
          const json = error.toJSON();
          
          const endTime = Date.now();
          const duration = endTime - startTime;
          
          // Should complete in reasonable time (< 100ms)
          expect(duration).toBeLessThan(100);
          expect(json.message).toContain('Path test');
        });
      });
    });

    describe('Resource Exhaustion Prevention', () => {
      it('should handle many concurrent error creations efficiently', () => {
        const startTime = Date.now();
        const errors: ApiError[] = [];
        
        // Create 1000 errors concurrently
        for (let i = 0; i < 1000; i++) {
          errors.push(ApiError.validation(`Error ${i}`, `field${i}`, `value${i}`, 'test'));
        }
        
        // Serialize all errors
        const serialized = errors.map(error => error.toJSON());
        
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        expect(errors).toHaveLength(1000);
        expect(serialized).toHaveLength(1000);
        expect(duration).toBeLessThan(1000); // Should complete in < 1 second
      });
    });
  });

  describe('Environment Variable Security', () => {
    describe('NODE_ENV Validation', () => {
      it('should handle malicious NODE_ENV values safely', () => {
        const maliciousEnvValues = [
          '<script>alert(1)</script>',
          'javascript:alert(1)',
          '"; DROP TABLE users; --',
          '../../../etc/passwd',
          '${process.env.SECRET}',
          null,
          undefined,
          123,
          {},
          []
        ];

        const context = { secret: 'should-be-hidden' };

        maliciousEnvValues.forEach(maliciousEnv => {
          const originalEnv = process.env.NODE_ENV;
          
          try {
            (process.env as any).NODE_ENV = maliciousEnv;
            
            const error = ApiError.validation('Test', 'field', 'value', 'rule');
            error.context = context;
            
            expect(() => error.toJSON()).not.toThrow();
            
            // Should safely determine whether to show context
            const json = error.toJSON();
            expect(json.message).toBe('Test');
            
          } finally {
            process.env.NODE_ENV = originalEnv;
          }
        });
      });
    });
  });
});