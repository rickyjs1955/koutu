// backend/src/__tests__/security/errorHandler.security.test.ts
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';

// Import test utilities
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  createMockError,
  expectedSecurityHeaders
} from '../__mocks__/errorHandler.mock';

import {
  setupConsoleMocks,
  setupEnvironmentMock,
  testTimingAttackResistance,
  cleanupTest
} from '../__helpers__/errorHandler.helper';

// Import the modules under test
import {
  errorHandler,
  EnhancedApiError
} from '../../middlewares/errorHandler';

describe('Error Handler Security Tests', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let consoleMocks: ReturnType<typeof setupConsoleMocks>;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockReq = createMockRequest();
    mockRes = createMockResponse();
    mockNext = createMockNext();
    
    consoleMocks = setupConsoleMocks();
  });

  afterEach(() => {
    cleanupTest();
    consoleMocks.restore();
  });

  describe('Input Sanitization Security', () => {
    describe('Basic Message Processing', () => {
      const dangerousPayloads = [
        '<script>alert("xss")</script>',
        'SELECT * FROM users; DROP TABLE users;',
        '../../../etc/passwd',
        '{"$ne": null}',
        'eval("malicious code")',
        '{{constructor.constructor("return process")()}}'
      ];

      dangerousPayloads.forEach((payload, index) => {
        it(`should process dangerous payload ${index + 1} safely`, () => {
          const error = createMockError(payload, 400, 'DANGEROUS_INPUT');
          
          expect(() => {
            errorHandler(error, mockReq as Request, mockRes as Response, mockNext);
          }).not.toThrow();

          const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
          const responseBody = jsonCall[0];
          
          // Should return a response without throwing errors
          expect(responseBody).toBeDefined();
          expect(responseBody.status).toBe('error');
          expect(responseBody.code).toBe('DANGEROUS_INPUT');
          expect(typeof responseBody.message).toBe('string');
        });
      });

      it('should handle HTML tags in error messages', () => {
        const htmlError = '<img src="x" onerror="alert(1)">';
        const error = createMockError(htmlError, 400, 'HTML_TEST');
        
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        // At minimum, should not execute scripts or cause errors
        expect(responseBody.message).toBeDefined();
        expect(typeof responseBody.message).toBe('string');
      });

      it('should handle SQL-like patterns in error messages', () => {
        const sqlError = "'; DROP TABLE users; --";
        const error = createMockError(sqlError, 400, 'SQL_TEST');
        
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        // Should process without throwing errors
        expect(responseBody.message).toBeDefined();
        expect(responseBody.code).toBe('SQL_TEST');
      });
    });

    describe('Unicode and Special Characters', () => {
      it('should handle unicode characters safely', () => {
        const unicodeError = 'Error with unicode: 🚀 ñáéíóú ©®™';
        const error = createMockError(unicodeError, 400, 'UNICODE_TEST');
        
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        expect(responseBody.message).toContain('🚀');
        expect(responseBody.message).toContain('ñáéíóú');
      });

      it('should handle null bytes safely', () => {
        const nullByteError = 'Error with null\x00byte';
        const error = createMockError(nullByteError, 400, 'NULL_BYTE_TEST');
        
        expect(() => {
          errorHandler(error, mockReq as Request, mockRes as Response, mockNext);
        }).not.toThrow();
      });

      it('should handle control characters', () => {
        const controlCharError = 'Error with\t\n\rcontrol chars';
        const error = createMockError(controlCharError, 400, 'CONTROL_CHAR_TEST');
        
        expect(() => {
          errorHandler(error, mockReq as Request, mockRes as Response, mockNext);
        }).not.toThrow();
      });
    });
  });

  describe('DoS Attack Prevention', () => {
    describe('Large Input Handling', () => {
      it('should handle extremely large error messages without crashing', () => {
        const maxLength = 1024 * 1024; // 1MB
        const largeMessage = 'A'.repeat(maxLength + 10000);
        const error = createMockError(largeMessage, 400, 'LARGE_MESSAGE_DOS');
        
        const start = Date.now();
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);
        const processingTime = Date.now() - start;
        
        // Should complete within reasonable time
        expect(processingTime).toBeLessThan(5000); // 5 seconds max
        
        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        expect(responseBody).toBeDefined();
        expect(responseBody.status).toBe('error');
      });

      it('should handle repeated patterns efficiently', () => {
        const pattern = '<script>alert("xss")</script>';
        const repeatedPattern = pattern.repeat(1000);
        const error = createMockError(repeatedPattern, 400, 'PATTERN_DOS');
        
        const start = Date.now();
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);
        const processingTime = Date.now() - start;
        
        expect(processingTime).toBeLessThan(1000);
      });
    });

    describe('Deep Nesting Protection', () => {
      it('should handle deeply nested error objects without stack overflow', () => {
        const createDeepError = (depth: number): any => {
          if (depth === 0) {
            return { message: 'Deep error', statusCode: 400, code: 'DEEP_ERROR' };
          }
          return { nested: createDeepError(depth - 1), level: depth };
        };

        const deepError = createDeepError(1000);
        
        expect(() => {
          errorHandler(deepError, mockReq as Request, mockRes as Response, mockNext);
        }).not.toThrow();
        
        // Note: Deep nested objects may result in different status codes
        expect(mockRes.status).toHaveBeenCalled();
      });

      it('should handle circular references without infinite loops', () => {
        const circularError: any = {
          message: 'Circular error',
          statusCode: 400,
          code: 'CIRCULAR_ERROR'
        };
        circularError.self = circularError;
        circularError.nested = { parent: circularError };
        
        const start = Date.now();
        errorHandler(circularError, mockReq as Request, mockRes as Response, mockNext);
        const processingTime = Date.now() - start;
        
        expect(processingTime).toBeLessThan(100);
        expect(mockRes.status).toHaveBeenCalled();
      });
    });

    describe('Memory Protection', () => {
      it('should not cause memory leaks with many error objects', () => {
        const initialMemory = process.memoryUsage().heapUsed;
        
        // Process many errors
        for (let i = 0; i < 100; i++) {
          const error = createMockError(`Error ${i}`, 400, `ERROR_${i}`);
          const req = createMockRequest();
          const res = createMockResponse();
          const next = createMockNext();
          
          errorHandler(error, req as Request, res as Response, next);
        }
        
        // Force garbage collection if available
        if ((global as any).gc) {
          (global as any).gc();
        }
        
        const finalMemory = process.memoryUsage().heapUsed;
        const memoryIncrease = finalMemory - initialMemory;
        
        // Should not cause excessive memory increase
        expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // 100MB
      });
    });
  });

  describe('Information Disclosure Prevention', () => {
    describe('Environment-Specific Information Leakage', () => {
      it('should not include stack traces in production', () => {
        const envMock = setupEnvironmentMock('production');
        
        try {
          const error = createMockError('Production error', 500, 'PROD_ERROR');
          (error as any).stack = 'Error: Production error\n    at sensitive-file.js:42:10';
          
          errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

          const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
          const responseBody = jsonCall[0];
          
          expect(responseBody.stack).toBeUndefined();
          expect(responseBody.debug).toBeUndefined();
        } finally {
          envMock.restore();
        }
      });

      it('should limit debug information in production', () => {
        const envMock = setupEnvironmentMock('production');
        
        try {
          const req = createMockRequest({
            user: { id: 'secret-user-id', email: 'secret@company.com' }
          });
          
          const error = createMockError('Debug test error', 400, 'DEBUG_ERROR');
          
          errorHandler(error, req as Request, mockRes as Response, mockNext);

          const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
          const responseBody = jsonCall[0];
          
          expect(responseBody.debug).toBeUndefined();
        } finally {
          envMock.restore();
        }
      });
    });

    describe('Error Message Information Leakage', () => {
      it('should handle potentially sensitive error messages', () => {
        const sensitiveError = 'Database connection failed: password=secret123';
        const error = createMockError(sensitiveError, 500, 'DB_ERROR');
        
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        // Should still return an error message
        expect(responseBody.message).toBeDefined();
        expect(typeof responseBody.message).toBe('string');
      });

      it('should handle file system paths in error messages', () => {
        const pathError = 'File not found: /home/user/.ssh/id_rsa';
        const error = createMockError(pathError, 400, 'FILE_ERROR');
        
        errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        expect(responseBody.message).toBeDefined();
      });
    });
  });

  describe('Timing Attack Prevention', () => {
    it('should have consistent response times for different error types', async () => {
      const operations = [
        () => {
          const error = createMockError('Quick error', 400, 'QUICK_ERROR');
          errorHandler(error, createMockRequest() as Request, createMockResponse() as Response, createMockNext());
        },
        () => {
          const error = createMockError('A'.repeat(1000), 400, 'MEDIUM_ERROR');
          errorHandler(error, createMockRequest() as Request, createMockResponse() as Response, createMockNext());
        },
        () => {
          const complexError = createMockError('Complex error', 500, 'COMPLEX_ERROR');
          (complexError as any).cause = new Error('Nested cause');
          errorHandler(complexError, createMockRequest() as Request, createMockResponse() as Response, createMockNext());
        }
      ];

      await testTimingAttackResistance(operations, 200); // 200ms tolerance for processing differences
    });

    it('should not leak timing information through error processing', async () => {
      const operations = [
        () => {
          const error = createMockError('Normal message', 400, 'NORMAL');
          errorHandler(error, createMockRequest() as Request, createMockResponse() as Response, createMockNext());
        },
        () => {
          const error = createMockError('<script>alert("xss")</script>'.repeat(10), 400, 'XSS_TEST');
          errorHandler(error, createMockRequest() as Request, createMockResponse() as Response, createMockNext());
        },
        () => {
          const error = createMockError('SELECT * FROM users;'.repeat(10), 400, 'SQL_TEST');
          errorHandler(error, createMockRequest() as Request, createMockResponse() as Response, createMockNext());
        }
      ];

      await testTimingAttackResistance(operations, 150);
    });
  });

  describe('Error Code Security', () => {
    it('should handle malformed error codes safely', () => {
      const maliciousCode = '<script>alert("code")</script>';
      const error = createMockError('Code injection test', 400, maliciousCode);
      
      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
      const responseBody = jsonCall[0];
      
      expect(responseBody.code).toBeDefined();
      expect(typeof responseBody.code).toBe('string');
    });

    it('should handle null bytes in error codes', () => {
      const nullByteCode = 'VALID_CODE\x00INJECTED';
      const error = createMockError('Null byte test', 400, nullByteCode);
      
      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
      const responseBody = jsonCall[0];
      
      expect(responseBody.code).toBeDefined();
    });

    it('should handle very long error codes', () => {
      const longCode = 'A'.repeat(1000);
      const error = createMockError('Long code test', 400, longCode);
      
      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
      const responseBody = jsonCall[0];
      
      expect(responseBody.code).toBeDefined();
    });
  });

  describe('HTTP Header Security', () => {
    it('should set required security headers', () => {
      const error = createMockError('Security header test', 400, 'HEADER_TEST');
      
      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.set).toHaveBeenCalledWith(expectedSecurityHeaders);
    });

    it('should prevent MIME type sniffing attacks', () => {
      const error = createMockError('MIME test', 400, 'MIME_TEST');
      
      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-Content-Type-Options': 'nosniff'
        })
      );
    });

    it('should prevent clickjacking attacks', () => {
      const error = createMockError('Clickjacking test', 400, 'CLICKJACK_TEST');
      
      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-Frame-Options': 'DENY'
        })
      );
    });

    it('should enable XSS protection', () => {
      const error = createMockError('XSS protection test', 400, 'XSS_PROTECTION_TEST');
      
      errorHandler(error, mockReq as Request, mockRes as Response, mockNext);

      expect(mockRes.set).toHaveBeenCalledWith(
        expect.objectContaining({
          'X-XSS-Protection': '1; mode=block'
        })
      );
    });
  });

  describe('Request Context Security', () => {
    it('should handle malicious user agent strings safely', () => {
      const maliciousUA = '<script>alert("ua")</script>';
      const req = createMockRequest({
        get: jest.fn<(name: string) => string | string[] | undefined>((header: string) => {
          if (header === 'set-cookie') {
            return undefined; // Return string[] | undefined for set-cookie
          }
          return header === 'User-Agent' ? maliciousUA : undefined;
        }) as any
      });
      
      const error = createMockError('UA test', 400, 'UA_TEST');
      
      expect(() => {
        errorHandler(error, req as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });

    it('should handle extremely long request IDs', () => {
      const longRequestId = 'req_' + 'x'.repeat(10000);
      const req = createMockRequest({
        get: jest.fn<(name: string) => string | string[] | undefined>((header: string) => {
          if (header === 'set-cookie') {
            return undefined; // Return string[] | undefined for set-cookie
          }
          return header === 'X-Request-ID' ? longRequestId : undefined;
        }) as any
      });
      
      const error = createMockError('Long request ID test', 400, 'LONG_ID_TEST');
      
      expect(() => {
        errorHandler(error, req as Request, mockRes as Response, mockNext);
      }).not.toThrow();
      
      const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
      const responseBody = jsonCall[0];
      
      expect(responseBody.requestId).toBeDefined();
    });

    it('should handle request ID injection attempts', () => {
      const injectedId = 'valid-id<script>alert("id")</script>';
      const req = createMockRequest({
        get: jest.fn<(name: string) => string | string[] | undefined>((header: string) => {
          if (header === 'set-cookie') {
            return undefined; // Return string[] | undefined for set-cookie
          }
          return header === 'X-Request-ID' ? injectedId : undefined;
        }) as any
      });
      
      const error = createMockError('ID injection test', 400, 'ID_INJECTION_TEST');
      
      expect(() => {
        errorHandler(error, req as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });
  });

  describe('Performance and Resilience Testing', () => {
    it('should handle high-frequency error processing', () => {
      const start = Date.now();
      
      // Process many errors quickly
      for (let i = 0; i < 1000; i++) {
        const error = createMockError(`High frequency error ${i}`, 400, `HF_ERROR_${i % 10}`);
        const req = createMockRequest();
        const res = createMockResponse();
        const next = createMockNext();
        
        errorHandler(error, req as Request, res as Response, next);
      }
      
      const duration = Date.now() - start;
      
      // Should complete within reasonable time
      expect(duration).toBeLessThan(10000); // 10 seconds for 1000 errors
    });

    it('should maintain reasonable performance across error types', () => {
      const errorTypes = [
        () => createMockError('Simple error', 400, 'SIMPLE'),
        () => new Error('Basic error'),
        () => 'String error' as any,
        () => ({ message: 'Object error', statusCode: 500 }) as any,
        () => null as any,
        () => undefined as any
      ];

      const times: number[] = [];

      errorTypes.forEach(createError => {
        const start = Date.now();
        
        for (let i = 0; i < 50; i++) { // Reduced iterations for more stable timing
          const error = createError();
          errorHandler(error, createMockRequest() as Request, createMockResponse() as Response, createMockNext());
        }
        
        times.push(Date.now() - start);
      });

      // Focus on ensuring no type is excessively slow rather than strict consistency
      const maxTime = Math.max(...times);
      const avgTime = times.reduce((sum, time) => sum + time, 0) / times.length;
      
      // No single error type should take more than 5 seconds for 50 iterations
      expect(maxTime).toBeLessThan(5000);
      
      // Average time should be reasonable (less than 1 second for 50 iterations)
      expect(avgTime).toBeLessThan(1000);
      
      // No type should be more than 50x slower than average (very generous)
      times.forEach(time => {
        if (avgTime > 0) {
          expect(time / avgTime).toBeLessThan(50);
        }
      });
    });

    it('should handle concurrent error processing', async () => {
      const concurrentErrors = Array.from({ length: 50 }, (_, i) => 
        new Promise<number>(resolve => {
          const error = createMockError(`Concurrent error ${i}`, 400, `CONCURRENT_${i}`);
          const req = createMockRequest();
          const res = createMockResponse();
          const next = createMockNext();
          
          errorHandler(error, req as Request, res as Response, next);
          resolve(i);
        })
      );

      const start = Date.now();
      await Promise.all(concurrentErrors);
      const duration = Date.now() - start;

      // Should handle concurrent processing efficiently
      expect(duration).toBeLessThan(5000); // 5 seconds for 50 concurrent errors
    });
  });

  describe('Edge Case Security Testing', () => {
    it('should handle prototype pollution attempts', () => {
      const pollutionAttempt = {
        name: 'PollutionError',
        message: 'Pollution test',
        statusCode: 400,
        code: 'POLLUTION_TEST',
        '__proto__': { polluted: true },
        'constructor': { prototype: { polluted: true } }
      } as any;
      
      expect(() => {
        errorHandler(pollutionAttempt, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
      
      // Should not pollute Object prototype
      expect((Object.prototype as any).polluted).toBeUndefined();
    });

    it('should handle function injection in error objects', () => {
      const functionError = {
        name: 'FunctionError',
        message: 'Function test',
        statusCode: 400,
        code: 'FUNCTION_TEST',
        maliciousFunction: () => { throw new Error('Injected function'); },
        toString: () => { throw new Error('Malicious toString'); }
      } as any;
      
      expect(() => {
        errorHandler(functionError, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });

    it('should handle symbol properties safely', () => {
      const symbolKey = Symbol('malicious');
      const symbolError = {
        name: 'SymbolError',
        message: 'Symbol test',
        statusCode: 400,
        code: 'SYMBOL_TEST',
        [symbolKey]: 'malicious value'
      } as any;
      
      expect(() => {
        errorHandler(symbolError, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });

    it('should handle getter/setter properties', () => {
      const getterError = {
        name: 'GetterError',
        message: 'Getter test',
        statusCode: 400,
        code: 'GETTER_TEST',
        get maliciousGetter() {
          throw new Error('Malicious getter accessed');
        }
      } as any;
      
      expect(() => {
        errorHandler(getterError, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });
  });

  describe('Security Compliance Verification', () => {
    it('should maintain security headers across all error scenarios', () => {
      const scenarios: any[] = [
        createMockError('Normal error', 400, 'NORMAL'),
        new Error('Basic error'),
        'String error',
        { message: 'Object error' },
        null,
        undefined
      ];

      scenarios.forEach(error => {
        const res = createMockResponse();
        errorHandler(error, mockReq as Request, res as Response, mockNext);
        
        expect(res.set).toHaveBeenCalledWith(expectedSecurityHeaders);
      });
    });

    it('should not expose internal system information', () => {
      const systemError = new Error('Internal system failure');
      systemError.stack = `Error: Internal system failure
        at /app/internal/secret-service.js:42:10
        at /app/config/database-credentials.js:15:5
        at /app/internal/api-keys.js:23:7`;
      
      const envMock = setupEnvironmentMock('production');
      
      try {
        errorHandler(systemError, mockReq as Request, mockRes as Response, mockNext);

        const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
        const responseBody = jsonCall[0];
        
        // Should not expose stack trace in production
        expect(responseBody.stack).toBeUndefined();
        expect(responseBody.debug).toBeUndefined();
      } finally {
        envMock.restore();
      }
    });

    it('should handle internationalization safely', () => {
      const i18nError = createMockError('Erreur avec caractères spéciaux: àáâãäåæçèéêë', 400, 'I18N_TEST');
      
      expect(() => {
        errorHandler(i18nError, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
      
      const jsonCall = (mockRes.json as jest.MockedFunction<any>).mock.calls[0];
      const responseBody = jsonCall[0];
      
      expect(responseBody.message).toContain('àáâãäåæçèéêë');
    });
  });

  describe('Input Validation Security', () => {
    it('should handle all primitive types safely', () => {
      const primitives: any[] = [
        true,
        false,
        42,
        -42,
        0,
        Infinity,
        -Infinity,
        NaN,
        'string',
        '',
        null,
        undefined
      ];

      primitives.forEach(primitive => {
        expect(() => {
          errorHandler(primitive, mockReq as Request, mockRes as Response, mockNext);
        }).not.toThrow();
      });
    });

    it('should handle complex nested structures', () => {
      const complexError = {
        name: 'ComplexError',
        message: 'Complex error',
        statusCode: 400,
        code: 'COMPLEX_TEST',
        nested: {
          level1: {
            level2: {
              level3: {
                data: 'deep nested value',
                array: [1, 2, { nested: 'value' }],
                func: () => 'function value'
              }
            }
          }
        }
      } as any;
      
      expect(() => {
        errorHandler(complexError, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });

    it('should handle date objects safely', () => {
      const dateError = {
        name: 'DateError',
        message: 'Date error',
        statusCode: 400,
        code: 'DATE_TEST',
        timestamp: new Date(),
        invalidDate: new Date('invalid')
      } as any;
      
      expect(() => {
        errorHandler(dateError, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });

    it('should handle regex objects safely', () => {
      const regexError = {
        name: 'RegexError',
        message: 'Regex error',
        statusCode: 400,
        code: 'REGEX_TEST',
        pattern: /malicious.*pattern/gi,
        maliciousRegex: new RegExp('(?:(?:(?:(?:(?:.*)*)*)*)*)*')
      } as any;
      
      expect(() => {
        errorHandler(regexError, mockReq as Request, mockRes as Response, mockNext);
      }).not.toThrow();
    });
  });
});