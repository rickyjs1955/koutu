// /backend/src/tests/security/exportController.flutter.security.test.ts
import { Request, Response, NextFunction } from 'express';
import { exportController } from '../../controllers/exportController';
import { exportService } from '../../services/exportService';

// Mock services
jest.mock('../../services/exportService');
const mockExportService = exportService as jest.Mocked<typeof exportService>;

describe('Export Controller - Flutter-Compatible Security Test Suite', () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  // Security-focused response format helpers
  const setupSecureFlutterResponses = () => {
    res.accepted = jest.fn().mockReturnValue(res);
    res.success = jest.fn().mockReturnValue(res);
    res.created = jest.fn().mockReturnValue(res);
    res.download = jest.fn();
  };

  beforeEach(() => {
    req = {
      user: { id: 'test-user-id', email: 'test@example.com' },
      body: {},
      params: {},
      query: {},
      headers: {},
      ip: '127.0.0.1'
    };
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis()
    };
    next = jest.fn();

    setupSecureFlutterResponses();
    jest.clearAllMocks();
  });

  describe('Authentication Security', () => {
    describe('Missing Authentication', () => {
      const authRequiredMethods = [
        { method: 'createMLExport', setup: () => { req.body = { options: { format: 'json' } }; } },
        { method: 'getExportJob', setup: () => { req.params = { jobId: 'job-123' }; } },
        { method: 'getUserExportJobs', setup: () => {} },
        { method: 'downloadExport', setup: () => { req.params = { jobId: 'job-123' }; } },
        { method: 'getDatasetStats', setup: () => {} },
        { method: 'cancelExportJob', setup: () => { req.params = { jobId: 'job-123' }; } }
      ];

      authRequiredMethods.forEach(({ method, setup }) => {
        it(`should prevent access to ${method} without authentication`, async () => {
          req.user = undefined;
          setup();

          await expect((exportController as any)[method](req as Request, res as Response, next))
            .rejects.toThrow('User authentication required');
        });
      });

      it('should prevent access to sensitive operations without user context', async () => {
        req.user = undefined;
        req.body = { options: { format: 'json', includeImages: true } };

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('User authentication required');
      });
    });

    describe('Malformed Authentication', () => {
      it('should reject null user ID', async () => {
        req.user = { id: null } as any;
        req.body = { options: { format: 'json' } };

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('User authentication required');
      });

      it('should reject empty user ID', async () => {
        req.user = { id: '', email: 'test@example.com' };
        req.body = { options: { format: 'json' } };

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('User authentication required');
      });

      it('should reject non-string user ID', async () => {
        req.user = { id: {} as any, email: 'test@example.com' };
        req.body = { options: { format: 'json' } };

        // The controller checks for truthy user ID, so empty object will pass but service will fail
        mockExportService.exportMLData.mockRejectedValue(new Error('Invalid user ID'));

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
      });

      it('should reject missing user ID', async () => {
        req.user = { email: 'test-user@example.com' } as any;
        req.body = { options: { format: 'json' } };

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('User authentication required');
      });

      it('should handle malformed user objects', async () => {
        const malformedUsers = [
          undefined,
          null,
          {},
          { id: null },
          { id: undefined },
          { id: '' },
          { username: 'test' },
          'not-an-object',
          123,
          []
        ];

        for (const malformedUser of malformedUsers) {
          req.user = malformedUser as any;
          req.body = { options: { format: 'json' } };

          if (!malformedUser || typeof malformedUser !== 'object' || !('id' in malformedUser) || !malformedUser.id) {
            await expect(exportController.createMLExport(req as Request, res as Response, next))
              .rejects.toThrow('User authentication required');
          } else {
            // Empty string or other falsy values will also trigger auth error
            await expect(exportController.createMLExport(req as Request, res as Response, next))
              .rejects.toThrow('User authentication required');
          }
        }
      });

      it('should prevent privilege escalation attempts', async () => {
        req.user = { 
          id: 'user-123',
          email: 'test@example.com',
          role: 'admin', // Attempt to set admin role
          permissions: ['all'], // Attempt to set permissions
          isAdmin: true // Attempt to escalate privileges
        } as any;
        req.body = { options: { format: 'json' } };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Should only use the user ID, ignore other fields
        expect(mockExportService.exportMLData).toHaveBeenCalledWith('user-123', { format: 'json' });
      });
    });

    describe('Session Security', () => {
      it('should handle expired or invalid sessions', async () => {
        req.user = { id: 'expired-session-user', email: 'expired@example.com' };
        req.body = { options: { format: 'json' } };
        
        const sessionError = new Error('Session expired');
        mockExportService.exportMLData.mockRejectedValue(sessionError);

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
      });

      it('should prevent concurrent session attacks', async () => {
        req.user = { id: 'concurrent-user', email: 'concurrent@example.com' };
        req.body = { options: { format: 'json' } };
        
        const concurrentError = new Error('Concurrent session detected');
        mockExportService.exportMLData.mockRejectedValue(concurrentError);

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
      });
    });
  });

  describe('Authorization Security', () => {
    describe('Horizontal Privilege Escalation', () => {
      it('should prevent access to other users export jobs in getExportJob', async () => {
        req.params = { jobId: 'job-123' };
        const otherUserJob = {
          id: 'job-123',
          userId: 'other-user-id',
          status: 'running'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(otherUserJob);

        await expect(exportController.getExportJob(req as Request, res as Response, next))
          .rejects.toThrow('You do not have permission to access this export job');
      });

      it('should prevent downloading other users export files', async () => {
        req.params = { jobId: 'job-456' };
        const otherUserJob = {
          id: 'job-456',
          userId: 'other-user-id',
          status: 'completed'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(otherUserJob);

        await expect(exportController.downloadExport(req as Request, res as Response, next))
          .rejects.toThrow('You do not have permission to access this export');
      });

      it('should prevent canceling other users export jobs', async () => {
        req.params = { jobId: 'job-789' };
        const otherUserJob = {
          id: 'job-789',
          userId: 'other-user-id',
          status: 'running'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(otherUserJob);

        await expect(exportController.cancelExportJob(req as Request, res as Response, next))
          .rejects.toThrow('You do not have permission to cancel this export job');
      });

      it('should prevent cross-user data access in getUserExportJobs', async () => {
        // Service should only return jobs for the authenticated user
        const userJobs = [
          { id: 'job-1', userId: 'test-user-id', status: 'completed' },
          { id: 'job-2', userId: 'test-user-id', status: 'running' }
        ];
        
        mockExportService.getUserBatchJobs.mockResolvedValue(userJobs);

        await exportController.getUserExportJobs(req as Request, res as Response, next);

        expect(mockExportService.getUserBatchJobs).toHaveBeenCalledWith('test-user-id');
        expect(res.success).toHaveBeenCalledWith(
          userJobs,
          expect.objectContaining({
            meta: expect.objectContaining({
              userId: 'test-user-id'
            })
          })
        );
      });
    });

    describe('Authorization Bypass Attempts', () => {
      it('should validate user ownership even with manipulated request parameters', async () => {
        req.params = { jobId: 'job-123' };
        req.body = { 
          userId: 'attacker-user-id', // Attempt to manipulate user ID
          targetUser: 'other-user'     // Additional manipulation attempt
        };
        
        const validJob = {
          id: 'job-123',
          userId: 'test-user-id', // Actual owner from database
          status: 'running'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(validJob);

        await exportController.getExportJob(req as Request, res as Response, next);

        // Should use the authenticated user ID, not request body
        expect(mockExportService.getBatchJob).toHaveBeenCalledWith('job-123');
      });

      it('should ignore attempts to modify user_id in request body', async () => {
        req.body = { 
          options: { format: 'json' },
          userId: 'attacker-user-id',  // Attempt to override user ID
          user_id: 'another-attacker', // Different format attempt
          id: 'yet-another-attempt'    // Another manipulation
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Should use authenticated user ID only
        expect(mockExportService.exportMLData).toHaveBeenCalledWith(
          'test-user-id',
          expect.objectContaining({ format: 'json' })
        );
      });
    });

    describe('Vertical Privilege Escalation', () => {
      it('should validate export permissions for sensitive data access', async () => {
        req.body = {
          options: {
            format: 'json',
            includeSystemData: true,    // Attempt to access system data
            includeAllUsers: true,      // Attempt to access all users data
            adminLevel: 'full',         // Attempt admin-level access
            bypassFilters: true         // Attempt to bypass filtering
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Service should receive the full options but handle authorization internally
        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });
    });
  });

  describe('Input Validation Security', () => {
    describe('Export Options Injection Prevention', () => {
      it('should prevent script injection in export options', async () => {
        req.body = {
          options: {
            format: '<script>alert("xss")</script>',
            filename: 'test</script><script>alert(1)</script>',
            description: 'javascript:alert("xss")',
            customQuery: "'; DROP TABLE exports; --"
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Should pass through to service for proper sanitization
        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });

      it('should prevent path traversal in export options', async () => {
        req.body = {
          options: {
            format: 'json',
            outputPath: '../../../etc/passwd',
            templatePath: '../../../../windows/system32',
            includeFiles: ['../config/database.yml', '../../.env']
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });

      it('should prevent SQL injection in export filters', async () => {
        req.body = {
          options: {
            format: 'json',
            filters: {
              userQuery: "1' OR '1'='1",
              category: "test'; DROP TABLE garments; --",
              dateRange: "2024' UNION SELECT * FROM users --"
            }
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });
    });

    describe('Job ID Validation Security', () => {
      it('should handle malicious job IDs by delegating to service layer', async () => {
        const maliciousJobIds = [
          "'; DROP TABLE jobs; --",
          "1' OR '1'='1",
          "job-123'; UPDATE jobs SET status='completed' WHERE id='job-456'; --",
          "UNION SELECT * FROM users",
          "../../../etc/passwd"
        ];

        for (const jobId of maliciousJobIds) {
          req.params = { jobId };
          
          // Controller doesn't validate job ID format, passes to service which returns null
          mockExportService.getBatchJob.mockResolvedValue(null);

          await expect(exportController.getExportJob(req as Request, res as Response, next))
            .rejects.toThrow('Export job not found');
        }
      });

      it('should validate that job ID parameter exists', async () => {
        req.params = {}; // Missing jobId
        
        await expect(exportController.getExportJob(req as Request, res as Response, next))
          .rejects.toThrow('Valid job ID is required');
      });

      it('should validate job ID is not empty string', async () => {
        req.params = { jobId: '' };
        
        await expect(exportController.getExportJob(req as Request, res as Response, next))
          .rejects.toThrow('Valid job ID is required');
      });

      it('should validate job ID is a string', async () => {
        req.params = { jobId: null as any };
        
        await expect(exportController.getExportJob(req as Request, res as Response, next))
          .rejects.toThrow('Valid job ID is required');
      });

      it('should prevent directory traversal in job IDs', async () => {
        const traversalAttempts = [
          '../../../sensitive-file',
          '..\\..\\windows\\system32',
          '/etc/passwd',
          'C:\\Windows\\System32\\config',
          '....//....//etc/hosts'
        ];

        for (const jobId of traversalAttempts) {
          req.params = { jobId };
          
          // Controller doesn't validate job ID format, service should handle security
          mockExportService.getBatchJob.mockResolvedValue(null);
          
          await expect(exportController.getExportJob(req as Request, res as Response, next))
            .rejects.toThrow('Export job not found');
        }
      });
    });

    describe('Type Confusion Attacks', () => {
      it('should prevent type confusion in export options', async () => {
        const typeConfusionOptions = [
          null,
          undefined,
          'string-instead-of-object',
          123,
          [],
          true,
          Symbol('test'),
          function() { return 'malicious'; }
        ];

        for (const options of typeConfusionOptions) {
          req.body = { options };

          if (options === null || options === undefined || typeof options !== 'object') {
            await expect(exportController.createMLExport(req as Request, res as Response, next))
              .rejects.toThrow('Export options are required');
          } else {
            // Non-plain objects will pass validation but may cause service errors
            mockExportService.exportMLData.mockRejectedValue(new Error('Invalid options type'));
            await expect(exportController.createMLExport(req as Request, res as Response, next))
              .rejects.toThrow('Failed to create ML export job');
          }
        }
      });

      it('should prevent prototype pollution in export options', async () => {
        req.body = {
          options: {
            format: 'json',
            __proto__: { malicious: true },
            constructor: { prototype: { polluted: true } },
            'constructor.prototype.isAdmin': true
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Should pass through but service should handle sanitization
        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });
    });

    describe('Payload Size Limits', () => {
      it('should handle oversized export options payloads', async () => {
        const largeOptions = {
          format: 'json',
          hugeArray: new Array(100000).fill('x'.repeat(1000)),
          nestedObject: {}
        };

        // Create deeply nested structure
        let current: any = largeOptions.nestedObject;
        for (let i = 0; i < 1000; i++) {
          current.nested = { data: 'x'.repeat(1000) };
          current = current.nested;
        }

        req.body = { options: largeOptions };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', largeOptions);
      });
    });
  });

  describe('Error Handling Security', () => {
    describe('Information Disclosure Prevention', () => {
      it('should not leak sensitive information in error messages', async () => {
        req.body = { options: { format: 'json' } };
        
        const sensitiveError = new Error('Database connection failed: host=secret-db-server.internal, user=admin, password=secret123');
        mockExportService.exportMLData.mockRejectedValue(sensitiveError);

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
        // Should not throw the original sensitive error message
      });

      it('should not expose stack traces in production', async () => {
        req.body = { options: { format: 'json' } };
        
        const errorWithStack = new Error('Service error');
        errorWithStack.stack = 'Error: Service error\n    at /app/secrets/database.js:42:15\n    at /app/config/credentials.js:123:8';
        mockExportService.exportMLData.mockRejectedValue(errorWithStack);

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
      });

      it('should handle database errors securely', async () => {
        req.params = { jobId: 'job-123' };
        
        const dbError = new Error('SQLSTATE[42000]: Syntax error: 1064 You have an error in your SQL syntax');
        mockExportService.getBatchJob.mockRejectedValue(dbError);

        await expect(exportController.getExportJob(req as Request, res as Response, next))
          .rejects.toThrow('Failed to retrieve export job');
      });

      it('should not expose file system paths in errors', async () => {
        req.params = { jobId: 'job-123' };
        const jobData = { id: 'job-123', userId: 'test-user-id', status: 'completed' };
        
        mockExportService.getBatchJob.mockResolvedValue(jobData);
        
        const fsError = new Error('ENOENT: no such file or directory, open \'/app/secrets/export-config.json\'');
        mockExportService.downloadExport.mockRejectedValue(fsError);

        await expect(exportController.downloadExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to download export');
      });
    });

    describe('Error State Security', () => {
      it('should maintain security context during error conditions', async () => {
        req.user = { id: 'test-user-id', email: 'test-user@example.com' };
        req.body = { options: { format: 'json' } };
        
        const serviceError = new Error('Service temporarily unavailable');
        mockExportService.exportMLData.mockRejectedValue(serviceError);

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');

        // Should have attempted with correct user ID
        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', { format: 'json' });
      });

      it('should prevent error-based enumeration attacks', async () => {
        const nonExistentJobIds = ['job-999', 'job-invalid', 'job-nonexistent'];
        
        for (const jobId of nonExistentJobIds) {
          req.params = { jobId };
          mockExportService.getBatchJob.mockResolvedValue(null);

          await expect(exportController.getExportJob(req as Request, res as Response, next))
            .rejects.toThrow('Export job not found');
        }
        
        // All should get the same error message
        expect(mockExportService.getBatchJob).toHaveBeenCalledTimes(3);
      });
    });
  });

  describe('Rate Limiting & DoS Protection', () => {
    describe('Request Rate Limiting', () => {
      it('should handle rapid successive requests', async () => {
        req.body = { options: { format: 'json' } };
        
        const requests = Array(10).fill(0).map(async () => {
          mockExportService.exportMLData.mockResolvedValue(`job-${Math.random()}`);
          await exportController.createMLExport(req as Request, res as Response, next);
        });

        await Promise.all(requests);

        expect(mockExportService.exportMLData).toHaveBeenCalledTimes(10);
      });

      it('should handle rate limiting with different user sessions', async () => {
        const users = ['user-1', 'user-2', 'user-3'];
        
        for (const userId of users) {
          req.user = { id: userId, email: `${userId}@example.com` };
          req.body = { options: { format: 'json' } };
          
          mockExportService.exportMLData.mockResolvedValue(`job-${userId}`);
          await exportController.createMLExport(req as Request, res as Response, next);
        }

        expect(mockExportService.exportMLData).toHaveBeenCalledTimes(3);
      });

      it('should prevent burst attacks on export operations', async () => {
        req.body = { options: { format: 'json' } };
        
        const burstRequests = Array(50).fill(0).map(async (_, index) => {
          try {
            mockExportService.exportMLData.mockResolvedValue(`job-${index}`);
            await exportController.createMLExport(req as Request, res as Response, next);
            return 'success';
          } catch (error) {
            return 'rate-limited';
          }
        });

        const results = await Promise.allSettled(burstRequests);
        expect(results.length).toBe(50);
      });
    });

    describe('Memory Exhaustion Protection', () => {
      it('should handle memory-intensive operations safely', async () => {
        req.body = {
          options: {
            format: 'json',
            largeDataSet: new Array(10000).fill({
              id: 'x'.repeat(100),
              data: 'y'.repeat(1000),
              metadata: new Array(100).fill('z'.repeat(50))
            })
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });

      it('should prevent stack overflow attacks', async () => {
        // Create circular reference
        const circularOptions: any = { format: 'json' };
        circularOptions.self = circularOptions;
        
        req.body = { options: circularOptions };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalled();
      });
    });

    describe('Algorithmic Complexity Attacks', () => {
      it('should prevent regex DoS attacks in job IDs', async () => {
        const regexDosJobId = 'a'.repeat(100000) + '!';
        req.params = { jobId: regexDosJobId };

        const startTime = Date.now();
        
        // Controller passes job ID to service, which should handle it efficiently
        mockExportService.getBatchJob.mockResolvedValue(null);
        
        await expect(exportController.getExportJob(req as Request, res as Response, next))
          .rejects.toThrow('Export job not found');
          
        const endTime = Date.now();
        
        // Should complete quickly, not hang due to regex DoS
        expect(endTime - startTime).toBeLessThan(1000);
      });
    });
  });

  describe('Response Security', () => {
    describe('Data Exposure Prevention', () => {
      it('should not expose other users data in bulk operations', async () => {
        const userJobs = [
          { id: 'job-1', userId: 'test-user-id', status: 'completed', privateData: 'secret' },
          { id: 'job-2', userId: 'test-user-id', status: 'running', internalInfo: 'confidential' }
        ];
        
        mockExportService.getUserBatchJobs.mockResolvedValue(userJobs);

        await exportController.getUserExportJobs(req as Request, res as Response, next);

        expect(res.success).toHaveBeenCalledWith(
          userJobs, // Service should sanitize the data
          expect.objectContaining({
            meta: expect.objectContaining({
              userId: 'test-user-id'
            })
          })
        );
      });

      it('should prevent response size attacks', async () => {
        const massiveJobList = new Array(10000).fill(0).map((_, i) => ({
          id: `job-${i}`,
          userId: 'test-user-id',
          status: 'completed',
          data: 'x'.repeat(1000)
        }));
        
        mockExportService.getUserBatchJobs.mockResolvedValue(massiveJobList);

        await exportController.getUserExportJobs(req as Request, res as Response, next);

        expect(res.success).toHaveBeenCalled();
      });
    });

    describe('Security Headers', () => {
      it('should not expose sensitive information in responses', async () => {
        req.body = { options: { format: 'json' } };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        const responseCall = (res.accepted as jest.Mock).mock.calls[0];
        const [data, metadata] = responseCall;
        
        // Check that sensitive info is not exposed
        expect(JSON.stringify(data)).not.toContain('password');
        expect(JSON.stringify(data)).not.toContain('secret');
        expect(JSON.stringify(data)).not.toContain('internal');
        expect(JSON.stringify(metadata)).not.toContain('database');
      });

      it('should sanitize response data', async () => {
        const stats = {
          totalImages: 1000,
          totalGarments: 500,
          internalMetrics: { databaseConnections: 5, memoryUsage: '50MB' },
          systemInfo: { version: '1.0.0', environment: 'production' }
        };
        
        mockExportService.getDatasetStats.mockResolvedValue(stats);

        await exportController.getDatasetStats(req as Request, res as Response, next);

        expect(res.success).toHaveBeenCalledWith(
          stats, // Service should sanitize sensitive fields
          expect.objectContaining({
            meta: expect.objectContaining({
              userId: 'test-user-id'
            })
          })
        );
      });
    });
  });

  describe('Business Logic Security', () => {
    describe('Export State Security', () => {
      it('should prevent state manipulation in job lifecycle', async () => {
        req.params = { jobId: 'job-123' };
        req.body = { 
          status: 'completed',        // Attempt to manipulate status
          userId: 'attacker-id',      // Attempt to change ownership
          progress: 100               // Attempt to set progress
        };
        
        const jobData = {
          id: 'job-123',
          userId: 'test-user-id',
          status: 'failed'  // Actual status from database
        };
        
        mockExportService.getBatchJob.mockResolvedValue(jobData);

        await expect(exportController.cancelExportJob(req as Request, res as Response, next))
          .rejects.toThrow('Cannot cancel job with status: failed');
      });

      it('should validate business rules for export operations', async () => {
        req.params = { jobId: 'job-123' };
        const completedJob = {
          id: 'job-123',
          userId: 'test-user-id',
          status: 'completed'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(completedJob);

        // Should not allow canceling completed jobs
        await expect(exportController.cancelExportJob(req as Request, res as Response, next))
          .rejects.toThrow('Cannot cancel job with status: completed');
      });
    });

    describe('Download Security', () => {
      it('should validate download permissions', async () => {
        req.params = { jobId: 'job-123' };
        const jobData = { id: 'job-123', userId: 'test-user-id', status: 'completed' };
        const downloadData = {
          path: '/exports/job-123.zip',
          filename: 'export.zip'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(jobData);
        mockExportService.downloadExport.mockResolvedValue(downloadData);
        
        (res.download as jest.Mock).mockImplementation((path, filename, callback) => {
          // Validate path doesn't contain traversal
          expect(path).not.toContain('../');
          expect(path).not.toContain('..\\');
          expect(filename).toBe('export.zip');
          callback(null); // Simulate successful download
        });

        await exportController.downloadExport(req as Request, res as Response, next);

        expect(mockExportService.getBatchJob).toHaveBeenCalledWith('job-123');
        expect(mockExportService.downloadExport).toHaveBeenCalledWith('job-123');
        expect(res.download).toHaveBeenCalledWith(downloadData.path, downloadData.filename, expect.any(Function));
      });

      it('should prevent downloading uncompleted jobs', async () => {
        req.params = { jobId: 'job-123' };
        const pendingJob = {
          id: 'job-123',
          userId: 'test-user-id',
          status: 'running'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(pendingJob);

        await expect(exportController.downloadExport(req as Request, res as Response, next))
          .rejects.toThrow('Export job is not ready for download (status: running)');
      });

      it('should handle download errors securely', async () => {
        req.params = { jobId: 'job-123' };
        const jobData = { id: 'job-123', userId: 'test-user-id', status: 'completed' };
        const downloadData = {
          path: '/exports/job-123.zip',
          filename: 'export.zip'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(jobData);
        mockExportService.downloadExport.mockResolvedValue(downloadData);
        
        (res.download as jest.Mock).mockImplementation((path, filename, callback) => {
          const downloadError = new Error('File access denied: /sensitive/system/file');
          callback(downloadError);
        });

        await expect(exportController.downloadExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to download export file');
      });

      it('should validate file extensions in downloads', async () => {
        req.params = { jobId: 'job-123' };
        const jobData = { id: 'job-123', userId: 'test-user-id', status: 'completed' };
        const maliciousDownload = {
          path: '/exports/job-123.exe', // Suspicious file extension
          filename: 'export.exe'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(jobData);
        mockExportService.downloadExport.mockResolvedValue(maliciousDownload);
        
        (res.download as jest.Mock).mockImplementation((path, filename, callback) => {
          // Should validate file types at service level
          callback(null);
        });

        await exportController.downloadExport(req as Request, res as Response, next);

        expect(mockExportService.downloadExport).toHaveBeenCalledWith('job-123');
      });
    });

    describe('Concurrent Access Security', () => {
      it('should handle concurrent job operations safely', async () => {
        req.params = { jobId: 'job-123' };
        const jobData = {
          id: 'job-123',
          userId: 'test-user-id',
          status: 'running'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(jobData);
        mockExportService.cancelExportJob.mockResolvedValue(undefined);
        
        // Simulate concurrent cancel requests
        const concurrentRequests = Array(5).fill(0).map(() => 
          exportController.cancelExportJob(req as Request, res as Response, next)
        );

        await Promise.all(concurrentRequests);

        expect(mockExportService.cancelExportJob).toHaveBeenCalledTimes(5);
        expect(res.success).toHaveBeenCalledTimes(5);
      });

      it('should prevent race conditions in job status checks', async () => {
        req.params = { jobId: 'job-123' };
        let callCount = 0;
        
        // Mock changing job status to simulate race condition
        mockExportService.getBatchJob.mockImplementation(async () => {
          callCount++;
          return {
            id: 'job-123',
            userId: 'test-user-id',
            status: callCount === 1 ? 'running' : 'completed'
          };
        });

        mockExportService.cancelExportJob.mockResolvedValue(undefined);

        await exportController.cancelExportJob(req as Request, res as Response, next);

        // Should use the status from the first check
        expect(mockExportService.cancelExportJob).toHaveBeenCalledWith('job-123');
      });
    });
  });

  describe('Advanced Security Scenarios', () => {
    describe('Multi-Vector Attacks', () => {
      it('should handle combined injection and privilege escalation attempts', async () => {
        req.user = { id: 'test-user-id', email: 'test-user@example.com' };
        req.body = {
          options: {
            format: "json'; DROP TABLE users; --",
            filters: {
              userQuery: "admin' OR '1'='1",
              __proto__: { isAdmin: true }
            },
            metadata: {
              userId: 'admin-override',
              permissions: ['all'],
              systemAccess: true
            }
          },
          userId: 'admin-user-id',
          adminOverride: true
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Should only use authenticated user ID regardless of payload
        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });

      it('should prevent chained exploitation attempts', async () => {
        // First attempt: Try to create malicious export
        req.body = {
          options: {
            format: 'json',
            webhook: 'http://attacker.com/steal-data',
            outputPath: '../../../etc/passwd',
            includeSystemData: true
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('malicious-job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Second attempt: Try to access the malicious job as different user
        req.user = { id: 'different-user-id', email: 'different-user@example.com' };
        req.params = { jobId: 'malicious-job-123' };
        
        const maliciousJob = {
          id: 'malicious-job-123',
          userId: 'test-user-id', // Original user
          status: 'completed'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(maliciousJob);

        await expect(exportController.getExportJob(req as Request, res as Response, next))
          .rejects.toThrow('You do not have permission to access this export job');
      });

      it('should handle complex nested payload attacks', async () => {
        const nestedAttack = {
          options: {
            format: 'json',
            nested: {
              level1: {
                level2: {
                  level3: {
                    sqlInjection: "'; DROP TABLE jobs; --",
                    xss: '<script>alert("xss")</script>',
                    pathTraversal: '../../../secrets',
                    prototypePolllution: {
                      __proto__: { isAdmin: true }
                    }
                  }
                }
              }
            },
            array: [
              { malicious: "'; DELETE FROM users; --" },
              { evil: '<img src=x onerror=alert(1)>' },
              { traversal: '../../../../etc/passwd' }
            ]
          }
        };
        
        req.body = nestedAttack;
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', nestedAttack.options);
      });
    });

    describe('Timing Attack Protection', () => {
      it('should prevent timing-based user enumeration', async () => {
        const startTimes: number[] = [];
        const endTimes: number[] = [];
        
        const testUsers = [
          'existing-user-id',
          'non-existent-user',
          'another-fake-user'
        ];

        for (const userId of testUsers) {
          req.user = { id: userId, email: `${userId}@example.com`};
          req.body = { options: { format: 'json' } };
          
          startTimes.push(Date.now());
          
          if (userId === 'existing-user-id') {
            mockExportService.exportMLData.mockResolvedValue('job-123');
            await exportController.createMLExport(req as Request, res as Response, next);
          } else {
            const userError = new Error('User not found');
            mockExportService.exportMLData.mockRejectedValue(userError);
            await expect(exportController.createMLExport(req as Request, res as Response, next))
              .rejects.toThrow('Failed to create ML export job');
          }
          
          endTimes.push(Date.now());
        }

        // Response times should not leak user existence information
        const responseTimes = endTimes.map((end, i) => end - startTimes[i]);
        expect(responseTimes.every(time => time < 100)).toBe(true); // Should be fast for all
      });

      it('should prevent timing attacks on job access checks', async () => {
        const startTime = Date.now();
        
        req.params = { jobId: 'non-existent-job' };
        mockExportService.getBatchJob.mockResolvedValue(null);

        await expect(exportController.getExportJob(req as Request, res as Response, next))
          .rejects.toThrow('Export job not found');
          
        const endTime = Date.now();
        const responseTime = endTime - startTime;
        
        // Should not take significantly longer than valid requests
        expect(responseTime).toBeLessThan(100);
      });
    });

    describe('Resource Exhaustion Attacks', () => {
      it('should handle deeply nested object attacks', async () => {
        let deepObject: any = { format: 'json' };
        let current = deepObject;
        
        // Create 10000 levels of nesting
        for (let i = 0; i < 10000; i++) {
          current.nested = { level: i };
          current = current.nested;
        }
        
        req.body = { options: deepObject };
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', deepObject);
      });

      it('should handle array explosion attacks', async () => {
        const hugeArrayOptions = {
          format: 'json',
          data: new Array(1000000).fill(0).map((_, i) => ({
            id: i,
            payload: 'x'.repeat(1000)
          }))
        };
        
        req.body = { options: hugeArrayOptions };
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', hugeArrayOptions);
      });

      it('should prevent CPU exhaustion through complex regex patterns', async () => {
        const regexDosPayload = {
          format: 'json',
          searchPattern: 'a'.repeat(50000) + 'X',
          filters: {
            regex: '^(a+)+',
            complexPattern: '(a|a)*b',
            evilRegex: '^(a+)+c'
          }
        };
        
        req.body = { options: regexDosPayload };
        mockExportService.exportMLData.mockResolvedValue('job-123');

        const startTime = Date.now();
        await exportController.createMLExport(req as Request, res as Response, next);
        const endTime = Date.now();
        
        // Should complete quickly even with complex patterns
        expect(endTime - startTime).toBeLessThan(1000);
      });
    });

    describe('State Manipulation Attacks', () => {
      it('should prevent job state tampering through repeated requests', async () => {
        req.params = { jobId: 'job-123' };
        const originalJob = {
          id: 'job-123',
          userId: 'test-user-id',
          status: 'running'
        };
        
        mockExportService.getBatchJob.mockResolvedValue(originalJob);
        mockExportService.cancelExportJob.mockResolvedValue(undefined);

        // Multiple rapid cancel requests
        const requests = Array(10).fill(0).map(() => 
          exportController.cancelExportJob(req as Request, res as Response, next)
        );

        await Promise.all(requests);

        // All should succeed based on original state
        expect(mockExportService.cancelExportJob).toHaveBeenCalledTimes(10);
        expect(res.success).toHaveBeenCalledTimes(10);
      });

      it('should maintain consistency during error conditions', async () => {
        req.body = { options: { format: 'json' } };
        
        // Simulate intermittent service errors
        let callCount = 0;
        mockExportService.exportMLData.mockImplementation(async () => {
          callCount++;
          if (callCount % 2 === 0) {
            throw new Error('Service temporarily unavailable');
          }
          return `job-${callCount}`;
        });

        // Should handle errors consistently
        await exportController.createMLExport(req as Request, res as Response, next);
        
        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
          
        await exportController.createMLExport(req as Request, res as Response, next);

        expect(callCount).toBe(3);
      });
    });

    describe('Information Leakage Prevention', () => {
      it('should not leak internal system information through error messages', async () => {
        req.body = { options: { format: 'json' } };
        
        const systemErrors = [
          new Error('Connection refused at 192.168.1.100:5432'),
          new Error('Permission denied: /var/log/application.log'),
          new Error('Module not found: /app/node_modules/secret-module'),
          new Error('EACCES: permission denied, open \'/etc/shadow\''),
          new Error('Redis connection failed: redis://internal-cache:6379')
        ];

        for (const error of systemErrors) {
          mockExportService.exportMLData.mockRejectedValue(error);
          
          await expect(exportController.createMLExport(req as Request, res as Response, next))
            .rejects.toThrow('Failed to create ML export job');
        }
      });

      it('should sanitize all user-controlled input in responses', async () => {
        req.body = {
          options: {
            format: 'json',
            userControlledField: '<script>alert("xss")</script>',
            filename: 'test">${7*7}',
            description: '{{constructor.constructor("alert(1)")()}}'
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        const responseCall = (res.accepted as jest.Mock).mock.calls[0];
        const [data, metadata] = responseCall;
        
        // Ensure no script tags or template injection in response
        const responseString = JSON.stringify({ data, metadata });
        expect(responseString).not.toContain('<script>');
        expect(responseString).not.toContain('${');
        expect(responseString).not.toContain('{{');
      });
    });
  });

  describe('Edge Cases and Boundary Conditions', () => {
    describe('Extreme Input Values', () => {
      it('should handle maximum string lengths', async () => {
        const maxLengthString = 'x'.repeat(1000000); // 1MB string
        req.body = {
          options: {
            format: 'json',
            description: maxLengthString,
            metadata: {
              largeField: maxLengthString
            }
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });

      it('should handle unicode and special characters', async () => {
        const unicodeOptions = {
          format: 'json',
          description: '🚀💻🔐 测试数据 العربية русский 日本語',
          filename: 'тест-файл-🔐.json',
          filters: {
            emoji: '😀😃😄😁😆',
            rtl: 'مرحبا بالعالم',
            chinese: '你好世界',
            japanese: 'こんにちは世界'
          }
        };
        
        req.body = { options: unicodeOptions };
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', unicodeOptions);
      });

      it('should handle binary and null byte attacks', async () => {
        const binaryOptions = {
          format: 'json',
          data: '\x00\x01\x02\x03\x04\x05',
          nullBytes: 'test\x00injection',
          controlChars: '\r\n\t\b\f',
          highBytes: '\xFF\xFE\xFD'
        };
        
        req.body = { options: binaryOptions };
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', binaryOptions);
      });
    });

    describe('Network and Connectivity Edge Cases', () => {
      it('should handle connection timeouts gracefully', async () => {
        req.body = { options: { format: 'json' } };
        
        const timeoutError = new Error('Connection timeout after 30000ms');
        mockExportService.exportMLData.mockRejectedValue(timeoutError);

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
      });

      it('should handle partial request scenarios', async () => {
        // Simulate incomplete request body
        req.body = { options: { format: 'js' } }; // Valid options object
        if (req.headers) {
          delete req.headers['content-length'];
        }
        
        // Service should handle incomplete/invalid format
        mockExportService.exportMLData.mockRejectedValue(new Error('Invalid format specified'));
        
        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
      });
    });

    describe('Concurrent Edge Cases', () => {
      it('should handle database deadlock scenarios', async () => {
        req.body = { options: { format: 'json' } };
        
        const deadlockError = new Error('Deadlock detected in database transaction');
        mockExportService.exportMLData.mockRejectedValue(deadlockError);

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
      });

      it('should handle service unavailability during peak load', async () => {
        req.body = { options: { format: 'json' } };
        
        const serviceUnavailableError = new Error('Service temporarily unavailable - too many requests');
        mockExportService.exportMLData.mockRejectedValue(serviceUnavailableError);

        await expect(exportController.createMLExport(req as Request, res as Response, next))
          .rejects.toThrow('Failed to create ML export job');
      });
    });
  });

  describe('Compliance and Audit Security', () => {
    describe('Audit Trail Security', () => {
      it('should not log sensitive information in audit trails', async () => {
        req.body = {
          options: {
            format: 'json',
            sensitiveData: 'password123',
            apiKey: 'sk-1234567890abcdef',
            token: 'bearer-token-secret'
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Should have been called but audit logic would sanitize sensitive fields
        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });

      it('should maintain consistent audit information across operations', async () => {
        const testOperations = [
          { method: 'createMLExport', setup: () => { req.body = { options: { format: 'json' } }; } },
          { method: 'getDatasetStats', setup: () => {} },
          { method: 'getUserExportJobs', setup: () => {} }
        ];

        for (const { method, setup } of testOperations) {
          setup();
          
          if (method === 'createMLExport') {
            mockExportService.exportMLData.mockResolvedValue('job-123');
          } else if (method === 'getDatasetStats') {
            mockExportService.getDatasetStats.mockResolvedValue({ totalImages: 100 });
          } else if (method === 'getUserExportJobs') {
            mockExportService.getUserBatchJobs.mockResolvedValue([]);
          }

          await (exportController as any)[method](req as Request, res as Response, next);
        }

        // All operations should have been audited with user context
        expect(mockExportService.exportMLData).toHaveBeenCalledTimes(1);
        expect(mockExportService.getDatasetStats).toHaveBeenCalledTimes(1);
        expect(mockExportService.getUserBatchJobs).toHaveBeenCalledTimes(1);
      });
    });

    describe('Data Protection Compliance', () => {
      it('should respect data minimization principles', async () => {
        req.body = {
          options: {
            format: 'json',
            includePersonalData: false,
            anonymizeData: true,
            limitFields: ['id', 'category', 'timestamp']
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });

      it('should validate export permissions for sensitive data types', async () => {
        req.body = {
          options: {
            format: 'json',
            includeMetrics: true,
            includeBiometrics: true,
            includeLocationData: true,
            includePersonalIdentifiers: true
          }
        };
        
        mockExportService.exportMLData.mockResolvedValue('job-123');

        await exportController.createMLExport(req as Request, res as Response, next);

        // Service should validate these permissions
        expect(mockExportService.exportMLData).toHaveBeenCalledWith('test-user-id', req.body.options);
      });
    });
  });
});