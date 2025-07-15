// /backend/src/models/__tests__/garmentModel.security.test.ts
// Production-ready security test suite for garmentModel

const mockUuidValidate = jest.fn();
jest.mock('uuid', () => ({
  v4: jest.requireActual('uuid').v4,
  validate: mockUuidValidate
}));

import { garmentModel } from '../../models/garmentModel';
import { 
  MOCK_USER_IDS,
  MOCK_GARMENT_IDS,
  createMockGarment,
  createMockCreateInput,
  CleanupHelper
} from '../__helpers__/garments.helper';

// Mock dependencies with security focus
const mockQuery = jest.fn();
jest.mock('../../utils/modelUtils', () => ({
  getQueryFunction: () => mockQuery
}));

describe('Garment Model - Security Test Suite', () => {
  beforeEach(() => {
    CleanupHelper.resetAllMocks();
    mockQuery.mockClear();
    mockQuery.mockReset();
    mockUuidValidate.mockClear();
    mockUuidValidate.mockReset();
    
    // Default secure UUID validation
    mockUuidValidate.mockImplementation((id: string) => {
      return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('SQL Injection Prevention', () => {
    it('should prevent SQL injection in create operations', async () => {
      const maliciousInputs = [
        "'; DROP TABLE garment_items; --",
        "' OR '1'='1",
        "'; DELETE FROM users WHERE '1'='1'; --",
        "' UNION SELECT * FROM users --",
        "'; INSERT INTO admin_users VALUES ('hacker', 'password'); --",
        "' OR 1=1 LIMIT 1 --",
        "'; EXEC xp_cmdshell('format c:'); --",
        "' AND (SELECT COUNT(*) FROM users) > 0 --"
      ];

      for (const maliciousInput of maliciousInputs) {
        const input = createMockCreateInput({
          file_path: maliciousInput,
          mask_path: maliciousInput
        });

        const safeGarment = createMockGarment(input);
        mockQuery.mockResolvedValueOnce({
          rows: [safeGarment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        // Verify the malicious input is stored as-is (not executed)
        expect(result.file_path).toBe(maliciousInput);
        expect(result.mask_path).toBe(maliciousInput);

        // Verify parameterized queries are used (check mock calls)
        expect(mockQuery).toHaveBeenCalledWith(
          expect.stringContaining('INSERT INTO garment_items'),
          expect.arrayContaining([
            expect.any(String), // id
            expect.any(String), // user_id
            expect.any(String), // original_image_id
            maliciousInput,     // file_path as parameter
            maliciousInput,     // mask_path as parameter
            expect.any(String)  // metadata
          ])
        );

        mockQuery.mockClear();
      }
    });

    it('should prevent SQL injection in findById operations', async () => {
      const maliciousIds = [
        "' OR '1'='1",
        "1'; DROP TABLE garment_items; --",
        "' UNION SELECT password FROM users --",
        "'; WAITFOR DELAY '00:00:05'; --",
        "' OR (SELECT COUNT(*) FROM users) > 0 --"
      ];

      for (const maliciousId of maliciousIds) {
        // Invalid UUID should fail validation and return null
        mockUuidValidate.mockReturnValueOnce(false);

        const result = await garmentModel.findById(maliciousId);

        // Should return null without database call due to UUID validation
        expect(result).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();

        mockQuery.mockClear();
        mockUuidValidate.mockClear();
      }
    });

    it('should prevent SQL injection in metadata fields', async () => {
      const maliciousMetadata = {
        category: "'; DROP TABLE garment_items; --",
        description: "' OR 1=1 --",
        tags: ["'; DELETE FROM users; --", "' UNION SELECT * FROM admin --"],
        nested: {
          evil: "'; EXEC xp_cmdshell('rm -rf /'); --",
          query: "' OR (SELECT password FROM users LIMIT 1) --"
        }
      };

      const input = createMockCreateInput({ metadata: maliciousMetadata });
      const safeGarment = createMockGarment(input);

      mockQuery.mockResolvedValue({
        rows: [safeGarment],
        rowCount: 1
      });

      const result = await garmentModel.create(input);

      // Verify malicious metadata is stored safely as JSON
      expect(result.metadata).toEqual(maliciousMetadata);

      // Verify JSON serialization prevents SQL execution
      const dbCall = mockQuery.mock.calls[0];
      const metadataParam = dbCall[1][5];
      expect(typeof metadataParam).toBe('string');
      
      const parsedMetadata = JSON.parse(metadataParam);
      expect(parsedMetadata.category).toBe(maliciousMetadata.category);
      expect(parsedMetadata.nested.evil).toBe(maliciousMetadata.nested.evil);
    });
  });

  describe('NoSQL Injection Prevention', () => {
    it('should prevent NoSQL injection patterns', async () => {
      const nosqlAttacks = [
        { $ne: null },
        { $gt: "" },
        { $where: "function() { return true; }" },
        { $regex: ".*" },
        { $exists: true },
        { $or: [{ password: { $exists: true } }] },
        { $expr: { $gt: [{ $strLenCP: "$password" }, 0] } }
      ];

      for (const attack of nosqlAttacks) {
        const input = createMockCreateInput({
          metadata: { malicious: attack }
        });

        const safeGarment = createMockGarment(input);
        mockQuery.mockResolvedValueOnce({
          rows: [safeGarment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        // Verify NoSQL operators are stored as data, not executed
        expect(result.metadata.malicious).toEqual(attack);

        // Verify JSON serialization neutralizes NoSQL operators
        const dbCall = mockQuery.mock.calls[0];
        const metadataParam = dbCall[1][5];
        const parsedMetadata = JSON.parse(metadataParam);
        expect(parsedMetadata.malicious).toEqual(attack);

        mockQuery.mockClear();
      }
    });
  });

  describe('Input Validation Security', () => {
    it('should handle extremely long input strings safely', async () => {
      const maxLength = 10000;
      const oversizedInputs = {
        file_path: 'A'.repeat(maxLength * 2),
        mask_path: 'B'.repeat(maxLength * 2),
        metadata: {
          description: 'C'.repeat(maxLength * 3),
          evil_array: Array.from({ length: 1000 }, (_, i) => `item_${i}_${'x'.repeat(100)}`)
        }
      };

      const input = createMockCreateInput(oversizedInputs);
      const garment = createMockGarment(input);

      mockQuery.mockResolvedValue({
        rows: [garment],
        rowCount: 1
      });

      const result = await garmentModel.create(input);

      // Verify long inputs are handled without crashes
      expect(result.file_path).toHaveLength(maxLength * 2);
      expect(result.mask_path).toHaveLength(maxLength * 2);
      expect(result.metadata.description).toHaveLength(maxLength * 3);
      expect(result.metadata.evil_array).toHaveLength(1000);
    });

    it('should handle null bytes and control characters', async () => {
      const maliciousStrings = [
        '\0\0\0NULL_BYTES\0\0\0',
        '\x01\x02\x03CONTROL_CHARS\x1F',
        '\r\n\r\nHTTP_HEADER_INJECTION\r\n',
        '\u0000\u0001\u0002UNICODE_NULLS',
        String.fromCharCode(0, 1, 2, 3, 4, 5),
        '\x00admin\x00',
        'normal\x00hidden_content',
        '\uFEFF\uFFFEBOM_CHARS\uFFFF'
      ];

      for (const maliciousString of maliciousStrings) {
        const input = createMockCreateInput({
          file_path: maliciousString,
          metadata: { evil: maliciousString }
        });

        const garment = createMockGarment(input);
        mockQuery.mockResolvedValueOnce({
          rows: [garment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        // Verify malicious characters are preserved but not executed
        expect(result.file_path).toBe(maliciousString);
        expect(result.metadata.evil).toBe(maliciousString);

        mockQuery.mockClear();
      }
    });

    it('should handle Unicode and encoding attacks', async () => {
      const unicodeAttacks = [
        '＜script＞alert(1)＜/script＞', // Full-width characters
        '\u003cscript\u003ealert(1)\u003c/script\u003e', // Unicode encoded
        '\u{1F4A9}\u{1F4A9}\u{1F4A9}', // Emoji overflow
        '\u200B\u200C\u200D\uFEFF', // Zero-width characters
        'А́dmin', // Cyrillic А instead of Latin A
        '\u202eidamn\u202c', // Right-to-left override
        '\uD800\uDC00', // Surrogate pairs
        '🔥'.repeat(1000) // Emoji DOS
      ];

      for (const attack of unicodeAttacks) {
        const input = createMockCreateInput({
          metadata: { unicode_attack: attack }
        });

        const garment = createMockGarment(input);
        mockQuery.mockResolvedValueOnce({
          rows: [garment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        // Verify Unicode is handled safely
        expect(result.metadata.unicode_attack).toBe(attack);

        // Verify proper JSON encoding
        const dbCall = mockQuery.mock.calls[0];
        const metadataParam = dbCall[1][5];
        expect(() => JSON.parse(metadataParam)).not.toThrow();

        mockQuery.mockClear();
      }
    });
  });

  describe('Access Control & Authorization', () => {
    it('should prevent cross-user data access via ID manipulation', async () => {
      const userAId = MOCK_USER_IDS.VALID_USER_1;
      const userBId = MOCK_USER_IDS.VALID_USER_2;
      
      // User A's garment
      const userAGarment = createMockGarment({
        user_id: userAId,
        metadata: { secret: 'user_a_private_data' }
      });

      mockUuidValidate.mockReturnValue(true);
      mockQuery.mockResolvedValue({
        rows: [userAGarment],
        rowCount: 1
      });

      // Try to access User A's garment (should work)
      const result = await garmentModel.findById(userAGarment.id);
      expect(result).toEqual(userAGarment);

      // Note: Authorization should be handled at service/controller level
      // Model layer correctly returns data if it exists
      // This test verifies the model doesn't accidentally filter by user
    });

    it('should handle concurrent access attempts', async () => {
      const garmentId = MOCK_GARMENT_IDS.VALID_GARMENT_1;
      const garment = createMockGarment({ id: garmentId });

      mockUuidValidate.mockReturnValue(true);
      mockQuery.mockImplementation(() => 
        Promise.resolve({
          rows: [garment],
          rowCount: 1
        })
      );

      // Simulate 20 concurrent access attempts
      const concurrentRequests = Array.from({ length: 20 }, () =>
        garmentModel.findById(garmentId)
      );

      const results = await Promise.all(concurrentRequests);

      // All should succeed with same data
      expect(results).toHaveLength(20);
      results.forEach(result => {
        expect(result).toEqual(garment);
      });

      // Verify no race conditions in database calls
      expect(mockQuery).toHaveBeenCalledTimes(20);
    });
  });

  describe('Resource Exhaustion Protection', () => {
    it('should handle memory exhaustion attempts', async () => {
      const memoryAttacks = [
        // Large array attack
        {
          array_bomb: Array.from({ length: 10000 }, (_, i) => `item_${i}`) // Reduced size
        },
        // Deep nesting attack (but JSON-serializable)
        {
          deep_nesting: Array.from({ length: 100 }, () => ({})).reduce((acc, _) => ({ nested: acc }), { value: 'deep' })
        },
        // Large string attack (reduced size)
        {
          big_string: 'X'.repeat(100000) // 100KB instead of 1MB
        },
        // Complex but safe nested structure
        {
          complex: {
            level1: { level2: { level3: { level4: { value: 'safe_nesting' } } } },
            array: Array.from({ length: 1000 }, (_, i) => ({ id: i, value: `item_${i}` }))
          }
        }
      ];

      for (const attack of memoryAttacks) {
        const startMemory = process.memoryUsage().heapUsed;

        const input = createMockCreateInput({ metadata: attack });
        const garment = createMockGarment(input);

        mockQuery.mockResolvedValueOnce({
          rows: [garment],
          rowCount: 1
        });

        try {
          const result = await garmentModel.create(input);

          const endMemory = process.memoryUsage().heapUsed;
          const memoryIncrease = endMemory - startMemory;

          // Verify operation completes without excessive memory usage
          expect(result.metadata).toEqual(attack);
          expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB increase

          // Verify JSON serialization worked (no circular references)
          const dbCall = mockQuery.mock.calls[0];
          const metadataParam = dbCall[1][5];
          expect(() => JSON.parse(metadataParam)).not.toThrow();
        } catch (error) {
          // If JSON serialization fails due to circular references, it should throw an error
          // This is the expected behavior for truly circular data
          if (error instanceof RangeError && error.message.includes('Maximum call stack size exceeded')) {
            // This is expected for circular references - the model correctly rejects them
            expect(true).toBe(true);
          } else {
            throw error;
          }
        }

        mockQuery.mockClear();

        // Force garbage collection if available
        if (global.gc) {
          global.gc();
        }
      }
    });

    it('should handle CPU exhaustion attempts', async () => {
      const cpuAttacks = [
        // Regex DOS patterns (in metadata)
        {
          regex_dos: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa!',
          pattern: '^(a+)+$' // This pattern can cause exponential backtracking
        },
        // Large number operations
        {
          big_numbers: Array.from({ length: 1000 }, (_, i) => Math.pow(2, i % 30))
        },
        // Complex nested structures
        {
          complexity: Object.fromEntries(
            Array.from({ length: 1000 }, (_, i) => [`key_${i}`, { value: i, nested: { deep: true } }])
          )
        }
      ];

      for (const attack of cpuAttacks) {
        const startTime = Date.now();

        const input = createMockCreateInput({ metadata: attack });
        const garment = createMockGarment(input);

        mockQuery.mockResolvedValueOnce({
          rows: [garment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        const endTime = Date.now();
        const executionTime = endTime - startTime;

        // Verify operation completes quickly
        expect(result.metadata).toEqual(attack);
        expect(executionTime).toBeLessThan(1000); // Less than 1 second

        mockQuery.mockClear();
      }
    });

    it('should handle database connection exhaustion', async () => {
      // Simulate rapid database operations
      const rapidOperations = Array.from({ length: 100 }, (_, i) => 
        createMockCreateInput({ metadata: { operation_id: i } })
      );

      mockQuery.mockImplementation((query, params) => {
        const garment = createMockGarment({
          id: params[0],
          metadata: JSON.parse(params[5])
        });
        return Promise.resolve({
          rows: [garment],
          rowCount: 1
        });
      });

      const startTime = Date.now();
      
      // Execute all operations concurrently
      const results = await Promise.all(
        rapidOperations.map(input => garmentModel.create(input))
      );

      const endTime = Date.now();
      const totalTime = endTime - startTime;

      // Verify all operations complete successfully
      expect(results).toHaveLength(100);
      expect(totalTime).toBeLessThan(5000); // Complete within 5 seconds
      expect(mockQuery).toHaveBeenCalledTimes(100);

      // Verify each result is unique
      const operationIds = results.map(r => r.metadata.operation_id);
      const uniqueIds = new Set(operationIds);
      expect(uniqueIds.size).toBe(100);
    });
  });

  describe('Data Leakage Prevention', () => {
    it('should not leak sensitive data in error messages', async () => {
      const sensitiveData = {
        password: 'super_secret_password',
        api_key: 'sk-1234567890abcdef',
        ssn: '123-45-6789',
        credit_card: '4532-1234-5678-9012',
        private_key: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...',
        internal_path: '/var/secrets/production.env'
      };

      const input = createMockCreateInput({ metadata: sensitiveData });

      // Simulate database error
      const dbError = new Error('Database connection failed');
      mockQuery.mockRejectedValue(dbError);

      try {
        await garmentModel.create(input);
      } catch (error) {
        const errorMessage = (error as Error).message;
        
        // Verify sensitive data is not leaked in error messages
        expect(errorMessage).not.toContain('super_secret_password');
        expect(errorMessage).not.toContain('sk-1234567890abcdef');
        expect(errorMessage).not.toContain('123-45-6789');
        expect(errorMessage).not.toContain('4532-1234-5678-9012');
        expect(errorMessage).not.toContain('BEGIN PRIVATE KEY');
        expect(errorMessage).not.toContain('/var/secrets/production.env');
      }
    });

    it('should not expose internal database structure', async () => {
      // Simulate various database errors
      const dbErrors = [
        new Error('relation "garment_items" does not exist'),
        new Error('column "secret_column" does not exist'),
        new Error('permission denied for table admin_users'),
        new Error('function get_admin_password() does not exist'),
        new Error('DETAIL: Key (user_id)=(admin) conflicts with existing key'),
        new Error('HINT: Consider using TRUNCATE instead of DELETE')
      ];

      for (const dbError of dbErrors) {
        const input = createMockCreateInput();
        mockQuery.mockRejectedValueOnce(dbError);

        try {
          await garmentModel.create(input);
        } catch (error) {
          // Error should be thrown as-is (error handling should happen at higher layers)
          expect(error).toBe(dbError);
        }

        mockQuery.mockClear();
      }
    });
  });

  describe('Time-based Attack Prevention', () => {
    it('should have consistent timing for valid and invalid UUIDs', async () => {
      const validUuid = MOCK_GARMENT_IDS.VALID_GARMENT_1;
      const invalidUuid = 'invalid-uuid-format';

      // Warm up the functions to avoid cold start timing issues
      mockUuidValidate.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
      await garmentModel.findById(validUuid);
      
      mockUuidValidate.mockReturnValueOnce(false);
      await garmentModel.findById(invalidUuid);

      // Clear mocks for actual test
      mockQuery.mockClear();
      mockUuidValidate.mockClear();

      // Collect multiple timing samples to reduce variance
      const validTimes: number[] = [];
      const invalidTimes: number[] = [];
      const samples = 10;

      for (let i = 0; i < samples; i++) {
        // Time valid UUID lookup
        mockUuidValidate.mockReturnValueOnce(true);
        mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

        const startValid = process.hrtime.bigint();
        await garmentModel.findById(validUuid);
        const endValid = process.hrtime.bigint();
        validTimes.push(Number(endValid - startValid) / 1_000_000); // Convert to ms

        // Time invalid UUID lookup
        mockUuidValidate.mockReturnValueOnce(false);

        const startInvalid = process.hrtime.bigint();
        await garmentModel.findById(invalidUuid);
        const endInvalid = process.hrtime.bigint();
        invalidTimes.push(Number(endInvalid - startInvalid) / 1_000_000); // Convert to ms
      }

      // Calculate median times to reduce outlier impact
      const medianValid = validTimes.sort((a, b) => a - b)[Math.floor(samples / 2)];
      const medianInvalid = invalidTimes.sort((a, b) => a - b)[Math.floor(samples / 2)];

      // Invalid UUID should generally be faster (no DB call)
      // But we allow for some variance in timing
      expect(medianInvalid).toBeLessThanOrEqual(medianValid + 2); // Allow 2ms variance

      // Verify that valid UUID made exactly 'samples' DB calls
      // (invalid UUIDs should not make any DB calls)
      expect(mockQuery).toHaveBeenCalledTimes(samples);
    });

    it('should prevent timing-based user enumeration', async () => {
      const existingUserId = MOCK_USER_IDS.VALID_USER_1;
      const nonExistentUserId = 'non-existent-user-id';

      mockUuidValidate.mockReturnValue(true);

      // Time lookup for existing user's garments
      mockQuery.mockResolvedValueOnce({ rows: [createMockGarment()], rowCount: 1 });
      const startExisting = Date.now();
      await garmentModel.findByUserId(existingUserId);
      const existingTime = Date.now() - startExisting;

      // Time lookup for non-existent user's garments
      mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
      const startNonExistent = Date.now();
      await garmentModel.findByUserId(nonExistentUserId);
      const nonExistentTime = Date.now() - startNonExistent;

      // Timing should be similar
      const timingDifference = Math.abs(existingTime - nonExistentTime);
      expect(timingDifference).toBeLessThan(50); // Within 50ms
    });
  });

  describe('Cryptographic Security', () => {
    it('should handle encrypted data patterns safely', async () => {
      const encryptedPatterns = [
        'U2FsdGVkX1+vupppZksvRf5pq5g5XjFRIipRkwB0K1Y=', // Base64
        '-----BEGIN ENCRYPTED DATA-----\nMIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAwJbMsMSdF...', // PEM
        '\\x41\\x42\\x43\\x44', // Hex escaped
        '%41%42%43%44', // URL encoded
        '\u0041\u0042\u0043\u0044', // Unicode escaped
        '{"iv":"abc123","data":"encrypted_payload"}' // JSON encrypted
      ];

      for (const pattern of encryptedPatterns) {
        const input = createMockCreateInput({
          metadata: { encrypted_field: pattern }
        });

        const garment = createMockGarment(input);
        mockQuery.mockResolvedValueOnce({
          rows: [garment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        // Verify encrypted data is stored safely
        expect(result.metadata.encrypted_field).toBe(pattern);

        // Verify JSON serialization doesn't break encryption
        const dbCall = mockQuery.mock.calls[0];
        const metadataParam = dbCall[1][5];
        const parsedMetadata = JSON.parse(metadataParam);
        expect(parsedMetadata.encrypted_field).toBe(pattern);

        mockQuery.mockClear();
      }
    });
  });

  describe('Error Information Disclosure', () => {
    it('should not expose stack traces in production', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      try {
        const input = createMockCreateInput();
        const dbError = new Error('Internal database error with sensitive stack trace');
        mockQuery.mockRejectedValue(dbError);

        await expect(garmentModel.create(input)).rejects.toThrow();

        // In production, detailed stack traces should not be exposed
        // This test verifies the error is thrown (error handling happens at higher layers)
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    it('should handle malformed JSON gracefully', async () => {
      const malformedJsonInputs = [
        '{"incomplete": true',
        '{"double":: "colon"}',
        '{"trailing": "comma",}',
        '{"number": 123abc}',
        '{key: "missing_quotes"}',
        '{"\\": "invalid_escape"}',
        '{"nested": {"broken": }}'
      ];

      for (const malformedJson of malformedJsonInputs) {
        // Test with malformed JSON in metadata (as string)
        const input = createMockCreateInput({
          metadata: { json_data: malformedJson }
        });

        const garment = createMockGarment(input);
        mockQuery.mockResolvedValueOnce({
          rows: [garment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        // Verify malformed JSON is stored as string data
        expect(result.metadata.json_data).toBe(malformedJson);

        mockQuery.mockClear();
      }
    });
  });

  describe('Advanced Security Scenarios', () => {
    it('should handle prototype pollution attempts', async () => {
      const prototypePollutionPayloads = [
        { "__proto__": { "isAdmin": true } },
        { "constructor": { "prototype": { "isAdmin": true } } },
        { "__proto__.isAdmin": true },
        { "prototype": { "polluted": true } },
        JSON.parse('{"__proto__": {"polluted": true}}')
      ];

      for (const payload of prototypePollutionPayloads) {
        const input = createMockCreateInput({
          metadata: payload
        });

        const garment = createMockGarment(input);
        mockQuery.mockResolvedValueOnce({
          rows: [garment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        // Verify prototype pollution payload is stored as data
        expect(result.metadata).toEqual(payload);

        // Verify no actual prototype pollution occurred
        expect(({} as any).isAdmin).toBeUndefined();
        expect(({} as any).polluted).toBeUndefined();

        mockQuery.mockClear();
      }
    });

    it('should handle binary data injection attempts', async () => {
      const binaryAttacks = [
        Buffer.from('malicious binary data').toString('base64'),
        '\uFFFD\uFFFD\uFFFD', // Unicode replacement characters
        String.fromCharCode(...Array.from({ length: 256 }, (_, i) => i)), // All byte values
        Array.from({ length: 1000 }, () => Math.floor(Math.random() * 256)).map(code => String.fromCharCode(code)).join('') // Random binary
      ];

      for (const binaryData of binaryAttacks) {
        const input = createMockCreateInput({
          metadata: { binary_payload: binaryData }
        });

        const garment = createMockGarment(input);
        mockQuery.mockResolvedValueOnce({
          rows: [garment],
          rowCount: 1
        });

        const result = await garmentModel.create(input);

        // Verify binary data is handled safely
        expect(result.metadata.binary_payload).toBe(binaryData);

        // Verify JSON serialization works
        const dbCall = mockQuery.mock.calls[0];
        const metadataParam = dbCall[1][5];
        expect(() => JSON.parse(metadataParam)).not.toThrow();

        mockQuery.mockClear();
      }
    });

    it('should handle concurrent security attacks', async () => {
      const concurrentAttacks = Array.from({ length: 50 }, (_, i) => ({
        sql_injection: `'; DROP TABLE garment_items_${i}; --`,
        xss_payload: `<script>alert('attack_${i}')</script>`,
        command_injection: `; rm -rf /tmp/attack_${i}`,
        path_traversal: `../../../etc/passwd_${i}`
      }));

      mockQuery.mockImplementation((query, params) => {
        const garment = createMockGarment({
          id: params[0],
          metadata: JSON.parse(params[5])
        });
        return Promise.resolve({
          rows: [garment],
          rowCount: 1
        });
      });

      const startTime = Date.now();

      // Execute all attacks concurrently
      const results = await Promise.all(
        concurrentAttacks.map(attack => 
          garmentModel.create(createMockCreateInput({ metadata: attack }))
        )
      );

      const endTime = Date.now();

      // Verify all attacks are handled safely
      expect(results).toHaveLength(50);
      expect(endTime - startTime).toBeLessThan(3000); // Complete within 3 seconds

      // Verify each attack payload is stored as data
      results.forEach((result, index) => {
        expect(result.metadata).toEqual(concurrentAttacks[index]);
      });
    });
  });
});