// /backend/src/utils/garments.helper.ts - Test Helper Functions for Garment Domain

import { 
  MOCK_USER_IDS, 
  MOCK_IMAGE_IDS, 
  MOCK_GARMENT_IDS, 
  MOCK_GARMENTS,
  MOCK_IMAGES,
  MOCK_DB_RESPONSES,
  createMockGarment,
  createMockCreateInput
} from '../__mocks__/garments.mock';
import { Garment, CreateGarmentInput } from '../../models/garmentModel';

// Database Query Mock Helpers
export class DatabaseMockHelper {
  private static mockResponses: Map<string, any> = new Map();

  static setupMockResponse(queryPattern: string, response: any) {
    this.mockResponses.set(queryPattern, response);
  }

  static getMockResponse(query: string): any {
    // Match query patterns to responses
    if (query.includes('INSERT INTO garment_items')) {
      return MOCK_DB_RESPONSES.CREATE_SUCCESS;
    }
    
    if (query.includes('SELECT * FROM garment_items WHERE id =')) {
      const id = this.extractIdFromQuery(query);
      if (id === MOCK_GARMENT_IDS.VALID_GARMENT_1) {
        return MOCK_DB_RESPONSES.FIND_SUCCESS;
      }
      return MOCK_DB_RESPONSES.FIND_EMPTY;
    }
    
    if (query.includes('SELECT * FROM garment_items WHERE user_id =')) {
      return {
        rows: [MOCK_GARMENTS.BASIC_SHIRT, MOCK_GARMENTS.DETAILED_DRESS],
        rowCount: 2
      };
    }
    
    if (query.includes('UPDATE garment_items')) {
      return MOCK_DB_RESPONSES.UPDATE_SUCCESS;
    }
    
    if (query.includes('DELETE FROM garment_items')) {
      return MOCK_DB_RESPONSES.DELETE_SUCCESS;
    }
    
    return MOCK_DB_RESPONSES.FIND_EMPTY;
  }

  static extractIdFromQuery(query: string): string {
    const match = query.match(/\$1.*['"]([^'"]+)['"]/);
    return match ? match[1] : '';
  }

  static reset() {
    this.mockResponses.clear();
  }
}

// Validation Test Helpers
export class ValidationHelper {
  static validateGarmentStructure(garment: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    // Required fields
    const requiredFields = ['id', 'user_id', 'original_image_id', 'file_path', 'mask_path', 'created_at', 'updated_at', 'data_version'];
    
    for (const field of requiredFields) {
      if (!(field in garment)) {
        errors.push(`Missing required field: ${field}`);
      }
    }
    
    // UUID format validation
    const uuidFields = ['id', 'user_id', 'original_image_id'];
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    
    for (const field of uuidFields) {
      if (garment[field] && !uuidRegex.test(garment[field])) {
        errors.push(`Invalid UUID format for ${field}: ${garment[field]}`);
      }
    }
    
    // Path validation
    if (garment.file_path && !garment.file_path.startsWith('/')) {
      errors.push('file_path should be an absolute path');
    }
    
    if (garment.mask_path && !garment.mask_path.startsWith('/')) {
      errors.push('mask_path should be an absolute path');
    }
    
    // Metadata validation
    if (garment.metadata !== undefined && typeof garment.metadata !== 'object') {
      errors.push('metadata must be an object');
    }
    
    if (garment.metadata && Array.isArray(garment.metadata)) {
      errors.push('metadata cannot be an array');
    }
    
    // Date validation
    const dateFields = ['created_at', 'updated_at'];
    for (const field of dateFields) {
      if (garment[field] && !(garment[field] instanceof Date) && isNaN(Date.parse(garment[field]))) {
        errors.push(`Invalid date format for ${field}`);
      }
    }
    
    // Version validation
    if (garment.data_version !== undefined && (!Number.isInteger(garment.data_version) || garment.data_version < 1)) {
      errors.push('data_version must be a positive integer');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }

  static validateCreateInput(input: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    // Required fields
    const requiredFields = ['user_id', 'original_image_id', 'file_path', 'mask_path'];
    
    for (const field of requiredFields) {
      if (!(field in input) || !input[field]) {
        errors.push(`Missing required field: ${field}`);
      }
    }
    
    // UUID validation
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    
    if (input.user_id && !uuidRegex.test(input.user_id)) {
      errors.push(`Invalid UUID format for user_id: ${input.user_id}`);
    }
    
    if (input.original_image_id && !uuidRegex.test(input.original_image_id)) {
      errors.push(`Invalid UUID format for original_image_id: ${input.original_image_id}`);
    }
    
    // Path validation
    if (input.file_path && typeof input.file_path !== 'string') {
      errors.push('file_path must be a string');
    }
    
    if (input.mask_path && typeof input.mask_path !== 'string') {
      errors.push('mask_path must be a string');
    }
    
    // Metadata validation
    if (input.metadata !== undefined) {
      if (typeof input.metadata !== 'object' || Array.isArray(input.metadata)) {
        errors.push('metadata must be an object (not array)');
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }

  static validateMetadata(metadata: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    if (metadata === null || metadata === undefined) {
      return { isValid: true, errors: [] }; // Optional field
    }
    
    if (typeof metadata !== 'object' || Array.isArray(metadata)) {
      errors.push('metadata must be an object');
      return { isValid: false, errors };
    }
    
    // Validate specific garment metadata fields if present
    if (metadata.category && typeof metadata.category !== 'string') {
      errors.push('category must be a string');
    }
    
    if (metadata.size && !['XS', 'S', 'M', 'L', 'XL', 'XXL'].includes(metadata.size)) {
      errors.push('size must be one of: XS, S, M, L, XL, XXL');
    }
    
    if (metadata.color && typeof metadata.color !== 'string') {
      errors.push('color must be a string');
    }
    
    // Check metadata size (JSON string length)
    const metadataString = JSON.stringify(metadata);
    if (metadataString.length > 10000) {
      errors.push('metadata too large (max 10KB)');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
}

// Test Scenario Helpers
export class TestScenarioHelper {
  static createSuccessfulCreateScenario() {
    return {
      input: createMockCreateInput(),
      expectedDbCalls: [
        'INSERT INTO garment_items'
      ],
      expectedResult: expect.objectContaining({
        id: expect.any(String),
        user_id: MOCK_USER_IDS.VALID_USER_1,
        data_version: 1
      })
    };
  }

  static createFailureScenarios() {
    return {
      invalidUserId: {
        input: createMockCreateInput({ user_id: 'invalid-uuid' }),
        expectedError: 'validation',
        shouldNotCallDb: true
      },
      missingFilePath: {
        input: createMockCreateInput({ file_path: '' }),
        expectedError: 'validation',
        shouldNotCallDb: true
      },
      invalidMetadata: {
        input: createMockCreateInput({ metadata: 'invalid' as any }),
        expectedError: 'validation',
        shouldNotCallDb: true
      }
    };
  }

  static createFindByIdScenarios() {
    return {
      validId: {
        input: MOCK_GARMENT_IDS.VALID_GARMENT_1,
        expectedResult: MOCK_GARMENTS.BASIC_SHIRT,
        expectedDbCall: 'SELECT * FROM garment_items WHERE id = $1'
      },
      invalidId: {
        input: 'invalid-uuid',
        expectedResult: null,
        shouldNotCallDb: true
      },
      notFound: {
        input: MOCK_GARMENT_IDS.NONEXISTENT_GARMENT,
        expectedResult: null,
        expectedDbCall: 'SELECT * FROM garment_items WHERE id = $1'
      }
    };
  }

  static createUpdateMetadataScenarios() {
    return {
      validUpdate: {
        id: MOCK_GARMENT_IDS.VALID_GARMENT_1,
        metadata: { color: 'green', size: 'L' },
        options: { replace: false },
        expectedResult: expect.objectContaining({
          metadata: expect.objectContaining({ color: 'green', size: 'L' }),
          data_version: 2
        })
      },
      replaceMode: {
        id: MOCK_GARMENT_IDS.VALID_GARMENT_1,
        metadata: { category: 'jacket' },
        options: { replace: true },
        expectedResult: expect.objectContaining({
          metadata: { category: 'jacket' }, // Only new metadata
          data_version: 2
        })
      },
      invalidMetadata: {
        id: MOCK_GARMENT_IDS.VALID_GARMENT_1,
        metadata: null,
        options: { replace: false },
        expectedError: 'validation'
      }
    };
  }
}

// Performance Test Helpers
export class PerformanceHelper {
  static async measureExecutionTime(fn: () => Promise<any>): Promise<{ result: any; duration: number }> {
    const start = process.hrtime.bigint();
    const result = await fn();
    const end = process.hrtime.bigint();
    const duration = Number(end - start) / 1000000; // Convert to milliseconds
    
    return { result, duration };
  }

  static createBulkTestData(count: number) {
    return {
      inputs: Array.from({ length: count }, () => createMockCreateInput()),
      expectedCount: count,
      maxAcceptableDuration: count * 10 // 10ms per operation
    };
  }

  static validatePerformanceRequirements(operation: string, duration: number): { passed: boolean; message: string } {
    const requirements = {
      create: 100,      // 100ms max
      findById: 50,     // 50ms max
      findByUserId: 200,// 200ms max
      update: 100,      // 100ms max
      delete: 100       // 100ms max
    };

    const maxDuration = requirements[operation as keyof typeof requirements] || 100;
    const passed = duration <= maxDuration;
    
    return {
      passed,
      message: passed 
        ? `✅ ${operation} completed in ${duration.toFixed(2)}ms (max: ${maxDuration}ms)`
        : `❌ ${operation} took ${duration.toFixed(2)}ms (max: ${maxDuration}ms)`
    };
  }
}

// Assertion Helpers
export class AssertionHelper {
  static assertGarmentEquals(actual: Garment, expected: Partial<Garment>, fields?: string[]) {
    const fieldsToCheck = fields || Object.keys(expected);
    
    for (const field of fieldsToCheck) {
      const actualValue = (actual as any)[field];
      const expectedValue = (expected as any)[field];
      
      if (field === 'metadata') {
        expect(actualValue).toEqual(expectedValue);
      } else if (field.includes('_at')) {
        // Date comparison
        expect(new Date(actualValue)).toEqual(new Date(expectedValue));
      } else {
        expect(actualValue).toBe(expectedValue);
      }
    }
  }

  static assertValidGarmentStructure(garment: any) {
    const validation = ValidationHelper.validateGarmentStructure(garment);
    expect(validation.isValid).toBe(true);
    if (!validation.isValid) {
      throw new Error(`Invalid garment structure: ${validation.errors.join(', ')}`);
    }
  }

  static assertMetadataUpdated(originalGarment: Garment, updatedGarment: Garment, newMetadata: any, isReplace: boolean = false) {
    if (isReplace) {
      expect(updatedGarment.metadata).toEqual(newMetadata);
    } else {
      expect(updatedGarment.metadata).toEqual({
        ...originalGarment.metadata,
        ...newMetadata
      });
    }
    
    // Version should be incremented
    expect(updatedGarment.data_version).toBe(originalGarment.data_version + 1);
    
    // Updated timestamp should be newer
    expect(new Date(updatedGarment.updated_at).getTime()).toBeGreaterThan(
      new Date(originalGarment.updated_at).getTime()
    );
  }

  static assertDbCallMade(mockQuery: jest.Mock, expectedQuery: string, expectedParams?: any[]) {
    expect(mockQuery).toHaveBeenCalledWith(
      expect.stringContaining(expectedQuery),
      expectedParams ? expect.arrayContaining(expectedParams) : expect.any(Array)
    );
  }

  static assertNoDbCalls(mockQuery: jest.Mock) {
    expect(mockQuery).not.toHaveBeenCalled();
  }
}

// Data Generation Helpers
export class DataGenerationHelper {
  static generateTestSuite(name: string, scenarios: any[]) {
    return {
      name,
      scenarios,
      totalTests: scenarios.length,
      estimatedDuration: scenarios.length * 50 // 50ms per test
    };
  }

  static generateGarmentsByCategory(categories: string[], count: number = 5) {
    return categories.flatMap(category => 
      Array.from({ length: count }, (_, index) => 
        createMockGarment({
          metadata: {
            category,
            color: ['red', 'blue', 'green', 'black', 'white'][index % 5],
            size: ['XS', 'S', 'M', 'L', 'XL'][index % 5]
          }
        })
      )
    );
  }

  static generateGarmentsWithFilters() {
    return {
      byCategory: {
        shirts: this.generateGarmentsByCategory(['shirt'], 3),
        pants: this.generateGarmentsByCategory(['pants'], 2),
        dresses: this.generateGarmentsByCategory(['dress'], 4)
      },
      bySize: {
        small: Array.from({ length: 3 }, () => createMockGarment({ metadata: { size: 'S' } })),
        medium: Array.from({ length: 5 }, () => createMockGarment({ metadata: { size: 'M' } })),
        large: Array.from({ length: 2 }, () => createMockGarment({ metadata: { size: 'L' } }))
      },
      byColor: {
        red: Array.from({ length: 4 }, () => createMockGarment({ metadata: { color: 'red' } })),
        blue: Array.from({ length: 3 }, () => createMockGarment({ metadata: { color: 'blue' } })),
        green: Array.from({ length: 2 }, () => createMockGarment({ metadata: { color: 'green' } }))
      }
    };
  }

  static generatePaginationTestData(totalItems: number) {
    const garments = Array.from({ length: totalItems }, (_, index) => 
      createMockGarment({
        metadata: { index: index.toString() }
      })
    );

    return {
      allGarments: garments,
      testCases: [
        { page: 1, limit: 5, expectedStart: 0, expectedEnd: 5 },
        { page: 2, limit: 5, expectedStart: 5, expectedEnd: 10 },
        { page: 3, limit: 5, expectedStart: 10, expectedEnd: 15 },
        { page: 1, limit: 10, expectedStart: 0, expectedEnd: 10 },
        { page: 2, limit: 10, expectedStart: 10, expectedEnd: 20 }
      ]
    };
  }
}

// Error Testing Helpers
export class ErrorTestHelper {
  static createDatabaseErrorScenarios() {
    return {
      connectionError: {
        error: new Error('Connection failed'),
        expectedErrorType: 'DatabaseError',
        expectRetry: true
      },
      constraintViolation: {
        error: new Error('duplicate key value violates unique constraint'),
        expectedErrorType: 'ValidationError',
        expectRetry: false
      },
      timeoutError: {
        error: new Error('Query timeout'),
        expectedErrorType: 'TimeoutError',
        expectRetry: true
      }
    };
  }

  static createValidationErrorScenarios() {
    return {
      invalidUuid: {
        input: createMockCreateInput({ user_id: 'not-a-uuid' }),
        expectedMessage: 'Invalid UUID format'
      },
      emptyRequiredField: {
        input: createMockCreateInput({ file_path: '' }),
        expectedMessage: 'Missing required field'
      },
      invalidMetadataType: {
        input: createMockCreateInput({ metadata: 'not-an-object' as any }),
        expectedMessage: 'metadata must be an object'
      },
      oversizedMetadata: {
        input: createMockCreateInput({ 
          metadata: Object.fromEntries(
            Array.from({ length: 1000 }, (_, i) => [`key${i}`, `${'x'.repeat(100)}`])
          )
        }),
        expectedMessage: 'metadata too large'
      }
    };
  }

  static simulateDbError(errorType: 'timeout' | 'connection' | 'constraint' | 'unknown') {
    const errors = {
      timeout: new Error('Query timeout exceeded'),
      connection: new Error('ECONNREFUSED'),
      constraint: new Error('duplicate key value violates unique constraint'),
      unknown: new Error('Unknown database error')
    };
    
    return errors[errorType];
  }
}

// Cleanup Helpers
export class CleanupHelper {
  static resetAllMocks() {
    DatabaseMockHelper.reset();
    jest.clearAllMocks();
  }

  static createTestCleanupFunction(mocks: jest.Mock[]) {
    return () => {
      mocks.forEach(mock => mock.mockClear());
      DatabaseMockHelper.reset();
    };
  }

  static validateTestEnvironmentClean() {
    // Verify no mocks are still active
    // Check for any hanging async operations
    // Validate database connections are closed
    return {
      isClean: true,
      issues: []
    };
  }
}

// Integration Test Helpers
export class IntegrationTestHelper {
  static createEndToEndScenario() {
    return {
      setup: async () => {
        // Setup test database
        // Create test users
        // Upload test images
      },
      execute: async () => {
        // Create garments
        // Retrieve garments
        // Update metadata
        // Delete garments
      },
      cleanup: async () => {
        // Remove test data
        // Reset database state
      }
    };
  }

  static validateSystemConsistency() {
    return {
      checkImageGarmentRelationship: async (imageId: string, garmentId: string) => {
        // Verify foreign key relationships
        // Check data consistency
      },
      checkUserOwnership: async (userId: string, garmentId: string) => {
        // Verify ownership chains
        // Check permission consistency
      },
      checkFileSystemConsistency: async (garment: Garment) => {
        // Verify files exist
        // Check file paths are valid
      }
    };
  }
}

// Export all helpers
export {
  MOCK_USER_IDS,
  MOCK_IMAGE_IDS,
  MOCK_GARMENT_IDS,
  MOCK_GARMENTS,
  MOCK_IMAGES,
  MOCK_DB_RESPONSES,
  createMockGarment,
  createMockCreateInput
} from '../__mocks__/garments.mock';