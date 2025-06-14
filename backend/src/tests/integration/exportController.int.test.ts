/**
 * ExportController Comprehensive Integration Test Suite
 * 
 * @description Complete production-ready integration test suite for exportController.
 * Tests complete HTTP request/response cycle with real database operations and 
 * service layer integration. Validates authentication, authorization, error handling,
 * and business logic with actual PostgreSQL transactions.
 * 
 * @prerequisites
 * - PostgreSQL instance running (Docker or Manual mode)
 * - Test database configured and accessible
 * - Required environment variables set
 * - Test data setup utilities available
 * 
 * @author JLS
 * @version 1.0.0
 * @since June 15, 2025
 */

import { Request, Response, NextFunction } from 'express';
import { jest } from '@jest/globals';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

// Use the dual-mode infrastructure
import { 
  setupWardrobeTestEnvironmentWithAllModels,
  createTestImageDirect 
} from '../../utils/dockerMigrationHelper';

// Import the controller under test
import { exportController } from '../../controllers/exportController';
import { exportService } from '../../services/exportService';
import { MLExportOptions, ExportFormat } from '../../../../shared/src/schemas/export';
import { ApiError } from '../../utils/ApiError';

// #region Utility Functions
/**
 * Sleep utility for async operations and retries
 * @param ms - Milliseconds to sleep
 * @returns Promise that resolves after specified time
 */
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Generates a unique test identifier for avoiding conflicts
 * @returns Unique test identifier string
 */
const generateTestId = () => `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

/**
 * Creates a date in the future for testing expiration logic
 * @param days - Number of days in the future
 * @returns Future date
 */
const getFutureDate = (days: number): Date => {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
};

/**
 * Creates a date in the past for testing cleanup logic
 * @param days - Number of days in the past
 * @returns Past date
 */
const getPastDate = (days: number): Date => {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
};

/**
 * Creates test export options with reasonable defaults
 */
const createTestExportOptions = (overrides: Partial<MLExportOptions> = {}): MLExportOptions => {
  return {
    format: 'coco',
    includeImages: true,
    includeRawPolygons: false,
    includeMasks: false,
    imageFormat: 'jpg',
    compressionQuality: 90,
    ...overrides
  };
};

/**
 * Creates mock Express request object with proper typing
 */
const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => {
  return {
    user: undefined,
    body: {},
    params: {},
    query: {},
    headers: {},
    method: 'GET',
    url: '/api/v1/export/ml',
    ip: '127.0.0.1',
    ...overrides
  };
};

/**
 * Creates mock Express response object with proper typing
 */
const createMockResponse = (): Partial<Response> => {
  const mockResponse = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    download: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis(),
    getHeader: jest.fn(),
    headers: {},
    locals: {}
  };
  
  return mockResponse as any;
};

/**
 * Creates mock Express next function
 */
const createMockNext = (): NextFunction => {
  return jest.fn() as NextFunction;
};

/**
 * Creates sample garment data for testing
 */
const createSampleGarmentData = async (TestDB: any, userId: string, count: number = 5) => {
  const garments = [];
  
  for (let i = 0; i < count; i++) {
    // Create image first
    const image = await createTestImageDirect(TestDB, userId, `garment-${i}`, i);
    
    // Create garment
    const garmentId = uuidv4();
    await TestDB.query(`
      INSERT INTO garments (id, user_id, image_id, category, polygon_points, attributes, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
    `, [
      garmentId,
      userId,
      image.id,
      ['shirt', 'pants', 'dress', 'jacket', 'shoes'][i % 5],
      JSON.stringify([
        { x: 10 + i * 10, y: 10 + i * 10 },
        { x: 50 + i * 10, y: 10 + i * 10 },
        { x: 50 + i * 10, y: 50 + i * 10 },
        { x: 10 + i * 10, y: 50 + i * 10 }
      ]),
      JSON.stringify({
        color: ['red', 'blue', 'green', 'black', 'white'][i % 5],
        size: ['S', 'M', 'L', 'XL', 'XXL'][i % 5],
        brand: `Brand${i % 3}`,
        material: ['cotton', 'polyester', 'wool'][i % 3]
      })
    ]);
    
    garments.push({
      id: garmentId,
      image_id: image.id,
      category: ['shirt', 'pants', 'dress', 'jacket', 'shoes'][i % 5]
    });
  }
  
  return garments;
};

/**
 * Validates HTTP response structure and status codes
 */
const validateResponseStructure = (mockResponse: any, expectedStatus: number) => {
  expect(mockResponse.status).toHaveBeenCalledWith(expectedStatus);
  
  if (expectedStatus >= 200 && expectedStatus < 300) {
    expect(mockResponse.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: true,
        data: expect.any(Object)
      })
    );
  }
};

/**
 * Validates error response handling
 */
const validateErrorResponse = (mockNext: NextFunction, errorType?: typeof ApiError) => {
  expect(mockNext).toHaveBeenCalled();
  
  if (errorType) {
    const errorArg = (mockNext as jest.Mock).mock.calls[0][0];
    expect(errorArg).toBeInstanceOf(Error);
  }
};
// #endregion

describe('ExportController - Comprehensive Integration Test Suite', () => {
  // #region Test Variables
  let TestDB: any;
  let testUserModel: any;
  let testUser1: any;
  let testUser2: any;
  let testAdmin: any;
  
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  // #endregion

  // #region Helper Functions
  // Helper function to ensure database is in clean state
  const ensureCleanDatabase = async () => {
    try {
      // Clear all data in proper order to avoid foreign key violations
      const tables = [
        'export_batch_jobs',
        'garments', 
        'user_oauth_providers',
        'garment_items',
        'wardrobes',
        'wardrobe_items',
        'original_images'
      ];

      for (const table of tables) {
        try {
          await TestDB.query(`DELETE FROM ${table}`);
        } catch (error) {
          // Table might not exist, continue
          console.log(`Table ${table} doesn't exist or couldn't be cleared, continuing...`);
        }
      }
    } catch (error) {
      console.warn('Error during database cleanup:', error);
    }
  };

  /**
   * Sets up required database tables if they don't exist
   */
  const setupDatabaseTables = async () => {
    try {
      // Create export_batch_jobs table
      await TestDB.query(`
        CREATE TABLE IF NOT EXISTS export_batch_jobs (
          id UUID PRIMARY KEY,
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'cancelled')),
          options JSONB NOT NULL DEFAULT '{}',
          progress INTEGER DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
          total_items INTEGER DEFAULT 0 CHECK (total_items >= 0),
          processed_items INTEGER DEFAULT 0 CHECK (processed_items >= 0),
          output_url TEXT,
          error TEXT,
          created_at TIMESTAMP DEFAULT NOW(),
          updated_at TIMESTAMP DEFAULT NOW(),
          completed_at TIMESTAMP,
          expires_at TIMESTAMP,
          CHECK (processed_items <= total_items)
        )
      `);

      // Create garments table if it doesn't exist
      const garmentTableCheck = await TestDB.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_name = 'garments'
        );
      `);

      if (!garmentTableCheck.rows[0].exists) {
        await TestDB.query(`
          CREATE TABLE garments (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            image_id UUID REFERENCES original_images(id) ON DELETE SET NULL,
            category VARCHAR(100),
            polygon_points JSONB DEFAULT '[]',
            attributes JSONB DEFAULT '{}',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
          )
        `);

        // Create images table alias for original_images
        await TestDB.query(`
          CREATE VIEW IF NOT EXISTS images AS SELECT * FROM original_images;
        `);
      }

      // Create indexes for performance
      await TestDB.query(`
        CREATE INDEX IF NOT EXISTS idx_export_batch_jobs_user_id ON export_batch_jobs(user_id);
        CREATE INDEX IF NOT EXISTS idx_export_batch_jobs_status ON export_batch_jobs(status);
        CREATE INDEX IF NOT EXISTS idx_export_batch_jobs_created_at ON export_batch_jobs(created_at);
        CREATE INDEX IF NOT EXISTS idx_garments_user_id ON garments(user_id);
        CREATE INDEX IF NOT EXISTS idx_garments_category ON garments(category);
      `);

      console.log('✅ Export controller tables and indexes set up successfully');
    } catch (error) {
      console.warn('⚠️ Error setting up database tables:', error);
    }
  };

  /**
   * Creates an authenticated request for testing
   */
  const createAuthenticatedRequest = (user: any, overrides: Partial<Request> = {}): Partial<Request> => {
    return createMockRequest({
      user: {
        id: user.id,
        email: user.email,
        name: user.name || 'Test User'
      },
      ...overrides
    });
  };

  /**
   * Creates an unauthenticated request for testing
   */
  const createUnauthenticatedRequest = (overrides: Partial<Request> = {}): Partial<Request> => {
    return createMockRequest({
      user: undefined,
      ...overrides
    });
  };

  /**
   * Executes controller method and captures response
   */
  const executeControllerMethod = async (
    method: keyof typeof exportController,
    request: Partial<Request>,
    response: Partial<Response>,
    next: NextFunction
  ) => {
    await (exportController[method] as any)(request, response, next);
    return {
      request,
      response,
      next,
      statusCode: (response.status as jest.Mock).mock.calls[0]?.[0],
      responseData: (response.json as jest.Mock).mock.calls[0]?.[0],
      downloadCall: (response.download as jest.Mock).mock.calls[0],
      nextCall: (next as jest.Mock).mock.calls[0]?.[0]
    };
  };
  // #endregion
  
  // #region Test Setup and Teardown
  /**
   * Global test setup - runs once before all tests
   * Initializes database, creates test users
   */
  beforeAll(async () => {
    try {
      console.log('🧪 Initializing ExportController comprehensive test environment...');
      
      // Initialize dual-mode test environment
      const setup = await setupWardrobeTestEnvironmentWithAllModels();
      TestDB = setup.TestDB;
      testUserModel = setup.testUserModel;

      // Ensure clean database state
      await ensureCleanDatabase();
      console.log('🧽 Database cleaned for fresh start');

      // Setup database tables
      await setupDatabaseTables();

      // Create unique test users with timestamp and random suffix to avoid conflicts
      const timestamp = Date.now();
      const random = Math.random().toString(36).substring(7);
      
      testUser1 = await testUserModel.create({
        email: `export-ctrl-user1-${timestamp}-${random}@test.com`,
        password: 'SecurePass123!'
      });

      testUser2 = await testUserModel.create({
        email: `export-ctrl-user2-${timestamp}-${random}@test.com`,
        password: 'SecurePass123!'
      });

      testAdmin = await testUserModel.create({
        email: `export-ctrl-admin-${timestamp}-${random}@test.com`,
        password: 'AdminPass123!'
      });

      console.log(`✅ ExportController comprehensive test environment ready`);
    } catch (error) {
      console.error('❌ Test setup failed:', error);
      throw error;
    }
  }, 120000);

  /**
   * Per-test setup - runs before each test
   * Clears export job data while preserving users and sets up fresh mocks
   */
  beforeEach(async () => {
    try {
      // Clear test data
      await TestDB.query('DELETE FROM export_batch_jobs');
      
      try {
        await TestDB.query('DELETE FROM garments');
        await TestDB.query('DELETE FROM original_images');
      } catch (error) {
        // Tables might not exist yet, ignore
      }
      
      // Setup fresh mocks for each test
      mockRequest = createMockRequest();
      mockResponse = createMockResponse();
      mockNext = createMockNext();
      
      console.log('🧽 Test data cleared and mocks reset for individual test');
    } catch (error) {
      console.warn('Could not clear test data in beforeEach:', error);
    }
  });

  /**
   * Global test cleanup - runs once after all tests
   * Cleans up database connections and test data
   */
  afterAll(async () => {
    try {
      console.log('🧹 Starting comprehensive database cleanup...');
      
      // Close TestDB
      if (TestDB && typeof TestDB.cleanup === 'function') {
        await TestDB.cleanup();
      }
      
      // CRITICAL: Force close the global singleton pool
      const dbModule = require('../../models/db');
      if (dbModule.pool && !dbModule.pool.ended) {
        await dbModule.pool.end();
        console.log('✅ Global pool closed');
      }
      
      // Also try the closePool function if it exists
      if (typeof dbModule.closePool === 'function') {
        await dbModule.closePool();
        console.log('✅ closePool() called');
      }
      
      console.log('✅ ExportController comprehensive test cleanup completed');
      
    } catch (error) {
      console.error('❌ Cleanup error:', error instanceof Error ? error.message : String(error));
    }
  }, 30000);
  // #endregion

  // #region Authentication and Authorization Integration Tests
  describe('1. Authentication and Authorization Integration', () => {
    test('should reject unauthenticated requests', async () => {
      // Arrange
      const request = createUnauthenticatedRequest({
        body: { options: createTestExportOptions() }
      });

      // Act
      const result = await executeControllerMethod(
        'createMLExport',
        request,
        mockResponse,
        mockNext
      );

      // Assert
      expect(result.nextCall).toBeInstanceOf(Error);
      expect(result.nextCall.message).toContain('User authentication required');
      expect(result.statusCode).toBeUndefined();
    });

    test('should reject requests with malformed user object', async () => {
      // Arrange
      const request = createMockRequest({
        user: { email: 'test@example.com' }, // Missing id
        body: { options: createTestExportOptions() }
      });

      // Act
      const result = await executeControllerMethod(
        'createMLExport',
        request,
        mockResponse,
        mockNext
      );

      // Assert
      expect(result.nextCall).toBeInstanceOf(Error);
      expect(result.nextCall.message).toContain('User authentication required');
    });

    test('should accept properly authenticated requests', async () => {
      // Arrange
      const request = createAuthenticatedRequest(testUser1, {
        body: { options: createTestExportOptions() }
      });

      // Act
      const result = await executeControllerMethod(
        'createMLExport',
        request,
        mockResponse,
        mockNext
      );

      // Assert
      expect(result.statusCode).toBe(202);
      expect(result.responseData).toMatchObject({
        success: true,
        message: 'ML export job created successfully',
        data: {
          jobId: expect.stringMatching(/^[0-9a-f-]{36}$/i)
        }
      });
      expect(result.nextCall).toBeUndefined();
    });

    test('should prevent access to other users\' export jobs', async () => {
      // Arrange - Create job for user1
      const user1Request = createAuthenticatedRequest(testUser1, {
        body: { options: createTestExportOptions() }
      });

      const createResult = await executeControllerMethod(
        'createMLExport',
        user1Request,
        createMockResponse(),
        createMockNext()
      );

      const jobId = createResult.responseData.data.jobId;

      // Act - Try to access job as user2
      const user2Request = createAuthenticatedRequest(testUser2, {
        params: { jobId }
      });

      const accessResult = await executeControllerMethod(
        'getExportJob',
        user2Request,
        createMockResponse(),
        createMockNext()
      );

      // Assert
      expect(accessResult.nextCall).toBeInstanceOf(Error);
      expect(accessResult.nextCall.message).toContain('You do not have permission to access this export job');
    });

    test('should allow users to access their own export jobs', async () => {
      // Arrange - Create job for user1
      const createRequest = createAuthenticatedRequest(testUser1, {
        body: { options: createTestExportOptions() }
      });

      const createResult = await executeControllerMethod(
        'createMLExport',
        createRequest,
        createMockResponse(),
        createMockNext()
      );

      const jobId = createResult.responseData.data.jobId;

      // Act - Access job as same user
      const accessRequest = createAuthenticatedRequest(testUser1, {
        params: { jobId }
      });

      const accessResult = await executeControllerMethod(
        'getExportJob',
        accessRequest,
        createMockResponse(),
        createMockNext()
      );

      // Assert
      expect(accessResult.statusCode).toBe(200);
      expect(accessResult.responseData).toMatchObject({
        success: true,
        data: expect.objectContaining({
          id: jobId,
          userId: testUser1.id
        })
      });
    });

    test('should handle authentication edge cases', async () => {
      const edgeCases = [
        { user: null, description: 'null user' },
        { user: { id: null }, description: 'null user id' },
        { user: { id: '' }, description: 'empty user id' },
        { user: { id: 'invalid' }, description: 'invalid user id format' }
      ];

      for (const edgeCase of edgeCases) {
        const request = createMockRequest({
          user: edgeCase.user as any,
          body: { options: createTestExportOptions() }
        });

        const result = await executeControllerMethod(
          'createMLExport',
          request,
          createMockResponse(),
          createMockNext()
        );

        expect(result.nextCall).toBeInstanceOf(Error);
        expect(result.nextCall.message).toContain('User authentication required');
      }
    });
  });
  // #endregion

  // #region Export Job Creation Integration Tests
  describe('2. Export Job Creation Integration', () => {
    test('should create export job with complete real database integration', async () => {
      // Arrange
      const options = createTestExportOptions({
        format: 'coco',
        includeImages: true,
        categoryFilter: ['shirt', 'pants']
      });

      const request = createAuthenticatedRequest(testUser1, {
        body: { options }
      });

      // Act
      const result = await executeControllerMethod(
        'createMLExport',
        request,
        mockResponse,
        mockNext
      );

      // Assert HTTP response
      expect(result.statusCode).toBe(202);
      expect(result.responseData).toMatchObject({
        success: true,
        message: 'ML export job created successfully',
        data: {
          jobId: expect.stringMatching(/^[0-9a-f-]{36}$/i)
        }
      });

      // Assert database persistence
      const jobId = result.responseData.data.jobId;
      const dbResult = await TestDB.query(
        'SELECT * FROM export_batch_jobs WHERE id = $1',
        [jobId]
      );

      expect(dbResult.rows).toHaveLength(1);
      const dbJob = dbResult.rows[0];
      expect(dbJob.user_id).toBe(testUser1.id);
      expect(dbJob.status).toBe('pending');
      
      const storedOptions = typeof dbJob.options === 'string' 
        ? JSON.parse(dbJob.options) 
        : dbJob.options;
      expect(storedOptions.format).toBe('coco');
      expect(storedOptions.categoryFilter).toEqual(['shirt', 'pants']);
    });

    test('should handle different export formats through real service integration', async () => {
      const formats: ExportFormat[] = ['coco', 'yolo', 'pascal_voc', 'csv', 'raw_json'];
      
      for (const format of formats) {
        const options = createTestExportOptions({ format });
        const request = createAuthenticatedRequest(testUser1, {
          body: { options }
        });

        const result = await executeControllerMethod(
          'createMLExport',
          request,
          createMockResponse(),
          createMockNext()
        );

        expect(result.statusCode).toBe(202);
        
        // Verify in database
        const jobId = result.responseData.data.jobId;
        const dbResult = await TestDB.query(
          'SELECT options FROM export_batch_jobs WHERE id = $1',
          [jobId]
        );
        
        const storedOptions = typeof dbResult.rows[0].options === 'string' 
          ? JSON.parse(dbResult.rows[0].options) 
          : dbResult.rows[0].options;
        expect(storedOptions.format).toBe(format);
      }
    });

    test('should handle complex export options with real JSON storage', async () => {
      // Arrange
      const complexOptions = createTestExportOptions({
        format: 'coco',
        includeImages: true,
        includeMasks: true,
        categoryFilter: ['formal', 'casual', 'sportswear'],
        garmentIds: [uuidv4(), uuidv4(), uuidv4()],
        imageFormat: 'png',
        compressionQuality: 95,
        metadata: {
          project: 'Fashion ML Dataset',
          version: '2.1.0',
          tags: ['production', 'high-quality'],
          customFields: {
            sourceSystem: 'Koutu',
            exportReason: 'Model Training',
            qualityThreshold: 0.95
          }
        }
      } as any);

      const request = createAuthenticatedRequest(testUser1, {
        body: { options: complexOptions }
      });

      // Act
      const result = await executeControllerMethod(
        'createMLExport',
        request,
        mockResponse,
        mockNext
      );

      // Assert
      expect(result.statusCode).toBe(202);
      
      // Verify complex JSON storage in database
      const jobId = result.responseData.data.jobId;
      const dbResult = await TestDB.query(
        'SELECT options FROM export_batch_jobs WHERE id = $1',
        [jobId]
      );
      
      const storedOptions = typeof dbResult.rows[0].options === 'string' 
        ? JSON.parse(dbResult.rows[0].options) 
        : dbResult.rows[0].options;
      
      expect(storedOptions).toEqual(complexOptions);
      expect(storedOptions.metadata.customFields.sourceSystem).toBe('Koutu');
    });

    test('should handle concurrent export job creation with real database', async () => {
      // Arrange
      const concurrentRequests = 10;
      const promises = Array.from({ length: concurrentRequests }, (_, i) => {
        const request = createAuthenticatedRequest(testUser1, {
          body: { 
            options: createTestExportOptions({
              categoryFilter: [`concurrent-${i}`]
            })
          }
        });

        return executeControllerMethod(
          'createMLExport',
          request,
          createMockResponse(),
          createMockNext()
        );
      });

      // Act
      const results = await Promise.all(promises);

      // Assert
      results.forEach(result => {
        expect(result.statusCode).toBe(202);
        expect(result.responseData.data.jobId).toBeTruthy();
      });

      // Verify all jobs in database
      const dbResult = await TestDB.query(
        'SELECT COUNT(*) as count FROM export_batch_jobs WHERE user_id = $1',
        [testUser1.id]
      );
      expect(parseInt(dbResult.rows[0].count)).toBe(concurrentRequests);
    });

    test('should handle service errors gracefully', async () => {
      // Arrange - Create request with invalid user ID that will cause service error
      const request = createMockRequest({
        user: { id: 'invalid-user-id', email: 'test@example.com' },
        body: { options: createTestExportOptions() }
      });

      // Act
      const result = await executeControllerMethod(
        'createMLExport',
        request,
        mockResponse,
        mockNext
      );

      // Assert
      expect(result.nextCall).toBeInstanceOf(Error);
      expect(result.statusCode).toBeUndefined();
    });

    test('should validate input structure and handle malformed requests', async () => {
      const malformedRequests = [
        { body: null, description: 'null body' },
        { body: {}, description: 'missing options' },
        { body: { invalidField: 'value' }, description: 'missing options field' },
        { body: { options: null }, description: 'null options' }
      ];

      for (const malformedRequest of malformedRequests) {
        const request = createAuthenticatedRequest(testUser1, malformedRequest.body as any);

        const result = await executeControllerMethod(
          'createMLExport',
          request,
          createMockResponse(),
          createMockNext()
        );

        // Should either succeed with undefined options or fail gracefully
        if (result.statusCode === 202) {
          // Service handled gracefully
          expect(result.responseData.data.jobId).toBeTruthy();
        } else {
          // Or failed with error
          expect(result.nextCall).toBeInstanceOf(Error);
        }
      }
    });
  });
  // #endregion

  // #region Export Job Retrieval Integration Tests  
  describe('3. Export Job Retrieval Integration', () => {
    test('should retrieve export job with complete database integration', async () => {
      // Arrange - Create a job first
      const createRequest = createAuthenticatedRequest(testUser1, {
        body: { options: createTestExportOptions() }
      });

      const createResult = await executeControllerMethod(
        'createMLExport',
        createRequest,
        createMockResponse(),
        createMockNext()
      );

      const jobId = createResult.responseData.data.jobId;

      // Act - Retrieve the job
      const retrieveRequest = createAuthenticatedRequest(testUser1, {
        params: { jobId }
      });

      const retrieveResult = await executeControllerMethod(
        'getExportJob',
        retrieveRequest,
        createMockResponse(),
        createMockNext()
      );

      // Assert
      expect(retrieveResult.statusCode).toBe(200);
      expect(retrieveResult.responseData).toMatchObject({
        success: true,
        data: expect.objectContaining({
          id: jobId,
          userId: testUser1.id,
          status: 'pending',
          options: expect.any(Object),
          progress: expect.any(Number),
          totalItems: expect.any(Number),
          processedItems: expect.any(Number)
        })
      });
    });

    test('should handle non-existent job retrieval', async () => {
      // Arrange
      const nonExistentJobId = uuidv4();
      const request = createAuthenticatedRequest(testUser1, {
        params: { jobId: nonExistentJobId }
      });

      // Act
      const result = await executeControllerMethod(
        'getExportJob',
        request,
        mockResponse,
        mockNext
      );

      // Assert
      expect(result.nextCall).toBeInstanceOf(Error);
      expect(result.nextCall.message).toContain('Export job not found');
    });

    test('should retrieve all user export jobs with real data', async () => {
      // Arrange - Create multiple jobs for user1
      const jobCount = 5;
      for (let i = 0; i < jobCount; i++) {
        const request = createAuthenticatedRequest(testUser1, {
          body: { 
            options: createTestExportOptions({
              categoryFilter: [`category-${i}`]
            })
          }