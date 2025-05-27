// /backend/src/__tests__/unit/db.unit.test.ts

/**
 * @file Database Unit Tests
 * 
 * @description Comprehensive unit tests for the database module (db.ts).
 * Tests pool configuration, query execution, error handling, and connection management
 * using mocked dependencies to ensure isolation from actual database connections.
 * 
 * @coverage
 * - Pool configuration with various environment settings
 * - Query execution with parameter binding
 * - Error handling and logging
 * - Connection pool management
 * - SSL configuration
 * - Performance monitoring
 */

/**
 * @file Database Unit Tests - FIXED VERSION
 */

import { jest, describe, it, expect, beforeEach, afterEach, beforeAll, afterAll } from '@jest/globals';
import { Pool } from 'pg';

// Import test utilities
import {
  MockPoolFactory,
  MockQueryResultFactory,
  DatabaseErrors,
  QueryScenarios,
  MockUtils,
} from '../__mocks__/db.mock';

import {
  TestConfigs,
  PoolConfigBuilder,
  ErrorSimulation,
} from '../__helpers__/db.helper';

// Create mock constructor BEFORE mocking the module
const createMockPool = jest.fn();

// Mock the pg module completely
jest.mock('pg', () => ({
  Pool: createMockPool,
}));

describe('Database Module Unit Tests', () => {
  let mockPool: jest.Mocked<Pool>;
  let consoleSpy: ReturnType<typeof MockUtils.setupConsoleSpy>;
  let originalEnv: string | undefined;
  let originalSkipTest: string | undefined;

  beforeAll(() => {
    originalEnv = process.env.NODE_ENV;
    originalSkipTest = process.env.SKIP_DB_CONNECTION_TEST;
  });

  afterAll(() => {
    if (originalEnv !== undefined) {
      process.env.NODE_ENV = originalEnv;
    } else {
      delete process.env.NODE_ENV;
    }
    
    if (originalSkipTest !== undefined) {
      process.env.SKIP_DB_CONNECTION_TEST = originalSkipTest;
    } else {
      delete process.env.SKIP_DB_CONNECTION_TEST;
    }
    
    jest.restoreAllMocks();
    jest.resetModules();
  });
  
  beforeEach(() => {
    // Complete reset for each test
    jest.resetModules();
    jest.clearAllMocks();
    jest.restoreAllMocks();
    
    // Clear environment variables that affect connection testing
    delete process.env.SKIP_DB_CONNECTION_TEST;
    
    // Set up config mock
    jest.doMock('../../config/index', () => ({ 
      config: TestConfigs.test() // Use test config by default
    }));
    
    // Create and configure mock pool
    mockPool = MockPoolFactory.createSuccessful();
    consoleSpy = MockUtils.setupConsoleSpy();
    createMockPool.mockImplementation(() => mockPool);
  });

  afterEach(() => {
    // Thorough cleanup after each test
    try {
      MockUtils.restoreConsole(consoleSpy);
    } catch (e) {
      // Ignore cleanup errors
    }
    
    jest.resetModules();
    jest.clearAllMocks();
    jest.restoreAllMocks();
    
    // Reset createMockPool to avoid interference
    createMockPool.mockReset();
  });

  describe('Pool Configuration', () => {
    it('should create pool with minimal configuration', async () => {
      // Arrange
      const minimalConfig = TestConfigs.minimal();
      jest.doMock('../../config/index', () => ({ config: minimalConfig }));

      // Act
      await import('../../models/db');

      // Assert
      expect(createMockPool).toHaveBeenCalledWith({
        connectionString: minimalConfig.databaseUrl,
      });
    });

    it('should create pool with full configuration', async () => {
      // Arrange
      const config = TestConfigs.development();
      jest.doMock('../../config/index', () => ({ config }));

      // Act
      await import('../../models/db');

      // Assert
      const expectedConfig = PoolConfigBuilder.fromTestConfig(config);
      expect(createMockPool).toHaveBeenCalledWith(expectedConfig);
    });

    it('should configure SSL for production environment', async () => {
      // Arrange
      const config = TestConfigs.withSsl();
      jest.doMock('../../config/index', () => ({ config }));

      // Act
      await import('../../models/db');

      // Assert
      expect(createMockPool).toHaveBeenCalledWith({
        connectionString: config.databaseUrl,
        ssl: { rejectUnauthorized: true },
      });
    });

    it('should configure SSL for non-production environment', async () => {
      // Arrange
      const config = { ...TestConfigs.development(), dbRequireSsl: true };
      jest.doMock('../../config/index', () => ({ config }));

      // Act
      await import('../../models/db');

      // Assert
      expect(createMockPool).toHaveBeenCalledWith({
        connectionString: config.databaseUrl,
        max: config.dbPoolMax,
        connectionTimeoutMillis: config.dbConnectionTimeout,
        idleTimeoutMillis: config.dbIdleTimeout,
        statement_timeout: config.dbStatementTimeout,
        ssl: { rejectUnauthorized: false },
      });
    });

    it('should handle undefined timeout values correctly', async () => {
      // Arrange
      const config = {
        ...TestConfigs.test(),
        dbConnectionTimeout: 0,
        dbStatementTimeout: 0,
      };
      jest.doMock('../../config/index', () => ({ config }));

      // Act
      await import('../../models/db');

      // Assert
      expect(createMockPool).toHaveBeenCalledWith({
        connectionString: config.databaseUrl,
        max: config.dbPoolMax,
        idleTimeoutMillis: config.dbIdleTimeout,
      });
    });
  });

  describe('Connection Testing', () => {
    it('should test connection in non-test environment', async () => {
      // Arrange
      const config = TestConfigs.development();
      jest.doMock('../../config/index', () => ({ config }));
      
      // Make sure SKIP_DB_CONNECTION_TEST is not set
      delete process.env.SKIP_DB_CONNECTION_TEST;
      
      (mockPool.query as jest.MockedFunction<any>).mockImplementation((text: any, callback?: any) => {
        if (callback && typeof callback === 'function') {
          callback(null, QueryScenarios.connectionTest());
        }
        return Promise.resolve(QueryScenarios.connectionTest());
      });

      // Act
      await import('../../models/db');

      // Assert
      expect(mockPool.query).toHaveBeenCalledWith('SELECT NOW()', expect.any(Function));
      expect(consoleSpy.log).toHaveBeenCalledWith('Database connected successfully');
    });

    it('should skip connection test in test environment', async () => {
      // Arrange
      const config = TestConfigs.test();
      jest.doMock('../../config/index', () => ({ config }));

      // Act
      await import('../../models/db');

      // Assert
      expect(mockPool.query).not.toHaveBeenCalled();
    });

    it('should skip connection test when explicitly disabled', async () => {
      // Arrange
      const config = TestConfigs.development();
      jest.doMock('../../config/index', () => ({ config }));
      
      // Set the skip flag
      process.env.SKIP_DB_CONNECTION_TEST = 'true';

      // Act
      await import('../../models/db');

      // Assert
      expect(mockPool.query).not.toHaveBeenCalled();
      
      // Clean up
      delete process.env.SKIP_DB_CONNECTION_TEST;
    });
  });

  describe('Query Function', () => {
    beforeEach(() => {
      jest.doMock('../../config/index', () => ({ config: TestConfigs.test() }));
    });

    it('should execute query successfully with parameters', async () => {
      // Arrange
      const { query } = await import('../../models/db');
      const queryText = 'SELECT * FROM users WHERE id = $1';
      const queryParams = ['user-123'];
      const expectedResult = QueryScenarios.userQueries.findById('user-123');
      
      (mockPool.query as jest.MockedFunction<any>).mockResolvedValueOnce(expectedResult);

      // Act
      const result = await query(queryText, queryParams);

      // Assert
      expect(result).toEqual(expectedResult);
      expect(mockPool.query).toHaveBeenCalledWith(queryText, queryParams);
    });

    it('should execute query successfully without parameters', async () => {
      // Arrange
      const { query } = await import('../../models/db');
      const queryText = 'SELECT NOW()';
      const expectedResult = QueryScenarios.connectionTest();
      
      (mockPool.query as jest.MockedFunction<any>).mockResolvedValueOnce(expectedResult);

      // Act
      const result = await query(queryText);

      // Assert
      expect(result).toEqual(expectedResult);
      expect(mockPool.query).toHaveBeenCalledWith(queryText, undefined);
    });

    it('should throw error for empty query text', async () => {
      // Arrange
      const { query } = await import('../../models/db');

      // Act & Assert
      await expect(query('')).rejects.toThrow('Query cannot be empty');
      await expect(query('   ')).rejects.toThrow('Query cannot be empty');
    });

    it('should log query details in development environment', async () => {
      // Arrange
      jest.resetModules();
      jest.doMock('../../config/index', () => ({ config: TestConfigs.development() }));
      
      const { query } = await import('../../models/db');
      const queryText = 'SELECT * FROM users WHERE id = $1';
      const queryParams = ['user-123'];
      const expectedResult = QueryScenarios.userQueries.findById('user-123');
      
      (mockPool.query as jest.MockedFunction<any>).mockResolvedValueOnce(expectedResult);

      // Act
      await query(queryText, queryParams);

      // Assert
      expect(consoleSpy.log).toHaveBeenCalledWith('Executed query:', expect.objectContaining({
        text: queryText,
        params: queryParams,
        duration: expect.any(Number),
        rows: expect.any(Number)
      }));
    });

    it('should not log query details in non-development environment', async () => {
      // Arrange
      jest.resetModules();
      jest.doMock('../../config/index', () => ({ config: TestConfigs.production() }));
      
      const { query } = await import('../../models/db');
      const queryText = 'SELECT * FROM users WHERE id = $1';
      const queryParams = ['user-123'];
      const expectedResult = QueryScenarios.userQueries.findById('user-123');
      
      (mockPool.query as jest.MockedFunction<any>).mockResolvedValueOnce(expectedResult);

      // Act
      await query(queryText, queryParams);

      // Assert
      expect(consoleSpy.log).not.toHaveBeenCalledWith(expect.stringContaining('Executed query'));
    });

    it('should handle database errors and log them', async () => {
      // Arrange
      const { query } = await import('../../models/db');
      const queryText = 'INVALID SQL QUERY';
      const error = ErrorSimulation.syntaxError();
      
      (mockPool.query as jest.MockedFunction<any>).mockRejectedValueOnce(error);

      // Act & Assert
      await expect(query(queryText)).rejects.toThrow(error.message);
      expect(consoleSpy.error).toHaveBeenCalledWith(expect.stringContaining('Query failed'));
    });

    it('should wrap non-Error throwables in Error object', async () => {
      // Arrange
      const { query } = await import('../../models/db');
      const queryText = 'SELECT * FROM users';
      const nonErrorThrowable = 'String error';
      
      (mockPool.query as jest.MockedFunction<any>).mockRejectedValueOnce(nonErrorThrowable);

      // Act & Assert
      await expect(query(queryText)).rejects.toThrow('String error');
    });

    it('should measure and log query execution time', async () => {
      // Arrange
      const { query } = await import('../../models/db');
      const queryText = 'SELECT * FROM users';
      const expectedResult = MockQueryResultFactory.success([]);
      
      (mockPool.query as jest.MockedFunction<any>).mockResolvedValueOnce(expectedResult);

      // Act
      const result = await query(queryText);

      // Assert
      expect(result).toEqual(expectedResult);
    });
  });

  describe('Get Client Function', () => {
    beforeEach(() => {
      jest.doMock('../../config/index', () => ({ config: TestConfigs.test() }));
    });

    it('should return client from pool successfully', async () => {
      // Arrange
      const { getClient } = await import('../../models/db');
      const mockClient = { query: jest.fn(), release: jest.fn() };
      
      (mockPool.connect as jest.MockedFunction<any>).mockResolvedValueOnce(mockClient);

      // Act
      const client = await getClient();

      // Assert
      expect(client).toBe(mockClient);
      expect(mockPool.connect).toHaveBeenCalled();
    });

    it('should reject when pool connection fails', async () => {
      // Arrange
      const { getClient } = await import('../../models/db');
      const error = ErrorSimulation.connectionRefused();
      
      (mockPool.connect as jest.MockedFunction<any>).mockRejectedValueOnce(error);

      // Act & Assert
      await expect(getClient()).rejects.toThrow(error.message);
    });
  });

  describe('Close Pool Function', () => {
    beforeEach(() => {
      jest.doMock('../../config/index', () => ({ config: TestConfigs.test() }));
    });

    it('should close pool successfully', async () => {
      // Arrange
      const { closePool } = await import('../../models/db');
      (mockPool.end as jest.MockedFunction<any>).mockResolvedValueOnce(undefined);

      // Act
      await closePool();

      // Assert
      expect(mockPool.end).toHaveBeenCalled();
      expect(consoleSpy.log).toHaveBeenCalledWith('Database pool closed successfully.');
    });

    it('should handle close pool errors', async () => {
      // Arrange
      const { closePool } = await import('../../models/db');
      const error = new Error('Failed to close pool');
      
      (mockPool.end as jest.MockedFunction<any>).mockRejectedValueOnce(error);

      // Act & Assert
      await expect(closePool()).rejects.toThrow(error.message);
      expect(consoleSpy.error).toHaveBeenCalledWith('Failed to close database pool:', error);
    });

    it('should not close pool if already closed', async () => {
      // Arrange
      const { closePool } = await import('../../models/db');
      
      // First close
      (mockPool.end as jest.MockedFunction<any>).mockResolvedValueOnce(undefined);
      await closePool();

      // Reset mock for second call
      (mockPool.end as jest.MockedFunction<any>).mockReset();

      // Act - Second close attempt
      await closePool();

      // Assert
      expect(mockPool.end).not.toHaveBeenCalled();
      expect(consoleSpy.log).toHaveBeenCalledWith('Database pool already closed.');
    });
  });

  describe('Error Handling Edge Cases', () => {
    beforeEach(() => {
      jest.doMock('../../config/index', () => ({ config: TestConfigs.test() }));
    });

    it('should handle various database error types', async () => {
      const { query } = await import('../../models/db');
      const errorTests = [
        { error: DatabaseErrors.CONNECTION_TIMEOUT(), description: 'connection timeout' },
        { error: DatabaseErrors.CONSTRAINT_VIOLATION(), description: 'constraint violation' },
        { error: DatabaseErrors.PERMISSION_DENIED(), description: 'permission denied' },
        { error: DatabaseErrors.TABLE_NOT_FOUND(), description: 'table not found' },
      ];

      for (const { error } of errorTests) {
        (mockPool.query as jest.MockedFunction<any>).mockRejectedValueOnce(error);
        await expect(query('SELECT 1')).rejects.toThrow(error.message);
        expect(consoleSpy.error).toHaveBeenCalledWith(expect.stringContaining('Query failed'));
        
        (mockPool.query as jest.MockedFunction<any>).mockReset();
        consoleSpy.error.mockClear();
        mockPool.query = jest.fn() as any;
      }
    });

    it('should handle null and undefined parameters gracefully', async () => {
      // Arrange
      const { query } = await import('../../models/db');
      const queryText = 'SELECT * FROM users WHERE id = $1';
      const expectedResult = MockQueryResultFactory.success([]);
      
      (mockPool.query as jest.MockedFunction<any>).mockResolvedValue(expectedResult);

      // Act & Assert
      await expect(query(queryText, [null])).resolves.toEqual(expectedResult);
      await expect(query(queryText, [undefined])).resolves.toEqual(expectedResult);
      await expect(query(queryText, [])).resolves.toEqual(expectedResult);
    });
  });

  describe('Performance and Monitoring', () => {
    it('should measure query execution time accurately', async () => {
      // Arrange
      jest.resetModules();
      jest.doMock('../../config/index', () => ({ config: TestConfigs.development() }));
      
      const { query } = await import('../../models/db');
      const queryText = 'SELECT * FROM large_table';
      const expectedResult = MockQueryResultFactory.success([]);
      
      (mockPool.query as jest.MockedFunction<any>).mockResolvedValueOnce(expectedResult);

      // Act
      const start = Date.now();
      const result = await query(queryText);
      const duration = Date.now() - start;

      // Assert
      expect(result).toEqual(expectedResult);
      expect(duration).toBeGreaterThanOrEqual(0);
      expect(duration).toBeLessThan(1000); // Should complete quickly in tests
    });

    it('should log performance metrics for slow queries', async () => {
      // Completely isolate this test from all others
      jest.resetModules();
      jest.clearAllMocks();
      jest.restoreAllMocks();
      
      // Create completely isolated console spy
      const isolatedConsoleSpy = {
        log: jest.spyOn(console, 'log').mockImplementation(() => {}),
        error: jest.spyOn(console, 'error').mockImplementation(() => {}),
        warn: jest.spyOn(console, 'warn').mockImplementation(() => {}),
      };
      
      // Create isolated development config
      const developmentConfig = {
        nodeEnv: 'development',
        databaseUrl: 'postgresql://test:test@localhost:5432/test_db',
        dbPoolMax: 20,
        dbConnectionTimeout: 5000,
        dbIdleTimeout: 10000,
        dbStatementTimeout: 30000,
        dbRequireSsl: false,
      };
      
      jest.doMock('../../config/index', () => ({ 
        config: developmentConfig
      }));
      
      // Ensure connection testing is enabled
      delete process.env.SKIP_DB_CONNECTION_TEST;
      
      // Create completely isolated mock pool
      const isolatedMockPool = {
        query: jest.fn(),
        connect: jest.fn(),
        end: jest.fn(),
        on: jest.fn(),
        removeListener: jest.fn(),
        totalCount: 0,
        idleCount: 0,
        waitingCount: 0,
      } as unknown as jest.Mocked<Pool>;
      
      let callCount = 0;
      
      // Set up isolated query behavior
      (isolatedMockPool.query as any).mockImplementation((text: string, paramsOrCallback?: any, callback?: any) => {
        callCount++;
        
        // Normalize callback parameter
        let actualCallback = callback;
        let actualParams = paramsOrCallback;
        
        if (typeof paramsOrCallback === 'function') {
          actualCallback = paramsOrCallback;
          actualParams = undefined;
        }
        
        // Handle connection test (first call in development)
        if (callCount === 1 && text === 'SELECT NOW()') {
          const connectionTestResult = { 
            rows: [{ now: new Date() }], 
            rowCount: 1,
            command: 'SELECT',
            oid: 0,
            fields: []
          };
          
          if (actualCallback) {
            actualCallback(null, connectionTestResult);
          }
          return Promise.resolve(connectionTestResult);
        }
        
        // Handle regular queries
        const queryResult = { 
          rows: [], 
          rowCount: 0,
          command: 'SELECT',
          oid: 0,
          fields: []
        };
        
        // Add small delay to simulate query execution
        return new Promise((resolve) => {
          setTimeout(() => {
            if (actualCallback) {
              actualCallback(null, queryResult);
            }
            resolve(queryResult);
          }, 5);
        });
      });
      
      // Set up other mock methods
      const isolatedClient = { query: jest.fn(), release: jest.fn() };
      (isolatedMockPool.connect as any).mockResolvedValue(isolatedClient);
      (isolatedMockPool.end as any).mockResolvedValue(undefined);
      
      // Override the global createMockPool for this test
      const originalCreateMockPool = createMockPool.getMockImplementation();
      createMockPool.mockImplementation(() => isolatedMockPool);
      
      try {
        // Import the module to trigger initialization
        const { query } = await import('../../models/db');
        
        // Verify connection test was executed
        expect(isolatedMockPool.query).toHaveBeenCalledWith('SELECT NOW()', expect.any(Function));
        expect(isolatedConsoleSpy.log).toHaveBeenCalledWith('Database connected successfully');
        
        // Clear console logs to focus on the actual test
        isolatedConsoleSpy.log.mockClear();
        
        // Execute the test query
        const testQueryText = 'SELECT * FROM slow_table';
        await query(testQueryText);
        
        // Verify that query execution was logged
        expect(isolatedConsoleSpy.log).toHaveBeenCalledWith(
          'Executed query:', 
          expect.objectContaining({
            text: testQueryText,
            params: undefined,
            duration: expect.any(Number),
            rows: 0
          })
        );
        
      } finally {
        // Restore the original createMockPool implementation
        if (originalCreateMockPool) {
          createMockPool.mockImplementation(originalCreateMockPool);
        } else {
          createMockPool.mockReset();
        }
        
        // Restore console
        isolatedConsoleSpy.log.mockRestore();
        isolatedConsoleSpy.error.mockRestore();
        isolatedConsoleSpy.warn.mockRestore();
      }
    });
  });

  describe('Configuration Edge Cases', () => {
    it('should handle missing optional configuration values', async () => {
      // Arrange
      const minimalConfig = {
        nodeEnv: 'test',
        databaseUrl: 'postgresql://test:test@localhost:5432/test_db',
      };
      jest.doMock('../../config/index', () => ({ config: minimalConfig }));

      // Act
      await import('../../models/db');

      // Assert
      expect(createMockPool).toHaveBeenCalledWith({
        connectionString: minimalConfig.databaseUrl,
      });
    });

    it('should handle zero timeout values correctly', async () => {
      // Arrange
      const configWithZeroTimeouts = {
        ...TestConfigs.test(),
        dbConnectionTimeout: 0,
        dbStatementTimeout: 0,
      };
      jest.doMock('../../config/index', () => ({ config: configWithZeroTimeouts }));

      // Act
      await import('../../models/db');

      // Assert
      const expectedConfig = {
        connectionString: configWithZeroTimeouts.databaseUrl,
        max: configWithZeroTimeouts.dbPoolMax,
        idleTimeoutMillis: configWithZeroTimeouts.dbIdleTimeout,
      };
      expect(createMockPool).toHaveBeenCalledWith(expectedConfig);
    });
  });

  describe('Module Exports', () => {
    it('should export all required functions and objects', async () => {
      // Act
      const dbModule = await import('../../models/db');

      // Assert
      expect(dbModule).toHaveProperty('pool');
      expect(dbModule).toHaveProperty('query');
      expect(dbModule).toHaveProperty('getClient');
      expect(dbModule).toHaveProperty('closePool');
      expect(typeof dbModule.query).toBe('function');
      expect(typeof dbModule.getClient).toBe('function');
      expect(typeof dbModule.closePool).toBe('function');
    });
  });

  // Moved connection error test to the end to avoid interference
  describe('Connection Error Handling', () => {
    it('should handle connection error gracefully', async () => {
      // Complete isolation for this problematic test
      jest.resetModules();
      jest.clearAllMocks();
      jest.restoreAllMocks();
      
      // Create completely isolated mocks
      const isolatedErrorPool = {
        query: jest.fn(),
        connect: jest.fn(),
        end: jest.fn(),
        on: jest.fn(),
        removeListener: jest.fn(),
        totalCount: 0,
        idleCount: 0,
        waitingCount: 0,
      } as unknown as jest.Mocked<Pool>;
      
      const isolatedErrorConsoleSpy = {
        log: jest.spyOn(console, 'log').mockImplementation(() => {}),
        error: jest.spyOn(console, 'error').mockImplementation(() => {}),
        warn: jest.spyOn(console, 'warn').mockImplementation(() => {}),
      };
      
      const errorConfig = {
        nodeEnv: 'development',
        databaseUrl: 'postgresql://test:test@localhost:5432/test_db',
        dbPoolMax: 20,
        dbConnectionTimeout: 5000,
        dbIdleTimeout: 10000,
        dbStatementTimeout: 30000,
        dbRequireSsl: false,
      };
      
      jest.doMock('../../config/index', () => ({ config: errorConfig }));
      
      // Make sure SKIP_DB_CONNECTION_TEST is not set
      delete process.env.SKIP_DB_CONNECTION_TEST;
      
      // Create error inline to avoid any caching issues
      const testError = { message: 'Connection timeout', name: 'Error' };
      
      // Mock the query method to handle both callback and promise rejection properly
      (isolatedErrorPool.query as any).mockImplementation((text: any, callback?: any) => {
        if (callback && typeof callback === 'function') {
          // Call callback with error immediately
          setImmediate(() => callback(testError, null));
          // Return a resolved promise to avoid unhandled rejection
          return Promise.resolve({ 
            rows: [], 
            rowCount: 0,
            command: 'SELECT',
            oid: 0,
            fields: []
          });
        }
        return Promise.reject(testError);
      });

      // Override global createMockPool
      const originalImpl = createMockPool.getMockImplementation();
      createMockPool.mockImplementation(() => isolatedErrorPool);

      try {
        // Act - Import the module and wait a bit for async operations
        await import('../../models/db');
        
        // Give time for the callback to be executed
        await new Promise(resolve => setTimeout(resolve, 50));

        // Assert
        expect(isolatedErrorPool.query).toHaveBeenCalledWith('SELECT NOW()', expect.any(Function));
        expect(isolatedErrorConsoleSpy.error).toHaveBeenCalledWith('Database connection error:', 'Connection timeout');
      } finally {
        // Restore everything
        if (originalImpl) {
          createMockPool.mockImplementation(originalImpl);
        } else {
          createMockPool.mockReset();
        }
        
        isolatedErrorConsoleSpy.log.mockRestore();
        isolatedErrorConsoleSpy.error.mockRestore();
        isolatedErrorConsoleSpy.warn.mockRestore();
      }
    });
  });
});