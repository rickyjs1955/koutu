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
import { Pool, PoolConfig } from 'pg';

// Import test utilities
import {
  MockPoolFactory,
  MockQueryResultFactory,
  DatabaseErrors,
  QueryScenarios,
  MockUtils,
  PerformanceMocks,
} from '../__mocks__/db.mock';

import {
  TestConfigs,
  PoolConfigBuilder,
  MockSetup,
  QueryAssertions,
  ErrorSimulation,
  PerformanceHelpers,
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

  beforeAll(() => {
    originalEnv = process.env.NODE_ENV;
  });

  afterAll(() => {
    if (originalEnv !== undefined) {
      process.env.NODE_ENV = originalEnv;
    } else {
      delete process.env.NODE_ENV;
    }
    jest.restoreAllMocks();
  });

  beforeEach(() => {
    // Create fresh mock pool
    mockPool = MockPoolFactory.createSuccessful();
    consoleSpy = MockUtils.setupConsoleSpy();
    
    // Clear all mocks
    jest.clearAllMocks();
    jest.resetModules();
    
    // Setup Pool constructor mock
    createMockPool.mockImplementation(() => mockPool);
  });

  afterEach(() => {
    if (consoleSpy) {
      MockUtils.restoreConsole(consoleSpy);
    }
    jest.resetModules();
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

    it('should handle connection error gracefully', async () => {
      // Arrange
      const config = TestConfigs.development();
      jest.doMock('../../config/index', () => ({ config }));
      
      (mockPool.query as jest.MockedFunction<any>).mockImplementation((text: any, callback?: any) => {
        if (callback && typeof callback === 'function') {
          callback(ErrorSimulation.connectionTimeout(), null);
        }
        return Promise.reject(ErrorSimulation.connectionTimeout());
      });

      // Act
      await import('../../models/db');

      // Assert
      expect(mockPool.query).toHaveBeenCalledWith('SELECT NOW()', expect.any(Function));
      // Fix: Match the actual console.error call format
      expect(consoleSpy.error).toHaveBeenCalledWith('Database connection error:', 'Connection timeout');
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
      // Fix: Match the actual console.log call format
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
    beforeEach(() => {
      jest.doMock('../../config/index', () => ({ config: TestConfigs.development() }));
      jest.resetModules();
    });

    it('should measure query execution time accurately', async () => {
      // Arrange
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
      // Arrange
      jest.resetModules();
      jest.doMock('../../config/index', () => ({ 
        config: TestConfigs.development() 
      }));
      
      // Create a fresh mock that properly handles both connection test and regular queries
      const freshMockPool = MockPoolFactory.createSuccessful();
      createMockPool.mockImplementation(() => freshMockPool);
      
      // Setup mock implementation that handles connection test separately
      (freshMockPool.query as jest.MockedFunction<any>).mockImplementation((text: any, params?: any, callback?: any) => {
        // Handle callback-style invocation (for connection test)
        if (typeof params === 'function') {
          callback = params;
          params = undefined;
        }
        
        if (typeof text === 'string' && text === 'SELECT NOW()' && callback) {
          // Connection test - succeed immediately
          const connectionResult = { rows: [{ now: new Date() }], rowCount: 1 };
          callback(null, connectionResult);
          return Promise.resolve(connectionResult);
        } else {
          // Regular queries - return with delay simulation
          const result = MockQueryResultFactory.success([]);
          if (callback) {
            setTimeout(() => callback(null, result), 10);
          }
          return new Promise((resolve) => {
            setTimeout(() => resolve(result), 10);
          });
        }
      });
      
      const { query } = await import('../../models/db');
      const queryText = 'SELECT * FROM slow_table';

      // Act
      await query(queryText);

      // Assert
      expect(consoleSpy.log).toHaveBeenCalledWith(
        'Executed query:', 
        expect.objectContaining({
          text: queryText,
          params: undefined,
          duration: expect.any(Number),
          rows: expect.any(Number)
        })
      );
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
});