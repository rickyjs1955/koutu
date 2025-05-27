// /backend/src/__tests__/helpers/db.helper.ts

/**
 * @file Database Test Helpers
 * 
 * @description Provides helper utilities for database testing, including
 * mock setup, assertion helpers, and common test scenarios.
 * Used across unit and integration tests for consistent test behavior.
 */

import { jest } from '@jest/globals';
import { Pool, PoolConfig } from 'pg';
import { 
  MockPoolFactory, 
  MockQueryResultFactory, 
  DatabaseErrors,
  MockUtils,
  type MockQueryResult 
} from '../__mocks__/db.mock';

// Test environment configuration
export interface TestDatabaseConfig {
  nodeEnv: string;
  databaseUrl: string;
  dbPoolMax?: number;
  dbConnectionTimeout?: number;
  dbIdleTimeout?: number;
  dbStatementTimeout?: number;
  dbRequireSsl?: boolean;
}

// Default test configurations
export const TestConfigs = {
  development: (): TestDatabaseConfig => ({
    nodeEnv: 'development',
    databaseUrl: 'postgresql://test:test@localhost:5432/test_db',
    dbPoolMax: 20,
    dbConnectionTimeout: 5000,
    dbIdleTimeout: 10000,
    dbStatementTimeout: 30000,
    dbRequireSsl: false,
  }),

  test: (): TestDatabaseConfig => ({
    nodeEnv: 'test',
    databaseUrl: 'postgresql://test:test@localhost:5432/test_db',
    dbPoolMax: 5,
    dbConnectionTimeout: 3000,
    dbIdleTimeout: 5000,
    dbStatementTimeout: 10000,
    dbRequireSsl: false,
  }),

  production: (): TestDatabaseConfig => ({
    nodeEnv: 'production',
    databaseUrl: 'postgresql://user:pass@localhost:5432/prod_db',
    dbPoolMax: 50,
    dbConnectionTimeout: 10000,
    dbIdleTimeout: 30000,
    dbStatementTimeout: 60000,
    dbRequireSsl: true,
  }),

  minimal: (): TestDatabaseConfig => ({
    nodeEnv: 'test',
    databaseUrl: 'postgresql://test:test@localhost:5432/test_db',
  }),

  withSsl: (): TestDatabaseConfig => ({
    nodeEnv: 'production',
    databaseUrl: 'postgresql://user:pass@localhost:5432/prod_db',
    dbRequireSsl: true,
  }),

  invalidUrl: (): TestDatabaseConfig => ({
    nodeEnv: 'test',
    databaseUrl: 'invalid-database-url',
  }),
} as const;

// Pool configuration builder
export class PoolConfigBuilder {
  /**
   * Builds a PoolConfig from test configuration
   */
  static fromTestConfig(config: TestDatabaseConfig): PoolConfig {
    const poolOptions: PoolConfig = {
      connectionString: config.databaseUrl,
    };

    if (config.dbPoolMax !== undefined) {
      poolOptions.max = config.dbPoolMax;
    }
    if (config.dbConnectionTimeout !== undefined && config.dbConnectionTimeout > 0) {
      poolOptions.connectionTimeoutMillis = config.dbConnectionTimeout;
    }
    if (config.dbIdleTimeout !== undefined) {
      poolOptions.idleTimeoutMillis = config.dbIdleTimeout;
    }
    if (config.dbStatementTimeout !== undefined && config.dbStatementTimeout > 0) {
      poolOptions.statement_timeout = config.dbStatementTimeout;
    }

    // SSL Configuration
    if (config.dbRequireSsl) {
      if (config.nodeEnv === 'production') {
        poolOptions.ssl = { rejectUnauthorized: true };
      } else {
        poolOptions.ssl = { rejectUnauthorized: false };
      }
    }

    return poolOptions;
  }

  /**
   * Validates that PoolConfig contains expected values
   */
  static validateConfig(poolConfig: PoolConfig, expectedConfig: TestDatabaseConfig): void {
    expect(poolConfig.connectionString).toBe(expectedConfig.databaseUrl);
    
    if (expectedConfig.dbPoolMax !== undefined) {
      expect(poolConfig.max).toBe(expectedConfig.dbPoolMax);
    }
    
    if (expectedConfig.dbConnectionTimeout !== undefined && expectedConfig.dbConnectionTimeout > 0) {
      expect(poolConfig.connectionTimeoutMillis).toBe(expectedConfig.dbConnectionTimeout);
    }
    
    if (expectedConfig.dbIdleTimeout !== undefined) {
      expect(poolConfig.idleTimeoutMillis).toBe(expectedConfig.dbIdleTimeout);
    }
    
    if (expectedConfig.dbStatementTimeout !== undefined && expectedConfig.dbStatementTimeout > 0) {
      expect(poolConfig.statement_timeout).toBe(expectedConfig.dbStatementTimeout);
    }

    if (expectedConfig.dbRequireSsl) {
      expect(poolConfig.ssl).toBeDefined();
      if (expectedConfig.nodeEnv === 'production') {
        expect(poolConfig.ssl).toEqual({ rejectUnauthorized: true });
      } else {
        expect(poolConfig.ssl).toEqual({ rejectUnauthorized: false });
      }
    }
  }
}

// Mock setup utilities
export class MockSetup {
  /**
   * Sets up basic pool mock
   */
  static setupPoolMock(behavior: 'success' | 'failure' | 'mixed' = 'success'): jest.Mocked<Pool> {
    let mockPool: jest.Mocked<Pool>;
    
    switch (behavior) {
      case 'success':
        mockPool = MockPoolFactory.createSuccessful();
        break;
      case 'failure':
        mockPool = MockPoolFactory.createFailing();
        break;
      case 'mixed':
        mockPool = MockPoolFactory.createMixed();
        break;
      default:
        mockPool = MockPoolFactory.create();
    }

    return mockPool;
  }

  /**
   * Sets up config mock with specified environment
   */
  static setupConfigMock(config: TestDatabaseConfig) {
    return jest.doMock('../../config/index', () => ({
      config,
    }));
  }

  /**
   * Sets up console mocks for testing logging
   */
  static setupConsoleMocks() {
    return MockUtils.setupConsoleSpy();
  }

  /**
   * Cleans up all mocks - safely handles null/undefined values
   */
  static cleanup(mockPool: jest.Mocked<Pool> | null, consoleSpy?: ReturnType<typeof MockUtils.setupConsoleSpy>) {
    // Safely clean up mock pool
    if (mockPool && typeof mockPool === 'object') {
      try {
        MockUtils.resetAllMocks(mockPool);
      } catch (error) {
        // Ignore cleanup errors for null/undefined mocks
        console.warn('Warning: Could not clean up mock pool:', error);
      }
    }
    
    // Safely clean up console spy
    if (consoleSpy && typeof consoleSpy === 'object') {
      try {
        MockUtils.restoreConsole(consoleSpy);
      } catch (error) {
        // Ignore cleanup errors
        console.warn('Warning: Could not restore console:', error);
      }
    }
  }
}

// Query assertion helpers
export class QueryAssertions {
  /**
   * Asserts that a query was executed with specific parameters
   */
  static assertQueryExecuted(
    mockPool: jest.Mocked<Pool>, 
    expectedText: string, 
    expectedParams?: any[]
  ) {
    expect(mockPool.query).toHaveBeenCalledWith(expectedText, expectedParams);
  }

  /**
   * Asserts that a query was not executed
   */
  static assertQueryNotExecuted(mockPool: jest.Mocked<Pool>) {
    expect(mockPool.query).not.toHaveBeenCalled();
  }

  /**
   * Asserts that multiple queries were executed in order
   */
  static assertQueriesExecutedInOrder(
    mockPool: jest.Mocked<Pool>, 
    expectedQueries: Array<{ text: string; params?: any[] }>
  ) {
    expect(mockPool.query).toHaveBeenCalledTimes(expectedQueries.length);
    
    expectedQueries.forEach((expectedQuery, index) => {
      expect(mockPool.query).toHaveBeenNthCalledWith(
        index + 1, 
        expectedQuery.text, 
        expectedQuery.params
      );
    });
  }

  /**
   * Asserts that connection was attempted
   */
  static assertConnectionAttempted(mockPool: jest.Mocked<Pool>) {
    expect(mockPool.connect).toHaveBeenCalled();
  }

  /**
   * Asserts that pool was closed
   */
  static assertPoolClosed(mockPool: jest.Mocked<Pool>) {
    expect(mockPool.end).toHaveBeenCalled();
  }

  /**
   * Asserts that console methods were called with specific messages
   */
  static assertConsoleOutput(
    consoleSpy: ReturnType<typeof MockUtils.setupConsoleSpy>,
    type: 'log' | 'error' | 'warn',
    expectedMessage?: string
  ) {
    expect(consoleSpy[type]).toHaveBeenCalled();
    
    if (expectedMessage) {
      expect(consoleSpy[type]).toHaveBeenCalledWith(expect.stringContaining(expectedMessage));
    }
  }
}

// Error simulation helpers
export class ErrorSimulation {
  static connectionTimeout(): Error {
    return DatabaseErrors.CONNECTION_TIMEOUT(); // Call as function
  }

  static connectionRefused(): Error {
    return DatabaseErrors.CONNECTION_REFUSED(); // Call as function
  }

  static syntaxError(): Error {
    return DatabaseErrors.SYNTAX_ERROR(); // Call as function
  }

  static constraintViolation(): Error {
    return DatabaseErrors.CONSTRAINT_VIOLATION(); // Call as function
  }

  static permissionDenied(): Error {
    return DatabaseErrors.PERMISSION_DENIED(); // Call as function
  }

  static customError(message: string, code?: string): Error {
    const error = new Error(message);
    if (code) {
      (error as any).code = code;
    }
    return error;
  }
}

// Performance testing helpers
export class PerformanceHelpers {
  /**
   * Measures execution time of a function
   */
  static async measureExecutionTime<T>(fn: () => Promise<T>): Promise<{ result: T; duration: number }> {
    const start = Date.now();
    const result = await fn();
    const duration = Date.now() - start;
    
    return { result, duration };
  }

  /**
   * Asserts that execution time is within expected range
   */
  static assertExecutionTime(duration: number, maxDuration: number, minDuration = 0) {
    expect(duration).toBeGreaterThanOrEqual(minDuration);
    expect(duration).toBeLessThanOrEqual(maxDuration);
  }

  /**
   * Creates a delayed promise for timeout testing
   */
  static delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// Data generation helpers
export class DataGenerators {
  /**
   * Generates a random database URL
   */
  static generateDatabaseUrl(
    host = 'localhost',
    port = 5432,
    dbName = 'test_db',
    username = 'test',
    password = 'test'
  ): string {
    return `postgresql://${username}:${password}@${host}:${port}/${dbName}`;
  }

  /**
   * Generates random pool configuration
   */
  static generatePoolConfig(): PoolConfig {
    return {
      connectionString: this.generateDatabaseUrl(),
      max: Math.floor(Math.random() * 50) + 10,
      connectionTimeoutMillis: Math.floor(Math.random() * 10000) + 1000,
      idleTimeoutMillis: Math.floor(Math.random() * 30000) + 5000,
    };
  }

  /**
   * Generates test query scenarios
   */
  static generateQueryScenarios() {
    return {
      select: {
        text: 'SELECT * FROM test_table WHERE id = $1',
        params: ['test-id'],
        result: MockQueryResultFactory.success([{ id: 'test-id', name: 'Test' }]),
      },
      insert: {
        text: 'INSERT INTO test_table (name) VALUES ($1) RETURNING id',
        params: ['Test Name'],
        result: MockQueryResultFactory.insert('new-id'),
      },
      update: {
        text: 'UPDATE test_table SET name = $1 WHERE id = $2',
        params: ['Updated Name', 'test-id'],
        result: MockQueryResultFactory.update(1),
      },
      delete: {
        text: 'DELETE FROM test_table WHERE id = $1',
        params: ['test-id'],
        result: MockQueryResultFactory.delete(1),
      },
    };
  }
}

// Test suite builders
export class TestSuiteBuilder {
  /**
   * Creates a standard test suite for database operations
   */
  static createStandardSuite(
    suiteName: string,
    setupFn: () => Promise<void>,
    teardownFn: () => Promise<void>
  ) {
    return {
      name: suiteName,
      setup: setupFn,
      teardown: teardownFn,
      testCases: {
        connectionTest: () => 'should connect to database successfully',
        queryTest: () => 'should execute queries successfully',
        errorHandling: () => 'should handle database errors gracefully',
        poolManagement: () => 'should manage connection pool correctly',
      },
    };
  }

  /**
   * Creates error-focused test scenarios
   */
  static createErrorScenarios() {
    return [
      {
        name: 'Connection timeout',
        error: ErrorSimulation.connectionTimeout(),
        expectedBehavior: 'should retry connection',
      },
      {
        name: 'Invalid query',
        error: ErrorSimulation.syntaxError(),
        expectedBehavior: 'should throw query error',
      },
      {
        name: 'Permission denied',
        error: ErrorSimulation.permissionDenied(),
        expectedBehavior: 'should throw authorization error',
      },
    ];
  }
}

export default {
  TestConfigs,
  PoolConfigBuilder,
  MockSetup,
  QueryAssertions,
  ErrorSimulation,
  PerformanceHelpers,
  DataGenerators,
  TestSuiteBuilder,
};