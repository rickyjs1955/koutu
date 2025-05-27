// /backend/src/__tests__/mocks/db.mock.ts

/**
 * @file Database Mock Utilities
 * 
 * @description Provides comprehensive mocking utilities for the database module,
 * including Pool mocks, query result mocks, and error simulation capabilities.
 * Used primarily for unit testing database operations without actual database connections.
 */

import { jest } from '@jest/globals';
import { Pool, PoolClient, QueryResult } from 'pg';

// Mock query result interface
export interface MockQueryResult extends Partial<QueryResult> {
  rows: any[];
  rowCount: number;
  command?: string;
  oid?: number;
  fields?: any[];
}

// Mock pool client
export interface MockPoolClient extends Partial<PoolClient> {
  query: jest.MockedFunction<any>;
  release: jest.MockedFunction<any>;
}

// Database error types for testing
export const DatabaseErrors = {
  CONNECTION_TIMEOUT: () => new Error('Connection timeout'),
  CONNECTION_REFUSED: () => new Error('Connection refused'),
  INVALID_QUERY: () => new Error('Invalid SQL query'),
  CONSTRAINT_VIOLATION: () => new Error('UNIQUE constraint violation'),
  FOREIGN_KEY_ERROR: () => new Error('FOREIGN KEY constraint failed'),
  SYNTAX_ERROR: () => new Error('Syntax error in SQL'),
  PERMISSION_DENIED: () => new Error('Permission denied'),
  TABLE_NOT_FOUND: () => new Error('Table "nonexistent" does not exist'),
  COLUMN_NOT_FOUND: () => new Error('Column "invalid_column" does not exist'),
  DATA_TYPE_MISMATCH: () => new Error('Invalid input syntax for type'),
} as const;

// Query result factory
export class MockQueryResultFactory {
  /**
   * Creates a successful query result
   */
  static success(rows: any[] = [], rowCount?: number): MockQueryResult {
    return {
      rows,
      rowCount: rowCount ?? rows.length,
      command: 'SELECT',
      oid: 0,
      fields: []
    };
  }

  /**
   * Creates an insert result
   */
  static insert(insertedId?: string): MockQueryResult {
    const rows = insertedId ? [{ id: insertedId }] : [];
    return {
      rows,
      rowCount: 1,
      command: 'INSERT',
      oid: 0,
      fields: []
    };
  }

  /**
   * Creates an update result
   */
  static update(affectedRows: number = 1): MockQueryResult {
    return {
      rows: [],
      rowCount: affectedRows,
      command: 'UPDATE',
      oid: 0,
      fields: []
    };
  }

  /**
   * Creates a delete result
   */
  static delete(deletedRows: number = 1): MockQueryResult {
    return {
      rows: [],
      rowCount: deletedRows,
      command: 'DELETE',
      oid: 0,
      fields: []
    };
  }

  /**
   * Creates an empty result (no rows found)
   */
  static empty(): MockQueryResult {
    return {
      rows: [],
      rowCount: 0,
      command: 'SELECT',
      oid: 0,
      fields: []
    };
  }
}

// Mock pool client factory
export class MockPoolClientFactory {
  /**
   * Creates a mock pool client with default behavior
   */
  static create(): MockPoolClient {
    const mockClient: MockPoolClient = {
      query: jest.fn(),
      release: jest.fn(),
    };

    return mockClient;
  }

  /**
   * Creates a mock pool client that always succeeds
   */
  static createSuccessful(defaultResult?: MockQueryResult): MockPoolClient {
    const mockClient = this.create();
    const result = defaultResult || MockQueryResultFactory.success();
    
    mockClient.query!.mockResolvedValue(result);
    
    return mockClient;
  }

  /**
   * Creates a mock pool client that always throws errors
   */
  static createFailing(error: Error = DatabaseErrors.CONNECTION_TIMEOUT()): MockPoolClient {
    const mockClient = this.create();
    
    mockClient.query!.mockRejectedValue(error);
    
    return mockClient;
  }
}

// Mock pool factory
export class MockPoolFactory {
  /**
   * Creates a mock pool with default behavior
   */
  static create(): jest.Mocked<Pool> {
    const mockPool = {
      query: jest.fn(),
      connect: jest.fn(),
      end: jest.fn(),
      on: jest.fn(),
      removeListener: jest.fn(),
      totalCount: 0,
      idleCount: 0,
      waitingCount: 0,
    } as unknown as jest.Mocked<Pool>;

    return mockPool;
  }

  /**
   * Creates a mock pool that always succeeds
   */
  static createSuccessful(defaultResult?: MockQueryResult): jest.Mocked<Pool> {
    const mockPool = this.create();
    const result = defaultResult || MockQueryResultFactory.success();
    
    (mockPool.query as jest.MockedFunction<any>).mockResolvedValue(result);
    (mockPool.connect as jest.MockedFunction<any>).mockResolvedValue(MockPoolClientFactory.createSuccessful(result));
    (mockPool.end as jest.MockedFunction<any>).mockResolvedValue(undefined);
    
    return mockPool;
  }

  /**
   * Creates a mock pool that fails on operations
   */
  static createFailing(error: Error = DatabaseErrors.CONNECTION_TIMEOUT()): jest.Mocked<Pool> {
    const mockPool = this.create();
    
    (mockPool.query as jest.MockedFunction<any>).mockRejectedValue(error);
    (mockPool.connect as jest.MockedFunction<any>).mockRejectedValue(error);
    (mockPool.end as jest.MockedFunction<any>).mockRejectedValue(error);
    
    return mockPool;
  }

  /**
   * Creates a mock pool with mixed behavior (some success, some failure)
   */
  static createMixed(): jest.Mocked<Pool> {
    const mockPool = this.create();
    
    // First call succeeds, subsequent calls fail
    (mockPool.query as jest.MockedFunction<any>)
      .mockResolvedValueOnce(MockQueryResultFactory.success([{ id: 1 }]))
      .mockRejectedValue(DatabaseErrors.CONNECTION_TIMEOUT);
    
    (mockPool.connect as jest.MockedFunction<any>)
      .mockResolvedValueOnce(MockPoolClientFactory.createSuccessful())
      .mockRejectedValue(DatabaseErrors.CONNECTION_REFUSED);
    
    return mockPool;
  }
}

// Query scenario mocks
export class QueryScenarios {
  /**
   * Mock for successful database connection test
   */
  static connectionTest(): MockQueryResult {
    return MockQueryResultFactory.success([{ now: new Date() }], 1);
  }

  /**
   * Mock for user queries
   */
  static userQueries = {
    findById: (id: string) => MockQueryResultFactory.success([
      { id, email: 'test@example.com', name: 'Test User' }
    ]),
    findByEmail: (email: string) => MockQueryResultFactory.success([
      { id: 'user-123', email, name: 'Test User' }
    ]),
    create: (id: string) => MockQueryResultFactory.insert(id),
    update: () => MockQueryResultFactory.update(1),
    delete: () => MockQueryResultFactory.delete(1),
    notFound: () => MockQueryResultFactory.empty(),
  };

  /**
   * Mock for garment queries
   */
  static garmentQueries = {
    findById: (id: string) => MockQueryResultFactory.success([
      { 
        id, 
        user_id: 'user-123', 
        file_path: '/test/garment.jpg',
        metadata: { type: 'shirt' },
        created_at: new Date(),
        updated_at: new Date()
      }
    ]),
    findByUserId: (userId: string) => MockQueryResultFactory.success([
      { 
        id: 'garment-1', 
        user_id: userId, 
        file_path: '/test/garment1.jpg',
        metadata: { type: 'shirt' },
        created_at: new Date(),
        updated_at: new Date()
      },
      { 
        id: 'garment-2', 
        user_id: userId, 
        file_path: '/test/garment2.jpg',
        metadata: { type: 'pants' },
        created_at: new Date(),
        updated_at: new Date()
      }
    ]),
    create: (id: string) => MockQueryResultFactory.insert(id),
    updateMetadata: () => MockQueryResultFactory.update(1),
    delete: () => MockQueryResultFactory.delete(1),
    notFound: () => MockQueryResultFactory.empty(),
  };

  /**
   * Mock for image queries
   */
  static imageQueries = {
    findById: (id: string) => MockQueryResultFactory.success([
      { 
        id, 
        user_id: 'user-123', 
        file_path: '/test/image.jpg',
        created_at: new Date()
      }
    ]),
    create: (id: string) => MockQueryResultFactory.insert(id),
    delete: () => MockQueryResultFactory.delete(1),
    notFound: () => MockQueryResultFactory.empty(),
  };
}

// Environment-based mock configurations
export class MockConfigurations {
  /**
   * Development environment mock configuration
   */
  static development() {
    return {
      pool: MockPoolFactory.createSuccessful(),
      enableLogging: true,
      connectionTest: true,
    };
  }

  /**
   * Test environment mock configuration
   */
  static test() {
    return {
      pool: MockPoolFactory.createSuccessful(),
      enableLogging: false,
      connectionTest: false,
    };
  }

  /**
   * Production environment mock configuration
   */
  static production() {
    return {
      pool: MockPoolFactory.createSuccessful(),
      enableLogging: false,
      connectionTest: true,
    };
  }

  /**
   * Error scenario mock configuration
   */
  static errorScenario() {
    return {
      pool: MockPoolFactory.createFailing(),
      enableLogging: true,
      connectionTest: true,
    };
  }
}

// Performance testing utilities
export class PerformanceMocks {
  /**
   * Creates a slow query mock (for timeout testing)
   */
  static slowQuery(delay: number = 5000): Promise<MockQueryResult> {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(MockQueryResultFactory.success([{ id: 1 }]));
      }, delay);
    });
  }

  /**
   * Creates a mock that measures query execution time
   * FIX: Simplified to avoid execution errors
   */
  static timedQuery(result: MockQueryResult, executionTime: number = 100): Promise<MockQueryResult> {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({ ...result }); // Return a clean copy of the result
      }, executionTime);
    });
  }
}

// Utility functions for test setup
export class MockUtils {
  /**
   * Resets all mocks to their initial state - safely handles null/undefined pools
   */
  static resetAllMocks(mockPool: jest.Mocked<Pool> | null | undefined) {
    if (!mockPool || typeof mockPool !== 'object') {
      console.warn('Warning: Attempted to reset null or undefined mock pool');
      return;
    }

    try {
      if (mockPool.query && typeof mockPool.query.mockReset === 'function') {
        mockPool.query.mockReset();
      }
      if (mockPool.connect && typeof mockPool.connect.mockReset === 'function') {
        mockPool.connect.mockReset();
      }
      if (mockPool.end && typeof mockPool.end.mockReset === 'function') {
        mockPool.end.mockReset();
      }
    } catch (error) {
      console.warn('Warning: Error resetting mock pool methods:', error);
    }
  }

  /**
   * Verifies that specific methods were called
   */
  static verifyMethodsCalled(mockPool: jest.Mocked<Pool>, methods: string[]) {
    if (!mockPool || typeof mockPool !== 'object') {
      throw new Error('Cannot verify methods on null or undefined mock pool');
    }

    methods.forEach(method => {
      expect(mockPool[method as keyof Pool]).toHaveBeenCalled();
    });
  }

  /**
   * Verifies query was called with specific parameters
   */
  static verifyQueryCalled(mockPool: jest.Mocked<Pool>, expectedText: string, expectedParams?: any[]) {
    if (!mockPool || typeof mockPool !== 'object') {
      throw new Error('Cannot verify query on null or undefined mock pool');
    }

    expect(mockPool.query).toHaveBeenCalledWith(expectedText, expectedParams);
  }

  /**
   * Sets up console spy for testing logging
   */
  static setupConsoleSpy() {
    return {
      log: jest.spyOn(console, 'log').mockImplementation(() => {}),
      error: jest.spyOn(console, 'error').mockImplementation(() => {}),
      warn: jest.spyOn(console, 'warn').mockImplementation(() => {}),
    };
  }

  /**
   * Restores console methods - safely handles null/undefined spy
   */
  static restoreConsole(consoleSpy: ReturnType<typeof MockUtils.setupConsoleSpy> | null | undefined) {
    if (!consoleSpy || typeof consoleSpy !== 'object') {
      console.warn('Warning: Attempted to restore null or undefined console spy');
      return;
    }

    try {
      if (consoleSpy.log && typeof consoleSpy.log.mockRestore === 'function') {
        consoleSpy.log.mockRestore();
      }
      if (consoleSpy.error && typeof consoleSpy.error.mockRestore === 'function') {
        consoleSpy.error.mockRestore();
      }
      if (consoleSpy.warn && typeof consoleSpy.warn.mockRestore === 'function') {
        consoleSpy.warn.mockRestore();
      }
    } catch (error) {
      console.warn('Warning: Error restoring console methods:', error);
    }
  }
}

export default {
  DatabaseErrors,
  MockQueryResultFactory,
  MockPoolClientFactory,
  MockPoolFactory,
  QueryScenarios,
  MockConfigurations,
  PerformanceMocks,
  MockUtils,
};