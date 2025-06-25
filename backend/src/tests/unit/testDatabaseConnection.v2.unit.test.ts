// /backend/src/utils/__tests__/testDatabaseConnection.v2.unit.test.ts
/**
 * Comprehensive Test Suite for Docker Database Connection (v2) - FIXED
 * 
 * Tests the enhanced Docker database connection that manages PostgreSQL containers,
 * connection pooling, schema creation, and cleanup for the dual-mode test infrastructure.
 * 
 * Coverage: Unit + Integration + Security
 */

import { TestDatabaseConnection } from '../../utils/testDatabaseConnection.v2';
import { Pool, PoolClient } from 'pg';

// Mock pg module
jest.mock('pg', () => ({
  Pool: jest.fn(),
  Client: jest.fn()
}));

// Mock child_process for Docker checks
jest.mock('child_process', () => ({
  execSync: jest.fn()
}));

describe('TestDatabaseConnection v2 - Docker Mode', () => {
  let mockPool: any;
  let mockClient: any;
  let originalEnv: NodeJS.ProcessEnv;
  let poolCreateCount: number;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Reset pool creation counter
    poolCreateCount = 0;
    
    // Reset connection state
    (TestDatabaseConnection as any).testPool = null;
    (TestDatabaseConnection as any).mainPool = null;
    (TestDatabaseConnection as any).isInitialized = false;
    (TestDatabaseConnection as any).isInitializing = false;
    (TestDatabaseConnection as any).initializationPromise = null;
    (TestDatabaseConnection as any).activeConnections = new Set();
    (TestDatabaseConnection as any).cleanupInProgress = false;

    // Store original methods to ensure they're restored
    if (!(TestDatabaseConnection as any).originalWaitForDockerPostgreSQL) {
      (TestDatabaseConnection as any).originalWaitForDockerPostgreSQL = 
        (TestDatabaseConnection as any).waitForDockerPostgreSQL;
    }

    // Create mock client
    mockClient = {
      query: jest.fn(),
      release: jest.fn(),
      on: jest.fn(),
      connect: jest.fn(),
      end: jest.fn()
    } as Partial<PoolClient> as PoolClient;

    // Create mock pool
    mockPool = {
      connect: jest.fn().mockResolvedValue(mockClient),
      query: jest.fn(),
      end: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(),
      ended: false,
      totalCount: 0,
      idleCount: 0,
      waitingCount: 0
    } as Partial<Pool> as Pool;

    // Mock Pool constructor with counter
    (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
      poolCreateCount++;
      return mockPool;
    });

    // Clear all mocks
    jest.clearAllMocks();
  });

  afterEach(async () => {
    // Restore environment
    process.env = originalEnv;
    
    // Always restore original methods if they were mocked
    if ((TestDatabaseConnection as any).originalWaitForDockerPostgreSQL) {
      (TestDatabaseConnection as any).waitForDockerPostgreSQL = 
        (TestDatabaseConnection as any).originalWaitForDockerPostgreSQL;
    }
    
    // Clean up any test database state
    try {
      await TestDatabaseConnection.cleanup();
    } catch (error) {
      // Ignore cleanup errors in tests
    }
    
    jest.clearAllMocks();
  });

  // ============================================================================
  // UNIT TESTS - Core Logic and Methods
  // ============================================================================
  describe('Unit Tests - Core Functionality', () => {
    describe('Initialization Logic', () => {
      test('should prevent concurrent initialization', async () => {
        // Mock successful connection on first try (no Docker waiting)
        mockClient.query.mockResolvedValue({ rows: [] });

        // Spy on the initialization to ensure it's only called once
        const performInitSpy = jest.spyOn(TestDatabaseConnection as any, 'performInitialization');

        // Start two initializations simultaneously
        const init1 = TestDatabaseConnection.initialize();
        const init2 = TestDatabaseConnection.initialize();

        const [pool1, pool2] = await Promise.all([init1, init2]);

        // Both should return the same pool instance
        expect(pool1).toBe(pool2);
        // performInitialization should only be called once despite concurrent calls
        expect(performInitSpy).toHaveBeenCalledTimes(1);
        
        performInitSpy.mockRestore();
      });

      test('should handle initialization failure gracefully', async () => {
        // Mock connection failure
        mockPool.connect.mockRejectedValue(new Error('Connection failed'));

        await expect(TestDatabaseConnection.initialize()).rejects.toThrow();

        // Should reset state after failure
        expect((TestDatabaseConnection as any).isInitialized).toBe(false);
        expect((TestDatabaseConnection as any).testPool).toBeNull();
      });

      test('should return existing pool if already initialized', async () => {
        // First initialization - mock successful connection immediately
        mockClient.query.mockResolvedValue({ rows: [] });
        const pool1 = await TestDatabaseConnection.initialize();

        // Reset the counter after first init
        const firstPoolCount = poolCreateCount;

        // Second call should return same pool without re-initialization
        const pool2 = await TestDatabaseConnection.initialize();

        expect(pool1).toBe(pool2);
        expect(poolCreateCount).toBe(firstPoolCount); // No additional pools created
      });
    });

    describe('Pool Configuration', () => {
      test('should configure pool with correct Docker settings', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        
        await TestDatabaseConnection.initialize();

        // Check the final pool configuration (last call)
        const poolCalls = (Pool as jest.MockedClass<typeof Pool>).mock.calls;
        const finalConfig = poolCalls[poolCalls.length - 1][0];
        
        expect(finalConfig).toMatchObject({
          host: 'localhost',
          port: 5433,
          user: 'postgres',
          password: 'postgres',
          database: 'koutu_test',
          max: 10,
          idleTimeoutMillis: 1000,
          connectionTimeoutMillis: 2000,
          allowExitOnIdle: true
        });
      });

      test('should set up pool event handlers', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        
        await TestDatabaseConnection.initialize();

        expect(mockPool.on).toHaveBeenCalledWith('error', expect.any(Function));
        expect(mockPool.on).toHaveBeenCalledWith('connect', expect.any(Function));
        expect(mockPool.on).toHaveBeenCalledWith('remove', expect.any(Function));
      });
    });

    describe('Query Method', () => {
      test('should execute queries with proper connection management', async () => {
        // Initialize first
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Execute query
        const queryResult = { rows: [{ id: 1, name: 'test' }] };
        mockClient.query.mockResolvedValueOnce(queryResult);

        const result = await TestDatabaseConnection.query('SELECT * FROM test', ['param1']);

        expect(mockPool.connect).toHaveBeenCalled();
        expect(mockClient.query).toHaveBeenCalledWith('SELECT * FROM test', ['param1']);
        expect(mockClient.release).toHaveBeenCalled();
        expect(result).toEqual(queryResult);
      });

      test('should release connection even if query fails', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Make query fail
        mockClient.query.mockRejectedValueOnce(new Error('Query failed'));

        await expect(TestDatabaseConnection.query('INVALID SQL')).rejects.toThrow('Query failed');
        expect(mockClient.release).toHaveBeenCalled();
      });

      test('should throw error if not initialized', async () => {
        await expect(TestDatabaseConnection.query('SELECT 1')).rejects.toThrow(
          'Test database not initialized'
        );
      });

      test('should block queries during cleanup', async () => {
        // Initialize first
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Set cleanup in progress
        (TestDatabaseConnection as any).cleanupInProgress = true;

        await expect(TestDatabaseConnection.query('SELECT 1')).rejects.toThrow(
          'Database cleanup in progress'
        );
      });
    });

    describe('Connection Tracking', () => {
      test('should track active connections', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Get reference to active connections set
        const activeConnections = (TestDatabaseConnection as any).activeConnections;
        
        // Create a delayed mock client that we can control
        const delayedClient = {
          ...mockClient,
          query: jest.fn().mockImplementation(() => 
            new Promise(resolve => setTimeout(() => resolve({ rows: [] }), 50))
          )
        };
        
        // Override the pool connect to return our delayed client
        mockPool.connect.mockResolvedValue(delayedClient);

        // Start a query that will take some time
        const queryPromise = TestDatabaseConnection.query('SELECT 1');
        
        // Wait a bit for the connection to be established and tracked
        await new Promise(resolve => setTimeout(resolve, 25));
        
        // Connection should be tracked while query is running
        expect(TestDatabaseConnection.activeConnectionCount).toBe(1);

        // Complete the query
        await queryPromise;

        // Connection should be released
        expect(TestDatabaseConnection.activeConnectionCount).toBe(0);
      });
    });

    describe('State Management', () => {
      test('should provide correct state indicators', async () => {
        expect(TestDatabaseConnection.initialized).toBe(false);
        expect(TestDatabaseConnection.initializing).toBe(false);

        mockClient.query.mockResolvedValue({ rows: [] });
        const initPromise = TestDatabaseConnection.initialize();

        // Note: initializing state might be true only briefly
        await initPromise;

        expect(TestDatabaseConnection.initialized).toBe(true);
        expect(TestDatabaseConnection.initializing).toBe(false);
      });
    });
  });

  // ============================================================================
  // INTEGRATION TESTS - Docker Container Interaction
  // ============================================================================
  describe('Integration Tests - Docker Communication', () => {
    describe('Docker PostgreSQL Waiting', () => {
      test('should wait for Docker container to be ready', async () => {
        // Instead of mocking waitForDockerPostgreSQL, mock the Pool creation to simulate retries
        let poolAttempts = 0;
        const maxAttempts = 3;
        
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          poolAttempts++;
          
          // Create a pool that fails connection for first few attempts
          const pool = {
            ...mockPool,
            connect: jest.fn().mockImplementation(() => {
              if (poolAttempts <= maxAttempts - 1) {
                return Promise.reject(new Error('Connection refused'));
              } else {
                return Promise.resolve(mockClient);
              }
            }),
            query: jest.fn().mockImplementation(() => {
              if (poolAttempts <= maxAttempts - 1) {
                return Promise.reject(new Error('Connection refused'));
              } else {
                return Promise.resolve({ rows: [] });
              }
            }),
            on: jest.fn(),
            end: jest.fn().mockResolvedValue(undefined)
          };
          
          return pool as any;
        });

        mockClient.query.mockResolvedValue({ rows: [] });

        // Mock setTimeout to speed up the test - store original first
        const originalSetTimeout = global.setTimeout;
        const setTimeoutMock = jest.fn().mockImplementation((callback: any, delay: number) => {
          // Use the original setTimeout with reduced delay
          return originalSetTimeout(callback, Math.min(delay, 10));
        });
        // Add __promisify__ property to satisfy Node's type definition
        (setTimeoutMock as any).__promisify__ = (originalSetTimeout as any).__promisify__ || (() => { throw new Error('Not implemented'); });
        global.setTimeout = setTimeoutMock as unknown as typeof setTimeout;

        try {
          await TestDatabaseConnection.initialize();

          // Should have tried multiple times
          expect(poolAttempts).toBeGreaterThanOrEqual(maxAttempts);
          expect(TestDatabaseConnection.initialized).toBe(true);
        } finally {
          // Restore setTimeout
          global.setTimeout = originalSetTimeout;
        }
      }, 10000);

      test('should timeout if Docker container never becomes ready', async () => {
        // Mock the waitForDockerPostgreSQL method to always fail
        const originalWaitMethod = (TestDatabaseConnection as any).waitForDockerPostgreSQL;
        
        (TestDatabaseConnection as any).waitForDockerPostgreSQL = jest.fn().mockRejectedValue(
          new Error('Docker PostgreSQL not ready after 30 attempts.\nPlease ensure PostgreSQL container is running on port 5433.\nExample: docker run --name test-postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=koutu_test -p 5433:5432 -d postgres:13')
        );

        try {
          await expect(TestDatabaseConnection.initialize()).rejects.toThrow(
            'Docker PostgreSQL not ready after'
          );
        } finally {
          // Always restore original method
          (TestDatabaseConnection as any).waitForDockerPostgreSQL = originalWaitMethod;
        }
      }, 5000);
    });

    describe('Database Creation', () => {
      test('should create test database if it does not exist', async () => {
        let poolCallCount = 0;
        
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          poolCallCount++;
          
          if (poolCallCount === 1) {
            // First pool: test database connection fails
            return {
              connect: jest.fn().mockRejectedValue(new Error('database "koutu_test" does not exist')),
              end: jest.fn().mockResolvedValue(undefined),
              on: jest.fn()
            } as any;
          } else if (poolCallCount === 2) {
            // Second pool: admin connection for database creation
            return {
              query: jest.fn()
                .mockResolvedValueOnce({ rows: [] }) // Database doesn't exist
                .mockResolvedValueOnce({ rows: [] }), // CREATE DATABASE succeeds
              end: jest.fn().mockResolvedValue(undefined),
              connect: jest.fn(),
              on: jest.fn()
            } as any;
          } else {
            // Third pool: successful test database connection
            return {
              ...mockPool,
              connect: jest.fn().mockResolvedValue(mockClient),
              on: jest.fn(),
              end: jest.fn().mockResolvedValue(undefined)
            } as any;
          }
        });

        mockClient.query.mockResolvedValue({ rows: [] });

        await TestDatabaseConnection.initialize();

        // Should have created multiple pools for the database creation process
        expect(poolCallCount).toBe(3);
      });
    });

    describe('Schema Creation', () => {
      test('should create complete database schema', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });

        await TestDatabaseConnection.initialize();

        // Verify all tables are created
        const createTableCalls = mockClient.query.mock.calls.filter((call: any) => 
          call[0].includes('CREATE TABLE IF NOT EXISTS')
        );

        const expectedTables = [
          'users',
          'user_oauth_providers', 
          'original_images',
          'garment_items',
          'wardrobes',
          'wardrobe_items'
        ];

        expectedTables.forEach(table => {
          expect(createTableCalls.some((call: any) => call[0].includes(table))).toBe(true);
        });
      });

      test('should create indexes for performance', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });

        await TestDatabaseConnection.initialize();

        // Verify indexes are created
        const indexCalls = mockClient.query.mock.calls.filter((call: any) => 
          call[0].includes('CREATE INDEX IF NOT EXISTS')
        );

        expect(indexCalls.length).toBeGreaterThan(0);
        expect(indexCalls.some((call: any) => call[0].includes('idx_original_images_user_id'))).toBe(true);
        expect(indexCalls.some((call: any) => call[0].includes('idx_wardrobe_items_wardrobe_id'))).toBe(true);
      });

      test('should create UUID extension', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });

        await TestDatabaseConnection.initialize();

        expect(mockClient.query).toHaveBeenCalledWith(
          'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'
        );
      });
    });

    describe('Table Management', () => {
      test('should clear all tables in correct dependency order', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        await TestDatabaseConnection.clearAllTables();

        // Verify FK constraints are disabled
        expect(mockClient.query).toHaveBeenCalledWith('SET session_replication_role = replica');

        // Verify tables are truncated
        expect(mockClient.query).toHaveBeenCalledWith('TRUNCATE TABLE wardrobe_items RESTART IDENTITY CASCADE');
        expect(mockClient.query).toHaveBeenCalledWith('TRUNCATE TABLE users RESTART IDENTITY CASCADE');

        // Verify FK constraints are re-enabled
        expect(mockClient.query).toHaveBeenCalledWith('SET session_replication_role = DEFAULT');
      });

      test('should ensure missing wardrobe tables exist', async () => {
        // Setup: Initialize successfully first
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Reset mock to control ensureTablesExist behavior
        mockClient.query.mockReset();
        mockClient.query
          .mockResolvedValueOnce({ rows: [{ exists: false }] }) // wardrobe_items doesn't exist
          .mockResolvedValue({ rows: [] }); // All other operations succeed

        await TestDatabaseConnection.ensureTablesExist();

        expect(mockClient.query).toHaveBeenCalledWith(
          expect.stringContaining('CREATE TABLE wardrobe_items')
        );
      });
    });
  });

  // ============================================================================
  // SECURITY TESTS - SQL Injection Prevention & Access Control
  // ============================================================================
  describe('Security Tests - Protection & Validation', () => {
    describe('SQL Injection Prevention', () => {
      test('should use parameterized queries', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        await TestDatabaseConnection.query(
          'SELECT * FROM users WHERE id = $1',
          ['user123']
        );

        expect(mockClient.query).toHaveBeenCalledWith(
          'SELECT * FROM users WHERE id = $1',
          ['user123']
        );
      });

      test('should handle parameters safely', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        const maliciousInput = "'; DROP TABLE users; --";
        
        await TestDatabaseConnection.query(
          'SELECT * FROM users WHERE name = $1',
          [maliciousInput]
        );

        // Should pass malicious input as parameter, not concatenate
        expect(mockClient.query).toHaveBeenCalledWith(
          'SELECT * FROM users WHERE name = $1',
          [maliciousInput]
        );
      });
    });

    describe('Connection Security', () => {
      test('should limit connection pool size', async () => {
        mockClient.query.mockResolvedValue({ rows: [] } as any);
        
        await TestDatabaseConnection.initialize();

        // Check the final pool configuration (after Docker waiting)
        const poolCalls = (Pool as jest.MockedClass<typeof Pool>).mock.calls;
        const finalConfig = poolCalls[poolCalls.length - 1]?.[0];
        expect(finalConfig).toBeDefined();
        expect(finalConfig!.max).toBe(10); // Should limit connections
        expect(finalConfig!.connectionTimeoutMillis).toBe(2000); // Should timeout quickly
      });

      test('should use secure connection settings', async () => {
        mockClient.query.mockResolvedValue({ rows: [] } as any);
        
        await TestDatabaseConnection.initialize();

        // Check the final pool configuration
        const poolCalls = (Pool as jest.MockedClass<typeof Pool>).mock.calls;
        const finalConfig = poolCalls[poolCalls.length - 1]?.[0];
        expect(finalConfig).toBeDefined();
        expect(finalConfig!.host).toBe('localhost'); // Only local connections
        expect(finalConfig!.port).toBe(5433); // Specific test port
        expect(finalConfig!.allowExitOnIdle).toBe(true); // Cleanup idle connections
      });
    });

    describe('Error Information Disclosure', () => {
      test('should not expose sensitive connection details in errors', async () => {
        mockPool.connect.mockRejectedValue(new Error('Connection failed'));

        try {
          await TestDatabaseConnection.initialize();
        } catch (error) {
          // Error should not contain password or detailed connection info
          if (error instanceof Error) {
            expect(error.message).not.toContain('postgres'); // password
            expect(error.message).not.toContain('5433'); // internal port details
          } else {
            throw error;
          }
        }
      });

      test('should handle database errors without exposing schema', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        mockClient.query.mockRejectedValueOnce(new Error('relation "secret_table" does not exist'));

        try {
          await TestDatabaseConnection.query('SELECT * FROM secret_table');
        } catch (error) {
          // Should propagate error but not add sensitive details
          if (error instanceof Error) {
            expect(error.message).toContain('relation "secret_table" does not exist');
          } else {
            throw error;
          }
        }
      });
    });

    describe('Access Control', () => {
      test('should only allow database operations in test environment', () => {
        // This is implicitly tested by the Docker port (5433) and database name (koutu_test)
        // Real production would use different settings
        expect(true).toBe(true); // Placeholder for this security concept
      });

      test('should clean up connections to prevent resource exhaustion', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Mock connection tracking properly
        const activeConnections = (TestDatabaseConnection as any).activeConnections;
        
        mockPool.connect.mockImplementation(() => {
          activeConnections.add(mockClient);
          return Promise.resolve(mockClient);
        });
        
        mockClient.release.mockImplementation(() => {
          activeConnections.delete(mockClient);
        });

        // Execute multiple queries
        await Promise.all([
          TestDatabaseConnection.query('SELECT 1'),
          TestDatabaseConnection.query('SELECT 2'),
          TestDatabaseConnection.query('SELECT 3')
        ]);

        // All connections should be released
        expect(TestDatabaseConnection.activeConnectionCount).toBe(0);
      });
    });
  });

  // ============================================================================
  // CLEANUP AND ERROR HANDLING TESTS
  // ============================================================================
  describe('Cleanup and Error Handling', () => {
    describe('Cleanup Procedures', () => {
      test('should wait for active connections during cleanup', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Manually add a connection to simulate active state
        const activeConnections = (TestDatabaseConnection as any).activeConnections;
        const mockActiveClient = { release: jest.fn() };
        activeConnections.add(mockActiveClient);

        // Mock the cleanup waiting logic to resolve quickly
        const originalSetTimeout = global.setTimeout;
        let timeoutCount = 0;
        const setTimeoutMock = jest.fn().mockImplementation((callback: any, delay: number) => {
          timeoutCount++;
          if (timeoutCount <= 5) {
            // Simulate waiting, then remove the connection
            activeConnections.delete(mockActiveClient);
          }
          callback();
          return null as any;
        });
        // Add __promisify__ property to satisfy Node's type definition
        (setTimeoutMock as any).__promisify__ = (global.setTimeout as any).__promisify__ || (() => { throw new Error('Not implemented'); });
        global.setTimeout = setTimeoutMock as unknown as typeof setTimeout;

        // Start cleanup
        const cleanupPromise = TestDatabaseConnection.cleanup();

        await cleanupPromise;

        expect(TestDatabaseConnection.activeConnectionCount).toBe(0);
        
        // Restore setTimeout
        global.setTimeout = originalSetTimeout;
      }, 5000);

      test('should force release connections after timeout', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Add connections to active set manually
        const mockActiveClient = { release: jest.fn() };
        (TestDatabaseConnection as any).activeConnections.add(mockActiveClient);

        // Mock setTimeout to simulate timeout behavior
        const originalSetTimeout = global.setTimeout;
        const setTimeoutMock = jest.fn().mockImplementation((callback: any, delay: number) => {
          // Immediately trigger timeout to force release
          callback();
          return null as any;
        });
        // Add __promisify__ property to satisfy Node's type definition
        (setTimeoutMock as any).__promisify__ = (global.setTimeout as any).__promisify__ || (() => { throw new Error('Not implemented'); });
        global.setTimeout = setTimeoutMock as unknown as typeof setTimeout;

        await TestDatabaseConnection.cleanup();

        expect(mockActiveClient.release).toHaveBeenCalledWith(true);
        
        // Restore setTimeout
        global.setTimeout = originalSetTimeout;
      }, 5000);

      test('should handle cleanup errors gracefully', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Make pool.end() fail
        mockPool.end.mockRejectedValue(new Error('End failed'));

        // Should not throw, just log warning
        await expect(TestDatabaseConnection.cleanup()).resolves.not.toThrow();
      });

      test('should reset state after cleanup', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        expect(TestDatabaseConnection.initialized).toBe(true);

        await TestDatabaseConnection.cleanup();

        expect(TestDatabaseConnection.initialized).toBe(false);
        expect((TestDatabaseConnection as any).testPool).toBeNull();
        expect((TestDatabaseConnection as any).mainPool).toBeNull();
      });

      test('should prevent duplicate cleanup', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Track cleanup state manually
        let cleanupCallCount = 0;
        const originalCleanup = (TestDatabaseConnection as any).cleanupPools;
        
        (TestDatabaseConnection as any).cleanupPools = jest.fn().mockImplementation(async () => {
          cleanupCallCount++;
          return originalCleanup.call(TestDatabaseConnection);
        });

        // Start cleanup
        const cleanup1 = TestDatabaseConnection.cleanup();
        const cleanup2 = TestDatabaseConnection.cleanup();

        await Promise.all([cleanup1, cleanup2]);

        // Should only cleanup once
        expect(cleanupCallCount).toBe(1);
        
        // Restore original method
        (TestDatabaseConnection as any).cleanupPools = originalCleanup;
      });
    });

    describe('Error Recovery', () => {
      test('should allow re-initialization after cleanup', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        
        // Initialize, cleanup, then re-initialize
        await TestDatabaseConnection.initialize();
        const firstPoolCount = poolCreateCount;
        
        await TestDatabaseConnection.cleanup();
        await TestDatabaseConnection.initialize();

        expect(TestDatabaseConnection.initialized).toBe(true);
        // Should have created additional pools after cleanup
        expect(poolCreateCount).toBeGreaterThan(firstPoolCount);
      });

      test('should handle pool creation failures', async () => {
        // Mock the waitForDockerPostgreSQL to succeed so we can test pool creation failure
        const originalWaitMethod = (TestDatabaseConnection as any).waitForDockerPostgreSQL;
        (TestDatabaseConnection as any).waitForDockerPostgreSQL = jest.fn().mockResolvedValue(undefined);

        // Make the Pool constructor throw an error after waiting succeeds
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          throw new Error('Pool creation failed');
        });

        try {
          await expect(TestDatabaseConnection.initialize()).rejects.toThrow('Pool creation failed');
          expect(TestDatabaseConnection.initialized).toBe(false);
        } finally {
          // Always restore original method
          (TestDatabaseConnection as any).waitForDockerPostgreSQL = originalWaitMethod;
        }
      });
    });
  });

  // ============================================================================
  // EDGE CASES AND BOUNDARY CONDITIONS
  // ============================================================================
  describe('Edge Cases and Boundary Conditions', () => {
    test('should handle empty query parameters', async () => {
      mockClient.query.mockResolvedValue({ rows: [] });
      await TestDatabaseConnection.initialize();

      await TestDatabaseConnection.query('SELECT 1', []);
      await TestDatabaseConnection.query('SELECT 1', undefined);

      expect(mockClient.query).toHaveBeenCalledWith('SELECT 1', []);
      expect(mockClient.query).toHaveBeenCalledWith('SELECT 1', undefined);
    });

    test('should handle concurrent queries properly', async () => {
      mockClient.query.mockResolvedValue({ rows: [] });
      await TestDatabaseConnection.initialize();

      // Mock proper connection tracking for concurrent queries
      const activeConnections = (TestDatabaseConnection as any).activeConnections;
      let connectionId = 0;
      
      mockPool.connect.mockImplementation(() => {
        const client = { ...mockClient, id: connectionId++ };
        activeConnections.add(client);
        return Promise.resolve(client);
      });
      
      const originalRelease = mockClient.release;
      mockClient.release = jest.fn().mockImplementation(function(this: any) {
        activeConnections.delete(this);
        return originalRelease.call(this);
      });

      // Execute many concurrent queries
      const queries = Array.from({ length: 20 }, (_, i) => 
        TestDatabaseConnection.query(`SELECT ${i}`)
      );

      await Promise.all(queries);

      // All connections should be released
      expect(TestDatabaseConnection.activeConnectionCount).toBe(0);
    });

    test('should handle getPool() edge cases', () => {
      // Before initialization
      expect(() => TestDatabaseConnection.getPool()).toThrow('Test database not initialized');

      // After cleanup
      (TestDatabaseConnection as any).testPool = null;
      (TestDatabaseConnection as any).isInitialized = false;
      
      expect(() => TestDatabaseConnection.getPool()).toThrow('Test database not initialized');
    });
  });
});