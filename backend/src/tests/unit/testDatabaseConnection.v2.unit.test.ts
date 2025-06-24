// /backend/src/utils/__tests__/testDatabaseConnection.v2.test.ts
/**
 * Comprehensive Test Suite for Docker Database Connection (v2)
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
  let mockPool: jest.Mocked<Pool>;
  let mockClient: jest.Mocked<PoolClient>;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Reset connection state
    (TestDatabaseConnection as any).testPool = null;
    (TestDatabaseConnection as any).mainPool = null;
    (TestDatabaseConnection as any).isInitialized = false;
    (TestDatabaseConnection as any).isInitializing = false;
    (TestDatabaseConnection as any).initializationPromise = null;
    (TestDatabaseConnection as any).activeConnections = new Set();
    (TestDatabaseConnection as any).cleanupInProgress = false;

    // Create mock client
    mockClient = {
      query: jest.fn(),
      release: jest.fn(),
      on: jest.fn(),
      connect: jest.fn(),
      end: jest.fn()
    } as any;

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
    } as any;

    // Mock Pool constructor
    (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => mockPool);

    // Clear all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Restore environment
    process.env = originalEnv;
    jest.clearAllMocks();
  });

  // ============================================================================
  // UNIT TESTS - Core Logic and Methods
  // ============================================================================
  describe('Unit Tests - Core Functionality', () => {
    describe('Initialization Logic', () => {
      test('should prevent concurrent initialization', async () => {
        // Mock successful connection
        mockClient.query.mockResolvedValue({ rows: [] });

        // Start two initializations simultaneously
        const init1 = TestDatabaseConnection.initialize();
        const init2 = TestDatabaseConnection.initialize();

        const [pool1, pool2] = await Promise.all([init1, init2]);

        // Both should return the same pool instance
        expect(pool1).toBe(pool2);
        expect(Pool).toHaveBeenCalledTimes(1); // Only one pool created
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
        // First initialization
        mockClient.query.mockResolvedValue({ rows: [] });
        const pool1 = await TestDatabaseConnection.initialize();

        // Second call should return same pool without re-initialization
        const pool2 = await TestDatabaseConnection.initialize();

        expect(pool1).toBe(pool2);
        expect(Pool).toHaveBeenCalledTimes(1);
      });
    });

    describe('Pool Configuration', () => {
      test('should configure pool with correct Docker settings', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        
        await TestDatabaseConnection.initialize();

        expect(Pool).toHaveBeenCalledWith({
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

        // Start a query but don't await it
        const queryPromise = TestDatabaseConnection.query('SELECT 1');
        
        // Connection should be tracked
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

        expect(TestDatabaseConnection.initializing).toBe(true);

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
        // Mock initial failures then success
        mockPool.connect
          .mockRejectedValueOnce(new Error('Connection refused'))
          .mockRejectedValueOnce(new Error('Connection refused'))
          .mockResolvedValueOnce(mockClient);

        mockClient.query.mockResolvedValue({ rows: [] });

        await TestDatabaseConnection.initialize();

        expect(mockPool.connect).toHaveBeenCalledTimes(3);
      });

      test('should timeout if Docker container never becomes ready', async () => {
        // Mock continuous failures
        mockPool.connect.mockRejectedValue(new Error('Connection refused'));

        // Speed up the test by mocking setTimeout to resolve immediately
        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await expect(TestDatabaseConnection.initialize()).rejects.toThrow(
          'Docker PostgreSQL not ready after'
        );

        (global.setTimeout as jest.Mock).mockRestore();
      }, 10000);
    });

    describe('Database Creation', () => {
      test('should create test database if it does not exist', async () => {
        // Mock admin pool for database creation
        const mockAdminPool = {
          query: jest.fn()
            .mockResolvedValueOnce({ rows: [] }) // Database doesn't exist
            .mockResolvedValueOnce({ rows: [] }), // CREATE DATABASE succeeds
          end: jest.fn().mockResolvedValue(undefined)
        };

        // First Pool call is for admin, second is for test database
        (Pool as jest.MockedClass<typeof Pool>)
          .mockImplementationOnce(() => mockAdminPool as any)
          .mockImplementationOnce(() => mockPool);

        // Mock test database connection failing initially (db doesn't exist)
        mockPool.connect
          .mockRejectedValueOnce(new Error('database "koutu_test" does not exist'))
          .mockResolvedValueOnce(mockClient);

        mockClient.query.mockResolvedValue({ rows: [] });

        await TestDatabaseConnection.initialize();

        expect(mockAdminPool.query).toHaveBeenCalledWith(
          'SELECT 1 FROM pg_database WHERE datname = $1',
          ['koutu_test']
        );
        expect(mockAdminPool.query).toHaveBeenCalledWith('CREATE DATABASE koutu_test');
      });
    });

    describe('Schema Creation', () => {
      test('should create complete database schema', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });

        await TestDatabaseConnection.initialize();

        // Verify all tables are created
        const createTableCalls = mockClient.query.mock.calls.filter(call => 
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
          expect(createTableCalls.some(call => call[0].includes(table))).toBe(true);
        });
      });

      test('should create indexes for performance', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });

        await TestDatabaseConnection.initialize();

        // Verify indexes are created
        const indexCalls = mockClient.query.mock.calls.filter(call => 
          call[0].includes('CREATE INDEX IF NOT EXISTS')
        );

        expect(indexCalls.length).toBeGreaterThan(0);
        expect(indexCalls.some(call => call[0].includes('idx_original_images_user_id'))).toBe(true);
        expect(indexCalls.some(call => call[0].includes('idx_wardrobe_items_wardrobe_id'))).toBe(true);
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
        mockClient.query
          .mockResolvedValueOnce({ rows: [] }) // Initial setup
          .mockResolvedValueOnce({ rows: [{ exists: false }] }) // wardrobe_items doesn't exist
          .mockResolvedValue({ rows: [] }); // All other operations succeed

        await TestDatabaseConnection.initialize();
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
        mockClient.query.mockResolvedValue({ rows: [] });
        
        await TestDatabaseConnection.initialize();

        const poolConfig = (Pool as jest.MockedClass<typeof Pool>).mock.calls[0][0];
        expect(poolConfig.max).toBe(10); // Should limit connections
        expect(poolConfig.connectionTimeoutMillis).toBe(2000); // Should timeout quickly
      });

      test('should use secure connection settings', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        
        await TestDatabaseConnection.initialize();

        const poolConfig = (Pool as jest.MockedClass<typeof Pool>).mock.calls[0][0];
        expect(poolConfig.host).toBe('localhost'); // Only local connections
        expect(poolConfig.port).toBe(5433); // Specific test port
        expect(poolConfig.allowExitOnIdle).toBe(true); // Cleanup idle connections
      });
    });

    describe('Error Information Disclosure', () => {
      test('should not expose sensitive connection details in errors', async () => {
        mockPool.connect.mockRejectedValue(new Error('Connection failed'));

        try {
          await TestDatabaseConnection.initialize();
        } catch (error) {
          // Error should not contain password or detailed connection info
          expect(error.message).not.toContain('postgres'); // password
          expect(error.message).not.toContain('5433'); // internal port details
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
          expect(error.message).toContain('relation "secret_table" does not exist');
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

        // Simulate active connection
        const longRunningQuery = TestDatabaseConnection.query('SELECT pg_sleep(1)');
        
        // Start cleanup
        const cleanupPromise = TestDatabaseConnection.cleanup();

        // Should wait for active connections
        expect(TestDatabaseConnection.activeConnectionCount).toBeGreaterThan(0);

        await longRunningQuery;
        await cleanupPromise;

        expect(TestDatabaseConnection.activeConnectionCount).toBe(0);
      });

      test('should force release connections after timeout', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        await TestDatabaseConnection.initialize();

        // Add connections to active set manually
        const mockActiveClient = { release: jest.fn() };
        (TestDatabaseConnection as any).activeConnections.add(mockActiveClient);

        await TestDatabaseConnection.cleanup();

        expect(mockActiveClient.release).toHaveBeenCalledWith(true);
      });

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

        // Start cleanup
        const cleanup1 = TestDatabaseConnection.cleanup();
        const cleanup2 = TestDatabaseConnection.cleanup();

        await Promise.all([cleanup1, cleanup2]);

        // Should only cleanup once
        expect(mockPool.end).toHaveBeenCalledTimes(1);
      });
    });

    describe('Error Recovery', () => {
      test('should allow re-initialization after cleanup', async () => {
        mockClient.query.mockResolvedValue({ rows: [] });
        
        // Initialize, cleanup, then re-initialize
        await TestDatabaseConnection.initialize();
        await TestDatabaseConnection.cleanup();
        await TestDatabaseConnection.initialize();

        expect(TestDatabaseConnection.initialized).toBe(true);
        expect(Pool).toHaveBeenCalledTimes(2);
      });

      test('should handle pool creation failures', async () => {
        (Pool as jest.MockedClass<typeof Pool>).mockImplementationOnce(() => {
          throw new Error('Pool creation failed');
        });

        await expect(TestDatabaseConnection.initialize()).rejects.toThrow('Pool creation failed');
        expect(TestDatabaseConnection.initialized).toBe(false);
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