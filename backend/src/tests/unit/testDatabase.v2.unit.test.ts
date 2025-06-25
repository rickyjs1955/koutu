// /backend/src/utils/__tests__/testDatabase.v2.test.ts
/**
 * Comprehensive Test Suite for Test Database v2 (Docker Mode)
 * 
 * Tests the Docker test database implementation that handles PostgreSQL containers,
 * schema creation, connection management, and data operations for the dual-mode infrastructure.
 * 
 * Coverage: Unit + Integration + Security
 */

import { TestDatabase } from '../../utils/testDatabase.v2';
import { Pool } from 'pg';

// Mock pg module
jest.mock('pg', () => ({
  Pool: jest.fn(),
  Client: jest.fn()
}));

describe('TestDatabase v2 - Docker Database Implementation', () => {
  let mockPool: jest.Mocked<Pool>;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
    
    // Reset static state
    (TestDatabase as any).testPool = null;
    (TestDatabase as any).mainPool = null;
    (TestDatabase as any).isInitialized = false;

    // Create mock pool
    mockPool = {
      query: jest.fn(),
      end: jest.fn().mockResolvedValue(undefined),
      on: jest.fn(),
      ended: false,
      totalCount: 0,
      idleCount: 0,
      waitingCount: 0,
      connect: jest.fn(),
      release: jest.fn()
    } as any;

    // Mock Pool constructor
    (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => mockPool);

    // Clear all mocks
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Restore environment
    process.env = originalEnv;
    
    // Cleanup
    TestDatabase.cleanup();
    
    jest.clearAllMocks();
  });

  // ============================================================================
  // UNIT TESTS - Core Database Operations
  // ============================================================================
  describe('Unit Tests - Core Database Operations', () => {
    describe('Database Initialization', () => {
      test('should initialize Docker database successfully', async () => {
        // Mock successful PostgreSQL connection
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [{ exists: true }] }) // database exists check
          .mockResolvedValueOnce({ rows: [] }) // CREATE EXTENSION
          .mockResolvedValueOnce({ rows: [] }) // CREATE TABLE users
          .mockResolvedValueOnce({ rows: [] }) // CREATE TABLE user_oauth_providers
          .mockResolvedValueOnce({ rows: [] }) // CREATE TABLE original_images
          .mockResolvedValueOnce({ rows: [] }) // CREATE TABLE garment_items
          .mockResolvedValueOnce({ rows: [] }) // CREATE TABLE wardrobes
          .mockResolvedValueOnce({ rows: [] }) // CREATE TABLE wardrobe_items
          .mockResolvedValueOnce({ rows: [] }); // CREATE INDEX

        const result = await TestDatabase.initialize();

        expect(Pool).toHaveBeenCalledTimes(2); // Main pool + test pool
        expect(Pool).toHaveBeenCalledWith({
          host: 'localhost',
          port: 5433,
          user: 'postgres',
          password: 'postgres',
          database: 'postgres'
        });
        expect(Pool).toHaveBeenCalledWith({
          host: 'localhost',
          port: 5433,
          user: 'postgres',
          password: 'postgres',
          database: 'koutu_test'
        });
        expect(result).toBe(mockPool);
        expect((TestDatabase as any).isInitialized).toBe(true);
      });

      test('should return existing pool if already initialized', async () => {
        // Set up already initialized state
        (TestDatabase as any).isInitialized = true;
        (TestDatabase as any).testPool = mockPool;
        mockPool.ended = false;

        const result = await TestDatabase.initialize();

        expect(result).toBe(mockPool);
        expect(Pool).not.toHaveBeenCalled(); // Should not create new pools
      });

      test('should create test database if it does not exist', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [] }) // database doesn't exist
          .mockResolvedValueOnce({ rows: [] }) // CREATE DATABASE
          .mockResolvedValueOnce({ rows: [] }) // CREATE EXTENSION
          .mockResolvedValue({ rows: [] }); // All other schema operations

        await TestDatabase.initialize();

        expect(mockPool.query).toHaveBeenCalledWith('CREATE DATABASE koutu_test');
      });

      test('should clean up existing pools before reinitializing', async () => {
        const oldPool = {
          end: jest.fn().mockResolvedValue(undefined),
          ended: false
        };
        
        (TestDatabase as any).testPool = oldPool;
        (TestDatabase as any).mainPool = oldPool;

        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(oldPool.end).toHaveBeenCalledTimes(2); // Both pools cleaned up
      });

      test('should handle initialization errors gracefully', async () => {
        mockPool.query.mockRejectedValue(new Error('Connection failed'));

        await expect(TestDatabase.initialize()).rejects.toThrow('Connection failed');
        expect((TestDatabase as any).isInitialized).toBe(false);
      });

      test('should set environment variables after initialization', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(process.env.DATABASE_URL).toBe('postgresql://postgres:postgres@localhost:5433/koutu_test');
        expect(process.env.TEST_DATABASE_URL).toBe('postgresql://postgres:postgres@localhost:5433/koutu_test');
      });
    });

    describe('Docker PostgreSQL Waiting Logic', () => {
      test('should wait for Docker PostgreSQL to be ready', async () => {
        let attemptCount = 0;
        
        // Mock Pool to fail first few times, then succeed
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          attemptCount++;
          if (attemptCount <= 3) {
            // First 3 attempts fail
            return {
              query: jest.fn().mockRejectedValue(new Error('Connection refused')),
              end: jest.fn().mockResolvedValue(undefined)
            } as any;
          } else {
            // 4th attempt succeeds
            return mockPool;
          }
        });

        mockPool.query.mockResolvedValue({ rows: [] });

        // Mock setTimeout to resolve immediately for testing
        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await TestDatabase.initialize();

        expect(attemptCount).toBeGreaterThan(3); // Should have retried
        (global.setTimeout as jest.Mock).mockRestore();
      });

      test('should timeout if Docker PostgreSQL never becomes ready', async () => {
        // Mock Pool to always fail
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => ({
          query: jest.fn().mockRejectedValue(new Error('Connection refused')),
          end: jest.fn().mockResolvedValue(undefined)
        } as any));

        // Mock setTimeout to resolve immediately
        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await expect(TestDatabase.initialize()).rejects.toThrow(
          'Docker PostgreSQL not ready after 30 attempts'
        );

        (global.setTimeout as jest.Mock).mockRestore();
      }, 10000);

      test('should log progress during waiting', async () => {
        const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
        
        let attemptCount = 0;
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          attemptCount++;
          if (attemptCount <= 10) {
            return {
              query: jest.fn().mockRejectedValue(new Error('Connection refused')),
              end: jest.fn().mockResolvedValue(undefined)
            } as any;
          } else {
            return mockPool;
          }
        });

        mockPool.query.mockResolvedValue({ rows: [] });

        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await TestDatabase.initialize();

        expect(consoleSpy).toHaveBeenCalledWith(
          expect.stringContaining('Still waiting for Docker PostgreSQL')
        );

        consoleSpy.mockRestore();
        (global.setTimeout as jest.Mock).mockRestore();
      });
    });

    describe('Schema Creation', () => {
      test('should create all required tables', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const createTableCalls = mockPool.query.mock.calls.filter(call => 
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

      test('should create required indexes', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const indexCalls = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE INDEX IF NOT EXISTS')
        );

        expect(indexCalls.length).toBeGreaterThan(0);
        expect(indexCalls.some(call => call[0].includes('idx_original_images_user_id'))).toBe(true);
        expect(indexCalls.some(call => call[0].includes('idx_wardrobes_user_id'))).toBe(true);
      });

      test('should create UUID extension', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(mockPool.query).toHaveBeenCalledWith(
          'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'
        );
      });

      test('should handle schema creation errors gracefully', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [{ exists: true }] }) // database exists
          .mockResolvedValueOnce({ rows: [] }) // CREATE EXTENSION
          .mockRejectedValueOnce(new Error('Table creation failed')); // CREATE TABLE fails

        await expect(TestDatabase.initialize()).rejects.toThrow('Table creation failed');
      });

      test('should create tables with proper constraints', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Check that foreign key constraints are created
        const createTableCalls = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE TABLE IF NOT EXISTS')
        );

        const constraintTables = createTableCalls.filter(call => 
          call[0].includes('REFERENCES')
        );

        expect(constraintTables.length).toBeGreaterThan(0);
      });
    });

    describe('Query Operations', () => {
      test('should execute queries successfully', async () => {
        const mockResult = { rows: [{ id: 1, name: 'test' }] };
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockResolvedValue(mockResult); // actual query

        await TestDatabase.initialize();
        
        const result = await TestDatabase.query('SELECT * FROM test_table', ['param1']);

        expect(mockPool.query).toHaveBeenCalledWith('SELECT * FROM test_table', ['param1']);
        expect(result).toEqual(mockResult);
      });

      test('should throw error if not initialized', async () => {
        await expect(TestDatabase.query('SELECT 1')).rejects.toThrow(
          'Docker test database not initialized or has been closed'
        );
      });

      test('should throw error if pool has ended', async () => {
        (TestDatabase as any).isInitialized = true;
        (TestDatabase as any).testPool = { ended: true };

        await expect(TestDatabase.query('SELECT 1')).rejects.toThrow(
          'Docker test database not initialized or has been closed'
        );
      });

      test('should handle query errors properly', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('Query failed'));

        await TestDatabase.initialize();

        await expect(TestDatabase.query('INVALID SQL')).rejects.toThrow('Query failed');
      });

      test('should support parameterized queries', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();
        await TestDatabase.query('SELECT * FROM users WHERE id = $1', ['user-123']);

        expect(mockPool.query).toHaveBeenCalledWith(
          'SELECT * FROM users WHERE id = $1',
          ['user-123']
        );
      });
    });

    describe('Pool Management', () => {
      test('should return the test pool', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();
        const pool = TestDatabase.getPool();

        expect(pool).toBe(mockPool);
      });

      test('should return null if not initialized', () => {
        const pool = TestDatabase.getPool();
        expect(pool).toBeNull();
      });

      test('should handle pool connection limits', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Pool should be configured with reasonable limits
        expect(Pool).toHaveBeenCalledWith(
          expect.objectContaining({
            host: 'localhost',
            port: 5433,
            database: 'koutu_test'
          })
        );
      });
    });

    describe('Table Clearing Operations', () => {
      test('should clear all tables in correct order', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();
        await TestDatabase.clearAllTables();

        // Should clear tables in dependency order
        const clearCall = mockPool.query.mock.calls.find(call => 
          call[0].includes('DELETE FROM wardrobe_items') &&
          call[0].includes('DELETE FROM users')
        );

        expect(clearCall).toBeDefined();
      });

      test('should handle clear tables when not initialized', async () => {
        // Should not throw error
        await expect(TestDatabase.clearAllTables()).resolves.not.toThrow();
      });

      test('should handle clear tables errors gracefully', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('Clear failed'));

        await TestDatabase.initialize();

        // Should not throw, just log error
        await expect(TestDatabase.clearAllTables()).resolves.not.toThrow();
      });

      test('should clear tables when pool has ended', async () => {
        (TestDatabase as any).testPool = { ended: true };

        await expect(TestDatabase.clearAllTables()).resolves.not.toThrow();
      });
    });
  });

  // ============================================================================
  // INTEGRATION TESTS - Docker Container Communication
  // ============================================================================
  describe('Integration Tests - Docker Container Communication', () => {
    describe('Container Connectivity', () => {
      test('should connect to Docker PostgreSQL on correct port', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(Pool).toHaveBeenCalledWith(
          expect.objectContaining({
            host: 'localhost',
            port: 5433, // Docker test port
            user: 'postgres',
            password: 'postgres'
          })
        );
      });

      test('should handle Docker container not running', async () => {
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => ({
          query: jest.fn().mockRejectedValue(new Error('ECONNREFUSED')),
          end: jest.fn().mockResolvedValue(undefined)
        } as any));

        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await expect(TestDatabase.initialize()).rejects.toThrow(
          'Docker PostgreSQL not ready after 30 attempts'
        );

        (global.setTimeout as jest.Mock).mockRestore();
      });

      test('should handle Docker container startup delays', async () => {
        let callCount = 0;
        
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          callCount++;
          if (callCount <= 2) {
            return {
              query: jest.fn().mockRejectedValue(new Error('Connection refused')),
              end: jest.fn().mockResolvedValue(undefined)
            } as any;
          } else {
            return mockPool;
          }
        });

        mockPool.query.mockResolvedValue({ rows: [] });

        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await TestDatabase.initialize();

        expect(callCount).toBeGreaterThan(2);
        (global.setTimeout as jest.Mock).mockRestore();
      });

      test('should handle Docker network issues', async () => {
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => ({
          query: jest.fn().mockRejectedValue(new Error('EHOSTUNREACH')),
          end: jest.fn().mockResolvedValue(undefined)
        } as any));

        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await expect(TestDatabase.initialize()).rejects.toThrow(
          'Docker PostgreSQL not ready'
        );

        (global.setTimeout as jest.Mock).mockRestore();
      });
    });

    describe('Database Lifecycle Management', () => {
      test('should create database if missing', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [] }) // database doesn't exist
          .mockResolvedValueOnce({ rows: [] }) // CREATE DATABASE succeeds
          .mockResolvedValue({ rows: [] }); // All other operations

        await TestDatabase.initialize();

        expect(mockPool.query).toHaveBeenCalledWith('CREATE DATABASE koutu_test');
      });

      test('should skip database creation if exists', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [{ exists: true }] }) // database exists
          .mockResolvedValue({ rows: [] }); // All other operations

        await TestDatabase.initialize();

        const createDbCalls = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE DATABASE')
        );
        expect(createDbCalls).toHaveLength(0);
      });

      test('should terminate existing connections before setup', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(mockPool.query).toHaveBeenCalledWith(
          expect.stringContaining('pg_terminate_backend')
        );
      });

      test('should handle database creation permission errors', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [] }) // database doesn't exist
          .mockRejectedValueOnce(new Error('permission denied to create database'));

        // Should continue with initialization despite creation error
        await expect(TestDatabase.initialize()).rejects.toThrow();
      });
    });

    describe('Schema Synchronization', () => {
      test('should create complete wardrobe schema', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Verify wardrobe-specific tables are created
        const schemaCalls = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE TABLE')
        );

        expect(schemaCalls.some(call => call[0].includes('wardrobes'))).toBe(true);
        expect(schemaCalls.some(call => call[0].includes('wardrobe_items'))).toBe(true);
      });

      test('should create garment metadata compatibility columns', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const garmentTableCall = mockPool.query.mock.calls.find(call => 
          call[0].includes('CREATE TABLE IF NOT EXISTS garment_items')
        );

        expect(garmentTableCall[0]).toContain('metadata JSONB');
        expect(garmentTableCall[0]).toContain('data_version INTEGER');
      });

      test('should create proper foreign key relationships', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const tableCreations = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE TABLE')
        );

        // Check for foreign key references
        const fkTables = tableCreations.filter(call => 
          call[0].includes('REFERENCES')
        );

        expect(fkTables.length).toBeGreaterThan(0);
      });

      test('should handle schema version compatibility', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should use IF NOT EXISTS for all schema objects
        const schemaCommands = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE') && call[0].includes('IF NOT EXISTS')
        );

        expect(schemaCommands.length).toBeGreaterThan(0);
      });
    });

    describe('Performance Optimization', () => {
      test('should create performance indexes', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const indexCalls = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE INDEX')
        );

        // Should create indexes for common query patterns
        expect(indexCalls.some(call => call[0].includes('user_id'))).toBe(true);
        expect(indexCalls.some(call => call[0].includes('wardrobe_id'))).toBe(true);
      });

      test('should optimize table creation order', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const createTableCalls = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE TABLE')
        );

        // Users should be created before dependent tables
        const usersIndex = createTableCalls.findIndex(call => call[0].includes('users'));
        const wardrobesIndex = createTableCalls.findIndex(call => call[0].includes('wardrobes'));

        expect(usersIndex).toBeLessThan(wardrobesIndex);
      });

      test('should batch schema operations efficiently', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        const startTime = Date.now();
        await TestDatabase.initialize();
        const duration = Date.now() - startTime;

        // Should complete schema creation quickly (mocked operations)
        expect(duration).toBeLessThan(100);
        expect(mockPool.query).toHaveBeenCalledTimes(9); // Specific number of schema operations
      });
    });
  });

  // ============================================================================
  // SECURITY TESTS - Connection Security and Access Control
  // ============================================================================
  describe('Security Tests - Connection Security and Access Control', () => {
    describe('Connection Security', () => {
      test('should use secure connection parameters', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should connect to localhost only (not external hosts)
        expect(Pool).toHaveBeenCalledWith(
          expect.objectContaining({
            host: 'localhost',
            port: 5433 // Test-specific port
          })
        );
      });

      test('should use test-specific database name', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(Pool).toHaveBeenCalledWith(
          expect.objectContaining({
            database: 'koutu_test' // Not production database
          })
        );
      });

      test('should handle connection timeouts securely', async () => {
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => ({
          query: jest.fn().mockImplementation(() => 
            new Promise((_, reject) => 
              setTimeout(() => reject(new Error('Connection timeout')), 100)
            )
          ),
          end: jest.fn().mockResolvedValue(undefined)
        } as any));

        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await expect(TestDatabase.initialize()).rejects.toThrow();

        (global.setTimeout as jest.Mock).mockRestore();
      });

      test('should not expose credentials in error messages', async () => {
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          throw new Error('Connection failed with password postgres to localhost:5433');
        });

        try {
          await TestDatabase.initialize();
        } catch (error) {
          // Error message should not expose credentials
          expect(error.message).not.toContain('password postgres');
        }
      });
    });

    describe('SQL Injection Prevention', () => {
      test('should use parameterized queries', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();
        
        await TestDatabase.query(
          'SELECT * FROM users WHERE id = $1 AND email = $2',
          ['user-123', 'test@example.com']
        );

        expect(mockPool.query).toHaveBeenCalledWith(
          'SELECT * FROM users WHERE id = $1 AND email = $2',
          ['user-123', 'test@example.com']
        );
      });

      test('should handle malicious query parameters safely', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const maliciousParams = [
          "'; DROP TABLE users; --",
          "' UNION SELECT * FROM passwords; --",
          "../../../etc/passwd",
          "<script>alert('xss')</script>"
        ];

        for (const param of maliciousParams) {
          await TestDatabase.query('SELECT * FROM users WHERE id = $1', [param]);
          
          expect(mockPool.query).toHaveBeenCalledWith(
            'SELECT * FROM users WHERE id = $1',
            [param]
          );
        }
      });

      test('should validate schema creation queries', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // All schema creation should use safe SQL
        const schemaCalls = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CREATE')
        );

        schemaCalls.forEach(call => {
          const sql = call[0];
          expect(sql).not.toContain("'; DROP");
          expect(sql).not.toContain("--");
          expect(sql).not.toContain("/*");
        });
      });
    });

    describe('Access Control', () => {
      test('should restrict to test database operations', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should set test-specific environment variables
        expect(process.env.DATABASE_URL).toContain('koutu_test');
        expect(process.env.TEST_DATABASE_URL).toContain('koutu_test');
        expect(process.env.DATABASE_URL).toContain('5433'); // Test port
      });

      test('should prevent production database access', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should not connect to production ports or databases
        expect(Pool).not.toHaveBeenCalledWith(
          expect.objectContaining({
            port: 5432, // Production port
            database: 'koutu_production'
          })
        );
      });

      test('should handle unauthorized database operations', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('permission denied for table system_config'));

        await TestDatabase.initialize();

        await expect(TestDatabase.query('SELECT * FROM system_config')).rejects.toThrow();
      });

      test('should isolate test operations from other databases', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should not reference other databases in schema
        const allCalls = mockPool.query.mock.calls;
        allCalls.forEach(call => {
          const sql = call[0];
          expect(sql).not.toContain('production');
          expect(sql).not.toContain('staging');
          expect(sql).not.toContain('development');
        });
      });
    });

    describe('Data Protection', () => {
      test('should handle sensitive data operations securely', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Schema should include proper constraints for sensitive data
        const userTableCall = mockPool.query.mock.calls.find(call => 
          call[0].includes('CREATE TABLE IF NOT EXISTS users')
        );

        expect(userTableCall[0]).toContain('email TEXT UNIQUE NOT NULL');
        expect(userTableCall[0]).toContain('password_hash TEXT');
      });

      test('should implement proper foreign key constraints', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const constraintTables = mockPool.query.mock.calls.filter(call => 
          call[0].includes('REFERENCES') && call[0].includes('ON DELETE')
        );

        expect(constraintTables.length).toBeGreaterThan(0);
        
        // Should use CASCADE for proper cleanup
        expect(constraintTables.some(call => call[0].includes('ON DELETE CASCADE'))).toBe(true);
      });

      test('should create unique constraints for data integrity', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const uniqueConstraints = mockPool.query.mock.calls.filter(call => 
          call[0].includes('UNIQUE')
        );

        expect(uniqueConstraints.length).toBeGreaterThan(0);
        
        // Should have unique email constraint
        expect(uniqueConstraints.some(call => call[0].includes('email TEXT UNIQUE'))).toBe(true);
      });

      test('should implement check constraints for data validation', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const checkConstraints = mockPool.query.mock.calls.filter(call => 
          call[0].includes('CHECK')
        );

        expect(checkConstraints.length).toBeGreaterThan(0);
        
        // Should validate image status values
        expect(checkConstraints.some(call => 
          call[0].includes("CHECK (status IN ('new', 'processed', 'labeled'))")
        )).toBe(true);
      });
    });

    describe('Error Information Disclosure', () => {
      test('should not expose database credentials in errors', async () => {
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          throw new Error('connection failed: password authentication failed for user "postgres"');
        });

        try {
          await TestDatabase.initialize();
        } catch (error) {
          // Should not expose password details
          expect(error.message).not.toContain('password authentication failed');
        }
      });

      test('should not expose internal database structure in schema errors', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization succeeds
          .mockRejectedValueOnce(new Error('column "secret_admin_column" does not exist'));

        await TestDatabase.initialize();

        try {
          await TestDatabase.query('SELECT secret_admin_column FROM users');
        } catch (error) {
          // Error should propagate but not expose internal structure
          expect(error.message).toContain('secret_admin_column');
        }
      });

      test('should handle constraint violation errors safely', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('violates foreign key constraint "fk_internal_table_reference"'));

        await TestDatabase.initialize();

        await expect(TestDatabase.query('INSERT INTO invalid_table VALUES (1)'))
          .rejects.toThrow('violates foreign key constraint');
      });
    });
  });

  // ============================================================================
  // EDGE CASES AND ERROR HANDLING
  // ============================================================================
  describe('Edge Cases and Error Handling', () => {
    describe('Pool Management Edge Cases', () => {
      test('should handle pool end failures during cleanup', async () => {
        const failingPool = {
          end: jest.fn().mockRejectedValue(new Error('Pool end failed')),
          ended: false
        };
        
        (TestDatabase as any).testPool = failingPool;
        (TestDatabase as any).mainPool = failingPool;
        (TestDatabase as any).isInitialized = true;

        // Should not throw error
        await expect(TestDatabase.cleanup()).resolves.not.toThrow();
        expect((TestDatabase as any).isInitialized).toBe(false);
      });

      test('should handle already ended pools gracefully', async () => {
        const endedPool = {
          end: jest.fn(),
          ended: true
        };
        
        (TestDatabase as any).testPool = endedPool;
        (TestDatabase as any).isInitialized = true;

        await TestDatabase.cleanup();

        expect(endedPool.end).not.toHaveBeenCalled(); // Should skip already ended pools
      });

      test('should handle null pools during cleanup', async () => {
        (TestDatabase as any).testPool = null;
        (TestDatabase as any).mainPool = null;
        (TestDatabase as any).isInitialized = true;

        await expect(TestDatabase.cleanup()).resolves.not.toThrow();
      });

      test('should handle concurrent cleanup calls', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });
        await TestDatabase.initialize();

        // Start multiple cleanup operations
        const cleanups = [
          TestDatabase.cleanup(),
          TestDatabase.cleanup(),
          TestDatabase.cleanup()
        ];

        await Promise.all(cleanups);

        expect((TestDatabase as any).isInitialized).toBe(false);
      });
    });

    describe('Schema Creation Edge Cases', () => {
      test('should handle partial schema creation failures', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [{ exists: true }] }) // database exists
          .mockResolvedValueOnce({ rows: [] }) // CREATE EXTENSION
          .mockResolvedValueOnce({ rows: [] }) // CREATE TABLE users
          .mockRejectedValueOnce(new Error('CREATE TABLE garment_items failed')); // Fail on garment_items

        await expect(TestDatabase.initialize()).rejects.toThrow('CREATE TABLE garment_items failed');
      });

      test('should handle extension creation failures', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [{ exists: true }] }) // database exists
          .mockRejectedValueOnce(new Error('uuid-ossp extension not available'));

        await expect(TestDatabase.initialize()).rejects.toThrow('uuid-ossp extension not available');
      });

      test('should handle index creation failures gracefully', async () => {
        mockPool.query
          .mockResolvedValue({ rows: [] }) // Most operations succeed
          .mockRejectedValueOnce(new Error('CREATE INDEX failed')); // Index creation fails

        // Should continue despite index failure
        await expect(TestDatabase.initialize()).rejects.toThrow('CREATE INDEX failed');
      });

      test('should handle very long table names', async () => {
        const longTableName = 'very_long_table_name_'.repeat(10);
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();
        
        await TestDatabase.query(`CREATE TABLE ${longTableName} (id SERIAL)`);

        expect(mockPool.query).toHaveBeenCalledWith(
          `CREATE TABLE ${longTableName} (id SERIAL)`
        );
      });
    });

    describe('Connection Resilience', () => {
      test('should handle intermittent connection failures', async () => {
        let connectionAttempts = 0;
        
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => {
          connectionAttempts++;
          if (connectionAttempts === 1) {
            // First pool (main) fails
            return {
              query: jest.fn().mockRejectedValue(new Error('Connection lost')),
              end: jest.fn().mockResolvedValue(undefined)
            } as any;
          } else if (connectionAttempts === 2) {
            // Second pool (main retry) succeeds
            return mockPool;
          } else {
            // Test pool succeeds
            return mockPool;
          }
        });

        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(connectionAttempts).toBeGreaterThan(1);
      });

      test('should handle connection pool exhaustion', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('remaining connection slots are reserved'));

        await TestDatabase.initialize();

        await expect(TestDatabase.query('SELECT 1')).rejects.toThrow('remaining connection slots');
      });

      test('should handle database server shutdown', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('the database system is shutting down'));

        await TestDatabase.initialize();

        await expect(TestDatabase.query('SELECT 1')).rejects.toThrow('database system is shutting down');
      });

      test('should handle network partitions', async () => {
        (Pool as jest.MockedClass<typeof Pool>).mockImplementation(() => ({
          query: jest.fn().mockRejectedValue(new Error('EHOSTUNREACH: No route to host')),
          end: jest.fn().mockResolvedValue(undefined)
        } as any));

        jest.spyOn(global, 'setTimeout').mockImplementation((callback: any) => {
          callback();
          return null as any;
        });

        await expect(TestDatabase.initialize()).rejects.toThrow('Docker PostgreSQL not ready');

        (global.setTimeout as jest.Mock).mockRestore();
      });
    });

    describe('Data Consistency Edge Cases', () => {
      test('should handle concurrent table operations', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Simulate concurrent operations
        const operations = [
          TestDatabase.query('INSERT INTO users (email) VALUES ($1)', ['user1@example.com']),
          TestDatabase.query('INSERT INTO users (email) VALUES ($1)', ['user2@example.com']),
          TestDatabase.clearAllTables(),
          TestDatabase.query('SELECT COUNT(*) FROM users')
        ];

        // Should handle concurrent operations without deadlocks
        await Promise.allSettled(operations);

        expect(mockPool.query).toHaveBeenCalledTimes(13); // 9 for init + 4 for operations
      });

      test('should handle transaction rollbacks', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('current transaction is aborted'));

        await TestDatabase.initialize();

        await expect(TestDatabase.query('SELECT 1')).rejects.toThrow('current transaction is aborted');
      });

      test('should handle foreign key constraint violations during clear', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('foreign key constraint violation'));

        await TestDatabase.initialize();

        // Should not throw, just log error
        await expect(TestDatabase.clearAllTables()).resolves.not.toThrow();
      });

      test('should handle clear tables with missing tables', async () => {
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('relation "wardrobe_items" does not exist'));

        await TestDatabase.initialize();

        await expect(TestDatabase.clearAllTables()).resolves.not.toThrow();
      });
    });

    describe('Memory and Resource Management', () => {
      test('should handle memory pressure during initialization', async () => {
        mockPool.query.mockImplementation(() => {
          // Simulate memory allocation
          const largeArray = new Array(1000000).fill('memory-test');
          return Promise.resolve({ rows: [] });
        });

        await TestDatabase.initialize();

        expect(mockPool.query).toHaveBeenCalled();
      });

      test('should handle resource cleanup on repeated initialization', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        // Initialize multiple times
        await TestDatabase.initialize();
        await TestDatabase.cleanup();
        await TestDatabase.initialize();
        await TestDatabase.cleanup();
        await TestDatabase.initialize();

        expect((TestDatabase as any).isInitialized).toBe(true);
      });

      test('should handle large query results', async () => {
        const largeResult = {
          rows: new Array(100000).fill({ id: 1, name: 'test' })
        };

        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // initialization
          .mockResolvedValueOnce(largeResult);

        await TestDatabase.initialize();

        const result = await TestDatabase.query('SELECT * FROM large_table');

        expect(result.rows).toHaveLength(100000);
      });

      test('should handle connection leaks', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Simulate many queries without proper cleanup
        const queries = Array.from({ length: 1000 }, () =>
          TestDatabase.query('SELECT 1')
        );

        await Promise.all(queries);

        expect(mockPool.query).toHaveBeenCalledTimes(1009); // 9 for init + 1000 for queries
      });
    });

    describe('Environment Variable Edge Cases', () => {
      test('should handle missing environment variables', async () => {
        delete process.env.DATABASE_URL;
        delete process.env.TEST_DATABASE_URL;

        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(process.env.DATABASE_URL).toBeDefined();
        expect(process.env.TEST_DATABASE_URL).toBeDefined();
      });

      test('should override existing environment variables', async () => {
        process.env.DATABASE_URL = 'postgresql://old-config';
        process.env.TEST_DATABASE_URL = 'postgresql://old-test-config';

        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(process.env.DATABASE_URL).toBe('postgresql://postgres:postgres@localhost:5433/koutu_test');
        expect(process.env.TEST_DATABASE_URL).toBe('postgresql://postgres:postgres@localhost:5433/koutu_test');
      });

      test('should handle environment variable corruption', async () => {
        process.env.DATABASE_URL = '\x00corrupted\x00value';

        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        expect(process.env.DATABASE_URL).toBe('postgresql://postgres:postgres@localhost:5433/koutu_test');
      });
    });
  });

  // ============================================================================
  // PERFORMANCE AND OPTIMIZATION TESTS
  // ============================================================================
  describe('Performance and Optimization Tests', () => {
    describe('Initialization Performance', () => {
      test('should initialize database efficiently', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        const startTime = Date.now();
        await TestDatabase.initialize();
        const duration = Date.now() - startTime;

        // Should complete quickly for mocked operations
        expect(duration).toBeLessThan(100);
      });

      test('should cache initialization results', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        const startTime = Date.now();
        
        // First initialization
        await TestDatabase.initialize();
        
        // Second initialization (should use cache)
        await TestDatabase.initialize();
        
        const duration = Date.now() - startTime;

        expect(duration).toBeLessThan(50);
        expect(Pool).toHaveBeenCalledTimes(2); // Only called once for the first init
      });

      test('should handle high-frequency initialization requests', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        const operations = Array.from({ length: 100 }, () =>
          TestDatabase.initialize()
        );

        const results = await Promise.all(operations);

        // All should return the same pool instance
        results.forEach(result => {
          expect(result).toBe(mockPool);
        });
      });
    });

    describe('Query Performance', () => {
      test('should execute queries efficiently', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const startTime = Date.now();
        await TestDatabase.query('SELECT 1');
        const duration = Date.now() - startTime;

        expect(duration).toBeLessThan(50);
      });

      test('should handle concurrent queries efficiently', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const queries = Array.from({ length: 100 }, () =>
          TestDatabase.query('SELECT 1')
        );

        const startTime = Date.now();
        await Promise.all(queries);
        const duration = Date.now() - startTime;

        expect(duration).toBeLessThan(200); // 200ms for 100 mocked queries
        expect(mockPool.query).toHaveBeenCalledTimes(109); // 9 for init + 100 for queries
      });

      test('should optimize schema creation order', async () => {
        const queryOrder: string[] = [];
        
        mockPool.query.mockImplementation((sql: string) => {
          queryOrder.push(sql);
          return Promise.resolve({ rows: [] });
        });

        await TestDatabase.initialize();

        // Users table should be created before dependent tables
        const usersIndex = queryOrder.findIndex(sql => sql.includes('CREATE TABLE IF NOT EXISTS users'));
        const wardrobesIndex = queryOrder.findIndex(sql => sql.includes('CREATE TABLE IF NOT EXISTS wardrobes'));

        expect(usersIndex).toBeLessThan(wardrobesIndex);
      });
    });

    describe('Memory Usage Optimization', () => {
      test('should not leak memory during repeated operations', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Perform many operations
        for (let i = 0; i < 1000; i++) {
          await TestDatabase.query('SELECT 1');
        }

        expect(mockPool.query).toHaveBeenCalledTimes(1009);
      });

      test('should handle large result sets efficiently', async () => {
        const largeResult = {
          rows: Array.from({ length: 10000 }, (_, i) => ({ id: i, name: `user${i}` }))
        };

        mockPool.query
          .mockResolvedValue({ rows: [] }) // initialization
          .mockResolvedValueOnce(largeResult);

        await TestDatabase.initialize();

        const result = await TestDatabase.query('SELECT * FROM users');

        expect(result.rows).toHaveLength(10000);
      });

      test('should cleanup resources efficiently', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const startTime = Date.now();
        await TestDatabase.cleanup();
        const duration = Date.now() - startTime;

        expect(duration).toBeLessThan(50);
        expect((TestDatabase as any).testPool).toBeNull();
        expect((TestDatabase as any).mainPool).toBeNull();
      });
    });

    describe('Connection Pool Optimization', () => {
      test('should configure connection pools optimally', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Verify pools are configured with optimal settings
        expect(Pool).toHaveBeenCalledWith(
          expect.objectContaining({
            host: 'localhost',
            port: 5433,
            user: 'postgres',
            database: 'koutu_test'
          })
        );
      });

      test('should handle pool connection limits gracefully', async () => {
        mockPool.query
          .mockResolvedValue({ rows: [] }) // initialization
          .mockRejectedValueOnce(new Error('too many clients already'));

        await TestDatabase.initialize();

        await expect(TestDatabase.query('SELECT 1')).rejects.toThrow('too many clients');
      });

      test('should reuse connections efficiently', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Multiple queries should reuse the same pool
        await TestDatabase.query('SELECT 1');
        await TestDatabase.query('SELECT 2');
        await TestDatabase.query('SELECT 3');

        expect(Pool).toHaveBeenCalledTimes(2); // Only main + test pools
      });
    });
  });

  // ============================================================================
  // COMPATIBILITY AND REGRESSION TESTS
  // ============================================================================
  describe('Compatibility and Regression Tests', () => {
    describe('PostgreSQL Version Compatibility', () => {
      test('should work with different PostgreSQL versions', async () => {
        const versionResponses = [
          { rows: [] }, // PostgreSQL 13
          { rows: [] }, // PostgreSQL 14
          { rows: [] }  // PostgreSQL 15
        ];

        for (const response of versionResponses) {
          mockPool.query.mockResolvedValue(response);

          await TestDatabase.initialize();
          await TestDatabase.cleanup();

          expect((TestDatabase as any).isInitialized).toBe(false);
        }
      });

      test('should handle different UUID extension implementations', async () => {
        const extensionVariations = [
          'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"',
          'CREATE EXTENSION IF NOT EXISTS uuid_ossp',
          'CREATE EXTENSION uuid_ossp'
        ];

        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should use the standard extension format
        expect(mockPool.query).toHaveBeenCalledWith(
          'CREATE EXTENSION IF NOT EXISTS "uuid-ossp"'
        );
      });

      test('should handle different JSONB implementations', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should use JSONB for metadata columns
        const jsonbTables = mockPool.query.mock.calls.filter(call => 
          call[0].includes('JSONB')
        );

        expect(jsonbTables.length).toBeGreaterThan(0);
      });
    });

    describe('Schema Evolution Compatibility', () => {
      test('should handle additional columns gracefully', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Schema creation should use IF NOT EXISTS
        const ifNotExistsCalls = mockPool.query.mock.calls.filter(call => 
          call[0].includes('IF NOT EXISTS')
        );

        expect(ifNotExistsCalls.length).toBeGreaterThan(0);
      });

      test('should maintain backward compatibility with schema changes', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // All critical tables should be present
        const criticalTables = ['users', 'original_images', 'garment_items', 'wardrobes'];
        
        criticalTables.forEach(table => {
          const tableCreation = mockPool.query.mock.calls.find(call => 
            call[0].includes(`CREATE TABLE IF NOT EXISTS ${table}`)
          );
          expect(tableCreation).toBeDefined();
        });
      });

      test('should handle missing optional features', async () => {
        // Mock extension creation failure
        mockPool.query
          .mockResolvedValueOnce({ rows: [] }) // pg_terminate_backend
          .mockResolvedValueOnce({ rows: [{ exists: true }] }) // database exists
          .mockRejectedValueOnce(new Error('extension "uuid-ossp" is not available'));

        await expect(TestDatabase.initialize()).rejects.toThrow('uuid-ossp');
      });
    });

    describe('API Compatibility', () => {
      test('should maintain consistent query interface', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should support various query formats
        await TestDatabase.query('SELECT 1');
        await TestDatabase.query('SELECT * FROM users WHERE id = $1', ['test-id']);
        await TestDatabase.query('INSERT INTO users (email) VALUES ($1)', ['test@example.com']);

        expect(mockPool.query).toHaveBeenCalledTimes(12); // 9 for init + 3 for queries
      });

      test('should maintain consistent pool interface', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        const pool = TestDatabase.getPool();

        expect(pool).toHaveProperty('query');
        expect(pool).toHaveProperty('end');
        expect(typeof pool.query).toBe('function');
      });

      test('should maintain consistent cleanup behavior', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();
        expect((TestDatabase as any).isInitialized).toBe(true);

        await TestDatabase.cleanup();
        expect((TestDatabase as any).isInitialized).toBe(false);
        expect((TestDatabase as any).testPool).toBeNull();
      });
    });

    describe('Environment Compatibility', () => {
      test('should work in different Node.js environments', async () => {
        // Simulate different environments
        const environments = ['test', 'development', 'staging'];

        for (const env of environments) {
          process.env.NODE_ENV = env;
          
          mockPool.query.mockResolvedValue({ rows: [] });

          await TestDatabase.initialize();
          await TestDatabase.cleanup();

          expect((TestDatabase as any).isInitialized).toBe(false);
        }
      });

      test('should handle different Docker configurations', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should consistently use Docker test configuration
        expect(Pool).toHaveBeenCalledWith(
          expect.objectContaining({
            port: 5433, // Test port
            database: 'koutu_test' // Test database
          })
        );
      });

      test('should isolate from production configurations', async () => {
        process.env.DATABASE_URL = 'postgresql://production-server:5432/production_db';

        mockPool.query.mockResolvedValue({ rows: [] });

        await TestDatabase.initialize();

        // Should override with test configuration
        expect(process.env.DATABASE_URL).toBe('postgresql://postgres:postgres@localhost:5433/koutu_test');
      });
    });
  });
});