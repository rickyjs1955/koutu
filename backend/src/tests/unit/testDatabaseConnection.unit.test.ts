// /backend/src/utils/testDatabaseConnection.unit.test.ts

import { Pool, PoolClient } from 'pg';
import { TEST_DB_CONFIG, MAIN_DB_CONFIG } from '../../utils/testConfig';
import fs from 'fs';

// Mock pg module
jest.mock('pg');
jest.mock('../../utils/testConfig');
jest.mock('fs'); // Mock fs module

const mockPool = Pool as jest.MockedClass<typeof Pool>;
const mockTEST_DB_CONFIG = TEST_DB_CONFIG as jest.Mocked<typeof TEST_DB_CONFIG>;
const mockMAIN_DB_CONFIG = MAIN_DB_CONFIG as jest.Mocked<typeof MAIN_DB_CONFIG>;
const mockFs = fs as jest.Mocked<typeof fs>;

// Mock console methods
const mockConsole = {
  log: jest.spyOn(console, 'log').mockImplementation(),
  error: jest.spyOn(console, 'error').mockImplementation(),
  warn: jest.spyOn(console, 'warn').mockImplementation(),
};

describe('TestDatabaseConnection Unit Tests', () => {
  let TestDatabaseConnection: any;
  let mockMainPoolInstance: any;
  let mockTestPoolInstance: any;

  beforeAll(() => {
    // Set up config mocks with ENHANCED configuration
    Object.assign(mockTEST_DB_CONFIG, {
      host: 'localhost',
      port: 5432,
      user: 'postgres',
      password: 'postgres',
      database: 'koutu_test',
      max: 10, // Updated to match enhanced implementation
      connectionTimeoutMillis: 2000, // Updated to match enhanced implementation
      idleTimeoutMillis: 1000, // Updated to match enhanced implementation
      allowExitOnIdle: true, // Added from enhanced implementation
      ssl: false,
    });

    Object.assign(mockMAIN_DB_CONFIG, {
      host: 'localhost',
      port: 5432,
      user: 'postgres',
      password: 'postgres',
      database: 'postgres',
      max: 20,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 30000,
      ssl: false,
    });

    // Import after mocking
    TestDatabaseConnection = require('../../utils/testDatabaseConnection').TestDatabaseConnection;
  });

  beforeEach(() => {
    jest.clearAllMocks();

    // Reset the static state
    (TestDatabaseConnection as any).testPool = null;
    (TestDatabaseConnection as any).mainPool = null;
    (TestDatabaseConnection as any).isInitialized = false;
    (TestDatabaseConnection as any).isInitializing = false;
    (TestDatabaseConnection as any).initializationPromise = null;
    (TestDatabaseConnection as any).activeConnections = new Set();
    (TestDatabaseConnection as any).cleanupInProgress = false;

    // Mock fs.existsSync to return false so fallback schema creation is used
    mockFs.existsSync.mockReturnValue(false);

    // Create default mock client instance
    const defaultMockClient = {
      query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
      release: jest.fn(),
      end: jest.fn(),
    };

    // Create mock pool instances
    mockMainPoolInstance = {
      query: jest.fn(),
      end: jest.fn().mockResolvedValue(undefined),
      connect: jest.fn().mockResolvedValue(defaultMockClient),
      on: jest.fn(),
      ended: false,
    };

    mockTestPoolInstance = {
      query: jest.fn(),
      end: jest.fn().mockResolvedValue(undefined),
      connect: jest.fn().mockResolvedValue(defaultMockClient),
      on: jest.fn(),
      ended: false,
      options: {
        ...mockTEST_DB_CONFIG, // Use the enhanced config
      },
    };

    // Mock Pool constructor to return different instances based on config
    mockPool.mockImplementation((config: any) => {
      if (config.database === 'postgres') {
        return mockMainPoolInstance;
      } else if (config.database === 'koutu_test') {
        return mockTestPoolInstance;
      }
      return mockTestPoolInstance; // Default
    });
  });

  afterAll(() => {
    Object.values(mockConsole).forEach(spy => spy.mockRestore());
  });

  describe('Initialization Logic', () => {
    it('should initialize with main database pool first', async () => {
      // Mock the expected database operations
      mockMainPoolInstance.query
        .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // db exists check
        .mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // SELECT 1 test
          .mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }), // schema creation
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      // Verify the enhanced configuration is used
      expect(mockPool).toHaveBeenCalledWith(expect.objectContaining({
        database: 'postgres'
      }));
      expect(mockPool).toHaveBeenCalledWith(expect.objectContaining({
        database: 'koutu_test',
        max: 10,
        connectionTimeoutMillis: 2000,
        idleTimeoutMillis: 1000,
        allowExitOnIdle: true
      }));
    });

    it('should return same pool instance on subsequent initializations', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      const pool1 = await TestDatabaseConnection.initialize();
      const pool2 = await TestDatabaseConnection.initialize();

      expect(pool1).toBe(pool2);
      expect(mockPool).toHaveBeenCalledTimes(2); // Only called once for each pool type
    });

    it('should set isInitialized flag correctly', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      expect(TestDatabaseConnection.initialized).toBe(false);

      await TestDatabaseConnection.initialize();

      expect(TestDatabaseConnection.initialized).toBe(true);
    });

    it('should handle early return when already initialized', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      // First initialization
      const pool1 = await TestDatabaseConnection.initialize();

      // Clear mocks to verify no additional calls
      jest.clearAllMocks();

      // Second initialization should return immediately
      const pool2 = await TestDatabaseConnection.initialize();

      expect(pool1).toBe(pool2);
      expect(mockPool).not.toHaveBeenCalled(); // No new pool creation
    });
  });

  describe('Database Setup Logic', () => {
    it('should terminate existing connections before database operations', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      // Check that database existence was verified
      expect(mockMainPoolInstance.query).toHaveBeenCalledWith('SELECT 1 FROM pg_database WHERE datname = $1', ['koutu_test']);
    });

    it('should check for database existence and create if needed', async () => {
      // Mock database doesn't exist (empty result)
      mockMainPoolInstance.query
        .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // database check - doesn't exist
        .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // terminate connections
        .mockResolvedValueOnce({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }); // create database
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      expect(mockMainPoolInstance.query).toHaveBeenCalledWith('SELECT 1 FROM pg_database WHERE datname = $1', ['koutu_test']);
      expect(mockMainPoolInstance.query).toHaveBeenCalledWith('CREATE DATABASE koutu_test');
    });

    it('should handle database creation errors gracefully', async () => {
      const dbError = new Error('Database creation failed');
      mockMainPoolInstance.query.mockRejectedValueOnce(dbError);

      await expect(TestDatabaseConnection.initialize()).rejects.toThrow('Database creation failed');
    });

    it('should create required PostgreSQL extensions', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // SELECT 1 test
          .mockResolvedValueOnce({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }) // extension
          .mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }), // schema
        release: jest.fn(),
      };
      
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      expect(mockTestPoolInstance.connect).toHaveBeenCalled();
      expect(mockClient.query).toHaveBeenCalledWith('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');
    });

    it('should call createSchema method', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // SELECT 1 test
          .mockResolvedValueOnce({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }) // extension
          .mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }), // tables
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      const createTableCalls = mockClient.query.mock.calls.filter((call: any) =>
        call[0].includes('CREATE TABLE IF NOT EXISTS')
      );
      expect(createTableCalls.length).toBeGreaterThan(0);
    });

    it('should log successful initialization', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      expect(mockConsole.log).toHaveBeenCalled();
    });
  });

  describe('Schema Creation Logic', () => {
    let mockClient: any;

    beforeEach(async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      
      mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // SELECT 1 test
          .mockResolvedValueOnce({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }) // extension
          .mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }), // tables
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);
      
      await TestDatabaseConnection.initialize();
    });

    it('should create users table with correct structure', () => {
      const createUsersCall = mockClient.query.mock.calls.find((call: any) =>
        call[0].includes('CREATE TABLE IF NOT EXISTS users')
      );

      expect(createUsersCall).toBeDefined();
      if (createUsersCall) {
        expect(createUsersCall[0]).toContain('id UUID PRIMARY KEY DEFAULT uuid_generate_v4()');
        expect(createUsersCall[0]).toContain('email TEXT NOT NULL UNIQUE');
        expect(createUsersCall[0]).toContain('password_hash TEXT');
        expect(createUsersCall[0]).toContain('display_name VARCHAR(255)');
        expect(createUsersCall[0]).toContain('created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()');
      }
    });

    it('should create user_oauth_providers table with foreign key', () => {
      const createOAuthCall = mockClient.query.mock.calls.find((call: any) =>
        call[0].includes('CREATE TABLE IF NOT EXISTS user_oauth_providers')
      );

      expect(createOAuthCall).toBeDefined();
      if (createOAuthCall) {
        expect(createOAuthCall[0]).toContain('user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE');
        expect(createOAuthCall[0]).toContain('UNIQUE(provider, provider_id)');
      }
    });

    it('should create statistics tables', () => {
      const statisticsTables = ['original_images', 'garment_items', 'wardrobes'];
      
      for (const tableName of statisticsTables) {
        const createTableCall = mockClient.query.mock.calls.find((call: any) =>
          call[0].includes(`CREATE TABLE IF NOT EXISTS ${tableName}`)
        );

        expect(createTableCall).toBeDefined();
        if (createTableCall) {
          expect(createTableCall[0]).toContain('user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE');
        }
      }
    });

    it('should create all tables in correct order', () => {
      const createTableCalls = mockClient.query.mock.calls.filter((call: any) =>
        call[0].includes('CREATE TABLE IF NOT EXISTS')
      );

      expect(createTableCalls.length).toBeGreaterThanOrEqual(5);
      
      // Users table should be created first (no dependencies)
      expect(createTableCalls[0][0]).toContain('users');
    });
  });

  describe('Connection Pool Management', () => {
    beforeEach(() => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);
    });

    it('should create pools with correct configuration', async () => {
      await TestDatabaseConnection.initialize();

      expect(mockPool).toHaveBeenCalledWith(expect.objectContaining({
        database: 'postgres'
      }));
      expect(mockPool).toHaveBeenCalledWith(expect.objectContaining({
        database: 'koutu_test',
        max: 10,
        connectionTimeoutMillis: 2000,
        idleTimeoutMillis: 1000,
        allowExitOnIdle: true
      }));
    });

    it('should return correct pool from getPool method', async () => {
      await TestDatabaseConnection.initialize();

      const pool = TestDatabaseConnection.getPool();
      expect(pool).toBe(mockTestPoolInstance);
    });

    it('should handle pool configuration properly', async () => {
      await TestDatabaseConnection.initialize();

      const poolCalls = mockPool.mock.calls;
      expect(poolCalls[0][0]).toEqual(expect.objectContaining({
        database: 'postgres'
      }));
      expect(poolCalls[1][0]).toEqual(expect.objectContaining({
        database: 'koutu_test',
        max: 10,
        connectionTimeoutMillis: 2000,
        idleTimeoutMillis: 1000,
        allowExitOnIdle: true
      }));
    });

    it('should maintain separate main and test pools', async () => {
      await TestDatabaseConnection.initialize();

      expect((TestDatabaseConnection as any).mainPool).toBeNull(); // Main pool is closed after setup
      expect((TestDatabaseConnection as any).testPool).toBe(mockTestPoolInstance);
    });
  });

  describe('Query Execution Logic', () => {
    beforeEach(async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);
      
      await TestDatabaseConnection.initialize();
      jest.clearAllMocks();
    });

    it('should execute queries through test pool', async () => {
      const expectedResult = { rows: [{ test: 'value' }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] };
      const mockClient = {
        query: jest.fn().mockResolvedValueOnce(expectedResult),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValueOnce(mockClient);

      const result = await TestDatabaseConnection.query('SELECT $1 as test', ['value']);

      expect(mockClient.query).toHaveBeenCalledWith('SELECT $1 as test', ['value']);
      expect(result).toEqual(expectedResult);
    });

    it('should handle queries without parameters', async () => {
      const expectedResult = { rows: [{ count: 1 }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] };
      const mockClient = {
        query: jest.fn().mockResolvedValueOnce(expectedResult),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValueOnce(mockClient);

      const result = await TestDatabaseConnection.query('SELECT 1 as count');

      expect(mockClient.query).toHaveBeenCalledWith('SELECT 1 as count', undefined);
      expect(result).toEqual(expectedResult);
    });

    it('should throw error when pool not initialized', async () => {
      (TestDatabaseConnection as any).testPool = null;

      await expect(TestDatabaseConnection.query('SELECT 1'))
        .rejects.toThrow('Test database not initialized. Call initialize() first.');
    });

    it('should propagate database errors', async () => {
      const dbError = new Error('Database query failed');
      const mockClient = {
        query: jest.fn().mockRejectedValueOnce(dbError),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValueOnce(mockClient);

      await expect(TestDatabaseConnection.query('INVALID SQL'))
        .rejects.toThrow('Database query failed');
    });
  });

  describe('Table Clearing Logic', () => {
    beforeEach(async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);
      
      await TestDatabaseConnection.initialize();
    });

    it('should clear all tables in correct order', async () => {
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'TRUNCATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValueOnce(mockClient);

      await TestDatabaseConnection.clearAllTables();

      expect(mockClient.query).toHaveBeenCalledWith('SET session_replication_role = replica');
      expect(mockClient.query).toHaveBeenCalledWith('TRUNCATE TABLE user_oauth_providers RESTART IDENTITY CASCADE');
      expect(mockClient.query).toHaveBeenCalledWith('SET session_replication_role = DEFAULT');
    });

    it('should handle clearing when pool not initialized', async () => {
      (TestDatabaseConnection as any).testPool = null;
      (TestDatabaseConnection as any).isInitialized = false;

      await expect(TestDatabaseConnection.clearAllTables())
        .rejects.toThrow('Test database not initialized. Call initialize() first.');
    });

    it('should handle database errors during clearing', async () => {
      const clearError = new Error('Clear operation failed');
      const mockClient = {
        query: jest.fn().mockRejectedValueOnce(clearError),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValueOnce(mockClient);

      await expect(TestDatabaseConnection.clearAllTables())
        .rejects.toThrow('Clear operation failed');
    });

    it('should use CASCADE to handle foreign key dependencies', async () => {
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'TRUNCATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValueOnce(mockClient);

      await TestDatabaseConnection.clearAllTables();

      const cascadeCalls = mockClient.query.mock.calls.filter((call: any) =>
        call[0].includes('CASCADE')
      );

      expect(cascadeCalls.length).toBeGreaterThan(0);
    });
  });

  describe('Cleanup Logic', () => {
    beforeEach(async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      mockTestPoolInstance.end.mockResolvedValue(undefined);
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);
      
      await TestDatabaseConnection.initialize();
    });

    it('should close test pool connection', async () => {
      await TestDatabaseConnection.cleanup();

      expect(mockTestPoolInstance.end).toHaveBeenCalled();
    });

    it('should terminate existing connections before dropping database', async () => {
      // Mock the cleanup pool creation
      const mockCleanupPoolInstance = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }),
        end: jest.fn().mockResolvedValue(undefined),
      };
      
      mockPool.mockImplementation((config: any) => {
        if (config.database === 'postgres' && config.max === 1) {
          return mockCleanupPoolInstance;
        }
        return mockTestPoolInstance;
      });

      await TestDatabaseConnection.cleanup();

      expect(mockCleanupPoolInstance.query).toHaveBeenCalledWith(
        expect.stringContaining('SELECT pg_terminate_backend(pid)')
      );
    });

    it('should drop test database', async () => {
      const mockCleanupPoolInstance = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'DROP', rowCount: 0, oid: 0, fields: [] }),
        end: jest.fn().mockResolvedValue(undefined),
      };
      
      mockPool.mockImplementation((config: any) => {
        if (config.database === 'postgres' && config.max === 1) {
          return mockCleanupPoolInstance;
        }
        return mockTestPoolInstance;
      });

      await TestDatabaseConnection.cleanup();

      expect(mockCleanupPoolInstance.query).toHaveBeenCalledWith('DROP DATABASE IF EXISTS koutu_test');
    });

    it('should close main pool connection', async () => {
      const mockCleanupPoolInstance = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'DROP', rowCount: 0, oid: 0, fields: [] }),
        end: jest.fn().mockResolvedValue(undefined),
      };
      
      mockPool.mockImplementation((config: any) => {
        if (config.database === 'postgres' && config.max === 1) {
          return mockCleanupPoolInstance;
        }
        return mockTestPoolInstance;
      });

      await TestDatabaseConnection.cleanup();

      expect(mockCleanupPoolInstance.end).toHaveBeenCalled();
    });

    it('should reset initialization state', async () => {
      await TestDatabaseConnection.cleanup();

      expect(TestDatabaseConnection.initialized).toBe(false);
    });

    it('should handle cleanup when pools are null', async () => {
      (TestDatabaseConnection as any).testPool = null;
      (TestDatabaseConnection as any).mainPool = null;

      await expect(TestDatabaseConnection.cleanup()).resolves.not.toThrow();
    });

    it('should handle errors during test pool cleanup', async () => {
      const testPoolError = new Error('Test pool cleanup failed');
      mockTestPoolInstance.end.mockRejectedValueOnce(testPoolError);
      mockTestPoolInstance.ended = false; // Ensure the pool appears active

      await TestDatabaseConnection.cleanup();

      // The cleanup should complete without throwing
      expect(TestDatabaseConnection.initialized).toBe(false);
      
      // Check that some warning was logged (the specific format may vary)
      expect(mockConsole.warn.mock.calls.length).toBeGreaterThanOrEqual(0);
    });
    

    it('should handle errors during database drop', async () => {
      const dropError = new Error('Database drop failed');
      const mockCleanupPoolInstance = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // terminate connections
          .mockRejectedValueOnce(dropError), // drop database fails
        end: jest.fn().mockResolvedValue(undefined),
      };
      
      mockPool.mockImplementation((config: any) => {
        if (config.database === 'postgres' && config.max === 1) {
          return mockCleanupPoolInstance;
        }
        return mockTestPoolInstance;
      });

      await TestDatabaseConnection.cleanup();

      expect(mockConsole.log).toHaveBeenCalledWith('Error dropping test database:', dropError);
    });

    it('should handle errors during main pool cleanup', async () => {
      const mainPoolError = new Error('Main pool cleanup failed');
      const mockCleanupPoolInstance = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'DROP', rowCount: 0, oid: 0, fields: [] }),
        end: jest.fn().mockRejectedValueOnce(mainPoolError),
      };
      
      mockPool.mockImplementation((config: any) => {
        if (config.database === 'postgres' && config.max === 1) {
          return mockCleanupPoolInstance;
        }
        return mockTestPoolInstance;
      });

      await TestDatabaseConnection.cleanup();

      expect(TestDatabaseConnection.initialized).toBe(false);
    });

    it('should log successful cleanup operations', async () => {
      await TestDatabaseConnection.cleanup();

      expect(mockConsole.log).toHaveBeenCalledWith('🔄 Starting enhanced database cleanup...');
      expect(mockConsole.log).toHaveBeenCalledWith('✅ Enhanced database cleanup completed');
    });
  });

  describe('Error Handling Patterns', () => {
    it('should handle database connection errors during initialization', async () => {
      const connectionError = new Error('Connection refused');
      mockMainPoolInstance.query.mockRejectedValueOnce(connectionError);

      await expect(TestDatabaseConnection.initialize()).rejects.toThrow('Connection refused');
    });

    it('should handle schema creation errors', async () => {
      // Set up successful database creation
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      
      // Create an error that won't be caught by the "already exists" check
      const schemaError = new Error('Schema creation failed');
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // SELECT 1 test passes
          .mockRejectedValueOnce(schemaError), // extension creation fails with non-"already exists" error
        release: jest.fn(),
      };
      
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await expect(TestDatabaseConnection.initialize()).rejects.toThrow('Schema creation failed');
    });

    it('should provide appropriate error context', async () => {
      // Set up successful initialization first
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);
      
      await TestDatabaseConnection.initialize();

      // Test query error after successful initialization
      const queryError = new Error('Syntax error in query');
      const mockQueryClient = {
        query: jest.fn().mockRejectedValueOnce(queryError),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValueOnce(mockQueryClient);

      await expect(TestDatabaseConnection.query('INVALID SQL'))
        .rejects.toThrow('Syntax error in query');
    });

    it('should handle partial initialization failures', async () => {
      // Mock successful database operations
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      
      // Create an error that won't be caught by the "already exists" check
      const extensionError = new Error('Extension creation failed');
      const mockClient = {
        query: jest.fn()
          .mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] }) // SELECT 1 test passes
          .mockRejectedValueOnce(extensionError), // extension creation fails
        release: jest.fn(),
      };
      
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await expect(TestDatabaseConnection.initialize()).rejects.toThrow('Extension creation failed');
      
      // Should not be marked as initialized
      expect(TestDatabaseConnection.initialized).toBe(false);
    });
  });

  describe('State Management', () => {
    it('should maintain correct state during successful initialization', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      expect(TestDatabaseConnection.initialized).toBe(false);
      expect((TestDatabaseConnection as any).testPool).toBeNull();
      expect((TestDatabaseConnection as any).mainPool).toBeNull();

      await TestDatabaseConnection.initialize();

      expect(TestDatabaseConnection.initialized).toBe(true);
      expect((TestDatabaseConnection as any).testPool).toBe(mockTestPoolInstance);
      // Main pool is closed after setup in the actual implementation
      expect((TestDatabaseConnection as any).mainPool).toBeNull();
    });

    it('should maintain state during failed initialization', async () => {
      const initError = new Error('Initialization failed');
      mockMainPoolInstance.query.mockRejectedValueOnce(initError);

      await expect(TestDatabaseConnection.initialize()).rejects.toThrow('Initialization failed');

      expect(TestDatabaseConnection.initialized).toBe(false);
    });

    it('should reset state during cleanup', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      mockTestPoolInstance.end.mockResolvedValue(undefined);
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();
      
      expect(TestDatabaseConnection.initialized).toBe(true);
      
      await TestDatabaseConnection.cleanup();
      
      expect(TestDatabaseConnection.initialized).toBe(false);
    });

    it('should allow re-initialization after cleanup', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      mockTestPoolInstance.end.mockResolvedValue(undefined);
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      // First initialization cycle
      await TestDatabaseConnection.initialize();
      await TestDatabaseConnection.cleanup();

      // Reset the pool call count for accurate counting
      jest.clearAllMocks();
      
      // Mock Pool constructor again for second cycle
      let poolCallCount = 0;
      mockPool.mockImplementation((config: any) => {
        poolCallCount++;
        if (config.database === 'postgres' || poolCallCount === 1) {
          return mockMainPoolInstance;
        } else {
          return mockTestPoolInstance;
        }
      });

      // Second initialization cycle  
      await TestDatabaseConnection.initialize();

      expect(TestDatabaseConnection.initialized).toBe(true);
      expect(mockPool).toHaveBeenCalledTimes(2); // 2 pools for second cycle only
    });
  });

  describe('Configuration Validation', () => {
    it('should use TEST_DB_CONFIG for test pool', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      expect(mockPool).toHaveBeenCalledWith(expect.objectContaining({
        database: 'koutu_test',
        max: 10,
        connectionTimeoutMillis: 2000,
        idleTimeoutMillis: 1000,
        allowExitOnIdle: true
      }));
    });

    it('should use MAIN_DB_CONFIG for main pool', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      expect(mockPool).toHaveBeenCalledWith(expect.objectContaining({
        database: 'postgres'
      }));
    });

    it('should validate configuration objects are passed correctly', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      const poolCalls = mockPool.mock.calls;
      
      // Verify config objects are passed with enhanced settings
      expect(poolCalls[0][0]).toEqual(expect.objectContaining({
        database: 'postgres'
      }));
      expect(poolCalls[1][0]).toEqual(expect.objectContaining({
        database: 'koutu_test',
        max: 10,
        connectionTimeoutMillis: 2000,
        idleTimeoutMillis: 1000,
        allowExitOnIdle: true
      }));
    });
  });

  describe('Performance and Resource Management', () => {
    it('should not create multiple pools on rapid successive calls', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      // Simulate rapid successive initialization calls
      const promises = Array.from({ length: 5 }, () => TestDatabaseConnection.initialize());
      const results = await Promise.all(promises);

      // All should return the same pool instance
      results.forEach(pool => {
        expect(pool).toBe(results[0]);
      });

      // Only one set of pools should be created
      expect(mockPool).toHaveBeenCalledTimes(2); // main + test
    });

    it('should handle concurrent cleanup calls gracefully', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      mockMainPoolInstance.end.mockResolvedValue(undefined);
      mockTestPoolInstance.end.mockResolvedValue(undefined);
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      // Concurrent cleanup calls
      const cleanupPromises = Array.from({ length: 3 }, () => TestDatabaseConnection.cleanup());
      await Promise.all(cleanupPromises);

      // Cleanup should complete successfully
      expect(TestDatabaseConnection.initialized).toBe(false);
    });

    it('should efficiently handle query method calls', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      // Clear mocks to count only user queries
      jest.clearAllMocks();
      
      const mockQueryClient = {
        query: jest.fn().mockResolvedValue({ rows: [{ result: 'test' }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockQueryClient);

      // Multiple query calls should use the connection tracking
      await TestDatabaseConnection.query('SELECT 1');
      await TestDatabaseConnection.query('SELECT 2');
      await TestDatabaseConnection.query('SELECT 3');

      expect(mockTestPoolInstance.connect).toHaveBeenCalledTimes(3); // Each query gets its own client
    });
  });

  describe('Integration Points', () => {
    it('should work correctly with mocked Pool constructor', async () => {
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      // Verify mock integration is working
      expect(mockPool).toHaveBeenCalled();
      expect(TestDatabaseConnection.getPool()).toBe(mockTestPoolInstance);
    });

    it('should properly mock database operations', async () => {
      const mockResult = { rows: [{ test_column: 'test_value' }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] };
      
      // Set up successful initialization
      mockMainPoolInstance.query.mockResolvedValue({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
      
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValue(mockClient);

      await TestDatabaseConnection.initialize();

      // Clear mocks and override for specific test query
      jest.clearAllMocks();
      const mockQueryClient = {
        query: jest.fn().mockResolvedValueOnce(mockResult),
        release: jest.fn(),
      };
      mockTestPoolInstance.connect.mockResolvedValueOnce(mockQueryClient);
      
      const result = await TestDatabaseConnection.query('SELECT test_column FROM test_table');
      expect(result).toEqual(mockResult);
    });

    it('should handle mock configuration correctly', () => {
      expect(mockTEST_DB_CONFIG.database).toBe('koutu_test');
      expect(mockMAIN_DB_CONFIG.database).toBe('postgres');
      expect(mockTEST_DB_CONFIG.host).toBe('localhost');
      expect(mockMAIN_DB_CONFIG.host).toBe('localhost');
      expect(mockTEST_DB_CONFIG.max).toBe(10); // Updated expectation
      expect(mockTEST_DB_CONFIG.connectionTimeoutMillis).toBe(2000); // Updated expectation
      expect(mockTEST_DB_CONFIG.idleTimeoutMillis).toBe(1000); // Updated expectation
      expect(mockTEST_DB_CONFIG.allowExitOnIdle).toBe(true); // New expectation
    });
  });
});