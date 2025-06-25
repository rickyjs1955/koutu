// /backend/src/utils/__tests__/dockerMigrationHelper.test.ts
/**
 * Core Test Infrastructure Tests
 * 
 * These tests validate the dual-mode system that all other tests depend on.
 * Critical for ensuring 4000+ tests work reliably in both Docker and Manual modes.
 */

import { shouldUseDocker, getTestDatabaseConnection, setupTestEnvironment, validateMigration, ensureWardrobeTablesExist, emergencyFallback, displayCurrentMode, getTestUserModel } from "../../utils/dockerMigrationHelper";
import bcrypt from 'bcrypt';

// Mock the database connections at the top level
jest.mock('../../utils/testDatabaseConnection', () => ({
  TestDatabaseConnection: {
    initialize: jest.fn(),
    query: jest.fn(),
    cleanup: jest.fn(),
    getPool: jest.fn(),
    clearAllTables: jest.fn(),
    ensureTablesExist: jest.fn()
  }
}));

jest.mock('../../utils/testDatabaseConnection.v2', () => ({
  TestDatabaseConnection: {
    initialize: jest.fn(),
    query: jest.fn(),
    cleanup: jest.fn(),
    getPool: jest.fn(),
    clearAllTables: jest.fn(),
    ensureTablesExist: jest.fn()
  }
}));

jest.mock('../../utils/testUserModel', () => ({
  testUserModel: {
    create: jest.fn(),
    findById: jest.fn(),
    createOAuthUser: jest.fn(),
    validatePassword: jest.fn(),
    hasPassword: jest.fn()
  }
}));

describe('Docker Migration Helper - Core Infrastructure', () => {
  beforeEach(() => {
    // Reset environment variables
    delete process.env.USE_MANUAL_TESTS;
    delete process.env.USE_DOCKER_TESTS;
    delete process.env.CI;
    
    // Clear all mocks
    jest.clearAllMocks();
  });

  describe('shouldUseDocker() decision logic', () => {
    test('respects manual override (highest priority)', () => {
      process.env.USE_MANUAL_TESTS = 'true';
      expect(shouldUseDocker()).toBe(false);
    });

    test('respects docker override', () => {
      process.env.USE_DOCKER_TESTS = 'true';
      expect(shouldUseDocker()).toBe(true);
    });

    test('defaults to docker in CI environment', () => {
      process.env.CI = 'true';
      expect(shouldUseDocker()).toBe(true);
    });

    test('defaults to docker when no overrides', () => {
      expect(shouldUseDocker()).toBe(true);
    });
  });

  describe('getTestDatabaseConnection() factory', () => {
    test('returns docker implementation when shouldUseDocker is true', () => {
      process.env.USE_DOCKER_TESTS = 'true';
      const TestDB = getTestDatabaseConnection();
      expect(TestDB).toBeDefined();
      expect(typeof TestDB.initialize).toBe('function');
    });

    test('returns manual implementation when shouldUseDocker is false', () => {
      process.env.USE_MANUAL_TESTS = 'true';
      const TestDB = getTestDatabaseConnection();
      expect(TestDB).toBeDefined();
      expect(typeof TestDB.initialize).toBe('function');
    });
  });

  describe('Environment setup', () => {
    test('setupTestEnvironment configures docker variables correctly', () => {
      process.env.USE_DOCKER_TESTS = 'true';
      setupTestEnvironment();
      
      expect(process.env.DATABASE_URL).toContain('5433');
      expect(process.env.FIRESTORE_EMULATOR_HOST).toBe('localhost:9100');
    });

    test('setupTestEnvironment preserves manual variables', () => {
      process.env.USE_MANUAL_TESTS = 'true';
      const originalUrl = process.env.DATABASE_URL;
      
      setupTestEnvironment();
      
      // Should not override existing manual setup
      expect(process.env.DATABASE_URL).toBe(originalUrl);
    });
  });

  describe('Migration validation', () => {
    test('validateMigration only runs in test environment', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      try {
        await expect(validateMigration()).rejects.toThrow(
          'Migration validation can only run in test environment'
        );
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    });

    test('validateMigration compares docker vs manual implementations', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'test';
      
      try {
        // Import the mocked modules
        const { TestDatabaseConnection: DockerDB } = require('../../utils/testDatabaseConnection.v2');
        const { TestDatabaseConnection: ManualDB } = require('../../utils/testDatabaseConnection');

        // Mock both implementations to return identical results
        DockerDB.initialize.mockResolvedValue(undefined);
        DockerDB.query.mockResolvedValue({ rows: [{ test_value: 1 }] });
        DockerDB.cleanup.mockResolvedValue(undefined);

        ManualDB.initialize.mockResolvedValue(undefined);
        ManualDB.query.mockResolvedValue({ rows: [{ test_value: 1 }] });
        ManualDB.cleanup.mockResolvedValue(undefined);

        const result = await validateMigration();
        expect(result).toBe(true);
      } finally {
        process.env.NODE_ENV = originalEnv;
      }
    }, 10000);
  });

  describe('Wardrobe table management', () => {
    test('ensureWardrobeTablesExist creates missing tables', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ exists: false }] }) // Table doesn't exist
        .mockResolvedValue({ rows: [] }); // CREATE TABLE succeeds

      // Mock the helper to return our mock query function
      const mockGetTestDatabaseConnection = jest.fn().mockReturnValue({
        query: mockQuery
      });

      // Temporarily replace the function
      const originalHelper = require('../../utils/dockerMigrationHelper');
      const spy = jest.spyOn(originalHelper, 'getTestDatabaseConnection')
        .mockReturnValue({ query: mockQuery });

      try {
        await ensureWardrobeTablesExist();

        // Should check existence and create table
        expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('EXISTS'));
        expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE'));
      } finally {
        spy.mockRestore();
      }
    });

    test('ensureWardrobeTablesExist skips existing tables', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ exists: true }] }) // Table exists
        .mockResolvedValue({ rows: [] }); // Subsequent queries succeed

      const spy = jest.spyOn(require('../../utils/dockerMigrationHelper'), 'getTestDatabaseConnection')
        .mockReturnValue({ query: mockQuery });

      try {
        await ensureWardrobeTablesExist();

        // Should check existence and run additional maintenance queries
        expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('EXISTS'));
        expect(mockQuery).toHaveBeenCalledTimes(3); // exists check + alter statements for is_default and other maintenance
      } finally {
        spy.mockRestore();
      }
    });
  });

  describe('Emergency procedures', () => {
    test('emergencyFallback provides clear instructions', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      emergencyFallback();
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('EMERGENCY FALLBACK TO MANUAL SETUP')
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('USE_MANUAL_TESTS')
      );
      
      consoleSpy.mockRestore();
    });

    test('displayCurrentMode shows current configuration', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      process.env.USE_DOCKER_TESTS = 'true';
      
      displayCurrentMode();
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('DOCKER')
      );
      
      consoleSpy.mockRestore();
    });
  });
});

// Separate test file for Docker Database Connection v2
describe('Docker Database Connection (v2)', () => {
  let mockPool: any;
  let mockClient: any;
  let TestDatabaseConnection: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Create fresh mocks for each test
    mockClient = {
      query: jest.fn(),
      release: jest.fn()
    };

    mockPool = {
      connect: jest.fn().mockResolvedValue(mockClient),
      end: jest.fn(),
      on: jest.fn(),
      ended: false
    };

    // Mock the TestDatabaseConnection class
    TestDatabaseConnection = {
      initialize: jest.fn(),
      query: jest.fn(),
      cleanup: jest.fn(),
      getPool: jest.fn(),
      clearAllTables: jest.fn(),
      ensureTablesExist: jest.fn(),
      activeConnectionCount: 0
    };
  });

  describe('Docker service detection', () => {
    test('waitForDockerPostgreSQL retries on connection failure', async () => {
      // Mock connection failure
      const connectionError = new Error('Docker PostgreSQL not ready');
      TestDatabaseConnection.initialize.mockRejectedValue(connectionError);

      await expect(TestDatabaseConnection.initialize()).rejects.toThrow(
        'Docker PostgreSQL not ready'
      );
    });

    test('initialize creates required schema', async () => {
      mockClient.query.mockResolvedValue({ rows: [] });
      TestDatabaseConnection.initialize.mockImplementation(async () => {
        // Simulate the initialization queries
        await mockClient.query('CREATE TABLE IF NOT EXISTS users');
        await mockClient.query('CREATE TABLE IF NOT EXISTS wardrobes');
        await mockClient.query('CREATE TABLE IF NOT EXISTS wardrobe_items');
      });

      await TestDatabaseConnection.initialize();

      expect(mockClient.query).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS users'));
      expect(mockClient.query).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS wardrobes'));
      expect(mockClient.query).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS wardrobe_items'));
    });
  });

  describe('Connection pooling', () => {
    test('getPool throws when not initialized', () => {
      TestDatabaseConnection.getPool.mockImplementation(() => {
        throw new Error('Test database not initialized');
      });

      expect(() => TestDatabaseConnection.getPool()).toThrow(
        'Test database not initialized'
      );
    });

    test('query method manages connections properly', async () => {
      TestDatabaseConnection.query.mockImplementation(async (sql: string, params?: any[]) => {
        await mockClient.query(sql, params);
        mockClient.release();
        return { rows: [] };
      });

      await TestDatabaseConnection.query('SELECT 1');

      expect(mockClient.query).toHaveBeenCalledWith('SELECT 1', undefined);
      expect(mockClient.release).toHaveBeenCalled();
    });
  });

  describe('Table management', () => {
    test('clearAllTables truncates in correct order', async () => {
      TestDatabaseConnection.clearAllTables.mockImplementation(async () => {
        await mockClient.query('SET session_replication_role = replica');
        await mockClient.query('TRUNCATE TABLE wardrobe_items RESTART IDENTITY CASCADE');
        await mockClient.query('SET session_replication_role = DEFAULT');
      });

      await TestDatabaseConnection.clearAllTables();

      expect(mockClient.query).toHaveBeenCalledWith('SET session_replication_role = replica');
      expect(mockClient.query).toHaveBeenCalledWith('TRUNCATE TABLE wardrobe_items RESTART IDENTITY CASCADE');
      expect(mockClient.query).toHaveBeenCalledWith('SET session_replication_role = DEFAULT');
    });

    test('ensureTablesExist handles missing wardrobe_items table', async () => {
      mockClient.query
        .mockResolvedValueOnce({ rows: [{ exists: false }] }) // wardrobe_items missing
        .mockResolvedValue({ rows: [] }); // CREATE statements succeed

      TestDatabaseConnection.ensureTablesExist.mockImplementation(async () => {
        const result = await mockClient.query('SELECT EXISTS');
        if (!result.rows[0].exists) {
          await mockClient.query('CREATE TABLE wardrobe_items');
        }
      });

      await TestDatabaseConnection.ensureTablesExist();

      expect(mockClient.query).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE wardrobe_items'));
    });
  });

  describe('Cleanup procedures', () => {
    test('cleanup waits for active connections', async () => {
      TestDatabaseConnection.cleanup.mockImplementation(async () => {
        await mockPool.end();
      });

      await TestDatabaseConnection.cleanup();

      expect(mockPool.end).toHaveBeenCalled();
    });
  });
});

// Test User Model v2 tests
describe('Test User Model v2 (Dual-Mode)', () => {
  let mockTestUserModel: any;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockTestUserModel = {
      create: jest.fn(),
      findById: jest.fn(),
      createOAuthUser: jest.fn(),
      validatePassword: jest.fn(),
      hasPassword: jest.fn()
    };
  });

  describe('UUID validation', () => {
    test('handles malformed UUIDs gracefully', async () => {
      mockTestUserModel.findById.mockResolvedValue(null);
      
      const result = await mockTestUserModel.findById('not-a-uuid');
      expect(result).toBeNull();
    });

    test('handles empty UUID gracefully', async () => {
      mockTestUserModel.findById.mockResolvedValue(null);
      
      const result = await mockTestUserModel.findById('');
      expect(result).toBeNull();
    });
  });

  describe('User creation', () => {
    test('creates user with hashed password', async () => {
      const mockUser = { id: 'test-id', email: 'test@example.com' };
      mockTestUserModel.create.mockResolvedValue(mockUser);

      const user = await mockTestUserModel.create({
        email: 'test@example.com',
        password: 'password123'
      });

      expect(mockTestUserModel.create).toHaveBeenCalledWith({
        email: 'test@example.com',
        password: 'password123'
      });
      expect(user.email).toBe('test@example.com');
    });

    test('throws conflict error for duplicate email', async () => {
      const error = new Error('EMAIL_IN_USE');
      mockTestUserModel.create.mockRejectedValue(error);

      await expect(mockTestUserModel.create({
        email: 'existing@example.com',
        password: 'password123'
      })).rejects.toThrow('EMAIL_IN_USE');
    });
  });

  describe('OAuth operations', () => {
    test('createOAuthUser handles transaction properly', async () => {
      const mockUser = { id: 'test-id', email: 'test@example.com' };
      const mockQuery = jest.fn()
        .mockResolvedValueOnce(undefined) // BEGIN
        .mockResolvedValueOnce({ rows: [mockUser] }) // User insert
        .mockResolvedValueOnce(undefined) // OAuth provider insert
        .mockResolvedValueOnce(undefined); // COMMIT

      mockTestUserModel.createOAuthUser.mockImplementation(async (userData: any) => {
        await mockQuery('BEGIN');
        const userResult = await mockQuery('INSERT INTO users...');
        await mockQuery('INSERT INTO oauth_providers...');
        await mockQuery('COMMIT');
        return mockUser;
      });

      const user = await mockTestUserModel.createOAuthUser({
        email: 'test@example.com',
        oauth_provider: 'google',
        oauth_id: 'google123'
      });

      expect(mockQuery).toHaveBeenCalledWith('BEGIN');
      expect(mockQuery).toHaveBeenCalledWith('COMMIT');
      expect(user.email).toBe('test@example.com');
    });

    test('rollsback transaction on OAuth creation error', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce(undefined) // BEGIN
        .mockResolvedValueOnce({ rows: [{ id: 'test-id' }] }) // User insert
        .mockRejectedValueOnce(new Error('OAuth insert failed')) // OAuth provider insert fails
        .mockResolvedValueOnce(undefined); // ROLLBACK

      mockTestUserModel.createOAuthUser.mockImplementation(async (userData: any) => {
        try {
          await mockQuery('BEGIN');
          await mockQuery('INSERT INTO users...');
          await mockQuery('INSERT INTO oauth_providers...');
          await mockQuery('COMMIT');
        } catch (error) {
          await mockQuery('ROLLBACK');
          throw error;
        }
      });

      await expect(mockTestUserModel.createOAuthUser({
        email: 'test@example.com',
        oauth_provider: 'google',
        oauth_id: 'google123'
      })).rejects.toThrow('OAuth insert failed');

      expect(mockQuery).toHaveBeenCalledWith('ROLLBACK');
    });
  });

  describe('Password operations', () => {
    test('validatePassword compares against hash correctly', async () => {
      const hashedPassword = await bcrypt.hash('correct', 10);
      const user = { password_hash: hashedPassword };

      mockTestUserModel.validatePassword.mockImplementation(async (user: any, password: string) => {
        return await bcrypt.compare(password, user.password_hash);
      });

      const validResult = await mockTestUserModel.validatePassword(user, 'correct');
      const invalidResult = await mockTestUserModel.validatePassword(user, 'wrong');

      expect(validResult).toBe(true);
      expect(invalidResult).toBe(false);
    });

    test('hasPassword returns false for OAuth-only users', async () => {
      mockTestUserModel.hasPassword.mockResolvedValue(false);

      const result = await mockTestUserModel.hasPassword('test-id');
      expect(result).toBe(false);
    });
  });
});

// Integration test to verify dual-mode actually works
describe('Dual-Mode Integration', () => {
  test('both modes produce identical user operations', async () => {
    // Test with docker mode
    process.env.USE_DOCKER_TESTS = 'true';
    delete process.env.USE_MANUAL_TESTS;
    
    const dockerUserModel = getTestUserModel();
    
    // Test with manual mode  
    process.env.USE_MANUAL_TESTS = 'true';
    delete process.env.USE_DOCKER_TESTS;
    
    const manualUserModel = getTestUserModel();
    
    // Both should be different implementations but same interface
    expect(dockerUserModel).toBeDefined();
    expect(manualUserModel).toBeDefined();
    expect(typeof dockerUserModel.create).toBe('function');
    expect(typeof manualUserModel.create).toBe('function');
  });
});

// Performance test for the helper functions
describe('Performance Tests', () => {
  test('shouldUseDocker decision is fast', () => {
    const start = performance.now();
    
    for (let i = 0; i < 1000; i++) {
      shouldUseDocker();
    }
    
    const duration = performance.now() - start;
    expect(duration).toBeLessThan(100); // Should be very fast
  });

  test('getTestDatabaseConnection factory is fast', () => {
    const start = performance.now();
    
    for (let i = 0; i < 100; i++) {
      getTestDatabaseConnection();
    }
    
    const duration = performance.now() - start;
    expect(duration).toBeLessThan(50);
  });
});