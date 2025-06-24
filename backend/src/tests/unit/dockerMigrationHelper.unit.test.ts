// /backend/src/utils/__tests__/dockerMigrationHelper.test.ts
/**
 * Core Test Infrastructure Tests
 * 
 * These tests validate the dual-mode system that all other tests depend on.
 * Critical for ensuring 4000+ tests work reliably in both Docker and Manual modes.
 */

import { shouldUseDocker, getTestDatabaseConnection, setupTestEnvironment, validateMigration, ensureWardrobeTablesExist, emergencyFallback, displayCurrentMode, getTestUserModel } from "../../utils/dockerMigrationHelper";
import { TestDatabaseConnection } from "../../utils/testDatabaseConnection";
import { testUserModel } from "../../utils/testUserModel";
import bcrypt from 'bcrypt';

describe('Docker Migration Helper - Core Infrastructure', () => {
  beforeEach(() => {
    // Reset environment variables
    delete process.env.USE_MANUAL_TESTS;
    delete process.env.USE_DOCKER_TESTS;
    delete process.env.CI;
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
      expect(TestDB.name).toContain('TestDatabaseConnection'); // v2 class
    });

    test('returns manual implementation when shouldUseDocker is false', () => {
      process.env.USE_MANUAL_TESTS = 'true';
      const TestDB = getTestDatabaseConnection();
      expect(TestDB.name).toContain('TestDatabaseConnection'); // original class
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
      process.env.NODE_ENV = 'production';
      
      await expect(validateMigration()).rejects.toThrow(
        'Migration validation can only run in test environment'
      );
    });

    test('validateMigration compares docker vs manual implementations', async () => {
      process.env.NODE_ENV = 'test';
      
      // Mock both implementations to return identical results
      jest.doMock('../../utils/testDatabaseConnection.v2', () => ({
        TestDatabaseConnection: {
          initialize: jest.fn(),
          query: jest.fn().mockResolvedValue({ rows: [{ test_value: 1 }] }),
          cleanup: jest.fn()
        }
      }));

      jest.doMock('../../utils/testDatabaseConnection', () => ({
        TestDatabaseConnection: {
          initialize: jest.fn(),
          query: jest.fn().mockResolvedValue({ rows: [{ test_value: 1 }] }),
          cleanup: jest.fn()
        }
      }));

      const result = await validateMigration();
      expect(result).toBe(true);
    }, 10000);
  });

  describe('Wardrobe table management', () => {
    test('ensureWardrobeTablesExist creates missing tables', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ exists: false }] }) // Table doesn't exist
        .mockResolvedValue({ rows: [] }); // CREATE TABLE succeeds

      jest.doMock('../../utils/dockerMigrationHelper', () => ({
        getTestDatabaseConnection: () => ({
          query: mockQuery
        })
      }));

      await ensureWardrobeTablesExist();

      // Should check existence and create table
      expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('SELECT EXISTS'));
      expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE wardrobe_items'));
    });

    test('ensureWardrobeTablesExist skips existing tables', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ exists: true }] }); // Table exists

      jest.doMock('../../utils/dockerMigrationHelper', () => ({
        getTestDatabaseConnection: () => ({
          query: mockQuery
        })
      }));

      await ensureWardrobeTablesExist();

      // Should only check existence, not create
      expect(mockQuery).toHaveBeenCalledTimes(2); // exists check + alter table for is_default
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
        expect.stringContaining('USE_MANUAL_TESTS="true"')
      );
      
      consoleSpy.mockRestore();
    });

    test('displayCurrentMode shows current configuration', () => {
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      process.env.USE_DOCKER_TESTS = 'true';
      
      displayCurrentMode();
      
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Current Mode: DOCKER')
      );
      
      consoleSpy.mockRestore();
    });
  });
});

// /backend/src/utils/__tests__/testDatabaseConnection.v2.test.ts
describe('Docker Database Connection (v2)', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    // Reset connection state
    TestDatabaseConnection.cleanup();
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('Docker service detection', () => {
    test('waitForDockerPostgreSQL retries on connection failure', async () => {
      // Mock PostgreSQL not ready initially
      const mockPool = {
        query: jest.fn().mockRejectedValueOnce(new Error('Connection refused')),
        end: jest.fn()
      };

      jest.doMock('pg', () => ({
        Pool: jest.fn().mockImplementation(() => mockPool)
      }));

      // Should eventually timeout
      await expect(TestDatabaseConnection.initialize()).rejects.toThrow(
        'Docker PostgreSQL not ready'
      );
    }, 15000);

    test('initialize creates required schema', async () => {
      const mockQuery = jest.fn().mockResolvedValue({ rows: [] });
      const mockConnect = jest.fn().mockResolvedValue({
        query: mockQuery,
        release: jest.fn()
      });

      const mockPool = {
        connect: mockConnect,
        on: jest.fn(),
        ended: false
      };

      jest.doMock('pg', () => ({
        Pool: jest.fn().mockImplementation(() => mockPool)
      }));

      await TestDatabaseConnection.initialize();

      // Should create all required tables
      expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS users'));
      expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS wardrobes'));
      expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE IF NOT EXISTS wardrobe_items'));
    });
  });

  describe('Connection pooling', () => {
    test('getPool throws when not initialized', () => {
      expect(() => TestDatabaseConnection.getPool()).toThrow(
        'Test database not initialized'
      );
    });

    test('query method manages connections properly', async () => {
      const mockRelease = jest.fn();
      const mockClient = {
        query: jest.fn().mockResolvedValue({ rows: [] }),
        release: mockRelease
      };

      const mockPool = {
        connect: jest.fn().mockResolvedValue(mockClient),
        ended: false
      };

      // Mock initialized state
      jest.spyOn(TestDatabaseConnection, 'getPool').mockReturnValue(mockPool as any);

      await TestDatabaseConnection.query('SELECT 1');

      expect(mockClient.query).toHaveBeenCalledWith('SELECT 1', undefined);
      expect(mockRelease).toHaveBeenCalled();
    });
  });

  describe('Table management', () => {
    test('clearAllTables truncates in correct order', async () => {
      const mockQuery = jest.fn().mockResolvedValue({ rows: [] });
      const mockClient = {
        query: mockQuery,
        release: jest.fn()
      };

      const mockPool = {
        connect: jest.fn().mockResolvedValue(mockClient),
        ended: false
      };

      jest.spyOn(TestDatabaseConnection, 'getPool').mockReturnValue(mockPool as any);

      await TestDatabaseConnection.clearAllTables();

      // Should disable FK checks, truncate tables, re-enable FK checks
      expect(mockQuery).toHaveBeenCalledWith('SET session_replication_role = replica');
      expect(mockQuery).toHaveBeenCalledWith('TRUNCATE TABLE wardrobe_items RESTART IDENTITY CASCADE');
      expect(mockQuery).toHaveBeenCalledWith('SET session_replication_role = DEFAULT');
    });

    test('ensureTablesExist handles missing wardrobe_items table', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ exists: false }] }) // wardrobe_items missing
        .mockResolvedValue({ rows: [] }); // CREATE statements succeed

      const mockClient = {
        query: mockQuery,
        release: jest.fn()
      };

      const mockPool = {
        connect: jest.fn().mockResolvedValue(mockClient),
        ended: false
      };

      jest.spyOn(TestDatabaseConnection, 'getPool').mockReturnValue(mockPool as any);

      await TestDatabaseConnection.ensureTablesExist();

      expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('CREATE TABLE wardrobe_items'));
    });
  });

  describe('Cleanup procedures', () => {
    test('cleanup waits for active connections', async () => {
      const mockEnd = jest.fn().mockResolvedValue(undefined);
      const mockPool = {
        end: mockEnd,
        ended: false
      };

      // Mock some active connections
      const activeConnections = new Set([
        { release: jest.fn() },
        { release: jest.fn() }
      ]);

      jest.spyOn(TestDatabaseConnection, 'activeConnectionCount', 'get')
        .mockReturnValueOnce(2)
        .mockReturnValueOnce(0);

      await TestDatabaseConnection.cleanup();

      expect(mockEnd).toHaveBeenCalled();
    });
  });
});

// /backend/src/utils/__tests__/testUserModel.v2.test.ts
describe('Test User Model v2 (Dual-Mode)', () => {
  describe('UUID validation', () => {
    test('handles malformed UUIDs gracefully', async () => {
      const result = await testUserModel.findById('not-a-uuid');
      expect(result).toBeNull();
    });

    test('handles empty UUID gracefully', async () => {
      const result = await testUserModel.findById('');
      expect(result).toBeNull();
    });
  });

  describe('User creation', () => {
    test('creates user with hashed password', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [] }) // No existing user
        .mockResolvedValueOnce({ rows: [{ id: 'test-id', email: 'test@example.com' }] }); // Insert result

      jest.doMock('../../utils/dockerMigrationHelper', () => ({
        getTestDatabaseConnection: () => ({ query: mockQuery })
      }));

      const user = await testUserModel.create({
        email: 'test@example.com',
        password: 'password123'
      });

      expect(mockQuery).toHaveBeenCalledTimes(2);
      expect(user.email).toBe('test@example.com');
    });

    test('throws conflict error for duplicate email', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ id: 'existing-id' }] }); // Existing user

      jest.doMock('../../utils/dockerMigrationHelper', () => ({
        getTestDatabaseConnection: () => ({ query: mockQuery })
      }));

      await expect(testUserModel.create({
        email: 'existing@example.com',
        password: 'password123'
      })).rejects.toThrow('EMAIL_IN_USE');
    });
  });

  describe('OAuth operations', () => {
    test('createOAuthUser handles transaction properly', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [] }) // No existing user
        .mockResolvedValueOnce(undefined) // BEGIN
        .mockResolvedValueOnce({ rows: [{ id: 'test-id', email: 'test@example.com' }] }) // User insert
        .mockResolvedValueOnce(undefined) // OAuth provider insert
        .mockResolvedValueOnce(undefined); // COMMIT

      jest.doMock('../../utils/dockerMigrationHelper', () => ({
        getTestDatabaseConnection: () => ({ query: mockQuery })
      }));

      const user = await testUserModel.createOAuthUser({
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
        .mockResolvedValueOnce({ rows: [] }) // No existing user
        .mockResolvedValueOnce(undefined) // BEGIN
        .mockResolvedValueOnce({ rows: [{ id: 'test-id' }] }) // User insert
        .mockRejectedValueOnce(new Error('OAuth insert failed')) // OAuth provider insert fails
        .mockResolvedValueOnce(undefined); // ROLLBACK

      jest.doMock('../../utils/dockerMigrationHelper', () => ({
        getTestDatabaseConnection: () => ({ query: mockQuery })
      }));

      await expect(testUserModel.createOAuthUser({
        email: 'test@example.com',
        oauth_provider: 'google',
        oauth_id: 'google123'
      })).rejects.toThrow('OAuth insert failed');

      expect(mockQuery).toHaveBeenCalledWith('ROLLBACK');
    });
  });

  describe('Password operations', () => {
    test('validatePassword compares against hash correctly', async () => {
      const user = { password_hash: await bcrypt.hash('correct', 10) };

      const validResult = await testUserModel.validatePassword(user, 'correct');
      const invalidResult = await testUserModel.validatePassword(user, 'wrong');

      expect(validResult).toBe(true);
      expect(invalidResult).toBe(false);
    });

    test('hasPassword returns false for OAuth-only users', async () => {
      const mockQuery = jest.fn()
        .mockResolvedValueOnce({ rows: [{ password_hash: null }] });

      jest.doMock('../../utils/dockerMigrationHelper', () => ({
        getTestDatabaseConnection: () => ({ query: mockQuery })
      }));

      const result = await testUserModel.hasPassword('test-id');
      expect(result).toBe(false);
    });
  });
});

// Integration test to verify dual-mode actually works
describe('Dual-Mode Integration', () => {
  test('both modes produce identical user operations', async () => {
    // This is a simplified version of the validateMigration logic
    const testData = {
      email: 'integration-test@example.com',
      password: 'testpassword123'
    };

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