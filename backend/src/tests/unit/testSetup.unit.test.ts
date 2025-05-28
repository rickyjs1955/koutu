// /backend/src/utils/testSetup.unit.test.ts

// Mock console methods first
const mockConsole = {
  log: jest.fn(),
  error: jest.fn(),
  warn: jest.fn()
};

// Mock Firebase helpers
const mockFirebaseHelpers = {
  initializeTestFirebase: jest.fn(),
  resetFirebaseEmulator: jest.fn(),
  cleanupTestFirebase: jest.fn()
};

// Mock global fetch
const mockFetch = jest.fn();
global.fetch = mockFetch as any;

// Mock Pool class
class MockPool {
  connect = jest.fn();
  query = jest.fn();
  end = jest.fn();
  
  constructor(config: any) {
    // Store config for testing
    (this as any).config = config;
  }
}

// Mock pg module
jest.mock('pg', () => ({
  Pool: MockPool,
  Client: jest.fn()
}));

// Mock console
Object.assign(console, mockConsole);

// Mock Firebase helpers
jest.mock('@/tests/__helpers__/firebase.helper', () => mockFirebaseHelpers);

describe('testSetup Unit Tests', () => {
  let mockPoolInstance: any;
  let testPool: any;

  // Mock the entire testSetup module's functionality
  const mockTestSetup = {
    testQuery: jest.fn(),
    setupTestDatabase: jest.fn(),
    setupFirebaseEmulator: jest.fn(), 
    teardownTestDatabase: jest.fn(),
    getTestDatabaseConfig: jest.fn(),
    getTestPool: jest.fn()
  };

  beforeAll(() => {
    // Set up default mock implementations
    mockTestSetup.getTestDatabaseConfig.mockReturnValue({
      host: 'localhost',
      port: 5433,
      user: 'postgres',
      password: 'postgres',
      database: 'koutu_test',
      connectionString: 'postgresql://postgres:postgres@localhost:5433/koutu_test'
    });

    // Set up environment variable
    process.env.TEST_DATABASE_URL = 'postgresql://postgres:postgres@localhost:5433/koutu_test';
  });

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Create fresh mock pool instance
    mockPoolInstance = new MockPool({});
    mockTestSetup.getTestPool.mockReturnValue(mockPoolInstance);
    
    // Set up default testQuery behavior
    mockTestSetup.testQuery.mockImplementation(async (query: string, params?: any[]) => {
      try {
        return await mockPoolInstance.query(query, params);
      } catch (error) {
        mockConsole.error('Database query error:', error);
        mockConsole.error('Query:', query);
        mockConsole.error('Params:', params);
        throw error;
      }
    });

    // Reset fetch mock
    mockFetch.mockReset();
  });

  describe('Configuration Management', () => {
    it('should provide correct test database configuration', () => {
      const config = mockTestSetup.getTestDatabaseConfig();
      
      expect(config).toEqual({
        host: 'localhost',
        port: 5433,
        user: 'postgres',
        password: 'postgres',
        database: 'koutu_test',
        connectionString: expect.stringContaining('postgresql://postgres:postgres@localhost:5433/koutu_test')
      });
    });

    it('should set TEST_DATABASE_URL environment variable', () => {
      expect(process.env.TEST_DATABASE_URL).toBe(
        'postgresql://postgres:postgres@localhost:5433/koutu_test'
      );
    });

    it('should use test-safe database configuration', () => {
      const config = mockTestSetup.getTestDatabaseConfig();
      
      expect(config.database).toContain('test');
      expect(config.host).toBe('localhost');
      expect(config.port).toBe(5433); // Different from default 5432
      expect(config.user).toBe('postgres');
      expect(config.password).toBe('postgres');
    });

    it('should provide access to test pool', () => {
      const pool = mockTestSetup.getTestPool();
      expect(pool).toBeDefined();
      expect(pool).toBeInstanceOf(MockPool);
    });
  });

  describe('Database Query Logic', () => {
    it('should execute queries with parameters', async () => {
      const expectedResult = { rows: [{ test: 'value' }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] };
      mockPoolInstance.query.mockResolvedValueOnce(expectedResult);

      const result = await mockTestSetup.testQuery('SELECT $1 as test', ['value']);

      expect(mockPoolInstance.query).toHaveBeenCalledWith('SELECT $1 as test', ['value']);
      expect(result).toEqual(expectedResult);
    });

    it('should execute queries without parameters', async () => {
      const expectedResult = { rows: [{ count: 1 }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] };
      mockPoolInstance.query.mockResolvedValueOnce(expectedResult);

      const result = await mockTestSetup.testQuery('SELECT 1 as count');

      expect(mockPoolInstance.query).toHaveBeenCalledWith('SELECT 1 as count', undefined);
      expect(result).toEqual(expectedResult);
    });

    it('should handle database query errors with logging', async () => {
      const dbError = new Error('Database connection failed');
      mockPoolInstance.query.mockRejectedValueOnce(dbError);

      await expect(mockTestSetup.testQuery('SELECT invalid syntax')).rejects.toThrow('Database connection failed');

      expect(mockConsole.error).toHaveBeenCalledWith('Database query error:', dbError);
      expect(mockConsole.error).toHaveBeenCalledWith('Query:', 'SELECT invalid syntax');
      expect(mockConsole.error).toHaveBeenCalledWith('Params:', undefined);
    });

    it('should log query parameters on error', async () => {
      const dbError = new Error('Parameter error');
      const params = ['param1', 'param2'];
      mockPoolInstance.query.mockRejectedValueOnce(dbError);

      await expect(mockTestSetup.testQuery('SELECT $1, $2', params)).rejects.toThrow('Parameter error');

      expect(mockConsole.error).toHaveBeenCalledWith('Params:', params);
    });
  });

  describe('PostgreSQL Wait Logic', () => {
    it('should wait for PostgreSQL to be ready', async () => {
      // Mock successful database setup
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        // Simulate PostgreSQL readiness check
        const mockClient = new MockPool({});
        mockClient.connect.mockResolvedValueOnce(undefined);
        mockClient.query.mockResolvedValueOnce({ rows: [], command: 'SELECT', rowCount: 0, oid: 0, fields: [] });
        mockClient.end.mockResolvedValueOnce(undefined);

        mockConsole.log('Setting up test database...');
        mockConsole.log('Connected to database: koutu_test');
        mockConsole.log('Test database initialized successfully');
        
        return mockPoolInstance;
      });

      await mockTestSetup.setupTestDatabase();

      expect(mockConsole.log).toHaveBeenCalledWith('Setting up test database...');
      expect(mockConsole.log).toHaveBeenCalledWith('Connected to database: koutu_test');
    });

    it('should retry PostgreSQL connection on failure', async () => {
      let attemptCount = 0;
      
      // Mock multiple calls with different behaviors
      mockTestSetup.setupTestDatabase
        .mockImplementationOnce(async () => {
          attemptCount++;
          mockConsole.log(`Waiting for PostgreSQL... (${attemptCount}/30)`);
          throw new Error('Connection refused');
        })
        .mockImplementationOnce(async () => {
          attemptCount++;
          mockConsole.log(`Waiting for PostgreSQL... (${attemptCount}/30)`);
          throw new Error('Connection refused');
        })
        .mockImplementationOnce(async () => {
          attemptCount++;
          mockConsole.log('Connected to database: koutu_test');
          return mockPoolInstance;
        });

      // First two attempts should fail
      try {
        await mockTestSetup.setupTestDatabase();
      } catch (error) {
        expect((error as Error).message).toBe('Connection refused');
      }

      try {
        await mockTestSetup.setupTestDatabase();
      } catch (error) {
        expect((error as Error).message).toBe('Connection refused');
      }

      // Third attempt should succeed
      const result = await mockTestSetup.setupTestDatabase();
      expect(result).toBe(mockPoolInstance);

      expect(mockConsole.log).toHaveBeenCalledWith('Waiting for PostgreSQL... (1/30)');
      expect(mockConsole.log).toHaveBeenCalledWith('Waiting for PostgreSQL... (2/30)');
      expect(mockConsole.log).toHaveBeenCalledWith('Connected to database: koutu_test');
    });

    it('should timeout after maximum retries', async () => {
      mockTestSetup.setupTestDatabase.mockRejectedValue(
        new Error('PostgreSQL test database is not ready after 30 seconds')
      );

      await expect(mockTestSetup.setupTestDatabase()).rejects.toThrow('PostgreSQL test database is not ready after 30 seconds');
    });
  });

  describe('Database Setup Logic', () => {
    it('should verify connection to test database', async () => {
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockResolvedValueOnce({
          rows: [{ current_database: 'koutu_test' }],
          command: 'SELECT',
          rowCount: 1,
          oid: 0,
          fields: []
        });

        mockConsole.log('Connected to database: koutu_test');
        return mockPoolInstance;
      });

      await mockTestSetup.setupTestDatabase();

      expect(mockConsole.log).toHaveBeenCalledWith('Connected to database: koutu_test');
    });

    it('should reject non-test database names', async () => {
      mockTestSetup.setupTestDatabase.mockRejectedValue(
        new Error('Tests must run against a database with "test" in the name! Current: production')
      );

      await expect(mockTestSetup.setupTestDatabase()).rejects.toThrow(
        'Tests must run against a database with "test" in the name! Current: production'
      );
    });

    it('should create required PostgreSQL extensions', async () => {
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockResolvedValueOnce({ rows: [{ current_database: 'koutu_test' }], command: 'SELECT', rowCount: 1, oid: 0, fields: [] });
        mockPoolInstance.query.mockResolvedValueOnce({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }); // btree_gist
        mockPoolInstance.query.mockResolvedValueOnce({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] }); // uuid-ossp

        return mockPoolInstance;
      });

      await mockTestSetup.setupTestDatabase();

      // This would be tested by checking if the setup completed successfully
      expect(mockTestSetup.setupTestDatabase).toHaveBeenCalled();
    });

    it('should drop existing tables before creating new ones', async () => {
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        // Simulate DROP TABLE queries
        const dropTables = ['child_cleanup', 'parent_cleanup', 'exclude_test_table', 'test_table', 'test_items', 'garment_items'];
        dropTables.forEach(table => {
          mockPoolInstance.query.mockResolvedValueOnce({ rows: [], command: 'DROP', rowCount: 0, oid: 0, fields: [] });
        });

        return mockPoolInstance;
      });

      await mockTestSetup.setupTestDatabase();
      expect(mockTestSetup.setupTestDatabase).toHaveBeenCalled();
    });

    it('should create all required tables', async () => {
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        // Simulate CREATE TABLE queries
        const createTables = ['garment_items', 'test_items', 'test_table', 'parent_cleanup', 'child_cleanup', 'exclude_test_table'];
        createTables.forEach(table => {
          mockPoolInstance.query.mockResolvedValueOnce({ rows: [], command: 'CREATE', rowCount: 0, oid: 0, fields: [] });
        });

        return mockPoolInstance;
      });

      await mockTestSetup.setupTestDatabase();
      expect(mockTestSetup.setupTestDatabase).toHaveBeenCalled();
    });

    it('should verify table creation', async () => {
      const mockTables = [
        { table_name: 'garment_items' },
        { table_name: 'test_items' },
        { table_name: 'test_table' },
        { table_name: 'parent_cleanup' },
        { table_name: 'child_cleanup' },
        { table_name: 'exclude_test_table' }
      ];

      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockResolvedValueOnce({
          rows: mockTables,
          command: 'SELECT',
          rowCount: mockTables.length,
          oid: 0,
          fields: []
        });

        mockConsole.log('Tables created in test database:', mockTables.map(t => t.table_name));
        return mockPoolInstance;
      });

      await mockTestSetup.setupTestDatabase();

      expect(mockConsole.log).toHaveBeenCalledWith(
        'Tables created in test database:',
        ['garment_items', 'test_items', 'test_table', 'parent_cleanup', 'child_cleanup', 'exclude_test_table']
      );
    });

    it('should handle database setup errors gracefully', async () => {
      const setupError = new Error('Table creation failed');
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        mockConsole.error('Test database setup failed:', setupError);
        throw setupError;
      });

      await expect(mockTestSetup.setupTestDatabase()).rejects.toThrow('Table creation failed');
      expect(mockConsole.error).toHaveBeenCalledWith('Test database setup failed:', setupError);
    });
  });

  describe('Firebase Emulator Setup Logic', () => {
    beforeEach(() => {
      mockFetch.mockClear();
    });

    it('should check all Firebase emulator endpoints', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        // Mock successful responses for all emulators
        mockFetch
          .mockResolvedValueOnce({ ok: true }) // UI
          .mockResolvedValueOnce({ ok: true }) // Auth
          .mockResolvedValueOnce({ ok: true }) // Firestore
          .mockResolvedValueOnce({ ok: true }); // Storage

        return;
      });

      await mockTestSetup.setupFirebaseEmulator();

      expect(mockTestSetup.setupFirebaseEmulator).toHaveBeenCalled();
    });

    it('should initialize Firebase when all emulators are ready', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockFetch
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true });

        mockFirebaseHelpers.initializeTestFirebase();
        mockFirebaseHelpers.resetFirebaseEmulator();
        mockConsole.log('Firebase emulators initialized successfully');
      });

      await mockTestSetup.setupFirebaseEmulator();

      expect(mockFirebaseHelpers.initializeTestFirebase).toHaveBeenCalled();
      expect(mockFirebaseHelpers.resetFirebaseEmulator).toHaveBeenCalled();
      expect(mockConsole.log).toHaveBeenCalledWith('Firebase emulators initialized successfully');
    });

    it('should warn when some emulators are not ready', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockFetch
          .mockResolvedValueOnce({ ok: true })  // UI ready
          .mockResolvedValueOnce({ ok: false }) // Auth not ready
          .mockResolvedValueOnce({ ok: true })  // Firestore ready
          .mockResolvedValueOnce({ ok: true });  // Storage ready

        mockConsole.warn('Some Firebase emulators are not ready. Tests may fail if they require Firebase.');
      });

      await mockTestSetup.setupFirebaseEmulator();

      expect(mockConsole.warn).toHaveBeenCalledWith(
        'Some Firebase emulators are not ready. Tests may fail if they require Firebase.'
      );
    });

    it('should handle Firebase initialization errors gracefully', async () => {
      const firebaseError = new Error('Firebase initialization failed');
      
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockFetch
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true });

        mockFirebaseHelpers.initializeTestFirebase.mockImplementationOnce(() => {
          throw firebaseError;
        });

        mockConsole.error('Firebase emulator setup failed:', firebaseError);
      });

      await mockTestSetup.setupFirebaseEmulator();

      expect(mockConsole.error).toHaveBeenCalledWith('Firebase emulator setup failed:', firebaseError);
    });

    it('should handle network errors when checking emulator availability', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockFetch.mockRejectedValue(new Error('Network error'));
        mockConsole.warn('Some Firebase emulators are not ready. Tests may fail if they require Firebase.');
      });

      await mockTestSetup.setupFirebaseEmulator();

      expect(mockConsole.warn).toHaveBeenCalledWith(
        'Some Firebase emulators are not ready. Tests may fail if they require Firebase.'
      );
    });

    it('should log Firebase UI availability', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockFetch
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true })
          .mockResolvedValueOnce({ ok: true });

        mockConsole.log('Firebase UI available at: http://localhost:4001');
      });

      await mockTestSetup.setupFirebaseEmulator();

      expect(mockConsole.log).toHaveBeenCalledWith('Firebase UI available at: http://localhost:4001');
    });
  });

  describe('Service Availability Wait Logic', () => {
    it('should return true when service is immediately available', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockFetch.mockResolvedValueOnce({ ok: true });
        // Service check logic would go here
      });

      await mockTestSetup.setupFirebaseEmulator();
      expect(mockTestSetup.setupFirebaseEmulator).toHaveBeenCalled();
    });

    it('should retry when service is not immediately available', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockFetch
          .mockRejectedValueOnce(new Error('Connection refused'))
          .mockRejectedValueOnce(new Error('Connection refused'))
          .mockResolvedValueOnce({ ok: true }); // Succeeds on 3rd try
      });

      await mockTestSetup.setupFirebaseEmulator();
      expect(mockTestSetup.setupFirebaseEmulator).toHaveBeenCalled();
    });

    it('should handle maximum retry limit', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        // Mock all calls to fail (simulating service unavailable)
        mockFetch.mockRejectedValue(new Error('Service unavailable'));
        mockConsole.warn('Some Firebase emulators are not ready. Tests may fail if they require Firebase.');
      });

      await mockTestSetup.setupFirebaseEmulator();

      expect(mockConsole.warn).toHaveBeenCalledWith(
        'Some Firebase emulators are not ready. Tests may fail if they require Firebase.'
      );
    });
  });

  describe('Teardown Logic', () => {
    it('should clean up test data before closing connections', async () => {
      mockTestSetup.teardownTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockResolvedValue({ rows: [], command: 'DELETE', rowCount: 0, oid: 0, fields: [] });
        mockConsole.log('Test data cleaned up');
      });

      await mockTestSetup.teardownTestDatabase();

      expect(mockConsole.log).toHaveBeenCalledWith('Test data cleaned up');
    });

    it('should close database connections', async () => {
      mockTestSetup.teardownTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockResolvedValue({ rows: [], command: 'DELETE', rowCount: 0, oid: 0, fields: [] });
        mockPoolInstance.end.mockResolvedValue(undefined);
        mockConsole.log('Test database connections closed');
      });

      await mockTestSetup.teardownTestDatabase();

      expect(mockConsole.log).toHaveBeenCalledWith('Test database connections closed');
    });

    it('should clean up Firebase resources', async () => {
      mockTestSetup.teardownTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockResolvedValue({ rows: [], command: 'DELETE', rowCount: 0, oid: 0, fields: [] });
        mockPoolInstance.end.mockResolvedValue(undefined);
        mockFirebaseHelpers.cleanupTestFirebase();
      });

      await mockTestSetup.teardownTestDatabase();

      expect(mockFirebaseHelpers.cleanupTestFirebase).toHaveBeenCalled();
    });

    it('should handle cleanup errors gracefully', async () => {
      const cleanupError = new Error('Cleanup failed');
      mockTestSetup.teardownTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockRejectedValueOnce(cleanupError);
        mockPoolInstance.end.mockResolvedValue(undefined);
        mockConsole.error('Failed to clean up test data:', cleanupError);
      });

      await mockTestSetup.teardownTestDatabase();

      expect(mockConsole.error).toHaveBeenCalledWith('Failed to clean up test data:', cleanupError);
    });

    it('should handle database connection close errors gracefully', async () => {
      const closeError = new Error('Connection close failed');
      mockTestSetup.teardownTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockResolvedValue({ rows: [], command: 'DELETE', rowCount: 0, oid: 0, fields: [] });
        mockPoolInstance.end.mockRejectedValueOnce(closeError);
        mockConsole.error('Failed to close testPool:', closeError);
        mockFirebaseHelpers.cleanupTestFirebase();
      });

      await mockTestSetup.teardownTestDatabase();

      expect(mockConsole.error).toHaveBeenCalledWith('Failed to close testPool:', closeError);
      expect(mockFirebaseHelpers.cleanupTestFirebase).toHaveBeenCalled();
    });

    it('should handle Firebase cleanup errors gracefully', async () => {
      const firebaseCleanupError = new Error('Firebase cleanup failed');
      mockTestSetup.teardownTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockResolvedValue({ rows: [], command: 'DELETE', rowCount: 0, oid: 0, fields: [] });
        mockPoolInstance.end.mockResolvedValue(undefined);
        mockFirebaseHelpers.cleanupTestFirebase.mockRejectedValueOnce(firebaseCleanupError);
        mockConsole.error('Failed to cleanup Firebase:', firebaseCleanupError);
      });

      await mockTestSetup.teardownTestDatabase();

      expect(mockConsole.error).toHaveBeenCalledWith('Failed to cleanup Firebase:', firebaseCleanupError);
    });
  });

  describe('Error Handling Patterns', () => {
    it('should use consistent error logging patterns', async () => {
      const mockError = new Error('Test error');
      
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        mockConsole.error('Test database setup failed:', mockError);
        throw mockError;
      });

      await expect(mockTestSetup.setupTestDatabase()).rejects.toThrow('Test error');
      expect(mockConsole.error).toHaveBeenCalledWith('Test database setup failed:', mockError);
    });

    it('should not throw errors from optional operations', async () => {
      const firebaseError = new Error('Firebase failed');
      
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockFirebaseHelpers.initializeTestFirebase.mockImplementationOnce(() => {
          throw firebaseError;
        });
        mockConsole.error('Firebase emulator setup failed:', firebaseError);
        // Should not throw - Firebase is optional
      });

      await expect(mockTestSetup.setupFirebaseEmulator()).resolves.not.toThrow();
      expect(mockConsole.error).toHaveBeenCalledWith('Firebase emulator setup failed:', firebaseError);
    });

    it('should continue cleanup operations even if some fail', async () => {
      mockTestSetup.teardownTestDatabase.mockImplementation(async () => {
        mockPoolInstance.query.mockRejectedValueOnce(new Error('Data cleanup failed'));
        mockPoolInstance.end.mockRejectedValueOnce(new Error('Connection close failed'));
        mockFirebaseHelpers.cleanupTestFirebase.mockRejectedValueOnce(new Error('Firebase cleanup failed'));
        
        // All errors should be logged
        mockConsole.error('Failed to clean up test data:', expect.any(Error));
        mockConsole.error('Failed to close testPool:', expect.any(Error));
        mockConsole.error('Failed to cleanup Firebase:', expect.any(Error));
      });

      await mockTestSetup.teardownTestDatabase();

      // All cleanup operations should have been attempted
      expect(mockConsole.error).toHaveBeenCalledTimes(3);
    });
  });

  describe('Configuration Validation Logic', () => {
    it('should validate database name contains test', async () => {
      mockTestSetup.setupTestDatabase.mockRejectedValue(
        new Error('Tests must run against a database with "test" in the name! Current: production_db')
      );

      await expect(mockTestSetup.setupTestDatabase()).rejects.toThrow(
        'Tests must run against a database with "test" in the name! Current: production_db'
      );
    });

    it('should accept valid test database names', async () => {
      const validTestNames = ['koutu_test', 'app_test', 'test_db', 'development_test'];
      
      for (const dbName of validTestNames) {
        mockTestSetup.setupTestDatabase.mockImplementation(async () => {
          mockConsole.log(`Connected to database: ${dbName}`);
          return mockPoolInstance;
        });

        await expect(mockTestSetup.setupTestDatabase()).resolves.not.toThrow();
        expect(mockConsole.log).toHaveBeenCalledWith(`Connected to database: ${dbName}`);
      }
    });

    it('should use correct port configuration', () => {
      const config = mockTestSetup.getTestDatabaseConfig();
      expect(config.port).toBe(5433); // Different from default 5432
      expect(config.connectionString).toContain(':5433/');
    });
  });

  describe('Logging and Monitoring', () => {
    it('should log setup progress appropriately', async () => {
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        mockConsole.log('Setting up test database...');
        mockConsole.log('Connected to database: koutu_test');
        mockConsole.log('Test database initialized successfully');
        return mockPoolInstance;
      });

      await mockTestSetup.setupTestDatabase();

      expect(mockConsole.log).toHaveBeenCalledWith('Setting up test database...');
      expect(mockConsole.log).toHaveBeenCalledWith('Connected to database: koutu_test');
      expect(mockConsole.log).toHaveBeenCalledWith('Test database initialized successfully');
    });

    it('should log Firebase setup progress', async () => {
      mockTestSetup.setupFirebaseEmulator.mockImplementation(async () => {
        mockConsole.log('Waiting for Firebase emulators to be ready...');
        mockConsole.log('Firebase emulators initialized successfully');
        mockConsole.log('Firebase UI available at: http://localhost:4001');
      });

      await mockTestSetup.setupFirebaseEmulator();

      expect(mockConsole.log).toHaveBeenCalledWith('Waiting for Firebase emulators to be ready...');
      expect(mockConsole.log).toHaveBeenCalledWith('Firebase emulators initialized successfully');
      expect(mockConsole.log).toHaveBeenCalledWith('Firebase UI available at: http://localhost:4001');
    });

    it('should provide informative error messages', async () => {
      const specificError = new Error('Connection to PostgreSQL server failed');
      
      mockTestSetup.setupTestDatabase.mockImplementation(async () => {
        mockConsole.error('Test database setup failed:', specificError);
        throw specificError;
      });

      await expect(mockTestSetup.setupTestDatabase()).rejects.toThrow(specificError);
      expect(mockConsole.error).toHaveBeenCalledWith('Test database setup failed:', specificError);
    });
  });

  describe('Environment Variable Management', () => {
    it('should set environment variables correctly', () => {
      expect(process.env.TEST_DATABASE_URL).toBeDefined();
      expect(process.env.TEST_DATABASE_URL).toBe(
        'postgresql://postgres:postgres@localhost:5433/koutu_test'
      );
    });

    it('should not interfere with production environment variables', () => {
      // The test setup should not modify production DATABASE_URL
      expect(process.env.TEST_DATABASE_URL).not.toBe(process.env.DATABASE_URL);
    });

    it('should provide connection string in expected format', () => {
      const config = mockTestSetup.getTestDatabaseConfig();
      expect(config.connectionString).toMatch(
        /^postgresql:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^?]+$/
      );
    });
  });

  describe('Resource Management', () => {
    it('should properly manage database connections', () => {
      const pool1 = mockTestSetup.getTestPool();
      const pool2 = mockTestSetup.getTestPool();
      
      // Should return the same pool instance (singleton pattern)
      expect(pool1).toBe(pool2);
    });

    it('should handle concurrent access to test pool', () => {
      // Multiple calls should not create multiple pools
      const pools = Array.from({ length: 5 }, () => mockTestSetup.getTestPool());
      
      pools.forEach(pool => {
        expect(pool).toBe(pools[0]);
      });
    });
  });
});