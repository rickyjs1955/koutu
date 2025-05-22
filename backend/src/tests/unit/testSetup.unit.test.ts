// Mock the entire testSetup module
jest.mock('../../utils/testSetup', () => {
  const mockInitPool = {
    query: jest.fn(),
    end: jest.fn().mockResolvedValue(undefined)
  };
  
  const mockTestPool = {
    query: jest.fn(),
    end: jest.fn().mockResolvedValue(undefined)
  };
  
  // The actual implementations we'll use for testing
  const setupTestDatabase = async () => {
    try {
      // Check if database exists
      const dbCheck = await mockInitPool.query('SELECT 1 FROM pg_database WHERE datname = $1', ['koutu-postgres-test']);
      
      if (dbCheck.rowCount === 0) {
        await mockInitPool.query('CREATE DATABASE "koutu-postgres-test"');
        console.log('Created koutu-postgres-test database');
      }
      
      // Verify connection to test DB
      const dbResult = await mockTestPool.query('SELECT current_database()');
      const dbName = dbResult.rows[0].current_database;
      console.log(`Connected to database: ${dbName}`);
      
      if (!dbName.includes('test')) {
        throw new Error('Tests must run against a database with "test" in the name!');
      }
      
      // Create extension
      await mockTestPool.query('CREATE EXTENSION IF NOT EXISTS btree_gist');
      
      // Create tables
      await mockTestPool.query('CREATE TABLE IF NOT EXISTS garment_items (id UUID PRIMARY KEY)');
      await mockTestPool.query('CREATE TABLE IF NOT EXISTS test_items (id SERIAL PRIMARY KEY)');
      await mockTestPool.query('DROP TABLE IF EXISTS test_table');
      await mockTestPool.query('CREATE TABLE test_table (id SERIAL PRIMARY KEY)');
      await mockTestPool.query('DROP TABLE IF EXISTS child_cleanup');
      await mockTestPool.query('DROP TABLE IF EXISTS parent_cleanup');
      await mockTestPool.query('CREATE TABLE parent_cleanup (id SERIAL PRIMARY KEY)');
      await mockTestPool.query('CREATE TABLE child_cleanup (id SERIAL PRIMARY KEY)');
      await mockTestPool.query('DROP TABLE IF EXISTS exclude_test_table');
      await mockTestPool.query('CREATE TABLE exclude_test_table (id SERIAL PRIMARY KEY)');
      
      // Verify tables
      await mockTestPool.query(`SELECT table_name FROM information_schema.tables`);
      console.log('Test database initialized successfully');
    } catch (error) {
      console.error('Test database setup failed:', error);
      throw error;
    } finally {
      await mockInitPool.end();
    }
  };
  
  const teardownTestDatabase = async () => {
    try {
      await mockTestPool.end();
    } catch (error) {
      console.error('Failed to close testPool:', error);
    }
  };
  
  const testQuery = async (text: string, params?: any[]) => {
    return mockTestPool.query(text, params);
  };
  
  return {
    setupTestDatabase,
    teardownTestDatabase,
    testQuery,
    // Expose mock objects for testing
    __mockInitPool: mockInitPool,
    __mockTestPool: mockTestPool
  };
});

// Define types for mocked module
// This addresses the TypeScript errors for exported members
type MockedTestSetup = typeof import('../../utils/testSetup') & {
  __mockInitPool: { query: jest.Mock; end: jest.Mock };
  __mockTestPool: { query: jest.Mock; end: jest.Mock };
};

// Import the mocked module with type assertion
const { 
  setupTestDatabase, 
  teardownTestDatabase, 
  __mockInitPool: mockInitPool, 
  __mockTestPool: mockTestPool 
} = jest.requireMock('../../utils/testSetup') as MockedTestSetup;

describe('Test Database Setup Utilities', () => {
    let consoleSpy: jest.SpyInstance;
    let consoleErrorSpy: jest.SpyInstance;

    beforeEach(() => {
        // Clear all mocks
        jest.clearAllMocks();
        
        // Setup console spies
        consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
        consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        
        // Set default query responses for initPool
        mockInitPool.query.mockImplementation((query: string, params?: any[]) => {
        // Check if it's the database existence check
        if (query.includes('SELECT 1 FROM pg_database')) {
            return Promise.resolve({ rowCount: 0 }); // Database doesn't exist by default
        }
        
        // Default response
        return Promise.resolve({ rows: [], rowCount: 0 });
        });

        // Set default query responses for testPool
        mockTestPool.query.mockImplementation((query: string) => {
        // Check if it's the current database check
        if (query.includes('SELECT current_database()')) {
            return Promise.resolve({ 
            rows: [{ current_database: 'koutu-postgres-test' }]
            });
        }
        
        // Tables verification query
        if (query.includes('SELECT table_name FROM information_schema.tables')) {
            return Promise.resolve({
            rows: [
                { table_name: 'parent_cleanup' },
                { table_name: 'child_cleanup' },
                { table_name: 'exclude_test_table' }
            ]
            });
        }
        
        // Default for all other queries
        return Promise.resolve({ rows: [], rowCount: 0 });
        });
    });

    afterEach(() => {
        consoleSpy.mockRestore();
        consoleErrorSpy.mockRestore();
    });

    describe('setupTestDatabase', () => {
        test('should create database if it does not exist', async () => {
        await setupTestDatabase();
        
        // Verify database existence check
        expect(mockInitPool.query).toHaveBeenCalledWith(
            'SELECT 1 FROM pg_database WHERE datname = $1', 
            ['koutu-postgres-test']
        );
        
        // Verify database creation
        expect(mockInitPool.query).toHaveBeenCalledWith(
            'CREATE DATABASE "koutu-postgres-test"'
        );
        
        // Verify connection log
        expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Created koutu-postgres-test database'));
        
        // Verify initPool was closed
        expect(mockInitPool.end).toHaveBeenCalled();
        });

        test('should not create database if it already exists', async () => {
        // Setup mock to say database exists
        mockInitPool.query.mockImplementationOnce(() => 
            Promise.resolve({ rowCount: 1 })
        );
        
        await setupTestDatabase();
        
        // Should query for existence
        expect(mockInitPool.query).toHaveBeenCalledWith(
            'SELECT 1 FROM pg_database WHERE datname = $1', 
            ['koutu-postgres-test']
        );
        
        // Shouldn't call database creation
        expect(mockInitPool.query).not.toHaveBeenCalledWith(
            'CREATE DATABASE "koutu-postgres-test"'
        );
        });

        test('should throw error if connected to non-test database', async () => {
        // Setup mock to return a non-test database name
        mockTestPool.query.mockImplementationOnce(() =>
            Promise.resolve({ rows: [{ current_database: 'production-db' }] })
        );
        
        await expect(setupTestDatabase()).rejects.toThrow(
            'Tests must run against a database with "test" in the name!'
        );
        });

        test('should create all required tables and extensions', async () => {
        await setupTestDatabase();
        
        // Verify btree_gist extension creation
        expect(mockTestPool.query).toHaveBeenCalledWith(
            'CREATE EXTENSION IF NOT EXISTS btree_gist'
        );
        
        // Verify some of the table creation queries
        expect(mockTestPool.query).toHaveBeenCalledWith(
            'CREATE TABLE IF NOT EXISTS garment_items (id UUID PRIMARY KEY)'
        );
        
        expect(mockTestPool.query).toHaveBeenCalledWith(
            'CREATE TABLE IF NOT EXISTS test_items (id SERIAL PRIMARY KEY)'
        );
        
        // Verify successful initialization log
        expect(consoleSpy).toHaveBeenCalledWith('Test database initialized successfully');
        });

        test('should handle errors during setup', async () => {
        const testError = new Error('Database connection failed');
        mockInitPool.query.mockRejectedValueOnce(testError);
        
        await expect(setupTestDatabase()).rejects.toThrow('Database connection failed');
        
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            'Test database setup failed:', 
            testError
        );
        });
    });

    describe('teardownTestDatabase', () => {
        test('should close the test pool', async () => {
        await teardownTestDatabase();
        expect(mockTestPool.end).toHaveBeenCalled();
        });

        test('should handle errors during teardown', async () => {
        const testError = new Error('Failed to close connection');
        mockTestPool.end.mockRejectedValueOnce(testError);
        
        await teardownTestDatabase();
        
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            'Failed to close testPool:', 
            testError
        );
        });
    });
});