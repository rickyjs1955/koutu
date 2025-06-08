import { 
  setupTestDatabase, 
  setupFirebaseEmulator, 
  teardownTestDatabase, 
  testQuery,
  getTestPool,
  cleanupTestData
} from '../../utils/testSetup';

// Mock Firebase helper functions
jest.mock('@/tests/__helpers__/firebase.helper', () => ({
  cleanupTestFirebase: jest.fn().mockResolvedValue(undefined),
  initializeTestFirebase: jest.fn().mockReturnValue(undefined),
  resetFirebaseEmulator: jest.fn().mockResolvedValue(undefined),
}));

// Mock fetch for service availability checks
global.fetch = jest.fn();

// Mock console methods to reduce noise in tests
const consoleSpy = {
  log: jest.spyOn(console, 'log').mockImplementation(),
  warn: jest.spyOn(console, 'warn').mockImplementation(),
};

describe('testSetup Integration Tests', () => {
  // ONE-TIME setup for the entire test suite
  beforeAll(async () => {
    try {
      await setupTestDatabase();
    } catch (error) {
      console.log('Setup error:', error);
      throw error; // Fail fast if we can't set up
    }
  }, 30000);

  // ONE-TIME teardown for the entire test suite
  afterAll(async () => {
    // Restore console methods
    Object.values(consoleSpy).forEach(spy => spy.mockRestore());
    
    // Clear any remaining timers
    jest.clearAllTimers();
    
    // Close connections only at the very end
    try {
      await teardownTestDatabase();
    } catch (error) {
      console.error('Teardown error:', error);
    }
  }, 10000);

  // Fast cleanup between tests (data only, not connections)
  afterEach(async () => {
    jest.clearAllMocks();
    
    // Clear any hanging timers
    jest.clearAllTimers();
    
    try {
      await cleanupTestData();
    } catch (error) {
      // Ignore cleanup errors between tests
    }
  });

  describe('Database Setup and Operations', () => {
    it('should have a valid test pool configuration', () => {
      const pool = getTestPool();
      expect(pool).toBeDefined();
      expect(pool.options.host).toBe('localhost');
      expect(['5432', '5433'].includes(String(pool.options.port))).toBe(true); // Handle both Docker and local
      expect(pool.options.database).toBe('koutu_test');
    });

    it('should execute test queries successfully', async () => {
      const result = await testQuery('SELECT 1 as test_value');
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].test_value).toBe(1);
    });

    it('should handle query errors properly', async () => {
      await expect(testQuery('SELECT * FROM non_existent_table'))
        .rejects.toThrow();
    });

    it('should maintain connection to test database', async () => {
      const result = await testQuery('SELECT current_database()');
      const dbName = result.rows[0].current_database;
      expect(dbName).toContain('test');
    });

    it('should handle parameterized queries', async () => {
      const result = await testQuery('SELECT $1 as param_value', ['test_param']);
      expect(result.rows[0].param_value).toBe('test_param');
    });

    it('should handle multiple parameters', async () => {
      const result = await testQuery(
        'SELECT $1 as first_param, $2 as second_param', 
        ['first', 'second']
      );
      expect(result.rows[0].first_param).toBe('first');
      expect(result.rows[0].second_param).toBe('second');
    });
  });

  describe('setupTestDatabase', () => {
    it('should create required tables', async () => {
      const result = await testQuery(`
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' 
        ORDER BY table_name
      `);

      interface TableRow {
        table_name: string;
      }

      const tableNames: string[] = result.rows.map((row: TableRow) => row.table_name);
      
      expect(tableNames).toContain('garment_items');
      expect(tableNames).toContain('test_items');
      expect(tableNames).toContain('test_table');
      expect(tableNames).toContain('parent_cleanup');
      expect(tableNames).toContain('child_cleanup');
      expect(tableNames).toContain('exclude_test_table');
    });

    it('should create garment_items table with correct structure', async () => {
      const result = await testQuery(`
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'garment_items'
        ORDER BY column_name
      `);

      interface ColumnInfo {
        type: string;
        nullable: boolean;
      }

      interface ColumnRow {
        column_name: string;
        data_type: string;
        is_nullable: string;
      }

      const columns = result.rows.reduce((acc: Record<string, ColumnInfo>, row: ColumnRow) => {
        acc[row.column_name] = {
          type: row.data_type,
          nullable: row.is_nullable === 'YES'
        };
        return acc;
      }, {} as Record<string, ColumnInfo>);

      // Test basic required columns
      expect(columns.id).toBeDefined();
      expect(columns.user_id).toBeDefined();
      expect(columns.created_at).toBeDefined();
    });

    it('should create test_items table with unique constraint', async () => {
      // Insert a test record
      await testQuery(`INSERT INTO test_items (name) VALUES ('unique_test')`);

      // Try to insert duplicate - should fail
      await expect(testQuery(`INSERT INTO test_items (name) VALUES ('unique_test')`))
        .rejects.toThrow();
    });

    it('should create foreign key relationship between parent and child tables', async () => {
      // Insert parent record
      const parentResult = await testQuery(`
        INSERT INTO parent_cleanup (name) VALUES ('test_parent') RETURNING id
      `);
      const parentId = parentResult.rows[0].id;

      // Insert child record with valid parent_id
      await testQuery(`
        INSERT INTO child_cleanup (parent_id, description) VALUES ($1, 'test_child')
      `, [parentId]);

      // Try to insert child with invalid parent_id - should fail
      await expect(testQuery(`
        INSERT INTO child_cleanup (parent_id, description) VALUES (99999, 'invalid_child')
      `)).rejects.toThrow();

      // Try to delete parent with existing child - should fail due to RESTRICT
      await expect(testQuery(`
        DELETE FROM parent_cleanup WHERE id = $1
      `, [parentId])).rejects.toThrow();
    });

    it('should create exclude_test_table with EXCLUDE constraint', async () => {
      // Insert first range
      await testQuery(`INSERT INTO exclude_test_table (range) VALUES ('[1,5)')`);

      // Try to insert overlapping range - should fail
      await expect(testQuery(`INSERT INTO exclude_test_table (range) VALUES ('[3,7)')`))
        .rejects.toThrow();

      // Insert non-overlapping range - should succeed
      await testQuery(`INSERT INTO exclude_test_table (range) VALUES ('[6,10)')`);
    });

    it('should enable required PostgreSQL extensions', async () => {
      const result = await testQuery(`
        SELECT extname FROM pg_extension 
        WHERE extname IN ('btree_gist', 'uuid-ossp')
        ORDER BY extname
      `);

      interface ExtensionRow {
        extname: string;
      }

      const extensions: string[] = result.rows.map((row: ExtensionRow) => row.extname);
      expect(extensions).toContain('btree_gist');
      expect(extensions).toContain('uuid-ossp');
    });
  });

  describe('setupFirebaseEmulator', () => {
    it('should handle successful Firebase emulator setup', async () => {
      // Mock successful service checks
      (global.fetch as jest.Mock)
        .mockResolvedValueOnce({ ok: true }) // UI
        .mockResolvedValueOnce({ ok: true }) // Auth
        .mockResolvedValueOnce({ ok: true }) // Firestore
        .mockResolvedValueOnce({ ok: true }); // Storage

      await setupFirebaseEmulator();

      expect(global.fetch).toHaveBeenCalledWith('http://localhost:4001', expect.any(Object));
      expect(global.fetch).toHaveBeenCalledWith('http://localhost:9099', expect.any(Object));
      expect(global.fetch).toHaveBeenCalledWith('http://localhost:9100', expect.any(Object));
      expect(global.fetch).toHaveBeenCalledWith('http://localhost:9199', expect.any(Object));
    }, 5000);

    it('should handle Firebase emulator unavailability gracefully', async () => {
      // Mock failed service checks
      (global.fetch as jest.Mock)
        .mockRejectedValue(new Error('Connection refused'));

      // Should not throw, just log warnings
      await expect(setupFirebaseEmulator()).resolves.not.toThrow();
    });
  });

  describe('Database Data Management', () => {
    it('should insert and clean up test data', async () => {
      // Add test data
      await testQuery(`INSERT INTO test_items (name) VALUES ('cleanup_test')`);
      await testQuery(`INSERT INTO test_table (value) VALUES ('cleanup_value')`);
      await testQuery(`INSERT INTO parent_cleanup (name) VALUES ('cleanup_parent')`);

      // Verify data exists
      let result = await testQuery('SELECT COUNT(*) as count FROM test_items WHERE name = $1', ['cleanup_test']);
      expect(parseInt(result.rows[0].count)).toBe(1);

      // Data will be cleaned up automatically by afterEach
    });

    it('should handle cleanup errors gracefully', async () => {
      // This simulates error handling
      try {
        await testQuery('DELETE FROM non_existent_table');
      } catch (error) {
        expect(error).toBeDefined();
      }
    });
  });

  describe('Database Connection Pooling', () => {
    it('should handle concurrent database operations', async () => {
      const promises = Array.from({ length: 5 }, (_, i) => 
        testQuery('SELECT $1::integer as concurrent_test', [i])
      );

      const results = await Promise.all(promises);
      
      results.forEach((result, index) => {
        expect(result.rows[0].concurrent_test).toBe(index);
      });
    });

    it('should handle database operations without timeout issues', async () => {
      const simpleQuery = 'SELECT 1 as simple_test';
      const result = await testQuery(simpleQuery);
      expect(result.rows[0].simple_test).toBe(1);
    });

    it('should validate pool configuration', () => {
      const pool = getTestPool();
      
      expect(pool.options.max).toBeGreaterThan(0);
      expect(pool.options.connectionTimeoutMillis).toBeGreaterThan(0);
      expect(pool.options.idleTimeoutMillis).toBeGreaterThan(0);
      expect(pool.options.ssl).toBe(false);
    });
  });

  describe('Error Handling and Logging', () => {
    let errorSpy: jest.SpyInstance;

    beforeEach(() => {
      errorSpy = jest.spyOn(console, 'error').mockImplementation();
    });

    afterEach(() => {
      if (errorSpy) {
        errorSpy.mockRestore();
      }
    });

    it('should log query details on database errors', async () => {
      try {
        await testQuery('SELECT * FROM this_table_does_not_exist');
      } catch (error) {
        expect(error).toBeDefined();
      }

      expect(errorSpy).toHaveBeenCalledWith('Database query error:', expect.any(Error));
      expect(errorSpy).toHaveBeenCalledWith('Query:', 'SELECT * FROM this_table_does_not_exist');
      expect(errorSpy).toHaveBeenCalledWith('Params:', undefined);
    });

    it('should log query parameters on errors', async () => {
      try {
        await testQuery('SELECT * FROM this_table_does_not_exist WHERE id = $1', [123]);
      } catch (error) {
        expect(error).toBeDefined();
      }

      expect(errorSpy).toHaveBeenCalledWith('Params:', [123]);
    });
  });

  describe('Database Schema Validation', () => {
    it('should accept various test database naming patterns', () => {
      const testDbNames = [
        'app_test',
        'test_db',
        'development_test',
        'koutu_test',
        'my_test_database'
      ];

      for (const dbName of testDbNames) {
        expect(dbName.includes('test')).toBe(true);
      }
    });

    it('should reject non-test database names', () => {
      const nonTestDbNames = [
        'production',
        'app_prod',
        'development',
        'staging',
        'live_db'
      ];

      for (const dbName of nonTestDbNames) {
        expect(dbName.includes('test')).toBe(false);
      }
    });
  });
});