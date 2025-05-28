// /backend/src/utils/testDatabaseConnection.int.test.ts

import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { Pool, Client } from 'pg';
import { TEST_DB_CONFIG, MAIN_DB_CONFIG } from '../../utils/testConfig';

// Test configuration for integration tests
const INTEGRATION_TEST_CONFIG = {
  host: 'localhost',
  port: 5432,
  user: 'postgres',
  password: 'postgres',
  database: 'postgres', // Connect to main db initially
};

describe('TestDatabaseConnection Integration Tests', () => {
  beforeAll(async () => {
    // Wait for PostgreSQL to be ready
    const maxRetries = 30;
    let connected = false;
    
    for (let i = 0; i < maxRetries; i++) {
      try {
        const client = new Client(INTEGRATION_TEST_CONFIG);
        await client.connect();
        await client.query('SELECT 1');
        await client.end();
        connected = true;
        break;
      } catch (error) {
        console.log(`Waiting for PostgreSQL... (${i + 1}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    if (!connected) {
      throw new Error('PostgreSQL is not available for integration tests');
    }

    console.log('PostgreSQL is ready for TestDatabaseConnection integration tests');
  }, 60000);

  afterAll(async () => {
    // Ensure cleanup
    try {
      await TestDatabaseConnection.cleanup();
    } catch (error) {
      console.log('Final cleanup error (may be expected):', error);
    }
  });

  beforeEach(async () => {
    // Ensure clean state before each test
    try {
      if (TestDatabaseConnection.initialized) {
        await TestDatabaseConnection.clearAllTables();
      }
    } catch (error) {
      // If clearing fails, do full cleanup and reinitialize
      await TestDatabaseConnection.cleanup();
    }
  });

  afterEach(async () => {
    // Give time for connections to settle
    await new Promise(resolve => setTimeout(resolve, 50));
  });

  describe('Connection Initialization', () => {
    it('should initialize database connection successfully', async () => {
      const pool = await TestDatabaseConnection.initialize();
      
      expect(pool).toBeDefined();
      expect(pool).toBeInstanceOf(Pool);
      
      // Verify connection works
      const result = await pool.query('SELECT current_database()');
      expect(result.rows[0].current_database).toBe('koutu_test');
    });

    it('should maintain singleton pattern for connections', async () => {
      const pool1 = await TestDatabaseConnection.initialize();
      const pool2 = await TestDatabaseConnection.initialize();
      
      expect(pool1).toBe(pool2); // Same instance
      
      // Both should work
      const [result1, result2] = await Promise.all([
        pool1.query('SELECT 1 as test'),
        pool2.query('SELECT 2 as test')
      ]);
      
      expect(result1.rows[0].test).toBe(1);
      expect(result2.rows[0].test).toBe(2);
    });

    it('should handle multiple rapid initialization calls', async () => {
  // Clean up first to ensure fresh state
  await TestDatabaseConnection.cleanup();
  
  // Simulate multiple simultaneous initialization attempts
  const initPromises = Array.from({ length: 5 }, () => 
    TestDatabaseConnection.initialize()
  );
  
  const pools = await Promise.all(initPromises);
  
  // All should return the same pool instance
  for (const pool of pools) {
    expect(pool).toBe(pools[0]);
  }
  
  // Pool should work correctly
  const result = await pools[0].query('SELECT NOW() as current_time');
  expect(result.rows[0].current_time).toBeInstanceOf(Date);
});

    it('should set isInitialized flag correctly', async () => {
  // Clean up first
  await TestDatabaseConnection.cleanup();
  
  // First initialization
  await TestDatabaseConnection.initialize();
  
  // Second call should be fast (no re-initialization)
  const startTime = Date.now();
  await TestDatabaseConnection.initialize();
  const duration = Date.now() - startTime;
  
  expect(duration).toBeLessThan(100); // Should be very fast for cached init
  
  // Check initialized state through behavior
  expect(TestDatabaseConnection.initialized).toBe(true);
});
  });

  describe('Database Creation and Setup', () => {
    it('should create test database successfully', async () => {
      await TestDatabaseConnection.initialize();
      
      // Verify test database exists by connecting to it
      const pool = TestDatabaseConnection.getPool();
      const result = await pool.query('SELECT current_database()');
      expect(result.rows[0].current_database).toBe('koutu_test');
    });

    it('should handle existing database gracefully', async () => {
      // Initialize once
      await TestDatabaseConnection.initialize();
      
      // Initialize again - should handle existing database
      await expect(TestDatabaseConnection.initialize()).resolves.not.toThrow();
      
      const pool = TestDatabaseConnection.getPool();
      expect(pool).toBeDefined();
    });

    it('should create database with correct extensions', async () => {
      await TestDatabaseConnection.initialize();
      
      const pool = TestDatabaseConnection.getPool();
      const result = await pool.query(`
        SELECT extname FROM pg_extension 
        WHERE extname = 'uuid-ossp'
      `);
      
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].extname).toBe('uuid-ossp');
    });

    it('should terminate existing connections before database operations', async () => {
      // This tests the connection termination logic
      await TestDatabaseConnection.initialize();
      
      // Get current connection count
      const pool = TestDatabaseConnection.getPool();
      const beforeResult = await pool.query(`
        SELECT count(*) as connections 
        FROM pg_stat_activity 
        WHERE datname = 'koutu_test'
      `);
      
      const connectionsBefore = parseInt(beforeResult.rows[0].connections);
      expect(connectionsBefore).toBeGreaterThan(0);
      
      // Re-initialize (should handle existing connections)
      await TestDatabaseConnection.cleanup();
      await TestDatabaseConnection.initialize();
      
      // Should still work
      const afterPool = TestDatabaseConnection.getPool();
      const afterResult = await afterPool.query('SELECT 1 as test');
      expect(afterResult.rows[0].test).toBe(1);
    });
  });

  describe('Schema Creation and Validation', () => {
    beforeEach(async () => {
      await TestDatabaseConnection.initialize();
    });

    it('should create all required tables', async () => {
      const pool = TestDatabaseConnection.getPool();
      const result = await pool.query(`
        SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' 
        ORDER BY table_name
      `);

      const tableNames = result.rows.map(row => row.table_name);
      
      expect(tableNames).toContain('users');
      expect(tableNames).toContain('user_oauth_providers');
      expect(tableNames).toContain('original_images');
      expect(tableNames).toContain('garment_items');
      expect(tableNames).toContain('wardrobes');
    });

    it('should create users table with correct structure', async () => {
      const pool = TestDatabaseConnection.getPool();
      const result = await pool.query(`
        SELECT 
          column_name, 
          data_type, 
          is_nullable, 
          column_default
        FROM information_schema.columns
        WHERE table_name = 'users'
        ORDER BY ordinal_position
      `);

      const columns = result.rows.reduce((acc, row) => {
        acc[row.column_name] = {
          type: row.data_type,
          nullable: row.is_nullable === 'YES',
          default: row.column_default
        };
        return acc;
      }, {} as Record<string, any>);

      // Verify essential columns
      expect(columns.id.type).toBe('uuid');
      expect(columns.id.nullable).toBe(false);
      expect(columns.id.default).toContain('uuid_generate_v4()');

      expect(columns.email.type).toBe('text');
      expect(columns.email.nullable).toBe(false);

      expect(columns.password_hash.type).toBe('text');
      expect(columns.password_hash.nullable).toBe(true);

      expect(columns.created_at.type).toBe('timestamp with time zone');
      expect(columns.created_at.nullable).toBe(false);
      expect(columns.created_at.default).toContain('now()');

      expect(columns.updated_at.type).toBe('timestamp with time zone');
      expect(columns.updated_at.nullable).toBe(false);
      expect(columns.updated_at.default).toContain('now()');
    });

    it('should create foreign key relationships correctly', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      // Check foreign key constraints
      const result = await pool.query(`
        SELECT 
          tc.constraint_name,
          tc.table_name,
          kcu.column_name,
          ccu.table_name AS foreign_table_name,
          ccu.column_name AS foreign_column_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
        JOIN information_schema.constraint_column_usage AS ccu
          ON ccu.constraint_name = tc.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY'
        ORDER BY tc.table_name, tc.constraint_name
      `);

      const foreignKeys = result.rows;
      
      // Verify user_oauth_providers references users
      const oauthFk = foreignKeys.find(fk => 
        fk.table_name === 'user_oauth_providers' && fk.column_name === 'user_id'
      );
      expect(oauthFk).toBeDefined();
      expect(oauthFk.foreign_table_name).toBe('users');
      expect(oauthFk.foreign_column_name).toBe('id');

      // Verify other tables reference users
      const expectedReferences = ['original_images', 'garment_items', 'wardrobes'];
      for (const tableName of expectedReferences) {
        const fk = foreignKeys.find(fk => 
          fk.table_name === tableName && fk.column_name === 'user_id'
        );
        expect(fk).toBeDefined();
        expect(fk.foreign_table_name).toBe('users');
        expect(fk.foreign_column_name).toBe('id');
      }
    });

    it('should create unique constraints correctly', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      // Check unique constraints
      const result = await pool.query(`
        SELECT 
          tc.constraint_name,
          tc.table_name,
          kcu.column_name
        FROM information_schema.table_constraints AS tc
        JOIN information_schema.key_column_usage AS kcu
          ON tc.constraint_name = kcu.constraint_name
        WHERE tc.constraint_type = 'UNIQUE'
        ORDER BY tc.table_name, tc.constraint_name
      `);

      const uniqueConstraints = result.rows;
      
      // Verify email unique constraint on users table
      const emailUnique = uniqueConstraints.find(uc => 
        uc.table_name === 'users' && uc.column_name === 'email'
      );
      expect(emailUnique).toBeDefined();

      // Verify unique constraint on OAuth providers
      const oauthUnique = uniqueConstraints.find(uc => 
        uc.table_name === 'user_oauth_providers' && 
        uc.constraint_name.includes('provider')
      );
      expect(oauthUnique).toBeDefined();
    });

    it('should handle schema creation idempotently', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      // Get initial table count
      const beforeResult = await pool.query(`
        SELECT COUNT(*) as table_count FROM information_schema.tables
        WHERE table_schema = 'public'
      `);
      const beforeCount = parseInt(beforeResult.rows[0].table_count);
      
      // Re-initialize (should not create duplicate tables)
      await TestDatabaseConnection.cleanup();
      await TestDatabaseConnection.initialize();
      
      const afterResult = await TestDatabaseConnection.getPool().query(`
        SELECT COUNT(*) as table_count FROM information_schema.tables
        WHERE table_schema = 'public'
      `);
      const afterCount = parseInt(afterResult.rows[0].table_count);
      
      expect(afterCount).toBe(beforeCount); // Same number of tables
    });
  });

  describe('Connection Pool Management', () => {
    beforeEach(async () => {
      await TestDatabaseConnection.initialize();
    });

    it('should provide working connection pool', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      expect(pool).toBeDefined();
      expect(pool).toBeInstanceOf(Pool);
      
      // Test basic query
      const result = await pool.query('SELECT NOW() as current_time');
      expect(result.rows[0].current_time).toBeInstanceOf(Date);
    });

    it('should handle concurrent connections efficiently', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      // Create multiple concurrent queries
      const queries = Array.from({ length: 10 }, (_, i) => 
        pool.query('SELECT $1::integer as query_id', [i])
      );
      
      const results = await Promise.all(queries);
      
      // All queries should succeed
      results.forEach((result, index) => {
        expect(result.rows[0].query_id).toBe(index);
      });
    });

    it('should respect connection pool limits', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      // Verify pool configuration
      expect(pool.options.max).toBe(TEST_DB_CONFIG.max);
      expect(pool.options.connectionTimeoutMillis).toBe(TEST_DB_CONFIG.connectionTimeoutMillis);
      expect(pool.options.idleTimeoutMillis).toBe(TEST_DB_CONFIG.idleTimeoutMillis);
    });

    it('should handle connection pool exhaustion gracefully', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      // Create more queries than pool max (20 + some buffer)
      const manyQueries = Array.from({ length: 25 }, (_, i) => 
        pool.query('SELECT pg_sleep(0.1), $1::integer as id', [i])
      );
      
      // Should handle without hanging
      const startTime = Date.now();
      const results = await Promise.all(manyQueries);
      const duration = Date.now() - startTime;
      
      expect(results).toHaveLength(25);
      expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
    }, 15000);

    it('should maintain connection health', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      // Test connection health over time
      for (let i = 0; i < 5; i++) {
        const result = await pool.query('SELECT $1::integer as iteration', [i]);
        expect(result.rows[0].iteration).toBe(i);
        
        // Small delay between queries
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    });
  });

  describe('Database Query Operations', () => {
    beforeEach(async () => {
      await TestDatabaseConnection.initialize();
    });

    it('should execute queries through static query method', async () => {
      const result = await TestDatabaseConnection.query(
        'SELECT $1::text as message', 
        ['Hello World']
      );
      
      expect(result.rows[0].message).toBe('Hello World');
    });

    it('should handle parameterized queries correctly', async () => {
      const testCases = [
        ['SELECT $1::integer as num', [42], 42],
        ['SELECT $1::text as str', ['test'], 'test'],
        ['SELECT $1::boolean as bool', [true], true],
        ['SELECT $1::timestamp as time', [new Date('2023-01-01')], new Date('2023-01-01')]
      ];
      
      for (const [query, params, expected] of testCases) {
        const result = await TestDatabaseConnection.query(query as string, params as any[]);
        expect(result.rows[0]).toEqual(expect.objectContaining({
          [Object.keys(result.rows[0])[0]]: expected
        }));
      }
    });

    it('should handle queries without parameters', async () => {
      const result = await TestDatabaseConnection.query('SELECT 1 as number');
      expect(result.rows[0].number).toBe(1);
    });

    it('should throw error when pool not initialized', async () => {
  await TestDatabaseConnection.cleanup();
  
  await expect(TestDatabaseConnection.query('SELECT 1'))
    .rejects.toThrow('Test database not initialized. Call initialize() first.');
});

    it('should handle complex queries with joins', async () => {
      // Insert test data
      const userResult = await TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('complex@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      await TestDatabaseConnection.query(`
        INSERT INTO garment_items (user_id, name)
        VALUES ($1, 'Test Garment')
      `, [userId]);

      // Complex join query
      const result = await TestDatabaseConnection.query(`
        SELECT u.email, COUNT(g.id) as garment_count
        FROM users u
        LEFT JOIN garment_items g ON u.id = g.user_id
        WHERE u.email = $1
        GROUP BY u.id, u.email
      `, ['complex@example.com']);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].email).toBe('complex@example.com');
      expect(parseInt(result.rows[0].garment_count)).toBe(1);
    });

    it('should handle transaction-like operations', async () => {
      // Use the pool directly for transactions
      const pool = TestDatabaseConnection.getPool();
      const client = await pool.connect();
      
      try {
        await client.query('BEGIN');
        
        const userResult = await client.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ('transaction@example.com', 'hash123')
          RETURNING id
        `);
        const userId = userResult.rows[0].id;

        await client.query(`
          INSERT INTO garment_items (user_id, name)
          VALUES ($1, 'Transaction Garment')
        `, [userId]);

        await client.query('COMMIT');

        // Verify data was committed
        const verifyResult = await TestDatabaseConnection.query(`
          SELECT COUNT(*) as count FROM users WHERE email = 'transaction@example.com'
        `);
        expect(parseInt(verifyResult.rows[0].count)).toBe(1);
      } finally {
        client.release();
      }
    });
  });

  describe('Data Management Operations', () => {
    beforeEach(async () => {
      await TestDatabaseConnection.initialize();
    });

    it('should clear all tables successfully', async () => {
      // Insert test data in multiple tables
      const userResult = await TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('clear@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      await TestDatabaseConnection.query(`
        INSERT INTO user_oauth_providers (user_id, provider, provider_id)
        VALUES ($1, 'google', '123')
      `, [userId]);

      await TestDatabaseConnection.query(`
        INSERT INTO original_images (user_id, file_path)
        VALUES ($1, '/path/to/image.jpg')
      `, [userId]);

      await TestDatabaseConnection.query(`
        INSERT INTO garment_items (user_id, name)
        VALUES ($1, 'Test Item')
      `, [userId]);

      await TestDatabaseConnection.query(`
        INSERT INTO wardrobes (user_id, name)
        VALUES ($1, 'Test Wardrobe')
      `, [userId]);

      // Clear all tables
      await TestDatabaseConnection.clearAllTables();

      // Verify all tables are empty
      const tables = ['users', 'user_oauth_providers', 'original_images', 'garment_items', 'wardrobes'];
      
      for (const table of tables) {
        const result = await TestDatabaseConnection.query(`SELECT COUNT(*) as count FROM ${table}`);
        expect(parseInt(result.rows[0].count)).toBe(0);
      }
    });

    it('should handle clearing empty tables', async () => {
      // Clear already empty tables - should not throw error
      await expect(TestDatabaseConnection.clearAllTables()).resolves.not.toThrow();
    });

    it('should reset identity sequences after clearing', async () => {
      // Insert and clear some data
      await TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('sequence@example.com', 'hash')
      `);

      await TestDatabaseConnection.clearAllTables();

      // Insert new data and verify UUID generation still works
      const result = await TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('newuser@example.com', 'hash')
        RETURNING id
      `);

      expect(result.rows[0].id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
    });

    it('should maintain referential integrity during clear operations', async () => {
      // The clear operation should handle foreign key dependencies correctly
      // by clearing in the right order (children before parents)
      
      // Insert data with dependencies
      const userResult = await TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('integrity@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      await TestDatabaseConnection.query(`
        INSERT INTO garment_items (user_id, name)
        VALUES ($1, 'Dependent Item')
      `, [userId]);

      // Clear should succeed without foreign key violations
      await expect(TestDatabaseConnection.clearAllTables()).resolves.not.toThrow();
    });
  });

  describe('Error Handling and Recovery', () => {
    beforeEach(async () => {
      await TestDatabaseConnection.initialize();
    });

    it('should handle database connection errors gracefully', async () => {
      // This is hard to test directly, but we can test error propagation
      await expect(TestDatabaseConnection.query('INVALID SQL SYNTAX'))
        .rejects.toThrow();
    });

    it('should handle constraint violations appropriately', async () => {
      // Insert user with email
      await TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('unique@example.com', 'hash123')
      `);

      // Try to insert duplicate email
      await expect(TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('unique@example.com', 'hash456')
      `)).rejects.toThrow(/duplicate key value violates unique constraint/);
    });

    it('should recover from connection pool issues', async () => {
      const pool = TestDatabaseConnection.getPool();
      
      // Perform normal operation
      const result1 = await pool.query('SELECT 1 as test');
      expect(result1.rows[0].test).toBe(1);
      
      // Simulate some connection stress
      const stressQueries = Array.from({ length: 30 }, () => 
        pool.query('SELECT pg_sleep(0.05)')
      );
      
      await Promise.all(stressQueries);
      
      // Should still work after stress
      const result2 = await pool.query('SELECT 2 as test');
      expect(result2.rows[0].test).toBe(2);
    });

    it('should handle long-running queries appropriately', async () => {
      // Test with reasonable timeout
      const startTime = Date.now();
      
      try {
        await TestDatabaseConnection.query('SELECT pg_sleep(1)');
      } catch (error) {
        // Query should complete or timeout gracefully
      }
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(15000); // Should not hang indefinitely
    }, 20000);
  });

  describe('Cleanup and Resource Management', () => {
    it('should cleanup connections and database properly', async () => {
      // Initialize database
      await TestDatabaseConnection.initialize();
      
      // Insert some test data
      await TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('cleanup@example.com', 'hash123')
      `);

      // Verify database exists and has data
      let result = await TestDatabaseConnection.query('SELECT current_database()');
      expect(result.rows[0].current_database).toBe('koutu_test');

      result = await TestDatabaseConnection.query('SELECT COUNT(*) as count FROM users');
      expect(parseInt(result.rows[0].count)).toBe(1);

      // Cleanup
      await TestDatabaseConnection.cleanup();

      // Queries should fail after cleanup
      await expect(TestDatabaseConnection.query('SELECT 1'))
        .rejects.toThrow('Test database not initialized. Call initialize() first.');
    });

    it('should reset initialization state after cleanup', async () => {
      await TestDatabaseConnection.initialize();
      await TestDatabaseConnection.cleanup();
      
      // Should be able to initialize again
      const pool = await TestDatabaseConnection.initialize();
      expect(pool).toBeDefined();
      
      const result = await pool.query('SELECT 1 as test');
      expect(result.rows[0].test).toBe(1);
    });

    it('should handle cleanup errors gracefully', async () => {
      await TestDatabaseConnection.initialize();
      
      // Even if there are errors during cleanup, it should not throw
      await expect(TestDatabaseConnection.cleanup()).resolves.not.toThrow();
    });
  });

  describe('Configuration Integration', () => {
    it('should use correct database configuration', async () => {
      await TestDatabaseConnection.initialize();
      
      const pool = TestDatabaseConnection.getPool();
      
      // Verify pool uses correct configuration
      expect(pool.options.host).toBe(TEST_DB_CONFIG.host);
      expect(pool.options.port).toBe(TEST_DB_CONFIG.port);
      expect(pool.options.user).toBe(TEST_DB_CONFIG.user);
      expect(pool.options.password).toBe(TEST_DB_CONFIG.password);
      expect(pool.options.database).toBe(TEST_DB_CONFIG.database);
      expect(pool.options.max).toBe(TEST_DB_CONFIG.max);
      expect(pool.options.connectionTimeoutMillis).toBe(TEST_DB_CONFIG.connectionTimeoutMillis);
      expect(pool.options.idleTimeoutMillis).toBe(TEST_DB_CONFIG.idleTimeoutMillis);
      expect(pool.options.ssl).toBe(TEST_DB_CONFIG.ssl);
    });

    it('should connect to test database only', async () => {
      await TestDatabaseConnection.initialize();
      
      const result = await TestDatabaseConnection.query('SELECT current_database()');
      const dbName = result.rows[0].current_database;
      
      expect(dbName).toBe('koutu_test');
      expect(dbName).toContain('test');
      expect(dbName).not.toBe('postgres');
      expect(dbName).not.toContain('prod');
    });
  });

  describe('Concurrent Access Patterns', () => {
    beforeEach(async () => {
      await TestDatabaseConnection.initialize();
    });

    it('should handle multiple simultaneous table operations', async () => {
      // Simulate multiple operations happening concurrently
      const operations = [
        TestDatabaseConnection.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ('concurrent1@example.com', 'hash1')
        `),
        TestDatabaseConnection.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ('concurrent2@example.com', 'hash2')
        `),
        TestDatabaseConnection.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ('concurrent3@example.com', 'hash3')
        `)
      ];

      await Promise.all(operations);

      // Verify all users were created
      const result = await TestDatabaseConnection.query(`
        SELECT COUNT(*) as count FROM users 
        WHERE email LIKE 'concurrent%@example.com'
      `);
      expect(parseInt(result.rows[0].count)).toBe(3);
    });

    it('should maintain data consistency under concurrent load', async () => {
      // Create a user first
      const userResult = await TestDatabaseConnection.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('load@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      // Multiple concurrent inserts for the same user
      const garmentInserts = Array.from({ length: 10 }, (_, i) => 
        TestDatabaseConnection.query(`
          INSERT INTO garment_items (user_id, name)
          VALUES ($1, $2)
        `, [userId, `Garment ${i}`])
      );

      await Promise.all(garmentInserts);

      // Verify all garments were inserted
      const result = await TestDatabaseConnection.query(`
        SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1
      `, [userId]);
      expect(parseInt(result.rows[0].count)).toBe(10);
    });

    it('should handle read/write concurrency correctly', async () => {
  // Insert initial data
  const userResult = await TestDatabaseConnection.query(`
    INSERT INTO users (email, password_hash) 
    VALUES ('readwrite@example.com', 'hash123')
    RETURNING id
  `);
  const userId = userResult.rows[0].id;

  // Mix of read and write operations - but wait for writes to complete first
  await Promise.all([
    TestDatabaseConnection.query(`
      INSERT INTO garment_items (user_id, name) VALUES ($1, 'Item 1')
    `, [userId]),
    TestDatabaseConnection.query(`
      INSERT INTO garment_items (user_id, name) VALUES ($1, 'Item 2')
    `, [userId])
  ]);

  // Then do reads
  const [countResult, emailResult] = await Promise.all([
    TestDatabaseConnection.query(`
      SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1
    `, [userId]),
    TestDatabaseConnection.query(`
      SELECT email FROM users WHERE id = $1
    `, [userId])
  ]);

  // Verify results
  expect(emailResult.rows[0].email).toBe('readwrite@example.com');
  expect(parseInt(countResult.rows[0].count)).toBe(2);
});
  });

  describe('Performance and Scalability', () => {
    beforeEach(async () => {
      await TestDatabaseConnection.initialize();
    });

    it('should handle bulk operations efficiently', async () => {
      const startTime = Date.now();
      
      // Bulk insert users
      const userInserts = Array.from({ length: 100 }, (_, i) => 
        TestDatabaseConnection.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ($1, 'hash')
        `, [`bulk${i}@example.com`])
      );
      
      await Promise.all(userInserts);
      
      const duration = Date.now() - startTime;
      console.log(`Bulk insert of 100 users took ${duration}ms`);
      
      // Verify all users were inserted
      const result = await TestDatabaseConnection.query(`
        SELECT COUNT(*) as count FROM users WHERE email LIKE 'bulk%@example.com'
      `);
      expect(parseInt(result.rows[0].count)).toBe(100);
      
      // Should complete in reasonable time
      expect(duration).toBeLessThan(5000);
    });

    it('should maintain performance under connection pressure', async () => {
      const iterations = 50;
      const startTime = Date.now();
      
      // Create many short-lived queries
      const queries = Array.from({ length: iterations }, (_, i) => 
        TestDatabaseConnection.query('SELECT $1::integer as iteration', [i])
      );
      
      const results = await Promise.all(queries);
      const duration = Date.now() - startTime;
      
      console.log(`${iterations} concurrent queries took ${duration}ms`);
      
      // All queries should succeed
      expect(results).toHaveLength(iterations);
      results.forEach((result, index) => {
        expect(result.rows[0].iteration).toBe(index);
      });
      
      // Should be efficient
      expect(duration).toBeLessThan(3000);
    });

    it('should handle complex aggregation queries efficiently', async () => {
      // Setup test data
      const userEmails = Array.from({ length: 50 }, (_, i) => `perf${i}@example.com`);
      
      for (const email of userEmails) {
        const userResult = await TestDatabaseConnection.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ($1, 'hash')
          RETURNING id
        `, [email]);
        
        const userId = userResult.rows[0].id;
        
        // Add related data
        await TestDatabaseConnection.query(`
          INSERT INTO garment_items (user_id, name)
          VALUES ($1, $2)
        `, [userId, `Garment for ${email}`]);
      }

      const startTime = Date.now();
      
      // Complex aggregation query
      const result = await TestDatabaseConnection.query(`
        SELECT 
          COUNT(DISTINCT u.id) as user_count,
          COUNT(g.id) as total_garments,
          AVG(garment_counts.garment_count) as avg_garments_per_user
        FROM users u
        LEFT JOIN garment_items g ON u.id = g.user_id
        LEFT JOIN (
          SELECT user_id, COUNT(*) as garment_count
          FROM garment_items
          GROUP BY user_id
        ) garment_counts ON u.id = garment_counts.user_id
        WHERE u.email LIKE 'perf%@example.com'
      `);
      
      const duration = Date.now() - startTime;
      console.log(`Complex aggregation query took ${duration}ms`);
      
      expect(parseInt(result.rows[0].user_count)).toBe(50);
      expect(parseInt(result.rows[0].total_garments)).toBe(50);
      
      // Should complete efficiently
      expect(duration).toBeLessThan(1000);
    });
  });
});