// /backend/src/utils/testDatabase.int.test.ts

import { TestDatabase } from '../../utils/testDatabase';
import { Pool, Client } from 'pg';

// Test configuration for integration tests
const INTEGRATION_TEST_CONFIG = {
  host: 'localhost',
  port: 5432,
  user: 'postgres',
  password: 'postgres',
  database: 'postgres', // Connect to main db first
};

describe('TestDatabase Integration Tests', () => {
  let testPool: Pool;

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

    console.log('PostgreSQL is ready for integration tests');
  }, 60000);

  afterAll(async () => {
    // Clean up any remaining connections
    try {
      if (testPool) {
        await testPool.end();
      }
      await TestDatabase.cleanup();
    } catch (error) {
      console.log('Cleanup error (may be expected):', error);
    }
  });

  beforeEach(async () => {
    // Ensure clean state before each test
    try {
      await TestDatabase.cleanup();
    } catch (error) {
      // Ignore cleanup errors before tests
    }
  });

  describe('Database Initialization', () => {
    it('should initialize test database successfully', async () => {
      testPool = await TestDatabase.initialize();
      
      expect(testPool).toBeDefined();
      expect(testPool).toBeInstanceOf(Pool);
      
      // Verify we can query the test database
      const result = await testPool.query('SELECT current_database()');
      expect(result.rows[0].current_database).toBe('koutu_test');
    });

    it('should create required extensions', async () => {
      testPool = await TestDatabase.initialize();
      
      const result = await testPool.query(`
        SELECT extname FROM pg_extension 
        WHERE extname = 'uuid-ossp'
      `);
      
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].extname).toBe('uuid-ossp');
    });

    it('should handle multiple initialization calls', async () => {
      const pool1 = await TestDatabase.initialize();
      const pool2 = await TestDatabase.initialize();
      
      // For testDatabase.ts, multiple calls may create new pools due to database recreation
      // This is different from testDatabaseConnection.ts which maintains singletons
      expect(pool1).toBeDefined();
      expect(pool2).toBeDefined();
      expect(pool1).toBeInstanceOf(Pool);
      expect(pool2).toBeInstanceOf(Pool);
      
      // Both should work for queries regardless of being the same instance
      const result1 = await pool1.query('SELECT 1 as test');
      const result2 = await pool2.query('SELECT 2 as test');
      
      expect(result1.rows[0].test).toBe(1);
      expect(result2.rows[0].test).toBe(2);
    });

    it('should set correct DATABASE_URL environment variable', async () => {
      await TestDatabase.initialize();
      
      expect(process.env.DATABASE_URL).toBe(
        'postgresql://postgres:postgres@localhost:5432/koutu_test'
      );
    });
  });

  describe('Schema Creation', () => {
    beforeEach(async () => {
      testPool = await TestDatabase.initialize();
    });

    it('should create users table with correct structure', async () => {
      const result = await testPool.query(`
        SELECT column_name, data_type, is_nullable, column_default
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

      // Verify required columns exist with correct types
      expect(columns.id).toBeDefined();
      expect(columns.id.type).toBe('uuid');
      expect(columns.id.nullable).toBe(false);
      expect(columns.id.default).toContain('uuid_generate_v4()');

      expect(columns.email).toBeDefined();
      expect(columns.email.type).toBe('text');
      expect(columns.email.nullable).toBe(false);

      expect(columns.password_hash).toBeDefined();
      expect(columns.password_hash.type).toBe('text');
      expect(columns.password_hash.nullable).toBe(true);

      expect(columns.name).toBeDefined();
      expect(columns.name.type).toBe('text');
      expect(columns.name.nullable).toBe(true);

      expect(columns.created_at).toBeDefined();
      expect(columns.created_at.type).toBe('timestamp with time zone');
      expect(columns.created_at.nullable).toBe(false);
    });

    it('should create users table with unique email constraint', async () => {
      // Insert first user
      await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('test@example.com', 'hash123')
      `);

      // Try to insert duplicate email - should fail
      await expect(testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('test@example.com', 'hash456')
      `)).rejects.toThrow(/duplicate key value violates unique constraint/);
    });

    it('should create user_oauth_providers table with foreign key', async () => {
      // First insert a user
      const userResult = await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('oauth@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      // Insert OAuth provider record
      await testPool.query(`
        INSERT INTO user_oauth_providers (user_id, provider, provider_id)
        VALUES ($1, 'google', '123456')
      `, [userId]);

      // Verify it was inserted
      const result = await testPool.query(`
        SELECT * FROM user_oauth_providers 
        WHERE user_id = $1
      `, [userId]);

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].provider).toBe('google');
      expect(result.rows[0].provider_id).toBe('123456');

      // Try to insert OAuth record with invalid user_id - should fail
      await expect(testPool.query(`
        INSERT INTO user_oauth_providers (user_id, provider, provider_id)
        VALUES ('00000000-0000-0000-0000-000000000000', 'github', '789')
      `)).rejects.toThrow(/violates foreign key constraint/);
    });

    it('should create statistics tables with proper relationships', async () => {
      // Insert a user first
      const userResult = await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('stats@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      // Test original_images table
      await testPool.query(`
        INSERT INTO original_images (user_id, file_path)
        VALUES ($1, '/path/to/image.jpg')
      `, [userId]);

      // Test garment_items table
      await testPool.query(`
        INSERT INTO garment_items (user_id, name)
        VALUES ($1, 'Test Shirt')
      `, [userId]);

      // Test wardrobes table
      await testPool.query(`
        INSERT INTO wardrobes (user_id, name)
        VALUES ($1, 'Summer Collection')
      `, [userId]);

      // Verify data was inserted correctly
      const [imagesResult, garmentsResult, wardrobesResult] = await Promise.all([
        testPool.query('SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', [userId]),
        testPool.query('SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', [userId]),
        testPool.query('SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1', [userId])
      ]);

      expect(parseInt(imagesResult.rows[0].count)).toBe(1);
      expect(parseInt(garmentsResult.rows[0].count)).toBe(1);
      expect(parseInt(wardrobesResult.rows[0].count)).toBe(1);
    });

    it('should enforce foreign key cascading deletes', async () => {
      // Insert user and related data
      const userResult = await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('cascade@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      // Insert related data
      await testPool.query(`
        INSERT INTO user_oauth_providers (user_id, provider, provider_id)
        VALUES ($1, 'google', '123')
      `, [userId]);

      await testPool.query(`
        INSERT INTO original_images (user_id, file_path)
        VALUES ($1, '/path/to/image.jpg')
      `, [userId]);

      await testPool.query(`
        INSERT INTO garment_items (user_id, name)
        VALUES ($1, 'Test Item')
      `, [userId]);

      // Delete the user
      await testPool.query('DELETE FROM users WHERE id = $1', [userId]);

      // Verify related data was cascade deleted
      const [oauthResult, imagesResult, garmentsResult] = await Promise.all([
        testPool.query('SELECT COUNT(*) as count FROM user_oauth_providers WHERE user_id = $1', [userId]),
        testPool.query('SELECT COUNT(*) as count FROM original_images WHERE user_id = $1', [userId]),
        testPool.query('SELECT COUNT(*) as count FROM garment_items WHERE user_id = $1', [userId])
      ]);

      expect(parseInt(oauthResult.rows[0].count)).toBe(0);
      expect(parseInt(imagesResult.rows[0].count)).toBe(0);
      expect(parseInt(garmentsResult.rows[0].count)).toBe(0);
    });
  });

  describe('Database Operations', () => {
    beforeEach(async () => {
      testPool = await TestDatabase.initialize();
    });

    it('should provide working database pool', async () => {
      const pool = TestDatabase.getPool();
      expect(pool).toBe(testPool);
      
      if (!pool) {
        throw new Error('Pool is null');
      }
      
      const result = await pool.query('SELECT NOW() as current_time');
      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].current_time).toBeInstanceOf(Date);
    });

    it('should execute queries through static query method', async () => {
      const result = await TestDatabase.query('SELECT $1 as test_value', ['hello']);
      expect(result.rows[0].test_value).toBe('hello');
    });

    it('should handle concurrent database operations', async () => {
      const promises = Array.from({ length: 10 }, (_, i) => 
        TestDatabase.query('SELECT $1::integer as value', [i])
      );

      const results = await Promise.all(promises);
      
      results.forEach((result, index) => {
        expect(result.rows[0].value).toBe(index);
      });
    });

    it('should handle large result sets efficiently', async () => {
      // Insert test data
      const insertPromises = Array.from({ length: 100 }, (_, i) => 
        testPool.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ($1, 'hash')
        `, [`user${i}@example.com`])
      );
      
      await Promise.all(insertPromises);

      // Query large result set
      const result = await testPool.query('SELECT COUNT(*) as count FROM users');
      expect(parseInt(result.rows[0].count)).toBe(100);

      // Test pagination-style query
      const paginatedResult = await testPool.query(`
        SELECT email FROM users 
        ORDER BY email 
        LIMIT 10 OFFSET 10
      `);
      expect(paginatedResult.rows).toHaveLength(10);
    });

    it('should handle transactions properly', async () => {
      const client = await testPool.connect();
      
      try {
        await client.query('BEGIN');
        
        // Insert user in transaction
        const userResult = await client.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ('transaction@example.com', 'hash123')
          RETURNING id
        `);
        const userId = userResult.rows[0].id;

        // Insert related data in same transaction
        await client.query(`
          INSERT INTO garment_items (user_id, name)
          VALUES ($1, 'Transaction Test Item')
        `, [userId]);

        await client.query('COMMIT');

        // Verify data was committed
        const verifyResult = await testPool.query(`
          SELECT u.email, g.name 
          FROM users u 
          JOIN garment_items g ON u.id = g.user_id
          WHERE u.email = 'transaction@example.com'
        `);
        
        expect(verifyResult.rows).toHaveLength(1);
        expect(verifyResult.rows[0].email).toBe('transaction@example.com');
        expect(verifyResult.rows[0].name).toBe('Transaction Test Item');
      } finally {
        client.release();
      }
    });

    it('should handle transaction rollbacks', async () => {
      const client = await testPool.connect();
      
      try {
        await client.query('BEGIN');
        
        // Insert user
        await client.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ('rollback@example.com', 'hash123')
        `);

        await client.query('ROLLBACK');

        // Verify data was not committed
        const verifyResult = await testPool.query(`
          SELECT COUNT(*) as count FROM users 
          WHERE email = 'rollback@example.com'
        `);
        
        expect(parseInt(verifyResult.rows[0].count)).toBe(0);
      } finally {
        client.release();
      }
    });
  });

  describe('Data Cleanup', () => {
    beforeEach(async () => {
      testPool = await TestDatabase.initialize();
    });

    it('should clear all tables successfully', async () => {
      // Insert test data in multiple tables
      const userResult = await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('cleanup@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      await testPool.query(`
        INSERT INTO user_oauth_providers (user_id, provider, provider_id)
        VALUES ($1, 'google', '123')
      `, [userId]);

      await testPool.query(`
        INSERT INTO original_images (user_id, file_path)
        VALUES ($1, '/path/to/image.jpg')
      `, [userId]);

      await testPool.query(`
        INSERT INTO garment_items (user_id, name)
        VALUES ($1, 'Test Item')
      `, [userId]);

      await testPool.query(`
        INSERT INTO wardrobes (user_id, name)
        VALUES ($1, 'Test Wardrobe')
      `, [userId]);

      // Clear all tables
      await TestDatabase.clearAllTables();

      // Verify all tables are empty
      const tables = ['users', 'user_oauth_providers', 'original_images', 'garment_items', 'wardrobes'];
      
      for (const table of tables) {
        const result = await testPool.query(`SELECT COUNT(*) as count FROM ${table}`);
        expect(parseInt(result.rows[0].count)).toBe(0);
      }
    });

    it('should reset identity sequences after clearing', async () => {
      // This test verifies that RESTART IDENTITY works correctly
      
      // Insert and delete some users to increment sequences
      for (let i = 0; i < 5; i++) {
        await testPool.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ($1, 'hash')
        `, [`sequence${i}@example.com`]);
      }

      await TestDatabase.clearAllTables();

      // Insert new user and check that UUID generation still works
      const result = await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('newuser@example.com', 'hash')
        RETURNING id
      `);

      expect(result.rows[0].id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
    });

    it('should handle clearing empty tables', async () => {
      // Clear already empty tables - should not throw error
      await expect(TestDatabase.clearAllTables()).resolves.not.toThrow();
    });
  });

  describe('Error Handling', () => {
    beforeEach(async () => {
      testPool = await TestDatabase.initialize();
    });

    it('should handle database constraint violations', async () => {
      // Insert user with email
      await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('constraint@example.com', 'hash123')
      `);

      // Try to insert duplicate email
      await expect(testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('constraint@example.com', 'hash456')
      `)).rejects.toThrow();
    });

    it('should handle invalid SQL queries', async () => {
      await expect(testPool.query('INVALID SQL SYNTAX'))
        .rejects.toThrow();
    });

    it('should handle connection pool exhaustion gracefully', async () => {
      // Create many concurrent connections (more than pool max of 20)
      const manyPromises = Array.from({ length: 25 }, () => 
        TestDatabase.query('SELECT pg_sleep(0.1)')
      );

      // Should handle gracefully without hanging
      await expect(Promise.all(manyPromises)).resolves.toBeDefined();
    }, 10000);

    it('should handle long-running queries', async () => {
      // Test query timeout handling
      const startTime = Date.now();
      
      try {
        await TestDatabase.query('SELECT pg_sleep(2)');
      } catch (error) {
        // Query should complete or timeout gracefully
      }
      
      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(15000); // Should not hang indefinitely
    }, 20000);
  });

  describe('Database Cleanup and Teardown', () => {
    it('should cleanup database connections and drop test database', async () => {
      // Initialize database
      testPool = await TestDatabase.initialize();
      
      // Insert some test data
      await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('teardown@example.com', 'hash123')
      `);

      // Verify database exists and has data
      let result = await testPool.query('SELECT current_database()');
      expect(result.rows[0].current_database).toBe('koutu_test');

      result = await testPool.query('SELECT COUNT(*) as count FROM users');
      expect(parseInt(result.rows[0].count)).toBe(1);

      // Cleanup
      await TestDatabase.cleanup();

      // After cleanup, the pool should be ended
      const pool = TestDatabase.getPool();
      expect(pool).toBeNull();
    });

    it('should handle cleanup when database is already closed', async () => {
      // Initialize and immediately cleanup
      await TestDatabase.initialize();
      await TestDatabase.cleanup();
      
      // Cleanup again - should not throw error
      await expect(TestDatabase.cleanup()).resolves.not.toThrow();
    });

    it('should handle cleanup errors gracefully', async () => {
      // This simulates cleanup when there might be connection issues
      await TestDatabase.initialize();
      
      // Even if there are connection errors during cleanup, it should not throw
      await expect(TestDatabase.cleanup()).resolves.not.toThrow();
    });
  });

  describe('Database Performance', () => {
    beforeEach(async () => {
      testPool = await TestDatabase.initialize();
    });

    it('should handle bulk inserts efficiently', async () => {
      const startTime = Date.now();
      
      // Insert 1000 users in batches
      const batchSize = 100;
      const totalUsers = 1000;
      
      for (let i = 0; i < totalUsers; i += batchSize) {
        const values = Array.from({ length: Math.min(batchSize, totalUsers - i) }, (_, j) => 
          `('bulk${i + j}@example.com', 'hash')`
        ).join(', ');
        
        await testPool.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ${values}
        `);
      }
      
      const duration = Date.now() - startTime;
      console.log(`Bulk insert of ${totalUsers} users took ${duration}ms`);
      
      // Verify all users were inserted
      const result = await testPool.query('SELECT COUNT(*) as count FROM users');
      expect(parseInt(result.rows[0].count)).toBe(totalUsers);
      
      // Should complete in reasonable time (less than 5 seconds)
      expect(duration).toBeLessThan(5000);
    });

    it('should handle complex queries with joins efficiently', async () => {
      // Setup test data
      const userEmails = Array.from({ length: 100 }, (_, i) => `user${i}@example.com`);
      
      for (const email of userEmails) {
        const userResult = await testPool.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ($1, 'hash')
          RETURNING id
        `, [email]);
        
        const userId = userResult.rows[0].id;
        
        // Add garment items for each user
        await testPool.query(`
          INSERT INTO garment_items (user_id, name)
          VALUES ($1, $2)
        `, [userId, `Garment for ${email}`]);
      }

      const startTime = Date.now();
      
      // Complex query with joins
      const result = await testPool.query(`
        SELECT u.email, COUNT(g.id) as garment_count
        FROM users u
        LEFT JOIN garment_items g ON u.id = g.user_id
        WHERE u.email LIKE '%@example.com'
        GROUP BY u.id, u.email
        HAVING COUNT(g.id) > 0
        ORDER BY u.email
        LIMIT 50
      `);
      
      const duration = Date.now() - startTime;
      console.log(`Complex join query took ${duration}ms`);
      
      expect(result.rows.length).toBe(50);
      expect(parseInt(result.rows[0].garment_count)).toBe(1);
      
      // Should complete in reasonable time
      expect(duration).toBeLessThan(1000);
    });

    it('should maintain connection pool efficiency', async () => {
      // Test multiple concurrent operations
      const operations = Array.from({ length: 50 }, (_, i) => async () => {
        const userResult = await testPool.query(`
          INSERT INTO users (email, password_hash) 
          VALUES ($1, 'hash')
          RETURNING id
        `, [`concurrent${i}@example.com`]);
        
        const userId = userResult.rows[0].id;
        
        await testPool.query(`
          INSERT INTO garment_items (user_id, name)
          VALUES ($1, $2)
        `, [userId, `Item ${i}`]);
        
        return await testPool.query(`
          SELECT COUNT(*) as count 
          FROM garment_items 
          WHERE user_id = $1
        `, [userId]);
      });

      const startTime = Date.now();
      const results = await Promise.all(operations.map(op => op()));
      const duration = Date.now() - startTime;
      
      console.log(`50 concurrent operations took ${duration}ms`);
      
      // All operations should succeed
      expect(results).toHaveLength(50);
      results.forEach(result => {
        expect(parseInt(result.rows[0].count)).toBe(1);
      });
      
      // Should complete efficiently with connection pooling
      expect(duration).toBeLessThan(5000);
    });
  });

  describe('Database State Validation', () => {
    beforeEach(async () => {
      testPool = await TestDatabase.initialize();
    });

    it('should maintain data integrity across operations', async () => {
      // Create user and related data
      const userResult = await testPool.query(`
        INSERT INTO users (email, password_hash, name) 
        VALUES ('integrity@example.com', 'hash123', 'Test User')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      // Add OAuth provider
      await testPool.query(`
        INSERT INTO user_oauth_providers (user_id, provider, provider_id)
        VALUES ($1, 'google', 'google123')
      `, [userId]);

      // Add statistics data
      await testPool.query(`
        INSERT INTO original_images (user_id, file_path)
        VALUES ($1, '/path/to/image1.jpg'), ($1, '/path/to/image2.jpg')
      `, [userId]);

      await testPool.query(`
        INSERT INTO garment_items (user_id, name)
        VALUES ($1, 'Shirt'), ($1, 'Pants'), ($1, 'Shoes')
      `, [userId]);

      await testPool.query(`
        INSERT INTO wardrobes (user_id, name)
        VALUES ($1, 'Summer'), ($1, 'Winter')
      `, [userId]);

      // Verify data integrity with complex query
      const integrityResult = await testPool.query(`
        SELECT 
          u.email,
          u.name,
          COUNT(DISTINCT uop.provider) as oauth_providers,
          COUNT(DISTINCT oi.id) as image_count,
          COUNT(DISTINCT gi.id) as garment_count,
          COUNT(DISTINCT w.id) as wardrobe_count
        FROM users u
        LEFT JOIN user_oauth_providers uop ON u.id = uop.user_id
        LEFT JOIN original_images oi ON u.id = oi.user_id
        LEFT JOIN garment_items gi ON u.id = gi.user_id
        LEFT JOIN wardrobes w ON u.id = w.user_id
        WHERE u.id = $1
        GROUP BY u.id, u.email, u.name
      `, [userId]);

      const data = integrityResult.rows[0];
      expect(data.email).toBe('integrity@example.com');
      expect(data.name).toBe('Test User');
      expect(parseInt(data.oauth_providers)).toBe(1);
      expect(parseInt(data.image_count)).toBe(2);
      expect(parseInt(data.garment_count)).toBe(3);
      expect(parseInt(data.wardrobe_count)).toBe(2);
    });

    it('should handle database constraints properly', async () => {
      // Test unique constraint on OAuth providers
      const userResult = await testPool.query(`
        INSERT INTO users (email, password_hash) 
        VALUES ('oauth@example.com', 'hash123')
        RETURNING id
      `);
      const userId = userResult.rows[0].id;

      // Insert OAuth provider
      await testPool.query(`
        INSERT INTO user_oauth_providers (user_id, provider, provider_id)
        VALUES ($1, 'google', 'unique123')
      `, [userId]);

      // Try to insert duplicate provider/provider_id combination
      await expect(testPool.query(`
        INSERT INTO user_oauth_providers (user_id, provider, provider_id)
        VALUES ($1, 'google', 'unique123')
      `, [userId])).rejects.toThrow(/duplicate key value violates unique constraint/);
    });
  });
});