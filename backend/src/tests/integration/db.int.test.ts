// /backend/src/__tests__/integration/db.int.test.ts

/**
 * @file Database Integration Tests
 * 
 * @description Full integration tests for the database module using a real PostgreSQL
 * database running in Docker. Tests actual database connections, query execution,
 * transaction handling, and connection pool management under real conditions.
 * 
 * @requirements
 * - Docker with PostgreSQL container running
 * - Test database configuration
 * - Network connectivity to database
 * 
 * @coverage
 * - Real database connection establishment
 * - Query execution with actual SQL
 * - Transaction management
 * - Connection pool behavior under load
 * - Error handling with real database errors
 * - Performance characteristics
 * - Concurrent operations
 */

import { jest, describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import { Pool, PoolClient } from 'pg';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';

// Test data generators
import { v4 as uuidv4 } from 'uuid';

describe('Database Integration Tests', () => {
  let testPool: Pool;
  
  const createdTestTables: string[] = [];
  const createdTestData: Array<{ table: string; id: string }> = [];

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';
    
    await setupTestDatabase();
    
    // Use correct database credentials from testSetup.ts
    testPool = new Pool({
      host: 'localhost',
      port: 5433,
      user: 'postgres',
      password: 'postgres',
      database: 'koutu_test',
      max: 10,
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 10000,
    });

    try {
      const result = await testPool.query('SELECT NOW() as current_time');
      console.log('✅ Integration test database connected:', result.rows[0].current_time);
    } catch (error) {
      console.error('❌ Failed to connect to integration test database:', error);
      throw error;
    }
  });

  afterAll(async () => {
    // Clean up test data
    for (const { table, id } of createdTestData.reverse()) {
      try {
        await testPool.query(`DELETE FROM ${table} WHERE id = $1`, [id]);
      } catch (error) {
        console.warn(`Failed to clean up test data from ${table}:`, error);
      }
    }

    // Clean up test tables
    for (const tableName of createdTestTables.reverse()) {
      try {
        await testPool.query(`DROP TABLE IF EXISTS ${tableName} CASCADE`);
      } catch (error) {
        console.warn(`Failed to drop test table ${tableName}:`, error);
      }
    }

    if (testPool) {
      await testPool.end();
    }

    await teardownTestDatabase();
  });

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Database Connection', () => {
    it('should establish connection to real database', async () => {
      const result = await testPool.query('SELECT version() as version, NOW() as current_time');

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0].version).toContain('PostgreSQL');
      expect(result.rows[0].current_time).toBeInstanceOf(Date);
    });

    it('should handle multiple concurrent connections', async () => {
      const connectionPromises = Array.from({ length: 5 }, (_, i) =>
        testPool.query('SELECT $1::int as connection_id, NOW() as timestamp', [i]) // Cast to int
      );

      const results = await Promise.all(connectionPromises);

      expect(results).toHaveLength(5);
      results.forEach((result, index) => {
        expect(result.rows[0].connection_id).toBe(index); // Now correctly returns integer
        expect(result.rows[0].timestamp).toBeInstanceOf(Date);
      });
    });

    it('should handle connection pool exhaustion gracefully', async () => {
      const clients: PoolClient[] = [];
      const maxConnections = testPool.options.max || 10;

      try {
        for (let i = 0; i < maxConnections; i++) {
          const client = await testPool.connect();
          clients.push(client);
        }

        const timeoutPromise = testPool.connect();
        
        setTimeout(() => {
          if (clients.length > 0) {
            clients[0].release();
            clients.shift();
          }
        }, 1000);

        const finalClient = await timeoutPromise;
        expect(finalClient).toBeDefined();
        finalClient.release();

      } finally {
        clients.forEach(client => client.release());
      }
    });
  });

  describe('Query Execution', () => {
    it('should execute SELECT queries successfully', async () => {
      const result = await testPool.query(
        'SELECT $1::text as message, $2::int as number, $3::boolean as flag',
        ['Hello, World!', 42, true]
      );

      expect(result.rows).toHaveLength(1);
      expect(result.rows[0]).toEqual({
        message: 'Hello, World!',
        number: 42,
        flag: true
      });
    });

    it('should handle parameterized queries with various data types', async () => {
      const testData = {
        text: 'Integration test',
        number: 12345,
        decimal: 123.45,
        boolean: true,
        date: new Date('2024-01-15T10:30:00Z'),
        json: { key: 'value', array: [1, 2, 3] },
        array: ['item1', 'item2', 'item3'],
      };

      const result = await testPool.query(
        `SELECT 
          $1::text as text_val,
          $2::int as int_val,
          $3::decimal as decimal_val,
          $4::boolean as bool_val,
          $5::timestamp as date_val,
          $6::jsonb as json_val,
          $7::text[] as array_val`,
        [
          testData.text,
          testData.number,
          testData.decimal,
          testData.boolean,
          testData.date,
          JSON.stringify(testData.json),
          testData.array
        ]
      );

      expect(result.rows).toHaveLength(1);
      const row = result.rows[0];
      expect(row.text_val).toBe(testData.text);
      expect(row.int_val).toBe(testData.number);
      expect(parseFloat(row.decimal_val)).toBe(testData.decimal);
      expect(row.bool_val).toBe(testData.boolean);
      expect(row.date_val).toEqual(testData.date);
      expect(row.json_val).toEqual(testData.json);
      expect(row.array_val).toEqual(testData.array);
    });

    it('should handle large result sets efficiently', async () => {
      const expectedRowCount = 1000;

      const start = Date.now();
      const result = await testPool.query(
        'SELECT generate_series(1, $1) as id, md5(random()::text) as data',
        [expectedRowCount]
      );
      const duration = Date.now() - start;

      expect(result.rows).toHaveLength(expectedRowCount);
      expect(result.rowCount).toBe(expectedRowCount);
      expect(duration).toBeLessThan(5000);
      
      expect(result.rows[0].id).toBe(1);
      expect(result.rows[expectedRowCount - 1].id).toBe(expectedRowCount);
      expect(result.rows[0].data).toMatch(/^[a-f0-9]{32}$/);
    });
  });

  describe('Database Operations with Real Tables', () => {
    let testTableName: string;

    beforeEach(async () => {
      // Create a unique test table for each test
      testTableName = `test_table_${uuidv4().replace(/-/g, '_')}`;
      
      await testPool.query(`
        CREATE TABLE ${testTableName} (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(255) NOT NULL,
          email VARCHAR(255) UNIQUE,
          age INTEGER CHECK (age >= 0 AND age <= 150),
          metadata JSONB DEFAULT '{}',
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )
      `);

      createdTestTables.push(testTableName);
    });

    it('should perform CRUD operations successfully', async () => {
      // CREATE
      const insertResult = await testPool.query(
        `INSERT INTO ${testTableName} (name, email, age, metadata) 
         VALUES ($1, $2, $3, $4) 
         RETURNING id, name, email, age, metadata, created_at`,
        ['John Doe', 'john@example.com', 30, JSON.stringify({ role: 'user' })]
      );

      expect(insertResult.rows).toHaveLength(1);
      const createdRecord = insertResult.rows[0];
      expect(createdRecord.id).toBeDefined();
      expect(createdRecord.name).toBe('John Doe');
      expect(createdRecord.email).toBe('john@example.com');
      expect(createdRecord.age).toBe(30);
      
      createdTestData.push({ table: testTableName, id: createdRecord.id });

      // READ
      const selectResult = await testPool.query(
        `SELECT * FROM ${testTableName} WHERE id = $1`,
        [createdRecord.id]
      );

      expect(selectResult.rows).toHaveLength(1);
      expect(selectResult.rows[0]).toMatchObject({
        id: createdRecord.id,
        name: 'John Doe',
        email: 'john@example.com',
        age: 30,
      });

      // UPDATE
      const updateResult = await testPool.query(
        `UPDATE ${testTableName} 
         SET name = $1, age = $2, updated_at = NOW() 
         WHERE id = $3 
         RETURNING *`,
        ['John Smith', 31, createdRecord.id]
      );

      expect(updateResult.rows).toHaveLength(1);
      expect(updateResult.rows[0].name).toBe('John Smith');
      expect(updateResult.rows[0].age).toBe(31);
      expect(new Date(updateResult.rows[0].updated_at).getTime())
        .toBeGreaterThan(new Date(createdRecord.created_at).getTime());

      // DELETE
      const deleteResult = await testPool.query(
        `DELETE FROM ${testTableName} WHERE id = $1`,
        [createdRecord.id]
      );

      expect(deleteResult.rowCount).toBe(1);

      // Verify deletion
      const verifyResult = await testPool.query(
        `SELECT * FROM ${testTableName} WHERE id = $1`,
        [createdRecord.id]
      );

      expect(verifyResult.rows).toHaveLength(0);
      
      // Remove from cleanup list since it's already deleted
      const cleanupIndex = createdTestData.findIndex(
        item => item.table === testTableName && item.id === createdRecord.id
      );
      if (cleanupIndex >= 0) {
        createdTestData.splice(cleanupIndex, 1);
      }
    });

    it('should handle constraint violations appropriately', async () => {
      // Create initial record
      const firstInsert = await testPool.query(
        `INSERT INTO ${testTableName} (name, email) VALUES ($1, $2) RETURNING id`,
        ['User One', 'unique@example.com']
      );
      
      createdTestData.push({ table: testTableName, id: firstInsert.rows[0].id });

      // Try to insert duplicate email
      await expect(
        testPool.query(
          `INSERT INTO ${testTableName} (name, email) VALUES ($1, $2)`,
          ['User Two', 'unique@example.com']
        )
      ).rejects.toThrow(/duplicate key value violates unique constraint/);

      // Try to insert invalid age
      await expect(
        testPool.query(
          `INSERT INTO ${testTableName} (name, age) VALUES ($1, $2)`,
          ['Invalid User', -5]
        )
      ).rejects.toThrow(/check constraint/);
    });

    it('should handle JSON operations correctly', async () => {
      // Insert record with complex JSON metadata
      const complexMetadata = {
        profile: {
          preferences: {
            theme: 'dark',
            notifications: true,
            language: 'en'
          },
          settings: {
            privacy: 'public',
            location: { city: 'San Francisco', country: 'USA' }
          }
        },
        tags: ['developer', 'javascript', 'postgresql'],
        metrics: {
          loginCount: 42,
          lastActive: '2024-01-15T10:30:00Z'
        }
      };

      const insertResult = await testPool.query(
        `INSERT INTO ${testTableName} (name, metadata) VALUES ($1, $2) RETURNING id, metadata`,
        ['JSON User', JSON.stringify(complexMetadata)]
      );

      const recordId = insertResult.rows[0].id;
      createdTestData.push({ table: testTableName, id: recordId });

      // Test JSON queries
      const jsonQueries = [
        // Extract nested values
        {
          query: `SELECT metadata->'profile'->'preferences'->>'theme' as theme FROM ${testTableName} WHERE id = $1`,
          params: [recordId],
          expected: 'dark'
        },
        // Test array operations
        {
          query: `SELECT jsonb_array_length(metadata->'tags') as tag_count FROM ${testTableName} WHERE id = $1`,
          params: [recordId],
          expected: 3
        },
        // Test JSON path queries - FIX: Remove quotes from expected value
        {
          query: `SELECT metadata #>> '{profile,settings,location,city}' as city FROM ${testTableName} WHERE id = $1`, // Use #>> instead of #>
          params: [recordId],
          expected: 'San Francisco' // Remove quotes from expected value
        }
      ];

      for (const { query, params, expected } of jsonQueries) {
        const result = await testPool.query(query, params);
        expect(result.rows[0]).toMatchObject(
          Object.fromEntries([[Object.keys(result.rows[0])[0], expected]])
        );
      }

      // Update JSON data
      await testPool.query(
        `UPDATE ${testTableName} 
         SET metadata = jsonb_set(metadata, '{profile,preferences,theme}', '"light"') 
         WHERE id = $1`,
        [recordId]
      );

      // Verify update
      const updatedResult = await testPool.query(
        `SELECT metadata->'profile'->'preferences'->>'theme' as theme FROM ${testTableName} WHERE id = $1`,
        [recordId]
      );

      expect(updatedResult.rows[0].theme).toBe('light');
    });
  });

  describe('Transaction Management', () => {
    let testTableName: string;

    beforeEach(async () => {
      testTableName = `transaction_test_${uuidv4().replace(/-/g, '_')}`;
      await testPool.query(`
        CREATE TABLE ${testTableName} (
          id SERIAL PRIMARY KEY,
          name VARCHAR(255),
          balance DECIMAL(10,2) DEFAULT 0.00
        )
      `);
      createdTestTables.push(testTableName);
    });

    it('should commit successful transactions', async () => {
      const client = await testPool.connect();
      
      try {
        // Begin transaction
        await client.query('BEGIN');

        // Insert multiple records
        const user1 = await client.query(
          `INSERT INTO ${testTableName} (name, balance) VALUES ($1, $2) RETURNING id`,
          ['Alice', 1000.00]
        );
        
        const user2 = await client.query(
          `INSERT INTO ${testTableName} (name, balance) VALUES ($1, $2) RETURNING id`,
          ['Bob', 500.00]
        );

        createdTestData.push(
          { table: testTableName, id: user1.rows[0].id.toString() },
          { table: testTableName, id: user2.rows[0].id.toString() }
        );

        // Commit transaction
        await client.query('COMMIT');

        // Verify data persisted
        const result = await testPool.query(`SELECT COUNT(*) as count FROM ${testTableName}`);
        expect(parseInt(result.rows[0].count)).toBe(2);

      } finally {
        client.release();
      }
    });

    it('should rollback failed transactions', async () => {
      const client = await testPool.connect();
      
      try {
        // Begin transaction
        await client.query('BEGIN');

        // Insert a valid record
        await client.query(
          `INSERT INTO ${testTableName} (name, balance) VALUES ($1, $2)`,
          ['Charlie', 750.00]
        );

        // Try to insert an invalid record (this should fail)
        await expect(
          client.query(
            `INSERT INTO ${testTableName} (name, balance) VALUES ($1, $2)`,
            ['Dave', 'invalid_balance'] // This will cause a type error
          )
        ).rejects.toThrow();

        // Rollback transaction
        await client.query('ROLLBACK');

        // Verify no data was persisted
        const result = await testPool.query(`SELECT COUNT(*) as count FROM ${testTableName}`);
        expect(parseInt(result.rows[0].count)).toBe(0);

      } finally {
        client.release();
      }
    });

    it('should handle concurrent transactions correctly', async () => {
      // Insert initial data
      const initialResult = await testPool.query(
        `INSERT INTO ${testTableName} (name, balance) VALUES ($1, $2) RETURNING id`,
        ['Concurrent User', 1000.00]
      );
      
      const userId = initialResult.rows[0].id;
      createdTestData.push({ table: testTableName, id: userId.toString() });

      // Simulate concurrent balance updates
      const transaction1 = async () => {
        const client = await testPool.connect();
        try {
          await client.query('BEGIN');
          
          // Read current balance
          const result = await client.query(
            `SELECT balance FROM ${testTableName} WHERE id = $1`,
            [userId]
          );
          const currentBalance = parseFloat(result.rows[0].balance);
          
          // Simulate processing time
          await new Promise(resolve => setTimeout(resolve, 100));
          
          // Update balance (subtract 200)
          await client.query(
            `UPDATE ${testTableName} SET balance = $1 WHERE id = $2`,
            [currentBalance - 200, userId]
          );
          
          await client.query('COMMIT');
          return 'transaction1_completed';
        } finally {
          client.release();
        }
      };

      const transaction2 = async () => {
        const client = await testPool.connect();
        try {
          await client.query('BEGIN');
          
          // Read current balance
          const result = await client.query(
            `SELECT balance FROM ${testTableName} WHERE id = $1`,
            [userId]
          );
          const currentBalance = parseFloat(result.rows[0].balance);
          
          // Simulate processing time
          await new Promise(resolve => setTimeout(resolve, 50));
          
          // Update balance (subtract 300)
          await client.query(
            `UPDATE ${testTableName} SET balance = $1 WHERE id = $2`,
            [currentBalance - 300, userId]
          );
          
          await client.query('COMMIT');
          return 'transaction2_completed';
        } finally {
          client.release();
        }
      };

      // Execute transactions concurrently
      const results = await Promise.all([transaction1(), transaction2()]);
      
      expect(results).toContain('transaction1_completed');
      expect(results).toContain('transaction2_completed');

      // Verify final balance (one of the transactions should have won)
      const finalResult = await testPool.query(
        `SELECT balance FROM ${testTableName} WHERE id = $1`,
        [userId]
      );
      
      const finalBalance = parseFloat(finalResult.rows[0].balance);
      // Final balance should be either 800 (1000-200) or 700 (1000-300)
      expect([700.00, 800.00]).toContain(finalBalance);
    });
  });

  describe('Error Handling with Real Database', () => {
    it('should handle invalid SQL syntax', async () => {
      await expect(
        testPool.query('INVALID SQL STATEMENT')
      ).rejects.toThrow(/syntax error/);
    });

    it('should handle non-existent table references', async () => {
      await expect(
        testPool.query('SELECT * FROM non_existent_table')
      ).rejects.toThrow(/relation "non_existent_table" does not exist/);
    });

    it('should handle connection timeouts', async () => {
      // Create a pool with very short timeout
      const shortTimeoutPool = new Pool({
        host: 'localhost',
        port: 5433,
        user: 'postgres',
        password: 'postgres',
        database: 'koutu_test',
        connectionTimeoutMillis: 1, // 1ms timeout
        max: 1
      });

      try {
        // This should timeout quickly
        await expect(
          shortTimeoutPool.query('SELECT pg_sleep(1)')
        ).rejects.toThrow();
      } finally {
        await shortTimeoutPool.end();
      }
    });

    it('should handle pool connection exhaustion', async () => {
      // Create a pool with only 1 connection
      const limitedPool = new Pool({
        host: 'localhost',
        port: 5433,
        user: 'postgres',
        password: 'postgres',
        database: 'koutu_test',
        max: 1,
        connectionTimeoutMillis: 1000 // 1 second timeout
      });

      const client1 = await limitedPool.connect();
      
      try {
        // This should timeout since pool is exhausted
        await expect(
          limitedPool.connect()
        ).rejects.toThrow();
      } finally {
        client1.release();
        await limitedPool.end();
      }
    });
  });

  describe('Performance Under Load', () => {
    it('should handle high concurrent query load', async () => {
      const concurrentQueries = 50;
      const queries = Array.from({ length: concurrentQueries }, (_, i) =>
        testPool.query(
          'SELECT $1 as query_id, pg_sleep(0.01), random() as random_value',
          [i]
        )
      );

      const start = Date.now();
      const results = await Promise.allSettled(queries);
      const duration = Date.now() - start;

      // All queries should succeed
      const successful = results.filter(r => r.status === 'fulfilled');
      expect(successful.length).toBe(concurrentQueries);

      // Should complete within reasonable time (considering connection pooling)
      expect(duration).toBeLessThan(10000); // 10 seconds max

      console.log(`✅ Completed ${concurrentQueries} concurrent queries in ${duration}ms`);
    });

    it('should maintain performance with large datasets', async () => {
      const testTableName = `performance_test_${uuidv4().replace(/-/g, '_')}`;
      
      try {
        // Create test table
        await testPool.query(`
          CREATE TABLE ${testTableName} (
            id SERIAL PRIMARY KEY,
            data TEXT,
            created_at TIMESTAMP DEFAULT NOW()
          )
        `);

        // Insert large dataset
        const batchSize = 1000;
        const batches = 5;
        
        for (let batch = 0; batch < batches; batch++) {
          const values = Array.from({ length: batchSize }, (_, i) => 
            `('Row ${batch * batchSize + i + 1} - ${Math.random().toString(36)}')`
          ).join(',');

          const insertStart = Date.now();
          await testPool.query(`
            INSERT INTO ${testTableName} (data) VALUES ${values}
          `);
          const insertDuration = Date.now() - insertStart;
          
          expect(insertDuration).toBeLessThan(5000); // Each batch should complete in under 5 seconds
        }

        // Test query performance on large dataset
        const queryStart = Date.now();
        const result = await testPool.query(`
          SELECT COUNT(*) as total_rows FROM ${testTableName}
        `);
        const queryDuration = Date.now() - queryStart;

        expect(parseInt(result.rows[0].total_rows)).toBe(batchSize * batches);
        expect(queryDuration).toBeLessThan(1000); // Count query should be fast

        console.log(`✅ Queried ${result.rows[0].total_rows} rows in ${queryDuration}ms`);

      } finally {
        // Clean up large test table
        await testPool.query(`DROP TABLE IF EXISTS ${testTableName}`);
      }
    });
  });

  describe('Connection Pool Behavior', () => {
    it('should handle connection timeouts', async () => {
      // Create a pool with very short timeout
      const shortTimeoutPool = new Pool({
        host: 'localhost',
        port: 5433,
        user: 'postgres',
        password: 'postgres',
        database: 'koutu_test',
        connectionTimeoutMillis: 1, // 1ms timeout
        max: 1
      });

      try {
        // This should timeout quickly
        await expect(
          shortTimeoutPool.query('SELECT pg_sleep(1)')
        ).rejects.toThrow();
      } finally {
        await shortTimeoutPool.end();
      }
    });

    it('should handle connection lifecycle correctly', async () => {
      const client = await testPool.connect();
      
      try {
        // Test that client is functional
        const result = await client.query('SELECT 1 as test');
        expect(result.rows[0].test).toBe(1);

        // Test that we can use the same client for multiple queries
        const result2 = await client.query('SELECT 2 as test');
        expect(result2.rows[0].test).toBe(2);

      } finally {
        // Release client back to pool
        client.release();
      }

      // Test that pool is still functional after client release
      const poolResult = await testPool.query('SELECT 3 as test');
      expect(poolResult.rows[0].test).toBe(3);
    });
  });

  describe('Database Module Integration', () => {
    it('should work with actual database module', async () => {
      // Set up test environment to use correct database
      process.env.TEST_DATABASE_URL = 'postgresql://postgres:postgres@localhost:5433/koutu_test';
      
      // Mock the config to use test database
      jest.doMock('../../config/index', () => ({
        config: {
          nodeEnv: 'test',
          databaseUrl: 'postgresql://postgres:postgres@localhost:5433/koutu_test',
          dbPoolMax: 5,
          dbConnectionTimeout: 3000,
          dbIdleTimeout: 5000,
          dbStatementTimeout: 10000,
          dbRequireSsl: false,
        }
      }));

      // Clear module cache and re-import
      jest.resetModules();
      
      const { query, getClient } = await import('../../models/db');

      const queryResult = await query('SELECT $1 as message', ['Integration test']);
      expect(queryResult.rows[0].message).toBe('Integration test');

      const client = await getClient();
      try {
        const clientResult = await client.query('SELECT $1 as client_test', ['Client test']);
        expect(clientResult.rows[0].client_test).toBe('Client test');
      } finally {
        client.release();
      }
    });

    it('should handle complex queries through database module', async () => {
      const { query } = await import('../../models/db');

      // Test with realistic application query
      const result = await query(`
        WITH test_data AS (
          SELECT 
            generate_series(1, 10) as id,
            'User ' || generate_series(1, 10) as name,
            (random() * 100)::int as score
        )
        SELECT 
          name,
          score,
          RANK() OVER (ORDER BY score DESC) as rank
        FROM test_data
        WHERE score > $1
        ORDER BY score DESC
      `, [50]);

      expect(result.rows.length).toBeGreaterThan(0);
      expect(result.rows[0]).toHaveProperty('name');
      expect(result.rows[0]).toHaveProperty('score');
      expect(result.rows[0]).toHaveProperty('rank');

      // Verify ranking is correct
      for (let i = 1; i < result.rows.length; i++) {
        expect(result.rows[i].score).toBeLessThanOrEqual(result.rows[i-1].score);
      }
    });
  });
});