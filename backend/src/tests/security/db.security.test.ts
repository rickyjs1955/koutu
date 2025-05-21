// filepath: /backend/src/tests/security/db.security.test.ts

/**
 * Security Test Suite for Database Utility (db.ts)
 *
 * This suite focuses on security-specific behaviors of the database utility functions in db.ts,
 * ensuring protection against SQL injection, unauthorized access, information leakage, resource exhaustion,
 * and secure pool cleanup. It builds on the unit and integration test suites, avoiding duplication by
 * focusing on advanced security scenarios.
 */

import { Pool, PoolClient, DatabaseError, QueryResult } from 'pg';
import { query, getClient, pool, closePool } from '../../models/db';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';

jest.mock('../../config', () => ({
  config: {
    databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
    nodeEnv: 'test',
  },
}));

// Type guard for pg.DatabaseError
const isDatabaseError = (error: unknown): error is DatabaseError => {
  return error instanceof Error && 'code' in error && 'message' in error;
};

// Type guard for error result in resource exhaustion test
const isErrorResult = (result: QueryResult<any> | { error: unknown }): result is { error: unknown } => {
  return 'error' in result;
};

describe('Database Utility Security Tests', () => {
    let testPool: Pool;

    beforeAll(async () => {
        await setupTestDatabase();
        testPool = new Pool({
        host: 'localhost',
        port: 5433,
        user: 'postgres',
        password: 'password',
        database: 'koutu-postgres-test',
        connectionTimeoutMillis: 5000,
        });
    });

    beforeEach(async () => {
        await testPool.query('TRUNCATE TABLE test_table, parent_cleanup, child_cleanup, exclude_test_table CASCADE');
    });

    afterAll(async () => {
        try {
        await teardownTestDatabase();
        await testPool.end();
        await closePool();
        } catch (error) {
        console.error('Failed to clean up test resources:', error);
        }
    });

    describe('SQL Injection Prevention', () => {
        it('should prevent multi-statement SQL injection attempts', async () => {
        const maliciousInput = "test'; SELECT pg_sleep(5); --";
        const result = await query('SELECT * FROM test_table WHERE value = $1', [maliciousInput]);

        expect(result.rows).toHaveLength(0);
        expect(result.command).toBe('SELECT');
        });

        it('should handle malformed parameterized inputs safely', async () => {
        const maliciousInputs = [null, undefined, { toString: () => "'; DROP TABLE test_table; --" }];

        for (const input of maliciousInputs) {
            const result = await query('SELECT * FROM test_table WHERE value = $1', [input]);
            expect(result.rows).toHaveLength(0);
        }

        const tableCheck = await testPool.query('SELECT * FROM information_schema.tables WHERE table_name = $1', ['test_table']);
        expect(tableCheck.rows).toHaveLength(1);
        });
    });

    describe('Connection String Security', () => {
        it('should not expose connection string in error messages', async () => {
        const mockQuery = jest.spyOn(pool, 'query').mockImplementationOnce(() => {
            throw new Error('Connection failed');
        });

        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        await expect(query('SELECT NOW()')).rejects.toThrow('Connection failed');

        expect(consoleSpy).toHaveBeenCalled();
        const errorLog = consoleSpy.mock.calls[0][0] as string;
        expect(errorLog).not.toContain('postgres://');
        expect(errorLog).not.toContain('postgres:password');
        expect(errorLog).not.toContain('localhost:5433');
        consoleSpy.mockRestore();
        mockQuery.mockRestore();
        });

        it('should handle invalid connection strings securely', async () => {
        jest.resetModules();
        jest.doMock('pg', () => ({
            Pool: jest.fn().mockImplementation(() => {
            throw new Error('Invalid connection string');
            }),
        }));
        jest.doMock('../../config', () => ({
            config: {
            databaseUrl: 'invalid://connection',
            nodeEnv: 'test',
            },
        }));

        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        let error: unknown;
        try {
            require('../../models/db');
        } catch (e) {
            error = e;
        }

        expect(error).toBeDefined();
        if (isDatabaseError(error) || error instanceof Error) {
            expect(error.message).toContain('Invalid connection string');
            expect(error.message).not.toContain('invalid://connection');
        } else {
            throw new Error('Expected an Error or DatabaseError');
        }
        consoleSpy.mockRestore();
        jest.resetAllMocks();
        jest.unmock('pg'); // Explicitly unmock pg to prevent leakage
        });
    });

    describe('Privilege Escalation Prevention', () => {
        it('should prevent unauthorized schema modifications', async () => {
        const limitedUser = 'security_test_user';
        await testPool.query(`
            DO $$
            BEGIN
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${limitedUser}') THEN
                CREATE USER ${limitedUser} WITH PASSWORD 'test';
                GRANT CONNECT ON DATABASE "koutu-postgres-test" TO ${limitedUser};
                GRANT USAGE ON SCHEMA public TO ${limitedUser};
                GRANT SELECT ON test_table TO ${limitedUser};
            END IF;
            END $$;
        `);

        const limitedPool = new Pool({
            host: 'localhost',
            port: 5433,
            user: limitedUser,
            password: 'test',
            database: 'koutu-postgres-test',
            connectionTimeoutMillis: 5000,
        });

        try {
            const selectResult = await limitedPool.query('SELECT * FROM test_table');
            expect(selectResult.rows).toHaveLength(0);

            await expect(
            limitedPool.query('CREATE TABLE unauthorized_table (id SERIAL PRIMARY KEY)')
            ).rejects.toThrow(
            expect.objectContaining({
                message: expect.stringContaining('permission denied'),
            })
            );

            await expect(
            limitedPool.query("INSERT INTO test_table (value) VALUES ('test')")
            ).rejects.toThrow(
            expect.objectContaining({
                message: expect.stringContaining('permission denied'),
            })
            );
        } catch (error: unknown) {
            if (isDatabaseError(error)) {
            console.error(`Database error: ${error.message}, code: ${error.code}`);
            }
            throw error;
        } finally {
            await limitedPool.end();
            await testPool.query(`DROP OWNED BY ${limitedUser} CASCADE`);
            await testPool.query(`DROP ROLE IF EXISTS ${limitedUser}`);
        }
        });
    });

    describe('Error Exposure Prevention', () => {
        it('should not leak stack traces in query errors', async () => {
        const mockQuery = jest.spyOn(pool, 'query').mockImplementationOnce(() => {
            throw new Error('Internal database error');
        });

        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        await expect(query('SELECT * FROM non_existent_table')).rejects.toThrow('Internal database error');

        expect(consoleSpy).toHaveBeenCalled();
        const errorLog = consoleSpy.mock.calls[0][0] as string;
        expect(errorLog).toContain('Query failed');
        expect(errorLog).not.toContain('stack');
        consoleSpy.mockRestore();
        mockQuery.mockRestore();
        });

        it('should log query text in errors but not sensitive credentials', async () => {
        const mockQuery = jest.spyOn(pool, 'query').mockImplementationOnce(() => {
            throw new Error('relation "non_existent_table" does not exist');
        });

        const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        await expect(query('SELECT * FROM non_existent_table')).rejects.toThrow();

        expect(consoleSpy).toHaveBeenCalled();
        const errorLog = consoleSpy.mock.calls[0][0] as string;
        expect(errorLog).toContain('Query failed');
        expect(errorLog).toContain('non_existent_table');
        expect(errorLog).not.toContain('postgres:password');
        consoleSpy.mockRestore();
        mockQuery.mockRestore();
        });
    });

    describe('Resource Exhaustion Prevention', () => {
        it('should handle excessive query attempts gracefully', async () => {
        const queryPromises = Array(50).fill(null).map(() =>
            query('SELECT NOW()').catch((e) => ({ error: e }))
        );

        const results = await Promise.all(queryPromises);
        const errors = results.filter(isErrorResult);

        expect(errors.length).toBeLessThan(10);
        expect(results.some((r) => !isErrorResult(r))).toBe(true);
        });

        it('should prevent connection pool exhaustion', async () => {
        const limitedPool = new Pool({
            host: 'localhost',
            port: 5433,
            user: 'postgres',
            password: 'password',
            database: 'koutu-postgres-test',
            max: 2,
            connectionTimeoutMillis: 1000,
        });

        let clients: PoolClient[] = [];
        try {
            clients = await Promise.all([getClient(), getClient()]);
            const thirdClientPromise = getClient();

            clients[0].release();
            const thirdClient = await thirdClientPromise;
            expect(thirdClient).toBeDefined();
            clients[1].release();
            thirdClient.release();
        } catch (error: unknown) {
            if (isDatabaseError(error) || error instanceof Error) {
            expect(error.message).not.toContain('password');
            } else {
            throw new Error('Expected an Error or DatabaseError');
            }
        } finally {
            await limitedPool.end();
        }
        });
    });

    describe('Secure Client Management', () => {
        it('should prevent client hijacking through shared references', async () => {
        const client1 = await getClient();
        const client2 = await getClient();

        expect(client1).not.toBe(client2);

        const mockQuery1 = jest.fn().mockResolvedValue({ rows: [{ id: 1 }], rowCount: 1 });
        const mockQuery2 = jest.fn().mockResolvedValue({ rows: [{ id: 2 }], rowCount: 1 });

        (client1 as any).query = mockQuery1;
        (client2 as any).query = mockQuery2;

        await client1.query('SELECT * FROM test_table WHERE id = 1');
        await client2.query('SELECT * FROM test_table WHERE id = 2');

        expect(mockQuery1).toHaveBeenCalledWith('SELECT * FROM test_table WHERE id = 1');
        expect(mockQuery2).toHaveBeenCalledWith('SELECT * FROM test_table WHERE id = 2');

        client1.release();
        client2.release();
        });

        it('should ensure clients are released after errors', async () => {
        const mockRelease = jest.fn();
        const mockConnect = jest.spyOn(pool, 'connect').mockImplementationOnce(async () => ({
            query: jest.fn().mockRejectedValueOnce(new Error('Query failed')),
            release: mockRelease,
        }));

        let client: PoolClient | undefined;
        try {
            client = await getClient();
            await client.query('SELECT * FROM test_table');
        } catch (error: unknown) {
            if (isDatabaseError(error) || error instanceof Error) {
            expect(error.message).toBe('Query failed');
            } else {
            throw new Error('Expected an Error or DatabaseError');
            }
        } finally {
            if (client) {
            client.release();
            expect(mockRelease).toHaveBeenCalled();
            }
            mockConnect.mockRestore();
        }
        });
    });

    // Isolated describe block for pool cleanup tests with extensive logging
    describe('Pool Cleanup Security', () => {
        let pool: Pool | undefined;
        let closePool: (() => Promise<void>) | undefined;
        let isPoolClosed = false; // Track pool closure to prevent multiple end calls

        beforeAll(async () => {
            jest.resetAllMocks();
            jest.resetModules();
            jest.unmock('pg'); // Ensure pg is not mocked
            
            jest.doMock('../../config', () => ({
            config: {
                databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                nodeEnv: 'test',
            },
            }));
            
            try {
            const dbModule = require('../../models/db');
            if (dbModule.pool && typeof dbModule.closePool === 'function') {
                pool = dbModule.pool;
                closePool = dbModule.closePool;
                
                Object.assign(module.exports, {
                query: dbModule.query,
                getClient: dbModule.getClient,
                pool: dbModule.pool,
                closePool: dbModule.closePool,
                });
            } else {
                throw new Error('Invalid db.ts exports: missing pool or closePool');
            }
            } catch (error) {
            throw error;
            }
        });

        afterAll(async () => {
            try {
            if (closePool && !isPoolClosed) {
                await closePool();
                isPoolClosed = true;
            }
            } catch (error) {
            console.error('Failed to close pool:', error); // Keep error logging for debugging
            }
        });

        it('should securely close the pool without leaking sensitive information', async () => {
            if (!pool || !closePool) {
            throw new Error('Pool or closePool not initialized');
            }
            
            // Mock the specific pool instance's end method to throw an error
            const mockEnd = jest.spyOn(pool, 'end').mockImplementationOnce(() => {
            return Promise.reject(new Error('Pool termination failed'));
            });
            
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

            await expect(closePool()).rejects.toThrow('Pool termination failed');

            expect(consoleSpy).toHaveBeenCalled();
            const errorLog = consoleSpy.mock.calls[0][0] as string;
            expect(errorLog).toContain('Failed to close database pool');
            expect(errorLog).not.toContain('postgres://');
            expect(errorLog).not.toContain('postgres:password');
            expect(errorLog).not.toContain('localhost:5433');

            consoleSpy.mockRestore();
            mockEnd.mockRestore();
            isPoolClosed = false; // Reset this so we can close in the next test
        });

        it('should ensure no connections remain after closePool', async () => {
        if (!pool || !closePool) {
            throw new Error('Pool or closePool not initialized');
        }
        
        // Create a fresh pool for this test to avoid the "already closed" error
        jest.resetModules();
        const freshDbModule = require('../../models/db');
        pool = freshDbModule.pool;
        closePool = freshDbModule.closePool;
        
        // Get and release a client to test pool management
        const client = await freshDbModule.getClient();
        client.release();

        // Close the pool
        if (closePool) {
            await closePool();
            isPoolClosed = true; // Mark pool as closed to skip afterAll cleanup
            console.log('Pool Cleanup Security: closePool completed');
        } else {
            throw new Error('closePool is not defined');
        }

        // Mock console.error before the query that's expected to fail
        const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        
        try {
            // Verify we can't use the pool after closing
            await expect(freshDbModule.query('SELECT NOW()')).rejects.toThrow(/Cannot use a pool after calling end/);
        } finally {
            // Always restore the mock
            errorSpy.mockRestore();
        }

        // Verify no connections remain
        expect(pool && pool.totalCount).toBe(0);
        expect(pool && pool.idleCount).toBe(0);
        expect(pool && pool.waitingCount).toBe(0);
        });
    });
});