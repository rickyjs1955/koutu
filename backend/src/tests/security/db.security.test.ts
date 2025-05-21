/**
 * Security Test Suite for Database Utility (db.ts)
 *
 * This suite focuses on security-specific behaviors of the database utility functions in db.ts,
 * ensuring protection against SQL injection, unauthorized access, information leakage, resource exhaustion,
 * and secure pool cleanup. It builds on the unit and integration test suites, avoiding duplication by
 * focusing on advanced security scenarios.
 */

import { Pool, PoolClient, DatabaseError, QueryResult } from 'pg';
// Rename the main pool and its closer to avoid ambiguity
import { query, getClient, pool as globalAppPool, closePool as globalAppClosePool, pool } from '../../models/db';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';
import { config as appConfig } from '../../config';

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
    let testPool: Pool; // This is the pool for direct test setup/assertions, separate from the app's pool

    beforeAll(async () => {
        await setupTestDatabase();
        testPool = new Pool({ // This pool is managed by testPool.end()
            host: 'localhost',
            port: 5433,
            user: 'postgres',
            password: 'password',
            database: 'koutu-postgres-test',
            connectionTimeoutMillis: 5000,
        });
    });

    afterAll(async () => {
        try {
            await teardownTestDatabase();
            if (testPool && typeof testPool.end === 'function' && !(testPool as any)._ended) { // Check if testPool exists and is not ended
                await testPool.end();
            }

            // Close the main application pool that was imported and used by `query`
            if (globalAppPool && typeof globalAppPool.end === 'function' && !globalAppPool.ended) {
                 await globalAppClosePool(); // Use the imported closePool for the main app pool
            }
        } catch (error) {
            console.error('[AFTER ALL] Failed to clean up test resources:', error);
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

        it('should prevent JSON/array parameter injection attempts', async () => {
            const maliciousJson = JSON.stringify({ test: "test'; DROP TABLE test_table; --" });
            const result = await query('SELECT * FROM test_table WHERE value = $1', [maliciousJson]);
            expect(result.rows).toHaveLength(0);

            const maliciousArray = ["normal", "test'; SELECT pg_sleep(5); --"];
            const arrayResult = await query('SELECT * FROM test_table WHERE value = ANY($1)', [maliciousArray]);
            expect(arrayResult.rows).toHaveLength(0);
        });

        it('should prevent type coercion attacks via toString()', async () => {
            const maliciousObject = {
                toString: () => "test'; DROP TABLE test_table; --"
            };
            const result = await query('SELECT * FROM test_table WHERE value = $1', [maliciousObject]);
            expect(result.rows).toHaveLength(0);
        });
    });

    describe('Connection String Security', () => {
        it('should not expose connection string in error messages', async () => {
            const mockQuery = jest.spyOn(pool, 'query').mockImplementationOnce(() => {
                throw new Error('Connection failed');
            });

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
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
            let consoleSpy: jest.SpyInstance | undefined;
            let error: unknown;

            try {
                jest.doMock('pg', () => {
                    return {
                        Pool: jest.fn().mockImplementation(() => {
                            throw new Error('Invalid connection string from mock');
                        }),
                    };
                });
                jest.doMock('../../config', () => {
                    return {
                        config: {
                            databaseUrl: 'invalid://connection',
                            nodeEnv: 'test',
                        },
                    };
                });

                consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
                require('../../models/db');
            } catch (e) {
                error = e;
            } finally {
                if (consoleSpy) {
                    consoleSpy.mockRestore();
                }
                jest.resetAllMocks();
                jest.unmock('pg');
                jest.unmock('../../config');
            }

            expect(error).toBeDefined();
            if (isDatabaseError(error) || error instanceof Error) {
                expect(error.message).toContain('Invalid connection string from mock');
                expect(error.message).not.toContain('invalid://connection');
            } else {
                throw new Error('Expected an Error or DatabaseError');
            }
        });

        it('should require SSL/TLS in production environment', async () => {
            jest.resetModules();

            const localConfig = {
                databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                nodeEnv: 'production',
                dbRequireSsl: true,
            };

            let error: unknown;
            let consoleErrorSpy: jest.SpyInstance | undefined;
            let sslDbModule;

            try {
                consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
                jest.doMock('../../config', () => {
                    return { config: localConfig };
                });
                sslDbModule = require('../../models/db');
                await sslDbModule.pool.query('SELECT 1');
            } catch (e) {
                error = e;
            } finally {
                if (consoleErrorSpy) {
                    consoleErrorSpy.mockRestore();
                }
                if (sslDbModule && sslDbModule.pool && typeof sslDbModule.pool.end === 'function' && !sslDbModule.pool.ended) {
                    await sslDbModule.pool.end().catch(() => {}); // Suppress close error if any
                }
                jest.resetModules();
                jest.mock('../../config', () => {
                    return {
                        config: {
                            databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                            nodeEnv: 'test',
                            dbRequireSsl: false,
                        },
                    };
                });
                require('../../config'); // Re-require to apply mock
            }

            expect(error).toBeDefined();
            if (error instanceof Error) {
                expect(error.message).toMatch(/The server does not support SSL connections|SSLRequired/i);
            } else {
                throw new Error('Expected an Error object for SSL failure.');
            }
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
            } finally {
                await limitedPool.end();
                await testPool.query(`DROP OWNED BY ${limitedUser} CASCADE`);
                await testPool.query(`DROP ROLE IF EXISTS ${limitedUser}`);
            }
        });

        it('should prevent SET ROLE privilege escalation', async () => {
            const limitedUser = 'security_test_user_2';
            await testPool.query(`
                DO $$
                BEGIN
                    CREATE ROLE ${limitedUser} WITH LOGIN PASSWORD 'test';
                    GRANT CONNECT ON DATABASE "koutu-postgres-test" TO ${limitedUser};
                    GRANT USAGE ON SCHEMA public TO ${limitedUser};
                    GRANT SELECT ON test_table TO ${limitedUser};
                EXCEPTION WHEN duplicate_object THEN
                    -- Role already exists
                END $$;
            `);

            const limitedPool = new Pool({
                host: 'localhost',
                port: 5433,
                user: limitedUser,
                password: 'test',
                database: 'koutu-postgres-test',
            });

            try {
                await expect(
                    limitedPool.query('SET ROLE postgres')
                ).rejects.toThrow(/permission denied/i);
            } finally {
                await limitedPool.end();
                await testPool.query(`DROP OWNED BY ${limitedUser} CASCADE`);
                await testPool.query(`DROP ROLE IF EXISTS ${limitedUser}`);
            }
        });
    });

    describe('Error Exposure Prevention', () => {
        it('should not leak stack traces in query errors', async () => {
            const mockActualPoolQuery = jest.spyOn(pool, 'query').mockImplementationOnce(() => {
                throw new Error('Internal database error');
            });

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
            await expect(query('SELECT * FROM non_existent_table')).rejects.toThrow('Internal database error');

            expect(consoleSpy).toHaveBeenCalled();
            const errorLog = consoleSpy.mock.calls.find(call => call[0].startsWith('Query failed:'))?.[0] as string;
            expect(errorLog).toBeDefined();
            if(errorLog) {
                expect(errorLog).toContain('Query failed');
                expect(errorLog).not.toContain('stack');
            }
            consoleSpy.mockRestore();
            mockActualPoolQuery.mockRestore();
        });

        it('should log query text in errors but not sensitive credentials', async () => {
            const mockQuery = jest.spyOn(pool, 'query').mockImplementationOnce(() => {
                throw new Error('relation "non_existent_table" does not exist');
            });

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
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

        it('should respect statement timeouts if set on a connection', async () => {
            const client = await getClient();
            let statementTimeoutError: unknown;
            try {
                await client.query('SET statement_timeout = 100');
                await client.query('SELECT pg_sleep(0.5)');
            } catch (error) {
                statementTimeoutError = error;
            } finally {
                try {
                    if (!(client as any)._connected || (client as any)._ending) {
                        // Client might be unusable
                    } else {
                        await client.query('SET statement_timeout = 0');
                    }
                } catch (resetError) {
                    // console.warn('Could not reset statement_timeout after test:', resetError);
                }
                client.release();
            }

            expect(statementTimeoutError).toBeDefined();
            if (isDatabaseError(statementTimeoutError)) {
                expect(statementTimeoutError.code).toBe('57014');
                expect(statementTimeoutError.message).toMatch(/canceling statement due to statement timeout/i);
            } else if (statementTimeoutError instanceof Error) {
                expect(statementTimeoutError.message).toMatch(/timeout/i);
            } else {
                throw new Error('Expected a DatabaseError or Error for statement timeout');
            }
        });

        it('should handle connection pool exhaustion gracefully', async () => {
            const maxConnections = 2;
            const acquireTimeout = 200;

            jest.resetModules();

            const mockConfigForThisTest = {
                databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                nodeEnv: 'test',
                dbPoolMax: maxConnections,
                dbConnectionTimeout: acquireTimeout,
                dbRequireSsl: false,
            };

            jest.doMock('../../config', () => {
                return { config: mockConfigForThisTest };
            });

            const { getClient: localGetClient, pool: localTestPool } = require('../../models/db');

            expect(localTestPool.options.max).toBe(maxConnections);
            expect(localTestPool.options.connectionTimeoutMillis).toBe(acquireTimeout);

            let client1: PoolClient | undefined, client2: PoolClient | undefined;
            let timeoutError: Error | undefined;

            try {
                client1 = await localGetClient();
                client2 = await localGetClient();
                await localGetClient(); // This should wait and then timeout
            } catch (e: any) {
                timeoutError = e;
            } finally {
                if (client1) client1.release();
                if (client2) client2.release();

                if (localTestPool && typeof localTestPool.end === 'function' && !localTestPool.ended) {
                    await localTestPool.end();
                }

                jest.resetModules();
                jest.mock('../../config', () => ({
                    config: {
                        databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                        nodeEnv: 'test',
                    },
                }));
                require('../../config'); // Re-require to apply mock
            }

            expect(timeoutError).toBeDefined();
            expect(timeoutError?.message).toMatch(/timeout|ConnectionAcquireTimeoutError/i);
        });

        it('should enforce transaction timeouts', async () => {
            const client = await getClient();
            try {
                await client.query('BEGIN');
                await client.query('SET LOCAL statement_timeout = 100');
                await expect(
                    client.query('SELECT pg_sleep(0.5)')
                ).rejects.toThrow(/canceling statement due to statement timeout/i);
            } finally {
                await client.query('ROLLBACK');
                client.release();
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

        it('should prevent client state leakage between requests', async () => {
            const client1 = await getClient();
            const client2 = await getClient();

            try {
                await client1.query("SET app.user_id = 'user1'");
                const result = await client2.query("SHOW app.user_id");
                expect(result.rows[0].app_user_id).not.toBe('user1');
            } finally {
                client1.release();
                client2.release();
            }
        });
    });

    describe('Pool Cleanup Security', () => {
        let currentPool: Pool | undefined;
        let currentClosePool: (() => Promise<void>) | undefined;
        let currentGetClient: (() => Promise<PoolClient>) | undefined; // Added
        let isCurrentPoolClosed = false;

        beforeEach(async () => {
            jest.resetAllMocks();
            jest.resetModules();
            jest.unmock('pg');

            jest.doMock('../../config', () => ({
                config: {
                    databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                    nodeEnv: 'test',
                },
            }));

            const dbModule = require('../../models/db');
            currentPool = dbModule.pool;
            currentClosePool = dbModule.closePool;
            currentGetClient = dbModule.getClient; // Get getClient from this module instance
            isCurrentPoolClosed = false;
        });

        afterEach(async () => {
            try {
                if (currentClosePool && !isCurrentPoolClosed && currentPool && !currentPool.ended) {
                    await currentClosePool();
                }
            } catch (error) {
                // console.error('Failed to close pool in Pool Cleanup afterEach:', error); // Keep if needed for debug
            }
        });

        it('should securely close the pool without leaking sensitive information', async () => {
            if (!currentPool || !currentClosePool) throw new Error('Pool not initialized for test');

            const mockEnd = jest.spyOn(currentPool, 'end').mockImplementationOnce(() => {
                return Promise.reject(new Error('Pool termination failed'));
            });
            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });

            await expect(currentClosePool()).rejects.toThrow('Pool termination failed');
            isCurrentPoolClosed = true; // Mark as closed because closePool was called

            expect(consoleSpy).toHaveBeenCalled();
            const errorLog = consoleSpy.mock.calls[0][0] as string;
            expect(errorLog).toContain('Failed to close database pool');
            expect(errorLog).not.toContain('postgres://');
            expect(errorLog).not.toContain('postgres:password');
            expect(errorLog).not.toContain('localhost:5433');

            consoleSpy.mockRestore();
            mockEnd.mockRestore();
        });

        it('should ensure no connections remain after closePool', async () => {
            if (!currentPool || !currentClosePool || !currentGetClient) { // Check for currentGetClient
                throw new Error('Pool or getClient not initialized for test');
            }

            const client = await currentGetClient(); // Use the getClient associated with currentPool
            client.release();

            await currentClosePool();
            isCurrentPoolClosed = true;

            const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => { });
            try {
                // This require will get the same module instance as in beforeEach
                // So queryFromClosedPool will use currentPool, which is now closed.
                const { query: queryFromClosedPool } = require('../../models/db');
                await expect(queryFromClosedPool('SELECT NOW()')).rejects.toThrow(/Cannot use a pool after calling end/);
            } finally {
                errorSpy.mockRestore();
            }

            expect(currentPool.totalCount).toBe(0);
            expect(currentPool.idleCount).toBe(0);
            expect(currentPool.waitingCount).toBe(0);
        });

        it('should handle cleanup with active transactions', async () => {
            if (!currentPool || !currentClosePool || !currentGetClient) { // Check for currentGetClient
                throw new Error('Pool or getClient not initialized for test');
            }
            // const { getClient: localGetClient } = require('../../models/db'); // Not needed if using currentGetClient

            const client = await currentGetClient(); // Use currentGetClient
            await client.query('BEGIN');

            const closePromise = currentClosePool();
            isCurrentPoolClosed = true;

            await client.query('ROLLBACK');
            client.release();

            await closePromise;
            expect(currentPool.ended).toBe(true);
        });
    });
});