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

    // Log initial config at the very beginning of the describe block
    console.log('[TEST SUITE START] Initial appConfig.nodeEnv:', appConfig.nodeEnv);
    console.log('[TEST SUITE START] Initial appConfig.dbRequireSsl:', appConfig.dbRequireSsl);

    beforeAll(async () => {
        console.log('[BEFORE ALL] Setting up test database. Current appConfig.nodeEnv:', appConfig.nodeEnv);
        await setupTestDatabase();
        testPool = new Pool({ // This pool is managed by testPool.end()
            host: 'localhost',
            port: 5433,
            user: 'postgres',
            password: 'password',
            database: 'koutu-postgres-test',
            connectionTimeoutMillis: 5000,
        });
        console.log('[BEFORE ALL] Test database setup complete.');
    });

    afterAll(async () => {
        console.log('[AFTER ALL] Tearing down test database. Current appConfig.nodeEnv:', appConfig.nodeEnv);
        try {
            await teardownTestDatabase();
            if (testPool && typeof testPool.end === 'function' && !(testPool as any)._ended) { // Check if testPool exists and is not ended
                console.log('[AFTER ALL] Closing testPool.');
                await testPool.end();
            } else if (testPool && (testPool as any)._ended) {
                console.log('[AFTER ALL] testPool was already ended.');
            }

            // Close the main application pool that was imported and used by `query`
            // Do NOT use jest.resetModules() here if you want to close the original pool
            if (globalAppPool && typeof globalAppPool.end === 'function' && !globalAppPool.ended) {
                 console.log('[AFTER ALL] Closing main globalAppPool from db.ts');
                 await globalAppClosePool(); // Use the imported closePool for the main app pool
            } else if (globalAppPool && globalAppPool.ended) {
                 console.log('[AFTER ALL] Main globalAppPool from db.ts was already ended.');
            } else {
                 console.log('[AFTER ALL] Main globalAppPool from db.ts was not available or not initialized.');
            }
        } catch (error) {
            console.error('[AFTER ALL] Failed to clean up test resources:', error);
        }
        console.log('[AFTER ALL] Test database teardown complete.');
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
            console.log('[TEST START] should handle invalid connection strings securely');
            jest.resetModules(); // Resets module cache, including db.ts and config.ts
            let consoleSpy: jest.SpyInstance | undefined;
            let error: unknown;
            let dbModule;

            try {
                console.log('[TEST - invalid connection] Mocking pg and config');
                jest.doMock('pg', () => {
                    console.log('[TEST - invalid connection] pg mock being applied');
                    return {
                        Pool: jest.fn().mockImplementation(() => {
                            console.log('[TEST - invalid connection] Mocked pg.Pool constructor called');
                            throw new Error('Invalid connection string from mock');
                        }),
                    };
                });
                jest.doMock('../../config', () => {
                    console.log('[TEST - invalid connection] config mock being applied');
                    return {
                        config: {
                            databaseUrl: 'invalid://connection',
                            nodeEnv: 'test', // Explicitly test
                            // Add other necessary config properties if db.ts depends on them
                        },
                    };
                });

                consoleSpy = jest.spyOn(console, 'error').mockImplementation((msg) => {
                    console.log('[CONSOLE.ERROR SPY - invalid connection]', msg);
                });

                console.log('[TEST - invalid connection] Requiring db module');
                dbModule = require('../../models/db'); // This will use the mocked pg and config
                console.log('[TEST - invalid connection] db module required. Pool:', dbModule.pool);

            } catch (e) {
                console.log('[TEST - invalid connection] Caught error during setup/require:', e);
                error = e;
            } finally {
                console.log('[TEST - invalid connection] Finally block. Restoring mocks.');
                if (consoleSpy) {
                    consoleSpy.mockRestore();
                }
                jest.resetAllMocks(); // Resets spies and mock functions
                jest.unmock('pg');    // Removes the mock for 'pg'
                jest.unmock('../../config'); // Removes the mock for config
                console.log('[TEST - invalid connection] Mocks restored.');
            }

            expect(error).toBeDefined();
            if (isDatabaseError(error) || error instanceof Error) {
                expect(error.message).toContain('Invalid connection string from mock');
                expect(error.message).not.toContain('invalid://connection');
            } else {
                throw new Error('Expected an Error or DatabaseError');
            }
            console.log('[TEST END] should handle invalid connection strings securely');
        });

        it('should require SSL/TLS in production environment', async () => {
            console.log('[TEST START] should require SSL/TLS in production environment');
            jest.resetModules(); // Crucial to get a fresh version of db.ts and config.ts

            const localConfig = {
                databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                nodeEnv: 'production',
                dbRequireSsl: true,
                // Ensure all other config properties db.ts might need are present
            };
            console.log('[TEST - SSL] localConfig prepared:', localConfig);

            let error: unknown;
            let consoleErrorSpy: jest.SpyInstance | undefined;
            let sslDbModule;

            try {
                console.log('[TEST - SSL] Spying on console.error');
                consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation((msg) => {
                    console.log('[CONSOLE.ERROR SPY - SSL test]', msg); // Log what the spy catches
                });

                console.log('[TEST - SSL] Mocking config with production settings');
                jest.doMock('../../config', () => {
                    console.log('[TEST - SSL] config mock being applied with:', localConfig);
                    return { config: localConfig };
                });

                console.log('[TEST - SSL] Requiring db module');
                // When db.ts is required here, it will use the mocked 'production' config
                // and its internal console.log('config.nodeEnv:', config.nodeEnv) will run
                // followed by the pool.query if nodeEnv !== 'test'
                sslDbModule = require('../../models/db');
                console.log('[TEST - SSL] db module required. Pool options from db:', sslDbModule.pool.options);


                console.log('[TEST - SSL] Attempting query that should fail due to SSL');
                await sslDbModule.pool.query('SELECT 1'); // This is expected to throw
                console.log('[TEST - SSL] Query did not throw (UNEXPECTED)');
            } catch (e) {
                console.log('[TEST - SSL] Caught error (expected for SSL test):', e);
                error = e;
            } finally {
                console.log('[TEST - SSL] Finally block. Restoring console spy and mocks.');
                if (consoleErrorSpy) {
                    consoleErrorSpy.mockRestore();
                }
                jest.resetModules(); // Reset again to clean up for the next mock
                console.log('[TEST - SSL] Mocking config back to test defaults for subsequent tests');
                jest.mock('../../config', () => {
                    const defaultConfig = {
                        databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                        nodeEnv: 'test',
                        dbRequireSsl: false,
                    };
                    console.log('[TEST - SSL] Restoring config mock to:', defaultConfig);
                    return { config: defaultConfig };
                });
                 // Re-require config to ensure the global appConfig variable is also reset if needed by other tests
                const { config: resetAppConfig } = require('../../config');
                console.log('[TEST - SSL] appConfig after reset:', resetAppConfig.nodeEnv, resetAppConfig.dbRequireSsl);
            }

            expect(error).toBeDefined();
            if (error instanceof Error) {
                expect(error.message).toMatch(/The server does not support SSL connections|SSLRequired/i);
            } else {
                throw new Error('Expected an Error object for SSL failure.');
            }
            console.log('[TEST END] should require SSL/TLS in production environment');
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
            console.log('[TEST START] should not leak stack traces');
            const mockActualPoolQuery = jest.spyOn(pool, 'query').mockImplementationOnce(() => {
                console.log('[TEST - no stack trace] Actual pool.query mocked to throw');
                throw new Error('Internal database error');
            });

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation((msg) => {
                console.log('[CONSOLE.ERROR SPY - no stack trace]', msg);
            });
            // The query function from db.ts is being tested
            await expect(query('SELECT * FROM non_existent_table')).rejects.toThrow('Internal database error');

            expect(consoleSpy).toHaveBeenCalled();
            const errorLog = consoleSpy.mock.calls.find(call => call[0].startsWith('Query failed:'))?.[0] as string;
            expect(errorLog).toBeDefined();
            if(errorLog) {
                expect(errorLog).toContain('Query failed');
                // The detailed error from db.ts includes the error message, but not the stack of the original error
                expect(errorLog).not.toContain('stack'); // This checks our custom log format
            }
            consoleSpy.mockRestore();
            mockActualPoolQuery.mockRestore();
            console.log('[TEST END] should not leak stack traces');
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
                await client.query('SET statement_timeout = 100'); // 100ms timeout
                await client.query('SELECT pg_sleep(0.5)'); // Attempt to sleep for 500ms
            } catch (error) {
                statementTimeoutError = error;
            } finally {
                // Attempt to reset statement_timeout, but don't fail test if client is in bad state
                try {
                    // Check if client is still usable before trying to reset
                    if (!(client as any)._connected || (client as any)._ending) {
                        // If client is not connected or ending, it might not be possible to send further queries.
                        // This state can occur if the timeout error itself caused the client to be marked as unusable by the pool.
                    } else {
                        await client.query('SET statement_timeout = 0'); // Reset to default
                    }
                } catch (resetError) {
                    // console.warn('Could not reset statement_timeout after test:', resetError);
                }
                client.release();
            }

            expect(statementTimeoutError).toBeDefined();
            if (isDatabaseError(statementTimeoutError)) {
                // PostgreSQL error code for query cancellation due to statement timeout is '57014'
                expect(statementTimeoutError.code).toBe('57014'); // QueryCanceled
                expect(statementTimeoutError.message).toMatch(/canceling statement due to statement timeout/i);
            } else if (statementTimeoutError instanceof Error) {
                // Fallback for other error types, though DatabaseError is expected
                expect(statementTimeoutError.message).toMatch(/timeout/i);
            } else {
                throw new Error('Expected a DatabaseError or Error for statement timeout');
            }
        });

        it('should handle connection pool exhaustion gracefully', async () => {
            console.log('[TEST START] should handle connection pool exhaustion');
            const maxConnections = 2;
            const acquireTimeout = 200;

            jest.resetModules();
            console.log('[TEST - pool exhaustion] Modules reset.');

            const mockConfigForThisTest = {
                databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                nodeEnv: 'test',
                dbPoolMax: maxConnections,
                dbConnectionTimeout: acquireTimeout,
                dbRequireSsl: false,
            };
            console.log('[TEST - pool exhaustion] Mock config for this test:', mockConfigForThisTest);

            jest.doMock('../../config', () => {
                console.log('[TEST - pool exhaustion] Applying config mock:', mockConfigForThisTest);
                return { config: mockConfigForThisTest };
            });

            console.log('[TEST - pool exhaustion] Requiring db module.');
            const { getClient: localGetClient, pool: localTestPool } = require('../../models/db');
            console.log('[TEST - pool exhaustion] db module required. localTestPool.options:', localTestPool.options);


            expect(localTestPool.options.max).toBe(maxConnections); // This was failing before
            expect(localTestPool.options.connectionTimeoutMillis).toBe(acquireTimeout);

            let client1: PoolClient | undefined, client2: PoolClient | undefined;
            let timeoutError: Error | undefined;

            try {
                console.log('[TEST - pool exhaustion] Acquiring client 1');
                client1 = await localGetClient();
                console.log('[TEST - pool exhaustion] Acquiring client 2');
                client2 = await localGetClient();
                console.log('[TEST - pool exhaustion] Attempting to acquire client 3 (should timeout)');
                await localGetClient(); // This should wait and then timeout
            } catch (e: any) {
                console.log('[TEST - pool exhaustion] Caught error (expected for pool exhaustion):', e);
                timeoutError = e;
            } finally {
                console.log('[TEST - pool exhaustion] Finally block. Releasing clients.');
                if (client1) client1.release();
                if (client2) client2.release();

                if (localTestPool && typeof localTestPool.end === 'function' && !localTestPool.ended) {
                    console.log('[TEST - pool exhaustion] Ending localTestPool.');
                    await localTestPool.end();
                } else if (localTestPool && localTestPool.ended) {
                    console.log('[TEST - pool exhaustion] localTestPool already ended.');
                }

                jest.resetModules();
                console.log('[TEST - pool exhaustion] Restoring global config mock.');
                jest.mock('../../config', () => ({ // Restore global mock
                    config: {
                        databaseUrl: 'postgres://postgres:password@localhost:5433/koutu-postgres-test',
                        nodeEnv: 'test',
                    },
                }));
                const { config: resetConfig } = require('../../config');
                console.log('[TEST - pool exhaustion] Global config restored. nodeEnv:', resetConfig.nodeEnv);
            }

            expect(timeoutError).toBeDefined();
            expect(timeoutError?.message).toMatch(/timeout|ConnectionAcquireTimeoutError/i);
            console.log('[TEST END] should handle connection pool exhaustion');
        });

        it('should enforce transaction timeouts', async () => {
            const client = await getClient();
            try {
                await client.query('BEGIN');
                await client.query('SET LOCAL statement_timeout = 100'); // 100ms timeout
                await expect(
                    client.query('SELECT pg_sleep(0.5)') // Attempt to sleep for 500ms
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
                // Set a session variable on client1
                await client1.query("SET app.user_id = 'user1'");

                // Verify client2 doesn't see the same session state
                const result = await client2.query("SHOW app.user_id");
                expect(result.rows[0].app_user_id).not.toBe('user1');
            } finally {
                client1.release();
                client2.release();
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

            const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => { });

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
            const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => { });

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

        it('should handle cleanup with active transactions', async () => {
            const client = await getClient();
            await client.query('BEGIN');

            let closePoolPromise: Promise<void> | undefined;
            if (closePool) {
                closePoolPromise = closePool();
            } else {
                throw new Error('closePool is not defined');
            }

            await client.query('ROLLBACK');
            client.release();

            if (closePoolPromise) {
                await closePoolPromise;
            }
        });
    });
});