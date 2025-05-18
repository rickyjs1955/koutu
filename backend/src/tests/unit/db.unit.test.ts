// filepath: /backend/src/tests/unit/db.unit.test.ts
/**
 * Database Helper Unit Tests
 *
 * This test suite verifies the behavior of database utility functions,
 * including connection pooling, query execution, and client acquisition.
 * It ensures correct handling across environments (test, development),
 * proper logging behavior, and robust error handling.
 */

jest.mock('pg', () => {
    const actualPg = jest.requireActual('pg');
    return {
        ...actualPg,
        Pool: jest.fn().mockImplementation(({ connectionString }) => ({
            query: jest.fn(),
            connect: jest.fn(),
            options: { connectionString },
        })),
    };
});

jest.mock('../../config', () => ({
    config: {
        databaseUrl: 'postgres://test:test@localhost:5432/test',
        nodeEnv: 'test',
    },
}));

import { query, getClient, pool } from '../../models/db';
import { config } from '../../config';
import { PoolClient, QueryResult } from 'pg';

describe('Database Helper Unit Tests', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Connection Pool Initialization', () => {
        /**
         * Verifies that the pool is initialized with the correct connection string.
         */
        it('should initialize Pool with correct connection string', () => {
            expect(pool).toBeDefined();
            expect(pool.options.connectionString).toBe(config.databaseUrl);
        });

        /**
         * Ensures no initial connection test occurs in test environment.
         */
        it('should skip test connection in test environment', () => {
            const mockQuery = jest.spyOn(pool, 'query');
            expect(mockQuery).not.toHaveBeenCalled();
        });

        /**
         * Confirms that no "database connected" message is logged during tests.
         */
        it('should not log database connected message in test environment', () => {
            const consoleSpy = jest.spyOn(console, 'log');
            expect(consoleSpy).not.toHaveBeenCalledWith('Database connected successfully');
        });
    });

    describe('query() Functionality', () => {
        const mockQueryFn = pool.query as jest.Mock;

        beforeEach(() => {
            mockQueryFn.mockClear();
        });

        /**
         * Validates successful query execution and result return.
         */
        it('should execute a query and return results', async () => {
            const mockResult: QueryResult = {
                rows: [{ id: 1 }],
                rowCount: 1,
                command: '',
                oid: 0,
                fields: [],
            };

            mockQueryFn.mockResolvedValue(mockResult);

            const result = await query('SELECT * FROM users WHERE id = $1', [1]);

            expect(mockQueryFn).toHaveBeenCalledWith('SELECT * FROM users WHERE id = $1', [1]);
            expect(result).toEqual(mockResult);
        });

        /**
         * Ensures queries are logged in development environment with metadata.
         */
        it('should log query details in development environment', async () => {
            mockQueryFn.mockResolvedValue({
                rows: [],
                rowCount: 0,
                command: '',
                oid: 0,
                fields: [],
            });

            const consoleSpy = jest.spyOn(console, 'log');
            config.nodeEnv = 'development';

            await query('SELECT NOW()');

            expect(consoleSpy).toHaveBeenCalledWith(
                'Executed query:',
                expect.objectContaining({
                    text: 'SELECT NOW()',
                    params: undefined,
                    duration: expect.any(Number),
                    rows: expect.any(Number),
                })
            );

            config.nodeEnv = 'test'; // Reset for other tests
        });

        /**
         * Ensures no query logs appear in test environment.
         */
        it('should not log query details in test environment', async () => {
            mockQueryFn.mockResolvedValue({
                rows: [],
                rowCount: 0,
                command: '',
                oid: 0,
                fields: [],
            });

            const consoleSpy = jest.spyOn(console, 'log');
            config.nodeEnv = 'test';

            await query('SELECT NOW()');

            expect(consoleSpy).not.toHaveBeenCalledWith('Executed query:', expect.anything());
        });

        /**
         * Verifies rejection on query error propagation.
         */
        it('should reject on query error', async () => {
            mockQueryFn.mockRejectedValue(new Error('Connection failed'));

            await expect(query('SELECT NOW()')).rejects.toThrow('Connection failed');
        });

        /**
         * Confirms undefined parameters are passed correctly when omitted.
         */
        it('should pass parameters as undefined if not provided', async () => {
            const mockResult: QueryResult = {
                rows: [],
                rowCount: 0,
                command: '',
                oid: 0,
                fields: [],
            };

            mockQueryFn.mockResolvedValue(mockResult);

            await query('SELECT NOW()');

            expect(mockQueryFn).toHaveBeenCalledWith('SELECT NOW()', undefined);
        });
    });

    describe('getClient() Functionality', () => {
        const mockConnectFn = pool.connect as jest.Mock;

        /**
         * Validates that a PoolClient instance is returned upon successful connection.
         */
        it('should return a PoolClient instance', async () => {
            const mockClient = {
                release: jest.fn(),
                query: jest.fn(),
            } as unknown as PoolClient;

            mockConnectFn.mockResolvedValue(mockClient);

            const client = await getClient();

            expect(client).toBe(mockClient);
            expect(mockConnectFn).toHaveBeenCalled();
        });

        /**
         * Ensures errors from pool.connect() are propagated correctly.
         */
        it('should propagate errors from pool.connect()', async () => {
            mockConnectFn.mockRejectedValue(new Error('No connection'));

            await expect(getClient()).rejects.toThrow('No connection');
        });
    });
});

// Feedback from the Challenger
/**
 * @summary Challenger Feedback on Database Helper Unit Test Suite
 * @description Identifies weaknesses, unchecked assumptions, and blind spots in the test suite for database utility functions (`query`, `getClient`, `pool`). The suite is evaluated for robustness, real-world brittleness, and untested scenarios. Several gaps are found, indicating the suite is not satisfactory in its current state.
 * 
 * @section Connection Pool Initialization
 * - **Environment Assumptions**: No tests for invalid or undefined `nodeEnv` (e.g., 'production', `undefined`). This risks unexpected logging or connection attempts in misconfigured environments.
 * - **Connection String Validation**: Unverified behavior for malformed, empty, or missing `connectionString`. This could cause silent failures or crashes.
 * - **Pool Creation Edge Cases**: No test for `Pool` constructor failures (e.g., invalid options, resource constraints), exposing potential initialization brittleness.
 * 
 * @section query() Functionality
 * - **Malformed Query Strings**: No tests for invalid SQL (e.g., empty strings, syntax errors, SQL injection attempts). Utility behavior (error handling, logging) is unverified.
 * - **Parameter Mismatches**: Untested scenarios where query placeholders mismatch parameters (e.g., `WHERE id = $1 AND name = $2` with `[1]`), risking runtime errors.
 * - **Concurrent Query Handling**: No coverage for simultaneous queries, which could expose pooling or contention issues under load.
 * - **Logging Robustness**: Unverified logging behavior if `console.log` is overridden or fails, potentially masking production issues.
 * - **Timeout or Slow Queries**: No tests for slow or timed-out queries, risking hanging promises or resource leaks.
 * 
 * @section getClient() Functionality
 * - **Client Release Handling**: No verification of client release or failure to release, risking pool exhaustion.
 * - **Concurrent Client Acquisition**: Untested behavior under multiple simultaneous `getClient` calls, which could cause deadlocks or errors.
 * - **Client State Assumptions**: No tests for unusable clients (e.g., disconnected due to network issues), risking unhandled errors.
 * - **Pool Exhaustion**: No simulation of exhausted connection pools, exposing brittleness under high load.
 * 
 * @section System-Level Concerns
 * - **Mocking Assumptions**: Heavy reliance on `pg.Pool` mocks without verifying real-world behavior, risking false confidence.
 * - **Security Risks**: No tests for malicious inputs (e.g., SQL injection, oversized queries/parameters), leaving utility robustness unverified.
 * - **Configuration Changes**: Unverified behavior for dynamic `config.databaseUrl` changes or unreachable database servers.
 * 
 * @conclusion
 * The test suite has significant gaps in environment handling, query robustness, client management, and security. These weaknesses could lead to failures under misconfiguration, high load, or adversarial inputs. The suite is not satisfactory due to unaddressed risks in real-world scenarios.
 */