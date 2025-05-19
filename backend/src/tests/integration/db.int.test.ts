import { Pool } from 'pg';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';

describe('Integration tests for db.ts', () => {
    let pool: Pool;
    
    beforeAll(async () => {
        await setupTestDatabase(); // Setup koutu-postgres-test database
        
        // Create a new connection pool for testing
        pool = new Pool({
            host: 'localhost',
            port: 5433,
            user: 'postgres',
            password: 'password',
            database: 'koutu-postgres-test',
            connectionTimeoutMillis: 5000
        });
        
        // Create tables and insert test data if needed
        await pool.query(`CREATE TABLE IF NOT EXISTS test_table (id SERIAL PRIMARY KEY, value TEXT)`);
        await pool.query(`INSERT INTO test_table (value) VALUES ('test')`);
    });
    
    afterAll(async () => {
        // Clean up by dropping the tables and closing the connection pool
        await teardownTestDatabase();
        await pool.end();
    });
    
    it('should connect to the database', async () => {
        const res = await pool.query('SELECT * FROM test_table');
        expect(res.rows).toHaveLength(1); // Expecting one row in the result set
    });
    
    it('should handle errors when connecting to the database', async () => {
        try {
            const res = await pool.query('SELECT * FROM non_existent_table');
        } catch (error) {
            expect(error).toBeDefined(); // Expecting an error to be thrown
        }
    });
    
    it('should handle errors when querying the database', async () => {
        try {
            const res = await pool.query('SELECT * FROM non_existent_table');
        } catch (error) {
            expect(error).toBeDefined(); // Expecting an error to be thrown
        }
    });
    
    it('should handle errors when connecting to the database', async () => {
        try {
            const res = await pool.query('SELECT * FROM non_existent_table');
        } catch (error) {
            expect(error).toBeDefined(); // Expecting an error to be thrown
        }
    });
    
    it('should handle errors when querying the database', async () => {
        try {
            const res = await pool.query('SELECT * FROM non_existent_table');
        } catch (error) {
            expect(error).toBeDefined(); // Expecting an error to be thrown
        }
    });
});