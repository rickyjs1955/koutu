// test-connection.js
import { Pool } from 'pg';

const pool = new Pool({
  host: 'localhost',
  port: 5433,
  user: 'postgres',
  password: 'password',
  database: 'koutu_test'
});

pool.query('SELECT current_database()')
  .then(res => {
    console.log('Connected to:', res.rows[0].current_database);
    pool.end();
  })
  .catch(err => {
    console.error('Connection error:', err);
    pool.end();
  });