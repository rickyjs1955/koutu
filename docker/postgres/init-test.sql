-- docker/postgres/init-test.sql
-- Fixed initialization script for test database

-- Create the test database
CREATE DATABASE koutu_test;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE koutu_test TO postgres;

-- Connect to the new database and create any needed tables
\c koutu_test

-- Create basic test tables (add your actual schema here)
CREATE TABLE IF NOT EXISTS test_table (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant table permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;