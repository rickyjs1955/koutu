// filepath: c:\Users\monmo\koutu\backend\jest.setup.ts
// Only modify environment for tests
process.env.NODE_ENV = 'test';

// Use the test database from Docker
process.env.DATABASE_URL = 'postgresql://postgres:password@localhost:5433/koutu_test';

console.log('Test environment initialized with DATABASE_URL:', process.env.DATABASE_URL);

// Make the connection string clearly visible in logs
console.log('DATABASE_URL =', process.env.DATABASE_URL);