// filepath: c:\Users\monmo\koutu\backend\jest.setup.ts

import { jest } from '@jest/globals';

// Only modify environment for tests
process.env.NODE_ENV = 'test';

// Use the test database from Docker
process.env.DATABASE_URL = 'postgresql://postgres:password@localhost:5433/koutu_test';

// console.log('Test environment initialized with DATABASE_URL:', process.env.DATABASE_URL);
// console.log('DATABASE_URL =', process.env.DATABASE_URL);

jest.mock('firebase-admin', () => ({
  initializeApp: jest.fn(),
  credential: {
    cert: jest.fn()
  }
}));