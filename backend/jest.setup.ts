// backend/jest.setup.ts
import { jest } from '@jest/globals';

// Only modify environment for tests
process.env.NODE_ENV = 'test';

// Use the test database from Docker - FIXED: matches the actual database name
process.env.DATABASE_URL = 'postgresql://postgres:password@localhost:5433/koutu_test';

console.log('Test environment initialized');
console.log('DATABASE_URL:', process.env.DATABASE_URL);

// Mock Firebase admin to prevent conflicts
jest.mock('firebase-admin', () => ({
  initializeApp: jest.fn(),
  credential: {
    cert: jest.fn()
  },
  auth: jest.fn(() => ({
    verifyIdToken: jest.fn(),
    createUser: jest.fn(),
    updateUser: jest.fn(),
    deleteUser: jest.fn()
  })),
  firestore: jest.fn(() => ({
    collection: jest.fn(),
    doc: jest.fn()
  }))
}));