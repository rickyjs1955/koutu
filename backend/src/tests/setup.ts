// /backend/src/tests/integration/setup.ts
// Integration test setup file

import { jest } from '@jest/globals';

// Set test environment
process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = 'postgresql://postgres:postgres@localhost:5433/koutu_test';

// Increase timeout for integration tests
jest.setTimeout(30000);

// Mock console methods to reduce noise
const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

beforeAll(() => {
  // Only suppress specific console outputs, not all
  console.warn = jest.fn((message) => {
    if (typeof message === 'string' && (
      message.includes('ExperimentalWarning') ||
      message.includes('deprecated') ||
      message.includes('Warning:')
    )) {
      return; // Suppress warnings
    }
    originalConsoleWarn(message);
  });

  console.error = jest.fn((message) => {
    if (typeof message === 'string' && (
      message.includes('ExperimentalWarning') ||
      message.includes('DeprecationWarning')
    )) {
      return; // Suppress deprecation warnings
    }
    originalConsoleError(message);
  });
});

afterAll(() => {
  console.error = originalConsoleError;
  console.warn = originalConsoleWarn;
});

// Global test utilities
global.testUtils = {
  // Helper to wait for async operations
  async waitFor(condition: () => boolean | Promise<boolean>, timeout: number = 5000) {
    const startTime = Date.now();
    while (Date.now() - startTime < timeout) {
      if (await condition()) {
        return true;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error(`Condition not met within ${timeout}ms`);
  },

  // Helper to create unique test identifiers
  createTestId(prefix: string = 'test') {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  },

  // Helper to validate UUID format
  isValidUUID(uuid: string) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }
};

// Declare global types
declare global {
  var testUtils: {
    waitFor: (condition: () => boolean | Promise<boolean>, timeout?: number) => Promise<boolean>;
    createTestId: (prefix?: string) => string;
    isValidUUID: (uuid: string) => boolean;
  };
}