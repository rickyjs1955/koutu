import { getQueryFunction } from '../../utils/modelUtils';
import { query } from '../../models/db';
import { testQuery } from '../../utils/testSetup';

// Mock both the regular query and test query functions
jest.mock('../../models/db', () => ({
  query: jest.fn().mockImplementation(() => Promise.resolve({ rows: [] }))
}));

jest.mock('../../utils/testSetup', () => ({
  testQuery: jest.fn().mockImplementation(() => Promise.resolve({ rows: [] }))
}));

describe('Model Utilities', () => {
  // Save original NODE_ENV
  const originalNodeEnv = process.env.NODE_ENV;

  afterEach(() => {
    // Restore original NODE_ENV after each test
    process.env.NODE_ENV = originalNodeEnv;
    jest.clearAllMocks();
  });

  describe('getQueryFunction', () => {
    test('should return testQuery when NODE_ENV is "test"', () => {
      // Set environment to test
      process.env.NODE_ENV = 'test';
      
      // Get query function
      const queryFn = getQueryFunction();
      
      // Verify it's the test query function
      expect(queryFn).toBe(testQuery);
    });

    test('should return regular query when NODE_ENV is not "test"', () => {
      // Set environment to something other than test
      process.env.NODE_ENV = 'development';
      
      // Get query function
      const queryFn = getQueryFunction();
      
      // Verify it's the regular query function
      expect(queryFn).toBe(query);
    });

    test('should return regular query when NODE_ENV is undefined', () => {
      // Set environment to undefined
      delete process.env.NODE_ENV;
      
      // Get query function
      const queryFn = getQueryFunction();
      
      // Verify it's the regular query function
      expect(queryFn).toBe(query);
    });
  });

  describe('query function usage', () => {
    test('should execute the correct query function based on environment', async () => {
      // Test in test environment
      process.env.NODE_ENV = 'test';
      let queryFn = getQueryFunction();
      await queryFn('SELECT 1');
      expect(testQuery).toHaveBeenCalledWith('SELECT 1');
      expect(query).not.toHaveBeenCalled();
      
      // Reset mocks
      jest.clearAllMocks();
      
      // Test in non-test environment
      process.env.NODE_ENV = 'production';
      queryFn = getQueryFunction();
      await queryFn('SELECT 2');
      expect(query).toHaveBeenCalledWith('SELECT 2');
      expect(testQuery).not.toHaveBeenCalled();
    });
  });
});