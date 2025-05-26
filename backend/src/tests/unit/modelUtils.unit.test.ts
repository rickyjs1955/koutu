
import { query } from '../../models/db';
import { getQueryFunction } from '../../utils/modelUtils';
import { testQuery } from '../../utils/testSetup';

// Mock the dependencies
jest.mock('../../models/db', () => ({
  query: jest.fn()
}));

jest.mock('../../utils/testSetup', () => ({
  testQuery: jest.fn()
}));

describe('modelUtils', () => {
  const originalEnv = process.env.NODE_ENV;

  afterEach(() => {
    // Restore original NODE_ENV after each test
    process.env.NODE_ENV = originalEnv;
    jest.clearAllMocks();
  });

  describe('getQueryFunction', () => {
    it('should return testQuery when NODE_ENV is test', () => {
      process.env.NODE_ENV = 'test';
      
      const result = getQueryFunction();
      
      expect(result).toBe(testQuery);
      expect(result).not.toBe(query);
    });

    it('should return query when NODE_ENV is development', () => {
      process.env.NODE_ENV = 'development';
      
      const result = getQueryFunction();
      
      expect(result).toBe(query);
      expect(result).not.toBe(testQuery);
    });

    it('should return query when NODE_ENV is production', () => {
      process.env.NODE_ENV = 'production';
      
      const result = getQueryFunction();
      
      expect(result).toBe(query);
      expect(result).not.toBe(testQuery);
    });

    it('should return query when NODE_ENV is undefined', () => {
      delete process.env.NODE_ENV;
      
      const result = getQueryFunction();
      
      expect(result).toBe(query);
      expect(result).not.toBe(testQuery);
    });

    it('should return query when NODE_ENV is empty string', () => {
      process.env.NODE_ENV = '';
      
      const result = getQueryFunction();
      
      expect(result).toBe(query);
      expect(result).not.toBe(testQuery);
    });

    it('should return query for any non-test environment', () => {
      const nonTestEnvs = ['staging', 'local', 'dev', 'prod', 'testing', 'TEST'];
      
      nonTestEnvs.forEach(env => {
        process.env.NODE_ENV = env;
        
        const result = getQueryFunction();
        
        expect(result).toBe(query);
        expect(result).not.toBe(testQuery);
      });
    });

    it('should be case sensitive for test environment', () => {
      process.env.NODE_ENV = 'TEST';
      
      const result = getQueryFunction();
      
      expect(result).toBe(query);
      expect(result).not.toBe(testQuery);
    });
  });
});