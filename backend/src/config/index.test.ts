import { describe, expect, test, jest, afterAll } from '@jest/globals';
import { config, isProd, isDev, isTest } from './index.js';

describe('Config Module', () => {
  // Store original environment
  const originalEnv = process.env.NODE_ENV;
  
  // Reset environment after tests
  afterAll(() => {
    process.env.NODE_ENV = originalEnv;
  });

  test('isProd should return true when NODE_ENV is production', () => {
    process.env.NODE_ENV = 'production';
    expect(isProd()).toBe(true);
    expect(isDev()).toBe(false);
    expect(isTest()).toBe(false);
  });

  test('config should have expected properties', () => {
    expect(config).toHaveProperty('port');
    expect(config).toHaveProperty('nodeEnv');
    expect(config).toHaveProperty('firebase');
  });
});