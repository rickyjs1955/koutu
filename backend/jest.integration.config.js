// /backend/jest.integration.config.js
// Jest configuration specifically for integration tests

const baseConfig = require('./jest.config.js');

module.exports = {
  ...baseConfig,
  displayName: 'Integration Tests',
  testMatch: [
    '<rootDir>/src/**/*.int.test.{js,ts}',
    '<rootDir>/src/**/__tests__/**/*.int.{js,ts}'
  ],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/__tests__/.*(?<!\.int)\.test\.(js|ts)' // Ignore unit tests
  ],
  
  // Integration test specific settings
  testTimeout: 30000, // 30 seconds per test
  maxWorkers: 1, // Run integration tests sequentially to avoid conflicts
  
  // Setup files for integration tests
  setupFilesAfterEnv: [
    '<rootDir>/src/tests/integrationSetup.ts'
  ],
  
  // Global setup and teardown for integration tests
  globalSetup: '<rootDir>/src/tests/globalIntegrationSetup.ts',
  globalTeardown: '<rootDir>/src/tests/globalIntegrationTeardown.ts',
  
  // Environment variables for integration tests
  testEnvironment: 'node',
  
  // Coverage settings for integration tests
  collectCoverageFrom: [
    'src/services/**/*.{js,ts}',
    'src/models/**/*.{js,ts}',
    'src/utils/**/*.{js,ts}',
    '!src/**/*.test.{js,ts}',
    '!src/**/*.mock.{js,ts}',
    '!src/**/__tests__/**',
    '!src/**/__mocks__/**'
  ],
  coverageDirectory: 'coverage/integration',
  coverageReporters: ['text', 'lcov', 'html'],
  
  // Verbose output for debugging
  verbose: true,
  
  // Don't clear mocks between tests (integration tests manage their own state)
  clearMocks: false,
  
  // Force exit after tests complete
  forceExit: true,
  
  // Detect open handles for debugging
  detectOpenHandles: false
};