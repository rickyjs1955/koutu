// jest.config.integration.js
// Jest configuration specifically for integration tests

module.exports = {
  // Test environment
  testEnvironment: 'node',
  
  // Test file patterns
  testMatch: [
    '**/tests/integration/**/*.test.ts',
    '**/tests/integration/**/*.int.test.ts',
    '**/__tests__/**/*.int.test.ts'
  ],
  
  // Transform TypeScript files
  preset: 'ts-jest',
  
  // Module resolution
  moduleNameMapping: {
    '^@/(.*)$': '<rootDir>/src/$1'
  },
  
  // Setup files
  setupFilesAfterEnv: [
    '<rootDir>/src/tests/integration/setup.ts'
  ],
  
  // Test timeout (30 seconds for integration tests)
  testTimeout: 30000,
  
  // Coverage configuration
  collectCoverageFrom: [
    'src/controllers/**/*.ts',
    'src/routes/**/*.ts',
    'src/services/**/*.ts',
    'src/models/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts'
  ],
  
  // Coverage thresholds
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 70,
      lines: 70,
      statements: 70
    }
  },
  
  // Verbose output
  verbose: true,
  
  // Run tests in sequence (not parallel) for integration tests
  maxWorkers: 1,
  
  // Clear mocks between tests
  clearMocks: true,
  
  // Restore mocks after each test
  restoreMocks: true,
  
  // Global setup and teardown
  globalSetup: '<rootDir>/src/tests/integration/globalSetup.ts',
  globalTeardown: '<rootDir>/src/tests/integration/globalTeardown.ts',
  
  // Force exit after tests complete
  forceExit: true,
  
  // Detect open handles
  detectOpenHandles: true,
  
  // Transform configuration
  transform: {
    '^.+\\.ts$': 'ts-jest'
  },
  
  // Module file extensions
  moduleFileExtensions: ['ts', 'js', 'json'],
  
  // Ignore patterns
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/build/'
  ]
};