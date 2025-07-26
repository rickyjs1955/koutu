module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/*.stress.test.ts'],
  testTimeout: 180000, // 3 minutes default timeout for stress tests
  maxWorkers: 1, // Run stress tests serially to prevent resource contention
  globals: {
    'ts-jest': {
      tsconfig: {
        esModuleInterop: true,
        allowSyntheticDefaultImports: true
      }
    }
  },
  setupFilesAfterEnv: ['<rootDir>/jest.stress.setup.js'],
  // Clear mocks between tests
  clearMocks: true,
  // Restore mocks between tests
  restoreMocks: true,
  // Report memory usage
  logHeapUsage: true
};