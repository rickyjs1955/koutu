// /Koutu/backend/jest.config.cjs - Clean version without global setup
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: [
    '**/tests/**/*.test.ts',
    '**/?(*.)+(spec|test).ts'
  ],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/tests/**',
    '!src/**/__mocks__/**',
    '!src/**/__helpers__/**'
  ],
  setupFilesAfterEnv: [
    '<rootDir>/src/tests/setup.ts'
  ],
  testTimeout: 60000,
  maxWorkers: 1,
  verbose: true,
  forceExit: true,
  detectOpenHandles: true,  
  // Exclude dist folder to avoid duplicate mock conflicts
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/'
  ],
  // Module name mapping
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1'
  },
  silent: false, // Suppress console output during tests
  
  // Removed global setup/teardown to avoid ES module issues
};