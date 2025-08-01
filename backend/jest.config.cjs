// /Koutu/backend/jest.config.cjs - Clean version without global setup
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>'],
  testMatch: [
    '**/tests/**/*.test.ts',
    '**/?(*.)+(spec|test).ts'
  ],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: '<rootDir>/tsconfig.test.json'
    }],
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/tests/**',
    '!src/**/__mocks__/**',
    '!src/**/__helpers__/**'
  ],
  setupFiles: [
    '<rootDir>/src/tests/pre-setup.ts',
    '<rootDir>/jest.setup.memory.js'
  ],
  setupFilesAfterEnv: [
    '<rootDir>/src/tests/setup.ts'
  ],
  testTimeout: 60000,
  maxWorkers: 1,
  verbose: true,
  forceExit: true,
  detectOpenHandles: false,  
  // Exclude dist folder to avoid duplicate mock conflicts
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/',
    '/backup/'
  ],
  // Module name mapping
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1'
  },
  // Add moduleDirectories to help Jest find manual mocks
  moduleDirectories: ['node_modules', '<rootDir>'],
  silent: true, // Suppress console output during tests
  
  // Removed global setup/teardown to avoid ES module issues
};