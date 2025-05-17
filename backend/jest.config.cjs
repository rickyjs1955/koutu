// backend/jest.config.cjs
/** @type {import('jest').Config} */
module.exports = {
    preset: 'ts-jest',
    testEnvironment: 'node',
    roots: ['<rootDir>/src'],
    testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
    transform: {
      '^.+\\.tsx?$': ['ts-jest']
    },
    moduleNameMapper: {
      '^(\\.{1,2}/.*)\\.js$': '$1',
      '^@/(.*)$': '<rootDir>/src/$1',
      '^@koutu/shared/(.*)$': '<rootDir>/../shared/src/$1',
    },
    moduleFileExtensions: ['ts', 'js', 'json', 'node'],
    setupFiles: ['dotenv/config', '<rootDir>/jest.setup.ts'],
    testTimeout: 10000,
    collectCoverageFrom: [
      '<rootDir>/src/**/*.ts',
      '!<rootDir>/src/**/*.d.ts',
      '!<rootDir>/src/**/*.test.ts',
      '!<rootDir>/src/types/**/*.ts',
    ],
    // Add verbose option for more detailed test output
    verbose: true,
  };