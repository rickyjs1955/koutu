// frontend/jest.config.cjs
/** @type {import('jest').Config} */
module.exports = {
    testEnvironment: 'jsdom',
    roots: ['<rootDir>/src'],
    testMatch: ['**/__tests__/**/*.ts?(x)', '**/?(*.)+(spec|test).ts?(x)'],
    transform: {
      '^.+\\.(ts|tsx)$': ['ts-jest']
    },
    moduleNameMapper: {
      '^(\\.{1,2}/.*)\\.js$': '$1',
      '^@/(.*)$': '<rootDir>/src/$1',
      '^@koutu/shared/(.*)$': '<rootDir>/../shared/src/$1',
      // Handle CSS and static file imports
      '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
      '\\.(jpg|jpeg|png|gif|webp|svg)$': '<rootDir>/src/__mocks__/fileMock.js'
    },
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
    setupFilesAfterEnv: [
      '<rootDir>/src/setupTests.ts',
    ],
    testTimeout: 10000,
    collectCoverageFrom: [
      '<rootDir>/src/**/*.{ts,tsx}',
      '!<rootDir>/src/**/*.d.ts',
      '!<rootDir>/src/**/*.test.{ts,tsx}',
      '!<rootDir>/src/**/__tests__/**',
      '!<rootDir>/src/**/__mocks__/**',
    ],
    moduleDirectories: ['node_modules', 'src'],
    // Add verbose option for more detailed test output
    verbose: true,
  };