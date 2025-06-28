// shared/jest.config.advanced.cjs
/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  
  // Test discovery
  roots: ['<rootDir>/src'],
  testMatch: [
    '**/__tests__/**/*.ts',
    '**/?(*.)+(spec|test).ts',
    '**/?(*.)+(integration|e2e).test.ts'
  ],
  
  // TypeScript transformation
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        strict: true,
        noImplicitAny: true,
        strictNullChecks: true
      }
    }]
  },
  
  // Module resolution
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
    '^@/(.*)$': '<rootDir>/src/$1',
    '^@schemas/(.*)$': '<rootDir>/src/schemas/$1',
    '^@validators/(.*)$': '<rootDir>/src/validators/$1'
  },
  
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  
  // Test environment setup
  setupFilesAfterEnv: [
    '<rootDir>/src/__tests__/setup/globalSetup.ts',
    '<rootDir>/src/__tests__/setup/schemaMatchers.ts'
  ],
  
  // Coverage configuration
  collectCoverageFrom: [
    '<rootDir>/src/**/*.ts',
    '!<rootDir>/src/**/*.d.ts',
    '!<rootDir>/src/**/__tests__/**',
    '!<rootDir>/src/**/index.ts',
    '!<rootDir>/src/**/*.test.ts',
    '!<rootDir>/src/**/*.spec.ts'
  ],
  
  coverageDirectory: 'coverage',
  coverageReporters: [
    'text',
    'text-summary',
    'lcov',
    'html',
    'json-summary'
  ],
  
  // Coverage thresholds
  coverageThreshold: {
    global: {
      branches: 90,
      functions: 95,
      lines: 95,
      statements: 95
    },
    './src/schemas/': {
      branches: 95,
      functions: 98,
      lines: 98,
      statements: 98
    },
    './src/validators/': {
      branches: 92,
      functions: 95,
      lines: 95,
      statements: 95
    }
  },
  
  // Performance and timeout
  testTimeout: 10000,
  maxWorkers: '50%',
  
  // Detailed output
  verbose: true,
  
  // Test result processing
  reporters: [
    'default',
    ['jest-junit', {
      outputDirectory: './test-results',
      outputName: 'shared-tests.xml',
      classNameTemplate: '{classname}',
      titleTemplate: '{title}',
      ancestorSeparator: ' › ',
      usePathForSuiteName: true
    }],
    ['jest-html-reporter', {
      pageTitle: 'Shared Schema Test Report',
      outputPath: './test-results/shared-test-report.html',
      includeFailureMsg: true,
      includeSuiteFailure: true,
      theme: 'lightTheme'
    }]
  ],
  
  // Global test configuration
  globals: {
    'ts-jest': {
      useESM: true
    }
  },
  
  // Test categorization
  testEnvironmentOptions: {
    url: 'http://localhost',
    userAgent: 'node.js'
  },
  
  // Error handling
  errorOnDeprecated: true,
  bail: false,
  
  // Watch mode configuration
  watchPlugins: [
    'jest-watch-typeahead/filename',
    'jest-watch-typeahead/testname'
  ]
};