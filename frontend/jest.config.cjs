// jest.config.cjs
module.exports = {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'jsdom',
  extensionsToTreatAsEsm: ['.ts', '.tsx'],
  setupFilesAfterEnv: ['<rootDir>/src/setupTests.ts'],
  moduleNameMapper: {
    // Handle CSS imports
    '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
    // Handle image imports
    '\\.(jpg|jpeg|png|gif|eot|otf|webp|svg|ttf|woff|woff2|mp4|webm|wav|mp3|m4a|aac|oga)$': 'jest-transform-stub',
    // Handle module path mapping
    '^@/(.*)$': '<rootDir>/src/$1',
    // Handle Vite's ?url imports
    '\\?url$': 'jest-transform-stub',
    // Handle other Vite-specific imports
    '\\?(raw|worker|inline)$': 'jest-transform-stub'
  },
  transform: {
    '^.+\\.(ts|tsx)$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        jsx: 'react-jsx',
        module: 'esnext',
        target: 'es2020',
        moduleResolution: 'node'
      }
    }]
  },
  transformIgnorePatterns: [
    'node_modules/(?!(.*\\.mjs$|@testing-library))'
  ],
  testMatch: [
    '<rootDir>/src/**/__tests__/**/*.(ts|tsx|js)',
    '<rootDir>/src/**/?(*.)(test|spec).(ts|tsx|js)'
  ],
  collectCoverageFrom: [
    'src/**/*.(ts|tsx)',
    '!src/**/*.d.ts',
    '!src/main.tsx',
    '!src/vite-env.d.ts'
  ],
  // Mock import.meta and other Vite globals
  globals: {
    'ts-jest': {
      useESM: true
    }
  },
  // Setup for import.meta support
  testEnvironmentOptions: {
    customExportConditions: ['node', 'node-addons']
  }
};