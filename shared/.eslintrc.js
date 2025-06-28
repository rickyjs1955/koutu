// shared/.eslintrc.js
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  plugins: ['@typescript-eslint'],
  env: {
    node: true,
    es2020: true,
    jest: true
  },
  parserOptions: {
    ecmaVersion: 2020,
    sourceType: 'module'
  },
  rules: {
    // Relaxed rules for development - focus on real issues
    '@typescript-eslint/no-explicit-any': 'off', // Allow any in utility/validator code
    '@typescript-eslint/no-unused-vars': ['warn', { 
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_|^[A-Z].*Schema$', // Allow unused schemas (they're exports)
      ignoreRestSiblings: true
    }],
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    'prefer-const': 'error',
    'no-var': 'error',
    
    // Suppress common development warnings
    'no-console': 'off', // Allow console.log in tests
    '@typescript-eslint/no-empty-function': 'off'
  },
  ignorePatterns: [
    'dist/',
    'coverage/',
    'node_modules/',
    '*.js',
    '*.d.ts',
    'jest.config.cjs'
  ],
  
  // Override for specific files that are meant to have exports
  overrides: [
    {
      files: ['src/schemas/api/index.ts', 'src/schemas/*/index.ts'],
      rules: {
        '@typescript-eslint/no-unused-vars': 'off' // Schemas are meant to be exported
      }
    },
    {
      files: ['src/schemas/validator/**/*.ts'],
      rules: {
        '@typescript-eslint/no-explicit-any': 'off', // Validators need any types
        '@typescript-eslint/no-unused-vars': 'off'
      }
    }
  ]
};