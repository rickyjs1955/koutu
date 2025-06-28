// shared/src/__tests__/setup/globalSetup.ts
export const globalSetup = `
import { jest } from '@jest/globals';

// Global test configuration
beforeAll(() => {
  // Set consistent timezone for date testing
  process.env.TZ = 'UTC';
  
  // Mock console.warn for cleaner test output
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  
  // Global timeout for async operations
  jest.setTimeout(10000);
});

afterAll(() => {
  // Restore console.warn
  jest.restoreAllMocks();
});

// Performance monitoring
let testStartTime: number;

beforeEach(() => {
  testStartTime = Date.now();
});

afterEach(() => {
  const testDuration = Date.now() - testStartTime;
  if (testDuration > 1000) {
    console.warn(\`Test took \${testDuration}ms - consider optimization\`);
  }
});

// Global test data factories
global.testHelpers = {
  generateUUID: () => '123e4567-e89b-12d3-a456-426614174000',
  generateEmail: (prefix = 'test') => \`\${prefix}@example.com\`,
  generateValidUser: (overrides = {}) => ({
    id: global.testHelpers.generateUUID(),
    email: global.testHelpers.generateEmail(),
    name: 'Test User',
    created_at: new Date(),
    ...overrides
  }),
  
  // Add more factories as needed
  generateValidGarment: (overrides = {}) => ({
    id: global.testHelpers.generateUUID(),
    user_id: global.testHelpers.generateUUID(),
    original_image_id: global.testHelpers.generateUUID(),
    file_path: '/uploads/garment.jpg',
    mask_path: '/uploads/mask.png',
    metadata: {
      type: 'shirt',
      color: 'blue',
      pattern: 'solid',
      season: 'summer'
    },
    created_at: new Date(),
    updated_at: new Date(),
    data_version: 1,
    ...overrides
  })
};

// Declare global types
declare global {
  var testHelpers: {
    generateUUID(): string;
    generateEmail(prefix?: string): string;
    generateValidUser(overrides?: any): any;
    generateValidGarment(overrides?: any): any;
  };
}
`;