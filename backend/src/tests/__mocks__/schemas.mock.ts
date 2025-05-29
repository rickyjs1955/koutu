// backend/src/__mocks__/schemas.mock.ts
import { Request, Response, NextFunction } from 'express';

// Mock validation results
export const mockValidationSuccess = {
  success: true as const,
  data: {},
  errors: []
};

export const mockValidationFailure = {
  success: false as const,
  data: null,
  errors: [
    {
      path: ['field'],
      message: 'Validation failed',
      code: 'invalid_type'
    }
  ]
};

// Mock garment data that matches the actual CreateGarmentSchema structure
export const mockValidGarment = {
  mask_data: {
    width: 100,
    height: 100,
    data: new Array(10000).fill(1) // 100x100 with non-zero values
  },
  metadata: {
    type: 'shirt',
    color: 'blue',
    brand: 'TestBrand',
    tags: ['casual', 'cotton'],
    season: 'summer',
    size: 'M',
    material: 'cotton'
  },
  original_image_id: 'img_123',
  processing_notes: 'Test garment'
};

export const mockInvalidGarment = {
  mask_data: {
    width: 100,
    height: 100,
    data: new Array(10000).fill(0) // All zeros - should fail business rule
  },
  metadata: {
    type: 'shirt',
    color: 'blue',
    brand: 'TestBrand'
  }
};

// Mock polygon data that matches CreatePolygonSchema structure
export const mockValidPolygon = {
  points: [
    { x: 0, y: 0 },
    { x: 100, y: 0 },
    { x: 100, y: 100 },
    { x: 0, y: 100 }
  ],
  metadata: {
    label: 'test_region',
    confidence: 0.95,
    source: 'manual_annotation'
  },
  original_image_id: 'img_456'
};

export const mockSmallPolygon = {
  points: [
    { x: 0, y: 0 },
    { x: 5, y: 0 },
    { x: 5, y: 5 },
    { x: 0, y: 5 }
  ], // Area = 25, below minimum of 100
  metadata: {
    label: 'small_region',
    confidence: 0.8,
    source: 'manual_annotation'
  },
  original_image_id: 'img_456'
};

export const mockSelfIntersectingPolygon = {
  points: [
    { x: 0, y: 0 },
    { x: 100, y: 100 },
    { x: 100, y: 0 },
    { x: 0, y: 100 }
  ], // Creates an X shape (self-intersecting)
  metadata: {
    label: 'intersecting_region',
    confidence: 0.7,
    source: 'manual_annotation'
  },
  original_image_id: 'img_456'
};

// Mock file upload data
export const mockValidFile = {
  fieldname: 'image',
  originalname: 'test-image.jpg',
  encoding: '7bit',
  mimetype: 'image/jpeg',
  size: 1024000, // 1MB
  buffer: Buffer.from('fake image data'),
  stream: {} as any,
  destination: '/tmp/uploads',
  filename: 'test-image-123.jpg',
  path: '/tmp/uploads/test-image-123.jpg'
};

export const mockInvalidFile = {
  fieldname: 'image',
  originalname: 'test-document.pdf',
  encoding: '7bit',
  mimetype: 'application/pdf',
  size: 6000000, // 6MB - too large
  buffer: Buffer.from('fake pdf data'),
  stream: {} as any,
  destination: '/tmp/uploads',
  filename: 'test-document-123.pdf',
  path: '/tmp/uploads/test-document-123.pdf'
};

export const mockOversizedFile = {
  fieldname: 'image',
  originalname: 'huge-image.jpg',
  encoding: '7bit',
  mimetype: 'image/jpeg',
  size: 10485760, // 10MB - over 5MB limit
  buffer: Buffer.from('fake large image data'),
  stream: {} as any,
  destination: '/tmp/uploads',
  filename: 'huge-image-123.jpg',
  path: '/tmp/uploads/huge-image-123.jpg'
};

// Mock request objects
export const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
  method: 'POST',
  path: '/api/v1/test',
  params: { id: 'test_123' },
  query: {},
  body: {},
  file: mockValidFile,
  user: { id: 'user_123', email: 'test@example.com' },
  ...overrides
});

export const createMockResponse = (): Partial<Response> => {
  const mockResponse = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
  };
  
  mockResponse.status.mockReturnValue(mockResponse);
  mockResponse.json.mockReturnValue(mockResponse);
  mockResponse.send.mockReturnValue(mockResponse);
  
  return mockResponse as Partial<Response>;
};

export const createMockNext = (): NextFunction => jest.fn() as NextFunction;

// Mock request with validation errors
export const createMaliciousSchemaRequest = (type: string): Partial<Request> => {
  const baseRequest = createMockRequest();
  
  switch (type) {
    case 'invalid_garment':
      return {
        ...baseRequest,
        body: mockInvalidGarment
      };
    case 'small_polygon':
      return {
        ...baseRequest,
        body: mockSmallPolygon
      };
    case 'self_intersecting_polygon':
      return {
        ...baseRequest,
        body: mockSelfIntersectingPolygon
      };
    case 'invalid_file':
      return {
        ...baseRequest,
        file: mockInvalidFile
      };
    case 'oversized_file':
      return {
        ...baseRequest,
        file: mockOversizedFile
      };
    case 'invalid_uuid':
      return {
        ...baseRequest,
        params: { id: 'invalid-uuid-format' }
      };
    case 'sql_injection':
      return {
        ...baseRequest,
        params: { id: "'; DROP TABLE users; --" }
      };
    default:
      return baseRequest;
  }
};

// Generate test data for schema validation
export const generateSchemaTestData = {
  validGarment: () => ({
    mask_data: {
      width: 200,
      height: 150,
      data: new Array(30000).fill(1) // Valid 200x150 mask with content
    },
    metadata: {
      type: 'jacket',
      color: 'black',
      brand: 'TestBrand',
      tags: ['winter', 'waterproof'],
      season: 'winter',
      size: 'L',
      material: 'polyester'
    },
    original_image_id: 'img_test_456',
    processing_notes: 'Generated test garment'
  }),
  
  invalidGarment: () => ({
    mask_data: {
      width: 100,
      height: 100,
      data: new Array(10000).fill(0) // All zeros - no content
    },
    metadata: {
      type: 'shirt',
      color: 'blue',
      brand: 'TestBrand'
    }
  }),
  
  validPolygon: () => ({
    points: [
      { x: 10, y: 10 },
      { x: 110, y: 10 },
      { x: 110, y: 110 },
      { x: 10, y: 110 }
    ], // 100x100 square, area = 10000
    metadata: {
      label: 'test_polygon',
      confidence: 0.9,
      source: 'manual_annotation',
      notes: 'Generated test polygon'
    },
    original_image_id: 'img_test_789'
  }),
  
  invalidPolygon: () => ({
    points: [
      { x: 0, y: 0 },
      { x: 3, y: 0 },
      { x: 3, y: 3 }
    ], // Triangle with area 4.5, below minimum
    metadata: {
      label: 'small_polygon',
      confidence: 0.5,
      source: 'manual_annotation'
    },
    original_image_id: 'img_test_small'
  }),
  
  validImage: () => ({
    description: 'Valid image description',
    tags: ['fashion', 'style', 'clothing'],
    width: 1920,
    height: 1080
  }),
  
  validWardrobe: () => ({
    name: 'Summer Collection',
    description: 'My favorite summer outfits',
    privacy: 'private'
  })
};

// Performance test data
export const performanceSchemaTestData = {
  largeGarmentDataset: Array(50).fill(0).map((_, i) => generateSchemaTestData.validGarment()),
  complexPolygonDataset: Array(25).fill(0).map((_, i) => ({
    points: Array(20).fill(0).map((_, j) => ({
      x: i * 10 + j,
      y: i * 10 + j * 2
    })),
    metadata: {
      label: `complex_polygon_${i}`,
      confidence: 0.85,
      source: 'automated_detection'
    },
    original_image_id: `img_complex_${i}`
  })),
  massiveFileList: Array(100).fill(0).map((_, i) => ({
    fieldname: 'image',
    originalname: `test-image-${i}.jpg`,
    encoding: '7bit',
    mimetype: 'image/jpeg',
    size: 1024 * (i + 1),
    buffer: Buffer.alloc(1024 * (i + 1), `data${i}`)
  }))
};

// Helper to create mock validation context
export const createMockValidationContext = (overrides: any = {}) => ({
  operation: 'test_validation',
  userId: 'user_123',
  timestamp: new Date().toISOString(),
  requestId: 'req_123',
  ...overrides
});

// Mock validation scenarios with proper structure
export const validationScenarios = {
  garment: {
    valid: [
      generateSchemaTestData.validGarment(),
      {
        mask_data: {
          width: 300,
          height: 200,
          data: new Array(60000).fill(128) // Valid with different values
        },
        metadata: {
          type: 'dress',
          color: 'red',
          brand: 'Designer',
          tags: ['formal', 'evening'],
          season: 'fall',
          size: 'S',
          material: 'silk'
        },
        original_image_id: 'img_valid_2',
        processing_notes: 'High quality detection'
      }
    ],
    invalid: [
      generateSchemaTestData.invalidGarment(),
      {
        mask_data: {
          width: 100,
          height: 100,
          data: new Array(9999).fill(1) // Wrong length
        },
        metadata: {
          type: 'shirt',
          color: 'blue',
          brand: 'TestBrand'
        }
      },
      {
        mask_data: {
          width: 0,
          height: 100,
          data: []
        },
        metadata: {
          type: 'invalid',
          color: 'unknown',
          brand: 'None'
        }
      }
    ]
  },
  
  polygon: {
    valid: [
      generateSchemaTestData.validPolygon(),
      {
        points: [
          { x: 0, y: 0 },
          { x: 50, y: 0 },
          { x: 25, y: 50 }
        ], // Triangle with sufficient area
        metadata: {
          label: 'triangle_region',
          confidence: 0.88,
          source: 'manual_annotation'
        },
        original_image_id: 'img_triangle'
      }
    ],
    invalid: [
      generateSchemaTestData.invalidPolygon(),
      {
        points: [
          { x: 0, y: 0 },
          { x: 1, y: 0 }
        ], // Only 2 points
        metadata: {
          label: 'line_segment',
          confidence: 0.1,
          source: 'manual_annotation'
        },
        original_image_id: 'img_invalid'
      },
      mockSelfIntersectingPolygon
    ]
  },
  
  file: {
    valid: [
      mockValidFile,
      {
        fieldname: 'image',
        originalname: 'test.png',
        encoding: '7bit',
        mimetype: 'image/png',
        size: 2048000,
        buffer: Buffer.from('valid png data')
      }
    ],
    invalid: [
      mockInvalidFile,
      mockOversizedFile,
      {
        fieldname: 'image',
        originalname: 'test.gif',
        encoding: '7bit',
        mimetype: 'image/gif', // Not allowed
        size: 1024000,
        buffer: Buffer.from('gif data')
      }
    ]
  }
};

// Export helper functions for test creation
export const createValidationTest = (schema: any, testData: any, shouldPass: boolean) => {
  return () => {
    const result = schema.safeParse(testData);
    if (shouldPass) {
      expect(result.success).toBe(true);
    } else {
      expect(result.success).toBe(false);
    }
  };
};

export const createPerformanceValidationTest = (validationFunction: Function, iterations: number = 1000) => {
  return () => {
    const startTime = performance.now();
    
    for (let i = 0; i < iterations; i++) {
      validationFunction(`test input ${i}`);
    }
    
    const endTime = performance.now();
    const executionTime = endTime - startTime;
    
    expect(executionTime).toBeLessThan(2000); // Should complete within 2 seconds
  };
};

export const assertValidationResults = (result: any, expectations: any) => {
  if (expectations.shouldSucceed) {
    expect(result.success).toBe(true);
    if (expectations.expectedData) {
      expect(result.data).toMatchObject(expectations.expectedData);
    }
  } else {
    expect(result.success).toBe(false);
    if (expectations.expectedErrors) {
      expect(result.error.issues).toHaveLength(expectations.expectedErrors.length);
    }
  }
};

// Mock data for update image status validation
export const mockUpdateImageStatusData = {
  valid: [
    { status: 'new' },
    { status: 'processed' },
    { status: 'labeled' }
  ],
  invalid: [
    { status: 'invalid' },
    { status: '' },
    { status: null },
    { status: undefined },
    { status: 123 },
    { status: ['new'] },
    { status: { value: 'new' } },
    {}, // Missing status
    { status: 'NEW' }, // Wrong case
    { status: 'new', extra: 'field' } // Extra fields
  ]
};

// Test middleware behavior helpers
export const testMiddlewareBehavior = (middleware: Function) => {
  return {
    withValidData: async (validData: any) => {
      const req = createMockRequest({ body: validData });
      const res = createMockResponse();
      const next = createMockNext();
      
      await middleware(req as Request, res as Response, next);
      return { req, res, next };
    },
    
    withInvalidData: async (invalidData: any) => {
      const req = createMockRequest({ body: invalidData });
      const res = createMockResponse();
      const next = createMockNext();
      
      await middleware(req as Request, res as Response, next);
      return { req, res, next };
    }
  };
};

export default {
  mockValidationSuccess,
  mockValidationFailure,
  createMockRequest,
  createMockResponse,
  createMockNext,
  generateSchemaTestData,
  validationScenarios,
  createValidationTest,
  assertValidationResults,
  mockUpdateImageStatusData
};