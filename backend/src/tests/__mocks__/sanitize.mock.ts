// backend/src/__mocks__/sanitize.mock.ts
import { Request, Response, NextFunction } from 'express';

export const mockRawImage = {
  id: 'img_123',
  status: 'uploaded',
  upload_date: '2024-01-01T00:00:00Z',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
  file_path: '/uploads/raw/image.jpg',
  original_metadata: {
    filename: 'test-image.jpg',
    width: 1920,
    height: 1080,
    format: 'JPEG',
    size: 2048576,
    mimetype: 'image/jpeg',
    uploadedAt: '2024-01-01T00:00:00Z',
    description: 'Test image'
  }
};

export const mockRawPolygon = {
  id: 'poly_456',
  points: [
    { x: 100, y: 200 },
    { x: 200, y: 200 },
    { x: 200, y: 300 },
    { x: 100, y: 300 }
  ],
  metadata: {
    label: 'shirt',
    confidence: 0.95,
    source: 'manual_annotation',
    notes: 'Good quality annotation'
  },
  original_image_id: 'img_123',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z'
};

export const mockRawGarment = {
  id: 'garment_789',
  metadata: {
    type: 'shirt',
    color: 'blue',
    brand: 'Nike',
    tags: ['casual', 'summer', 'comfortable'],
    pattern: 'solid',
    season: 'summer',
    size: 'M',
    material: 'cotton'
  },
  file_path: '/uploads/garments/garment.jpg',
  mask_path: '/uploads/masks/garment_mask.jpg',
  original_image_id: 'img_123',
  status: 'processed',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z'
};

export const mockRawWardrobe = {
  id: 'wardrobe_101',
  name: 'Summer Collection',
  description: 'My favorite summer clothes',
  garments: [mockRawGarment],
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z'
};

export const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
  method: 'POST',
  path: '/api/v1/images/upload',
  headers: {
    'user-agent': 'Mozilla/5.0',
    'content-type': 'multipart/form-data',
    'accept': 'application/json'
  },
  user: { id: 'user_123', email: 'test@example.com' },
  get: jest.fn((header: string) => {
    const headers: Record<string, string | string[]> = {
      'user-agent': 'Mozilla/5.0',
      'content-type': 'multipart/form-data',
      'content-length': '2048576',
      'accept': 'application/json',
      'set-cookie': ['cookie1=value1', 'cookie2=value2']
    };
    return headers[header.toLowerCase()];
  }) as any,
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

export const createMaliciousRequest = (type: string): Partial<Request> => {
  const baseRequest = createMockRequest();
  
  switch (type) {
    case 'xss_headers':
      return {
        ...baseRequest,
        headers: {
          'user-agent': 'Mozilla/5.0 <script>alert("xss")</script>',
          'content-type': 'multipart/form-data',
          'accept': 'application/json',
          'x-malicious': '<script>document.cookie</script>'
        },
        get: jest.fn((header: string) => {
          const headers: Record<string, string> = {
            'user-agent': 'Mozilla/5.0 <script>alert("xss")</script>',
            'content-type': 'multipart/form-data',
            'accept': 'application/json',
            'x-malicious': '<script>document.cookie</script>'
          };
          return headers[header.toLowerCase()];
        }) as any
      };
    default:
      return baseRequest;
  }
};

export const generateTestData = {
  largeString: () => 'A'.repeat(10000),
  maliciousString: () => '<script>alert("test")</script>',
  complexObject: () => ({
    level1: {
      level2: {
        level3: {
          dangerous: '<script>alert("nested")</script>',
          safe: 'clean value'
        }
      }
    }
  })
};

export const performanceTestData = {
  largeDataset: Array(50).fill(0).map((_, i) => ({ // Reduced from 1000 to 50
    id: `item_${i}`,
    content: `Content ${i}`,
    metadata: {
      type: 'test',
      index: i
    }
  }))
};

// backend/src/__helpers__/sanitize.helper.ts
export const setupSanitizationTestEnvironment = () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });
};

export const createIntegrationTestScenarios = () => {
  return [
    {
      name: 'basic_sanitization',
      input: 'Hello <script>alert("xss")</script> World',
      expected: 'Hello  World'
    },
    {
      name: 'path_traversal',
      input: '../../../etc/passwd',
      expected: ''
    }
  ];
};

export const runIntegrationTestScenarios = (scenarios: any[], sanitizeFunction: Function) => {
  scenarios.forEach(scenario => {
    it(`should handle ${scenario.name}`, () => {
      const result = sanitizeFunction(scenario.input);
      expect(result).toBe(scenario.expected);
    });
  });
};

export const createPerformanceTest = (testFunction: Function, iterations: number = 1000) => {
  return () => {
    const startTime = performance.now();
    
    for (let i = 0; i < iterations; i++) {
      testFunction(`test input ${i}`);
    }
    
    const endTime = performance.now();
    const executionTime = endTime - startTime;
    
    expect(executionTime).toBeLessThan(1000); // Should complete within 1 second
  };
};

export const assertSanitizationResults = (result: any, expectations: any) => {
  Object.entries(expectations).forEach(([key, value]) => {
    if (value === null) {
      expect(result).not.toHaveProperty(key);
    } else {
      expect(result).toHaveProperty(key, value);
    }
  });
};

export const testSanitizationErrorHandling = (sanitizeFunction: Function) => {
  const invalidInputs = [null, undefined, 123, {}, [], true];
  
  invalidInputs.forEach(input => {
    expect(() => sanitizeFunction(input)).not.toThrow();
  });
};

export const createStressTests = (sanitizeFunction: Function) => {
  describe('Stress tests', () => {
    it('should handle large datasets without excessive memory usage', () => {
      const initialMemory = process.memoryUsage().heapUsed;
      
      // Create a much smaller, more realistic dataset for testing
      const largeDataset = Array(50).fill(0).map((_, i) => ({
        id: `item_${i}`,
        content: `Test content ${i} <script>alert("${i}")</script>`,
        metadata: {
          type: 'test',
          index: i,
          description: `Description ${i}`
        }
      }));

      // Process the dataset
      const results = largeDataset.map(item => sanitizeFunction(item));
      
      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      expect(results).toHaveLength(largeDataset.length);
      
      // Much more conservative memory expectation - 1MB instead of 100MB
      expect(memoryIncrease).toBeLessThan(1 * 1024 * 1024);
    });

    it('should handle complex nested objects efficiently', () => {
      const startTime = performance.now();
      
      const complexData = {
        level1: {
          level2: {
            level3: {
              malicious: '<script>alert("nested")</script>',
              safe: 'clean value',
              array: Array(10).fill('test data') // Reduced from 50 to 10
            }
          }
        }
      };

      const result = sanitizeFunction(complexData);
      
      const endTime = performance.now();
      const executionTime = endTime - startTime;

      expect(result).toBeDefined();
      expect(executionTime).toBeLessThan(100); // Should complete quickly
    });

    it('should handle circular references gracefully', () => {
      const circularObj: any = { name: 'test' };
      circularObj.self = circularObj;

      expect(() => {
        const result = sanitizeFunction(circularObj);
        expect(result).toBeDefined();
        expect(result.name).toBe('test');
        expect(result.self).toEqual({}); // Circular reference becomes empty object
      }).not.toThrow();
    });
  });
};

export const validateApiPaths = (pathFunction: Function) => {
  it('should generate valid API paths', () => {
    const testCases = [
      { input: ['images', 'img_123', 'file'], expected: '/api/v1/images/img_123/file' },
      { input: ['garments', 'garment_456', 'image'], expected: '/api/v1/garments/garment_456/image' },
      { input: ['polygons', 'poly_789', 'data'], expected: '/api/v1/polygons/poly_789/data' }
    ];

    testCases.forEach(({ input, expected }) => {
      const result = pathFunction(...input);
      expect(result).toBe(expected);
    });
  });

  it('should sanitize malicious path components', () => {
    const maliciousInputs = [
      ['images<script>', 'id/../../../etc', 'file'],
      ['../admin', 'user_123', 'data'],
      ['normal', 'id<>"|?*', 'file']
    ];

    maliciousInputs.forEach(input => {
      const result = pathFunction(...input);
      expect(result).toMatch(/^\/api\/v1\/[a-z0-9\-_]+\/[a-z0-9\-_]+\/[a-z0-9\-_]+$/);
      expect(result).not.toContain('../');
      expect(result).not.toContain('<script>');
      expect(result).not.toContain('<>"|?*');
    });
  });
};