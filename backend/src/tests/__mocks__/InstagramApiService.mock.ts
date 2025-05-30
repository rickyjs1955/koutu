// tests/__mocks__/instagramApiService.mock.ts
import { v4 as uuidv4 } from 'uuid';

// ==================== INSTAGRAM API SERVICE MOCKS ====================

export const mockInstagramApiServiceInstance = {
  importInstagramImage: jest.fn(),
  checkInstagramAPIHealth: jest.fn(),
  validateInstagramAPIImage: jest.fn(),
  saveInstagramImage: jest.fn(),
  isDuplicateImport: jest.fn(),
  fetchInstagramImageWithErrorHandling: jest.fn(),
  performImport: jest.fn(),
  withRetry: jest.fn(),
  handleImportError: jest.fn(),
  saveFailedImportForRetry: jest.fn(),
  clearUserInstagramAuth: jest.fn(),
  trackRateLimit: jest.fn(),
  markAPIHealthy: jest.fn(),
  markAPIUnhealthy: jest.fn(),
  isValidInstagramMediaUrl: jest.fn(),
  sleep: jest.fn()
};

// ==================== DATABASE QUERY MOCKS ====================

export const mockDatabaseQuery = jest.fn();

// Mock query results
export const createMockQueryResult = (rows: any[] = [], rowCount?: number) => ({
  rows,
  rowCount: rowCount ?? rows.length,
  fields: [],
  command: 'SELECT',
  oid: 0
});

// ==================== FETCH API MOCKS ====================

export const mockFetchGlobal = jest.fn();
export const mockAbortController = {
  abort: jest.fn(),
  signal: { aborted: false }
};

export const createMockResponse = (options: {
  ok?: boolean;
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  data?: any;
  arrayBuffer?: ArrayBuffer;
} = {}) => {
  const {
    ok = true,
    status = 200,
    statusText = 'OK',
    headers = {},
    data = {},
    arrayBuffer
  } = options;

  const mockHeaders = new Map(Object.entries(headers));
  
  return {
    ok,
    status,
    statusText,
    headers: {
      get: jest.fn().mockImplementation((key: string) => mockHeaders.get(key.toLowerCase()) || null)
    },
    json: jest.fn().mockResolvedValue(data),
    text: jest.fn().mockResolvedValue(JSON.stringify(data)),
    arrayBuffer: jest.fn().mockResolvedValue(arrayBuffer || new ArrayBuffer(1024))
  };
};

// ==================== SHARP MOCKS ====================

export const mockSharp = {
  metadata: jest.fn(),
  resize: jest.fn(),
  jpeg: jest.fn(),
  png: jest.fn(),
  toColorspace: jest.fn(),
  toFile: jest.fn(),
  toBuffer: jest.fn(),
  composite: jest.fn()
};

// Setup chainable methods
Object.keys(mockSharp).forEach(key => {
  if (key !== 'metadata' && key !== 'toFile' && key !== 'toBuffer') {
    (mockSharp as any)[key].mockReturnThis();
  }
});

// ==================== STORAGE SERVICE MOCKS ====================

export const mockStorageService = {
  saveFile: jest.fn(),
  deleteFile: jest.fn(),
  getAbsolutePath: jest.fn(),
  getSignedUrl: jest.fn(),
  getContentType: jest.fn(),
  ensureDirectoryExists: jest.fn()
};

// ==================== IMAGE MODEL MOCKS ====================

export const mockImageModel = {
  create: jest.fn(),
  findById: jest.fn(),
  findByUserId: jest.fn(),
  updateStatus: jest.fn(),
  updateMetadata: jest.fn(),
  delete: jest.fn(),
  findByFilePath: jest.fn()
};

// ==================== INSTAGRAM API HELPERS ====================

export const createValidInstagramUrls = () => [
  'https://scontent.cdninstagram.com/v/t51.2885-15/123456789_123456789_n.jpg',
  'https://scontent-lax3-1.cdninstagram.com/v/t51.2885-15/image.jpg',
  'https://instagram.flax1-1.fbcdn.net/v/t51.2885-15/photo.jpg',
  'https://scontent-atl3-1.xx.fbcdn.net/v/t51.2885-15/media.jpg'
];

export const createInvalidInstagramUrls = () => [
  'https://example.com/image.jpg',
  'https://facebook.com/image.jpg',
  'https://twitter.com/image.jpg',
  'not-a-url',
  '',
  'https://malicious-site.com/instagram-lookalike.jpg'
];

export const createMockInstagramImageBuffer = (size: number = 1024): Buffer => {
  // Create a minimal valid JPEG buffer
  const jpegHeader = Buffer.from([
    0xFF, 0xD8, // SOI
    0xFF, 0xE0, // APP0
    0x00, 0x10, // Length
    0x4A, 0x46, 0x49, 0x46, 0x00, // JFIF
    0x01, 0x01, // Version
    0x01, 0x00, 0x01, 0x00, 0x01, // Density
    0x00, 0x00 // Thumbnail
  ]);
  
  const jpegEnd = Buffer.from([0xFF, 0xD9]); // EOI
  const padding = Buffer.alloc(size - jpegHeader.length - jpegEnd.length, 0x00);
  
  return Buffer.concat([jpegHeader, padding, jpegEnd]);
};

export const createCorruptedImageBuffer = (): Buffer => {
  // Truncated JPEG (missing EOI marker)
  return Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]);
};

// ==================== INSTAGRAM ERROR SCENARIOS ====================

export const createInstagramErrorScenarios = () => ({
  networkErrors: {
    timeout: () => {
      const error = new Error('Request timeout');
      error.name = 'AbortError';
      return error;
    },
    connectionRefused: () => {
      const error = new Error('Connection refused');
      (error as any).code = 'ECONNREFUSED';
      return error;
    },
    dnsFailure: () => {
      const error = new Error('DNS lookup failed');
      (error as any).code = 'ENOTFOUND';
      return error;
    },
    connectionReset: () => {
      const error = new Error('Connection reset');
      (error as any).code = 'ECONNRESET';
      return error;
    },
    generalNetwork: () => {
      const error = new TypeError('Failed to fetch');
      return error;
    }
  },
  
  httpErrors: {
    badRequest: () => createMockResponse({
      ok: false,
      status: 400,
      statusText: 'Bad Request'
    }),
    unauthorized: () => createMockResponse({
      ok: false,
      status: 401,
      statusText: 'Unauthorized'
    }),
    forbidden: () => createMockResponse({
      ok: false,
      status: 403,
      statusText: 'Forbidden'
    }),
    notFound: () => createMockResponse({
      ok: false,
      status: 404,
      statusText: 'Not Found'
    }),
    rateLimited: (retryAfter: string = '300') => createMockResponse({
      ok: false,
      status: 429,
      statusText: 'Too Many Requests',
      headers: {
        'retry-after': retryAfter,
        'x-ratelimit-remaining': '0'
      }
    }),
    serverError: () => createMockResponse({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error'
    }),
    serviceUnavailable: () => createMockResponse({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable'
    })
  }
});

// ==================== SECURITY TEST HELPERS ====================

export const createSecurityTestPayloads = () => ({
  maliciousUrls: [
    'javascript:alert("XSS")',
    'data:text/html,<script>alert("XSS")</script>',
    'https://evil.com/image.jpg?redirect=https://instagram.com',
    'https://instagram.com.evil.com/image.jpg',
    'https://scontent.cdninstagram.com/../../../etc/passwd',
    'https://scontent.cdninstagram.com/image.jpg?callback=evil',
    'file:///etc/passwd',
    'ftp://malicious.com/image.jpg'
  ],
  
  oversizedPayloads: {
    createLargeUrl: (size: number = 10000) => 
      'https://scontent.cdninstagram.com/' + 'a'.repeat(size) + '.jpg',
    createLargeUserId: (size: number = 1000) => 'u'.repeat(size),
    createLargeBuffer: (size: number = 50 * 1024 * 1024) => Buffer.alloc(size) // 50MB
  },
  
  injectionAttempts: {
    sqlInjection: [
      "'; DROP TABLE images; --",
      "' OR '1'='1",
      "'; DELETE FROM users WHERE '1'='1; --",
      "user-123'; UPDATE users SET role='admin' WHERE id='user-123'; --"
    ],
    nosqlInjection: [
      '{"$ne": null}',
      '{"$gt": ""}',
      '{"$where": "function() { return true; }"}'
    ],
    pathTraversal: [
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '....//....//....//etc//passwd'
    ]
  },
  
  headersInjection: {
    'X-Forwarded-For': '127.0.0.1, evil.com',
    'User-Agent': '<script>alert("XSS")</script>',
    'Referer': 'javascript:alert("XSS")',
    'Cookie': 'session=<script>alert("XSS")</script>',
    'Content-Type': 'text/html; charset=UTF-8'
  }
});

// ==================== RATE LIMITING TEST HELPERS ====================

export const createRateLimitingScenarios = () => ({
  withinLimits: {
    requestCount: 10,
    timeWindow: 60000, // 1 minute
    expectedBehavior: 'success'
  },
  
  exceedsLimits: {
    requestCount: 100,
    timeWindow: 60000, // 1 minute
    expectedBehavior: 'rate_limited'
  },
  
  burstTraffic: {
    requestCount: 50,
    timeWindow: 1000, // 1 second
    expectedBehavior: 'temporary_throttle'
  },
  
  distributedLoad: {
    userCount: 10,
    requestsPerUser: 20,
    timeWindow: 60000,
    expectedBehavior: 'selective_throttle'
  }
});

// ==================== CONCURRENCY TEST HELPERS ====================

export const createConcurrencyTestScenarios = () => ({
  simultaneousRequests: async (
    requestCount: number,
    operation: () => Promise<any>
  ) => {
    const promises = Array.from({ length: requestCount }, () => operation());
    return Promise.allSettled(promises);
  },
  
  raceconditionTests: {
    duplicateImports: (url: string, userId: string, count: number = 5) => 
      Array.from({ length: count }, () => ({ url, userId })),
    
    concurrentAuth: (userId: string, count: number = 3) =>
      Array.from({ length: count }, () => ({ userId, action: 'auth_refresh' }))
  }
});

// ==================== VALIDATION HELPERS ====================

export const createValidationHelpers = () => ({
  isValidImageBuffer: (buffer: Buffer): boolean => {
    // Check for JPEG SOI marker
    return buffer.length >= 2 && buffer[0] === 0xFF && buffer[1] === 0xD8;
  },
  
  isValidImageMetadata: (metadata: any): boolean => {
    return metadata &&
           typeof metadata.width === 'number' && metadata.width > 0 &&
           typeof metadata.height === 'number' && metadata.height > 0 &&
           typeof metadata.format === 'string';
  },
  
  isInstagramCompatible: (metadata: any): boolean => {
    const { width, height } = metadata;
    const aspectRatio = width / height;
    
    return width >= 320 && width <= 1440 &&
           height >= 168 && height <= 1800 &&
           aspectRatio >= 0.8 && aspectRatio <= 1.91;
  }
});

// ==================== PERFORMANCE TEST HELPERS ====================

export const createPerformanceTestHelpers = () => ({
  measureExecutionTime: async <T>(
    operation: () => Promise<T>
  ): Promise<{ result: T; duration: number }> => {
    const start = performance.now();
    const result = await operation();
    const duration = performance.now() - start;
    return { result, duration };
  },
  
  createLoadTestScenario: (
    concurrentUsers: number,
    requestsPerUser: number,
    operation: (userId: string) => Promise<any>
  ) => {
    const users = Array.from({ length: concurrentUsers }, (_, i) => `user-${i}`);
    const allRequests = users.flatMap(userId =>
      Array.from({ length: requestsPerUser }, () => () => operation(userId))
    );
    
    return allRequests;
  }
});

// ==================== MOCK SETUP AND TEARDOWN ====================

export const setupInstagramApiServiceMocks = () => {
  // Reset all mocks
  Object.values(mockInstagramApiServiceInstance).forEach(mock => {
    if (jest.isMockFunction(mock)) {
      mock.mockReset();
    }
  });
  
  mockDatabaseQuery.mockReset();
  mockFetchGlobal.mockReset();
  
  // Setup default successful behaviors
  mockInstagramApiServiceInstance.checkInstagramAPIHealth.mockResolvedValue(true);
  mockInstagramApiServiceInstance.isValidInstagramMediaUrl.mockReturnValue(true);
  mockInstagramApiServiceInstance.isDuplicateImport.mockResolvedValue(false);
  mockInstagramApiServiceInstance.validateInstagramAPIImage.mockResolvedValue({
    isValid: true,
    metadata: { width: 1080, height: 1080, format: 'jpeg' },
    errors: []
  });
  
  // Setup storage mocks
  mockStorageService.saveFile.mockResolvedValue('uploads/instagram-import.jpg');
  mockImageModel.create.mockResolvedValue({
    id: uuidv4(),
    user_id: 'test-user',
    file_path: 'uploads/instagram-import.jpg',
    status: 'new'
  });
  
  // Setup fetch mock
  global.fetch = mockFetchGlobal;
  global.AbortController = jest.fn(() => mockAbortController) as any;
  global.setTimeout = jest.fn((callback, delay) => {
    if (typeof callback === 'function') callback();
    return 123;
  }) as any;
  global.clearTimeout = jest.fn();
};

export const teardownInstagramApiServiceMocks = () => {
  jest.restoreAllMocks();
  delete (global as any).fetch;
  delete (global as any).AbortController;
};

// ==================== EXPORT ALL ====================

export default {
  mockInstagramApiServiceInstance,
  mockDatabaseQuery,
  mockFetchGlobal,
  mockAbortController,
  createMockResponse,
  mockSharp,
  mockStorageService,
  mockImageModel,
  createValidInstagramUrls,
  createInvalidInstagramUrls,
  createMockInstagramImageBuffer,
  createCorruptedImageBuffer,
  createInstagramErrorScenarios,
  createSecurityTestPayloads,
  createRateLimitingScenarios,
  createConcurrencyTestScenarios,
  createValidationHelpers,
  createPerformanceTestHelpers,
  setupInstagramApiServiceMocks,
  teardownInstagramApiServiceMocks
};