// tests/__mocks__/images.mock.ts
import { v4 as uuidv4 } from 'uuid';

// ==================== TYPE DEFINITIONS ====================

export interface MockImage {
  id: string;
  user_id: string;
  file_path: string;
  original_metadata: Record<string, any>;
  upload_date: Date;
  status: 'new' | 'processed' | 'labeled';
}

export interface MockImageUpload {
  fieldname: string;
  originalname: string;
  encoding: string;
  mimetype: string;
  size: number;
  buffer: Buffer;
}

export interface MockInstagramResponse {
  access_token: string;
  user: {
    id: string;
    username: string;
    account_type: string;
    media_count: number;
  };
  media: {
    id: string;
    media_type: string;
    media_url: string;
    thumbnail_url?: string;
    caption?: string;
  }[];
}

// ==================== MOCK DATA FACTORIES ====================

export const createMockImage = (overrides: Partial<MockImage> = {}): MockImage => ({
  id: uuidv4(),
  user_id: uuidv4(),
  file_path: 'uploads/test-image.jpg',
  original_metadata: {
    width: 800,
    height: 600,
    format: 'jpeg',
    size: 204800,
    mimetype: 'image/jpeg',
    filename: 'test-image.jpg',
    uploadedAt: new Date().toISOString(),
    space: 'srgb',
    channels: 3,
    density: 72
  },
  upload_date: new Date(),
  status: 'new',
  ...overrides
});

export const createMockImageUpload = (overrides: Partial<MockImageUpload> = {}): MockImageUpload => ({
  fieldname: 'image',
  originalname: 'test-image.jpg',
  encoding: '7bit',
  mimetype: 'image/jpeg',
  size: 204800,
  buffer: Buffer.from('mock-image-data'),
  ...overrides
});

export const createMockInstagramMedia = (overrides: Partial<any> = {}) => ({
  id: '12345678901234567',
  media_type: 'IMAGE',
  media_url: 'https://scontent.cdninstagram.com/test-image.jpg',
  thumbnail_url: 'https://scontent.cdninstagram.com/test-thumb.jpg',
  caption: 'Test Instagram post',
  timestamp: new Date().toISOString(),
  ...overrides
});

export const createMockInstagramUser = (overrides: Partial<any> = {}) => ({
  id: '12345678901234567',
  username: 'testuser',
  account_type: 'PERSONAL',
  media_count: 42,
  ...overrides
});

// ==================== DATABASE MOCKS ====================

// Note: mockDatabaseQuery is now defined in the test files directly
export const mockDatabaseResult = {
  rows: [] as any[],
  rowCount: 0,
  fields: [],
  command: 'SELECT',
  oid: 0
};

export const createMockQueryResult = (rows: any[], rowCount?: number) => ({
  ...mockDatabaseResult,
  rows,
  rowCount: rowCount ?? rows.length
});

// Mock database operations
export const mockImageModelOperations = {
  create: jest.fn(),
  findById: jest.fn(),
  findByUserId: jest.fn(),
  updateStatus: jest.fn(),
  updateMetadata: jest.fn(),
  delete: jest.fn(),
  findDependentGarments: jest.fn(),
  findDependentPolygons: jest.fn(),
  getUserImageStats: jest.fn(),
  batchUpdateStatus: jest.fn(),
  findByFilePath: jest.fn()
};

// ==================== STORAGE SERVICE MOCKS ====================

export const mockStorageService = {
  saveFile: jest.fn().mockResolvedValue('uploads/mock-file.jpg'),
  deleteFile: jest.fn().mockResolvedValue(true),
  getAbsolutePath: jest.fn().mockReturnValue('/absolute/path/to/file.jpg'),
  getSignedUrl: jest.fn().mockResolvedValue('https://signed-url.com/file.jpg'),
  getContentType: jest.fn().mockReturnValue('image/jpeg')
};

// ==================== IMAGE PROCESSING MOCKS ====================

export const mockImageProcessingService = {
  validateImageBuffer: jest.fn().mockResolvedValue({
    width: 800,
    height: 600,
    format: 'jpeg',
    channels: 3,
    space: 'srgb'
  }),
  convertToSRGB: jest.fn().mockResolvedValue('uploads/converted-image.jpg'),
  resizeImage: jest.fn().mockResolvedValue('uploads/resized-image.jpg'),
  extractMetadata: jest.fn().mockResolvedValue({
    width: 800,
    height: 600,
    format: 'jpeg'
  }),
  generateThumbnail: jest.fn().mockResolvedValue('uploads/thumbnail.jpg'),
  optimizeForWeb: jest.fn().mockResolvedValue('uploads/optimized.jpg')
};

// ==================== INSTAGRAM API MOCKS ====================

export const mockInstagramApiService = {
  importInstagramImage: jest.fn(),
  validateInstagramApiImage: jest.fn().mockResolvedValue({
    isValid: true,
    metadata: { width: 800, height: 600, format: 'jpeg' },
    errors: []
  }),
  saveInstagramImage: jest.fn(),
  checkInstagramAPIHealth: jest.fn().mockResolvedValue(true),
  isDuplicateImport: jest.fn().mockResolvedValue(false)
};

// Mock Instagram HTTP responses
export const mockInstagramTokenResponse = {
  access_token: 'mock_access_token_12345',
  token_type: 'bearer',
  expires_in: 3600
};

export const mockInstagramUserResponse = {
  id: '12345678901234567',
  username: 'testuser',
  account_type: 'PERSONAL',
  media_count: 42
};

export const mockInstagramMediaResponse = {
  data: [
    createMockInstagramMedia(),
    createMockInstagramMedia({ id: '98765432109876543' })
  ],
  paging: {
    cursors: {
      before: 'before_cursor',
      after: 'after_cursor'
    },
    next: 'https://graph.instagram.com/me/media?after=after_cursor'
  }
};

// ==================== HTTP MOCKS ====================

export const mockFetch = jest.fn();
export const mockFetchResponse = {
  ok: true,
  status: 200,
  statusText: 'OK',
  headers: new Map([
    ['content-type', 'application/json'],
    ['x-ratelimit-remaining', '100'],
    ['x-ratelimit-reset', '3600']
  ]),
  json: jest.fn(),
  text: jest.fn(),
  arrayBuffer: jest.fn()
};

// ==================== SHARP MOCKS ====================

export const mockSharp = {
  metadata: jest.fn().mockResolvedValue({
    width: 800,
    height: 600,
    format: 'jpeg',
    channels: 3,
    space: 'srgb',
    density: 72,
    hasProfile: false,
    hasAlpha: false
  }),
  resize: jest.fn().mockReturnThis(),
  jpeg: jest.fn().mockReturnThis(),
  png: jest.fn().mockReturnThis(),
  toColorspace: jest.fn().mockReturnThis(),
  toFile: jest.fn().mockResolvedValue({ size: 204800 }),
  toBuffer: jest.fn().mockResolvedValue(Buffer.from('processed-image-data')),
  composite: jest.fn().mockReturnThis()
};

// ==================== MULTER MOCKS ====================

export const mockMulter = {
  single: jest.fn().mockReturnValue((req: any, res: any, next: any) => {
    req.file = createMockImageUpload();
    next();
  }),
  memoryStorage: jest.fn(),
  MulterError: class MulterError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.code = code;
      this.name = 'MulterError';
    }
  }
};

// ==================== ERROR MOCKS ====================

export const mockApiError = {
  badRequest: jest.fn().mockImplementation((message, code) => ({
    message,
    statusCode: 400,
    code: code || 'BAD_REQUEST'
  })),
  unauthorized: jest.fn().mockImplementation((message, code) => ({
    message,
    statusCode: 401,
    code: code || 'UNAUTHORIZED'
  })),
  forbidden: jest.fn().mockImplementation((message, code) => ({
    message,
    statusCode: 403,
    code: code || 'FORBIDDEN'
  })),
  notFound: jest.fn().mockImplementation((message, code) => ({
    message,
    statusCode: 404,
    code: code || 'NOT_FOUND'
  })),
  internal: jest.fn().mockImplementation((message, code) => ({
    message,
    statusCode: 500,
    code: code || 'INTERNAL_ERROR'
  })),
  validation: jest.fn().mockImplementation((message, field, value) => ({
    message,
    statusCode: 400,
    code: 'VALIDATION_ERROR',
    context: { field, value }
  })),
  businessLogic: jest.fn().mockImplementation((message, rule) => ({
    message,
    statusCode: 400,
    code: 'BUSINESS_LOGIC_ERROR',
    context: { rule }
  }))
};

// ==================== INSTAGRAM API ERROR MOCKS ====================

export const mockInstagramApiError = {
  fromHttpStatus: jest.fn().mockImplementation((status) => ({
    message: `Instagram API error ${status}`,
    statusCode: status >= 500 ? 503 : status,
    code: `INSTAGRAM_ERROR_${status}`
  })),
  fromNetworkError: jest.fn().mockImplementation((error) => ({
    message: 'Instagram network error',
    statusCode: 503,
    code: 'INSTAGRAM_NETWORK_ERROR'
  })),
  fromBusinessRule: jest.fn().mockImplementation((rule) => ({
    message: `Instagram business rule error: ${rule}`,
    statusCode: 400,
    code: `INSTAGRAM_${rule}`
  })),
  isRetryable: jest.fn().mockReturnValue(true),
  getActionSuggestion: jest.fn().mockReturnValue('Try again later'),
  createMonitoringEvent: jest.fn().mockReturnValue({
    category: 'external_error',
    severity: 'medium',
    retryable: true,
    context: {}
  })
};

// ==================== REQUEST/RESPONSE MOCKS ====================

export const createMockRequest = (overrides: Partial<any> = {}) => ({
  user: {
    id: uuidv4(),
    email: 'test@example.com'
  },
  params: {},
  query: {},
  body: {},
  file: undefined,
  files: undefined,
  headers: {
    'content-type': 'application/json',
    'user-agent': 'test-agent'
  },
  method: 'GET',
  path: '/api/v1/images',
  get: jest.fn().mockImplementation((header) => {
    return overrides.headers?.[header.toLowerCase()] || '';
  }),
  ...overrides
});

export const createMockResponse = () => {
  const res = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    sendFile: jest.fn().mockReturnThis(),
    redirect: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    download: jest.fn().mockReturnThis(),
    locals: {}
  };
  return res;
};

export const mockNext = jest.fn();

// ==================== SECURITY TESTING MOCKS ====================

export const createMaliciousImageUpload = (type: 'executable' | 'oversized' | 'malformed' | 'script_injection' = 'malformed') => {
  const base = createMockImageUpload();
  
  switch (type) {
    case 'executable':
      return {
        ...base,
        originalname: 'malicious.exe',
        mimetype: 'application/octet-stream',
        buffer: Buffer.from('MZ\x90\x00') // PE header
      };
    
    case 'oversized':
      return {
        ...base,
        size: 10 * 1024 * 1024, // 10MB
        buffer: Buffer.alloc(10 * 1024 * 1024)
      };
    
    case 'script_injection':
      return {
        ...base,
        originalname: '<script>alert("xss")</script>.jpg',
        buffer: Buffer.from('<script>alert("xss")</script>')
      };
    
    case 'malformed':
    default:
      return {
        ...base,
        buffer: Buffer.from('not-an-image')
      };
  }
};

export const createPathTraversalAttempt = () => ({
  ...createMockImageUpload(),
  originalname: '../../../etc/passwd.jpg'
});

// ==================== MOCK RESET UTILITIES ====================

export const resetAllMocks = () => {
  jest.clearAllMocks();
  
  // Reset database mocks
  Object.values(mockImageModelOperations).forEach(mock => mock.mockReset());
  
  // Reset service mocks
  Object.values(mockStorageService).forEach(mock => mock.mockReset());
  Object.values(mockImageProcessingService).forEach(mock => mock.mockReset());
  Object.values(mockInstagramApiService).forEach(mock => mock.mockReset());
  
  // Reset error mocks
  Object.values(mockApiError).forEach(mock => mock.mockReset());
  Object.values(mockInstagramApiError).forEach(mock => mock.mockReset());
  
  // Reset HTTP mocks
  mockFetch.mockReset();
  mockFetchResponse.json.mockReset();
  mockFetchResponse.text.mockReset();
  mockFetchResponse.arrayBuffer.mockReset();
  
  // Reset Sharp mocks
  Object.values(mockSharp).forEach(mock => {
    if (typeof mock === 'function') mock.mockReset();
  });
  
  // Reset other mocks
  mockNext.mockReset();
};

// ==================== MOCK SETUP HELPERS ====================

export const setupHappyPathMocks = () => {
  // Database operations succeed
  mockImageModelOperations.create.mockResolvedValue(createMockImage());
  mockImageModelOperations.findById.mockResolvedValue(createMockImage());
  mockImageModelOperations.findByUserId.mockResolvedValue([createMockImage()]);
  mockImageModelOperations.updateStatus.mockResolvedValue(createMockImage({ status: 'processed' }));
  mockImageModelOperations.delete.mockResolvedValue(true);
  mockImageModelOperations.findDependentGarments.mockResolvedValue([]);
  mockImageModelOperations.findDependentPolygons.mockResolvedValue([]);
  
  // Storage operations succeed
  mockStorageService.saveFile.mockResolvedValue('uploads/saved-file.jpg');
  mockStorageService.deleteFile.mockResolvedValue(true);
  
  // Image processing succeeds
  mockImageProcessingService.validateImageBuffer.mockResolvedValue({
    width: 800,
    height: 600,
    format: 'jpeg',
    space: 'srgb'
  });
  
  // Instagram API succeeds
  mockInstagramApiService.importInstagramImage.mockResolvedValue({
    id: uuidv4(),
    url: 'https://example.com/imported-image.jpg'
  });
  
  // HTTP requests succeed
  mockFetch.mockResolvedValue({
    ...mockFetchResponse,
    json: jest.fn().mockResolvedValue(mockInstagramUserResponse)
  });
};

export const setupErrorMocks = () => {
  // Database operations fail
  mockImageModelOperations.create.mockRejectedValue(new Error('Database error'));
  mockImageModelOperations.findById.mockRejectedValue(new Error('Database error'));
  
  // Storage operations fail
  mockStorageService.saveFile.mockRejectedValue(new Error('Storage error'));
  mockStorageService.deleteFile.mockRejectedValue(new Error('Storage error'));
  
  // Image processing fails
  mockImageProcessingService.validateImageBuffer.mockRejectedValue(new Error('Invalid image'));
  
  // Instagram API fails
  mockInstagramApiService.importInstagramImage.mockRejectedValue(new Error('Instagram API error'));
  
  // HTTP requests fail
  mockFetch.mockRejectedValue(new Error('Network error'));
};

// Export all mocks for easy importing
export default {
  // Factories
  createMockImage,
  createMockImageUpload,
  createMockInstagramMedia,
  createMockInstagramUser,
  createMockRequest,
  createMockResponse,
  
  // Mocks
  mockImageModelOperations,
  mockStorageService,
  mockImageProcessingService,
  mockInstagramApiService,
  mockApiError,
  mockInstagramApiError,
  mockSharp,
  mockMulter,
  mockFetch,
  mockNext,
  
  // Security
  createMaliciousImageUpload,
  createPathTraversalAttempt,
  
  // Utilities
  resetAllMocks,
  setupHappyPathMocks,
  setupErrorMocks
};