// src/tests/unit/debug.unit.test.ts
console.log('debug.unit.test.ts: Starting test file');

// Mock dependencies
jest.mock('multer', () => {
  console.log('debug.unit.test.ts: Mocking multer');
  const mockMulter = jest.fn(() => ({
    single: jest.fn(() => (req: Request, res: Response, next: NextFunction) => {
      console.log('debug.unit.test.ts: Multer middleware called');
      req.file = {
        buffer: Buffer.from('fake-image-data'),
        originalname: 'realistic-image.jpg',
        mimetype: 'image/jpeg',
        size: 2048000,
        fieldname: 'image',
        encoding: '7bit',
        stream: undefined as any,
        destination: '/uploads',
        filename: 'realistic-image.jpg',
        path: '/uploads/realistic-image.jpg'
      };
      next();
    })
  }));
  (mockMulter as any).memoryStorage = jest.fn().mockReturnValue({});
  (mockMulter as any).MulterError = class extends Error {
    constructor(code: string) {
      super(code);
      this.code = code;
    }
    code: string;
  };
  return mockMulter;
});

jest.mock('../../../src/config/firebase', () => {
  console.log('debug.unit.test.ts: Mocking firebase');
  return { default: { storage: jest.fn() } };
});

jest.mock('../../../src/services/imageService', () => {
  console.log('debug.unit.test.ts: Mocking imageService');
  return {};
});

jest.mock('../../../src/utils/ApiError', () => {
  console.log('debug.unit.test.ts: Mocking ApiError');
  const MockApiError = jest.fn().mockImplementation((message, status, code) => ({
    message,
    status,
    code
  }));
  (MockApiError as any).badRequest = jest.fn().mockImplementation((message, code) => ({
    message,
    status: 400,
    code: code || 'BAD_REQUEST'
  }));
  return { ApiError: MockApiError };
});

jest.mock('../../../src/utils/sanitize', () => {
  console.log('debug.unit.test.ts: Mocking sanitization');
  return {
    sanitization: {
      wrapImageController: jest.fn((handler, operation) => {
        console.log(`debug.unit.test.ts: Mock wrapImageController for ${operation}`);
        return async (req: Request, res: Response, next: NextFunction) => {
          try {
            await handler(req, res, next);
          } catch (error) {
            next(error);
          }
        };
      }),
      sanitizeImageForResponse: jest.fn((image) => {
        console.log('debug.unit.test.ts: Mock sanitizeImageForResponse');
        return image;
      })
    }
  };
});

jest.mock('../../../src/config', () => {
  console.log('debug.unit.test.ts: Mocking config');
  return { config: { maxFileSize: 8388608 } };
});

console.log('debug.unit.test.ts: Importing modules');

// Import after mocks
import { Request, Response, NextFunction } from 'express';
import { imageController } from '../../../src/controllers/imageController';
import { imageService } from '../../../src/services/imageService';
import { ApiError } from '../../../src/utils/ApiError';
import { sanitization } from '../../../src/utils/sanitize';

console.log('debug.unit.test.ts: Imported modules', {
  imageController,
  hasUploadMiddleware: !!imageController?.uploadMiddleware,
  imageService: !!imageService,
  ApiError: !!ApiError,
  badRequest: !!ApiError.badRequest,
  sanitization: !!sanitization
});

// Test utilities
const createMockRequest = (): Partial<Request> => {
  const req = {
    user: { id: 'user-123', email: 'test@example.com' },
    file: undefined,
    params: {},
    query: {},
    body: {},
    method: 'POST',
    path: '/api/images/upload',
    headers: {
      'content-type': 'multipart/form-data; boundary=----WebKitFormBoundary'
    },
    get: jest.fn((header: string) => {
      console.log(`debug.unit.test.ts: req.get called for ${header}`);
      if (header.toLowerCase() === 'content-type') {
        return 'multipart/form-data; boundary=----WebKitFormBoundary';
      }
      if (header === 'set-cookie') {
        return undefined;
      }
      return undefined;
    }) as jest.MockedFunction<{
      (name: 'set-cookie'): string[] | undefined;
      (name: string): string | undefined;
    }>
  };
  console.log('debug.unit.test.ts: Created mock request', { headers: req.headers });
  return req;
};

const createMockResponse = (): Partial<Response> => ({
  status: jest.fn().mockReturnThis(),
  json: jest.fn().mockReturnThis(),
  send: jest.fn().mockReturnThis()
});

const mockNext: NextFunction = jest.fn();

const resetAllMocks = () => {
  console.log('debug.unit.test.ts: Resetting mocks');
  jest.clearAllMocks();
  (mockNext as jest.Mock).mockClear();
};

describe('ImageController', () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  const mockImageService = imageService as jest.Mocked<typeof imageService>;
  const mockSanitization = sanitization as jest.Mocked<typeof sanitization>;

  beforeEach(() => {
    console.log('debug.unit.test.ts: beforeEach');
    resetAllMocks();
    req = createMockRequest();
    res = createMockResponse();
    next = mockNext;

    mockSanitization.wrapImageController.mockImplementation((handler, operation) => {
      console.log('debug.unit.test.ts: Setting up wrapImageController', operation);
      return async (req: Request, res: Response, next: NextFunction) => {
        try {
          await handler(req, res, next);
        } catch (error) {
          next(error);
        }
      };
    });
    mockSanitization.sanitizeImageForResponse.mockImplementation((image) => image);
  });

  describe('uploadMiddleware', () => {
    it('should handle valid file upload successfully', async () => {
      console.log('debug.unit.test.ts: Running uploadMiddleware test');

      console.log('debug.unit.test.ts: imageController', {
        imageController,
        uploadMiddleware: imageController.uploadMiddleware
      });

      await imageController.uploadMiddleware(req as Request, res as Response, next);

      console.log('debug.unit.test.ts: After calling uploadMiddleware', {
        nextCalled: (mockNext as jest.Mock).mock.calls.length,
        nextArgs: (mockNext as jest.Mock).mock.calls
      });

      expect(next).toHaveBeenCalledWith();
    });
  });
});