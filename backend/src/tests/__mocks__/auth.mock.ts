// backend/src/__tests__/mocks/auth.mock.ts
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';

// Extend Request interface to include custom properties
declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
      };
      resourceContext?: {
        resourceType: string;
        resourceId: string;
        ownerId: string;
      };
    }
  }
}

// Mock user data
export const mockUser = {
  id: '123e4567-e89b-12d3-a456-426614174000',
  email: 'test@example.com',
  password: 'hashedPassword',
  created_at: new Date(),
  updated_at: new Date()
};

export const mockUserWithoutId = {
  email: 'test@example.com',
  password: 'hashedPassword'
};

// Mock JWT tokens
export const validToken = 'valid.jwt.token';
export const invalidToken = 'invalid.token';
export const expiredToken = 'expired.jwt.token';
export const malformedToken = 'malformed-token';

// Mock JWT payload
export const mockJwtPayload = {
  id: mockUser.id,
  email: mockUser.email,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 86400 // 24 hours
};

// Mock Express Request with different auth scenarios
export const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
  headers: {},
  params: {},
  user: undefined,
  resourceContext: undefined,
  ...overrides
});

// Mock Express Response
export const createMockResponse = (): Partial<Response> => {
  const mockResponse = {
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis()
  } as any;
  
  return mockResponse;
};

// Mock Express NextFunction
export const createMockNext = (): NextFunction => 
  jest.fn() as NextFunction;

// Mock requests with different authorization headers
export const createRequestWithValidToken = (): Partial<Request> => 
  createMockRequest({
    headers: {
      authorization: `Bearer ${validToken}`
    }
  });

export const createRequestWithInvalidToken = (): Partial<Request> => 
  createMockRequest({
    headers: {
      authorization: `Bearer ${invalidToken}`
    }
  });

export const createRequestWithExpiredToken = (): Partial<Request> => 
  createMockRequest({
    headers: {
      authorization: `Bearer ${expiredToken}`
    }
  });

export const createRequestWithMalformedHeader = (): Partial<Request> => 
  createMockRequest({
    headers: {
      authorization: 'InvalidFormat token'
    }
  });

export const createRequestWithoutAuth = (): Partial<Request> => 
  createMockRequest();

export const createRequestWithEmptyBearer = (): Partial<Request> => 
  createMockRequest({
    headers: {
      authorization: 'Bearer '
    }
  });

// Mock authenticated request (after middleware processing)
export const createAuthenticatedRequest = (userId?: string): Partial<Request> => 
  createMockRequest({
    user: {
      id: userId || mockUser.id,
      email: mockUser.email
    }
  });

// Mock unauthenticated request
export const createUnauthenticatedRequest = (): Partial<Request> => 
  createMockRequest({
    user: undefined
  });

// Mock request with resource context
export const createRequestWithResourceContext = (
  resourceType: string,
  resourceId: string,
  ownerId?: string
): Partial<Request> => ({
  ...createAuthenticatedRequest(),
  params: { id: resourceId },
  resourceContext: {
    resourceType,
    resourceId,
    ownerId: ownerId || mockUser.id
  }
});

// Mock resources for authorization testing
export const mockImage = {
  id: '456e7890-e89b-12d3-a456-426614174001',
  user_id: mockUser.id,
  file_path: '/path/to/image.jpg',
  metadata: {},
  created_at: new Date(),
  updated_at: new Date()
};

export const mockGarment = {
  id: '789e1234-e89b-12d3-a456-426614174002',
  user_id: mockUser.id,
  original_image_id: mockImage.id,
  file_path: '/path/to/garment.jpg',
  mask_path: '/path/to/mask.jpg',
  metadata: {},
  created_at: new Date(),
  updated_at: new Date()
};

export const mockPolygon = {
  id: '012e3456-e89b-12d3-a456-426614174003',
  original_image_id: mockImage.id,
  polygon_data: '[]',
  metadata: {},
  created_at: new Date(),
  updated_at: new Date()
};

export const mockWardrobe = {
  id: '345e6789-e89b-12d3-a456-426614174004',
  user_id: mockUser.id,
  name: 'Test Wardrobe',
  metadata: {},
  created_at: new Date(),
  updated_at: new Date()
};

// Mock different users for ownership testing
export const otherUser = {
  id: '987e6543-e89b-12d3-a456-426614174005',
  email: 'other@example.com'
};

export const mockResourceOwnedByOtherUser = {
  ...mockImage,
  id: '111e2222-e89b-12d3-a456-426614174006',
  user_id: otherUser.id
};

// Rate limiting mocks
export const rateLimitScenarios = {
  firstRequest: { count: 1, resetTime: Date.now() + 900000 }, // 15 minutes from now
  nearLimit: { count: 99, resetTime: Date.now() + 900000 },
  atLimit: { count: 100, resetTime: Date.now() + 900000 },
  overLimit: { count: 101, resetTime: Date.now() + 900000 },
  expiredWindow: { count: 50, resetTime: Date.now() - 1000 } // 1 second ago
};

// Mock model methods
export const createMockUserModel = () => ({
  findById: jest.fn(),
  findByEmail: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn()
});

export const createMockImageModel = () => ({
  findById: jest.fn(),
  findByUserId: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn()
});

export const createMockGarmentModel = () => ({
  findById: jest.fn(),
  findByUserId: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn()
});

export const createMockPolygonModel = () => ({
  findById: jest.fn(),
  findByImageId: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn()
});

export const createMockWardrobeModel = () => ({
  findById: jest.fn(),
  findByUserId: jest.fn(),
  create: jest.fn(),
  update: jest.fn(),
  delete: jest.fn()
});

// JWT mock setup helpers
export const setupJWTMocks = (jwt: any) => {
  jwt.verify.mockImplementation((token: string) => {
    switch (token) {
      case validToken:
        return mockJwtPayload;
      case expiredToken:
        const expiredError = new Error('jwt expired');
        expiredError.name = 'TokenExpiredError';
        throw expiredError;
      case invalidToken:
        const invalidError = new Error('invalid token');
        invalidError.name = 'JsonWebTokenError';
        throw invalidError;
      default:
        const defaultError = new Error('invalid token');
        defaultError.name = 'JsonWebTokenError';
        throw defaultError;
    }
  });
};

// Config mock
export const mockConfig = {
  jwtSecret: 'test-secret-key-for-testing-only',
  jwtExpiresIn: '1d'
};

// API Error scenarios for testing
export const errorScenarios = {
  missingToken: {
    type: 'authentication',
    message: 'Authentication token required',
    code: 'missing_token'
  },
  invalidToken: {
    type: 'authentication', 
    message: 'Invalid authentication token',
    code: 'invalid_token'
  },
  expiredToken: {
    type: 'authentication',
    message: 'Authentication token has expired', 
    code: 'expired_token'
  },
  userNotFound: {
    type: 'authentication',
    message: 'User not found',
    code: 'user_not_found'
  },
  unauthorizedAccess: {
    type: 'authorization',
    message: 'You do not have permission to access this resource'
  },
  rateLimitExceeded: {
    type: 'rateLimited',
    message: 'Rate limit exceeded'
  }
};