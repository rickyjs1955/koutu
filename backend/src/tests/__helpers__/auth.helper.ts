// /backend/src/__tests__/helpers/auth.helper.ts
import { jest } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { createMockUserModel, 
         createMockImageModel, 
         createMockGarmentModel, 
         createMockPolygonModel, 
         createMockWardrobeModel, 
         mockUser, 
         mockImage, 
         mockGarment, 
         mockPolygon, 
         mockWardrobe, 
         createMockRequest, 
         createMockResponse, 
         createMockNext 
} from '../__mocks__/auth.mock';

// Re-export existing mock functionality
export {
  mockUser,
  mockJwtPayload,
  createMockRequest,
  createMockResponse,
  createMockNext,
  createMockUserModel,
  createMockImageModel,
  createMockGarmentModel,
  createMockPolygonModel,
  createMockWardrobeModel,
  setupJWTMocks,
  mockConfig,
  validToken,
  mockImage,
  mockGarment,
  mockPolygon,
  mockWardrobe
} from '../__mocks__/auth.mock';

// ===== MOCK TESTING HELPERS (for unit tests) =====

/**
 * Helper to set up all authentication-related mocks
 */
export const setupAuthMocks = () => {
  // Mock JWT
  const mockJWT = {
    verify: jest.fn(),
    sign: jest.fn()
  };

  // Mock models
  const mockUserModel = createMockUserModel();
  const mockImageModel = createMockImageModel();
  const mockGarmentModel = createMockGarmentModel();
  const mockPolygonModel = createMockPolygonModel();
  const mockWardrobeModel = createMockWardrobeModel();

  // Set default successful responses with proper type casting
  (mockUserModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockUser);
  (mockImageModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockImage);
  (mockGarmentModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockGarment);
  (mockPolygonModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockPolygon);
  (mockWardrobeModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockWardrobe);

  return {
    mockJWT,
    mockUserModel,
    mockImageModel,
    mockGarmentModel,
    mockPolygonModel,
    mockWardrobeModel
  };
};

/**
 * Helper to create test scenario for middleware testing
 */
export interface TestScenario {
  name: string;
  request: Partial<Request>;
  response: Partial<Response>;
  next: NextFunction;
  expectedError?: any;
  expectedUser?: any;
  shouldCallNext?: boolean;
}

export const createTestScenario = (
  name: string,
  requestOverrides: Partial<Request> = {},
  expectations: {
    expectedError?: any;
    expectedUser?: any;
    shouldCallNext?: boolean;
  } = {}
): TestScenario => ({
  name,
  request: createMockRequest(requestOverrides),
  response: createMockResponse(),
  next: createMockNext(),
  ...expectations,
  shouldCallNext: expectations.shouldCallNext !== false // default to true
});

/**
 * Helper to run middleware and assert common behaviors
 */
export const runMiddlewareTest = async (
  middleware: (req: Request, res: Response, next: NextFunction) => Promise<void> | void,
  scenario: TestScenario
) => {
  await middleware(
    scenario.request as Request,
    scenario.response as Response,
    scenario.next
  );

  if (scenario.expectedError) {
    expect(scenario.next).toHaveBeenCalledWith(
      expect.objectContaining(scenario.expectedError)
    );
  } else if (scenario.shouldCallNext) {
    expect(scenario.next).toHaveBeenCalledWith();
  }

  if (scenario.expectedUser) {
    expect(scenario.request.user).toEqual(scenario.expectedUser);
  }
};

/**
 * Helper to test authentication scenarios
 */
export const testAuthenticationScenarios = (
  middleware: (req: Request, res: Response, next: NextFunction) => Promise<void> | void,
  scenarios: TestScenario[]
) => {
  scenarios.forEach(scenario => {
    it(scenario.name, async () => {
      await runMiddlewareTest(middleware, scenario);
    });
  });
};

/**
 * Helper to create authorization test scenarios for different resource types
 */
export const createAuthorizationScenarios = (
  resourceType: 'image' | 'garment' | 'polygon' | 'wardrobe',
  validResourceId: string = '123e4567-e89b-12d3-a456-426614174000'
): TestScenario[] => [
  createTestScenario(
    'should allow access to owned resource',
    {
      user: { id: mockUser.id, email: mockUser.email },
      params: { id: validResourceId }
    },
    {
      shouldCallNext: true,
      expectedUser: { id: mockUser.id, email: mockUser.email }
    }
  ),
  createTestScenario(
    'should reject access without authentication',
    {
      params: { id: validResourceId }
    },
    {
      expectedError: {
        message: 'Authentication required for resource access'
      },
      shouldCallNext: false
    }
  ),
  createTestScenario(
    'should reject access with invalid resource ID format',
    {
      user: { id: mockUser.id, email: mockUser.email },
      params: { id: 'invalid-uuid' }
    },
    {
      expectedError: {
        message: `Invalid ${resourceType} ID format`
      },
      shouldCallNext: false
    }
  ),
  createTestScenario(
    'should reject access without resource ID',
    {
      user: { id: mockUser.id, email: mockUser.email },
      params: {}
    },
    {
      expectedError: {
        message: 'Missing id parameter'
      },
      shouldCallNext: false
    }
  )
];

/**
 * Helper to setup model mocks for authorization testing
 */
export const setupAuthorizationMocks = (
  models: ReturnType<typeof setupAuthMocks>,
  resourceType: 'image' | 'garment' | 'polygon' | 'wardrobe',
  scenario: 'success' | 'not_found' | 'unauthorized' | 'error'
) => {
  const { mockUserModel, mockImageModel, mockGarmentModel, mockPolygonModel, mockWardrobeModel } = models;

  // Reset all mocks with proper type casting
  [mockUserModel, mockImageModel, mockGarmentModel, mockPolygonModel, mockWardrobeModel].forEach(model => {
    Object.values(model).forEach(method => {
      if (jest.isMockFunction(method)) {
        (method as jest.MockedFunction<any>).mockReset();
      }
    });
  });

  // Set up user model to always return the mock user
  (mockUserModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockUser);

  switch (scenario) {
    case 'success':
      switch (resourceType) {
        case 'image':
          (mockImageModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockImage);
          break;
        case 'garment':
          (mockGarmentModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockGarment);
          break;
        case 'polygon':
          (mockPolygonModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockPolygon);
          (mockImageModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockImage);
          break;
        case 'wardrobe':
          (mockWardrobeModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockWardrobe);
          break;
      }
      break;

    case 'not_found':
      switch (resourceType) {
        case 'image':
          (mockImageModel.findById as jest.MockedFunction<any>).mockResolvedValue(null);
          break;
        case 'garment':
          (mockGarmentModel.findById as jest.MockedFunction<any>).mockResolvedValue(null);
          break;
        case 'polygon':
          (mockPolygonModel.findById as jest.MockedFunction<any>).mockResolvedValue(null);
          break;
        case 'wardrobe':
          (mockWardrobeModel.findById as jest.MockedFunction<any>).mockResolvedValue(null);
          break;
      }
      break;

    case 'unauthorized':
      const unauthorizedResource = { ...mockImage, user_id: 'other-user-id' };
      switch (resourceType) {
        case 'image':
          (mockImageModel.findById as jest.MockedFunction<any>).mockResolvedValue(unauthorizedResource);
          break;
        case 'garment':
          (mockGarmentModel.findById as jest.MockedFunction<any>).mockResolvedValue({ ...mockGarment, user_id: 'other-user-id' });
          break;
        case 'polygon':
          (mockPolygonModel.findById as jest.MockedFunction<any>).mockResolvedValue(mockPolygon);
          (mockImageModel.findById as jest.MockedFunction<any>).mockResolvedValue(unauthorizedResource);
          break;
        case 'wardrobe':
          (mockWardrobeModel.findById as jest.MockedFunction<any>).mockResolvedValue({ ...mockWardrobe, user_id: 'other-user-id' });
          break;
      }
      break;

    case 'error':
      const error = new Error('Database error');
      switch (resourceType) {
        case 'image':
          (mockImageModel.findById as jest.MockedFunction<any>).mockRejectedValue(error);
          break;
        case 'garment':
          (mockGarmentModel.findById as jest.MockedFunction<any>).mockRejectedValue(error);
          break;
        case 'polygon':
          (mockPolygonModel.findById as jest.MockedFunction<any>).mockRejectedValue(error);
          break;
        case 'wardrobe':
          (mockWardrobeModel.findById as jest.MockedFunction<any>).mockRejectedValue(error);
          break;
      }
      break;
  }
};

/**
 * Helper to create rate limiting test scenarios
 */
export const createRateLimitScenarios = (): TestScenario[] => [
  createTestScenario(
    'should allow request when under rate limit',
    {
      user: { id: mockUser.id, email: mockUser.email }
    },
    {
      shouldCallNext: true
    }
  ),
  createTestScenario(
    'should skip rate limiting for unauthenticated requests',
    {},
    {
      shouldCallNext: true
    }
  ),
  createTestScenario(
    'should reject request when rate limit exceeded',
    {
      user: { id: mockUser.id, email: mockUser.email }
    },
    {
      expectedError: {
        message: expect.stringContaining('Rate limit exceeded')
      },
      shouldCallNext: false
    }
  )
];

// ===== INTEGRATION TESTING HELPERS (for integration tests) =====

/**
 * Clean up auth-related test data
 */
export async function cleanupAuthTestData(): Promise<void> {
  try {
    // Clean up in the correct order to handle foreign key constraints
    await TestDatabaseConnection.query('DELETE FROM user_oauth_providers WHERE created_at > NOW() - INTERVAL \'1 hour\'');
    await TestDatabaseConnection.query('DELETE FROM users WHERE created_at > NOW() - INTERVAL \'1 hour\'');
  } catch (error) {
    console.warn('Failed to clean up auth test data:', error);
  }
}

/**
 * Generate unique email for testing
 */
export function generateTestEmail(prefix: string = 'test'): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(7);
  return `${prefix}-${timestamp}-${random}@example.com`;
}

/**
 * Generate test user data
 */
export function generateTestUser(emailPrefix?: string) {
  return {
    email: generateTestEmail(emailPrefix),
    password: 'TestPass123!'
  };
}

/**
 * Wait for a specified amount of time (for testing async operations)
 */
export function wait(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Create multiple unique test users
 */
export function generateMultipleTestUsers(count: number, prefix: string = 'user'): Array<{email: string, password: string}> {
  return Array(count).fill(null).map((_, index) => ({
    email: generateTestEmail(`${prefix}${index}`),
    password: 'TestPass123!'
  }));
}

// ===== UTILITY HELPERS (shared by all test types) =====

/**
 * Helper to validate UUID format
 */
export const isValidUUID = (uuid: string): boolean => {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
};

/**
 * Helper to generate valid test UUIDs
 */
export const generateTestUUID = (): string => {
  return '123e4567-e89b-12d3-a456-426614174000';
};

/**
 * Helper to generate invalid test UUIDs
 */
export const generateInvalidUUID = (): string => {
  return 'invalid-uuid-format';
};

/**
 * Helper to create mock API errors for testing
 */
export const createMockApiError = (
  type: string,
  message: string,
  code?: string,
  statusCode: number = 400
) => ({
  name: 'ApiError',
  message,
  statusCode,
  type,
  code,
  isOperational: true
});

/**
 * Helper to assert mock calls with better type safety
 */
export const expectMockToBeCalled = <T extends (...args: any[]) => any>(
  mockFn: jest.MockedFunction<T>,
  times?: number
) => {
  if (times !== undefined) {
    expect(mockFn).toHaveBeenCalledTimes(times);
  } else {
    expect(mockFn).toHaveBeenCalled();
  }
};

/**
 * Helper to assert mock calls with specific arguments
 */
export const expectMockToBeCalledWith = <T extends (...args: any[]) => any>(
  mockFn: jest.MockedFunction<T>,
  ...expectedArgs: Parameters<T>
) => {
  expect(mockFn).toHaveBeenCalledWith(...expectedArgs);
};

/**
 * Helper to wait for async operations in tests
 */
export const waitForAsync = () => new Promise(resolve => setImmediate(resolve));

/**
 * Helper to cleanup after tests
 */
export const cleanupTest = () => {
  jest.clearAllMocks();
  jest.restoreAllMocks();
  if (jest.isMockFunction(setTimeout)) {
    jest.useRealTimers();
  }
};