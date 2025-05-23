// koutu/backend/src/tests/__helpers__/garmentController.helper.ts

import { Request, Response, NextFunction } from 'express';
import { ApiError } from '../../utils/ApiError';
import { garmentModel } from '../../models/garmentModel';
import { imageModel } from '../../models/imageModel';
import { labelingService } from '../../services/labelingService';
import { garmentService } from '../../services/garmentService';
import { sanitization } from '../../utils/sanitize';

// Setup mocks (now mostly handled in the test file before imports)
export const setupMocks = () => {
  // Additional setup if needed
  // Most mocking is now done in the test file before imports
};

// Helper to assert API error was called correctly
export const assertApiError = (
  next: NextFunction,
  expectedError: ApiError,
  callIndex: number = 0
) => {
  expect(next).toHaveBeenCalled();
  const actualError = (next as jest.Mock).mock.calls[callIndex][0];
  expect(actualError).toBeInstanceOf(ApiError);
  expect(actualError.statusCode).toBe(expectedError.statusCode);
  expect(actualError.code).toBe(expectedError.code);
  expect(actualError.message).toBe(expectedError.message);
};

// Helper to assert successful response
export const assertSuccessResponse = (
  res: Response,
  expectedStatus: number,
  expectedData: any
) => {
  expect(res.status).toHaveBeenCalledWith(expectedStatus);
  expect(res.json).toHaveBeenCalledWith({
    status: 'success',
    ...expectedData
  });
};

// Helper to reset all mocks
export const resetAllMocks = () => {
  jest.clearAllMocks();
};

// Helper to setup authenticated request
export const setupAuthenticatedRequest = (req: Request, userId: string = 'test-user-id') => {
  req.user = { id: userId, email: `${userId}@example.com` };
};

// Helper to setup unauthenticated request
export const setupUnauthenticatedRequest = (req: Request) => {
  delete req.user;
};

// Helper to verify service calls
export const verifyServiceCalls = {
  createGarment: (expectedParams: any) => {
    expect(garmentService.createGarment).toHaveBeenCalledWith(expectedParams);
  },
  
  getGarments: (expectedParams: any) => {
    expect(garmentService.getGarments).toHaveBeenCalledWith(expectedParams);
  },
  
  getGarment: (expectedParams: any) => {
    expect(garmentService.getGarment).toHaveBeenCalledWith(expectedParams);
  },
  
  updateGarmentMetadata: (expectedParams: any) => {
    expect(garmentService.updateGarmentMetadata).toHaveBeenCalledWith(expectedParams);
  },
  
  deleteGarment: (expectedParams: any) => {
    expect(garmentService.deleteGarment).toHaveBeenCalledWith(expectedParams);
  }
};

// Helper to verify sanitization calls
export const verifySanitizationCalls = {
  sanitizeGarmentForResponse: (garment: any) => {
    expect(sanitization.sanitizeGarmentForResponse).toHaveBeenCalledWith(garment);
  },
  
  sanitizeGarmentMetadata: (metadata: any) => {
    expect(sanitization.sanitizeGarmentMetadata).toHaveBeenCalledWith(metadata);
  }
};

// Helper to simulate service errors
export const simulateServiceError = (serviceName: string, methodName: string, error: Error) => {
  const service = serviceName === 'garmentService' ? garmentService : 
                  serviceName === 'imageModel' ? imageModel :
                  serviceName === 'garmentModel' ? garmentModel :
                  labelingService;
  
  (service[methodName as keyof typeof service] as jest.Mock).mockRejectedValueOnce(error);
};

// Helper to simulate service success
export const simulateServiceSuccess = (serviceName: string, methodName: string, response: any) => {
  const service = serviceName === 'garmentService' ? garmentService : 
                  serviceName === 'imageModel' ? imageModel :
                  serviceName === 'garmentModel' ? garmentModel :
                  labelingService;
  
  (service[methodName as keyof typeof service] as jest.Mock).mockResolvedValueOnce(response);
};

// Helper to create request with query params
export const createRequestWithQuery = (query: any): Request => {
  return {
    query,
    user: { id: 'test-user-id', email: 'test@example.com' }
  } as Request;
};

// Helper to create request with params
export const createRequestWithParams = (params: any): Request => {
  return {
    params,
    user: { id: 'test-user-id', email: 'test@example.com' }
  } as Request;
};

// Helper to create request with body
export const createRequestWithBody = (body: any): Request => {
  return {
    body,
    user: { id: 'test-user-id', email: 'test@example.com' }
  } as Request;
};

// Helper to verify error handling
export const verifyErrorHandling = async (
  controllerMethod: Function,
  req: Request,
  res: Response,
  next: NextFunction,
  expectedErrorMessage: string
) => {
  await controllerMethod(req, res, next);
  
  expect(next).toHaveBeenCalled();
  const error = (next as jest.Mock).mock.calls[0][0];
  expect(error).toBeInstanceOf(ApiError);
  expect(error.message).toBe(expectedErrorMessage);
};