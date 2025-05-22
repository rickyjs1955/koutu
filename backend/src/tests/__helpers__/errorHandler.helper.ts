import { AppError } from '../../middlewares/errorHandler';
import { Request, Response, NextFunction } from 'express';

/**
 * Creates a standard error object for testing purposes.
 * 
 * @param message - The error message.
 * @param statusCode - The HTTP status code (default is 500).
 * @param code - An optional error code.
 * @returns An AppError object.
 */
export const createError = (message: string, statusCode: number = 500, code?: string): AppError => {
  const error: AppError = new Error(message) as AppError;
  error.statusCode = statusCode;
  error.code = code;
  return error;
};

/**
 * Formats an error response for testing.
 * 
 * @param error - The error object to format.
 * @returns A formatted error response object.
 */
export const formatErrorResponse = (error: AppError) => {
  return {
    status: 'error',
    code: error.code || 'INTERNAL_ERROR',
    message: error.message,
    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
  };
};

export const mockRequest = {} as Request;

export const mockResponse = () => {
  const res = {} as Response;
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
};

export const mockNext = jest.fn() as NextFunction;