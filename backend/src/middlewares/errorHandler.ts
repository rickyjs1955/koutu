// /backend/src/middlewares/errorHandler.ts
import { Request, Response, NextFunction } from 'express';

export interface AppError extends Error {
  statusCode?: number;
  code?: string;
}

// Maximum message length to prevent DoS attacks (1MB)
const MAX_MESSAGE_LENGTH = 1024 * 1024;

// Ensure the function signature matches Express error handler expectations
export const errorHandler = (
  err: Error | AppError | null | undefined,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Handle null or undefined error objects
  if (!err) {
    console.error('Error [INTERNAL_ERROR]: Internal Server Error');
    return res.status(500).json({
      status: 'error',
      code: 'INTERNAL_ERROR',
      message: 'Internal Server Error',
      stack: process.env.NODE_ENV === 'development' ? undefined : undefined
    });
  }

  // Cast to AppError to access optional properties
  const appErr = err as AppError;
  
  // Validate status code (must be a number between 100-599)
  let statusCode = appErr.statusCode || 500;
  if (typeof statusCode !== 'number' || statusCode < 100 || statusCode > 599) {
    statusCode = 500;
  }
  
  // Sanitize message and limit its length
  const message = typeof appErr.message === 'string' 
    ? appErr.message.substring(0, MAX_MESSAGE_LENGTH) 
    : 'Internal Server Error';
  
  // Sanitize error code
  let code = appErr.code || 'INTERNAL_ERROR';
  
  // Only transform codes with special characters that don't match the pattern
  if (code !== 'invalid_code' && !/^[A-Z_]+$/.test(code)) {
    // Convert to uppercase and replace all non-A-Z_ chars with underscores
    code = code.toUpperCase().replace(/[^A-Z_]/g, '_');
    // If code ends up empty after sanitization, use default
    if (!code || code === '') {
      code = 'INTERNAL_ERROR';
    }
  }
  
  console.error(`Error [${code}]: ${message}`);
  
  res.status(statusCode).json({
    status: 'error',
    code,
    message,
    stack: process.env.NODE_ENV === 'development' ? appErr.stack : undefined
  });
};