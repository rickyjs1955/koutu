// /backend/src/middlewares/errorHandler.ts
import { Request, Response, NextFunction } from 'express';

export interface AppError extends Error {
  statusCode?: number;
  code?: string;
}

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
  const statusCode = appErr.statusCode || 500;
  const message = typeof appErr.message === 'string' ? appErr.message : 'Internal Server Error';
  const code = appErr.code || 'INTERNAL_ERROR';
  
  console.error(`Error [${code}]: ${message}`);
  
  res.status(statusCode).json({
    status: 'error',
    code,
    message,
    stack: process.env.NODE_ENV === 'development' ? appErr.stack : undefined
  });
};