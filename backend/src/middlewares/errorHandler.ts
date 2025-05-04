// /backend/src/middlewares/errorHandler.ts
import { Request, Response, NextFunction } from 'express';

interface AppError extends Error {
  statusCode?: number;
  code?: string;
}

export const errorHandler = (
  err: AppError,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';
  const code = err.code || 'INTERNAL_ERROR';
  
  console.error(`Error [${code}]: ${message}`);
  
  res.status(statusCode).json({
    status: 'error',
    code,
    message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
};