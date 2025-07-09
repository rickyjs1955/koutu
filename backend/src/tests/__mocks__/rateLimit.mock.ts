// backend/src/middlewares/__mocks__/rateLimitMiddleware.ts
import { Request, Response, NextFunction } from 'express';

// Mock rate limiting middleware for tests - just passes through
const mockMiddleware = (req: Request, res: Response, next: NextFunction): void => {
  next();
};

export const healthRateLimitMiddleware = mockMiddleware;
export const diagnosticsRateLimitMiddleware = mockMiddleware;
export const generalRateLimitMiddleware = mockMiddleware;

export const cleanupRateLimiters = (): void => {
  // No-op for tests
};

export const healthRateLimit = {
  middleware: () => mockMiddleware,
  destroy: () => {},
  reset: () => {}
};

export const diagnosticsRateLimit = {
  middleware: () => mockMiddleware,
  destroy: () => {},
  reset: () => {}
};

export const generalRateLimit = {
  middleware: () => mockMiddleware,
  destroy: () => {},
  reset: () => {}
};