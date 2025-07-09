// src/config/__tests__/__helpers__/ratelimit.helper.ts
import { RequestHandler } from 'express';

/**
 * Helper to create rate limiter with proper types
 * This avoids type conflicts between express-rate-limit versions
 */
export async function createRateLimiter(options: {
  windowMs: number;
  limit: number;
  message?: any;
  standardHeaders?: boolean;
  legacyHeaders?: boolean;
}): Promise<RequestHandler> {
  const { rateLimit } = await import('express-rate-limit');
  
  return rateLimit(options) as unknown as RequestHandler;
}

/**
 * Simple in-memory rate limiter for testing
 * Use this if express-rate-limit types are problematic
 */
export function createTestRateLimiter(options: {
  windowMs: number;
  limit: number;
  message?: any;
}): RequestHandler {
  const requests = new Map<string, number[]>();
  
  return (req, res, next) => {
    const key = req.ip || 'unknown';
    const now = Date.now();
    
    // Clean old requests
    const userRequests = requests.get(key) || [];
    const validRequests = userRequests.filter(time => now - time < options.windowMs);
    
    if (validRequests.length >= options.limit) {
      res.status(429).json(options.message || { error: 'Too many requests' });
      return;
    }
    
    validRequests.push(now);
    requests.set(key, validRequests);
    
    // Add rate limit headers
    res.set({
      'RateLimit-Limit': options.limit.toString(),
      'RateLimit-Remaining': Math.max(0, options.limit - validRequests.length).toString(),
      'RateLimit-Reset': new Date(now + options.windowMs).toISOString()
    });
    
    next();
  };
}