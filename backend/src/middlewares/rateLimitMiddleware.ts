// backend/src/middlewares/rateLimitMiddleware.ts
import { Request, Response, NextFunction } from 'express';

// Type declaration for jest global
declare const jest: any;

interface RateLimitStore {
  [key: string]: {
    count: number;
    resetTime: number;
  };
}

export class RateLimiter {
  private store: RateLimitStore = {};
  private cleanupInterval?: NodeJS.Timeout;

  constructor(
    private windowMs: number = 15 * 60 * 1000, // 15 minutes
    private maxRequests: number = 100
  ) {
    // Only create cleanup interval in non-test environments
    if (process.env.NODE_ENV !== 'test' && typeof jest === 'undefined') {
      this.cleanupInterval = setInterval(() => {
        this.cleanup();
      }, 5 * 60 * 1000);
    }
  }

  private cleanup(): void {
    const now = Date.now();
    Object.keys(this.store).forEach(key => {
      if (this.store[key].resetTime < now) {
        delete this.store[key];
      }
    });
  }

  private getKey(req: Request): string {
    // Use IP address as the key
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    return ip;
  }

  public middleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
      // Skip rate limiting in test environment or if jest is detected
      if (process.env.NODE_ENV === 'test' || typeof jest !== 'undefined') {
        return next();
      }

      const key = this.getKey(req);
      const now = Date.now();

      // Initialize or reset if window expired
      if (!this.store[key] || this.store[key].resetTime < now) {
        this.store[key] = {
          count: 1,
          resetTime: now + this.windowMs
        };
        
        // Add rate limit headers
        res.set({
          'X-RateLimit-Limit': this.maxRequests.toString(),
          'X-RateLimit-Remaining': (this.maxRequests - 1).toString(),
          'X-RateLimit-Reset': Math.ceil(this.store[key].resetTime / 1000).toString()
        });
        
        return next();
      }

      // Increment count
      this.store[key].count++;

      // Check if limit exceeded
      if (this.store[key].count > this.maxRequests) {
        res.status(429).json({
          success: false,
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Too many requests. Please try again later.',
            retryAfter: Math.ceil((this.store[key].resetTime - now) / 1000)
          }
        });
        return;
      }

      // Add rate limit headers
      res.set({
        'X-RateLimit-Limit': this.maxRequests.toString(),
        'X-RateLimit-Remaining': (this.maxRequests - this.store[key].count).toString(),
        'X-RateLimit-Reset': Math.ceil(this.store[key].resetTime / 1000).toString()
      });

      next();
    };
  }

  public destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = undefined;
    }
  }

  public reset(): void {
    this.store = {};
  }

  // Getter methods for testing
  public getStore(): RateLimitStore {
    return { ...this.store };
  }

  public getWindowMs(): number {
    return this.windowMs;
  }

  public getMaxRequests(): number {
    return this.maxRequests;
  }
}

// Only create rate limiters if not in test environment
let healthRateLimit: RateLimiter;
let diagnosticsRateLimit: RateLimiter;
let generalRateLimit: RateLimiter;

if (process.env.NODE_ENV !== 'test' && typeof jest === 'undefined') {
  healthRateLimit = new RateLimiter(15 * 60 * 1000, 100); // 100 requests per 15 minutes
  diagnosticsRateLimit = new RateLimiter(60 * 60 * 1000, 10); // 10 requests per hour
  generalRateLimit = new RateLimiter(15 * 60 * 1000, 200); // 200 requests per 15 minutes
} else {
  // Create mock rate limiters for testing
  const mockRateLimiter = new RateLimiter(15 * 60 * 1000, 1000); // High limit for tests
  healthRateLimit = mockRateLimiter;
  diagnosticsRateLimit = mockRateLimiter;
  generalRateLimit = mockRateLimiter;
}

// Middleware functions - these will be no-ops in test environment
export const healthRateLimitMiddleware = healthRateLimit.middleware();
export const diagnosticsRateLimitMiddleware = diagnosticsRateLimit.middleware();
export const generalRateLimitMiddleware = generalRateLimit.middleware();

// Cleanup function for tests
export const cleanupRateLimiters = (): void => {
  try {
    if (healthRateLimit && typeof healthRateLimit.destroy === 'function') {
      healthRateLimit.destroy();
    }
    if (diagnosticsRateLimit && typeof diagnosticsRateLimit.destroy === 'function') {
      diagnosticsRateLimit.destroy();
    }
    if (generalRateLimit && typeof generalRateLimit.destroy === 'function') {
      generalRateLimit.destroy();
    }
  } catch (error) {
    // Ignore cleanup errors in tests
  }
};

export { healthRateLimit, diagnosticsRateLimit, generalRateLimit };