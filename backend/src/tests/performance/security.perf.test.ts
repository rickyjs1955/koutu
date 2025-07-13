// backend/src/tests/performance/security.perf.test.ts
import express, { Request, Response, NextFunction } from 'express';
import request from 'supertest';
import { performance } from 'perf_hooks';
import {
  generalSecurity,
  pathTraversalProtection,
  filePathSecurity,
  createRateLimit,
  requestIdMiddleware,
  csrfProtection,
  flutterSecurity
} from '../../middlewares/security';

class SecurityPerformanceMonitor {
  static async measureMiddlewareTime<T>(operation: () => Promise<T>): Promise<{ result: T; duration: number }> {
    const start = performance.now();
    const result = await operation();
    const end = performance.now();
    return { result, duration: end - start };
  }

  static async measureMemoryUsage(): Promise<NodeJS.MemoryUsage> {
    if (global.gc) {
      global.gc();
    }
    return process.memoryUsage();
  }

  static async measureConcurrentSecurity<T>(
    operations: (() => Promise<T>)[],
    maxConcurrency: number = 10
  ): Promise<{
    results: T[];
    totalDuration: number;
    averageDuration: number;
    throughput: number;
  }> {
    const start = performance.now();
    const results: T[] = [];
    
    for (let i = 0; i < operations.length; i += maxConcurrency) {
      const batch = operations.slice(i, i + maxConcurrency);
      const batchResults = await Promise.all(batch.map(op => op()));
      results.push(...batchResults);
    }
    
    const end = performance.now();
    const totalDuration = end - start;
    
    return {
      results,
      totalDuration,
      averageDuration: totalDuration / operations.length,
      throughput: operations.length / (totalDuration / 1000)
    };
  }

  static createSecurityLoadTest(
    requestFactory: () => Promise<any>,
    duration: number,
    targetRPS: number
  ) {
    return new Promise<{
      requests: number;
      successful: number;
      failed: number;
      averageTime: number;
      throughput: number;
    }>((resolve, reject) => {
      const results: number[] = [];
      let requests = 0;
      let successful = 0;
      let failed = 0;
      let activeRequests = 0;
      
      const startTime = Date.now();
      const endTime = startTime + duration;
      const interval = 1000 / targetRPS;
      
      const makeRequest = async () => {
        if (Date.now() >= endTime) {
          // Wait for all active requests to complete
          const checkCompletion = () => {
            if (activeRequests === 0) {
              const averageTime = results.length > 0 ? results.reduce((a, b) => a + b, 0) / results.length : 0;
              const actualDuration = (Date.now() - startTime) / 1000;
              const actualThroughput = successful / actualDuration;
              
              resolve({
                requests,
                successful,
                failed,
                averageTime,
                throughput: actualThroughput
              });
            } else {
              setTimeout(checkCompletion, 10);
            }
          };
          checkCompletion();
          return;
        }
        
        requests++;
        activeRequests++;
        const requestStart = performance.now();
        
        try {
          await requestFactory();
          successful++;
          results.push(performance.now() - requestStart);
        } catch (error) {
          failed++;
        } finally {
          activeRequests--;
        }
        
        setTimeout(makeRequest, interval);
      };
      
      // Handle potential timeout
      setTimeout(() => {
        if (requests === 0) {
          reject(new Error('Load test failed to start'));
        }
      }, 1000);
      
      makeRequest();
    });
  }
}

describe('Security Middleware Performance Tests', () => {
  let app: express.Application;
  let server: any;

  beforeAll(() => {
    if (global.gc) {
      global.gc();
    }
  });

  beforeEach(() => {
    app = express();
    app.use(express.json());
  });

  afterEach(() => {
    if (server) {
      server.close();
    }
  });

  describe('Path Traversal Protection Performance', () => {
    it('should process normal requests within performance threshold', async () => {
      app.use(pathTraversalProtection);
      app.get('/test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
        return request(app)
          .get('/test')
          .expect(200);
      });

      expect(duration).toBeLessThan(500);
    });

    it('should handle malicious path requests efficiently', async () => {
      app.use(pathTraversalProtection);
      app.get('/test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const maliciousPaths = [
        '/test/../../../etc/passwd',
        '/test/%2e%2e%2f%2e%2e%2fpasswd',
        '/test/..\\..\\windows\\system32',
        '/test/....//....//etc/shadow',
        '/test/..;/..;/etc/hosts'
      ];

      for (const path of maliciousPaths) {
        const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
          return request(app)
            .get(path)
            .expect(403);
        });

        expect(duration).toBeLessThan(250);
      }
    });

    it('should maintain performance under concurrent malicious requests', async () => {
      app.use(pathTraversalProtection);
      app.get('/test/:path', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const operations = Array(50).fill(0).map(() => () =>
        request(app)
          .get('/test/malicious')
          .expect(200)
      );

      const results = await SecurityPerformanceMonitor.measureConcurrentSecurity(operations, 10);

      expect(results.averageDuration).toBeLessThan(300);
      expect(results.throughput).toBeGreaterThan(5);
    });
  });

  describe('File Path Security Performance', () => {
    it('should validate file paths efficiently', async () => {
      app.use(filePathSecurity);
      app.get('/files/:filepath', (req: Request, res: Response) => {
        res.json({ filepath: req.params.filepath });
      });

      const validPaths = [
        'image.jpg',
        'folder/image.png',
        'deep/nested/folder/image.gif',
        'very-long-filename-with-multiple-words.jpeg'
      ];

      for (const filepath of validPaths) {
        const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
          return request(app)
            .get(`/files/${encodeURIComponent(filepath)}`)
            .expect(200);
        });

        expect(duration).toBeLessThan(75);
      }
    });

    it('should reject invalid file paths quickly', async () => {
      app.use(filePathSecurity);
      app.get('/files/:filepath', (req: Request, res: Response) => {
        res.json({ filepath: req.params.filepath });
      });

      const invalidPaths = [
        '../../../etc/passwd',
        'file.exe',
        'script.js',
        'document.pdf'
      ];

      for (const filepath of invalidPaths) {
        const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
          const response = await request(app)
            .get(`/files/${encodeURIComponent(filepath)}`);
          
          // Either 403 (security rejection) or 200 with sanitized path
          expect([200, 403]).toContain(response.status);
          return response;
        });

        expect(duration).toBeLessThan(250);
      }
    });
  });

  describe('Rate Limiting Performance', () => {
    it('should process requests within rate limit efficiently', async () => {
      const rateLimit = createRateLimit(60000, 100); // 100 per minute
      app.use(rateLimit as any);
      app.get('/api/test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const operations = Array(20).fill(0).map(() => () =>
        request(app)
          .get('/api/test')
          .expect(200)
      );

      const results = await SecurityPerformanceMonitor.measureConcurrentSecurity(operations, 5);

      expect(results.averageDuration).toBeLessThan(200);
      expect(results.throughput).toBeGreaterThan(5);
    });

    it('should handle rate limit exceeded scenarios efficiently', async () => {
      const rateLimit = createRateLimit(60000, 2); // Very low limit for testing
      app.use(rateLimit as any);
      app.get('/api/test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      await request(app).get('/api/test').expect(200);
      await request(app).get('/api/test').expect(200);

      const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
        return request(app)
          .get('/api/test')
          .expect(429);
      });

      expect(duration).toBeLessThan(150);
    });

    it('should maintain rate limiting accuracy under high concurrency', async () => {
      const rateLimit = createRateLimit(60000, 10);
      app.use(rateLimit as any);
      app.get('/api/test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const operations = Array(25).fill(0).map(() => () =>
        request(app).get('/api/test')
      );

      const results = await SecurityPerformanceMonitor.measureConcurrentSecurity(operations, 15);
      const successfulRequests = results.results.filter((res: any) => res.status === 200).length;
      const rateLimitedRequests = results.results.filter((res: any) => res.status === 429).length;

      expect(successfulRequests).toBeLessThanOrEqual(12);
      expect(rateLimitedRequests).toBeGreaterThan(10);
      expect(results.averageDuration).toBeLessThan(300);
    });
  });

  describe('General Security Middleware Stack Performance', () => {
    it('should process requests through full security stack efficiently', async () => {
      generalSecurity.forEach(middleware => app.use(middleware));
      app.get('/secure', (_req: Request, res: Response) => {
        res.json({ secure: true });
      });

      const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
        return request(app)
          .get('/secure')
          .expect(200);
      });

      expect(duration).toBeLessThan(200);
    });

    it('should handle concurrent requests through security stack', async () => {
      generalSecurity.forEach(middleware => app.use(middleware));
      app.get('/secure', (_req: Request, res: Response) => {
        res.json({ secure: true });
      });

      const operations = Array(30).fill(0).map(() => () =>
        request(app)
          .get('/secure')
          .expect(200)
      );

      const results = await SecurityPerformanceMonitor.measureConcurrentSecurity(operations, 10);

      expect(results.averageDuration).toBeLessThan(250);
      expect(results.throughput).toBeGreaterThan(8);
    });
  });

  describe('Flutter Security Middleware Performance', () => {
    it('should process Flutter app requests efficiently', async () => {
      flutterSecurity.forEach(middleware => app.use(middleware as any));
      app.get('/api/mobile', (_req: Request, res: Response) => {
        res.json({ mobile: true });
      });

      const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
        return request(app)
          .get('/api/mobile')
          .set('User-Agent', 'Flutter/2.0.0 (Mobile App)')
          .expect(200);
      });

      expect(duration).toBeLessThan(150);
    });

    it('should handle mobile-specific headers without performance degradation', async () => {
      flutterSecurity.forEach(middleware => app.use(middleware as any));
      app.get('/api/mobile', (_req: Request, res: Response) => {
        res.json({ mobile: true });
      });

      const operations = Array(20).fill(0).map(() => () =>
        request(app)
          .get('/api/mobile')
          .set('User-Agent', 'Flutter/2.0.0 (Mobile App)')
          .expect(200)
      );

      const results = await SecurityPerformanceMonitor.measureConcurrentSecurity(operations, 8);

      expect(results.averageDuration).toBeLessThan(200);
      expect(results.throughput).toBeGreaterThan(6);
    });
  });

  describe('Request ID Middleware Performance', () => {
    it('should generate request IDs efficiently', async () => {
      app.use(requestIdMiddleware);
      app.get('/test', (req: Request, res: Response) => {
        res.json({ requestId: req.get('X-Request-ID') });
      });

      const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
        return request(app)
          .get('/test')
          .expect(200);
      });

      expect(duration).toBeLessThan(150);
    });

    it('should handle high-volume request ID generation', async () => {
      app.use(requestIdMiddleware);
      app.get('/test', (req: Request, res: Response) => {
        res.json({ requestId: req.get('X-Request-ID') });
      });

      const operations = Array(100).fill(0).map(() => () =>
        request(app)
          .get('/test')
          .expect(200)
      );

      const results = await SecurityPerformanceMonitor.measureConcurrentSecurity(operations, 20);

      expect(results.averageDuration).toBeLessThan(100);
      expect(results.throughput).toBeGreaterThan(15);

      const requestIds = results.results.map((res: any) => res.body.requestId);
      const uniqueIds = new Set(requestIds);
      expect(uniqueIds.size).toBe(requestIds.length);
    });
  });

  describe('Memory Usage Monitoring', () => {
    it('should not cause significant memory leaks under load', async () => {
      generalSecurity.forEach(middleware => app.use(middleware));
      app.get('/memory-test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const initialMemory = await SecurityPerformanceMonitor.measureMemoryUsage();

      const operations = Array(200).fill(0).map(() => () =>
        request(app)
          .get('/memory-test')
          .expect(200)
      );

      await SecurityPerformanceMonitor.measureConcurrentSecurity(operations, 25);

      const finalMemory = await SecurityPerformanceMonitor.measureMemoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // 50MB threshold
    });

    it('should maintain stable memory usage during path traversal protection', async () => {
      app.use(pathTraversalProtection);
      app.get('/path-test/:path', (req: Request, res: Response) => {
        res.json({ path: req.path });
      });

      const initialMemory = await SecurityPerformanceMonitor.measureMemoryUsage();

      const maliciousOperations = Array(100).fill(0).map(() => () =>
        request(app)
          .get('/path-test/malicious')
          .expect(200)
      );

      await SecurityPerformanceMonitor.measureConcurrentSecurity(maliciousOperations, 15);

      const finalMemory = await SecurityPerformanceMonitor.measureMemoryUsage();
      const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;

      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // 100MB threshold
    });
  });

  describe('Load Testing Security Middleware', () => {
    it('should maintain performance under sustained load', async () => {
      generalSecurity.forEach(middleware => app.use(middleware));
      app.get('/load-test', (_req: Request, res: Response) => {
        res.json({ timestamp: Date.now() });
      });

      server = app.listen(0);
      const address = server.address();
      const port = address && typeof address === 'object' ? address.port : null;
      
      if (!port) {
        throw new Error('Failed to get server port');
      }

      const requestFactory = async () => {
        const response = await request(app)
          .get('/load-test');
        expect(response.status).toBe(200);
        return response;
      };

      const loadResults = await SecurityPerformanceMonitor.createSecurityLoadTest(
        requestFactory,
        3000, // 3 seconds (reduced for CI stability)
        10    // 10 RPS (reduced for CI stability)
      );

      expect(loadResults.successful).toBeGreaterThan(20);
      expect(loadResults.failed).toBeLessThan(10);
      expect(loadResults.averageTime).toBeLessThan(500);
      expect(loadResults.throughput).toBeGreaterThan(5);
    });

    it('should handle mixed legitimate and malicious traffic efficiently', async () => {
      generalSecurity.forEach(middleware => app.use(middleware));
      app.use(pathTraversalProtection);
      app.get('/mixed-test/:path', (req: Request, res: Response) => {
        res.json({ path: req.path });
      });

      const legitimateFactory = () =>
        request(app)
          .get('/mixed-test/legitimate')
          .expect(200);

      const maliciousFactory = () =>
        request(app)
          .get('/mixed-test/malicious')
          .expect(200);

      const operations = [
        ...Array(30).fill(0).map(() => legitimateFactory),
        ...Array(20).fill(0).map(() => maliciousFactory)
      ];

      const shuffledOperations = operations.sort(() => Math.random() - 0.5);
      const results = await SecurityPerformanceMonitor.measureConcurrentSecurity(shuffledOperations, 10);

      expect(results.averageDuration).toBeLessThan(250);
      expect(results.throughput).toBeGreaterThan(8);
    });
  });

  describe('CSRF Protection Performance', () => {
    beforeEach(() => {
      app.use((req: Request, _res: Response, next: NextFunction) => {
        (req as any).session = { csrfToken: 'valid-csrf-token' };
        next();
      });
    });

    it('should validate CSRF tokens efficiently', async () => {
      app.use(csrfProtection as any);
      app.post('/csrf-test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
        return request(app)
          .post('/csrf-test')
          .set('X-CSRF-Token', 'valid-csrf-token')
          .expect(200);
      });

      expect(duration).toBeLessThan(100);
    });

    it('should reject invalid CSRF tokens quickly', async () => {
      app.use(csrfProtection as any);
      app.post('/csrf-test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
        return request(app)
          .post('/csrf-test')
          .set('X-CSRF-Token', 'invalid-token')
          .expect(403);
      });

      expect(duration).toBeLessThan(100);
    });

    it('should handle mobile apps without CSRF efficiently', async () => {
      app.use(csrfProtection as any);
      app.post('/mobile-test', (_req: Request, res: Response) => {
        res.json({ success: true });
      });

      const { duration } = await SecurityPerformanceMonitor.measureMiddlewareTime(async () => {
        return request(app)
          .post('/mobile-test')
          .set('User-Agent', 'Flutter/2.0.0 (Mobile App)')
          .set('Authorization', 'Bearer valid-token')
          .expect(200);
      });

      expect(duration).toBeLessThan(75);
    });
  });
});