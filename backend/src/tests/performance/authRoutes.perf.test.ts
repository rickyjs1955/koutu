// /backend/src/tests/performance/authRoutes.isolated.perf.test.ts
// Isolated Performance Tests for Authentication Routes

import express from 'express';
import request from 'supertest';
import { performance } from 'perf_hooks';

// Create test app with mock routes
const createTestApp = () => {
  const app = express();
  app.use(express.json());

  // Mock auth routes
  app.post('/auth/register', (req, res) => {
    setTimeout(() => {
      res.status(201).json({
        status: 'success',
        data: { user: { id: 'new-user-id', email: req.body.email }, token: 'test-token' }
      });
    }, 10); // Simulate 10ms processing
  });

  app.post('/auth/login', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        data: { user: { id: 'user123', email: req.body.email }, token: 'test-token' }
      });
    }, 8); // Simulate 8ms processing
  });

  app.post('/auth/validate-token', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        data: { valid: true, user: { id: 'user123', email: 'test@example.com' } }
      });
    }, 2); // Simulate 2ms processing
  });

  app.get('/auth/me', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        data: { user: { id: 'user123', email: 'test@example.com' } }
      });
    }, 5); // Simulate 5ms processing
  });

  app.patch('/auth/password', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        message: 'Password updated successfully'
      });
    }, 15); // Simulate 15ms processing
  });

  app.patch('/auth/email', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        data: { user: { id: 'user123', email: req.body.newEmail } }
      });
    }, 12); // Simulate 12ms processing
  });

  app.post('/auth/refresh', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        data: { token: 'new-token', refreshToken: 'new-refresh-token' }
      });
    }, 5); // Simulate 5ms processing
  });

  app.post('/auth/mobile/login', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        data: { user: { id: 'user123', email: req.body.email }, token: 'test-token', refreshToken: 'refresh-token' }
      });
    }, 12); // Simulate 12ms processing
  });

  app.post('/auth/device/register', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        data: { device: { id: 'device-id', userId: 'user123' } }
      });
    }, 8); // Simulate 8ms processing
  });

  app.post('/auth/biometric/register', (req, res) => {
    setTimeout(() => {
      res.status(200).json({
        status: 'success',
        data: { biometric: { id: 'biometric-id', userId: 'user123' } }
      });
    }, 10); // Simulate 10ms processing
  });

  app.get('/oauth/:provider/authorize', (req, res) => {
    res.status(200).json({
      status: 'success',
      data: { url: `https://oauth.${req.params.provider}.com/authorize?params` }
    });
  });

  app.get('/oauth/:provider/callback', (req, res) => {
    res.redirect(302, '/success');
  });

  app.delete('/oauth/:provider/unlink', (req, res) => {
    res.status(200).json({
      status: 'success',
      message: 'Provider unlinked successfully'
    });
  });

  return app;
};

// Performance monitoring utilities
class PerformanceMonitor {
  static async measure<T>(operation: () => Promise<T>): Promise<{ result: T; duration: number }> {
    const start = performance.now();
    const result = await operation();
    const duration = performance.now() - start;
    return { result, duration };
  }

  static async measureConcurrent<T>(
    operations: (() => Promise<T>)[],
    concurrency: number = 10
  ): Promise<{ results: T[]; totalDuration: number; avgDuration: number; p95: number }> {
    const start = performance.now();
    const durations: number[] = [];
    const results: T[] = [];
    
    for (let i = 0; i < operations.length; i += concurrency) {
      const batch = operations.slice(i, i + concurrency);
      const batchStart = performance.now();
      const batchResults = await Promise.all(batch.map(op => op()));
      results.push(...batchResults);
      const batchDuration = performance.now() - batchStart;
      durations.push(batchDuration / batch.length);
    }
    
    const totalDuration = performance.now() - start;
    const avgDuration = durations.reduce((a, b) => a + b, 0) / durations.length;
    
    // Calculate p95
    durations.sort((a, b) => a - b);
    const p95Index = Math.floor(durations.length * 0.95);
    const p95 = durations[p95Index] || avgDuration;
    
    return { results, totalDuration, avgDuration, p95 };
  }

  static async runLoadTest(
    requestFactory: () => Promise<any>,
    duration: number,
    targetRPS: number
  ): Promise<{ 
    completedRequests: number; 
    errors: number; 
    avgResponseTime: number; 
    p95ResponseTime: number;
    requestsPerSecond: number;
  }> {
    return new Promise((resolve) => {
      const interval = 1000 / targetRPS;
      let completedRequests = 0;
      let errors = 0;
      const responseTimes: number[] = [];
      const startTime = performance.now();
      
      const makeRequest = async () => {
        const reqStart = performance.now();
        try {
          await requestFactory();
          completedRequests++;
          responseTimes.push(performance.now() - reqStart);
        } catch (error) {
          errors++;
        }
      };

      const intervalId = setInterval(makeRequest, interval);
      
      setTimeout(() => {
        clearInterval(intervalId);
        const totalTime = (performance.now() - startTime) / 1000; // in seconds
        
        // Calculate metrics
        responseTimes.sort((a, b) => a - b);
        const p95Index = Math.floor(responseTimes.length * 0.95);
        const p95ResponseTime = responseTimes[p95Index] || 0;
        const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length || 0;
        const requestsPerSecond = completedRequests / totalTime;
        
        resolve({
          completedRequests,
          errors,
          avgResponseTime,
          p95ResponseTime,
          requestsPerSecond
        });
      }, duration);
    });
  }
}

describe('Auth Routes Performance Tests - Isolated', () => {
  let app: express.Application;

  beforeAll(() => {
    app = createTestApp();
  });

  describe('Individual Route Performance', () => {
    it('should handle registration within 200ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .post('/auth/register')
          .send({
            email: 'test@example.com',
            password: 'Password123!',
            firstName: 'Test',
            lastName: 'User'
          })
          .expect(201);
      });

      expect(duration).toBeLessThan(200);
      console.log(`Registration: ${duration.toFixed(2)}ms`);
    });

    it('should handle login within 150ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .post('/auth/login')
          .send({
            email: 'test@example.com',
            password: 'Password123!'
          })
          .expect(200);
      });

      expect(duration).toBeLessThan(150);
      console.log(`Login: ${duration.toFixed(2)}ms`);
    });

    it('should validate tokens within 50ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .post('/auth/validate-token')
          .set('Authorization', 'Bearer test-token')
          .expect(200);
      });

      expect(duration).toBeLessThan(50);
      console.log(`Token validation: ${duration.toFixed(2)}ms`);
    });

    it('should retrieve profile within 100ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .get('/auth/me')
          .set('Authorization', 'Bearer test-token')
          .expect(200);
      });

      expect(duration).toBeLessThan(100);
      console.log(`Profile retrieval: ${duration.toFixed(2)}ms`);
    });

    it('should handle password updates within 200ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .patch('/auth/password')
          .set('Authorization', 'Bearer test-token')
          .send({
            currentPassword: 'Password123!',
            newPassword: 'NewPassword456!'
          })
          .expect(200);
      });

      expect(duration).toBeLessThan(200);
      console.log(`Password update: ${duration.toFixed(2)}ms`);
    });
  });

  describe('Mobile Authentication Performance', () => {
    it('should handle mobile login within 200ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .post('/auth/mobile/login')
          .send({
            email: 'test@example.com',
            password: 'Password123!',
            deviceId: 'device-123'
          })
          .expect(200);
      });

      expect(duration).toBeLessThan(200);
      console.log(`Mobile login: ${duration.toFixed(2)}ms`);
    });

    it('should register devices within 150ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .post('/auth/device/register')
          .set('Authorization', 'Bearer test-token')
          .send({
            deviceId: 'device-123',
            platform: 'ios',
            pushToken: 'push-token'
          })
          .expect(200);
      });

      expect(duration).toBeLessThan(150);
      console.log(`Device registration: ${duration.toFixed(2)}ms`);
    });
  });

  describe('OAuth Performance', () => {
    it('should generate OAuth URLs within 50ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .get('/oauth/google/authorize')
          .expect(200);
      });

      expect(duration).toBeLessThan(50);
      console.log(`OAuth URL generation: ${duration.toFixed(2)}ms`);
    });

    it('should handle OAuth callbacks within 100ms', async () => {
      const { duration } = await PerformanceMonitor.measure(async () => {
        return request(app)
          .get('/oauth/google/callback')
          .query({ code: 'auth-code', state: 'state' })
          .expect(302);
      });

      expect(duration).toBeLessThan(100);
      console.log(`OAuth callback: ${duration.toFixed(2)}ms`);
    });
  });

  describe('Concurrent Request Performance', () => {
    it('should handle 100 concurrent logins efficiently', async () => {
      const operations = Array.from({ length: 100 }, (_, i) => 
        () => request(app)
          .post('/auth/login')
          .send({ email: `user${i}@example.com`, password: 'Password123!' })
      );

      const { totalDuration, avgDuration, p95 } = await PerformanceMonitor.measureConcurrent(operations, 20);

      expect(avgDuration).toBeLessThan(50);
      expect(p95).toBeLessThan(100);
      console.log(`100 concurrent logins: Total ${totalDuration.toFixed(2)}ms, Avg ${avgDuration.toFixed(2)}ms, P95 ${p95.toFixed(2)}ms`);
    });

    it('should handle mixed concurrent operations', async () => {
      const operations = [
        ...Array.from({ length: 40 }, () => () => request(app).post('/auth/login').send({ email: 'test@example.com', password: 'Password123!' })),
        ...Array.from({ length: 30 }, () => () => request(app).post('/auth/validate-token').set('Authorization', 'Bearer test-token')),
        ...Array.from({ length: 20 }, () => () => request(app).get('/auth/me').set('Authorization', 'Bearer test-token')),
        ...Array.from({ length: 10 }, () => () => request(app).post('/auth/refresh').send({ refreshToken: 'refresh-token' }))
      ];

      const { totalDuration, avgDuration, p95 } = await PerformanceMonitor.measureConcurrent(operations, 25);

      expect(avgDuration).toBeLessThan(50);
      expect(p95).toBeLessThan(100);
      console.log(`Mixed operations (100 total): Total ${totalDuration.toFixed(2)}ms, Avg ${avgDuration.toFixed(2)}ms, P95 ${p95.toFixed(2)}ms`);
    });
  });

  describe('Load Testing', () => {
    it('should sustain 50 requests per second', async () => {
      const results = await PerformanceMonitor.runLoadTest(
        () => request(app)
          .post('/auth/login')
          .send({ email: 'test@example.com', password: 'Password123!' }),
        3000, // 3 seconds
        50    // 50 RPS target
      );

      console.log('Load test results (50 RPS for 3s):');
      console.log(`  Completed: ${results.completedRequests}`);
      console.log(`  Errors: ${results.errors}`);
      console.log(`  Actual RPS: ${results.requestsPerSecond.toFixed(2)}`);
      console.log(`  Avg response: ${results.avgResponseTime.toFixed(2)}ms`);
      console.log(`  P95 response: ${results.p95ResponseTime.toFixed(2)}ms`);

      expect(results.completedRequests).toBeGreaterThanOrEqual(90); // Allow some variance in load testing
      expect(results.errors).toBeLessThan(5);
      expect(results.avgResponseTime).toBeLessThan(100);
      expect(results.p95ResponseTime).toBeLessThan(200);
    });
  });

  describe('Performance SLA Compliance', () => {
    it('should meet all endpoint SLAs', async () => {
      const slaTests = [
        { name: 'Registration', endpoint: '/auth/register', method: 'post', sla: 200, 
          body: { email: 'sla@test.com', password: 'Password123!', firstName: 'SLA', lastName: 'Test' } },
        { name: 'Login', endpoint: '/auth/login', method: 'post', sla: 150,
          body: { email: 'test@example.com', password: 'Password123!' } },
        { name: 'Token Validation', endpoint: '/auth/validate-token', method: 'post', sla: 50,
          headers: { 'Authorization': 'Bearer test-token' } },
        { name: 'Get Profile', endpoint: '/auth/me', method: 'get', sla: 100,
          headers: { 'Authorization': 'Bearer test-token' } },
        { name: 'Refresh Token', endpoint: '/auth/refresh', method: 'post', sla: 100,
          body: { refreshToken: 'refresh-token' } },
        { name: 'Mobile Login', endpoint: '/auth/mobile/login', method: 'post', sla: 200,
          body: { email: 'test@example.com', password: 'Password123!', deviceId: 'device-123' } }
      ];

      console.log('\nSLA Compliance Report:');
      console.log('=====================');
      
      const results = [];
      for (const test of slaTests) {
        const { duration } = await PerformanceMonitor.measure(async () => {
          const req = request(app)[test.method as 'get' | 'post'](test.endpoint);
          
          if (test.headers) {
            Object.entries(test.headers).forEach(([key, value]) => {
              req.set(key, value);
            });
          }
          
          if (test.body) {
            req.send(test.body);
          }
          
          return req;
        });

        const passed = duration < test.sla;
        results.push({ ...test, duration, passed });
        
        console.log(`${passed ? '✓' : '✗'} ${test.name}: ${duration.toFixed(2)}ms (SLA: ${test.sla}ms)`);
        expect(duration).toBeLessThan(test.sla);
      }

      const passRate = (results.filter(r => r.passed).length / results.length) * 100;
      console.log(`\nOverall pass rate: ${passRate.toFixed(1)}%`);
    });
  });
});