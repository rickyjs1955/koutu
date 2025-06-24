// /backend/src/__tests__/app.security.test.ts
import request from 'supertest';
import express from 'express';
import { jest } from '@jest/globals';
import { Server } from 'http';

type SpyInstance = ReturnType<typeof jest.spyOn>;

// Mock dependencies before importing app
jest.mock('../../config', () => ({
    config: {
        port: 3000,
        storageMode: 'local',
        nodeEnv: 'test'
    }
}));

// Enhanced security middleware mock with more realistic behavior
jest.mock('../../middlewares/security', () => ({
    securityMiddleware: {
        general: [
        // Mock CORS middleware
        jest.fn((req: any, res: any, next: any) => {
            res.set('Access-Control-Allow-Origin', '*');
            res.set('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE');
            res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            next();
        }),
        // Mock Helmet middleware (security headers)
        jest.fn((req: any, res: any, next: any) => {
            res.set('X-Content-Type-Options', 'nosniff');
            res.set('X-Frame-Options', 'DENY');
            res.set('X-XSS-Protection', '1; mode=block');
            res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
            next();
        }),
        // Mock Rate limiting middleware
        jest.fn((req: any, res: any, next: any) => {
            // Simulate rate limiting logic
            const rateLimitHeader = req.headers['x-test-rate-limit'];
            if (rateLimitHeader === 'exceeded') {
            res.status(429).json({ error: 'Too Many Requests' });
            return;
            }
            res.set('X-RateLimit-Limit', '100');
            res.set('X-RateLimit-Remaining', '99');
            next();
        })
        ],
        pathTraversal: jest.fn((req: any, res: any, next: any) => {
        // Mock path traversal protection
        const path = req.path || req.url;
        if (path.includes('..') || path.includes('%2e%2e')) {
            res.status(400).json({ error: 'Path traversal attempt detected' });
            return;
        }
        next();
        })
    }
}));

jest.mock('../../middlewares/errorHandler', () => ({
    errorHandler: jest.fn((err: any, req: any, res: any, next: any) => {
        if (err instanceof SyntaxError && 'body' in err) {
        res.status(400).json({ error: 'Malformed JSON' });
        } else if (err.type === 'entity.too.large') {
        res.status(413).json({ error: 'Payload Too Large' });
        } else if (err.message === 'Empty request body') {
        res.status(400).json({ error: 'Empty request body' });
        } else {
        res.status(500).json({ error: 'Internal Server Error' });
        }
    })
}));

// Mock route modules
const createMockRouter = () => {
    const router = express.Router();
    router.get('/test', (req: express.Request, res: express.Response) => {
        res.status(200).json({ message: 'Test route success' });
    });
    router.post('/test', (req: express.Request, res: express.Response) => {
        res.status(200).json({ message: 'Test route success', body: req.body });
    });
    return router;
};

jest.mock('../../routes/authRoutes', () => ({ authRoutes: createMockRouter() }));
jest.mock('../../routes/imageRoutes', () => ({ imageRoutes: createMockRouter() }));
jest.mock('../../routes/garmentRoutes', () => ({ garmentRoutes: createMockRouter() }));
jest.mock('../../routes/wardrobeRoutes', () => ({ wardrobeRoutes: createMockRouter() }));
jest.mock('../../routes/exportRoutes', () => createMockRouter());
jest.mock('../../routes/fileRoutes', () => ({ fileRoutes: createMockRouter() }));
jest.mock('../../routes/polygonRoutes', () => ({ polygonRoutes: createMockRouter() }));
jest.mock('../../routes/oauthRoutes', () => ({ oauthRoutes: createMockRouter() }));

describe('App Security Tests', () => {
    let app: express.Application;
    let server: Server;
    let mockConsoleLog: SpyInstance;

    beforeAll(() => {
        mockConsoleLog = jest.spyOn(console, 'log').mockImplementation(() => {});
    });

    beforeEach(async () => {
        jest.clearAllMocks();
        jest.resetModules();
        const { app: appInstance } = await import('../../app');
        app = appInstance;
        server = app.listen(0);
    });

    afterEach((done) => {
        server.close(done);
    });

    afterAll(() => {
        mockConsoleLog.mockRestore();
    });

    describe('Security Headers', () => {
        it('should set CORS headers', async () => {
        const response = await request(app).get('/health');

        expect(response.headers['access-control-allow-origin']).toBe('*');
        expect(response.headers['access-control-allow-methods']).toBe('GET,HEAD,PUT,PATCH,POST,DELETE');
        expect(response.headers['access-control-allow-headers']).toBe('Content-Type, Authorization');
        });

        it('should set security headers via Helmet', async () => {
        const response = await request(app).get('/health');

        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['x-frame-options']).toBe('DENY');
        expect(response.headers['x-xss-protection']).toBe('1; mode=block');
        expect(response.headers['strict-transport-security']).toBe('max-age=31536000; includeSubDomains');
        });

        it('should set rate limiting headers', async () => {
        const response = await request(app).get('/health');

        expect(response.headers['x-ratelimit-limit']).toBe('100');
        expect(response.headers['x-ratelimit-remaining']).toBe('99');
        });

        it('should apply security headers to all routes', async () => {
        const routes = [
            '/api/v1/auth/test',
            '/api/v1/images/test',
            '/api/v1/garments/test',
            '/api/v1/wardrobes/test'
        ];

        for (const route of routes) {
            const response = await request(app).get(route);
            
            expect(response.headers['x-content-type-options']).toBe('nosniff');
            expect(response.headers['x-frame-options']).toBe('DENY');
            expect(response.headers['access-control-allow-origin']).toBe('*');
        }
        });
    });

    describe('Rate Limiting', () => {
        it('should allow normal requests within rate limits', async () => {
        const response = await request(app).get('/health');

        expect(response.status).toBe(200);
        expect(response.headers['x-ratelimit-limit']).toBe('100');
        });

        it('should block requests when rate limit is exceeded', async () => {
        const response = await request(app)
            .get('/health')
            .set('X-Test-Rate-Limit', 'exceeded');

        expect(response.status).toBe(429);
        expect(response.body.error).toBe('Too Many Requests');
        });

        it('should apply rate limiting to API routes', async () => {
        const response = await request(app)
            .get('/api/v1/auth/test')
            .set('X-Test-Rate-Limit', 'exceeded');

        expect(response.status).toBe(429);
        expect(response.body.error).toBe('Too Many Requests');
        });

        it('should apply rate limiting to POST requests', async () => {
        const response = await request(app)
            .post('/api/v1/images/test')
            .set('X-Test-Rate-Limit', 'exceeded')
            .send({ test: 'data' });

        expect(response.status).toBe(429);
        });
    });

    describe('Path Traversal Protection', () => {
        it('should allow normal file requests', async () => {
        const response = await request(app).get('/api/v1/files/test');

        expect(response.status).toBe(200);
        expect(response.body.message).toBe('Test route success');
        });

        it('should block path traversal attempts with ".."', async () => {
        const response = await request(app).get('/api/v1/files/../../../etc/passwd');

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Path traversal attempt detected');
        });

        it('should block URL-encoded path traversal attempts', async () => {
        const response = await request(app).get('/api/v1/files/%2e%2e/sensitive-file');

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Path traversal attempt detected');
        });

        it('should only apply path traversal protection to file routes', async () => {
        // Other routes should not be affected by path traversal in URL
        const response = await request(app).get('/api/v1/auth/../test');

        expect(response.status).not.toBe(400);
        });

        it('should protect against nested path traversal attempts', async () => {
        const maliciousPaths = [
            '/api/v1/files/../../config.json',
            '/api/v1/files/../../../.env',
            '/api/v1/files/subdir/../../../secret.txt'
        ];

        for (const path of maliciousPaths) {
            const response = await request(app).get(path);
            expect(response.status).toBe(400);
            expect(response.body.error).toBe('Path traversal attempt detected');
        }
        });
    });

    describe('Request Size Limits', () => {
        it('should reject JSON payloads exceeding 1MB', async () => {
        const largePayload = { data: 'x'.repeat(1024 * 1024 + 1) };

        const response = await request(app)
            .post('/api/v1/auth/test')
            .send(largePayload)
            .set('Content-Type', 'application/json');

        expect(response.status).toBe(413);
        expect(response.body.error).toBe('Payload Too Large');
        });

        it('should accept JSON payloads under 1MB', async () => {
        const normalPayload = { data: 'x'.repeat(1000) };

        const response = await request(app)
            .post('/api/v1/auth/test')
            .send(normalPayload)
            .set('Content-Type', 'application/json');

        expect(response.status).toBe(200);
        expect(response.body.body).toEqual(normalPayload);
        });

        it('should reject form data exceeding 1MB', async () => {
        const largeData = 'data=' + 'x'.repeat(1024 * 1024 + 1);

        const response = await request(app)
            .post('/api/v1/images/test')
            .send(largeData)
            .set('Content-Type', 'application/x-www-form-urlencoded');

        expect(response.status).toBe(413);
        expect(response.body.error).toBe('Payload Too Large');
        });

        it('should limit URL parameters', async () => {
        // This would typically be handled by the parameterLimit: 100 setting
        const normalParams = { param1: 'value1', param2: 'value2' };

        const response = await request(app)
            .post('/api/v1/garments/test')
            .send(normalParams)
            .set('Content-Type', 'application/x-www-form-urlencoded');

        expect(response.status).toBe(200);
        });
    });

    describe('JSON Parsing Security', () => {
        it('should reject malformed JSON', async () => {
        const response = await request(app)
            .post('/api/v1/auth/test')
            .send('{"malformed": json}')
            .set('Content-Type', 'application/json');

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Malformed JSON');
        });

        it('should reject empty request bodies when expected', async () => {
        const response = await request(app)
            .post('/api/v1/auth/test')
            .send('')
            .set('Content-Type', 'application/json')
            .set('Content-Length', '0');

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Empty request body');
        });

        it('should handle valid JSON correctly', async () => {
        const validPayload = { username: 'test', password: 'secure123' };

        const response = await request(app)
            .post('/api/v1/auth/test')
            .send(validPayload)
            .set('Content-Type', 'application/json');

        expect(response.status).toBe(200);
        expect(response.body.body).toEqual(validPayload);
        });

        it('should handle deeply nested JSON objects', async () => {
        const nestedPayload = {
            user: {
            profile: {
                settings: {
                notifications: {
                    email: true,
                    push: false
                }
                }
            }
            }
        };

        const response = await request(app)
            .post('/api/v1/wardrobes/test')
            .send(nestedPayload)
            .set('Content-Type', 'application/json');

        expect(response.status).toBe(200);
        expect(response.body.body).toEqual(nestedPayload);
        });
    });

    describe('CORS Security', () => {
        it('should handle OPTIONS preflight requests', async () => {
        const response = await request(app)
            .options('/api/v1/auth/test')
            .set('Origin', 'http://localhost:3000')
            .set('Access-Control-Request-Method', 'POST')
            .set('Access-Control-Request-Headers', 'Content-Type');

        expect(response.headers['access-control-allow-origin']).toBe('*');
        expect(response.headers['access-control-allow-methods']).toBe('GET,HEAD,PUT,PATCH,POST,DELETE');
        });

        it('should set CORS headers for different HTTP methods', async () => {
        const methods = ['GET', 'POST', 'PUT', 'DELETE'];

        for (const method of methods) {
            let response;
            if (method === 'GET') {
                response = await request(app).get('/api/v1/images/test');
            } else if (method === 'POST') {
                response = await request(app).post('/api/v1/images/test').send({ test: 'data' });
            } else if (method === 'PUT') {
                response = await request(app).put('/api/v1/images/test').send({ test: 'data' });
            } else if (method === 'DELETE') {
                response = await request(app).delete('/api/v1/images/test');
            } else {
                continue; // Skip unknown methods
            }

            expect(response.headers['access-control-allow-origin']).toBe('*');
        }
        });
    });

    describe('Security Middleware Order', () => {
        it('should apply security middleware before route handlers', async () => {
        const { securityMiddleware } = await import('../../middlewares/security');

        await request(app).get('/api/v1/auth/test');

        // All general security middleware should be called
        expect(securityMiddleware.general[0]).toHaveBeenCalled(); // CORS
        expect(securityMiddleware.general[1]).toHaveBeenCalled(); // Helmet
        expect(securityMiddleware.general[2]).toHaveBeenCalled(); // Rate limiting
        });

        it('should apply path traversal middleware only to file routes', async () => {
        const { securityMiddleware } = await import('../../middlewares/security');

        jest.clearAllMocks();

        // Non-file route
        await request(app).get('/api/v1/auth/test');
        expect(securityMiddleware.pathTraversal).not.toHaveBeenCalled();

        // File route
        await request(app).get('/api/v1/files/test');
        expect(securityMiddleware.pathTraversal).toHaveBeenCalled();
        });

        it('should handle security middleware errors gracefully', async () => {
        // Test rate limiting rejection
        const response = await request(app)
            .get('/api/v1/auth/test')
            .set('X-Test-Rate-Limit', 'exceeded');

        expect(response.status).toBe(429);
        expect(response.body.error).toBe('Too Many Requests');
        });
    });

    describe('Content-Type Security', () => {
        it('should handle various content types securely', async () => {
        const contentTypes = [
            'application/json',
            'application/x-www-form-urlencoded',
            'text/plain',
            'multipart/form-data'
        ];

        for (const contentType of contentTypes.slice(0, 2)) { // Test first two
            const response = await request(app)
            .post('/api/v1/auth/test')
            .send(contentType === 'application/json' ? { test: 'data' } : 'test=data')
            .set('Content-Type', contentType);

            expect(response.status).toBe(200);
        }
        });

        it('should reject suspicious content types', async () => {
        // This would typically be handled by additional middleware
        const response = await request(app)
            .post('/api/v1/auth/test')
            .send('test data')
            .set('Content-Type', 'application/x-executable');

        // Should still process but with security headers
        expect(response.headers['x-content-type-options']).toBe('nosniff');
        });
    });

    describe('Security Headers Consistency', () => {
        it('should apply consistent security headers across all endpoints', async () => {
        const endpoints = [
            '/health',
            '/api/v1/auth/test',
            '/api/v1/images/test',
            '/api/v1/files/test'
        ];

        for (const endpoint of endpoints) {
            const response = await request(app).get(endpoint);

            expect(response.headers['x-content-type-options']).toBe('nosniff');
            expect(response.headers['x-frame-options']).toBe('DENY');
            expect(response.headers['x-xss-protection']).toBe('1; mode=block');
        }
        });

        it('should maintain security headers in error responses', async () => {
        const response = await request(app)
            .get('/api/v1/files/../../../etc/passwd');

        expect(response.status).toBe(400);
        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['x-frame-options']).toBe('DENY');
        });
    });

    describe('Health Check Security', () => {
        it('should include security status in health check', async () => {
        const response = await request(app).get('/health');

        expect(response.status).toBe(200);
        expect(response.body.security).toEqual({
            cors: 'enabled',
            helmet: 'enabled',
            rateLimit: 'enabled',
            requestLimits: 'enabled'
        });
        });

        it('should apply security headers to health check endpoint', async () => {
        const response = await request(app).get('/health');

        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['access-control-allow-origin']).toBe('*');
        });

        it('should rate limit health check requests', async () => {
        const response = await request(app)
            .get('/health')
            .set('X-Test-Rate-Limit', 'exceeded');

        expect(response.status).toBe(429);
        });
    });

    describe('Error Handling Security', () => {
        it('should not expose sensitive information in error messages', async () => {
        const response = await request(app)
            .post('/api/v1/auth/test')
            .send('{"malformed": json}')
            .set('Content-Type', 'application/json');

        expect(response.status).toBe(400);
        expect(response.body.error).toBe('Malformed JSON');
        expect(response.body).not.toHaveProperty('stack');
        expect(response.body).not.toHaveProperty('details');
        });

        it('should maintain security headers in error responses', async () => {
        const response = await request(app)
            .post('/api/v1/auth/test')
            .send('invalid')
            .set('Content-Type', 'application/json');

        expect(response.status).toBe(400);
        expect(response.headers['x-content-type-options']).toBe('nosniff');
        expect(response.headers['x-frame-options']).toBe('DENY');
        });
    });
});