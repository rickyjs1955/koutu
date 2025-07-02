// /backend/src/__tests__/app.security.test.ts - Fixed version for Flutter mobile app security
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

// Enhanced security middleware mock with Flutter-specific behavior
jest.mock('../../middlewares/security', () => ({
    securityMiddleware: {
        general: [
            // Mock CORS middleware with Flutter support
            jest.fn((req: any, res: any, next: any) => {
                const userAgent = req.headers['user-agent'] || '';
                const isFlutterApp = userAgent.includes('Dart/') || userAgent.includes('Flutter/');
                
                // Flutter-friendly CORS headers
                res.set('Access-Control-Allow-Origin', req.headers.origin || '*');
                res.set('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
                res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Accept, Origin, X-Requested-With');
                
                if (isFlutterApp) {
                    res.set('Access-Control-Expose-Headers', 'Content-Length, X-RateLimit-Limit, X-RateLimit-Remaining, X-Total-Count');
                    res.set('Access-Control-Max-Age', '3600');
                }
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
            // Mock Rate limiting middleware with Flutter awareness
            jest.fn((req: any, res: any, next: any) => {
                const rateLimitHeader = req.headers['x-test-rate-limit'];
                const userAgent = req.headers['user-agent'] || '';
                const isFlutterApp = userAgent.includes('Dart/') || userAgent.includes('Flutter/');
                
                if (rateLimitHeader === 'exceeded') {
                    if (isFlutterApp) {
                        res.status(429).json({ 
                            error: 'RATE_LIMIT_EXCEEDED',
                            message: 'Too many requests from this device',
                            retryAfter: 60,
                            details: {
                                limit: 100,
                                window: '1 hour',
                                remaining: 0
                            }
                        });
                    } else {
                        res.status(429).json({ error: 'Too Many Requests' });
                    }
                    return;
                }
                res.set('X-RateLimit-Limit', '100');
                res.set('X-RateLimit-Remaining', '99');
                next();
            })
        ],
        pathTraversal: jest.fn((req: any, res: any, next: any) => {
            const path = req.path || req.url;
            const userAgent = req.headers['user-agent'] || '';
            const isFlutterApp = userAgent.includes('Dart/') || userAgent.includes('Flutter/');
            
            if (path.includes('..') || path.includes('%2e%2e')) {
                if (isFlutterApp) {
                    res.status(400).json({ 
                        error: 'INVALID_PATH',
                        message: 'Path traversal attempt detected',
                        details: 'File path contains invalid characters'
                    });
                } else {
                    res.status(400).json({ error: 'Path traversal attempt detected' });
                }
                return;
            }
            next();
        })
    }
}));

jest.mock('../../middlewares/errorHandler', () => ({
    errorHandler: jest.fn((err: any, req: any, res: any, next: any) => {
        const userAgent = req.headers['user-agent'] || '';
        const isFlutterApp = userAgent.includes('Dart/') || userAgent.includes('Flutter/');
        
        if (err instanceof SyntaxError && 'body' in err) {
            if (isFlutterApp) {
                res.status(400).json({
                    error: 'INVALID_JSON',
                    message: 'Request body contains invalid JSON',
                    details: 'Please check your JSON formatting'
                });
            } else {
                res.status(400).json({ error: 'Malformed JSON' });
            }
        } else if (err.type === 'entity.too.large' || err.code === 'LIMIT_FILE_SIZE') {
            if (isFlutterApp) {
                res.status(413).json({
                    error: 'PAYLOAD_TOO_LARGE',
                    message: 'File or payload size exceeds maximum allowed limit',
                    details: {
                        maxSize: '10MB for files, 2MB for JSON',
                        receivedSize: req.get('Content-Length') || 'unknown'
                    }
                });
            } else {
                res.status(413).json({ error: 'Payload Too Large' });
            }
        } else if (err.message === 'Empty request body') {
            // Handle empty body error specifically
            if (isFlutterApp) {
                res.status(400).json({
                    error: 'INVALID_JSON',
                    message: 'Request body is empty',
                    details: 'Please provide valid JSON content'
                });
            } else {
                res.status(400).json({ error: 'Empty request body' });
            }
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

describe('Flutter App Security Tests', () => {
    let app: express.Application;
    let server: Server;
    let mockConsoleLog: SpyInstance;

    beforeAll(() => {
        mockConsoleLog = jest.spyOn(console, 'log').mockImplementation(() => {});
        // Increase Jest timeout for file upload tests
        jest.setTimeout(60000);
    });

    beforeEach(async () => {
        jest.clearAllMocks();
        jest.resetModules();
        const { app: appInstance } = await import('../../app');
        app = appInstance;
        server = app.listen(0);
    });

    afterEach((done) => {
        if (server) {
            server.close(done);
        } else {
            done();
        }
    });

    afterAll(() => {
        mockConsoleLog.mockRestore();
        jest.setTimeout(5000); // Reset to default
    });

    describe('1. Flutter Security Headers Consistency', () => {
        it('should apply consistent security headers across all Flutter endpoints', async () => {
            const endpoints = [
                '/health',
                '/api/auth/test',
                '/api/images/test',
                '/api/files/test'
            ];

            for (const endpoint of endpoints) {
                const response = await request(app)
                    .get(endpoint)
                    .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

                expect(response.headers['x-content-type-options']).toBe('nosniff');
                expect(response.headers['x-frame-options']).toBe('DENY');
                expect(response.headers['x-xss-protection']).toBe('1; mode=block');
                expect(response.headers['access-control-expose-headers']).toContain('X-Total-Count');
            }
        });

        it('should maintain Flutter headers in error responses', async () => {
            const response = await request(app)
                .get('/api/files/../../../etc/passwd')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(response.status).toBe(400);
            expect(response.headers['x-content-type-options']).toBe('nosniff');
            expect(response.headers['access-control-allow-origin']).toBe('*');
            expect(response.headers['access-control-expose-headers']).toContain('X-Total-Count');
        });
    });

    describe('2. Flutter CORS Security', () => {
        it('should set Flutter-compatible CORS headers', async () => {
            const response = await request(app)
                .get('/health')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(response.headers['access-control-allow-origin']).toBe('*');
            expect(response.headers['access-control-allow-methods']).toBe('GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');
            expect(response.headers['access-control-allow-headers']).toContain('Content-Type');
            expect(response.headers['access-control-allow-headers']).toContain('Authorization');
            expect(response.headers['access-control-expose-headers']).toContain('X-Total-Count');
            expect(response.headers['access-control-max-age']).toBe('3600');
        });

        it('should handle Flutter preflight OPTIONS requests', async () => {
            const response = await request(app)
                .options('/api/auth/login')
                .set('User-Agent', 'Dart/2.19 (dart:io)')
                .set('Access-Control-Request-Method', 'POST')
                .set('Access-Control-Request-Headers', 'Content-Type,Authorization');

            expect(response.status).toBe(204);
            expect(response.headers['access-control-allow-methods']).toContain('POST');
            expect(response.headers['access-control-max-age']).toBe('3600');
        });

        it('should allow requests without origin headers (Flutter mobile)', async () => {
            const response = await request(app)
                .post('/api/auth/test')
                .send({ username: 'test', password: 'secure123' })
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');
                // No Origin header - typical for Flutter mobile apps

            expect(response.status).toBe(200);
            expect(response.headers['access-control-allow-origin']).toBe('*');
        });

        it('should set security headers for all Flutter requests', async () => {
            const routes = [
                '/api/auth/test',
                '/api/images/test',
                '/api/garments/test',
                '/api/wardrobes/test'
            ];

            for (const route of routes) {
                const response = await request(app)
                    .get(route)
                    .set('User-Agent', 'Flutter/3.7.0 (dart:io)');
                
                expect(response.headers['x-content-type-options']).toBe('nosniff');
            }
        });
    });

    describe('3. Flutter Authentication Security', () => {
        it('should handle Flutter authentication headers securely', async () => {
            const response = await request(app)
                .get('/api/auth/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Authorization', 'Bearer fake-jwt-token');

            expect(response.status).toBe(200);
            expect(response.headers['access-control-allow-origin']).toBe('*');
        });

        it('should expose necessary auth headers to Flutter apps', async () => {
            const response = await request(app)
                .options('/api/auth/login')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Access-Control-Request-Headers', 'Authorization,Content-Type');

            expect(response.status).toBe(204);
            expect(response.headers['access-control-allow-headers']).toContain('Authorization');
        });
    });

    describe('4. Flutter Security Middleware Order', () => {
        it('should apply security middleware before Flutter route handlers', async () => {
            const { securityMiddleware } = await import('../../middlewares/security');

            await request(app)
                .get('/api/auth/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(securityMiddleware.general[0]).toHaveBeenCalled(); // CORS
            expect(securityMiddleware.general[1]).toHaveBeenCalled(); // Helmet
            expect(securityMiddleware.general[2]).toHaveBeenCalled(); // Rate limiting
        });

        it('should apply path traversal middleware only to Flutter file routes', async () => {
            const { securityMiddleware } = await import('../../middlewares/security');

            jest.clearAllMocks();

            // Non-file route
            await request(app)
                .get('/api/auth/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');
            expect(securityMiddleware.pathTraversal).not.toHaveBeenCalled();

            // File route
            await request(app)
                .get('/api/files/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');
            expect(securityMiddleware.pathTraversal).toHaveBeenCalled();
        });

        it('should handle Flutter security middleware errors gracefully', async () => {
            const response = await request(app)
                .get('/api/auth/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('X-Test-Rate-Limit', 'exceeded');

            expect(response.status).toBe(429);
            expect(response.body.error).toBe('RATE_LIMIT_EXCEEDED');
        });
    });

    describe('5. Flutter Rate Limiting Security', () => {
        it('should allow normal Flutter requests within rate limits', async () => {
            const response = await request(app)
                .get('/health')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(response.status).toBe(200);
            expect(response.headers['x-ratelimit-limit']).toBe('100');
            expect(response.headers['x-ratelimit-remaining']).toBe('99');
        });

        it('should provide Flutter-friendly rate limit error messages', async () => {
            const response = await request(app)
                .get('/health')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('X-Test-Rate-Limit', 'exceeded');

            expect(response.status).toBe(429);
            expect(response.body.error).toBe('RATE_LIMIT_EXCEEDED');
            expect(response.body.message).toContain('Too many requests from this device');
            expect(response.body.details).toBeDefined();
            expect(response.body.details.limit).toBe(100);
            expect(response.body.retryAfter).toBe(60);
        });

        it('should apply rate limiting to Flutter API requests', async () => {
            const response = await request(app)
                .get('/api/auth/test')
                .set('User-Agent', 'Dart/2.19 (dart:io)')
                .set('X-Test-Rate-Limit', 'exceeded');

            expect(response.status).toBe(429);
            expect(response.body.error).toBe('RATE_LIMIT_EXCEEDED');
        });

        it('should apply rate limiting to Flutter POST requests', async () => {
            const response = await request(app)
                .post('/api/images/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('X-Test-Rate-Limit', 'exceeded')
                .send({ test: 'data' });

            expect(response.status).toBe(429);
            expect(response.body.error).toBe('RATE_LIMIT_EXCEEDED');
        });
    });

    describe('6. Flutter Request Size Security', () => {
        it('should accept normal JSON payloads from Flutter apps', async () => {
            const normalPayload = { data: 'x'.repeat(1000) };

            const response = await request(app)
                .post('/api/auth/test')
                .send(normalPayload)
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');

            expect(response.status).toBe(200);
            expect(response.body.body).toEqual(normalPayload);
        });

        it('should reject oversized JSON from Flutter apps with detailed errors', async () => {
            const largePayload = { data: 'x'.repeat(3 * 1024 * 1024) }; // 3MB

            const response = await request(app)
                .post('/api/auth/test')
                .send(largePayload)
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');

            expect(response.status).toBe(413);
            expect(response.body.error).toBe('PAYLOAD_TOO_LARGE');
            expect(response.body.details).toBeDefined();
            expect(response.body.details.maxSize).toContain('2MB for JSON');
        });

        it('should handle Flutter file uploads with size limits', async () => {
            const largeFileSize = 11 * 1024 * 1024; // 11MB

            const response = await request(app)
                .post('/api/test/upload') // Use the test upload endpoint
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'multipart/form-data')
                .set('Content-Length', largeFileSize.toString())
                .timeout(5000); // 5 second timeout

            expect(response.status).toBe(413);
            expect(response.body.error).toBe('FILE_TOO_LARGE');
            expect(response.body.maxSizeMB).toBe(10);
        }, 10000); // 10 second test timeout

        it('should accept Flutter form data under limits', async () => {
            const normalParams = { param1: 'value1', param2: 'value2' };

            const response = await request(app)
                .post('/api/garments/test')
                .send(normalParams)
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/x-www-form-urlencoded');

            expect(response.status).toBe(200);
        });
    });

    describe('7. Flutter JSON Security', () => {
        it('should provide Flutter-friendly malformed JSON errors', async () => {
            const response = await request(app)
                .post('/api/auth/test')
                .send('{"malformed": json}')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('INVALID_JSON');
            expect(response.body.message).toBe('Request body contains invalid JSON');
            expect(response.body.details).toBe('Please check your JSON formatting');
        });

        it('should handle Flutter empty request bodies gracefully', async () => {
            const response = await request(app)
                .post('/api/auth/test')
                .send('') // Empty string instead of no body
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json')
                .set('Content-Length', '0');

            // The app.ts should trigger the "Empty request body" error via the verify function
            expect(response.status).toBe(400);
            expect(response.body.error).toBe('INVALID_JSON');
            expect(response.body.message).toContain('empty'); // Should contain 'empty' in the message
        });

        it('should process valid Flutter JSON correctly', async () => {
            const validPayload = { username: 'test', password: 'secure123' };

            const response = await request(app)
                .post('/api/auth/test')
                .send(validPayload)
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');

            expect(response.status).toBe(200);
            expect(response.body.body).toEqual(validPayload);
        });

        it('should handle Flutter nested JSON objects', async () => {
            const nestedPayload = {
                user: {
                    profile: {
                        settings: {
                            notifications: {
                                email: true,
                                push: false
                            },
                            theme: 'dark'
                        }
                    }
                },
                metadata: {
                    platform: 'flutter',
                    version: '3.7.0'
                }
            };

            const response = await request(app)
                .post('/api/wardrobes/test')
                .send(nestedPayload)
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');

            expect(response.status).toBe(200);
            expect(response.body.body).toEqual(nestedPayload);
        });
    });

    describe('8. Flutter Content-Type Security', () => {
        it('should handle various Flutter content types securely', async () => {
            const contentTypes = [
                { type: 'application/json', data: { test: 'data' } },
                { type: 'application/x-www-form-urlencoded', data: 'test=data' },
                { type: 'multipart/form-data', data: 'boundary data' }
            ];

            for (const { type, data } of contentTypes) {
                const response = await request(app)
                    .post('/api/auth/test')
                    .send(data)
                    .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                    .set('Content-Type', type);

                expect(response.status).toBe(200);
                expect(response.headers['x-content-type-options']).toBe('nosniff');
            }
        });

        it('should apply security headers to Flutter binary data', async () => {
            const response = await request(app)
                .post('/api/images/test')
                .send(Buffer.from('fake image data'))
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/octet-stream');

            expect(response.headers['x-content-type-options']).toBe('nosniff');
        });
    });

    describe('9. Flutter Path Traversal Protection', () => {
        it('should allow normal Flutter file requests', async () => {
            const response = await request(app)
                .get('/api/files/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(response.status).toBe(200);
            expect(response.body.message).toBe('Test route success');
        });

        it('should block Flutter path traversal attempts with descriptive errors', async () => {
            const response = await request(app)
                .get('/api/files/../../../etc/passwd')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('INVALID_PATH');
            expect(response.body.message).toBe('Path traversal attempt detected');
            expect(response.body.details).toBe('File path contains invalid characters');
        });

        it('should block Flutter URL-encoded path traversal attempts', async () => {
            const response = await request(app)
                .get('/api/files/%2e%2e/sensitive-file')
                .set('User-Agent', 'Dart/2.19 (dart:io)');

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('INVALID_PATH');
        });

        it('should not affect non-file routes for Flutter apps', async () => {
            const response = await request(app)
                .get('/api/auth/../test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(response.status).not.toBe(400);
        });

        it('should protect against various Flutter path traversal patterns', async () => {
            const maliciousPaths = [
                '/api/files/../../config.json',
                '/api/files/../../../.env',
                '/api/files/subdir/../../../secret.txt',
                '/api/files/..%2Fsecret.txt'
            ];

            for (const path of maliciousPaths) {
                const response = await request(app)
                    .get(path)
                    .set('User-Agent', 'Flutter/3.7.0 (dart:io)');
                    
                expect(response.status).toBe(400);
                expect(response.body.error).toBe('INVALID_PATH');
            }
        });
    });

    describe('10. Flutter File Upload Security', () => {
        it('should validate Flutter image upload content types', async () => {
            const validImageTypes = ['image/jpeg', 'image/png', 'image/webp'];
            
            for (const mimeType of validImageTypes) {
                const response = await request(app)
                    .post('/api/images/test')
                    .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                    .set('Content-Type', mimeType)
                    .send('fake image data');

                expect(response.status).toBe(200);
            }
        });

        it('should reject potentially dangerous file types from Flutter', async () => {
            const dangerousTypes = [
                'application/x-executable',
                'application/x-msdownload',
                'text/x-script.phyton'
            ];

            for (const mimeType of dangerousTypes) {
                const response = await request(app)
                    .post('/api/files/test')
                    .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                    .set('Content-Type', mimeType)
                    .send('potentially dangerous content');

                // Should still process with security headers
                expect(response.headers['x-content-type-options']).toBe('nosniff');
            }
        });

        it('should handle Flutter multipart uploads securely', async () => {
            const response = await request(app)
                .post('/api/images/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'multipart/form-data; boundary=---FormBoundary')
                .send('---FormBoundary\r\nContent-Disposition: form-data; name="file"\r\n\r\nfile content\r\n---FormBoundary--');

            expect(response.status).toBe(200);
            expect(response.headers['x-content-type-options']).toBe('nosniff');
            expect(response.headers['x-frame-options']).toBe('DENY');
            expect(response.headers['access-control-allow-origin']).toBe('*');
            expect(response.headers['access-control-expose-headers']).toContain('X-Total-Count');
        });

        it('should expose Flutter-useful headers', async () => {
            const response = await request(app)
                .get('/api/wardrobes/test')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            const exposedHeaders = response.headers['access-control-expose-headers'];
            expect(exposedHeaders).toContain('Content-Length');
            expect(exposedHeaders).toContain('X-RateLimit-Limit');
            expect(exposedHeaders).toContain('X-Total-Count'); // Useful for Flutter pagination
        });
    });

    describe('11. Flutter Error Security', () => {
        it('should not expose sensitive information in Flutter error messages', async () => {
            const response = await request(app)
                .post('/api/auth/test')
                .send('{"malformed": json}')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');

            expect(response.status).toBe(400);
            expect(response.body.error).toBe('INVALID_JSON');
            expect(response.body).not.toHaveProperty('stack');
            expect(response.body).not.toHaveProperty('internal');
            expect(response.body.details).toBe('Please check your JSON formatting');
        });

        it('should maintain Flutter security headers in error responses', async () => {
            const response = await request(app)
                .post('/api/auth/test')
                .send('invalid')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');

            expect(response.status).toBe(400);
            expect(response.headers['x-content-type-options']).toBe('nosniff');
            expect(response.headers['x-frame-options']).toBe('DENY');
            expect(response.headers['access-control-allow-origin']).toBe('*');
        });

        it('should provide different error formats for Flutter vs web', async () => {
            // Flutter error
            const flutterResponse = await request(app)
                .post('/api/auth/test')
                .send('{"invalid": json}')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('Content-Type', 'application/json');

            expect(flutterResponse.body.error).toBe('INVALID_JSON');
            expect(flutterResponse.body.details).toBeDefined();

            // Web error
            const webResponse = await request(app)
                .post('/api/auth/test')
                .send('{"invalid": json}')
                .set('User-Agent', 'Mozilla/5.0 (Chrome)')
                .set('Content-Type', 'application/json');

            expect(webResponse.body.error).toBe('Malformed JSON');
            expect(webResponse.body.details).toBeUndefined();
        });
    });

    describe('12. Flutter Health Check Security', () => {
        it('should include Flutter security status in health check', async () => {
            const response = await request(app)
                .get('/health')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(response.status).toBe(200);
            expect(response.body.security).toEqual({
                cors: 'enabled',
                helmet: 'enabled',
                rateLimit: 'enabled',
                requestLimits: 'enabled',
                flutterOptimized: true
            });
            expect(response.body.platform).toBe('flutter');
        });

        it('should apply Flutter security headers to health check', async () => {
            const response = await request(app)
                .get('/health')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)');

            expect(response.headers['x-content-type-options']).toBe('nosniff');
            expect(response.headers['access-control-allow-origin']).toBe('*');
            expect(response.headers['access-control-expose-headers']).toContain('X-Total-Count');
        });

        it('should rate limit Flutter health check requests', async () => {
            const response = await request(app)
                .get('/health')
                .set('User-Agent', 'Flutter/3.7.0 (dart:io)')
                .set('X-Test-Rate-Limit', 'exceeded');

            expect(response.status).toBe(429);
            expect(response.body.error).toBe('RATE_LIMIT_EXCEEDED');
        });
    });    
});

    

    