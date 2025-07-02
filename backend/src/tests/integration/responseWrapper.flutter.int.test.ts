// backend/src/__tests__/integration/responseWrapper.integration.test.ts
import { Request, Response, NextFunction } from 'express';
import express from 'express';
import request from 'supertest';
import {
  responseWrapperMiddleware,
  ResponseMessages,
  ResponseUtils,
  TypedResponse
} from '../../utils/responseWrapper';

describe('Response Wrapper Integration Tests', () => {
    let app: express.Application;

    beforeEach(() => {
        // Create fresh Express app for each test
        app = express();
        app.use(express.json());
        app.use(responseWrapperMiddleware);
    });

    describe('Complete Response Flow Integration', () => {
        beforeEach(() => {
            // Setup test routes that demonstrate different response patterns
            
            // Basic success response
            app.get('/api/test/success', (req: Request, res: Response) => {
                const data = { id: 1, name: 'Test User', email: 'test@example.com' };
                res.success(data, { message: 'User retrieved successfully' });
            });

            // Created response (201)
            app.post('/api/test/create', (req: Request, res: Response) => {
                const userData = req.body;
                const newUser = { id: Date.now(), ...userData };
                res.created(newUser, { message: ResponseMessages.CREATED });
            });

            // Accepted response (202) for async operations
            app.post('/api/test/async', (req: Request, res: Response) => {
                const taskData = { taskId: `task_${Date.now()}`, status: 'queued' };
                res.accepted(taskData, { message: 'Task queued for processing' });
            });

            // No content response (204)
            app.delete('/api/test/delete/:id', (req: Request, res: Response) => {
                // Simulate deletion
                res.noContent();
            });

            // Paginated response
            app.get('/api/test/users', (req: Request, res: Response) => {
                const { page, limit } = ResponseUtils.validatePagination(req.query.page, req.query.limit);
                
                // Mock data
                const totalUsers = 150;
                const users = Array.from({ length: Math.min(limit, totalUsers) }, (_, i) => ({
                    id: (page - 1) * limit + i + 1,
                    name: `User ${(page - 1) * limit + i + 1}`,
                    email: `user${(page - 1) * limit + i + 1}@example.com`
                }));

                const pagination = ResponseUtils.createPagination(page, limit, totalUsers);

                res.successWithPagination(users, pagination, {
                    message: ResponseMessages.LIST_RETRIEVED
                });
            });

            // Response with meta data (filters, sorting, caching)
            app.get('/api/test/search', (req: Request, res: Response) => {
                const { page, limit } = ResponseUtils.validatePagination(req.query.page, req.query.limit);
                const query = req.query.q as string || '';
                const sortBy = req.query.sortBy as string || 'name';
                const order = req.query.order as 'asc' | 'desc' || 'asc';
                
                // Mock search results
                const results = [
                    { id: 1, name: 'John Doe', relevance: 0.95 },
                    { id: 2, name: 'Jane Smith', relevance: 0.87 }
                ];

                const pagination = ResponseUtils.createPagination(page, limit, results.length);

                res.successWithPagination(results, pagination, {
                    message: ResponseMessages.SEARCH_COMPLETED,
                    meta: {
                        query,
                        sort: { field: sortBy, order },
                        cached: false,
                        processingTime: 25
                    }
                });
            });

            // Custom status code
            app.post('/api/test/custom-status', (req: Request, res: Response) => {
                const data = { message: 'Custom operation completed' };
                res.success(data, { statusCode: 207, message: 'Multi-status response' });
            });

            // Using TypedResponse helpers
            app.get('/api/test/typed-user', (req: Request, res: Response) => {
                const user = { id: 1, name: 'John Doe', email: 'john@example.com' };
                const responseData = TypedResponse.user.profile(user);
                res.success(responseData.data, { message: responseData.message });
            });

            app.post('/api/test/typed-auth', (req: Request, res: Response) => {
                const authData = { 
                    user: { id: 1, email: 'user@example.com' }, 
                    token: 'jwt-token-123',
                    refreshToken: 'refresh-token-456'
                };
                const responseData = TypedResponse.auth.login(authData);
                res.success(responseData.data, { message: responseData.message });
            });

            // Error handling (should still work with existing error handler)
            app.get('/api/test/error', (req: Request, res: Response, next: NextFunction) => {
                const error = new Error('Test error for integration');
                next(error);
            });

            // Large data response
            app.get('/api/test/large-data', (req: Request, res: Response) => {
                const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
                    id: i,
                    name: `Item ${i}`,
                    description: 'Lorem ipsum '.repeat(10),
                    metadata: {
                        created: new Date().toISOString(),
                        tags: ['tag1', 'tag2', 'tag3']
                    }
                }));

                res.success(largeDataset, { 
                    message: 'Large dataset retrieved',
                    meta: { count: largeDataset.length }
                });
            });

            // Response with special characters and unicode
            app.get('/api/test/unicode', (req: Request, res: Response) => {
                const unicodeData = {
                    name: '🚀 Unicode Test ñáéíóú',
                    chinese: '测试数据',
                    arabic: 'اختبار البيانات',
                    emoji: '😀😍🎉🚀💻',
                    mathematical: '∑∆∏∫√≈≠≤≥'
                };

                res.success(unicodeData, { 
                    message: 'Unicode data retrieved successfully' 
                });
            });

            // File upload simulation
            app.post('/api/test/upload', (req: Request, res: Response) => {
                const fileInfo = {
                    id: Date.now(),
                    filename: 'test-file.jpg',
                    originalName: 'my-photo.jpg',
                    size: 1024567,
                    mimetype: 'image/jpeg',
                    uploadedAt: new Date().toISOString()
                };

                const responseData = TypedResponse.file.uploaded(fileInfo);
                res.created(responseData.data, { message: responseData.message });
            });
        });

        describe('Basic Response Patterns', () => {
            it('should handle basic success response', async () => {
                const response = await request(app)
                .get('/api/test/success')
                .expect(200);

                expect(response.body).toMatchObject({
                success: true,
                data: {
                    id: 1,
                    name: 'Test User',
                    email: 'test@example.com'
                },
                message: 'User retrieved successfully',
                timestamp: expect.any(String),
                requestId: expect.any(String),
                meta: {
                    processingTime: expect.any(Number)
                }
                });

                // Validate timestamp format
                expect(new Date(response.body.timestamp)).toBeInstanceOf(Date);
                
                // Validate request ID format
                expect(response.body.requestId).toMatch(/^req_\d+_[a-z0-9]{9}$/);
            });

            it('should handle created response (201)', async () => {
                const userData = { name: 'New User', email: 'new@example.com' };
                
                const response = await request(app)
                .post('/api/test/create')
                .send(userData)
                .expect(201);

                expect(response.body).toMatchObject({
                    success: true,
                    data: {
                        id: expect.any(Number),
                        name: 'New User',
                        email: 'new@example.com'
                    },
                    message: ResponseMessages.CREATED,
                    timestamp: expect.any(String),
                    requestId: expect.any(String),
                    meta: {
                        processingTime: expect.any(Number)
                    }
                });
            });

            it('should handle accepted response (202)', async () => {
                const response = await request(app)
                .post('/api/test/async')
                .send({ operation: 'process-data' })
                .expect(202);

                expect(response.body).toMatchObject({
                    success: true,
                    data: {
                        taskId: expect.stringMatching(/^task_\d+$/),
                        status: 'queued'
                    },
                    message: 'Task queued for processing',
                    timestamp: expect.any(String),
                    requestId: expect.any(String),
                    meta: {
                        processingTime: expect.any(Number)
                    }
                });
            });

            it('should handle no content response (204)', async () => {
                const response = await request(app)
                .delete('/api/test/delete/123')
                .expect(204);

                expect(response.body).toEqual({});
            });

            it('should handle custom status codes', async () => {
                const response = await request(app)
                .post('/api/test/custom-status')
                .send({ data: 'test' })
                .expect(207);

                expect(response.body).toMatchObject({
                    success: true,
                    data: { message: 'Custom operation completed' },
                    message: 'Multi-status response',
                    timestamp: expect.any(String),
                    requestId: expect.any(String),
                    meta: {
                        processingTime: expect.any(Number)
                    }
                });
            });
        });

        describe('Paginated Responses', () => {
            it('should handle basic pagination', async () => {
                const response = await request(app)
                .get('/api/test/users?page=1&limit=10')
                .expect(200);

                expect(response.body).toMatchObject({
                success: true,
                data: expect.arrayContaining([
                    expect.objectContaining({
                    id: expect.any(Number),
                    name: expect.any(String),
                    email: expect.any(String)
                    })
                ]),
                message: ResponseMessages.LIST_RETRIEVED,
                meta: {
                    pagination: {
                    page: 1,
                    limit: 10,
                    total: 150,
                    totalPages: 15,
                    hasNext: true,
                    hasPrev: false
                    },
                    processingTime: expect.any(Number)
                },
                timestamp: expect.any(String),
                requestId: expect.any(String)
                });

                expect(response.body.data).toHaveLength(10);
            });

            it('should handle pagination with different pages', async () => {
                const response = await request(app)
                .get('/api/test/users?page=2&limit=5')
                .expect(200);

                expect(response.body.meta.pagination).toMatchObject({
                    page: 2,
                    limit: 5,
                    total: 150,
                    totalPages: 30,
                    hasNext: true,
                    hasPrev: true
                });

                expect(response.body.data).toHaveLength(5);
                expect(response.body.data[0].id).toBe(6); // First item on page 2
            });

            it('should handle last page pagination', async () => {
                const response = await request(app)
                .get('/api/test/users?page=15&limit=10')
                .expect(200);

                expect(response.body.meta.pagination).toMatchObject({
                    page: 15,
                    limit: 10,
                    total: 150,
                    totalPages: 15,
                    hasNext: false,
                    hasPrev: true
                });

                expect(response.body.data).toHaveLength(10);
            });

            it('should validate and correct invalid pagination parameters', async () => {
                const response = await request(app)
                .get('/api/test/users?page=-1&limit=200')
                .expect(200);

                expect(response.body.meta.pagination).toMatchObject({
                page: 1, // Corrected from -1
                limit: 100, // Corrected from 200 (max limit)
                total: 150,
                totalPages: 2,
                hasNext: true,
                hasPrev: false
                });
            });
        });

        describe('Advanced Response Features', () => {
            it('should handle search with meta data', async () => {
                const response = await request(app)
                .get('/api/test/search?q=john&page=1&limit=10&sortBy=relevance&order=desc')
                .expect(200);

                expect(response.body).toMatchObject({
                success: true,
                data: expect.any(Array),
                message: ResponseMessages.SEARCH_COMPLETED,
                meta: {
                    query: 'john',
                    sort: {
                    field: 'relevance',
                    order: 'desc'
                    },
                    pagination: expect.any(Object),
                    cached: false,
                    processingTime: expect.any(Number)
                },
                timestamp: expect.any(String),
                requestId: expect.any(String)
                });
            });

            it('should include processing time in meta', async () => {
                const response = await request(app)
                .get('/api/test/users')
                .expect(200);

                expect(response.body.meta.processingTime).toBeGreaterThanOrEqual(0);
                expect(response.body.meta.processingTime).toBeLessThan(1000); // Should be reasonably fast
            });

            it('should handle large data responses efficiently', async () => {
                const start = Date.now();
                
                const response = await request(app)
                .get('/api/test/large-data')
                .expect(200);

                const duration = Date.now() - start;

                expect(response.body).toMatchObject({
                success: true,
                data: expect.any(Array),
                message: 'Large dataset retrieved',
                meta: {
                    count: 1000,
                    processingTime: expect.any(Number)
                }
                });

                expect(response.body.data).toHaveLength(1000);
                expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
            });

            it('should handle unicode and special characters', async () => {
                const response = await request(app)
                .get('/api/test/unicode')
                .expect(200);

                expect(response.body.data).toMatchObject({
                name: '🚀 Unicode Test ñáéíóú',
                chinese: '测试数据',
                arabic: 'اختبار البيانات',
                emoji: '😀😍🎉🚀💻',
                mathematical: '∑∆∏∫√≈≠≤≥'
                });

                // Ensure proper encoding
                expect(response.headers['content-type']).toMatch(/application\/json/);
            });
        });

        describe('TypedResponse Integration', () => {
            it('should work with TypedResponse.user helpers', async () => {
                const response = await request(app)
                .get('/api/test/typed-user')
                .expect(200);

                expect(response.body).toMatchObject({
                success: true,
                data: {
                    id: 1,
                    name: 'John Doe',
                    email: 'john@example.com'
                },
                message: ResponseMessages.RETRIEVED,
                timestamp: expect.any(String),
                requestId: expect.any(String),
                meta: {
                    processingTime: expect.any(Number)
                }
                });
            });

            it('should work with TypedResponse.auth helpers', async () => {
                const response = await request(app)
                .post('/api/test/typed-auth')
                .send({ email: 'user@example.com', password: 'password' })
                .expect(200);

                expect(response.body).toMatchObject({
                success: true,
                data: {
                    user: {
                    id: 1,
                    email: 'user@example.com'
                    },
                    token: 'jwt-token-123',
                    refreshToken: 'refresh-token-456'
                },
                message: ResponseMessages.LOGIN_SUCCESS,
                timestamp: expect.any(String),
                requestId: expect.any(String),
                meta: {
                    processingTime: expect.any(Number)
                }
                });
            });

            it('should work with TypedResponse.file helpers', async () => {
                const response = await request(app)
                .post('/api/test/upload')
                .send({ filename: 'test.jpg' })
                .expect(201);

                expect(response.body).toMatchObject({
                success: true,
                data: {
                    id: expect.any(Number),
                    filename: 'test-file.jpg',
                    originalName: 'my-photo.jpg',
                    size: 1024567,
                    mimetype: 'image/jpeg',
                    uploadedAt: expect.any(String)
                },
                message: ResponseMessages.FILE_UPLOADED,
                timestamp: expect.any(String),
                requestId: expect.any(String),
                meta: {
                    processingTime: expect.any(Number)
                }
                });
            });
        });

        describe('Request ID Handling', () => {
            it('should generate unique request IDs for concurrent requests', async () => {
                const promises = Array.from({ length: 10 }, () =>
                request(app).get('/api/test/success').expect(200)
                );

                const responses = await Promise.all(promises);
                const requestIds = responses.map(r => r.body.requestId);

                // All request IDs should be unique
                const uniqueIds = new Set(requestIds);
                expect(uniqueIds.size).toBe(requestIds.length);

                // All should match the expected pattern
                requestIds.forEach(id => {
                expect(id).toMatch(/^req_\d+_[a-z0-9]{9}$/);
                });
            });

            it('should use provided request ID from headers', async () => {
                const customRequestId = 'custom-req-id-123';

                const response = await request(app)
                .get('/api/test/success')
                .set('X-Request-ID', customRequestId)
                .expect(200);

                expect(response.body.requestId).toBe(customRequestId);
            });

            it('should handle malformed request IDs gracefully', async () => {
                const malformedId = '<script>alert("xss")</script>';

                const response = await request(app)
                .get('/api/test/success')
                .set('X-Request-ID', malformedId)
                .expect(200);

                expect(response.body.requestId).toBe(malformedId);
                expect(response.body.success).toBe(true);
            });
        });

        describe('Performance and Scalability', () => {
            it('should handle multiple concurrent requests efficiently', async () => {
                const concurrentRequests = 20;
                const promises = Array.from({ length: concurrentRequests }, () =>
                request(app).get('/api/test/users?page=1&limit=5').expect(200)
                );

                const start = Date.now();
                const responses = await Promise.all(promises);
                const duration = Date.now() - start;

                // All requests should succeed
                responses.forEach(response => {
                expect(response.body.success).toBe(true);
                expect(response.body.data).toHaveLength(5);
                });

                // Should complete within reasonable time
                expect(duration).toBeLessThan(5000);
            });

            it('should maintain consistent response structure under load', async () => {
                const responses = await Promise.all([
                request(app).get('/api/test/success').expect(200),
                request(app).post('/api/test/create').send({ name: 'Test' }).expect(201),
                request(app).get('/api/test/users?page=1&limit=5').expect(200),
                request(app).post('/api/test/async').send({}).expect(202),
                request(app).get('/api/test/unicode').expect(200)
                ]);

                responses.forEach(response => {
                expect(response.body.success).toBe(true);
                expect(response.body.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
                expect(response.body.requestId).toMatch(/^req_\d+_[a-z0-9]{9}$|^[a-zA-Z0-9\-_]+$/);
                expect(response.body.meta.processingTime).toBeGreaterThanOrEqual(0);
                });
            });

            it('should handle rapid sequential requests', async () => {
                const requestCount = 50;
                const responses: any[] = [];

                for (let i = 0; i < requestCount; i++) {
                const response = await request(app)
                    .get('/api/test/success')
                    .expect(200);
                
                responses.push(response.body);
                }

                // All responses should be valid
                responses.forEach((body, index) => {
                expect(body.success).toBe(true);
                expect(body.data.id).toBe(1);
                expect(body.requestId).toBeDefined();
                });

                // Request IDs should all be unique
                const requestIds = responses.map(r => r.requestId);
                const uniqueIds = new Set(requestIds);
                expect(uniqueIds.size).toBe(requestIds.length);
            });
        });

        describe('Edge Cases and Error Scenarios', () => {
            it('should handle empty data gracefully', async () => {
                app.get('/api/test/empty', (req: Request, res: Response) => {
                    res.success(null);
                });

                const response = await request(app)
                .get('/api/test/empty')
                .expect(200);

                expect(response.body).toMatchObject({
                success: true,
                data: null,
                timestamp: expect.any(String),
                requestId: expect.any(String),
                meta: {
                    processingTime: expect.any(Number)
                }
                });
            });

            it('should handle array data', async () => {
                app.get('/api/test/array', (req: Request, res: Response) => {
                const data = [1, 2, 3, 'test', { nested: true }];
                    res.success(data);
                });

                const response = await request(app)
                .get('/api/test/array')
                .expect(200);

                expect(response.body.data).toEqual([1, 2, 3, 'test', { nested: true }]);
            });

            it('should handle boolean and number data', async () => {
                app.get('/api/test/primitives', (req: Request, res: Response) => {
                    res.success({ 
                        boolean: true, 
                        number: 42, 
                        zero: 0, 
                        negative: -1,
                        float: 3.14
                    });
                });

                const response = await request(app)
                .get('/api/test/primitives')
                .expect(200);

                expect(response.body.data).toEqual({
                    boolean: true,
                    number: 42,
                    zero: 0,
                    negative: -1,
                    float: 3.14
                });
            });

            it('should handle deeply nested objects', async () => {
                app.get('/api/test/nested', (req: Request, res: Response) => {
                const deepData = {
                    level1: {
                    level2: {
                        level3: {
                        level4: {
                            value: 'deep nested value',
                            array: [1, 2, { nested: 'item' }]
                        }
                        }
                    }
                    }
                };
                res.success(deepData);
                });

                const response = await request(app)
                .get('/api/test/nested')
                .expect(200);

                expect(response.body.data.level1.level2.level3.level4.value).toBe('deep nested value');
            });
        });

        describe('Middleware Chain Integration', () => {
            it('should work with additional middleware in the chain', async () => {
                // Add a custom middleware that modifies request
                app.use('/api/test/middleware', (req: Request, res: Response, next: NextFunction) => {
                    (req as any).customData = { middleware: 'executed' };
                    next();
                });

                app.get('/api/test/middleware/test', (req: Request, res: Response) => {
                const customData = (req as any).customData;
                    res.success(customData, { message: 'Middleware test successful' });
                });

                const response = await request(app)
                .get('/api/test/middleware/test')
                .expect(200);

                expect(response.body).toMatchObject({
                    success: true,
                    data: { middleware: 'executed' },
                    message: 'Middleware test successful',
                    meta: {
                        processingTime: expect.any(Number)
                    }
                });
            });

            it('should maintain response wrapper functionality after other middleware', async () => {
                // Add body parsing and custom middleware
                app.use('/api/test/complex', express.urlencoded({ extended: true }));
                app.use('/api/test/complex', (req: Request, res: Response, next: NextFunction) => {
                res.setHeader('X-Custom-Header', 'test-value');
                next();
                });

                app.post('/api/test/complex/endpoint', (req: Request, res: Response) => {
                    res.created(req.body, { message: 'Complex middleware chain successful' });
                });

                const response = await request(app)
                .post('/api/test/complex/endpoint')
                .send({ test: 'data' })
                .expect(201);

                expect(response.body).toMatchObject({
                    success: true,
                    data: { test: 'data' },
                    message: 'Complex middleware chain successful',
                    meta: {
                        processingTime: expect.any(Number)
                    }
                });

                expect(response.headers['x-custom-header']).toBe('test-value');
            });
        });

        describe('Real-world Scenario Simulation', () => {
            it('should simulate a complete user management flow', async () => {
                // Create user
                const createResponse = await request(app)
                .post('/api/test/create')
                .send({ name: 'John Doe', email: 'john@example.com' })
                .expect(201);

                expect(createResponse.body.success).toBe(true);
                expect(createResponse.body.data.name).toBe('John Doe');

                // List users
                const listResponse = await request(app)
                .get('/api/test/users?page=1&limit=10')
                .expect(200);

                expect(listResponse.body.success).toBe(true);
                expect(listResponse.body.meta.pagination).toBeDefined();

                // Search users
                const searchResponse = await request(app)
                .get('/api/test/search?q=john&sortBy=name&order=asc')
                .expect(200);

                expect(searchResponse.body.success).toBe(true);
                expect(searchResponse.body.meta.query).toBe('john');
                expect(searchResponse.body.meta.sort.field).toBe('name');
            });

            it('should simulate file upload and processing workflow', async () => {
                // Upload file
                const uploadResponse = await request(app)
                .post('/api/test/upload')
                .send({ file: 'binary-data' })
                .expect(201);

                expect(uploadResponse.body.success).toBe(true);
                expect(uploadResponse.body.message).toBe(ResponseMessages.FILE_UPLOADED);

                // Start async processing
                const processResponse = await request(app)
                .post('/api/test/async')
                .send({ fileId: uploadResponse.body.data.id, operation: 'resize' })
                .expect(202);

                expect(processResponse.body.success).toBe(true);
                expect(processResponse.body.data.status).toBe('queued');
            });

            it('should handle authentication flow simulation', async () => {
                const authResponse = await request(app)
                .post('/api/test/typed-auth')
                .send({ email: 'user@example.com', password: 'secure-password' })
                .expect(200);

                expect(authResponse.body).toMatchObject({
                success: true,
                data: {
                    user: expect.objectContaining({
                    id: expect.any(Number),
                    email: 'user@example.com'
                    }),
                    token: expect.any(String),
                    refreshToken: expect.any(String)
                },
                message: ResponseMessages.LOGIN_SUCCESS
                });
            });
        });
    });

    describe('Consistency with Error Handler', () => {
        let errorApp: express.Application;

        beforeEach(() => {
            // Create a separate app instance for error handler testing
            errorApp = express();
            errorApp.use(express.json());
            errorApp.use(responseWrapperMiddleware);

            // Setup basic success route
            errorApp.get('/api/test/success', (req: Request, res: Response) => {
                const data = { id: 1, name: 'Test User', email: 'test@example.com' };
                res.success(data, { message: 'User retrieved successfully' });
            });

            // Add a route that throws an error to test error handler integration
            errorApp.get('/api/test/trigger-error', (req: Request, res: Response, next: NextFunction) => {
                const error = new Error('Integration test error');
                next(error);
            });

            // Mock error handler for testing
            errorApp.use((err: any, req: Request, res: Response, next: NextFunction) => {
                res.status(500).json({
                    success: false,
                    error: {
                    code: 'INTERNAL_SERVER_ERROR',
                    message: err.message,
                    statusCode: 500,
                    timestamp: new Date().toISOString(),
                    requestId: req.get('X-Request-ID') || `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
                    }
                });
            });
        });

        it('should maintain consistent structure between success and error responses', async () => {
            // Test success response
            const successResponse = await request(errorApp)
            .get('/api/test/success')
            .expect(200);

            // Test error response
            const errorResponse = await request(errorApp)
            .get('/api/test/trigger-error')
            .expect(500);

            // Both should have consistent top-level structure
            expect(successResponse.body.success).toBe(true);
            expect(errorResponse.body.success).toBe(false);

            // Both should have timestamp and requestId
            expect(successResponse.body.timestamp).toBeDefined();
            expect(errorResponse.body.error.timestamp).toBeDefined();
            expect(successResponse.body.requestId).toBeDefined();
            expect(errorResponse.body.error.requestId).toBeDefined();

            // Timestamp formats should be consistent
            expect(successResponse.body.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
            expect(errorResponse.body.error.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
        });

        it('should use the same request ID format', async () => {
            const customRequestId = 'integration-test-id-123';

            const successResponse = await request(errorApp)
            .get('/api/test/success')
            .set('X-Request-ID', customRequestId)
            .expect(200);

            const errorResponse = await request(errorApp)
            .get('/api/test/trigger-error')
            .set('X-Request-ID', customRequestId)
            .expect(500);

            expect(successResponse.body.requestId).toBe(customRequestId);
            expect(errorResponse.body.error.requestId).toBe(customRequestId);
        });
    });
});