// filepath: /backend/src/tests/security/validate.security.test.ts

/**
 * Security Test Suite for validate.ts Middleware
 *
 * This suite focuses on testing the resilience of the validation middleware
 * against common security vulnerabilities related to input processing.
 *
 * Key Areas Tested:
 * - Large payloads (potential for DoS).
 * - Deeply nested structures (potential for DoS / stack overflow).
 * - Prototype pollution attempts.
 * - Malformed or unexpected data types.
 * - Behavior with overly long strings or parameter values.
 * - Robustness of Zod's parsing and coercion in security-sensitive contexts.
 *
 * The goal is to ensure the middleware, along with Zod and Express,
 * handles potentially malicious inputs gracefully without crashing, leaking
 * sensitive information, or allowing validation bypass.
 */

// Mock ApiError similar to integration tests for consistent error objects
jest.mock('../../utils/ApiError', () => ({
  ApiError: {
    badRequest: jest.fn((message, code) => {      
      const error = new Error(message);
      error.name = 'ApiError';
      Object.defineProperties(error, {
        statusCode: { value: 400, enumerable: true, writable: true, configurable: true },
        code: { value: code || 'VALIDATION_ERROR', enumerable: true, writable: true, configurable: true },
        status: { value: 'error', enumerable: true, writable: true, configurable: true }
      });      
      return error;
    })
  }
}));

import express, { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import request from 'supertest';
import { validate } from '../../middlewares/validate';
import { ApiError } from '../../utils/ApiError'; // Though mocked, import for type usage if needed

describe('Validation Middleware Security', () => {
    let app: express.Application;

    beforeEach(() => {
        app = express();
        // Apply a body parser with a reasonable limit for most tests.
        // Specific tests for large payloads might need to adjust this or test Express's default.
        app.use(express.json({ limit: '1mb' }));
        app.use(express.urlencoded({ extended: true, limit: '1mb' }));

        // General success handler for routes
        const successHandler = (req: Request, res: Response) => {
            res.status(200).json({ status: 'success', data: req.body || req.query || req.params });
        };

        // Route-specific error handler for tests needing explicit error catching
        const routeSpecificErrorHandler: express.ErrorRequestHandler = (err, _req, res, next) => {
            if (res.headersSent) {
                return next(err);
            }
            if (err) {
                res.status(err.statusCode || 400).json({
                    status: 'error',
                    message: err.message,
                    code: err.code || 'VALIDATION_ERROR'
                });
                return;
            }
            next();
        };
        
        // Global error handler (fallback)
        app.use(((err: any, _req: Request, res: Response, _next: NextFunction) => {
            if (res.headersSent) {
                return _next(err); // Delegate to default Express error handler if headers already sent
            }
            console.error("Global Error Handler Caught in Test:", err); // For debugging tests
            res.status(err.statusCode || 500).json({
                status: 'error',
                message: err.message || 'An unexpected error occurred.',
                code: err.code || 'INTERNAL_SERVER_ERROR'
            });
        }) as express.ErrorRequestHandler);


        // Setup a basic route with a simple schema for general security tests
        const basicSchema = z.object({
            name: z.string().max(100), // Max length to prevent overly long strings
            value: z.any().optional()
        });
        app.post('/secure-test', validate(basicSchema), routeSpecificErrorHandler, successHandler);
        app.get('/secure-query-test', validate(basicSchema, 'query'), routeSpecificErrorHandler, successHandler);


        jest.clearAllMocks();
    });

    describe('Large Payloads and Resource Exhaustion', () => {
        it('should reject a string payload that violates a Zod max length for large strings', async () => {
            app = express();
            app.use(express.json({ limit: '5mb' })); // Allow large payload to reach Zod
            const largeSchemaWithMax = z.object({
                data: z.string().max(1024 * 1024 * 2) // Max 2MB string
            });
            app.post('/large-payload-max-test', validate(largeSchemaWithMax), (_req, res) => { res.status(200).json({status: 'ok'}); });
            
            // Add a global error handler that checks for specific route
            app.use(((err: any, _req: Request, res: Response, next: NextFunction) => {
                if (_req.path === '/large-payload-max-test' && err) {
                    return res.status(err.statusCode || 400).json({
                        status: 'error',
                        message: err.message,
                        code: err.code || 'VALIDATION_ERROR'
                    });
                }
                next(err);
            }) as express.ErrorRequestHandler);

            const overlyLargeString = 'a'.repeat(1024 * 1024 * 3); // 3MB string (violates max 2MB)
            const response = await request(app)
                .post('/large-payload-max-test')
                .send({ data: overlyLargeString });

            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(response.body.message).toContain('data: String must contain at most 2097152 character(s)');
        });

        it('should handle a very large string that exceeds schema max length', async () => {
            const stringLimitSchema = z.object({ comment: z.string().max(1000) });
            app.post('/string-limit-test', validate(stringLimitSchema), (req,res) => { res.status(200).json({status:'ok'}); });
             app.use(((err: any, _req: Request, res: Response, _next: NextFunction) => {
                 res.status(err.statusCode || 400).json({ message: err.message, code: err.code || 'VALIDATION_ERROR' });
            }) as express.ErrorRequestHandler);

            const overlyLongString = 'a'.repeat(2000);
            const response = await request(app)
                .post('/string-limit-test')
                .send({ comment: overlyLongString });

            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(response.body.message).toContain('comment: String must contain at most 1000 character(s)');
        });


        it('should handle deeply nested JSON objects gracefully', async () => {
            const nestedSchema = z.object({
                level1: z.object({
                    level2: z.object({
                        level3: z.string().optional()
                    }).optional()
                }).optional()
            });
            app.post('/deep-nest-test', validate(nestedSchema), (req,res) => { res.status(200).json({status:'ok'}); });
            app.use(((err: any, _req: Request, res: Response, _next: NextFunction) => {
                 res.status(err.statusCode || 400).json({ message: err.message, code: err.code || 'VALIDATION_ERROR' });
            }) as express.ErrorRequestHandler);

            let deepObject: any = { value: "leaf" };
            for (let i = 0; i < 500; i++) { // Create 500 levels of nesting
                deepObject = { nested: deepObject };
            }

            const response = await request(app)
                .post('/deep-nest-test')
                .send({ level1: { level2: { level3: deepObject } } }); // This structure doesn't match schema. Let's send valid but deep.
            
            // Corrected deep object matching schema structure (simplified for test)
            let validDeepObject: any = {};
            let currentLevel = validDeepObject;
            for(let i=0; i<30; i++){ // Zod might have its own nesting limits for parsing. Node's default is ~1000 for call stack.
                currentLevel.level1 = { level2: { level3: "deep" } };
                if (i < 29) currentLevel.level1.level2.level3 = {}; // Make it an object to nest further
                currentLevel = currentLevel.level1.level2.level3;
            }
            // This construction is flawed. Let's simplify the test to send a deeply nested object
            // and ensure Zod/Express don't crash.
            // The schema itself doesn't allow infinite nesting.

            const simpleDeepSchema = z.object({}).passthrough(); // Allow any object structure for this DoS test
             app.post('/deep-dos-test', validate(simpleDeepSchema), (_req,res) => { res.status(200).json({status:'ok'}); });

            const responseDos = await request(app)
                .post('/deep-dos-test')
                .send(deepObject); // Send the 500-level nested object

            // Expect a 400 if Zod has internal limits or if Express's parser has issues,
            // or 200 if it handles it (unlikely for extreme depth without limits).
            // Most importantly, not a 500 or crash.
            // Node's JSON.parse has limits, Express relies on this.
            expect(responseDos.status).not.toBe(500);
            // Depending on Express/Node versions, this might be a 400 due to JSON parsing limits for depth.
            // Or if Zod processes it, it might hit Zod's own limits.
            // For this test, we primarily care it doesn't crash the server.
            // A specific status like 400 is good. If it's 200, it means it was processed, which is less likely for extreme depth.
            // Let's assume it will be rejected by the parser or Zod before becoming a DoS.
             if (responseDos.status !== 200) { // If not 200, it should be a client error
                expect(responseDos.status).toBeGreaterThanOrEqual(400);
                expect(responseDos.status).toBeLessThan(500);
            }
        });
    });

    describe('Prototype Pollution', () => {
        it('should not allow prototype pollution via JSON body and process valid part of payload', async () => {
            // Schema for /secure-test requires 'name'. Let's make it optional for this test's first part
            // or provide it. For now, let's adjust the schema used by /secure-test for this test case.
            // Better: define a new route for this specific pollution test with an appropriate schema.

            const pollutionTestSchema = z.object({
                name: z.string().optional(), // Make name optional or provide it
                value: z.any().optional()
            });
            // Re-define /secure-test for this test block or use a new route
            app.post('/pollution-secure-test', validate(pollutionTestSchema), (_req, res, next) => {
                // Check if req.body itself has __proto__ (it shouldn't after Zod parsing)
                if (Object.prototype.hasOwnProperty.call(_req.body, '__proto__')) {
                    res.status(500).json({ message: "Pollution detected on req.body instance" });
                    return;
                }
                res.status(200).json({ status: 'success', data: _req.body });
            });
            // Add a specific error handler that checks for the route path
            app.use(((err: any, _req: Request, res: Response, next: NextFunction) => {
                if (_req.path === '/pollution-secure-test' && err) {
                    return res.status(err.statusCode || 400).json({
                        status: 'error',
                        message: err.message,
                        code: err.code || 'VALIDATION_ERROR'
                    });
                }
                next(err);
            }) as express.ErrorRequestHandler);


            const pollutionPayload = JSON.parse('{"name": "test", "__proto__": {"isPolluted": true}}');
            
            const response = await request(app)
                .post('/pollution-secure-test') // Use the new or adjusted route
                .send(pollutionPayload);

            expect(response.status).toBe(200); // Should now pass schema validation
            expect(response.body.data).toBeDefined();
            expect(response.body.data.name).toBe("test");
            expect(Object.prototype.hasOwnProperty.call(response.body.data, '__proto__')).toBe(false);


            // The rest of the pollution check on a separate endpoint can remain similar,
            // but ensure its schema also accommodates the payload.
            const pollutionCheckSchema = z.object({
                name: z.string().optional(), // Or match the payload being sent
                // If __proto__ is part of the payload, Zod will strip it if not in schema.
            });
            app.post('/pollution-check-specific', validate(pollutionCheckSchema), (req, res) => {
                const obj:any = {};
                let serverSidePollutionDetected = false;
                if (obj.isPolluted !== undefined || Object.prototype.hasOwnProperty.call(Object.prototype, 'isPolluted')) {
                    serverSidePollutionDetected = true;
                }
                
                // Zod should return a new object. The __proto__ key from input should not be on req.body.
                const bodyHasProtoKey = Object.prototype.hasOwnProperty.call(req.body, '__proto__');

                res.status(200).json({
                    serverSidePollutionDetected,
                    bodyHasProtoKey,
                    bodyData: req.body
                });
                // Clean up global pollution if it happened for test isolation
                delete (Object.prototype as any).isPolluted;
            });

            const pollutionResponse = await request(app)
                .post('/pollution-check-specific')
                .send(pollutionPayload); // Sending {"name": "test", "__proto__": {"isPolluted": true}}

            expect(pollutionResponse.status).toBe(200);
            expect(pollutionResponse.body.serverSidePollutionDetected).toBe(false);
            expect(pollutionResponse.body.bodyHasProtoKey).toBe(false);
            expect(pollutionResponse.body.bodyData.name).toBe("test");


            const objAfter: any = {};
            expect(objAfter.isPolluted).toBeUndefined(); // Final check
        });
    });

    describe('Malformed and Unexpected Inputs', () => {
        it('should handle non-JSON body when JSON is expected', async () => {
            const response = await request(app)
                .post('/secure-test')
                .set('Content-Type', 'text/plain')
                .send('this is not json');

            // Express's express.json() middleware will likely reject this first.
            expect(response.status).toBe(400); // Or 415 Unsupported Media Type, or other client error
            expect(response.body.message).toBeDefined();
        });

        it('should handle array as top-level JSON body when an object is expected by schema', async () => {
            const response = await request(app)
                .post('/secure-test') // basicSchema expects an object { name: string }
                .send([{ name: "unexpected array" }]);

            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(response.body.message).toContain("Expected object, received array");
        });

        it('should handle null as JSON body, which body-parser rejects before Zod validation', async () => {
            const localApp = express();
            localApp.use(express.json()); // Body parser

            localApp.post('/null-body-test-for-parser-error', // Renamed route for clarity if needed
                validate(z.object({ name: z.string() })), // This validate middleware won't be reached
                (_req, res) => { res.status(200).json({ status: 'success' }); }
            );
            // Error handler for this localApp
            localApp.use(((err: any, _req: Request, res: Response, _next: NextFunction) => {
                // Respond based on the properties of the body-parser error
                res.status(err.statusCode || 400).json({
                    status: 'error',
                    message: err.message, // Message from body-parser
                    // 'code' will be undefined from body-parser, or we can assign a custom one
                    type: err.type // body-parser provides 'type'
                });
                return;
            }) as express.ErrorRequestHandler);

            const response = await request(localApp)
                .post('/null-body-test-for-parser-error')
                .set('Content-Type', 'application/json')
                .send(null as any); // Sending actual null

            expect(response.status).toBe(400); // body-parser sets statusCode 400
            // Assert based on what body-parser provides
            expect(response.body.message).toContain("Unexpected token"); // Or a more specific message if consistent
            expect(response.body.type).toBe('entity.parse.failed'); // Key indicator of body-parser error
            expect(response.body.code).toBeUndefined(); // body-parser error doesn't have our custom 'code'
        });

        it('should handle the string "null" as malformed JSON body', async () => {
            // Use a local app for this test
            const localApp = express();
            localApp.use(express.json());

            localApp.post('/malformed-null-body-test',
                validate(z.object({ name: z.string() })),
                (_req: express.Request, res: express.Response): void => { res.status(200).json({ status: 'success' }); }
            );
            // Error handler specific to this localApp
            localApp.use(((err: any, _req: Request, res: Response, _next: NextFunction): void => {
                if (err.type === 'entity.parse.failed') {
                    void res.status(err.statusCode || 400).json({
                        status: 'error',
                        message: err.message,
                        code: 'BODY_PARSE_FAILED'
                    });
                    return;
                }
                void res.status(err.statusCode || 500).json({ // Fallback for unexpected errors
                    status: 'error',
                    message: err.message,
                    code: 'UNEXPECTED_LOCAL_ERROR'
                });
                return; // Prevent returning the response object
            }) as express.ErrorRequestHandler);

            const response = await request(localApp)
                .post('/malformed-null-body-test')
                .set('Content-Type', 'application/json')
                .send('"null"'); // Send the string "null"

            expect(response.status).toBe(400);
            expect(response.body.code).toBe('BODY_PARSE_FAILED');
            expect(response.body.message).toBeDefined();
        });

        it('should handle overly long query parameter values', async () => {
            const longQueryVal = 'a'.repeat(2048); // URLs have limits, often around 2KB.
            const response = await request(app)
                .get(`/secure-query-test?name=${longQueryVal}`);
            
            // The schema for /secure-query-test has name: z.string().max(100)
            expect(response.status).toBe(400);
            expect(response.body.code).toBe('VALIDATION_ERROR');
            expect(response.body.message).toContain('name: String must contain at most 100 character(s)');
        });
    });

    // Add more tests:
    // - SQL injection-like strings (though Zod primarily validates structure/type, not content for XSS/SQLi unless regex is used)
    // - Strings that look like file paths or commands.
    // - Test with schemas that use z.coerce and try to break coercion.
    // - Test with schemas that use .regex() and provide ReDoS vulnerable strings (if applicable to user's schemas).
});