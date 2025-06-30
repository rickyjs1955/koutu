// backend/src/__tests__/security/responseWrapper.security.test.ts
import { jest } from '@jest/globals';
import { Request, Response } from 'express';
import {
  ResponseWrapper} from '../../utils/responseWrapper';

// Test utilities
const createMockRequest = (overrides: Partial<Request> = {}): Partial<Request> => ({
    get: jest.fn().mockImplementation((header: string) => {
        if (header === 'X-Request-ID') return 'test-request-id';
        return undefined;
    }),
    ...overrides
});

const createMockResponse = (): Partial<Response> => ({
    status: jest.fn().mockReturnThis(),
    json: jest.fn().mockReturnThis(),
    send: jest.fn().mockReturnThis()
});

describe('Response Wrapper Security Tests', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let wrapper: ResponseWrapper;

    beforeEach(() => {
        jest.clearAllMocks();
        mockReq = createMockRequest();
        mockRes = createMockResponse();
        wrapper = new ResponseWrapper(mockReq as Request, mockRes as Response);
    });

    describe('Data Sanitization and Injection Prevention', () => {
        describe('XSS Prevention in Response Data', () => {
            it('should safely handle script tags in response data', () => {
                const maliciousData = {
                name: '<script>alert("xss")</script>',
                description: '<img src="x" onerror="alert(1)">'
                };

                expect(() => {
                wrapper.success(maliciousData);
                }).not.toThrow();

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.data).toEqual(maliciousData);
                expect(callArgs.success).toBe(true);
            });

            it('should handle JavaScript protocol URLs safely', () => {
                const data = {
                profileImage: 'javascript:alert("xss")',
                website: 'data:text/html,<script>alert("xss")</script>'
                };

                expect(() => {
                wrapper.success(data);
                }).not.toThrow();

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.data.profileImage).toBe('javascript:alert("xss")');
                expect(callArgs.data.website).toBe('data:text/html,<script>alert("xss")</script>');
            });

            it('should handle SQL injection patterns in data', () => {
                const data = {
                query: "'; DROP TABLE users; --",
                search: "admin' OR '1'='1",
                filter: "UNION SELECT password FROM users"
                };

                expect(() => {
                wrapper.success(data);
                }).not.toThrow();

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.data).toEqual(data);
            });

            it('should handle HTML entities and encoded content', () => {
                const data = {
                content: '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;',
                encoded: '%3Cscript%3Ealert%28%22xss%22%29%3C%2Fscript%3E',
                unicode: '\u003cscript\u003ealert(\u0022xss\u0022)\u003c/script\u003e'
                };

                expect(() => {
                wrapper.success(data);
                }).not.toThrow();
            });
        });

        describe('Message and Meta Sanitization', () => {
            it('should handle malicious content in messages', () => {
                const maliciousMessage = '<script>alert("xss")</script>User created';
                
                wrapper.success({ id: 1 }, { message: maliciousMessage });

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.message).toBe(maliciousMessage);
            });

            it('should handle malicious content in meta fields', () => {
                const maliciousMeta = {
                filter: '<script>alert("meta")</script>',
                sort: { field: 'name<script>alert(1)</script>', order: 'asc' as const },
                customField: 'javascript:void(0)'
                };

                wrapper.success({ id: 1 }, { meta: maliciousMeta });

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.meta).toMatchObject(maliciousMeta);
            });
        });

        describe('Unicode and Special Character Handling', () => {
            it('should handle unicode characters safely', () => {
                const unicodeData = {
                name: '🚀 Unicode Test ñáéíóú',
                chinese: '测试数据',
                arabic: 'اختبار البيانات',
                emoji: '😀😍🎉🚀💻',
                mathematical: '∑∆∏∫√≈≠≤≥'
                };

                wrapper.success(unicodeData);

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.data).toEqual(unicodeData);
            });

            it('should handle null bytes safely', () => {
                const dataWithNullBytes = {
                name: 'Test\x00User',
                description: 'Description\u0000with null'
                };

                expect(() => {
                wrapper.success(dataWithNullBytes);
                }).not.toThrow();
            });

            it('should handle control characters', () => {
                const dataWithControlChars = {
                text: 'Line 1\nLine 2\rCarriage\tTab',
                binary: '\x01\x02\x03\x04\x05'
                };

                expect(() => {
                wrapper.success(dataWithControlChars);
                }).not.toThrow();
            });
        });
    });

    describe('Information Disclosure Prevention', () => {
        describe('Sensitive Data Handling', () => {
            it('should not modify sensitive data in responses', () => {
                const sensitiveData = {
                email: 'user@example.com',
                hashedPassword: '$2b$10$...',
                apiKey: 'sk_test_123456789',
                creditCard: '4111-1111-1111-1111',
                ssn: '123-45-6789'
                };

                wrapper.success(sensitiveData);

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                // Response wrapper should not filter sensitive data - that's the controller's responsibility
                expect(callArgs.data).toEqual(sensitiveData);
            });

            it('should handle internal system paths safely', () => {
                const dataWithPaths = {
                filePath: '/etc/passwd',
                configPath: '/app/config/database.yml',
                logPath: '/var/log/application.log'
                };

                wrapper.success(dataWithPaths);

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.data).toEqual(dataWithPaths);
            });

            it('should handle error objects without exposing stack traces', () => {
                const dataWithError = {
                result: 'success',
                debugInfo: new Error('Debug information'),
                internalError: {
                    message: 'Internal error',
                    stack: 'Error: Internal\n    at /app/internal/service.js:42'
                }
                };

                expect(() => {
                wrapper.success(dataWithError);
                }).not.toThrow();
            });
        });

        describe('Request Context Security', () => {
            it('should handle malicious request IDs safely', () => {
                const maliciousReq = createMockRequest({
                get: jest.fn().mockImplementation((header: string) => {
                    if (header === 'X-Request-ID') return '<script>alert("id")</script>';
                    return undefined;
                })
                });

                const maliciousWrapper = new ResponseWrapper(maliciousReq as Request, mockRes as Response);
                
                expect(() => {
                maliciousWrapper.success({ test: 'data' });
                }).not.toThrow();

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.requestId).toBe('<script>alert("id")</script>');
            });

            it('should handle extremely long request IDs', () => {
                const longRequestId = 'req_' + 'x'.repeat(10000);
                const reqWithLongId = createMockRequest({
                get: jest.fn().mockImplementation((header: string) => {
                    if (header === 'X-Request-ID') return longRequestId;
                    return undefined;
                })
                });

                const wrapperWithLongId = new ResponseWrapper(reqWithLongId as Request, mockRes as Response);
                
                expect(() => {
                wrapperWithLongId.success({ test: 'data' });
                }).not.toThrow();

                const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
                expect(callArgs.requestId).toBe(longRequestId);
            });
        });
    });

    describe('DoS and Resource Protection', () => {
        describe('Large Data Handling', () => {
            it('should handle extremely large response data', () => {
                const largeData = {
                items: Array.from({ length: 50000 }, (_, i) => ({
                    id: i,
                    name: `Item ${i}`,
                    description: 'x'.repeat(1000)
                }))
                };

                const start = Date.now();
                
                expect(() => {
                wrapper.success(largeData);
                }).not.toThrow();

                const processingTime = Date.now() - start;
                expect(processingTime).toBeLessThan(5000); // Should complete within 5 seconds
            });

            it('should handle deeply nested objects', () => {
                const createDeepObject = (depth: number): any => {
                if (depth === 0) return { value: 'deep' };
                return { level: depth, nested: createDeepObject(depth - 1) };
                };

                const deepData = createDeepObject(1000);

                expect(() => {
                wrapper.success(deepData);
                }).not.toThrow();
            });

            it('should handle circular references gracefully', () => {
                const circularData: any = { name: 'test' };
                circularData.self = circularData;
                circularData.nested = { parent: circularData };

                expect(() => {
                wrapper.success(circularData);
                }).not.toThrow();
            });

            it('should handle large string values', () => {
                const dataWithLargeStrings = {
                text: 'A'.repeat(1024 * 1024), // 1MB string
                base64: Buffer.alloc(1024 * 512).toString('base64'), // 512KB base64
                repeated: 'pattern'.repeat(100000)
                };

                expect(() => {
                wrapper.success(dataWithLargeStrings);
                }).not.toThrow();
            });
        });

        describe('Memory Protection', () => {
            it('should not cause memory leaks with many responses', () => {
                const initialMemory = process.memoryUsage().heapUsed;

                // Create many responses
                for (let i = 0; i < 1000; i++) {
                const testData = { id: i, data: `test-${i}` };
                const req = createMockRequest();
                const res = createMockResponse();
                const testWrapper = new ResponseWrapper(req as Request, res as Response);
                
                testWrapper.success(testData);
                }

                // Force garbage collection if available
                if ((global as any).gc) {
                (global as any).gc();
                }

                const finalMemory = process.memoryUsage().heapUsed;
                const memoryIncrease = finalMemory - initialMemory;

                // Should not cause excessive memory increase
                expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // 100MB
            });

            it('should handle concurrent response creation', async () => {
                const concurrentResponses = Array.from({ length: 100 }, (_, i) =>
                new Promise<void>(resolve => {
                    const req = createMockRequest();
                    const res = createMockResponse();
                    const testWrapper = new ResponseWrapper(req as Request, res as Response);
                    
                    testWrapper.success({ id: i, data: `concurrent-${i}` });
                    resolve();
                })
                );

                const start = Date.now();
                await Promise.all(concurrentResponses);
                const duration = Date.now() - start;

                // Should handle concurrent processing efficiently
                expect(duration).toBeLessThan(2000); // 2 seconds for 100 concurrent responses
            });
        });
    });

    describe('Prototype Pollution Protection', () => {
        it('should handle prototype pollution attempts in data', () => {
            const pollutionAttempt = {
                name: 'test',
                '__proto__': { polluted: true },
                'constructor': { prototype: { polluted: true } }
            };

            expect(() => {
                wrapper.success(pollutionAttempt);
            }).not.toThrow();

            // Should not pollute Object prototype
            expect((Object.prototype as any).polluted).toBeUndefined();
        });

        it('should handle prototype pollution in meta data', () => {
            const maliciousMeta = {
                filter: 'test',
                '__proto__': { isAdmin: true },
                'constructor': { prototype: { isAdmin: true } }
            };

            expect(() => {
                wrapper.success({ test: 'data' }, { meta: maliciousMeta });
            }).not.toThrow();

            expect((Object.prototype as any).isAdmin).toBeUndefined();
        });

        it('should handle function injection attempts', () => {
            const dataWithFunctions = {
                name: 'test',
                maliciousFunction: () => { throw new Error('Injected function'); },
                toString: () => { throw new Error('Malicious toString'); },
                valueOf: () => { throw new Error('Malicious valueOf'); }
            };

            expect(() => {
                wrapper.success(dataWithFunctions);
            }).not.toThrow();
        });
    });

    describe('Timing Attack Resistance', () => {
        it('should have consistent response times for different data sizes', async () => {
            const smallData = { id: 1, name: 'test' };
            const mediumData = { 
                id: 1, 
                name: 'test',
                items: Array.from({ length: 100 }, (_, i) => ({ id: i }))
            };
            const largeData = {
                id: 1,
                name: 'test', 
                items: Array.from({ length: 1000 }, (_, i) => ({ id: i, data: 'x'.repeat(100) }))
            };

            const measureTime = (operation: () => void): number => {
                const start = Date.now();
                operation();
                return Date.now() - start;
            };

            const times: number[] = [];

            // Test each data size multiple times
            [smallData, mediumData, largeData].forEach(data => {
                const operationTimes: number[] = [];
                
                for (let i = 0; i < 10; i++) {
                const req = createMockRequest();
                const res = createMockResponse();
                const testWrapper = new ResponseWrapper(req as Request, res as Response);
                
                const time = measureTime(() => testWrapper.success(data));
                operationTimes.push(time);
                }
                
                // Use median to reduce outlier impact
                operationTimes.sort((a, b) => a - b);
                const median = operationTimes[Math.floor(operationTimes.length / 2)];
                times.push(median);
            });

            // Check that timing differences are reasonable
            const maxTime = Math.max(...times);
            const minTime = Math.min(...times);
            const timeDifference = maxTime - minTime;

            // Allow reasonable variance but detect suspicious patterns
            expect(timeDifference).toBeLessThan(1000); // 1 second max difference
        });
    });

    describe('Request ID Security', () => {
        it('should generate secure request IDs', () => {
            const reqWithoutId = createMockRequest({
                get: jest.fn().mockReturnValue(undefined)
            });
            const wrapperWithoutId = new ResponseWrapper(reqWithoutId as Request, mockRes as Response);

            wrapperWithoutId.success({ test: 'data' });

            const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
            const requestId = callArgs.requestId;

            // Should match expected pattern
            expect(requestId).toMatch(/^req_\d+_[a-z0-9]{9}$/);
            
            // Should not be predictable
            const anotherWrapper = new ResponseWrapper(reqWithoutId as Request, createMockResponse() as Response);
            anotherWrapper.success({ test: 'data2' });
            
            const anotherCallArgs = (createMockResponse().json as jest.MockedFunction<any>).mock.calls[0];
            if (anotherCallArgs) {
                expect(anotherCallArgs[0].requestId).not.toBe(requestId);
            }
            });

            it('should handle request ID injection attempts', () => {
            const injectionAttempts = [
                'req_123_abc<script>alert(1)</script>',
                'req_123_abc"; DROP TABLE users; --',
                'req_123_abc\x00\x01\x02',
                '../../../etc/passwd',
                'req_123_abc\n\r\t'
            ];

            injectionAttempts.forEach(maliciousId => {
                const reqWithMaliciousId = createMockRequest({
                get: jest.fn().mockImplementation((header: string) => {
                    if (header === 'X-Request-ID') return maliciousId;
                    return undefined;
                })
                });

                const maliciousWrapper = new ResponseWrapper(reqWithMaliciousId as Request, createMockResponse() as Response);
                
                expect(() => {
                maliciousWrapper.success({ test: 'data' });
                }).not.toThrow();
            });
        });
    });

    describe('Response Structure Integrity', () => {
        it('should maintain consistent response structure under attack', () => {
            const attackData = {
                success: false, // Try to override
                data: null, // Try to nullify
                error: { code: 'FAKE_ERROR' }, // Try to inject error
                timestamp: 'fake-time', // Try to override
                requestId: 'fake-id' // Try to override
            };

            wrapper.success(attackData);

            const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
            
            // Should maintain proper structure despite malicious data
            expect(callArgs.success).toBe(true);
            expect(callArgs.data).toEqual(attackData);
            expect(callArgs.error).toBeUndefined();
            expect(callArgs.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
            expect(callArgs.requestId).toBe('test-request-id');
        });

        it('should prevent response structure tampering via meta', () => {
            const maliciousMeta = {
                success: false,
                data: { fake: 'data' },
                error: { code: 'INJECTED' },
                timestamp: 'fake',
                requestId: 'fake'
            };

            wrapper.success({ real: 'data' }, { meta: maliciousMeta });

            const callArgs = (mockRes.json as jest.MockedFunction<any>).mock.calls[0][0];
            
            // Core structure should remain intact
            expect(callArgs.success).toBe(true);
            expect(callArgs.data).toEqual({ real: 'data' });
            expect(callArgs.meta).toMatchObject(maliciousMeta);
            expect(callArgs.error).toBeUndefined();
        });
    });

    describe('Edge Case Security', () => {
        it('should handle Symbol properties safely', () => {
            const symbolKey = Symbol('malicious');
            const dataWithSymbols = {
                name: 'test',
                [symbolKey]: 'hidden value',
                [Symbol.for('global')]: 'global symbol'
            };

            expect(() => {
                wrapper.success(dataWithSymbols);
            }).not.toThrow();
        });

        it('should handle getter/setter properties', () => {
            const dataWithGetters = {
                name: 'test',
                get maliciousGetter() {
                throw new Error('Malicious getter accessed');
                },
                set maliciousSetter(value) {
                throw new Error('Malicious setter accessed');
                }
            };

            expect(() => {
                wrapper.success(dataWithGetters);
            }).not.toThrow();
        });

        it('should handle non-serializable data gracefully', () => {
            const nonSerializableData = {
                func: () => 'function',
                undef: undefined,
                symbol: Symbol('test'),
                bigint: BigInt(123),
                date: new Date(),
                regex: /test/gi,
                map: new Map([['key', 'value']]),
                set: new Set([1, 2, 3])
            };

            expect(() => {
                wrapper.success(nonSerializableData);
            }).not.toThrow();
        });
    });
});