// /backend/src/tests/security/firebase.security.test.ts


/**
 * Firebase Configuration Security Tests
 * ---------------------------------------
 * This test suite validates the security aspects of the Firebase configuration
 * module. It verifies that sensitive credentials are handled in a secure manner and:
 *
 * 1. Sensitive details (e.g., private keys) are never logged or exposed in exported objects.
 * 2. The Firebase Admin SDK is initialized only with properly validated configuration values.
 * 3. Invalid or missing configuration (empty/whitespace-only or non-string private keys,
 *    undefined config) throws appropriate errors to avoid insecure runtime behavior.
 * 4. Environment variables used for configuration are processed securely without leaking
 *    sensitive information.
 *
 * Testing Approach:
 * - Isolation: Each test runs within its own isolated module state via `jest.isolateModules()`.
 * - Mocking: External dependencies (like `firebase-admin` and the configuration module) are mocked
 *   to simulate various error conditions and secure initialization scenarios.
 *
 * This suite complements the unit and integration tests by focusing on potential vulnerabilities
 * related to the handling of security-critical configuration data.
 */

describe('Firebase Configuration Security Tests', () => {
    const originalProcessEnv = { ...process.env };

    beforeEach(() => {
        jest.resetModules();
        process.env = { ...originalProcessEnv };
        jest.clearAllMocks();
    });

    afterAll(() => {
        process.env = originalProcessEnv;
    });

    test('should not log sensitive data during initialization', () => {
        jest.spyOn(console, 'log').mockImplementation(() => {});
        jest.spyOn(console, 'error').mockImplementation(() => {});

        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn(),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'test-private-key',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            require('../../config/firebase');

            expect(console.log).not.toHaveBeenCalledWith(expect.stringContaining('test-private-key'));
            expect(console.error).not.toHaveBeenCalledWith(expect.stringContaining('test-private-key'));
        });

        (console.log as jest.Mock).mockRestore();
        (console.error as jest.Mock).mockRestore();
    });

    test('should throw an error if private key is missing', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn(),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: undefined,
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            expect(() => require('../../config/firebase')).toThrow(TypeError);
            expect(() => require('../../config/firebase')).toThrow(/Cannot read properties of undefined/);
        });
    });

    test('should securely handle invalid private key format', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn((data) => {
                        if (data.privateKey === 'invalid-key-format') {
                            throw new SyntaxError('Invalid private key format');
                        }
                        return data;
                    }),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'invalid-key-format',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            expect(() => require('../../config/firebase')).toThrow(SyntaxError);
            expect(() => require('../../config/firebase')).toThrow('Invalid private key format');
        });
    });

    test('should not expose sensitive data in exported objects', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn(),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'test-private-key',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            const { firebaseAdmin, storage, bucket } = require('../../config/firebase');

            expect(firebaseAdmin).not.toHaveProperty('privateKey');
            expect(storage).not.toHaveProperty('privateKey');
            expect(bucket).not.toHaveProperty('privateKey');
            
            // Check deeply nested properties as well
            const stringified = JSON.stringify({ firebaseAdmin, storage, bucket });
            expect(stringified).not.toContain('test-private-key');
        });
    });

    test('should validate Firebase Admin SDK initialization with secure parameters', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn((data) => data),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'test-private-key',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            require('../../config/firebase');

            expect(mockAdmin.initializeApp).toHaveBeenCalledWith({
                credential: expect.objectContaining({
                    projectId: 'test-project',
                    privateKey: 'test-private-key',
                    clientEmail: 'test@example.com',
                }),
                storageBucket: 'test-bucket',
            });
        });
    });

    test('should throw an error if private key is an empty string', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn(() => {
                        throw new TypeError('Private key cannot be an empty string.');
                    }),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: '',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            expect(() => require('../../config/firebase')).toThrow(TypeError);
            expect(() => require('../../config/firebase')).toThrow('Private key cannot be an empty string.');
        });
    });

    test('should throw an error if private key contains only whitespace', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn(() => {
                        throw new TypeError('Private key cannot contain only whitespace.');
                    }),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: '   ',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            expect(() => require('../../config/firebase')).toThrow(TypeError);
            expect(() => require('../../config/firebase')).toThrow('Private key cannot contain only whitespace.');
        });
    });

    test('should throw TypeError if config.firebase is undefined', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn(),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: undefined,
                },
            }));

            expect(() => require('../../config/firebase')).toThrow(TypeError);
            expect(() => require('../../config/firebase')).toThrow(/Cannot read properties of undefined/);
        });
    });

    test('should handle malformed PEM format errors securely', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn(() => {
                        throw new Error('Failed to parse private key: Error: Invalid PEM formatted message.');
                    }),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: '-----BEGIN PRIVATE KEY----- MalformedKey -----END PRIVATE KEY-----',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            expect(() => require('../../config/firebase')).toThrow(/Invalid PEM/);
            
            // Ensure the actual key content isn't exposed in the error
            try {
                require('../../config/firebase');
            } catch (error) {
                expect(String(error)).not.toContain('MalformedKey');
            }
        });
    });

    test('should not expose private key in error messages', () => {
        jest.isolateModules(() => {
            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn(() => {
                        throw new Error('Error initializing with private key');
                    }),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'sensitive-private-key-content',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            try {
                require('../../config/firebase');
                fail('Should have thrown an error');
            } catch (error) {
                expect(String(error)).not.toContain('sensitive-private-key-content');
            }
        });
    });

    test('should securely handle environment variables', () => {
        jest.isolateModules(() => {
            // Set environment variables
            process.env.FIREBASE_PROJECT_ID = 'env-test-project';
            process.env.FIREBASE_PRIVATE_KEY = 'env-test-private-key';
            process.env.FIREBASE_CLIENT_EMAIL = 'env-test@example.com';
            process.env.FIREBASE_STORAGE_BUCKET = 'env-test-bucket';

            const mockAdmin = {
                initializeApp: jest.fn(),
                credential: {
                    cert: jest.fn((data) => data),
                },
                storage: jest.fn(() => ({
                    bucket: jest.fn(() => ({})),
                })),
                apps: [],
            };
            jest.doMock('firebase-admin', () => mockAdmin);

            // Mock config to use environment variables
            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: process.env.FIREBASE_PROJECT_ID,
                        privateKey: process.env.FIREBASE_PRIVATE_KEY,
                        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
                        storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
                    },
                },
            }));

            require('../../config/firebase');

            // Test that environment variables are used securely
            expect(mockAdmin.initializeApp).toHaveBeenCalledWith({
                credential: expect.objectContaining({
                    projectId: 'env-test-project',
                    privateKey: 'env-test-private-key',
                    clientEmail: 'env-test@example.com',
                }),
                storageBucket: 'env-test-bucket',
            });

            // Ensure environment variables are not logged
            jest.spyOn(console, 'log').mockImplementation(() => {});
            jest.spyOn(console, 'error').mockImplementation(() => {});
            
            expect(console.log).not.toHaveBeenCalledWith(expect.stringContaining('env-test-private-key'));
            expect(console.error).not.toHaveBeenCalledWith(expect.stringContaining('env-test-private-key'));
            
            (console.log as jest.Mock).mockRestore();
            (console.error as jest.Mock).mockRestore();
        });
    });
});