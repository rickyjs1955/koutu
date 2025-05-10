// /backend/src/tests/unit/firebase.unit.test.ts

import { jest } from '@jest/globals';

// Define a reusable mock function for firebase-admin
const createMockAdmin = () => ({
    initializeApp: jest.fn(),
    credential: {
        cert: jest.fn((arg) => arg),
    },
    storage: jest.fn(() => ({
        bucket: jest.fn(() => ({})),
    })),
    apps: [] as Array<object>,
});

/**
 * Firebase Configuration Module Test Suite
 * ----------------------------------------
 * This suite tests the functionality of the Firebase configuration module,
 * which handles initialization of Firebase Admin SDK and exports the required
 * Firebase services for the application.
 *
 * Testing Approach:
 * - Isolation: Each test runs with isolated modules to ensure clean state
 * - Mocking: Firebase Admin SDK is mocked to prevent actual initialization
 * 
 * Key Focus Areas:
 * 1. Initialization Logic:
 *    - Verify Firebase is initialized only once
 *    - Confirm correct configuration is passed to initialization
 * 2. Private Key Handling:
 *    - Test proper transformation of escaped newlines
 * 3. Export Integrity:
 *    - Validate all required Firebase services are exported
 * 4. Error Handling:
 *    - Test behavior with invalid or missing configuration
 */
describe('Firebase Configuration Module', () => {
    const originalProcessEnv = { ...process.env };

    beforeEach(() => {
        jest.resetModules();
        process.env = { ...originalProcessEnv };
        jest.clearAllMocks();
    });

    afterAll(() => {
        process.env = originalProcessEnv;
    });

    test('should initialize Firebase Admin SDK when no app exists', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project-env',
                        privateKey: 'line1\\nline2-env',
                        clientEmail: 'test-env@example.com',
                        storageBucket: 'test-bucket-env',
                    },
                },
            }));

            // Require the module after setting up the mocks
            require('../../config/firebase');

            expect(mockAdmin.initializeApp).toHaveBeenCalledWith({
                credential: expect.objectContaining({
                    projectId: 'test-project-env',
                    privateKey: 'line1\nline2-env',
                    clientEmail: 'test-env@example.com',
                }),
                storageBucket: 'test-bucket-env',
            });
        });
    });

    test('should not initialize Firebase Admin SDK if an app already exists', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            mockAdmin.apps = [{}]; // Simulate an existing app
            jest.doMock('firebase-admin', () => mockAdmin);

            // Require the module after setting up the mocks
            require('../../config/firebase');

            expect(mockAdmin.initializeApp).not.toHaveBeenCalled();
        });
    });

    test('should correctly handle private keys with multiple newlines', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'line1\\nline2\\nline3\\nline4',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            // Require the module after setting up the mocks
            require('../../config/firebase');

            expect(mockAdmin.credential.cert).toHaveBeenCalledWith(
                expect.objectContaining({
                    privateKey: 'line1\nline2\nline3\nline4',
                })
            );
        });
    });

    test('should use values from config module when environment variables are not set', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'default-project',
                        privateKey: 'default-key\\nwith-newlines',
                        clientEmail: 'default@example.com',
                        storageBucket: 'default-bucket',
                    },
                },
            }));

            // Require the module after setting up the mocks
            require('../../config/firebase');

            expect(mockAdmin.credential.cert).toHaveBeenCalledWith(
                expect.objectContaining({
                    projectId: 'default-project',
                    privateKey: 'default-key\nwith-newlines',
                    clientEmail: 'default@example.com',
                })
            );
        });
    });

    test('should properly expose the Firebase storage and bucket objects', () => {
        jest.isolateModules(() => {
            const mockBucket = { name: 'test-bucket', upload: jest.fn() };
            const mockAdmin = createMockAdmin();

            mockAdmin.storage.mockImplementation(() => ({
                bucket: jest.fn(() => mockBucket),
            }));

            jest.doMock('firebase-admin', () => mockAdmin);

            const { storage, bucket } = require('../../config/firebase');

            expect(storage).toBeDefined();
            expect(storage.bucket).toBeDefined();
            expect(bucket).toBe(mockBucket);
            expect(bucket.name).toBe('test-bucket');
            expect(typeof bucket.upload).toBe('function');
        });
    });

    test('should handle empty private key gracefully', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
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

            // Require the module after setting up the mocks
            require('../../config/firebase');

            expect(mockAdmin.credential.cert).toHaveBeenCalledWith(
                expect.objectContaining({
                    privateKey: '',
                })
            );
        });
    });

    test('should throw TypeError if config.firebase is undefined', () => {
        jest.isolateModules(() => {
            jest.doMock('../../config/index', () => ({
                config: {},
            }));

            expect(() => {
                require('../../config/firebase');
            }).toThrow(TypeError);
        });
    });

    test('should throw TypeError if config.firebase.privateKey is undefined', () => {
        jest.isolateModules(() => {
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

            expect(() => {
                require('../../config/firebase');
            }).toThrow(TypeError);
        });
    });

    test('should throw TypeError if config.firebase.privateKey is not a string', () => {
        jest.isolateModules(() => {
            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 12345,
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            expect(() => {
                require('../../config/firebase');
            }).toThrow(TypeError);
        });
    });

    test('should pass undefined to SDK if projectId is undefined in config', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: undefined,
                        privateKey: 'key\\nkey',
                        clientEmail: 'client@email.com',
                        storageBucket: 'bucket-name',
                    },
                },
            }));

            // Require the module after setting up the mocks
            require('../../config/firebase');

            expect(mockAdmin.credential.cert).toHaveBeenCalledWith(
                expect.objectContaining({
                    projectId: undefined,
                })
            );
        });
    });

    test('should pass undefined to SDK if clientEmail is undefined in config', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'project-id',
                        privateKey: 'key\\nkey',
                        clientEmail: undefined,
                        storageBucket: 'bucket-name',
                    },
                },
            }));

            // Require the module after setting up the mocks
            require('../../config/firebase');

            expect(mockAdmin.credential.cert).toHaveBeenCalledWith(
                expect.objectContaining({
                    clientEmail: undefined,
                })
            );
        });
    });

    test('should pass undefined to SDK if storageBucket is undefined in config', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'project-id',
                        privateKey: 'key\\nkey',
                        clientEmail: 'client@email.com',
                        storageBucket: undefined,
                    },
                },
            }));

            // Require the module after setting up the mocks
            require('../../config/firebase');

            expect(mockAdmin.initializeApp).toHaveBeenCalledWith(
                expect.objectContaining({
                    storageBucket: undefined,
                })
            );
        });
    });
});