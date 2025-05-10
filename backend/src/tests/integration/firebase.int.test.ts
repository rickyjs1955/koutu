// /backend/src/tests/integration/firebase.int.test.ts

import { jest } from '@jest/globals';

// Define a reusable mock function for firebase-admin
const createMockAdmin = () => ({
    initializeApp: jest.fn(),
    credential: {
        cert: jest.fn((arg) => arg), // Return the input to allow inspection
    },
    storage: jest.fn(() => ({
        bucket: jest.fn(() => ({})), // Default mock bucket
    })),
    apps: [] as Array<object>, // Start with no apps initialized
});

/**
 * Firebase Configuration Module Integration Test Suite
 * --------------------------------------------------
 * This suite tests the Firebase configuration module's initialization
 * and export logic in an isolated environment with mocked dependencies.
 *
 * Testing Approach:
 * - Isolation: Each test uses `jest.isolateModules` to ensure a fresh module state.
 * - Mocking: `firebase-admin` and `config` modules are mocked to control
 *   dependencies and prevent actual SDK calls.
 *
 * Key Focus Areas:
 * 1. Conditional Initialization:
 *    - Verify Firebase initializes only if no apps exist.
 *    - Confirm correct configuration is passed during initialization.
 * 2. Configuration Handling:
 *    - Test transformation of private keys (newline characters).
 *    - Test behavior with default vs. environment-specific config.
 *    - Test handling of undefined or invalid configuration values.
 * 3. Export Integrity:
 *    - Validate that `firebaseAdmin`, `storage`, and `bucket` are correctly exported
 *      and reflect the (mocked) SDK state.
 */
describe('Firebase Configuration Module Integration Tests', () => {
    const originalProcessEnv = { ...process.env };

    beforeEach(() => {
        jest.resetModules(); // Ensures a clean slate for modules between tests
        process.env = { ...originalProcessEnv }; // Reset environment variables
        jest.clearAllMocks(); // Clear mock call history
    });

    afterAll(() => {
        process.env = originalProcessEnv; // Restore original environment variables
    });

    test('should initialize Firebase Admin SDK when no app exists', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            mockAdmin.apps = []; // Ensure no apps are pre-existing
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

            // Require the module under test *after* setting up mocks
            require('../../config/firebase');

            expect(mockAdmin.initializeApp).toHaveBeenCalledTimes(1);
            expect(mockAdmin.initializeApp).toHaveBeenCalledWith({
                credential: expect.objectContaining({
                    projectId: 'test-project-env',
                    privateKey: 'line1\nline2-env', // Transformed private key
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

            jest.doMock('../../config/index', () => ({ // Mock config to prevent errors
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'test-key',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            require('../../config/firebase');

            expect(mockAdmin.initializeApp).not.toHaveBeenCalled();
        });
    });

    test('should correctly handle private keys with multiple newlines', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            mockAdmin.apps = [];
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
            mockAdmin.apps = [];
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
            const mockBucketInstance = { name: 'test-bucket-instance', upload: jest.fn() };
            const mockAdmin = createMockAdmin();
            mockAdmin.apps = []; // Ensure initialization runs if needed
            mockAdmin.storage.mockImplementation(() => ({
                bucket: jest.fn(() => mockBucketInstance),
            }));
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({ // Provide necessary config
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'test-key',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            // Import *here* to get the exports from the mocked environment
            const { storage, bucket, firebaseAdmin } = require('../../config/firebase');

            expect(firebaseAdmin.default).toBe(mockAdmin); // Exported admin's default property should be our mock
            expect(storage).toBeDefined();
            expect(mockAdmin.storage).toHaveBeenCalled(); // storage getter was called
            expect(storage.bucket).toBeDefined(); // Check if the mocked storage object has bucket method

            const retrievedBucket = storage.bucket(); // Call the method on the mocked storage
            expect(retrievedBucket).toBe(mockBucketInstance);

            expect(bucket).toBe(mockBucketInstance); // Exported bucket should be the instance from mock
            expect(bucket.name).toBe('test-bucket-instance');
            expect(typeof bucket.upload).toBe('function');
        });
    });

    test('should handle empty private key gracefully', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            mockAdmin.apps = [];
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: '', // Empty private key
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

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
            const mockAdmin = createMockAdmin(); // Mock admin to prevent other errors
            jest.doMock('firebase-admin', () => mockAdmin);
            jest.doMock('../../config/index', () => ({
                config: {}, // config.firebase will be undefined
            }));

            expect(() => {
                require('../../config/firebase');
            }).toThrow(TypeError); // e.g., Cannot read properties of undefined (reading 'privateKey')
        });
    });

    test('should throw TypeError if config.firebase.privateKey is undefined', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            jest.doMock('firebase-admin', () => mockAdmin);
            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: undefined, // privateKey is undefined
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            expect(() => {
                require('../../config/firebase');
            }).toThrow(TypeError); // e.g., Cannot read properties of undefined (reading 'replace')
        });
    });

    test('should throw TypeError if config.firebase.privateKey is not a string', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            jest.doMock('firebase-admin', () => mockAdmin);
            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 12345, // privateKey is a number
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));
            expect(() => {
                require('../../config/firebase');
            }).toThrow(TypeError); // privateKey.replace is not a function
        });
    });

    test('should pass undefined to SDK if projectId is undefined in config', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            mockAdmin.apps = [];
            jest.doMock('firebase-admin', () => mockAdmin);
            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: undefined,
                        privateKey: 'test-key\\nmore-lines',
                        clientEmail: 'test@example.com',
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            require('../../config/firebase');

            expect(mockAdmin.initializeApp).toHaveBeenCalledWith(
                expect.objectContaining({
                    credential: expect.objectContaining({ projectId: undefined }),
                })
            );
        });
    });

    test('should pass undefined to SDK if clientEmail is undefined in config', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            mockAdmin.apps = [];
            jest.doMock('firebase-admin', () => mockAdmin);
            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'test-key\\nmore-lines',
                        clientEmail: undefined,
                        storageBucket: 'test-bucket',
                    },
                },
            }));

            require('../../config/firebase');

            expect(mockAdmin.initializeApp).toHaveBeenCalledWith(
                expect.objectContaining({
                    credential: expect.objectContaining({ clientEmail: undefined }),
                })
            );
        });
    });

    test('should pass undefined to SDK if storageBucket is undefined in config and exports are correct', () => {
        jest.isolateModules(() => {
            const mockAdmin = createMockAdmin();
            mockAdmin.apps = []; // Ensure initializeApp is called
            // storage().bucket() will return {} by default from createMockAdmin
            jest.doMock('firebase-admin', () => mockAdmin);

            jest.doMock('../../config/index', () => ({
                config: {
                    firebase: {
                        projectId: 'test-project',
                        privateKey: 'test-key\\nmore-lines',
                        clientEmail: 'test@example.com',
                        storageBucket: undefined, // storageBucket is undefined
                    },
                },
            }));

            // Import here to get the exports after initialization
            const { storage, bucket } = require('../../config/firebase');

            expect(mockAdmin.initializeApp).toHaveBeenCalledWith(
                expect.objectContaining({
                    storageBucket: undefined,
                })
            );
            
            // Verify that storage and bucket are still exported and reflect the mock
            expect(storage).toBeDefined(); // storage is mockAdmin.storage()
            expect(mockAdmin.storage).toHaveBeenCalled();
            
            const bucketFromStorageCall = storage.bucket(); // Calls mockAdmin.storage().bucket()
            expect(bucketFromStorageCall).toEqual({}); // Default mock from createMockAdmin

            expect(bucket).toEqual({}); // Exported bucket is mockAdmin.storage().bucket()
        });
    });
});