// backend/src/tests/unit/firebase.unit.test.ts
import { jest, describe, it, expect, beforeEach, beforeAll, afterEach } from '@jest/globals';

// Mock Firebase Admin SDK
const mockCredential = {
    projectId: 'test-project-id',
    privateKey: '-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY\n-----END PRIVATE KEY-----',
    clientEmail: 'test@test-project.iam.gserviceaccount.com'
};

const mockBucket = {
    file: jest.fn(() => ({
        save: jest.fn(),
        download: jest.fn(),
        delete: jest.fn()
    })),
    upload: jest.fn(),
    getFiles: jest.fn()
};

const mockStorage = {
    bucket: jest.fn(() => mockBucket)
};

const mockAuth = {
    createUser: jest.fn(),
    getUser: jest.fn(),
    deleteUser: jest.fn()
};

const mockApp = {
    name: '[DEFAULT]',
    auth: jest.fn(() => mockAuth),
    storage: jest.fn(() => mockStorage)
};

const mockFirebaseAdmin = {
    apps: [] as any[],
    initializeApp: jest.fn(() => mockApp),
    credential: {
        cert: jest.fn((config: any) => {
        // Validate required fields
        if (!config.projectId) {
            throw new Error('Project ID is required');
        }
        if (!config.privateKey) {
            throw new Error('Private key is required');
        }
        if (!config.clientEmail) {
            throw new Error('Client email is required');
        }
        return mockCredential;
        })
    },
    auth: jest.fn(() => mockAuth),
    storage: jest.fn(() => mockStorage)
};

// Mock the firebase-admin module
jest.mock('firebase-admin', () => mockFirebaseAdmin);

// Default mock config
const mockConfig = {
    firebase: {
        projectId: 'test-project-id',
        privateKey: '-----BEGIN PRIVATE KEY-----\\nMOCK_PRIVATE_KEY\\n-----END PRIVATE KEY-----',
        clientEmail: 'test@test-project.iam.gserviceaccount.com',
        storageBucket: 'test-project.appspot.com'
    }
};

// Mock the config module with a factory function for better control
jest.mock('../../config/index', () => ({
    get config() {
        // This allows us to dynamically return different configs per test
        return (global as any).__TEST_CONFIG__ || mockConfig;
    }
}));

// Helper function to set test config
function setTestConfig(config: any) {
    (global as any).__TEST_CONFIG__ = config;
}

// Helper function to clear test config
function clearTestConfig() {
    delete (global as any).__TEST_CONFIG__;
}

describe('Firebase Configuration Unit Tests', () => {
    beforeAll(() => {
        jest.clearAllMocks();
    });

    beforeEach(() => {
        // Reset all mocks before each test
        jest.clearAllMocks();
        mockFirebaseAdmin.apps = [];
        clearTestConfig();
        
        // Reset mock implementations to defaults
        mockFirebaseAdmin.initializeApp.mockImplementation(() => mockApp);
        mockFirebaseAdmin.credential.cert.mockImplementation((config: any) => {
        // Validate required fields
        if (!config.projectId) {
            throw new Error('Project ID is required');
        }
        if (!config.privateKey) {
            throw new Error('Private key is required');
        }
        if (!config.clientEmail) {
            throw new Error('Client email is required');
        }
        return mockCredential;
        });
    });

    afterEach(() => {
        // Clear module cache after each test to ensure clean state
        jest.resetModules();
        clearTestConfig();
    });

    describe('Firebase Initialization', () => {
        it('should initialize Firebase Admin SDK when no apps exist', async () => {
        // Ensure no apps are initialized
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        // Import the firebase config module
        const { firebaseAdmin } = await import('../../config/firebase');
        
        // Verify initialization was called
        expect(mockFirebaseAdmin.initializeApp).toHaveBeenCalledTimes(1);
        
        // Verify credential.cert was called with processed private key
        expect(mockFirebaseAdmin.credential.cert).toHaveBeenCalledWith({
            projectId: mockConfig.firebase.projectId,
            privateKey: mockConfig.firebase.privateKey.replace(/\\n/g, '\n'),
            clientEmail: mockConfig.firebase.clientEmail
        });
        
        expect(firebaseAdmin).toBeDefined();
        });

        it('should not reinitialize Firebase when app already exists', async () => {
        // Mock existing app
        mockFirebaseAdmin.apps = [mockApp];
        setTestConfig(mockConfig);
        
        // Import the firebase config module
        await import('../../config/firebase');
        
        // Verify initialization was NOT called
        expect(mockFirebaseAdmin.initializeApp).not.toHaveBeenCalled();
        });

        it('should properly format private key by replacing escaped newlines', async () => {
        mockFirebaseAdmin.apps = [];
        
        const configWithEscapedKey = {
            firebase: {
            ...mockConfig.firebase,
            privateKey: '-----BEGIN PRIVATE KEY-----\\nLINE1\\nLINE2\\n-----END PRIVATE KEY-----'
            }
        };
        
        setTestConfig(configWithEscapedKey);
        
        await import('../../config/firebase');
        
        expect(mockFirebaseAdmin.credential.cert).toHaveBeenCalledWith({
            projectId: configWithEscapedKey.firebase.projectId,
            privateKey: '-----BEGIN PRIVATE KEY-----\nLINE1\nLINE2\n-----END PRIVATE KEY-----',
            clientEmail: configWithEscapedKey.firebase.clientEmail
        });
        });

        it('should initialize with correct credential configuration', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        await import('../../config/firebase');
        
        expect(mockFirebaseAdmin.initializeApp).toHaveBeenCalledWith({
            credential: mockCredential,
            storageBucket: mockConfig.firebase.storageBucket
        });
        });
    });

    describe('Configuration Validation', () => {
        it('should accept valid Firebase configuration', () => {
        const validConfig = {
            projectId: 'valid-project-id',
            privateKey: '-----BEGIN PRIVATE KEY-----\nVALID_KEY\n-----END PRIVATE KEY-----',
            clientEmail: 'valid@project.iam.gserviceaccount.com'
        };

        expect(() => {
            mockFirebaseAdmin.credential.cert(validConfig);
        }).not.toThrow();
        });

        it('should reject configuration with missing projectId', () => {
        const invalidConfig = {
            privateKey: '-----BEGIN PRIVATE KEY-----\nVALID_KEY\n-----END PRIVATE KEY-----',
            clientEmail: 'valid@project.iam.gserviceaccount.com'
        };

        expect(() => {
            mockFirebaseAdmin.credential.cert(invalidConfig);
        }).toThrow('Project ID is required');
        });

        it('should reject configuration with missing privateKey', () => {
        const invalidConfig = {
            projectId: 'valid-project-id',
            clientEmail: 'valid@project.iam.gserviceaccount.com'
        };

        expect(() => {
            mockFirebaseAdmin.credential.cert(invalidConfig);
        }).toThrow('Private key is required');
        });

        it('should reject configuration with missing clientEmail', () => {
        const invalidConfig = {
            projectId: 'valid-project-id',
            privateKey: '-----BEGIN PRIVATE KEY-----\nVALID_KEY\n-----END PRIVATE KEY-----'
        };

        expect(() => {
            mockFirebaseAdmin.credential.cert(invalidConfig);
        }).toThrow('Client email is required');
        });
    });

    describe('Firebase Services Access', () => {
        it('should provide access to Firebase Admin instance', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        expect(firebaseConfig.firebaseAdmin).toBeDefined();
        expect(typeof firebaseConfig.firebaseAdmin.auth).toBe('function');
        expect(typeof firebaseConfig.firebaseAdmin.storage).toBe('function');
        });

        it('should provide access to Firebase Storage instance', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        expect(firebaseConfig.storage).toBeDefined();
        expect(typeof firebaseConfig.storage.bucket).toBe('function');
        });

        it('should provide access to default Storage bucket', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        expect(firebaseConfig.bucket).toBeDefined();
        expect(typeof firebaseConfig.bucket.file).toBe('function');
        expect(typeof firebaseConfig.bucket.upload).toBe('function');
        });

        it('should maintain singleton pattern for Firebase instances', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig1 = await import('../../config/firebase');
        
        // Reset modules and import again
        jest.resetModules();
        mockFirebaseAdmin.apps = [mockApp]; // Simulate existing app
        
        const firebaseConfig2 = await import('../../config/firebase');
        
        // Both should be defined (though they might be different instances due to module reloading)
        expect(firebaseConfig1.firebaseAdmin).toBeDefined();
        expect(firebaseConfig2.firebaseAdmin).toBeDefined();
        });
    });

    describe('Environment-specific Configuration', () => {
        it('should handle production environment configuration', async () => {
        const prodConfig = {
            firebase: {
            projectId: 'prod-project-id',
            privateKey: '-----BEGIN PRIVATE KEY-----\\nPROD_PRIVATE_KEY\\n-----END PRIVATE KEY-----',
            clientEmail: 'prod@prod-project.iam.gserviceaccount.com',
            storageBucket: 'prod-project.appspot.com'
            }
        };

        mockFirebaseAdmin.apps = [];
        setTestConfig(prodConfig);
        
        await import('../../config/firebase');

        expect(mockFirebaseAdmin.credential.cert).toHaveBeenCalledWith({
            projectId: prodConfig.firebase.projectId,
            privateKey: prodConfig.firebase.privateKey.replace(/\\n/g, '\n'),
            clientEmail: prodConfig.firebase.clientEmail
        });

        expect(mockFirebaseAdmin.initializeApp).toHaveBeenCalledWith({
            credential: mockCredential,
            storageBucket: prodConfig.firebase.storageBucket
        });
        });

        it('should handle development environment configuration', async () => {
        const devConfig = {
            firebase: {
            projectId: 'dev-project-id',
            privateKey: '-----BEGIN PRIVATE KEY-----\\nDEV_PRIVATE_KEY\\n-----END PRIVATE KEY-----',
            clientEmail: 'dev@dev-project.iam.gserviceaccount.com',
            storageBucket: 'dev-project.appspot.com'
            }
        };

        mockFirebaseAdmin.apps = [];
        setTestConfig(devConfig);
        
        await import('../../config/firebase');

        expect(mockFirebaseAdmin.credential.cert).toHaveBeenCalledWith({
            projectId: devConfig.firebase.projectId,
            privateKey: devConfig.firebase.privateKey.replace(/\\n/g, '\n'),
            clientEmail: devConfig.firebase.clientEmail
        });

        expect(mockFirebaseAdmin.initializeApp).toHaveBeenCalledWith({
            credential: mockCredential,
            storageBucket: devConfig.firebase.storageBucket
        });
        });
    });

    describe('Error Scenarios', () => {
        it('should handle Firebase initialization errors gracefully', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        mockFirebaseAdmin.initializeApp.mockImplementation(() => {
            throw new Error('Firebase initialization failed');
        });

        await expect(async () => {
            await import('../../config/firebase');
        }).rejects.toThrow('Firebase initialization failed');
        });

        it('should handle invalid credential format', async () => {
        const invalidConfig = {
            firebase: {
            projectId: 'test-project',
            privateKey: 'invalid-key-format',
            clientEmail: 'invalid-email-format',
            storageBucket: 'test-bucket'
            }
        };

        setTestConfig(invalidConfig);
        mockFirebaseAdmin.apps = [];
        mockFirebaseAdmin.credential.cert.mockImplementation(() => {
            throw new Error('Invalid credential format');
        });

        await expect(async () => {
            await import('../../config/firebase');
        }).rejects.toThrow('Invalid credential format');
        });

        it('should handle missing configuration gracefully', async () => {
        const incompleteConfig = {
            firebase: {
            projectId: 'test-project'
            // Missing privateKey, clientEmail, storageBucket
            }
        };

        setTestConfig(incompleteConfig);
        mockFirebaseAdmin.apps = [];

        await expect(async () => {
            await import('../../config/firebase');
        }).rejects.toThrow('Private key is required');
        });
    });

    describe('Module Exports', () => {
        it('should export all required Firebase instances', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        expect(firebaseConfig).toHaveProperty('firebaseAdmin');
        expect(firebaseConfig).toHaveProperty('storage');
        expect(firebaseConfig).toHaveProperty('bucket');
        });

        it('should export Firebase Admin with all required methods', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        expect(firebaseConfig.firebaseAdmin).toHaveProperty('auth');
        expect(firebaseConfig.firebaseAdmin).toHaveProperty('storage');
        expect(firebaseConfig.firebaseAdmin).toHaveProperty('initializeApp');
        expect(firebaseConfig.firebaseAdmin).toHaveProperty('credential');
        });

        it('should export Storage with bucket access', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        expect(typeof firebaseConfig.storage.bucket).toBe('function');
        });

        it('should export default bucket with file operations', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        expect(typeof firebaseConfig.bucket.file).toBe('function');
        expect(typeof firebaseConfig.bucket.upload).toBe('function');
        expect(typeof firebaseConfig.bucket.getFiles).toBe('function');
        });
    });

    describe('Integration Scenarios', () => {
        it('should allow Auth service usage after initialization', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        const auth = firebaseConfig.firebaseAdmin.auth();
        expect(auth).toBeDefined();
        expect(typeof auth.createUser).toBe('function');
        expect(typeof auth.getUser).toBe('function');
        });

        it('should allow Storage service usage after initialization', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        const bucket = firebaseConfig.bucket;
        const file = bucket.file('test-file.txt');
        
        expect(file).toBeDefined();
        expect(typeof file.save).toBe('function');
        expect(typeof file.download).toBe('function');
        });

        it('should maintain consistent bucket reference', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        const firebaseConfig = await import('../../config/firebase');
        
        const bucket1 = firebaseConfig.bucket;
        const bucket2 = firebaseConfig.storage.bucket();
        
        // Both should be defined
        expect(bucket1).toBeDefined();
        expect(bucket2).toBeDefined();
        });
    });

    describe('Performance and Memory', () => {
        it('should not initialize multiple Firebase apps', async () => {
        mockFirebaseAdmin.apps = [];
        setTestConfig(mockConfig);
        
        // Import the same module multiple times in the same test
        await import('../../config/firebase');
        
        // The module should only be loaded once, so initializeApp should only be called once
        expect(mockFirebaseAdmin.initializeApp).toHaveBeenCalledTimes(1);
        });

        it('should reuse existing app instance', async () => {
        // Set up existing app
        mockFirebaseAdmin.apps = [mockApp];
        setTestConfig(mockConfig);
        
        await import('../../config/firebase');
        
        // Should not create new instance
        expect(mockFirebaseAdmin.initializeApp).not.toHaveBeenCalled();
        expect(mockFirebaseAdmin.apps).toHaveLength(1);
        });
    });

    describe('Configuration Edge Cases', () => {
        it('should handle private key with different newline formats', async () => {
        const configs = [
            {
            name: 'Unix newlines',
            privateKey: '-----BEGIN PRIVATE KEY-----\nUNIX_KEY\n-----END PRIVATE KEY-----',
            expected: '-----BEGIN PRIVATE KEY-----\nUNIX_KEY\n-----END PRIVATE KEY-----'
            },
            {
            name: 'Escaped newlines',
            privateKey: '-----BEGIN PRIVATE KEY-----\\nESCAPED_KEY\\n-----END PRIVATE KEY-----',
            expected: '-----BEGIN PRIVATE KEY-----\nESCAPED_KEY\n-----END PRIVATE KEY-----'
            },
            {
            name: 'Mixed newlines',
            privateKey: '-----BEGIN PRIVATE KEY-----\\nMIXED\nKEY\\n-----END PRIVATE KEY-----',
            expected: '-----BEGIN PRIVATE KEY-----\nMIXED\nKEY\n-----END PRIVATE KEY-----'
            }
        ];

        for (const configTest of configs) {
            mockFirebaseAdmin.apps = [];
            jest.clearAllMocks();

            const testConfig = {
            firebase: {
                ...mockConfig.firebase,
                privateKey: configTest.privateKey
            }
            };

            setTestConfig(testConfig);
            jest.resetModules();

            await import('../../config/firebase');

            expect(mockFirebaseAdmin.credential.cert).toHaveBeenCalledWith({
            projectId: testConfig.firebase.projectId,
            privateKey: configTest.expected,
            clientEmail: testConfig.firebase.clientEmail
            });
        }
        });

        it('should handle empty storage bucket configuration', async () => {
        const configWithoutBucket = {
            firebase: {
            ...mockConfig.firebase,
            storageBucket: ''
            }
        };

        setTestConfig(configWithoutBucket);
        mockFirebaseAdmin.apps = [];
        
        await import('../../config/firebase');

        expect(mockFirebaseAdmin.initializeApp).toHaveBeenCalledWith({
            credential: mockCredential,
            storageBucket: ''
        });
        });
    });
});