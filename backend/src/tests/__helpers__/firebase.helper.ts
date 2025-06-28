// backend/src/__tests__/__helpers__/firebase.helper.ts
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  MockFirebaseAdmin,
  MockFirebaseStorageBucket,
  MockFirebaseStorageFile,
  MockFirebaseUser,
  MockUserRecord,
  firebaseErrorScenarios,
  firebaseTestScenarios,
  storageTestScenarios,
  createFirebaseAuthError,
  createFirebaseStorageError,
  createMockUser,
  createMockUserRecord,
  resetFirebaseMocks,
  setupFirebaseMockImplementations,
  mockFirebaseConfig
} from '../__mocks__/firebase.mock';
import * as admin from 'firebase-admin';

/**
 * Firebase test scenario interface
 */
export interface FirebaseTestScenario {
  name: string;
  setup?: () => void | Promise<void>;
  teardown?: () => void | Promise<void>;
  expectation: () => void | Promise<void>;
}

/**
 * Firebase Auth test scenario interface
 */
export interface FirebaseAuthTestScenario {
  name: string;
  uid?: string;
  email?: string;
  userProperties?: Partial<MockFirebaseUser>;
  expectedResult?: Partial<MockFirebaseUser>;
  expectedError?: keyof typeof firebaseErrorScenarios.auth;
  setup?: () => void | Promise<void>;
}

/**
 * Firebase Storage test scenario interface
 */
export interface FirebaseStorageTestScenario {
  name: string;
  fileName: string;
  fileData?: Buffer | string;
  expectedResult?: boolean | [Buffer] | [boolean] | [string];
  expectedError?: keyof typeof firebaseErrorScenarios.storage;
  setup?: () => void | Promise<void>;
}

/**
 * Helper to setup Firebase test environment
 */
export const setupFirebaseTestEnvironment = () => {
  beforeEach(() => {
    resetFirebaseMocks();
    setupFirebaseMockImplementations();
  });

  afterEach(() => {
    resetFirebaseMocks();
  });
};

/**
 * Helper to clean up Firebase test environment
 */
export const cleanupFirebaseTests = () => {
  resetFirebaseMocks();
  jest.restoreAllMocks();
};

/**
 * Helper to test Firebase initialization
 */
export const testFirebaseInitialization = (expectedConfig: any) => {
  expect(MockFirebaseAdmin.initializeApp).toHaveBeenCalledWith(
    expect.objectContaining({
      credential: expect.any(Object),
      storageBucket: expectedConfig.storageBucket
    })
  );
};

/**
 * Helper to assert Firebase app initialization
 */
export const assertFirebaseAppInitialized = (
  expectedProjectId: string,
  expectedStorageBucket: string
) => {
  expect(MockFirebaseAdmin.apps.length).toBeGreaterThan(0);
  expect(MockFirebaseAdmin.initializeApp).toHaveBeenCalledWith(
    expect.objectContaining({
      credential: expect.objectContaining({
        projectId: expectedProjectId
      }),
      storageBucket: expectedStorageBucket
    })
  );
};

/**
 * Helper to test Firebase auth operations
 */
export const testFirebaseAuthOperation = async (
  operation: string,
  method: jest.MockedFunction<any>,
  args: any[],
  expectedResult?: any,
  expectedError?: string
) => {
  if (expectedError) {
    const error = createFirebaseAuthError(expectedError as keyof typeof firebaseErrorScenarios.auth);
    method.mockRejectedValueOnce(error);
    
    await expect(async () => {
      await method(...args);
    }).rejects.toThrow(error.message);
    
    expect(method).toHaveBeenCalledWith(...args);
  } else {
    if (expectedResult) {
      method.mockResolvedValueOnce(expectedResult);
    }
    
    const result = await method(...args);
    
    expect(method).toHaveBeenCalledWith(...args);
    
    if (expectedResult) {
      expect(result).toEqual(expectedResult);
    }
  }
};

/**
 * Helper to test Firebase storage operations
 */
export const testFirebaseStorageOperation = async (
  operation: string,
  fileOrBucket: MockFirebaseStorageFile | MockFirebaseStorageBucket,
  method: string,
  args: any[] = [],
  expectedResult?: any,
  expectedError?: string
) => {
  const methodMock = (fileOrBucket as any)[method] as jest.MockedFunction<any>;
  
  if (expectedError) {
    const error = createFirebaseStorageError(expectedError as keyof typeof firebaseErrorScenarios.storage);
    methodMock.mockRejectedValueOnce(error);
    
    await expect(async () => {
      await methodMock(...args);
    }).rejects.toThrow(error.message);
    
    expect(methodMock).toHaveBeenCalledWith(...args);
  } else {
    if (expectedResult !== undefined) {
      methodMock.mockResolvedValueOnce(expectedResult);
    }
    
    const result = await methodMock(...args);
    
    expect(methodMock).toHaveBeenCalledWith(...args);
    
    if (expectedResult !== undefined) {
      expect(result).toEqual(expectedResult);
    }
  }
};

/**
 * Helper to create Firebase auth test scenarios
 */
export const createFirebaseAuthTestScenarios = (): FirebaseAuthTestScenario[] => [
  {
    name: 'should create user successfully',
    userProperties: {
      email: 'new@example.com',
      displayName: 'New User',
      emailVerified: false
    },
    expectedResult: {
      email: 'new@example.com',
      displayName: 'New User',
      emailVerified: false
    }
  },
  {
    name: 'should get user by ID successfully',
    uid: 'existing-user-123',
    expectedResult: {
      uid: 'existing-user-123',
      email: 'existing@example.com'
    }
  },
  {
    name: 'should get user by email successfully',
    email: 'existing@example.com',
    expectedResult: {
      email: 'existing@example.com',
      uid: 'existing-user-123'
    }
  },
  {
    name: 'should throw error when user not found',
    uid: 'non-existent-user',
    expectedError: 'userNotFound'
  },
  {
    name: 'should throw error when email already exists',
    userProperties: {
      email: 'existing@example.com'
    },
    expectedError: 'emailAlreadyExists'
  },
  {
    name: 'should throw error for invalid email',
    userProperties: {
      email: 'invalid-email'
    },
    expectedError: 'invalidEmail'
  }
];

/**
 * Helper to create Firebase storage test scenarios
 */
export const createFirebaseStorageTestScenarios = (): FirebaseStorageTestScenario[] => [
  {
    name: 'should upload file successfully',
    fileName: 'test-upload.jpg',
    fileData: Buffer.from('test file content'),
    expectedResult: true
  },
  {
    name: 'should download file successfully',
    fileName: 'existing-file.jpg',
    expectedResult: [Buffer.from('existing file content')]
  },
  {
    name: 'should delete file successfully',
    fileName: 'file-to-delete.jpg',
    expectedResult: undefined
  },
  {
    name: 'should check if file exists',
    fileName: 'check-existence.jpg',
    expectedResult: [true]
  },
  {
    name: 'should get signed URL for file',
    fileName: 'get-url.jpg',
    expectedResult: ['https://signed-url-example.com']
  },
  {
    name: 'should throw error when file not found',
    fileName: 'non-existent-file.jpg',
    expectedError: 'objectNotFound'
  },
  {
    name: 'should throw error when access forbidden',
    fileName: 'forbidden-file.jpg',
    expectedError: 'forbidden'
  },
  {
    name: 'should throw error when payload too large',
    fileName: 'large-file.zip',
    expectedError: 'payloadTooLarge'
  }
];

/**
 * Helper to run Firebase auth test scenarios
 */
export const runFirebaseAuthTestScenarios = (scenarios: FirebaseAuthTestScenario[]) => {
  scenarios.forEach(scenario => {
    it(scenario.name, async () => {
      const auth = MockFirebaseAdmin.getAuthInstance();
      
      if (scenario.setup) {
        await scenario.setup();
      }
      
      if (scenario.expectedError) {
        const error = createFirebaseAuthError(scenario.expectedError);
        
        if (scenario.uid) {
          (auth.getUser as jest.MockedFunction<any>).mockRejectedValueOnce(error);
          await expect(auth.getUser(scenario.uid)).rejects.toThrow(error.message);
        } else if (scenario.email) {
          (auth.getUserByEmail as jest.MockedFunction<any>).mockRejectedValueOnce(error);
          await expect(auth.getUserByEmail(scenario.email)).rejects.toThrow(error.message);
        } else if (scenario.userProperties) {
          (auth.createUser as jest.MockedFunction<any>).mockRejectedValueOnce(error);
          await expect(auth.createUser(scenario.userProperties)).rejects.toThrow(error.message);
        }
      } else {
        if (scenario.userProperties) {
          const result = await auth.createUser(scenario.userProperties);
          if (scenario.expectedResult) {
            expect(result).toMatchObject(scenario.expectedResult);
          }
        } else if (scenario.uid) {
          const result = await auth.getUser(scenario.uid);
          if (scenario.expectedResult) {
            expect(result).toMatchObject(scenario.expectedResult);
          }
        } else if (scenario.email) {
          const result = await auth.getUserByEmail(scenario.email);
          if (scenario.expectedResult) {
            expect(result).toMatchObject(scenario.expectedResult);
          }
        }
      }
    });
  });
};

/**
 * Helper to run Firebase storage test scenarios
 */
export const runFirebaseStorageTestScenarios = (scenarios: FirebaseStorageTestScenario[]) => {
  scenarios.forEach(scenario => {
    it(scenario.name, async () => {
      const storage = MockFirebaseAdmin.getStorageInstance();
      const bucket = storage.bucket() as MockFirebaseStorageBucket;
      const file = bucket.file(scenario.fileName);
      
      if (scenario.setup) {
        await scenario.setup();
      }
      
      if (scenario.expectedError) {
        const error = createFirebaseStorageError(scenario.expectedError);
        
        // Test different operations based on scenario
        if (scenario.name.includes('upload')) {
          (bucket.upload as jest.MockedFunction<any>).mockRejectedValueOnce(error);
          await expect(bucket.upload(`/local/path/${scenario.fileName}`)).rejects.toThrow(error.message);
        } else if (scenario.name.includes('download')) {
          (file.download as jest.MockedFunction<any>).mockRejectedValueOnce(error);
          await expect(file.download()).rejects.toThrow(error.message);
        } else if (scenario.name.includes('delete')) {
          (file.delete as jest.MockedFunction<any>).mockRejectedValueOnce(error);
          await expect(file.delete()).rejects.toThrow(error.message);
        } else if (scenario.name.includes('exists')) {
          (file.exists as jest.MockedFunction<any>).mockRejectedValueOnce(error);
          await expect(file.exists()).rejects.toThrow(error.message);
        } else if (scenario.name.includes('URL')) {
          (file.getSignedUrl as jest.MockedFunction<any>).mockRejectedValueOnce(error);
          await expect(file.getSignedUrl({ action: 'read', expires: Date.now() + 3600000 })).rejects.toThrow(error.message);
        }
      } else {
        // Test successful operations
        if (scenario.name.includes('upload')) {
          const result = await bucket.upload(`/local/path/${scenario.fileName}`);
          expect(result).toBeDefined();
          expect(result[0]).toBeInstanceOf(MockFirebaseStorageFile);
        } else if (scenario.name.includes('download')) {
          if (scenario.expectedResult) {
            (file.download as jest.MockedFunction<any>).mockResolvedValueOnce(scenario.expectedResult);
          }
          const result = await file.download();
          if (scenario.expectedResult) {
            expect(result).toEqual(scenario.expectedResult);
          }
        } else if (scenario.name.includes('delete')) {
          await file.delete();
          expect(file.delete).toHaveBeenCalled();
        } else if (scenario.name.includes('exists')) {
          if (scenario.expectedResult) {
            (file.exists as jest.MockedFunction<any>).mockResolvedValueOnce(scenario.expectedResult);
          }
          const result = await file.exists();
          if (scenario.expectedResult) {
            expect(result).toEqual(scenario.expectedResult);
          }
        } else if (scenario.name.includes('URL')) {
          if (scenario.expectedResult) {
            (file.getSignedUrl as jest.MockedFunction<any>).mockResolvedValueOnce(scenario.expectedResult);
          }
          const result = await file.getSignedUrl({ action: 'read', expires: Date.now() + 3600000 });
          if (scenario.expectedResult) {
            expect(result).toEqual(scenario.expectedResult);
          }
        }
      }
    });
  });
};

/**
 * Helper to assert user properties
 */
export const assertUserProperties = (
  user: MockFirebaseUser | MockUserRecord,
  expectedProperties: Partial<MockFirebaseUser>
) => {
  Object.keys(expectedProperties).forEach(key => {
    const expectedValue = expectedProperties[key as keyof MockFirebaseUser];
    const actualValue = user[key as keyof MockFirebaseUser];
    expect(actualValue).toEqual(expectedValue);
  });
};

/**
 * Helper to assert file properties
 */
export const assertFileProperties = (
  file: MockFirebaseStorageFile,
  expectedProperties: {
    name?: string;
    bucket?: string;
    exists?: boolean;
    metadata?: Record<string, any>;
  }
) => {
  if (expectedProperties.name) {
    expect(file.name).toBe(expectedProperties.name);
  }
  
  if (expectedProperties.bucket) {
    expect(file.bucket).toBe(expectedProperties.bucket);
  }
  
  if (expectedProperties.metadata) {
    expect(file.metadata).toMatchObject(expectedProperties.metadata);
  }
};

/**
 * Helper to create mock Firebase initialization test
 */
export const testFirebaseInitializationScenario = (
  scenario: {
    name: string;
    config: any;
    expectedCalls: number;
    shouldInitialize: boolean;
  }
) => {
  it(scenario.name, () => {
    // Reset apps array to simulate different initialization states
    MockFirebaseAdmin.apps = scenario.shouldInitialize ? [] : [{ name: '[DEFAULT]' } as any];
    
    if (scenario.shouldInitialize) {
      expect(MockFirebaseAdmin.initializeApp).toHaveBeenCalledTimes(scenario.expectedCalls);
    } else {
      expect(MockFirebaseAdmin.initializeApp).not.toHaveBeenCalled();
    }
  });
};

/**
 * Helper to test Firebase config validation
 */
export const testFirebaseConfigValidation = (
  configs: Array<{
    name: string;
    config: any;
    isValid: boolean;
    expectedError?: string;
  }>
) => {
  configs.forEach(configTest => {
    it(configTest.name, () => {
      if (configTest.isValid) {
        expect(() => {
          MockFirebaseAdmin.credential.cert(configTest.config);
        }).not.toThrow();
      } else {
        expect(() => {
          MockFirebaseAdmin.credential.cert(configTest.config);
        }).toThrow(configTest.expectedError);
      }
    });
  });
};

/**
 * Helper to create comprehensive Firebase test suites
 */
export const createFirebaseTestSuite = (
  testType: 'auth' | 'storage' | 'both',
  customScenarios?: {
    auth?: FirebaseAuthTestScenario[];
    storage?: FirebaseStorageTestScenario[];
  }
) => {
  const authScenarios = customScenarios?.auth || createFirebaseAuthTestScenarios();
  const storageScenarios = customScenarios?.storage || createFirebaseStorageTestScenarios();
  
  if (testType === 'auth' || testType === 'both') {
    describe('Firebase Auth Operations', () => {
      runFirebaseAuthTestScenarios(authScenarios);
    });
  }
  
  if (testType === 'storage' || testType === 'both') {
    describe('Firebase Storage Operations', () => {
      runFirebaseStorageTestScenarios(storageScenarios);
    });
  }
};

/**
 * Helper to mock Firebase method implementations for specific tests
 */
export const mockFirebaseMethod = (
  service: 'auth' | 'storage',
  method: string,
  implementation: (...args: any[]) => any
) => {
  if (service === 'auth') {
    const auth = MockFirebaseAdmin.getAuthInstance();
    const methodMock = (auth as any)[method] as jest.MockedFunction<any>;
    methodMock.mockImplementation(implementation);
  } else if (service === 'storage') {
    const storage = MockFirebaseAdmin.getStorageInstance();
    const methodMock = (storage as any)[method] as jest.MockedFunction<any>;
    methodMock.mockImplementation(implementation);
  }
};

/**
 * Helper to simulate Firebase rate limiting
 */
export const simulateFirebaseRateLimit = (
  service: 'auth' | 'storage',
  method: string,
  retryAfter: number = 1000
) => {
  const rateLimitError = new Error('Rate limit exceeded');
  (rateLimitError as any).code = 'RATE_LIMIT_EXCEEDED';
  (rateLimitError as any).retryAfter = retryAfter;
  
  mockFirebaseMethod(service, method, jest.fn<(...args: any[]) => Promise<never>>().mockRejectedValue(rateLimitError));
};

/**
 * Helper to simulate Firebase network errors
 */
export const simulateFirebaseNetworkError = (
  service: 'auth' | 'storage',
  method: string
) => {
  const networkError = new Error('Network error');
  (networkError as any).code = 'NETWORK_ERROR';
  
  mockFirebaseMethod(service, method, jest.fn<(...args: any[]) => Promise<never>>().mockRejectedValue(networkError));
};

/**
 * Firebase batch operation interface
 */
interface FirebaseBatchOperation {
  type: 'auth' | 'storage';
  method: string;
  args: any[];
  expectedResult?: any;
  expectedError?: string;
}

/**
 * Helper to test Firebase batch operations
 */
export const testFirebaseBatchOperations = async (
  operations: FirebaseBatchOperation[]
) => {
  const results = [];
  
  for (const operation of operations) {
    try {
      if (operation.type === 'auth') {
        const auth = MockFirebaseAdmin.getAuthInstance();
        const method = (auth as any)[operation.method] as jest.MockedFunction<any>;
        
        if (operation.expectedError) {
          const error = createFirebaseAuthError(operation.expectedError as keyof typeof firebaseErrorScenarios.auth);
          method.mockRejectedValueOnce(error);
          await expect(method(...operation.args)).rejects.toThrow(error.message);
        } else {
          const result = await method(...operation.args);
          results.push(result);
          
          if (operation.expectedResult) {
            expect(result).toMatchObject(operation.expectedResult);
          }
        }
      } else if (operation.type === 'storage') {
        const storage = MockFirebaseAdmin.getStorageInstance();
        const bucket = storage.bucket() as MockFirebaseStorageBucket;
        const method = (bucket as any)[operation.method] as jest.MockedFunction<any>;
        
        if (operation.expectedError) {
          const error = createFirebaseStorageError(operation.expectedError as keyof typeof firebaseErrorScenarios.storage);
          method.mockRejectedValueOnce(error);
          await expect(method(...operation.args)).rejects.toThrow(error.message);
        } else {
          const result = await method(...operation.args);
          results.push(result);
          
          if (operation.expectedResult) {
            expect(result).toEqual(operation.expectedResult);
          }
        }
      }
    } catch (error) {
      if (!operation.expectedError) {
        throw error;
      }
    }
  }
  
  return results;
};

/**
 * Expected method call interface
 */
interface ExpectedMethodCall {
  args: any[];
  callIndex?: number;
}

/**
 * Helper to assert Firebase method calls
 */
export const assertFirebaseMethodCalls = (
  service: 'auth' | 'storage',
  method: string,
  expectedCalls: ExpectedMethodCall[]
) => {
  let methodMock: jest.MockedFunction<any>;
  
  if (service === 'auth') {
    const auth = MockFirebaseAdmin.getAuthInstance();
    methodMock = (auth as any)[method] as jest.MockedFunction<any>;
  } else {
    const storage = MockFirebaseAdmin.getStorageInstance();
    methodMock = (storage as any)[method] as jest.MockedFunction<any>;
  }
  
  expect(methodMock).toHaveBeenCalledTimes(expectedCalls.length);
  
  expectedCalls.forEach((expectedCall, index) => {
    const callIndex = expectedCall.callIndex ?? index;
    expect(methodMock).toHaveBeenNthCalledWith(callIndex + 1, ...expectedCall.args);
  });
};

/**
 * Error handling scenario interfaces
 */
interface AuthErrorScenario {
  name: string;
  errorType: keyof typeof firebaseErrorScenarios.auth;
  expectedStatusCode: number;
  expectedMessage: string;
}

interface StorageErrorScenario {
  name: string;
  errorType: keyof typeof firebaseErrorScenarios.storage;
  expectedStatusCode: number;
  expectedMessage: string;
}

/**
 * Helper to create Firebase error handling test scenarios
 */
export const createFirebaseErrorHandlingScenarios = () => ({
  authErrors: Object.keys(firebaseErrorScenarios.auth).map((errorType): AuthErrorScenario => ({
    name: `should handle ${errorType} error`,
    errorType: errorType as keyof typeof firebaseErrorScenarios.auth,
    expectedStatusCode: 400,
    expectedMessage: firebaseErrorScenarios.auth[errorType as keyof typeof firebaseErrorScenarios.auth].message
  })),
  
  storageErrors: Object.keys(firebaseErrorScenarios.storage).map((errorType): StorageErrorScenario => ({
    name: `should handle ${errorType} error`,
    errorType: errorType as keyof typeof firebaseErrorScenarios.storage,
    expectedStatusCode: firebaseErrorScenarios.storage[errorType as keyof typeof firebaseErrorScenarios.storage].code,
    expectedMessage: firebaseErrorScenarios.storage[errorType as keyof typeof firebaseErrorScenarios.storage].message
  }))
});

/**
 * Express integration test scenario interface
 */
interface FirebaseExpressTestScenario {
  name: string;
  requestData: any;
  firebaseOperation: () => Promise<any>;
  expectedResponse: {
    statusCode: number;
    body: any;
  };
  expectedError?: string;
}

/**
 * Helper to test Firebase service integration with Express middleware
 */
export const testFirebaseExpressIntegration = (
  scenario: FirebaseExpressTestScenario
) => {
  it(scenario.name, async () => {
    try {
      if (scenario.expectedError) {
        await expect(scenario.firebaseOperation()).rejects.toThrow(scenario.expectedError);
      } else {
        const result = await scenario.firebaseOperation();
        expect(result).toBeDefined();
      }
    } catch (error) {
      if (!scenario.expectedError) {
        throw error;
      }
      expect((error as Error).message).toContain(scenario.expectedError);
    }
  });
};

/**
 * Helper to create parameterized Firebase tests
 */
export const createParameterizedFirebaseTests = (
  testFunction: (scenario: any) => void,
  scenarios: any[]
) => {
  scenarios.forEach(scenario => {
    testFunction(scenario);
  });
};

/**
 * Helper to setup Firebase test data
 */
export const setupFirebaseTestData = () => {
  const auth = MockFirebaseAdmin.getAuthInstance();
  const storage = MockFirebaseAdmin.getStorageInstance();
  const bucket = storage.bucket() as MockFirebaseStorageBucket;
  
  // Setup test users
  Object.values(firebaseTestScenarios).forEach(userData => {
    if ('uid' in userData) {
      (auth.getUser as jest.MockedFunction<any>).mockImplementation(async (uid: string) => {
        if (uid === userData.uid) {
          return createMockUserRecord(userData);
        }
        throw createFirebaseAuthError('userNotFound');
      });
      
      if (userData.email) {
        (auth.getUserByEmail as jest.MockedFunction<any>).mockImplementation(async (email: string) => {
          if (email === userData.email) {
            return createMockUserRecord(userData);
          }
          throw createFirebaseAuthError('userNotFound');
        });
      }
    }
  });
  
  // Setup test files
  Object.values(storageTestScenarios).forEach(fileData => {
    bucket.addFile(fileData.name, new MockFirebaseStorageFile(fileData.name));
  });
  
  return { auth, storage, bucket };
};

/**
 * Helper to verify Firebase initialization with correct config
 */
export const verifyFirebaseInitialization = (expectedConfig: typeof mockFirebaseConfig) => {
  expect(MockFirebaseAdmin.initializeApp).toHaveBeenCalledWith(
    expect.objectContaining({
      credential: expect.objectContaining({
        projectId: expectedConfig.projectId,
        clientEmail: expectedConfig.clientEmail
      }),
      storageBucket: expectedConfig.storageBucket
    })
  );
};

/**
 * Mock stream interfaces
 */
interface MockReadStream {
  pipe: jest.MockedFunction<any>;
  on: jest.MockedFunction<any>;
  read: jest.MockedFunction<any>;
  destroy: jest.MockedFunction<any>;
}

interface MockWriteStream {
  write: jest.MockedFunction<any>;
  end: jest.MockedFunction<any>;
  on: jest.MockedFunction<any>;
  destroy: jest.MockedFunction<any>;
}

/**
 * Helper to create mock Firebase streams for testing
 */
export const createMockFirebaseStreams = (): { readStream: MockReadStream; writeStream: MockWriteStream } => {
  const readStream: MockReadStream = {
    pipe: jest.fn(),
    on: jest.fn(),
    read: jest.fn(),
    destroy: jest.fn()
  };
  
  const writeStream: MockWriteStream = {
    write: jest.fn(),
    end: jest.fn(),
    on: jest.fn(),
    destroy: jest.fn()
  };
  
  return { readStream, writeStream };
};

let firebaseApp: admin.app.App | null = null;

/**
 * Initialize Firebase for testing with emulator
 */
const initializeTestFirebase = () => {
  // Set emulator environment variables with new ports
  process.env.FIRESTORE_EMULATOR_HOST = 'localhost:9100';
  process.env.FIREBASE_AUTH_EMULATOR_HOST = 'localhost:9099';
  process.env.FIREBASE_STORAGE_EMULATOR_HOST = 'localhost:9199';

  // Initialize Firebase Admin SDK for testing
  if (!firebaseApp && admin.apps.length === 0) {
    firebaseApp = admin.initializeApp({
      projectId: 'demo-test-project',
      storageBucket: 'demo-test-project.appspot.com'
    }, 'test-app');
  }

  const storage = admin.storage(firebaseApp!);
  const bucket = storage.bucket();

  return {
    firebaseAdmin: firebaseApp!,
    storage,
    bucket
  };
};

/**
 * Clean up Firebase test instance
 */
const cleanupTestFirebase = async () => {
  if (firebaseApp) {
    await firebaseApp.delete();
    firebaseApp = null;
  }
};

/**
 * Reset Firebase emulator data
 */
const resetFirebaseEmulator = async () => {
  // Clear Auth emulator
  try {
    const response = await fetch('http://localhost:9099/emulator/v1/projects/demo-test-project/accounts');
    if (response.ok) {
      const { users } = await response.json();
      for (const user of users || []) {
        await fetch(`http://localhost:9099/emulator/v1/projects/demo-test-project/accounts/${user.localId}`, {
          method: 'DELETE'
        });
      }
    }
  } catch (error) {
    console.warn('Failed to clear Auth emulator:', error);
  }

  // Clear Firestore emulator
  try {
    await fetch('http://localhost:9100/emulator/v1/projects/demo-test-project/databases/(default)/documents', {
      method: 'DELETE'
    });
  } catch (error) {
    console.warn('Failed to clear Firestore emulator:', error);
  }

  // Clear Storage emulator
  try {
    await fetch('http://localhost:9199/storage/v1/b/demo-test-project.appspot.com/o', {
      method: 'DELETE'
    });
  } catch (error) {
    console.warn('Failed to clear Storage emulator:', error);
  }
};

/**
 * Wait for Firebase emulators to be ready
 */
export const waitForFirebaseEmulators = async (maxRetries = 30, interval = 1000): Promise<boolean> => {
  const emulatorUrls = [
    'http://localhost:4001',  // Firebase UI
    'http://localhost:9099',  // Auth Emulator
    'http://localhost:9100',  // Firestore Emulator
    'http://localhost:9199'   // Storage Emulator
  ];

  for (let i = 0; i < maxRetries; i++) {
    try {
      const checks = emulatorUrls.map(async (url) => {
        const response = await fetch(url);
        return response.ok;
      });

      const results = await Promise.all(checks);
      if (results.every(ready => ready)) {
        return true;
      }
    } catch (error) {
      // Emulators not ready yet
    }
    
    await new Promise(resolve => setTimeout(resolve, interval));
  }
  
  return false;
};

/**
 * Export commonly used test utilities
 */
export {
  firebaseTestScenarios,
  storageTestScenarios,
  mockFirebaseConfig,
  createMockUser,
  createMockUserRecord,
  createFirebaseAuthError,
  createFirebaseStorageError,
  initializeTestFirebase,
  cleanupTestFirebase,
  resetFirebaseEmulator,
};