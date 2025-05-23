// koutu/backend/src/tests/__helpers__/firebase.helper.ts

import * as admin from 'firebase-admin';
import { 
  createMockAdmin, 
  createMockBucket, 
  createMockFile,
  MockAdmin,
  MockBucket,
  MockFile,
  MockWriteStream,
  mockFirebaseConfig
} from '../__mocks__/firebase.mock';

// Module path for mocking
export const FIREBASE_MODULE_PATH = '../../config/firebase';
export const FIREBASE_ADMIN_MODULE = 'firebase-admin';

// Setup Firebase mocks
export const setupFirebaseMocks = () => {
  // Create mock instances
  const mockAdmin = createMockAdmin();
  const mockBucket = createMockBucket(mockFirebaseConfig.storageBucket);
  
  // Mock the firebase-admin module
  jest.mock(FIREBASE_ADMIN_MODULE, () => mockAdmin);
  
  // Mock the firebase config module
  jest.mock(FIREBASE_MODULE_PATH, () => ({
    firebaseAdmin: mockAdmin,
    storage: mockAdmin.storage(),
    bucket: mockBucket
  }));
  
  return { mockAdmin, mockBucket };
};

// Reset Firebase mocks
export const resetFirebaseMocks = () => {
  jest.clearAllMocks();
};

// Helper to simulate Firebase initialization
export const simulateFirebaseInit = (
  mockAdmin: MockAdmin,
  config = mockFirebaseConfig
) => {
  // Simulate no apps initially
  mockAdmin.apps = [];
  
  // Setup cert mock
  mockAdmin.credential.cert.mockReturnValue({ config });
  
  // Setup initializeApp to add app to apps array
  mockAdmin.initializeApp.mockImplementation((appConfig) => {
    const app = {
      name: '[DEFAULT]',
      options: appConfig,
      delete: jest.fn()
    };
    mockAdmin.apps.push(app);
    return app;
  });
};

// Helper to verify Firebase initialization
export const verifyFirebaseInit = (mockAdmin: MockAdmin, expectedConfig: any) => {
  expect(mockAdmin.credential.cert).toHaveBeenCalledWith({
    projectId: expectedConfig.projectId,
    privateKey: expectedConfig.privateKey,
    clientEmail: expectedConfig.clientEmail,
  });
  
  expect(mockAdmin.initializeApp).toHaveBeenCalledWith({
    credential: expect.any(Object),
    storageBucket: expectedConfig.storageBucket
  });
};

// Helper to simulate file operations
export const simulateFileOperations = {
  // Simulate successful file upload
  upload: (mockFile: MockFile, content: Buffer | string) => {
    const writeStream = new MockWriteStream();
    mockFile.createWriteStream.mockReturnValue(writeStream);
    
    // Simulate successful write
    setTimeout(() => {
      writeStream.emit('finish');
    }, 0);
    
    return writeStream;
  },
  
  // Simulate file upload error
  uploadError: (mockFile: MockFile, error: Error) => {
    const writeStream = new MockWriteStream();
    mockFile.createWriteStream.mockReturnValue(writeStream);
    
    // Simulate error during write
    setTimeout(() => {
      writeStream.emit('error', error);
    }, 0);
    
    return writeStream;
  },
  
  // Simulate file exists check
  exists: (mockFile: MockFile, exists: boolean) => {
    mockFile.exists.mockResolvedValue([exists]);
  },
  
  // Simulate file deletion
  delete: (mockFile: MockFile, success: boolean = true) => {
    if (success) {
      mockFile.delete.mockResolvedValue(undefined);
    } else {
      mockFile.delete.mockRejectedValue(new Error('Delete failed'));
    }
  },
  
  // Simulate getting signed URL
  getSignedUrl: (mockFile: MockFile, url: string) => {
    mockFile.getSignedUrl.mockResolvedValue([url]);
  },
  
  // Simulate file metadata
  getMetadata: (mockFile: MockFile, metadata: any) => {
    mockFile.getMetadata.mockResolvedValue([metadata]);
  }
};

// Helper to verify bucket operations
export const verifyBucketOperations = {
  fileAccess: (mockBucket: MockBucket, fileName: string) => {
    expect(mockBucket.file).toHaveBeenCalledWith(fileName);
  },
  
  upload: (mockBucket: MockBucket, localPath: string, options?: any) => {
    expect(mockBucket.upload).toHaveBeenCalledWith(localPath, options);
  },
  
  getFiles: (mockBucket: MockBucket, query?: any) => {
    expect(mockBucket.getFiles).toHaveBeenCalledWith(query);
  }
};

// Helper to verify file operations
export const verifyFileOperations = {
  createWriteStream: (mockFile: MockFile, options?: any) => {
    expect(mockFile.createWriteStream).toHaveBeenCalledWith(options);
  },
  
  delete: (mockFile: MockFile) => {
    expect(mockFile.delete).toHaveBeenCalled();
  },
  
  exists: (mockFile: MockFile) => {
    expect(mockFile.exists).toHaveBeenCalled();
  },
  
  getSignedUrl: (mockFile: MockFile, config: any) => {
    expect(mockFile.getSignedUrl).toHaveBeenCalledWith(config);
  },
  
  getMetadata: (mockFile: MockFile) => {
    expect(mockFile.getMetadata).toHaveBeenCalled();
  }
};

// Helper to create test scenarios
export const createFirebaseTestScenario = {
  // Scenario: Firebase not initialized
  notInitialized: (mockAdmin: MockAdmin) => {
    mockAdmin.apps = [];
  },
  
  // Scenario: Firebase already initialized
  alreadyInitialized: (mockAdmin: MockAdmin) => {
    mockAdmin.apps = [{
      name: '[DEFAULT]',
      options: {},
      delete: jest.fn()
    }];
  },
  
  // Scenario: Invalid credentials
  invalidCredentials: () => {
    return {
      projectId: '',
      privateKey: '',
      clientEmail: '',
      storageBucket: ''
    };
  },
  
  // Scenario: Multiple buckets
  multipleBuckets: (mockStorage: any) => {
    const buckets = {
      primary: createMockBucket('primary-bucket'),
      backup: createMockBucket('backup-bucket'),
      temp: createMockBucket('temp-bucket')
    };
    
    mockStorage.bucket.mockImplementation((name: string) => {
      return buckets[name as keyof typeof buckets] || buckets.primary;
    });
    
    return buckets;
  }
};

// Helper to test error handling
export const testFirebaseErrorHandling = async (
  operation: () => Promise<any>,
  expectedError: Error
) => {
  await expect(operation()).rejects.toThrow(expectedError);
};

// Helper to mock config with different environments
export const mockConfigForEnvironment = (env: 'development' | 'production' | 'test') => {
  const configs = {
    development: {
      ...mockFirebaseConfig,
      projectId: 'dev-project',
      storageBucket: 'dev-bucket.appspot.com'
    },
    production: {
      ...mockFirebaseConfig,
      projectId: 'prod-project',
      storageBucket: 'prod-bucket.appspot.com'
    },
    test: {
      ...mockFirebaseConfig,
      projectId: 'test-project',
      storageBucket: 'test-bucket.appspot.com'
    }
  };
  
  return configs[env];
};

// Helper to simulate network conditions
export const simulateNetworkConditions = {
  // Simulate network timeout
  timeout: (mockFile: MockFile, operation: string, delay: number = 5000) => {
    (mockFile as any)[operation].mockImplementation(() => 
      new Promise((_, reject) => 
        setTimeout(() => reject(new Error('Network timeout')), delay)
      )
    );
  },
  
  // Simulate intermittent failures
  intermittent: (mockFile: MockFile, operation: string, failureRate: number = 0.5) => {
    let callCount = 0;
    (mockFile as any)[operation].mockImplementation(() => {
      callCount++;
      if (Math.random() < failureRate) {
        return Promise.reject(new Error('Network error'));
      }
      return Promise.resolve([true]);
    });
  }
};

// Helper to verify private key transformation
export const verifyPrivateKeyTransformation = (originalKey: string, transformedKey: string) => {
  expect(transformedKey).toBe(originalKey.replace(/\\n/g, '\n'));
};

// Helper for testing concurrent operations
export const testConcurrentOperations = async (
  operations: (() => Promise<any>)[],
  expectedResults?: any[]
) => {
  const results = await Promise.all(operations);
  if (expectedResults) {
    expect(results).toEqual(expectedResults);
  }
  return results;
};