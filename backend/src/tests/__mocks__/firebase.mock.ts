// koutu/backend/src/tests/__mocks__/firebase.mock.ts

// Mock Firebase Admin types
export interface MockFile {
  name: string;
  bucket: MockBucket;
  createWriteStream: jest.Mock;
  createReadStream: jest.Mock;
  download: jest.Mock;
  delete: jest.Mock;
  exists: jest.Mock;
  getMetadata: jest.Mock;
  getSignedUrl: jest.Mock;
  makePublic: jest.Mock;
  save: jest.Mock;
}

export interface MockBucket {
  name: string;
  file: jest.Mock;
  upload: jest.Mock;
  getFiles: jest.Mock;
  deleteFiles: jest.Mock;
  exists: jest.Mock;
}

export interface MockStorage {
  bucket: jest.Mock;
}

export interface MockApp {
  name: string;
  options: any;
  delete: jest.Mock;
}

export interface MockAdmin {
  apps: MockApp[];
  initializeApp: jest.Mock;
  credential: {
    cert: jest.Mock;
    applicationDefault: jest.Mock;
  };
  storage: jest.Mock;
}

// Mock file stream
export class MockWriteStream {
  private eventHandlers: { [key: string]: Function[] } = {};
  
  on(event: string, handler: Function) {
    if (!this.eventHandlers[event]) {
      this.eventHandlers[event] = [];
    }
    this.eventHandlers[event].push(handler);
    return this;
  }
  
  end(data?: any) {
    // Simulate async behavior
    setTimeout(() => {
      this.emit('finish');
    }, 0);
  }
  
  write(data: any) {
    return true;
  }
  
  emit(event: string, ...args: any[]) {
    if (this.eventHandlers[event]) {
      this.eventHandlers[event].forEach(handler => handler(...args));
    }
  }
  
  simulateError(error: Error) {
    this.emit('error', error);
  }
}

// Create mock file
export const createMockFile = (name: string): MockFile => {
  const mockFile: MockFile = {
    name,
    bucket: {} as MockBucket,
    createWriteStream: jest.fn(() => new MockWriteStream()),
    createReadStream: jest.fn(),
    download: jest.fn(),
    delete: jest.fn(),
    exists: jest.fn(() => Promise.resolve([true])),
    getMetadata: jest.fn(() => Promise.resolve([{
      name,
      size: 1024,
      contentType: 'image/jpeg',
      timeCreated: new Date().toISOString(),
      updated: new Date().toISOString()
    }])),
    getSignedUrl: jest.fn(() => Promise.resolve([`https://storage.googleapis.com/mock-bucket/${name}?signature=mock`])),
    makePublic: jest.fn(() => Promise.resolve()),
    save: jest.fn(() => Promise.resolve())
  };
  
  return mockFile;
};

// Create mock bucket
export const createMockBucket = (name: string = 'mock-bucket'): MockBucket => {
  const fileMap = new Map<string, MockFile>();
  
  const mockBucket: MockBucket = {
    name,
    file: jest.fn((fileName: string) => {
      if (!fileMap.has(fileName)) {
        const mockFile = createMockFile(fileName);
        mockFile.bucket = mockBucket;
        fileMap.set(fileName, mockFile);
      }
      return fileMap.get(fileName);
    }),
    upload: jest.fn(() => Promise.resolve([createMockFile('uploaded-file.jpg')])),
    getFiles: jest.fn(() => Promise.resolve([Array.from(fileMap.values())])),
    deleteFiles: jest.fn(() => Promise.resolve()),
    exists: jest.fn(() => Promise.resolve([true]))
  };
  
  return mockBucket;
};

// Create mock storage
export const createMockStorage = (): MockStorage => {
  const bucketMap = new Map<string, MockBucket>();
  
  return {
    bucket: jest.fn((bucketName?: string) => {
      const name = bucketName || 'default-bucket';
      if (!bucketMap.has(name)) {
        bucketMap.set(name, createMockBucket(name));
      }
      return bucketMap.get(name);
    })
  };
};

// Create mock admin
export const createMockAdmin = (): MockAdmin => {
  const mockStorage = createMockStorage();
  
  return {
    apps: [],
    initializeApp: jest.fn((config) => {
      const app: MockApp = {
        name: '[DEFAULT]',
        options: config,
        delete: jest.fn()
      };
      return app;
    }),
    credential: {
      cert: jest.fn((config) => ({ config })),
      applicationDefault: jest.fn()
    },
    storage: jest.fn(() => mockStorage)
  };
};

// Mock Firebase config
export const mockFirebaseConfig = {
  projectId: 'test-project-id',
  privateKey: '-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY\n-----END PRIVATE KEY-----',
  clientEmail: 'test@test-project.iam.gserviceaccount.com',
  storageBucket: 'test-bucket.appspot.com'
};

// Mock successful file upload scenario
export const mockSuccessfulUpload = {
  fileName: 'test-image.jpg',
  fileBuffer: Buffer.from('mock image data'),
  uploadedPath: 'uploads/test-image.jpg',
  signedUrl: 'https://storage.googleapis.com/test-bucket/uploads/test-image.jpg?signature=mock'
};

// Mock file metadata
export const mockFileMetadata = {
  name: 'test-file.jpg',
  size: 102400,
  contentType: 'image/jpeg',
  metadata: {
    originalFilename: 'original.jpg',
    uploadedBy: 'test-user-id'
  },
  timeCreated: '2024-01-01T00:00:00.000Z',
  updated: '2024-01-01T00:00:00.000Z'
};

// Mock error scenarios
export const mockFirebaseErrors = {
  authError: new Error('Firebase authentication failed'),
  networkError: new Error('Network error: Unable to connect to Firebase'),
  quotaError: new Error('Quota exceeded for Firebase Storage'),
  notFoundError: new Error('File not found in Firebase Storage'),
  permissionError: new Error('Permission denied: Insufficient permissions')
};

// Mock stream events
export const mockStreamEvents = {
  success: () => {
    const stream = new MockWriteStream();
    setTimeout(() => stream.emit('finish'), 10);
    return stream;
  },
  error: (error: Error) => {
    const stream = new MockWriteStream();
    setTimeout(() => stream.emit('error', error), 10);
    return stream;
  }
};

// Helper to create a mock file with specific properties
export const createMockFileWithProperties = (properties: Partial<MockFile>): MockFile => {
  const defaultFile = createMockFile('custom-file.jpg');
  return { ...defaultFile, ...properties };
};