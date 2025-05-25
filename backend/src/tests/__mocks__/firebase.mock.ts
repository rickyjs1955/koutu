// backend/src/__tests__/__mocks__/firebase.mock.ts
import { jest } from '@jest/globals';

/**
 * Mock Firebase Authentication User
 */
export interface MockFirebaseUser {
  uid: string;
  email?: string | null;
  emailVerified: boolean;
  displayName?: string | null;
  photoURL?: string | null;
  phoneNumber?: string | null;
  disabled?: boolean;
  metadata: {
    creationTime?: string;
    lastSignInTime?: string;
  };
  customClaims?: Record<string, any>;
  providerData: Array<{
    uid: string;
    displayName?: string | null;
    email?: string | null;
    photoURL?: string | null;
    providerId: string;
    phoneNumber?: string | null;
  }>;
  toJSON(): Record<string, any>;
}

/**
 * Mock Firebase Auth Result
 */
export interface MockUserRecord extends MockFirebaseUser {
  delete(): Promise<void>;
  reload(): Promise<void>;
}

/**
 * Mock Firebase Storage File
 */
export interface MockStorageFile {
  name: string;
  bucket: string;
  generation?: string;
  metadata?: Record<string, any>;
  save(data: Buffer | string, options?: any): Promise<void>;
  delete(): Promise<void>;
  exists(): Promise<[boolean]>;
  download(): Promise<[Buffer]>;
  getMetadata(): Promise<[Record<string, any>]>;
  setMetadata(metadata: Record<string, any>): Promise<[Record<string, any>]>;
  getSignedUrl(options: any): Promise<[string]>;
  createReadStream(): NodeJS.ReadableStream;
  createWriteStream(options?: any): NodeJS.WritableStream;
}

/**
 * Mock Firebase Storage Bucket
 */
export interface MockStorageBucket {
  name: string;
  file(name: string): MockStorageFile;
  getFiles(options?: any): Promise<[MockStorageFile[]]>;
  upload(localFilePath: string, options?: any): Promise<[MockStorageFile]>;
  exists(): Promise<[boolean]>;
  delete(): Promise<void>;
}

/**
 * Mock Firebase Admin Auth
 */
class MockFirebaseAuth {
  createUser = jest.fn<(properties: any) => Promise<MockUserRecord>>();
  updateUser = jest.fn<(uid: string, properties: any) => Promise<MockUserRecord>>();
  deleteUser = jest.fn<(uid: string) => Promise<void>>();
  getUser = jest.fn<(uid: string) => Promise<MockUserRecord>>();
  getUserByEmail = jest.fn<(email: string) => Promise<MockUserRecord>>();
  getUserByPhoneNumber = jest.fn<(phoneNumber: string) => Promise<MockUserRecord>>();
  listUsers = jest.fn<(maxResults?: number, pageToken?: string) => Promise<any>>();
  setCustomUserClaims = jest.fn<(uid: string, customClaims: Record<string, any> | null) => Promise<void>>();
  createCustomToken = jest.fn<(uid: string, developerClaims?: Record<string, any>) => Promise<string>>();
  verifyIdToken = jest.fn<(idToken: string, checkRevoked?: boolean) => Promise<any>>();
  verifySessionCookie = jest.fn<(sessionCookie: string, checkRevoked?: boolean) => Promise<any>>();
  createSessionCookie = jest.fn<(idToken: string, sessionCookieOptions: any) => Promise<string>>();
  revokeRefreshTokens = jest.fn<(uid: string) => Promise<void>>();
  importUsers = jest.fn<(users: any[], options?: any) => Promise<any>>();
  generatePasswordResetLink = jest.fn<(email: string, actionCodeSettings?: any) => Promise<string>>();
  generateEmailVerificationLink = jest.fn<(email: string, actionCodeSettings?: any) => Promise<string>>();
  generateSignInWithEmailLink = jest.fn<(email: string, actionCodeSettings: any) => Promise<string>>();

  constructor() {
    this.setupDefaultImplementations();
  }

  private setupDefaultImplementations(): void {
    // Default successful implementations
    this.createUser.mockImplementation(async (properties: any): Promise<MockUserRecord> => ({
      uid: `user_${Date.now()}`,
      email: properties.email,
      emailVerified: properties.emailVerified || false,
      displayName: properties.displayName,
      photoURL: properties.photoURL,
      phoneNumber: properties.phoneNumber,
      disabled: properties.disabled || false,
      metadata: {
        creationTime: new Date().toISOString(),
        lastSignInTime: undefined
      },
      customClaims: {},
      providerData: [],
      toJSON: (): Record<string, any> => ({}),
      delete: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
      reload: jest.fn<() => Promise<void>>().mockResolvedValue(undefined)
    }));

    this.getUser.mockImplementation(async (uid: string): Promise<MockUserRecord> => ({
      uid,
      email: `user${uid}@example.com`,
      emailVerified: true,
      displayName: `User ${uid}`,
      photoURL: null,
      phoneNumber: null,
      disabled: false,
      metadata: {
        creationTime: new Date().toISOString(),
        lastSignInTime: new Date().toISOString()
      },
      customClaims: {},
      providerData: [],
      toJSON: (): Record<string, any> => ({}),
      delete: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
      reload: jest.fn<() => Promise<void>>().mockResolvedValue(undefined)
    }));

    this.getUserByEmail.mockImplementation(async (email: string): Promise<MockUserRecord> => ({
      uid: `uid_for_${email.replace(/[@.]/g, '_')}`,
      email,
      emailVerified: true,
      displayName: email.split('@')[0],
      photoURL: null,
      phoneNumber: null,
      disabled: false,
      metadata: {
        creationTime: new Date().toISOString(),
        lastSignInTime: new Date().toISOString()
      },
      customClaims: {},
      providerData: [],
      toJSON: (): Record<string, any> => ({}),
      delete: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
      reload: jest.fn<() => Promise<void>>().mockResolvedValue(undefined)
    }));

    this.updateUser.mockImplementation(async (uid: string, properties: any): Promise<MockUserRecord> => ({
      uid,
      email: properties.email || `user${uid}@example.com`,
      emailVerified: properties.emailVerified !== undefined ? properties.emailVerified : true,
      displayName: properties.displayName || `User ${uid}`,
      photoURL: properties.photoURL || null,
      phoneNumber: properties.phoneNumber || null,
      disabled: properties.disabled || false,
      metadata: {
        creationTime: new Date().toISOString(),
        lastSignInTime: new Date().toISOString()
      },
      customClaims: properties.customClaims || {},
      providerData: [],
      toJSON: (): Record<string, any> => ({}),
      delete: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
      reload: jest.fn<() => Promise<void>>().mockResolvedValue(undefined)
    }));

    this.deleteUser.mockResolvedValue(undefined);
    this.setCustomUserClaims.mockResolvedValue(undefined);
    this.createCustomToken.mockResolvedValue('mock-custom-token');
    this.verifyIdToken.mockResolvedValue({
      uid: 'verified-user-id',
      email: 'verified@example.com'
    });
    this.revokeRefreshTokens.mockResolvedValue(undefined);
  }
}

/**
 * Mock Firebase Storage File Implementation
 */
class MockFirebaseStorageFile implements MockStorageFile {
  name: string;
  bucket: string;
  generation?: string;
  metadata?: Record<string, any>;

  save = jest.fn<(data: Buffer | string, options?: any) => Promise<void>>();
  delete = jest.fn<() => Promise<void>>();
  exists = jest.fn<() => Promise<[boolean]>>();
  download = jest.fn<() => Promise<[Buffer]>>();
  getMetadata = jest.fn<() => Promise<[Record<string, any>]>>();
  setMetadata = jest.fn<(metadata: Record<string, any>) => Promise<[Record<string, any>]>>();
  getSignedUrl = jest.fn<(options: any) => Promise<[string]>>();
  createReadStream = jest.fn<() => NodeJS.ReadableStream>();
  createWriteStream = jest.fn<(options?: any) => NodeJS.WritableStream>();

  constructor(name: string, bucket: string = 'test-bucket') {
    this.name = name;
    this.bucket = bucket;
    this.generation = `gen_${Date.now()}`;
    this.metadata = {};
    this.setupDefaultImplementations();
  }

  private setupDefaultImplementations(): void {
    this.save.mockResolvedValue(undefined);
    this.delete.mockResolvedValue(undefined);
    this.exists.mockResolvedValue([true]);
    this.download.mockResolvedValue([Buffer.from('mock file content')]);
    this.getMetadata.mockResolvedValue([{
      name: this.name,
      bucket: this.bucket,
      generation: this.generation,
      contentType: 'application/octet-stream',
      size: '1024',
      updated: new Date().toISOString()
    }]);
    this.setMetadata.mockImplementation(async (metadata: Record<string, any>): Promise<[Record<string, any>]> => {
      this.metadata = { ...this.metadata, ...metadata };
      return [this.metadata];
    });
    this.getSignedUrl.mockResolvedValue([`https://storage.googleapis.com/signed-url-for-${this.name}`]);
    this.createReadStream.mockReturnValue({
      pipe: jest.fn(),
      on: jest.fn(),
      read: jest.fn(),
      readable: true,
      readableHighWaterMark: 16384,
      readableLength: 0,
      destroy: jest.fn(),
      destroyed: false,
      pause: jest.fn(),
      resume: jest.fn(),
      isPaused: jest.fn().mockReturnValue(false),
      setEncoding: jest.fn(),
      unpipe: jest.fn(),
      unshift: jest.fn(),
      wrap: jest.fn(),
      push: jest.fn(),
      _read: jest.fn(),
      readableEnded: false,
      readableFlowing: null,
      readableObjectMode: false,
      _destroy: jest.fn(),
      _undestroy: jest.fn(),
      errorEmitted: false,
      closed: false,
      closeEmitted: false,
      readableAborted: false,
      _readableState: {} as any,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      off: jest.fn(),
      removeAllListeners: jest.fn(),
      setMaxListeners: jest.fn(),
      getMaxListeners: jest.fn(),
      listeners: jest.fn(),
      rawListeners: jest.fn(),
      emit: jest.fn(),
      listenerCount: jest.fn(),
      prependListener: jest.fn(),
      prependOnceListener: jest.fn(),
      once: jest.fn(),
      addListener: jest.fn(),
      removeListener: jest.fn(),
      eventNames: jest.fn(),
      [Symbol.asyncIterator]: jest.fn().mockReturnValue({
        next: jest.fn<() => Promise<IteratorResult<Buffer>>>().mockResolvedValue({ value: Buffer.from('test'), done: false }),
        return: jest.fn<(value?: any) => Promise<IteratorResult<Buffer>>>().mockResolvedValue({ value: undefined, done: true }),
        throw: jest.fn<(e?: any) => Promise<IteratorResult<Buffer>>>().mockRejectedValue(new Error('Mock error'))
      })
    } as NodeJS.ReadableStream);
    
    this.createWriteStream.mockReturnValue({
      write: jest.fn(),
      end: jest.fn(),
      on: jest.fn(),
      writable: true,
      writableEnded: false,
      writableFinished: false,
      writableHighWaterMark: 16384,
      writableLength: 0,
      writableObjectMode: false,
      writableCorked: 0,
      destroyed: false,
      _write: jest.fn(),
      _writev: jest.fn(),
      _destroy: jest.fn(),
      _final: jest.fn(),
      destroy: jest.fn(),
      cork: jest.fn(),
      uncork: jest.fn(),
      setDefaultEncoding: jest.fn(),
      _writableState: {} as any,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      off: jest.fn(),
      removeAllListeners: jest.fn(),
      setMaxListeners: jest.fn(),
      getMaxListeners: jest.fn(),
      listeners: jest.fn(),
      rawListeners: jest.fn(),
      emit: jest.fn(),
      listenerCount: jest.fn(),
      prependListener: jest.fn(),
      prependOnceListener: jest.fn(),
      once: jest.fn(),
      addListener: jest.fn(),
      removeListener: jest.fn(),
      eventNames: jest.fn(),
      pipe: jest.fn(),
      closed: false,
      closeEmitted: false,
      errorEmitted: false,
      _undestroy: jest.fn()
    } as NodeJS.WritableStream);
  }
}

/**
 * Mock Firebase Storage Bucket Implementation
 */
class MockFirebaseStorageBucket implements MockStorageBucket {
  name: string;
  private files: Map<string, MockFirebaseStorageFile> = new Map();

  file = jest.fn<(name: string) => MockStorageFile>();
  getFiles = jest.fn<(options?: any) => Promise<[MockStorageFile[]]>>();
  upload = jest.fn<(localFilePath: string, options?: any) => Promise<[MockStorageFile]>>();
  exists = jest.fn<() => Promise<[boolean]>>();
  delete = jest.fn<() => Promise<void>>();

  constructor(name: string = 'test-bucket') {
    this.name = name;
    this.setupDefaultImplementations();
  }

  private setupDefaultImplementations(): void {
    this.file.mockImplementation((name: string): MockStorageFile => {
      if (!this.files.has(name)) {
        this.files.set(name, new MockFirebaseStorageFile(name, this.name));
      }
      return this.files.get(name)!;
    });

    this.getFiles.mockResolvedValue([Array.from(this.files.values())]);
    
    this.upload.mockImplementation(async (localFilePath: string, options?: any): Promise<[MockStorageFile]> => {
      const fileName = options?.destination || localFilePath.split('/').pop() || 'uploaded-file';
      const file = new MockFirebaseStorageFile(fileName, this.name);
      this.files.set(fileName, file);
      return [file];
    });

    this.exists.mockResolvedValue([true]);
    this.delete.mockResolvedValue(undefined);
  }

  // Helper method to add files for testing
  addFile(name: string, file?: MockFirebaseStorageFile): MockFirebaseStorageFile {
    const mockFile = file || new MockFirebaseStorageFile(name, this.name);
    this.files.set(name, mockFile);
    return mockFile;
  }

  // Helper method to clear files for testing
  clearFiles(): void {
    this.files.clear();
  }

  // Helper method to get all files for testing
  getStoredFiles(): MockFirebaseStorageFile[] {
    return Array.from(this.files.values());
  }
}

/**
 * Mock Firebase Storage
 */
class MockFirebaseStorage {
  bucket = jest.fn<(name?: string) => MockStorageBucket>();
  private buckets: Map<string, MockFirebaseStorageBucket> = new Map();

  constructor() {
    this.setupDefaultImplementations();
  }

  private setupDefaultImplementations(): void {
    this.bucket.mockImplementation((name?: string): MockStorageBucket => {
      const bucketName = name || 'default-bucket';
      if (!this.buckets.has(bucketName)) {
        this.buckets.set(bucketName, new MockFirebaseStorageBucket(bucketName));
      }
      return this.buckets.get(bucketName)!;
    });
  }

  // Helper method to get specific bucket for testing
  getBucket(name: string): MockFirebaseStorageBucket | undefined {
    return this.buckets.get(name);
  }

  // Helper method to clear all buckets for testing
  clearBuckets(): void {
    this.buckets.clear();
  }
}

/**
 * Mock Firebase Credential
 */
export class MockFirebaseCredential {
  static cert = jest.fn<(serviceAccountPathOrObject: any) => any>().mockReturnValue({
    projectId: 'mock-project-id',
    privateKey: 'mock-private-key',
    clientEmail: 'mock@serviceaccount.com'
  });
}

/**
 * Mock Firebase Admin SDK
 */
class MockFirebaseAdmin {
  static apps: any[] = [];
  static auth = jest.fn<() => MockFirebaseAuth>();
  static storage = jest.fn<() => MockFirebaseStorage>();
  static credential = MockFirebaseCredential;
  static initializeApp = jest.fn<(config?: any, name?: string) => any>();

  private static authInstance = new MockFirebaseAuth();
  private static storageInstance = new MockFirebaseStorage();

  static setupMocks(): void {
    this.auth.mockReturnValue(this.authInstance);
    this.storage.mockReturnValue(this.storageInstance);
    this.initializeApp.mockImplementation((config?: any, name?: string): any => {
      const app = {
        name: name || '[DEFAULT]',
        options: config || {}
      };
      this.apps.push(app);
      return app;
    });
  }

  static resetMocks(): void {
    this.apps = [];
    this.authInstance = new MockFirebaseAuth();
    this.storageInstance = new MockFirebaseStorage();
    this.auth.mockClear();
    this.storage.mockClear();
    this.initializeApp.mockClear();
    this.setupMocks();
  }

  static getAuthInstance(): MockFirebaseAuth {
    return this.authInstance;
  }

  static getStorageInstance(): MockFirebaseStorage {
    return this.storageInstance;
  }
}

// Initialize mocks
MockFirebaseAdmin.setupMocks();

/**
 * Firebase Error Scenarios for Testing
 */
export const firebaseErrorScenarios = {
  auth: {
    userNotFound: {
      code: 'auth/user-not-found',
      message: 'There is no user record corresponding to the provided identifier.'
    },
    emailAlreadyExists: {
      code: 'auth/email-already-exists',
      message: 'The provided email is already in use by an existing user.'
    },
    invalidEmail: {
      code: 'auth/invalid-email',
      message: 'The provided email is invalid.'
    },
    invalidIdToken: {
      code: 'auth/invalid-id-token',
      message: 'The provided ID token is not valid.'
    },
    tokenExpired: {
      code: 'auth/id-token-expired',
      message: 'The provided ID token is expired.'
    },
    insufficientPermission: {
      code: 'auth/insufficient-permission',
      message: 'The caller does not have permission to access the requested resource.'
    }
  },
  storage: {
    objectNotFound: {
      code: 404,
      message: 'No such object: bucket/file-name'
    },
    forbidden: {
      code: 403,
      message: 'Forbidden'
    },
    payloadTooLarge: {
      code: 413,
      message: 'Request entity too large'
    },
    quotaExceeded: {
      code: 413,
      message: 'The project quota has been exceeded'
    },
    bucketNotFound: {
      code: 404,
      message: 'The specified bucket does not exist'
    },
    invalidArgument: {
      code: 400,
      message: 'Invalid argument'
    }
  }
} as const;

/**
 * Helper function to create Firebase auth errors
 */
export const createFirebaseAuthError = (errorType: keyof typeof firebaseErrorScenarios.auth): Error => {
  const scenario = firebaseErrorScenarios.auth[errorType];
  const error = new Error(scenario.message);
  (error as any).code = scenario.code;
  return error;
};

/**
 * Helper function to create Firebase storage errors
 */
export const createFirebaseStorageError = (errorType: keyof typeof firebaseErrorScenarios.storage): Error => {
  const scenario = firebaseErrorScenarios.storage[errorType];
  const error = new Error(scenario.message);
  (error as any).code = scenario.code;
  return error;
};

/**
 * Test data factories
 */
export const createMockUser = (overrides?: Partial<MockFirebaseUser>): MockFirebaseUser => ({
  uid: `user_${Date.now()}`,
  email: 'test@example.com',
  emailVerified: true,
  displayName: 'Test User',
  photoURL: null,
  phoneNumber: null,
  disabled: false,
  metadata: {
    creationTime: new Date().toISOString(),
    lastSignInTime: new Date().toISOString()
  },
  customClaims: {},
  providerData: [],
  toJSON: (): Record<string, any> => ({}),
  ...overrides
});

export const createMockUserRecord = (overrides?: Partial<MockUserRecord>): MockUserRecord => ({
  ...createMockUser(overrides),
  delete: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
  reload: jest.fn<() => Promise<void>>().mockResolvedValue(undefined),
  ...overrides
});

/**
 * Common test scenarios
 */
export const firebaseTestScenarios = {
  validUser: {
    uid: 'valid-user-123',
    email: 'valid@example.com',
    emailVerified: true,
    displayName: 'Valid User',
    disabled: false
  },
  invalidUser: {
    uid: 'invalid-user-123',
    email: 'invalid@example.com',
    emailVerified: false,
    displayName: 'Invalid User',
    disabled: true
  },
  adminUser: {
    uid: 'admin-user-123',
    email: 'admin@example.com',
    emailVerified: true,
    displayName: 'Admin User',
    customClaims: { role: 'admin' },
    disabled: false
  },
  newUser: {
    email: 'new@example.com',
    password: 'newpassword123',
    displayName: 'New User',
    emailVerified: false
  }
} as const;

/**
 * Storage test scenarios
 */
export const storageTestScenarios = {
  imageFile: {
    name: 'test-image.jpg',
    contentType: 'image/jpeg',
    size: 1024 * 100, // 100KB
    data: Buffer.from('fake image data')
  },
  documentFile: {
    name: 'test-document.pdf',
    contentType: 'application/pdf',
    size: 1024 * 500, // 500KB
    data: Buffer.from('fake pdf data')
  },
  largeFile: {
    name: 'large-file.zip',
    contentType: 'application/zip',
    size: 1024 * 1024 * 10, // 10MB
    data: Buffer.alloc(1024 * 1024 * 10)
  },
  invalidFile: {
    name: '',
    contentType: 'invalid/type',
    size: 0,
    data: Buffer.alloc(0)
  }
} as const;

/**
 * Reset all Firebase mocks
 */
export const resetFirebaseMocks = (): void => {
  MockFirebaseAdmin.resetMocks();
};

/**
 * Setup Firebase mock implementations for specific test scenarios
 */
export const setupFirebaseMockImplementations = (): void => {
  const auth = MockFirebaseAdmin.getAuthInstance();
  const storage = MockFirebaseAdmin.getStorageInstance();

  // Reset to default implementations
  auth.createUser.mockImplementation(async (properties: any): Promise<MockUserRecord> => createMockUserRecord(properties));
  auth.getUser.mockImplementation(async (uid: string): Promise<MockUserRecord> => createMockUserRecord({ uid }));
  auth.getUserByEmail.mockImplementation(async (email: string): Promise<MockUserRecord> => 
    createMockUserRecord({ email, uid: `uid_for_${email.replace(/[@.]/g, '_')}` })
  );

  // Setup storage default implementations
  const defaultBucket = storage.bucket();
  (defaultBucket as MockFirebaseStorageBucket).clearFiles();
};

/**
 * Firebase config mock for testing
 */
export const mockFirebaseConfig = {
  projectId: 'test-project-id',
  privateKey: '-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY\n-----END PRIVATE KEY-----',
  clientEmail: 'test@test-project.iam.gserviceaccount.com',
  storageBucket: 'test-project.appspot.com'
};

/**
 * Mock the firebase-admin module
 */
export const mockFirebaseModule = {
  apps: MockFirebaseAdmin.apps,
  auth: MockFirebaseAdmin.auth,
  storage: MockFirebaseAdmin.storage,
  credential: MockFirebaseAdmin.credential,
  initializeApp: MockFirebaseAdmin.initializeApp
};

// Export the main mock instances for direct access in tests
export { MockFirebaseAdmin, 
         MockFirebaseAuth, 
         MockFirebaseStorage, 
         MockFirebaseStorageBucket, 
         MockFirebaseStorageFile };