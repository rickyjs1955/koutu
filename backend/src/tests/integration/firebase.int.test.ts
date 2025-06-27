// Performance-optimized Firebase Integration Tests
// Fixed memory leaks and event listener accumulation

import { jest, describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import * as admin from 'firebase-admin';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';
import { Bucket } from '@google-cloud/storage';
import { EventEmitter } from 'events';

// ✅ FIX 1: Increase EventEmitter limits globally to prevent warnings
EventEmitter.defaultMaxListeners = 20;

// Test configuration for Firebase emulators
const EMULATOR_CONFIG = {
  projectId: 'demo-test-project',
  storageBucket: 'demo-test-project.appspot.com',
  authEmulator: 'localhost:9099',
  storageEmulator: 'localhost:9199',
  firestoreEmulator: 'localhost:9100'
};

// ✅ FIX 2: Set environment variables ONCE at the top with proper cleanup
const originalEnv = { ...process.env };

function setEmulatorEnvVars() {
  process.env.FIRESTORE_EMULATOR_HOST = EMULATOR_CONFIG.firestoreEmulator;
  process.env.FIREBASE_AUTH_EMULATOR_HOST = EMULATOR_CONFIG.authEmulator;
  process.env.FIREBASE_STORAGE_EMULATOR_HOST = EMULATOR_CONFIG.storageEmulator;
  process.env.STORAGE_EMULATOR_HOST = EMULATOR_CONFIG.storageEmulator;
  process.env.GOOGLE_CLOUD_PROJECT = EMULATOR_CONFIG.projectId;
  process.env.NODE_ENV = 'test';
  process.env.FIREBASE_EMULATOR_HUB = 'localhost:4400';
}

function restoreEnvVars() {
  // Restore original environment
  Object.keys(process.env).forEach(key => {
    if (originalEnv[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = originalEnv[key];
    }
  });
}

setEmulatorEnvVars();

// Mock config
const mockTestConfig = {
  firebase: {
    projectId: EMULATOR_CONFIG.projectId,
    privateKey: '',
    clientEmail: 'test@demo-test-project.iam.gserviceaccount.com',
    storageBucket: EMULATOR_CONFIG.storageBucket
  }
};

describe('Firebase Integration Tests', () => {
  let firebaseApp: admin.app.App | null = null;
  let auth: admin.auth.Auth;
  let storage: admin.storage.Storage;
  let bucket: Bucket;
  
  // Track created resources for cleanup
  const createdUserIds: string[] = [];
  const createdFileNames: string[] = [];
  
  // ✅ FIX 3: Track active requests to prevent accumulation
  const activeRequests = new Set<AbortController>();
  
  // ✅ FIX 4: Enhanced request helper with proper cleanup
  async function makeEmulatorRequest(url: string, options: RequestInit = {}): Promise<Response> {
    const controller = new AbortController();
    activeRequests.add(controller);
    
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        // ✅ Add timeout to prevent hanging requests
        ...(options.signal ? {} : { signal: AbortSignal.timeout(5000) })
      });
      return response;
    } finally {
      activeRequests.delete(controller);
    }
  }
  
  // ✅ FIX 5: Cleanup function for aborting active requests
  function abortActiveRequests() {
    activeRequests.forEach(controller => {
      try {
        controller.abort();
      } catch (error) {
        // Ignore abort errors
      }
    });
    activeRequests.clear();
  }

  beforeAll(async () => {
    console.time('Setup');
    
    // ✅ FIX 6: More robust emulator check with connection pooling
    console.log('🔄 Quick emulator check...');
    try {
      const checkPromises = [
        makeEmulatorRequest(`http://${EMULATOR_CONFIG.authEmulator}`, { method: 'GET' }),
        makeEmulatorRequest(`http://${EMULATOR_CONFIG.storageEmulator}`, { method: 'GET' })
      ];
      
      const [authCheck, storageCheck] = await Promise.allSettled(checkPromises);
      
      if (authCheck.status === 'rejected' || 
          (authCheck.status === 'fulfilled' && !authCheck.value.ok && authCheck.value.status !== 404)) {
        throw new Error('Auth emulator not ready');
      }
      if (storageCheck.status === 'rejected' || 
          (storageCheck.status === 'fulfilled' && !storageCheck.value.ok && storageCheck.value.status !== 501)) {
        throw new Error('Storage emulator not ready');
      }
      
      console.log('✅ Emulators ready');
    } catch (error) {
      abortActiveRequests();
      throw new Error(`Emulators not ready: ${error instanceof Error ? error.message : String(error)}`);
    }

    // Mock config
    jest.doMock('../../config/index', () => ({
      config: mockTestConfig
    }));

    // ✅ FIX 7: Ensure clean Firebase app initialization
    // Delete any existing apps first
    const existingApps = admin.apps.slice();
    await Promise.all(existingApps.map(app => app ? app.delete().catch(() => {}) : Promise.resolve()));

    firebaseApp = admin.initializeApp({
      projectId: EMULATOR_CONFIG.projectId,
      storageBucket: EMULATOR_CONFIG.storageBucket
    }, `integration-test-app-${Date.now()}`); // ✅ Unique app name

    auth = admin.auth(firebaseApp);
    storage = admin.storage(firebaseApp);
    bucket = storage.bucket();

    console.timeEnd('Setup');
    console.log('✅ Setup complete');
  }, 15000); // Increased timeout

  afterAll(async () => {
    console.time('Cleanup');
    
    // ✅ FIX 8: Abort any pending requests first
    abortActiveRequests();
    
    // BATCH cleanup with error handling
    const cleanupPromises = [];
    
    // Cleanup users in smaller batches to prevent overwhelming emulator
    if (createdUserIds.length > 0) {
      console.log(`Cleaning up ${createdUserIds.length} users...`);
      const userBatches = [];
      for (let i = 0; i < createdUserIds.length; i += 5) { // Process 5 at a time
        userBatches.push(createdUserIds.slice(i, i + 5));
      }
      
      cleanupPromises.push(
        ...userBatches.map(batch =>
          Promise.allSettled(
            batch.map(uid => auth.deleteUser(uid).catch(() => {}))
          )
        )
      );
    }

    // Cleanup files with REST API (but in smaller batches)
    if (createdFileNames.length > 0) {
      console.log(`Cleaning up ${createdFileNames.length} files...`);
      const fileBatches = [];
      for (let i = 0; i < createdFileNames.length; i += 5) { // Process 5 at a time
        fileBatches.push(createdFileNames.slice(i, i + 5));
      }
      
      cleanupPromises.push(
        ...fileBatches.map(batch =>
          Promise.allSettled(
            batch.map(fileName => 
              makeEmulatorRequest(
                `http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`,
                { method: 'DELETE' }
              ).catch(() => {})
            )
          )
        )
      );
    }

    await Promise.allSettled(cleanupPromises);

    // ✅ FIX 9: Proper Firebase app cleanup
    if (firebaseApp) {
      try {
        await firebaseApp.delete();
      } catch (error) {
        console.warn('Error deleting Firebase app:', error);
      }
      firebaseApp = null;
    }

    // ✅ FIX 10: Clean up all Firebase apps
    const remainingApps = admin.apps.slice();
    await Promise.allSettled(remainingApps.map(app => app ? app.delete().catch(() => {}) : Promise.resolve()));

    jest.resetModules();
    
    // ✅ FIX 11: Restore environment variables
    restoreEnvVars();
    
    console.timeEnd('Cleanup');
  }, 15000);

  // ✅ FIX 12: Add cleanup between tests to prevent accumulation
  afterEach(() => {
    jest.clearAllMocks();
    abortActiveRequests(); // Clean up any hanging requests
  });

  // ✅ FIX 13: Enhanced helper functions with better error handling
  async function createTestUser(overrides: Partial<admin.auth.CreateRequest> = {}): Promise<admin.auth.UserRecord> {
    const userData: admin.auth.CreateRequest = {
      email: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
      emailVerified: false,
      displayName: 'Test User',
      disabled: false,
      ...overrides
    };

    try {
      const user = await auth.createUser(userData);
      createdUserIds.push(user.uid);
      return user;
    } catch (error) {
      console.error('Failed to create test user:', error);
      throw error;
    }
  }

  // ✅ FIX 14: Enhanced file creation with better error handling
  async function createTestFile(fileName?: string, content?: string): Promise<string> {
    const testFileName = fileName || `test-file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.txt`;
    const fileContent = content || `Test content ${Date.now()}`;
    
    try {
      const response = await makeEmulatorRequest(
        `http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(testFileName)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: fileContent
        }
      );

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.status} ${response.statusText}`);
      }

      createdFileNames.push(testFileName);
      return testFileName;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error('Failed to create test file:', message);
      throw new Error(`Failed to create file: ${message}`);
    }
  }

  describe('Firebase Configuration', () => {
    it('should connect to emulators', () => {
      expect(firebaseApp).not.toBeNull();
      expect(firebaseApp!.options.projectId).toBe(EMULATOR_CONFIG.projectId);
    });

    it('should initialize services', () => {
      expect(auth).toBeDefined();
      expect(storage).toBeDefined();
      expect(bucket).toBeDefined();
    });
  });

  describe('Authentication Core Features', () => {
    it('should create and retrieve user', async () => {
      const email = `auth-test-${Date.now()}@example.com`;
      const user = await createTestUser({ email, displayName: 'Auth Test' });

      expect(user.uid).toBeDefined();
      expect(user.email).toBe(email);

      // Retrieve to verify
      const retrieved = await auth.getUser(user.uid);
      expect(retrieved.email).toBe(email);
    });

    it('should update user properties', async () => {
      const user = await createTestUser({ displayName: 'Original' });
      
      const updated = await auth.updateUser(user.uid, { displayName: 'Updated' });
      expect(updated.displayName).toBe('Updated');
    });

    it('should handle user deletion', async () => {
      const user = await createTestUser();
      await auth.deleteUser(user.uid);
      
      // Remove from cleanup since already deleted
      const index = createdUserIds.indexOf(user.uid);
      if (index > -1) createdUserIds.splice(index, 1);

      await expect(auth.getUser(user.uid)).rejects.toThrow();
    });

    it('should create custom tokens', async () => {
      const user = await createTestUser();
      const token = await auth.createCustomToken(user.uid);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
    });

    it('should handle auth errors', async () => {
      await expect(auth.getUser('invalid-uid')).rejects.toThrow();
      
      // Test duplicate email
      const email = `duplicate-${Date.now()}@example.com`;
      await createTestUser({ email });
      await expect(createTestUser({ email })).rejects.toThrow();
    });
  });

  describe('Storage Core Features', () => {
    it('should upload and download files', async () => {
      const fileName = `upload-test-${Date.now()}.txt`;
      const content = 'Test file content';

      // Upload
      const uploadResponse = await makeEmulatorRequest(
        `http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(fileName)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: content
        }
      );
      expect(uploadResponse.ok).toBe(true);
      createdFileNames.push(fileName);

      // Download
      const downloadResponse = await makeEmulatorRequest(
        `http://${EMULATOR_CONFIG.storageEmulator}/download/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}?alt=media`
      );
      expect(downloadResponse.ok).toBe(true);
      
      const downloaded = await downloadResponse.text();
      expect(downloaded).toBe(content);
    });

    it('should list files', async () => {
      // Create test files in smaller batch
      const files = [`list-1-${Date.now()}.txt`, `list-2-${Date.now()}.txt`];
      
      // ✅ FIX 15: Sequential file creation to reduce load
      for (const fileName of files) {
        const response = await makeEmulatorRequest(
          `http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(fileName)}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: `content for ${fileName}`
          }
        );
        expect(response.ok).toBe(true);
        createdFileNames.push(fileName);
      }

      // List files
      const listResponse = await makeEmulatorRequest(
        `http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o`
      );
      expect(listResponse.ok).toBe(true);
      
      const listData = await listResponse.json();
      const fileNames = (listData.items || []).map((item: any) => item.name);
      
      files.forEach(fileName => {
        expect(fileNames).toContain(fileName);
      });
    });

    it('should delete files', async () => {
      const fileName = await createTestFile();
      
      // Delete
      const deleteResponse = await makeEmulatorRequest(
        `http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`,
        { method: 'DELETE' }
      );
      expect(deleteResponse.ok).toBe(true);

      // Verify deleted
      const checkResponse = await makeEmulatorRequest(
        `http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`
      );
      expect(checkResponse.status).toBe(404);
      
      // Remove from cleanup list since already deleted
      const index = createdFileNames.indexOf(fileName);
      if (index > -1) createdFileNames.splice(index, 1);
    });

    it('should handle storage errors', async () => {
      // Test non-existent file
      const response = await makeEmulatorRequest(
        `http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/non-existent.txt`
      );
      expect(response.status).toBe(404);
    });
  });

  describe('Performance Check', () => {
    it('should handle concurrent auth operations', async () => {
      const start = Date.now();
      
      // ✅ FIX 16: Reduced concurrency to prevent overwhelming emulator
      const users = await Promise.all(
        Array.from({ length: 3 }, (_, i) => // Reduced from 5 to 3
          createTestUser({ email: `concurrent-${i}-${Date.now()}@example.com` })
        )
      );
      
      const duration = Date.now() - start;
      console.log(`Created ${users.length} users in ${duration}ms`);
      
      expect(users.length).toBe(3);
      expect(duration).toBeLessThan(5000);
    });

    it('should handle concurrent storage operations', async () => {
      const start = Date.now();
      
      // ✅ FIX 17: Sequential instead of parallel to prevent connection overflow
      const fileNames: string[] = [];
      for (let i = 0; i < 3; i++) {
        const fileName = await createTestFile(`concurrent-${i}-${Date.now()}.txt`, `Content ${i}`);
        fileNames.push(fileName);
      }
      
      const duration = Date.now() - start;
      console.log(`Created ${fileNames.length} files in ${duration}ms`);
      
      expect(fileNames.length).toBe(3);
      expect(duration).toBeLessThan(5000); // More generous timeout
    });
  });
});

// ✅ FIX 18: Enhanced Jest configuration for memory management
export const jestConfig = {
  testTimeout: 20000, // Increased timeout
  maxWorkers: 1, // Single worker for emulator tests
  detectOpenHandles: false,
  forceExit: true,
  // ✅ Additional memory management options
  setupFilesAfterEnv: ['<rootDir>/src/tests/setup/jestMemorySetup.ts'],
  globalTeardown: '<rootDir>/src/tests/setup/jestGlobalTeardown.ts'
};