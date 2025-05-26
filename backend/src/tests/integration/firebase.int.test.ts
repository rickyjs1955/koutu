// Performance-optimized Firebase Integration Tests
// Should run in under 30 seconds total

import { jest, describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import * as admin from 'firebase-admin';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';
import { Bucket } from '@google-cloud/storage';

// Test configuration for Firebase emulators
const EMULATOR_CONFIG = {
  projectId: 'demo-test-project',
  storageBucket: 'demo-test-project.appspot.com',
  authEmulator: 'localhost:9099',
  storageEmulator: 'localhost:9199',
  firestoreEmulator: 'localhost:9100'
};

// Set environment variables ONCE at the top
process.env.FIRESTORE_EMULATOR_HOST = EMULATOR_CONFIG.firestoreEmulator;
process.env.FIREBASE_AUTH_EMULATOR_HOST = EMULATOR_CONFIG.authEmulator;
process.env.FIREBASE_STORAGE_EMULATOR_HOST = EMULATOR_CONFIG.storageEmulator;
process.env.STORAGE_EMULATOR_HOST = EMULATOR_CONFIG.storageEmulator;
process.env.GOOGLE_CLOUD_PROJECT = EMULATOR_CONFIG.projectId;
process.env.NODE_ENV = 'test';
process.env.FIREBASE_EMULATOR_HUB = 'localhost:4400';

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
  let bucket:Bucket;
  
  // Track created resources for cleanup
  const createdUserIds: string[] = [];
  const createdFileNames: string[] = [];

  beforeAll(async () => {
    console.time('Setup');
    
    // SIMPLIFIED emulator check - just ping once quickly
    console.log('🔄 Quick emulator check...');
    try {
      const authCheck = await fetch(`http://${EMULATOR_CONFIG.authEmulator}`, { 
        method: 'GET',
        signal: AbortSignal.timeout(2000) // 2 second timeout
      });
      const storageCheck = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}`, { 
        method: 'GET',
        signal: AbortSignal.timeout(2000)
      });
      
      if (!authCheck.ok && authCheck.status !== 404) {
        throw new Error('Auth emulator not ready');
      }
      if (!storageCheck.ok && storageCheck.status !== 501) {
        throw new Error('Storage emulator not ready');
      }
      
      console.log('✅ Emulators ready');
    } catch (error) {
      throw new Error(`Emulators not ready: ${error instanceof Error ? error.message : String(error)}`);
    }

    // Skip database setup if not needed for Firebase tests
    // await setupTestDatabase(); // Comment this out if not needed

    // Mock config
    jest.doMock('../../config/index', () => ({
      config: mockTestConfig
    }));

    // Initialize Firebase app - SIMPLE
    if (admin.apps.length === 0) {
      firebaseApp = admin.initializeApp({
        projectId: EMULATOR_CONFIG.projectId,
        storageBucket: EMULATOR_CONFIG.storageBucket
      }, 'integration-test-app');
    } else {
      firebaseApp = admin.apps[0];
    }

    // Add null check before using firebaseApp
    if (!firebaseApp) {
      throw new Error('Failed to initialize Firebase app');
    }

    auth = admin.auth(firebaseApp);
    storage = admin.storage(firebaseApp);
    bucket = storage.bucket();

    console.timeEnd('Setup');
    console.log('✅ Setup complete');
  }, 10000);

  afterAll(async () => {
    console.time('Cleanup');
    
    // BATCH cleanup instead of individual operations
    const cleanupPromises = [];
    
    // Cleanup users in batches
    if (createdUserIds.length > 0) {
      console.log(`Cleaning up ${createdUserIds.length} users...`);
      cleanupPromises.push(
        Promise.allSettled(
          createdUserIds.map(uid => auth.deleteUser(uid).catch(() => {}))
        )
      );
    }

    // Cleanup files via REST API (faster)
    if (createdFileNames.length > 0) {
      console.log(`Cleaning up ${createdFileNames.length} files...`);
      cleanupPromises.push(
        Promise.allSettled(
          createdFileNames.map(fileName => 
            fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`, {
              method: 'DELETE'
            }).catch(() => {})
          )
        )
      );
    }

    await Promise.all(cleanupPromises);

    // Clean up Firebase app
    if (firebaseApp) {
      await firebaseApp.delete();
      firebaseApp = null;
    }

    // await teardownTestDatabase(); // Comment out if not needed

    jest.resetModules();
    console.timeEnd('Cleanup');
  }, 10000); // Reduced timeout

  // REMOVE beforeEach data clearing - it's too slow
  // beforeEach(async () => {
  //   await clearFirebaseEmulatorData(); // REMOVE THIS
  // });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // FAST helper functions
  async function createTestUser(overrides: Partial<admin.auth.CreateRequest> = {}): Promise<admin.auth.UserRecord> {
    const userData: admin.auth.CreateRequest = {
      email: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
      emailVerified: false,
      displayName: 'Test User',
      disabled: false,
      ...overrides
    };

    const user = await auth.createUser(userData);
    createdUserIds.push(user.uid);
    return user;
  }

  // FAST file creation using REST API
  async function createTestFile(fileName?: string, content?: string): Promise<string> {
    const testFileName = fileName || `test-file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.txt`;
    const fileContent = content || `Test content ${Date.now()}`;
    
    try {
      const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(testFileName)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: fileContent,
        signal: AbortSignal.timeout(5000) // 5 second timeout
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.status}`);
      }

      createdFileNames.push(testFileName);
      return testFileName;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
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
      const uploadResponse = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(fileName)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: content,
        signal: AbortSignal.timeout(5000)
      });
      expect(uploadResponse.ok).toBe(true);
      createdFileNames.push(fileName);

      // Download
      const downloadResponse = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/download/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}?alt=media`, {
        signal: AbortSignal.timeout(5000)
      });
      expect(downloadResponse.ok).toBe(true);
      
      const downloaded = await downloadResponse.text();
      expect(downloaded).toBe(content);
    });

    it('should list files', async () => {
      // Create test files
      const files = [`list-1-${Date.now()}.txt`, `list-2-${Date.now()}.txt`];
      
      await Promise.all(files.map(async (fileName) => {
        const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(fileName)}`, {
          method: 'POST',
          headers: { 'Content-Type': 'text/plain' },
          body: `content for ${fileName}`,
          signal: AbortSignal.timeout(5000)
        });
        expect(response.ok).toBe(true);
        createdFileNames.push(fileName);
      }));

      // List files
      const listResponse = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o`, {
        signal: AbortSignal.timeout(5000)
      });
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
      const deleteResponse = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`, {
        method: 'DELETE',
        signal: AbortSignal.timeout(5000)
      });
      expect(deleteResponse.ok).toBe(true);

      // Verify deleted
      const checkResponse = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`, {
        signal: AbortSignal.timeout(5000)
      });
      expect(checkResponse.status).toBe(404);
    });

    it('should handle storage errors', async () => {
      // Test non-existent file
      const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/non-existent.txt`, {
        signal: AbortSignal.timeout(5000)
      });
      expect(response.status).toBe(404);
    });
  });

  describe('Performance Check', () => {
    it('should handle concurrent auth operations', async () => {
      const start = Date.now();
      
      const users = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          createTestUser({ email: `concurrent-${i}-${Date.now()}@example.com` })
        )
      );
      
      const duration = Date.now() - start;
      console.log(`Created 5 users in ${duration}ms`);
      
      expect(users.length).toBe(5);
      expect(duration).toBeLessThan(5000); // Should take less than 5 seconds
    });

    it('should handle concurrent storage operations', async () => {
      const start = Date.now();
      
      const fileNames = await Promise.all(
        Array.from({ length: 3 }, (_, i) =>
          createTestFile(`concurrent-${i}-${Date.now()}.txt`, `Content ${i}`)
        )
      );
      
      const duration = Date.now() - start;
      console.log(`Created 3 files in ${duration}ms`);
      
      expect(fileNames.length).toBe(3);
      expect(duration).toBeLessThan(3000); // Should take less than 3 seconds
    });
  });
});

// Export optimized Jest configuration
module.exports = {
  testTimeout: 15000, // 15 second max per test
  maxWorkers: 1, // Single worker for emulator tests
  detectOpenHandles: false, // Don't wait for handles in test environment
  forceExit: true, // Force exit after tests complete
};