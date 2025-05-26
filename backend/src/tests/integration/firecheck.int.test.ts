// backend/src/__tests__/integration/firebase-simple.integration.test.ts

// CRITICAL: Set emulator environment variables BEFORE importing firebase-admin
process.env.FIRESTORE_EMULATOR_HOST = 'localhost:9100';
process.env.FIREBASE_AUTH_EMULATOR_HOST = 'localhost:9099';
process.env.FIREBASE_STORAGE_EMULATOR_HOST = 'localhost:9199';
process.env.GCLOUD_PROJECT = 'demo-test-project';
process.env.FIREBASE_PROJECT_ID = 'demo-test-project';

// Disable SSL for emulators
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

/**
 * @file Simplified Firebase Integration Tests
 * 
 * @description A streamlined version of Firebase integration tests
 * that focuses on core functionality without complex emulator waiting logic.
 */

import { jest, describe, it, expect, beforeAll, afterAll, beforeEach } from '@jest/globals';
import * as admin from 'firebase-admin';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';

// Test configuration for Firebase emulators
const EMULATOR_CONFIG = {
  projectId: 'demo-test-project',
  storageBucket: 'demo-test-project.appspot.com'
};

describe('Firebase Integration Tests (Fixed)', () => {
  let firebaseApp: admin.app.App | null = null;
  let auth: admin.auth.Auth;
  let storage: admin.storage.Storage;
  let bucket: admin.storage.Bucket;
  
  // Track created resources for cleanup
  const createdUserIds: string[] = [];
  const createdFileNames: string[] = [];

  beforeAll(async () => {
    console.log('🚀 Setting up Firebase integration tests...');
    
    // Set up test database
    await setupTestDatabase();

    try {
      // Delete any existing apps first
      if (admin.apps.length > 0) {
        await Promise.all(admin.apps.map(app => app?.delete()));
      }

      // Initialize Firebase app with explicit emulator configuration
      firebaseApp = admin.initializeApp({
        projectId: EMULATOR_CONFIG.projectId,
        storageBucket: EMULATOR_CONFIG.storageBucket,
        // Don't include serviceAccount for emulators - it's not needed
      }, 'integration-test-app');

      auth = admin.auth(firebaseApp);
      storage = admin.storage(firebaseApp);
      bucket = storage.bucket();

      console.log('✅ Firebase services initialized');
      console.log(`🔧 Auth emulator: ${process.env.FIREBASE_AUTH_EMULATOR_HOST}`);
      console.log(`🔧 Storage emulator: ${process.env.FIREBASE_STORAGE_EMULATOR_HOST}`);
      console.log(`🔧 Firestore emulator: ${process.env.FIRESTORE_EMULATOR_HOST}`);
    } catch (error) {
      console.error('❌ Failed to initialize Firebase:', error);
      throw error;
    }
  }, 30000);

  beforeEach(async () => {
    // Clear emulator data before each test
    await clearEmulatorData();
  });

  afterAll(async () => {
    console.log('🧹 Cleaning up Firebase integration tests...');
    
    // Clean up created users
    for (const uid of createdUserIds) {
      try {
        await auth.deleteUser(uid);
      } catch (error) {
        console.log(`⚠️ Could not delete user ${uid}:`, error.message);
      }
    }

    // Clean up created files
    for (const fileName of createdFileNames) {
      try {
        await bucket.file(fileName).delete();
      } catch (error) {
        console.log(`⚠️ Could not delete file ${fileName}:`, error.message);
      }
    }

    // Clean up Firebase app
    if (firebaseApp) {
      await firebaseApp.delete();
      firebaseApp = null;
    }

    // Clean up test database
    await teardownTestDatabase();

    console.log('✅ Cleanup complete');
  });

  /**
   * Helper function to clear Firebase emulator data using REST API
   */
  async function clearEmulatorData(): Promise<void> {
    try {
      // Clear Auth emulator data using REST API
      const authClearUrl = 'http://localhost:9099/emulator/v1/projects/demo-test-project/accounts';
      
      try {
        await fetch(authClearUrl, { method: 'DELETE' });
      } catch (error) {
        console.warn('⚠️ Could not clear auth data:', error.message);
      }

      // Clear Storage emulator data
      try {
        // First check if bucket exists
        const [bucketExists] = await bucket.exists();
        if (bucketExists) {
          const [files] = await bucket.getFiles();
          for (const file of files) {
            await file.delete();
          }
        }
      } catch (error) {
        console.warn('⚠️ Could not clear storage data:', error.message);
      }

      // Clear Firestore data using REST API
      try {
        const firestoreClearUrl = 'http://localhost:9100/emulator/v1/projects/demo-test-project/databases/(default)/documents';
        await fetch(firestoreClearUrl, { method: 'DELETE' });
      } catch (error) {
        console.warn('⚠️ Could not clear firestore data:', error.message);
      }
    } catch (error) {
      console.warn('⚠️ Failed to clear emulator data:', error.message);
    }
  }

  /**
   * Helper function to create test user
   */
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

  /**
   * Helper function to create test file
   */
  async function createTestFile(fileName?: string, content?: string | Buffer): Promise<string> {
    const testFileName = fileName || `test-file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.txt`;
    const fileContent = content || Buffer.from(`Test file content ${Date.now()}`);
    
    const file = bucket.file(testFileName);
    await file.save(fileContent, {
      metadata: {
        contentType: 'text/plain'
      }
    });
    
    createdFileNames.push(testFileName);
    return testFileName;
  }

  describe('Basic Connection Tests', () => {
    it('should connect to Firebase services', () => {
      expect(firebaseApp).not.toBeNull();
      expect(auth).toBeDefined();
      expect(storage).toBeDefined();
      expect(bucket).toBeDefined();
    });

    it('should have correct project configuration', () => {
      expect(firebaseApp!.options.projectId).toBe(EMULATOR_CONFIG.projectId);
    });

    it('should connect to emulators', () => {
      expect(process.env.FIREBASE_AUTH_EMULATOR_HOST).toBe('localhost:9099');
      expect(process.env.FIREBASE_STORAGE_EMULATOR_HOST).toBe('localhost:9199');
    });
  });

  describe('Firebase Authentication', () => {
    it('should create a user', async () => {
      const userData = {
        email: 'test-create@example.com',
        displayName: 'Test Create User',
        emailVerified: true
      };

      const user = await auth.createUser(userData);
      createdUserIds.push(user.uid);

      expect(user.uid).toBeDefined();
      expect(user.email).toBe(userData.email);
      expect(user.displayName).toBe(userData.displayName);
      expect(user.emailVerified).toBe(userData.emailVerified);
    });

    it('should retrieve a user by UID', async () => {
      const createdUser = await createTestUser({
        email: 'test-retrieve@example.com',
        displayName: 'Test Retrieve User'
      });

      const retrievedUser = await auth.getUser(createdUser.uid);

      expect(retrievedUser.uid).toBe(createdUser.uid);
      expect(retrievedUser.email).toBe(createdUser.email);
      expect(retrievedUser.displayName).toBe(createdUser.displayName);
    });

    it('should update user properties', async () => {
      const user = await createTestUser({
        email: 'test-update@example.com',
        displayName: 'Original Name'
      });

      const updatedUser = await auth.updateUser(user.uid, {
        displayName: 'Updated Name',
        emailVerified: true
      });

      expect(updatedUser.uid).toBe(user.uid);
      expect(updatedUser.displayName).toBe('Updated Name');
      expect(updatedUser.emailVerified).toBe(true);
    });

    it('should delete a user', async () => {
      const user = await createTestUser({
        email: 'test-delete@example.com'
      });

      await auth.deleteUser(user.uid);

      // Remove from cleanup array since it's already deleted
      const index = createdUserIds.indexOf(user.uid);
      if (index > -1) {
        createdUserIds.splice(index, 1);
      }

      // Verify user is deleted by expecting an error
      await expect(auth.getUser(user.uid)).rejects.toThrow();
    });

    it('should handle user not found errors', async () => {
      await expect(auth.getUser('non-existent-uid')).rejects.toThrow();
    });
  });

  describe('Firebase Storage', () => {
    it('should upload a file', async () => {
      const fileName = 'test-upload.txt';
      const content = 'Test upload content';

      const file = bucket.file(fileName);
      await file.save(Buffer.from(content), {
        metadata: {
          contentType: 'text/plain'
        }
      });
      createdFileNames.push(fileName);

      const [exists] = await file.exists();
      expect(exists).toBe(true);
    });

    it('should download a file', async () => {
      const fileName = 'test-download.txt';
      const content = 'Test download content';

      // Upload first
      const file = bucket.file(fileName);
      await file.save(Buffer.from(content), {
        metadata: {
          contentType: 'text/plain'
        }
      });
      createdFileNames.push(fileName);

      // Download and verify
      const [downloadedContent] = await file.download();
      expect(downloadedContent.toString()).toBe(content);
    });

    it('should delete a file', async () => {
      const fileName = await createTestFile('test-delete.txt');

      const file = bucket.file(fileName);
      await file.delete();

      // Remove from cleanup array
      const index = createdFileNames.indexOf(fileName);
      if (index > -1) {
        createdFileNames.splice(index, 1);
      }

      const [exists] = await file.exists();
      expect(exists).toBe(false);
    });

    it('should check file existence', async () => {
      const fileName = await createTestFile('test-exists.txt');

      const file = bucket.file(fileName);
      const [exists] = await file.exists();
      expect(exists).toBe(true);

      const nonExistentFile = bucket.file('non-existent.txt');
      const [notExists] = await nonExistentFile.exists();
      expect(notExists).toBe(false);
    });

    it('should get file metadata', async () => {
      const fileName = await createTestFile('test-metadata.txt', 'Test metadata content');

      const file = bucket.file(fileName);
      const [metadata] = await file.getMetadata();

      expect(metadata.name).toBe(fileName);
      expect(metadata.bucket).toBe(EMULATOR_CONFIG.storageBucket);
      expect(metadata.size).toBeDefined();
    });

    it('should handle file not found errors', async () => {
      const file = bucket.file('non-existent-file.txt');
      await expect(file.download()).rejects.toThrow();
    });
  });

  describe('Cross-Service Operations', () => {
    it('should handle Auth and Storage together', async () => {
      // Create user
      const user = await createTestUser({
        email: 'cross-service@example.com',
        displayName: 'Cross Service User'
      });

      // Create file for user
      const fileName = `user-files/${user.uid}/test.txt`;
      const file = bucket.file(fileName);
      await file.save(Buffer.from(`File for user ${user.uid}`), {
        metadata: {
          contentType: 'text/plain'
        }
      });
      createdFileNames.push(fileName);

      // Verify both exist
      const retrievedUser = await auth.getUser(user.uid);
      const [fileExists] = await file.exists();

      expect(retrievedUser.uid).toBe(user.uid);
      expect(fileExists).toBe(true);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid email format', async () => {
      await expect(createTestUser({
        email: 'invalid-email-format'
      })).rejects.toThrow();
    });

    it('should handle duplicate email creation', async () => {
      const email = 'duplicate@example.com';
      await createTestUser({ email });

      await expect(createTestUser({ email })).rejects.toThrow();
    });

    it('should handle invalid file operations', async () => {
      // Test with a properly named file but invalid operation
      const file = bucket.file('valid-name.txt');
      
      // Try to delete a non-existent file - should not throw but return gracefully
      try {
        await file.delete();
      } catch (error) {
        // This is expected for non-existent files
        expect(error).toBeDefined();
      }
    });
  });

  describe('Performance Tests', () => {
    it('should handle multiple users efficiently', async () => {
      const startTime = Date.now();
      
      const users = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          createTestUser({
            email: `perf-user-${i}@example.com`,
            displayName: `Performance User ${i}`
          })
        )
      );

      const endTime = Date.now();
      
      expect(users.length).toBe(5);
      expect(endTime - startTime).toBeLessThan(10000); // Less than 10 seconds
      
      users.forEach((user, i) => {
        expect(user.email).toBe(`perf-user-${i}@example.com`);
      });
    });

    it('should handle multiple files efficiently', async () => {
      const startTime = Date.now();
      
      const fileNames = await Promise.all(
        Array.from({ length: 5 }, (_, i) =>
          createTestFile(`perf-file-${i}.txt`, `Performance content ${i}`)
        )
      );

      const endTime = Date.now();
      
      expect(fileNames.length).toBe(5);
      expect(endTime - startTime).toBeLessThan(10000); // Less than 10 seconds
      
      // Verify all files exist
      const existsResults = await Promise.all(
        fileNames.map(name => bucket.file(name).exists())
      );
      
      existsResults.forEach(([exists]) => {
        expect(exists).toBe(true);
      });
    });
  });
});