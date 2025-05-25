// /Koutu/backend/src/__tests__/integration/firebase.int.test.ts

import { jest } from '@jest/globals';
import * as admin from 'firebase-admin';
import { initializeTestFirebase, cleanupTestFirebase, resetFirebaseEmulator } from '../__helpers__/firebase.helper';

describe('Firebase Integration Tests', () => {
    let firebaseServices: ReturnType<typeof initializeTestFirebase>;

    beforeAll(async () => {
        // Check if emulators are accessible before starting tests
        const emulatorUrls = [
        'http://localhost:4001',  // Firebase UI
        'http://localhost:9099',  // Auth 
        'http://localhost:9100',  // Firestore
        'http://localhost:9199'   // Storage
        ];

        console.log('🔍 Checking Firebase emulator accessibility...');
        
        const checks = await Promise.allSettled(
        emulatorUrls.map(async (url) => {
            const response = await fetch(url, { signal: AbortSignal.timeout(5000) });
            return { url, ok: response.ok, status: response.status };
        })
        );

        const workingEmulators = checks.filter(
        (result): result is PromiseFulfilledResult<any> => 
            result.status === 'fulfilled' && result.value.ok
        );

        if (workingEmulators.length === 0) {
        console.error('❌ No Firebase emulators are accessible!');
        console.error('   Make sure to run: npm run docker:test-up');
        console.error('   And wait for emulators to start (30-60 seconds)');
        throw new Error('Firebase emulators not accessible. Integration tests cannot run.');
        }

        console.log(`✅ Found ${workingEmulators.length}/4 Firebase emulators accessible`);
        workingEmulators.forEach(result => {
        console.log(`   - ${result.value.url}: ${result.value.status}`);
        });

        // Initialize Firebase services
        firebaseServices = initializeTestFirebase();
    });

    afterAll(async () => {
        await cleanupTestFirebase();
    });

    beforeEach(async () => {
        // Reset emulator data before each test
        try {
        await resetFirebaseEmulator();
        } catch (error) {
        console.warn('Failed to reset Firebase emulator:', error);
        }
    });

    describe('Firebase Emulator Connection', () => {
        it('should connect to Firebase emulators with correct ports', () => {
        expect(process.env.FIRESTORE_EMULATOR_HOST).toBe('localhost:9100');
        expect(process.env.FIREBASE_AUTH_EMULATOR_HOST).toBe('localhost:9099');
        expect(process.env.FIREBASE_STORAGE_EMULATOR_HOST).toBe('localhost:9199');
        });

        it('should initialize Firebase Admin SDK correctly', () => {
        expect(firebaseServices.firebaseAdmin).toBeDefined();
        expect(firebaseServices.storage).toBeDefined();
        expect(firebaseServices.bucket).toBeDefined();
        });

        it('should use test project configuration', () => {
        expect(firebaseServices.firebaseAdmin.options.projectId).toBe('demo-test-project');
        });
    });

    describe('Firebase Auth Integration', () => {
        it('should create and retrieve a user', async () => {
        const auth = admin.auth(firebaseServices.firebaseAdmin);
        
        // Create user
        const userRecord = await auth.createUser({
            email: 'test@example.com',
            password: 'testpassword123',
            displayName: 'Test User'
        });

        expect(userRecord.uid).toBeDefined();
        expect(userRecord.email).toBe('test@example.com');
        expect(userRecord.displayName).toBe('Test User');

        // Retrieve user
        const retrievedUser = await auth.getUser(userRecord.uid);
        expect(retrievedUser.email).toBe('test@example.com');
        expect(retrievedUser.displayName).toBe('Test User');

        // Cleanup
        await auth.deleteUser(userRecord.uid);
        });

        it('should handle user not found error', async () => {
        const auth = admin.auth(firebaseServices.firebaseAdmin);
        
        await expect(auth.getUser('non-existent-uid')).rejects.toThrow();
        });

        it('should create custom tokens', async () => {
        const auth = admin.auth(firebaseServices.firebaseAdmin);
        
        // Create user first
        const userRecord = await auth.createUser({
            email: 'token-test@example.com'
        });

        // Create custom token
        const customToken = await auth.createCustomToken(userRecord.uid, {
            role: 'admin',
            permissions: ['read', 'write']
        });

        expect(customToken).toBeDefined();
        expect(typeof customToken).toBe('string');

        // Cleanup
        await auth.deleteUser(userRecord.uid);
        });
    });

    describe('Firebase Storage Integration', () => {
        it('should upload and download files', async () => {
        const fileName = 'test-file.txt';
        const fileContent = 'Hello, Firebase Storage!';
        const file = firebaseServices.bucket.file(fileName);

        // Upload file
        await file.save(fileContent, {
            metadata: {
            contentType: 'text/plain'
            }
        });

        // Verify file exists
        const [exists] = await file.exists();
        expect(exists).toBe(true);

        // Download file
        const [downloadedContent] = await file.download();
        expect(downloadedContent.toString()).toBe(fileContent);

        // Cleanup
        await file.delete();
        });

        it('should handle file metadata', async () => {
        const fileName = 'metadata-test.jpg';
        const fileContent = Buffer.from('fake-image-data');
        const file = firebaseServices.bucket.file(fileName);

        const customMetadata = {
            uploadedBy: 'test-user',
            purpose: 'integration-test'
        };

        // Upload with metadata
        await file.save(fileContent, {
            metadata: {
            contentType: 'image/jpeg',
            metadata: customMetadata
            }
        });

        // Get metadata
        const [metadata] = await file.getMetadata();
        expect(metadata.contentType).toBe('image/jpeg');
        expect(metadata.metadata?.uploadedBy).toBe('test-user');
        expect(metadata.metadata?.purpose).toBe('integration-test');

        // Cleanup
        await file.delete();
        });

        it('should list files in bucket', async () => {
        const fileNames = ['list-test-1.txt', 'list-test-2.txt', 'list-test-3.txt'];
        
        // Upload multiple files
        for (const fileName of fileNames) {
            await firebaseServices.bucket.file(fileName).save(`Content of ${fileName}`);
        }

        // List files
        const [files] = await firebaseServices.bucket.getFiles();
        const uploadedFileNames = files.map(file => file.name);

        for (const fileName of fileNames) {
            expect(uploadedFileNames).toContain(fileName);
        }

        // Cleanup
        for (const fileName of fileNames) {
            await firebaseServices.bucket.file(fileName).delete();
        }
        });

        it('should handle file deletion', async () => {
        const fileName = 'delete-test.txt';
        const file = firebaseServices.bucket.file(fileName);

        // Upload file
        await file.save('Content to be deleted');

        // Verify file exists
        let [exists] = await file.exists();
        expect(exists).toBe(true);

        // Delete file
        await file.delete();

        // Verify file is deleted
        [exists] = await file.exists();
        expect(exists).toBe(false);
        });
    });

    describe('Firebase Firestore Integration', () => {
        it('should create and retrieve documents', async () => {
        const firestore = admin.firestore(firebaseServices.firebaseAdmin);
        
        const testData = {
            name: 'Test Document',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            active: true
        };

        // Create document
        const docRef = await firestore.collection('test').add(testData);
        expect(docRef.id).toBeDefined();

        // Retrieve document
        const doc = await docRef.get();
        expect(doc.exists).toBe(true);
        expect(doc.data()?.name).toBe('Test Document');
        expect(doc.data()?.active).toBe(true);

        // Cleanup
        await docRef.delete();
        });

        it('should handle document updates', async () => {
        const firestore = admin.firestore(firebaseServices.firebaseAdmin);
        
        // Create initial document
        const docRef = await firestore.collection('test').add({
            value: 1,
            status: 'initial'
        });

        // Update document
        await docRef.update({
            value: 2,
            status: 'updated',
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Verify update
        const updatedDoc = await docRef.get();
        expect(updatedDoc.data()?.value).toBe(2);
        expect(updatedDoc.data()?.status).toBe('updated');
        expect(updatedDoc.data()?.updatedAt).toBeDefined();

        // Cleanup
        await docRef.delete();
        });

        it('should perform queries', async () => {
        const firestore = admin.firestore(firebaseServices.firebaseAdmin);
        
        // Create test documents
        const testDocs = [
            { name: 'Doc 1', category: 'A', priority: 1 },
            { name: 'Doc 2', category: 'B', priority: 2 },
            { name: 'Doc 3', category: 'A', priority: 3 }
        ];

        const createdRefs = [];
        for (const doc of testDocs) {
            const ref = await firestore.collection('items').add(doc);
            createdRefs.push(ref);
        }

        // Query by category
        const categoryADocs = await firestore
            .collection('items')
            .where('category', '==', 'A')
            .get();

        expect(categoryADocs.size).toBe(2);

        // Query with ordering
        const orderedDocs = await firestore
            .collection('items')
            .orderBy('priority', 'desc')
            .limit(2)
            .get();

        expect(orderedDocs.size).toBe(2);
        const priorities = orderedDocs.docs.map(doc => doc.data().priority);
        expect(priorities).toEqual([3, 2]);

        // Cleanup
        for (const ref of createdRefs) {
            await ref.delete();
        }
        });
    });

    describe('Error Handling', () => {
        it('should handle Firebase Auth errors gracefully', async () => {
        const auth = admin.auth(firebaseServices.firebaseAdmin);
        
        // Test invalid email format
        await expect(auth.createUser({
            email: 'invalid-email-format'
        })).rejects.toThrow();

        // Test duplicate email
        const user1 = await auth.createUser({
            email: 'duplicate@example.com'
        });

        await expect(auth.createUser({
            email: 'duplicate@example.com'
        })).rejects.toThrow();

        // Cleanup
        await auth.deleteUser(user1.uid);
        });

        it('should handle Firebase Storage errors gracefully', async () => {
        const file = firebaseServices.bucket.file('error-test.txt');

        // Test downloading non-existent file
        await expect(file.download()).rejects.toThrow();

        // Test getting metadata for non-existent file
        await expect(file.getMetadata()).rejects.toThrow();
        });

        it('should handle Firestore errors gracefully', async () => {
        const firestore = admin.firestore(firebaseServices.firebaseAdmin);
        
        // Test getting non-existent document
        const nonExistentDoc = await firestore.collection('test').doc('non-existent').get();
        expect(nonExistentDoc.exists).toBe(false);

        // Test updating non-existent document
        await expect(
            firestore.collection('test').doc('non-existent').update({ field: 'value' })
        ).rejects.toThrow();
        });
    });

    describe('Data Persistence and Reset', () => {
        it('should clear data between tests', async () => {
        const auth = admin.auth(firebaseServices.firebaseAdmin);
        const firestore = admin.firestore(firebaseServices.firebaseAdmin);
        
        // Create some data
        const userRecord = await auth.createUser({
            email: 'reset-test@example.com'
        });
        
        await firestore.collection('reset-test').add({
            message: 'This should be cleared'
        });
        
        await firebaseServices.bucket.file('reset-test.txt').save('This should be cleared');

        // Reset emulator
        await resetFirebaseEmulator();

        // Verify data is cleared
        await expect(auth.getUser(userRecord.uid)).rejects.toThrow();
        
        const docs = await firestore.collection('reset-test').get();
        expect(docs.empty).toBe(true);
        
        const [fileExists] = await firebaseServices.bucket.file('reset-test.txt').exists();
        expect(fileExists).toBe(false);
        });
    });
});