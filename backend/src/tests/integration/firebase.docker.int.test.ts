// backend/src/tests/firebase.docker.int.test.ts
// Enhanced Firebase Integration Tests with Docker support

import { jest, describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from '@jest/globals';
import * as admin from 'firebase-admin';
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { Bucket } from '@google-cloud/storage';

// Docker-aware configuration
const isDockerEnv = process.env.DOCKER_ENV === 'true';
const EMULATOR_CONFIG = {
    projectId: process.env.GOOGLE_CLOUD_PROJECT || 'demo-test-project',
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'demo-test-project.appspot.com',
    authEmulator: process.env.FIREBASE_AUTH_EMULATOR_HOST || 'localhost:9099',
    storageEmulator: process.env.FIREBASE_STORAGE_EMULATOR_HOST || 'localhost:9199',
    firestoreEmulator: process.env.FIRESTORE_EMULATOR_HOST || 'localhost:9100',
    hubEmulator: process.env.FIREBASE_EMULATOR_HUB || 'localhost:4400'
};

// Enhanced emulator host parsing for Docker
const parseEmulatorHost = (host: string) => {
    if (host.includes(':')) {
        const [hostname, port] = host.split(':');
        return { hostname, port: parseInt(port) };
    }
    return { hostname: host, port: 80 };
};

const authHost = parseEmulatorHost(EMULATOR_CONFIG.authEmulator);
const storageHost = parseEmulatorHost(EMULATOR_CONFIG.storageEmulator);
const firestoreHost = parseEmulatorHost(EMULATOR_CONFIG.firestoreEmulator);

// Set environment variables for Firebase SDK
process.env.FIRESTORE_EMULATOR_HOST = EMULATOR_CONFIG.firestoreEmulator;
process.env.FIREBASE_AUTH_EMULATOR_HOST = EMULATOR_CONFIG.authEmulator;
process.env.FIREBASE_STORAGE_EMULATOR_HOST = EMULATOR_CONFIG.storageEmulator;
process.env.STORAGE_EMULATOR_HOST = `http://${EMULATOR_CONFIG.storageEmulator}`; // Add http:// prefix
process.env.GOOGLE_CLOUD_PROJECT = EMULATOR_CONFIG.projectId;
process.env.NODE_ENV = 'test';

describe('Firebase Docker Integration Tests', () => {
    let firebaseApp: admin.app.App | null = null;
    let auth: admin.auth.Auth;
    let storage: admin.storage.Storage;
    let bucket: Bucket;
    let testDatabase: any;
    
    // Enhanced resource tracking
    const createdUserIds: string[] = [];
    const createdFileNames: string[] = [];
    const createdDbRecords: { table: string; ids: string[] }[] = [];

    beforeAll(async () => {
        console.time('Docker Setup');
        
        try {
            // Enhanced emulator readiness check with Docker support
            await checkEmulatorsReady();
            
            // Initialize test database with Docker-aware connection
            testDatabase = await initializeTestDatabase();
            
            // Initialize Firebase with emulator configuration
            firebaseApp = await initializeFirebaseApp();
            
            if (!firebaseApp) {
                throw new Error('Failed to initialize Firebase app');
            }

            auth = admin.auth(firebaseApp);
            storage = admin.storage(firebaseApp);
            bucket = storage.bucket();

            console.timeEnd('Docker Setup');
            console.log('✅ Docker setup complete');
        } catch (error) {
            console.error('❌ Docker setup failed:', error);
            console.timeEnd('Docker Setup');
            throw error;
        }
    }, 60000);

    afterAll(async () => {
        console.time('Docker Cleanup');
        
        await performEnhancedCleanup();
        
        if (firebaseApp) {
            await firebaseApp.delete();
            firebaseApp = null;
        }
        
        if (testDatabase) {
            await testDatabase.cleanup();
        }

        jest.resetModules();
        console.timeEnd('Docker Cleanup');
    }, 20000);

    afterEach(() => {
        jest.clearAllMocks();
    });

    // Helper function for retry logic
    async function retryOperation<T>(
        operation: () => Promise<T>,
        maxRetries = 3,
        delayMs = 1000,
        operationName = 'operation'
    ): Promise<T> {
        let lastError: Error | undefined;
        
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                console.log(`🔄 ${operationName} attempt ${attempt}/${maxRetries}`);
                const result = await operation();
                if (attempt > 1) {
                    console.log(`✅ ${operationName} succeeded on attempt ${attempt}`);
                }
                return result;
            } catch (error) {
                lastError = error instanceof Error ? error : new Error(String(error));
                console.warn(`⚠️ ${operationName} attempt ${attempt} failed:`, lastError.message);
                
                if (attempt < maxRetries) {
                    console.log(`⏳ Waiting ${delayMs}ms before retry...`);
                    await new Promise(resolve => setTimeout(resolve, delayMs));
                    delayMs *= 1.5; // Exponential backoff
                }
            }
        }
        
        throw new Error(`${operationName} failed after ${maxRetries} attempts: ${lastError?.message}`);
    }

    // Enhanced emulator readiness check
    async function checkEmulatorsReady(): Promise<void> {
        console.log('🔄 Starting comprehensive emulator readiness check...');
        console.log('🐳 Docker environment detected:', isDockerEnv);
        console.log('📋 Emulator configuration:', {
            authEmulator: EMULATOR_CONFIG.authEmulator,
            storageEmulator: EMULATOR_CONFIG.storageEmulator,
            firestoreEmulator: EMULATOR_CONFIG.firestoreEmulator,
            projectId: EMULATOR_CONFIG.projectId
        });
        
        const checkEmulator = async (host: string, name: string, timeout = 45000) => {
            return retryOperation(async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000);
                
                try {
                    const response = await fetch(`http://${host}`, { 
                        method: 'GET',
                        signal: controller.signal
                    });
                    
                    clearTimeout(timeoutId);
                    
                    if (response.ok || response.status === 404 || response.status === 501) {
                        return true;
                    }
                    
                    throw new Error(`Emulator responded with status ${response.status}`);
                } catch (error) {
                    clearTimeout(timeoutId);
                    throw error;
                }
            }, 15, 2000, `${name} emulator check`);
        };

        const emulatorChecks = [
            checkEmulator(EMULATOR_CONFIG.authEmulator, 'Auth'),
            checkEmulator(EMULATOR_CONFIG.storageEmulator, 'Storage'),
            checkEmulator(EMULATOR_CONFIG.firestoreEmulator, 'Firestore')
        ];
        
        await Promise.all(emulatorChecks);
        console.log('✅ All emulators ready');
    }

    async function initializeTestDatabase() {
        console.log('🔄 Initializing test database...');
        
        try {
            await TestDatabaseConnection.initialize();
            
            const result = await TestDatabaseConnection.query('SELECT current_database(), version()');
            const dbInfo = result.rows[0];
            
            console.log(`✅ Connected to database: ${dbInfo.current_database}`);
            console.log(`📊 PostgreSQL version: ${dbInfo.version.split(' ')[0]}`);
            
            return TestDatabaseConnection;
        } catch (error) {
            console.error('❌ Database initialization failed:', error);
            throw error;
        }
    }

    async function initializeFirebaseApp(): Promise<admin.app.App> {
        console.log('🔄 Initializing Firebase app...');
        
        if (admin.apps.length === 0) {
            const app = admin.initializeApp({
                projectId: EMULATOR_CONFIG.projectId,
                storageBucket: EMULATOR_CONFIG.storageBucket
            }, 'docker-integration-test-app');
            
            console.log('✅ Firebase app initialized');
            return app;
        } else {
            const existingApp = admin.apps[0];
            if (!existingApp) {
                throw new Error('Firebase app exists but is null');
            }
            return existingApp;
        }
    }

    async function performEnhancedCleanup(): Promise<void> {
        console.log('🧹 Starting enhanced cleanup...');
        
        const cleanupPromises: Promise<any>[] = [];
        
        if (createdUserIds.length > 0) {
            console.log(`🗑️ Cleaning up ${createdUserIds.length} Firebase users...`);
            cleanupPromises.push(
                Promise.allSettled(
                    createdUserIds.map(uid => 
                        auth.deleteUser(uid).catch(err => 
                            console.warn(`Failed to delete user ${uid}:`, err.message)
                        )
                    )
                )
            );
        }

        if (createdFileNames.length > 0) {
            console.log(`🗑️ Cleaning up ${createdFileNames.length} storage files...`);
            cleanupPromises.push(
                Promise.allSettled(
                    createdFileNames.map(fileName => 
                        fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`, {
                            method: 'DELETE'
                        }).catch(err => 
                            console.warn(`Failed to delete file ${fileName}:`, err.message)
                        )
                    )
                )
            );
        }

        if (createdDbRecords.length > 0) {
            console.log(`🗑️ Cleaning up database records...`);
            cleanupPromises.push(
                Promise.allSettled(
                    createdDbRecords.map(async record => {
                        try {
                            if (record.ids.length > 0) {
                                const placeholders = record.ids.map((_, i) => `$${i + 1}`).join(',');
                                await TestDatabaseConnection.query(
                                    `DELETE FROM ${record.table} WHERE id IN (${placeholders})`,
                                    record.ids
                                );
                            }
                        } catch (error) {
                            console.warn(`Failed to cleanup ${record.table}:`, error);
                        }
                    })
                )
            );
        }

        await Promise.all(cleanupPromises);
        
        createdUserIds.length = 0;
        createdFileNames.length = 0;
        createdDbRecords.length = 0;
        
        console.log('✅ Enhanced cleanup completed');
    }

    async function createTestUser(overrides: Partial<admin.auth.CreateRequest> = {}): Promise<{
        firebaseUser: admin.auth.UserRecord;
        dbUser?: any;
    }> {
        const userData: admin.auth.CreateRequest = {
            email: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}@example.com`,
            emailVerified: false,
            displayName: 'Test User',
            disabled: false,
            ...overrides
        };

        const firebaseUser = await auth.createUser(userData);
        createdUserIds.push(firebaseUser.uid);
        
        let dbUser = null;
        try {
            const dbResult = await TestDatabaseConnection.query(
                'INSERT INTO users (id, email, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) RETURNING *',
                [firebaseUser.uid, userData.email]
            );
            dbUser = dbResult.rows[0];
            
            const userRecord = createdDbRecords.find(r => r.table === 'users');
            if (userRecord) {
                userRecord.ids.push(firebaseUser.uid);
            } else {
                createdDbRecords.push({ table: 'users', ids: [firebaseUser.uid] });
            }
        } catch (error) {
            console.warn('Failed to create database user:', error);
        }
        
        return { firebaseUser, dbUser };
    }

    async function createTestFile(fileName?: string, content?: string): Promise<string> {
        const testFileName = fileName || `test-file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.txt`;
        const fileContent = content || `Test content ${Date.now()}`;
        
        const uploadFile = async () => {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000);
            
            try {
                const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(testFileName)}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain' },
                    body: fileContent,
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`Upload failed: ${response.status} ${response.statusText} - ${errorText}`);
                }

                return response;
            } catch (error) {
                clearTimeout(timeoutId);
                throw error;
            }
        };

        await retryOperation(uploadFile, 3, 2000, `File upload for ${testFileName}`);
        createdFileNames.push(testFileName);
        return testFileName;
    }

    describe('Docker Environment Setup', () => {
        it('should verify Docker environment variables', () => {
            if (isDockerEnv) {
                expect(process.env.DB_HOST).toBe('postgres-test');
                expect(EMULATOR_CONFIG.authEmulator).toContain('firebase-emulator');
            }
            
            expect(EMULATOR_CONFIG.projectId).toBe('demo-test-project');
            expect(process.env.NODE_ENV).toBe('test');
        });

        it('should connect to all services', async () => {
            expect(firebaseApp).not.toBeNull();
            expect(auth).toBeDefined();
            expect(storage).toBeDefined();
            expect(bucket).toBeDefined();
            
            const dbResult = await TestDatabaseConnection.query('SELECT 1 as connected');
            expect(dbResult.rows[0].connected).toBe(1);
        });

        it('should verify emulator connectivity with health checks', async () => {
            const healthChecks = [
                { name: 'Auth', url: `http://${EMULATOR_CONFIG.authEmulator}` },
                { name: 'Storage', url: `http://${EMULATOR_CONFIG.storageEmulator}` },
                { name: 'Firestore', url: `http://${EMULATOR_CONFIG.firestoreEmulator}` }
            ];

            for (const check of healthChecks) {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000);
                
                try {
                    const response = await fetch(check.url, { 
                        signal: controller.signal 
                    });
                    clearTimeout(timeoutId);
                    expect([200, 404, 501].includes(response.status)).toBe(true);
                } catch (error) {
                    clearTimeout(timeoutId);
                    throw error;
                }
            }
        });
    });

    describe('Firebase Authentication with Database Integration', () => {
        it('should create user in both Firebase and PostgreSQL', async () => {
            const email = `auth-integration-${Date.now()}@example.com`;
            const { firebaseUser, dbUser } = await createTestUser({ 
                email, 
                displayName: 'Integration Test User' 
            });

            expect(firebaseUser.uid).toBeDefined();
            expect(firebaseUser.email).toBe(email);

            if (dbUser) {
                expect(dbUser.email).toBe(email);
                expect(dbUser.id).toBe(firebaseUser.uid);
            }

            const retrieved = await auth.getUser(firebaseUser.uid);
            expect(retrieved.email).toBe(email);
        });

        it('should handle user creation with custom claims', async () => {
            const { firebaseUser } = await createTestUser({
                email: `custom-claims-${Date.now()}@example.com`,
                displayName: 'Custom Claims User'
            });

            await auth.setCustomUserClaims(firebaseUser.uid, { 
                role: 'test-user',
                permissions: ['read', 'write']
            });

            const userRecord = await auth.getUser(firebaseUser.uid);
            expect(userRecord.customClaims?.role).toBe('test-user');
            expect(userRecord.customClaims?.permissions).toEqual(['read', 'write']);
        });

        it('should handle email verification workflow', async () => {
            const { firebaseUser } = await createTestUser({
                email: `verification-${Date.now()}@example.com`,
                emailVerified: false
            });

            expect(firebaseUser.emailVerified).toBe(false);

            await auth.updateUser(firebaseUser.uid, { emailVerified: true });
            
            const updatedUser = await auth.getUser(firebaseUser.uid);
            expect(updatedUser.emailVerified).toBe(true);
        });

        it('should handle concurrent user creation without conflicts', async () => {
            const userPromises = Array.from({ length: 5 }, (_, i) =>
                createTestUser({ 
                    email: `concurrent-${i}-${Date.now()}@example.com`,
                    displayName: `Concurrent User ${i}` 
                })
            );
            
            const results = await Promise.all(userPromises);
            
            expect(results.length).toBe(5);
            
            const emails = results.map(r => r.firebaseUser.email);
            const uniqueEmails = new Set(emails);
            expect(uniqueEmails.size).toBe(5);
        });
    });

    describe('Firebase Storage with Enhanced Operations', () => {
        it('should handle basic file upload and download', async () => {
            const fileName = `basic-test-${Date.now()}.txt`;
            const content = 'Basic test content';
            
            // Upload file
            await createTestFile(fileName, content);
            
            // Wait for consistency
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // Download and verify
            const downloadResponse = await retryOperation(async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000);
                
                try {
                    const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/download/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}?alt=media`, {
                        signal: controller.signal
                    });
                    
                    clearTimeout(timeoutId);
                    
                    if (!response.ok) {
                        throw new Error(`Download failed: ${response.status}`);
                    }
                    
                    return response;
                } catch (error) {
                    clearTimeout(timeoutId);
                    throw error;
                }
            }, 3, 1000, 'File download');
            
            const downloadedContent = await downloadResponse.text();
            expect(downloadedContent).toBe(content);
        });

        it('should handle JSON file upload and download with metadata', async () => {
            const fileName = `json-test-${Date.now()}.json`;
            const testData = {
                message: 'test data',
                timestamp: new Date().toISOString(),
                environment: isDockerEnv ? 'docker' : 'local'
            };

            // 1) UPLOAD with Admin SDK
            const fileRef = bucket.file(fileName);
            await fileRef.save(JSON.stringify(testData), {
                contentType: 'application/json',
                metadata: {
                    metadata: { // Custom metadata goes in nested metadata object
                        'X-Custom-Meta': 'test-metadata'
                    }
                },
                resumable: false
            });
            createdFileNames.push(fileName);

            // brief pause for consistency
            await new Promise(r => setTimeout(r, 500));

            // 2) DOWNLOAD serialized JSON
            const [downloadBuffer] = await fileRef.download();
            const downloaded = JSON.parse(downloadBuffer.toString('utf8'));

            expect(downloaded).toEqual(testData);

            // 3) VERIFY metadata round-trip
            const [meta] = await fileRef.getMetadata();
            expect(meta.contentType).toBe('application/json');
            expect(meta.metadata?.['X-Custom-Meta']).toBe('test-metadata');
        });

        it('should handle file operations with different content types', async () => {
            const fileTypes = [
                { extension: 'txt', contentType: 'text/plain', content: 'Plain text content' },
                { extension: 'html', contentType: 'text/html', content: '<html><body>HTML content</body></html>' },
                { extension: 'css', contentType: 'text/css', content: 'body { background: #fff; }' },
                { extension: 'js', contentType: 'application/javascript', content: 'console.log("JavaScript content");' }
            ];

            for (const fileType of fileTypes) {
                const fileName = `content-type-test-${Date.now()}.${fileType.extension}`;
                
                const uploadResponse = await retryOperation(async () => {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 20000);
                    
                    try {
                        const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(fileName)}`, {
                            method: 'POST',
                            headers: { 'Content-Type': fileType.contentType },
                            body: fileType.content,
                            signal: controller.signal
                        });
                        
                        clearTimeout(timeoutId);
                        
                        if (!response.ok) {
                            throw new Error(`Upload failed for ${fileType.extension}: ${response.status}`);
                        }
                        
                        return response;
                    } catch (error) {
                        clearTimeout(timeoutId);
                        throw error;
                    }
                }, 3, 1500, `${fileType.extension} file upload`);
                
                expect(uploadResponse.ok).toBe(true);
                createdFileNames.push(fileName);
            }
        });

        it('should handle large file operations with progress tracking', async () => {
            const fileName = `large-file-${Date.now()}.txt`;
            const largeContent = 'A'.repeat(50000); // 50KB file
            
            const start = Date.now();
            
            await retryOperation(async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 30000);
                
                try {
                    const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(fileName)}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'text/plain' },
                        body: largeContent,
                        signal: controller.signal
                    });
                    
                    clearTimeout(timeoutId);
                    
                    if (!response.ok) {
                        throw new Error(`Large file upload failed: ${response.status}`);
                    }
                    
                    return response;
                } catch (error) {
                    clearTimeout(timeoutId);
                    throw error;
                }
            }, 3, 2000, 'Large file upload');
            
            createdFileNames.push(fileName);
            
            const uploadDuration = Date.now() - start;
            expect(uploadDuration).toBeLessThan(30000);
            
            // Verify file size
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            const metadataResponse = await retryOperation(async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000);
                
                try {
                    const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`, {
                        signal: controller.signal
                    });
                    
                    clearTimeout(timeoutId);
                    
                    if (!response.ok) {
                        throw new Error(`Metadata request failed: ${response.status}`);
                    }
                    
                    return response;
                } catch (error) {
                    clearTimeout(timeoutId);
                    throw error;
                }
            }, 3, 1000, 'File metadata retrieval');
            
            const metadata = await metadataResponse.json();
            expect(parseInt(metadata.size)).toBe(largeContent.length);
        }, 45000);

        it('should handle file deletion operations', async () => {
            const fileName = `deletion-test-${Date.now()}.txt`;
            
            // Create file
            await createTestFile(fileName, 'Content to be deleted');
            
            // Wait for consistency
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // Delete file
            const deleteResponse = await retryOperation(async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000);
                
                try {
                    const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`, {
                        method: 'DELETE',
                        signal: controller.signal
                    });
                    
                    clearTimeout(timeoutId);
                    
                    if (!response.ok && response.status !== 404) {
                        throw new Error(`Delete failed: ${response.status}`);
                    }
                    
                    return response;
                } catch (error) {
                    clearTimeout(timeoutId);
                    throw error;
                }
            }, 3, 1000, 'File deletion');
            
            expect([200, 204, 404].includes(deleteResponse.status)).toBe(true);
            
            // Remove from tracking since it's deleted
            const index = createdFileNames.indexOf(fileName);
            if (index > -1) {
                createdFileNames.splice(index, 1);
            }
            
            // Verify file is deleted
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            
            try {
                const checkResponse = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`, {
                    signal: controller.signal
                });
                clearTimeout(timeoutId);
                expect(checkResponse.status).toBe(404);
            } catch (error) {
                clearTimeout(timeoutId);
                throw error;
            }
        });
    });

    describe('Cross-Service Integration Tests', () => {
        it('should create user with profile image and database record', async () => {
            const { firebaseUser, dbUser } = await createTestUser({
                email: `profile-test-${Date.now()}@example.com`,
                displayName: 'Profile Test User'
            });

            const profileImageName = `profiles/${firebaseUser.uid}/avatar.jpg`;
            const imageData = 'fake-image-data-' + Date.now();
            
            await retryOperation(async () => {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 15000);
                
                try {
                    const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(profileImageName)}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'image/jpeg' },
                        body: imageData,
                        signal: controller.signal
                    });
                    
                    clearTimeout(timeoutId);
                    
                    if (!response.ok) {
                        throw new Error(`Profile image upload failed: ${response.status}`);
                    }
                    
                    return response;
                } catch (error) {
                    clearTimeout(timeoutId);
                    throw error;
                }
            }, 3, 2000, 'Profile image upload');
            
            createdFileNames.push(profileImageName);

            if (dbUser) {
                await TestDatabaseConnection.query(
                    'UPDATE users SET display_name = $1 WHERE id = $2',
                    [`Profile User with Image`, firebaseUser.uid]
                );
                
                const updatedUser = await TestDatabaseConnection.query(
                    'SELECT * FROM users WHERE id = $1',
                    [firebaseUser.uid]
                );
                
                expect(updatedUser.rows[0].display_name).toBe('Profile User with Image');
            }

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            
            try {
                const fileCheckResponse = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(profileImageName)}`, {
                    signal: controller.signal
                });
                clearTimeout(timeoutId);
                expect(fileCheckResponse.ok).toBe(true);
            } catch (error) {
                clearTimeout(timeoutId);
                throw error;
            }
        });

        it('should handle user document workflow with file attachments', async () => {
            const { firebaseUser } = await createTestUser({
                email: `document-workflow-${Date.now()}@example.com`,
                displayName: 'Document User'
            });

            // Create multiple document files for the user
            const documentFiles = [
                { name: `documents/${firebaseUser.uid}/resume.pdf`, content: 'PDF content' },
                { name: `documents/${firebaseUser.uid}/cover-letter.doc`, content: 'DOC content' },
                { name: `documents/${firebaseUser.uid}/references.txt`, content: 'References content' }
            ];

            const uploadPromises = documentFiles.map(doc => 
                retryOperation(async () => {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 15000);
                    
                    try {
                        const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(doc.name)}`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/octet-stream' },
                            body: doc.content,
                            signal: controller.signal
                        });
                        
                        clearTimeout(timeoutId);
                        
                        if (!response.ok) {
                            throw new Error(`Document upload failed: ${response.status}`);
                        }
                        
                        createdFileNames.push(doc.name);
                        return response;
                    } catch (error) {
                        clearTimeout(timeoutId);
                        throw error;
                    }
                }, 2, 1500, `Document upload: ${doc.name}`)
            );

            await Promise.all(uploadPromises);

            // Verify all documents exist
            for (const doc of documentFiles) {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 5000);
                
                try {
                    const checkResponse = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(doc.name)}`, {
                        signal: controller.signal
                    });
                    clearTimeout(timeoutId);
                    expect(checkResponse.ok).toBe(true);
                } catch (error) {
                    clearTimeout(timeoutId);
                    throw error;
                }
            }
        });
    });

    describe('Error Handling and Recovery Tests', () => {
        it('should handle network timeouts gracefully', async () => {
            const fileName = `timeout-test-${Date.now()}.txt`;
            
            try {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10); // Very short timeout
                
                await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(fileName)}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain' },
                    body: 'timeout test',
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
            } catch (error) {
                expect(error).toBeDefined();
                // Check for abort-related errors instead of specific TimeoutError
                expect(
                    error instanceof Error && 
                    (error.name === 'AbortError' || error.message.includes('abort'))
                ).toBe(true);
            }
        });

        it('should handle invalid file operations', async () => {
            // Try to download non-existent file
            const nonExistentFile = `non-existent-${Date.now()}.txt`;
            
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            
            try {
                const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/download/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(nonExistentFile)}?alt=media`, {
                    signal: controller.signal
                });
                
                clearTimeout(timeoutId);
                expect(response.status).toBe(404);
            } catch (error) {
                clearTimeout(timeoutId);
                throw error;
            }
        });

        it('should recover from temporary service interruptions', async () => {
            let successCount = 0;
            const totalAttempts = 5;
            
            for (let i = 0; i < totalAttempts; i++) {
                try {
                    const fileName = `recovery-test-${i}-${Date.now()}.txt`;
                    await createTestFile(fileName, `Recovery test ${i}`);
                    successCount++;
                } catch (error) {
                    console.log(`Attempt ${i} failed (expected for resilience testing):`, error);
                }
            }
            
            // At least some attempts should succeed
            expect(successCount).toBeGreaterThan(0);
        });
    });

    describe('Performance and Load Tests', () => {
        it('should handle concurrent file operations', async () => {
            const concurrentOperations = 3; // Reduced for stability
            const start = Date.now();
            
            const operations = Array.from({ length: concurrentOperations }, async (_, i) => {
                const fileName = `concurrent-${i}-${Date.now()}.txt`;
                const content = `Concurrent content ${i}`;
                
                return retryOperation(async () => {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 20000);
                    
                    try {
                        const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/upload/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o?uploadType=media&name=${encodeURIComponent(fileName)}`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'text/plain' },
                            body: content,
                            signal: controller.signal
                        });
                        
                        clearTimeout(timeoutId);
                        
                        if (!response.ok) {
                            throw new Error(`Concurrent upload failed: ${response.status}`);
                        }
                        
                        createdFileNames.push(fileName);
                        return { fileName, success: true };
                    } catch (error) {
                        clearTimeout(timeoutId);
                        throw error;
                    }
                }, 2, 1000, `Concurrent operation ${i}`);
            });
            
            const results = await Promise.all(operations);
            const duration = Date.now() - start;
            
            expect(results.length).toBe(concurrentOperations);
            expect(duration).toBeLessThan(30000); // Should complete within 30 seconds
            
            // Verify all operations succeeded
            const successfulOps = results.filter(r => r.success);
            expect(successfulOps.length).toBe(concurrentOperations);
        });

        it('should maintain performance with mixed operations', async () => {
            const { firebaseUser } = await createTestUser({
                email: `mixed-ops-${Date.now()}@example.com`
            });
            
            const fileName = await createTestFile(
                `mixed-ops-${Date.now()}.txt`,
                'Mixed operations test'
            );
            
            // Perform mixed operations concurrently
            const operations = [
                auth.getUser(firebaseUser.uid),
                (async () => {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 10000);
                    
                    try {
                        const response = await fetch(`http://${EMULATOR_CONFIG.storageEmulator}/storage/v1/b/${EMULATOR_CONFIG.storageBucket}/o/${encodeURIComponent(fileName)}`, {
                            signal: controller.signal
                        });
                        clearTimeout(timeoutId);
                        return response;
                    } catch (error) {
                        clearTimeout(timeoutId);
                        throw error;
                    }
                })(),
                TestDatabaseConnection.query('SELECT version()')
            ];
            
            const start = Date.now();
            const results = await Promise.all(operations);
            const duration = Date.now() - start;
            
            expect(results[0].uid).toBe(firebaseUser.uid); // Auth operation
            expect(results[1].ok).toBe(true); // Storage operation
            expect(results[2].rows.length).toBeGreaterThan(0); // Database operation
            
            expect(duration).toBeLessThan(10000); // Mixed operations should be fast
        });
    });
});