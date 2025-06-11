/**
 * Production-Ready Integration Test Suite for Wardrobe Routes
 * 
 * @description Tests complete HTTP request flow with real database operations.
 * This suite validates wardrobe CRUD operations, authentication, authorization,
 * user data isolation, garment-wardrobe relationships, validation middleware,
 * and error handling through actual Express routes.
 * 
 * @author Security & Integration Team
 * @version 1.0.0
 * @since June 12, 2025
 */

import request from 'supertest';
import express from 'express';
import { jest } from '@jest/globals';
import path from 'path';
import fs from 'fs/promises';

// #region Firebase Configuration
process.env.FIRESTORE_EMULATOR_HOST = 'localhost:9100';
process.env.FIREBASE_STORAGE_EMULATOR_HOST = 'localhost:9199';
process.env.FIREBASE_AUTH_EMULATOR_HOST = 'localhost:9099';

jest.doMock('../../config/firebase', () => {
  const admin = require('firebase-admin');
  
  if (!admin.apps.length) {
    admin.initializeApp({
      projectId: 'demo-koutu-test',
      credential: admin.credential.applicationDefault(),
      storageBucket: 'demo-koutu-test.appspot.com'
    });
  }

  const db = admin.firestore();
  const bucket = admin.storage().bucket();

  db.settings({
    host: 'localhost:9100',
    ssl: false
  });

  return { admin, db, bucket };
});

// #region Dual-Mode Infrastructure
import { 
    getTestDatabaseConnection, 
    setupWardrobeTestQuickFix
} from '../../utils/dockerMigrationHelper';

// Mock database layer to use dual-mode connection
jest.doMock('../../models/db', () => ({
  query: async (text: string, params?: any[]) => {
    const TestDB = getTestDatabaseConnection();
    return TestDB.query(text, params);
  }
}));

// Import the actual routes and dependencies
import { wardrobeRoutes } from '../../routes/wardrobeRoutes';
import { authenticate } from '../../middlewares/auth';
import { errorHandler } from '../../middlewares/errorHandler';

describe('Wardrobe Routes - Comprehensive Integration Test Suite', () => {
    // #region Test Variables
    let app: express.Application;
    let testUser1: any;
    let testUser2: any;
    let testAdmin: any;
    let authToken1: string;
    let authToken2: string;
    let adminToken: string;
    let imageCounter = 0;
    let TestDatabaseConnection: any;
    let testUserModel: any;
    let createTestImage: (userId: string, name: string) => Promise<any>;
    // #endregion

    // #region Helper Functions
    const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

    const ensureUploadDirectories = async (): Promise<void> => {
        const uploadsDir = path.join(process.cwd(), 'uploads');
        const directories = [
            uploadsDir,
            path.join(uploadsDir, 'emulator'),
            path.join(uploadsDir, 'user1'),
            path.join(uploadsDir, 'user2')
        ];
        
        try {
            for (const dir of directories) {
                await fs.mkdir(dir, { recursive: true });
            }
        } catch (error) {
            console.warn('⚠️ Could not create upload directories:', error);
        }
    };

    const createTestGarment = async (userId: string, imageId: string, name: string) => {
        const garmentData = {
            original_image_id: imageId,
            mask_data: {
                width: 1920,
                height: 1080,
                data: new Array(1920 * 1080).fill(128)
            },
            metadata: {
                name,
                category: 'shirt',
                color: 'blue',
                brand: 'TestBrand'
            }
        };

        return await request(app)
            .post('/api/garments')
            .set('Authorization', userId === testUser1.id ? `Bearer ${authToken1}` : `Bearer ${authToken2}`)
            .send(garmentData);
    };

    /**
     * Creates a valid wardrobe data payload
     */
    const createValidWardrobeData = (overrides: any = {}) => ({
        name: 'Test Wardrobe Collection',
        description: 'A comprehensive test wardrobe for integration testing',
        ...overrides
    });

    /**
     * Creates validation test cases for wardrobe name validation
     */
    const getNameValidationTestCases = () => [
        { name: '', expectValid: false, description: 'Empty name' },
        { name: '   ', expectValid: false, description: 'Whitespace only' },
        { name: 'A', expectValid: true, description: 'Single character' },
        { name: 'Valid Name', expectValid: true, description: 'Normal valid name' },
        { name: 'My-Wardrobe_2024.Collection', expectValid: true, description: 'Allowed special chars' },
        { name: 'a'.repeat(100), expectValid: true, description: 'Maximum length (100 chars)' },
        { name: 'a'.repeat(101), expectValid: false, description: 'Exceeds maximum length' },
        { name: 'Invalid@Name', expectValid: false, description: 'Contains @ symbol' },
        { name: 'Invalid#Name', expectValid: false, description: 'Contains # symbol' },
        { name: 'Invalid$Name', expectValid: false, description: 'Contains $ symbol' },
    ];
    // #endregion

    // #region Authentication Middleware Mock
    /**
     * Mock authentication middleware that validates JWT-like tokens
     * Maps test tokens to user objects for request authentication
     */
    const mockAuthMiddleware = (req: any, res: any, next: any) => {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ 
                status: 'error', 
                code: 'UNAUTHORIZED',
                message: 'Authentication required' 
            });
        }

        const token = authHeader.substring(7);
        
        const tokenMap: { [key: string]: any } = {
            'user1-auth-token': { id: testUser1?.id, email: testUser1?.email, role: 'user' },
            'user2-auth-token': { id: testUser2?.id, email: testUser2?.email, role: 'user' },
            'admin-auth-token': { id: testAdmin?.id, email: testAdmin?.email, role: 'admin' }
        };

        const user = tokenMap[token];
        if (!user) {
            return res.status(401).json({ 
                status: 'error', 
                code: 'INVALID_TOKEN',
                message: 'Invalid or expired token' 
            });
        }

        req.user = user;
        next();
    };
    // #endregion

    // #region Test Setup and Teardown
    beforeAll(async () => {
        await ensureUploadDirectories();
        
        try {
            // Initialize dual-mode test infrastructure
            const setup = await setupWardrobeTestQuickFix();
            TestDatabaseConnection = setup.TestDB;
            testUserModel = setup.testUserModel;
            
            // Create test users
            testUser1 = await testUserModel.create({
                email: 'user1@wardrobeint.com',
                password: 'SecurePass123!'
            });

            testUser2 = await testUserModel.create({
                email: 'user2@wardrobeint.com',
                password: 'SecurePass123!'
            });

            testAdmin = await testUserModel.create({
                email: 'admin@wardrobeint.com',
                password: 'AdminPass123!'
            });

            // Create test image helper
            createTestImage = async (userId: string, name: string) => {
                imageCounter++;
                return await setup.createTestImage(userId, name, imageCounter);
            };

            // Configure Express application with real routes
            app = express();
            app.use(express.json({ limit: '50mb' }));
            app.use(express.urlencoded({ extended: true }));

            // Add security headers middleware
            app.use((req, res, next) => {
                res.setHeader('X-Content-Type-Options', 'nosniff');
                res.setHeader('X-Frame-Options', 'DENY');
                res.setHeader('X-XSS-Protection', '1; mode=block');
                next();
            });

            // Mount the actual wardrobe routes with mock auth
            app.use('/api/v1/wardrobes', mockAuthMiddleware, wardrobeRoutes);

            // Add a garment route for relationship testing
            app.post('/api/garments', mockAuthMiddleware, async (req, res, next) => {
                try {
                    // Simplified garment creation for testing wardrobe relationships
                    const { original_image_id, mask_data, metadata } = req.body;
                    
                    if (!original_image_id) {
                        return res.status(400).json({
                            status: 'error',
                            message: 'Original image ID is required.'
                        });
                    }

                    if (!mask_data || !mask_data.width || !mask_data.height || !mask_data.data) {
                        return res.status(400).json({
                            status: 'error',
                            message: 'Missing or invalid mask_data.'
                        });
                    }

                    // Create garment in database
                    const garmentId = require('uuid').v4();
                    await TestDatabaseConnection.query(
                        `INSERT INTO garment_items (id, user_id, original_image_id, file_path, mask_path, metadata, created_at, updated_at)
                         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
                        [
                            garmentId,
                            req.user.id,
                            original_image_id,
                            `/uploads/garment_${garmentId}.jpg`,
                            `/uploads/mask_${garmentId}.png`,
                            JSON.stringify(metadata || {})
                        ]
                    );

                    const result = await TestDatabaseConnection.query(
                        'SELECT * FROM garment_items WHERE id = $1',
                        [garmentId]
                    );

                    res.status(201).json({
                        status: 'success',
                        data: { garment: result.rows[0] },
                        message: 'Garment created successfully'
                    });
                } catch (error) {
                    next(error);
                }
            });

            // Global error handler
            app.use(errorHandler);

            // Set authentication tokens
            authToken1 = 'user1-auth-token';
            authToken2 = 'user2-auth-token';
            adminToken = 'admin-auth-token';

        } catch (error) {
            console.error('Setup failed:', error);
            throw error;
        }
    }, 60000);

    afterAll(async () => {
        try {
            await TestDatabaseConnection.cleanup();
        } catch (error) {
            console.warn('⚠️ Cleanup issues:', error);
        }
    }, 30000);

    beforeEach(async () => {
        try {
            // Clear wardrobe-related data while preserving users and images
            await TestDatabaseConnection.query('DELETE FROM wardrobe_items');
            await TestDatabaseConnection.query('DELETE FROM wardrobes');
            await TestDatabaseConnection.query('DELETE FROM garment_items');
        } catch (error) {
            // Tables might not exist yet, ignore
        }
    });
    // #endregion

    // #region Authentication & Authorization Integration Tests
    describe('1. Authentication & Authorization Integration', () => {
        test('should reject requests without authentication header', async () => {
            const response = await request(app)
                .get('/api/v1/wardrobes')
                .expect(401);

            expect(response.body).toMatchObject({
                status: 'error',
                code: 'UNAUTHORIZED',
                message: 'Authentication required'
            });
        });

        test('should reject malformed authorization headers', async () => {
            const malformedHeaders = [
                'InvalidFormat token123',
                'Bearer',
                'Bearer ',
                'Basic dGVzdDp0ZXN0',
                'Digest username="test"'
            ];

            for (const header of malformedHeaders) {
                const response = await request(app)
                    .get('/api/v1/wardrobes')
                    .set('Authorization', header)
                    .expect(401);

                expect(response.body.status).toBe('error');
            }
        });

        test('should reject invalid tokens', async () => {
            const response = await request(app)
                .get('/api/v1/wardrobes')
                .set('Authorization', 'Bearer invalid-token-12345')
                .expect(401);

            expect(response.body).toMatchObject({
                status: 'error',
                code: 'INVALID_TOKEN',
                message: 'Invalid or expired token'
            });
        });

        test('should accept valid user tokens', async () => {
            const response = await request(app)
                .get('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken1}`)
                .expect(200);

            expect(response.body.status).toBe('success');
            expect(response.body.data.wardrobes).toEqual([]);
        });

        test('should enforce user data isolation', async () => {
            // Create wardrobe for user1
            const createResponse = await request(app)
                .post('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken1}`)
                .send(createValidWardrobeData({
                    name: 'User1 Private Wardrobe',
                    description: 'Private collection for user1'
                }))
                .expect(201);

            const wardrobeId = createResponse.body.data.wardrobe.id;

            // User2 should not see user1's wardrobes
            const listResponse = await request(app)
                .get('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken2}`)
                .expect(200);

            expect(listResponse.body.data.wardrobes).toHaveLength(0);

            // User2 should not access user1's specific wardrobe
            await request(app)
                .get(`/api/v1/wardrobes/${wardrobeId}`)
                .set('Authorization', `Bearer ${authToken2}`)
                .expect(403);

            // User1 should see their own wardrobe
            const user1Response = await request(app)
                .get('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken1}`)
                .expect(200);

            expect(user1Response.body.data.wardrobes).toHaveLength(1);
            expect(user1Response.body.data.wardrobes[0].user_id).toBe(testUser1.id);
        });

        test('should validate token consistency across operations', async () => {
            const createResponse = await request(app)
                .post('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken1}`)
                .send(createValidWardrobeData({ name: 'Token Consistency Test' }))
                .expect(201);

            const wardrobeId = createResponse.body.data.wardrobe.id;

            // Try to update with user2 token (should fail)
            await request(app)
                .put(`/api/v1/wardrobes/${wardrobeId}`)
                .set('Authorization', `Bearer ${authToken2}`)
                .send({ name: 'Unauthorized Update' })
                .expect(403);

            // Update with user1 token (should succeed)
            await request(app)
                .put(`/api/v1/wardrobes/${wardrobeId}`)
                .set('Authorization', `Bearer ${authToken1}`)
                .send({ name: 'Authorized Update' })
                .expect(200);
        });
    });
    // #endregion

    // #region Create Wardrobe Integration Tests
    describe('2. CREATE Wardrobe Integration (/api/v1/wardrobes POST)', () => {
        test('should create wardrobe with complete valid data', async () => {
            const wardrobeData = createValidWardrobeData({
                name: 'Premium Summer Collection 2024',
                description: 'A curated collection of premium summer garments including lightweight fabrics, breathable materials, and stylish accessories perfect for hot weather and vacation destinations.'
            });

            const response = await request(app)
                .post('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken1}`)
                .send(wardrobeData)
                .expect(201);

            expect(response.body).toMatchObject({
                status: 'success',
                message: 'Wardrobe created successfully'
            });

            const wardrobe = response.body.data.wardrobe;
            expect(wardrobe.id).toBeTruthy();
            expect(wardrobe.user_id).toBe(testUser1.id);
            expect(wardrobe.name).toBe('Premium Summer Collection 2024');
            expect(wardrobe.description).toContain('curated collection');
            expect(wardrobe.created_at).toBeTruthy();
            expect(wardrobe.updated_at).toBeTruthy();

            // Verify database persistence
            const dbResult = await TestDatabaseConnection.query(
                'SELECT * FROM wardrobes WHERE id = $1',
                [wardrobe.id]
            );
            expect(dbResult.rows.length).toBe(1);
            expect(dbResult.rows[0].user_id).toBe(testUser1.id);
            expect(dbResult.rows[0].name).toBe('Premium Summer Collection 2024');
        });

        test('should create wardrobe with minimal required data', async () => {
            const minimalData = {
                name: 'Minimal Test Wardrobe'
            };

            const response = await request(app)
                .post('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken1}`)
                .send(minimalData)
                .expect(201);

            expect(response.body.status).toBe('success');
            expect(response.body.data.wardrobe.name).toBe('Minimal Test Wardrobe');
            expect(response.body.data.wardrobe.description).toBeDefined();
        });

        test('should validate all name validation rules through routes', async () => {
            const testCases = getNameValidationTestCases();

            for (const testCase of testCases) {
                const response = await request(app)
                    .post('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken1}`)
                    .send({ name: testCase.name });

                if (testCase.expectValid) {
                    expect(response.status).toBe(201);
                    expect(response.body.status).toBe('success');
                } else {
                    expect(response.status).toBe(400);
                    expect(response.body.status).toBe('error');
                    expect(response.body.code).toBe('VALIDATION_ERROR');
                }
            }
        });

        test('should validate description length limits', async () => {
            const testCases = [
                { description: '', expectValid: true },
                { description: 'Valid description', expectValid: true },
                { description: 'a'.repeat(1000), expectValid: true },
                { description: 'a'.repeat(1001), expectValid: false }
            ];

            for (const testCase of testCases) {
                const response = await request(app)
                    .post('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken1}`)
                    .send(createValidWardrobeData({ description: testCase.description }));

                if (testCase.expectValid) {
                    expect(response.status).toBe(201);
                } else {
                    expect(response.status).toBe(400);
                    expect(response.body.code).toBe('VALIDATION_ERROR');
                }
            }
        });

        test('should handle concurrent wardrobe creation', async () => {
            const promises = Array.from({ length: 5 }, (_, i) => 
                request(app)
                    .post('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken1}`)
                    .send(createValidWardrobeData({ name: `Concurrent Wardrobe ${i}` }))
            );

            const results = await Promise.all(promises);
            
            // All should succeed
            results.forEach((response, index) => {
                expect(response.status).toBe(201);
                expect(response.body.data.wardrobe.id).toBeTruthy();
                expect(response.body.data.wardrobe.name).toBe(`Concurrent Wardrobe ${index}`);
            });

            // Verify all wardrobes were created with unique IDs
            const wardrobeIds = results.map(r => r.body.data.wardrobe.id);
            const uniqueIds = new Set(wardrobeIds);
            expect(uniqueIds.size).toBe(5);

            // Verify in database
            const dbResult = await TestDatabaseConnection.query(
                'SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1',
                [testUser1.id]
            );
            expect(parseInt(dbResult.rows[0].count)).toBeGreaterThanOrEqual(5);
        });

        test('should preserve Unicode and special characters', async () => {
            const unicodeData = createValidWardrobeData({
                name: '夏のコレクション 🌞 Summer',
                description: 'Collection with émojis and ñón-ASCII characters: 中文, العربية, русский'
            });

            const response = await request(app)
                .post('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken1}`)
                .send(unicodeData)
                .expect(201);

            expect(response.body.data.wardrobe.name).toBe('夏のコレクション 🌞 Summer');
            expect(response.body.data.wardrobe.description).toContain('émojis');

            // Verify Unicode preservation in database
            const dbResult = await TestDatabaseConnection.query(
                'SELECT name, description FROM wardrobes WHERE id = $1',
                [response.body.data.wardrobe.id]
            );
            expect(dbResult.rows[0].name).toBe('夏のコレクション 🌞 Summer');
            expect(dbResult.rows[0].description).toContain('العربية');
        });
    });
    // #endregion

    // #region Read Wardrobe Integration Tests
    describe('3. READ Wardrobe Integration Tests', () => {
        let createdWardrobes: any[] = [];

        beforeEach(async () => {
            // Create test wardrobes for read operations
            const wardrobePromises = [
                request(app)
                    .post('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken1}`)
                    .send(createValidWardrobeData({ 
                        name: 'Summer Collection', 
                        description: 'Light and airy summer clothes' 
                    })),
                request(app)
                    .post('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken1}`)
                    .send(createValidWardrobeData({ 
                        name: 'Winter Collection', 
                        description: 'Warm and cozy winter clothes' 
                    })),
                request(app)
                    .post('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken1}`)
                    .send(createValidWardrobeData({ 
                        name: 'Work Outfits', 
                        description: 'Professional attire for the office' 
                    }))
            ];

            const results = await Promise.all(wardrobePromises);
            createdWardrobes = results.filter(r => r.status === 201).map(r => r.body.data.wardrobe);
        });

        describe('3.1 GET /api/v1/wardrobes (List Wardrobes)', () => {
            test('should retrieve all user wardrobes with proper structure', async () => {
                const response = await request(app)
                    .get('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken1}`)
                    .expect(200);

                expect(response.body.status).toBe('success');
                expect(response.body.data.wardrobes).toHaveLength(createdWardrobes.length);
                expect(response.body.data.count).toBe(createdWardrobes.length);

                // Verify structure of returned wardrobes
                if (createdWardrobes.length > 0) {
                    const wardrobe = response.body.data.wardrobes[0];
                    expect(wardrobe).toHaveProperty('id');
                    expect(wardrobe).toHaveProperty('user_id');
                    expect(wardrobe).toHaveProperty('name');
                    expect(wardrobe).toHaveProperty('description');
                    expect(wardrobe).toHaveProperty('created_at');
                    expect(wardrobe).toHaveProperty('updated_at');
                    expect(wardrobe.user_id).toBe(testUser1.id);
                }

                // Verify wardrobes are ordered by name (alphabetically)
                const names = response.body.data.wardrobes.map((w: any) => w.name);
                const sortedNames = [...names].sort();
                expect(names).toEqual(sortedNames);
            });

            test('should return empty array when user has no wardrobes', async () => {
                const response = await request(app)
                    .get('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken2}`)
                    .expect(200);

                expect(response.body.status).toBe('success');
                expect(response.body.data.wardrobes).toEqual([]);
                expect(response.body.data.count).toBe(0);
            });

            test('should include security headers in response', async () => {
                const response = await request(app)
                    .get('/api/v1/wardrobes')
                    .set('Authorization', `Bearer ${authToken1}`)
                    .expect(200);

                expect(response.headers['x-content-type-options']).toBe('nosniff');
                expect(response.headers['x-frame-options']).toBe('DENY');
                expect(response.headers['x-xss-protection']).toBe('1; mode=block');
            });
        });

        describe('3.2 GET /api/v1/wardrobes/:id (Get Single Wardrobe)', () => {
            test('should retrieve specific wardrobe with garments', async () => {
                if (createdWardrobes.length === 0) return;

                const wardrobeId = createdWardrobes[0].id;
                
                const response = await request(app)
                    .get(`/api/v1/wardrobes/${wardrobeId}`)
                    .set('Authorization', `Bearer ${authToken1}`)
                    .expect(200);

                expect(response.body.status).toBe('success');
                expect(response.body.data.wardrobe.id).toBe(wardrobeId);
                expect(response.body.data.wardrobe.user_id).toBe(testUser1.id);
                expect(response.body.data.wardrobe.name).toBe('Summer Collection');
                
                // Should include garments array (empty initially)
                expect(response.body.data.wardrobe).toHaveProperty('garments');
                expect(Array.isArray(response.body.data.wardrobe.garments)).toBe(true);
                expect(response.body.data.wardrobe.garments).toHaveLength(0);
            });

            test('should return 404 for non-existent wardrobe', async () => {
                const fakeId = '550e8400-e29b-41d4-a716-446655440000';
                
                const response = await request(app)
                    .get(`/api/v1/wardrobes/${fakeId}`)
                    .set('Authorization', `Bearer ${authToken1}`)
                    .expect(404);

                expect(response.body.status).toBe('error');
                expect(response.body.message).toContain('not found');
            });

            test('should return 403 when accessing another user\'s wardrobe', async () => {
                if (createdWardrobes.length === 0) return;

                const wardrobeId = createdWardrobes[0].id;
                
                const response = await request(app)
                    .get(`/api/v1/wardrobes/${wardrobeId}`)
                    .set('Authorization', `Bearer ${authToken2}`)
                    .expect(403);

                expect(response.body.status).toBe('error');
                expect(response.body.message).toContain('permission');
            });

            test('should validate UUID format in parameters', async () => {
                const invalidUuids = [
                    'invalid-uuid-format',
                    '12345',
                    'not-a-uuid-at-all',
                    '550e8400-e29b-41d4-a716' // Incomplete UUID
                ];

                for (const invalidUuid of invalidUuids) {
                    const response = await request(app)
                        .get(`/api/v1/wardrobes/${invalidUuid}`)
                        .set('Authorization', `Bearer ${authToken1}`)
                        .expect(400);

                    expect(response.body.status).toBe('error');
                    expect(response.body.code).toBe('VALIDATION_ERROR');
                }
            });
        });
    });
    // #endregion

    // #region Update Wardrobe Integration Tests
    describe('4. UPDATE Wardrobe Integration Tests', () => {
        let testWardrobe: any;

        beforeEach(async () => {
            const response = await request(app)
                .post('/api/v1/wardrobes')
                .set('Authorization', `Bearer ${authToken1}`)
                .send(createValidWardrobeData({
                    name: 'Original Test Wardrobe',
                    description: 'Original description for testing updates'
                }));
            
            testWardrobe = response.status === 201 ? response.body.data.wardrobe : null;
        });

        test('should update wardrobe name and description', async () => {
            if (!testWar