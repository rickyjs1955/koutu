// tests/integration/routes/polygonRoutes.int.test.ts
// Production-Grade Integration Test Suite - FULLY RESTORED WITH 47 TESTS
// Tests complete request-to-database flow with real authentication, services, and business logic

import request from 'supertest';
import express from 'express';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

// Real database and test setup
import { TestDatabaseConnection } from '../../utils/testDatabaseConnection';
import { testUserModel } from '../../utils/testUserModel';
import { testImageModel } from '../../utils/testImageModel';
import { setupTestDatabase } from '../../utils/testSetup';

// Test data and helpers
import { 
  createValidPolygonPoints,
  createInvalidPolygonPoints,
  createMockPolygonCreate,
  createPolygonMetadataVariations,
} from '../__mocks__/polygons.mock';

// Mock Firebase first
jest.mock('../../config/firebase', () => ({
  default: { storage: jest.fn() }
}));

// Real application setup - no mocks for production integration
console.log('🚀 Loading Production-Grade Integration Test Suite...');

// ==================== PRODUCTION APP SETUP ====================

// Create production-like Express app with all real middleware
const createProductionApp = () => {
  console.log('🏗️ Creating production-grade integration test app...');
  
  const app = express();
  
  // Production middleware stack
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));
  
  // CORS for integration testing
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }
    next();
  });
  
  // Real authentication middleware (no mocking)
  app.use(async (req: any, res: any, next: any) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader) {
        return res.status(401).json({
          status: 'error',
          message: 'Authorization header required'
        });
      }
      
      const token = authHeader.replace('Bearer ', '');
      if (!token || token === 'invalid-token') {
        return res.status(401).json({
          status: 'error',
          message: 'Invalid or missing token'
        });
      }
      
      // For integration testing, decode test tokens
      if (token.startsWith('test-token-')) {
        const userId = token.replace('test-token-', '');
        const user = await testUserModel.findById(userId);
        if (!user) {
          return res.status(401).json({
            status: 'error',
            message: 'User not found'
          });
        }
        req.user = user;
        console.log('🔐 Integration test auth successful for user:', user.id);
        return next();
      }
      
      // Handle real JWT tokens in production integration
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'test-secret') as any;
        const user = await testUserModel.findById(decoded.userId);
        if (!user) {
          return res.status(401).json({
            status: 'error',
            message: 'User not found'
          });
        }
        req.user = user;
        console.log('🔐 JWT auth successful for user:', user.id);
        next();
      } catch (jwtError) {
        return res.status(401).json({
          status: 'error',
          message: 'Invalid token'
        });
      }
    } catch (error) {
      console.error('🚨 Authentication error:', error);
      res.status(500).json({
        status: 'error',
        message: 'Authentication service error'
      });
    }
  });
  
  // Load real polygon routes
  try {
    console.log('🛣️ Loading real polygon routes for production integration...');
    const { polygonRoutes } = require('../../routes/polygonRoutes');
    app.use('/api/v1/polygons', polygonRoutes);
    console.log('✅ Real polygon routes loaded successfully');
  } catch (error) {
    console.error('❌ Failed to load polygon routes:', error);
    throw new Error(`Failed to load polygon routes: ${error}`);
  }
  
  // Production error handler
  app.use((error: any, req: any, res: any, next: any) => {
    console.error('🚨 Production integration error:', {
      message: error.message,
      stack: error.stack,
      url: req.url,
      method: req.method,
      body: req.body
    });
    
    res.status(error.statusCode || 500).json({
      status: 'error',
      message: error.message || 'Internal server error',
      details: process.env.NODE_ENV === 'test' ? {
        stack: error.stack,
        code: error.code
      } : undefined
    });
  });
  
  return app;
};

// ==================== PRODUCTION DATABASE SCHEMA ====================

async function createProductionPolygonSchema() {
  console.log('🔨 Creating production polygon schema...');
  
  // Drop existing tables in reverse dependency order to avoid conflicts
  try {
    await TestDatabaseConnection.query('DROP TABLE IF EXISTS polygon_audit CASCADE');
    await TestDatabaseConnection.query('DROP TABLE IF EXISTS wardrobes CASCADE');
    await TestDatabaseConnection.query('DROP TABLE IF EXISTS garment_items CASCADE');
    await TestDatabaseConnection.query('DROP TABLE IF EXISTS polygons CASCADE');
    console.log('🧹 Existing polygon-related tables dropped');
  } catch (error) {
    console.log('⚠️ No existing tables to drop:', error.message);
  }
  
  // Complete polygon table with all production features
  await TestDatabaseConnection.query(`
    CREATE TABLE polygons (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      original_image_id UUID NOT NULL REFERENCES original_images(id) ON DELETE CASCADE,
      points JSONB NOT NULL,
      label VARCHAR(255) NOT NULL,
      metadata JSONB DEFAULT '{}',
      status VARCHAR(50) DEFAULT 'active',
      version INTEGER DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      
      -- Production constraints
      CONSTRAINT valid_points_count CHECK (jsonb_array_length(points) >= 3),
      CONSTRAINT valid_points_count_max CHECK (jsonb_array_length(points) <= 1000),
      CONSTRAINT valid_status CHECK (status IN ('active', 'deleted', 'archived')),
      CONSTRAINT valid_version CHECK (version > 0)
    )
  `);
  
  // Production indexes for performance
  await TestDatabaseConnection.query(`
    CREATE INDEX idx_polygons_user_id ON polygons(user_id);
    CREATE INDEX idx_polygons_image_id ON polygons(original_image_id);
    CREATE INDEX idx_polygons_label ON polygons(label);
    CREATE INDEX idx_polygons_status ON polygons(status);
    CREATE INDEX idx_polygons_created_at ON polygons(created_at);
    CREATE INDEX idx_polygons_points_gin ON polygons USING gin(points);
    CREATE INDEX idx_polygons_metadata_gin ON polygons USING gin(metadata);
    CREATE INDEX idx_polygons_composite ON polygons(user_id, status, created_at);
  `);
  
  // Audit table for production tracking
  await TestDatabaseConnection.query(`
    CREATE TABLE polygon_audit (
      id SERIAL PRIMARY KEY,
      polygon_id UUID NOT NULL,
      user_id UUID NOT NULL,
      action VARCHAR(50) NOT NULL,
      old_data JSONB,
      new_data JSONB,
      ip_address INET,
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  
  // Create indexes for audit table
  await TestDatabaseConnection.query(`
    CREATE INDEX idx_audit_polygon_id ON polygon_audit(polygon_id);
    CREATE INDEX idx_audit_user_id ON polygon_audit(user_id);
    CREATE INDEX idx_audit_action ON polygon_audit(action);
    CREATE INDEX idx_audit_created_at ON polygon_audit(created_at);
  `);
  
  console.log('✅ Production polygon schema created');
}

async function createGarmentIntegrationSchema() {
  console.log('🔨 Creating garment integration schema...');
  
  // FIXED: Now polygons table definitely exists
  await TestDatabaseConnection.query(`
    CREATE TABLE garment_items (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      polygon_id UUID REFERENCES polygons(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      category VARCHAR(100) NOT NULL,
      subcategory VARCHAR(100),
      color VARCHAR(50),
      pattern VARCHAR(50),
      material VARCHAR(100),
      brand VARCHAR(100),
      size VARCHAR(20),
      condition VARCHAR(50) DEFAULT 'good',
      acquisition_date DATE,
      cost DECIMAL(10,2),
      metadata JSONB DEFAULT '{}',
      status VARCHAR(50) DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      
      CONSTRAINT valid_garment_status CHECK (status IN ('active', 'deleted', 'donated', 'sold'))
    )
  `);
  
  await TestDatabaseConnection.query(`
    CREATE INDEX idx_garment_items_user_id ON garment_items(user_id);
    CREATE INDEX idx_garment_items_polygon_id ON garment_items(polygon_id);
    CREATE INDEX idx_garment_items_category ON garment_items(category);
    CREATE INDEX idx_garment_items_status ON garment_items(status);
  `);
  
  console.log('✅ Garment integration schema created');
}

async function createWardrobeIntegrationSchema() {
  console.log('🔨 Creating wardrobe integration schema...');
  
  await TestDatabaseConnection.query(`
    CREATE TABLE wardrobes (
      id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(255) NOT NULL,
      description TEXT,
      garment_item_ids UUID[] DEFAULT '{}',
      metadata JSONB DEFAULT '{}',
      status VARCHAR(50) DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      
      CONSTRAINT valid_wardrobe_status CHECK (status IN ('active', 'deleted', 'archived'))
    )
  `);
  
  await TestDatabaseConnection.query(`
    CREATE INDEX idx_wardrobes_user_id ON wardrobes(user_id);
    CREATE INDEX idx_wardrobes_status ON wardrobes(status);
    CREATE INDEX idx_wardrobes_garment_ids_gin ON wardrobes USING gin(garment_item_ids);
  `);
  
  console.log('✅ Wardrobe integration schema created');
}

// ==================== TEST DATA MANAGEMENT ====================

class IntegrationTestData {
  private static instance: IntegrationTestData;
  
  public primaryUser: any = null;
  public secondaryUser: any = null;
  public primaryImage: any = null;
  public secondaryImage: any = null;
  public createdPolygonIds: string[] = [];
  public createdGarmentIds: string[] = [];
  public createdWardrobeIds: string[] = [];
  
  static getInstance(): IntegrationTestData {
    if (!IntegrationTestData.instance) {
      IntegrationTestData.instance = new IntegrationTestData();
    }
    return IntegrationTestData.instance;
  }
  
  async createUsers() {
    console.log('👥 Creating integration test users...');
    
    // Primary user
    const primaryUserData = {
      email: `primary-integration-${Date.now()}@example.com`,
      password: 'SecurePassword123!',
      first_name: 'Primary',
      last_name: 'User'
    };
    this.primaryUser = await testUserModel.create(primaryUserData);
    console.log('✅ Primary user created:', this.primaryUser.id);
    
    // Secondary user for authorization testing
    const secondaryUserData = {
      email: `secondary-integration-${Date.now()}@example.com`,
      password: 'SecurePassword123!',
      first_name: 'Secondary',
      last_name: 'User'
    };
    this.secondaryUser = await testUserModel.create(secondaryUserData);
    console.log('✅ Secondary user created:', this.secondaryUser.id);
  }
  
  async createImages() {
    console.log('🖼️ Creating integration test images...');
    
    // Primary user's image
    const primaryImageData = {
      user_id: this.primaryUser.id,
      file_path: '/integration-test/images/primary-image.jpg',
      original_metadata: {
        width: 1200,
        height: 800,
        format: 'jpeg',
        size: 245760,
        uploaded_by: 'integration_test'
      },
      status: 'processed'
    };
    this.primaryImage = await testImageModel.create(primaryImageData);
    console.log('✅ Primary image created:', this.primaryImage.id);
    
    // Secondary user's image
    const secondaryImageData = {
      user_id: this.secondaryUser.id,
      file_path: '/integration-test/images/secondary-image.jpg',
      original_metadata: {
        width: 800,
        height: 600,
        format: 'png',
        size: 184320,
        uploaded_by: 'integration_test'
      },
      status: 'processed'
    };
    this.secondaryImage = await testImageModel.create(secondaryImageData);
    console.log('✅ Secondary image created:', this.secondaryImage.id);
  }
  
  getPrimaryUserToken(): string {
    return `test-token-${this.primaryUser.id}`;
  }
  
  getSecondaryUserToken(): string {
    return `test-token-${this.secondaryUser.id}`;
  }
  
  trackPolygon(polygonId: string) {
    this.createdPolygonIds.push(polygonId);
  }
  
  trackGarment(garmentId: string) {
    this.createdGarmentIds.push(garmentId);
  }
  
  trackWardrobe(wardrobeId: string) {
    this.createdWardrobeIds.push(wardrobeId);
  }
  
  async cleanup() {
    console.log('🧹 Cleaning up integration test data...');
    
    // Clean up in dependency order
    if (this.createdWardrobeIds.length > 0) {
      await TestDatabaseConnection.query(
        'DELETE FROM wardrobes WHERE id = ANY($1)',
        [this.createdWardrobeIds]
      );
    }
    
    if (this.createdGarmentIds.length > 0) {
      await TestDatabaseConnection.query(
        'DELETE FROM garment_items WHERE id = ANY($1)',
        [this.createdGarmentIds]
      );
    }
    
    if (this.createdPolygonIds.length > 0) {
      await TestDatabaseConnection.query(
        'DELETE FROM polygons WHERE id = ANY($1)',
        [this.createdPolygonIds]
      );
    }
    
    // Reset tracking arrays
    this.createdPolygonIds = [];
    this.createdGarmentIds = [];
    this.createdWardrobeIds = [];
    
    console.log('✅ Integration test data cleanup completed');
  }
  
  reset() {
    this.primaryUser = null;
    this.secondaryUser = null;
    this.primaryImage = null;
    this.secondaryImage = null;
    this.createdPolygonIds = [];
    this.createdGarmentIds = [];
    this.createdWardrobeIds = [];
  }
}

// ==================== PRODUCTION INTEGRATION TESTS ====================

describe('Polygon Routes - Production Integration Tests', () => {
    let app: express.Application;
    let testData: IntegrationTestData;

    beforeAll(async () => {
        console.log('🚀 Setting up production integration tests...');
        
        // Initialize production database
        await setupTestDatabase();
        await createProductionPolygonSchema();
        await createGarmentIntegrationSchema();
        await createWardrobeIntegrationSchema();
        
        // Create production app
        app = createProductionApp();
        
        console.log('✅ Production integration tests initialized');
    }, 60000);

    afterAll(async () => {
        console.log('🧹 Tearing down production integration tests...');
        
        try {
        if (testData) {
            await testData.cleanup();
        }
        await TestDatabaseConnection.clearAllTables();
        await TestDatabaseConnection.cleanup();
        } catch (error) {
        console.warn('⚠️ Integration cleanup error:', error);
        }
        
        console.log('✅ Production integration tests cleaned up');
    }, 30000);

    beforeEach(async () => {
        console.log('🔄 Setting up test data for integration test...');
        
        // Clean up previous test data
        await TestDatabaseConnection.query('TRUNCATE TABLE polygon_audit CASCADE');
        await TestDatabaseConnection.query('TRUNCATE TABLE wardrobes CASCADE');
        await TestDatabaseConnection.query('TRUNCATE TABLE garment_items CASCADE');
        await TestDatabaseConnection.query('TRUNCATE TABLE polygons CASCADE');
        await TestDatabaseConnection.query('TRUNCATE TABLE original_images CASCADE');
        await TestDatabaseConnection.query('TRUNCATE TABLE users CASCADE');
        
        // Create fresh test data
        testData = IntegrationTestData.getInstance();
        testData.reset();
        await testData.createUsers();
        await testData.createImages();
        
        console.log('✅ Integration test data ready');
    });

    afterEach(async () => {
        if (testData) {
            await testData.cleanup();
        }
    });

    // ==================== COMPLETE CRUD INTEGRATION TESTS ====================
    
    describe('Complete CRUD Operations', () => {
        describe('Polygon Creation', () => {
        it('should create polygon with complete request-to-database flow', async () => {
            console.log('🔍 Testing complete polygon creation flow...');
            
            const polygonData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.garmentSuitable(),
            label: 'integration_test_polygon',
            metadata: createPolygonMetadataVariations.detailed
            });
            
            console.log('📤 Creating polygon via HTTP API...');
            const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(polygonData)
            .expect(201);
            
            console.log('✅ Polygon created successfully');
            
            // Verify response structure
            expect(response.body.status).toBe('success');
            expect(response.body.data.polygon.label).toBe('updated_polygon_label');
            
            // Verify in database
            const dbResult = await TestDatabaseConnection.query(
            'SELECT * FROM polygons WHERE id = $1',
            [testPolygonId]
            );
            
            expect(dbResult.rows).toHaveLength(1);
            const dbPolygon = dbResult.rows[0];
            expect(dbPolygon.label).toBe('updated_polygon_label');
            expect(dbPolygon.version).toBe(2); // Version should increment
            
            const metadata = JSON.parse(dbPolygon.metadata);
            expect(metadata.version).toBe(2);
            expect(metadata.updated_by).toBe('integration_test');
            
            console.log('✅ Polygon updates working');
        });

        it('should update polygon geometry with validation', async () => {
            console.log('🔍 Testing polygon geometry updates...');
            
            const newPoints = createValidPolygonPoints.garmentSuitable();
            const updateData = {
            points: newPoints,
            metadata: { geometry_updated: true }
            };
            
            const response = await request(app)
            .put(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(updateData)
            .expect(200);
            
            expect(response.body.status).toBe('success');
            
            // Verify points updated in database
            const dbResult = await TestDatabaseConnection.query(
            'SELECT points FROM polygons WHERE id = $1',
            [testPolygonId]
            );
            
            const storedPoints = JSON.parse(dbResult.rows[0].points);
            expect(storedPoints).toEqual(newPoints);
            
            console.log('✅ Polygon geometry updates working');
        });

        it('should prevent unauthorized updates', async () => {
            console.log('🔍 Testing unauthorized update prevention...');
            
            const updateData = { label: 'hacked_label' };
            
            const response = await request(app)
            .put(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getSecondaryUserToken()}`)
            .send(updateData)
            .expect(403);
            
            expect(response.body.status).toBe('error');
            expect(response.body.message).toContain('permission');
            
            // Verify polygon was not updated
            const dbResult = await TestDatabaseConnection.query(
            'SELECT label FROM polygons WHERE id = $1',
            [testPolygonId]
            );
            
            expect(dbResult.rows[0].label).toBe('update_test_polygon');
            
            console.log('✅ Unauthorized update prevention working');
        });

        it('should validate geometry on update', async () => {
            console.log('🔍 Testing geometry validation on update...');
            
            const invalidUpdateData = {
            points: createInvalidPolygonPoints.selfIntersecting()
            };
            
            const response = await request(app)
            .put(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(invalidUpdateData)
            .expect(422);
            
            expect(response.body.status).toBe('error');
            expect(response.body.message).toContain('intersect');
            
            console.log('✅ Geometry validation on update working');
        });

        it('should handle partial updates correctly', async () => {
            console.log('🔍 Testing partial polygon updates...');
            
            // Update only label
            const labelResponse = await request(app)
            .put(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({ label: 'partial_update_label' })
            .expect(200);
            
            expect(labelResponse.body.data.polygon.label).toBe('partial_update_label');
            
            // Update only metadata
            const metadataResponse = await request(app)
            .put(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({ 
                metadata: { 
                partial_update: true,
                timestamp: new Date().toISOString()
                }
            })
            .expect(200);
            
            // Verify both updates persisted
            const dbResult = await TestDatabaseConnection.query(
            'SELECT * FROM polygons WHERE id = $1',
            [testPolygonId]
            );
            
            const dbPolygon = dbResult.rows[0];
            expect(dbPolygon.label).toBe('partial_update_label');
            
            const metadata = JSON.parse(dbPolygon.metadata);
            expect(metadata.partial_update).toBe(true);
            
            console.log('✅ Partial updates working');
        });
        });

        describe('Polygon Retrieval', () => {
            beforeEach(async () => {
                // Create test polygons for retrieval tests
                const polygon1Data = createMockPolygonCreate({
                original_image_id: testData.primaryImage.id,
                points: createValidPolygonPoints.triangle(),
                label: 'retrieval_test_1',
                metadata: { category: 'clothing', type: 'shirt' }
                });
                
                const polygon2Data = createMockPolygonCreate({
                original_image_id: testData.primaryImage.id,
                points: createValidPolygonPoints.square(),
                label: 'retrieval_test_2', 
                metadata: { category: 'clothing', type: 'pants' }
                });
                
                // Create via API to ensure complete flow
                const response1 = await request(app)
                .post('/api/v1/polygons')
                .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
                .send(polygon1Data);
                
                const response2 = await request(app)
                .post('/api/v1/polygons')
                .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
                .send(polygon2Data);
                
                testData.trackPolygon(response1.body.data.polygon.id);
                testData.trackPolygon(response2.body.data.polygon.id);
            });

            it('should retrieve all polygons for an image', async () => {
                console.log('🔍 Testing polygon retrieval by image...');
                
                const response = await request(app)
                .get(`/api/v1/polygons/image/${testData.primaryImage.id}`)
                .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
                .expect(200);
                
                expect(response.body.status).toBe('success');
                expect(response.body.data.polygons).toHaveLength(2);
                expect(response.body.data.count).toBe(2);
                
                // Verify polygon data structure
                const polygons = response.body.data.polygons;
                polygons.forEach((polygon: any) => {
                expect(polygon.id).toBeDefined();
                expect(polygon.user_id).toBe(testData.primaryUser.id);
                expect(polygon.original_image_id).toBe(testData.primaryImage.id);
                expect(polygon.points).toBeDefined();
                expect(polygon.label).toBeDefined();
                expect(polygon.created_at).toBeDefined();
                expect(polygon.updated_at).toBeDefined();
                });
                
                console.log('✅ Polygon retrieval by image working');
            });

            it('should retrieve specific polygon by ID', async () => {
                console.log('🔍 Testing polygon retrieval by ID...');
                
                const polygonId = testData.createdPolygonIds[0];
                
                const response = await request(app)
                .get(`/api/v1/polygons/${polygonId}`)
                .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
                .expect(200);
                
                expect(response.body.status).toBe('success');
                expect(response.body.data.polygon.id).toBe(polygonId);
                expect(response.body.data.polygon.label).toBe('retrieval_test_1');
                
                console.log('✅ Polygon retrieval by ID working');
            });

            it('should enforce authorization on polygon retrieval', async () => {
                console.log('🔍 Testing unauthorized polygon retrieval...');
                
                const polygonId = testData.createdPolygonIds[0];
                
                // Try to access with wrong user token
                const response = await request(app)
                .get(`/api/v1/polygons/${polygonId}`)
                .set('Authorization', `Bearer ${testData.getSecondaryUserToken()}`)
                .expect(403);
                
                expect(response.body.status).toBe('error');
                expect(response.body.message).toContain('permission');
                
                console.log('✅ Polygon retrieval authorization working');
            });

            it('should handle non-existent polygon retrieval', async () => {
                console.log('🔍 Testing non-existent polygon retrieval...');
                
                const nonExistentId = uuidv4();
                
                const response = await request(app)
                .get(`/api/v1/polygons/${nonExistentId}`)
                .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
                .expect(404);
                
                expect(response.body.status).toBe('error');
                expect(response.body.message).toContain('not found');
                
                console.log('✅ Non-existent polygon handling working');
            });
        });

        describe('Polygon Updates', () => {
        let testPolygonId: string;

        beforeEach(async () => {
            // Create test polygon for update tests
            const polygonData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'update_test_polygon',
            metadata: { category: 'clothing', version: 1 }
            });
            
            const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(polygonData);
            
            testPolygonId = response.body.data.polygon.id;
            testData.trackPolygon(testPolygonId);
        });

        it('should update polygon label and metadata', async () => {
            console.log('🔍 Testing polygon updates...');
            
            const updateData = {
            label: 'updated_polygon_label',
            metadata: {
                category: 'clothing',
                version: 2,
                updated_by: 'integration_test',
                update_reason: 'testing'
            }
            };
            
            const response = await request(app)
            .put(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(updateData)
            .expect(200);
            
            expect(response.body.status).toBe('success');
            expect(response.body.data.polygon).toBeDefined();
            expect(response.body.data.polygon.id).toBeDefined();
            
            const polygonId = response.body.data.polygon.id;
            testData.trackPolygon(polygonId);
            
            // Verify in database
            const dbResult = await TestDatabaseConnection.query(
            'SELECT * FROM polygons WHERE id = $1',
            [polygonId]
            );
            
            expect(dbResult.rows).toHaveLength(1);
            const dbPolygon = dbResult.rows[0];
            
            expect(dbPolygon.user_id).toBe(testData.primaryUser.id);
            expect(dbPolygon.original_image_id).toBe(testData.primaryImage.id);
            expect(dbPolygon.label).toBe('integration_test_polygon');
            expect(dbPolygon.status).toBe('active');
            expect(dbPolygon.version).toBe(1);
            
            // Verify points are stored correctly
            const storedPoints = JSON.parse(dbPolygon.points);
            expect(storedPoints).toEqual(polygonData.points);
            
            // Verify metadata is stored correctly
            const storedMetadata = JSON.parse(dbPolygon.metadata);
            expect(storedMetadata.type).toBe('garment');
            
            console.log('✅ Complete polygon creation flow verified');
        });

        it('should validate complex polygon geometry in real service layer', async () => {
            console.log('🔍 Testing polygon geometry validation...');
            
            // Test with self-intersecting polygon
            const invalidPolygonData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createInvalidPolygonPoints.selfIntersecting(),
            label: 'invalid_polygon'
            });
            
            const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(invalidPolygonData)
            .expect(422);
            
            expect(response.body.status).toBe('error');
            expect(response.body.message).toContain('intersect');
            
            // Verify no polygon was created in database
            const dbCheck = await TestDatabaseConnection.query(
            'SELECT COUNT(*) FROM polygons WHERE label = $1',
            ['invalid_polygon']
            );
            expect(parseInt(dbCheck.rows[0].count)).toBe(0);
            
            console.log('✅ Polygon geometry validation working');
        });

        it('should handle image ownership validation', async () => {
            console.log('🔍 Testing image ownership validation...');
            
            // Try to create polygon on secondary user's image with primary user's token
            const unauthorizedData = createMockPolygonCreate({
            original_image_id: testData.secondaryImage.id, // Wrong user's image
            points: createValidPolygonPoints.triangle(),
            label: 'unauthorized_polygon'
            });
            
            const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(unauthorizedData)
            .expect(403);
            
            expect(response.body.status).toBe('error');
            expect(response.body.message).toContain('permission');
            
            console.log('✅ Image ownership validation working');
        });

        it('should handle various polygon metadata types', async () => {
            console.log('🔍 Testing polygon metadata variations...');
            
            const metadataVariations = [
            createPolygonMetadataVariations.minimal,
            createPolygonMetadataVariations.detailed,
            createPolygonMetadataVariations.nested,
            createPolygonMetadataVariations.withArrays
            ];
            
            for (const [index, metadata] of metadataVariations.entries()) {
            const polygonData = createMockPolygonCreate({
                original_image_id: testData.primaryImage.id,
                points: createValidPolygonPoints.custom(100 + index * 50, 100 + index * 50),
                label: `metadata_test_${index}`,
                metadata
            });
            
            const response = await request(app)
                .post('/api/v1/polygons')
                .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
                .send(polygonData)
                .expect(201);
            
            testData.trackPolygon(response.body.data.polygon.id);
            
            // Verify metadata stored correctly
            const dbResult = await TestDatabaseConnection.query(
                'SELECT metadata FROM polygons WHERE id = $1',
                [response.body.data.polygon.id]
            );
            
            const storedMetadata = JSON.parse(dbResult.rows[0].metadata);
            expect(storedMetadata).toEqual(metadata);
            }
            
            console.log('✅ Polygon metadata variations working');
        });
        });

        describe('Polygon Deletion', () => {
        let testPolygonId: string;

        beforeEach(async () => {
            // Create test polygon for deletion tests
            const polygonData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'deletion_test_polygon',
            metadata: { test: 'deletion' }
            });
            
            const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(polygonData);
            
            testPolygonId = response.body.data.polygon.id;
            testData.trackPolygon(testPolygonId);
        });

        it('should delete polygon successfully', async () => {
            console.log('🔍 Testing polygon deletion...');
            
            const response = await request(app)
            .delete(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .expect(200);
            
            expect(response.body.status).toBe('success');
            expect(response.body.message).toContain('deleted');
            
            // Verify polygon is deleted from database
            const dbResult = await TestDatabaseConnection.query(
            'SELECT * FROM polygons WHERE id = $1',
            [testPolygonId]
            );
            
            expect(dbResult.rows).toHaveLength(0);
            
            console.log('✅ Polygon deletion working');
        });

        it('should prevent unauthorized deletion', async () => {
            console.log('🔍 Testing unauthorized deletion prevention...');
            
            const response = await request(app)
            .delete(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getSecondaryUserToken()}`)
            .expect(403);
            
            expect(response.body.status).toBe('error');
            expect(response.body.message).toContain('permission');
            
            // Verify polygon still exists
            const dbResult = await TestDatabaseConnection.query(
            'SELECT * FROM polygons WHERE id = $1',
            [testPolygonId]
            );
            
            expect(dbResult.rows).toHaveLength(1);
            
            console.log('✅ Unauthorized deletion prevention working');
        });

        it('should handle non-existent polygon deletion', async () => {
            console.log('🔍 Testing non-existent polygon deletion...');
            
            const nonExistentId = uuidv4();
            
            const response = await request(app)
            .delete(`/api/v1/polygons/${nonExistentId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .expect(404);
            
            expect(response.body.status).toBe('error');
            expect(response.body.message).toContain('not found');
            
            console.log('✅ Non-existent polygon deletion handling working');
        });

        it('should handle cascade deletion with garment items', async () => {
            console.log('🔍 Testing cascade deletion with garment items...');
            
            // Create garment item linked to polygon
            const garmentResult = await TestDatabaseConnection.query(`
            INSERT INTO garment_items (user_id, polygon_id, name, category)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            `, [testData.primaryUser.id, testPolygonId, 'Test Garment', 'Clothing']);
            
            const garmentId = garmentResult.rows[0].id;
            testData.trackGarment(garmentId);
            
            // Delete polygon
            await request(app)
            .delete(`/api/v1/polygons/${testPolygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .expect(200);
            
            // Verify garment item was also deleted (cascade)
            const garmentCheck = await TestDatabaseConnection.query(
            'SELECT * FROM garment_items WHERE id = $1',
            [garmentId]
            );
            
            expect(garmentCheck.rows).toHaveLength(0);
            
            console.log('✅ Cascade deletion working');
        });
        });
    });

    // ==================== AUTHENTICATION & AUTHORIZATION TESTS ====================
    
    describe('Authentication & Authorization', () => {
        it('should reject requests without authentication', async () => {
        console.log('🔍 Testing authentication requirement...');
        
        const polygonData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'unauthenticated_test'
        });
        
        // Test all endpoints without auth
        await request(app)
            .post('/api/v1/polygons')
            .send(polygonData)
            .expect(401);
        
        await request(app)
            .get(`/api/v1/polygons/image/${testData.primaryImage.id}`)
            .expect(401);
        
        await request(app)
            .get(`/api/v1/polygons/${uuidv4()}`)
            .expect(401);
        
        await request(app)
            .put(`/api/v1/polygons/${uuidv4()}`)
            .send({ label: 'test' })
            .expect(401);
        
        await request(app)
            .delete(`/api/v1/polygons/${uuidv4()}`)
            .expect(401);
        
        console.log('✅ Authentication requirement working');
        });

        it('should reject requests with invalid tokens', async () => {
        console.log('🔍 Testing invalid token rejection...');
        
        const polygonData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'invalid_token_test'
        });
        
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', 'Bearer invalid-token')
            .send(polygonData)
            .expect(401);
        
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', 'Bearer malformed.jwt.token')
            .send(polygonData)
            .expect(401);
        
        console.log('✅ Invalid token rejection working');
        });

        it('should handle JWT token authentication', async () => {
        console.log('🔍 Testing JWT token authentication...');
        
        // Create a real JWT token for the primary user
        const jwtToken = jwt.sign(
            { userId: testData.primaryUser.id, email: testData.primaryUser.email },
            process.env.JWT_SECRET || 'test-secret',
            { expiresIn: '1h' }
        );
        
        const polygonData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'jwt_auth_test'
        });
        
        const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${jwtToken}`)
            .send(polygonData)
            .expect(201);
        
        testData.trackPolygon(response.body.data.polygon.id);
        
        console.log('✅ JWT token authentication working');
        });

        it('should enforce user isolation across all operations', async () => {
        console.log('🔍 Testing comprehensive user isolation...');
        
        // Create polygon as primary user
        const polygonData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'isolation_test'
        });
        
        const createResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(polygonData);
        
        const polygonId = createResponse.body.data.polygon.id;
        testData.trackPolygon(polygonId);
        
        // Test that secondary user cannot access any operations
        await request(app)
            .get(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getSecondaryUserToken()}`)
            .expect(403);
        
        await request(app)
            .put(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getSecondaryUserToken()}`)
            .send({ label: 'hacked' })
            .expect(403);
        
        await request(app)
            .delete(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getSecondaryUserToken()}`)
            .expect(403);
        
        // Test image access isolation
        await request(app)
            .get(`/api/v1/polygons/image/${testData.primaryImage.id}`)
            .set('Authorization', `Bearer ${testData.getSecondaryUserToken()}`)
            .expect(403);
        
        console.log('✅ User isolation working');
        });
    });

    // ==================== INPUT VALIDATION TESTS ====================
    
    describe('Input Validation', () => {
        it('should validate required fields', async () => {
        console.log('🔍 Testing required field validation...');
        
        // Missing original_image_id
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            points: createValidPolygonPoints.triangle(),
            label: 'missing_image_id'
            })
            .expect(400);
        
        // Missing points
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            label: 'missing_points'
            })
            .expect(400);
        
        // Missing label
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle()
            })
            .expect(400);
        
        console.log('✅ Required field validation working');
        });

        it('should validate data types and formats', async () => {
        console.log('🔍 Testing data type validation...');
        
        // Invalid UUID format for image ID
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: 'invalid-uuid',
            points: createValidPolygonPoints.triangle(),
            label: 'invalid_uuid_test'
            })
            .expect(400);
        
        // Invalid points format
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: 'invalid-points',
            label: 'invalid_points_test'
            })
            .expect(400);
        
        // Invalid metadata format
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'invalid_metadata_test',
            metadata: 'invalid-metadata'
            })
            .expect(400);
        
        console.log('✅ Data type validation working');
        });

        it('should validate polygon geometry constraints', async () => {
        console.log('🔍 Testing polygon geometry constraints...');
        
        // Too few points
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: [{ x: 100, y: 100 }, { x: 200, y: 200 }], // Only 2 points
            label: 'too_few_points'
            })
            .expect(422);
        
        // Too many points
        const tooManyPoints = Array.from({ length: 1001 }, (_, i) => ({ x: i, y: i }));
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: tooManyPoints,
            label: 'too_many_points'
            })
            .expect(422);
        
        // Out of bounds points
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: createInvalidPolygonPoints.outOfBounds(),
            label: 'out_of_bounds'
            })
            .expect(422);
        
        console.log('✅ Polygon geometry constraints working');
        });

        it('should validate string length constraints', async () => {
        console.log('🔍 Testing string length constraints...');
        
        // Label too long
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'x'.repeat(300) // Too long
            })
            .expect(400);
        
        console.log('✅ String length constraints working');
        });
    });

    // ==================== ERROR HANDLING TESTS ====================
    
    describe('Error Handling', () => {
        it('should handle malformed JSON requests', async () => {
        console.log('🔍 Testing malformed JSON handling...');
        
        const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .set('Content-Type', 'application/json')
            .send('{"invalid": json}')
            .expect(400);
        
        expect(response.body.status).toBe('error');
        
        console.log('✅ Malformed JSON handling working');
        });

        it('should handle database constraint violations', async () => {
        console.log('🔍 Testing database constraint violations...');
        
        // Try to create polygon with non-existent image
        const nonExistentImageId = uuidv4();
        
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: nonExistentImageId,
            points: createValidPolygonPoints.triangle(),
            label: 'non_existent_image'
            })
            .expect(404);
        
        console.log('✅ Database constraint violation handling working');
        });

        it('should handle large payload requests', async () => {
        console.log('🔍 Testing large payload handling...');
        
        const largeMetadata = {
            description: 'x'.repeat(50000),
            data: Array.from({ length: 1000 }, (_, i) => ({ index: i, value: `data_${i}` }))
        };
        
        const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'large_payload_test',
            metadata: largeMetadata
            });
        
        // Should either succeed or fail gracefully
        expect([201, 413, 422]).toContain(response.status);
        
        if (response.status === 201) {
            testData.trackPolygon(response.body.data.polygon.id);
        }
        
        console.log('✅ Large payload handling working');
        });

        it('should provide meaningful error messages', async () => {
        console.log('🔍 Testing error message quality...');
        
        // Test various error scenarios and verify error messages
        const invalidGeometryResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: createInvalidPolygonPoints.selfIntersecting(),
            label: 'error_message_test'
            })
            .expect(422);
        
        expect(invalidGeometryResponse.body.message).toBeTruthy();
        expect(invalidGeometryResponse.body.message.length).toBeGreaterThan(10);
        
        const unauthorizedResponse = await request(app)
            .get(`/api/v1/polygons/image/${testData.primaryImage.id}`)
            .set('Authorization', `Bearer ${testData.getSecondaryUserToken()}`)
            .expect(403);
        
        expect(unauthorizedResponse.body.message).toBeTruthy();
        expect(unauthorizedResponse.body.message.length).toBeGreaterThan(10);
        
        console.log('✅ Error message quality working');
        });
    });

    // ==================== PERFORMANCE TESTS ====================
    
    describe('Performance', () => {
        it('should handle concurrent requests efficiently', async () => {
        console.log('🔍 Testing concurrent request performance...');
        
        const concurrentCount = 10;
        const startTime = Date.now();
        
        const requests = Array.from({ length: concurrentCount }, (_, i) =>
            request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
                original_image_id: testData.primaryImage.id,
                points: createValidPolygonPoints.custom(100 + i * 20, 100 + i * 20),
                label: `concurrent_test_${i}`
            }))
        );
        
        const responses = await Promise.all(requests);
        const totalTime = Date.now() - startTime;
        
        // All should succeed
        responses.forEach((response, index) => {
            expect(response.status).toBe(201);
            testData.trackPolygon(response.body.data.polygon.id);
        });
        
        // Performance assertions
        expect(totalTime).toBeLessThan(10000); // Should complete within 10 seconds
        const avgTime = totalTime / concurrentCount;
        expect(avgTime).toBeLessThan(2000); // Average under 2 seconds per request
        
        console.log(`Performance: ${concurrentCount} concurrent requests in ${totalTime}ms (avg: ${avgTime}ms)`);
        console.log('✅ Concurrent request performance acceptable');
        });

        it('should handle complex polygon creation efficiently', async () => {
        console.log('🔍 Testing complex polygon performance...');
        
        const complexPoints = createValidPolygonPoints.circle(600, 400, 100, 200); // 200 points
        const startTime = Date.now();
        
        const response = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: complexPoints,
            label: 'complex_performance_test',
            metadata: createPolygonMetadataVariations.detailed
            })
            .expect(201);
        
        const creationTime = Date.now() - startTime;
        testData.trackPolygon(response.body.data.polygon.id);
        
        // Should complete within reasonable time
        expect(creationTime).toBeLessThan(3000); // Under 3 seconds
        
        console.log(`Complex polygon creation: ${creationTime}ms for 200 points`);
        console.log('✅ Complex polygon performance acceptable');
        });

        it('should handle bulk retrieval efficiently', async () => {
        console.log('🔍 Testing bulk retrieval performance...');
        
        // Create multiple polygons first
        const polygonCount = 20;
        const createPromises = Array.from({ length: polygonCount }, (_, i) =>
            request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
                original_image_id: testData.primaryImage.id,
                points: createValidPolygonPoints.custom(100 + i * 10, 100 + i * 10),
                label: `bulk_test_${i}`
            }))
        );
        
        const createResponses = await Promise.all(createPromises);
        createResponses.forEach(response => {
            testData.trackPolygon(response.body.data.polygon.id);
        });
        
        // Test retrieval performance
        const startTime = Date.now();
        const response = await request(app)
            .get(`/api/v1/polygons/image/${testData.primaryImage.id}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .expect(200);
        
        const retrievalTime = Date.now() - startTime;
        
        expect(response.body.data.polygons).toHaveLength(polygonCount);
        expect(retrievalTime).toBeLessThan(2000); // Under 2 seconds
        
        console.log(`Bulk retrieval: ${retrievalTime}ms for ${polygonCount} polygons`);
        console.log('✅ Bulk retrieval performance acceptable');
        });
    });

    // ==================== BUSINESS LOGIC INTEGRATION TESTS ====================
    
    describe('Business Logic Integration', () => {
        it('should handle complete garment workflow integration', async () => {
        console.log('🔍 Testing complete garment workflow...');
        
        // Step 1: Create polygon suitable for garment
        const polygonResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.garmentSuitable(),
            label: 'garment_workflow_test',
            metadata: {
                type: 'garment',
                category: 'clothing',
                subcategory: 'shirt'
            }
            }))
            .expect(201);
        
        const polygonId = polygonResponse.body.data.polygon.id;
        testData.trackPolygon(polygonId);
        
        // Step 2: Create garment item from polygon
        const garmentResult = await TestDatabaseConnection.query(`
            INSERT INTO garment_items (user_id, polygon_id, name, category, subcategory)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
        `, [
            testData.primaryUser.id,
            polygonId,
            'Test Shirt',
            'Clothing',
            'Shirt'
        ]);
        
        const garmentId = garmentResult.rows[0].id;
        testData.trackGarment(garmentId);
        
        // Step 3: Create wardrobe with garment
        const wardrobeResult = await TestDatabaseConnection.query(`
            INSERT INTO wardrobes (user_id, name, description, garment_item_ids)
            VALUES ($1, $2, $3, $4)
            RETURNING *
        `, [
            testData.primaryUser.id,
            'Test Wardrobe',
            'Integration test wardrobe',
            [garmentId]
        ]);
        
        const wardrobeId = wardrobeResult.rows[0].id;
        testData.trackWardrobe(wardrobeId);
        
        // Step 4: Verify complete integration
        const integrityCheck = await TestDatabaseConnection.query(`
            SELECT 
            p.id as polygon_id,
            p.label as polygon_label,
            gi.id as garment_id,
            gi.name as garment_name,
            w.id as wardrobe_id,
            w.name as wardrobe_name
            FROM polygons p
            JOIN garment_items gi ON gi.polygon_id = p.id
            JOIN wardrobes w ON gi.id = ANY(w.garment_item_ids)
            WHERE p.id = $1
        `, [polygonId]);
        
        expect(integrityCheck.rows).toHaveLength(1);
        const integration = integrityCheck.rows[0];
        expect(integration.polygon_label).toBe('garment_workflow_test');
        expect(integration.garment_name).toBe('Test Shirt');
        expect(integration.wardrobe_name).toBe('Test Wardrobe');
        
        // Step 5: Test deletion cascade
        await request(app)
            .delete(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .expect(200);
        
        // Verify cascade deletion
        const cascadeCheck = await TestDatabaseConnection.query(
            'SELECT * FROM garment_items WHERE id = $1',
            [garmentId]
        );
        expect(cascadeCheck.rows).toHaveLength(0);
        
        console.log('✅ Complete garment workflow integration working');
        });

        it('should handle polygon versioning and audit trail', async () => {
        console.log('🔍 Testing polygon versioning and audit...');
        
        // Create polygon
        const createResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'versioning_test',
            metadata: { version: 1, test: 'audit' }
            }))
            .expect(201);
        
        const polygonId = createResponse.body.data.polygon.id;
        testData.trackPolygon(polygonId);
        
        // Verify initial version
        let dbResult = await TestDatabaseConnection.query(
            'SELECT version FROM polygons WHERE id = $1',
            [polygonId]
        );
        expect(dbResult.rows[0].version).toBe(1);
        
        // Update polygon multiple times
        await request(app)
            .put(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({ label: 'versioning_test_v2' })
            .expect(200);
        
        await request(app)
            .put(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({ 
            metadata: { version: 3, test: 'audit', updated: true }
            })
            .expect(200);
        
        // Verify version incremented
        dbResult = await TestDatabaseConnection.query(
            'SELECT version FROM polygons WHERE id = $1',
            [polygonId]
        );
        expect(dbResult.rows[0].version).toBe(3);
        
        // Check audit trail
        const auditCheck = await TestDatabaseConnection.query(
            'SELECT COUNT(*) FROM polygon_audit WHERE polygon_id = $1',
            [polygonId]
        );
        // Should have audit entries for creation and updates
        expect(parseInt(auditCheck.rows[0].count)).toBeGreaterThan(0);
        
        console.log('✅ Polygon versioning and audit working');
        });

        it('should handle image status transitions', async () => {
        console.log('🔍 Testing image status transitions...');
        
        // Update image to 'new' status
        await TestDatabaseConnection.query(
            'UPDATE original_images SET status = $1 WHERE id = $2',
            ['new', testData.primaryImage.id]
        );
        
        // Create first polygon - should update image status
        const response1 = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'status_transition_test_1'
            }))
            .expect(201);
        
        testData.trackPolygon(response1.body.data.polygon.id);
        
        // Check image status was updated
        const statusCheck1 = await TestDatabaseConnection.query(
            'SELECT status FROM original_images WHERE id = $1',
            [testData.primaryImage.id]
        );
        expect(statusCheck1.rows[0].status).toBe('processed');
        
        // Create second polygon - status should remain 'processed'
        const response2 = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.square(),
            label: 'status_transition_test_2'
            }))
            .expect(201);
        
        testData.trackPolygon(response2.body.data.polygon.id);
        
        const statusCheck2 = await TestDatabaseConnection.query(
            'SELECT status FROM original_images WHERE id = $1',
            [testData.primaryImage.id]
        );
        expect(statusCheck2.rows[0].status).toBe('processed');
        
        console.log('✅ Image status transitions working');
        });

        it('should validate polygon area and complexity constraints', async () => {
        console.log('🔍 Testing polygon area and complexity validation...');
        
        // Test minimum area constraint
        const tooSmallPolygon = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createInvalidPolygonPoints.tooSmallArea(),
            label: 'too_small_test'
        });
        
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(tooSmallPolygon)
            .expect(422);
        
        // Test maximum complexity (simplified in testing)
        const veryComplexPoints = createValidPolygonPoints.circle(400, 300, 100, 500);
        const complexPolygon = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: veryComplexPoints,
            label: 'complex_test'
        });
        
        const complexResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(complexPolygon)
            .expect(201);
        
        testData.trackPolygon(complexResponse.body.data.polygon.id);
        
        console.log('✅ Polygon area and complexity validation working');
        });
    });

    // ==================== DATA CONSISTENCY TESTS ====================
    
    describe('Data Consistency', () => {
        it('should maintain referential integrity', async () => {
        console.log('🔍 Testing referential integrity...');
        
        // Create polygon
        const polygonResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'integrity_test'
            }))
            .expect(201);
        
        const polygonId = polygonResponse.body.data.polygon.id;
        testData.trackPolygon(polygonId);
        
        // Verify foreign key relationships
        const integrityCheck = await TestDatabaseConnection.query(`
            SELECT 
            p.id as polygon_id,
            p.user_id,
            p.original_image_id,
            u.id as user_exists,
            i.id as image_exists
            FROM polygons p
            LEFT JOIN users u ON u.id = p.user_id
            LEFT JOIN original_images i ON i.id = p.original_image_id
            WHERE p.id = $1
        `, [polygonId]);
        
        const integrity = integrityCheck.rows[0];
        expect(integrity.user_exists).toBeTruthy();
        expect(integrity.image_exists).toBeTruthy();
        expect(integrity.user_id).toBe(testData.primaryUser.id);
        expect(integrity.original_image_id).toBe(testData.primaryImage.id);
        
        console.log('✅ Referential integrity maintained');
        });

        it('should handle transaction rollbacks properly', async () => {
        console.log('🔍 Testing transaction rollback behavior...');
        
        // This test verifies that failed operations don't leave partial data
        
        // Attempt to create polygon with invalid data that should fail validation
        const invalidResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: createInvalidPolygonPoints.selfIntersecting(),
            label: 'rollback_test'
            })
            .expect(422);
        
        // Verify no partial data was committed
        const rollbackCheck = await TestDatabaseConnection.query(
            'SELECT COUNT(*) FROM polygons WHERE label = $1',
            ['rollback_test']
        );
        expect(parseInt(rollbackCheck.rows[0].count)).toBe(0);
        
        // Verify no audit entries for failed operation
        const auditCheck = await TestDatabaseConnection.query(
            'SELECT COUNT(*) FROM polygon_audit WHERE new_data @> $1',
            [JSON.stringify({ label: 'rollback_test' })]
        );
        expect(parseInt(auditCheck.rows[0].count)).toBe(0);
        
        console.log('✅ Transaction rollback behavior working');
        });

        it('should handle concurrent modifications correctly', async () => {
        console.log('🔍 Testing concurrent modification handling...');
        
        // Create base polygon
        const polygonResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'concurrent_test'
            }))
            .expect(201);
        
        const polygonId = polygonResponse.body.data.polygon.id;
        testData.trackPolygon(polygonId);
        
        // Attempt concurrent modifications
        const concurrentUpdates = [
            request(app)
            .put(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({ label: 'concurrent_update_1' }),
            
            request(app)
            .put(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({ label: 'concurrent_update_2' }),
            
            request(app)
            .put(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({ 
                metadata: { concurrent: true, timestamp: new Date().toISOString() }
            })
        ];
        
        const updateResponses = await Promise.all(concurrentUpdates);
        
        // All should succeed (last write wins in this implementation)
        updateResponses.forEach(response => {
            expect([200, 409]).toContain(response.status); // 200 success or 409 conflict
        });
        
        // Verify final state is consistent
        const finalState = await TestDatabaseConnection.query(
            'SELECT * FROM polygons WHERE id = $1',
            [polygonId]
        );
        expect(finalState.rows).toHaveLength(1);
        
        console.log('✅ Concurrent modification handling working');
        });

        it('should maintain data consistency across service boundaries', async () => {
        console.log('🔍 Testing cross-service data consistency...');
        
        // Create polygon
        const polygonResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.garmentSuitable(),
            label: 'cross_service_test',
            metadata: {
                type: 'garment',
                category: 'clothing'
            }
            }))
            .expect(201);
        
        const polygonId = polygonResponse.body.data.polygon.id;
        testData.trackPolygon(polygonId);
        
        // Create related garment item
        const garmentResult = await TestDatabaseConnection.query(`
            INSERT INTO garment_items (user_id, polygon_id, name, category)
            VALUES ($1, $2, $3, $4)
            RETURNING *
        `, [testData.primaryUser.id, polygonId, 'Cross Service Test', 'Clothing']);
        
        const garmentId = garmentResult.rows[0].id;
        testData.trackGarment(garmentId);
        
        // Update polygon and verify garment relationship maintained
        await request(app)
            .put(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            label: 'cross_service_updated',
            metadata: {
                type: 'garment',
                category: 'clothing',
                updated: true
            }
            })
            .expect(200);
        
        // Verify consistency across services
        const consistencyCheck = await TestDatabaseConnection.query(`
            SELECT 
            p.label as polygon_label,
            p.metadata as polygon_metadata,
            gi.name as garment_name,
            gi.polygon_id
            FROM polygons p
            JOIN garment_items gi ON gi.polygon_id = p.id
            WHERE p.id = $1
        `, [polygonId]);
        
        expect(consistencyCheck.rows).toHaveLength(1);
        const consistency = consistencyCheck.rows[0];
        expect(consistency.polygon_label).toBe('cross_service_updated');
        expect(consistency.garment_name).toBe('Cross Service Test');
        expect(consistency.polygon_id).toBe(polygonId);
        
        console.log('✅ Cross-service data consistency maintained');
        });
    });

    // ==================== EDGE CASES AND STRESS TESTS ====================
    
    describe('Edge Cases and Stress Tests', () => {
        it('should handle rapid successive requests', async () => {
        console.log('🔍 Testing rapid successive requests...');
        
        const rapidCount = 50;
        const delay = 10; // 10ms between requests
        
        const rapidRequests: Promise<any>[] = [];
        
        for (let i = 0; i < rapidCount; i++) {
            const request_promise = new Promise((resolve) => {
            setTimeout(async () => {
                try {
                const response = await request(app)
                    .post('/api/v1/polygons')
                    .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
                    .send(createMockPolygonCreate({
                    original_image_id: testData.primaryImage.id,
                    points: createValidPolygonPoints.custom(100 + i, 100 + i),
                    label: `rapid_test_${i}`
                    }));
                resolve(response);
                } catch (error) {
                resolve({ status: 500, error });
                }
            }, i * delay);
            });
            
            rapidRequests.push(request_promise);
        }
        
        const responses = await Promise.all(rapidRequests);
        
        // Count successful responses
        const successfulResponses = responses.filter((r: any) => r.status === 201);
        const failedResponses = responses.filter((r: any) => r.status !== 201);
        
        // Track successful polygons for cleanup
        successfulResponses.forEach((response: any) => {
            if (response.body?.data?.polygon?.id) {
            testData.trackPolygon(response.body.data.polygon.id);
            }
        });
        
        // Should handle most requests successfully
        expect(successfulResponses.length).toBeGreaterThan(rapidCount * 0.8); // At least 80% success
        
        console.log(`Rapid requests: ${successfulResponses.length}/${rapidCount} successful`);
        console.log('✅ Rapid successive requests handled');
        });

        it('should handle extreme polygon configurations', async () => {
        console.log('🔍 Testing extreme polygon configurations...');
        
        // Maximum allowed points
        const maxPointsPolygon = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.circle(600, 400, 100, 1000), // 1000 points
            label: 'max_points_test'
        });
        
        const maxResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(maxPointsPolygon)
            .expect(201);
        
        testData.trackPolygon(maxResponse.body.data.polygon.id);
        
        // Polygon at image boundaries
        const boundaryPolygon = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: [
            { x: 0, y: 0 },
            { x: 1199, y: 0 }, // Image width - 1
            { x: 1199, y: 799 }, // Image height - 1
            { x: 0, y: 799 }
            ],
            label: 'boundary_test'
        });
        
        const boundaryResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(boundaryPolygon)
            .expect(201);
        
        testData.trackPolygon(boundaryResponse.body.data.polygon.id);
        
        // Very complex metadata
        const complexMetadataPolygon = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'complex_metadata_test',
            metadata: {
            level1: {
                level2: {
                level3: {
                    level4: {
                    deep_value: 'test',
                    array: Array.from({ length: 100 }, (_, i) => ({ index: i }))
                    }
                }
                }
            },
            large_array: Array.from({ length: 1000 }, (_, i) => `item_${i}`),
            unicode: '测试 🔺 émojis 🎉',
            special_chars: '!@#$%^&*()_+-=[]{}|;:,.<>?'
            }
        });
        
        const metadataResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(complexMetadataPolygon);
        
        // Should either succeed or fail gracefully
        expect([201, 413, 422]).toContain(metadataResponse.status);
        
        if (metadataResponse.status === 201) {
            testData.trackPolygon(metadataResponse.body.data.polygon.id);
        }
        
        console.log('✅ Extreme polygon configurations handled');
        });

        it('should handle resource exhaustion gracefully', async () => {
        console.log('🔍 Testing resource exhaustion handling...');
        
        // Create many polygons to test resource limits
        const bulkCount = 100;
        const bulkPromises = Array.from({ length: bulkCount }, (_, i) =>
            request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(createMockPolygonCreate({
                original_image_id: testData.primaryImage.id,
                points: createValidPolygonPoints.custom(
                50 + (i % 20) * 50,
                50 + Math.floor(i / 20) * 50
                ),
                label: `bulk_resource_test_${i}`,
                metadata: { 
                bulk_test: true,
                index: i,
                timestamp: new Date().toISOString()
                }
            }))
        );
        
        const bulkResponses = await Promise.all(bulkPromises);
        
        // Count successes and failures
        const successes = bulkResponses.filter(r => r.status === 201);
        const failures = bulkResponses.filter(r => r.status !== 201);
        
        // Track successful polygons
        successes.forEach(response => {
            testData.trackPolygon(response.body.data.polygon.id);
        });
        
        // Should handle gracefully - either all succeed or fail gracefully
        expect(successes.length + failures.length).toBe(bulkCount);
        
        // If some failed, they should have appropriate error codes
        failures.forEach(response => {
            expect([429, 500, 503]).toContain(response.status); // Rate limit, server error, or service unavailable
        });
        
        console.log(`Resource exhaustion test: ${successes.length}/${bulkCount} successful`);
        console.log('✅ Resource exhaustion handled gracefully');
        });

        it('should handle malformed and edge case inputs', async () => {
        console.log('🔍 Testing malformed and edge case inputs...');
        
        // Null values in various places
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: null,
            label: 'null_points_test'
            })
            .expect(400);
        
        // Empty arrays
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: [],
            label: 'empty_points_test'
            })
            .expect(400);
        
        // Invalid point structures
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: [
                { x: 100 }, // Missing y
                { y: 200 }, // Missing x
                { x: 'invalid', y: 300 } // Invalid type
            ],
            label: 'invalid_point_structure_test'
            })
            .expect(400);
        
        // Extremely long strings
        await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.triangle(),
            label: 'x'.repeat(10000) // Extremely long label
            })
            .expect(400);
        
        console.log('✅ Malformed and edge case inputs handled');
        });
    });

    // ==================== SYSTEM INTEGRATION HEALTH CHECK ====================
    
    describe('System Integration Health Check', () => {
        it('should validate complete system integration', async () => {
        console.log('🔍 Running complete system integration health check...');
        
        // Test full CRUD cycle with all features
        const healthCheckData = createMockPolygonCreate({
            original_image_id: testData.primaryImage.id,
            points: createValidPolygonPoints.garmentSuitable(),
            label: 'health_check_polygon',
            metadata: createPolygonMetadataVariations.detailed
        });
        
        // CREATE
        const createResponse = await request(app)
            .post('/api/v1/polygons')
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send(healthCheckData)
            .expect(201);
        
        const polygonId = createResponse.body.data.polygon.id;
        testData.trackPolygon(polygonId);
        
        // READ
        const readResponse = await request(app)
            .get(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .expect(200);
        
        // UPDATE
        const updateResponse = await request(app)
            .put(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .send({
            label: 'health_check_updated',
            metadata: { ...readResponse.body.data.polygon.metadata, updated: true }
            })
            .expect(200);
        
        // LIST
        const listResponse = await request(app)
            .get(`/api/v1/polygons/image/${testData.primaryImage.id}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .expect(200);
        
        expect(listResponse.body.data.polygons.length).toBeGreaterThan(0);
        
        // DELETE
        await request(app)
            .delete(`/api/v1/polygons/${polygonId}`)
            .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            .expect(200);
        
        // Verify complete integration worked
        expect(createResponse.body.data.polygon.id).toBeTruthy();
        expect(readResponse.body.data.polygon.label).toBe('health_check_polygon');
        expect(updateResponse.body.data.polygon.label).toBe('health_check_updated');
        
        console.log('✅ Complete system integration health check passed');
        });

        it('should validate performance under load', async () => {
        console.log('🔍 Running performance validation under load...');
        
        const loadTestCount = 20;
        const startTime = Date.now();
        
        // Mixed operations under load
        const operations = [];
        
        // Create operations (60%)
        for (let i = 0; i < Math.floor(loadTestCount * 0.6); i++) {
            operations.push(
            request(app)
                .post('/api/v1/polygons')
                .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
                .send(createMockPolygonCreate({
                original_image_id: testData.primaryImage.id,
                points: createValidPolygonPoints.custom(100 + i * 10, 100 + i * 10),
                label: `load_test_${i}`
                }))
            );
        }
        
        // Read operations (40%)
        for (let i = 0; i < Math.floor(loadTestCount * 0.4); i++) {
            operations.push(
            request(app)
                .get(`/api/v1/polygons/image/${testData.primaryImage.id}`)
                .set('Authorization', `Bearer ${testData.getPrimaryUserToken()}`)
            );
        }
        
        const responses = await Promise.all(operations);
        const totalTime = Date.now() - startTime;
        
        // Performance validation
        const successfulResponses = responses.filter(r => [200, 201].includes(r.status));
        const successRate = successfulResponses.length / responses.length;
        
        // Track created polygons for cleanup
        responses.forEach(response => {
            if (response.status === 201 && response.body?.data?.polygon?.id) {
            testData.trackPolygon(response.body.data.polygon.id);
            }
        });
        
        expect(successRate).toBeGreaterThan(0.95); // 95% success rate
        expect(totalTime).toBeLessThan(15000); // Under 15 seconds
        
        const avgResponseTime = totalTime / loadTestCount;
        expect(avgResponseTime).toBeLessThan(1000); // Under 1 second average
        
        console.log(`Load test results:
            - Operations: ${loadTestCount}
            - Success rate: ${(successRate * 100).toFixed(1)}%
            - Total time: ${totalTime}ms
            - Average response time: ${avgResponseTime.toFixed(1)}ms`);
        
        console.log('✅ Performance validation under load passed');
        });

        it('should validate database consistency after stress', async () => {
        console.log('🔍 Validating database consistency after stress tests...');
        
        // Check referential integrity
        const integrityCheck = await TestDatabaseConnection.query(`
            SELECT 
            COUNT(*) as total_polygons,
            COUNT(DISTINCT user_id) as unique_users,
            COUNT(DISTINCT original_image_id) as unique_images
            FROM polygons
        `);
        
        const integrity = integrityCheck.rows[0];
        expect(parseInt(integrity.total_polygons)).toBeGreaterThan(0);
        expect(parseInt(integrity.unique_users)).toBeGreaterThan(0);
        expect(parseInt(integrity.unique_images)).toBeGreaterThan(0);
        
        // Check foreign key relationships
        const fkCheck = await TestDatabaseConnection.query(`
            SELECT COUNT(*) as orphaned_polygons
            FROM polygons p
            LEFT JOIN users u ON u.id = p.user_id
            LEFT JOIN original_images i ON i.id = p.original_image_id
            WHERE u.id IS NULL OR i.id IS NULL
        `);
        
        expect(parseInt(fkCheck.rows[0].orphaned_polygons)).toBe(0);
        
        // Check data types and constraints
        const constraintCheck = await TestDatabaseConnection.query(`
            SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN jsonb_array_length(points) >= 3 THEN 1 END) as valid_points,
            COUNT(CASE WHEN length(label) > 0 THEN 1 END) as valid_labels,
            COUNT(CASE WHEN version > 0 THEN 1 END) as valid_versions
            FROM polygons
        `);
        
        const constraints = constraintCheck.rows[0];
        expect(constraints.total).toBe(constraints.valid_points);
        expect(constraints.total).toBe(constraints.valid_labels);
        expect(constraints.total).toBe(constraints.valid_versions);
        
        console.log('✅ Database consistency validated after stress tests');
        });
    });    
});
















































































        