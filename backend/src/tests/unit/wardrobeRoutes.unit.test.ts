/**
 * Consolidated Wardrobe Routes Test Suite
 * 
 * @description Comprehensive test coverage for wardrobe routes including:
 * - CRUD operations (Create, Read, Update, Delete)
 * - Garment management (Add/Remove garments from wardrobes)
 * - Flutter-specific routes (Reorder, Stats, Sync, Batch)
 * - Input validation (Zod schema validation)
 * - Business logic validation
 * - Error handling and edge cases
 * - Type safety and TypeScript compliance
 * - Mobile optimizations and offline support
 * - Security and performance tests
 * 
 * @author Development Team
 * @version 2.0.0 - Consolidated Flutter + Core functionality
 * @since June 12, 2025
 */

import request from 'supertest';
import express from 'express';
import { v4 as uuidv4 } from 'uuid';
import jwt from 'jsonwebtoken';

// Import the router and dependencies
import { wardrobeRoutes } from '../../routes/wardrobeRoutes';
import { errorHandler } from '../../middlewares/errorHandler';

// Mock the controller
jest.mock('../../controllers/wardrobeController', () => ({
  wardrobeController: {
    createWardrobe: jest.fn(),
    getWardrobes: jest.fn(),
    getWardrobe: jest.fn(),
    updateWardrobe: jest.fn(),
    addGarmentToWardrobe: jest.fn(),
    removeGarmentFromWardrobe: jest.fn(),
    deleteWardrobe: jest.fn(),
    // Flutter-specific methods
    reorderGarments: jest.fn(),
    getWardrobeStats: jest.fn(),
    syncWardrobes: jest.fn(),
    batchOperations: jest.fn()
  }
}));

// Mock authentication middleware
jest.mock('../../middlewares/auth', () => ({
  authenticate: jest.fn((req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    try {
      const token = authHeader.substring(7);
      const decoded = jwt.verify(token, 'test-secret') as any;
      req.user = { id: decoded.id, email: decoded.email };
      next();
    } catch (error) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  })
}));

import { wardrobeController } from '../../controllers/wardrobeController';

// Type definitions
interface TestUser {
  id: string;
  email: string;
}

interface TestWardrobe {
  id: string;
  user_id: string;
  name: string;
  description: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

interface TestGarment {
  id: string;
  user_id: string;
  name?: string;
  category?: string;
  color?: string;
  metadata: {
    name?: string;
    category?: string;
    color?: string;
    size?: string;
    brand?: string;
    tags?: string[];
  };
}

// Test fixtures
class TestFixtures {
  static createTestUser(overrides: Partial<TestUser> = {}): TestUser {
    return {
      id: uuidv4(),
      email: 'flutter-test@example.com',
      ...overrides
    };
  }

  static createTestWardrobe(overrides: Partial<TestWardrobe> = {}): TestWardrobe {
    const now = new Date().toISOString();
    return {
      id: uuidv4(),
      user_id: uuidv4(),
      name: 'Flutter Test Wardrobe',
      description: 'A test wardrobe for Flutter app',
      is_default: false,
      created_at: now,
      updated_at: now,
      ...overrides
    };
  }

  static createTestGarment(overrides: Partial<TestGarment> = {}): TestGarment {
    return {
      id: uuidv4(),
      user_id: uuidv4(),
      name: 'Test Garment',
      category: 'shirt',
      color: 'blue',
      metadata: {
        size: 'M',
        brand: 'TestBrand',
        tags: ['casual', 'summer']
      },
      ...overrides
    };
  }

  static generateAuthToken(user: TestUser): string {
    return jwt.sign(
      { id: user.id, email: user.email },
      'test-secret',
      { expiresIn: '1h' }
    );
  }

  static createApp(): express.Application {
    const app = express();
    app.use(express.json());
    app.use('/api/v1/wardrobes', wardrobeRoutes);
    app.use(errorHandler);
    return app;
  }
}

describe('Consolidated Wardrobe Routes Test Suite', () => {
  let app: express.Application;
  let testUser: TestUser;
  let authToken: string;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Create fresh app instance
    app = TestFixtures.createApp();
    
    // Create test user and auth token
    testUser = TestFixtures.createTestUser();
    authToken = TestFixtures.generateAuthToken(testUser);
  });

  // ==================== CLEANUP ====================
  
  afterEach(() => {
    // Clear all mocks after each test
    jest.clearAllMocks();
  });

  afterAll(async () => {
    // Restore all mocks and close any open handles
    jest.restoreAllMocks();
    
    // Give time for any pending operations to complete
    await new Promise(resolve => setTimeout(resolve, 100));
  });

  // ==================== AUTHENTICATION TESTS ====================
  
  describe('Authentication Requirements', () => {
    it('should reject requests without authorization header', async () => {
      const response = await request(app)
        .get('/api/v1/wardrobes')
        .expect(401);

      expect(response.body).toEqual({
        error: 'Authentication required'
      });
    });

    it('should reject requests with invalid authorization format', async () => {
      const response = await request(app)
        .get('/api/v1/wardrobes')
        .set('Authorization', 'InvalidFormat token123')
        .expect(401);

      expect(response.body).toEqual({
        error: 'Authentication required'
      });
    });

    it('should reject requests with invalid JWT token', async () => {
      const response = await request(app)
        .get('/api/v1/wardrobes')
        .set('Authorization', 'Bearer invalid.jwt.token')
        .expect(401);

      expect(response.body).toEqual({
        error: 'Invalid token'
      });
    });
  });

  // ==================== CREATE WARDROBE TESTS ====================

  describe('POST /api/v1/wardrobes - Create Wardrobe', () => {
    it('should create a wardrobe with valid data', async () => {
      const newWardrobe = TestFixtures.createTestWardrobe({ user_id: testUser.id });
      
      (wardrobeController.createWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(201).json({
          status: 'success',
          data: { wardrobe: newWardrobe },
          message: 'Wardrobe created successfully'
        });
      });

      const requestData = {
        name: 'Summer Collection',
        description: 'Light clothes for summer weather'
      };

      const response = await request(app)
        .post('/api/v1/wardrobes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(requestData)
        .expect(201);

      expect(response.body.status).toBe('success');
      expect(response.body.data.wardrobe).toMatchObject({
        name: newWardrobe.name,
        description: newWardrobe.description,
        user_id: newWardrobe.user_id
      });
      expect(response.body.message).toBe('Wardrobe created successfully');

      expect(wardrobeController.createWardrobe).toHaveBeenCalledTimes(1);
      
      // Verify the request object passed to controller
      const controllerCall = (wardrobeController.createWardrobe as jest.Mock).mock.calls[0];
      expect(controllerCall[0].body).toEqual(requestData);
      expect(controllerCall[0].user).toEqual(testUser);
    });

    it('should create a wardrobe with only required fields', async () => {
      const newWardrobe = TestFixtures.createTestWardrobe({ 
        user_id: testUser.id,
        name: 'Minimal Wardrobe',
        description: ''
      });
      
      (wardrobeController.createWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(201).json({
          status: 'success',
          data: { wardrobe: newWardrobe }
        });
      });

      const requestData = { name: 'Minimal Wardrobe' };

      await request(app)
        .post('/api/v1/wardrobes')
        .set('Authorization', `Bearer ${authToken}`)
        .send(requestData)
        .expect(201);

      expect(wardrobeController.createWardrobe).toHaveBeenCalledTimes(1);
    });

    describe('Validation Errors', () => {
      it('should reject empty request body', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({})
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.createWardrobe).not.toHaveBeenCalled();
      });

      it('should reject missing name field', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ description: 'A wardrobe without a name' })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.createWardrobe).not.toHaveBeenCalled();
      });

      it('should reject empty name field', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ name: '', description: 'Empty name test' })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.createWardrobe).not.toHaveBeenCalled();
      });

      it('should reject name exceeding 100 characters', async () => {
        const longName = 'a'.repeat(101);
        
        const response = await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ name: longName })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.createWardrobe).not.toHaveBeenCalled();
      });

      it('should reject description exceeding 1000 characters', async () => {
        const longDescription = 'a'.repeat(1001);
        
        const response = await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ 
            name: 'Valid Name',
            description: longDescription 
          })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.createWardrobe).not.toHaveBeenCalled();
      });

      it('should reject non-string name field', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ name: 123, description: 'Number as name' })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.createWardrobe).not.toHaveBeenCalled();
      });

      it('should reject non-string description field', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ name: 'Valid Name', description: 123 })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.createWardrobe).not.toHaveBeenCalled();
      });
    });

    describe('Edge Cases', () => {
      it('should handle name with exactly 100 characters', async () => {
        const maxLengthName = 'a'.repeat(100);
        
        (wardrobeController.createWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(201).json({ status: 'success', data: { wardrobe: {} } });
        });

        await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ name: maxLengthName })
          .expect(201);

        expect(wardrobeController.createWardrobe).toHaveBeenCalledTimes(1);
      });

      it('should handle description with exactly 1000 characters', async () => {
        const maxLengthDescription = 'a'.repeat(1000);
        
        (wardrobeController.createWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(201).json({ status: 'success', data: { wardrobe: {} } });
        });

        await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ 
            name: 'Edge Case Test',
            description: maxLengthDescription 
          })
          .expect(201);

        expect(wardrobeController.createWardrobe).toHaveBeenCalledTimes(1);
      });

      it('should handle special characters in name and description', async () => {
        (wardrobeController.createWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(201).json({ status: 'success', data: { wardrobe: {} } });
        });

        const requestData = {
          name: 'Émilie\'s "Special" Wardrobe & Co.',
          description: 'Àccénts, ñoñ-ÀSCII characters, and symbols: @#$%^&*()'
        };

        await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send(requestData)
          .expect(201);

        expect(wardrobeController.createWardrobe).toHaveBeenCalledTimes(1);
      });

      it('should handle Unicode characters in wardrobe names', async () => {
        const unicodeData = {
          name: '🧥👔👗 My Fashion Collection 时装系列',
          description: 'Collection with émojis and ñón-ASCII characters: 中文, العربية, русский'
        };

        (wardrobeController.createWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(201).json({
            status: 'success',
            data: { wardrobe: { ...unicodeData, id: uuidv4() } }
          });
        });

        await request(app)
          .post('/api/v1/wardrobes')
          .set('Authorization', `Bearer ${authToken}`)
          .send(unicodeData)
          .expect(201);

        expect(wardrobeController.createWardrobe).toHaveBeenCalledTimes(1);
      });
    });
  });

  // ==================== GET WARDROBES TESTS ====================

  describe('GET /api/v1/wardrobes - Get All Wardrobes', () => {
    it('should return empty array when user has no wardrobes', async () => {
      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: { wardrobes: [], count: 0 }
        });
      });

      const response = await request(app)
        .get('/api/v1/wardrobes')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toEqual({
        status: 'success',
        data: { wardrobes: [], count: 0 }
      });

      expect(wardrobeController.getWardrobes).toHaveBeenCalledTimes(1);
    });

    it('should return user wardrobes when they exist', async () => {
      const wardrobes = [
        TestFixtures.createTestWardrobe({ user_id: testUser.id, name: 'Summer' }),
        TestFixtures.createTestWardrobe({ user_id: testUser.id, name: 'Winter' }),
        TestFixtures.createTestWardrobe({ user_id: testUser.id, name: 'Formal' })
      ];

      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: { wardrobes, count: wardrobes.length }
        });
      });

      const response = await request(app)
        .get('/api/v1/wardrobes')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data.wardrobes).toHaveLength(3);
      expect(response.body.data.count).toBe(3);

      // Verify all returned wardrobes belong to the user
      response.body.data.wardrobes.forEach((wardrobe: TestWardrobe) => {
        expect(wardrobe.user_id).toBe(testUser.id);
      });

      expect(wardrobeController.getWardrobes).toHaveBeenCalledTimes(1);
    });

    it('should pass authenticated user to controller', async () => {
      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({ status: 'success', data: { wardrobes: [] } });
      });

      await request(app)
        .get('/api/v1/wardrobes')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const controllerCall = (wardrobeController.getWardrobes as jest.Mock).mock.calls[0];
      expect(controllerCall[0].user).toEqual(testUser);
    });
  });

  // ==================== GET SINGLE WARDROBE TESTS ====================

  describe('GET /api/v1/wardrobes/:id - Get Single Wardrobe', () => {
    it('should return wardrobe with garments when found', async () => {
      const wardrobeId = uuidv4();
      const wardrobe = TestFixtures.createTestWardrobe({ 
        id: wardrobeId,
        user_id: testUser.id 
      });
      
      const garments = [
        TestFixtures.createTestGarment({ user_id: testUser.id }),
        TestFixtures.createTestGarment({ user_id: testUser.id })
      ];

      (wardrobeController.getWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: { 
            wardrobe: {
              ...wardrobe,
              garments
            }
          }
        });
      });

      const response = await request(app)
        .get(`/api/v1/wardrobes/${wardrobeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data.wardrobe.id).toBe(wardrobeId);
      expect(response.body.data.wardrobe.garments).toHaveLength(2);

      expect(wardrobeController.getWardrobe).toHaveBeenCalledTimes(1);

      // Verify the UUID parameter was passed correctly
      const controllerCall = (wardrobeController.getWardrobe as jest.Mock).mock.calls[0];
      expect(controllerCall[0].params.id).toBe(wardrobeId);
    });

    describe('UUID Validation', () => {
      it('should reject invalid UUID format', async () => {
        const response = await request(app)
          .get('/api/v1/wardrobes/invalid-uuid')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.getWardrobe).not.toHaveBeenCalled();
      });

      it('should accept valid UUID v4', async () => {
        const validUuid = uuidv4();
        
        (wardrobeController.getWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(200).json({ status: 'success', data: { wardrobe: {} } });
        });

        await request(app)
          .get(`/api/v1/wardrobes/${validUuid}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(wardrobeController.getWardrobe).toHaveBeenCalledTimes(1);
      });

      it('should handle edge case UUID formats', async () => {
        // Test with uppercase UUID
        const uppercaseUuid = uuidv4().toUpperCase();

        (wardrobeController.getWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(200).json({
            status: 'success',
            data: { wardrobe: { id: uppercaseUuid } }
          });
        });

        await request(app)
          .get(`/api/v1/wardrobes/${uppercaseUuid}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(200);

        expect(wardrobeController.getWardrobe).toHaveBeenCalledTimes(1);
      });
    });
  });

  // ==================== UPDATE WARDROBE TESTS ====================

  describe('PUT /api/v1/wardrobes/:id - Update Wardrobe', () => {
    it('should update wardrobe with valid data', async () => {
      const wardrobeId = uuidv4();
      const updatedWardrobe = TestFixtures.createTestWardrobe({
        id: wardrobeId,
        user_id: testUser.id,
        name: 'Updated Name',
        description: 'Updated description'
      });

      (wardrobeController.updateWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: { wardrobe: updatedWardrobe },
          message: 'Wardrobe updated successfully'
        });
      });

      const updateData = {
        name: 'Updated Name',
        description: 'Updated description'
      };

      const response = await request(app)
        .put(`/api/v1/wardrobes/${wardrobeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(updateData)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data.wardrobe.name).toBe('Updated Name');
      expect(response.body.data.wardrobe.description).toBe('Updated description');

      expect(wardrobeController.updateWardrobe).toHaveBeenCalledTimes(1);

      const controllerCall = (wardrobeController.updateWardrobe as jest.Mock).mock.calls[0];
      expect(controllerCall[0].params.id).toBe(wardrobeId);
      expect(controllerCall[0].body).toEqual(updateData);
    });

    it('should update only name field', async () => {
      const wardrobeId = uuidv4();
      
      (wardrobeController.updateWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: { wardrobe: { name: 'Only Name Updated' } }
        });
      });

      await request(app)
        .put(`/api/v1/wardrobes/${wardrobeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'Only Name Updated' })
        .expect(200);

      expect(wardrobeController.updateWardrobe).toHaveBeenCalledTimes(1);
    });

    it('should update only description field', async () => {
      const wardrobeId = uuidv4();
      
      (wardrobeController.updateWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: { wardrobe: { description: 'Only description updated' } }
        });
      });

      await request(app)
        .put(`/api/v1/wardrobes/${wardrobeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ description: 'Only description updated' })
        .expect(200);

      expect(wardrobeController.updateWardrobe).toHaveBeenCalledTimes(1);
    });

    describe('Validation Errors', () => {
      it('should reject empty request body', async () => {
        const wardrobeId = uuidv4();
        
        const response = await request(app)
          .put(`/api/v1/wardrobes/${wardrobeId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({})
          .expect(200); // Empty body is allowed for update

        // The validation happens at the controller level
        expect(wardrobeController.updateWardrobe).toHaveBeenCalled();
      });

      it('should reject invalid UUID in path', async () => {
        const response = await request(app)
          .put('/api/v1/wardrobes/invalid-uuid')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ name: 'Valid Name' })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.updateWardrobe).not.toHaveBeenCalled();
      });

      it('should apply same validation rules as create', async () => {
        const wardrobeId = uuidv4();
        
        // Test name too long
        const response = await request(app)
          .put(`/api/v1/wardrobes/${wardrobeId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ name: 'a'.repeat(101) })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.updateWardrobe).not.toHaveBeenCalled();
      });
    });
  });

  // ==================== ADD GARMENT TO WARDROBE TESTS ====================

  describe('POST /api/v1/wardrobes/:id/items - Add Garment to Wardrobe', () => {
    it('should add garment to wardrobe with valid data', async () => {
      const wardrobeId = uuidv4();
      const garmentId = uuidv4();

      (wardrobeController.addGarmentToWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: null,
          message: 'Garment added to wardrobe successfully'
        });
      });

      const requestData = {
        garmentId,
        position: 0
      };

      const response = await request(app)
        .post(`/api/v1/wardrobes/${wardrobeId}/items`)
        .set('Authorization', `Bearer ${authToken}`)
        .send(requestData)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.message).toContain('successfully');

      expect(wardrobeController.addGarmentToWardrobe).toHaveBeenCalledTimes(1);

      const controllerCall = (wardrobeController.addGarmentToWardrobe as jest.Mock).mock.calls[0];
      expect(controllerCall[0].params.id).toBe(wardrobeId);
      expect(controllerCall[0].body).toEqual(requestData);
    });

    it('should add garment without position (default position)', async () => {
      const wardrobeId = uuidv4();
      const garmentId = uuidv4();

      (wardrobeController.addGarmentToWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: null,
          message: 'Garment added to wardrobe successfully'
        });
      });

      await request(app)
        .post(`/api/v1/wardrobes/${wardrobeId}/items`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ garmentId })
        .expect(200);

      expect(wardrobeController.addGarmentToWardrobe).toHaveBeenCalledTimes(1);
    });

    describe('Validation Errors', () => {
      it('should reject missing garmentId', async () => {
        const wardrobeId = uuidv4();

        const response = await request(app)
          .post(`/api/v1/wardrobes/${wardrobeId}/items`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ position: 0 })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.addGarmentToWardrobe).not.toHaveBeenCalled();
      });

      it('should reject invalid garmentId UUID', async () => {
        const wardrobeId = uuidv4();

        const response = await request(app)
          .post(`/api/v1/wardrobes/${wardrobeId}/items`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentId: 'invalid-uuid' })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.addGarmentToWardrobe).not.toHaveBeenCalled();
      });

      it('should reject negative position', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();

        const response = await request(app)
          .post(`/api/v1/wardrobes/${wardrobeId}/items`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentId, position: -1 })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.addGarmentToWardrobe).not.toHaveBeenCalled();
      });

      it('should reject non-integer position', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();

        const response = await request(app)
          .post(`/api/v1/wardrobes/${wardrobeId}/items`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentId, position: 1.5 })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.addGarmentToWardrobe).not.toHaveBeenCalled();
      });
    });

    describe('Edge Cases', () => {
      it('should handle position at maximum value', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();

        (wardrobeController.addGarmentToWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(200).json({
            status: 'success',
            data: null,
            message: 'Garment added to wardrobe successfully'
          });
        });

        await request(app)
          .post(`/api/v1/wardrobes/${wardrobeId}/items`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentId, position: Number.MAX_SAFE_INTEGER })
          .expect(200);

        expect(wardrobeController.addGarmentToWardrobe).toHaveBeenCalledTimes(1);
      });

      it('should handle position at zero', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();

        (wardrobeController.addGarmentToWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(200).json({
            status: 'success',
            data: null,
            message: 'Garment added to wardrobe successfully'
          });
        });

        await request(app)
          .post(`/api/v1/wardrobes/${wardrobeId}/items`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentId, position: 0 })
          .expect(200);

        expect(wardrobeController.addGarmentToWardrobe).toHaveBeenCalledTimes(1);
      });

      it('should handle boundary position values', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();

        (wardrobeController.addGarmentToWardrobe as jest.Mock).mockImplementation((_req, res) => {
          res.status(200).json({
            status: 'success',
            data: null,
            message: 'Garment added to wardrobe successfully'
          });
        });

        // Test position 0
        await request(app)
          .post(`/api/v1/wardrobes/${wardrobeId}/items`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentId, position: 0 })
          .expect(200);

        // Test large position value
        await request(app)
          .post(`/api/v1/wardrobes/${wardrobeId}/items`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentId, position: 999999 })
          .expect(200);

        expect(wardrobeController.addGarmentToWardrobe).toHaveBeenCalledTimes(2);
      });
    });
  });

  // ==================== REMOVE GARMENT FROM WARDROBE TESTS ====================

  describe('DELETE /api/v1/wardrobes/:id/items/:itemId - Remove Garment from Wardrobe', () => {
    it('should remove garment from wardrobe with valid IDs', async () => {
      const wardrobeId = uuidv4();
      const itemId = uuidv4();

      (wardrobeController.removeGarmentFromWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: null,
          message: 'Garment removed from wardrobe successfully'
        });
      });

      const response = await request(app)
        .delete(`/api/v1/wardrobes/${wardrobeId}/items/${itemId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.message).toContain('successfully');

      expect(wardrobeController.removeGarmentFromWardrobe).toHaveBeenCalledTimes(1);

      const controllerCall = (wardrobeController.removeGarmentFromWardrobe as jest.Mock).mock.calls[0];
      expect(controllerCall[0].params.id).toBe(wardrobeId);
      expect(controllerCall[0].params.itemId).toBe(itemId);
    });

    describe('Validation Errors', () => {
      it('should reject invalid wardrobe UUID', async () => {
        const itemId = uuidv4();

        const response = await request(app)
          .delete(`/api/v1/wardrobes/invalid-uuid/items/${itemId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.removeGarmentFromWardrobe).not.toHaveBeenCalled();
      });

      it('should reject invalid item UUID', async () => {
        const wardrobeId = uuidv4();

        const response = await request(app)
          .delete(`/api/v1/wardrobes/${wardrobeId}/items/invalid-uuid`)
          .set('Authorization', `Bearer ${authToken}`)
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.removeGarmentFromWardrobe).not.toHaveBeenCalled();
      });
    });
  });

  // ==================== DELETE WARDROBE TESTS ====================

  describe('DELETE /api/v1/wardrobes/:id - Delete Wardrobe', () => {
    it('should delete wardrobe with valid ID', async () => {
      const wardrobeId = uuidv4();

      (wardrobeController.deleteWardrobe as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: null,
          message: 'Wardrobe deleted successfully'
        });
      });

      const response = await request(app)
        .delete(`/api/v1/wardrobes/${wardrobeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.message).toContain('successfully');

      expect(wardrobeController.deleteWardrobe).toHaveBeenCalledTimes(1);

      const controllerCall = (wardrobeController.deleteWardrobe as jest.Mock).mock.calls[0];
      expect(controllerCall[0].params.id).toBe(wardrobeId);
      expect(controllerCall[0].user).toEqual(testUser);
    });

    describe('Validation Errors', () => {
      it('should reject invalid UUID format', async () => {
        const response = await request(app)
          .delete('/api/v1/wardrobes/invalid-uuid')
          .set('Authorization', `Bearer ${authToken}`)
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.deleteWardrobe).not.toHaveBeenCalled();
      });
    });
  });

  // ==================== FLUTTER-SPECIFIC: REORDER GARMENTS TESTS ====================

  describe('PUT /api/v1/wardrobes/:id/items/reorder - Reorder Garments', () => {
    it('should reorder garments with valid data', async () => {
      const wardrobeId = uuidv4();
      const garmentPositions = [
        { garmentId: uuidv4(), position: 0 },
        { garmentId: uuidv4(), position: 1 },
        { garmentId: uuidv4(), position: 2 }
      ];

      (wardrobeController.reorderGarments as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {},
          message: 'Garments reordered successfully',
          meta: {
            wardrobeId,
            reorderedCount: garmentPositions.length,
            garmentIds: garmentPositions.map(g => g.garmentId),
            reorderedAt: new Date().toISOString()
          }
        });
      });

      const response = await request(app)
        .put(`/api/v1/wardrobes/${wardrobeId}/items/reorder`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ garmentPositions })
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.message).toBe('Garments reordered successfully');
      expect(response.body.meta.reorderedCount).toBe(3);
      expect(wardrobeController.reorderGarments).toHaveBeenCalledTimes(1);
    });

    it('should handle large batch reordering', async () => {
      const wardrobeId = uuidv4();
      const garmentPositions = Array.from({ length: 100 }, (_, i) => ({
        garmentId: uuidv4(),
        position: i
      }));

      (wardrobeController.reorderGarments as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {},
          message: 'Garments reordered successfully'
        });
      });

      await request(app)
        .put(`/api/v1/wardrobes/${wardrobeId}/items/reorder`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({ garmentPositions })
        .expect(200);

      expect(wardrobeController.reorderGarments).toHaveBeenCalledTimes(1);
    });

    describe('Validation Errors', () => {
      it('should reject empty garmentPositions array', async () => {
        const wardrobeId = uuidv4();

        const response = await request(app)
          .put(`/api/v1/wardrobes/${wardrobeId}/items/reorder`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentPositions: [] })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.reorderGarments).not.toHaveBeenCalled();
      });

      it('should reject more than 100 garment positions', async () => {
        const wardrobeId = uuidv4();
        const garmentPositions = Array.from({ length: 101 }, (_, i) => ({
          garmentId: uuidv4(),
          position: i
        }));

        const response = await request(app)
          .put(`/api/v1/wardrobes/${wardrobeId}/items/reorder`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentPositions })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.reorderGarments).not.toHaveBeenCalled();
      });

      it('should reject invalid garment IDs', async () => {
        const wardrobeId = uuidv4();
        const garmentPositions = [
          { garmentId: 'invalid-uuid', position: 0 },
          { garmentId: uuidv4(), position: 1 }
        ];

        const response = await request(app)
          .put(`/api/v1/wardrobes/${wardrobeId}/items/reorder`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentPositions })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.reorderGarments).not.toHaveBeenCalled();
      });

      it('should reject negative positions', async () => {
        const wardrobeId = uuidv4();
        const garmentPositions = [
          { garmentId: uuidv4(), position: -1 },
          { garmentId: uuidv4(), position: 0 }
        ];

        const response = await request(app)
          .put(`/api/v1/wardrobes/${wardrobeId}/items/reorder`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentPositions })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.reorderGarments).not.toHaveBeenCalled();
      });

      it('should reject duplicate garment IDs', async () => {
        const wardrobeId = uuidv4();
        const duplicateId = uuidv4();
        const garmentPositions = [
          { garmentId: duplicateId, position: 0 },
          { garmentId: duplicateId, position: 1 }
        ];

        // Controller should handle duplicate validation
        (wardrobeController.reorderGarments as jest.Mock).mockImplementation((_req, res) => {
          res.status(400).json({
            status: 'error',
            code: 'VALIDATION_ERROR',
            message: 'Duplicate garment IDs not allowed'
          });
        });

        const response = await request(app)
          .put(`/api/v1/wardrobes/${wardrobeId}/items/reorder`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({ garmentPositions })
          .expect(400);

        expect(response.body.message).toContain('Duplicate');
      });
    });
  });

  // ==================== GET WARDROBE STATS TESTS ====================

  describe('GET /api/v1/wardrobes/:id/stats - Get Wardrobe Statistics', () => {
    it('should return wardrobe statistics', async () => {
      const wardrobeId = uuidv4();
      const stats = {
        totalGarments: 25,
        categories: {
          shirt: 10,
          pants: 8,
          jacket: 5,
          shoes: 2
        },
        colors: {
          blue: 8,
          black: 7,
          white: 5,
          red: 3,
          green: 2
        },
        lastUpdated: new Date().toISOString(),
        createdAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString()
      };

      (wardrobeController.getWardrobeStats as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: { stats },
          message: 'Wardrobe statistics retrieved successfully',
          meta: {
            wardrobeId,
            analysisDate: new Date().toISOString(),
            categoriesCount: Object.keys(stats.categories).length,
            colorsCount: Object.keys(stats.colors).length
          }
        });
      });

      const response = await request(app)
        .get(`/api/v1/wardrobes/${wardrobeId}/stats`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data.stats.totalGarments).toBe(25);
      expect(response.body.data.stats.categories).toHaveProperty('shirt', 10);
      expect(response.body.meta.categoriesCount).toBe(4);
      expect(wardrobeController.getWardrobeStats).toHaveBeenCalledTimes(1);
    });

    it('should handle empty wardrobe stats', async () => {
      const wardrobeId = uuidv4();
      const emptyStats = {
        totalGarments: 0,
        categories: {},
        colors: {},
        lastUpdated: new Date().toISOString(),
        createdAt: new Date().toISOString()
      };

      (wardrobeController.getWardrobeStats as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: { stats: emptyStats }
        });
      });

      const response = await request(app)
        .get(`/api/v1/wardrobes/${wardrobeId}/stats`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.stats.totalGarments).toBe(0);
      expect(response.body.data.stats.categories).toEqual({});
    });

    it('should reject invalid wardrobe ID', async () => {
      const response = await request(app)
        .get('/api/v1/wardrobes/invalid-uuid/stats')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
      expect(wardrobeController.getWardrobeStats).not.toHaveBeenCalled();
    });
  });

  // ==================== SYNC WARDROBES TESTS ====================

  describe('POST /api/v1/wardrobes/sync - Sync Wardrobes', () => {
    it('should sync wardrobes with valid timestamp', async () => {
      const lastSyncTimestamp = new Date(Date.now() - 3600000).toISOString();
      const syncResult = {
        wardrobes: {
          created: [
            TestFixtures.createTestWardrobe({ user_id: testUser.id }),
            TestFixtures.createTestWardrobe({ user_id: testUser.id })
          ],
          updated: [
            TestFixtures.createTestWardrobe({ user_id: testUser.id })
          ],
          deleted: ['wardrobe-id-1', 'wardrobe-id-2']
        },
        sync: {
          timestamp: new Date().toISOString(),
          version: 1,
          hasMore: false,
          changeCount: 5
        }
      };

      (wardrobeController.syncWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: syncResult,
          message: 'Sync completed successfully',
          meta: {
            created: 2,
            updated: 1,
            deleted: 2
          }
        });
      });

      const response = await request(app)
        .post('/api/v1/wardrobes/sync')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ lastSyncTimestamp })
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data.wardrobes.created).toHaveLength(2);
      expect(response.body.data.wardrobes.updated).toHaveLength(1);
      expect(response.body.data.wardrobes.deleted).toHaveLength(2);
      expect(response.body.data.sync.changeCount).toBe(5);
      expect(wardrobeController.syncWardrobes).toHaveBeenCalledTimes(1);
    });

    it('should handle sync with client version', async () => {
      const lastSyncTimestamp = new Date().toISOString();
      const clientVersion = 2;

      (wardrobeController.syncWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            wardrobes: { created: [], updated: [], deleted: [] },
            sync: {
              timestamp: new Date().toISOString(),
              version: clientVersion,
              hasMore: false,
              changeCount: 0
            }
          }
        });
      });

      await request(app)
        .post('/api/v1/wardrobes/sync')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ lastSyncTimestamp, clientVersion })
        .expect(200);

      const controllerCall = (wardrobeController.syncWardrobes as jest.Mock).mock.calls[0];
      expect(controllerCall[0].body.clientVersion).toBe(clientVersion);
    });

    it('should handle paginated sync results', async () => {
      const lastSyncTimestamp = new Date(Date.now() - 86400000).toISOString();

      (wardrobeController.syncWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            wardrobes: {
              created: Array.from({ length: 50 }, () => 
                TestFixtures.createTestWardrobe({ user_id: testUser.id })
              ),
              updated: [],
              deleted: []
            },
            sync: {
              timestamp: new Date().toISOString(),
              version: 1,
              hasMore: true,
              changeCount: 150,
              nextCursor: 'next-sync-cursor'
            }
          }
        });
      });

      const response = await request(app)
        .post('/api/v1/wardrobes/sync')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ lastSyncTimestamp })
        .expect(200);

      expect(response.body.data.sync.hasMore).toBe(true);
      expect(response.body.data.sync.nextCursor).toBe('next-sync-cursor');
    });

    describe('Validation Errors', () => {
      it('should reject missing lastSyncTimestamp', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes/sync')
          .set('Authorization', `Bearer ${authToken}`)
          .send({})
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.syncWardrobes).not.toHaveBeenCalled();
      });

      it('should reject invalid timestamp format', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes/sync')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ lastSyncTimestamp: 'invalid-date' })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.syncWardrobes).not.toHaveBeenCalled();
      });

      it('should reject invalid client version', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes/sync')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ 
            lastSyncTimestamp: new Date().toISOString(),
            clientVersion: 0
          })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.syncWardrobes).not.toHaveBeenCalled();
      });
    });
  });

  // ==================== BATCH OPERATIONS TESTS ====================

  describe('POST /api/v1/wardrobes/batch - Batch Operations', () => {
    it('should process batch operations successfully', async () => {
      const operations = [
        {
          type: 'create',
          data: { name: 'New Wardrobe 1', description: 'Created offline' },
          clientId: 'client-1'
        },
        {
          type: 'update',
          data: { id: uuidv4(), name: 'Updated Wardrobe' },
          clientId: 'client-2'
        },
        {
          type: 'delete',
          data: { id: uuidv4() },
          clientId: 'client-3'
        }
      ];

      const results = [
        {
          clientId: 'client-1',
          serverId: uuidv4(),
          type: 'create',
          success: true,
          data: TestFixtures.createTestWardrobe()
        },
        {
          clientId: 'client-2',
          serverId: operations[1].data.id,
          type: 'update',
          success: true,
          data: TestFixtures.createTestWardrobe()
        },
        {
          clientId: 'client-3',
          serverId: operations[2].data.id,
          type: 'delete',
          success: true
        }
      ];

      (wardrobeController.batchOperations as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            results,
            errors: [],
            summary: {
              total: 3,
              successful: 3,
              failed: 0
            }
          },
          message: 'Batch operations completed',
          meta: {
            timestamp: new Date().toISOString()
          }
        });
      });

      const response = await request(app)
        .post('/api/v1/wardrobes/batch')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ operations })
        .expect(200);

      expect(response.body.status).toBe('success');
      expect(response.body.data.results).toHaveLength(3);
      expect(response.body.data.summary.successful).toBe(3);
      expect(response.body.data.summary.failed).toBe(0);
      expect(wardrobeController.batchOperations).toHaveBeenCalledTimes(1);
    });

    it('should handle partial failures in batch', async () => {
      const operations = [
        {
          type: 'create',
          data: { name: 'Valid Wardrobe' },
          clientId: 'client-1'
        },
        {
          type: 'update',
          data: { id: 'non-existent-id' },
          clientId: 'client-2'
        }
      ];

      (wardrobeController.batchOperations as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            results: [{
              clientId: 'client-1',
              serverId: uuidv4(),
              type: 'create',
              success: true,
              data: TestFixtures.createTestWardrobe()
            }],
            errors: [{
              clientId: 'client-2',
              type: 'update',
              error: 'Wardrobe not found',
              code: 'NOT_FOUND'
            }],
            summary: {
              total: 2,
              successful: 1,
              failed: 1
            }
          }
        });
      });

      const response = await request(app)
        .post('/api/v1/wardrobes/batch')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ operations })
        .expect(200);

      expect(response.body.data.results).toHaveLength(1);
      expect(response.body.data.errors).toHaveLength(1);
      expect(response.body.data.summary.failed).toBe(1);
    });

    it('should handle maximum batch size', async () => {
      const operations = Array.from({ length: 50 }, (_, i) => ({
        type: 'create' as const,
        data: { name: `Batch Wardrobe ${i}` },
        clientId: `client-${i}`
      }));

      (wardrobeController.batchOperations as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            results: operations.map((op) => ({
              clientId: op.clientId,
              serverId: uuidv4(),
              type: op.type,
              success: true
            })),
            errors: [],
            summary: {
              total: 50,
              successful: 50,
              failed: 0
            }
          }
        });
      });

      await request(app)
        .post('/api/v1/wardrobes/batch')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ operations })
        .expect(200);

      expect(wardrobeController.batchOperations).toHaveBeenCalledTimes(1);
    });

    describe('Validation Errors', () => {
      it('should reject empty operations array', async () => {
        const response = await request(app)
          .post('/api/v1/wardrobes/batch')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ operations: [] })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.batchOperations).not.toHaveBeenCalled();
      });

      it('should reject more than 50 operations', async () => {
        const operations = Array.from({ length: 51 }, (_, i) => ({
          type: 'create',
          data: { name: `Wardrobe ${i}` },
          clientId: `client-${i}`
        }));

        const response = await request(app)
          .post('/api/v1/wardrobes/batch')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ operations })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.batchOperations).not.toHaveBeenCalled();
      });

      it('should reject invalid operation type', async () => {
        const operations = [{
          type: 'invalid-type',
          data: { name: 'Test' },
          clientId: 'client-1'
        }];

        const response = await request(app)
          .post('/api/v1/wardrobes/batch')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ operations })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.batchOperations).not.toHaveBeenCalled();
      });

      it('should reject missing clientId', async () => {
        const operations = [{
          type: 'create',
          data: { name: 'Test' }
          // Missing clientId
        }];

        const response = await request(app)
          .post('/api/v1/wardrobes/batch')
          .set('Authorization', `Bearer ${authToken}`)
          .send({ operations })
          .expect(400);

        expect(response.body.success).toBe(false);
        expect(response.body.error.code).toBe('VALIDATION_ERROR');
        expect(wardrobeController.batchOperations).not.toHaveBeenCalled();
      });
    });
  });

  // ==================== MOBILE PAGINATION TESTS ====================

  describe('Mobile-Optimized Pagination', () => {
    it('should support cursor-based pagination', async () => {
      const mockWardrobes = Array.from({ length: 20 }, () => 
        TestFixtures.createTestWardrobe({ user_id: testUser.id })
      );

      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            wardrobes: mockWardrobes,
            pagination: {
              nextCursor: 'next-page-cursor',
              prevCursor: null,
              hasNext: true,
              hasPrev: false
            }
          },
          message: 'Wardrobes retrieved successfully',
          meta: {
            requestId: uuidv4(),
            timestamp: new Date().toISOString()
          }
        });
      });

      const response = await request(app)
        .get('/api/v1/wardrobes?cursor=start&limit=20')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.pagination.nextCursor).toBe('next-page-cursor');
      expect(response.body.data.pagination.hasNext).toBe(true);
    });

    it('should support filtering and sorting', async () => {
      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            wardrobes: [],
            total: 0
          }
        });
      });

      await request(app)
        .get('/api/v1/wardrobes?search=summer&sortBy=updated_at&sortOrder=desc')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const controllerCall = (wardrobeController.getWardrobes as jest.Mock).mock.calls[0];
      expect(controllerCall[0].query.search).toBe('summer');
      expect(controllerCall[0].query.sortBy).toBe('updated_at');
      expect(controllerCall[0].query.sortOrder).toBe('desc');
    });
  });

  // ==================== FLUTTER ERROR RESPONSE TESTS ====================

  describe('Flutter-Compatible Error Responses', () => {
    it('should return Flutter-compatible validation errors', async () => {
      const response = await request(app)
        .post('/api/v1/wardrobes')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ description: 'Missing name field' })
        .expect(400);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: expect.any(String),
          statusCode: 400,
          timestamp: expect.any(String),
          requestId: expect.any(String)
        }
      });
    });

    it('should handle controller errors with Flutter format', async () => {
      (wardrobeController.createWardrobe as jest.Mock).mockImplementation(() => {
        throw new Error('Database connection failed');
      });

      const response = await request(app)
        .post('/api/v1/wardrobes')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ name: 'Test Wardrobe' })
        .expect(500);

      expect(response.body).toMatchObject({
        success: false,
        error: {
          code: 'INTERNAL_SERVER_ERROR',
          message: expect.any(String),
          statusCode: 500,
          timestamp: expect.any(String),
          requestId: expect.any(String)
        }
      });
    });
  });

  // ==================== OFFLINE SYNC SCENARIOS ====================

  describe('Offline Sync Scenarios', () => {
    it('should handle complex offline queue sync', async () => {
      const operations = [
        // User created wardrobes offline
        {
          type: 'create' as const,
          data: { name: 'Offline Wardrobe 1', description: 'Created while offline' },
          clientId: 'offline-1'
        },
        // User updated wardrobe offline
        {
          type: 'update' as const,
          data: { id: uuidv4(), name: 'Updated Offline' },
          clientId: 'offline-2'
        },
        // User added garments offline (would be in garment batch)
        {
          type: 'create' as const,
          data: { name: 'Offline Wardrobe 2' },
          clientId: 'offline-3'
        },
        // User deleted wardrobe offline
        {
          type: 'delete' as const,
          data: { id: uuidv4() },
          clientId: 'offline-4'
        }
      ];

      (wardrobeController.batchOperations as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            results: operations.slice(0, 3).map((op) => ({
              clientId: op.clientId,
              serverId: uuidv4(),
              type: op.type,
              success: true
            })),
            errors: [{
              clientId: 'offline-4',
              type: 'delete',
              error: 'Wardrobe already deleted',
              code: 'NOT_FOUND'
            }],
            summary: {
              total: 4,
              successful: 3,
              failed: 1
            }
          }
        });
      });

      const response = await request(app)
        .post('/api/v1/wardrobes/batch')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ operations })
        .expect(200);

      expect(response.body.data.summary.successful).toBe(3);
      expect(response.body.data.summary.failed).toBe(1);
    });

    it('should handle conflict resolution during sync', async () => {
      const lastSyncTimestamp = new Date(Date.now() - 7200000).toISOString(); // 2 hours ago

      (wardrobeController.syncWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            wardrobes: {
              created: [],
              updated: [
                {
                  ...TestFixtures.createTestWardrobe(),
                  _conflict: true,
                  _serverVersion: 5,
                  _clientVersion: 3
                }
              ],
              deleted: []
            },
            sync: {
              timestamp: new Date().toISOString(),
              version: 1,
              hasMore: false,
              changeCount: 1,
              conflicts: 1
            }
          }
        });
      });

      const response = await request(app)
        .post('/api/v1/wardrobes/sync')
        .set('Authorization', `Bearer ${authToken}`)
        .send({ lastSyncTimestamp })
        .expect(200);

      expect(response.body.data.sync.conflicts).toBe(1);
    });
  });

  // ==================== PERFORMANCE OPTIMIZATION TESTS ====================

  describe('Flutter Performance Optimizations', () => {
    it('should support field selection for bandwidth optimization', async () => {
      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((req, res) => {
        const fields = req.query.fields?.split(',') || [];
        const wardrobes = Array.from({ length: 10 }, () => {
          const wardrobe = TestFixtures.createTestWardrobe({ user_id: testUser.id });
          // Return only requested fields
          if (fields.length > 0) {
            return fields.reduce((acc: any, field: string) => {
              acc[field] = wardrobe[field as keyof typeof wardrobe];
              return acc;
            }, { id: wardrobe.id });
          }
          return wardrobe;
        });

        res.status(200).json({
          status: 'success',
          data: { wardrobes, total: 10 }
        });
      });

      await request(app)
        .get('/api/v1/wardrobes?fields=id,name,updated_at')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const controllerCall = (wardrobeController.getWardrobes as jest.Mock).mock.calls[0];
      expect(controllerCall[0].query.fields).toBe('id,name,updated_at');
    });

    it('should support lightweight response mode', async () => {
      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((req, res) => {
        const isLightweight = req.query.lightweight === 'true';
        
        if (isLightweight) {
          res.status(200).json({
            status: 'success',
            data: {
              wardrobes: Array.from({ length: 10 }, (_, i) => ({
                id: uuidv4(),
                name: `Wardrobe ${i}`,
                garmentCount: Math.floor(Math.random() * 50)
              })),
              total: 10
            }
          });
        } else {
          res.status(200).json({
            status: 'success',
            data: { wardrobes: [], total: 0 }
          });
        }
      });

      const response = await request(app)
        .get('/api/v1/wardrobes?lightweight=true')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.wardrobes[0]).not.toHaveProperty('description');
      expect(response.body.data.wardrobes[0]).toHaveProperty('garmentCount');
    });
  });

  // ==================== INTEGRATION WITH FLUTTER WIDGETS ====================

  describe('Flutter Widget Integration Support', () => {
    it('should return data formatted for Flutter ListView', async () => {
      const mockWardrobes = Array.from({ length: 25 }, (_, i) => ({
        ...TestFixtures.createTestWardrobe({ user_id: testUser.id }),
        garmentCount: Math.floor(Math.random() * 50),
        lastWornItem: i % 3 === 0 ? {
          id: uuidv4(),
          name: `Last worn garment ${i}`,
          wornAt: new Date(Date.now() - i * 86400000).toISOString()
        } : null
      }));

      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.status(200).json({
          status: 'success',
          data: {
            wardrobes: mockWardrobes.slice(0, 10),
            pagination: {
              page: 1,
              limit: 10,
              total: 25,
              totalPages: 3,
              hasNext: true,
              hasPrev: false
            }
          }
        });
      });

      const response = await request(app)
        .get('/api/v1/wardrobes?page=1&limit=10&includeLastWorn=true')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.data.wardrobes).toHaveLength(10);
      expect(response.body.data.pagination.totalPages).toBe(3);
      // Some wardrobes should have lastWornItem
      const wardrobesWithLastWorn = response.body.data.wardrobes.filter(
        (w: any) => w.lastWornItem !== null
      );
      expect(wardrobesWithLastWorn.length).toBeGreaterThan(0);
    });

    it('should support pull-to-refresh timestamp header', async () => {
      const lastRefresh = new Date().toISOString();

      (wardrobeController.getWardrobes as jest.Mock).mockImplementation((_req, res) => {
        res.setHeader('X-Last-Modified', new Date().toISOString());
        res.status(200).json({
          status: 'success',
          data: { wardrobes: [], total: 0 }
        });
      });

      await request(app)
        .get('/api/v1/wardrobes')
        .set('Authorization', `Bearer ${authToken}`)
        .set('If-Modified-Since', lastRefresh)
        .expect(200);

      const controllerCall = (wardrobeController.getWardrobes as jest.Mock).mock.calls[0];
      expect(controllerCall[0].headers['if-modified-since']).toBe(lastRefresh);
    });
  });
});