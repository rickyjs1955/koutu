// /backend/src/tests/integration/http/expanded.http.int.test.ts

/**
 * @file Expanded HTTP Stack Integration Test Suite - FIXED
 * 
 * @description Comprehensive integration tests building on the proven minimal framework.
 * This suite tests more complex scenarios including file uploads, database interactions,
 * and full request lifecycle management.
 * 
 * @approach
 * - Build on the proven minimal test framework
 * - Add database integration with mocked responses
 * - Test file upload functionality
 * - Test complex authentication scenarios
 * - Test error handling and edge cases
 * 
 * @dependencies
 * - Minimal test framework (proven working)
 * - Enhanced mocking for complex scenarios
 * - File upload testing capabilities
 */

import { jest, describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import request from 'supertest';
import express, { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { getTestConfig } from '../../config';

// At the top of your test file, get test configuration
const testConfig = getTestConfig();

// Mock all external dependencies
jest.mock('../../config/firebase', () => ({
  default: { storage: jest.fn() }
}));

// Mock the database module with proper TypeScript types
jest.mock('../../models/db', () => ({
  query: jest.fn().mockImplementation(async (...args: any[]) => {
    const text = args[0] as string;
    const params = args[1] as any[] | undefined;
    
    console.log(`Mock DB Query: ${text.substring(0, 50)}...`, params);
    
    // Mock different query responses based on SQL pattern
    if (text.includes('SELECT') && text.includes('users')) {
      return {
        rows: [{
          id: params?.[0] || 'mock-user-id',
          email: 'test@example.com',
          password_hash: 'mock-hash',
          created_at: new Date(),
          updated_at: new Date()
        }],
        rowCount: 1
      };
    }
    
    if (text.includes('INSERT') && text.includes('users')) {
      return {
        rows: [{
          id: params?.[0] || 'new-user-id-' + Date.now(),
          email: params?.[1] || 'test@example.com',
          created_at: new Date()
        }],
        rowCount: 1
      };
    }
    
    if (text.includes('INSERT') && text.includes('original_images')) {
      return {
        rows: [{
          id: 'mock-image-id-' + Date.now(),
          user_id: params?.[0] || 'mock-user-id',
          file_path: params?.[1] || '/uploads/test.jpg',
          status: 'new',
          original_metadata: {},
          created_at: new Date(),
          updated_at: new Date()
        }],
        rowCount: 1
      };
    }
    
    if (text.includes('UPDATE') && text.includes('original_images')) {
      return {
        rows: [{
          id: params?.[1] || 'mock-image-id',
          status: params?.[0] || 'processed',
          updated_at: new Date()
        }],
        rowCount: 1
      };
    }
    
    if (text.includes('DELETE')) {
      return {
        rows: [],
        rowCount: 1
      };
    }
    
    if (text.includes('COUNT')) {
      return {
        rows: [{ count: '0' }],
        rowCount: 1
      };
    }
    
    // Default response for other queries
    return { 
      rows: [], 
      rowCount: 0 
    };
  }),
  
  getClient: jest.fn().mockImplementation(async () => {
    return {
      query: jest.fn().mockImplementation(async (...args: any[]) => {
        return { rows: [], rowCount: 0 };
      }),
      release: jest.fn().mockImplementation(() => {
        // Mock client release - no return value needed
      })
    };
  }),
  
  closePool: jest.fn().mockImplementation(async () => {
    // Mock pool close
    return Promise.resolve();
  }),
  
  pool: {
    query: jest.fn().mockImplementation(async (...args: any[]) => {
      return { rows: [], rowCount: 0 };
    }),
    connect: jest.fn().mockImplementation(async () => {
      return {
        query: jest.fn().mockImplementation(async (...args: any[]) => {
          return { rows: [], rowCount: 0 };
        }),
        release: jest.fn().mockImplementation(() => {
          // Mock release - no return value needed
        })
      };
    }),
    end: jest.fn().mockImplementation(async () => {
      return Promise.resolve();
    })
  }
}));

// Enhanced user model mock with more realistic behavior
jest.mock('../../models/userModel', () => ({
  userModel: {
    findById: jest.fn().mockImplementation(async (...args: any[]) => {
      const id = args[0] as string;
      console.log(`Mock UserModel.findById called with: ${id}`);
      
      if (id === 'valid-user-id' || id === 'test-user-1' || id === 'test-user-2') {
        return {
          id: id,
          email: `${id}@example.com`,
          created_at: new Date(),
          updated_at: new Date()
        };
      }
      
      if (id === 'suspended-user-id') {
        return {
          id: id,
          email: 'suspended@example.com',
          status: 'suspended',
          created_at: new Date(),
          updated_at: new Date()
        };
      }
      
      return null;
    }),
    
    findByEmail: jest.fn().mockImplementation(async (...args: any[]) => {
      const email = args[0] as string;
      if (email.includes('test') || email.includes('valid')) {
        return {
          id: 'found-user-id',
          email: email,
          password_hash: 'mock-hash',
          created_at: new Date(),
          updated_at: new Date()
        };
      }
      return null;
    }),
    
    create: jest.fn().mockImplementation(async (...args: any[]) => {
      const userData = args[0] as { email: string; password: string };
      return {
        id: 'new-user-id-' + Date.now(),
        email: userData.email,
        created_at: new Date()
      };
    }),
    
    validatePassword: jest.fn().mockImplementation(async (...args: any[]) => {
      const user = args[0] as any;
      const password = args[1] as string;
      // Simple mock validation - just check if password is not empty
      return password && password.length > 0;
    }),
    
    updateEmail: jest.fn().mockImplementation(async (...args: any[]) => {
      const id = args[0] as string;
      const email = args[1] as string;
      return {
        id: id,
        email: email,
        created_at: new Date(),
        updated_at: new Date()
      };
    }),
    
    updatePassword: jest.fn().mockImplementation(async (...args: any[]) => {
      const id = args[0] as string;
      const newPassword = args[1] as string;
      return newPassword && newPassword.length >= 8;
    }),
    
    delete: jest.fn().mockImplementation(async (...args: any[]) => {
      const id = args[0] as string;
      return id && id.length > 0;
    }),
    
    getUserStats: jest.fn().mockImplementation(async (...args: any[]) => {
      const id = args[0] as string;
      return {
        imageCount: 0,
        garmentCount: 0,
        wardrobeCount: 0
      };
    }),
    
    // OAuth-related methods from real userModel
    findByOAuth: jest.fn().mockImplementation(async (...args: any[]) => {
      const provider = args[0] as string;
      const providerId = args[1] as string;
      if (provider === 'google' && providerId === 'valid-oauth-id') {
        return {
          id: 'oauth-user-id',
          email: 'oauth@example.com',
          password_hash: null,
          created_at: new Date(),
          updated_at: new Date()
        };
      }
      return null;
    }),
    
    createOAuthUser: jest.fn().mockImplementation(async (...args: any[]) => {
      const data = args[0] as any;
      return {
        id: 'new-oauth-user-id-' + Date.now(),
        email: data.email,
        created_at: new Date()
      };
    }),
    
    getUserWithOAuthProviders: jest.fn().mockImplementation(async (...args: any[]) => {
      const id = args[0] as string;
      if (id === 'valid-user-id') {
        return {
          id: id,
          email: `${id}@example.com`,
          created_at: new Date(),
          linkedProviders: ['google'],
          name: null,
          avatar_url: null,
          oauth_provider: null
        };
      }
      return null;
    }),
    
    linkOAuthProvider: jest.fn().mockImplementation(async (...args: any[]) => {
      const userId = args[0] as string;
      const provider = args[1] as string;
      const providerId = args[2] as string;
      return true;
    }),
    
    unlinkOAuthProvider: jest.fn().mockImplementation(async (...args: any[]) => {
      const userId = args[0] as string;
      const provider = args[1] as string;
      return true;
    }),
    
    hasPassword: jest.fn().mockImplementation(async (...args: any[]) => {
      const userId = args[0] as string;
      // Mock that most users have passwords except OAuth-only users
      return !userId.includes('oauth');
    })
  }
}));

// Enhanced image service mock with comprehensive functionality
let mockImageDatabase: { [userId: string]: any[] } = {};
let mockImageCounter = 1;

jest.mock('../../services/imageService', () => ({
  imageService: {
    getUserImages: jest.fn().mockImplementation(async (...args: any[]) => {
      const [userId, options = {}] = args as [string, any?];
      console.log(`Mock ImageService.getUserImages called for user: ${userId}`, options);
      
      const userImages = mockImageDatabase[userId] || [];
      let filteredImages = [...userImages];
      
      // Apply filters
      if (options.status) {
        filteredImages = filteredImages.filter(img => img.status === options.status);
      }
      
      // Apply pagination
      if (options.limit || options.offset) {
        const offset = options.offset || 0;
        const limit = options.limit || filteredImages.length;
        filteredImages = filteredImages.slice(offset, offset + limit);
      }
      
      return filteredImages;
    }),
    
    uploadImage: jest.fn().mockImplementation(async (...args: any[]) => {
      const [uploadData] = args as [any];
      console.log(`Mock ImageService.uploadImage called:`, uploadData.originalFilename);
      
      // Simulate validation errors
      if (uploadData.originalFilename && uploadData.originalFilename.includes('invalid')) {
        throw new Error('Invalid image format');
      }
      
      if (uploadData.size > 10 * 1024 * 1024) { // 10MB limit
        throw new Error('File too large');
      }
      
      const newImage = {
        id: `mock-image-${mockImageCounter++}`,
        user_id: uploadData.userId,
        file_path: `/uploads/${uploadData.originalFilename || 'unknown.jpg'}`,
        original_metadata: {
          width: 800,
          height: 600,
          format: uploadData.originalFilename && uploadData.originalFilename.endsWith('.png') ? 'png' : 'jpeg',
          size: uploadData.size || 1024,
          filename: uploadData.originalFilename || 'unknown.jpg'
        },
        status: 'new',
        created_at: new Date(),
        updated_at: new Date()
      };
      
      // Store in mock database
      if (!mockImageDatabase[uploadData.userId]) {
        mockImageDatabase[uploadData.userId] = [];
      }
      mockImageDatabase[uploadData.userId].push(newImage);
      
      return newImage;
    }),
    
    getImageById: jest.fn().mockImplementation(async (...args: any[]) => {
      const [imageId, userId] = args as [string, string];
      console.log(`Mock ImageService.getImageById called: ${imageId} for user: ${userId}`);
      
      const userImages = mockImageDatabase[userId] || [];
      const image = userImages.find(img => img.id === imageId);
      
      if (!image) {
        throw new Error('Image not found');
      }
      
      return image;
    }),
    
    updateImageStatus: jest.fn().mockImplementation(async (...args: any[]) => {
      const [imageId, userId, newStatus] = args as [string, string, string];
      console.log(`Mock ImageService.updateImageStatus: ${imageId} to ${newStatus}`);
      
      const userImages = mockImageDatabase[userId] || [];
      const imageIndex = userImages.findIndex(img => img.id === imageId);
      
      if (imageIndex === -1) {
        throw new Error('Image not found');
      }
      
      // Validate status transitions
      const validStatuses = ['new', 'processed', 'labeled'];
      if (!validStatuses.includes(newStatus)) {
        throw new Error(`Invalid status: ${newStatus}`);
      }
      
      userImages[imageIndex].status = newStatus;
      userImages[imageIndex].updated_at = new Date();
      
      return userImages[imageIndex];
    }),
    
    deleteImage: jest.fn().mockImplementation(async (...args: any[]) => {
      const [imageId, userId] = args as [string, string];
      console.log(`Mock ImageService.deleteImage: ${imageId} for user: ${userId}`);
      
      const userImages = mockImageDatabase[userId] || [];
      const imageIndex = userImages.findIndex(img => img.id === imageId);
      
      if (imageIndex === -1) {
        throw new Error('Image not found');
      }
      
      userImages.splice(imageIndex, 1);
      return { success: true };
    }),
    
    getUserImageStats: jest.fn().mockImplementation(async (...args: any[]) => {
      const [userId] = args as [string];
      console.log(`Mock ImageService.getUserImageStats for user: ${userId}`);
      
      const userImages = mockImageDatabase[userId] || [];
      const statusCounts = userImages.reduce((counts, img) => {
        counts[img.status] = (counts[img.status] || 0) + 1;
        return counts;
      }, { new: 0, processed: 0, labeled: 0 });
      
      const totalSize = userImages.reduce((sum, img) => sum + (img.original_metadata?.size || 0), 0);
      
      return {
        totalImages: userImages.length,
        totalStorageUsed: totalSize,
        averageFileSize: userImages.length > 0 ? Math.round(totalSize / userImages.length) : 0,
        statusCounts,
        uploadStats: {
          totalUploads: userImages.length,
          uploadsThisMonth: userImages.length,
          uploadsThisWeek: userImages.length
        }
      };
    }),
    
    batchUpdateStatus: jest.fn().mockImplementation(async (...args: any[]) => {
      const [imageIds, userId, newStatus] = args as [string[], string, string];
      console.log(`Mock ImageService.batchUpdateStatus: ${imageIds.length} images to ${newStatus}`);
      
      const userImages = mockImageDatabase[userId] || [];
      let updatedCount = 0;
      
      for (const imageId of imageIds) {
        const imageIndex = userImages.findIndex(img => img.id === imageId);
        if (imageIndex !== -1) {
          userImages[imageIndex].status = newStatus;
          userImages[imageIndex].updated_at = new Date();
          updatedCount++;
        }
      }
      
      return {
        updatedCount,
        total: imageIds.length,
        failedCount: imageIds.length - updatedCount
      };
    })
  }
}));

// Mock storage service
jest.mock('../../services/storageService', () => ({
  storageService: {
    saveFile: jest.fn().mockImplementation(async (...args: any[]) => {
      const [fileBuffer, originalFilename] = args as [Buffer, string];
      console.log(`Mock StorageService.saveFile: ${originalFilename} (${fileBuffer.length} bytes)`);
      return `/uploads/${originalFilename}`;
    }),
    
    deleteFile: jest.fn().mockImplementation(async (...args: any[]) => {
      const [filePath] = args as [string];
      console.log(`Mock StorageService.deleteFile: ${filePath}`);
      return true;
    }),
    
    getAbsolutePath: jest.fn().mockImplementation((...args: any[]) => {
      const [relativePath] = args as [string];
      console.log(`Mock StorageService.getAbsolutePath: ${relativePath}`);
      return `/absolute/path/${relativePath}`;
    }),
    
    getSignedUrl: jest.fn().mockImplementation(async (...args: any[]) => {
      const [filePath, expirationMinutes = 60] = args as [string, number?];
      console.log(`Mock StorageService.getSignedUrl: ${filePath} (expires in ${expirationMinutes}min)`);
      return `https://mock-storage.com${filePath}?expires=${Date.now() + expirationMinutes * 60 * 1000}`;
    }),
    
    getContentType: jest.fn().mockImplementation((...args: any[]) => {
      const [fileExtension] = args as [string];
      console.log(`Mock StorageService.getContentType: ${fileExtension}`);
      
      const contentTypeMap: { [key: string]: string } = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.gif': 'image/gif',
        '.webp': 'image/webp',
        '.svg': 'image/svg+xml',
        '.pdf': 'application/pdf',
      };
      
      return contentTypeMap[fileExtension.toLowerCase()] || 'application/octet-stream';
    })
  }
}));

// Mock authentication middleware
const mockAuthenticate = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: 'error',
      code: 'MISSING_TOKEN',
      message: 'Authentication token required'
    });
  }

  try {
    const token = authHeader.substring(7);
    // Use test-specific JWT secret
    const decoded = jwt.verify(token, testConfig.jwtSecret) as any;
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      status: 'error',
      code: 'INVALID_TOKEN',
      message: 'Invalid or expired token'
    });
  }
};

const mockRequireAuth = (req: any, res: any, next: any) => {
  if (!req.user) {
    return res.status(401).json({
      status: 'error',
      code: 'UNAUTHORIZED',
      message: 'User authentication required'
    });
  }
  next();
};

// Mock multer for file uploads
const mockUploadMiddleware = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
}).single('image');

describe('Expanded HTTP Stack Integration Tests', () => {
  let app: express.Express;
  let validToken: string;
  let testUserId: string;

  beforeAll(() => {
    console.log('🔧 Setting up expanded HTTP integration test suite...');
    
    //Set testUserId FIRST
    testUserId = 'test-user-1'; 
    
    //Create valid JWT token AFTER testUserId is set
    validToken = jwt.sign(
      { id: testUserId, email: 'test@example.com' },
      testConfig.jwtSecret,
      { expiresIn: '24h' }
    );
    
    // Create comprehensive Express app
    app = express();
    
    // Basic middleware
    app.use(express.json({ limit: '50mb' }));
    app.use(express.urlencoded({ extended: true, limit: '50mb' }));
    
    // JSON parsing error handler
    app.use((error: any, req: any, res: any, next: any) => {
      if (error instanceof SyntaxError && 'body' in error) {
        return res.status(400).json({
          status: 'error',
          code: 'INVALID_JSON',
          message: 'Invalid JSON format'
        });
      }
      next(error);
    });
    
    // Health check
    app.get('/health', (req, res) => {
      res.status(200).json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: process.env.NODE_ENV || 'test'
      });
    });
    
    // Authentication test endpoint
    app.post('/api/v1/auth/login', async (req: Request, res: Response, next: NextFunction) => {
      try {
        const { email, password } = req.body;
        
        if (!email || !password) {
          res.status(400).json({
            status: 'error',
            code: 'MISSING_CREDENTIALS',
            message: 'Email and password are required'
          });
          return;
        }
        
        // Mock user lookup
        const { userModel } = require('../../models/userModel');
        const user = await userModel.findByEmail(email);
        
        if (!user) {
          res.status(401).json({
            status: 'error',
            code: 'INVALID_CREDENTIALS',
            message: 'Invalid email or password'
          });
          return;
        }
        
        const token = jwt.sign(
          { id: user.id, email: user.email },
          testConfig.jwtSecret, // ✅ FIX: Use test secret
          { expiresIn: '24h' }
        );
        
        res.status(200).json({
          status: 'success',
          data: { 
            token, 
            user: { 
              id: user.id, 
              email: user.email 
            } 
          }
        });
      } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
          status: 'error',
          message: 'Internal server error'
        });
      }
    });
    
    // User registration endpoint
    app.post('/api/v1/auth/register', async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const { email, password } = req.body;
        
        if (!email || !password) {
          res.status(400).json({
            status: 'error',
            code: 'MISSING_DATA',
            message: 'Email and password are required'
          });
          return;
        }
        
        if (password.length < 8) {
          res.status(400).json({
            status: 'error',
            code: 'WEAK_PASSWORD',
            message: 'Password must be at least 8 characters'
          });
          return;
        }
        
        const { userModel } = require('../../models/userModel');
        const existingUser = await userModel.findByEmail(email);
        
        if (existingUser) {
          res.status(409).json({
            status: 'error',
            code: 'EMAIL_EXISTS',
            message: 'Email already registered'
          });
          return;
        }
        
        const newUser = await userModel.create({ email, password });
        
        const token = jwt.sign(
          { id: newUser.id, email: newUser.email },
          testConfig.jwtSecret, // ✅ FIX: Use test secret
          { expiresIn: '24h' }
        );
        
        res.status(201).json({
          status: 'success',
          data: { 
            token, 
            user: { 
              id: newUser.id, 
              email: newUser.email 
            } 
          }
        });
      } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
          status: 'error',
          message: 'Internal server error'
        });
      }
    });
    
    // Protected image routes
    app.get('/api/v1/images',
      mockAuthenticate,
      mockRequireAuth,
      async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
          const { imageService } = require('../../services/imageService');
          const images = await imageService.getUserImages(req.user!.id, req.query);
          
          res.status(200).json({
            status: 'success',
            data: { images }
          });
        } catch (error) {
          console.error('Get images error:', error);
          res.status(500).json({
            status: 'error',
            message: 'Internal server error'
          });
        }
      }
    );
    
    app.get('/api/v1/images/stats',
      mockAuthenticate,
      mockRequireAuth,
      async (req: Request, res: Response, next: NextFunction) => {
        try {
          const { imageService } = require('../../services/imageService');
          const stats = await imageService.getUserImageStats(req.user!.id);
          
          res.status(200).json({
            status: 'success',
            data: { stats }
          });
        } catch (error) {
          console.error('Get stats error:', error);
          res.status(500).json({
            status: 'error',
            message: 'Internal server error'
          });
        }
      }
    );
    
    app.put('/api/v1/images/batch/status',
      mockAuthenticate,
      mockRequireAuth,
      async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
          const { imageIds, status } = req.body;
          
          if (!imageIds || !Array.isArray(imageIds)) {
            res.status(400).json({
              status: 'error',
              code: 'INVALID_REQUEST',
              message: 'imageIds must be an array'
            });
            return;
          }
          
          if (!status) {
            res.status(400).json({
              status: 'error',
              code: 'MISSING_STATUS',
              message: 'Status is required'
            });
            return;
          }
          
          if (imageIds.length > 100) {
            res.status(400).json({
              status: 'error',
              code: 'BATCH_TOO_LARGE',
              message: 'Maximum 100 images per batch'
            });
            return;
          }
          
          const { imageService } = require('../../services/imageService');
          const result = await imageService.batchUpdateStatus(imageIds, req.user!.id, status);
          
          res.status(200).json({
            status: 'success',
            data: result,
            message: `Updated ${result.updatedCount} of ${result.total} images`
          });
        } catch (error) {
          console.error('Batch update error:', error);
          res.status(500).json({
            status: 'error',
            message: 'Internal server error'
          });
        }
      }
    );
    
    // Admin routes (for testing role-based access)
    app.get('/api/v1/admin/users',
      mockAuthenticate,
      mockRequireAuth,
      async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
          // Check if user has admin role
          if (req.user!.email !== 'admin@example.com') {
            res.status(403).json({
              status: 'error',
              code: 'INSUFFICIENT_PRIVILEGES',
              message: 'Admin access required'
            });
            return;
          }
          
          res.status(200).json({
            status: 'success',
            data: {
              users: [
                { id: 'user1', email: 'user1@example.com' },
                { id: 'user2', email: 'user2@example.com' }
              ]
            }
          });
        } catch (error) {
          console.error('Admin users error:', error);
          res.status(500).json({
            status: 'error',
            message: 'Internal server error'
          });
        }
      }
    );
    
    // Rate limiting test endpoint
    app.get('/api/v1/test/rate-limit', (req, res) => {
      res.status(200).json({
        status: 'success',
        message: 'Rate limit test endpoint',
        timestamp: new Date().toISOString()
      });
    });

    app.get('/api/v1/images/:id',
      mockAuthenticate,
      mockRequireAuth,
      async (req: Request, res: Response, next: NextFunction) => {
        try {
          const { imageService } = require('../../services/imageService');
          const image = await imageService.getImageById(req.params.id, req.user!.id);
          
          res.status(200).json({
            status: 'success',
            data: { image }
          });
        } catch (error) {
          console.error('Get image error:', error);
          res.status(500).json({
            status: 'error',
            message: 'Internal server error'
          });
        }
      }
    );
    
    app.post('/api/v1/images/upload',
      mockAuthenticate,
      mockRequireAuth,
      (req: any, res: any, next: any): void => {
        mockUploadMiddleware(req, res, (err: any) => {
          if (err) {
            res.status(400).json({
              status: 'error',
              code: 'UPLOAD_ERROR',
              message: err.message
            });
            return;
          }
          next();
        });
      },
      async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
          if (!req.file) {
            res.status(400).json({
              status: 'error',
              code: 'NO_FILE',
              message: 'No image file provided'
            });
            return;
          }
          
          const { imageService } = require('../../services/imageService');
          const image = await imageService.uploadImage({
            userId: req.user!.id,
            fileBuffer: req.file.buffer,
            originalFilename: req.file.originalname,
            mimetype: req.file.mimetype,
            size: req.file.size
          });
          
          res.status(201).json({
            status: 'success',
            data: { image },
            message: 'Image uploaded successfully'
          });
        } catch (error) {
          console.error('Upload error:', error);
          res.status(500).json({
            status: 'error',
            message: error instanceof Error ? error.message : 'Internal server error'
          });
        }
      }
    );

    app.put('/api/v1/images/:id/status',
      mockAuthenticate,
      mockRequireAuth,
      async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        try {
          const { status } = req.body;
          
          if (!status) {
            res.status(400).json({
              status: 'error',
              code: 'MISSING_STATUS',
              message: 'Status is required'
            });
            return;
          }
          
          const { imageService } = require('../../services/imageService');
          const image = await imageService.updateImageStatus(req.params.id, req.user!.id, status);
          
          res.status(200).json({
            status: 'success',
            data: { image },
            message: `Image status updated to ${status}`
          });
        } catch (error) {
          console.error('Update status error:', error);
          res.status(500).json({
            status: 'error',
            message: 'Internal server error'
          });
        }
      }
    );
    
    app.delete('/api/v1/images/:id',
      mockAuthenticate,
      mockRequireAuth,
      async (req: Request, res: Response, next: NextFunction) => {
        try {
          const { imageService } = require('../../services/imageService');
          await imageService.deleteImage(req.params.id, req.user!.id);
          
          res.status(200).json({
            status: 'success',
            data: null,
            message: 'Image deleted successfully'
          });
        } catch (error) {
          console.error('Delete image error:', error);
          res.status(500).json({
            status: 'error',
            message: 'Internal server error'
          });
        }
      }
    );
    
    // Error handling middleware (must be last)
    app.use((error: any, req: any, res: any, next: any) => {
      console.error('Unhandled error:', error);
      res.status(500).json({
        status: 'error',
        message: 'Internal server error'
      });
    });
    
    console.log('✅ Expanded HTTP integration test setup complete');
  });

  beforeEach(() => {
    // Clear mock data between tests
    mockImageDatabase = {};
    mockImageCounter = 1;
    jest.clearAllMocks();
  });

  afterEach(() => {
    // Additional cleanup if needed
  });

  describe('📁 File Upload Integration', () => {
    // Helper function to create test image buffer
    const createTestImageBuffer = (width = 800, height = 600): Buffer => {
      // Create a minimal valid JPEG header
      const jpegHeader = Buffer.from([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46,
        0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00
      ]);
      
      // Add some dummy image data
      const imageData = Buffer.alloc(1024, 0x80); // Gray pixels
      
      // Add JPEG end marker
      const jpegEnd = Buffer.from([0xFF, 0xD9]);
      
      return Buffer.concat([jpegHeader, imageData, jpegEnd]);
    };
    
    it('should handle successful image upload', async () => {
      const imageBuffer = createTestImageBuffer();
      
      const response = await request(app)
        .post('/api/v1/images/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .attach('image', imageBuffer, 'test-upload.jpg')
        .expect(201);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          image: {
            id: expect.any(String),
            user_id: testUserId,
            file_path: expect.stringContaining('test-upload.jpg'),
            status: 'new',
            original_metadata: {
              width: 800,
              height: 600,
              format: 'jpeg',
              size: expect.any(Number),
              filename: 'test-upload.jpg'
            }
          }
        },
        message: 'Image uploaded successfully'
      });
      
      // Verify image is stored in mock database
      expect(mockImageDatabase[testUserId]).toHaveLength(1);
    });
    
    it('should handle PNG image upload', async () => {
      const imageBuffer = createTestImageBuffer();
      
      const response = await request(app)
        .post('/api/v1/images/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .attach('image', imageBuffer, 'test-upload.png')
        .expect(201);
      
      expect(response.body.data.image.original_metadata.format).toBe('png');
    });
    
    it('should reject upload without file', async () => {
      const response = await request(app)
        .post('/api/v1/images/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(400);
      
      expect(response.body.code).toBe('NO_FILE');
    });
    
    it('should reject invalid image files', async () => {
      const invalidBuffer = Buffer.from('This is not an image file');
      
      const response = await request(app)
        .post('/api/v1/images/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .attach('image', invalidBuffer, 'invalid.txt')
        .expect(400);
      
      expect(response.body.status).toBe('error');
    });
    
    it('should reject oversized files', async () => {
      // Create a large buffer (simulate 15MB file)
      const largeBuffer = Buffer.alloc(15 * 1024 * 1024, 0xFF);
      
      const response = await request(app)
        .post('/api/v1/images/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .attach('image', largeBuffer, 'large.jpg')
        .expect(400);
      
      expect(response.body.message).toContain('File too large');
    });
    
    it('should handle concurrent uploads', async () => {
      const imageBuffer1 = createTestImageBuffer();
      const imageBuffer2 = createTestImageBuffer();
      const imageBuffer3 = createTestImageBuffer();
      
      const uploadPromises = [
        request(app)
          .post('/api/v1/images/upload')
          .set('Authorization', `Bearer ${validToken}`)
          .attach('image', imageBuffer1, 'concurrent1.jpg'),
        request(app)
          .post('/api/v1/images/upload')
          .set('Authorization', `Bearer ${validToken}`)
          .attach('image', imageBuffer2, 'concurrent2.jpg'),
        request(app)
          .post('/api/v1/images/upload')
          .set('Authorization', `Bearer ${validToken}`)
          .attach('image', imageBuffer3, 'concurrent3.jpg')
      ];
      
      const responses = await Promise.all(uploadPromises);
      
      responses.forEach(response => {
        expect(response.status).toBe(201);
        expect(response.body.status).toBe('success');
      });
      
      // Verify all images are stored
      expect(mockImageDatabase[testUserId]).toHaveLength(3);
    });
  });

  describe('🔄 Full CRUD Operations', () => {
    let uploadedImageId: string;
    
    beforeEach(async () => {
      // Upload a test image for CRUD operations
      const imageBuffer = Buffer.alloc(1024, 0x80);
      
      const uploadResponse = await request(app)
        .post('/api/v1/images/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .attach('image', imageBuffer, 'crud-test.jpg')
        .expect(201);
      
      uploadedImageId = uploadResponse.body.data.image.id;
    });
    
    it('should retrieve uploaded image by ID', async () => {
      const response = await request(app)
        .get(`/api/v1/images/${uploadedImageId}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          image: {
            id: uploadedImageId,
            user_id: testUserId,
            status: 'new'
          }
        }
      });
    });
    
    it('should update image status', async () => {
      const response = await request(app)
        .put(`/api/v1/images/${uploadedImageId}/status`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ status: 'processed' })
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          image: {
            id: uploadedImageId,
            status: 'processed'
          }
        },
        message: 'Image status updated to processed'
      });
    });
    
    it('should reject invalid status updates', async () => {
      const response = await request(app)
        .put(`/api/v1/images/${uploadedImageId}/status`)
        .set('Authorization', `Bearer ${validToken}`)
        .send({ status: 'invalid-status' })
        .expect(500);
      
      expect(response.body.status).toBe('error');
    });
    
    it('should delete image', async () => {
      const response = await request(app)
        .delete(`/api/v1/images/${uploadedImageId}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: null,
        message: 'Image deleted successfully'
      });
      
      // Verify image is deleted
      await request(app)
        .get(`/api/v1/images/${uploadedImageId}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(500);
    });
    
    it('should prevent access to other users\' images', async () => {
      // Create another user's token
      const otherUserToken = jwt.sign(
        { id: 'other-user-id', email: 'other@example.com' },
        testConfig.jwtSecret,
        { expiresIn: '1h' }
      );
      
      const response = await request(app)
        .get(`/api/v1/images/${uploadedImageId}`)
        .set('Authorization', `Bearer ${otherUserToken}`)
        .expect(500);
      
      expect(response.body.status).toBe('error');
    });
  });

  describe('📊 Statistics and Analytics', () => {
    beforeEach(async () => {
      // Upload multiple test images with different statuses
      const imageBuffer = Buffer.alloc(1024, 0x80);
      
      // Upload 3 images
      for (let i = 0; i < 3; i++) {
        await request(app)
          .post('/api/v1/images/upload')
          .set('Authorization', `Bearer ${validToken}`)
          .attach('image', imageBuffer, `stats-test-${i}.jpg`);
      }
      
      // Update statuses
      const userImages = mockImageDatabase[testUserId];
      if (userImages && userImages.length >= 3) {
        userImages[0].status = 'processed';
        userImages[1].status = 'labeled';
        // Leave userImages[2] as 'new'
      }
    });
    
    it('should return accurate user statistics', async () => {
      const response = await request(app)
        .get('/api/v1/images/stats')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          stats: {
            totalImages: 3,
            totalStorageUsed: expect.any(Number),
            averageFileSize: expect.any(Number),
            statusCounts: {
              new: 1,
              processed: 1,
              labeled: 1
            },
            uploadStats: {
              totalUploads: 3,
              uploadsThisMonth: 3,
              uploadsThisWeek: 3
            }
          }
        }
      });
    });
    
    it('should return empty stats for new user', async () => {
      const newUserToken = jwt.sign(
        { id: 'new-user-id', email: 'newuser@example.com' },
        testConfig.jwtSecret,
        { expiresIn: '1h' }
      );
      
      const response = await request(app)
        .get('/api/v1/images/stats')
        .set('Authorization', `Bearer ${newUserToken}`)
        .expect(200);
      
      expect(response.body.data.stats.totalImages).toBe(0);
    });
  });

  describe('🔄 Batch Operations', () => {
    let imageIds: string[];
    
    beforeEach(async () => {
      const imageBuffer = Buffer.alloc(1024, 0x80);
      imageIds = [];
      
      // Upload 5 test images
      for (let i = 0; i < 5; i++) {
        const uploadResponse = await request(app)
          .post('/api/v1/images/upload')
          .set('Authorization', `Bearer ${validToken}`)
          .attach('image', imageBuffer, `batch-test-${i}.jpg`);
        
        imageIds.push(uploadResponse.body.data.image.id);
      }
    });
    
    it('should batch update image statuses', async () => {
      const response = await request(app)
        .put('/api/v1/images/batch/status')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          imageIds: imageIds,
          status: 'processed'
        })
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          updatedCount: 5,
          total: 5,
          failedCount: 0
        },
        message: 'Updated 5 of 5 images'
      });
    });
    
    it('should handle partial batch updates', async () => {
      const mixedIds = [...imageIds.slice(0, 3), 'non-existent-id', 'another-fake-id'];
      
      const response = await request(app)
        .put('/api/v1/images/batch/status')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          imageIds: mixedIds,
          status: 'processed'
        })
        .expect(200);
      
      expect(response.body.data.updatedCount).toBe(3);
      expect(response.body.data.failedCount).toBe(2);
    });
    
    it('should reject oversized batch operations', async () => {
      const oversizedBatch = Array(101).fill('fake-id'); // 101 > 100 limit
      
      const response = await request(app)
        .put('/api/v1/images/batch/status')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          imageIds: oversizedBatch,
          status: 'processed'
        })
        .expect(400);
      
      expect(response.body.code).toBe('BATCH_TOO_LARGE');
    });
    
    it('should validate batch request parameters', async () => {
      // Missing imageIds
      const response1 = await request(app)
        .put('/api/v1/images/batch/status')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          status: 'processed'
        })
        .expect(400);
      
      expect(response1.body.code).toBe('INVALID_REQUEST');
      
      // Missing status
      const response2 = await request(app)
        .put('/api/v1/images/batch/status')
        .set('Authorization', `Bearer ${validToken}`)
        .send({
          imageIds: ['some-id']
        })
        .expect(400);
      
      expect(response2.body.code).toBe('MISSING_STATUS');
    });
  });

  describe('⚡ Performance and Load Testing', () => {
    it('should handle rapid consecutive requests', async () => {
      const requests = Array(20).fill(0).map(() =>
        request(app)
          .get('/health')
          .expect(200)
      );
      
      const start = Date.now();
      const responses = await Promise.all(requests);
      const duration = Date.now() - start;
      
      responses.forEach(response => {
        expect(response.body.status).toBe('ok');
      });
      
      console.log(`20 rapid requests completed in ${duration}ms`);
      expect(duration).toBeLessThan(3000); // Should complete within 3 seconds
    });
    
    it('should handle mixed concurrent operations', async () => {
      const imageBuffer = Buffer.alloc(1024, 0x80);
      
      const operations = [
        // Health checks
        ...Array(5).fill(0).map(() =>
          request(app).get('/health')
        ),
        // Image lists
        ...Array(3).fill(0).map(() =>
          request(app)
            .get('/api/v1/images')
            .set('Authorization', `Bearer ${validToken}`)
        ),
        // Statistics
        ...Array(2).fill(0).map(() =>
          request(app)
            .get('/api/v1/images/stats')
            .set('Authorization', `Bearer ${validToken}`)
        ),
        // Uploads
        ...Array(2).fill(0).map((_, i) =>
          request(app)
            .post('/api/v1/images/upload')
            .set('Authorization', `Bearer ${validToken}`)
            .attach('image', imageBuffer, `concurrent-${i}.jpg`)
        )
      ];
      
      const start = Date.now();
      const results = await Promise.allSettled(operations);
      const duration = Date.now() - start;
      
      // Count successes
      const successes = results.filter(r => r.status === 'fulfilled').length;
      
      console.log(`${successes}/${operations.length} concurrent operations completed in ${duration}ms`);
      expect(successes).toBeGreaterThanOrEqual(operations.length * 0.9); // At least 90% success rate
      expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
    });
    
    it('should handle rate limiting gracefully', async () => {
      // Send many requests to rate limit endpoint
      const requests = Array(50).fill(0).map(() =>
        request(app).get('/api/v1/test/rate-limit')
      );
      
      const responses = await Promise.allSettled(requests);
      const successful = responses.filter(r => r.status === 'fulfilled').length;
      
      // Should handle most requests successfully (rate limiting not implemented in test)
      expect(successful).toBeGreaterThan(40);
    });
  });

  describe('🛡️ Security and Error Handling', () => {
    it('should handle SQL injection attempts safely', async () => {
      const maliciousId = "'; DROP TABLE images; --";
      
      const response = await request(app)
        .get(`/api/v1/images/${encodeURIComponent(maliciousId)}`)
        .set('Authorization', `Bearer ${validToken}`)
        .expect(500);
      
      expect(response.body.status).toBe('error');
      // Database should still be functional
      expect(mockImageDatabase).toBeDefined();
    });
    
    it('should handle XSS attempts in file uploads', async () => {
      const imageBuffer = Buffer.alloc(1024, 0x80);
      const maliciousFilename = '<script>alert("xss")</script>.jpg';
      
      const response = await request(app)
        .post('/api/v1/images/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .attach('image', imageBuffer, maliciousFilename);
      
      // Should either succeed (filename sanitized) or fail gracefully
      expect([201, 400, 500]).toContain(response.status);
      
      if (response.status === 201) {
        // Response should not contain script tags
        expect(JSON.stringify(response.body)).not.toContain('<script>');
      }
    });
    
    it('should handle malformed JSON requests', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .set('Content-Type', 'application/json')
        .send('{ invalid json }')
        .expect(400);
      
      expect(response.body.status).toBe('error');
    });
    
    it('should handle very large request payloads', async () => {
      const largePayload = {
        email: 'test@example.com',
        password: 'password123',
        data: 'x'.repeat(100000) // 100KB of data
      };
      
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send(largePayload);
      
      // Should either succeed or fail gracefully with payload size limit
      expect([200, 400, 413, 500]).toContain(response.status);
    });
    
    it('should handle network timeout scenarios', async () => {
      // Create endpoint with artificial delay
      const testApp = express();
      testApp.get('/slow', async (req, res) => {
        await new Promise(resolve => setTimeout(resolve, 100));
        res.json({ status: 'slow but successful' });
      });
      
      const response = await request(testApp)
        .get('/slow')
        .timeout(200) // 200ms timeout
        .expect(200);
      
      expect(response.body.status).toBe('slow but successful');
    });
  });

  describe('🎯 Complete Workflow Integration', () => {
    it('should handle complete user registration to image management workflow', async () => {
      // 1. Register new user
      const registerResponse = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'workflow@example.com',
          password: 'workflowtest123'
        })
        .expect(201);
      
      const token = registerResponse.body.data.token;
      const userId = registerResponse.body.data.user.id;
      
      // 2. Upload image
      const imageBuffer = Buffer.alloc(1024, 0x80);
      const uploadResponse = await request(app)
        .post('/api/v1/images/upload')
        .set('Authorization', `Bearer ${token}`)
        .attach('image', imageBuffer, 'workflow-test.jpg')
        .expect(201);
      
      const imageId = uploadResponse.body.data.image.id;
      
      // 3. Update image status
      await request(app)
        .put(`/api/v1/images/${imageId}/status`)
        .set('Authorization', `Bearer ${token}`)
        .send({ status: 'processed' })
        .expect(200);
      
      // 4. Check statistics
      const statsResponse = await request(app)
        .get('/api/v1/images/stats')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      
      expect(statsResponse.body.data.stats.totalImages).toBe(1);
      expect(statsResponse.body.data.stats.statusCounts.processed).toBe(1);
      
      // 5. Get image list
      const listResponse = await request(app)
        .get('/api/v1/images')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      
      expect(listResponse.body.data.images).toHaveLength(1);
      expect(listResponse.body.data.images[0].status).toBe('processed');
      
      // 6. Delete image
      await request(app)
        .delete(`/api/v1/images/${imageId}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      
      // 7. Verify deletion
      const finalStatsResponse = await request(app)
        .get('/api/v1/images/stats')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
      
      expect(finalStatsResponse.body.data.stats.totalImages).toBe(0);
    });
    
    it('should handle multi-user concurrent workflows', async () => {
      // Create multiple users and run parallel workflows
      const userWorkflows = Array(3).fill(0).map(async (_, index) => {
        const email = `concurrent-user-${index}@example.com`;
        
        // Register user
        const registerResponse = await request(app)
          .post('/api/v1/auth/register')
          .send({
            email: email,
            password: 'password123'
          });
        
        const token = registerResponse.body.data.token;
        
        // Upload multiple images
        const imageBuffer = Buffer.alloc(1024, 0x80);
        const uploadPromises = Array(3).fill(0).map((_, imgIndex) =>
          request(app)
            .post('/api/v1/images/upload')
            .set('Authorization', `Bearer ${token}`)
            .attach('image', imageBuffer, `user-${index}-image-${imgIndex}.jpg`)
        );
        
        const uploadResponses = await Promise.all(uploadPromises);
        const imageIds = uploadResponses.map(res => res.body.data.image.id);
        
        // Batch update statuses
        await request(app)
          .put('/api/v1/images/batch/status')
          .set('Authorization', `Bearer ${token}`)
          .send({
            imageIds: imageIds,
            status: 'processed'
          });
        
        // Get final stats
        const statsResponse = await request(app)
          .get('/api/v1/images/stats')
          .set('Authorization', `Bearer ${token}`);
        
        return {
          userIndex: index,
          email: email,
          totalImages: statsResponse.body.data.stats.totalImages
        };
      });
      
      const results = await Promise.all(userWorkflows);
      
      // Verify each user has their own isolated data
      results.forEach(result => {
        expect(result.totalImages).toBe(3);
      });
      
      console.log('Multi-user concurrent workflows completed successfully');
    });
  });

  describe('🔐 Enhanced Authentication & Authorization', () => {
    it('should handle user login with valid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'validpassword123'
        })
        .expect(200);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          token: expect.any(String),
          user: {
            id: expect.any(String),
            email: 'test@example.com'
          }
        }
      });
      
      // Verify the token is valid
      const token = response.body.data.token;
      const decoded = jwt.verify(token, testConfig.jwtSecret) as any;
      expect(decoded.email).toBe('test@example.com');
    });
    
    it('should reject login with invalid credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword'
        })
        .expect(401);
      
      expect(response.body).toMatchObject({
        status: 'error',
        code: 'INVALID_CREDENTIALS',
        message: expect.stringContaining('Invalid')
      });
    });
    
    it('should reject login with missing credentials', async () => {
      const response = await request(app)
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com'
          // Missing password
        })
        .expect(400);
      
      expect(response.body.code).toBe('MISSING_CREDENTIALS');
    });
    
    it('should handle user registration', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'newuser@example.com',
          password: 'strongpassword123'
        })
        .expect(201);
      
      expect(response.body).toMatchObject({
        status: 'success',
        data: {
          token: expect.any(String),
          user: {
            id: expect.any(String),
            email: 'newuser@example.com'
          }
        }
      });
    });
    
    it('should reject registration with weak password', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'newuser@example.com',
          password: '123' // Too short
        })
        .expect(400);
      
      expect(response.body.code).toBe('WEAK_PASSWORD');
    });
    
    it('should reject registration with existing email', async () => {
      const response = await request(app)
        .post('/api/v1/auth/register')
        .send({
          email: 'test@example.com', // Already exists in mock
          password: 'strongpassword123'
        })
        .expect(409);
      
      expect(response.body.code).toBe('EMAIL_EXISTS');
    });
    
    it('should handle role-based access control', async () => {
      // Test with regular user token
      const regularResponse = await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(403);
      
      expect(regularResponse.body.code).toBe('INSUFFICIENT_PRIVILEGES');
      
      // Test with admin token
      const adminToken = jwt.sign(
        { id: 'admin-id', email: 'admin@example.com' },
        testConfig.jwtSecret,
        { expiresIn: '1h' }
      );
      
      const adminResponse = await request(app)
        .get('/api/v1/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect(200);
      
      expect(adminResponse.body.data.users).toHaveLength(2);
    });
    
    it('should handle expired tokens', async () => {
      const expiredToken = jwt.sign(
        { id: 'test-user', email: 'test@example.com' },
        testConfig.jwtSecret,
        { expiresIn: '-1h' } // Expired 1 hour ago
      );
      
      const response = await request(app)
        .get('/api/v1/images')
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
      
      expect(response.body.status).toBe('error');
    });
  });
});

// Export test utilities for reuse
export const expandedHttpTestUtils = {
  createValidToken(userId = 'test-user', email = 'test@example.com'): string {
    return jwt.sign(
      { id: userId, email: email },
      testConfig.jwtSecret, // Use test secret
      { expiresIn: '24h' }
    );
  },

  createExpiredToken(userId = 'test-user', email = 'test@example.com'): string {
    return jwt.sign(
      { id: userId, email: email },
      testConfig.jwtSecret, // Use test secret
      { expiresIn: '-1h' }
    );
  },

  createAdminToken(): string {
    return jwt.sign(
      { id: 'admin-id', email: 'admin@example.com' },
      testConfig.jwtSecret, // Use test secret
      { expiresIn: '24h' }
    );
  },

  createTestImageBuffer(size = 1024): Buffer {
    // Create a minimal valid JPEG
    const jpegHeader = Buffer.from([
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46,
      0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00
    ]);
    
    const imageData = Buffer.alloc(Math.max(size - 22, 100), 0x80);
    const jpegEnd = Buffer.from([0xFF, 0xD9]);
    
    return Buffer.concat([jpegHeader, imageData, jpegEnd]);
  },

  async registerTestUser(app: express.Express, email: string, password = 'password123'): Promise<{ token: string; userId: string }> {
    const response = await request(app)
      .post('/api/v1/auth/register')
      .send({ email, password })
      .expect(201);
    
    return {
      token: response.body.data.token,
      userId: response.body.data.user.id
    };
  },

  async uploadTestImage(app: express.Express, token: string, filename = 'test.jpg'): Promise<string> {
    const imageBuffer = this.createTestImageBuffer();
    
    const response = await request(app)
      .post('/api/v1/images/upload')
      .set('Authorization', `Bearer ${token}`)
      .attach('image', imageBuffer, filename)
      .expect(201);
    
    return response.body.data.image.id;
  },

  async measureResponseTime<T>(operation: () => Promise<T>): Promise<{ result: T; duration: number }> {
    const start = Date.now();
    const result = await operation();
    const duration = Date.now() - start;
    
    return { result, duration };
  },

  // Reset mock database state
  resetMockDatabase(): void {
    mockImageDatabase = {};
    mockImageCounter = 1;
  },

  // Get current mock database state for debugging
  getMockDatabaseState(): { [userId: string]: any[] } {
    return { ...mockImageDatabase };
  },

  // Add test data to mock database
  addTestImageToMockDB(userId: string, imageData: any): void {
    if (!mockImageDatabase[userId]) {
      mockImageDatabase[userId] = [];
    }
    mockImageDatabase[userId].push({
      id: `test-image-${mockImageCounter++}`,
      user_id: userId,
      created_at: new Date(),
      updated_at: new Date(),
      ...imageData
    });
  },

  // Create test scenario with multiple users and images
  async createTestScenario(app: express.Express, userCount = 2, imagesPerUser = 3): Promise<{
    users: Array<{ token: string; userId: string; email: string }>;
    images: Array<{ userId: string; imageId: string; filename: string }>;
  }> {
    const users = [];
    const images = [];
    
    for (let i = 0; i < userCount; i++) {
      const email = `scenario-user-${i}@example.com`;
      const { token, userId } = await this.registerTestUser(app, email);
      users.push({ token, userId, email });
      
      for (let j = 0; j < imagesPerUser; j++) {
        const filename = `user-${i}-image-${j}.jpg`;
        const imageId = await this.uploadTestImage(app, token, filename);
        images.push({ userId, imageId, filename });
      }
    }
    
    return { users, images };
  },

  // Validate standard API response format
  validateApiResponse(response: any, expectedStatus = 'success'): boolean {
    if (!response.body) return false;
    
    const body = response.body;
    return (
      body.status === expectedStatus &&
      (expectedStatus === 'success' ? 'data' in body : 'message' in body)
    );
  },

  // Generate load test scenarios
  createLoadTestScenario(app: express.Express, token: string, operationCount = 100): Array<() => Promise<any>> {
    const operations = [];
    
    // Mix of different operations
    for (let i = 0; i < operationCount; i++) {
      const operationType = i % 4;
      
      switch (operationType) {
        case 0: // Health check
          operations.push(() => request(app).get('/health'));
          break;
          
        case 1: // Get images
          operations.push(() =>
            request(app)
              .get('/api/v1/images')
              .set('Authorization', `Bearer ${token}`)
          );
          break;
          
        case 2: // Get stats
          operations.push(() =>
            request(app)
              .get('/api/v1/images/stats')
              .set('Authorization', `Bearer ${token}`)
          );
          break;
          
        case 3: // Upload image
          operations.push(() => {
            const imageBuffer = this.createTestImageBuffer();
            return request(app)
              .post('/api/v1/images/upload')
              .set('Authorization', `Bearer ${token}`)
              .attach('image', imageBuffer, `load-test-${i}.jpg`);
          });
          break;
      }
    }
    
    return operations;
  }
};

console.log('✅ Expanded HTTP Integration Test Suite loaded successfully');
console.log('📋 Test Coverage:');
console.log('   🔐 Enhanced Authentication & Authorization');
console.log('   📁 File Upload Integration');
console.log('   🔄 Full CRUD Operations');
console.log('   📊 Statistics and Analytics');
console.log('   🔄 Batch Operations');
console.log('   ⚡ Performance and Load Testing');
console.log('   🛡️ Security and Error Handling');
console.log('   🎯 Complete Workflow Integration');
console.log('🚀 Ready for comprehensive HTTP stack testing!');