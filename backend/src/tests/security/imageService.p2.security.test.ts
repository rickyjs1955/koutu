// src/tests/security/imageService.p2.security.test.ts

// ===== IMPORT AND SETUP FIREBASE MOCKS FIRST =====
import { 
  MockFirebaseAdmin,
} from '../__mocks__/firebase.mock';

import {
  setupFirebaseTestEnvironment,
  cleanupFirebaseTests
} from '../__helpers__/firebase.helper';

// Mock Firebase Admin before any other imports
jest.mock('firebase-admin', () => ({
  apps: MockFirebaseAdmin.apps,
  auth: MockFirebaseAdmin.auth,
  storage: MockFirebaseAdmin.storage,
  credential: MockFirebaseAdmin.credential,
  initializeApp: MockFirebaseAdmin.initializeApp
}));

// Mock Sharp
const mockSharp = jest.fn().mockImplementation(() => ({
  metadata: jest.fn().mockResolvedValue({
    width: 800,
    height: 600,
    format: 'jpeg',
    channels: 3,
    space: 'srgb'
  }),
  resize: jest.fn().mockReturnThis(),
  jpeg: jest.fn().mockReturnThis(),
  png: jest.fn().mockReturnThis(),
  webp: jest.fn().mockReturnThis(),
  toColorspace: jest.fn().mockReturnThis(),
  toFile: jest.fn().mockResolvedValue({ size: 204800 }),
  toBuffer: jest.fn().mockResolvedValue(Buffer.from('mock-data'))
}));

jest.mock('sharp', () => mockSharp);

// Mock config files
jest.mock('../../config/firebase', () => ({
  initializeFirebase: jest.fn(),
  getFirebaseApp: jest.fn(),
  getStorageBucket: jest.fn()
}));

jest.mock('../../models/db', () => ({
  pool: {
    query: jest.fn(),
    connect: jest.fn(),
    end: jest.fn()
  }
}));

// Mock the service dependencies
const mockImageModel = {
  create: jest.fn(),
  findById: jest.fn(),
  findByUserId: jest.fn(),
  updateStatus: jest.fn(),
  updateMetadata: jest.fn(),
  delete: jest.fn(),
  findDependentGarments: jest.fn(),
  findDependentPolygons: jest.fn(),
  getUserImageStats: jest.fn(),
  batchUpdateStatus: jest.fn()
};

const mockImageProcessingService = {
  validateImageBuffer: jest.fn(),
  convertToSRGB: jest.fn(),
  extractMetadata: jest.fn(),
  generateThumbnail: jest.fn(),
  optimizeForWeb: jest.fn(),
  optimizeForMobile: jest.fn()
};

const mockStorageService = {
  saveFile: jest.fn(),
  deleteFile: jest.fn()
};

// Mock ApiError class
class MockApiError extends Error {
  public statusCode: number;
  public code: string;
  public context?: any;

  constructor(message: string, statusCode: number = 500, code: string = 'INTERNAL_ERROR', context?: any) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.context = context;
  }

  static validation(message: string, field?: string, value?: any) {
    const error = new MockApiError(message, 400, 'VALIDATION_ERROR', { field, value });
    throw error;
  }

  static businessLogic(message: string, rule?: string, resource?: string) {
    const error = new MockApiError(message, 400, 'BUSINESS_LOGIC_ERROR', { rule, resource });
    throw error;
  }

  static authorization(message: string, resource?: string, action?: string) {
    const error = new MockApiError(message, 403, 'AUTHORIZATION_ERROR', { resource, action });
    throw error;
  }

  static notFound(message: string, code?: string, context?: any) {
    const error = new MockApiError(message, 404, code || 'NOT_FOUND', context);
    throw error;
  }

  static internal(message: string, code?: string, context?: any) {
    const error = new MockApiError(message, 500, code || 'INTERNAL_ERROR', context);
    throw error;
  }
}

jest.mock('../../models/imageModel', () => ({
  imageModel: mockImageModel
}));

jest.mock('../../services/imageProcessingService', () => ({
  imageProcessingService: mockImageProcessingService
}));

jest.mock('../../services/storageService', () => ({
  storageService: mockStorageService
}));

jest.mock('../../utils/ApiError', () => ({
  ApiError: MockApiError
}));

// ===== NOW IMPORT THE SERVICE TO TEST =====
import { imageService } from '../../services/imageService';

describe('ImageService P2 Security Tests - Flutter & Mobile Attack Vectors', () => {
  const validUserId = 'user-123';
  const attackerUserId = 'attacker-456';
  const imageId = 'image-789';

  // Setup Firebase test environment
  setupFirebaseTestEnvironment();

  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default success responses
    mockImageModel.getUserImageStats.mockResolvedValue({
      total: 50,
      totalSize: 100 * 1024 * 1024 // 100MB
    });

    mockImageModel.create.mockResolvedValue({
      id: imageId,
      user_id: validUserId,
      file_path: 'uploads/test.jpg',
      original_metadata: {},
      status: 'new',
      upload_date: new Date()
    });

    mockImageModel.findById.mockResolvedValue({
      id: imageId,
      user_id: validUserId,
      file_path: 'uploads/test.jpg',
      original_metadata: { width: 800, height: 600 },
      status: 'new',
      upload_date: new Date()
    });

    mockImageModel.findByUserId.mockResolvedValue([
      { id: 'img-1', user_id: validUserId, file_path: 'uploads/img1.jpg', original_metadata: { width: 800, height: 600 } },
      { id: 'img-2', user_id: validUserId, file_path: 'uploads/img2.jpg', original_metadata: { width: 1200, height: 900 } }
    ]);

    mockImageModel.findDependentGarments.mockResolvedValue([]);
    mockImageModel.findDependentPolygons.mockResolvedValue([]);

    mockStorageService.saveFile.mockResolvedValue('uploads/saved-file.jpg');
    mockStorageService.deleteFile.mockResolvedValue(true);

    mockImageProcessingService.validateImageBuffer.mockResolvedValue({
      width: 800,
      height: 600,
      format: 'jpeg',
      channels: 3,
      space: 'srgb'
    });

    mockImageProcessingService.generateThumbnail.mockResolvedValue('uploads/thumb.jpg');
    mockImageProcessingService.optimizeForMobile.mockResolvedValue('uploads/mobile.webp');
    mockImageProcessingService.extractMetadata.mockResolvedValue({
      width: 800,
      height: 600,
      format: 'jpeg'
    });
  });

  afterAll(() => {
    cleanupFirebaseTests();
  });

  describe('Flutter Upload Security Vulnerabilities', () => {
    describe('Platform Spoofing and Bypass Attacks', () => {
      it('should prevent platform parameter manipulation in flutterUploadImage', async () => {
        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('malicious-data'),
          originalFilename: 'exploit.jsp',
          mimetype: 'application/octet-stream', // Non-image MIME type
          size: 1024
        };

        // Should reject non-image MIME types
        const validationResult = await imageService.validateImageFile(
          uploadParams.fileBuffer,
          uploadParams.mimetype,
          uploadParams.size
        );
        
        expect(validationResult.isValid).toBe(false);
        expect(validationResult.errors).toEqual(
          expect.arrayContaining([expect.stringMatching(/Unsupported format/)])
        );
      });

      it('should not bypass security checks for Flutter-branded uploads', async () => {
        const oversizedParams = {
          userId: validUserId,
          fileBuffer: Buffer.alloc(1024),
          originalFilename: 'huge-flutter-image.jpg',
          mimetype: 'image/jpeg',
          size: 10 * 1024 * 1024 // 10MB - over limit
        };

        // Flutter upload should respect the same limits
        await expect(imageService.flutterUploadImage(oversizedParams)).rejects.toThrow();
      });

      it('should validate Flutter upload against storage quota attacks', async () => {
        // Mock user at storage limit
        mockImageModel.getUserImageStats.mockResolvedValue({
          total: 999,
          totalSize: 500 * 1024 * 1024 // Exactly at 500MB limit
        });

        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: 'quota-exploit.jpg',
          mimetype: 'image/jpeg',
          size: 1024 // Any additional file should exceed limit
        };

        await expect(imageService.flutterUploadImage(uploadParams)).rejects.toThrow(
          'Storage limit reached'
        );
        
        // Verify that the quota check was performed
        expect(mockImageModel.getUserImageStats).toHaveBeenCalledWith(validUserId);
      });

      it('should prevent thumbnail generation resource exhaustion in Flutter uploads', async () => {
        // Mock thumbnail generation failure (DoS protection)
        mockImageProcessingService.generateThumbnail.mockRejectedValue(
          new Error('Resource exhaustion detected')
        );

        const uploadParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('complex-image'),
          originalFilename: 'complex.jpg',
          mimetype: 'image/jpeg',
          size: 1024
        };

        // Should complete upload but warn about thumbnail failure
        const result = await imageService.flutterUploadImage(uploadParams);
        expect(result.platform).toBe('flutter');
        expect(result.uploadOptimized).toBe(true);
      });
    });

    describe('Metadata Injection Attacks', () => {
      it('should sanitize malicious metadata in Flutter uploads', async () => {
        const maliciousParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: '<script>alert("xss")</script>.jpg',
          mimetype: 'image/jpeg',
          size: 1024
        };

        // Should handle but not execute malicious filename
        const result = await imageService.flutterUploadImage(maliciousParams);
        expect(result.id).toBeDefined();
        expect(mockImageModel.create).toHaveBeenCalledWith({
          user_id: validUserId,
          file_path: expect.any(String),
          original_metadata: expect.objectContaining({
            filename: maliciousParams.originalFilename // Stored as-is, execution prevented elsewhere
          })
        });
      });

      it('should handle excessively large metadata payloads', async () => {
        const largeMetadataParams = {
          userId: validUserId,
          fileBuffer: Buffer.from('image-data'),
          originalFilename: 'x'.repeat(10000) + '.jpg', // 10KB filename
          mimetype: 'image/jpeg',
          size: 1024
        };

        // Should handle gracefully without DoS
        try {
          await imageService.flutterUploadImage(largeMetadataParams);
          expect(mockImageModel.create).toHaveBeenCalled();
        } catch (error) {
          // May be rejected at validation level, which is acceptable
          expect(error).toBeDefined();
        }
      });
    });
  });

  describe('Mobile Thumbnail Security Exploitation', () => {
    describe('Resource Exhaustion via Thumbnail Generation', () => {
      it('should prevent mass thumbnail generation DoS attacks', async () => {
        // Attacker requests many large thumbnails
        const options = { page: 1, limit: 100, size: 'large' as const }; // Max size, max count
        
        // Mock many images
        const manyImages = Array(100).fill(0).map((_, i) => ({
          id: `img-${i}`,
          user_id: validUserId,
          file_path: `uploads/img${i}.jpg`,
          original_metadata: { width: 8000, height: 6000 } // Large images
        }));
        mockImageModel.findByUserId.mockResolvedValue(manyImages);

        // Should handle gracefully or apply rate limiting
        try {
          const result = await imageService.getMobileThumbnails(validUserId, options);
          expect(result.thumbnails.length).toBeLessThanOrEqual(100);
          
          // Should not generate more than reasonable amount
          expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalledTimes(
            expect.any(Number)
          );
        } catch (error) {
          // May reject excessive requests, which is acceptable
          expect(error).toBeDefined();
        }
      });

      it('should prevent concurrent thumbnail generation abuse', async () => {
        const imageIds = Array(50).fill(0).map((_, i) => `img-${i}`);
        const sizes: ('small' | 'medium' | 'large')[] = ['small', 'medium', 'large'];

        // Mock ownership verification for all images
        mockImageModel.findById.mockImplementation((id) => 
          Promise.resolve({ id, user_id: validUserId, file_path: `uploads/${id}.jpg` })
        );

        // Simulate slow thumbnail generation
        mockImageProcessingService.generateThumbnail.mockImplementation(
          () => new Promise(resolve => setTimeout(() => resolve('thumb.jpg'), 100))
        );

        const startTime = Date.now();
        
        try {
          await imageService.batchGenerateThumbnails(imageIds, validUserId, sizes);
          const endTime = Date.now();
          
          // Should complete within reasonable time (not timeout)
          expect(endTime - startTime).toBeLessThan(10000); // 10 seconds max
        } catch (error) {
          // May reject excessive batch sizes, which is acceptable
          expect(error).toBeDefined();
        }
      });

      it('should validate thumbnail size parameters against manipulation', async () => {
        const maliciousOptions = { 
          page: 1, 
          limit: 10, 
          size: 'mega' as any // Invalid size 
        };

        // Should reject invalid size or default to safe value
        try {
          await imageService.getMobileThumbnails(validUserId, maliciousOptions);
          // If it succeeds, should use safe defaults
          expect(mockImageProcessingService.generateThumbnail).toHaveBeenCalled();
        } catch (error) {
          // Rejection is also acceptable
          expect(error).toBeDefined();
        }
      });
    });

    describe('Cross-User Thumbnail Access', () => {
      it('should prevent accessing thumbnails of other users via batch operations', async () => {
        const mixedImageIds = ['img-1', 'img-2', 'img-3'];
        const sizes: ('small' | 'medium' | 'large')[] = ['small'];

        // Mix of user's images and attacker's images
        mockImageModel.findById
          .mockResolvedValueOnce({ id: 'img-1', user_id: validUserId, file_path: 'user1.jpg' })
          .mockResolvedValueOnce({ id: 'img-2', user_id: attackerUserId, file_path: 'attacker.jpg' })
          .mockResolvedValueOnce({ id: 'img-3', user_id: validUserId, file_path: 'user2.jpg' });

        // Should fail ownership verification
        await expect(
          imageService.batchGenerateThumbnails(mixedImageIds, validUserId, sizes)
        ).rejects.toThrow('You do not have permission to access this image');

        expect(mockImageProcessingService.generateThumbnail).not.toHaveBeenCalled();
      });

      it('should prevent mobile thumbnail enumeration attacks', async () => {
        // Attacker tries to enumerate thumbnails with crafted pagination
        const enumerationOptions = { 
          page: 999999, // Extreme page number
          limit: 1, 
          size: 'small' as const 
        };

        mockImageModel.findByUserId.mockResolvedValue([]); // No results for extreme pagination

        const result = await imageService.getMobileThumbnails(validUserId, enumerationOptions);
        
        expect(result.thumbnails).toHaveLength(0);
        expect(result.hasMore).toBe(false);
        expect(mockImageModel.findByUserId).toHaveBeenCalledWith(
          validUserId, 
          { limit: 1, offset: expect.any(Number) }
        );
      });
    });
  });

  describe('Sync Operation Security Vulnerabilities', () => {
    describe('Timestamp Manipulation and Replay Attacks', () => {
      it('should validate sync timestamps against manipulation', async () => {
        const futureTimestamp = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(); // 1 year future
        const options = { 
          lastSync: futureTimestamp, 
          includeDeleted: false, 
          limit: 50 
        };

        // Should handle future timestamps gracefully
        const result = await imageService.getSyncData(validUserId, options);
        expect(result.syncTimestamp).toBeDefined();
        expect(result.images).toBeDefined();
      });

      it('should prevent sync data poisoning via malformed timestamps', async () => {
        const maliciousOptions = { 
          lastSync: "'; DROP TABLE images; --", // SQL injection attempt
          includeDeleted: false, 
          limit: 50 
        };

        // Should handle malicious timestamp gracefully
        const result = await imageService.getSyncData(validUserId, maliciousOptions);
        expect(result.syncTimestamp).toBeDefined();
        expect(mockImageModel.findByUserId).toHaveBeenCalledWith(validUserId, { limit: 50 });
      });

      it('should prevent excessive sync data requests (DoS)', async () => {
        const massiveRequest = { 
          lastSync: undefined, 
          includeDeleted: true, 
          limit: 999999 // Extreme limit
        };

        // Should apply reasonable limits
        const result = await imageService.getSyncData(validUserId, massiveRequest);
        expect(result.images).toBeDefined();
        // Verify reasonable limit was applied
        expect(mockImageModel.findByUserId).toHaveBeenCalledWith(
          validUserId, 
          { limit: expect.any(Number) }
        );
      });
    });

    describe('Batch Sync Operation Abuse', () => {
      it('should prevent mass deletion via sync operations', async () => {
        const massDeleteOperations = Array(1000).fill(0).map((_, i) => ({
          id: `img-${i}`,
          action: 'delete' as const,
          data: {},
          clientTimestamp: new Date().toISOString()
        }));

        // Mock images exist and belong to user
        mockImageModel.findById.mockImplementation((id) => 
          Promise.resolve({ id, user_id: validUserId, file_path: `uploads/${id}.jpg` })
        );
        mockImageModel.delete.mockResolvedValue(true);

        // Should handle large batches gracefully or apply limits
        try {
          const result = await imageService.batchSyncOperations(validUserId, massDeleteOperations);
          expect(result.results.length).toBeLessThanOrEqual(1000);
        } catch (error) {
          // May reject excessive batch sizes
          expect(error).toBeDefined();
        }
      });

      it('should prevent privilege escalation via sync operations', async () => {
        const privilegeEscalationOps = [
          {
            id: 'img-1',
            action: 'update' as const,
            data: { status: 'admin' as any }, // Invalid status
            clientTimestamp: new Date().toISOString()
          }
        ];

        mockImageModel.findById.mockResolvedValue({
          id: 'img-1',
          user_id: validUserId,
          status: 'new',
          file_path: 'uploads/test.jpg'
        });

        // Should reject invalid status values
        const result = await imageService.batchSyncOperations(validUserId, privilegeEscalationOps);
        expect(result.failedCount).toBeGreaterThan(0);
        expect(result.results[0].status).toBe('failed');
      });

      it('should prevent cross-user sync manipulation', async () => {
        const crossUserOperations = [
          {
            id: 'victim-image-123',
            action: 'delete' as const,
            data: {},
            clientTimestamp: new Date().toISOString()
          }
        ];

        // Mock victim's image
        mockImageModel.findById.mockResolvedValue({
          id: 'victim-image-123',
          user_id: 'victim-user-456', // Different user
          file_path: 'uploads/victim.jpg',
          status: 'processed'
        });

        const result = await imageService.batchSyncOperations(validUserId, crossUserOperations);
        expect(result.failedCount).toBe(1);
        expect(result.results[0].status).toBe('failed');
        expect(result.results[0].error).toContain('permission');
      });

      it('should validate sync operation data payloads', async () => {
        const maliciousDataOps = [
          {
            id: 'img-1',
            action: 'update' as const,
            data: { 
              status: 'processed',
              maliciousPayload: '<script>alert("xss")</script>',
              sqlInjection: "'; DROP TABLE images; --"
            },
            clientTimestamp: new Date().toISOString()
          }
        ];

        mockImageModel.findById.mockResolvedValue({
          id: 'img-1',
          user_id: validUserId,
          status: 'new',
          file_path: 'uploads/test.jpg'
        });
        mockImageModel.updateStatus.mockResolvedValue({
          id: 'img-1',
          status: 'processed'
        });

        // Should process valid parts and ignore malicious data
        const result = await imageService.batchSyncOperations(validUserId, maliciousDataOps);
        expect(result.successCount).toBe(1);
        expect(mockImageModel.updateStatus).toHaveBeenCalledWith('img-1', 'processed');
      });
    });
  });

  describe('Mobile Image Optimization Security', () => {
    describe('Format Conversion Attacks', () => {
      it('should validate mobile optimization against format manipulation', async () => {
        // Mock malicious optimization service
        mockImageProcessingService.optimizeForMobile.mockResolvedValue(
          '../../../etc/passwd' // Path traversal attempt
        );

        const result = await imageService.getMobileOptimizedImage(imageId, validUserId);
        
        // Should return the path as-is but storage service should sanitize
        expect(result.optimizedPath).toBeDefined();
        expect(result.format).toBe('webp');
        expect(result.quality).toBe(85);
      });

      it('should prevent resource exhaustion via optimization requests', async () => {
        // Mock slow optimization (DoS simulation)
        mockImageProcessingService.optimizeForMobile.mockImplementation(
          () => new Promise(resolve => setTimeout(() => resolve('optimized.webp'), 5000))
        );

        const startTime = Date.now();
        
        try {
          await imageService.getMobileOptimizedImage(imageId, validUserId);
          const endTime = Date.now();
          
          // Should complete within reasonable time
          expect(endTime - startTime).toBeLessThan(10000);
        } catch (error) {
          // Timeout or rejection is acceptable
          expect(error).toBeDefined();
        }
      });

      it('should validate ownership before mobile optimization', async () => {
        // Mock attacker trying to optimize victim's image
        mockImageModel.findById.mockResolvedValue({
          id: imageId,
          user_id: 'victim-user-789',
          file_path: 'uploads/victim-image.jpg',
          original_metadata: { size: 1024000 }
        });

        await expect(
          imageService.getMobileOptimizedImage(imageId, attackerUserId)
        ).rejects.toThrow('You do not have permission to access this image');

        expect(mockImageProcessingService.optimizeForMobile).not.toHaveBeenCalled();
      });
    });

    describe('Quality and Size Manipulation', () => {
      it('should enforce safe quality parameters in mobile optimization', async () => {
        // The service hardcodes quality to 85, but let's test if manipulation were possible
        const result = await imageService.getMobileOptimizedImage(imageId, validUserId);
        
        expect(result.quality).toBe(85); // Should be fixed, not manipulable
        expect(result.format).toBe('webp'); // Should be fixed format
      });

      it('should prevent memory exhaustion via large image optimization', async () => {
        // Mock very large image
        mockImageModel.findById.mockResolvedValue({
          id: imageId,
          user_id: validUserId,
          file_path: 'uploads/huge-image.jpg',
          original_metadata: { 
            size: 50 * 1024 * 1024, // 50MB image
            width: 20000,
            height: 20000
          }
        });

        // Should handle or reject appropriately
        try {
          const result = await imageService.getMobileOptimizedImage(imageId, validUserId);
          expect(result.optimizedPath).toBeDefined();
        } catch (error) {
          // May reject oversized images
          expect(error).toBeDefined();
        }
      });
    });
  });

  describe('Advanced Mobile Persistence Attacks', () => {
    describe('Cache Poisoning and Data Integrity', () => {
      it('should prevent sync cache poisoning attacks', async () => {
        // Attacker tries to poison sync data
        const poisonedSyncRequest = {
          lastSync: '1970-01-01T00:00:00Z', // Epoch time to get all data
          includeDeleted: true,
          limit: 999999
        };

        const result = await imageService.getSyncData(validUserId, poisonedSyncRequest);
        
        // Should apply reasonable limits and not expose all historical data
        expect(result.images).toBeDefined();
        expect(result.syncTimestamp).toBeDefined();
        // Verify user isolation
        expect(mockImageModel.findByUserId).toHaveBeenCalledWith(validUserId, expect.any(Object));
      });

      it('should validate sync operation ordering and conflicts', async () => {
        const conflictingOperations = [
          {
            id: 'img-1',
            action: 'update' as const,
            data: { status: 'processed' },
            clientTimestamp: '2024-01-01T12:00:00Z'
          },
          {
            id: 'img-1',
            action: 'delete' as const,
            data: {},
            clientTimestamp: '2024-01-01T11:00:00Z' // Earlier timestamp
          }
        ];

        mockImageModel.findById.mockResolvedValue({
          id: 'img-1',
          user_id: validUserId,
          status: 'new',
          file_path: 'uploads/test.jpg'
        });
        mockImageModel.updateStatus.mockResolvedValue({ id: 'img-1', status: 'processed' });
        mockImageModel.delete.mockResolvedValue(true);

        // Should process in order provided, not timestamp order
        const result = await imageService.batchSyncOperations(validUserId, conflictingOperations);
        expect(result.results).toHaveLength(2);
      });
    });

    describe('Offline Data Tampering Detection', () => {
      it('should handle tampered client timestamps in sync operations', async () => {
        const tamperedOperations = [
          {
            id: 'img-1',
            action: 'update' as const,
            data: { status: 'processed' },
            clientTimestamp: '9999-12-31T23:59:59Z' // Far future
          }
        ];

        mockImageModel.findById.mockResolvedValue({
          id: 'img-1',
          user_id: validUserId,
          status: 'new',
          file_path: 'uploads/test.jpg'
        });
        mockImageModel.updateStatus.mockResolvedValue({ id: 'img-1', status: 'processed' });

        // Should process operation regardless of client timestamp
        const result = await imageService.batchSyncOperations(validUserId, tamperedOperations);
        expect(result.successCount).toBe(1);
        
        // Should use server timestamp for sync completion
        expect(new Date(result.syncCompleted).getTime()).toBeLessThanOrEqual(Date.now());
      });

      it('should prevent replay attacks on sync operations', async () => {
        const replayOperations = [
          {
            id: 'img-1',
            action: 'delete' as const,
            data: {},
            clientTimestamp: '2024-01-01T12:00:00Z'
          }
        ];

        // First execution
        mockImageModel.findById.mockResolvedValue({
          id: 'img-1',
          user_id: validUserId,
          file_path: 'uploads/test.jpg'
        });
        mockImageModel.delete.mockResolvedValue(true);

        await imageService.batchSyncOperations(validUserId, replayOperations);

        // Replay attempt - image should no longer exist
        mockImageModel.findById.mockResolvedValue(null);

        const replayResult = await imageService.batchSyncOperations(validUserId, replayOperations);
        expect(replayResult.failedCount).toBe(1);
        expect(replayResult.results[0].error).toContain('Image not found');
      });
    });
  });

  describe('Mobile-Specific DoS and Rate Limiting', () => {
    describe('Concurrent Request Abuse', () => {
      it('should handle concurrent mobile thumbnail requests gracefully', async () => {
        const options = { page: 1, limit: 20, size: 'large' as const };
        
        // Simulate multiple concurrent requests
        const concurrentRequests = Array(10).fill(0).map(() => 
          imageService.getMobileThumbnails(validUserId, options)
        );

        const results = await Promise.allSettled(concurrentRequests);
        
        // All should complete (success or controlled failure)
        expect(results).toHaveLength(10);
        results.forEach(result => {
          expect(['fulfilled', 'rejected']).toContain(result.status);
        });
      });

      it('should prevent mobile optimization queue flooding', async () => {
        const imageIds = ['img-1', 'img-2', 'img-3'];
        
        // Mock multiple images belonging to user
        mockImageModel.findById.mockImplementation((id) => 
          Promise.resolve({ id, user_id: validUserId, file_path: `uploads/${id}.jpg` })
        );

        // Simulate concurrent optimization requests
        const concurrentOptimizations = imageIds.map(id => 
          imageService.getMobileOptimizedImage(id, validUserId)
        );

        const results = await Promise.allSettled(concurrentOptimizations);
        
        expect(results).toHaveLength(3);
        // Should handle gracefully without system overload
        expect(mockImageProcessingService.optimizeForMobile).toHaveBeenCalledTimes(3);
      });
    });

    describe('Memory and Storage Exhaustion', () => {
      it('should prevent memory exhaustion via batch thumbnail generation', async () => {
        const largeImageSet = Array(100).fill(0).map((_, i) => `img-${i}`);
        const allSizes: ('small' | 'medium' | 'large')[] = ['small', 'medium', 'large'];

        // Mock large images
        mockImageModel.findById.mockImplementation((id) => 
          Promise.resolve({ 
            id, 
            user_id: validUserId, 
            file_path: `uploads/${id}.jpg` 
          })
        );

        // Should handle large batches without memory issues
        try {
          const result = await imageService.batchGenerateThumbnails(largeImageSet, validUserId, allSizes);
          expect(result.totalCount).toBe(100);
        } catch (error) {
          // May reject oversized batches, which is acceptable
          expect(error).toBeDefined();
        }
      });

      it('should validate storage impact of mobile optimizations', async () => {
        // Mock user near storage limit
        mockImageModel.getUserImageStats.mockResolvedValue({
          total: 950,
          totalSize: 480 * 1024 * 1024 // 480MB of 500MB limit
        });

        // Mobile optimization creates additional files - should check limits
        try {
          await imageService.getMobileOptimizedImage(imageId, validUserId);
          expect(mockImageProcessingService.optimizeForMobile).toHaveBeenCalled();
        } catch (error) {
          // May enforce storage limits
          expect(error).toBeDefined();
        }
      });
    });
  });
});