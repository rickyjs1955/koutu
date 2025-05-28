// backend/src/__tests__/unit/schemas.unit.test.ts
import { beforeEach, describe, it, expect } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';

// Import the actual schemas (no mocking for proper testing)
import {
  CreateGarmentWithBusinessRulesSchema,
  CreatePolygonWithGeometryValidationSchema,
  FileUploadSchema,
} from '../../validators/schemas';

import {
  validateBody,
  validateUUIDParam,
  validateImageQuery,
  validateFile
} from '../../middlewares/validate';

// Import test helpers and data
import {
  mockValidFile,
  mockInvalidFile,
  mockOversizedFile,
  createMockRequest,
  createMockResponse,
  createMockNext,
  generateSchemaTestData,
  validationScenarios
} from '../__mocks__/schemas.mock';

import {
  setupSchemaTestEnvironment,
  createSchemaStressTests,
  testSchemaPerformance
} from '../__helpers__/schemas.helper';

describe('Schema Validation Unit Tests', () => {
  setupSchemaTestEnvironment();

  describe('CreateGarmentWithBusinessRulesSchema', () => {
    it('should validate a complete valid garment', () => {
      const validGarment = generateSchemaTestData.validGarment();
      const result = CreateGarmentWithBusinessRulesSchema.safeParse(validGarment);
      
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.mask_data.width).toBe(200);
        expect(result.data.mask_data.height).toBe(150);
        expect(result.data.mask_data.data.length).toBe(30000);
        expect(result.data.metadata?.type).toBe('jacket');
      }
    });

    it('should reject garment with all-zero mask data', () => {
      const invalidGarment = {
        mask_data: {
          width: 100,
          height: 100,
          data: new Array(10000).fill(0) // All zeros
        },
        metadata: {
          type: 'shirt',
          color: 'blue',
          brand: 'TestBrand',
          tags: ['casual'],
          season: 'summer',
          size: 'M',
          material: 'cotton'
        },
        original_image_id: 'img_123'
      };

      const result = CreateGarmentWithBusinessRulesSchema.safeParse(invalidGarment);
      expect(result.success).toBe(false);
    });

    it('should reject garment with mismatched mask dimensions', () => {
      const invalidGarment = {
        mask_data: {
          width: 100,
          height: 100,
          data: new Array(5000).fill(1) // Wrong length: should be 10000
        },
        metadata: {
          type: 'shirt',
          color: 'blue',
          brand: 'TestBrand',
          tags: ['casual'],
          season: 'summer',
          size: 'M',
          material: 'cotton'
        },
        original_image_id: 'img_123'
      };

      const result = CreateGarmentWithBusinessRulesSchema.safeParse(invalidGarment);
      expect(result.success).toBe(false);
    });

    it('should validate garment with minimal required fields', () => {
      const minimalGarment = {
        mask_data: {
          width: 50,
          height: 50,
          data: new Array(2500).fill(1)
        },
        metadata: {
          type: 'shirt',
          color: 'blue',
          brand: 'TestBrand'
        }
      };

      const result = CreateGarmentWithBusinessRulesSchema.safeParse(minimalGarment);
      expect(result.success).toBe(true);
    });
  });

  describe('CreatePolygonWithGeometryValidationSchema', () => {
    it('should validate a polygon with sufficient area', () => {
      const validPolygon = generateSchemaTestData.validPolygon();
      const result = CreatePolygonWithGeometryValidationSchema.safeParse(validPolygon);
      
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.points.length).toBeGreaterThanOrEqual(3);
        expect(result.data.metadata?.label).toBe('test_polygon');
      }
    });

    it('should reject polygon with area too small', () => {
      const smallPolygon = {
        points: [
          { x: 0, y: 0 },
          { x: 5, y: 0 },
          { x: 5, y: 5 },
          { x: 0, y: 5 }
        ], // Area = 25, below minimum of 100
        metadata: {
          label: 'small_region',
          confidence: 0.8,
          source: 'manual_annotation'
        },
        original_image_id: 'img_456'
      };

      const result = CreatePolygonWithGeometryValidationSchema.safeParse(smallPolygon);
      expect(result.success).toBe(false);
    });

    it('should reject self-intersecting polygon', () => {
      const selfIntersectingPolygon = {
        points: [
          { x: 0, y: 0 },
          { x: 100, y: 100 },
          { x: 100, y: 0 },
          { x: 0, y: 100 }
        ], // Creates an X shape
        metadata: {
          label: 'intersecting_region',
          confidence: 0.7,
          source: 'manual_annotation'
        },
        original_image_id: 'img_456'
      };

      const result = CreatePolygonWithGeometryValidationSchema.safeParse(selfIntersectingPolygon);
      expect(result.success).toBe(false);
    });

    it('should reject polygon with insufficient points', () => {
      const twoPointPolygon = {
        points: [
          { x: 0, y: 0 },
          { x: 10, y: 0 }
        ], // Only 2 points
        metadata: {
          label: 'line_segment',
          confidence: 0.1,
          source: 'manual_annotation'
        },
        original_image_id: 'img_invalid'
      };

      const result = CreatePolygonWithGeometryValidationSchema.safeParse(twoPointPolygon);
      expect(result.success).toBe(false);
    });

    it('should validate complex polygon with many points', () => {
      const complexPolygon = {
        points: [
          { x: 0, y: 0 },
          { x: 50, y: 0 },
          { x: 50, y: 25 },
          { x: 100, y: 25 },
          { x: 100, y: 50 },
          { x: 50, y: 50 },
          { x: 50, y: 75 },
          { x: 0, y: 75 }
        ], // L-shaped polygon with sufficient area
        metadata: {
          label: 'complex_region',
          confidence: 0.9,
          source: 'automated_detection'
        },
        original_image_id: 'img_complex'
      };

      const result = CreatePolygonWithGeometryValidationSchema.safeParse(complexPolygon);
      expect(result.success).toBe(true);
    });
  });

  describe('FileUploadSchema', () => {
    it('should validate a proper JPEG file', () => {
      const validFile = {
        fieldname: 'image',
        originalname: 'photo.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 2048576, // 2MB
        buffer: Buffer.from('fake jpeg data')
      };

      const result = FileUploadSchema.safeParse(validFile);
      expect(result.success).toBe(true);
    });

    it('should validate a proper PNG file', () => {
      const validFile = {
        fieldname: 'image',
        originalname: 'graphic.png',
        encoding: '7bit',
        mimetype: 'image/png',
        size: 1024000, // 1MB
        buffer: Buffer.from('fake png data')
      };

      const result = FileUploadSchema.safeParse(validFile);
      expect(result.success).toBe(true);
    });

    it('should validate a proper WebP file', () => {
      const validFile = {
        fieldname: 'image',
        originalname: 'modern.webp',
        encoding: '7bit',
        mimetype: 'image/webp',
        size: 512000, // 512KB
        buffer: Buffer.from('fake webp data')
      };

      const result = FileUploadSchema.safeParse(validFile);
      expect(result.success).toBe(true);
    });

    it('should reject oversized file', () => {
      const oversizedFile = {
        fieldname: 'image',
        originalname: 'huge.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 6291456, // 6MB - over 5MB limit
        buffer: Buffer.from('fake large data')
      };

      const result = FileUploadSchema.safeParse(oversizedFile);
      expect(result.success).toBe(false);
    });

    it('should reject invalid file type', () => {
      const invalidFile = {
        fieldname: 'image',
        originalname: 'document.pdf',
        encoding: '7bit',
        mimetype: 'application/pdf',
        size: 1024000,
        buffer: Buffer.from('fake pdf data')
      };

      const result = FileUploadSchema.safeParse(invalidFile);
      expect(result.success).toBe(false);
    });

    it('should reject filename that is too long', () => {
      const invalidFile = {
        fieldname: 'image',
        originalname: 'a'.repeat(300) + '.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 1024000,
        buffer: Buffer.from('fake data')
      };

      const result = FileUploadSchema.safeParse(invalidFile);
      expect(result.success).toBe(false);
    });
  });

  describe('Middleware Functions', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;

    beforeEach(() => {
      mockReq = createMockRequest();
      mockRes = createMockResponse();
      mockNext = createMockNext() as jest.MockedFunction<NextFunction>;
    });

    describe('validateUUIDParam', () => {
      it('should accept valid UUID', () => {
        mockReq.params = { id: '123e4567-e89b-12d3-a456-426614174000' };
        
        validateUUIDParam(mockReq as Request, mockRes as Response, mockNext);
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should reject invalid UUID format', () => {
        mockReq.params = { id: 'invalid-uuid-format' };
        
        validateUUIDParam(mockReq as Request, mockRes as Response, mockNext);
        expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
      });

      it('should reject SQL injection attempt', () => {
        mockReq.params = { id: "'; DROP TABLE users; --" };
        
        validateUUIDParam(mockReq as Request, mockRes as Response, mockNext);
        expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
      });
    });

    describe('validateImageQuery', () => {
      it('should handle basic query validation', () => {
        mockReq.query = { limit: '10', offset: '0' };
        
        validateImageQuery(mockReq as Request, mockRes as Response, mockNext);
        expect(mockNext).toHaveBeenCalledWith();
      });
    });

    describe('validateFile', () => {
      it('should accept valid file upload', () => {
        mockReq.file = mockValidFile;
        
        validateFile(mockReq as Request, mockRes as Response, mockNext);
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should reject oversized file', () => {
        mockReq.file = mockOversizedFile;
        
        validateFile(mockReq as Request, mockRes as Response, mockNext);
        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            code: 'INVALID_FILE'
          })
        );
      });

      it('should reject invalid file type', () => {
        mockReq.file = mockInvalidFile;
        
        validateFile(mockReq as Request, mockRes as Response, mockNext);
        expect(mockNext).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400,
            code: 'INVALID_FILE'
          })
        );
      });
    });

    describe('validateBody', () => {
      it('should accept valid garment data', () => {
        const validGarmentData = generateSchemaTestData.validGarment();
        mockReq.body = validGarmentData;
        
        const bodyValidator = validateBody(CreateGarmentWithBusinessRulesSchema);
        bodyValidator(mockReq as Request, mockRes as Response, mockNext);
        
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should reject invalid garment data', () => {
        const invalidGarmentData = {
          mask_data: {
            width: 100,
            height: 100,
            data: new Array(10000).fill(0) // All zeros - invalid
          },
          metadata: {
            type: 'shirt',
            color: 'blue',
            brand: 'TestBrand'
          }
        };
        mockReq.body = invalidGarmentData;
        
        const bodyValidator = validateBody(CreateGarmentWithBusinessRulesSchema);
        bodyValidator(mockReq as Request, mockRes as Response, mockNext);
        
        expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
      });

      it('should accept valid polygon data', () => {
        const validPolygonData = generateSchemaTestData.validPolygon();
        mockReq.body = validPolygonData;
        
        const bodyValidator = validateBody(CreatePolygonWithGeometryValidationSchema);
        bodyValidator(mockReq as Request, mockRes as Response, mockNext);
        
        expect(mockNext).toHaveBeenCalledWith();
      });

      it('should reject polygon with insufficient area', () => {
        const smallPolygonData = {
          points: [
            { x: 0, y: 0 },
            { x: 5, y: 0 },
            { x: 5, y: 5 },
            { x: 0, y: 5 }
          ], // Area = 25, below minimum
          metadata: {
            label: 'small_region',
            confidence: 0.8,
            source: 'manual_annotation'
          },
          original_image_id: 'img_456'
        };
        mockReq.body = smallPolygonData;
        
        const bodyValidator = validateBody(CreatePolygonWithGeometryValidationSchema);
        bodyValidator(mockReq as Request, mockRes as Response, mockNext);
        
        expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
      });
    });
  });

  describe('End-to-End Validation Flow', () => {
    it('should handle complete garment creation workflow', () => {
      const garmentRequest = {
        mask_data: {
          width: 300,
          height: 400,
          data: new Array(120000).fill(1) // Non-zero data
        },
        metadata: {
          type: 'jacket',
          color: 'black',
          brand: 'North Face',
          tags: ['outdoor', 'winter', 'waterproof'],
          season: 'winter',
          size: 'L',
          material: 'polyester'
        },
        original_image_id: 'img_12345',
        processing_notes: 'High quality detection'
      };

      const bodyValidation = CreateGarmentWithBusinessRulesSchema.safeParse(garmentRequest);
      expect(bodyValidation.success).toBe(true);

      if (bodyValidation.success) {
        expect(bodyValidation.data.mask_data.data.length).toBe(
          bodyValidation.data.mask_data.width * bodyValidation.data.mask_data.height
        );

        const nonZeroCount = bodyValidation.data.mask_data.data.filter(val => val > 0).length;
        expect(nonZeroCount).toBeGreaterThan(0);

        expect(bodyValidation.data.metadata).toHaveProperty('type');
        expect(bodyValidation.data.metadata).toHaveProperty('color');
        expect(bodyValidation.data.metadata).toHaveProperty('brand');
      }
    });

    it('should handle complete polygon annotation workflow', () => {
      const polygonRequest = {
        points: [
          { x: 50, y: 50 },
          { x: 150, y: 50 },
          { x: 200, y: 100 },
          { x: 150, y: 150 },
          { x: 50, y: 150 },
          { x: 0, y: 100 }
        ], // Hexagon with area > 100
        metadata: {
          label: 'shirt_front',
          confidence: 0.95,
          source: 'manual_annotation',
          notes: 'Clean polygon boundaries',
          annotator_id: 'annotator_123'
        },
        original_image_id: 'img_67890',
        created_by: 'user_456'
      };

      const polygonValidation = CreatePolygonWithGeometryValidationSchema.safeParse(polygonRequest);
      expect(polygonValidation.success).toBe(true);

      if (polygonValidation.success) {
        const points = polygonValidation.data.points;
        let area = 0;
        for (let i = 0; i < points.length; i++) {
          const j = (i + 1) % points.length;
          area += points[i].x * points[j].y;
          area -= points[j].x * points[i].y;
        }
        area = Math.abs(area / 2);
        expect(area).toBeGreaterThanOrEqual(100);

        expect(points.length).toBeGreaterThanOrEqual(3);
      }
    });

    it('should handle complete file upload and validation workflow', () => {
      const uploadFile = {
        fieldname: 'image',
        originalname: 'fashion-photo.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 3145728, // 3MB
        buffer: Buffer.from('fake jpeg binary data')
      };

      const fileValidation = FileUploadSchema.safeParse(uploadFile);
      expect(fileValidation.success).toBe(true);

      if (fileValidation.success) {
        expect(fileValidation.data.size).toBeLessThanOrEqual(5242880); // 5MB max
        expect(fileValidation.data.mimetype).toMatch(/^image\/(jpeg|png|webp)$/);
        expect(fileValidation.data.originalname.length).toBeLessThanOrEqual(255);
        expect(fileValidation.data.buffer).toBeInstanceOf(Buffer);

        expect(fileValidation.data.originalname).not.toContain('../');
        expect(fileValidation.data.originalname).not.toContain('\\');
      }
    });

    it('should handle complex multi-entity validation scenario', () => {
      const complexRequest = {
        // Garment data
        mask_data: {
          width: 500,
          height: 600,
          data: new Array(300000).fill(0).map((_, i) => 
            (i > 50000 && i < 250000) ? Math.floor(Math.random() * 256) : 1
          ) // Realistic mask with content
        },
        metadata: {
          type: 'dress',
          color: 'floral',
          brand: 'Anthropologie',
          tags: ['summer', 'casual', 'floral-pattern'],
          season: 'summer',
          size: 'M',
          material: 'cotton-blend'
        },
        // Source polygon
        source_polygon: {
          points: [
            { x: 100, y: 150 },
            { x: 400, y: 150 },
            { x: 450, y: 200 },
            { x: 400, y: 450 },
            { x: 100, y: 450 },
            { x: 50, y: 200 }
          ],
          metadata: {
            label: 'dress_region',
            confidence: 0.92,
            source: 'automated_detection'
          },
          original_image_id: 'img_complex_123'
        },
        // Source image
        original_image_id: 'img_complex_123'
      };

      // Step 1: Validate garment data
      const garmentValidation = CreateGarmentWithBusinessRulesSchema.safeParse({
        mask_data: complexRequest.mask_data,
        metadata: complexRequest.metadata,
        original_image_id: complexRequest.original_image_id
      });
      expect(garmentValidation.success).toBe(true);

      // Step 2: Validate polygon data
      const polygonValidation = CreatePolygonWithGeometryValidationSchema.safeParse(
        complexRequest.source_polygon
      );
      expect(polygonValidation.success).toBe(true);

      // Step 3: Cross-validate consistency
      if (garmentValidation.success && polygonValidation.success) {
        const maskArea = garmentValidation.data.mask_data.width * garmentValidation.data.mask_data.height;
        expect(maskArea).toBeGreaterThan(100000); // Reasonable size

        const points = polygonValidation.data.points;
        let polygonArea = 0;
        for (let i = 0; i < points.length; i++) {
          const j = (i + 1) % points.length;
          polygonArea += points[i].x * points[j].y;
          polygonArea -= points[j].x * points[i].y;
        }
        polygonArea = Math.abs(polygonArea / 2);
        expect(polygonArea).toBeGreaterThanOrEqual(100);
      }
    });
  });

  describe('Cross-Schema Validation', () => {
    it('should maintain consistency across related schema validations', () => {
      const imageId = 'img_shared_789';
      
      // Validate file upload for the image
      const imageFile = {
        ...mockValidFile,
        originalname: 'shared-image.jpg'
      };
      const fileValidation = FileUploadSchema.safeParse(imageFile);
      expect(fileValidation.success).toBe(true);

      // Validate polygon referencing the image
      const polygon = {
        points: [
          { x: 0, y: 0 },
          { x: 100, y: 0 },
          { x: 100, y: 100 },
          { x: 0, y: 100 }
        ],
        original_image_id: imageId,
        metadata: {
          source: 'automated_detection',
          confidence: 0.89,
          label: 'test_region'
        }
      };
      const polygonValidation = CreatePolygonWithGeometryValidationSchema.safeParse(polygon);
      expect(polygonValidation.success).toBe(true);

      // Validate garment derived from the polygon
      const garment = {
        mask_data: {
          width: 200,
          height: 200,
          data: new Array(40000).fill(1)
        },
        original_image_id: imageId,
        source_polygon_id: 'poly_456',
        metadata: {
          type: 'shirt',
          color: 'blue',
          brand: 'TestBrand',
          detection_method: 'polygon_based'
        }
      };
      const garmentValidation = CreateGarmentWithBusinessRulesSchema.safeParse(garment);
      expect(garmentValidation.success).toBe(true);

      // Verify all entities reference the same image
      expect(polygon.original_image_id).toBe(imageId);
      expect(garment.original_image_id).toBe(imageId);
    });

    it('should handle batch validation of multiple entities', () => {
      const batchData = {
        garments: [
            generateSchemaTestData.validGarment(),
            generateSchemaTestData.validGarment(),
            generateSchemaTestData.validGarment()
        ],
        polygons: [
            generateSchemaTestData.validPolygon(),
            generateSchemaTestData.validPolygon(),
            generateSchemaTestData.validPolygon()
        ],
        files: validationScenarios.file.valid.slice(0, 2)
        };

      // Validate all garments
      const garmentResults = batchData.garments.map(garment => 
        CreateGarmentWithBusinessRulesSchema.safeParse(garment)
      );
      expect(garmentResults.every(result => result.success)).toBe(true);

      // Validate all polygons
      const polygonResults = batchData.polygons.map(polygon => 
        CreatePolygonWithGeometryValidationSchema.safeParse(polygon)
      );
      expect(polygonResults.every(result => result.success)).toBe(true);

      // Validate all files
      const fileResults = batchData.files.map(file => 
        FileUploadSchema.safeParse(file)
      );
      expect(fileResults.every(result => result.success)).toBe(true);

      // Verify batch processing performance
      expect(garmentResults.length).toBe(3);
      expect(polygonResults.length).toBe(3);
      expect(fileResults.length).toBe(2);
    });
  });

  describe('Error Recovery and Resilience', () => {
    it('should handle partial validation failures gracefully', () => {
      const mixedBatch = [
        generateSchemaTestData.validGarment(),
        {
          mask_data: {
            width: 100,
            height: 100,
            data: new Array(10000).fill(0) // All zeros - invalid
          },
          metadata: {
            type: 'shirt',
            color: 'blue',
            brand: 'TestBrand'
          }
        },
        generateSchemaTestData.validGarment(),
        {
          mask_data: null, // Completely invalid
          metadata: 'not an object'
        },
        generateSchemaTestData.validGarment()
      ];

      const results = mixedBatch.map((data, index) => {
        try {
          return {
            index,
            result: CreateGarmentWithBusinessRulesSchema.safeParse(data),
            error: null
          };
        } catch (error) {
          return {
            index,
            result: null,
            error: error
          };
        }
      });

      // Should process all items without throwing
      expect(results).toHaveLength(5);
      
      // Valid items should pass
      expect(results[0].result?.success).toBe(true);
      expect(results[2].result?.success).toBe(true);
      expect(results[4].result?.success).toBe(true);
      
      // Invalid items should fail gracefully
      expect(results[1].result?.success).toBe(false);
      expect(results[3].result?.success).toBe(false);
    });

    it('should provide meaningful error context for debugging', () => {
      const invalidData = {
        mask_data: {
          width: 100,
          height: 100,
          data: new Array(5000).fill(0) // Wrong length AND all zeros
        },
        metadata: {
          type: '', // Empty required field
          color: null, // Null value
          brand: undefined // Undefined value
        }
      };

      const result = CreateGarmentWithBusinessRulesSchema.safeParse(invalidData);
      expect(result.success).toBe(false);

      if (!result.success) {
        expect(result.error.issues.length).toBeGreaterThan(0);
        
        // Should have specific error paths
        const errorPaths = result.error.issues.map(issue => issue.path.join('.'));
        const hasRelevantPath = errorPaths.some(path => 
        path.includes('mask_data') || 
        path.includes('metadata') || 
        path === 'mask_data.data' ||
        path === 'metadata.type'
        );
        expect(hasRelevantPath).toBe(true);
        
        // Should have descriptive messages
        const errorMessages = result.error.issues.map(issue => issue.message);
        expect(errorMessages.some(msg => msg.length > 10)).toBe(true);
      }
    });
  });

  // Include stress tests and performance tests
  createSchemaStressTests((data: any) => {
    return CreateGarmentWithBusinessRulesSchema.safeParse(data);
  });

  testSchemaPerformance(
    (data: any) => CreateGarmentWithBusinessRulesSchema.safeParse(data),
    (size: number) => generateSchemaTestData.validGarment()
  );
});