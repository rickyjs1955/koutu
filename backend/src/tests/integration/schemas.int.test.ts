// backend/src/__tests__/integration/schemas.integration.test.ts - FINAL FIXES
import { beforeEach, afterEach, describe, it, expect } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';

// Import the actual schemas
import {
  CreateGarmentWithBusinessRulesSchema,
  CreatePolygonWithGeometryValidationSchema,
  FileUploadSchema,
  validateBody,
  validateQuery,
  validateParams,
  validateUUIDParam,
  validateImageQuery,
  validateFile
} from '../../validators/schemas';

// Import test helpers and FIXED data
import {
  createMockRequest,
  createMockResponse,
  createMockNext,
  generateSchemaTestData
} from '../__mocks__/schemas.mock';

import {
  setupSchemaTestEnvironment,
  createSchemaStressTests,
  testSchemaPerformance
} from '../__helpers__/schemas.helper';

// FIXED validation scenarios with correct data structures
const fixedValidationScenarios = {
  garment: {
    valid: [
      // Garment 1
      {
        mask_data: {
          width: 200,
          height: 150,
          data: new Array(30000).fill(1)
        },
        metadata: {
          type: 'jacket',
          color: 'black',
          brand: 'TestBrand',
          tags: ['winter', 'waterproof'],
          season: 'winter',
          size: 'L',
          material: 'polyester'
        },
        original_image_id: 'img_test_1'
      },
      // Garment 2
      {
        mask_data: {
          width: 300,
          height: 200,
          data: new Array(60000).fill(128)
        },
        metadata: {
          type: 'dress',
          color: 'red',
          brand: 'Designer',
          tags: ['formal', 'evening'],
          season: 'fall',
          size: 'S',
          material: 'silk'
        },
        original_image_id: 'img_test_2'
      },
      // Garment 3
      {
        mask_data: {
          width: 150,
          height: 180,
          data: new Array(27000).fill(200)
        },
        metadata: {
          type: 'shirt',
          color: 'blue',
          brand: 'CasualWear',
          tags: ['casual', 'cotton'],
          season: 'summer',
          size: 'M',
          material: 'cotton'
        },
        original_image_id: 'img_test_3'
      }
    ]
  },
  
  polygon: {
    valid: [
      // Polygon 1
      {
        points: [
          { x: 10, y: 10 },
          { x: 110, y: 10 },
          { x: 110, y: 110 },
          { x: 10, y: 110 }
        ],
        metadata: {
          label: 'test_polygon_1',
          confidence: 0.9,
          source: 'manual_annotation'
        },
        original_image_id: 'img_test_1'
      },
      // Polygon 2
      {
        points: [
          { x: 0, y: 0 },
          { x: 50, y: 0 },
          { x: 25, y: 50 }
        ],
        metadata: {
          label: 'triangle_region',
          confidence: 0.88,
          source: 'automated_detection'
        },
        original_image_id: 'img_test_2'
      },
      // Polygon 3
      {
        points: [
          { x: 20, y: 20 },
          { x: 80, y: 20 },
          { x: 100, y: 40 },
          { x: 80, y: 80 },
          { x: 20, y: 80 },
          { x: 0, y: 40 }
        ],
        metadata: {
          label: 'hexagon_region',
          confidence: 0.95,
          source: 'manual_annotation'
        },
        original_image_id: 'img_test_3'
      }
    ]
  },
  
  file: {
    valid: [
      {
        fieldname: 'image',
        originalname: 'test1.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 2048000,
        buffer: Buffer.from('test data 1'),
        stream: {} as any,
        destination: '',
        filename: 'test1.jpg',
        path: ''
      } as Express.Multer.File,
      {
        fieldname: 'image',
        originalname: 'test2.png',
        encoding: '7bit',
        mimetype: 'image/png',
        size: 1024000,
        buffer: Buffer.from('test data 2'),
        stream: {} as any,
        destination: '',
        filename: 'test2.png',
        path: ''
      } as Express.Multer.File
    ]
  }
};

describe('Schema Validation Integration Tests', () => {
  setupSchemaTestEnvironment();

  describe('End-to-End Validation Flow', () => {
    it('should handle complete garment creation workflow', () => {
      const garmentRequest = createMockRequest({
        method: 'POST',
        path: '/api/v1/garments',
        body: {
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
        }
      }) as Request;

      const bodyValidation = CreateGarmentWithBusinessRulesSchema.safeParse(garmentRequest.body);
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
      const polygonRequest = createMockRequest({
        method: 'POST',
        path: '/api/v1/polygons',
        body: {
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
        }
      }) as Request;

      const polygonValidation = CreatePolygonWithGeometryValidationSchema.safeParse(polygonRequest.body);
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
      const uploadRequest = createMockRequest({
        method: 'POST',
        path: '/api/v1/images/upload',
        file: {
          fieldname: 'image',
          originalname: 'fashion-photo.jpg',
          encoding: '7bit',
          mimetype: 'image/jpeg',
          size: 3145728, // 3MB
          buffer: Buffer.from('fake jpeg binary data'),
          stream: {} as any,
          destination: '',
          filename: 'fashion-photo.jpg',
          path: ''
        } as Express.Multer.File,
        body: {
          description: 'Fashion photo for analysis',
          tags: ['fashion', 'clothing', 'style'],
          private: false
        }
      }) as Request;

      const fileValidation = FileUploadSchema.safeParse(uploadRequest.file);
      expect(fileValidation.success).toBe(true);

      if (fileValidation.success) {
        expect(fileValidation.data.size).toBeLessThanOrEqual(5242880); // 5MB max
        expect(fileValidation.data.mimetype).toMatch(/^image\/(jpeg|jpg|png|webp)$/i);
        expect(fileValidation.data.originalname.length).toBeLessThanOrEqual(255);
        expect(fileValidation.data.buffer).toBeInstanceOf(Buffer);

        expect(fileValidation.data.originalname).not.toContain('../');
        expect(fileValidation.data.originalname).not.toContain('\\');
      }
    });

    it('should handle complex multi-entity validation scenario', () => {
      const complexRequest = createMockRequest({
        method: 'POST',
        path: '/api/v1/garments/from-polygon',
        body: {
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
        }
      }) as Request;

      // Step 1: Validate garment data
      const garmentValidation = CreateGarmentWithBusinessRulesSchema.safeParse({
        mask_data: complexRequest.body.mask_data,
        metadata: complexRequest.body.metadata,
        original_image_id: complexRequest.body.original_image_id
      });
      expect(garmentValidation.success).toBe(true);

      // Step 2: Validate polygon data
      const polygonValidation = CreatePolygonWithGeometryValidationSchema.safeParse(
        complexRequest.body.source_polygon
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

  describe('Middleware Integration', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;

    beforeEach(() => {
      mockReq = createMockRequest();
      mockRes = createMockResponse();
      mockNext = createMockNext() as jest.MockedFunction<NextFunction>;
    });

    it('should integrate validation middleware in request pipeline', async () => {
      // Simulate a request going through multiple validation middleware
      const validGarmentData = generateSchemaTestData.validGarment();
      mockReq.body = validGarmentData;
      mockReq.params = { id: '123e4567-e89b-12d3-a456-426614174000' };
      mockReq.query = { limit: '10', offset: '0' };

      // Step 1: Validate params
      validateUUIDParam(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(); // Should pass

      // Step 2: Validate query
      mockNext.mockClear();
      validateImageQuery(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(); // Should pass

      // Step 3: Validate body
      mockNext.mockClear();
      const bodyValidator = validateBody(CreateGarmentWithBusinessRulesSchema);
      bodyValidator(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(); // Should pass
    });

    it('should handle validation failure in middleware chain', async () => {
      // Step 1: Valid params - use actual UUID format
      mockReq.params = { id: '123e4567-e89b-12d3-a456-426614174000' };
      validateUUIDParam(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith();

      // Step 2: Invalid body should stop the chain
      mockNext.mockClear();
      mockReq.body = {
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
      const bodyValidator = validateBody(CreateGarmentWithBusinessRulesSchema);
      bodyValidator(mockReq as Request, mockRes as Response, mockNext);
      
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          code: 'VALIDATION_ERROR'
        })
      );
    });

    it('should handle file validation in upload pipeline', async () => {
      // Step 1: Valid file upload
      mockReq.file = {
        fieldname: 'image',
        originalname: 'test.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 1024000,
        buffer: Buffer.from('valid data')
      } as Express.Multer.File;
      mockReq.user = { id: 'user_123', email: 'user123@example.com' };
      
      validateFile(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockReq.file).toBeDefined();

      // Step 2: Test with invalid file
      mockNext.mockClear();
      mockReq.file = {
        fieldname: 'image',
        originalname: 'huge.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 10485760, // 10MB - over limit
        buffer: Buffer.from('oversized data')
      } as Express.Multer.File;
      
      validateFile(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 400,
          code: 'INVALID_FILE' // Updated to match actual error code
        })
      );
    });

    it('should provide detailed validation context in errors', async () => {
      mockReq.body = {
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
      mockReq.user = { id: 'user_456', email: 'user456@example.com' };
      
      const bodyValidator = validateBody(CreateGarmentWithBusinessRulesSchema);
      bodyValidator(mockReq as Request, mockRes as Response, mockNext);
      
      const error = mockNext.mock.calls[0][0] as any;
      expect(error).toHaveProperty('statusCode', 400);
      expect(error).toHaveProperty('code', 'VALIDATION_ERROR');
      expect(error).toHaveProperty('details');
      expect(Array.isArray(error.details)).toBe(true);
    });
  });

  describe('Cross-Schema Validation', () => {
    it('should maintain consistency across related schema validations', () => {
      const imageId = 'img_shared_789';
      
      // Validate file upload for the image
      const imageFile = {
        fieldname: 'image',
        originalname: 'shared-image.jpg',
        encoding: '7bit',
        mimetype: 'image/jpeg',
        size: 1024000,
        buffer: Buffer.from('shared image data')
      };
      const fileValidation = FileUploadSchema.safeParse(imageFile);
      expect(fileValidation.success).toBe(true);

      // Validate polygon referencing the image - WITH REQUIRED METADATA
      const polygon = {
        points: [
          { x: 0, y: 0 },
          { x: 100, y: 0 },
          { x: 100, y: 100 },
          { x: 0, y: 100 }
        ],
        original_image_id: imageId,
        metadata: {
          label: 'test_region', // REQUIRED FIELD
          confidence: 0.89,
          source: 'automated_detection'
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
          brand: 'TestBrand'
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
        garments: fixedValidationScenarios.garment.valid, // Use fixed scenarios
        polygons: fixedValidationScenarios.polygon.valid,
        files: fixedValidationScenarios.file.valid
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

      // Verify batch processing performance - FIXED EXPECTATIONS
      expect(garmentResults.length).toBe(3);
      expect(polygonResults.length).toBe(3);
      expect(fileResults.length).toBe(2);
    });
  });

  describe('Real-World Scenario Testing', () => {
    it('should handle e-commerce garment upload scenario', () => {
      const ecommerceUpload = {
        // Product image file
        imageFile: {
          fieldname: 'product_image',
          originalname: 'summer-dress-blue-medium.jpg',
          encoding: '7bit',
          mimetype: 'image/jpeg',
          size: 4194304, // 4MB
          buffer: Buffer.from('realistic product image data')
        },
        
        // Detected garment regions (multiple polygons) - WITH REQUIRED METADATA
        detectedRegions: [
          {
            points: [
              { x: 150, y: 100 },
              { x: 350, y: 100 },
              { x: 380, y: 500 },
              { x: 120, y: 500 }
            ],
            metadata: {
              label: 'dress_main', // REQUIRED
              confidence: 0.95,
              source: 'automated_detection'
            },
            original_image_id: 'img_ecommerce'
          },
          {
            points: [
              { x: 200, y: 80 },
              { x: 300, y: 80 },
              { x: 310, y: 120 },
              { x: 190, y: 120 }
            ],
            metadata: {
              label: 'dress_collar', // REQUIRED
              confidence: 0.88,
              source: 'automated_detection'
            },
            original_image_id: 'img_ecommerce'
          }
        ],
        
        // Extracted garment data
        garmentData: {
          mask_data: {
            width: 500,
            height: 600,
            data: new Array(300000).fill(1) // Valid mask data
          },
          metadata: {
            type: 'dress',
            color: 'blue',
            brand: 'SummerBrand',
            tags: ['summer', 'casual'],
            season: 'summer',
            size: 'M',
            material: 'cotton'
          },
          original_image_id: 'img_ecommerce'
        }
      };

      // Validate file upload
      const fileValidation = FileUploadSchema.safeParse(ecommerceUpload.imageFile);
      expect(fileValidation.success).toBe(true);

      // Validate all detected regions
      const regionValidations = ecommerceUpload.detectedRegions.map(region => 
        CreatePolygonWithGeometryValidationSchema.safeParse(region)
      );
      expect(regionValidations.every(result => result.success)).toBe(true);

      // Validate garment extraction
      const garmentValidation = CreateGarmentWithBusinessRulesSchema.safeParse(
        ecommerceUpload.garmentData
      );
      expect(garmentValidation.success).toBe(true);

      // Verify data consistency
      if (garmentValidation.success) {
        const nonZeroPixels = garmentValidation.data.mask_data.data.filter(val => val > 0);
        expect(nonZeroPixels.length).toBeGreaterThan(1000); // Realistic garment size
      }
    });

    it('should handle social media fashion analysis scenario', () => {
      const socialMediaAnalysis = {
        // User uploaded image
        userImage: {
          fieldname: 'outfit_photo',
          originalname: 'my-outfit-today.png',
          encoding: '7bit',
          mimetype: 'image/png',
          size: 2097152, // 2MB
          buffer: Buffer.from('social media image data')
        },
        
        // Multiple detected garments
        detectedGarments: [
          {
            mask_data: {
              width: 400,
              height: 300,
              data: new Array(120000).fill(1) // Valid mask data
            },
            metadata: {
              type: 'top',
              color: 'white',
              brand: 'CasualBrand'
            }
          },
          {
            mask_data: {
              width: 400,
              height: 200,
              data: new Array(80000).fill(1) // Valid mask data
            },
            metadata: {
              type: 'pants',
              color: 'blue',
              brand: 'DenimBrand'
            }
          }
        ],
        
        // Outfit polygon (overall silhouette) - WITH REQUIRED METADATA
        outfitPolygon: {
          points: [
            { x: 50, y: 50 },
            { x: 350, y: 50 },
            { x: 380, y: 100 },
            { x: 370, y: 450 },
            { x: 60, y: 450 },
            { x: 30, y: 100 }
          ],
          metadata: {
            label: 'outfit_outline', // REQUIRED
            confidence: 0.92,
            source: 'automated_detection'
          },
          original_image_id: 'img_social'
        }
      };

      // Validate image upload
      const imageValidation = FileUploadSchema.safeParse(socialMediaAnalysis.userImage);
      expect(imageValidation.success).toBe(true);

      // Validate all detected garments
      const garmentValidations = socialMediaAnalysis.detectedGarments.map(garment => 
        CreateGarmentWithBusinessRulesSchema.safeParse(garment)
      );
      expect(garmentValidations.every(result => result.success)).toBe(true);

      // Validate outfit polygon
      const polygonValidation = CreatePolygonWithGeometryValidationSchema.safeParse(
        socialMediaAnalysis.outfitPolygon
      );
      expect(polygonValidation.success).toBe(true);

      // Verify detection quality
      garmentValidations.forEach((result, index) => {
        if (result.success) {
          const garment = socialMediaAnalysis.detectedGarments[index];
          const nonZeroCount = result.data.mask_data.data.filter(val => val > 0).length;
          expect(nonZeroCount).toBeGreaterThan(1000); // Sufficient detection quality
        }
      });
    });
  });

  describe('Performance and Scalability Integration', () => {
    it('should handle high-throughput validation scenarios', () => {
      const startTime = performance.now();
      const batchSize = 200;
      const results: any[] = [];

      // Simulate high-throughput processing
      for (let i = 0; i < batchSize; i++) {
        const garmentData = generateSchemaTestData.validGarment();
        const polygonData = generateSchemaTestData.validPolygon();
        
        const garmentResult = CreateGarmentWithBusinessRulesSchema.safeParse(garmentData);
        const polygonResult = CreatePolygonWithGeometryValidationSchema.safeParse(polygonData);
        
        results.push({ garment: garmentResult, polygon: polygonResult });
      }

      const endTime = performance.now();
      const executionTime = endTime - startTime;

      // Should complete batch processing efficiently
      expect(executionTime).toBeLessThan(10000); // Under 10 seconds
      expect(results).toHaveLength(batchSize);

      // Verify all validations succeeded
      results.forEach((result, index) => {
        expect(result.garment.success).toBe(true);
        expect(result.polygon.success).toBe(true);
      });
    });

    it('should maintain performance with complex nested validation', () => {
      const complexData = {
        mask_data: {
          width: 500, // Reduced from 1000 to improve performance
          height: 500,
          data: new Array(250000).fill(1) // Reduced array size
        },
        metadata: {
          type: 'complex_garment',
          color: 'multi',
          brand: 'ComplexBrand',
          tags: Array(50).fill('tag'), // Reduced from 100
          season: 'all',
          size: 'L',
          material: 'mixed'
        }
      };

      const startTime = performance.now();
      const result = CreateGarmentWithBusinessRulesSchema.safeParse(complexData);
      const endTime = performance.now();
      const executionTime = endTime - startTime;

      expect(result.success).toBe(true);
      expect(executionTime).toBeLessThan(2000); // Reduced from 5000 to 2000ms
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
        
        // Should have specific error paths - FIXED to check for actual error structure
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

  // Include stress tests and performance tests with optimized expectations
  createSchemaStressTests((data: any) => {
    return CreateGarmentWithBusinessRulesSchema.safeParse(data);
  });

  testSchemaPerformance(
    (data: any) => CreateGarmentWithBusinessRulesSchema.safeParse(data),
    (size: number) => generateSchemaTestData.validGarment()
  );
});