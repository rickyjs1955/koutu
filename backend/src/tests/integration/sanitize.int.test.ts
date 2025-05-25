// backend/src/__tests__/integration/sanitize.integration.test.ts
import { beforeEach, afterEach, describe, it, expect } from '@jest/globals';
import { Request, Response, NextFunction } from 'express';

// Import the actual sanitization module (no mocking for integration tests)
import { sanitization } from '../../utils/sanitize';

// Import test helpers and minimal mocking
import {
  mockRawImage,
  mockRawPolygon,
  mockRawGarment,
  mockRawWardrobe,
  createMockRequest,
  createMockResponse,
  createMockNext,
  createMaliciousRequest,
  generateTestData,
  performanceTestData
} from '../__mocks__/sanitize.mock';

import {
  setupSanitizationTestEnvironment,
  createStressTests,
  validateApiPaths
} from '../__helpers__/sanitize.helper';

describe('Sanitization Integration Tests', () => {
  setupSanitizationTestEnvironment();

  describe('End-to-End Data Flow Sanitization', () => {
    it('should handle complete image upload and processing flow', () => {
      // Simulate a complete image upload request
      const uploadRequest = createMockRequest({
        method: 'POST',
        path: '/api/v1/images/upload',
        body: {
          description: 'My vacation photo <script>alert("xss")</script>',
          tags: ['vacation', 'beach', 'javascript:alert("hack")']
        },
        headers: {
          'user-agent': 'Mozilla/5.0 <img onerror="alert(1)" />',
          'content-type': 'multipart/form-data',
          'x-malicious': '<script>document.cookie</script>'
        }
      }) as Request;

      // Step 1: Sanitize upload context
      const uploadContext = sanitization.sanitizeUploadContext(uploadRequest);
      expect(uploadContext.userAgent).not.toContain('<img');
      expect(uploadContext.userAgent).not.toContain('onerror');

      // Step 2: Sanitize headers
      const sanitizedHeaders = sanitization.sanitizeHeaders(uploadRequest.headers);
      expect(sanitizedHeaders).toHaveProperty('user-agent');
      expect(sanitizedHeaders).not.toHaveProperty('x-malicious');

      // Step 3: Sanitize request body data
      const sanitizedBody = sanitization.sanitizeForSecurity(uploadRequest.body);
      expect(sanitizedBody.description).not.toContain('<script>');
      expect(sanitizedBody.tags[2]).not.toContain('javascript:');

      // Step 4: Process and sanitize image data
      const processedImage = sanitization.sanitizeImageForResponse(mockRawImage);
      expect(processedImage).toHaveProperty('file_path');
      expect(processedImage.file_path).toMatch(/^\/api\/v1\/images\/[^\/]+\/file$/);
      expect(processedImage).not.toHaveProperty('internal_path');
      expect(processedImage).not.toHaveProperty('password_hash');
    });

    it('should handle complete garment analysis workflow', () => {
      // Simulate garment analysis request with potential malicious data
      const analysisRequest = createMaliciousRequest('xss_headers') as Request;
      
      // Step 1: Sanitize request context
      const context = sanitization.sanitizeUploadContext(analysisRequest);
      expect(context).toHaveProperty('method');
      expect(context).toHaveProperty('timestamp');
      expect(context.userAgent).not.toContain('<script>');

      // Step 2: Process garment data with nested metadata
      const garmentWithMaliciousMetadata = {
        ...mockRawGarment,
        metadata: {
          ...mockRawGarment.metadata,
          type: 'shirt<script>alert("xss")</script>',
          color: 'blue; DROP TABLE colors;',
          brand: 'Nike`rm -rf /`',
          tags: [
            'casual',
            '<img src=x onerror=alert(1)>',
            'javascript:alert("hack")',
            'summer'
          ],
          customField: 'should be removed',
          __proto__: { isAdmin: true }
        },
        internalData: {
          processingHistory: ['step1', 'step2'],
          userSession: 'abc123'
        }
      };

      const sanitizedGarment = sanitization.sanitizeGarmentForResponse(garmentWithMaliciousMetadata);

      // Verify all malicious content was removed
      expect(sanitizedGarment.metadata.type).toBe('shirt');
      expect(sanitizedGarment.metadata.color).toBe('blue colors');
      expect(sanitizedGarment.metadata.brand).toBe('Nikermrf ');
      expect(sanitizedGarment.metadata.tags).not.toContain('<img src=x onerror=alert(1)>');
      expect(sanitizedGarment.metadata.tags).not.toContain('javascript:alert("hack")');
      expect(sanitizedGarment.metadata).not.toHaveProperty('customField');
      expect(sanitizedGarment.metadata).not.toHaveProperty('__proto__');
      expect(sanitizedGarment).not.toHaveProperty('internalData');

      // Verify paths were converted to API endpoints
      expect(sanitizedGarment.file_path).toBe('/api/v1/garments/garment_789/image');
      expect(sanitizedGarment.mask_path).toBe('/api/v1/garments/garment_789/mask');
    });

    it('should handle polygon creation with coordinate validation', () => {
  const polygonWithInvalidData = {
    ...mockRawPolygon,
    points: [
      { x: 100.5, y: 200.7 }, // Valid coordinates
      { x: 'invalid', y: 150 }, // Invalid x coordinate
      { x: 200, y: null }, // Null y coordinate
      { x: 300, y: 400 }, // Valid coordinates
      { x: -50, y: 500 } // Negative coordinate (should be allowed)
    ],
    metadata: {
      label: 'shirt<script>alert("polygon")</script>',
      confidence: 1.8, // Out of range
      source: 'manual_annotation',
      notes: 'Good quality annotation javascript:alert("notes")',
      internalScore: 0.95, // Should be filtered
      '__proto__': { type: 'Polygon' }
    },
    algorithmData: {
      version: '1.2.3',
      weights: [0.1, 0.2, 0.3]
    }
  } as any; // Add type assertion to bypass strict typing

  const sanitizedPolygon = sanitization.sanitizePolygonForResponse(polygonWithInvalidData);

  // Check coordinate sanitization
  expect(sanitizedPolygon.points).toHaveLength(5);
  expect(sanitizedPolygon.points[0]).toEqual({ x: 100.5, y: 200.7 });
  expect(sanitizedPolygon.points[1]).toEqual({ x: 0, y: 150 }); // Invalid x becomes 0
  expect(sanitizedPolygon.points[2]).toEqual({ x: 200, y: 0 }); // Null y becomes 0
  expect(sanitizedPolygon.points[3]).toEqual({ x: 300, y: 400 });
  expect(sanitizedPolygon.points[4]).toEqual({ x: -50, y: 500 }); // Negative allowed

  // Check metadata sanitization
  expect(sanitizedPolygon.metadata.label).toBe('shirt');
  expect(sanitizedPolygon.metadata.confidence).toBe(1); // Clamped to 1
  expect(sanitizedPolygon.metadata.notes).toBe('Good quality annotation ');
  expect(sanitizedPolygon.metadata).not.toHaveProperty('internalScore');
  expect(sanitizedPolygon.metadata).not.toHaveProperty('__proto__');
  expect(sanitizedPolygon).not.toHaveProperty('algorithmData');
});

    it('should handle wardrobe with nested garments', () => {
      const complexWardrobe = {
        ...mockRawWardrobe,
        name: 'Summer Collection <svg onload="alert(\'wardrobe\')">',
        description: 'My summer wardrobe with lots of clothes. '.repeat(50), // Very long
        garments: [
          mockRawGarment,
          {
            ...mockRawGarment,
            id: 'garment_456',
            metadata: {
              type: 'pants',
              color: 'black<script>alert("garment2")</script>',
              tags: ['formal', 'work', 'comfortable']
            }
          }
        ],
        settings: {
          privacy: 'private',
          sharing: false
        },
        analytics: {
          views: 150,
          likes: 25
        }
      };

      const sanitizedWardrobe = sanitization.sanitizeWardrobeForResponse(complexWardrobe);

      // Check wardrobe level sanitization
      expect(sanitizedWardrobe.name).toBe('Summer Collection ');
      expect(sanitizedWardrobe.name).not.toContain('<svg');
      expect(sanitizedWardrobe.description.length).toBeLessThanOrEqual(1000);
      expect(sanitizedWardrobe).not.toHaveProperty('settings');
      expect(sanitizedWardrobe).not.toHaveProperty('analytics');

      // Check nested garments sanitization
      expect(sanitizedWardrobe.garments).toHaveLength(2);
      expect(sanitizedWardrobe.garments[0].metadata.type).toBe('shirt');
      expect(sanitizedWardrobe.garments[1].metadata.color).toBe('black');
      expect(sanitizedWardrobe.garments[1].metadata.color).not.toContain('<script>');
    });
  });

  describe('Controller Integration', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: jest.MockedFunction<NextFunction>;

    beforeEach(() => {
      mockReq = createMockRequest();
      mockRes = createMockResponse();
      mockNext = createMockNext() as unknown as jest.MockedFunction<NextFunction>;
    });

    it('should integrate with image controller error handling', async () => {
      const imageController = async (req: Request, res: Response, next: NextFunction) => {
        // Simulate database error with sensitive information
        const dbError = new Error('Connection failed: postgresql://admin:secret123@prod-db:5432/koutu_images');
        dbError.stack = 'Error: Connection failed\n    at Database.connect(/app/db.js:45)\n    at ImageController.upload(/app/controllers/image.js:123)';
        throw dbError;
      };

      const wrappedController = sanitization.wrapImageController(imageController, 'uploading');
      await wrappedController(mockReq as Request, mockRes as Response, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'An error occurred while uploading the image',
          statusCode: 500
        })
      );

      // Ensure sensitive information was not leaked
      const errorArg = mockNext.mock.calls[0][0] as any;
      expect(typeof errorArg).toBe('object');
      expect(errorArg).toHaveProperty('message');
      expect(errorArg.message).not.toContain('secret123');
      expect(errorArg.message).not.toContain('postgresql://');
      expect(errorArg.message).not.toContain('admin');
    });

    it('should handle complex error objects in garment controller', async () => {
              const garmentController = async (req: Request, res: Response, next: NextFunction) => {
        const complexError = {
          name: 'ValidationError',
          message: 'Garment validation failed: <script>alert("error")</script>',
          statusCode: 400,
          details: [
            'Field "type" contains javascript:alert("hack")',
            'Field "brand" has invalid characters: <>"|'
          ],
          internalData: {
            userId: 'user_123',
            sessionId: 'session_abc',
            apiKey: 'sk-1234567890abcdef'
          }
        };
        throw complexError;
      };

      const wrappedController = sanitization.wrapGarmentController(garmentController, 'processing');
      await wrappedController(mockReq as Request, mockRes as Response, mockNext);

      const errorArg = mockNext.mock.calls[0][0] as any;
      expect(errorArg.message).toBe('An error occurred while processing the garment');
      expect(errorArg.statusCode).toBe(500);
      
      // Verify original error was logged but sanitized error was passed
      expect(errorArg.message).not.toContain('<script>');
      expect(errorArg.message).not.toContain('javascript:');
    });

    it('should handle polygon controller with nested async operations', async () => {
      const polygonController = async (req: Request, res: Response, next: NextFunction) => {
        // Simulate nested async operation that throws
        await new Promise(resolve => setTimeout(resolve, 10));
        
        const asyncError = new Error('ML model inference failed: python /models/polygon_detector.py --input=/tmp/sensitive_data.json');
        asyncError.stack = 'Error at line 45 in /home/user/.secrets/model_config.py';
        throw asyncError;
      };

      const wrappedController = sanitization.wrapPolygonController(polygonController, 'detecting');
      await wrappedController(mockReq as Request, mockRes as Response, mockNext);

      const errorArg = mockNext.mock.calls[0][0] as any;
      expect(errorArg.message).toBe('An error occurred while detecting the polygon');
      expect(errorArg.message).not.toContain('/tmp/sensitive_data.json');
      expect(errorArg.message).not.toContain('.secrets');
    });

    it('should handle wardrobe controller with user context', async () => {
      const wardrobeController = async (req: Request, res: Response, next: NextFunction) => {
        // Simulate error that includes user context
        const userError = new Error(`Access denied for user: ${req.user?.id} (email: user@example.com)`);
        userError.name = 'AuthorizationError';
        throw userError;
      };

      const wrappedController = sanitization.wrapWardrobeController(wardrobeController, 'accessing');
      await wrappedController(mockReq as Request, mockRes as Response, mockNext);

      const errorArg = mockNext.mock.calls[0][0] as any;
      expect(errorArg.message).toBe('An error occurred while accessing the wardrobe');
      expect(errorArg.message).not.toContain('user@example.com');
      expect(errorArg.message).not.toContain('user_123');
    });
  });

  describe('Cross-Entity Data Processing', () => {
    it('should maintain data consistency across related entities', () => {
      const relatedImageId = 'img_shared_123';
      
      // Process image first
      const imageData = {
        ...mockRawImage,
        id: relatedImageId,
        file_path: '/uploads/shared/image.jpg'
      };
      const sanitizedImage = sanitization.sanitizeImageForResponse(imageData);

      // Process polygon that references the image
      const polygonData = {
        ...mockRawPolygon,
        original_image_id: relatedImageId,
        metadata: {
          source: 'automated_detection',
          confidence: 0.87,
          imageReference: '/uploads/shared/image.jpg' // Should be filtered
        }
      };
      const sanitizedPolygon = sanitization.sanitizePolygonForResponse(polygonData);

      // Process garment that also references the image
      const garmentData = {
        ...mockRawGarment,
        original_image_id: relatedImageId,
        file_path: '/uploads/shared/garment_crop.jpg'
      };
      const sanitizedGarment = sanitization.sanitizeGarmentForResponse(garmentData);

      // Verify consistent referencing
      expect(sanitizedImage.id).toBe(relatedImageId);
      expect(sanitizedPolygon.original_image_id).toBe(relatedImageId);
      expect(sanitizedGarment.original_image_id).toBe(relatedImageId);

      // Verify paths were properly converted
      expect(sanitizedImage.file_path).toBe(`/api/v1/images/${relatedImageId}/file`);
      expect(sanitizedGarment.file_path).toBe(`/api/v1/garments/${sanitizedGarment.id}/image`);

      // Verify sensitive references were removed
      expect(sanitizedPolygon.metadata).not.toHaveProperty('imageReference');
    });

    it('should handle batch processing of multiple entities', () => {
      const batchData = {
        images: [mockRawImage, { ...mockRawImage, id: 'img_456' }],
        polygons: [mockRawPolygon, { ...mockRawPolygon, id: 'poly_789' }],
        garments: [mockRawGarment, { ...mockRawGarment, id: 'garment_101' }]
      };

      // Process all entities
      const sanitizedBatch = {
        images: batchData.images.map(img => sanitization.sanitizeImageForResponse(img)),
        polygons: batchData.polygons.map(poly => sanitization.sanitizePolygonForResponse(poly)),
        garments: batchData.garments.map(garment => sanitization.sanitizeGarmentForResponse(garment))
      };

      // Verify all entities were processed correctly
      expect(sanitizedBatch.images).toHaveLength(2);
      expect(sanitizedBatch.polygons).toHaveLength(2);
      expect(sanitizedBatch.garments).toHaveLength(2);

      // Verify each entity maintains its structure
      sanitizedBatch.images.forEach(img => {
        expect(img).toHaveProperty('id');
        expect(img).toHaveProperty('file_path');
        expect(img.file_path).toMatch(/^\/api\/v1\/images\/[^\/]+\/file$/);
      });

      sanitizedBatch.polygons.forEach(poly => {
        expect(poly).toHaveProperty('id');
        expect(poly).toHaveProperty('points');
        expect(Array.isArray(poly.points)).toBe(true);
      });

      sanitizedBatch.garments.forEach(garment => {
        expect(garment).toHaveProperty('id');
        expect(garment).toHaveProperty('metadata');
        expect(garment.file_path).toMatch(/^\/api\/v1\/garments\/[^\/]+\/image$/);
      });
    });
  });

  describe('Path Generation Integration', () => {
    validateApiPaths(sanitization.sanitizePath);

    it('should generate consistent API paths across different entities', () => {
      const entityId = 'entity_123';
      
      const paths = {
        imageFile: sanitization.sanitizePath('images', entityId, 'file'),
        imageThumbnail: sanitization.sanitizePath('images', entityId, 'thumbnail'),
        garmentImage: sanitization.sanitizePath('garments', entityId, 'image'),
        garmentMask: sanitization.sanitizePath('garments', entityId, 'mask'),
        polygonData: sanitization.sanitizePath('polygons', entityId, 'data')
      };

      // Verify all paths follow the same pattern
      Object.values(paths).forEach(path => {
        expect(path).toMatch(/^\/api\/v1\/[a-z]+\/entity_123\/[a-z]+$/);
      });

      expect(paths.imageFile).toBe('/api/v1/images/entity_123/file');
      expect(paths.imageThumbnail).toBe('/api/v1/images/entity_123/thumbnail');
      expect(paths.garmentImage).toBe('/api/v1/garments/entity_123/image');
      expect(paths.garmentMask).toBe('/api/v1/garments/entity_123/mask');
      expect(paths.polygonData).toBe('/api/v1/polygons/entity_123/data');
    });

    it('should handle special characters in entity IDs', () => {
      const specialIds = [
        'entity-with-dashes',
        'entity_with_underscores',
        'entity123numbers',
        'ENTITY_UPPERCASE',
        'entity@#$%special',
        'entity spaces'
      ];

      specialIds.forEach(id => {
        const path = sanitization.sanitizePath('images', id, 'file');
        expect(path).toMatch(/^\/api\/v1\/images\/[a-z0-9\-_]+\/file$/);
        expect(path).not.toContain('@');
        expect(path).not.toContain('#');
        expect(path).not.toContain(' ');
      });
    });
  });

  describe('Request-Response Cycle Integration', () => {
    it('should handle complete HTTP request processing', () => {
      // Simulate incoming request with mixed malicious and valid data
      const incomingRequest = createMaliciousRequest('xss_headers') as Request;
      incomingRequest.body = {
        name: 'My Garment <script>alert("body")</script>',
        description: 'A nice piece of clothing javascript:alert("desc")',
        metadata: {
          type: 'shirt',
          color: 'blue<img onerror="alert(1)" />',
          tags: ['casual', '<svg onload="alert(2)" />', 'summer']
        }
      };

      // Step 1: Sanitize request headers
      const sanitizedHeaders = sanitization.sanitizeHeaders(incomingRequest.headers);
      expect(Object.keys(sanitizedHeaders)).toEqual(
        expect.arrayContaining(['user-agent', 'accept', 'content-type'])
      );

      // Step 2: Sanitize request body
      const sanitizedBody = sanitization.sanitizeForSecurity(incomingRequest.body);
      expect(sanitizedBody.name).toBe('My Garment');
      expect(sanitizedBody.description).toBe('A nice piece of clothing ');
      expect(sanitizedBody.metadata.color).toBe('blue ');
      expect(sanitizedBody.metadata.tags).not.toContain('<svg onload="alert(2)" />');

      // Step 3: Create response data
      const responseData = {
        id: 'garment_new_123',
        name: sanitizedBody.name,
        description: sanitizedBody.description,
        metadata: sanitizedBody.metadata,
        file_path: '/uploads/garments/new_garment.jpg',
        created_at: new Date().toISOString()
      };

      // Step 4: Sanitize response
      const sanitizedResponse = sanitization.sanitizeGarmentForResponse(responseData);
      expect(sanitizedResponse.file_path).toBe('/api/v1/garments/garment_new_123/image');
      expect(sanitizedResponse).not.toHaveProperty('internalField');

      // Verify no malicious content survived the full cycle
      const responseString = JSON.stringify(sanitizedResponse);
      expect(responseString).not.toMatch(/<script|javascript:|on\w+=/i);
    });

    it('should maintain performance during high-throughput processing', () => {
      const startTime = performance.now();
      const batchSize = 100;
      const results: any[] = [];

      // Process multiple entities simultaneously
      for (let i = 0; i < batchSize; i++) {
        const imageResult = sanitization.sanitizeImageForResponse({
          ...mockRawImage,
          id: `img_${i}`,
          metadata: {
            ...mockRawImage.original_metadata,
            description: `Image ${i} with <script>alert(${i})</script>`
          }
        });

        const garmentResult = sanitization.sanitizeGarmentForResponse({
          ...mockRawGarment,
          id: `garment_${i}`,
          metadata: {
            ...mockRawGarment.metadata,
            type: `type_${i}<script>alert("garment")</script>`
          }
        });

        results.push({ image: imageResult, garment: garmentResult });
      }

      const endTime = performance.now();
      const executionTime = endTime - startTime;

      // Should complete batch processing quickly
      expect(executionTime).toBeLessThan(1000); // Under 1 second
      expect(results).toHaveLength(batchSize);

      // Verify all results are properly sanitized
      results.forEach((result, index) => {
        expect(result.image.id).toBe(`img_${index}`);
        expect(result.garment.id).toBe(`garment_${index}`);
        expect(result.image.metadata.description).not.toContain('<script>');
        expect(result.garment.metadata.type).not.toContain('<script>');
      });
    });
  });

  describe('Memory Management and Resource Cleanup', () => {
    it('should handle large datasets without memory leaks', () => {
      const initialMemory = process.memoryUsage().heapUsed;
      const largeDataset = performanceTestData.largeDataset;

      // Process large dataset
      const results = largeDataset.map(item => 
        sanitization.sanitizeForSecurity(item)
      );

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      expect(results).toHaveLength(largeDataset.length);
      expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB increase
    });

    it('should clean up after processing malicious datasets', () => {
      const maliciousData = Array(1000).fill(0).map((_, i) => ({
        id: `malicious_${i}`,
        content: `<script>alert("${i}")</script>`.repeat(10),
        metadata: {
          description: `javascript:alert("meta${i}")`.repeat(5),
          tags: Array(50).fill(`<img onerror="alert(${i})" />`)
        }
      }));

      const startTime = performance.now();
      const cleanedData = maliciousData.map(item => 
        sanitization.sanitizeForSecurity(item)
      );
      const endTime = performance.now();

      expect(endTime - startTime).toBeLessThan(2000); // Should complete in under 2 seconds
      expect(cleanedData).toHaveLength(1000);

      // Verify all malicious content was removed
      const stringified = JSON.stringify(cleanedData);
      expect(stringified).not.toContain('<script>');
      expect(stringified).not.toContain('javascript:');
      expect(stringified).not.toContain('onerror');
    });
  });

  describe('Error Recovery and Fault Tolerance', () => {
    it('should gracefully handle corrupted data structures', () => {
      const corruptedData = {
        id: 'corrupted_123',
        // Simulate circular reference
        circular: null as any,
        // Simulate prototype pollution attempt
        __proto__: { isAdmin: true },
        constructor: { prototype: { hack: true } },
        // Simulate deeply nested malicious data
        nested: {}
      };

      // Create circular reference
      corruptedData.circular = corruptedData;

      // Create deep nesting with malicious content
      let current = corruptedData.nested as any;
      for (let i = 0; i < 100; i++) {
        current.next = {
          level: i,
          malicious: `<script>alert("level${i}")</script>`,
          next: {}
        };
        current = current.next.next;
      }

      // Should not throw and should sanitize what it can
      expect(() => {
        const result = sanitization.sanitizeForSecurity(corruptedData);
        expect(result).toBeDefined();
        expect(result.id).toBe('corrupted_123');
      }).not.toThrow();
    });

    it('should handle network timeout scenarios gracefully', async () => {
      // Simulate a controller that times out
      const timeoutController = async (req: Request, res: Response, next: NextFunction) => {
        await new Promise(resolve => setTimeout(resolve, 100));
        throw new Error('Network timeout: Failed to connect to external service after 30 seconds');
      };

      const wrappedController = sanitization.wrapImageController(timeoutController, 'uploading');
      const mockReq = createMockRequest() as Request;
      const mockRes = createMockResponse() as Response;
      const mockNext = createMockNext();

      await wrappedController(mockReq, mockRes, mockNext);

      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'An error occurred while uploading the image',
          statusCode: 500
        })
      );
    });
  });

  createStressTests(sanitization.sanitizeForSecurity);

  describe('Real-World Scenario Testing', () => {
    it('should handle social media-style content upload', () => {
      const socialMediaPost = {
        id: 'post_123',
        content: `Check out my new outfit! 👗✨ 
                  <script>alert("Follow me for more!")</script>
                  Visit my profile: javascript:window.location='http://evil.com'
                  #fashion #style #ootd`,
        images: [
          {
            ...mockRawImage,
            description: 'Outfit photo <img src="x" onerror="location.href=\'http://malicious.com\'" />'
          }
        ],
        hashtags: [
          '#fashion',
          '#style<script>alert("hashtag")</script>',
          '#ootd',
          'javascript:alert("tag")'
        ],
        userMentions: [
          '@friend1',
          '@<script>document.cookie</script>',
          '@normaluser'
        ]
      };

      const sanitizedPost = sanitization.sanitizeForSecurity(socialMediaPost);
      const sanitizedImage = sanitization.sanitizeImageForResponse(socialMediaPost.images[0]);

      expect(sanitizedPost.content).not.toContain('<script>');
      expect(sanitizedPost.content).not.toContain('javascript:');
      expect(sanitizedPost.content).toContain('#fashion #style #ootd');

      expect(sanitizedImage.metadata.description).not.toContain('<img');
      expect(sanitizedImage.metadata.description).not.toContain('onerror');

      expect(sanitizedPost.hashtags).not.toContain('#style<script>alert("hashtag")</script>');
      expect(sanitizedPost.hashtags).not.toContain('javascript:alert("tag")');
      expect(sanitizedPost.userMentions).not.toContain('@<script>document.cookie</script>');
    });

    it('should handle e-commerce product data', () => {
      const productData = {
        id: 'product_456',
        name: 'Summer Dress <iframe src="javascript:alert(\'product\')"></iframe>',
        description: 'Beautiful summer dress perfect for any occasion. <script>fetch("/api/steal-data")</script>',
        price: 29.99,
        categories: ['dresses', '<svg onload="alert(\'category\')" />', 'summer'],
        specifications: {
          material: '100% cotton <meta http-equiv="refresh" content="0;url=http://evil.com">',
          size: 'M',
          color: 'blue',
          care: 'Machine wash <object data="javascript:alert(\'care\')"></object>'
        },
        reviews: [
          {
            rating: 5,
            comment: 'Great dress! <link rel="stylesheet" href="javascript:alert(\'review\')" />'
          }
        ],
        seo: {
          title: 'Best Summer Dress <title>Hacked</title>',
          description: 'Shop the best summer dress <script>location.href="http://phishing.com"</script>'
        }
      };

      const sanitizedProduct = sanitization.sanitizeForSecurity(productData);

      expect(sanitizedProduct.name).toBe('Summer Dress ');
      expect(sanitizedProduct.description).not.toContain('<script>');
      expect(sanitizedProduct.description).not.toContain('fetch(');
      expect(sanitizedProduct.categories).not.toContain('<svg onload="alert(\'category\')" />');
      expect(sanitizedProduct.specifications.material).not.toContain('<meta');
      expect(sanitizedProduct.specifications.care).not.toContain('<object');
      expect(sanitizedProduct.reviews[0].comment).not.toContain('<link');
      expect(sanitizedProduct.seo.title).not.toContain('<title>');
      expect(sanitizedProduct.seo.description).not.toContain('<script>');
    });
  });
});