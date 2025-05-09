// shared/src/schemas/export.test.ts
import { 
    mlExportOptionsSchema, 
    mlExportBatchJobSchema,
    datasetStatsSchema,
    pointSchema
  } from './export';
  
  describe('Export Schemas', () => {
    describe('pointSchema', () => {
      test('validates a valid point', () => {
        const validPoint = { x: 10, y: 20 };
        const result = pointSchema.safeParse(validPoint);
        expect(result.success).toBe(true);
      });
      
      test('rejects a point with missing coordinates', () => {
        const invalidPoint = { x: 10 };
        const result = pointSchema.safeParse(invalidPoint);
        expect(result.success).toBe(false);
      });
      
      test('rejects a point with non-numeric coordinates', () => {
        const invalidPoint = { x: '10', y: 20 };
        const result = pointSchema.safeParse(invalidPoint);
        expect(result.success).toBe(false);
      });
    });
    
    describe('mlExportOptionsSchema', () => {
      test('validates valid export options with defaults', () => {
        const validOptions = {
          format: 'coco'
        };
        
        const result = mlExportOptionsSchema.safeParse(validOptions);
        expect(result.success).toBe(true);
        
        if (result.success) {
          // Check defaults are applied
          expect(result.data).toEqual({
            format: 'coco',
            includeImages: true,
            includeRawPolygons: true,
            includeMasks: false,
            imageFormat: 'jpg',
            compressionQuality: 90
          });
        }
      });
      
      test('validates full export options', () => {
        const validOptions = {
          format: 'yolo',
          includeImages: false,
          includeRawPolygons: false,
          includeMasks: true,
          imageFormat: 'png',
          compressionQuality: 75,
          garmentIds: ['id1', 'id2'],
          categoryFilter: ['shirt', 'pants'],
          dateRange: {
            from: '2023-01-01T00:00:00Z',
            to: '2023-12-31T23:59:59Z'
          }
        };
        
        const result = mlExportOptionsSchema.safeParse(validOptions);
        expect(result.success).toBe(true);
      });
      
      test('rejects invalid export format', () => {
        const invalidOptions = {
          format: 'invalid_format'
        };
        
        const result = mlExportOptionsSchema.safeParse(invalidOptions);
        expect(result.success).toBe(false);
        
        if (!result.success) {
          expect(result.error.issues[0].path).toContain('format');
        }
      });
      
      test('rejects invalid compression quality', () => {
        const invalidOptions = {
          format: 'coco',
          compressionQuality: 101 // Over the max of 100
        };
        
        const result = mlExportOptionsSchema.safeParse(invalidOptions);
        expect(result.success).toBe(false);
        
        if (!result.success) {
          expect(result.error.issues[0].path).toContain('compressionQuality');
        }
      });
    });
    
    describe('mlExportBatchJobSchema', () => {
      test('validates a valid batch job', () => {
        const validJob = {
          id: '123e4567-e89b-12d3-a456-426614174000',
          userId: '123e4567-e89b-12d3-a456-426614174001',
          status: 'processing',
          options: {
            format: 'coco',
            includeImages: true,
            includeRawPolygons: true,
            includeMasks: false,
            imageFormat: 'jpg',
            compressionQuality: 90
          },
          progress: 35,
          totalItems: 100,
          processedItems: 35,
          createdAt: '2023-01-01T12:00:00Z',
          updatedAt: '2023-01-01T12:05:00Z'
        };
        
        const result = mlExportBatchJobSchema.safeParse(validJob);
        expect(result.success).toBe(true);
      });
      
      test('validates a completed batch job with optional fields', () => {
        const validJob = {
          id: '123e4567-e89b-12d3-a456-426614174000',
          userId: '123e4567-e89b-12d3-a456-426614174001',
          status: 'completed',
          options: {
            format: 'coco',
            includeImages: true,
            includeRawPolygons: true,
            includeMasks: false,
            imageFormat: 'jpg',
            compressionQuality: 90
          },
          progress: 100,
          totalItems: 100,
          processedItems: 100,
          outputUrl: 'https://example.com/exports/123e4567-e89b-12d3-a456-426614174000.zip',
          createdAt: '2023-01-01T12:00:00Z',
          updatedAt: '2023-01-01T12:15:00Z',
          completedAt: '2023-01-01T12:15:00Z'
        };
        
        const result = mlExportBatchJobSchema.safeParse(validJob);
        expect(result.success).toBe(true);
      });
      
      test('rejects a job with invalid UUID', () => {
        const invalidJob = {
          id: 'not-a-uuid',
          userId: '123e4567-e89b-12d3-a456-426614174001',
          status: 'processing',
          options: {
            format: 'coco',
            includeImages: true,
            includeRawPolygons: true,
            includeMasks: false,
            imageFormat: 'jpg',
            compressionQuality: 90
          },
          progress: 35,
          totalItems: 100,
          processedItems: 35,
          createdAt: '2023-01-01T12:00:00Z',
          updatedAt: '2023-01-01T12:05:00Z'
        };
        
        const result = mlExportBatchJobSchema.safeParse(invalidJob);
        expect(result.success).toBe(false);
      });
      
      test('rejects a job with invalid status', () => {
        const invalidJob = {
          id: '123e4567-e89b-12d3-a456-426614174000',
          userId: '123e4567-e89b-12d3-a456-426614174001',
          status: 'invalid_status',
          options: {
            format: 'coco',
            includeImages: true,
            includeRawPolygons: true,
            includeMasks: false,
            imageFormat: 'jpg',
            compressionQuality: 90
          },
          progress: 35,
          totalItems: 100,
          processedItems: 35,
          createdAt: '2023-01-01T12:00:00Z',
          updatedAt: '2023-01-01T12:05:00Z'
        };
        
        const result = mlExportBatchJobSchema.safeParse(invalidJob);
        expect(result.success).toBe(false);
      });
    });
    
    describe('datasetStatsSchema', () => {
      test('validates valid dataset stats', () => {
        const validStats = {
          totalImages: 100,
          totalGarments: 150,
          categoryCounts: {
            shirt: 50,
            pants: 35,
            dress: 25,
            jacket: 40
          },
          attributeCounts: {
            color: {
              blue: 30,
              red: 25,
              black: 45,
              other: 50
            },
            season: {
              winter: 60,
              summer: 90
            }
          },
          averagePolygonPoints: 12
        };
        
        const result = datasetStatsSchema.safeParse(validStats);
        expect(result.success).toBe(true);
      });
    });
  });