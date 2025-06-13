// /backend/src/utils/exports.mock.ts
import { v4 as uuidv4 } from 'uuid';
import { ExportBatchJob } from '../../models/exportModel';
import { MLExportBatchJob, ExportFormat, MLExportOptions } from '@koutu/shared/schemas/export';

/**
 * Mock data for export testing
 */
export class ExportMocks {
  /**
   * Generate a mock ExportBatchJob
   */
  static createMockExportBatchJob(overrides: Partial<ExportBatchJob> = {}): ExportBatchJob {
    const baseDate = new Date('2024-01-15T10:00:00Z');
    const id = uuidv4();
    
    return {
      id,
      user_id: uuidv4(),
      status: 'pending',
      options: {
        format: 'coco',
        includeImages: true,
        includeMasks: false,
        imageFormat: 'jpg',
        compressionQuality: 90
      },
      progress: 0,
      total_items: 100,
      processed_items: 0,
      created_at: baseDate,
      updated_at: baseDate,
      ...overrides
    };
  }

  /**
   * Generate a mock MLExportBatchJob
   */
  static createMockMLExportBatchJob(overrides: Partial<MLExportBatchJob> = {}): MLExportBatchJob {
    const baseDate = new Date('2024-01-15T10:00:00Z');
    const id = uuidv4();
    
    return {
      id,
      userId: uuidv4(),
      status: 'pending',
      options: {
        format: 'coco' as ExportFormat,
        includeImages: true,
        includeMasks: false,
        imageFormat: 'jpg',
        compressionQuality: 90,
        includeRawPolygons: false,
        garmentIds: [],
        categoryFilter: []
      },
      progress: 0,
      totalItems: 100,
      processedItems: 0,
      createdAt: baseDate.toISOString(),
      updatedAt: baseDate.toISOString(),
      ...overrides
    };
  }

  /**
   * Generate mock ML export options
   */
  static createMockMLExportOptions(overrides: Partial<MLExportOptions> = {}): MLExportOptions {
    return {
      format: 'coco' as ExportFormat,
      includeImages: true,
      includeMasks: false,
      imageFormat: 'jpg',
      compressionQuality: 90,
      includeRawPolygons: false,
      garmentIds: [],
      categoryFilter: [],
      ...overrides
    };
  }

  /**
   * Generate mock garment data for export
   */
  static createMockGarmentData(count: number = 5): any[] {
    const garments = [];
    const categories = ['shirt', 'pants', 'dress', 'jacket', 'shoes'];
    const baseDate = new Date('2024-01-15T10:00:00Z');

    for (let i = 0; i < count; i++) {
      const garmentId = uuidv4();
      const imageId = uuidv4();
      
      garments.push({
        // Garment fields
        id: garmentId,
        user_id: uuidv4(),
        image_id: imageId,
        category: categories[i % categories.length],
        attributes: {
          color: ['red', 'blue', 'green', 'black', 'white'][i % 5],
          size: ['S', 'M', 'L', 'XL'][i % 4],
          brand: `Brand ${i + 1}`,
          material: ['cotton', 'polyester', 'wool', 'silk'][i % 4]
        },
        polygon_points: this.generateMockPolygonPoints(),
        created_at: new Date(baseDate.getTime() + i * 86400000).toISOString(),
        updated_at: new Date(baseDate.getTime() + i * 86400000).toISOString(),
        
        // Image fields (joined)
        path: `uploads/images/${imageId}.jpg`,
        filename: `garment_${i + 1}.jpg`,
        mimetype: 'image/jpeg',
        size: 1024000 + (i * 100000),
        width: 800,
        height: 600,
        url: `https://example.com/uploads/images/${imageId}.jpg`
      });
    }

    return garments;
  }

  /**
   * Generate mock polygon points for garment boundaries
   */
  static generateMockPolygonPoints(): Array<{x: number, y: number}> {
    // Generate a realistic garment outline (roughly rectangular with some curves)
    const baseWidth = 400;
    const baseHeight = 600;
    const centerX = 400;
    const centerY = 300;
    
    return [
      { x: centerX - baseWidth/2, y: centerY - baseHeight/2 },
      { x: centerX + baseWidth/2, y: centerY - baseHeight/2 },
      { x: centerX + baseWidth/2, y: centerY + baseHeight/2 },
      { x: centerX - baseWidth/2, y: centerY + baseHeight/2 },
      { x: centerX - baseWidth/2, y: centerY - baseHeight/2 }
    ];
  }

  /**
   * Generate mock dataset statistics
   */
  static createMockDatasetStats(): any {
    return {
      totalImages: 150,
      totalGarments: 200,
      categoryCounts: {
        'shirt': 45,
        'pants': 35,
        'dress': 30,
        'jacket': 25,
        'shoes': 20,
        'accessories': 15,
        'other': 30
      },
      attributeCounts: {
        'color': {
          'red': 25,
          'blue': 30,
          'green': 20,
          'black': 40,
          'white': 35,
          'other': 50
        },
        'size': {
          'XS': 15,
          'S': 35,
          'M': 50,
          'L': 45,
          'XL': 30,
          'XXL': 25
        },
        'material': {
          'cotton': 60,
          'polyester': 45,
          'wool': 25,
          'silk': 20,
          'denim': 30,
          'leather': 10,
          'other': 10
        }
      },
      averagePolygonPoints: 8
    };
  }

  /**
   * Generate mock user statistics
   */
  static createMockUserStats(): any {
    return {
      total: 25,
      byStatus: {
        'completed': 15,
        'failed': 3,
        'cancelled': 2,
        'processing': 1,
        'pending': 4
      },
      completedToday: 2,
      totalProcessedItems: 1250,
      averageProcessingTime: 145 // seconds
    };
  }

  /**
   * Generate mock COCO format data
   */
  static createMockCOCOData(): any {
    return {
      info: {
        year: 2024,
        version: '1.0',
        description: 'Koutu Fashion Dataset',
        contributor: 'Koutu',
        date_created: new Date().toISOString()
      },
      images: [
        {
          id: 1,
          file_name: 'garment_1.jpg',
          width: 800,
          height: 600,
          date_captured: '2024-01-15T10:00:00Z'
        },
        {
          id: 2,
          file_name: 'garment_2.jpg',
          width: 800,
          height: 600,
          date_captured: '2024-01-16T10:00:00Z'
        }
      ],
      annotations: [
        {
          id: 1,
          image_id: 1,
          category_id: 1,
          segmentation: [[200, 150, 600, 150, 600, 450, 200, 450]],
          area: 120000,
          bbox: [200, 150, 400, 300],
          iscrowd: 0,
          attributes: { color: 'red', size: 'M' }
        },
        {
          id: 2,
          image_id: 2,
          category_id: 2,
          segmentation: [[150, 100, 650, 100, 650, 500, 150, 500]],
          area: 200000,
          bbox: [150, 100, 500, 400],
          iscrowd: 0,
          attributes: { color: 'blue', size: 'L' }
        }
      ],
      categories: [
        { id: 1, name: 'shirt', supercategory: 'garment' },
        { id: 2, name: 'pants', supercategory: 'garment' },
        { id: 3, name: 'dress', supercategory: 'garment' }
      ]
    };
  }

  /**
   * Generate mock export progress updates
   */
  static createMockProgressUpdates(): Array<{id: string, progress: number, processed_items: number}> {
    const updates = [];
    const jobCount = 3;
    
    for (let i = 0; i < jobCount; i++) {
      updates.push({
        id: uuidv4(),
        progress: Math.floor(Math.random() * 100),
        processed_items: Math.floor(Math.random() * 50)
      });
    }
    
    return updates;
  }

  /**
   * Generate mock stale jobs for cleanup testing
   */
  static createMockStaleJobs(count: number = 3): ExportBatchJob[] {
    const staleDate = new Date(Date.now() - 48 * 60 * 60 * 1000); // 48 hours ago
    const jobs = [];
    
    for (let i = 0; i < count; i++) {
      jobs.push(this.createMockExportBatchJob({
        status: Math.random() > 0.5 ? 'pending' : 'processing',
        created_at: new Date(staleDate.getTime() - (i * 3600000)), // Staggered times
        updated_at: new Date(staleDate.getTime() - (i * 3600000))
      }));
    }
    
    return jobs;
  }

  /**
   * Generate mock expired jobs
   */
  static createMockExpiredJobs(count: number = 2): ExportBatchJob[] {
    const expiredDate = new Date(Date.now() - 24 * 60 * 60 * 1000); // 24 hours ago
    const jobs = [];
    
    for (let i = 0; i < count; i++) {
      jobs.push(this.createMockExportBatchJob({
        status: 'completed',
        expires_at: new Date(expiredDate.getTime() - (i * 3600000)),
        completed_at: new Date(expiredDate.getTime() - (i * 7200000))
      }));
    }
    
    return jobs;
  }

  /**
   * Generate mock file system paths for testing
   */
  static createMockFilePaths(): any {
    const baseId = uuidv4();
    
    return {
      exportDir: `/tmp/exports/${baseId}`,
      imagesDir: `/tmp/exports/${baseId}/images`,
      masksDir: `/tmp/exports/${baseId}/masks`,
      zipPath: `/exports/${baseId}.zip`,
      tempPath: `/tmp/${baseId}`,
      annotationsFile: `/tmp/exports/${baseId}/annotations.json`,
      pythonScript: `/tmp/exports/${baseId}/loader.py`
    };
  }

  /**
   * Generate mock database query results
   */
  static createMockQueryResult(rows: any[] = []): any {
    return {
      rows,
      rowCount: rows.length,
      command: 'SELECT',
      oid: null,
      fields: []
    };
  }

  /**
   * Generate mock error scenarios for testing
   */
  static createMockErrors(): any {
    return {
      invalidJobId: new Error('Export job not found'),
      unauthorizedAccess: new Error('You do not have permission to access this export job'),
      jobNotReady: new Error('Export job is not ready for download (status: processing)'),
      fileNotFound: new Error('Export file not found'),
      processingError: new Error('Error during ML export processing'),
      databaseError: new Error('Database connection failed'),
      validationError: new Error('Invalid export options provided'),
      storageError: new Error('Failed to create export directory'),
      compressionError: new Error('Failed to create ZIP archive'),
      imageProcessingError: new Error('Failed to process image')
    };
  }

  /**
   * Generate mock request bodies for API testing
   */
  static createMockRequestBodies(): any {
    return {
      mlExportRequest: {
        options: this.createMockMLExportOptions()
      },
      mlExportRequestWithFilters: {
        options: this.createMockMLExportOptions({
          categoryFilter: ['shirt', 'pants'],
          garmentIds: [uuidv4(), uuidv4()]
        })
      },
      mlExportRequestYOLO: {
        options: this.createMockMLExportOptions({
          format: 'yolo' as ExportFormat,
          includeMasks: true,
          imageFormat: 'png',
          compressionQuality: 95
        })
      }
    };
  }

  /**
   * Generate mock response bodies for API testing
   */
  static createMockResponseBodies(): any {
    const jobId = uuidv4();
    
    return {
      createJobSuccess: {
        success: true,
        message: 'ML export job created successfully',
        data: { jobId }
      },
      getJobSuccess: {
        success: true,
        data: this.createMockMLExportBatchJob({ id: jobId })
      },
      getUserJobsSuccess: {
        success: true,
        data: [
          this.createMockMLExportBatchJob({ status: 'completed' }),
          this.createMockMLExportBatchJob({ status: 'processing' }),
          this.createMockMLExportBatchJob({ status: 'pending' })
        ]
      },
      getStatsSuccess: {
        success: true,
        data: this.createMockDatasetStats()
      },
      cancelJobSuccess: {
        success: true,
        message: 'Export job canceled successfully'
      }
    };
  }

  /**
   * Generate mock image metadata
   */
  static createMockImageMetadata(): any {
    return {
      width: 800,
      height: 600,
      format: 'jpeg',
      size: 1024000,
      channels: 3,
      density: 72,
      hasProfile: false,
      hasAlpha: false
    };
  }

  /**
   * Generate mock archive statistics
   */
  static createMockArchiveStats(): any {
    return {
      totalFiles: 105, // 100 images + 5 metadata files
      totalSize: 52428800, // ~50MB
      compressionRatio: 0.85,
      createdAt: new Date().toISOString()
    };
  }
}