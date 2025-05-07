// /backend/src/services/exportService.ts
import fs from 'fs';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { ExportFormat, MLExportOptions, MLExportBatchJob } from '@koutu/shared/schemas/export';
import { garmentModel } from '../models/garmentModel';
// Only import what we actually use
import { query } from '../models/db';
import archiver from 'archiver';
import sharp from 'sharp';

class ExportService {
  private readonly EXPORTS_PATH = path.join(__dirname, '../../exports');
  private readonly TEMP_PATH = path.join(__dirname, '../../temp');

  constructor() {
    // Ensure export and temp directories exist
    if (!fs.existsSync(this.EXPORTS_PATH)) {
      fs.mkdirSync(this.EXPORTS_PATH, { recursive: true });
    }
    if (!fs.existsSync(this.TEMP_PATH)) {
      fs.mkdirSync(this.TEMP_PATH, { recursive: true });
    }
  }

  /**
   * Export user data in various formats for machine learning
   */
  async exportMLData(userId: string, options: MLExportOptions): Promise<string> {
    const batchJobId = uuidv4();
    const batchJob: MLExportBatchJob = {
      id: batchJobId,
      userId,
      status: 'pending',
      options,
      progress: 0,
      totalItems: 0,
      processedItems: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Create batch job in database
    await this.createBatchJob(batchJob);

    // Start processing in background
    this.processMLExport(batchJob).catch(error => {
      console.error('Error processing ML export:', error);
      this.updateBatchJobStatus(batchJobId, 'failed', error.message);
    });

    return batchJobId;
  }

  /**
   * Cancel an export job
   * Public method that can be called from the controller
   */
  async cancelExportJob(jobId: string): Promise<void> {
    await this.updateBatchJobStatus(jobId, 'failed', 'Job canceled by user');
  }

  /**
   * Process ML export in background
   */
  private async processMLExport(batchJob: MLExportBatchJob): Promise<void> {
    try {
      // Update status to processing
      await this.updateBatchJobStatus(batchJob.id, 'processing');

      // Create a directory for this export
      const exportDir = path.join(this.TEMP_PATH, batchJob.id);
      fs.mkdirSync(exportDir, { recursive: true });
      
      // Fetch garments based on filters
      const garments = await this.fetchFilteredGarments(
        batchJob.userId, 
        batchJob.options.garmentIds, 
        batchJob.options.categoryFilter
      );
      
      batchJob.totalItems = garments.length;
      await this.updateBatchJob(batchJob);

      // Process based on the requested format
      let outputPath: string;
      switch (batchJob.options.format) {
        case 'coco':
          outputPath = await this.exportCOCOFormat(garments, exportDir, batchJob);
          break;
        case 'yolo':
          outputPath = await this.exportYOLOFormat(garments, exportDir, batchJob);
          break;
        case 'pascal_voc':
          outputPath = await this.exportPascalVOCFormat(garments, exportDir, batchJob);
          break;
        case 'csv':
          outputPath = await this.exportCSVFormat(garments, exportDir, batchJob);
          break;
        case 'raw_json':
        default:
          outputPath = await this.exportRawJSONFormat(garments, exportDir, batchJob);
          break;
      }

      // Create a zip file of the export directory
      const zipPath = path.join(this.EXPORTS_PATH, `${batchJob.id}.zip`);
      await this.createZipArchive(exportDir, zipPath);

      // Clean up temp directory
      fs.rmSync(exportDir, { recursive: true, force: true });

      // Update batch job with completion status and output URL
      batchJob.status = 'completed';
      batchJob.progress = 100;
      batchJob.outputUrl = `/api/v1/export/ml/download/${batchJob.id}.zip`;
      batchJob.completedAt = new Date().toISOString();
      batchJob.updatedAt = new Date().toISOString();
      await this.updateBatchJob(batchJob);
    } catch (error) {
      console.error('Error in ML export processing:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error during ML export processing';
      await this.updateBatchJobStatus(batchJob.id, 'failed', errorMessage);
      throw error;
    }
  }
  /*
    Regarding the handling of 'error' of type 'unknown' in catch blocks:

    The pattern `if (error instanceof Error)` is a **type guard**.
    It performs a runtime check to see if the `error` object is an instance of the `Error` class.
    If it is, TypeScript narrows the type of `error` to `Error` within that scope,
    allowing safe access to properties like `error.message`.

    This is different from a **type assertion**, which would look like:
    - `(error as Error).message` (as-syntax)
    - `<Error>error.message` (angle-bracket syntax)

    Type assertions do not perform any runtime checks. They are purely a way to tell the
    TypeScript compiler that you, the developer, know the type of a variable better than
    the compiler does. If a type assertion is incorrect, it can lead to runtime errors.
    For `unknown` types, especially from `catch` clauses or external data, type guards
    are generally safer and preferred over type assertions because they validate the type
    at runtime before attempting to use it in a type-specific way.
  */
  /**
   * Fetch garments with applied filters
   */
  private async fetchFilteredGarments(
    userId: string, 
    garmentIds?: string[], 
    categoryFilter?: string[]
  ): Promise<any[]> {
    // Use the query function instead of the model object
    let queryString = 'SELECT g.*, i.* FROM garments g JOIN images i ON g.image_id = i.id WHERE g.user_id = $1';
    const queryParams: any[] = [userId];
    
    if (garmentIds && garmentIds.length > 0) {
      queryString += ` AND g.id IN (${garmentIds.map((_, idx) => `$${idx + 2}`).join(',')})`;
      queryParams.push(...garmentIds);
    }
    
    if (categoryFilter && categoryFilter.length > 0) {
      const startIdx = queryParams.length + 1;
      queryString += ` AND g.category IN (${categoryFilter.map((_, idx) => `$${startIdx + idx}`).join(',')})`;
      queryParams.push(...categoryFilter);
    }
    
    const result = await query(queryString, queryParams);
    return result.rows;
  }

  /**
   * Export data in COCO format (Common Objects in Context)
   * Used by many computer vision frameworks
   */
  private async exportCOCOFormat(
    garments: any[], 
    exportDir: string, 
    batchJob: MLExportBatchJob
  ): Promise<string> {
    // Create directories
    const imagesDir = path.join(exportDir, 'images');
    fs.mkdirSync(imagesDir, { recursive: true });
    
    // Define interfaces for COCO format
    interface COCOCategory {
      id: number;
      name: string;
      supercategory: string;
    }

    interface COCOImage {
      id: number;
      file_name: string;
      width: number | undefined;
      height: number | undefined;
      date_captured: string; // Assuming garment.created_at is a string
    }

    interface COCOAnnotation {
      id: number;
      image_id: number;
      category_id: number;
      segmentation: number[][]; // Assuming flattenPolygonPoints returns number[] which is then wrapped in an array
      area: number;
      bbox: [number, number, number, number];
      iscrowd: number;
      attributes: any;
    }

    interface COCOData {
      info: {
        year: number;
        version: string;
        description: string;
        contributor: string;
        date_created: string;
      };
      images: COCOImage[];
      annotations: COCOAnnotation[];
      categories: COCOCategory[];
    }
    
    // Initialize COCO format structure
    const cocoData: COCOData = {
      info: {
        year: new Date().getFullYear(),
        version: '1.0',
        description: 'Koutu Fashion Dataset',
        contributor: 'Koutu',
        date_created: new Date().toISOString()
      },
      images: [],
      annotations: [],
      categories: []
    };
    
    // Create a map of categories
    const categoryMap = new Map();
    
    // Process each garment
    for (let i = 0; i < garments.length; i++) {
      const garment = garments[i];
      
      // Add category if not exists
      if (!categoryMap.has(garment.category)) {
        const categoryId = categoryMap.size + 1;
        categoryMap.set(garment.category, categoryId);
        cocoData.categories.push({
          id: categoryId,
          name: garment.category,
          supercategory: 'garment'
        });
      }
      
      // Get image data
      const imageFilePath = await this.prepareImageForExport(
        garment, 
        imagesDir, 
        batchJob.options.imageFormat, 
        batchJob.options.compressionQuality
      );
      
      // Get image dimensions
      const imageMetadata = await sharp(imageFilePath).metadata();
      
      // Add image to COCO format
      const imageId = i + 1;
      cocoData.images.push({
        id: imageId,
        file_name: path.basename(imageFilePath),
        width: imageMetadata.width,
        height: imageMetadata.height,
        date_captured: garment.created_at
      });
      
      // Add annotation
      cocoData.annotations.push({
        id: i + 1,
        image_id: imageId,
        category_id: categoryMap.get(garment.category),
        segmentation: [this.flattenPolygonPoints(garment.polygon_points)],
        area: this.calculatePolygonArea(garment.polygon_points),
        bbox: this.calculateBoundingBox(garment.polygon_points),
        iscrowd: 0,
        attributes: garment.attributes || {}
      });
      
      // Export mask if requested
      if (batchJob.options.includeMasks) {
        const { width, height } = imageMetadata;
        if (width === undefined || height === undefined) {
          throw new Error(
            `Cannot generate mask for ${path.basename(imageFilePath)}: image dimensions are missing.`
          );
        }
        const maskPath = path.join(exportDir, 'masks', `${imageId}.png`);
        fs.mkdirSync(path.dirname(maskPath), { recursive: true });
        await this.exportMaskFromPolygon(garment.polygon_points, width, height, maskPath);
      }
      
      // Update progress
      batchJob.processedItems = i + 1;
      batchJob.progress = Math.round((batchJob.processedItems / batchJob.totalItems) * 100);
      await this.updateBatchJob(batchJob);
    }
    
    // Write COCO JSON file
    const cocoFilePath = path.join(exportDir, 'annotations.json');
    fs.writeFileSync(cocoFilePath, JSON.stringify(cocoData, null, 2));
    
    return exportDir;
  }

  /**
   * Export data in YOLO format
   * Used for YOLO object detection models
   */
  private async exportYOLOFormat(
    garments: any[], 
    exportDir: string, 
    batchJob: MLExportBatchJob
  ): Promise<string> {
    // Implementation simplified for brevity
    return exportDir;
  }

  /**
   * Export data in Pascal VOC format
   * Used for object detection and segmentation
   */
  private async exportPascalVOCFormat(
    garments: any[], 
    exportDir: string, 
    batchJob: MLExportBatchJob
  ): Promise<string> {
    // Implementation simplified for brevity
    return exportDir;
  }

  /**
   * Export data in raw JSON format
   * Custom format with all data
   */
  private async exportRawJSONFormat(
    garments: any[], 
    exportDir: string, 
    batchJob: MLExportBatchJob
  ): Promise<string> {
    // Implementation simplified for brevity
    return exportDir;
  }

  /**
   * Export data in CSV format
   * Simple tabular format for analysis
   */
  private async exportCSVFormat(
    garments: any[], 
    exportDir: string, 
    batchJob: MLExportBatchJob
  ): Promise<string> {
    // Implementation simplified for brevity
    return exportDir;
  }

  /**
   * Generate a Python loader script based on the format
   */
  private createPythonLoaderScript(exportDir: string, format: ExportFormat): void {
    // Implementation simplified for brevity
  }

  /**
   * Create a ZIP archive from a directory
   */
  private async createZipArchive(sourceDir: string, outputPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const output = fs.createWriteStream(outputPath);
      const archive = archiver('zip', {
        zlib: { level: 9 } // Maximum compression
      });
      
      output.on('close', () => {
        resolve();
      });
      
      archive.on('error', (err) => {
        reject(err);
      });
      
      archive.pipe(output);
      archive.directory(sourceDir, false);
      archive.finalize();
    });
  }

  /**
   * Calculate polygon area using Shoelace formula
   */
  private calculatePolygonArea(points: Array<{x: number, y: number}>): number {
    if (points.length < 3) return 0;
    
    let area = 0;
    for (let i = 0; i < points.length; i++) {
      const j = (i + 1) % points.length;
      area += points[i].x * points[j].y;
      area -= points[j].x * points[i].y;
    }
    
    return Math.abs(area / 2);
  }

  /**
   * Calculate bounding box from polygon points
   * Returns [x, y, width, height]
   */
  private calculateBoundingBox(points: Array<{x: number, y: number}>): [number, number, number, number] {
    if (points.length === 0) return [0, 0, 0, 0];
    
    let minX = points[0].x;
    let minY = points[0].y;
    let maxX = points[0].x;
    let maxY = points[0].y;
    
    for (let i = 1; i < points.length; i++) {
      const point = points[i];
      minX = Math.min(minX, point.x);
      minY = Math.min(minY, point.y);
      maxX = Math.max(maxX, point.x);
      maxY = Math.max(maxY, point.y);
    }
    
    return [minX, minY, maxX - minX, maxY - minY];
  }

  /**
   * Flatten polygon points for COCO format
   */
  private flattenPolygonPoints(points: Array<{x: number, y: number}>): number[] {
    const result = [];
    for (const point of points) {
      result.push(point.x, point.y);
    }
    return result;
  }

  /**
   * Create a Pascal VOC XML annotation file content
   */
  private createPascalVOCXML(
    filename: string,
    width: number,
    height: number,
    category: string,
    bbox: [number, number, number, number],
    polygonPoints: Array<{x: number, y: number}>
  ): string {
    // Implementation simplified for brevity
    return "";
  }

  /**
   * Create a binary mask image from polygon points
   */
  private async exportMaskFromPolygon(
    points: Array<{x: number, y: number}>,
    width: number,
    height: number,
    outputPath: string
  ): Promise<void> {
    // Ensure directory exists
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    
    // Create an SVG path from the polygon points
    let svgPath = `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">`;
    svgPath += '<path d="';
    
    for (let i = 0; i < points.length; i++) {
      const prefix = i === 0 ? 'M' : 'L';
      svgPath += `${prefix}${points[i].x},${points[i].y} `;
    }
    
    svgPath += 'Z" fill="white" /></svg>';
    
    // Use sharp to create a mask image
    await sharp(Buffer.from(svgPath))
      .toFormat('png')
      .toFile(outputPath);
  }

  /**
   * Copy and prepare image for export
   */
  private async prepareImageForExport(
    garment: any,
    outputDir: string,
    format: string = 'jpg',
    quality: number = 90
  ): Promise<string> {
    // Generate output filename
    const outputExt = format === 'jpg' ? 'jpg' : 'png';
    const outputFilename = `${garment.id}.${outputExt}`;
    const outputPath = path.join(outputDir, outputFilename);
    
    // Get image path
    const imagePath = path.join(__dirname, '../../uploads', garment.path);
    
    // Process the image
    if (format === 'jpg') {
      await sharp(imagePath)
        .jpeg({ quality })
        .toFile(outputPath);
    } else {
      await sharp(imagePath)
        .png({ quality: Math.round(quality / 100 * 9) }) // PNG quality is 0-9
        .toFile(outputPath);
    }
    
    return outputPath;
  }

  /**
   * Create a batch job in the database
   */
  private async createBatchJob(batchJob: MLExportBatchJob): Promise<void> {
    await query(
      'INSERT INTO export_batch_jobs (id, user_id, status, options, progress, total_items, processed_items, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
      [
        batchJob.id,
        batchJob.userId,
        batchJob.status,
        JSON.stringify(batchJob.options),
        batchJob.progress,
        batchJob.totalItems,
        batchJob.processedItems,
        batchJob.createdAt,
        batchJob.updatedAt
      ]
    );
  }

  /**
   * Update batch job status in the database
   */
  private async updateBatchJobStatus(batchJobId: string, status: string, errorMessage?: string): Promise<void> {
    const updates: any = {
      status,
      updated_at: new Date().toISOString()
    };
    
    if (status === 'completed') {
      updates.completed_at = new Date().toISOString();
    }
    
    if (errorMessage) {
      updates.error = errorMessage;
    }
    
    const setClause = Object.keys(updates)
      .map((key, index) => `${key.replace(/([A-Z])/g, '_$1').toLowerCase()} = $${index + 2}`)
      .join(', ');
    
    await query(
      `UPDATE export_batch_jobs SET ${setClause} WHERE id = $1`,
      [batchJobId, ...Object.values(updates)]
    );
  }

  /**
   * Update batch job in the database
   */
  private async updateBatchJob(batchJob: MLExportBatchJob): Promise<void> {
    await query(
      `UPDATE export_batch_jobs 
       SET status = $1, progress = $2, total_items = $3, processed_items = $4, 
           output_url = $5, error = $6, updated_at = $7, completed_at = $8 
       WHERE id = $9`,
      [
        batchJob.status,
        batchJob.progress,
        batchJob.totalItems,
        batchJob.processedItems,
        batchJob.outputUrl,
        batchJob.error,
        batchJob.updatedAt,
        batchJob.completedAt,
        batchJob.id
      ]
    );
  }

  /**
   * Get batch job by ID
   */
  async getBatchJob(batchJobId: string): Promise<MLExportBatchJob | null> {
    const result = await query(
      `SELECT id, user_id, status, options, progress, total_items, processed_items, 
              output_url, error, created_at, updated_at, completed_at 
       FROM export_batch_jobs WHERE id = $1`,
      [batchJobId]
    );
    
    if (result.rows.length === 0) return null;
    
    const job = result.rows[0];
    
    return {
      id: job.id,
      userId: job.user_id,
      status: job.status,
      options: JSON.parse(job.options),
      progress: job.progress,
      totalItems: job.total_items,
      processedItems: job.processed_items,
      outputUrl: job.output_url,
      error: job.error,
      createdAt: job.created_at,
      updatedAt: job.updated_at,
      completedAt: job.completed_at
    };
  }

  /**
   * Get user batch jobs
   */
  async getUserBatchJobs(userId: string): Promise<MLExportBatchJob[]> {
    const result = await query(
      `SELECT id, user_id, status, options, progress, total_items, processed_items, 
              output_url, error, created_at, updated_at, completed_at 
       FROM export_batch_jobs 
       WHERE user_id = $1 
       ORDER BY created_at DESC`,
      [userId]
    );
    
    return result.rows.map(job => ({
      id: job.id,
      userId: job.user_id,
      status: job.status,
      options: JSON.parse(job.options),
      progress: job.progress,
      totalItems: job.total_items,
      processedItems: job.processed_items,
      outputUrl: job.output_url,
      error: job.error,
      createdAt: job.created_at,
      updatedAt: job.updated_at,
      completedAt: job.completed_at
    }));
  }

  /**
   * Get dataset statistics for ML
   */
  async getDatasetStats(userId: string): Promise<any> {
    // Get all garments for the user
    const result = await query(
      `SELECT g.*, i.* 
       FROM garments g 
       JOIN images i ON g.image_id = i.id 
       WHERE g.user_id = $1`,
      [userId]
    );
    
    const garments = result.rows;
    
    if (!garments || garments.length === 0) {
      return {
        totalImages: 0,
        totalGarments: 0,
        categoryCounts: {},
        attributeCounts: {},
        averagePolygonPoints: 0
      };
    }
    
    // Count unique images
    const uniqueImageIds = new Set(garments.map(g => g.image_id));
    
    // Count categories
    const categoryCounts: Record<string, number> = {};
    garments.forEach(g => {
      categoryCounts[g.category] = (categoryCounts[g.category] || 0) + 1;
    });
    
    // Count attributes
    const attributeCounts: Record<string, Record<string, number>> = {};
    garments.forEach(g => {
      if (!g.attributes) return;
      
      const attrs = typeof g.attributes === 'string' 
        ? JSON.parse(g.attributes) 
        : g.attributes;
      
      Object.entries(attrs).forEach(([key, value]) => {
        if (!attributeCounts[key]) {
          attributeCounts[key] = {};
        }
        
        const strValue = String(value);
        attributeCounts[key][strValue] = (attributeCounts[key][strValue] || 0) + 1;
      });
    });
    
    // Calculate average polygon points
    let totalPoints = 0;
    let garmentWithPolygons = 0;
    
    garments.forEach(g => {
      if (g.polygon_points && Array.isArray(g.polygon_points)) {
        totalPoints += g.polygon_points.length;
        garmentWithPolygons++;
      }
    });
    
    const averagePolygonPoints = garmentWithPolygons > 0 
      ? Math.round(totalPoints / garmentWithPolygons) 
      : 0;
    
    return {
      totalImages: uniqueImageIds.size,
      totalGarments: garments.length,
      categoryCounts,
      attributeCounts,
      averagePolygonPoints
    };
  }

  /**
   * Download batch job export file
   */
  async downloadExport(batchJobId: string): Promise<{path: string, filename: string}> {
    const job = await this.getBatchJob(batchJobId);
    
    if (!job) {
      throw new Error('Export job not found');
    }
    
    if (job.status !== 'completed') {
      throw new Error(`Export job status is ${job.status}, not ready for download`);
    }
    
    const zipPath = path.join(this.EXPORTS_PATH, `${batchJobId}.zip`);
    if (!fs.existsSync(zipPath)) {
      throw new Error('Export file not found');
    }
    
    return {
      path: zipPath,
      filename: `koutu-export-${batchJobId.slice(0, 8)}.zip`
    };
  }
}

export const exportService = new ExportService();