import cv from 'opencv-wasm';
import { ApiError } from './ApiError';

interface Point {
  x: number;
  y: number;
}

interface ProcessedPolygon {
  points: Point[];
  simplified: Point[];
  confidence: number;
  area: number;
  perimeter: number;
}

interface ImageMetadata {
  width: number;
  height: number;
  channels?: number;
}

export class PolygonProcessor {
  private static instance: PolygonProcessor;
  private cvInstance: any;
  private initialized: boolean = false;

  private constructor() {}

  static getInstance(): PolygonProcessor {
    if (!PolygonProcessor.instance) {
      PolygonProcessor.instance = new PolygonProcessor();
    }
    return PolygonProcessor.instance;
  }

  /**
   * Initialize OpenCV WebAssembly module
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      this.cvInstance = await cv;
      this.initialized = true;
      console.log('OpenCV initialized successfully');
    } catch (error) {
      console.error('Failed to initialize OpenCV:', error);
      throw ApiError.internal('Failed to initialize polygon processor');
    }
  }

  /**
   * Process an image buffer and suggest AI-assisted polygons
   */
  async suggestPolygons(
    imageBuffer: Buffer,
    metadata: ImageMetadata,
    options?: {
      maxPolygons?: number;
      minArea?: number;
      simplificationTolerance?: number;
    }
  ): Promise<ProcessedPolygon[]> {
    await this.initialize();

    const {
      maxPolygons = 10,
      minArea = 100,
      simplificationTolerance = 2
    } = options || {};

    try {
      // Convert buffer to OpenCV Mat
      const mat = this.bufferToMat(imageBuffer, metadata);
      
      // Apply preprocessing
      const processed = this.preprocessImage(mat);
      
      // Find contours
      const contours = this.findContours(processed);
      
      // Convert contours to polygons
      const polygons: ProcessedPolygon[] = [];
      
      for (let i = 0; i < Math.min(contours.size(), maxPolygons); i++) {
        const contour = contours.get(i);
        const area = this.cvInstance.contourArea(contour);
        
        if (area < minArea) continue;
        
        // Approximate polygon
        const epsilon = simplificationTolerance * this.cvInstance.arcLength(contour, true) / 100;
        const approx = new this.cvInstance.Mat();
        this.cvInstance.approxPolyDP(contour, approx, epsilon, true);
        
        // Convert to points
        const points = this.matToPoints(contour);
        const simplified = this.matToPoints(approx);
        
        polygons.push({
          points,
          simplified,
          confidence: this.calculateConfidence(contour, approx),
          area,
          perimeter: this.cvInstance.arcLength(contour, true)
        });
        
        approx.delete();
      }
      
      // Cleanup
      mat.delete();
      processed.delete();
      contours.delete();
      
      return polygons;
    } catch (error) {
      console.error('Error processing polygons:', error);
      throw ApiError.internal('Failed to process polygons');
    }
  }

  /**
   * Enhance existing polygon points using AI assistance
   */
  async enhancePolygon(
    points: Point[],
    imageBuffer: Buffer,
    metadata: ImageMetadata
  ): Promise<ProcessedPolygon> {
    await this.initialize();

    try {
      const mat = this.bufferToMat(imageBuffer, metadata);
      const processed = this.preprocessImage(mat);
      
      // Convert points to OpenCV contour
      const contour = this.pointsToMat(points);
      
      // Find the best matching contour in the processed image
      const enhanced = this.findBestMatchingContour(processed, contour);
      
      // Simplify the enhanced contour
      const epsilon = 2 * this.cvInstance.arcLength(enhanced, true) / 100;
      const simplified = new this.cvInstance.Mat();
      this.cvInstance.approxPolyDP(enhanced, simplified, epsilon, true);
      
      const result: ProcessedPolygon = {
        points: this.matToPoints(enhanced),
        simplified: this.matToPoints(simplified),
        confidence: this.calculateConfidence(enhanced, simplified),
        area: this.cvInstance.contourArea(enhanced),
        perimeter: this.cvInstance.arcLength(enhanced, true)
      };
      
      // Cleanup
      mat.delete();
      processed.delete();
      contour.delete();
      enhanced.delete();
      simplified.delete();
      
      return result;
    } catch (error) {
      console.error('Error enhancing polygon:', error);
      throw ApiError.internal('Failed to enhance polygon');
    }
  }

  /**
   * Detect edges in an image for polygon assistance
   */
  async detectEdges(
    imageBuffer: Buffer,
    metadata: ImageMetadata,
    threshold1: number = 100,
    threshold2: number = 200
  ): Promise<Buffer> {
    await this.initialize();

    try {
      const mat = this.bufferToMat(imageBuffer, metadata);
      const gray = new this.cvInstance.Mat();
      
      // Convert to grayscale if needed
      if (mat.channels() > 1) {
        this.cvInstance.cvtColor(mat, gray, this.cvInstance.COLOR_RGBA2GRAY);
      } else {
        mat.copyTo(gray);
      }
      
      // Apply Canny edge detection
      const edges = new this.cvInstance.Mat();
      this.cvInstance.Canny(gray, edges, threshold1, threshold2);
      
      // Convert back to buffer
      const result = this.matToBuffer(edges);
      
      // Cleanup
      mat.delete();
      gray.delete();
      edges.delete();
      
      return result;
    } catch (error) {
      console.error('Error detecting edges:', error);
      throw ApiError.internal('Failed to detect edges');
    }
  }

  /**
   * Convert buffer to OpenCV Mat
   */
  private bufferToMat(buffer: Buffer, metadata: ImageMetadata): any {
    const { width, height, channels = 4 } = metadata;
    const mat = new this.cvInstance.Mat(height, width, this.cvInstance.CV_8UC4);
    
    // Copy buffer data to Mat
    const data = new Uint8Array(buffer);
    mat.data.set(data);
    
    return mat;
  }

  /**
   * Convert OpenCV Mat to buffer
   */
  private matToBuffer(mat: any): Buffer {
    const data = new Uint8Array(mat.data);
    return Buffer.from(data);
  }

  /**
   * Convert OpenCV Mat contour to points array
   */
  private matToPoints(mat: any): Point[] {
    const points: Point[] = [];
    const data = mat.data32S;
    
    for (let i = 0; i < mat.rows; i++) {
      points.push({
        x: data[i * 2],
        y: data[i * 2 + 1]
      });
    }
    
    return points;
  }

  /**
   * Convert points array to OpenCV Mat
   */
  private pointsToMat(points: Point[]): any {
    const mat = new this.cvInstance.Mat(points.length, 1, this.cvInstance.CV_32SC2);
    const data = mat.data32S;
    
    points.forEach((point, i) => {
      data[i * 2] = point.x;
      data[i * 2 + 1] = point.y;
    });
    
    return mat;
  }

  /**
   * Preprocess image for better contour detection
   */
  private preprocessImage(mat: any): any {
    const gray = new this.cvInstance.Mat();
    const blurred = new this.cvInstance.Mat();
    const edges = new this.cvInstance.Mat();
    
    // Convert to grayscale
    if (mat.channels() > 1) {
      this.cvInstance.cvtColor(mat, gray, this.cvInstance.COLOR_RGBA2GRAY);
    } else {
      mat.copyTo(gray);
    }
    
    // Apply Gaussian blur
    const ksize = new this.cvInstance.Size(5, 5);
    this.cvInstance.GaussianBlur(gray, blurred, ksize, 0);
    
    // Apply adaptive threshold or Canny edge detection
    this.cvInstance.Canny(blurred, edges, 50, 150);
    
    // Cleanup intermediate matrices
    gray.delete();
    blurred.delete();
    
    return edges;
  }

  /**
   * Find contours in processed image
   */
  private findContours(processed: any): any {
    const contours = new this.cvInstance.MatVector();
    const hierarchy = new this.cvInstance.Mat();
    
    this.cvInstance.findContours(
      processed,
      contours,
      hierarchy,
      this.cvInstance.RETR_EXTERNAL,
      this.cvInstance.CHAIN_APPROX_SIMPLE
    );
    
    hierarchy.delete();
    
    // Sort contours by area (largest first)
    const sortedContours = new this.cvInstance.MatVector();
    const areas: { index: number; area: number }[] = [];
    
    for (let i = 0; i < contours.size(); i++) {
      areas.push({
        index: i,
        area: this.cvInstance.contourArea(contours.get(i))
      });
    }
    
    areas.sort((a, b) => b.area - a.area);
    
    for (const { index } of areas) {
      sortedContours.push_back(contours.get(index));
    }
    
    contours.delete();
    return sortedContours;
  }

  /**
   * Find the best matching contour for enhancement
   */
  private findBestMatchingContour(processed: any, originalContour: any): any {
    const contours = this.findContours(processed);
    let bestMatch = originalContour;
    let bestScore = Infinity;
    
    for (let i = 0; i < contours.size(); i++) {
      const contour = contours.get(i);
      const score = this.cvInstance.matchShapes(
        originalContour,
        contour,
        this.cvInstance.CONTOURS_MATCH_I2,
        0
      );
      
      if (score < bestScore) {
        bestScore = score;
        bestMatch = contour;
      }
    }
    
    // Create a copy of the best match
    const result = new this.cvInstance.Mat();
    bestMatch.copyTo(result);
    
    contours.delete();
    return result;
  }

  /**
   * Calculate confidence score for a polygon
   */
  private calculateConfidence(original: any, simplified: any): number {
    const originalArea = this.cvInstance.contourArea(original);
    const simplifiedArea = this.cvInstance.contourArea(simplified);
    const areaRatio = simplifiedArea / originalArea;
    
    const originalPerimeter = this.cvInstance.arcLength(original, true);
    const simplifiedPerimeter = this.cvInstance.arcLength(simplified, true);
    const perimeterRatio = simplifiedPerimeter / originalPerimeter;
    
    // Confidence based on how well the simplified version preserves area and perimeter
    const confidence = (areaRatio * 0.7 + perimeterRatio * 0.3);
    
    return Math.min(Math.max(confidence, 0), 1);
  }

  /**
   * Validate if polygon is suitable for processing
   */
  validatePolygon(points: Point[]): { valid: boolean; reason?: string } {
    if (points.length < 3) {
      return { valid: false, reason: 'Polygon must have at least 3 points' };
    }

    if (points.length > 1000) {
      return { valid: false, reason: 'Polygon has too many points (max 1000)' };
    }

    // Check for duplicate consecutive points
    for (let i = 0; i < points.length; i++) {
      const next = (i + 1) % points.length;
      if (points[i].x === points[next].x && points[i].y === points[next].y) {
        return { valid: false, reason: 'Polygon contains duplicate consecutive points' };
      }
    }

    return { valid: true };
  }
}

// Export singleton instance
export const polygonProcessor = PolygonProcessor.getInstance();