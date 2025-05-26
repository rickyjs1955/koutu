import { PolygonServiceUtils } from "../../utils/PolygonServiceUtils";
import * as fs from 'fs/promises';
import * as path from 'path';

// Mock storage service that simulates real file operations
class MockStorageService {
  private savedFiles: Map<string, Buffer> = new Map();
  private shouldFail: boolean = false;

  setShouldFail(fail: boolean) {
    this.shouldFail = fail;
  }

  async saveFile(buffer: Buffer, filePath: string): Promise<void> {
    if (this.shouldFail) {
      throw new Error('Mock storage service failure');
    }
    this.savedFiles.set(filePath, buffer);
  }

  getSavedFile(filePath: string): Buffer | undefined {
    return this.savedFiles.get(filePath);
  }

  getSavedFiles(): Map<string, Buffer> {
    return new Map(this.savedFiles);
  }

  clear() {
    this.savedFiles.clear();
    this.shouldFail = false;
  }
}

describe('PolygonServiceUtils Integration Tests', () => {
  let mockStorageService: MockStorageService;

  beforeEach(() => {
    mockStorageService = new MockStorageService();
  });

  afterEach(() => {
    mockStorageService.clear();
  });

  describe('savePolygonDataForML', () => {
    const mockPolygon = {
      id: 'poly-123',
      points: [
        { x: 0, y: 0 },
        { x: 10, y: 0 },
        { x: 10, y: 10 },
        { x: 0, y: 10 }
      ],
      label: 'test-polygon',
      metadata: {
        category: 'building',
        confidence: 0.95
      },
      created_at: '2024-01-15T10:30:00Z'
    };

    const mockImage = {
      id: 'img-456',
      file_path: '/images/test-image.jpg',
      original_metadata: {
        width: 1920,
        height: 1080,
        format: 'JPEG'
      }
    };

    it('should save polygon data with correct structure', async () => {
      await PolygonServiceUtils.savePolygonDataForML(
        mockPolygon,
        mockImage,
        mockStorageService
      );

      const expectedFilePath = 'data/polygons/poly-123.json';
      const savedBuffer = mockStorageService.getSavedFile(expectedFilePath);
      
      expect(savedBuffer).toBeDefined();
      
      const savedData = JSON.parse(savedBuffer!.toString('utf-8'));
      
      // Verify structure
      expect(savedData).toHaveProperty('polygon');
      expect(savedData).toHaveProperty('image');
      expect(savedData).toHaveProperty('export_metadata');
    });

    it('should include calculated area and perimeter', async () => {
      await PolygonServiceUtils.savePolygonDataForML(
        mockPolygon,
        mockImage,
        mockStorageService
      );

      const savedBuffer = mockStorageService.getSavedFile('data/polygons/poly-123.json');
      const savedData = JSON.parse(savedBuffer!.toString('utf-8'));
      
      expect(savedData.polygon.area).toBe(100); // 10x10 square
      expect(savedData.polygon.perimeter).toBe(40); // 4 sides of 10 units each
    });

    it('should preserve all original polygon data', async () => {
      await PolygonServiceUtils.savePolygonDataForML(
        mockPolygon,
        mockImage,
        mockStorageService
      );

      const savedBuffer = mockStorageService.getSavedFile('data/polygons/poly-123.json');
      const savedData = JSON.parse(savedBuffer!.toString('utf-8'));
      
      expect(savedData.polygon.id).toBe(mockPolygon.id);
      expect(savedData.polygon.points).toEqual(mockPolygon.points);
      expect(savedData.polygon.label).toBe(mockPolygon.label);
      expect(savedData.polygon.metadata).toEqual(mockPolygon.metadata);
      expect(savedData.polygon.created_at).toBe(mockPolygon.created_at);
    });

    it('should preserve all original image data', async () => {
      await PolygonServiceUtils.savePolygonDataForML(
        mockPolygon,
        mockImage,
        mockStorageService
      );

      const savedBuffer = mockStorageService.getSavedFile('data/polygons/poly-123.json');
      const savedData = JSON.parse(savedBuffer!.toString('utf-8'));
      
      expect(savedData.image.id).toBe(mockImage.id);
      expect(savedData.image.file_path).toBe(mockImage.file_path);
      expect(savedData.image.width).toBe(mockImage.original_metadata.width);
      expect(savedData.image.height).toBe(mockImage.original_metadata.height);
      expect(savedData.image.format).toBe(mockImage.original_metadata.format);
    });

    it('should include export metadata with timestamp and version', async () => {
      const beforeSave = new Date();
      
      await PolygonServiceUtils.savePolygonDataForML(
        mockPolygon,
        mockImage,
        mockStorageService
      );

      const afterSave = new Date();
      const savedBuffer = mockStorageService.getSavedFile('data/polygons/poly-123.json');
      const savedData = JSON.parse(savedBuffer!.toString('utf-8'));
      
      expect(savedData.export_metadata.format_version).toBe('1.0');
      
      const exportedAt = new Date(savedData.export_metadata.exported_at);
      expect(exportedAt.getTime()).toBeGreaterThanOrEqual(beforeSave.getTime());
      expect(exportedAt.getTime()).toBeLessThanOrEqual(afterSave.getTime());
    });

    it('should generate properly formatted JSON', async () => {
      await PolygonServiceUtils.savePolygonDataForML(
        mockPolygon,
        mockImage,
        mockStorageService
      );

      const savedBuffer = mockStorageService.getSavedFile('data/polygons/poly-123.json');
      const jsonString = savedBuffer!.toString('utf-8');
      
      // Should be formatted with 2-space indentation
      expect(jsonString).toContain('  ');
      
      // Should be valid JSON
      expect(() => JSON.parse(jsonString)).not.toThrow();
    });

    it('should handle missing image metadata gracefully', async () => {
      const imageWithoutMetadata = {
        id: 'img-no-meta',
        file_path: '/images/no-meta.jpg',
        original_metadata: null
      };

      await PolygonServiceUtils.savePolygonDataForML(
        mockPolygon,
        imageWithoutMetadata,
        mockStorageService
      );

      const savedBuffer = mockStorageService.getSavedFile('data/polygons/poly-123.json');
      const savedData = JSON.parse(savedBuffer!.toString('utf-8'));
      
      expect(savedData.image.width).toBeNull();
      expect(savedData.image.height).toBeNull();
      expect(savedData.image.format).toBeNull();
    });

    it('should handle storage service errors gracefully', async () => {
      mockStorageService.setShouldFail(true);
      
      // Should not throw error, just log it
      await expect(
        PolygonServiceUtils.savePolygonDataForML(
          mockPolygon,
          mockImage,
          mockStorageService
        )
      ).resolves.not.toThrow();
      
      // Should not have saved any files
      expect(mockStorageService.getSavedFiles().size).toBe(0);
    });

    it('should handle complex polygon shapes', async () => {
      const complexPolygon = {
        ...mockPolygon,
        id: 'complex-poly',
        points: [
          { x: 0, y: 0 },
          { x: 5, y: 2 },
          { x: 8, y: 0 },
          { x: 10, y: 5 },
          { x: 6, y: 8 },
          { x: 4, y: 6 },
          { x: 2, y: 8 },
          { x: 0, y: 5 }
        ]
      };

      await PolygonServiceUtils.savePolygonDataForML(
        complexPolygon,
        mockImage,
        mockStorageService
      );

      const savedBuffer = mockStorageService.getSavedFile('data/polygons/complex-poly.json');
      const savedData = JSON.parse(savedBuffer!.toString('utf-8'));
      
      expect(savedData.polygon.area).toBeGreaterThan(0);
      expect(savedData.polygon.perimeter).toBeGreaterThan(0);
      expect(savedData.polygon.points).toEqual(complexPolygon.points);
    });

    it('should handle polygons with minimal points', async () => {
      const trianglePolygon = {
        ...mockPolygon,
        id: 'triangle-poly',
        points: [
          { x: 0, y: 0 },
          { x: 3, y: 0 },
          { x: 1.5, y: 2.6 }
        ]
      };

      await PolygonServiceUtils.savePolygonDataForML(
        trianglePolygon,
        mockImage,
        mockStorageService
      );

      const savedBuffer = mockStorageService.getSavedFile('data/polygons/triangle-poly.json');
      const savedData = JSON.parse(savedBuffer!.toString('utf-8'));
      
      expect(savedData.polygon.area).toBeCloseTo(3.9, 1); // Approximately 3.9 for this triangle
      expect(savedData.polygon.points).toEqual(trianglePolygon.points);
    });

    it('should create unique file paths for different polygons', async () => {
      const polygon1 = { ...mockPolygon, id: 'poly-1' };
      const polygon2 = { ...mockPolygon, id: 'poly-2' };

      await PolygonServiceUtils.savePolygonDataForML(polygon1, mockImage, mockStorageService);
      await PolygonServiceUtils.savePolygonDataForML(polygon2, mockImage, mockStorageService);

      const savedFiles = mockStorageService.getSavedFiles();
      expect(savedFiles.size).toBe(2);
      expect(savedFiles.has('data/polygons/poly-1.json')).toBe(true);
      expect(savedFiles.has('data/polygons/poly-2.json')).toBe(true);
    });
  });
});