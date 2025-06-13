// /backend/src/utils/exports.helper.ts
import fs from 'fs';
import path from 'path';
import { Request, Response, NextFunction } from 'express';
import { MLExportBatchJob, ExportFormat } from '@koutu/shared/schemas/export';
import { ExportMocks } from '../__mocks__/exports.mock';

/**
 * Helper utilities for export testing
 */
export class ExportTestHelpers {
    private static readonly TEST_TEMP_DIR = path.join(__dirname, '../../test-temp');
    private static readonly TEST_EXPORTS_DIR = path.join(__dirname, '../../test-exports');

    /**
     * Create mock Express Request object
     */
    static createMockRequest(overrides: Partial<Request> = {}): Partial<Request> {
        return {
            user: { id: 'user-123', email: 'test@example.com' },
            body: {},
            params: {},
            query: {},
            headers: {},
            method: 'GET',
            url: '/',
            ...overrides
        };
    }

    /**
     * Create mock Express Response object
     */
    static createMockResponse(): Partial<Response> {
        const response = {
            status: jest.fn().mockReturnThis(),
            json: jest.fn().mockReturnThis(),
            send: jest.fn().mockReturnThis(),
            download: jest.fn().mockReturnThis(),
            end: jest.fn().mockReturnThis(),
            header: jest.fn().mockReturnThis(),
            cookie: jest.fn().mockReturnThis(),
            clearCookie: jest.fn().mockReturnThis(),
            redirect: jest.fn().mockReturnThis(),
            render: jest.fn().mockReturnThis(),
            type: jest.fn().mockReturnThis(),
            locals: {},
            headersSent: false,
            statusCode: 200
        };
        return response;
    }

    /**
     * Create mock Express NextFunction
     */
    static createMockNext(): NextFunction {
        return jest.fn();
    }

    /**
     * Setup test directories
     */
    static setupTestDirectories(): void {
        if (!fs.existsSync(this.TEST_TEMP_DIR)) {
            fs.mkdirSync(this.TEST_TEMP_DIR, { recursive: true });
        }
        if (!fs.existsSync(this.TEST_EXPORTS_DIR)) {
            fs.mkdirSync(this.TEST_EXPORTS_DIR, { recursive: true });
        }
    }

    /**
     * Cleanup test directories
     */
    static cleanupTestDirectories(): void {
        if (fs.existsSync(this.TEST_TEMP_DIR)) {
            fs.rmSync(this.TEST_TEMP_DIR, { recursive: true, force: true });
        }
        if (fs.existsSync(this.TEST_EXPORTS_DIR)) {
            fs.rmSync(this.TEST_EXPORTS_DIR, { recursive: true, force: true });
        }
    }

    /**
     * Create a test export directory structure
     */
    static createTestExportStructure(exportId: string): string {
        const exportDir = path.join(this.TEST_TEMP_DIR, exportId);
        const imagesDir = path.join(exportDir, 'images');
        const masksDir = path.join(exportDir, 'masks');

        fs.mkdirSync(exportDir, { recursive: true });
        fs.mkdirSync(imagesDir, { recursive: true });
        fs.mkdirSync(masksDir, { recursive: true });

        return exportDir;
    }

    /**
     * Create mock image files for testing
     */
    static createMockImageFiles(exportDir: string, count: number = 3): string[] {
        const imagesDir = path.join(exportDir, 'images');
        const imagePaths: string[] = [];

        for (let i = 0; i < count; i++) {
            const imagePath = path.join(imagesDir, `garment_${i + 1}.jpg`);
            // Create a minimal fake image file (just for file system testing)
            fs.writeFileSync(imagePath, Buffer.from([0xFF, 0xD8, 0xFF, 0xE0])); // JPEG header
            imagePaths.push(imagePath);
        }

        return imagePaths;
    }

    /**
     * Create mock annotation files
     */
    static createMockAnnotationFiles(exportDir: string, format: ExportFormat): string[] {
        const files: string[] = [];

        switch (format) {
            case 'coco':
                const cocoPath = path.join(exportDir, 'annotations.json');
                fs.writeFileSync(cocoPath, JSON.stringify(ExportMocks.createMockCOCOData(), null, 2));
                files.push(cocoPath);
                break;

            case 'yolo':
                // YOLO format has individual .txt files for each image
                const classesPath = path.join(exportDir, 'classes.txt');
                fs.writeFileSync(classesPath, 'shirt\npants\ndress\njacket\nshoes');
                files.push(classesPath);

                for (let i = 1; i <= 3; i++) {
                    const labelPath = path.join(exportDir, `garment_${i}.txt`);
                    fs.writeFileSync(labelPath, `0 0.5 0.5 0.5 0.5\n`); // class_id x_center y_center width height
                    files.push(labelPath);
                }
                break;

            case 'pascal_voc':
                // Pascal VOC has individual .xml files for each image
                for (let i = 1; i <= 3; i++) {
                    const xmlPath = path.join(exportDir, `garment_${i}.xml`);
                    const xmlContent = this.createMockPascalVOCXML(`garment_${i}.jpg`, 800, 600);
                    fs.writeFileSync(xmlPath, xmlContent);
                    files.push(xmlPath);
                }
                break;

            case 'csv':
                const csvPath = path.join(exportDir, 'dataset.csv');
                const csvContent = this.createMockCSVContent();
                fs.writeFileSync(csvPath, csvContent);
                files.push(csvPath);
                break;

            case 'raw_json':
                const jsonPath = path.join(exportDir, 'dataset.json');
                const jsonContent = { garments: ExportMocks.createMockGarmentData(3) };
                fs.writeFileSync(jsonPath, JSON.stringify(jsonContent, null, 2));
                files.push(jsonPath);
                break;
        }

        return files;
    }

    /**
     * Create a mock ZIP file
     */
    static createMockZipFile(exportId: string): string {
        const zipPath = path.join(this.TEST_EXPORTS_DIR, `${exportId}.zip`);
        // Create a minimal ZIP file (just for file system testing)
        const zipHeader = Buffer.from([0x50, 0x4B, 0x03, 0x04]); // ZIP file header
        fs.writeFileSync(zipPath, zipHeader);
        return zipPath;
    }

    /**
     * Validate export directory structure
     */
    static validateExportStructure(exportDir: string, format: ExportFormat): boolean {
        if (!fs.existsSync(exportDir)) return false;

        const imagesDir = path.join(exportDir, 'images');
        if (!fs.existsSync(imagesDir)) return false;

        switch (format) {
            case 'coco':
                return fs.existsSync(path.join(exportDir, 'annotations.json'));
            
            case 'yolo':
                return fs.existsSync(path.join(exportDir, 'classes.txt'));
            
            case 'pascal_voc':
                // Check if at least one XML file exists
                const xmlFiles = fs.readdirSync(exportDir).filter(f => f.endsWith('.xml'));
                return xmlFiles.length > 0;
            
            case 'csv':
                return fs.existsSync(path.join(exportDir, 'dataset.csv'));
            
            case 'raw_json':
                return fs.existsSync(path.join(exportDir, 'dataset.json'));
            
            default:
                return false;
        }
    }

    /**
     * Calculate mock polygon area (for testing geometric calculations)
     */
    static calculatePolygonArea(points: Array<{x: number, y: number}>): number {
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
     * Calculate mock bounding box (for testing coordinate calculations)
     */
    static calculateBoundingBox(points: Array<{x: number, y: number}>): [number, number, number, number] {
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
     * Flatten polygon points for COCO format (testing data transformation)
     */
    static flattenPolygonPoints(points: Array<{x: number, y: number}>): number[] {
        const result = [];
        for (const point of points) {
            result.push(point.x, point.y);
        }
        return result;
    }

    /**
     * Create mock Pascal VOC XML content
     */
    private static createMockPascalVOCXML(filename: string, width: number, height: number): string {
        return `<?xml version="1.0" encoding="UTF-8"?>
<annotation>
    <folder>images</folder>
    <filename>${filename}</filename>
    <size>
        <width>${width}</width>
        <height>${height}</height>
        <depth>3</depth>
    </size>
    <object>
        <name>shirt</name>
        <pose>Unspecified</pose>
        <truncated>0</truncated>
        <difficult>0</difficult>
        <bndbox>
            <xmin>200</xmin>
            <ymin>150</ymin>
            <xmax>600</xmax>
            <ymax>450</ymax>
        </bndbox>
    </object>
</annotation>`;
    }

    /**
     * Create mock CSV content
     */
    private static createMockCSVContent(): string {
        return `id,filename,category,width,height,bbox_x,bbox_y,bbox_width,bbox_height,color,size,material
1,garment_1.jpg,shirt,800,600,200,150,400,300,red,M,cotton
2,garment_2.jpg,pants,800,600,150,100,500,400,blue,L,denim
3,garment_3.jpg,dress,800,600,100,50,600,500,green,S,silk`;
    }

    /**
     * Create mock database query function for testing
     */
    static createMockQueryFunction() {
        return jest.fn().mockImplementation((queryText: string, params: any[] = []) => {
            // Simple mock that returns different results based on query patterns
            if (queryText.includes('INSERT INTO export_batch_jobs')) {
                return Promise.resolve(ExportMocks.createMockQueryResult([
                    ExportMocks.createMockExportBatchJob()
                ]));
            }
            
            if (queryText.includes('SELECT * FROM export_batch_jobs WHERE id')) {
                return Promise.resolve(ExportMocks.createMockQueryResult([
                    ExportMocks.createMockExportBatchJob()
                ]));
            }
            
            if (queryText.includes('SELECT * FROM export_batch_jobs WHERE user_id')) {
                return Promise.resolve(ExportMocks.createMockQueryResult([
                    ExportMocks.createMockExportBatchJob({ status: 'completed' }),
                    ExportMocks.createMockExportBatchJob({ status: 'processing' })
                ]));
            }
            
            if (queryText.includes('SELECT g.*, i.* FROM garments g JOIN images i')) {
                return Promise.resolve(ExportMocks.createMockQueryResult(
                    ExportMocks.createMockGarmentData(5)
                ));
            }
            
            if (queryText.includes('UPDATE export_batch_jobs')) {
                return Promise.resolve(ExportMocks.createMockQueryResult([
                    ExportMocks.createMockExportBatchJob({ status: 'completed' })
                ]));
            }
            
            if (queryText.includes('DELETE FROM export_batch_jobs')) {
                return Promise.resolve({ rowCount: 1 });
            }
            
            // Default empty result
            return Promise.resolve(ExportMocks.createMockQueryResult([]));
        });
    }

    /**
     * Create mock file system operations
     */
    static createMockFileSystemOps() {
        return {
            existsSync: jest.fn().mockReturnValue(true),
            mkdirSync: jest.fn(),
            writeFileSync: jest.fn(),
            readFileSync: jest.fn().mockReturnValue(Buffer.from('mock file content')),
            rmSync: jest.fn(),
            readdirSync: jest.fn().mockReturnValue(['file1.jpg', 'file2.jpg']),
            createWriteStream: jest.fn().mockReturnValue({
                on: jest.fn(),
                write: jest.fn(),
                end: jest.fn()
            })
        };
    }

    /**
     * Create mock Sharp image processing operations
     */
    static createMockSharpOps() {
        const mockSharp = {
            metadata: jest.fn().mockResolvedValue(ExportMocks.createMockImageMetadata()),
            jpeg: jest.fn().mockReturnThis(),
            png: jest.fn().mockReturnThis(),
            toFormat: jest.fn().mockReturnThis(),
            toFile: jest.fn().mockResolvedValue(undefined),
            resize: jest.fn().mockReturnThis(),
            extract: jest.fn().mockReturnThis(),
            toBuffer: jest.fn().mockResolvedValue(Buffer.from('mock image buffer'))
        };

        return jest.fn().mockImplementation(() => mockSharp);
    }

    /**
     * Create mock archiver operations
     */
    static createMockArchiverOps() {
        const mockArchive = {
            on: jest.fn(),
            pipe: jest.fn(),
            directory: jest.fn(),
            file: jest.fn(),
            finalize: jest.fn()
        };

        return jest.fn().mockImplementation(() => mockArchive);
    }

    /**
     * Simulate export job progression
     */
    static simulateJobProgression(initialJob: MLExportBatchJob): MLExportBatchJob[] {
        const progressions = [];
        const statuses = ['pending', 'processing', 'completed'];
        
        for (let i = 0; i < statuses.length; i++) {
            const progress = i === 2 ? 100 : (i * 50);
            const processedItems = Math.floor((progress / 100) * initialJob.totalItems);
            
            progressions.push({
                ...initialJob,
                status: statuses[i] as any,
                progress,
                processedItems,
                updatedAt: new Date(Date.now() + (i * 30000)).toISOString(), // 30 seconds apart
                completedAt: i === 2 ? new Date(Date.now() + (i * 30000)).toISOString() : undefined
            });
        }
        
        return progressions;
    }

    /**
     * Create mock authenticated user for testing
     */
    static createMockAuthenticatedUser(overrides: any = {}) {
        return {
            id: 'user-123',
            email: 'test@example.com',
            name: 'Test User',
            role: 'user',
            isActive: true,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            ...overrides
        };
    }

    /**
     * Create mock HTTP headers for testing
     */
    static createMockHeaders(overrides: any = {}) {
        return {
            'content-type': 'application/json',
            'authorization': 'Bearer mock-token',
            'user-agent': 'Jest Test Suite',
            'accept': 'application/json',
            ...overrides
        };
    }

    /**
     * Create mock error objects for testing
     */
    static createMockError(message: string = 'Test error', statusCode: number = 500) {
        const error = new Error(message) as any;
        error.statusCode = statusCode;
        error.isOperational = true;
        return error;
    }

    /**
     * Create mock API error responses
     */
    static createMockApiErrorResponse(statusCode: number, message: string, code?: string) {
        return {
            success: false,
            error: {
                message,
                statusCode,
                code: code || 'GENERIC_ERROR',
                timestamp: new Date().toISOString()
            }
        };
    }

    /**
     * Create mock successful API responses
     */
    static createMockApiSuccessResponse(data: any, message?: string) {
        return {
            success: true,
            message: message || 'Operation completed successfully',
            data,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Validate API response structure
     */
    static validateApiResponse(response: any, expectedFields: string[] = []) {
        const requiredFields = ['success'];
        const allFields = [...requiredFields, ...expectedFields];
        
        for (const field of allFields) {
            if (!(field in response)) {
                throw new Error(`Missing required field: ${field}`);
            }
        }
        
        if (response.success && !response.data && expectedFields.includes('data')) {
            throw new Error('Success response missing data field');
        }
        
        if (!response.success && !response.error) {
            throw new Error('Error response missing error field');
        }
        
        return true;
    }

    /**
     * Create mock database transaction
     */
    static createMockTransaction() {
        return {
            query: jest.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
            release: jest.fn(),
            commit: jest.fn(),
            rollback: jest.fn()
        };
    }

    /**
     * Create mock middleware functions
     */
    static createMockMiddleware() {
        return {
            authenticate: jest.fn((req: any, res: any, next: any) => {
                req.user = this.createMockAuthenticatedUser();
                next();
            }),
            authorize: jest.fn((req: any, res: any, next: any) => next()),
            validate: jest.fn((req: any, res: any, next: any) => next()),
            rateLimit: jest.fn((req: any, res: any, next: any) => next()),
            cors: jest.fn((req: any, res: any, next: any) => next())
        };
    }
}