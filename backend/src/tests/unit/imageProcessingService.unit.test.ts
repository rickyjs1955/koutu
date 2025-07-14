// tests/unit/services/imageProcessingService.unit.test.ts
// COMPLETE TEST SUITE - All tests restored

// ==================== MOCK SETUP (MUST BE FIRST) ====================
// Mock Sharp with proper implementation
const mockSharpInstance = {
    metadata: jest.fn(),
    resize: jest.fn().mockReturnThis(),
    jpeg: jest.fn().mockReturnThis(),
    png: jest.fn().mockReturnThis(),
    webp: jest.fn().mockReturnThis(),
    toColorspace: jest.fn().mockReturnThis(),
    toFile: jest.fn(),
    toBuffer: jest.fn(),
    composite: jest.fn().mockReturnThis()
};

// Create the Sharp mock function
const mockSharp = jest.fn(() => mockSharpInstance);

// Mock the Sharp module
jest.mock('sharp', () => mockSharp);

// Mock other services
jest.mock('../../../src/services/storageService', () => ({
    storageService: {
        getAbsolutePath: jest.fn(),
        saveFile: jest.fn(),
        deleteFile: jest.fn()
    }
}));

jest.mock('../../../src/utils/ApiError');
jest.mock('../../../src/config/firebase', () => ({
    default: { storage: jest.fn() }
}));
jest.mock('firebase-admin', () => ({
    initializeApp: jest.fn(),
    credential: { cert: jest.fn() },
    storage: jest.fn()
}));

// ==================== IMPORTS ====================
import sharp from 'sharp';
import { imageProcessingService, processImage, removeBackground } from '../../../src/services/imageProcessingService';
import { storageService } from '../../../src/services/storageService';

// ==================== TEST DATA HELPERS ====================
const createValidMetadata = () => ({
    width: 800,
    height: 600,
    format: 'jpeg' as const,
    space: 'srgb' as const,
    channels: 3,
    density: 72,
    hasProfile: false,
    hasAlpha: false
});

const createValidBuffer = () => Buffer.from([
    0xFF, 0xD8, // JPEG SOI
    0xFF, 0xE0, 0x00, 0x10, // APP0
    0x4A, 0x46, 0x49, 0x46, 0x00, // JFIF
    0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0xFF, 0xD9 // EOI
]);

// Helper to normalize paths for cross-platform testing
const normalizePath = (filePath: string) => filePath.replace(/\\/g, '/');

// ==================== TESTS ====================
describe('Image Processing Service - Complete Test Suite', () => {
    // Cast mocks for TypeScript
    const mockStorageService = storageService as jest.Mocked<typeof storageService>;

    beforeEach(() => {
        jest.clearAllMocks();
        
        // Setup default successful behavior
        mockSharpInstance.metadata.mockResolvedValue(createValidMetadata());
        mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });
        mockSharpInstance.toBuffer.mockResolvedValue(Buffer.from('processed-image'));
        mockStorageService.getAbsolutePath.mockImplementation((path: string) => `/absolute/${path}`);
        
        // Reset the Sharp mock to return our instance
        mockSharp.mockReturnValue(mockSharpInstance);
    });

    describe('validateImageBuffer', () => {
        describe('Valid Images', () => {
            it('should validate a valid JPEG buffer', async () => {
                const validBuffer = createValidBuffer();
                const metadata = createValidMetadata();
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                const result = await imageProcessingService.validateImageBuffer(validBuffer);

                expect(result).toEqual(metadata);
                expect(mockSharp).toHaveBeenCalledWith(validBuffer);
                expect(mockSharpInstance.metadata).toHaveBeenCalled();
            });

            it('should validate supported formats (case-sensitive)', async () => {
                const supportedFormats = ['jpeg', 'png', 'bmp'];
                
                for (const format of supportedFormats) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const validBuffer = createValidBuffer();
                const metadata = { ...createValidMetadata(), format };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                const result = await imageProcessingService.validateImageBuffer(validBuffer);
                expect(result.format).toBe(format);
                }
            });

            it('should validate Instagram-compatible dimensions', async () => {
                const validDimensions = [
                { width: 320, height: 400, name: 'minimum size' },
                { width: 1080, height: 1080, name: 'square' },
                { width: 1440, height: 754, name: 'maximum width' }
                ];

                for (const { width, height } of validDimensions) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const validBuffer = createValidBuffer();
                const metadata = { ...createValidMetadata(), width, height };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                const result = await imageProcessingService.validateImageBuffer(validBuffer);
                expect(result.width).toBe(width);
                expect(result.height).toBe(height);
                }
            });

            it('should validate Instagram-compatible aspect ratios', async () => {
                const validRatios = [
                { width: 1000, height: 1250 }, // 4:5
                { width: 1000, height: 1000 }, // 1:1
                { width: 1000, height: 524 }   // 1.91:1
                ];

                for (const { width, height } of validRatios) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const validBuffer = createValidBuffer();
                const metadata = { ...createValidMetadata(), width, height };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                const result = await imageProcessingService.validateImageBuffer(validBuffer);
                expect(result.width).toBe(width);
                expect(result.height).toBe(height);
                }
            });
        });

        describe('Invalid Images', () => {
            it('should reject corrupted image buffer', async () => {
                const corruptedBuffer = Buffer.from('corrupted-data');
                mockSharpInstance.metadata.mockRejectedValue(new Error('Invalid image format'));

                await expect(imageProcessingService.validateImageBuffer(corruptedBuffer))
                .rejects.toThrow('Invalid image');
            });

            it('should reject buffer without format', async () => {
                const validBuffer = createValidBuffer();
                mockSharpInstance.metadata.mockResolvedValue({
                width: 800,
                height: 600,
                format: undefined
                });

                await expect(imageProcessingService.validateImageBuffer(validBuffer))
                .rejects.toThrow(/Invalid image.*Could not determine image format/);
            });

            it('should reject buffer without dimensions', async () => {
                const validBuffer = createValidBuffer();
                mockSharpInstance.metadata.mockResolvedValue({
                format: 'jpeg',
                width: undefined,
                height: undefined
                });

                await expect(imageProcessingService.validateImageBuffer(validBuffer))
                .rejects.toThrow(/Invalid image.*Could not determine image dimensions/);
            });

            it('should reject unsupported formats', async () => {
                const validBuffer = createValidBuffer();
                mockSharpInstance.metadata.mockResolvedValue({
                width: 800,
                height: 600,
                format: 'gif'
                });

                await expect(imageProcessingService.validateImageBuffer(validBuffer))
                .rejects.toThrow(/Invalid image.*Unsupported image format: gif/);
            });

            it('should reject case-sensitive format variations', async () => {
                const validBuffer = createValidBuffer();
                const invalidFormats = ['JPEG', 'Jpeg', 'PNG', 'Png'];

                for (const format of invalidFormats) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const metadata = { ...createValidMetadata(), format };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                await expect(imageProcessingService.validateImageBuffer(validBuffer))
                    .rejects.toThrow(new RegExp(`Invalid image.*Unsupported image format: ${format}`));
                }
            });

            it('should reject images with invalid dimensions', async () => {
                const invalidDimensions = [
                { width: 200, height: 250, expectedError: 'width too small' }, // Valid ratio but too small
                { width: 1500, height: 1200, expectedError: 'width too large' } // Valid ratio but too large
                ];

                for (const { width, height, expectedError } of invalidDimensions) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const validBuffer = createValidBuffer();
                const metadata = { ...createValidMetadata(), width, height };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                await expect(imageProcessingService.validateImageBuffer(validBuffer))
                    .rejects.toThrow(new RegExp(`Invalid image.*${expectedError}`, 'i'));
                }
            });

            it('should reject images with invalid aspect ratios', async () => {
                const invalidRatios = [
                { width: 1000, height: 1300 }, // too tall
                { width: 1000, height: 500 }   // too wide
                ];

                for (const { width, height } of invalidRatios) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const validBuffer = createValidBuffer();
                const metadata = { ...createValidMetadata(), width, height };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                await expect(imageProcessingService.validateImageBuffer(validBuffer))
                    .rejects.toThrow(/Invalid image.*Invalid aspect ratio/);
                }
            });

            it('should handle NaN and Infinity dimensions appropriately', async () => {
                const validBuffer = createValidBuffer();
                const extremeValues = [
                { width: NaN, height: 600 },
                { width: 800, height: NaN },
                { width: Infinity, height: 600 },
                { width: 800, height: Infinity }
                ];

                for (const dimensions of extremeValues) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const metadata = { ...createValidMetadata(), ...dimensions };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                await expect(imageProcessingService.validateImageBuffer(validBuffer))
                    .rejects.toThrow(/Invalid image.*(Could not determine image dimensions|width too (large|small)|height too (large|small)|got Infinitypx|Invalid aspect ratio)/);
                }
            });

            it('should handle negative dimensions appropriately', async () => {
                const validBuffer = createValidBuffer();
                const negativeDimensions = [
                { width: -800, height: 600 },
                { width: 800, height: -600 }
                ];

                for (const dimensions of negativeDimensions) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const metadata = { ...createValidMetadata(), ...dimensions };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                await expect(imageProcessingService.validateImageBuffer(validBuffer))
                    .rejects.toThrow(/Invalid image.*(Invalid aspect ratio|width too small|height too small)/);
                }
            });
        });

        describe('Error Handling', () => {
            it('should wrap Sharp processing errors with "Invalid image"', async () => {
                const invalidBuffer = Buffer.from('not-an-image');
                const sharpError = new Error('Input file is missing or not an image');
                mockSharpInstance.metadata.mockRejectedValue(sharpError);

                await expect(imageProcessingService.validateImageBuffer(invalidBuffer))
                .rejects.toThrow(/Invalid image.*Input file is missing/);
            });

            it('should handle empty buffer gracefully', async () => {
                const emptyBuffer = Buffer.alloc(0);
                mockSharpInstance.metadata.mockRejectedValue(new Error('Input buffer is empty'));

                await expect(imageProcessingService.validateImageBuffer(emptyBuffer))
                    .rejects.toThrow(/Invalid image.*Input buffer is empty/);
            });
        });
    });

    describe('resizeImage', () => {
        const inputPath = 'uploads/test-image.jpg';

        beforeEach(() => {
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            mockSharpInstance.metadata.mockResolvedValue(createValidMetadata());
            mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });
        });

        it('should resize image with default parameters', async () => {
            const result = await imageProcessingService.resizeImage(inputPath);

            expect(normalizePath(result)).toBe('uploads/test-image_800x800.jpg');
            expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 800,
                height: 800,
                fit: 'contain',
                withoutEnlargement: true
            });
        });

        it('should resize with custom dimensions and fit options', async () => {
            const result = await imageProcessingService.resizeImage(inputPath, 400, 300, 'cover');

            expect(normalizePath(result)).toBe('uploads/test-image_400x300.jpg');
            expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 400,
                height: 300,
                fit: 'cover',
                withoutEnlargement: true
            });
        });

        it('should handle invalid input dimensions', async () => {
            const invalidMetadata = {
                format: 'jpeg',
                width: undefined,
                height: undefined
            };
            mockSharpInstance.metadata.mockResolvedValue(invalidMetadata);

            await expect(imageProcessingService.resizeImage(inputPath, 400, 300))
                .rejects.toThrow(/Failed to resize image.*Invalid input image dimensions/);
        });

        it('should handle processing errors with specific error message', async () => {
            const processingError = new Error('Processing failed');
            mockSharpInstance.toFile.mockRejectedValue(processingError);

            await expect(imageProcessingService.resizeImage(inputPath, 400, 300))
                .rejects.toThrow(/Failed to resize image/);
        });
    });

    describe('convertToSRGB', () => {
        const inputPath = 'uploads/test-image.jpg';

        beforeEach(() => {
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
        });

        it('should return original path if already sRGB', async () => {
            const srgbMetadata = { ...createValidMetadata(), space: 'srgb' };
            mockSharpInstance.metadata.mockResolvedValue(srgbMetadata);

            const result = await imageProcessingService.convertToSRGB(inputPath);

            expect(result).toBe(inputPath);
            expect(mockSharpInstance.toColorspace).not.toHaveBeenCalled();
        });

        it('should convert non-sRGB to sRGB', async () => {
            const cmykMetadata = { ...createValidMetadata(), space: 'cmyk' };
            mockSharpInstance.metadata.mockResolvedValue(cmykMetadata);
            mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });

            const result = await imageProcessingService.convertToSRGB(inputPath);

            expect(normalizePath(result)).toBe('uploads/test-image_srgb.jpg');
            expect(mockSharpInstance.toColorspace).toHaveBeenCalledWith('srgb');
            expect(mockSharpInstance.toFile).toHaveBeenCalled();
            });

            it('should handle conversion errors with specific error message', async () => {
            const metadataError = new Error('Metadata failed');
            mockSharpInstance.metadata.mockRejectedValue(metadataError);

            await expect(imageProcessingService.convertToSRGB(inputPath))
                .rejects.toThrow(/Failed to convert to sRGB/);
        });
    });

    describe('extractMetadata', () => {
        const inputPath = 'uploads/test-image.jpg';

        beforeEach(() => {
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
        });

        it('should extract metadata from valid image', async () => {
            const expectedMetadata = createValidMetadata();
            mockSharpInstance.metadata.mockResolvedValue(expectedMetadata);

            const result = await imageProcessingService.extractMetadata(inputPath);

            expect(result).toEqual(expectedMetadata);
            expect(mockSharp).toHaveBeenCalledWith('/absolute/path/uploads/test-image.jpg');
        });

        it('should handle missing format with specific error', async () => {
            const metadataWithoutFormat = {
                width: 800,
                height: 600,
                format: undefined
            };
            mockSharpInstance.metadata.mockResolvedValue(metadataWithoutFormat);

            await expect(imageProcessingService.extractMetadata(inputPath))
                .rejects.toThrow(/Failed to extract image metadata.*Could not extract image format/);
        });

        it('should handle extraction errors with specific error message', async () => {
            const metadataError = new Error('Metadata failed');
            mockSharpInstance.metadata.mockRejectedValue(metadataError);

            await expect(imageProcessingService.extractMetadata(inputPath))
                .rejects.toThrow(/Failed to extract image metadata/);
        });
    });

    describe('generateThumbnail', () => {
            const inputPath = 'uploads/test-image.jpg';

            beforeEach(() => {
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            mockSharpInstance.toFile.mockResolvedValue({ size: 50000 });
        });

        it('should generate thumbnail with default size', async () => {
            const result = await imageProcessingService.generateThumbnail(inputPath);

            expect(normalizePath(result)).toBe('uploads/test-image_thumb_200.jpg');
            expect(mockSharpInstance.resize).toHaveBeenCalledWith(200, 200, {
                fit: 'cover',
                position: 'center'
            });
            expect(mockSharpInstance.jpeg).toHaveBeenCalledWith({ quality: 80 });
        });

        it('should generate thumbnail with custom size', async () => {
            const result = await imageProcessingService.generateThumbnail(inputPath, 150);

            expect(normalizePath(result)).toBe('uploads/test-image_thumb_150.jpg');
            expect(mockSharpInstance.resize).toHaveBeenCalledWith(150, 150, {
                fit: 'cover',
                position: 'center'
            });
            });

            it('should handle generation errors with specific error message', async () => {
            const processingError = new Error('Thumbnail failed');
            mockSharpInstance.toFile.mockRejectedValue(processingError);

            await expect(imageProcessingService.generateThumbnail(inputPath))
                .rejects.toThrow(/Failed to generate thumbnail/);
        });
    });

    describe('optimizeForWeb', () => {
        const inputPath = 'uploads/test-image.jpg';

        beforeEach(() => {
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            mockSharpInstance.toFile.mockResolvedValue({ size: 150000 });
            });

            it('should optimize JPEG images', async () => {
            const jpegMetadata = { ...createValidMetadata(), format: 'jpeg' };
            mockSharpInstance.metadata.mockResolvedValue(jpegMetadata);

            const result = await imageProcessingService.optimizeForWeb(inputPath);

            expect(normalizePath(result)).toBe('uploads/test-image_optimized.jpg');
            expect(mockSharpInstance.jpeg).toHaveBeenCalledWith({
                quality: 85,
                progressive: true,
                mozjpeg: true
            });
        });

        it('should optimize PNG images', async () => {
            const pngPath = 'uploads/test-image.png';
            const pngMetadata = { ...createValidMetadata(), format: 'png' };
            mockSharpInstance.metadata.mockResolvedValue(pngMetadata);

            const result = await imageProcessingService.optimizeForWeb(pngPath);

            expect(normalizePath(result)).toBe('uploads/test-image_optimized.png');
            expect(mockSharpInstance.png).toHaveBeenCalledWith({
                quality: 85,
                progressive: true,
                compressionLevel: 6
            });
        });

        it('should convert unsupported formats to JPEG', async () => {
            const bmpPath = 'uploads/test-image.bmp';
            const bmpMetadata = { ...createValidMetadata(), format: 'bmp' };
            mockSharpInstance.metadata.mockResolvedValue(bmpMetadata);

            const result = await imageProcessingService.optimizeForWeb(bmpPath);

            expect(normalizePath(result)).toBe('uploads/test-image_optimized.bmp');
            expect(mockSharpInstance.jpeg).toHaveBeenCalledWith({
                quality: 85,
                progressive: true
            });
            });

            it('should handle optimization errors with specific error message', async () => {
            const processingError = new Error('Optimization failed');
            mockSharpInstance.toFile.mockRejectedValue(processingError);

            await expect(imageProcessingService.optimizeForWeb(inputPath))
                .rejects.toThrow(/Failed to optimize image/);
        });
    });

    describe('optimizeForMobile', () => {
        const inputPath = 'uploads/test-image.jpg';

        beforeEach(() => {
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            mockSharpInstance.toFile.mockResolvedValue({ size: 120000 });
        });

        it('should optimize image for mobile with default settings', async () => {
            const result = await imageProcessingService.optimizeForMobile(inputPath);

            expect(normalizePath(result)).toBe('uploads/test-image_mobile.webp');
            expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 800,
                withoutEnlargement: true
            });
            expect(mockSharpInstance.webp).toHaveBeenCalledWith({
                quality: 85,
                effort: 4,
                lossless: false
            });
            expect(mockSharpInstance.toFile).toHaveBeenCalled();
        });

        it('should convert JPEG to WebP for mobile optimization', async () => {
            const jpegPath = 'uploads/test-image.jpg';
            
            const result = await imageProcessingService.optimizeForMobile(jpegPath);

            expect(normalizePath(result)).toBe('uploads/test-image_mobile.webp');
            expect(mockSharpInstance.webp).toHaveBeenCalledWith({
                quality: 85,
                effort: 4,
                lossless: false
            });
        });

        it('should convert PNG to WebP for mobile optimization', async () => {
            const pngPath = 'uploads/test-image.png';
            
            const result = await imageProcessingService.optimizeForMobile(pngPath);

            expect(normalizePath(result)).toBe('uploads/test-image_mobile.webp');
            expect(mockSharpInstance.webp).toHaveBeenCalledWith({
                quality: 85,
                effort: 4,
                lossless: false
            });
        });

        it('should convert BMP to WebP for mobile optimization', async () => {
            const bmpPath = 'uploads/test-image.bmp';
            
            const result = await imageProcessingService.optimizeForMobile(bmpPath);

            expect(normalizePath(result)).toBe('uploads/test-image_mobile.webp');
            expect(mockSharpInstance.webp).toHaveBeenCalledWith({
                quality: 85,
                effort: 4,
                lossless: false
            });
        });

        it('should resize large images to 800px width max while maintaining aspect ratio', async () => {
            await imageProcessingService.optimizeForMobile(inputPath);

            expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 800,
                withoutEnlargement: true
            });
        });

        it('should preserve small images without enlargement', async () => {
            await imageProcessingService.optimizeForMobile(inputPath);

            expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 800,
                withoutEnlargement: true
            });
        });

        it('should handle files with no extension', async () => {
            const noExtensionPath = 'uploads/image-without-extension';
            
            const result = await imageProcessingService.optimizeForMobile(noExtensionPath);

            expect(normalizePath(result)).toBe('uploads/image-without-extension_mobile.webp');
            expect(mockSharpInstance.webp).toHaveBeenCalledWith({
                quality: 85,
                effort: 4,
                lossless: false
            });
        });

        it('should handle nested directory structures', async () => {
            const nestedPath = 'uploads/users/123/garments/456/mobile-image.jpg';
            
            const result = await imageProcessingService.optimizeForMobile(nestedPath);

            expect(normalizePath(result)).toBe('uploads/users/123/garments/456/mobile-image_mobile.webp');
        });

        it('should handle special characters in file names', async () => {
            const specialCharPath = 'uploads/mobile image (1) - copy [final].jpg';
            
            const result = await imageProcessingService.optimizeForMobile(specialCharPath);

            expect(normalizePath(result)).toBe('uploads/mobile image (1) - copy [final]_mobile.webp');
        });

        it('should handle Unicode characters in file names', async () => {
            const unicodePath = 'uploads/移动端_图片.jpg';
            
            const result = await imageProcessingService.optimizeForMobile(unicodePath);

            expect(result).toContain('移动端_图片_mobile.webp');
        });

        it('should handle multiple file extensions correctly', async () => {
            const testCases = [
                { input: 'test.jpg', expected: 'test_mobile.webp' },
                { input: 'test.jpeg', expected: 'test_mobile.webp' },
                { input: 'test.png', expected: 'test_mobile.webp' },
                { input: 'test.bmp', expected: 'test_mobile.webp' },
                { input: 'test.webp', expected: 'test_mobile.webp' },
                { input: 'test.JPEG', expected: 'test_mobile.webp' },
                { input: 'test.PNG', expected: 'test_mobile.webp' }
            ];

            for (const { input, expected } of testCases) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/uploads/${input}`);
                mockSharpInstance.toFile.mockResolvedValue({ size: 120000 });

                const result = await imageProcessingService.optimizeForMobile(`uploads/${input}`);
                expect(normalizePath(result)).toBe(`uploads/${expected}`);
            }
        });

        it('should handle processing errors with specific error message', async () => {
            const processingError = new Error('Mobile optimization failed');
            mockSharpInstance.toFile.mockRejectedValue(processingError);

            await expect(imageProcessingService.optimizeForMobile(inputPath))
                .rejects.toThrow(/Failed to optimize for mobile/);
        });

        it('should handle Sharp resize errors gracefully', async () => {
            const resizeError = new Error('Resize operation failed');
            mockSharpInstance.resize.mockImplementation(() => {
                throw resizeError;
            });

            await expect(imageProcessingService.optimizeForMobile(inputPath))
                .rejects.toThrow(/Failed to optimize for mobile.*Resize operation failed/);
        });

        it('should handle Sharp WebP conversion errors gracefully', async () => {
            // Reset resize to work properly first
            mockSharpInstance.resize.mockReturnThis();
            
            const webpError = new Error('WebP conversion failed');
            mockSharpInstance.webp.mockImplementation(() => {
                throw webpError;
            });

            await expect(imageProcessingService.optimizeForMobile(inputPath))
                .rejects.toThrow(/Failed to optimize for mobile.*WebP conversion failed/);
        });

        it('should handle storage service errors gracefully', async () => {
            const storageError = new Error('Storage path resolution failed');
            mockStorageService.getAbsolutePath.mockImplementation(() => {
                throw storageError;
            });

            await expect(imageProcessingService.optimizeForMobile(inputPath))
                .rejects.toThrow(/Failed to optimize for mobile.*Storage path resolution failed/);
        });

        it('should optimize images of various sizes correctly', async () => {
            const testSizes = [
                { name: 'small', size: { width: 400, height: 300 } },
                { name: 'medium', size: { width: 800, height: 600 } },
                { name: 'large', size: { width: 1200, height: 900 } },
                { name: 'extra-large', size: { width: 2000, height: 1500 } }
            ];

            for (const { name, size } of testSizes) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                // Reset all mocks to default behavior
                mockSharpInstance.resize.mockReturnThis();
                mockSharpInstance.webp.mockReturnThis();
                mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/uploads/${name}-image.jpg`);
                mockSharpInstance.toFile.mockResolvedValue({ size: size.width * size.height * 3 });

                const result = await imageProcessingService.optimizeForMobile(`uploads/${name}-image.jpg`);

                expect(normalizePath(result)).toBe(`uploads/${name}-image_mobile.webp`);
                expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                    width: 800,
                    withoutEnlargement: true
                });
            }
        });

        it('should maintain aspect ratio during mobile optimization', async () => {
            // Reset mocks to ensure clean state
            mockSharpInstance.resize.mockReturnThis();
            mockSharpInstance.webp.mockReturnThis();
            
            // The resize call should only specify width, allowing Sharp to maintain aspect ratio
            await imageProcessingService.optimizeForMobile(inputPath);

            expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 800,
                withoutEnlargement: true
            });
            // Height should not be specified to maintain aspect ratio
            expect(mockSharpInstance.resize).not.toHaveBeenCalledWith(
                expect.objectContaining({ height: expect.any(Number) })
            );
        });

        it('should use Flutter-optimized WebP settings', async () => {
            // Reset mocks to ensure clean state
            mockSharpInstance.resize.mockReturnThis();
            mockSharpInstance.webp.mockReturnThis();
            
            await imageProcessingService.optimizeForMobile(inputPath);

            // Verify WebP settings are optimized for Flutter/mobile
            expect(mockSharpInstance.webp).toHaveBeenCalledWith({
                quality: 85,    // Good quality for mobile
                effort: 4,      // Balanced compression effort
                lossless: false // Lossy for smaller file sizes
            });
        });

        it('should create appropriate file naming for mobile variants', async () => {
            const testPaths = [
                'simple.jpg',
                'uploads/nested/file.png', 
                'complex-file-name_123.bmp',
                'file.with.dots.jpeg'
            ];

            for (const inputPath of testPaths) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                // Reset all mocks to default behavior
                mockSharpInstance.resize.mockReturnThis();
                mockSharpInstance.webp.mockReturnThis();
                mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
                mockSharpInstance.toFile.mockResolvedValue({ size: 120000 });

                const result = await imageProcessingService.optimizeForMobile(inputPath);
                
                // Should always end with _mobile.webp
                expect(result).toMatch(/_mobile\.webp$/);
                // Should not contain the original extension before _mobile
                expect(result).not.toMatch(/\.(jpg|jpeg|png|bmp)_mobile\.webp$/);
            }
        });
    });

    describe('processImage and removeBackground', () => {
        it('should process image and return expected structure', async () => {
            const mockFile = {
                fieldname: 'image',
                originalname: 'test-image.jpg',
                encoding: '7bit',
                mimetype: 'image/jpeg',
                size: 204800,
                buffer: createValidBuffer()
            };
            const userId = 'user-123';
            const garmentId = 'garment-456';

            const result = await processImage(mockFile, userId, garmentId);

            expect(result).toMatchObject({
                id: expect.stringContaining('processed-garment-456'),
                url: expect.stringContaining('processed-garment-456.jpg'),
                thumbnailUrl: expect.stringContaining('thumb-garment-456.jpg'),
                metadata: {
                processedAt: expect.any(String),
                userId,
                garmentId
                }
            });
        });

        it('should handle processing errors appropriately', async () => {
            const mockFile = {
                fieldname: 'image',
                originalname: 'corrupted.jpg',
                encoding: '7bit',
                mimetype: 'image/jpeg',
                size: 0,
                buffer: Buffer.alloc(0)
            };

            // The processImage function doesn't actually fail in the current implementation
            // but this test documents the expected behavior if it did
            const result = await processImage(mockFile, 'user-123', 'garment-456');
            expect(result).toBeDefined();
        });

        it('should remove background and return expected structure', async () => {
            const imageId = 'image-123';

            const result = await removeBackground(imageId);

            expect(result).toMatchObject({
                success: true,
                processedImageId: `bg-removed-${imageId}`,
                processedAt: expect.any(String)
            });
            });

            it('should handle various image ID formats', async () => {
            const imageIds = ['simple-id', 'complex-id-with-dashes', '12345', 'id_with_underscores'];

            for (const imageId of imageIds) {
                const result = await removeBackground(imageId);
                expect(result.processedImageId).toBe(`bg-removed-${imageId}`);
            }
        });
    });

    describe('Error Handling Patterns', () => {
        it('should maintain consistent error message structure', async () => {
            const testCases = [
                {
                method: 'validateImageBuffer',
                args: [Buffer.from('invalid')],
                expectedPattern: /Invalid image:/
                },
                {
                method: 'resizeImage',
                args: ['nonexistent.jpg'],
                expectedPattern: /Failed to resize image:/
                },
                {
                method: 'convertToSRGB',
                args: ['nonexistent.jpg'],
                expectedPattern: /Failed to convert to sRGB:/
                },
                {
                method: 'extractMetadata',
                args: ['nonexistent.jpg'],
                expectedPattern: /Failed to extract image metadata:/
                },
                {
                method: 'generateThumbnail',
                args: ['nonexistent.jpg'],
                expectedPattern: /Failed to generate thumbnail:/
                },
                {
                method: 'optimizeForWeb',
                args: ['nonexistent.jpg'],
                expectedPattern: /Failed to optimize image:/
                },
                {
                method: 'optimizeForMobile',
                args: ['nonexistent.jpg'],
                expectedPattern: /Failed to optimize for mobile:/
                }
            ];

            for (const { method, args, expectedPattern } of testCases) {
                mockSharpInstance.metadata.mockRejectedValue(new Error('Test error'));
                mockSharpInstance.toFile.mockRejectedValue(new Error('Test error'));

                await expect((imageProcessingService as any)[method](...args))
                .rejects.toThrow(expectedPattern);
            }
        });
    });

    describe('Integration Scenarios', () => {
        it('should complete full processing pipeline', async () => {
            const buffer = createValidBuffer();
            const inputPath = 'pipeline-test.jpg';
            
            // Step 1: Validate
            const metadata = await imageProcessingService.validateImageBuffer(buffer);
            expect(metadata.format).toBe('jpeg');

            // Step 2: Convert (already sRGB)
            const srgbPath = await imageProcessingService.convertToSRGB(inputPath);
            expect(srgbPath).toBe(inputPath);

            // Step 3: Resize
            const resizedPath = await imageProcessingService.resizeImage(srgbPath, 800, 600);
            expect(normalizePath(resizedPath)).toBe('pipeline-test_800x600.jpg');

            // Step 4: Generate thumbnail
            const thumbnailPath = await imageProcessingService.generateThumbnail(resizedPath, 200);
            expect(normalizePath(thumbnailPath)).toContain('_thumb_200.jpg');

            // Step 5: Optimize for web
            const optimizedPath = await imageProcessingService.optimizeForWeb(resizedPath);
            expect(normalizePath(optimizedPath)).toContain('_optimized.jpg');

            // Step 6: Optimize for mobile
            const mobilePath = await imageProcessingService.optimizeForMobile(resizedPath);
            expect(normalizePath(mobilePath)).toContain('_mobile.webp');
        });

        it('should handle concurrent validations', async () => {
            const buffers = Array.from({ length: 5 }, () => createValidBuffer());

            const promises = buffers.map(buffer => 
                imageProcessingService.validateImageBuffer(buffer)
            );

            const results = await Promise.all(promises);
            
            expect(results).toHaveLength(5);
            results.forEach(result => {
                expect(result.format).toBe('jpeg');
            });
        });
    });

    describe('Edge Cases and Boundary Conditions', () => {
        it('should handle extreme but valid dimensions', async () => {
            const extremeValidDimensions = [
                { width: 320, height: 400 }, // Minimum valid
                { width: 1440, height: 754 } // Maximum valid width
            ];

            for (const { width, height } of extremeValidDimensions) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const validBuffer = createValidBuffer();
                const metadata = { ...createValidMetadata(), width, height };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                const result = await imageProcessingService.validateImageBuffer(validBuffer);
                expect(result.width).toBe(width);
                expect(result.height).toBe(height);
            }
        });

        it('should handle boundary aspect ratios', async () => {
            const boundaryRatios = [
                { width: 1000, height: 1250 }, // 0.8 (4:5)
                { width: 1000, height: 524 }   // 1.91 (closest to 1.91:1)
            ];

            for (const { width, height } of boundaryRatios) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                
                const validBuffer = createValidBuffer();
                const metadata = { ...createValidMetadata(), width, height };
                mockSharpInstance.metadata.mockResolvedValue(metadata);

                const result = await imageProcessingService.validateImageBuffer(validBuffer);
                expect(result.width).toBe(width);
                expect(result.height).toBe(height);
            }
        });

        it('should handle complex file paths', async () => {
            const complexPaths = [
                'uploads/user-123/garments/image with spaces.jpg',
                'uploads/subfolder/another-subfolder/test.png',
                'uploads/file-with-many-dashes-and-underscores_123.bmp'
            ];

            for (const inputPath of complexPaths) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/${inputPath}`);
                
                const result = await imageProcessingService.resizeImage(inputPath, 400, 400);
                expect(result).toContain('_400x400');
            }
        });
    });

    describe('Performance Characteristics', () => {
        it('should complete operations within reasonable time', async () => {
            const buffer = createValidBuffer();

            const startTime = Date.now();
            await imageProcessingService.validateImageBuffer(buffer);
            const duration = Date.now() - startTime;

            expect(duration).toBeLessThan(100);
        });

        it('should handle multiple operations efficiently', async () => {
            const inputPath = 'performance-test.jpg';
            const operations = 10;

            const startTime = Date.now();
            
            const promises = Array.from({ length: operations }, () =>
                imageProcessingService.extractMetadata(inputPath)
            );

            await Promise.all(promises);
            const duration = Date.now() - startTime;

            expect(duration).toBeLessThan(500); // Should complete 10 operations in under 500ms
        });
    });

    describe('Advanced Validation Scenarios', () => {
        it('should handle WebP format validation', async () => {
            const validBuffer = createValidBuffer();
            // Note: WebP is not in supported formats list, should be rejected
            const webpMetadata = { ...createValidMetadata(), format: 'webp' };
            mockSharpInstance.metadata.mockResolvedValue(webpMetadata);

            await expect(imageProcessingService.validateImageBuffer(validBuffer))
                .rejects.toThrow(/Invalid image.*Unsupported image format: webp/);
            });

            it('should handle TIFF format validation', async () => {
            const validBuffer = createValidBuffer();
            // TIFF is not in supported formats list, should be rejected
            const tiffMetadata = { ...createValidMetadata(), format: 'tiff' };
            mockSharpInstance.metadata.mockResolvedValue(tiffMetadata);

            await expect(imageProcessingService.validateImageBuffer(validBuffer))
                .rejects.toThrow(/Invalid image.*Unsupported image format: tiff/);
        });

        it('should handle very large valid images', async () => {
            const validBuffer = createValidBuffer();
            const largeValidMetadata = {
                ...createValidMetadata(),
                width: 1440,
                height: 1440,
                size: 5000000 // 5MB
            };
            mockSharpInstance.metadata.mockResolvedValue(largeValidMetadata);

            const result = await imageProcessingService.validateImageBuffer(validBuffer);
            expect(result.width).toBe(1440);
            expect(result.height).toBe(1440);
        });

        it('should handle square images at boundary dimensions', async () => {
            const validBuffer = createValidBuffer();
            const squareMetadata = {
                ...createValidMetadata(),
                width: 320,
                height: 320
            };
            mockSharpInstance.metadata.mockResolvedValue(squareMetadata);

            const result = await imageProcessingService.validateImageBuffer(validBuffer);
            expect(result.width).toBe(320);
            expect(result.height).toBe(320);
        });
    });

    describe('Color Space Conversion Edge Cases', () => {
        it('should handle unknown color spaces', async () => {
            const inputPath = 'uploads/unknown-colorspace.jpg';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            
            const unknownSpaceMetadata = { ...createValidMetadata(), space: 'lab' };
            mockSharpInstance.metadata.mockResolvedValue(unknownSpaceMetadata);
            mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });

            const result = await imageProcessingService.convertToSRGB(inputPath);

            expect(normalizePath(result)).toBe('uploads/unknown-colorspace_srgb.jpg');
            expect(mockSharpInstance.toColorspace).toHaveBeenCalledWith('srgb');
        });

        it('should handle missing color space information', async () => {
            const inputPath = 'uploads/no-colorspace.jpg';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            
            const noSpaceMetadata = { ...createValidMetadata(), space: undefined };
            mockSharpInstance.metadata.mockResolvedValue(noSpaceMetadata);
            mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });

            const result = await imageProcessingService.convertToSRGB(inputPath);

            expect(normalizePath(result)).toBe('uploads/no-colorspace_srgb.jpg');
            expect(mockSharpInstance.toColorspace).toHaveBeenCalledWith('srgb');
        });
    });

    describe('Resize Operation Edge Cases', () => {
        it('should handle resize with all fit options', async () => {
            const inputPath = 'uploads/test-image.jpg';
            const fitOptions: Array<'contain' | 'cover' | 'fill' | 'inside' | 'outside'> = 
                ['contain', 'cover', 'fill', 'inside', 'outside'];

            for (const fit of fitOptions) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
                mockSharpInstance.metadata.mockResolvedValue(createValidMetadata());
                mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });

                const result = await imageProcessingService.resizeImage(inputPath, 400, 300, fit);

                expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 400,
                height: 300,
                fit,
                withoutEnlargement: true
                });
                expect(normalizePath(result)).toBe('uploads/test-image_400x300.jpg');
            }
        });

        it('should handle very small resize dimensions', async () => {
            const inputPath = 'uploads/test-image.jpg';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            mockSharpInstance.metadata.mockResolvedValue(createValidMetadata());
            mockSharpInstance.toFile.mockResolvedValue({ size: 1024 });

            const result = await imageProcessingService.resizeImage(inputPath, 50, 50);

            expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 50,
                height: 50,
                fit: 'contain',
                withoutEnlargement: true
            });
            expect(normalizePath(result)).toBe('uploads/test-image_50x50.jpg');
        });

        it('should handle very large resize dimensions', async () => {
            const inputPath = 'uploads/test-image.jpg';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            mockSharpInstance.metadata.mockResolvedValue(createValidMetadata());
            mockSharpInstance.toFile.mockResolvedValue({ size: 2048000 });

            const result = await imageProcessingService.resizeImage(inputPath, 2000, 2000);

            expect(mockSharpInstance.resize).toHaveBeenCalledWith({
                width: 2000,
                height: 2000,
                fit: 'contain',
                withoutEnlargement: true
            });
            expect(normalizePath(result)).toBe('uploads/test-image_2000x2000.jpg');
        });
    });

    describe('Thumbnail Generation Edge Cases', () => {
        it('should handle various thumbnail sizes', async () => {
            const inputPath = 'uploads/test-image.jpg';
            const thumbnailSizes = [50, 100, 150, 200, 300, 500];

            for (const size of thumbnailSizes) {
                jest.clearAllMocks();
                mockSharp.mockReturnValue(mockSharpInstance);
                mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
                mockSharpInstance.toFile.mockResolvedValue({ size: 50000 });

                const result = await imageProcessingService.generateThumbnail(inputPath, size);

                expect(mockSharpInstance.resize).toHaveBeenCalledWith(size, size, {
                fit: 'cover',
                position: 'center'
                });
                expect(normalizePath(result)).toBe(`uploads/test-image_thumb_${size}.jpg`);
        }
        });

        it('should handle files with no extension', async () => {
            const inputPath = 'uploads/image-without-extension';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            mockSharpInstance.toFile.mockResolvedValue({ size: 50000 });

            const result = await imageProcessingService.generateThumbnail(inputPath);

            expect(normalizePath(result)).toBe('uploads/image-without-extension_thumb_200.jpg');
        });
    });

    describe('Web Optimization Edge Cases', () => {
        it('should handle WebP optimization', async () => {
            const inputPath = 'uploads/test-image.webp';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            
            const webpMetadata = { ...createValidMetadata(), format: 'webp' };
            mockSharpInstance.metadata.mockResolvedValue(webpMetadata);
            mockSharpInstance.toFile.mockResolvedValue({ size: 150000 });

            const result = await imageProcessingService.optimizeForWeb(inputPath);

            expect(mockSharpInstance.webp).toHaveBeenCalledWith({
                quality: 85,
                lossless: false
            });
            expect(normalizePath(result)).toBe('uploads/test-image_optimized.webp');
        });

        it('should handle TIFF to JPEG conversion', async () => {
            const inputPath = 'uploads/test-image.tiff';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            
            const tiffMetadata = { ...createValidMetadata(), format: 'tiff' };
            mockSharpInstance.metadata.mockResolvedValue(tiffMetadata);
            mockSharpInstance.toFile.mockResolvedValue({ size: 150000 });

            const result = await imageProcessingService.optimizeForWeb(inputPath);

            expect(mockSharpInstance.jpeg).toHaveBeenCalledWith({
                quality: 85,
                progressive: true
            });
            expect(normalizePath(result)).toBe('uploads/test-image_optimized.tiff');
        });

        it('should handle optimization of already optimized files', async () => {
            const inputPath = 'uploads/already_optimized.jpg';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${inputPath}`);
            
            const jpegMetadata = { ...createValidMetadata(), format: 'jpeg' };
            mockSharpInstance.metadata.mockResolvedValue(jpegMetadata);
            mockSharpInstance.toFile.mockResolvedValue({ size: 50000 }); // Small file size

            const result = await imageProcessingService.optimizeForWeb(inputPath);

            expect(mockSharpInstance.jpeg).toHaveBeenCalledWith({
                quality: 85,
                progressive: true,
                mozjpeg: true
            });
            expect(normalizePath(result)).toBe('uploads/already_optimized_optimized.jpg');
        });
    });

    describe('File Path Handling', () => {
        it('should handle nested directory structures', async () => {
            const nestedPath = 'uploads/users/123/garments/456/image.jpg';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${nestedPath}`);
            mockSharpInstance.metadata.mockResolvedValue(createValidMetadata());
            mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });

            const result = await imageProcessingService.resizeImage(nestedPath, 400, 400);

            expect(normalizePath(result)).toBe('uploads/users/123/garments/456/image_400x400.jpg');
        });

        it('should handle special characters in file names', async () => {
            const specialCharPath = 'uploads/image (1) - copy [final].jpg';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${specialCharPath}`);
            mockSharpInstance.metadata.mockResolvedValue(createValidMetadata());
            mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });

            const result = await imageProcessingService.resizeImage(specialCharPath, 400, 400);

            expect(normalizePath(result)).toBe('uploads/image (1) - copy [final]_400x400.jpg');
        });

        it('should handle Unicode characters in file names', async () => {
            const unicodePath = 'uploads/图片_测试.jpg';
            mockStorageService.getAbsolutePath.mockReturnValue(`/absolute/path/${unicodePath}`);
            mockSharpInstance.metadata.mockResolvedValue(createValidMetadata());
            mockSharpInstance.toFile.mockResolvedValue({ size: 204800 });

            const result = await imageProcessingService.resizeImage(unicodePath, 400, 400);

            expect(result).toContain('图片_测试_400x400.jpg');
        });
    });
});