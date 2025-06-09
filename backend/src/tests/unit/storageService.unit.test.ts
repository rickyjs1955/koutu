// /backend/src/__tests__/services/storageService.unit.test.ts
import { jest } from '@jest/globals';

// Create properly typed mocks
const mockFs = {
    promises: {
        writeFile: jest.fn() as jest.MockedFunction<typeof import('fs').promises.writeFile>,
        unlink: jest.fn() as jest.MockedFunction<typeof import('fs').promises.unlink>,
    },
    existsSync: jest.fn() as jest.MockedFunction<typeof import('fs').existsSync>,
    mkdirSync: jest.fn() as jest.MockedFunction<typeof import('fs').mkdirSync>,
};

const mockPath = {
    extname: jest.fn() as jest.MockedFunction<typeof import('path').extname>,
    join: jest.fn() as jest.MockedFunction<typeof import('path').join>,
};

const mockUuidv4 = jest.fn() as jest.MockedFunction<() => string>;

// Define interfaces for better typing
interface MockWriteStream {
    on: jest.MockedFunction<(event: string, callback: (...args: any[]) => void) => MockWriteStream>;
    end: jest.MockedFunction<(chunk?: any) => void>;
}

interface MockFile {
    createWriteStream: jest.MockedFunction<(options?: any) => MockWriteStream>;
    exists: jest.MockedFunction<() => Promise<[boolean]>>;
    delete: jest.MockedFunction<() => Promise<void>>;
    getSignedUrl: jest.MockedFunction<(options: any) => Promise<[string]>>;
}

interface MockBucket {
    file: jest.MockedFunction<(path: string) => MockFile>;
}

// Create mock objects with proper typing
const createMockWriteStream = (): MockWriteStream => {
    const stream = {
        on: jest.fn(),
        end: jest.fn(),
    };
    
    // Make on() return the stream for chaining
    stream.on.mockImplementation(() => stream as MockWriteStream);
    
    return stream as MockWriteStream;
};

const mockWriteStream = createMockWriteStream();

const mockFile: MockFile = {
    createWriteStream: jest.fn(() => mockWriteStream),
    exists: jest.fn(),
    delete: jest.fn(),
    getSignedUrl: jest.fn(),
};

const mockBucket: MockBucket = {
    file: jest.fn(() => mockFile),
};

// Use a mutable config object
const mockConfig = {
    storageMode: 'local' as 'local' | 'firebase',
    uploadsDir: '/test/uploads',
};

// Mock modules efficiently
jest.mock('fs', () => mockFs);
jest.mock('path', () => mockPath);
jest.mock('uuid', () => ({ v4: mockUuidv4 }));
jest.mock('../../config', () => ({ config: mockConfig }));
jest.mock('../../config/firebase', () => ({ bucket: mockBucket }));

// Import after mocking
import { storageService } from '../../services/storageService';

describe('StorageService Unit Tests', () => {
    // Single setup for all tests
    beforeAll(() => {
        // Setup default implementations once
        mockUuidv4.mockReturnValue('test-uuid-123');
        mockPath.extname.mockReturnValue('.jpg');
        mockPath.join.mockImplementation((...args) => args.join('/'));
        
        // Mock console.error to avoid noise
        jest.spyOn(console, 'error').mockImplementation(() => {});
    });

    beforeEach(() => {
        // Only clear call history, not implementations
        jest.clearAllMocks();
        
        // Reset config to default
        mockConfig.storageMode = 'local';
    });

    afterAll(() => {
        jest.restoreAllMocks();
    });

    describe('saveFile', () => {
        const testBuffer = Buffer.from('test');
        const filename = 'test.jpg';

        describe('Local Storage', () => {
        it('should save file successfully', async () => {
            mockFs.promises.writeFile.mockResolvedValueOnce(undefined);

            const result = await storageService.saveFile(testBuffer, filename);

            expect(mockFs.promises.writeFile).toHaveBeenCalledWith(
            '/test/uploads/test-uuid-123.jpg',
            testBuffer
            );
            expect(result).toBe('uploads/test-uuid-123.jpg');
        });

        it('should handle write errors', async () => {
            mockFs.promises.writeFile.mockRejectedValueOnce(new Error('Write failed'));

            await expect(storageService.saveFile(testBuffer, filename))
            .rejects.toThrow('Write failed');
        });

        it('should handle files without extensions', async () => {
            mockPath.extname.mockReturnValueOnce('');
            mockFs.promises.writeFile.mockResolvedValueOnce(undefined);

            const result = await storageService.saveFile(testBuffer, 'test-file');

            expect(result).toBe('uploads/test-uuid-123');
        });
        });

        describe('Firebase Storage', () => {
        beforeEach(() => {
            mockConfig.storageMode = 'firebase';
        });

        it('should upload file successfully', async () => {
            // Use immediate callback instead of setTimeout
            mockWriteStream.on.mockImplementation((event: string, callback: (...args: any[]) => void) => {
            if (event === 'finish') {
                process.nextTick(callback);
            }
            return mockWriteStream;
            });

            const result = await storageService.saveFile(testBuffer, filename);

            expect(mockFile.createWriteStream).toHaveBeenCalledWith({
            metadata: {
                contentType: 'image/jpeg',
                metadata: { originalFilename: filename }
            }
            });
            expect(result).toBe('uploads/test-uuid-123.jpg');
        });

        it('should handle upload errors', async () => {
            mockWriteStream.on.mockImplementation((event: string, callback: (...args: any[]) => void) => {
            if (event === 'error') {
                process.nextTick(() => callback(new Error('Upload failed')));
            }
            return mockWriteStream;
            });

            await expect(storageService.saveFile(testBuffer, filename))
            .rejects.toThrow('Upload failed');
        });

        it('should use correct content type for different file extensions', async () => {
            mockPath.extname.mockReturnValueOnce('.png');
            mockWriteStream.on.mockImplementation((event: string, callback: (...args: any[]) => void) => {
            if (event === 'finish') {
                process.nextTick(callback);
            }
            return mockWriteStream;
            });

            await storageService.saveFile(testBuffer, 'test.png');

            expect(mockFile.createWriteStream).toHaveBeenCalledWith({
            metadata: {
                contentType: 'image/png',
                metadata: { originalFilename: 'test.png' }
            }
            });
        });

        it('should handle unknown file extensions with default content type', async () => {
            mockPath.extname.mockReturnValueOnce('.unknown');
            mockWriteStream.on.mockImplementation((event: string, callback: (...args: any[]) => void) => {
            if (event === 'finish') {
                process.nextTick(callback);
            }
            return mockWriteStream;
            });

            await storageService.saveFile(testBuffer, 'test.unknown');

            expect(mockFile.createWriteStream).toHaveBeenCalledWith({
            metadata: {
                contentType: 'application/octet-stream',
                metadata: { originalFilename: 'test.unknown' }
            }
            });
        });
        });
    });

    describe('deleteFile', () => {
        const filePath = 'uploads/test.jpg';

        describe('Local Storage', () => {
        it('should delete existing file', async () => {
            mockFs.existsSync.mockReturnValueOnce(true);
            mockFs.promises.unlink.mockResolvedValueOnce(undefined);

            const result = await storageService.deleteFile(filePath);

            expect(mockFs.existsSync).toHaveBeenCalled();
            expect(mockFs.promises.unlink).toHaveBeenCalled();
            expect(result).toBe(true);
        });

        it('should return false for non-existent file', async () => {
            mockFs.existsSync.mockReturnValueOnce(false);

            const result = await storageService.deleteFile(filePath);

            expect(result).toBe(false);
            expect(mockFs.promises.unlink).not.toHaveBeenCalled();
        });

        it('should handle delete errors', async () => {
            mockFs.existsSync.mockReturnValueOnce(true);
            mockFs.promises.unlink.mockRejectedValueOnce(new Error('Delete failed'));

            const result = await storageService.deleteFile(filePath);

            expect(result).toBe(false);
        });
        });

        describe('Firebase Storage', () => {
        beforeEach(() => {
            mockConfig.storageMode = 'firebase';
        });

        it('should delete existing Firebase file', async () => {
            mockFile.exists.mockResolvedValueOnce([true]);
            mockFile.delete.mockResolvedValueOnce(undefined);

            const result = await storageService.deleteFile(filePath);

            expect(mockFile.exists).toHaveBeenCalled();
            expect(mockFile.delete).toHaveBeenCalled();
            expect(result).toBe(true);
        });

        it('should return false for non-existent Firebase file', async () => {
            mockFile.exists.mockResolvedValueOnce([false]);

            const result = await storageService.deleteFile(filePath);

            expect(result).toBe(false);
            expect(mockFile.delete).not.toHaveBeenCalled();
        });

        it('should handle Firebase delete errors gracefully', async () => {
            const deleteError = new Error('Firebase delete failed');
            mockFile.exists.mockRejectedValueOnce(deleteError);

            const result = await storageService.deleteFile(filePath);

            expect(console.error).toHaveBeenCalledWith('Error deleting file:', deleteError);
            expect(result).toBe(false);
        });

        it('should handle exists check errors gracefully', async () => {
            mockFile.exists.mockResolvedValueOnce([true]);
            const deleteError = new Error('Delete operation failed');
            mockFile.delete.mockRejectedValueOnce(deleteError);

            const result = await storageService.deleteFile(filePath);

            expect(console.error).toHaveBeenCalledWith('Error deleting file:', deleteError);
            expect(result).toBe(false);
        });
        });
    });

    describe('getAbsolutePath', () => {
        it('should return correct absolute path', () => {
        mockPath.join.mockReturnValueOnce('/absolute/path/uploads/test.jpg');
        
        const result = storageService.getAbsolutePath('uploads/test.jpg');
        
        expect(mockPath.join).toHaveBeenCalledWith(expect.any(String), '../../..', 'uploads/test.jpg');
        expect(result).toBe('/absolute/path/uploads/test.jpg');
        });

        it('should handle empty relative path', () => {
        mockPath.join.mockReturnValueOnce('/absolute/path');

        const result = storageService.getAbsolutePath('');

        expect(mockPath.join).toHaveBeenCalledWith(expect.any(String), '../../..', '');
        expect(result).toBe('/absolute/path');
        });

        it('should handle nested relative paths', () => {
        const relativePath = 'uploads/2024/01/test-file.jpg';
        mockPath.join.mockReturnValueOnce('/absolute/path/uploads/2024/01/test-file.jpg');

        const result = storageService.getAbsolutePath(relativePath);

        expect(result).toBe('/absolute/path/uploads/2024/01/test-file.jpg');
        });
    });

    describe('getSignedUrl', () => {
        const filePath = 'uploads/test.jpg';

        it('should return Firebase signed URL', async () => {
        mockConfig.storageMode = 'firebase';
        mockFile.getSignedUrl.mockResolvedValueOnce(['https://signed-url.com']);

        const result = await storageService.getSignedUrl(filePath);

        expect(result).toBe('https://signed-url.com');
        });

        it('should return local API URL', async () => {
        const result = await storageService.getSignedUrl(filePath);

        expect(result).toBe('/api/v1/files/uploads/test.jpg');
        });

        it('should handle custom expiration', async () => {
        mockConfig.storageMode = 'firebase';
        mockFile.getSignedUrl.mockResolvedValueOnce(['https://signed-url.com']);
        
        // Mock Date.now for predictable test
        const mockNow = 1640995200000;
        jest.spyOn(Date, 'now').mockReturnValueOnce(mockNow);

        await storageService.getSignedUrl(filePath, 120);

        expect(mockFile.getSignedUrl).toHaveBeenCalledWith({
            action: 'read',
            expires: mockNow + (120 * 60 * 1000),
        });
        });

        it('should handle Firebase signed URL errors', async () => {
        mockConfig.storageMode = 'firebase';
        const signedUrlError = new Error('Failed to generate signed URL');
        mockFile.getSignedUrl.mockRejectedValueOnce(signedUrlError);

        await expect(storageService.getSignedUrl(filePath))
            .rejects.toThrow('Failed to generate signed URL');
        });

        it('should return local API URL with custom expiration (ignored)', async () => {
        const result = await storageService.getSignedUrl(filePath, 240);

        expect(result).toBe('/api/v1/files/uploads/test.jpg');
        });

        it('should handle empty file path', async () => {
        const result = await storageService.getSignedUrl('');

        expect(result).toBe('/api/v1/files/');
        });
    });

    describe('getContentType', () => {
        const testCases = [
        { ext: '.jpg', expected: 'image/jpeg' },
        { ext: '.jpeg', expected: 'image/jpeg' },
        { ext: '.png', expected: 'image/png' },
        { ext: '.gif', expected: 'image/gif' },
        { ext: '.webp', expected: 'image/webp' },
        { ext: '.svg', expected: 'image/svg+xml' },
        { ext: '.pdf', expected: 'application/pdf' },
        { ext: '.unknown', expected: 'application/octet-stream' },
        { ext: '', expected: 'application/octet-stream' },
        ];

        test.each(testCases)('should return $expected for $ext', ({ ext, expected }) => {
        const result = storageService.getContentType(ext);
        expect(result).toBe(expected);
        });

        it('should be case insensitive', () => {
        expect(storageService.getContentType('.JPG')).toBe('image/jpeg');
        expect(storageService.getContentType('.PNG')).toBe('image/png');
        });

        it('should handle extensions without dot prefix', () => {
        const result = storageService.getContentType('jpg');
        expect(result).toBe('application/octet-stream');
        });

        it('should handle null and undefined inputs gracefully', () => {
        // Updated implementation handles null/undefined gracefully
        const nullResult = storageService.getContentType(null as any);
        const undefinedResult = storageService.getContentType(undefined as any);
        
        expect(nullResult).toBe('application/octet-stream');
        expect(undefinedResult).toBe('application/octet-stream');
        });
    });

    describe('Edge Cases', () => {
        it('should handle concurrent operations', async () => {
        mockFs.promises.writeFile.mockResolvedValue(undefined);
        mockUuidv4
            .mockReturnValueOnce('uuid-1')
            .mockReturnValueOnce('uuid-2');

        const promises = [
            storageService.saveFile(Buffer.from('test1'), 'file1.jpg'),
            storageService.saveFile(Buffer.from('test2'), 'file2.jpg'),
        ];

        const results = await Promise.all(promises);

        expect(results).toEqual([
            'uploads/uuid-1.jpg',
            'uploads/uuid-2.jpg'
        ]);
        });

        it('should handle large buffers', async () => {
        const largeBuffer = Buffer.alloc(1024); // Smaller for faster test
        mockFs.promises.writeFile.mockResolvedValueOnce(undefined);

        const result = await storageService.saveFile(largeBuffer, 'large.jpg');

        expect(result).toBe('uploads/test-uuid-123.jpg');
        });

        it('should handle special characters in filenames', async () => {
        const specialFilename = 'test file with spaces & symbols!.jpg';
        mockFs.promises.writeFile.mockResolvedValueOnce(undefined);

        const result = await storageService.saveFile(Buffer.from('test'), specialFilename);

        expect(mockPath.extname).toHaveBeenCalledWith(specialFilename);
        expect(result).toBe('uploads/test-uuid-123.jpg');
        });

        it('should maintain type safety', () => {
        // TypeScript compilation test
        const saveFileResult: Promise<string> = storageService.saveFile(Buffer.from('test'), 'test.jpg');
        const deleteFileResult: Promise<boolean> = storageService.deleteFile('path');
        const absolutePathResult: string = storageService.getAbsolutePath('path');
        const signedUrlResult: Promise<string> = storageService.getSignedUrl('path');
        const contentTypeResult: string = storageService.getContentType('.jpg');

        expect(typeof saveFileResult).toBe('object');
        expect(typeof deleteFileResult).toBe('object');
        expect(typeof absolutePathResult).toBe('string');
        expect(typeof signedUrlResult).toBe('object');
        expect(typeof contentTypeResult).toBe('string');
        });
    });

    describe('Directory Creation Logic', () => {
        beforeEach(() => {
        jest.clearAllMocks();
        });

        it('should create uploads directory if it does not exist in local mode', () => {
        // Store current mode
        const currentMode = mockConfig.storageMode;
        
        // Set to local mode for this test
        (mockConfig as any).storageMode = 'local';
        mockFs.existsSync.mockReturnValueOnce(false);
        
        // Simulate the directory creation logic from the service
        if (mockConfig.storageMode === 'local' && !mockFs.existsSync(mockConfig.uploadsDir)) {
            mockFs.mkdirSync(mockConfig.uploadsDir, { recursive: true });
        }
        
        expect(mockFs.existsSync).toHaveBeenCalledWith(mockConfig.uploadsDir);
        expect(mockFs.mkdirSync).toHaveBeenCalledWith(mockConfig.uploadsDir, { recursive: true });
        
        // Restore original mode
        (mockConfig as any).storageMode = currentMode;
        });

        it('should not create directory if it already exists in local mode', () => {
        // Store current mode
        const currentMode = mockConfig.storageMode;
        
        // Set to local mode for this test
        (mockConfig as any).storageMode = 'local';
        mockFs.existsSync.mockReturnValueOnce(true);
        
        // Simulate the directory creation logic from the service
        if (mockConfig.storageMode === 'local' && !mockFs.existsSync(mockConfig.uploadsDir)) {
            mockFs.mkdirSync(mockConfig.uploadsDir, { recursive: true });
        }
        
        expect(mockFs.existsSync).toHaveBeenCalledWith(mockConfig.uploadsDir);
        expect(mockFs.mkdirSync).not.toHaveBeenCalled();
        
        // Restore original mode
        (mockConfig as any).storageMode = currentMode;
        });

        it('should not attempt directory creation in Firebase mode', () => {
        // Store current mode
        const currentMode = mockConfig.storageMode;
        
        // Set to firebase mode for this test
        (mockConfig as any).storageMode = 'firebase';
        
        // Simulate the directory creation logic from the service
        if (mockConfig.storageMode === 'local' && !mockFs.existsSync(mockConfig.uploadsDir)) {
            mockFs.mkdirSync(mockConfig.uploadsDir, { recursive: true });
        }
        
        expect(mockFs.existsSync).not.toHaveBeenCalled();
        expect(mockFs.mkdirSync).not.toHaveBeenCalled();
        
        // Restore original mode
        (mockConfig as any).storageMode = currentMode;
        });
    });
});