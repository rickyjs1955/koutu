// Mock fs with promises BEFORE importing anything
const mockFs = {
  existsSync: jest.fn().mockReturnValue(false),
  mkdirSync: jest.fn(),
  promises: {
    writeFile: jest.fn(),
    unlink: jest.fn(),
    readFile: jest.fn()
  }
};

jest.mock('fs', () => mockFs);
jest.mock('uuid');

// Mock config
const mockConfig = {
  config: {
    storageMode: 'local',
    uploadsDir: '/test/uploads'
  }
};

jest.mock('../../config', () => mockConfig);

// Mock console.log to suppress Firebase warnings
const originalConsoleLog = console.log;
beforeAll(() => {
  console.log = jest.fn();
});

afterAll(() => {
  console.log = originalConsoleLog;
});

// We need to import storageService in each test to handle different storage modes
describe('StorageService - Unit Tests', () => {
  let storageService: any;
  
  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
    const { v4: uuidv4 } = require('uuid');
    (uuidv4 as jest.Mock).mockReturnValue('test-uuid');
  });

  describe('saveFile', () => {
    const testBuffer = Buffer.from('test file content');
    const testFilename = 'test-image.jpg';

    describe('local storage mode', () => {
      beforeEach(() => {
        mockConfig.config.storageMode = 'local';
        storageService = require('../../services/storageService').storageService;
      });

      it('should save file with unique filename', async () => {
        mockFs.promises.writeFile.mockResolvedValue(undefined);

        const result = await storageService.saveFile(testBuffer, testFilename);

        const { v4: uuidv4 } = require('uuid');
        expect(uuidv4).toHaveBeenCalled();
        expect(mockFs.promises.writeFile).toHaveBeenCalledWith(
          expect.stringContaining('test-uuid.jpg'),
          testBuffer
        );
        expect(result).toBe('uploads/test-uuid.jpg');
      });

      it('should handle write errors', async () => {
        const mockError = new Error('Write failed');
        mockFs.promises.writeFile.mockRejectedValue(mockError);

        await expect(storageService.saveFile(testBuffer, testFilename))
          .rejects.toThrow('Write failed');
      });
    });

    describe('firebase storage mode', () => {
      let mockBucket: any;
      
      beforeEach(() => {
        mockConfig.config.storageMode = 'firebase';
        
        // Mock bucket for Firebase tests
        mockBucket = {
          file: jest.fn()
        };
        
        jest.doMock('../../config/firebase', () => ({
          bucket: mockBucket
        }));
        
        storageService = require('../../services/storageService').storageService;
      });

      it('should upload file to Firebase', async () => {
        const mockWriteStream = {
          on: jest.fn(),
          end: jest.fn()
        };
        const mockFile = {
          createWriteStream: jest.fn().mockReturnValue(mockWriteStream)
        };
        mockBucket.file.mockReturnValue(mockFile);

        // Simulate successful upload
        mockWriteStream.on.mockImplementation((event, callback) => {
          if (event === 'finish') {
            setTimeout(() => callback(), 0);
          }
          return mockWriteStream;
        });

        const result = await storageService.saveFile(testBuffer, testFilename);

        expect(mockBucket.file).toHaveBeenCalledWith('uploads/test-uuid.jpg');
        expect(mockFile.createWriteStream).toHaveBeenCalledWith({
          metadata: {
            contentType: 'image/jpeg',
            metadata: {
              originalFilename: testFilename
            }
          }
        });
        expect(mockWriteStream.end).toHaveBeenCalledWith(testBuffer);
        expect(result).toBe('uploads/test-uuid.jpg');
      });

      it('should handle Firebase upload errors', async () => {
        const mockWriteStream = {
          on: jest.fn(),
          end: jest.fn()
        };
        const mockFile = {
          createWriteStream: jest.fn().mockReturnValue(mockWriteStream)
        };
        mockBucket.file.mockReturnValue(mockFile);

        // Simulate upload error
        mockWriteStream.on.mockImplementation((event, callback) => {
          if (event === 'error') {
            setTimeout(() => callback(new Error('Upload failed')), 0);
          }
          return mockWriteStream;
        });

        await expect(storageService.saveFile(testBuffer, testFilename))
          .rejects.toThrow('Upload failed');
      });
    });
  });

  describe('deleteFile', () => {
    const testFilePath = 'uploads/test-file.jpg';

    describe('local storage mode', () => {
      beforeEach(() => {
        mockConfig.config.storageMode = 'local';
        storageService = require('../../services/storageService').storageService;
      });

      it('should delete existing file', async () => {
        mockFs.existsSync.mockReturnValue(true);
        mockFs.promises.unlink.mockResolvedValue(undefined);

        const result = await storageService.deleteFile(testFilePath);

        expect(mockFs.existsSync).toHaveBeenCalled();
        expect(mockFs.promises.unlink).toHaveBeenCalled();
        expect(result).toBe(true);
      });

      it('should return false for non-existent file', async () => {
        mockFs.existsSync.mockReturnValue(false);

        const result = await storageService.deleteFile(testFilePath);

        expect(result).toBe(false);
        expect(mockFs.promises.unlink).not.toHaveBeenCalled();
      });

      it('should handle delete errors', async () => {
        mockFs.existsSync.mockReturnValue(true);
        mockFs.promises.unlink.mockRejectedValue(new Error('Delete failed'));
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        const result = await storageService.deleteFile(testFilePath);

        expect(result).toBe(false);
        expect(consoleSpy).toHaveBeenCalledWith('Error deleting file:', expect.any(Error));
      });
    });

    describe('firebase storage mode', () => {
      let mockBucket: any;
      
      beforeEach(() => {
        mockConfig.config.storageMode = 'firebase';
        
        mockBucket = {
          file: jest.fn()
        };
        
        jest.doMock('../../config/firebase', () => ({
          bucket: mockBucket
        }));
        
        storageService = require('../../services/storageService').storageService;
      });

      it('should delete existing file from Firebase', async () => {
        const mockFile = {
          exists: jest.fn().mockResolvedValue([true]),
          delete: jest.fn().mockResolvedValue(undefined)
        };
        mockBucket.file.mockReturnValue(mockFile);

        const result = await storageService.deleteFile(testFilePath);

        expect(mockBucket.file).toHaveBeenCalledWith(testFilePath);
        expect(mockFile.exists).toHaveBeenCalled();
        expect(mockFile.delete).toHaveBeenCalled();
        expect(result).toBe(true);
      });

      it('should return false for non-existent Firebase file', async () => {
        const mockFile = {
          exists: jest.fn().mockResolvedValue([false]),
          delete: jest.fn()
        };
        mockBucket.file.mockReturnValue(mockFile);

        const result = await storageService.deleteFile(testFilePath);

        expect(result).toBe(false);
        expect(mockFile.delete).not.toHaveBeenCalled();
      });
    });
  });

  describe('getContentType', () => {
    beforeEach(() => {
      storageService = require('../../services/storageService').storageService;
    });

    it('should return correct content type for common image formats', () => {
      expect(storageService.getContentType('.jpg')).toBe('image/jpeg');
      expect(storageService.getContentType('.jpeg')).toBe('image/jpeg');
      expect(storageService.getContentType('.png')).toBe('image/png');
      expect(storageService.getContentType('.gif')).toBe('image/gif');
      expect(storageService.getContentType('.webp')).toBe('image/webp');
      expect(storageService.getContentType('.svg')).toBe('image/svg+xml');
    });

    it('should return correct content type for PDF', () => {
      expect(storageService.getContentType('.pdf')).toBe('application/pdf');
    });

    it('should be case insensitive', () => {
      expect(storageService.getContentType('.JPG')).toBe('image/jpeg');
      expect(storageService.getContentType('.PNG')).toBe('image/png');
    });

    it('should return default content type for unknown extensions', () => {
      expect(storageService.getContentType('.xyz')).toBe('application/octet-stream');
      expect(storageService.getContentType('.doc')).toBe('application/octet-stream');
    });

    it('should handle null, undefined, and empty inputs', () => {
      expect(storageService.getContentType(null)).toBe('application/octet-stream');
      expect(storageService.getContentType(undefined)).toBe('application/octet-stream');
      expect(storageService.getContentType('')).toBe('application/octet-stream');
    });

    it('should handle non-string inputs', () => {
      expect(storageService.getContentType(123 as any)).toBe('application/octet-stream');
      expect(storageService.getContentType({} as any)).toBe('application/octet-stream');
    });
  });

  describe('getAbsolutePath', () => {
    beforeEach(() => {
      storageService = require('../../services/storageService').storageService;
    });

    it('should construct correct absolute path', () => {
      const relativePath = 'uploads/test-file.jpg';
      const result = storageService.getAbsolutePath(relativePath);
      
      // Normalize path separators for cross-platform compatibility
      const normalizedResult = result.replace(/\\/g, '/');
      expect(normalizedResult).toContain(relativePath);
      expect(require('path').isAbsolute(result)).toBe(true);
    });
  });

  describe('getSignedUrl', () => {
    const testFilePath = 'uploads/test-file.jpg';

    describe('local storage mode', () => {
      beforeEach(() => {
        mockConfig.config.storageMode = 'local';
        storageService = require('../../services/storageService').storageService;
      });

      it('should return API endpoint for local files', async () => {
        const result = await storageService.getSignedUrl(testFilePath);
        expect(result).toBe(`/api/v1/files/${testFilePath}`);
      });

      it('should ignore expiration parameter in local mode', async () => {
        const result = await storageService.getSignedUrl(testFilePath, 120);
        expect(result).toBe(`/api/v1/files/${testFilePath}`);
      });
    });

    describe('firebase storage mode', () => {
      let mockBucket: any;
      
      beforeEach(() => {
        mockConfig.config.storageMode = 'firebase';
        
        mockBucket = {
          file: jest.fn()
        };
        
        jest.doMock('../../config/firebase', () => ({
          bucket: mockBucket
        }));
        
        storageService = require('../../services/storageService').storageService;
      });

      it('should generate signed URL with default expiration', async () => {
        const mockUrl = 'https://storage.googleapis.com/signed-url';
        const mockFile = {
          getSignedUrl: jest.fn().mockResolvedValue([mockUrl])
        };
        mockBucket.file.mockReturnValue(mockFile);

        const result = await storageService.getSignedUrl(testFilePath);

        expect(mockBucket.file).toHaveBeenCalledWith(testFilePath);
        expect(mockFile.getSignedUrl).toHaveBeenCalledWith({
          action: 'read',
          expires: expect.any(Number)
        });
        expect(result).toBe(mockUrl);
      });

      it('should use custom expiration time', async () => {
        const mockUrl = 'https://storage.googleapis.com/signed-url';
        const mockFile = {
          getSignedUrl: jest.fn().mockResolvedValue([mockUrl])
        };
        mockBucket.file.mockReturnValue(mockFile);

        const customMinutes = 120;
        await storageService.getSignedUrl(testFilePath, customMinutes);

        const callArgs = mockFile.getSignedUrl.mock.calls[0][0];
        const expectedExpiry = Date.now() + customMinutes * 60 * 1000;
        expect(callArgs.expires).toBeCloseTo(expectedExpiry, -3); // Within 1 second
      });
    });
  });

  describe('getFile', () => {
    const testFilePath = 'uploads/test-file.jpg';
    const testBuffer = Buffer.from('test content');

    describe('local storage mode', () => {
      beforeEach(() => {
        mockConfig.config.storageMode = 'local';
        storageService = require('../../services/storageService').storageService;
      });

      it('should read existing file', async () => {
        mockFs.existsSync.mockReturnValue(true);
        mockFs.promises.readFile.mockResolvedValue(testBuffer);

        const result = await storageService.getFile(testFilePath);

        expect(mockFs.existsSync).toHaveBeenCalled();
        expect(mockFs.promises.readFile).toHaveBeenCalled();
        expect(result).toEqual(testBuffer);
      });

      it('should throw error for non-existent file', async () => {
        mockFs.existsSync.mockReturnValue(false);
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        await expect(storageService.getFile(testFilePath))
          .rejects.toThrow(`File not found: ${testFilePath}`);
        
        expect(consoleSpy).toHaveBeenCalled();
      });

      it('should handle read errors', async () => {
        mockFs.existsSync.mockReturnValue(true);
        const readError = new Error('Read failed');
        mockFs.promises.readFile.mockRejectedValue(readError);
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        await expect(storageService.getFile(testFilePath))
          .rejects.toThrow('Read failed');
        
        expect(consoleSpy).toHaveBeenCalled();
      });
    });

    describe('firebase storage mode', () => {
      let mockBucket: any;
      
      beforeEach(() => {
        mockConfig.config.storageMode = 'firebase';
        
        mockBucket = {
          file: jest.fn()
        };
        
        jest.doMock('../../config/firebase', () => ({
          bucket: mockBucket
        }));
        
        storageService = require('../../services/storageService').storageService;
      });

      it('should download file from Firebase', async () => {
        const mockFile = {
          exists: jest.fn().mockResolvedValue([true]),
          download: jest.fn().mockResolvedValue([testBuffer])
        };
        mockBucket.file.mockReturnValue(mockFile);

        const result = await storageService.getFile(testFilePath);

        expect(mockBucket.file).toHaveBeenCalledWith(testFilePath);
        expect(mockFile.exists).toHaveBeenCalled();
        expect(mockFile.download).toHaveBeenCalled();
        expect(result).toEqual(testBuffer);
      });

      it('should throw error for non-existent Firebase file', async () => {
        const mockFile = {
          exists: jest.fn().mockResolvedValue([false]),
          download: jest.fn()
        };
        mockBucket.file.mockReturnValue(mockFile);
        const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

        await expect(storageService.getFile(testFilePath))
          .rejects.toThrow(`File not found: ${testFilePath}`);
        
        expect(mockFile.download).not.toHaveBeenCalled();
        expect(consoleSpy).toHaveBeenCalled();
      });
    });
  });
});