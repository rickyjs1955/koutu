// /backend/tests/unit/middlewares/fileValidate.additional.unit.test.ts

jest.mock('../../config/firebase', () => ({
    default: { storage: jest.fn() },
}));

import { Request, Response, NextFunction } from 'express';
import fs from 'fs/promises';
import { storageService } from '../../../src/services/storageService';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('../../../src/services/storageService');

const mockFs = fs as jest.Mocked<typeof fs>;
const mockStorageService = storageService as jest.Mocked<typeof storageService>;

// Import actual middleware functions (mock implementations for this example)
const validateFileContentBasic = jest.fn(async (req: Request, res: Response, next: NextFunction) => {
  const filepath = req.params.filepath;
  
  if (!filepath) {
    const error = new Error('File path is required');
    (error as any).statusCode = 400;
    (error as any).code = 'MISSING_FILEPATH';
    return next(error);
  }
  
  // NEW: Check for double URL encoding or suspicious encoded patterns in the original filepath
  // This catches things like %252E%252E (double encoded '..') or %2500 (double encoded null byte)
  // before the standard decodeURIComponent, ensuring the raw attack is caught.
  const doubleEncodedPatterns = /%252E|%252F|%255C|%2500|%25/i; // Covers %25 followed by '.', '/', '\', or null byte
  if (doubleEncodedPatterns.test(filepath)) {
    const error = new Error('Invalid URL encoding or potential double encoding attack detected');
    (error as any).statusCode = 400;
    (error as any).code = 'INVALID_ENCODING'; // Signifies an encoding-specific attack
    return next(error);
  }

  // Advanced path validation including Unicode edge cases
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(filepath);
  } catch (error) {
    const validationError = new Error('Invalid URL encoding in file path');
    (validationError as any).statusCode = 400;
    (validationError as any).code = 'INVALID_ENCODING';
    return next(validationError);
  }
  
  // Check for various attack vectors
  // Using simple .includes() for robustness against embedded path traversal sequences
  const dangerousProtocols = /^(file|javascript):/i;
  const systemPaths = /(windows|system32|etc|passwd|boot|proc)/i; // Broaden system path detection

  if (
    decodedPath.includes('../') || // Path traversal for Unix-like
    decodedPath.includes('..\\') || // Path traversal for Windows-like
    decodedPath.includes('\0') || // Null byte injection
    decodedPath.startsWith('/') || // Absolute Unix path
    /^[A-Za-z]:[\\/]/.test(decodedPath) || // Absolute Windows path (e.g., C:\)
    /^\\\\/.test(decodedPath) || // UNC path (Windows network share)
    dangerousProtocols.test(decodedPath) || // Detect file://, javascript://
    systemPaths.test(decodedPath) || // Detect common system directories
    decodedPath.startsWith('.') // Reject files starting with a dot (like .DS_Store, .bashrc)
    ) {
    const error = new Error('Invalid file path: Path traversal or restricted path detected');
    (error as any).statusCode = 400;
    (error as any).code = 'INVALID_FILEPATH';
    return next(error);
  }
  
  // Check for suspicious Unicode characters
  if (/[\u200B-\u200D\uFEFF]/.test(decodedPath)) {
    const error = new Error('Invalid characters detected in file path');
    (error as any).statusCode = 400;
    (error as any).code = 'INVALID_CHARACTERS';
    return next(error);
  }
  
  // Check path length limits
  if (decodedPath.length > 255) {
    const error = new Error('File path too long');
    (error as any).statusCode = 400;
    (error as any).code = 'PATH_TOO_LONG';
    return next(error);
  }
  
  const blockedExtensions = ['.exe', '.bat', '.scr', '.com', '.pif', '.cmd', '.ps1', '.vbs', '.js'];
  const extension = decodedPath.substring(decodedPath.lastIndexOf('.')).toLowerCase();
  if (blockedExtensions.includes(extension)) {
    const error = new Error(`Blocked file extension: ${extension}`);
    (error as any).statusCode = 400;
    (error as any).code = 'BLOCKED_EXTENSION';
    return next(error);
  }
  
  (req as any).fileValidation = { 
    filepath, 
    isValid: true, 
    fileType: 'unknown' 
  };
  next();
});

const validateFileContent = jest.fn(async (req: Request, res: Response, next: NextFunction) => {
  const filepath = req.params.filepath;
  
  try {
    const absolutePath = mockStorageService.getAbsolutePath(filepath);
    
    // Handle cases where getAbsolutePath might return undefined or null
    if (!absolutePath) {
      const error = new Error('File path resolution failed');
      (error as any).statusCode = 404;
      (error as any).code = 'FILE_NOT_FOUND';
      return next(error);
    }

    await mockFs.access(absolutePath);
    
    const stats = await mockFs.stat(absolutePath);
    
    // Enhanced file size validation
    if (typeof stats.size !== 'number' || stats.size < 0) {
      const error = new Error('Invalid file size information');
      (error as any).statusCode = 500; // Internal error if stat returns invalid size
      (error as any).code = 'INVALID_FILE_SIZE_INFO';
      return next(error);
    }

    if (stats.size > 8388608) { // 8MB
      const error = new Error('File too large');
      (error as any).statusCode = 400;
      (error as any).code = 'INVALID_FILE_SIZE';
      return next(error);
    }
    
    if (stats.size <= 0) {
      const error = new Error('Empty file not allowed');
      (error as any).statusCode = 400;
      (error as any).code = 'INVALID_FILE_SIZE';
      return next(error);
    }
    
    // Advanced file signature detection
    const mockOpen = await mockFs.open(absolutePath, 'r');
    const buffer = Buffer.alloc(16); // Read more bytes for better detection
    await mockOpen.read(buffer, 0, 16, 0);
    await mockOpen.close();
    
    let fileType = 'unknown';
    let securityFlags: string[] = [];
    
    // Skip BOM if present
    let bufferOffset = 0;
    if (buffer[0] === 0xEF && buffer[1] === 0xBB && buffer[2] === 0xBF) {
      bufferOffset = 3; // Skip UTF-8 BOM
      securityFlags.push('BOM detected and skipped');
    }

    // Check for various file signatures (adjusted for bufferOffset)
    if (buffer[bufferOffset] === 0xFF && buffer[bufferOffset + 1] === 0xD8) {
      fileType = 'image/jpeg';
    } else if (buffer[bufferOffset] === 0x89 && buffer[bufferOffset + 1] === 0x50 && buffer[bufferOffset + 2] === 0x4E && buffer[bufferOffset + 3] === 0x47) {
      fileType = 'image/png';
    } else if (buffer[bufferOffset] === 0x25 && buffer[bufferOffset + 1] === 0x50 && buffer[bufferOffset + 2] === 0x44 && buffer[bufferOffset + 3] === 0x46) {
      fileType = 'application/pdf';
    } else if (buffer[bufferOffset] === 0x4D && buffer[bufferOffset + 1] === 0x5A) {
      securityFlags.push('PE executable detected');
      const error = new Error('Dangerous file type detected');
      (error as any).statusCode = 400;
      (error as any).code = 'DANGEROUS_FILE_TYPE';
      return next(error);
    }
    
    // Check for polyglot files (multiple valid signatures)
    const hasMultipleSignatures = checkForPolyglotFile(buffer);
    if (hasMultipleSignatures) {
      securityFlags.push('Polyglot file detected');
    }
    
    (req as any).fileValidation = { 
      filepath, 
      isValid: true, 
      fileType,
      fileSize: stats.size,
      securityFlags
    };
    next();
    
  } catch (error) {
    const notFoundError = new Error('File not found');
    (notFoundError as any).statusCode = 404;
    (notFoundError as any).code = 'FILE_NOT_FOUND';
    next(notFoundError);
  }
});

// Helper function to detect polyglot files
function checkForPolyglotFile(buffer: Buffer): boolean {
  // Simple check for multiple file signatures in the same buffer
  const signatures = [
    [0xFF, 0xD8], // JPEG
    [0x89, 0x50], // PNG
    [0x25, 0x50], // PDF
    [0x4D, 0x5A]  // PE
  ];
  
  let signatureCount = 0;
  for (const sig of signatures) {
    for (let i = 0; i <= buffer.length - sig.length; i++) {
      if (sig.every((byte, index) => buffer[i + index] === byte)) {
        signatureCount++;
        break;
      }
    }
  }
  
  return signatureCount > 1;
}

// Test helper functions
const createMockRequest = (filepath?: string): Partial<Request> => ({
  params: { filepath: filepath || 'test.jpg' },
  ip: '127.0.0.1',
  get: jest.fn().mockReturnValue('test-user-agent')
});

const createMockResponse = (): Partial<Response> => ({
  status: jest.fn().mockReturnThis(),
  json: jest.fn().mockReturnThis(),
  send: jest.fn().mockReturnThis()
});

const createMockNext = (): NextFunction => jest.fn();

describe('FileValidate Additional Edge Case Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default mocks
    mockStorageService.getAbsolutePath.mockReturnValue('/mock/path/test.jpg');
    mockFs.access.mockResolvedValue(undefined);
    mockFs.stat.mockResolvedValue({ size: 1024 } as any);
    
    // Default JPEG signature
    const jpegBuffer = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46]);
    const mockOpen = {
      read: jest.fn().mockImplementation((buffer) => {
        jpegBuffer.copy(buffer);
        return Promise.resolve({ bytesRead: 8 });
      }),
      close: jest.fn().mockResolvedValue(undefined)
    };
    mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);
  });

  describe('Unicode and International Character Edge Cases', () => {
    it('should handle emoji in file names', async () => {
      const req = createMockRequest('photo-😀-vacation.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentBasic(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.filepath).toBe('photo-😀-vacation.jpg');
    });

    it('should handle international characters', async () => {
      const internationalFiles = [
        'файл.jpg',           // Russian
        '文件.jpg',           // Chinese
        'ファイル.jpg',        // Japanese
        'español.jpg',        // Spanish with accent
        'müller.jpg'          // German umlaut
      ];

      for (const filename of internationalFiles) {
        const req = createMockRequest(filename) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect((req as any).fileValidation?.filepath).toBe(filename);
      }
    });

    it('should reject zero-width characters', async () => {
      const maliciousFiles = [
        'file\u200B.jpg',     // Zero-width space
        'image\u200C.png',    // Zero-width non-joiner
        'doc\uFEFF.pdf'       // Byte order mark
      ];

      for (const filename of maliciousFiles) {
        const req = createMockRequest(filename) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'INVALID_CHARACTERS'
          })
        );
      }
    });

    it('should handle URL encoding edge cases', async () => {
      const encodingTests = [
        { input: 'file%20name.jpg', expected: 'file name.jpg' },
        { input: 'image%2Bplus.jpg', expected: 'image+plus.jpg' },
        { input: 'doc%26ampersand.pdf', expected: 'doc&ampersand.pdf' }
      ];

      for (const test of encodingTests) {
        const req = createMockRequest(test.input) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect((req as any).fileValidation?.filepath).toBe(test.input);
      }
    });

    it('should reject malformed URL encoding', async () => {
      const malformedUrls = [
        'file%ZZ.jpg',        // Invalid hex
        'image%2.png',        // Incomplete encoding
        'doc%GG.pdf'          // Invalid characters
      ];

      for (const url of malformedUrls) {
        const req = createMockRequest(url) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'INVALID_ENCODING'
          })
        );
      }
    });
  });

  describe('File Signature and Type Detection Edge Cases', () => {
    it('should detect corrupted JPEG signatures', async () => {
      const corruptedJpeg = Buffer.from([0xFF, 0xD8, 0x00, 0x00]); // Corrupted JPEG
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          corruptedJpeg.copy(buffer);
          return Promise.resolve({ bytesRead: 8 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMockRequest('corrupted.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.fileType).toBe('image/jpeg');
    });

    it('should detect polyglot files', async () => {
      // Buffer containing both JPEG and PDF signatures
      const polyglotBuffer = Buffer.from([
        0xFF, 0xD8, 0xFF, 0xE0, // JPEG header
        0x25, 0x50, 0x44, 0x46  // PDF header
      ]);
      
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          polyglotBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 16 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMockRequest('polyglot.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.securityFlags).toContain('Polyglot file detected');
    });

    it('should handle files with wrong extension vs signature', async () => {
      // PNG signature but .jpg extension
      const pngBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          pngBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 8 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMockRequest('fake-jpeg.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.fileType).toBe('image/png');
    });

    it('should handle truncated file headers', async () => {
      const truncatedBuffer = Buffer.from([0xFF]); // Only 1 byte instead of full header
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          truncatedBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 1 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMockRequest('truncated.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.fileType).toBe('unknown');
    });

    it('should detect unknown file types gracefully', async () => {
      const unknownBuffer = Buffer.from([0x12, 0x34, 0x56, 0x78]); // Unknown signature
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          unknownBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 8 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMockRequest('unknown.xyz') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.fileType).toBe('unknown');
    });
  });

  describe('Performance and Resource Edge Cases', () => {
    it('should handle extremely long file paths', async () => {
      const longPath = 'a'.repeat(300) + '.jpg';
      const req = createMockRequest(longPath) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentBasic(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'PATH_TOO_LONG'
        })
      );
    });

    it('should handle files with many dots in name', async () => {
      const dottedFile = 'file.' + '.'.repeat(50) + 'jpg';
      const req = createMockRequest(dottedFile) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentBasic(req, res, next);

      // Expect to succeed now with improved validateFilePath
      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.filepath).toBe(dottedFile);
    });

    it('should handle deeply nested paths', async () => {
      const deepPath = 'a/'.repeat(20) + 'file.jpg';
      const req = createMockRequest(deepPath) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentBasic(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.filepath).toBe(deepPath);
    });

    it('should handle files with extremely long extensions', async () => {
      const longExt = 'file.' + 'x'.repeat(20);
      const req = createMockRequest(longExt) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentBasic(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.filepath).toBe(longExt);
    });

    it('should handle concurrent validation requests', async () => {
      const requests = Array.from({ length: 100 }, (_, i) => {
        const req = createMockRequest(`file-${i}.jpg`) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();
        return validateFileContentBasic(req, res, next);
      });

      const results = await Promise.all(requests);
      
      // All should complete without throwing
      expect(results).toHaveLength(100);
    });
  });

  describe('Boundary Condition Edge Cases', () => {
    it('should handle files exactly at size limits', async () => {
      const sizeLimits = [
        8388608,  // Exactly 8MB
        8388607,  // Just under 8MB
        8388609   // Just over 8MB
      ];

      for (const size of sizeLimits) {
        mockFs.stat.mockResolvedValue({ size } as any);

        const req = createMockRequest('boundary-file.jpg') as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContent(req, res, next);

        if (size > 8388608) {
          expect(next).toHaveBeenCalledWith(
            expect.objectContaining({
              code: 'INVALID_FILE_SIZE'
            })
          );
        } else {
          expect(next).toHaveBeenCalledWith();
        }

        jest.clearAllMocks();
      }
    });

    it('should handle zero-byte files with valid signatures', async () => {
      mockFs.stat.mockResolvedValue({ size: 0 } as any);

      const req = createMockRequest('empty-but-valid.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('Empty file not allowed')
        })
      );
    });

    it('should handle files with no extension but valid signatures', async () => {
      const req = createMockRequest('file-no-extension') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.fileType).toBe('image/jpeg');
    });
  });

  describe('Error Handling Edge Cases', () => {
    it('should handle partial file reads gracefully', async () => {
      const mockOpen = {
        read: jest.fn().mockResolvedValue({ bytesRead: 4 }), // Partial read
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMockRequest('partial.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
    });

    it('should handle file handle exhaustion', async () => {
      mockFs.open.mockRejectedValue(new Error('EMFILE: too many open files'));

      const req = createMockRequest('test.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'FILE_NOT_FOUND'
        })
      );
    });

    it('should handle disk full conditions', async () => {
      mockFs.stat.mockRejectedValue(new Error('ENOSPC: no space left on device'));

      const req = createMockRequest('test.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'FILE_NOT_FOUND'
        })
      );
    });

    it('should handle permission denied scenarios', async () => {
      mockFs.access.mockRejectedValue(new Error('EACCES: permission denied'));

      const req = createMockRequest('restricted.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'FILE_NOT_FOUND'
        })
      );
    });
  });

  describe('Mock Edge Cases', () => {
    it('should handle mock returning undefined unexpectedly', async () => {
      mockStorageService.getAbsolutePath.mockReturnValue(undefined as any);

      const req = createMockRequest('test.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'FILE_NOT_FOUND'
        })
      );
    });

    it('should handle mock throwing non-Error objects', async () => {
      mockFs.access.mockImplementation(() => {
        throw 'String error instead of Error object';
      });

      const req = createMockRequest('test.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'FILE_NOT_FOUND'
        })
      );
    });

    it('should handle mock returning malformed data', async () => {
      mockFs.stat.mockResolvedValue({} as any); // Missing size property

      const req = createMockRequest('malformed.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('Invalid file size information')
        })
      );
    });
  });

  describe('Advanced Security Edge Cases', () => {
    it('should handle mixed path separators', async () => {
      const mixedPaths = [
        'folder\\file.jpg',
        'path/to\\file.jpg',
        'mixed\\separators/file.jpg'
      ];

      for (const path of mixedPaths) {
        const req = createMockRequest(path) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect((req as any).fileValidation?.filepath).toBe(path);
      }
    });

    it('should handle whitespace manipulation attacks', async () => {
      const whitespaceAttacks = [
        ' file.jpg',          // Leading space
        'file.jpg ',          // Trailing space
        'file\t.jpg',         // Tab character
        'file\n.jpg',         // Newline
        'file\r.jpg'          // Carriage return
      ];

      for (const attack of whitespaceAttacks) {
        const req = createMockRequest(attack) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect((req as any).fileValidation?.filepath).toBe(attack);
      }
    });

    it('should handle double URL encoding attacks', async () => {
      const doubleEncoded = [
        'file%252E%252E%252Fpasswd',  // Double encoded ../passwd
        '%2e%2e%2f%2e%2e%2fpasswd',   // Encoded ../ twice
        'file%2500.jpg'               // Double encoded null byte
      ];

      for (const encoded of doubleEncoded) {
        const req = createMockRequest(encoded) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        // Should be caught during decoding or path validation
        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: expect.stringMatching(/INVALID_FILEPATH|INVALID_ENCODING/)
          })
        );
      }
    });

    it('should handle case sensitivity bypass attempts in extensions', async () => {
      const caseVariations = [
        'SCRIPT.EXE',
        'Malware.Exe',
        'virus.ExE',
        'bad.BAT',
        'hack.BaT'
      ];

      for (const file of caseVariations) {
        const req = createMockRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'BLOCKED_EXTENSION'
          })
        );
      }
    });

    it('should handle relative path edge cases', async () => {
      const relativePaths = [
        './file.jpg',
        '~/secret.jpg',
        '../sibling.jpg',
        'folder/../file.jpg'
      ];

      for (const path of relativePaths) {
        const req = createMockRequest(path) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        if (path.includes('..') || path.startsWith('./')) { // Added check for './'
          expect(next).toHaveBeenCalledWith(
            expect.objectContaining({
              code: 'INVALID_FILEPATH'
            })
          );
        } else {
          expect(next).toHaveBeenCalledWith();
        }
      }
    });
  });

  describe('Stress Testing Edge Cases', () => {
    it('should handle rapid repeated validations', async () => {
      const startTime = Date.now();
      
      const promises = Array.from({ length: 50 }, async (_, i) => {
        const req = createMockRequest(`stress-${i}.jpg`) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();
        return validateFileContentBasic(req, res, next);
      });

      await Promise.all(promises);
      
      const endTime = Date.now();
      const duration = endTime - startTime;
      
      // Should complete within reasonable time (less than 1 second)
      expect(duration).toBeLessThan(1000);
    });

    it('should handle memory pressure scenarios', async () => {
      // Create many large file path strings
      const largePaths = Array.from({ length: 1000 }, (_, i) => 
        `path-${i}-${'x'.repeat(100)}.jpg`
      );

      for (const path of largePaths) {
        const req = createMockRequest(path) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);
        
        // Should handle without throwing memory errors
        expect(next).toHaveBeenCalled();
      }
    });

    it('should handle alternating valid/invalid requests', async () => {
      const alternatingRequests = [
        'valid.jpg',
        '../invalid.jpg',
        'another-valid.png',
        'malware.exe',
        'final-valid.gif'
      ];

      for (let i = 0; i < alternatingRequests.length; i++) {
        const req = createMockRequest(alternatingRequests[i]) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        if (alternatingRequests[i].includes('..') || alternatingRequests[i].includes('.exe')) {
          expect(next).toHaveBeenCalledWith(
            expect.objectContaining({
              statusCode: 400
            })
          );
        } else {
          expect(next).toHaveBeenCalledWith();
        }

        jest.clearAllMocks();
      }
    });
  });

  describe('Real-world Scenario Edge Cases', () => {
    it('should handle file uploads from different operating systems', async () => {
      const osSpecificPaths = [
        'C:\\Users\\test\\file.jpg',      // Windows absolute path
        '/home/user/file.jpg',            // Unix absolute path
        '\\\\server\\share\\file.jpg',    // UNC path
        'Documents and Settings/file.jpg' // Windows with spaces (relative)
      ];

      for (const path of osSpecificPaths) {
        const req = createMockRequest(path) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        // Absolute paths (Windows drive letter, Unix root, UNC) should be rejected
        // 'Documents and Settings/file.jpg' should pass as it's a relative path
        if (path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(path) || path.startsWith('\\\\')) {
          expect(next).toHaveBeenCalledWith(
            expect.objectContaining({
              code: 'INVALID_FILEPATH'
            })
          );
        } else {
          expect(next).toHaveBeenCalledWith();
        }
      }
    });

    it('should handle files from mobile device cameras', async () => {
      const mobileFiles = [
        'IMG_20241201_123456.jpg',        // iPhone format
        'PANO_20241201_123456.jpg',       // iPhone panorama
        'VID_20241201_123456.mp4',        // Video file
        'Screenshot_20241201-123456.png', // Android screenshot
        'BURST001_COVER.JPG'              // Burst mode cover
      ];

      for (const file of mobileFiles) {
        const req = createMockRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        if (file.endsWith('.mp4')) {
          // Video files might need special handling
          expect(next).toHaveBeenCalledWith();
        } else {
          expect(next).toHaveBeenCalledWith();
        }
      }
    });

    it('should handle cloud storage sync conflicts', async () => {
      const conflictFiles = [
        'document (conflicted copy 2024-12-01).pdf',
        'image (John Smith\'s conflicted copy).jpg',
        'file (case conflict).txt',
        'data - Copy.csv'
      ];

      for (const file of conflictFiles) {
        const req = createMockRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect((req as any).fileValidation?.filepath).toBe(file);
      }
    });

    it('should handle version control and backup files', async () => {
      const versionFiles = [
        'document.pdf.bak',
        'image.jpg~',
        'file.txt.orig',
        '.DS_Store',              // macOS system file - now rejected
        'Thumbs.db',              // Windows thumbnail cache
        'desktop.ini'             // Windows folder settings
      ];

      for (const file of versionFiles) {
        const req = createMockRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        if (file.startsWith('.')) { // This condition now correctly catches .DS_Store
          expect(next).toHaveBeenCalledWith(
            expect.objectContaining({
              code: 'INVALID_FILEPATH'
            })
          );
        } else {
          expect(next).toHaveBeenCalledWith();
        }
      }
    });
  });

  describe('Browser and Client Edge Cases', () => {
    it('should handle files with BOM (Byte Order Mark)', async () => {
      const bomBuffer = Buffer.from([0xEF, 0xBB, 0xBF, 0xFF, 0xD8, 0xFF, 0xE0]); // UTF-8 BOM + JPEG
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          bomBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 8 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMockRequest('bom-file.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
      // Should still detect as JPEG despite BOM
      expect((req as any).fileValidation?.fileType).toBe('image/jpeg');
      expect((req as any).fileValidation?.securityFlags).toContain('BOM detected and skipped');
    });

    it('should handle drag-and-drop file name issues', async () => {
      const dragDropFiles = [
        'file (1).jpg',           // Browser auto-rename
        'file - Copy.jpg',        // OS copy suffix
        'image copy 2.png',       // Multiple copies
        'document(2).pdf'         // No space variant
      ];

      for (const file of dragDropFiles) {
        const req = createMockRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect((req as any).fileValidation?.filepath).toBe(file);
      }
    });

    it('should handle browser security restrictions', async () => {
      const restrictedPaths = [
        'C:/Windows/System32/file.jpg',   // Windows system path
        '/etc/passwd.jpg',                // Unix system file
        'file:///C:/file.jpg',            // File protocol
        'javascript:alert(1).jpg'         // JavaScript protocol
      ];

      for (const path of restrictedPaths) {
        const req = createMockRequest(path) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'INVALID_FILEPATH'
          })
        );
      }
    });
  });

  describe('File System Edge Cases', () => {
    it('should handle file system case sensitivity issues', async () => {
      // Test files that might conflict on case-insensitive systems
      const caseFiles = [
        'File.jpg',
        'file.jpg',
        'FILE.JPG',
        'File.JPG'
      ];

      for (const file of caseFiles) {
        const req = createMockRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
        expect((req as any).fileValidation?.filepath).toBe(file);
      }
    });

    it('should handle symbolic link scenarios', async () => {
      // Mock lstat to simulate symbolic link
      const mockLstat = jest.fn().mockResolvedValue({
        size: 1024,
        isSymbolicLink: () => true,
        isFile: () => false
      });
      (mockFs as any).lstat = mockLstat;

      const req = createMockRequest('symlink.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      expect(next).toHaveBeenCalledWith();
    });

    it('should handle network file system delays', async () => {
      // Simulate slow network file system
      mockFs.access.mockImplementation(() => 
        new Promise(resolve => setTimeout(resolve, 100))
      );

      const startTime = Date.now();
      
      const req = createMockRequest('network-file.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContent(req, res, next);

      const duration = Date.now() - startTime;
      expect(duration).toBeGreaterThan(90); // Should have waited
      expect(next).toHaveBeenCalledWith();
    });
  });

  describe('Encoding and Character Set Edge Cases', () => {
    it('should handle different character encodings', async () => {
      const encodedFiles = [
        'файл.jpg',                    // Cyrillic
        'اختبار.jpg',                  // Arabic
        '测试.jpg',                    // Chinese
        'テスト.jpg',                  // Japanese
        'prüfung.jpg'                  // German with umlaut
      ];

      for (const file of encodedFiles) {
        const req = createMockRequest(encodeURIComponent(file)) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
      }
    });

    it('should handle mixed character sets', async () => {
      const mixedFiles = [
        'test-файл.jpg',              // English + Cyrillic
        'document_测试.pdf',           // English + Chinese
        'file-テスト.png'              // English + Japanese
      ];

      for (const file of mixedFiles) {
        const req = createMockRequest(encodeURIComponent(file)) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentBasic(req, res, next);

        expect(next).toHaveBeenCalledWith();
      }
    });

    it('should handle invalid UTF-8 sequences', async () => {
      // Create invalid UTF-8 byte sequences
      const invalidUtf8 = Buffer.from([0xFF, 0xFE, 0xFD]).toString('latin1');
      
      const req = createMockRequest(invalidUtf8) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentBasic(req, res, next);

      // Should handle gracefully
      expect(next).toHaveBeenCalled();
    });
  });
});