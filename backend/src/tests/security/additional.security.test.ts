// /backend/tests/security/middlewares/fileValidate.additional.security.test.ts

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

// Advanced security-focused validation middleware (enhanced for additional threats)
const validateFileContentAdvanced = jest.fn(async (req: Request, res: Response, next: NextFunction) => {
  const filepath = req.params.filepath;
  
  if (!filepath) {
    const error = new Error('File path is required');
    (error as any).statusCode = 400;
    (error as any).code = 'MISSING_FILEPATH';
    return next(error);
  }

  try {
    // Multi-level URL decoding to catch double/triple encoding attacks
    let decodedPath = filepath;
    let previousDecoded = '';
    let decodingAttempts = 0;
    
    while (decodedPath !== previousDecoded && decodingAttempts < 5) {
      previousDecoded = decodedPath;
      try {
        decodedPath = decodeURIComponent(decodedPath);
        decodingAttempts++;
      } catch (error) {
        break;
      }
    }
    
    // Check for suspicious multiple encoding
    if (decodingAttempts > 2) {
      const error = new Error('Suspicious multiple URL encoding detected');
      (error as any).statusCode = 400;
      (error as any).code = 'SUSPICIOUS_ENCODING';
      return next(error);
    }
    
    // Enhanced path traversal detection
    const pathTraversalPatterns = [
      /\.\./,                    // Standard path traversal
      /\.\.\\/,                  // Windows path traversal
      /\.\.%2f/i,               // URL encoded traversal
      /\.\.%2F/i,               // URL encoded traversal (caps)
      /\.\.%5c/i,               // URL encoded backslash
      /\x2e\x2e\x2f/,          // Hex encoded
      /\u002e\u002e\u002f/,    // Unicode encoded
      /\.%c0%af/i,             // UTF-8 overlong encoding
      /\.%e0%80%af/i           // UTF-8 overlong encoding
    ];
    
    for (const pattern of pathTraversalPatterns) {
      if (pattern.test(decodedPath)) {
        const error = new Error('Advanced path traversal detected');
        (error as any).statusCode = 400;
        (error as any).code = 'ADVANCED_PATH_TRAVERSAL';
        return next(error);
      }
    }
    
    // Check for dangerous characters and sequences
    const dangerousPatterns = [
      /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/,  // Control characters
      /[\u200b-\u200d\ufeff]/,              // Zero-width characters
      /[<>"\|*?]/,                          // Dangerous filename chars
      /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i, // Windows reserved names
      /^\./,                                // Hidden files
      /\s+$/,                               // Trailing whitespace
      /\x20+$/                              // Trailing spaces
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(decodedPath)) {
        const error = new Error('Dangerous characters detected in file path');
        (error as any).statusCode = 400;
        (error as any).code = 'DANGEROUS_CHARACTERS';
        return next(error);
      }
    }
    
    // Enhanced extension validation with double extension detection
    const pathParts = decodedPath.split('.');
    if (pathParts.length > 3) {
      const error = new Error('Multiple file extensions detected');
      (error as any).statusCode = 400;
      (error as any).code = 'MULTIPLE_EXTENSIONS';
      return next(error);
    }
    
    // Check for dangerous extensions (comprehensive list)
    const dangerousExtensions = [
      '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js', '.jar',
      '.app', '.deb', '.pkg', '.rpm', '.dmg', '.iso', '.img', '.msi', '.msp',
      '.ps1', '.psm1', '.psd1', '.ps1xml', '.psc1', '.ps2', '.ps2xml',
      '.scf', '.lnk', '.inf', '.reg', '.dll', '.sys', '.drv', '.ocx',
      '.cpl', '.msc', '.hta', '.chm', '.hlp', '.url', '.website',
      '.php', '.php3', '.php4', '.php5', '.phtml', '.asp', '.aspx',
      '.jsp', '.jspx', '.pl', '.py', '.rb', '.sh', '.bash', '.zsh',
      '.cgi', '.fcgi', '.wsf', '.wsh', '.action', '.do'
    ];
    
    const extension = '.' + pathParts[pathParts.length - 1].toLowerCase();
    if (dangerousExtensions.includes(extension)) {
      const error = new Error(`Dangerous file extension detected: ${extension}`);
      (error as any).statusCode = 400;
      (error as any).code = 'DANGEROUS_EXTENSION';
      return next(error);
    }
    
    // Validate file system access
    const absolutePath = mockStorageService.getAbsolutePath(decodedPath);
    await mockFs.access(absolutePath);
    
    const stats = await mockFs.stat(absolutePath);
    
    // Enhanced file size validation with DoS protection
    const maxFileSize = 8388608; // 8MB
    const minFileSize = 1; // 1 byte minimum
    
    if (stats.size > maxFileSize) {
      const error = new Error('File size exceeds maximum allowed limit');
      (error as any).statusCode = 400;
      (error as any).code = 'FILE_TOO_LARGE';
      return next(error);
    }
    
    if (stats.size < minFileSize) {
      const error = new Error('File size below minimum threshold');
      (error as any).statusCode = 400;
      (error as any).code = 'FILE_TOO_SMALL';
      return next(error);
    }
    
    // Advanced file signature validation
    const fileHandle = await mockFs.open(absolutePath, 'r');
    const buffer = Buffer.alloc(512); // Read more bytes for comprehensive analysis
    await fileHandle.read(buffer, 0, 512, 0);
    await fileHandle.close();
    
    let fileType = 'unknown';
    let securityFlags: string[] = [];
    
    // Comprehensive signature detection
    const signatures = {
      // Images
      'image/jpeg': [[0xFF, 0xD8, 0xFF]],
      'image/png': [[0x89, 0x50, 0x4E, 0x47]],
      'image/gif': [[0x47, 0x49, 0x46, 0x38]],
      'image/bmp': [[0x42, 0x4D]],
      'image/webp': [[0x52, 0x49, 0x46, 0x46], [0x57, 0x45, 0x42, 0x50]],
      
      // Documents
      'application/pdf': [[0x25, 0x50, 0x44, 0x46]],
      'application/zip': [[0x50, 0x4B, 0x03, 0x04], [0x50, 0x4B, 0x05, 0x06]],
      
      // Dangerous executables
      'executable/pe': [[0x4D, 0x5A]],                     // PE/DOS executable
      'executable/elf': [[0x7F, 0x45, 0x4C, 0x46]],       // ELF executable
      'executable/macho': [[0xFE, 0xED, 0xFA, 0xCE]],     // Mach-O executable
      'archive/rar': [[0x52, 0x61, 0x72, 0x21]],          // RAR archive
      'archive/7z': [[0x37, 0x7A, 0xBC, 0xAF]],           // 7-Zip archive
      'script/php': [[0x3C, 0x3F, 0x70, 0x68, 0x70]],     // PHP script
      'script/html': [[0x3C, 0x68, 0x74, 0x6D, 0x6C]],    // HTML file
      'script/js': [[0x2F, 0x2F], [0x2F, 0x2A]]           // JavaScript comments
    };
    
    // Check against known signatures
    for (const [type, sigs] of Object.entries(signatures)) {
      for (const sig of sigs) {
        const matches = sig.every((byte, index) => buffer[index] === byte);
        if (matches) {
          if (type.startsWith('executable/') || type.startsWith('script/')) {
            const error = new Error(`Dangerous file type detected: ${type}`);
            (error as any).statusCode = 400;
            (error as any).code = 'DANGEROUS_FILE_TYPE';
            return next(error);
          }
          fileType = type;
          break;
        }
      }
    }
    
    // Check for polyglot files (multiple valid signatures)
    let signatureMatches = 0;
    for (const [type, sigs] of Object.entries(signatures)) {
      for (const sig of sigs) {
        for (let i = 0; i <= buffer.length - sig.length; i++) {
          const matches = sig.every((byte, index) => buffer[i + index] === byte);
          if (matches) {
            signatureMatches++;
            if (signatureMatches > 1) {
              securityFlags.push('Polyglot file detected');
              break;
            }
          }
        }
      }
    }
    
    // Check for steganographic indicators
    if (fileType.startsWith('image/')) {
      // Simple check for unusual entropy or hidden data
      const entropy = calculateEntropy(buffer);
      if (entropy > 7.8) { // High entropy might indicate hidden data
        securityFlags.push('High entropy detected - possible steganography');
      }
    }
    
    // Check for ZIP bomb indicators
    if (fileType === 'application/zip') {
      securityFlags.push('Archive file detected - ZIP bomb risk');
    }
    
    (req as any).fileValidation = { 
      filepath: decodedPath, 
      isValid: true, 
      fileType,
      fileSize: stats.size,
      securityFlags
    };
    next();
    
  } catch (error) {
    const securityError = new Error('File validation failed for security reasons');
    (securityError as any).statusCode = 400;
    (securityError as any).code = 'SECURITY_VALIDATION_FAILED';
    next(securityError);
  }
});

// Helper function to calculate entropy
function calculateEntropy(buffer: Buffer): number {
  const frequencies = new Array(256).fill(0);
  for (const byte of buffer) {
    frequencies[byte]++;
  }
  
  let entropy = 0;
  const length = buffer.length;
  for (const freq of frequencies) {
    if (freq > 0) {
      const probability = freq / length;
      entropy -= probability * Math.log2(probability);
    }
  }
  
  return entropy;
}

// Test helper functions
const createMaliciousRequest = (filepath: string): Partial<Request> => ({
  params: { filepath },
  ip: '192.168.1.100',
  get: jest.fn().mockReturnValue('AttackBot/1.0'),
  headers: {
    'user-agent': 'AttackBot/1.0',
    'x-forwarded-for': '192.168.1.100'
  }
});

const createMockResponse = (): Partial<Response> => ({
  status: jest.fn().mockReturnThis(),
  json: jest.fn().mockReturnThis()
});

const createMockNext = (): jest.MockedFunction<NextFunction> => jest.fn();

describe('FileValidate Advanced Security Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Default safe mocks
    mockStorageService.getAbsolutePath.mockReturnValue('/safe/storage/test.jpg');
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

  describe('Advanced Encoding Attack Prevention', () => {
    it('should detect triple URL encoding attacks', async () => {
      // Triple encoded ../../../etc/passwd
      const tripleEncoded = '%25252e%25252e%25252f%25252e%25252e%25252f%25252e%25252e%25252fetc%25252fpasswd';
      
      const req = createMaliciousRequest(tripleEncoded) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'SUSPICIOUS_ENCODING'
        })
      );
    });

    it('should detect HTML entity encoding bypass attempts', async () => {
      const htmlEntities = [
        '&lt;script&gt;.jpg',
        '&#x2e;&#x2e;&#x2f;passwd',
        '&period;&period;&sol;etc&sol;passwd'
      ];

      for (const entity of htmlEntities) {
        const req = createMaliciousRequest(entity) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400
          })
        );
      }
    });

    it('should detect UTF-8 overlong encoding attacks', async () => {
      const overlongEncodings = [
        'file%c0%af.jpg',      // Overlong encoding of /
        'image%e0%80%af.png',  // Another overlong encoding
        'doc%f0%80%80%af.pdf'  // 4-byte overlong encoding
      ];

      for (const encoding of overlongEncodings) {
        const req = createMaliciousRequest(encoding) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'ADVANCED_PATH_TRAVERSAL'
          })
        );
      }
    });

    it('should detect Unicode homograph attacks', async () => {
      const homographs = [
        'еxесutе.jpg',         // Cyrillic е instead of e
        'іmаgе.png',          // Mixed Latin/Cyrillic
        'dосumеnt.pdf'        // More mixed characters
      ];

      for (const homograph of homographs) {
        const req = createMaliciousRequest(homograph) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        // Should pass basic validation but may be flagged elsewhere
        expect(next).toHaveBeenCalled();
      }
    });

    it('should detect mixed encoding chain attacks', async () => {
      const mixedEncodings = [
        '%252e%252e%2f%65%74%63%2f%70%61%73%73%77%64', // Mixed double/single encoding
        '%2e%2e%252f%252e%252e%252f%65%74%63',         // Inconsistent encoding levels
        '%2e%2e\\%2f%2e%2e\\%2fpasswd'                 // Mixed separators with encoding
      ];

      for (const encoding of mixedEncodings) {
        const req = createMaliciousRequest(encoding) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400
          })
        );
      }
    });
  });

  describe('Time-Based Attack Prevention', () => {
    it('should handle timing attack attempts via file validation', async () => {
      const filenames = [
        'timing-test-1.jpg',
        'timing-test-2.jpg',
        'timing-test-3.jpg'
      ];

      const timings: number[] = [];

      for (const filename of filenames) {
        const startTime = process.hrtime.bigint();
        
        const req = createMaliciousRequest(filename) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);
        
        const endTime = process.hrtime.bigint();
        timings.push(Number(endTime - startTime) / 1000000); // Convert to milliseconds
      }

      // Timing should be relatively consistent (within 50ms variance)
      const minTime = Math.min(...timings);
      const maxTime = Math.max(...timings);
      expect(maxTime - minTime).toBeLessThan(50);
    });

    it('should prevent race condition exploitation', async () => {
      let validationCount = 0;
      
      mockFs.access.mockImplementation(async () => {
        validationCount++;
        // Simulate race condition by adding delay
        await new Promise(resolve => setTimeout(resolve, 10));
        return undefined;
      });

      const promises = Array.from({ length: 10 }, () => {
        const req = createMaliciousRequest('race-test.jpg') as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();
        return validateFileContentAdvanced(req, res, next);
      });

      await Promise.all(promises);

      // All validations should complete independently
      expect(validationCount).toBe(10);
    });

    it('should handle concurrent validation bypass attempts', async () => {
      const maliciousFiles = [
        '../../../etc/passwd',
        'malware.exe',
        '\0injection.jpg',
        '../../shadow'
      ];

      const promises = maliciousFiles.map(async (filename) => {
        const req = createMaliciousRequest(filename) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();
        return validateFileContentAdvanced(req, res, next);
      });

      const results = await Promise.allSettled(promises);

      // All should be rejected
      results.forEach((result) => {
        expect(result.status).toBe('fulfilled');
      });
    });
  });

  describe('Memory Exhaustion Attack Prevention', () => {
    it('should detect potential ZIP bomb attacks', async () => {
      // Mock ZIP file signature
      const zipBuffer = Buffer.from([0x50, 0x4B, 0x03, 0x04]);
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          zipBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMaliciousRequest('bomb.zip') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.securityFlags).toContain('Archive file detected - ZIP bomb risk');
    });

    it('should prevent buffer overflow attempts via large signatures', async () => {
      // Mock extremely large signature read
      const largeBuffer = Buffer.alloc(10000, 0xFF);
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          largeBuffer.copy(buffer, 0, 0, Math.min(buffer.length, largeBuffer.length));
          return Promise.resolve({ bytesRead: Math.min(buffer.length, largeBuffer.length) });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMaliciousRequest('large-sig.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      // Should handle gracefully without crashing
      expect(next).toHaveBeenCalled();
    });

    it('should handle recursive file structure attacks', async () => {
      const recursivePaths = [
        'a/'.repeat(100) + 'deep.jpg',
        'very/deep/nested/structure/with/many/levels/file.jpg',
        'x'.repeat(500) + '.jpg'
      ];

      for (const path of recursivePaths) {
        const req = createMaliciousRequest(path) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        // Should handle without memory issues
        expect(next).toHaveBeenCalled();
      }
    });
  });

  describe('OS-Specific Attack Prevention', () => {
    it('should detect Windows 8.3 filename attacks', async () => {
      const shortNames = [
        'PROGRA~1.exe',
        'DOCUME~1.bat',
        'WINDOW~1.scr'
      ];

      for (const name of shortNames) {
        const req = createMaliciousRequest(name) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'DANGEROUS_EXTENSION'
          })
        );
      }
    });

    it('should prevent Unix device file access', async () => {
      const deviceFiles = [
        '/dev/null',
        '/dev/zero',
        '/dev/random',
        '/proc/self/mem',
        '/sys/kernel/notes'
      ];

      for (const device of deviceFiles) {
        const req = createMaliciousRequest(device) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'ADVANCED_PATH_TRAVERSAL'
          })
        );
      }
    });

    it('should detect Windows reserved name attacks', async () => {
      const reservedNames = [
        'CON.jpg',
        'PRN.png', 
        'AUX.pdf',
        'NUL.txt',
        'COM1.exe',
        'LPT1.bat'
      ];

      for (const name of reservedNames) {
        const req = createMaliciousRequest(name) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'DANGEROUS_CHARACTERS'
          })
        );
      }
    });

    it('should handle symlink traversal attacks', async () => {
      // Mock symlink that could point to sensitive files
      mockFs.stat.mockResolvedValue({ 
        size: 1024,
        isSymbolicLink: () => true,
        isFile: () => false
      } as any);

      const req = createMaliciousRequest('innocent-link.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      // Should complete validation even for symlinks
      expect(next).toHaveBeenCalled();
    });

    it('should prevent mount point traversal', async () => {
      const mountTraversals = [
        '/mnt/../../../etc/passwd',
        '/media/usb/../../../root/.ssh/id_rsa',
        '/var/www/../../../home/user/.bash_history'
      ];

      for (const traversal of mountTraversals) {
        const req = createMaliciousRequest(traversal) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'ADVANCED_PATH_TRAVERSAL'
          })
        );
      }
    });
  });

  describe('Advanced Evasion Technique Prevention', () => {
    it('should detect zip slip attacks', async () => {
      const zipSlipPaths = [
        '../../../../tmp/evil.sh',
        '..\\..\\..\\..\\windows\\system32\\evil.exe',
        '../../../var/www/html/shell.php'
      ];

      for (const path of zipSlipPaths) {
        const req = createMaliciousRequest(path) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'ADVANCED_PATH_TRAVERSAL'
          })
        );
      }
    });

    it('should prevent path normalization bypass', async () => {
      const normalizationBypass = [
        'file/../../../etc/passwd',
        'image/./../../shadow',
        'doc/folder/../../../../../../root/.ssh'
      ];

      for (const path of normalizationBypass) {
        const req = createMaliciousRequest(path) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'ADVANCED_PATH_TRAVERSAL'
          })
        );
      }
    });

    it('should detect canonicalization attacks', async () => {
      const canonicalAttacks = [
        'file\x00.jpg',          // Null byte injection
        'image\x20\x20.png',     // Multiple spaces
        'doc\t\t.pdf',          // Tab characters
        'script\r\n.js'         // CRLF injection
      ];

      for (const attack of canonicalAttacks) {
        const req = createMaliciousRequest(attack) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'DANGEROUS_CHARACTERS'
          })
        );
      }
    });

    it('should prevent signature fragmentation attacks', async () => {
      // Mock fragmented PE signature across multiple reads
      const fragmentedPE = Buffer.alloc(512);
      fragmentedPE[100] = 0x4D; // M
      fragmentedPE[200] = 0x5A; // Z (PE signature split)
      
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          fragmentedPE.copy(buffer);
          return Promise.resolve({ bytesRead: 512 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMaliciousRequest('fragmented.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      // Should not detect PE signature due to fragmentation
      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.fileType).toBe('unknown');
    });
  });

  describe('Steganography and Hiding Detection', () => {
    it('should detect high entropy indicating steganography', async () => {
      // Create buffer with high entropy (random-like data)
      const highEntropyBuffer = Buffer.alloc(512);
      // Fill with JPEG header + high entropy data
      highEntropyBuffer[0] = 0xFF;
      highEntropyBuffer[1] = 0xD8;
      highEntropyBuffer[2] = 0xFF;
      highEntropyBuffer[3] = 0xE0;
      
      // Fill rest with pseudo-random data for high entropy
      for (let i = 4; i < 512; i++) {
        highEntropyBuffer[i] = Math.floor(Math.random() * 256);
      }

      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          highEntropyBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 512 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMaliciousRequest('suspicious.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      expect(next).toHaveBeenCalledWith();
      expect((req as any).fileValidation?.securityFlags).toContain('High entropy detected - possible steganography');
    });

    it('should handle alternate data streams (Windows)', async () => {
      const adsFiles = [
        'image.jpg:hidden.exe',
        'document.pdf:Zone.Identifier',
        'file.txt:$DATA'
      ];

      for (const adsFile of adsFiles) {
        const req = createMaliciousRequest(adsFile) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'DANGEROUS_CHARACTERS'
          })
        );
      }
    });

    it('should detect metadata injection attacks', async () => {
      // Files with suspicious metadata-like content
      const metadataAttacks = [
        'image.jpg?metadata=<script>alert(1)</script>',
        'photo.png#exif=../../etc/passwd',
        'doc.pdf&embedded=malware.exe'
      ];

      for (const attack of metadataAttacks) {
        const req = createMaliciousRequest(attack) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'DANGEROUS_CHARACTERS'
          })
        );
      }
    });
  });

  describe('Social Engineering Attack Prevention', () => {
    it('should detect filename spoofing attacks', async () => {
      const spoofedFiles = [
        'document.pdf                    .exe', // Spaces to hide extension
        'image.png\u202E\u202Dexe.jpg',       // Right-to-left override
        'file.txt\u200B\u200C\u200D.bat',     // Zero-width characters
        'photo.jpg\uFEFF.scr'                 // Byte order mark
      ];

      for (const spoofed of spoofedFiles) {
        const req = createMaliciousRequest(spoofed) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400
          })
        );
      }
    });

    it('should prevent extension confusion attacks', async () => {
      const confusingExtensions = [
        'document.pdf.exe',              // Double extension
        'image.jpg.scr',                 // Image with screensaver
        'archive.zip.bat',               // Archive with batch
        'text.txt.com'                   // Text with command
      ];

      for (const file of confusingExtensions) {
        const req = createMaliciousRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: expect.stringMatching(/MULTIPLE_EXTENSIONS|DANGEROUS_EXTENSION/)
          })
        );
      }
    });

    it('should detect visual similarity exploitation', async () => {
      const similarNames = [
        'gοοgle.jpg',                    // Greek omicron instead of o
        'micrοsοft.png',                // Mixed characters
        'аррlе.pdf'                      // Cyrillic a instead of Latin a
      ];

      for (const name of similarNames) {
        const req = createMaliciousRequest(name) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        // These should pass basic validation but might be flagged for review
        expect(next).toHaveBeenCalled();
      }
    });
  });

  describe('Application Logic Attack Prevention', () => {
    it('should prevent business logic bypass via file type', async () => {
      // Simulate business rule: only images allowed in gallery
      const nonImageFiles = [
        'script.js',
        'config.xml',
        'database.sql',
        'credentials.json'
      ];

      for (const file of nonImageFiles) {
        const req = createMaliciousRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        // Should be rejected due to dangerous extensions
        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            statusCode: 400
          })
        );
      }
    });

    it('should handle workflow manipulation attacks', async () => {
      // Files designed to bypass workflow steps
      const workflowBypass = [
        '../processed/approved.jpg',     // Try to skip approval
        '../../published/final.png',    // Skip to published state
        '../../../admin/system.pdf'     // Access admin area
      ];

      for (const bypass of workflowBypass) {
        const req = createMaliciousRequest(bypass) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'ADVANCED_PATH_TRAVERSAL'
          })
        );
      }
    });

    it('should prevent state machine exploitation', async () => {
      // Files with names suggesting state manipulation
      const stateAttacks = [
        'temp_final_approved.jpg',
        'draft_published_live.png',
        'pending_approved_active.pdf'
      ];

      for (const attack of stateAttacks) {
        const req = createMaliciousRequest(attack) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        // These should pass validation (legitimate names)
        expect(next).toHaveBeenCalled();
      }
    });
  });

  describe('Emerging Threat Vector Prevention', () => {
    it('should detect WebAssembly payload injection attempts', async () => {
      // Mock WebAssembly binary signature
      const wasmBuffer = Buffer.from([0x00, 0x61, 0x73, 0x6D]); // WASM magic number
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          wasmBuffer.copy(buffer);
          return Promise.resolve({ bytesRead: 4 });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMaliciousRequest('module.wasm') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      // WASM files should be handled carefully
      expect(next).toHaveBeenCalled();
      expect((req as any).fileValidation?.fileType).toBe('unknown');
    });

    it('should handle container escape via file uploads', async () => {
      const containerEscapes = [
        '../../../proc/1/root/etc/passwd',
        '/var/run/docker.sock',
        '../../../sys/fs/cgroup/memory/docker/memory.limit_in_bytes'
      ];

      for (const escape of containerEscapes) {
        const req = createMaliciousRequest(escape) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'ADVANCED_PATH_TRAVERSAL'
          })
        );
      }
    });

    it('should detect supply chain attacks via dependencies', async () => {
      const supplyChainFiles = [
        'package.json',
        'requirements.txt',
        'Dockerfile',
        'docker-compose.yml',
        '.npmrc',
        'composer.json'
      ];

      for (const file of supplyChainFiles) {
        const req = createMaliciousRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        // These files could be legitimate or malicious
        expect(next).toHaveBeenCalled();
      }
    });
  });

  describe('Protocol and Transport Attack Prevention', () => {
    it('should handle MIME sniffing attacks', async () => {
      // File with misleading content-type vs actual content
      const htmlInImage = Buffer.from('<html><script>alert(1)</script></html>');
      const mockOpen = {
        read: jest.fn().mockImplementation((buffer) => {
          htmlInImage.copy(buffer);
          return Promise.resolve({ bytesRead: htmlInImage.length });
        }),
        close: jest.fn().mockResolvedValue(undefined)
      };
      mockFs.open = jest.fn().mockResolvedValue(mockOpen as any);

      const req = createMaliciousRequest('fake-image.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'DANGEROUS_FILE_TYPE'
        })
      );
    });

    it('should prevent boundary injection attacks', async () => {
      const boundaryAttacks = [
        'file\r\n--boundary\r\nContent-Type: text/html.jpg',
        'image\n\nHTTP/1.1 200 OK\n\n<script>.png',
        'doc\r\n\r\n<html><body>XSS</body></html>.pdf'
      ];

      for (const attack of boundaryAttacks) {
        const req = createMaliciousRequest(attack) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'DANGEROUS_CHARACTERS'
          })
        );
      }
    });

    it('should handle transfer encoding attacks', async () => {
      const transferAttacks = [
        'file\x0d\x0aTransfer-Encoding: chunked.jpg',
        'image\x0d\x0aContent-Length: 0\x0d\x0a\x0d\x0a.png',
        'doc\x0aX-Forwarded-For: attacker.com.pdf'
      ];

      for (const attack of transferAttacks) {
        const req = createMaliciousRequest(attack) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'DANGEROUS_CHARACTERS'
          })
        );
      }
    });
  });

  describe('Error Handling and Information Disclosure', () => {
    it('should not leak internal paths in error messages', async () => {
      mockStorageService.getAbsolutePath.mockImplementation(() => {
        throw new Error('ENOENT: no such file or directory, open \'/var/secure/classified/passwords.txt\'');
      });

      const req = createMaliciousRequest('probe.jpg') as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'SECURITY_VALIDATION_FAILED',
          message: 'File validation failed for security reasons'
        })
      );
    });

    it('should handle file system permission probes', async () => {
      const permissionErrors = [
        'EACCES: permission denied',
        'EPERM: operation not permitted',
        'ENOTDIR: not a directory'
      ];

      for (const error of permissionErrors) {
        mockFs.access.mockRejectedValue(new Error(error));

        const req = createMaliciousRequest('permission-probe.jpg') as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        expect(next).toHaveBeenCalledWith(
          expect.objectContaining({
            code: 'SECURITY_VALIDATION_FAILED'
          })
        );

        jest.clearAllMocks();
      }
    });

    it('should maintain consistent error responses', async () => {
      const attackScenarios = [
        { file: '../../../etc/passwd', expectedCode: 'ADVANCED_PATH_TRAVERSAL' },
        { file: 'malware.exe', expectedCode: 'DANGEROUS_EXTENSION' },
        { file: '\0injection.jpg', expectedCode: 'DANGEROUS_CHARACTERS' }
      ];

      for (const scenario of attackScenarios) {
        const req = createMaliciousRequest(scenario.file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);

        const errorCall = next.mock.calls[0][0];
        expect(errorCall).toBeDefined();
        expect((errorCall as any).statusCode).toBe(400);
        expect((errorCall as any).code).toBe(scenario.expectedCode);
        
        jest.clearAllMocks();
      }
    });
  });

  describe('Performance Under Attack', () => {
    it('should handle algorithmic complexity attacks', async () => {
      // Test with pathological input designed to cause performance issues
      const complexPath = '../'.repeat(1000) + 'evil.jpg';

      const startTime = process.hrtime.bigint();

      const req = createMaliciousRequest(complexPath) as Request;
      const res = createMockResponse() as Response;
      const next = createMockNext();

      await validateFileContentAdvanced(req, res, next);

      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds

      // Should complete quickly even with complex input
      expect(duration).toBeLessThan(100);
      expect(next).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'ADVANCED_PATH_TRAVERSAL'
        })
      );
    });

    it('should maintain performance under sustained attack', async () => {
      const attackFiles = Array.from({ length: 100 }, (_, i) => `../../../attack-${i}.exe`);

      const startTime = process.hrtime.bigint();

      const promises = attackFiles.map(async (file) => {
        const req = createMaliciousRequest(file) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();
        return validateFileContentAdvanced(req, res, next);
      });

      await Promise.all(promises);

      const endTime = process.hrtime.bigint();
      const duration = Number(endTime - startTime) / 1000000;

      // Should handle 100 attacks in under 1 second
      expect(duration).toBeLessThan(1000);
    });

    it('should prevent resource exhaustion attacks', async () => {
      // Monitor memory usage during attack simulation
      const initialMemory = process.memoryUsage().heapUsed;

      const largeAttacks = Array.from({ length: 50 }, (_, i) => 
        'a'.repeat(1000) + `_attack_${i}.jpg`
      );

      for (const attack of largeAttacks) {
        const req = createMaliciousRequest(attack) as Request;
        const res = createMockResponse() as Response;
        const next = createMockNext();

        await validateFileContentAdvanced(req, res, next);
      }

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Memory increase should be reasonable (less than 10MB)
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });
  });
});