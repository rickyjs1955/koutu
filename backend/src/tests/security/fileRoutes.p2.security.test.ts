// /backend/src/tests/security/fileRoutes.p2.security.test.ts
// Advanced Security Tests for FileRoutes - Phase 2
// These tests complement the existing fileRoutes.security.test.ts

/**
 * @file fileRoutes.p2.security.test.ts
 * @description
 *
 * ### Important Note for Security Tests (fileRoutes.p2.security.test.ts)
 *
 * These tests, specifically those marked with `it.skip`, represent **Phase 2 (P2) Advanced Security vulnerabilities and attack vectors** that our `fileRoutes` module is currently susceptible to.
 *
 * **Why are they skipped?**
 * They are intentionally skipped because the corresponding security detection, prevention, or mitigation features have **not yet been implemented** in the core application logic. Running them would currently result in failures (e.g., expecting `400` but receiving `200` or `500`).
 * It doesn't make sense to enable them until the necessary security features are in place to handle these advanced attack vectors.
 * 
 * **Purpose as a Roadmap:**
 * These `it.skip` tests serve as an **executable security roadmap**. They clearly define the specific types of advanced attacks (e.g., polyglot files, homographs, injection attempts, missing security headers) that our system needs to defend against in future development phases.
 *
 * **For Future Team Members:**
 * As our application grows and security becomes a higher priority, your task will be to **enable these tests (by changing `it.skip` to `it`) and implement the necessary security features** in the `fileRoutes` or relevant middleware to make them pass. This ensures we are systematically closing known security gaps.
 */

jest.mock('../../config/firebase', () => ({
    default: { storage: jest.fn() },
}));

import express, { Request, Response, NextFunction } from 'express';
import request from 'supertest';
import { config } from '../../../src/config';
import { storageService } from '../../../src/services/storageService';
import { authenticate } from '../../../src/middlewares/auth';
import path from 'path';

// Mock dependencies
jest.mock('../../../src/config');
jest.mock('../../../src/services/storageService');
jest.mock('../../../src/middlewares/auth');

const mockConfig = config as jest.Mocked<typeof config>;
const mockStorageService = storageService as jest.Mocked<typeof storageService>;
const mockAuthenticate = authenticate as jest.MockedFunction<typeof authenticate>;

// Mock fileValidate middleware
jest.mock('../../../src/middlewares/fileValidate', () => ({
    validateFileContentBasic: jest.fn((req: Request, res: Response, next: NextFunction) => {
        const filepath = req.params.filepath;
        
        // This will initially cause tests to fail - that's expected
        // Advanced security detection can be added here later
        
        (req as any).fileValidation = { 
        filepath, 
        isValid: true, 
        fileType: 'unknown',
        securityFlags: []
        };
        next();
    }),
    validateFileContent: jest.fn((req: Request, res: Response, next: NextFunction) => {
        const filepath = req.params.filepath;
        
        // Advanced content validation can be added here later
        
        (req as any).fileValidation = { 
        filepath, 
        isValid: true, 
        fileType: 'image/jpeg',
        fileSize: 1024,
        securityFlags: []
        };
        next();
    }),
    validateImageFile: jest.fn((req: Request, res: Response, next: NextFunction) => {
        const filepath = req.params.filepath;
        
        // Advanced image validation can be added here later
        
        (req as any).fileValidation = { 
        filepath, 
        isValid: true, 
        fileType: 'image/jpeg'
        };
        next();
    }),
    logFileAccess: jest.fn((req: Request, res: Response, next: NextFunction) => {
        // Enhanced logging can be added here later
        next();
    })
}));

// Mock path module
jest.mock('path', () => ({
    ...jest.requireActual('path'),
    extname: jest.fn(),
    basename: jest.fn(),
    normalize: jest.fn()
}));

const mockPath = path as jest.Mocked<typeof path>;

// Import fileRoutes AFTER mocking
import { fileRoutes } from '../../../src/routes/fileRoutes';

const createTestApp = () => {
    const app = express();
    app.use('/api/v1/files', fileRoutes);
    
    app.use((err: any, req: Request, res: Response, next: NextFunction) => {
        res.status(err.statusCode || 500).json({
        error: {
            message: err.message,
            code: err.code || 'INTERNAL_ERROR',
            timestamp: new Date().toISOString()
        }
        });
    });
    
    return app;
};

describe('FileRoutes Advanced Security Tests (P2)', () => {
    let app: express.Application;
    let consoleSpy: jest.SpyInstance;

    beforeEach(() => {
        app = createTestApp();
        jest.clearAllMocks();
        
        consoleSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
        
        // Default safe mocks
        mockConfig.storageMode = 'local';
        mockStorageService.getAbsolutePath = jest.fn().mockReturnValue('/safe/storage/file.jpg');
        mockStorageService.getSignedUrl = jest.fn().mockResolvedValue('https://firebase.url/signed');
        
        mockAuthenticate.mockImplementation(async (req, res, next) => {
            (req as any).user = { id: 'user123', role: 'user' };
            next();
        });

        // Mock path functions
        mockPath.extname.mockImplementation((filepath: string) => {
            const ext = filepath.substring(filepath.lastIndexOf('.'));
            return ext || '';
        });
        
        mockPath.basename.mockImplementation((filepath: string) => {
            return filepath.substring(filepath.lastIndexOf('/') + 1);
        });
        
        mockPath.normalize.mockImplementation((filepath: string) => {
            return filepath.replace(/\\/g, '/').replace(/\/+/g, '/');
        });

        // Mock Express response methods
        jest.spyOn(express.response, 'sendFile').mockImplementation(function(this: Response) {
            this.setHeader('Content-Type', this.getHeader('Content-Type') || 'application/octet-stream');
            this.status(200).send('mocked file content');
            return this;
        });

        jest.spyOn(express.response, 'download').mockImplementation(function(this: Response, path: string, filename?: string) {
            this.setHeader('Content-Type', this.getHeader('Content-Type') || 'application/octet-stream');
            this.setHeader('Content-Disposition', `attachment; filename="${filename || 'download'}"`);
            this.status(200).send('mocked download content');
            return this;
        });

        jest.spyOn(express.response, 'redirect').mockImplementation(function(this: Response, status: number | string, url?: string) {
        if (typeof status === 'string') {
            url = status;
            status = 302;
        }
        this.status(status as number);
        this.setHeader('Location', url || '');
        this.send();
        return this;
        });
    });

    afterEach(() => {
        if (consoleSpy) {
        consoleSpy.mockRestore();
        }
        jest.restoreAllMocks();
    });

    describe('Advanced Unicode Encoding Attack Prevention', () => {
        it.skip('should detect UTF-8 overlong encoding attacks', async () => {
            const overlongSequences = [
                '%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd', // Overlong dot and slash
                '%e0%80%ae%e0%80%ae%e0%80%af',                        // 3-byte overlong
                '%f0%80%80%ae%f0%80%80%ae%f0%80%80%af',             // 4-byte overlong
                '%c1%9c%c1%9c%c1%9c%c1%9c%c1%9c%c1%9c'              // Invalid UTF-8 sequence
            ];

            for (const sequence of overlongSequences) {
                const response = await request(app)
                .get(`/api/v1/files/${sequence}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toMatch(/INVALID_ENCODING|ADVANCED_SECURITY_VIOLATION/);
            }
        });

        it.skip('should detect Unicode homograph attacks', async () => {
            const homographAttacks = [
                // Cyrillic characters that look like Latin
                encodeURIComponent('../../../еtc/passwd'),     // Cyrillic 'е' instead of 'e'
                encodeURIComponent('../../../еtс/passwd'),     // Cyrillic 'с' instead of 'c'
                encodeURIComponent('../../../рasswd'),         // Cyrillic 'р' instead of 'p'
                encodeURIComponent('аdmin/config.json'),       // Cyrillic 'а' instead of 'a'
            ];

            for (const attack of homographAttacks) {
                const response = await request(app)
                .get(`/api/v1/files/${attack}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('HOMOGRAPH_ATTACK_DETECTED');
            }
        });

        it.skip('should detect multiple encoding chain attacks', async () => {
            const chainAttacks = [
                // Triple URL encoding
                '%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%36%35%25%37%34%25%36%33%25%32%66%25%37%30%25%36%31%25%37%33%25%37%33%25%37%37%25%36%34',
                // Mixed encoding types
                'test%252e%252e%252f..%5c..%5cetc%5cpasswd',
                // Unicode + URL encoding mix
                '%u002e%u002e%u002f%2e%2e%2fetc%2fpasswd'
            ];

            for (const attack of chainAttacks) {
                const response = await request(app)
                .get(`/api/v1/files/${attack}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toMatch(/MULTIPLE_ENCODING|ADVANCED_SECURITY_VIOLATION/);
            }
        });

        it('should handle malformed Unicode sequences gracefully', async () => {
            const malformedSequences = [
                '%c0%c0%c0%c0',           // Invalid UTF-8 start bytes
                '%ff%fe%fd%fc',           // Invalid high bytes
                '%80%81%82%83',           // Invalid continuation bytes
                'test%c0',                 // Incomplete sequence
                'file%e0%80'              // Truncated 3-byte sequence
            ];

            for (const sequence of malformedSequences) {
                const response = await request(app)
                .get(`/api/v1/files/${sequence}`);

                expect([400, 500]).toContain(response.status);
                if (response.status === 400) {
                expect(response.body.error.code).toMatch(/INVALID_ENCODING|MALFORMED_UNICODE/);
                }
            }
        });
    });

    describe('Advanced File Pattern Detection', () => {
        it.skip('should detect polyglot file attacks', async () => {
            const polyglotFiles = [
                'image%PDF-1.4.jpg',           // PDF header in image filename
                'photo#!/bin/bash.png',        // Shell script header
                'gallery<script>alert(1)</script>.jpg', // JavaScript in filename
                'document<?php echo shell_exec($_GET[\'cmd\']); ?>.png', // PHP code
                'file%89PNG%0D%0A%1A%0A.exe',  // PNG signature with executable extension
                'JFIF%FF%D8%FF%E0.php'         // JPEG header in PHP file
            ];

            for (const file of polyglotFiles) {
                const response = await request(app)
                .get(`/api/v1/files/images/${file}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('POLYGLOT_FILE_DETECTED');
            }
        });

        it.skip('should detect Windows reserved device names', async () => {
            const reservedNames = [
                'CON.jpg', 'PRN.png', 'AUX.gif', 'NUL.bmp',
                'COM1.jpg', 'COM9.png', 'LPT1.gif', 'LPT9.bmp',
                // With paths
                'folder/CON.txt', 'path/to/PRN.pdf',
                // Case variations
                'con.jpg', 'prn.PNG', 'Aux.GIF'
            ];

            for (const name of reservedNames) {
                const response = await request(app)
                .get(`/api/v1/files/${name}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('WINDOWS_RESERVED_NAME');
            }
        });

        it.skip('should detect backup and temporary file patterns', async () => {
            const backupFiles = [
                'database.sql.bak', 'config.php.old', 'secrets.json.tmp',
                'application.log', 'debug.log', 'error.log',
                'backup.tar.gz', 'site-backup.zip',
                'file.txt~', 'document.pdf.backup',
                '.DS_Store', 'Thumbs.db', 'desktop.ini'
            ];

            for (const file of backupFiles) {
                const response = await request(app)
                .get(`/api/v1/files/${file}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('BACKUP_FILE_DETECTED');
            }
        });

        it.skip('should detect MIME confusion attacks', async () => {
            const mimeConfusionFiles = [
                'script.js.png',           // JavaScript disguised as PNG
                'executable.exe.jpg',      // Executable disguised as image
                'php_shell.php.gif',       // PHP file disguised as GIF
                'html_payload.html.bmp',   // HTML disguised as bitmap
                'java.class.png',          // Java bytecode as image
                'python.py.jpg'            // Python script as image
            ];

            for (const file of mimeConfusionFiles) {
                const response = await request(app)
                .get(`/api/v1/files/images/${file}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('MIME_CONFUSION_DETECTED');
            }
        });

        it.skip('should detect alternate data stream attacks (Windows)', async () => {
            const adsFiles = [
                'image.jpg:hidden.exe',
                'document.pdf:script.bat',
                'photo.png:malware.dll',
                'file.txt:zone.identifier'
            ];

            for (const file of adsFiles) {
                const response = await request(app)
                .get(`/api/v1/files/${encodeURIComponent(file)}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('ADS_ATTACK_DETECTED');
            }
        });
    });

    describe('Content Security and Steganography Detection', () => {
        it.skip('should detect potential steganography in image requests', async () => {
            const steganographyIndicators = [
                'image_with_hidden_data.jpg',
                'photo_high_entropy.png',
                'steganography_payload.gif',
                'lsb_hidden_message.bmp',
                'frequency_domain_hiding.jpg'
            ];

            for (const file of steganographyIndicators) {
                const response = await request(app)
                .get(`/api/v1/files/images/${file}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('STEGANOGRAPHY_DETECTED');
            }
        });

        it.skip('should detect malicious metadata injection', async () => {
            const metadataAttacks = [
                'photo_exif_xss.jpg',
                'image_malicious_comment.png',
                'file_script_metadata.gif',
                'document_embedded_js.pdf'
            ];

            for (const file of metadataAttacks) {
                const response = await request(app)
                .get(`/api/v1/files/${file}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('MALICIOUS_METADATA_DETECTED');
            }
        });

        it.skip('should detect ZIP bomb and compression bomb attempts', async () => {
            const compressionBombs = [
                'zip_bomb.zip',
                'gzip_bomb.tar.gz',
                'xml_billion_laughs.xml',
                'nested_archive_bomb.rar'
            ];

            for (const bomb of compressionBombs) {
                const response = await request(app)
                .get(`/api/v1/files/${bomb}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('COMPRESSION_BOMB_DETECTED');
            }
        });

        it.skip('should validate file size vs content inconsistencies', async () => {
            const inconsistentFiles = [
                'tiny_claims_huge.jpg',      // Claims to be large but actually tiny
                'huge_claims_tiny.png',      // Claims to be tiny but actually huge
                'zero_byte_with_header.gif'  // Zero bytes but has valid header
            ];

            for (const file of inconsistentFiles) {
                const response = await request(app)
                .get(`/api/v1/files/${file}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('SIZE_CONTENT_MISMATCH');
            }
        });
    });

    describe('Network and Protocol Level Attacks', () => {
        it.skip('should detect Server-Side Request Forgery (SSRF) attempts', async () => {
            const ssrfPayloads = [
                encodeURIComponent('http://169.254.169.254/metadata'),      // AWS metadata
                encodeURIComponent('http://metadata.google.internal/'),     // GCP metadata
                encodeURIComponent('http://localhost:22/ssh-probe'),        // Local service probe
                encodeURIComponent('file:///etc/passwd'),                   // Local file access
                encodeURIComponent('ftp://internal.company.com/secrets')    // Internal FTP
            ];

            for (const payload of ssrfPayloads) {
                const response = await request(app)
                .get(`/api/v1/files/${payload}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('SSRF_ATTEMPT_DETECTED');
            }
        });

        it.skip('should detect DNS rebinding attacks', async () => {
            const dnsRebindingDomains = [
                'http://admin.localhost.evil.com/secret',
                'http://192.168.1.1.attacker.com/router-config',
                'http://127.0.0.1.malicious.org/internal-api'
            ];

            for (const domain of dnsRebindingDomains) {
                const response = await request(app)
                .get(`/api/v1/files/${encodeURIComponent(domain)}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('DNS_REBINDING_DETECTED');
            }
        });

        it.skip('should detect HTTP smuggling attempts', async () => {
            const smugglingPayloads = [
                'test.jpg\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal',
                'image.png\nTransfer-Encoding: chunked\n\n0\n\nGET /secret HTTP/1.1',
                'file.pdf\r\nContent-Length: 30\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'
            ];

            for (const payload of smugglingPayloads) {
                const response = await request(app)
                .get(`/api/v1/files/${encodeURIComponent(payload)}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('HTTP_SMUGGLING_DETECTED');
            }
        });
    });

    describe('Injection Attack Prevention', () => {
        it.skip('should detect template injection attempts', async () => {
            const templateInjections = [
                encodeURIComponent('{{7*7}}.jpg'),
                encodeURIComponent('${7*7}.png'),
                encodeURIComponent('<%=7*7%>.gif'),
                encodeURIComponent('#{7*7}.bmp')
            ];

            for (const injection of templateInjections) {
                const response = await request(app)
                .get(`/api/v1/files/${injection}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('TEMPLATE_INJECTION_DETECTED');
            }
        });

        it.skip('should detect LDAP injection attempts', async () => {
            const ldapInjections = [
                encodeURIComponent('file*)(uid=*))(|(uid=*'),
                encodeURIComponent('image*)(|(password=*))'),
                encodeURIComponent('doc*)((|userPassword=*))'),
                encodeURIComponent('test*))%00')
            ];

            for (const injection of ldapInjections) {
                const response = await request(app)
                .get(`/api/v1/files/${injection}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('LDAP_INJECTION_DETECTED');
            }
        });

        it.skip('should detect NoSQL injection attempts', async () => {
            const nosqlInjections = [
                encodeURIComponent('{"$gt": ""}'),
                encodeURIComponent('{"$regex": ".*"}'),
                encodeURIComponent('{"$where": "function() { return true; }"}'),
                encodeURIComponent('{"$ne": null}')
            ];

            for (const injection of nosqlInjections) {
                const response = await request(app)
                .get(`/api/v1/files/${injection}`);

                expect(response.status).toBe(400);
                expect(response.body.error.code).toBe('NOSQL_INJECTION_DETECTED');
            }
        });
    });

    describe('Advanced Rate Limiting and DoS Prevention', () => {
        it.skip('should implement adaptive security responses', async () => {
            const suspiciousRequests = [
                'attack_file_1.jpg',
                'malicious_payload_2.png',
                'suspicious_script_3.gif',
                'attack_vector_4.bmp',
                'malicious_content_5.jpg'
            ];

            let rateLimitTriggered = false;

            for (let i = 0; i < suspiciousRequests.length; i++) {
                const response = await request(app)
                .get(`/api/v1/files/${suspiciousRequests[i]}`);

                if (response.status === 429) {
                rateLimitTriggered = true;
                expect(response.body.error.code).toBe('ADAPTIVE_SECURITY_TRIGGERED');
                break;
                }
            }

            expect(rateLimitTriggered).toBe(true);
        });

        it.skip('should detect suspicious request patterns', async () => {
            const patterns = [
                'admin_config.jpg',
                'database_backup.png',
                'secret_keys.gif',
                'password_file.bmp'
            ];

            let suspiciousDetected = false;

            for (const pattern of patterns) {
                const response = await request(app)
                .get(`/api/v1/files/${pattern}`);

                if (response.status === 429 && response.body.error.code === 'SUSPICIOUS_PATTERN_DETECTED') {
                suspiciousDetected = true;
                break;
                }
            }

            expect(suspiciousDetected).toBe(true);
        });

        it('should prevent ReDoS (Regular Expression Denial of Service)', async () => {
            const redosPatterns = [
                'a'.repeat(1000) + 'X.jpg',                    // Linear ReDoS pattern
                '(' + 'a+'.repeat(50) + ')*.png',              // Polynomial ReDoS
                'test' + '(a+)+'.repeat(30) + 'X.gif'          // Exponential ReDoS
            ];

            for (const pattern of redosPatterns) {
                const startTime = Date.now();
                
                const response = await request(app)
                .get(`/api/v1/files/${encodeURIComponent(pattern)}`);
                
                const endTime = Date.now();
                const processingTime = endTime - startTime;
                
                // Should not take excessive time (protect against ReDoS)
                expect(processingTime).toBeLessThan(1000); // Max 1 second
                expect([200, 400, 414]).toContain(response.status); // 414 = URI Too Long
            }
        });
    });

    describe('Security Headers and Response Integrity', () => {
        it.skip('should set comprehensive security headers for all file types', async () => {
            const fileTypes = [
                { path: 'document.pdf', route: 'download' },
                { path: 'image.jpg', route: 'images' },
                { path: 'file.txt', route: 'secure' }
            ];

            for (const { path: filePath, route } of fileTypes) {
                const response = await request(app)
                .get(`/api/v1/files/${route}/${filePath}`);

                // Should have comprehensive security headers
                expect(response.headers['x-content-type-options']).toBe('nosniff');
                expect(response.headers['x-frame-options']).toMatch(/DENY|SAMEORIGIN/);
                expect(response.headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
                expect(response.headers['x-xss-protection']).toBe('1; mode=block');
                
                // Should have CSP header
                expect(response.headers['content-security-policy']).toBeDefined();
            }
        });

        it('should prevent MIME sniffing for all content types', async () => {
            const contentTypes = [
                'application/pdf',
                'image/jpeg',
                'text/plain',
                'application/octet-stream'
            ];

            for (const contentType of contentTypes) {
                const response = await request(app)
                .get('/api/v1/files/test-file')
                .set('Accept', contentType);

                expect(response.headers['x-content-type-options']).toBe('nosniff');
            }
        });

        it.skip('should implement proper Content Security Policy for downloads', async () => {
            const response = await request(app)
                .get('/api/v1/files/download/secure-document.pdf');

            const csp = response.headers['content-security-policy'];
            expect(csp).toContain("default-src 'none'");
            expect(csp).toMatch(/sandbox/);
        });
    });

    describe('Error Handling and Information Disclosure Prevention', () => {
        it.skip('should not leak internal file paths in error responses', async () => {
            const response = await request(app)
                .get('/api/v1/files/non-existent-file.jpg');

            expect(response.status).toBe(404);
            expect(response.body.error.message).not.toMatch(/\/var\/www|\/home\/|C:\\|\/tmp\//);
            expect(response.body.error.message).not.toContain('ENOENT');
            expect(response.body.error.message).not.toContain('getAbsolutePath');
        });

        it.skip('should provide consistent error responses for security violations', async () => {
            const securityViolations = [
                '../../../etc/passwd',
                'malware.exe',
                '.env',
                'test\0.jpg'
            ];

            const responses = [];
            for (const violation of securityViolations) {
                const response = await request(app)
                .get(`/api/v1/files/${encodeURIComponent(violation)}`);
                responses.push(response);
            }

            // All should return 400 status
            responses.forEach(response => {
                expect(response.status).toBe(400);
                expect(response.body.error).toBeDefined();
                expect(response.body.error.code).toBeDefined();
                expect(response.body.error.timestamp).toBeDefined();
        });

            // Response times should be similar (prevent timing attacks)
            // This is a basic check - more sophisticated timing analysis could be added
            responses.forEach(response => {
                expect(response.body.error.message).not.toContain('internal');
                expect(response.body.error.message).not.toContain('stack');
                expect(response.body.error.message).not.toContain('Error:');
        });
        });
    });

    describe('Edge Cases and Boundary Conditions', () => {
        it('should handle extremely long file paths safely', async () => {
            const longPaths = [
                'a'.repeat(1000) + '.jpg',
                'b'.repeat(5000) + '.png',
                'path/' + 'segment/'.repeat(100) + 'file.gif'
            ];

            for (const longPath of longPaths) {
                const response = await request(app)
                .get(`/api/v1/files/${encodeURIComponent(longPath)}`);

                // Should handle gracefully without causing crashes
                expect([200, 400, 414]).toContain(response.status); // 414 = URI Too Long
            }
        });

        it('should handle Unicode edge cases in filenames', async () => {
            const unicodeEdgeCases = [
                'test\uFFFD.jpg',                    // Replacement character
                'file\u200B\u200C\u200D.png',       // Zero-width characters
                'emoji\uD83D\uDE00.gif',             // Emoji
                'rtl\u202E.jpg',                     // Right-to-left override
                'bom\uFEFF.png'                      // Byte order mark
            ];

            for (const filename of unicodeEdgeCases) {
                const response = await request(app)
                .get(`/api/v1/files/${encodeURIComponent(filename)}`);

                // Should handle Unicode edge cases gracefully
                expect([200, 400]).toContain(response.status);
            }
        });

        it('should handle concurrent requests to same suspicious file', async () => {
            const suspiciousFile = 'potential-attack.exe';
            
            const promises = Array.from({ length: 10 }, () =>
                request(app).get(`/api/v1/files/${suspiciousFile}`)
            );

            const responses = await Promise.all(promises);
            
            // All should be handled consistently
            responses.forEach(response => {
                expect([200, 400, 429]).toContain(response.status);
        });
        });
    });
});