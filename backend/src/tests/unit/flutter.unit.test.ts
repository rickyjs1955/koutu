// backend/src/config/__tests__/flutter.unit.test.ts
import {
  getFlutterConfig,
  getFlutterCorsConfig,
  getFlutterUploadConfig,
  getPlatformConfig,
  validateFlutterConfig,
  getConfigSummary,
  updateFlutterConfig,
  resetFlutterConfig,
  flutterConfig
} from '../../config/flutter';

describe('Flutter Configuration Unit Tests', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('getFlutterConfig', () => {
    it('should return development config by default', () => {
      process.env.NODE_ENV = 'development';
      const config = getFlutterConfig();

      expect(config.cors.allowNoOrigin).toBe(true);
      expect(config.security.requireOriginInProduction).toBe(false);
      expect(config.responses.enableDebugMode).toBe(true);
      expect(config.security.rateLimitMax).toBe(1000);
    });

    it('should return production config with secure defaults', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_ORIGINS = 'https://example.com,https://api.example.com';
      
      const config = getFlutterConfig();

      expect(config.cors.allowNoOrigin).toBe(false);
      expect(config.security.requireOriginInProduction).toBe(true);
      expect(config.responses.enableDebugMode).toBe(false);
      expect(config.security.rateLimitMax).toBe(50);
      expect(config.performance.enableCompression).toBe(true);
      expect(config.performance.enableCaching).toBe(true);
    });

    it('should return test config with relaxed security', () => {
      process.env.NODE_ENV = 'test';
      
      const config = getFlutterConfig();

      expect(config.cors.allowNoOrigin).toBe(true);
      expect(config.cors.allowedOrigins).toContain('*');
      expect(config.security.enableRateLimiting).toBe(false);
      expect(config.uploads.maxFileSize).toBe(1024 * 1024); // 1MB
      expect(config.performance.connectionTimeout).toBe(5000);
      expect(config.monitoring.enablePerformanceTracking).toBe(false);
    });

    it('should handle custom environment variables', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_ORIGINS = 'https://app1.com,https://app2.com';
      process.env.PORT = '8080';
      process.env.UPLOAD_TEMP_DIR = '/custom/upload/dir';

      const config = getFlutterConfig();

      expect(config.cors.allowedOrigins).toContain('https://app1.com');
      expect(config.cors.allowedOrigins).toContain('https://app2.com');
      expect(config.networking.defaultPort).toBe(8080);
      expect(config.uploads.tempDir).toBe('/custom/upload/dir');
    });

    it('should have correct default values', () => {
      const config = getFlutterConfig();

      expect(config.uploads.maxFileSize).toBe(10 * 1024 * 1024); // 10MB
      expect(config.uploads.maxFiles).toBe(5);
      expect(config.cors.maxAge).toBe(3600);
      expect(config.security.rateLimitWindowMs).toBe(15 * 60 * 1000); // 15 minutes
      expect(config.performance.connectionTimeout).toBe(30000);
      expect(config.monitoring.slowRequestThreshold).toBe(2000);
    });

    it('should include required headers for Flutter apps', () => {
      const config = getFlutterConfig();

      expect(config.cors.allowedHeaders).toContain('X-Flutter-App');
      expect(config.cors.allowedHeaders).toContain('X-Platform');
      expect(config.cors.allowedHeaders).toContain('X-App-Version');
      expect(config.cors.allowedHeaders).toContain('X-Device-ID');
      expect(config.cors.exposedHeaders).toContain('X-Flutter-Optimized');
    });

    it('should include Android emulator origin', () => {
      const config = getFlutterConfig();
      expect(config.cors.allowedOrigins).toContain('http://10.0.2.2:3000');
    });
  });

  describe('getFlutterCorsConfig', () => {
    it('should allow requests with no origin when configured', () => {
      process.env.NODE_ENV = 'development';
      const corsConfig = getFlutterCorsConfig();

      const callback = jest.fn();
      corsConfig.origin(undefined, callback);

      expect(callback).toHaveBeenCalledWith(null, true);
    });

    it('should allow configured origins', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_ORIGINS = 'https://example.com';
      
      const corsConfig = getFlutterCorsConfig();
      const callback = jest.fn();
      
      corsConfig.origin('https://example.com', callback);
      expect(callback).toHaveBeenCalledWith(null, true);
    });

    it('should allow localhost variations for development', () => {
      process.env.NODE_ENV = 'development';
      const corsConfig = getFlutterCorsConfig();
      const callback = jest.fn();

      corsConfig.origin('http://localhost:3000', callback);
      expect(callback).toHaveBeenCalledWith(null, true);

      corsConfig.origin('http://127.0.0.1:3000', callback);
      expect(callback).toHaveBeenCalledWith(null, true);

      corsConfig.origin('http://10.0.2.2:3000', callback);
      expect(callback).toHaveBeenCalledWith(null, true);
    });

    it('should reject unknown origins in production', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_ORIGINS = 'https://example.com';
      
      const corsConfig = getFlutterCorsConfig();
      const callback = jest.fn();
      
      corsConfig.origin('https://malicious.com', callback);
      expect(callback).toHaveBeenCalledWith(new Error('Origin not allowed'));
    });

    it('should require origin in production when configured', () => {
      process.env.NODE_ENV = 'production';
      process.env.ALLOWED_ORIGINS = 'https://example.com';
      
      const corsConfig = getFlutterCorsConfig();
      const callback = jest.fn();
      
      corsConfig.origin(undefined, callback);
      expect(callback).toHaveBeenCalledWith(new Error('Origin required in production'));
    });

    it('should have correct CORS properties', () => {
      const corsConfig = getFlutterCorsConfig();

      expect(corsConfig.credentials).toBe(true);
      expect(corsConfig.methods).toContain('GET');
      expect(corsConfig.methods).toContain('POST');
      expect(corsConfig.methods).toContain('PUT');
      expect(corsConfig.methods).toContain('DELETE');
      expect(corsConfig.preflightContinue).toBe(true);
      expect(corsConfig.optionsSuccessStatus).toBe(204);
      expect(corsConfig.maxAge).toBe(3600);
    });
  });

  describe('getFlutterUploadConfig', () => {
    it('should return default upload config', () => {
      const uploadConfig = getFlutterUploadConfig();

      expect(uploadConfig.limits.fileSize).toBe(10 * 1024 * 1024); // 10MB
      expect(uploadConfig.limits.files).toBe(5);
      expect(uploadConfig.limits.fieldSize).toBe(1024 * 1024); // 1MB
      expect(uploadConfig.limits.fieldNameSize).toBe(100);
      expect(uploadConfig.limits.headerPairs).toBe(2000);
    });

    it('should return platform-specific upload limits', () => {
      const androidConfig = getFlutterUploadConfig('android');
      const iosConfig = getFlutterUploadConfig('ios');
      const webConfig = getFlutterUploadConfig('web');
      const desktopConfig = getFlutterUploadConfig('desktop');

      expect(androidConfig.limits.fileSize).toBe(50 * 1024 * 1024); // 50MB
      expect(iosConfig.limits.fileSize).toBe(25 * 1024 * 1024); // 25MB
      expect(webConfig.limits.fileSize).toBe(10 * 1024 * 1024); // 10MB
      expect(desktopConfig.limits.fileSize).toBe(100 * 1024 * 1024); // 100MB
    });

    it('should filter allowed MIME types', () => {
      const uploadConfig = getFlutterUploadConfig();
      const mockFile = {
        mimetype: 'image/jpeg',
        originalname: 'test.jpg'
      };
      const callback = jest.fn();

      uploadConfig.fileFilter(null, mockFile, callback);
      expect(callback).toHaveBeenCalledWith(null, true);
    });

    it('should reject disallowed MIME types', () => {
      const uploadConfig = getFlutterUploadConfig();
      const mockFile = {
        mimetype: 'application/pdf',
        originalname: 'test.pdf'
      };
      const callback = jest.fn();

      uploadConfig.fileFilter(null, mockFile, callback);
      expect(callback).toHaveBeenCalledWith(new Error('File type application/pdf not allowed'));
    });

    it('should reject files with long names', () => {
      const uploadConfig = getFlutterUploadConfig();
      const mockFile = {
        mimetype: 'image/jpeg',
        originalname: 'a'.repeat(300) + '.jpg'
      };
      const callback = jest.fn();

      uploadConfig.fileFilter(null, mockFile, callback);
      expect(callback).toHaveBeenCalledWith(new Error('Filename too long'));
    });

    it('should reject suspicious file extensions', () => {
      const uploadConfig = getFlutterUploadConfig();
      const suspiciousFiles = [
        'test.php',
        'test.asp',
        'test.jsp',
        'test.exe',
        'test.bat',
        'test.sh'
      ];

      suspiciousFiles.forEach(filename => {
        const mockFile = {
          mimetype: 'image/jpeg',
          originalname: filename
        };
        const callback = jest.fn();

        uploadConfig.fileFilter(null, mockFile, callback);
        expect(callback).toHaveBeenCalledWith(new Error('File type not allowed'));
      });
    });

    it('should generate secure filenames', () => {
      const uploadConfig = getFlutterUploadConfig();
      const mockFile = {
        originalname: 'test.jpg'
      };
      const callback = jest.fn();

      uploadConfig.filename(null, mockFile, callback);

      expect(callback).toHaveBeenCalledWith(null, expect.stringMatching(/^flutter_\d+_[a-z0-9]+\.jpg$/));
    });
  });

  describe('getPlatformConfig', () => {
    it('should return platform-specific configurations', () => {
      const androidConfig = getPlatformConfig('android');
      const iosConfig = getPlatformConfig('ios');
      const webConfig = getPlatformConfig('web');
      const desktopConfig = getPlatformConfig('desktop');

      expect(androidConfig.maxUploadSize).toBe(50 * 1024 * 1024);
      expect(androidConfig.requestTimeout).toBe(15000);

      expect(iosConfig.maxUploadSize).toBe(25 * 1024 * 1024);
      expect(iosConfig.requestTimeout).toBe(10000);

      expect(webConfig.maxUploadSize).toBe(10 * 1024 * 1024);
      expect(webConfig.requestTimeout).toBe(8000);

      expect(desktopConfig.maxUploadSize).toBe(100 * 1024 * 1024);
      expect(desktopConfig.requestTimeout).toBe(30000);
    });

    it('should return web config for unknown platforms', () => {
      const unknownConfig = getPlatformConfig('unknown');
      const webConfig = getPlatformConfig('web');

      expect(unknownConfig).toEqual(webConfig);
    });

    it('should return web config when no platform specified', () => {
      const defaultConfig = getPlatformConfig();
      const webConfig = getPlatformConfig('web');

      expect(defaultConfig).toEqual(webConfig);
    });
  });

  describe('validateFlutterConfig', () => {
    it('should validate successful configuration', () => {
      process.env.NODE_ENV = 'development';
      const validation = validateFlutterConfig();

      expect(validation.valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it('should detect file size too large', () => {
      process.env.NODE_ENV = 'development';
      updateFlutterConfig({
        uploads: {
          maxFileSize: 150 * 1024 * 1024, // 150MB
          maxFiles: 5,
          allowedMimeTypes: ['image/jpeg'],
          tempDir: '/tmp',
          platformLimits: {
            android: 50 * 1024 * 1024,
            ios: 25 * 1024 * 1024,
            web: 10 * 1024 * 1024,
            desktop: 100 * 1024 * 1024
          }
        }
      });

      const validation = validateFlutterConfig();
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Max file size too large (>100MB)');
    });

    it('should detect empty allowed MIME types', () => {
      process.env.NODE_ENV = 'development';
      updateFlutterConfig({
        uploads: {
          maxFileSize: 10 * 1024 * 1024,
          maxFiles: 5,
          allowedMimeTypes: [], // Empty array
          tempDir: '/tmp',
          platformLimits: {
            android: 50 * 1024 * 1024,
            ios: 25 * 1024 * 1024,
            web: 10 * 1024 * 1024,
            desktop: 100 * 1024 * 1024
          }
        }
      });

      const validation = validateFlutterConfig();
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('No allowed MIME types specified');
    });

    it('should detect production security issues', () => {
      process.env.NODE_ENV = 'production';
      updateFlutterConfig({
        cors: {
          allowNoOrigin: true, // Should be false in production
          allowedOrigins: [], // Should not be empty in production
          maxAge: 3600,
          credentials: true,
          allowedHeaders: ['Content-Type'],
          exposedHeaders: ['Content-Length'],
          allowedMethods: ['GET', 'POST']
        }
      });

      const validation = validateFlutterConfig();
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('allowNoOrigin should be false in production');
      expect(validation.errors).toContain('No allowed origins specified for production');
    });

    it('should detect timeout configuration issues', () => {
      process.env.NODE_ENV = 'development';
      updateFlutterConfig({
        performance: {
          enableCompression: true,
          enableCaching: false,
          cacheMaxAge: 300,
          enableGzip: true,
          connectionTimeout: 500, // Too short
          requestTimeout: 500, // Too short
          enableKeepAlive: true
        }
      });

      const validation = validateFlutterConfig();
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Connection timeout too short (<1s)');
      expect(validation.errors).toContain('Request timeout too short (<1s)');
    });

    it('should detect slow request threshold too low', () => {
      process.env.NODE_ENV = 'development';
      updateFlutterConfig({
        monitoring: {
          enablePerformanceTracking: true,
          enableErrorTracking: true,
          logSlowRequests: true,
          slowRequestThreshold: 50, // Too low
          enableHealthChecks: true
        }
      });

      const validation = validateFlutterConfig();
      expect(validation.valid).toBe(false);
      expect(validation.errors).toContain('Slow request threshold too low (<100ms)');
    });
  });

  describe('getConfigSummary', () => {
    it('should return configuration summary', () => {
      process.env.NODE_ENV = 'development';
      const summary = getConfigSummary();

      expect(summary.environment).toBe('development');
      expect(summary.version).toBe('1.0.0');
      expect(summary.cors).toHaveProperty('allowNoOrigin');
      expect(summary.cors).toHaveProperty('originsCount');
      expect(summary.cors).toHaveProperty('credentials');
      expect(summary.uploads).toHaveProperty('maxSize');
      expect(summary.uploads).toHaveProperty('allowedTypes');
      expect(summary.uploads).toHaveProperty('platformLimits');
      expect(summary.security).toHaveProperty('rateLimiting');
      expect(summary.performance).toHaveProperty('compression');
      expect(summary.monitoring).toHaveProperty('performanceTracking');
    });

    it('should format file sizes correctly', () => {
      const summary = getConfigSummary();
      
      expect(summary.uploads.maxSize).toBe('10MB');
      expect(summary.uploads.platformLimits.android).toBe('50MB');
      expect(summary.uploads.platformLimits.ios).toBe('25MB');
      expect(summary.uploads.platformLimits.web).toBe('10MB');
      expect(summary.uploads.platformLimits.desktop).toBe('100MB');
    });
  });

  describe('updateFlutterConfig', () => {
    it('should update configuration in non-production environments', () => {
      process.env.NODE_ENV = 'development';
      
      expect(() => {
        updateFlutterConfig({
          uploads: {
            maxFileSize: 5 * 1024 * 1024,
            maxFiles: 3,
            allowedMimeTypes: ['image/png'],
            tempDir: '/custom/temp',
            platformLimits: {
              android: 20 * 1024 * 1024,
              ios: 15 * 1024 * 1024,
              web: 5 * 1024 * 1024,
              desktop: 50 * 1024 * 1024
            }
          }
        });
      }).not.toThrow();
    });

    it('should prevent updates in production', () => {
      process.env.NODE_ENV = 'production';
      
      expect(() => {
        updateFlutterConfig({
          uploads: {
            maxFileSize: 5 * 1024 * 1024,
            maxFiles: 3,
            allowedMimeTypes: ['image/png'],
            tempDir: '/custom/temp',
            platformLimits: {
              android: 20 * 1024 * 1024,
              ios: 15 * 1024 * 1024,
              web: 5 * 1024 * 1024,
              desktop: 50 * 1024 * 1024
            }
          }
        });
      }).toThrow('Configuration updates not allowed in production');
    });
  });

  describe('resetFlutterConfig', () => {
    it('should reset configuration in non-production environments', () => {
      process.env.NODE_ENV = 'development';
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      expect(() => {
        resetFlutterConfig();
      }).not.toThrow();
      
      expect(consoleSpy).toHaveBeenCalledWith('Flutter configuration reset to defaults');
      consoleSpy.mockRestore();
    });

    it('should prevent reset in production', () => {
      process.env.NODE_ENV = 'production';
      
      expect(() => {
        resetFlutterConfig();
      }).toThrow('Configuration reset not allowed in production');
    });
  });

  describe('flutterConfig export', () => {
    it('should export the configuration object', () => {
      expect(flutterConfig).toBeDefined();
      expect(flutterConfig).toHaveProperty('cors');
      expect(flutterConfig).toHaveProperty('uploads');
      expect(flutterConfig).toHaveProperty('responses');
      expect(flutterConfig).toHaveProperty('security');
      expect(flutterConfig).toHaveProperty('performance');
      expect(flutterConfig).toHaveProperty('networking');
      expect(flutterConfig).toHaveProperty('monitoring');
      expect(flutterConfig).toHaveProperty('features');
    });
  });

  describe('Configuration validation on module load', () => {
    it('should warn about invalid configuration', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      // Force invalid configuration
      process.env.NODE_ENV = 'production';
      delete process.env.ALLOWED_ORIGINS;
      
      // Re-import module to trigger validation
      jest.resetModules();
      require('../../config/flutter');
      
      expect(consoleSpy).toHaveBeenCalledWith(
        'Flutter configuration validation warnings:',
        expect.arrayContaining([
          'No allowed origins specified for production'
        ])
      );
      
      consoleSpy.mockRestore();
    });
  });
});