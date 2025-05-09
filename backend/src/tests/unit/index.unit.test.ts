// backend/src/tests/unit/index.unit.test.ts

import path from "path";

const mockDotenvConfig = jest.fn();
jest.mock('dotenv', () => ({
  config: mockDotenvConfig,
}));

/**
 * Configuration Module Unit Test Suite
 * ------------------------------------
 * This suite tests the functionality of the configuration module, which centralizes application 
 * settings and provides environment-specific configurations.
 *
 * Testing Approach:
 * - Black Box Testing: Each test validates the inputs and expected outputs without exposing internal implementation details.
 * 
 * Key Focus Areas:
 * 1. Default Values:
 *    - Verify that default values are correctly applied when environment variables are not set.
 * 2. Environment Variable Handling:
 *    - Confirm that environment variables are properly loaded and override defaults.
 * 3. Configuration Structure:
 *    - Validate the structure of the configuration object and its properties.
 * 4. Helper Functions:
 *    - Test environment detection helper functions (isProd, isDev, isTest).
 * 5. Calculated Values:
 *    - Verify that calculated values (e.g., file paths) are correctly computed.
 *
 * The suite covers all major configuration sections:
 * - Core settings (port, nodeEnv)
 * - Database configuration
 * - JWT settings
 * - File storage configuration
 * - Firebase configuration
 * - OAuth settings
 * - Environment helpers
 */

describe('Configuration Module', () => {
  const originalProcessEnv = { ...process.env };
  
  beforeEach(() => {
    mockDotenvConfig.mockClear(); // Clear calls for each test
    jest.resetModules();          // Reset module cache
    process.env = { ...originalProcessEnv }; // Reset environment
  });
  
  afterAll(() => {
    process.env = originalProcessEnv;
    jest.unmock('dotenv'); // Clean up the global mock
  });

  describe('Configuration Object', () => {
    test('should have the correct structure with all required sections', () => {
        const { config } = require('../../config/index');
        expect(config).toHaveProperty('port');
        expect(config).toHaveProperty('nodeEnv');
        expect(config).toHaveProperty('databaseUrl');
        expect(config).toHaveProperty('jwtSecret');
        expect(config).toHaveProperty('jwtExpiresIn');
        expect(config).toHaveProperty('uploadsDir');
        expect(config).toHaveProperty('maxFileSize');
        expect(config).toHaveProperty('firebase');
        expect(config).toHaveProperty('logLevel');
        expect(config).toHaveProperty('storageMode');
        expect(config).toHaveProperty('appUrl');
        expect(config).toHaveProperty('oauth');
    });

    test('should have correct default values when environment variables are not set', () => {
      jest.isolateModules(() => { 
        const isolatedScopeOriginalEnv = { ...process.env };
        const mockDotenvConfig = jest.fn();

        // Use jest.doMock here
        jest.doMock('dotenv', () => {
          return {
            config: mockDotenvConfig,
          };
        });

        const keysToClear = [
          'NODE_ENV', 'PORT', 'DATABASE_URL', 'JWT_SECRET', 'JWT_EXPIRES_IN',
          'MAX_FILE_SIZE', 'LOG_LEVEL', 'STORAGE_MODE', 'APP_URL',
          'FIREBASE_PROJECT_ID', 'FIREBASE_PRIVATE_KEY', 'FIREBASE_CLIENT_EMAIL',
          'FIREBASE_STORAGE_BUCKET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET',
          'MICROSOFT_CLIENT_ID', 'MICROSOFT_CLIENT_SECRET', 'GITHUB_CLIENT_ID',
          'GITHUB_CLIENT_SECRET'
        ];
        keysToClear.forEach(key => delete process.env[key]);
        
        const { config: freshConfig } = require('../../config/index');

        expect(mockDotenvConfig).toHaveBeenCalled();
        expect(freshConfig.port).toBe(3000); // Expecting number due to || 3000 fallback
        expect(freshConfig.nodeEnv).toBe('development');
        expect(freshConfig.databaseUrl).toBeUndefined();
        expect(freshConfig.jwtSecret).toBeUndefined();
        expect(freshConfig.jwtExpiresIn).toBe('1d');
        expect(freshConfig.maxFileSize).toBe(5242880); // 5MB
        
        // Firebase defaults
        expect(freshConfig.firebase.projectId).toBeUndefined();
        expect(freshConfig.firebase.privateKey).toBe('');
        expect(freshConfig.firebase.clientEmail).toBe('');
        expect(freshConfig.firebase.storageBucket).toBe('');
        
        expect(freshConfig.logLevel).toBe('info');
        expect(freshConfig.storageMode).toBe('firebase');
        expect(freshConfig.appUrl).toBe('http://localhost:3000');
        
        // OAuth defaults
        expect(freshConfig.oauth.googleClientId).toBeUndefined();
        expect(freshConfig.oauth.googleClientSecret).toBeUndefined();
        expect(freshConfig.oauth.microsoftClientId).toBeUndefined();
        expect(freshConfig.oauth.microsoftClientSecret).toBeUndefined();
        expect(freshConfig.oauth.githubClientId).toBeUndefined();
        expect(freshConfig.oauth.githubClientSecret).toBeUndefined();

        process.env = isolatedScopeOriginalEnv;
        jest.unmock('dotenv');        
        });
      });

    test('should correctly construct the uploads directory path', () => {
        const { config } = require('../../config/index');
        const expectedPath = path.join(__dirname, '../../../../uploads');
        expect(config.uploadsDir).toBe(expectedPath);
    });
  });

  describe('Environment Variables Override', () => {
    test('should use environment variables when provided', () => {
      process.env.PORT = '4000';
      process.env.NODE_ENV = 'production';
      process.env.LOG_LEVEL = 'debug';
      process.env.STORAGE_MODE = 'local';
      process.env.MAX_FILE_SIZE = '10485760'; // 10MB
      
      // Need to reimport the module to reflect env changes
      jest.isolateModules(() => {
        const { config } = require('../../config/index');
        
        expect(config.port).toBe('4000');
        expect(config.nodeEnv).toBe('production');
        expect(config.logLevel).toBe('debug');
        expect(config.storageMode).toBe('local');
        expect(config.maxFileSize).toBe(10485760);
      });
    });

    test('should handle Firebase configuration from environment variables', () => {
      process.env.FIREBASE_PROJECT_ID = 'test-project';
      process.env.FIREBASE_PRIVATE_KEY = 'test-private-key';
      process.env.FIREBASE_CLIENT_EMAIL = 'test@example.com';
      process.env.FIREBASE_STORAGE_BUCKET = 'test-bucket';
      
      jest.isolateModules(() => {
        const { config } = require('../../config/index');
        
        expect(config.firebase.projectId).toBe('test-project');
        expect(config.firebase.privateKey).toBe('test-private-key');
        expect(config.firebase.clientEmail).toBe('test@example.com');
        expect(config.firebase.storageBucket).toBe('test-bucket');
      });
    });

    test('should handle OAuth configuration from environment variables', () => {
      process.env.GOOGLE_CLIENT_ID = 'google-id';
      process.env.GOOGLE_CLIENT_SECRET = 'google-secret';
      process.env.MICROSOFT_CLIENT_ID = 'microsoft-id';
      process.env.MICROSOFT_CLIENT_SECRET = 'microsoft-secret';
      process.env.GITHUB_CLIENT_ID = 'github-id';
      process.env.GITHUB_CLIENT_SECRET = 'github-secret';
      
      jest.isolateModules(() => {
        const { config } = require('../../config/index');
        
        expect(config.oauth.googleClientId).toBe('google-id');
        expect(config.oauth.googleClientSecret).toBe('google-secret');
        expect(config.oauth.microsoftClientId).toBe('microsoft-id');
        expect(config.oauth.microsoftClientSecret).toBe('microsoft-secret');
        expect(config.oauth.githubClientId).toBe('github-id');
        expect(config.oauth.githubClientSecret).toBe('github-secret');
      });
    });

    test('should set maxFileSize to NaN if MAX_FILE_SIZE is an invalid number string', () => {
      process.env.MAX_FILE_SIZE = 'not-a-number';
      
      jest.isolateModules(() => {
        const { config: freshConfig } = require('../../config/index');
        // parseInt('not-a-number', 10) results in NaN
        expect(isNaN(freshConfig.maxFileSize)).toBe(true);
      });
    });

    test('should set maxFileSize to the default value if MAX_FILE_SIZE is an empty string', () => {
      process.env.MAX_FILE_SIZE = '';
      
      jest.isolateModules(() => {
        const { config: freshConfig } = require('../../config/index');
        // When MAX_FILE_SIZE is '', it uses the default '5242880' due to the || operator
        expect(freshConfig.maxFileSize).toBe(5242880); 
      });
    });
  });

  describe('Environment Helper Functions', () => {
    test('isProd should return true only in production environment', () => {
      const { isProd } = require('../../config/index');
      process.env.NODE_ENV = 'production';
      expect(isProd()).toBe(true);
      
      process.env.NODE_ENV = 'development';
      expect(isProd()).toBe(false);
      
      process.env.NODE_ENV = 'test';
      expect(isProd()).toBe(false);
    });
    
    test('isDev should return true only in development environment', () => {
      const { isDev } = require('../../config/index');
      process.env.NODE_ENV = 'development';
      expect(isDev()).toBe(true);
      
      process.env.NODE_ENV = 'production';
      expect(isDev()).toBe(false);
      
      process.env.NODE_ENV = 'test';
      expect(isDev()).toBe(false);
    });
    
    test('isTest should return true only in test environment', () => {
      const { isTest } = require('../../config/index');
      process.env.NODE_ENV = 'test';
      expect(isTest()).toBe(true);
      
      process.env.NODE_ENV = 'production';
      expect(isTest()).toBe(false);
      
      process.env.NODE_ENV = 'development';
      expect(isTest()).toBe(false);
    });
  });
});