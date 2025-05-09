// backend/src/tests/unit/index.unit.test.ts
import path from 'path';
import { config, isProd, isDev, isTest } from '../../config/index';

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
  // Store original environment
  const originalEnv = process.env;
  
  beforeEach(() => {
    // Reset the environment before each test
    jest.resetModules();
    process.env = { ...originalEnv };
  });
  
  afterAll(() => {
    // Restore original environment after all tests
    process.env = originalEnv;
  });

  describe('Configuration Object', () => {
    test('should have the correct structure with all required sections', () => {
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
        expect(config.port).toBe("3000");
        expect(config.nodeEnv).toBe('development');
        expect(config.jwtExpiresIn).toBe('1d');
        expect(config.maxFileSize).toBe(5242880); // 5MB
        expect(config.logLevel).toBe('info');
        expect(config.storageMode).toBe('firebase');
        expect(config.appUrl).toBe('http://localhost:3000');
        });

    test('should correctly construct the uploads directory path', () => {
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
  });

  describe('Environment Helper Functions', () => {
    test('isProd should return true only in production environment', () => {
      process.env.NODE_ENV = 'production';
      expect(isProd()).toBe(true);
      
      process.env.NODE_ENV = 'development';
      expect(isProd()).toBe(false);
      
      process.env.NODE_ENV = 'test';
      expect(isProd()).toBe(false);
    });
    
    test('isDev should return true only in development environment', () => {
      process.env.NODE_ENV = 'development';
      expect(isDev()).toBe(true);
      
      process.env.NODE_ENV = 'production';
      expect(isDev()).toBe(false);
      
      process.env.NODE_ENV = 'test';
      expect(isDev()).toBe(false);
    });
    
    test('isTest should return true only in test environment', () => {
      process.env.NODE_ENV = 'test';
      expect(isTest()).toBe(true);
      
      process.env.NODE_ENV = 'production';
      expect(isTest()).toBe(false);
      
      process.env.NODE_ENV = 'development';
      expect(isTest()).toBe(false);
    });
  });
});