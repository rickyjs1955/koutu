import { config, isProd, isDev, isTest } from '../../src/config/index';

describe('Configuration Module - Extended Tests', () => {
  describe('Firebase Configuration', () => {
    test('should have firebase properties defined', () => {
      expect(config.firebase).toBeDefined();
      expect(config.firebase).toHaveProperty('projectId');
      expect(config.firebase).toHaveProperty('privateKey');
      expect(config.firebase).toHaveProperty('clientEmail');
      expect(config.firebase).toHaveProperty('storageBucket');
    });

    test('firebase properties should be strings or undefined', () => {
      // Assuming projectId is mandatory and others can be empty strings if not set
      if (process.env.FIREBASE_PROJECT_ID) {
        expect(typeof config.firebase.projectId).toBe('string');
      } else {
        expect(config.firebase.projectId).toBeUndefined();
      }
      expect(typeof config.firebase.privateKey).toBe('string');
      expect(typeof config.firebase.clientEmail).toBe('string');
      expect(typeof config.firebase.storageBucket).toBe('string');
    });
  });

  describe('Application Settings', () => {
    test('should have logLevel defined', () => {
      expect(config.logLevel).toBeDefined();
      expect(typeof config.logLevel).toBe('string');
    });

    test('should have storageMode defined and be either local or firebase', () => {
      expect(config.storageMode).toBeDefined();
      expect(['local', 'firebase']).toContain(config.storageMode);
    });

    test('should have appUrl defined', () => {
      expect(config.appUrl).toBeDefined();
      expect(typeof config.appUrl).toBe('string');
    });
  });

  describe('OAuth Configuration', () => {
    test('should have oauth properties defined', () => {
      expect(config.oauth).toBeDefined();
      expect(config.oauth).toHaveProperty('googleClientId');
      expect(config.oauth).toHaveProperty('googleClientSecret');
      // Add checks for other OAuth providers if necessary
      expect(config.oauth).toHaveProperty('githubClientId');
      expect(config.oauth).toHaveProperty('githubClientSecret');
    });
  });

  describe('Environment Helper Functions', () => {
    let originalNodeEnv;

    beforeEach(() => {
      originalNodeEnv = process.env.NODE_ENV;
    });

    afterEach(() => {
      process.env.NODE_ENV = originalNodeEnv;
    });

    test('isProd should return true when NODE_ENV is production', () => {
      process.env.NODE_ENV = 'production';
      expect(isProd()).toBe(true);
      expect(isDev()).toBe(false);
      expect(isTest()).toBe(false);
    });

    test('isDev should return true when NODE_ENV is development', () => {
      process.env.NODE_ENV = 'development';
      expect(isDev()).toBe(true);
      expect(isProd()).toBe(false);
      expect(isTest()).toBe(false);
    });

    test('isTest should return true when NODE_ENV is test', () => {
        process.env.NODE_ENV = 'test';
        expect(isTest()).toBe(true);
        expect(isProd()).toBe(false);
        expect(isDev()).toBe(false);
    });

    test('config.nodeEnv should default to development and helpers reflect current env when NODE_ENV is not set', async () => {
        delete process.env.NODE_ENV;
        // Re-import to pick up the change in process.env for default values
        // This dynamic import with a cache-busting query param forces a re-evaluation of the module.
        const { isDev: isDevLocal, config: localConfig, isProd: isProdLocal, isTest: isTestLocal } = await import('../../../src/config/index.js?bustcache=' + Date.now());
        
        expect(localConfig.nodeEnv).toBe('development'); // Checks the default value in the re-imported config object
        
        // The helper functions (isDevLocal, isProdLocal, isTestLocal) from the re-imported module
        // will read the current state of process.env.NODE_ENV, which is undefined.
        expect(isDevLocal()).toBe(false); // undefined === 'development' is false
        expect(isProdLocal()).toBe(false); // undefined === 'production' is false
        expect(isTestLocal()).toBe(false); // undefined === 'test' is false
      });
    });
  });
});