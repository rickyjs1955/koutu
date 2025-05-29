// backend/src/config/index.ts
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config();

export const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Database
  databaseUrl: process.env.NODE_ENV === 'test' 
    ? process.env.TEST_DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu_test'
    : process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/koutu',
  dbPoolMax: parseInt(process.env.DB_POOL_MAX || (process.env.NODE_ENV === 'test' ? '5' : '10'), 10),
  dbConnectionTimeout: parseInt(process.env.DB_CONNECTION_TIMEOUT || '0', 10),
  dbIdleTimeout: parseInt(process.env.DB_IDLE_TIMEOUT || '10000', 10),
  dbStatementTimeout: parseInt(process.env.DB_STATEMENT_TIMEOUT || '0', 10),
  dbRequireSsl: process.env.DB_REQUIRE_SSL === 'true' || false,
  
  // JWT - validate that JWT_SECRET is provided
  jwtSecret: (() => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
      throw new Error('JWT_SECRET environment variable is required');
    }
    return secret;
  })(),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
  
  // File storage - keeping these for backward compatibility
  uploadsDir: path.join(__dirname, '../../../uploads'),
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '8388608', 10), // 8MB (8 * 1024 * 1024)
  
  // Firebase configuration
  firebase: {
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKey: process.env.FIREBASE_PRIVATE_KEY || '',
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL || '',
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || '',
  },
  
  // Application settings
  logLevel: process.env.LOG_LEVEL || 'info',
  
  // Storage mode - 'local' or 'firebase'
  storageMode: process.env.STORAGE_MODE || 'firebase',

  // App URL for OAuth redirects
  appUrl: process.env.APP_URL || 'http://localhost:3000',
  
  // OAuth
  oauth: {
    googleClientId: process.env.GOOGLE_CLIENT_ID,
    googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
    microsoftClientId: process.env.MICROSOFT_CLIENT_ID,
    microsoftClientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    githubClientId: process.env.GITHUB_CLIENT_ID,
    githubClientSecret: process.env.GITHUB_CLIENT_SECRET,
    instagramClientId: process.env.INSTAGRAM_CLIENT_ID,
    instagramClientSecret: process.env.INSTAGRAM_CLIENT_SECRET,
  },
};

// Helper functions to check environment
export const isProd = () => process.env.NODE_ENV === 'production';
export const isDev = () => process.env.NODE_ENV === 'development';
export const isTest = () => process.env.NODE_ENV === 'test';