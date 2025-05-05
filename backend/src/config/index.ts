// backend/src/config/index.ts
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config();

export const config = {
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Database
  databaseUrl: process.env.DATABASE_URL,
  
  // JWT
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
  
  // File storage - keeping these for backward compatibility
  uploadsDir: path.join(__dirname, '../../../uploads'),
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10), // 5MB
  
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
};

// Helper functions to check environment
export const isProd = (): boolean => config.nodeEnv === 'production';
export const isDev = (): boolean => config.nodeEnv === 'development';
export const isTest = (): boolean => config.nodeEnv === 'test';