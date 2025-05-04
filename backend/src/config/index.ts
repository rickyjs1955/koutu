// src/config/index.ts
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables from .env file
dotenv.config();

export const config = {
  // Server configuration
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Database
  databaseUrl: process.env.DATABASE_URL,
  
  // JWT
  jwtSecret: process.env.JWT_SECRET || 'dev_secret_change_this_in_production',
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1d',
  
  // File storage
  uploadsDir: path.join(__dirname, '../../uploads'),
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10), // 5MB
  
  // Application settings
  logLevel: process.env.LOG_LEVEL || 'info',
  
  // Data export
  exportsDir: path.join(__dirname, '../../exports'),
  
  // CORS settings
  corsOrigin: process.env.CORS_ORIGIN || '*',
  
  // Rate limiting
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per windowMs
  }
};
