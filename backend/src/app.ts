// src/app.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config as appConfig } from './config';
import { errorHandler } from './middlewares/errorHandler';
import { authRoutes } from './routes/authRoutes';
import { imageRoutes } from './routes/imageRoutes';
import { garmentRoutes } from './routes/garmentRoutes';
import { wardrobeRoutes } from './routes/wardrobeRoutes';
import { exportRoutes } from './routes/exportRoutes';

// Initialize express app
const app = express();

// Middlewares
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/images', imageRoutes);
app.use('/api/v1/garments', garmentRoutes);
app.use('/api/v1/wardrobes', wardrobeRoutes);
app.use('/api/v1/export', exportRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Error handling middleware (should be registered last)
app.use(errorHandler);

// Start the server
const PORT = appConfig.port;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export { app };

// src/config/index.ts
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
  
  // File storage
  uploadsDir: path.join(__dirname, '../../uploads'),
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '5242880', 10), // 5MB
  
  // Application settings
  logLevel: process.env.LOG_LEVEL || 'info'
};