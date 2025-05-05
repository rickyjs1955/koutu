// backend/src/app.ts
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config } from './config';
import { errorHandler } from './middlewares/errorHandler';
import { authRoutes } from './routes/authRoutes';
import { imageRoutes } from './routes/imageRoutes';
import { garmentRoutes } from './routes/garmentRoutes';
import { wardrobeRoutes } from './routes/wardrobeRoutes';
import { exportRoutes } from './routes/exportRoutes';
import { fileRoutes } from './routes/fileRoutes';

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
app.use('/api/v1/files', fileRoutes); // Add new file routes

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'ok', 
    storage: config.storageMode 
  });
});

// Error handling middleware (should be registered last)
app.use(errorHandler);

// Start the server
const PORT = config.port;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Storage mode: ${config.storageMode}`);
});

export { app };