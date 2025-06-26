// /backend/src/app.ts - Enhanced with security middleware integration
import express from 'express';
import { config } from './config';
import { errorHandler } from './middlewares/errorHandler';
import { securityMiddleware } from './middlewares/security';

// Route imports
import { authRoutes } from './routes/authRoutes';
import { imageRoutes } from './routes/imageRoutes';
import { garmentRoutes } from './routes/garmentRoutes';
import { wardrobeRoutes } from './routes/wardrobeRoutes';
import exportRoutes from './routes/exportRoutes';
import { fileRoutes } from './routes/fileRoutes';
import { polygonRoutes } from './routes/polygonRoutes';
import { oauthRoutes } from './routes/oauthRoutes';

// Initialize express app
const app = express();

// ==================== SECURITY MIDDLEWARE (APPLIED FIRST) ====================
// Apply general security middleware to all routes
securityMiddleware.general.forEach(middleware => {
  app.use(middleware as express.RequestHandler);
});

// ==================== BODY PARSING WITH SIZE LIMITS ====================
// JSON parsing with size limits
app.use(express.json({
  limit: '1mb',  // 1MB for JSON requests
  verify: (req, res, buf) => {
    // Additional validation can be added here
    if (buf.length === 0) {
      throw new Error('Empty request body');
    }
  }
}));

// URL-encoded parsing with size limits
app.use(express.urlencoded({
  extended: true,
  limit: '1mb',  // 1MB for form data
  parameterLimit: 100  // Limit number of parameters
}));

// ==================== ROUTES WITH SPECIFIC SECURITY ====================

// Authentication routes (enhanced security) - FIXED PATH
app.use('/api/auth', authRoutes);

// OAuth routes (already have enhanced security built-in) - FIXED PATH  
app.use('/api/oauth', oauthRoutes);

// API routes with standard security - FIXED PATHS
app.use('/api/images', imageRoutes);
app.use('/api/garments', garmentRoutes);
app.use('/api/wardrobes', wardrobeRoutes);
app.use('/api/export', exportRoutes);
app.use('/api/polygons', polygonRoutes);

// Apply file-specific security to file routes - FIXED PATH
// IMPORTANT: Mount fileRoutes with its specific path traversal middleware
app.use('/api/files', securityMiddleware.pathTraversal, fileRoutes);

// ==================== HEALTH CHECK ====================
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    storage: config.storageMode,
    security: {
      cors: 'enabled',
      helmet: 'enabled',
      rateLimit: 'enabled',
      requestLimits: 'enabled'
    },
    timestamp: new Date().toISOString()
  });
});

// ==================== ERROR HANDLING (APPLIED LAST) ====================
app.use(errorHandler);

// Export the app instance directly for testing
export { app };

// ==================== SERVER STARTUP (CONDITIONAL) ====================
// Only start the server if this file is executed directly (not imported as a module)
if (require.main === module) {
  const PORT = config.port;
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Storage mode: ${config.storageMode}`);
    console.log(`🔒 Security: Enhanced middleware enabled`);
    console.log(`🌍 Environment: ${config.nodeEnv}`);
  });
}