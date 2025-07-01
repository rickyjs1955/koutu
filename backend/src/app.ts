// /backend/src/app.ts - Enhanced for Flutter mobile app integration
import express from 'express';
import cors from 'cors';
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

// ==================== FLUTTER-SPECIFIC CORS CONFIGURATION ====================
// Flutter apps make requests without traditional web origins
const corsConfig = process.env.NODE_ENV === 'test' 
  ? {
      origin: '*', // Allow all origins in test
      credentials: false,
      methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
      exposedHeaders: ['Content-Length', 'X-RateLimit-Limit', 'X-RateLimit-Remaining'],
      preflightContinue: true, // Don't end the request, pass to next handler
      optionsSuccessStatus: 204,
      maxAge: 3600
    }
  : {
      // Flutter apps often don't send Origin headers or send null
      origin: function(origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void): void {
        // Allow requests with no origin (like mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        // Allow localhost for development
        if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
          return callback(null, true);
        }
        
        // Allow your Flutter app's domains in production
        const allowedOrigins: string[] = [
          'http://localhost:5173', // Web development server (if still needed)
          'https://your-flutter-app.com', // Production Flutter web
          // Flutter mobile apps typically don't send origin headers
        ];
        
        if (allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          // For Flutter mobile apps, allow null/undefined origins
          callback(null, true);
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'] as Array<'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'PATCH'>,
      allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'Accept', 
        'Origin', 
        'X-Requested-With',
        'Cache-Control',
        'Pragma'
      ] as string[],
      exposedHeaders: [
        'Content-Length', 
        'X-RateLimit-Limit', 
        'X-RateLimit-Remaining',
        'X-Total-Count' // Useful for pagination in Flutter apps
      ] as string[],
      preflightContinue: true, // Don't end the request, pass to next handler
      optionsSuccessStatus: 204,
      maxAge: 3600
    };

app.use(cors(corsConfig));

// ==================== FLUTTER-FRIENDLY REQUEST LOGGING ====================
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const userAgent = req.headers['user-agent'] || 'Unknown';
  // Enhanced Flutter detection to handle more user agent patterns
  const isFlutterApp = userAgent.includes('Dart/') || 
                       userAgent.includes('Flutter/') || 
                       userAgent.includes('dart:io') ||
                       userAgent.toLowerCase().includes('flutter');
  
  console.log(`📱 [${timestamp}] ${req.method} ${req.path} ${isFlutterApp ? '(Flutter)' : '(Web)'}`);
  
  // Log headers for debugging Flutter requests
  if (req.headers.authorization) {
    console.log(`🔑 Auth header present: ${req.headers.authorization.substring(0, 20)}...`);
  }
  
  // Flutter apps often send different content types
  if (req.headers['content-type']) {
    console.log(`📦 Content-Type: ${req.headers['content-type']}`);
  }
  
  // Log body for non-GET requests (but be careful with file uploads)
  if (req.method !== 'GET' && req.body && Object.keys(req.body).length > 0) {
    const bodyPreview = JSON.stringify(req.body, null, 2);
    if (bodyPreview.length < 1000) { // Only log small bodies
      console.log(`📦 Body:`, bodyPreview);
    } else {
      console.log(`📦 Body: Large payload (${bodyPreview.length} chars)`);
    }
  }
  
  next();
});

// ==================== FLUTTER API TEST ENDPOINT ====================
// PLACED EARLY to ensure it's not intercepted by route mocks
app.get('/api/test', (req, res) => {
  console.log('🧪 API test endpoint hit');
  
  const userAgent = req.headers['user-agent'] || 'Unknown';
  // Enhanced Flutter detection to handle more user agent patterns
  const isFlutterApp = userAgent.includes('Dart/') || 
                       userAgent.includes('Flutter/') || 
                       userAgent.includes('dart:io') ||
                       userAgent.toLowerCase().includes('flutter');
  
  console.log(`🔍 User-Agent: "${userAgent}" -> isFlutterApp: ${isFlutterApp}`);
  
  res.json({
    message: 'API is working for Flutter!',
    timestamp: new Date().toISOString(),
    clientInfo: {
      userAgent: userAgent,
      isFlutterApp: isFlutterApp,
      origin: req.headers.origin || 'no-origin',
      acceptLanguage: req.headers['accept-language'] || 'not-specified'
    },
    endpoints: {
      auth: '/api/auth',
      images: '/api/images', 
      garments: '/api/garments',
      wardrobes: '/api/wardrobes',
      files: '/api/files'
    }
  });
});

// ==================== PREFLIGHT OPTIONS HANDLING FOR FLUTTER CORS ====================
// Handle OPTIONS requests after CORS middleware
app.use((req: express.Request, res: express.Response, next: express.NextFunction): void => {
  if (req.method === 'OPTIONS') {
    console.log(`✈️ CORS preflight: ${req.method} ${req.originalUrl}`);
    // Set additional headers that might not be set by CORS
    res.set('Access-Control-Max-Age', '3600');
    res.status(204).end();
    return;
  }
  next();
});

// ==================== FLUTTER-COMPATIBLE SECURITY MIDDLEWARE ====================
// Apply general security middleware to all routes
securityMiddleware.general.forEach(middleware => {
  app.use(middleware as express.RequestHandler);
});

// ==================== FLUTTER-OPTIMIZED BODY PARSING ====================
// JSON parsing with size limits (Flutter apps typically send JSON)
app.use(express.json({
  limit: '2mb',  // Slightly larger for Flutter apps which might send more data
  verify: (req, res, buf) => {
    if (buf.length === 0) {
      throw new Error('Empty request body');
    }
  }
}));

// URL-encoded parsing (less common in Flutter but still supported)
app.use(express.urlencoded({
  extended: true,
  limit: '2mb',
  parameterLimit: 200  // Higher limit for Flutter form data
}));

// Raw body parsing for file uploads (Flutter uses multipart/form-data)
app.use('/api/images', express.raw({
  type: ['image/*', 'application/octet-stream', 'multipart/form-data'],
  limit: '10mb'
}));

app.use('/api/files', express.raw({
  type: ['*/*'],
  limit: '10mb'
}));

// ==================== FLUTTER-FRIENDLY HEALTH CHECK ====================
app.get('/health', (req, res) => {
  console.log('🏥 Health check requested');
  
  const userAgent = req.headers['user-agent'] || 'Unknown';
  // Enhanced Flutter detection to handle more user agent patterns
  const isFlutterApp = userAgent.includes('Dart/') || 
                       userAgent.includes('Flutter/') || 
                       userAgent.includes('dart:io') ||
                       userAgent.toLowerCase().includes('flutter');
  
  const healthData: any = {
    status: 'ok',
    storage: config.storageMode,
    platform: isFlutterApp ? 'flutter' : 'web',
    security: {
      cors: 'enabled',
      helmet: 'enabled',
      rateLimit: 'enabled',
      requestLimits: 'enabled',
      flutterOptimized: true
    },
    timestamp: new Date().toISOString(),
    server: {
      nodeEnv: config.nodeEnv,
      version: process.version
    }
  };

  // Add API endpoints info for Flutter developers
  if (process.env.NODE_ENV !== 'test') {
    healthData.endpoints = {
      auth: {
        login: 'POST /api/auth/login',
        register: 'POST /api/auth/register',
        profile: 'GET /api/auth/me'
      },
      wardrobes: {
        list: 'GET /api/wardrobes',
        create: 'POST /api/wardrobes',
        get: 'GET /api/wardrobes/:id',
        update: 'PUT /api/wardrobes/:id',
        delete: 'DELETE /api/wardrobes/:id'
      },
      images: {
        upload: 'POST /api/images',
        list: 'GET /api/images',
        get: 'GET /api/images/:id',
        delete: 'DELETE /api/images/:id'
      },
      garments: {
        list: 'GET /api/garments',
        create: 'POST /api/garments',
        get: 'GET /api/garments/:id',
        update: 'PUT /api/garments/:id',
        delete: 'DELETE /api/garments/:id'
      }
    };
    
    healthData.uploadLimits = {
      maxFileSize: '10MB',
      maxFileSizeBytes: 10 * 1024 * 1024,
      allowedImageTypes: ['image/jpeg', 'image/png', 'image/webp'],
      maxJsonSize: '2MB'
    };
  }

  res.status(200).json(healthData);
});

// ==================== FLUTTER FILE UPLOAD TEST ENDPOINTS ====================
// Test endpoint specifically designed for Flutter file uploads
app.post('/api/test/upload', (req: any, res: any) => {
  console.log('🧪 Flutter test upload endpoint hit');
  
  const contentLength = parseInt(req.get('Content-Length') || '0');
  const contentType = req.get('Content-Type') || 'unknown';
  const maxSize = 10 * 1024 * 1024; // 10MB limit
  
  console.log(`📏 Flutter test upload: ${Math.round(contentLength / 1024)}KB, type: ${contentType}`);
  
  if (contentLength > maxSize) {
    console.log(`❌ Flutter test upload rejected: ${Math.round(contentLength / 1024)}KB > ${Math.round(maxSize / 1024)}KB`);
    return res.status(413).json({
      error: 'FILE_TOO_LARGE',
      message: 'File size exceeds the maximum allowed size',
      maxSizeMB: Math.round(maxSize / (1024 * 1024)),
      receivedSizeKB: Math.round(contentLength / 1024),
      contentType: contentType
    });
  }
  
  console.log(`✅ Flutter test upload accepted: ${Math.round(contentLength / 1024)}KB`);
  res.status(200).json({
    success: true,
    message: 'File upload would succeed',
    sizeKB: Math.round(contentLength / 1024),
    contentType: contentType,
    timestamp: new Date().toISOString()
  });
});

// Generic upload endpoint for Flutter multipart uploads
app.post('/api/upload', (req: any, res: any) => {
  console.log('🧪 Flutter generic upload endpoint hit');
  
  const contentLength = parseInt(req.get('Content-Length') || '0');
  const maxSize = 10 * 1024 * 1024; // 10MB limit
  
  if (contentLength > maxSize) {
    return res.status(413).json({
      error: 'PAYLOAD_TOO_LARGE',
      message: 'File size exceeds the maximum allowed size of 10MB',
      details: {
        maxSizeBytes: maxSize,
        receivedSizeBytes: contentLength,
        maxSizeMB: Math.round(maxSize / (1024 * 1024))
      }
    });
  }
  
  res.status(200).json({
    success: true,
    message: 'Upload successful',
    sizeBytes: contentLength,
    timestamp: new Date().toISOString()
  });
});

// Enhanced file size limit middleware for Flutter file uploads
// MOVED AFTER TEST ENDPOINTS so they can handle their own logic
app.use((req: any, res: any, next: any) => {
  // Skip our test endpoints - they handle their own file size logic
  if (req.path === '/api/test/upload' || req.path === '/api/upload') {
    return next();
  }
  
  // Check for Flutter file upload endpoints
  const isFileUpload = (req.method === 'POST' || req.method === 'PUT') && 
    (req.path.startsWith('/api/images') || 
     req.path.startsWith('/api/files') ||
     req.headers['content-type']?.includes('multipart/form-data'));
  
  if (isFileUpload) {
    const contentLength = parseInt(req.get('Content-Length') || '0');
    const maxSize = 10 * 1024 * 1024; // 10MB (good for mobile photo uploads)
    
    console.log(`📏 Flutter file upload check: ${Math.round(contentLength / 1024)}KB / ${Math.round(maxSize / 1024)}KB limit`);
    
    if (contentLength > maxSize) {
      console.log(`❌ Flutter upload rejected: ${Math.round(contentLength / 1024)}KB > ${Math.round(maxSize / 1024)}KB`);
      
      return res.status(413).json({
        error: 'PAYLOAD_TOO_LARGE',
        message: 'File size exceeds the maximum allowed size of 10MB',
        maxSizeBytes: maxSize,
        receivedSizeBytes: contentLength,
        maxSizeMB: Math.round(maxSize / (1024 * 1024))
      });
    }
  }
  
  next();
});

// ==================== FLUTTER-OPTIMIZED ROUTES MOUNTING ====================

console.log('🔧 Mounting Flutter-optimized routes...');

// Authentication routes (critical for Flutter apps)
app.use('/api/auth', (req, res, next) => {
  console.log(`🔐 Flutter auth route: ${req.method} ${req.originalUrl}`);
  next();
}, authRoutes);

// OAuth routes (for social login in Flutter)
app.use('/api/oauth', (req, res, next) => {
  console.log(`🔑 Flutter OAuth route: ${req.method} ${req.originalUrl}`);
  next();
}, oauthRoutes);

// Core API routes for Flutter app functionality
app.use('/api/images', (req, res, next) => {
  console.log(`📸 Flutter image route: ${req.method} ${req.originalUrl}`);
  next();
}, imageRoutes);

app.use('/api/garments', (req, res, next) => {
  console.log(`👕 Flutter garment route: ${req.method} ${req.originalUrl}`);
  next();
}, garmentRoutes);

app.use('/api/wardrobes', (req, res, next) => {
  console.log(`👗 Flutter wardrobe route: ${req.method} ${req.originalUrl}`);
  next();
}, wardrobeRoutes);

app.use('/api/export', (req, res, next) => {
  console.log(`📤 Flutter export route: ${req.method} ${req.originalUrl}`);
  next();
}, exportRoutes);

app.use('/api/polygons', (req, res, next) => {
  console.log(`🔺 Flutter polygon route: ${req.method} ${req.originalUrl}`);
  next();
}, polygonRoutes);

// File routes with enhanced security for Flutter uploads
app.use('/api/files', (req, res, next) => {
  console.log(`📁 Flutter file route: ${req.method} ${req.originalUrl}`);
  next();
}, securityMiddleware.pathTraversal, fileRoutes);

console.log('✅ All Flutter-optimized routes mounted successfully');

// ==================== FLUTTER-FRIENDLY 404 HANDLER ====================
app.use((req, res) => {
  console.log(`❌ 404 (Flutter): ${req.method} ${req.originalUrl}`);
  
  const userAgent = req.headers['user-agent'] || 'Unknown';
  // Enhanced Flutter detection to handle more user agent patterns
  const isFlutterApp = userAgent.includes('Dart/') || 
                       userAgent.includes('Flutter/') || 
                       userAgent.includes('dart:io') ||
                       userAgent.toLowerCase().includes('flutter');
  
  res.status(404).json({ 
    error: 'ROUTE_NOT_FOUND',
    message: 'The requested endpoint does not exist',
    path: req.originalUrl,
    method: req.method,
    platform: isFlutterApp ? 'flutter' : 'web',
    availableEndpoints: {
      health: 'GET /health',
      apiTest: 'GET /api/test',
      auth: {
        login: 'POST /api/auth/login',
        register: 'POST /api/auth/register',
        profile: 'GET /api/auth/me'
      },
      images: 'GET|POST|PUT|DELETE /api/images/*',
      garments: 'GET|POST|PUT|DELETE /api/garments/*',
      wardrobes: 'GET|POST|PUT|DELETE /api/wardrobes/*',
      files: 'GET|POST|DELETE /api/files/*',
      oauth: 'GET|POST /api/oauth/*',
      polygons: 'GET|POST|PUT|DELETE /api/polygons/*',
      export: 'GET|POST /api/export/*'
    },
    documentation: 'https://your-api-docs.com' // Add your API documentation URL
  });
});

// ==================== FLUTTER-AWARE ERROR HANDLING ====================
app.use(((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  const userAgent = req.headers['user-agent'] || 'Unknown';
  // Enhanced Flutter detection to handle more user agent patterns
  const isFlutterApp = userAgent.includes('Dart/') || 
                       userAgent.includes('Flutter/') || 
                       userAgent.includes('dart:io') ||
                       userAgent.toLowerCase().includes('flutter');
  
  console.error(`💥 Error on ${req.method} ${req.path} (${isFlutterApp ? 'Flutter' : 'Web'}):`, err.message);
  
  if (config.nodeEnv !== 'production') {
    console.error('Stack:', err.stack);
  }
  
  // Enhanced error response for Flutter apps
  if (isFlutterApp) {
    // Flutter apps prefer structured error responses
    if (err.code === 'LIMIT_FILE_SIZE' || err.type === 'entity.too.large') {
      return res.status(413).json({
        error: 'PAYLOAD_TOO_LARGE',
        message: 'File or payload size exceeds maximum allowed limit',
        details: {
          maxSize: '10MB for files, 2MB for JSON',
          receivedSize: req.get('Content-Length') || 'unknown'
        }
      });
    }
    
    if (err instanceof SyntaxError && 'body' in err) {
      return res.status(400).json({
        error: 'INVALID_JSON',
        message: 'Request body contains invalid JSON',
        details: 'Please check your JSON formatting'
      });
    }
  }
  
  // Call the standard error handler
  errorHandler(err, req, res, next);
}) as express.ErrorRequestHandler);

// Export the app instance for testing and module imports
export { app };

// ==================== FLUTTER-OPTIMIZED SERVER STARTUP ====================
if (require.main === module) {
  const PORT = Number(config.port);
  app.listen(PORT, '0.0.0.0', () => { // Listen on all interfaces for Flutter connectivity
    console.log(`🚀 Flutter-optimized server running on port ${PORT}`);
    console.log(`📱 Optimized for Flutter mobile and web applications`);
    console.log(`📁 Storage mode: ${config.storageMode}`);
    console.log(`🔒 Security: Flutter-compatible CORS and headers enabled`);
    console.log(`🌍 Environment: ${config.nodeEnv}`);
    console.log(`🌐 Network: Listening on 0.0.0.0:${PORT} (accessible from Flutter apps)`);
    console.log(`📍 API Base URL: http://localhost:${PORT}/api`);
    console.log(`🏥 Health Check: http://localhost:${PORT}/health`);
    console.log(`🧪 Test Endpoint: http://localhost:${PORT}/api/test`);
    console.log(`\n📱 Flutter Integration Features:`);
    console.log(`   ✅ No-origin CORS requests supported`);
    console.log(`   ✅ Multipart file upload handling`);
    console.log(`   ✅ User-Agent detection for Flutter apps`);
    console.log(`   ✅ Enhanced error responses for mobile`);
    console.log(`   ✅ Preflight CORS caching enabled`);
    console.log(`\n📋 Available API Endpoints:`);
    console.log(`   🔐 Auth: http://localhost:${PORT}/api/auth/*`);
    console.log(`   📸 Images: http://localhost:${PORT}/api/images/*`);
    console.log(`   👕 Garments: http://localhost:${PORT}/api/garments/*`);
    console.log(`   👗 Wardrobes: http://localhost:${PORT}/api/wardrobes/*`);
    console.log(`   📁 Files: http://localhost:${PORT}/api/files/*`);
    console.log(`   🔑 OAuth: http://localhost:${PORT}/api/oauth/*`);
    console.log(`   🔺 Polygons: http://localhost:${PORT}/api/polygons/*`);
    console.log(`   📤 Export: http://localhost:${PORT}/api/export/*`);
    console.log(`\n🔧 Flutter Development Tips:`);
    console.log(`   • Use http://10.0.2.2:${PORT} for Android emulator`);
    console.log(`   • Use http://localhost:${PORT} for iOS simulator`);
    console.log(`   • Use your machine's IP for physical devices`);
  });
}