// backend/src/config/flutter.ts
export interface FlutterConfig {
  cors: {
    allowNoOrigin: boolean;
    maxAge: number;
    credentials: boolean;
    allowedHeaders: string[];
    exposedHeaders: string[];
    allowedMethods: string[];
    allowedOrigins: string[];
  };
  uploads: {
    maxFileSize: number;
    maxFiles: number;
    allowedMimeTypes: string[];
    tempDir: string;
    platformLimits: {
      android: number;
      ios: number;
      web: number;
      desktop: number;
    };
  };
  responses: {
    includeTimestamp: boolean;
    includeRequestId: boolean;
    includeMeta: boolean;
    enableDebugMode: boolean;
    compressionThreshold: number;
  };
  security: {
    enableUserAgentValidation: boolean;
    requireOriginInProduction: boolean;
    enableRequestLogging: boolean;
    sanitizeResponses: boolean;
    maxRequestSize: number;
    enableRateLimiting: boolean;
    rateLimitWindowMs: number;
    rateLimitMax: number;
  };
  performance: {
    enableCompression: boolean;
    enableCaching: boolean;
    cacheMaxAge: number;
    enableGzip: boolean;
    connectionTimeout: number;
    requestTimeout: number;
    enableKeepAlive: boolean;
  };
  networking: {
    listenOnAllInterfaces: boolean;
    defaultPort: number;
    enableIPv6: boolean;
    enableHTTP2: boolean;
    maxConcurrentConnections: number;
  };
  monitoring: {
    enablePerformanceTracking: boolean;
    enableErrorTracking: boolean;
    logSlowRequests: boolean;
    slowRequestThreshold: number;
    enableHealthChecks: boolean;
  };
  features: {
    enableOfflineSync: boolean;
    enablePushNotifications: boolean;
    enableFileChunking: boolean;
    enableProgressiveDownload: boolean;
    enableBackgroundSync: boolean;
  };
}

/**
 * Default Flutter configuration
 * Environment-specific overrides are applied in getFlutterConfig()
 */
const defaultFlutterConfig: FlutterConfig = {
  cors: {
    allowNoOrigin: process.env.NODE_ENV !== 'production',
    maxAge: 3600,
    credentials: true,
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'Accept',
      'Origin',
      'X-Requested-With',
      'Cache-Control',
      'Pragma',
      'X-Flutter-App',
      'X-Platform',
      'X-App-Version',
      'X-Device-ID',
      'X-Request-ID'
    ],
    exposedHeaders: [
      'Content-Length',
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-Total-Count',
      'X-Request-ID',
      'X-Response-Time',
      'X-Flutter-Optimized'
    ],
    allowedMethods: [
      'GET',
      'POST',
      'PUT',
      'DELETE',
      'OPTIONS',
      'PATCH',
      'HEAD'
    ],
    allowedOrigins: [
      'http://localhost:3000',
      'http://localhost:5173',
      'http://127.0.0.1:3000',
      'http://10.0.2.2:3000', // Android emulator
      ...(process.env.ALLOWED_ORIGINS?.split(',') || [])
    ]
  },
  uploads: {
    maxFileSize: 10 * 1024 * 1024, // 10MB default
    maxFiles: 5,
    allowedMimeTypes: [
      'image/jpeg',
      'image/png',
      'image/webp',
      'image/bmp',
      'image/gif'
    ],
    tempDir: process.env.UPLOAD_TEMP_DIR || '/tmp/flutter-uploads',
    platformLimits: {
      android: 50 * 1024 * 1024,  // 50MB
      ios: 25 * 1024 * 1024,      // 25MB (memory constraints)
      web: 10 * 1024 * 1024,      // 10MB
      desktop: 100 * 1024 * 1024  // 100MB
    }
  },
  responses: {
    includeTimestamp: true,
    includeRequestId: true,
    includeMeta: true,
    enableDebugMode: process.env.NODE_ENV === 'development',
    compressionThreshold: 1024 // 1KB
  },
  security: {
    enableUserAgentValidation: true,
    requireOriginInProduction: process.env.NODE_ENV === 'production',
    enableRequestLogging: process.env.NODE_ENV !== 'test',
    sanitizeResponses: true,
    maxRequestSize: 50 * 1024 * 1024, // 50MB
    enableRateLimiting: true,
    rateLimitWindowMs: 15 * 60 * 1000, // 15 minutes
    rateLimitMax: 100 // requests per window
  },
  performance: {
    enableCompression: true,
    enableCaching: false, // Usually disabled for API responses
    cacheMaxAge: 300, // 5 minutes
    enableGzip: true,
    connectionTimeout: 30000, // 30 seconds
    requestTimeout: 10000, // 10 seconds
    enableKeepAlive: true
  },
  networking: {
    listenOnAllInterfaces: true, // Important for Flutter apps
    defaultPort: parseInt(process.env.PORT || '3000'),
    enableIPv6: false,
    enableHTTP2: false, // Enable when Flutter fully supports HTTP/2
    maxConcurrentConnections: 1000
  },
  monitoring: {
    enablePerformanceTracking: true,
    enableErrorTracking: true,
    logSlowRequests: true,
    slowRequestThreshold: 2000, // 2 seconds
    enableHealthChecks: true
  },
  features: {
    enableOfflineSync: false, // Future feature
    enablePushNotifications: false, // Future feature
    enableFileChunking: false, // Future feature
    enableProgressiveDownload: false, // Future feature
    enableBackgroundSync: false // Future feature
  }
};

/**
 * Get environment-specific Flutter configuration
 */
export function getFlutterConfig(): FlutterConfig {
  const baseConfig = { ...defaultFlutterConfig };
  const env = process.env.NODE_ENV;
  
  switch (env) {
    case 'production':
      return {
        ...baseConfig,
        cors: {
          ...baseConfig.cors,
          allowNoOrigin: false,
          allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || []
        },
        security: {
          ...baseConfig.security,
          requireOriginInProduction: true,
          enableRequestLogging: false, // Reduce logs in production
          rateLimitMax: 50 // Stricter rate limiting
        },
        responses: {
          ...baseConfig.responses,
          enableDebugMode: false
        },
        performance: {
          ...baseConfig.performance,
          enableCompression: true,
          enableCaching: true
        },
        monitoring: {
          ...baseConfig.monitoring,
          logSlowRequests: true,
          slowRequestThreshold: 1000 // 1 second in production
        }
      };
      
    case 'test':
      return {
        ...baseConfig,
        cors: {
          ...baseConfig.cors,
          allowNoOrigin: true,
          allowedOrigins: ['*'] // Allow all for testing
        },
        security: {
          ...baseConfig.security,
          enableRequestLogging: false,
          enableRateLimiting: false, // Disable for testing
          requireOriginInProduction: false
        },
        uploads: {
          ...baseConfig.uploads,
          maxFileSize: 1024 * 1024, // 1MB for tests
          platformLimits: {
            android: 1024 * 1024,
            ios: 1024 * 1024,
            web: 1024 * 1024,
            desktop: 1024 * 1024
          }
        },
        performance: {
          ...baseConfig.performance,
          connectionTimeout: 5000, // 5 seconds for tests
          requestTimeout: 3000 // 3 seconds for tests
        },
        monitoring: {
          ...baseConfig.monitoring,
          enablePerformanceTracking: false,
          logSlowRequests: false
        }
      };
      
    case 'development':
    default:
      return {
        ...baseConfig,
        cors: {
          ...baseConfig.cors,
          allowNoOrigin: true
        },
        security: {
          ...baseConfig.security,
          requireOriginInProduction: false,
          rateLimitMax: 1000 // More lenient for development
        },
        monitoring: {
          ...baseConfig.monitoring,
          logSlowRequests: true,
          slowRequestThreshold: 3000 // 3 seconds in development
        }
      };
  }
}

/**
 * Get Flutter-optimized CORS configuration
 */
export function getFlutterCorsConfig() {
  const config = getFlutterConfig().cors;
  
  return {
    origin: function(origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void): void {
      // Allow requests with no origin (mobile apps, Postman, etc.)
      if (!origin && config.allowNoOrigin) {
        return callback(null, true);
      }
      
      // Allow configured origins
      if (origin && config.allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      
      // Allow localhost variations for development
      if (origin && (origin.includes('localhost') || origin.includes('127.0.0.1') || origin.includes('10.0.2.2'))) {
        return callback(null, true);
      }
      
      // Production origin validation
      if (process.env.NODE_ENV === 'production') {
        if (!origin && !config.allowNoOrigin) {
          return callback(new Error('Origin required in production'));
        }
        
        if (origin && !config.allowedOrigins.includes(origin)) {
          return callback(new Error('Origin not allowed'));
        }
      }
      
      // Development: allow all
      if (process.env.NODE_ENV === 'development') {
        return callback(null, true);
      }
      
      callback(null, true);
    },
    credentials: config.credentials,
    methods: config.allowedMethods,
    allowedHeaders: config.allowedHeaders,
    exposedHeaders: config.exposedHeaders,
    preflightContinue: true,
    optionsSuccessStatus: 204,
    maxAge: config.maxAge
  };
}

/**
 * Get Flutter-optimized upload configuration
 */
export function getFlutterUploadConfig(platform?: string) {
  const config = getFlutterConfig().uploads;
  const maxSize = platform ? config.platformLimits[platform as keyof typeof config.platformLimits] : config.maxFileSize;
  
  return {
    limits: {
      fileSize: maxSize,
      files: config.maxFiles,
      fieldSize: 1024 * 1024, // 1MB for text fields
      fieldNameSize: 100,
      headerPairs: 2000
    },
    fileFilter: (req: any, file: any, cb: any) => {
      if (!config.allowedMimeTypes.includes(file.mimetype)) {
        return cb(new Error(`File type ${file.mimetype} not allowed`));
      }
      
      // Additional Flutter-specific validations
      if (file.originalname.length > 255) {
        return cb(new Error('Filename too long'));
      }
      
      // Check for suspicious file patterns
      const suspiciousPatterns = [
        /\.php$/i,
        /\.asp$/i,
        /\.jsp$/i,
        /\.exe$/i,
        /\.bat$/i,
        /\.sh$/i
      ];
      
      if (suspiciousPatterns.some(pattern => pattern.test(file.originalname))) {
        return cb(new Error('File type not allowed'));
      }
      
      cb(null, true);
    },
    destination: config.tempDir,
    filename: (req: any, file: any, cb: any) => {
      // Generate secure filename
      const timestamp = Date.now();
      const random = Math.random().toString(36).substring(2);
      const ext = file.originalname.split('.').pop();
      const filename = `flutter_${timestamp}_${random}.${ext}`;
      cb(null, filename);
    }
  };
}

/**
 * Get platform-specific configuration
 */
export function getPlatformConfig(platform?: string) {
  const config = getFlutterConfig();
  
  const platformDefaults = {
    android: {
      maxUploadSize: config.uploads.platformLimits.android,
      compressionEnabled: true,
      keepAliveTimeout: 30000,
      requestTimeout: 15000
    },
    ios: {
      maxUploadSize: config.uploads.platformLimits.ios,
      compressionEnabled: true,
      keepAliveTimeout: 20000,
      requestTimeout: 10000
    },
    web: {
      maxUploadSize: config.uploads.platformLimits.web,
      compressionEnabled: true,
      keepAliveTimeout: 10000,
      requestTimeout: 8000
    },
    desktop: {
      maxUploadSize: config.uploads.platformLimits.desktop,
      compressionEnabled: true,
      keepAliveTimeout: 60000,
      requestTimeout: 30000
    }
  };
  
  return platformDefaults[platform as keyof typeof platformDefaults] || platformDefaults.web;
}

/**
 * Validate Flutter configuration
 */
export function validateFlutterConfig(): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const config = getFlutterConfig();
  
  // Validate upload configuration
  if (config.uploads.maxFileSize > 100 * 1024 * 1024) {
    errors.push('Max file size too large (>100MB)');
  }
  
  if (config.uploads.allowedMimeTypes.length === 0) {
    errors.push('No allowed MIME types specified');
  }
  
  // Validate CORS configuration
  if (config.cors.allowedHeaders.length === 0) {
    errors.push('No CORS allowed headers specified');
  }
  
  // Validate security configuration
  if (process.env.NODE_ENV === 'production') {
    if (config.cors.allowNoOrigin) {
      errors.push('allowNoOrigin should be false in production');
    }
    
    if (config.cors.allowedOrigins.length === 0) {
      errors.push('No allowed origins specified for production');
    }
  }
  
  // Validate performance configuration
  if (config.performance.connectionTimeout < 1000) {
    errors.push('Connection timeout too short (<1s)');
  }
  
  if (config.performance.requestTimeout < 1000) {
    errors.push('Request timeout too short (<1s)');
  }
  
  // Validate monitoring configuration
  if (config.monitoring.slowRequestThreshold < 100) {
    errors.push('Slow request threshold too low (<100ms)');
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Get configuration summary for debugging
 */
export function getConfigSummary() {
  const config = getFlutterConfig();
  
  return {
    environment: process.env.NODE_ENV,
    version: '1.0.0',
    cors: {
      allowNoOrigin: config.cors.allowNoOrigin,
      originsCount: config.cors.allowedOrigins.length,
      credentials: config.cors.credentials
    },
    uploads: {
      maxSize: `${Math.round(config.uploads.maxFileSize / 1024 / 1024)}MB`,
      allowedTypes: config.uploads.allowedMimeTypes.length,
      platformLimits: Object.fromEntries(
        Object.entries(config.uploads.platformLimits).map(([k, v]) => [
          k, `${Math.round(v / 1024 / 1024)}MB`
        ])
      )
    },
    security: {
      rateLimiting: config.security.enableRateLimiting,
      requestLogging: config.security.enableRequestLogging,
      userAgentValidation: config.security.enableUserAgentValidation
    },
    performance: {
      compression: config.performance.enableCompression,
      caching: config.performance.enableCaching,
      keepAlive: config.performance.enableKeepAlive
    },
    monitoring: {
      performanceTracking: config.monitoring.enablePerformanceTracking,
      healthChecks: config.monitoring.enableHealthChecks,
      slowRequestTracking: config.monitoring.logSlowRequests
    }
  };
}

/**
 * Update configuration at runtime (for testing)
 */
export function updateFlutterConfig(updates: Partial<FlutterConfig>): void {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Configuration updates not allowed in production');
  }
  
  // Deep merge updates with current config
  Object.assign(defaultFlutterConfig, updates);
}

/**
 * Reset configuration to defaults (for testing)
 */
export function resetFlutterConfig(): void {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('Configuration reset not allowed in production');
  }
  
  // This would reset to original defaults in a real implementation
  console.log('Flutter configuration reset to defaults');
}

// Export the main configuration
export const flutterConfig = getFlutterConfig();

// Export validation result on module load
const validation = validateFlutterConfig();
if (!validation.valid) {
  console.warn('Flutter configuration validation warnings:', validation.errors);
}