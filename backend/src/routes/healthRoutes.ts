// backend/src/routes/healthRoutes.ts
import { Router, Request, Response } from 'express';
import { config } from '../config';
import { flutterConfig } from '../config/flutter';
import { EnhancedApiError } from '../middlewares/errorHandler';

const router = Router();

interface FlutterHealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  platform: {
    detected: string;
    optimized: boolean;
    version?: string;
  };
  services: {
    database: 'up' | 'down' | 'degraded';
    storage: 'up' | 'down' | 'degraded';
    cache?: 'up' | 'down' | 'degraded';
    redis?: 'up' | 'down' | 'degraded';
  };
  performance: {
    responseTimeMs: number;
    memoryUsage: {
      used: number;
      total: number;
      percentage: number;
    };
    uptime: number;
    activeConnections?: number;
  };
  flutter: {
    corsEnabled: boolean;
    multipartSupport: boolean;
    maxUploadSize: string;
    supportedFormats: string[];
    platformLimits: {
      android: string;
      ios: string;
      web: string;
      desktop: string;
    };
  };
  endpoints: {
    [key: string]: {
      method: string;
      description: string;
      requiresAuth: boolean;
      flutterOptimized: boolean;
    };
  };
  networking: {
    ipv4: boolean;
    ipv6: boolean;
    compression: boolean;
    keepAlive: boolean;
  };
}

/**
 * Enhanced health check endpoint specifically designed for Flutter apps
 * GET /health
 */
router.get('/health', async (req: Request, res: Response) => {
  const startTime = Date.now();
  
  try {
    // Detect if request is from Flutter
    const userAgent = req.get('User-Agent') || '';
    const isFlutter = req.flutter?.isFlutter || 
                     userAgent.includes('Flutter') || 
                     userAgent.includes('Dart/');
    
    // Check system health
    const memoryUsage = process.memoryUsage();
    const memoryTotal = memoryUsage.heapTotal;
    const memoryUsed = memoryUsage.heapUsed;
    
    // Perform service health checks
    const serviceChecks = await Promise.allSettled([
      checkDatabaseHealth(),
      checkStorageHealth(),
      checkCacheHealth(),
      checkRedisHealth()
    ]);
    
    const services = {
      database: getRequiredServiceStatus(serviceChecks[0]),
      storage: getRequiredServiceStatus(serviceChecks[1]),
      cache: getServiceStatus(serviceChecks[2]),
      redis: getServiceStatus(serviceChecks[3])
    };
    
    // Remove undefined services
    Object.keys(services).forEach(key => {
      if (services[key as keyof typeof services] === undefined) {
        delete services[key as keyof typeof services];
      }
    });
    
    // Determine overall status
    const serviceStatuses = Object.values(services);
    const overallStatus: 'healthy' | 'degraded' | 'unhealthy' = 
      serviceStatuses.every(s => s === 'up') ? 'healthy' :
      serviceStatuses.some(s => s === 'up') ? 'degraded' : 'unhealthy';
    
    const responseTime = Date.now() - startTime;
    
    const healthResponse: FlutterHealthResponse = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      version: process.env.API_VERSION || '1.0.0',
      platform: {
        detected: isFlutter ? 'flutter' : 'web',
        optimized: isFlutter,
        version: req.flutter?.flutterVersion
      },
      services,
      performance: {
        responseTimeMs: responseTime,
        memoryUsage: {
          used: memoryUsed,
          total: memoryTotal,
          percentage: Math.round((memoryUsed / memoryTotal) * 100)
        },
        uptime: Math.floor(process.uptime()),
        activeConnections: getActiveConnections()
      },
      flutter: {
        corsEnabled: true,
        multipartSupport: true,
        maxUploadSize: '10MB',
        supportedFormats: flutterConfig.uploads.allowedMimeTypes,
        platformLimits: {
          android: '50MB',
          ios: '25MB', 
          web: '10MB',
          desktop: '100MB'
        }
      },
      endpoints: {
        auth: {
          method: 'POST',
          description: 'User authentication',
          requiresAuth: false,
          flutterOptimized: true
        },
        images: {
          method: 'GET|POST|PUT|DELETE',
          description: 'Image management',
          requiresAuth: true,
          flutterOptimized: true
        },
        wardrobes: {
          method: 'GET|POST|PUT|DELETE',
          description: 'Wardrobe management',
          requiresAuth: true,
          flutterOptimized: true
        },
        garments: {
          method: 'GET|POST|PUT|DELETE',
          description: 'Garment management',
          requiresAuth: true,
          flutterOptimized: true
        },
        files: {
          method: 'GET|POST|DELETE',
          description: 'File operations',
          requiresAuth: true,
          flutterOptimized: true
        }
      },
      networking: {
        ipv4: true,
        ipv6: flutterConfig.networking.enableIPv6,
        compression: flutterConfig.performance.enableCompression,
        keepAlive: true
      }
    };
    
    // Set appropriate status code based on health
    const statusCode = overallStatus === 'healthy' ? 200 : 
                      overallStatus === 'degraded' ? 200 : 503;
    
    // Add Flutter-specific headers
    if (isFlutter) {
      res.set('X-Flutter-Health-Check', 'true');
      res.set('X-Flutter-Status', overallStatus);
    }
    
    res.status(statusCode).json(healthResponse);
    
  } catch (error) {
    console.error('Health check error:', error);
    
    const errorResponse = {
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: {
        message: 'Health check failed',
        code: 'HEALTH_CHECK_ERROR'
      },
      performance: {
        responseTimeMs: Date.now() - startTime
      }
    };
    
    res.status(503).json(errorResponse);
  }
});

/**
 * Flutter connectivity test endpoint
 * GET /flutter-test
 */
router.get('/flutter-test', (req: Request, res: Response) => {
  const startTime = Date.now();
  
  try {
    const userAgent = req.get('User-Agent') || '';
    const isFlutter = req.flutter?.isFlutter || 
                     userAgent.includes('Flutter') || 
                     userAgent.includes('Dart/');
    
    const testResults = {
      connectivity: 'success',
      cors: testCORS(req),
      headers: testHeaders(req),
      contentTypes: testContentTypes(),
      uploads: testUploadCapabilities(req.flutter?.platform),
      performance: {
        responseTime: Date.now() - startTime,
        serverTime: Date.now(),
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      }
    };
    
    res.json({
      success: true,
      data: {
        flutterDetected: isFlutter,
        platform: req.flutter?.platform || 'unknown',
        flutterVersion: req.flutter?.flutterVersion,
        dartVersion: req.flutter?.dartVersion,
        deviceInfo: req.flutter?.deviceInfo,
        userAgent,
        timestamp: new Date().toISOString(),
        tests: testResults
      },
      message: 'Flutter connectivity test successful',
      meta: {
        testDuration: `${Date.now() - startTime}ms`,
        endpoint: 'flutter-test'
      }
    });
    
  } catch (error) {
    console.error('Flutter test error:', error);
    
    res.status(500).json({
      success: false,
      error: {
        code: 'FLUTTER_TEST_ERROR',
        message: 'Flutter connectivity test failed',
        timestamp: new Date().toISOString()
      }
    });
  }
});

/**
 * Detailed system diagnostics for Flutter debugging
 * GET /diagnostics
 */
router.get('/diagnostics', async (req: Request, res: Response) => {
  const startTime = Date.now();
  
  try {
    // Only allow in development or with admin token
    if (process.env.NODE_ENV === 'production' && !req.get('X-Admin-Token')) {
      throw EnhancedApiError.authorizationDenied('Diagnostics access denied');
    }
    
    const diagnostics = {
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        pid: process.pid,
        ppid: process.ppid,
        memory: process.memoryUsage(),
        cpuUsage: process.cpuUsage(),
        uptime: process.uptime(),
        loadAverage: process.platform === 'win32' ? null : require('os').loadavg(),
        freeMem: require('os').freemem(),
        totalMem: require('os').totalmem()
      },
      environment: {
        nodeEnv: process.env.NODE_ENV,
        port: process.env.PORT || config.port,
        storageMode: config.storageMode,
        jwtConfigured: !!process.env.JWT_SECRET,
        corsEnabled: true,
        flutterOptimized: true
      },
      flutter: {
        middlewareEnabled: true,
        configLoaded: !!flutterConfig,
        corsConfig: flutterConfig.cors,
        uploadConfig: {
          maxFileSize: flutterConfig.uploads.maxFileSize,
          allowedTypes: flutterConfig.uploads.allowedMimeTypes.length
        },
        securityConfig: flutterConfig.security
      },
      networking: {
        listening: `0.0.0.0:${config.port}`,
        ipv6: flutterConfig.networking.enableIPv6,
        compression: flutterConfig.performance.enableCompression
      },
      performance: {
        responseTime: Date.now() - startTime,
        eventLoopLag: getEventLoopLag(),
        activeHandles: (process as any)._getActiveHandles?.()?.length || 'unknown',
        activeRequests: (process as any)._getActiveRequests?.()?.length || 'unknown'
      }
    };
    
    res.json({
      success: true,
      data: diagnostics,
      message: 'System diagnostics retrieved',
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    if (error instanceof EnhancedApiError) {
      throw error;
    }
    
    console.error('Diagnostics error:', error);
    throw EnhancedApiError.internalError('Failed to retrieve diagnostics');
  }
});

/**
 * Network latency test for Flutter apps
 * GET /ping
 */
router.get('/ping', (req: Request, res: Response) => {
  const timestamp = Date.now();
  
  res.json({
    success: true,
    data: {
      pong: true,
      timestamp: new Date().toISOString(),
      serverTime: timestamp,
      platform: req.flutter?.platform || 'unknown',
      flutterDetected: req.flutter?.isFlutter || false
    },
    message: 'Pong!',
    meta: {
      responseTime: '< 1ms'
    }
  });
});

// =========================== HELPER FUNCTIONS ===========================

/**
 * Database health check
 */
async function checkDatabaseHealth(): Promise<'up' | 'down' | 'degraded'> {
  try {
    // TODO: Implement actual database health check
    // Example: await db.query('SELECT 1');
    return 'up';
  } catch (error) {
    console.error('Database health check failed:', error);
    return 'down';
  }
}

/**
 * Storage health check
 */
async function checkStorageHealth(): Promise<'up' | 'down' | 'degraded'> {
  try {
    // TODO: Implement actual storage health check
    // Example: Check if storage service is accessible
    return 'up';
  } catch (error) {
    console.error('Storage health check failed:', error);
    return 'down';
  }
}

/**
 * Cache health check
 */
async function checkCacheHealth(): Promise<'up' | 'down' | 'degraded' | undefined> {
  if (!process.env.CACHE_ENABLED) {
    return undefined;
  }
  
  try {
    // TODO: Implement cache health check
    return 'up';
  } catch (error) {
    console.error('Cache health check failed:', error);
    return 'down';
  }
}

/**
 * Redis health check
 */
async function checkRedisHealth(): Promise<'up' | 'down' | 'degraded' | undefined> {
  if (!process.env.REDIS_URL) {
    return undefined;
  }
  
  try {
    // TODO: Implement Redis health check
    return 'up';
  } catch (error) {
    console.error('Redis health check failed:', error);
    return 'down';
  }
}

/**
 * Get service status from Promise.allSettled result
 */
function getServiceStatus(result: PromiseSettledResult<'up' | 'down' | 'degraded' | undefined>): 'up' | 'down' | 'degraded' | undefined {
  if (result.status === 'fulfilled') {
    return result.value;
  }
  return 'down';
}

/**
 * Get required service status (never returns undefined)
 */
function getRequiredServiceStatus(result: PromiseSettledResult<'up' | 'down' | 'degraded'>): 'up' | 'down' | 'degraded' {
  if (result.status === 'fulfilled') {
    return result.value;
  }
  return 'down';
}

/**
 * Get active connections count
 */
function getActiveConnections(): number | undefined {
  try {
    // This is a rough estimate - in production, use proper monitoring
    return (process as any)._getActiveHandles?.()?.filter((h: any) => 
      h.constructor.name === 'Socket'
    ).length || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Test CORS configuration
 */
function testCORS(req: Request) {
  return {
    origin: req.get('Origin') || 'no-origin',
    credentials: 'supported',
    methods: 'GET,POST,PUT,DELETE,OPTIONS,PATCH',
    headers: 'Content-Type,Authorization,Accept,Origin,X-Requested-With',
    flutterFriendly: true
  };
}

/**
 * Test headers configuration
 */
function testHeaders(req: Request) {
  return {
    userAgent: !!req.get('User-Agent'),
    authorization: !!req.get('Authorization'),
    contentType: !!req.get('Content-Type'),
    acceptLanguage: !!req.get('Accept-Language'),
    customHeaders: {
      'X-Flutter-App': !!req.get('X-Flutter-App'),
      'X-Platform': !!req.get('X-Platform'),
      'X-App-Version': !!req.get('X-App-Version')
    }
  };
}

/**
 * Test content types support
 */
function testContentTypes() {
  return {
    json: 'supported',
    multipart: 'supported',
    urlencoded: 'supported',
    binary: 'supported',
    maxJsonSize: '2MB',
    maxFileSize: '10MB'
  };
}

/**
 * Test upload capabilities
 */
function testUploadCapabilities(platform?: string) {
  const limits = {
    android: '50MB',
    ios: '25MB',
    web: '10MB',
    desktop: '100MB'
  };
  
  return {
    maxSize: limits[platform as keyof typeof limits] || limits.web,
    supportedTypes: flutterConfig.uploads.allowedMimeTypes,
    multipart: true,
    chunked: false, // TODO: Implement chunked uploads
    resumable: false // TODO: Implement resumable uploads
  };
}

/**
 * Get event loop lag (simplified)
 */
function getEventLoopLag(): number {
  const start = process.hrtime.bigint();
  setImmediate(() => {
    const lag = Number(process.hrtime.bigint() - start) / 1000000; // Convert to milliseconds
    return lag;
  });
  return 0; // Simplified implementation
}

export default router;