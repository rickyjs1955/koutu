// tests/unit/flutterMiddleware.unit.test.ts
import { Request, Response, NextFunction } from 'express';
import {
  flutterDetectionMiddleware,
  flutterValidationMiddleware,
  flutterResponseMiddleware,
  flutterPerformanceMiddleware
} from '../../middlewares/flutterMiddleware';
import { EnhancedApiError } from '../../middlewares/errorHandler';

// Mock Express objects
const mockRequest = (userAgent = '', headers: { [key: string]: string } = {}, method = 'GET', path = '/test') => ({
  get: jest.fn((header: string) => {
    if (header === 'User-Agent') return userAgent;
    return headers[header.toLowerCase()] || undefined;
  }),
  headers: { 'user-agent': userAgent, ...headers },
  method,
  path,
  flutter: undefined
} as unknown as Request);

const mockResponse = () => {
  const res = {
    set: jest.fn(),
    json: jest.fn(),
    status: jest.fn(() => res),
    on: jest.fn(),
    get: jest.fn() // Add the missing get method
  } as unknown as Response;
  return res;
};

const mockNext = jest.fn() as NextFunction;

describe('Flutter Middleware Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Clear console logs for cleaner test output
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('flutterDetectionMiddleware', () => {
    describe('Flutter Detection', () => {
      test('should detect Flutter from Dart User-Agent', () => {
        const req = mockRequest('Dart/2.19.0 (dart:io) Flutter/3.7.0');
        const res = mockResponse();

        flutterDetectionMiddleware(req, res, mockNext);

        expect(req.flutter?.isFlutter).toBe(true);
        expect(req.flutter?.flutterVersion).toBe('3.7.0');
        expect(req.flutter?.dartVersion).toBe('2.19.0');
        expect(mockNext).toHaveBeenCalledWith();
      });

      test('should detect Flutter from alternative User-Agent patterns', () => {
        const testCases = [
          'Flutter/3.0.0 Dart/2.17.0',
          'dartvm/2.19.0',
          'dart:io client'
        ];

        testCases.forEach(userAgent => {
          const req = mockRequest(userAgent);
          flutterDetectionMiddleware(req, mockResponse(), mockNext);
          expect(req.flutter?.isFlutter).toBe(true);
        });
      });

      test('should not detect Flutter from regular browser User-Agent', () => {
        const req = mockRequest('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
        const res = mockResponse();

        flutterDetectionMiddleware(req, res, mockNext);

        expect(req.flutter?.isFlutter).toBe(false);
        expect(req.flutter?.flutterVersion).toBeUndefined();
        expect(req.flutter?.dartVersion).toBeUndefined();
      });

      test('should detect Flutter from X-Flutter-App header', () => {
        const req = mockRequest('Custom App', { 'x-flutter-app': 'true' });
        const res = mockResponse();

        flutterDetectionMiddleware(req, res, mockNext);

        expect(req.flutter?.isFlutter).toBe(true);
      });
    });

    describe('Platform Detection', () => {
      test('should detect Android platform', () => {
        const req = mockRequest('Dart/2.19.0 Flutter/3.7.0 Android 13');
        flutterDetectionMiddleware(req, mockResponse(), mockNext);
        expect(req.flutter?.platform).toBe('android');
      });

      test('should detect iOS platform', () => {
        const req = mockRequest('Dart/2.19.0 Flutter/3.7.0 iPhone iOS 16');
        flutterDetectionMiddleware(req, mockResponse(), mockNext);
        expect(req.flutter?.platform).toBe('ios');
      });

      test('should detect platform from X-Platform header', () => {
        const req = mockRequest('Dart/2.19.0', { 'x-platform': 'desktop' });
        flutterDetectionMiddleware(req, mockResponse(), mockNext);
        expect(req.flutter?.platform).toBe('desktop');
      });

      test('should prefer header over User-Agent for platform detection', () => {
        const req = mockRequest('Dart/2.19.0 Android', { 'x-platform': 'ios' });
        flutterDetectionMiddleware(req, mockResponse(), mockNext);
        expect(req.flutter?.platform).toBe('ios');
      });
    });

    describe('Device Info Extraction', () => {
      test('should extract app version from headers', () => {
        const req = mockRequest('Dart/2.19.0', { 'x-app-version': '1.2.3' });
        flutterDetectionMiddleware(req, mockResponse(), mockNext);
        expect(req.flutter?.deviceInfo?.appVersion).toBe('1.2.3');
      });

      test('should extract device model from Android User-Agent', () => {
        const req = mockRequest('Dart/2.19.0 (SM-G991B; Android 13)');
        flutterDetectionMiddleware(req, mockResponse(), mockNext);
        expect(req.flutter?.deviceInfo?.model).toContain('SM-G991B');
        expect(req.flutter?.deviceInfo?.os).toBe('Android');
      });

      test('should handle missing device info gracefully', () => {
        const req = mockRequest('Dart/2.19.0');
        flutterDetectionMiddleware(req, mockResponse(), mockNext);
        expect(req.flutter?.deviceInfo).toBeUndefined();
      });
    });

    describe('Debug Headers in Development', () => {
      const originalEnv = process.env.NODE_ENV;

      afterEach(() => {
        process.env.NODE_ENV = originalEnv;
      });

      test('should add debug headers in development', () => {
        process.env.NODE_ENV = 'development';
        const req = mockRequest('Dart/2.19.0 Flutter/3.7.0 Android');
        const res = mockResponse();

        flutterDetectionMiddleware(req, res, mockNext);

        expect(res.set).toHaveBeenCalledWith('X-Flutter-Detected', 'true');
        expect(res.set).toHaveBeenCalledWith('X-Flutter-Platform', 'android');
        expect(res.set).toHaveBeenCalledWith('X-Flutter-Version', '3.7.0');
      });

      test('should not add debug headers in production', () => {
        process.env.NODE_ENV = 'production';
        const req = mockRequest('Dart/2.19.0 Flutter/3.7.0');
        const res = mockResponse();

        flutterDetectionMiddleware(req, res, mockNext);

        expect(res.set).not.toHaveBeenCalled();
      });
    });

    describe('Error Handling', () => {
      test('should handle malformed User-Agent gracefully', () => {
        const req = mockRequest('\x00\x01\x02invalid');
        const res = mockResponse();

        expect(() => {
          flutterDetectionMiddleware(req, res, mockNext);
        }).not.toThrow();

        expect(req.flutter?.isFlutter).toBe(false);
        expect(mockNext).toHaveBeenCalledWith();
      });

      test('should handle missing User-Agent', () => {
        const req = mockRequest('');
        const res = mockResponse();

        flutterDetectionMiddleware(req, res, mockNext);

        expect(req.flutter?.isFlutter).toBe(false);
        expect(mockNext).toHaveBeenCalledWith();
      });
    });
  });

  describe('flutterValidationMiddleware', () => {
    describe('File Upload Validation', () => {
      test('should validate multipart upload size for Flutter apps', () => {
        const req = mockRequest('Dart/2.19.0 Android', {
          'content-type': 'multipart/form-data',
          'content-length': '100000000' // 100MB
        }, 'POST');
        req.flutter = { isFlutter: true, platform: 'android' };

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });

      test('should allow valid upload sizes', () => {
        const req = mockRequest('Dart/2.19.0', {
          'content-type': 'multipart/form-data',
          'content-length': '1000000' // 1MB
        }, 'POST');
        req.flutter = { isFlutter: true, platform: 'web' };

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith();
      });

      test('should skip validation for non-Flutter requests', () => {
        const req = mockRequest('Mozilla/5.0', {
          'content-type': 'multipart/form-data',
          'content-length': '100000000'
        }, 'POST');
        req.flutter = { isFlutter: false };

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith();
      });

      test('should skip validation for non-multipart requests', () => {
        const req = mockRequest('Dart/2.19.0', {
          'content-type': 'application/json'
        }, 'POST');
        req.flutter = { isFlutter: true };

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith();
      });
    });

    describe('Platform-Specific Limits', () => {
      test('should use Android limits for Android platform', () => {
        const req = mockRequest('Dart/2.19.0', {
          'content-type': 'multipart/form-data',
          'content-length': '75000000' // 75MB (exceeds Android 50MB limit)
        }, 'POST');
        req.flutter = { isFlutter: true, platform: 'android' };

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });

      test('should use iOS limits for iOS platform', () => {
        const req = mockRequest('Dart/2.19.0', {
          'content-type': 'multipart/form-data',
          'content-length': '30000000' // 30MB (exceeds iOS 25MB limit)
        }, 'POST');
        req.flutter = { isFlutter: true, platform: 'ios' };

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });

      test('should use default limits for unknown platform', () => {
        const req = mockRequest('Dart/2.19.0', {
          'content-type': 'multipart/form-data',
          'content-length': '15000000' // 15MB (exceeds default 10MB limit)
        }, 'POST');
        req.flutter = { isFlutter: true };

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });
    });

    describe('Error Handling', () => {
      test('should handle missing Content-Length header', () => {
        const req = mockRequest('Dart/2.19.0', {
          'content-type': 'multipart/form-data'
        }, 'POST');
        req.flutter = { isFlutter: true };

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith();
      });

      test('should handle internal errors gracefully', () => {
        const req = mockRequest('Dart/2.19.0');
        req.flutter = { isFlutter: true };
        
        // Mock req.get to throw an error
        req.get = jest.fn(() => {
          throw new Error('Test error');
        });

        flutterValidationMiddleware(req, mockResponse(), mockNext);

        expect(mockNext).toHaveBeenCalledWith(expect.any(EnhancedApiError));
      });
    });
  });

  describe('flutterResponseMiddleware', () => {
    describe('Response Optimization', () => {
      test('should add Flutter-optimized headers', () => {
        const req = mockRequest('Dart/2.19.0');
        req.flutter = { isFlutter: true };
        const res = mockResponse();
        
        // Mock original json method
        const originalJson = jest.fn();
        res.json = originalJson;

        flutterResponseMiddleware(req, res, mockNext);

        // Call the overridden json method
        res.json({ test: 'data' });

        expect(res.set).toHaveBeenCalledWith('Cache-Control', 'no-cache, no-store, must-revalidate');
        expect(res.set).toHaveBeenCalledWith('X-Flutter-Optimized', 'true');
      });

      test('should wrap non-standard responses', () => {
        const req = mockRequest('Dart/2.19.0');
        req.flutter = { isFlutter: true, platform: 'android', flutterVersion: '3.7.0' };
        const res = mockResponse();
        
        const originalJson = jest.fn();
        res.json = originalJson;

        flutterResponseMiddleware(req, res, mockNext);
        
        const testData = { message: 'test' };
        res.json(testData);

        expect(originalJson).toHaveBeenCalledWith(
          expect.objectContaining({
            success: true,
            data: testData,
            timestamp: expect.any(String),
            requestId: expect.any(String),
            meta: expect.objectContaining({
              platform: 'android',
              flutterVersion: '3.7.0'
            })
          })
        );
      });

      test('should not modify already wrapped responses', () => {
        const req = mockRequest('Dart/2.19.0');
        req.flutter = { isFlutter: true };
        const res = mockResponse();
        
        const originalJson = jest.fn();
        res.json = originalJson;

        flutterResponseMiddleware(req, res, mockNext);
        
        const wrappedData = { success: true, data: { message: 'test' } };
        res.json(wrappedData);

        expect(originalJson).toHaveBeenCalledWith(wrappedData);
      });

      test('should not modify responses for non-Flutter requests', () => {
        const req = mockRequest('Mozilla/5.0');
        req.flutter = { isFlutter: false };
        const res = mockResponse();

        flutterResponseMiddleware(req, res, mockNext);

        expect(mockNext).toHaveBeenCalledWith();
        expect(res.set).not.toHaveBeenCalled();
      });
    });

    describe('Response Timing', () => {
      test('should include response time when available', () => {
        const req = mockRequest('Dart/2.19.0') as any;
        req.flutter = { isFlutter: true };
        req.startTime = Date.now() - 100; // 100ms ago
        const res = mockResponse();
        
        const originalJson = jest.fn();
        res.json = originalJson;

        flutterResponseMiddleware(req, res, mockNext);
        res.json({ test: 'data' });

        expect(res.set).toHaveBeenCalledWith('X-Response-Time', expect.stringMatching(/\d+ms/));
      });
    });

    describe('Error Handling', () => {
      test('should handle json override errors gracefully', () => {
        const req = mockRequest('Dart/2.19.0');
        req.flutter = { isFlutter: true };
        const res = mockResponse();
        
        // Make res.set throw an error
        res.set = jest.fn(() => {
          throw new Error('Header error');
        });

        expect(() => {
          flutterResponseMiddleware(req, res, mockNext);
        }).not.toThrow();

        expect(mockNext).toHaveBeenCalledWith();
      });
    });
  });

  describe('flutterPerformanceMiddleware', () => {
    describe('Performance Tracking', () => {
      test('should track request start time for Flutter apps', () => {
        const req = mockRequest('Dart/2.19.0') as any;
        req.flutter = { isFlutter: true };
        const res = mockResponse();

        flutterPerformanceMiddleware(req, res, mockNext);

        expect(req.startTime).toBeDefined();
        expect(typeof req.startTime).toBe('number');
        expect(mockNext).toHaveBeenCalledWith();
      });

      test('should not track performance for non-Flutter requests', () => {
        const req = mockRequest('Mozilla/5.0') as any;
        req.flutter = { isFlutter: false };
        const res = mockResponse();

        flutterPerformanceMiddleware(req, res, mockNext);

        expect(req.startTime).toBeUndefined();
        expect(mockNext).toHaveBeenCalledWith();
      });

      test('should set up response finish listener', () => {
        const req = mockRequest('Dart/2.19.0');
        req.flutter = { isFlutter: true };
        const res = mockResponse();

        flutterPerformanceMiddleware(req, res, mockNext);

        expect(res.on).toHaveBeenCalledWith('finish', expect.any(Function));
      });
    });

    describe('Performance Logging', () => {
      test('should log performance metrics on response finish', () => {
        const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
        
        const req = mockRequest('Dart/2.19.0') as any;
        req.flutter = { isFlutter: true, platform: 'android', flutterVersion: '3.7.0' };
        req.method = 'GET';
        req.path = '/api/test';
        const res = mockResponse();
        res.statusCode = 200;
        res.get = jest.fn(() => '1024');

        process.env.NODE_ENV = 'development';
        
        flutterPerformanceMiddleware(req, res, mockNext);
        
        // Simulate response finish
        const finishCallback = (res.on as jest.Mock).mock.calls[0][1];
        finishCallback();

        expect(consoleLogSpy).toHaveBeenCalledWith(
          expect.stringContaining('📱 Flutter Performance:'),
          expect.objectContaining({
            endpoint: 'GET /api/test',
            platform: 'android'
          })
        );

        consoleLogSpy.mockRestore();
      });

      test('should warn on slow responses', () => {
        const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
        
        const req = mockRequest('Dart/2.19.0') as any;
        req.flutter = { isFlutter: true, platform: 'ios' };
        req.method = 'POST';
        req.path = '/api/upload';
        const res = mockResponse();
        res.statusCode = 200;
        res.get = jest.fn(() => '2048');

        // Set environment to development to ensure logging is enabled
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'development';

        flutterPerformanceMiddleware(req, res, mockNext);
        
        // Set startTime after middleware is called to ensure it's set by the middleware
        // but make it old enough to trigger the slow response warning (5+ seconds)
        req.startTime = Date.now() - 5500; // 5.5 seconds ago
        
        // Simulate response finish
        const finishCallback = (res.on as jest.Mock).mock.calls[0][1];
        finishCallback();

        expect(consoleWarnSpy).toHaveBeenCalledWith(
          expect.stringContaining('Slow Flutter response: POST /api/upload'),
          expect.objectContaining({
            platform: 'ios',
            statusCode: 200
          })
        );

        // Restore environment
        process.env.NODE_ENV = originalEnv;
        consoleWarnSpy.mockRestore();
      });
    });

    describe('Error Handling', () => {
      test('should handle performance tracking errors gracefully', () => {
        const req = mockRequest('Dart/2.19.0');
        req.flutter = { isFlutter: true };
        const res = mockResponse();
        
        // Make res.on throw an error
        res.on = jest.fn(() => {
          throw new Error('Event listener error');
        });

        expect(() => {
          flutterPerformanceMiddleware(req, res, mockNext);
        }).not.toThrow();

        expect(mockNext).toHaveBeenCalledWith();
      });
    });
  });

  describe('Helper Functions Integration', () => {
    test('should generate unique request IDs', () => {
      const req1 = mockRequest('Dart/2.19.0');
      const req2 = mockRequest('Dart/2.19.0');
      req1.flutter = { isFlutter: true };
      req2.flutter = { isFlutter: true };
      
      const res1 = mockResponse();
      const res2 = mockResponse();
      
      // Properly mock the json method with implementation
      const jsonMock1 = jest.fn();
      const jsonMock2 = jest.fn();
      res1.json = jsonMock1;
      res2.json = jsonMock2;

      flutterResponseMiddleware(req1, res1, mockNext);
      flutterResponseMiddleware(req2, res2, mockNext);

      res1.json({ test: 'data1' });
      res2.json({ test: 'data2' });

      // Now the mock.calls should be defined
      expect(jsonMock1.mock.calls).toBeDefined();
      expect(jsonMock2.mock.calls).toBeDefined();
      expect(jsonMock1.mock.calls.length).toBe(1);
      expect(jsonMock2.mock.calls.length).toBe(1);

      const call1 = jsonMock1.mock.calls[0][0];
      const call2 = jsonMock2.mock.calls[0][0];

      expect(call1.requestId).toBeDefined();
      expect(call2.requestId).toBeDefined();
      expect(call1.requestId).not.toBe(call2.requestId);
    });

    test('should validate timestamps format', () => {
      const req = mockRequest('Dart/2.19.0');
      req.flutter = { isFlutter: true };
      const res = mockResponse();
      
      // Properly mock the json method
      const jsonMock = jest.fn();
      res.json = jsonMock;

      flutterResponseMiddleware(req, res, mockNext);
      res.json({ test: 'data' });

      // Now the mock.calls should be defined
      expect(jsonMock.mock.calls).toBeDefined();
      expect(jsonMock.mock.calls.length).toBe(1);

      const responseData = jsonMock.mock.calls[0][0];
      expect(responseData.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
    });
  });
});