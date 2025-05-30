// backend/src/tests/unit/InstagramApiError.unit.test.ts
import { InstagramApiError, InstagramErrorContext } from '../../utils/InstagramApiError';
import { ApiError } from '../../utils/ApiError';

// Mock ApiError class
jest.mock('../../utils/ApiError');

describe('InstagramApiError', () => {
  let mockApiError: jest.Mocked<typeof ApiError>;
  let mockContext: InstagramErrorContext;

  beforeEach(() => {
    jest.clearAllMocks();
    mockApiError = ApiError as jest.Mocked<typeof ApiError>;
    
    // Setup default context
    mockContext = {
      url: 'https://scontent.cdninstagram.com/test-image.jpg',
      userId: 'user-123',
      mediaId: 'media-456',
      timestamp: new Date('2025-01-01T10:00:00Z')
    };

    // Setup ApiError mock implementations
    mockApiError.badRequest = jest.fn().mockImplementation((message, code, context) => ({
      message,
      code,
      statusCode: 400,
      context
    }));
    
    mockApiError.unauthorized = jest.fn().mockImplementation((message, code, context) => ({
      message,
      code,
      statusCode: 401,
      context
    }));
    
    mockApiError.forbidden = jest.fn().mockImplementation((message, code, context) => ({
      message,
      code,
      statusCode: 403,
      context
    }));
    
    mockApiError.notFound = jest.fn().mockImplementation((message, code, context) => ({
      message,
      code,
      statusCode: 404,
      context
    }));
    
    mockApiError.conflict = jest.fn().mockImplementation((message, code, context) => ({
      message,
      code,
      statusCode: 409,
      context
    }));
    
    mockApiError.rateLimited = jest.fn().mockImplementation((message, retryAfter, code, waitTime) => ({
      message,
      code: code || 'RATE_LIMITED',
      statusCode: 429,
      retryAfter: waitTime
    }));
    
    mockApiError.serviceUnavailable = jest.fn().mockImplementation((message, code, context) => ({
      message,
      code,
      statusCode: 503,
      context
    }));
    
    mockApiError.externalService = jest.fn().mockImplementation((message, service, error) => ({
      message,
      code: 'EXTERNAL_SERVICE_ERROR',
      statusCode: 502,
      service,
      originalError: error
    }));
  });

  describe('fromHttpStatus', () => {
    it('should handle 400 Bad Request', () => {
      const result = InstagramApiError.fromHttpStatus(400, undefined, mockContext);
      
      expect(mockApiError.badRequest).toHaveBeenCalledWith(
        'The Instagram photo URL is invalid or the post cannot be accessed.',
        'INSTAGRAM_INVALID_REQUEST',
        mockContext
      );
    });

    it('should handle 401 Unauthorized', () => {
      const result = InstagramApiError.fromHttpStatus(401, undefined, mockContext);
      
      expect(mockApiError.unauthorized).toHaveBeenCalledWith(
        'Your Instagram connection has expired. Please go to Settings and reconnect your Instagram account.',
        'INSTAGRAM_AUTH_EXPIRED',
        {
          ...mockContext,
          userAction: 'reconnect_instagram',
          redirectTo: '/settings/integrations'
        }
      );
    });

    it('should handle 403 Forbidden', () => {
      const result = InstagramApiError.fromHttpStatus(403, undefined, mockContext);
      
      expect(mockApiError.forbidden).toHaveBeenCalledWith(
        'Access denied to this Instagram post. The post may be private or you may not have permission to view it.',
        'INSTAGRAM_ACCESS_DENIED',
        mockContext
      );
    });

    it('should handle 404 Not Found', () => {
      const result = InstagramApiError.fromHttpStatus(404, undefined, mockContext);
      
      expect(mockApiError.notFound).toHaveBeenCalledWith(
        'Instagram post not found. The post may have been deleted or the URL is incorrect.',
        'INSTAGRAM_MEDIA_NOT_FOUND',
        mockContext
      );
    });

    it('should handle 429 Rate Limited with retry-after header', () => {
      const mockResponse = {
        headers: {
          get: jest.fn().mockImplementation((header) => {
            switch (header) {
              case 'retry-after': return '600'; // 10 minutes
              case 'x-ratelimit-reset': return '1640995200';
              case 'x-ratelimit-remaining': return '0';
              default: return null;
            }
          })
        }
      } as unknown as Response;

      const result = InstagramApiError.fromHttpStatus(429, mockResponse, mockContext);
      
      expect(mockApiError.rateLimited).toHaveBeenCalledWith(
        'Instagram rate limit reached. Please wait 10 minutes before trying again.',
        undefined,
        undefined,
        600
      );
    });

    it('should handle 429 Rate Limited with short wait time', () => {
      const mockResponse = {
        headers: {
          get: jest.fn().mockImplementation((header) => {
            switch (header) {
              case 'retry-after': return '120'; // 2 minutes
              default: return null;
            }
          })
        }
      } as unknown as Response;

      const result = InstagramApiError.fromHttpStatus(429, mockResponse, mockContext);
      
      expect(mockApiError.rateLimited).toHaveBeenCalledWith(
        'Instagram rate limit reached. Please wait 2 minutes before importing more photos.',
        undefined,
        undefined,
        120
      );
    });

    it('should handle 429 Rate Limited without retry-after header', () => {
      const mockResponse = {
        headers: {
          get: jest.fn().mockReturnValue(null)
        }
      } as unknown as Response;

      const result = InstagramApiError.fromHttpStatus(429, mockResponse, mockContext);
      
      expect(mockApiError.rateLimited).toHaveBeenCalledWith(
        'Instagram rate limit reached. Please wait 5 minutes before importing more photos.',
        undefined,
        undefined,
        300
      );
    });

    it('should handle 500 Internal Server Error', () => {
      const result = InstagramApiError.fromHttpStatus(500, undefined, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram is experiencing server issues. Please try again in a few minutes.',
        'INSTAGRAM_SERVER_ERROR',
        {
          ...mockContext,
          httpStatus: 500
        }
      );
    });

    it('should handle 502 Bad Gateway', () => {
      const result = InstagramApiError.fromHttpStatus(502, undefined, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram gateway error. Please try again in a few minutes.',
        'INSTAGRAM_SERVER_ERROR',
        {
          ...mockContext,
          httpStatus: 502
        }
      );
    });

    it('should handle 503 Service Unavailable', () => {
      const result = InstagramApiError.fromHttpStatus(503, undefined, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram service temporarily unavailable. Please try again in a few minutes.',
        'INSTAGRAM_SERVER_ERROR',
        {
          ...mockContext,
          httpStatus: 503
        }
      );
    });

    it('should handle 504 Gateway Timeout', () => {
      const result = InstagramApiError.fromHttpStatus(504, undefined, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram request timed out. Please try again in a few minutes.',
        'INSTAGRAM_SERVER_ERROR',
        {
          ...mockContext,
          httpStatus: 504
        }
      );
    });

    it('should handle unknown status codes', () => {
      const result = InstagramApiError.fromHttpStatus(418, undefined, mockContext);
      
      expect(mockApiError.externalService).toHaveBeenCalledWith(
        'Instagram returned an unexpected response (418). Please try again later.',
        'instagram_api',
        expect.any(Error)
      );
    });

    it('should work without context', () => {
      const result = InstagramApiError.fromHttpStatus(400);
      
      expect(mockApiError.badRequest).toHaveBeenCalledWith(
        'The Instagram photo URL is invalid or the post cannot be accessed.',
        'INSTAGRAM_INVALID_REQUEST',
        undefined
      );
    });
  });

  describe('fromNetworkError', () => {
    it('should handle AbortError (timeout)', () => {
      const error = new Error('Operation aborted');
      error.name = 'AbortError';
      
      const result = InstagramApiError.fromNetworkError(error, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram request timed out. The service may be slow right now. Please try again.',
        'INSTAGRAM_TIMEOUT',
        mockContext
      );
    });

    it('should handle TypeError with fetch in message', () => {
      const error = new TypeError('fetch failed');
      
      const result = InstagramApiError.fromNetworkError(error, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Unable to connect to Instagram. Please check your internet connection and try again.',
        'INSTAGRAM_CONNECTION_ERROR',
        mockContext
      );
    });

    it('should handle ENOTFOUND error code', () => {
      const error = new Error('getaddrinfo ENOTFOUND');
      (error as any).code = 'ENOTFOUND';
      
      const result = InstagramApiError.fromNetworkError(error, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Unable to connect to Instagram. Please check your internet connection and try again.',
        'INSTAGRAM_CONNECTION_ERROR',
        mockContext
      );
    });

    it('should handle ECONNREFUSED error code', () => {
      const error = new Error('Connection refused');
      (error as any).code = 'ECONNREFUSED';
      
      const result = InstagramApiError.fromNetworkError(error, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Unable to connect to Instagram. Please check your internet connection and try again.',
        'INSTAGRAM_CONNECTION_ERROR',
        mockContext
      );
    });

    it('should handle ECONNRESET error code', () => {
      const error = new Error('Connection reset');
      (error as any).code = 'ECONNRESET';
      
      const result = InstagramApiError.fromNetworkError(error, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Unable to connect to Instagram. Please check your internet connection and try again.',
        'INSTAGRAM_CONNECTION_ERROR',
        mockContext
      );
    });

    it('should handle ETIMEDOUT error code', () => {
      const error = new Error('Operation timed out');
      (error as any).code = 'ETIMEDOUT';
      
      const result = InstagramApiError.fromNetworkError(error, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram request timed out. The service may be slow right now. Please try again.',
        'INSTAGRAM_TIMEOUT',
        mockContext
      );
    });

    it('should handle unknown network errors', () => {
      const error = new Error('Unknown network error');
      
      const result = InstagramApiError.fromNetworkError(error, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Network error while connecting to Instagram. Please try again.',
        'INSTAGRAM_NETWORK_ERROR',
        {
          ...mockContext,
          originalError: 'Unknown network error'
        }
      );
    });

    it('should work without context', () => {
      const error = new Error('Network error');
      
      const result = InstagramApiError.fromNetworkError(error);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Network error while connecting to Instagram. Please try again.',
        'INSTAGRAM_NETWORK_ERROR',
        {
          originalError: 'Network error'
        }
      );
    });
  });

  describe('fromBusinessRule', () => {
    it('should handle DUPLICATE_IMPORT', () => {
      const result = InstagramApiError.fromBusinessRule('DUPLICATE_IMPORT', mockContext);
      
      expect(mockApiError.conflict).toHaveBeenCalledWith(
        'This Instagram photo has already been imported to your wardrobe.',
        'INSTAGRAM_DUPLICATE_IMPORT',
        mockContext
      );
    });

    it('should handle UNSUPPORTED_MEDIA', () => {
      const result = InstagramApiError.fromBusinessRule('UNSUPPORTED_MEDIA', mockContext);
      
      expect(mockApiError.badRequest).toHaveBeenCalledWith(
        'This Instagram post type is not supported. Only photos can be imported.',
        'INSTAGRAM_UNSUPPORTED_MEDIA',
        mockContext
      );
    });

    it('should handle PRIVATE_ACCOUNT', () => {
      const result = InstagramApiError.fromBusinessRule('PRIVATE_ACCOUNT', mockContext);
      
      expect(mockApiError.forbidden).toHaveBeenCalledWith(
        'Cannot import from private Instagram accounts.',
        'INSTAGRAM_PRIVATE_ACCOUNT',
        mockContext
      );
    });

    it('should handle EXPIRED_MEDIA', () => {
      const result = InstagramApiError.fromBusinessRule('EXPIRED_MEDIA', mockContext);
      
      expect(mockApiError.notFound).toHaveBeenCalledWith(
        'This Instagram post is no longer available.',
        'INSTAGRAM_EXPIRED_MEDIA',
        mockContext
      );
    });

    it('should work without context', () => {
      const result = InstagramApiError.fromBusinessRule('DUPLICATE_IMPORT');
      
      expect(mockApiError.conflict).toHaveBeenCalledWith(
        'This Instagram photo has already been imported to your wardrobe.',
        'INSTAGRAM_DUPLICATE_IMPORT',
        undefined
      );
    });
  });

  describe('createServiceUnavailable', () => {
    it('should create service unavailable error with recovery time', () => {
      // Set a fixed current time for predictable testing
      const mockNow = new Date('2025-01-01T10:00:00Z');
      jest.spyOn(Date, 'now').mockReturnValue(mockNow.getTime());
      
      const recoveryTime = new Date('2025-01-01T10:15:00Z'); // 15 minutes from now
      
      const result = InstagramApiError.createServiceUnavailable(3, recoveryTime, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram services are temporarily unavailable. Please try again in approximately 15 minutes.',
        'INSTAGRAM_SERVICE_UNAVAILABLE',
        {
          ...mockContext,
          consecutiveFailures: 3,
          estimatedRecoveryTime: recoveryTime.toISOString()
        }
      );
      
      jest.restoreAllMocks();
    });

    it('should create service unavailable error without recovery time', () => {
      const result = InstagramApiError.createServiceUnavailable(2, undefined, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram services are temporarily unavailable. Please try again later.',
        'INSTAGRAM_SERVICE_UNAVAILABLE',
        {
          ...mockContext,
          consecutiveFailures: 2,
          estimatedRecoveryTime: undefined
        }
      );
    });

    it('should handle recovery time in the past', () => {
      // Set a fixed current time for predictable testing
      const mockNow = new Date('2025-01-01T10:00:00Z');
      jest.spyOn(Date, 'now').mockReturnValue(mockNow.getTime());
      
      const pastTime = new Date('2025-01-01T09:59:00Z'); // 1 minute ago
      
      const result = InstagramApiError.createServiceUnavailable(1, pastTime, mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram services are temporarily unavailable. Please try again in approximately 1 minutes.',
        'INSTAGRAM_SERVICE_UNAVAILABLE',
        expect.objectContaining({
          ...mockContext,
          consecutiveFailures: 1
        })
      );
      
      jest.restoreAllMocks();
    });

    it('should work with minimal parameters', () => {
      const result = InstagramApiError.createServiceUnavailable();
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram services are temporarily unavailable. Please try again later.',
        'INSTAGRAM_SERVICE_UNAVAILABLE',
        {
          consecutiveFailures: 0,
          estimatedRecoveryTime: undefined
        }
      );
    });
  });

  describe('createQueuedForRetry', () => {
    it('should create queued for retry error', () => {
      const result = InstagramApiError.createQueuedForRetry(mockContext);
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram is temporarily busy. We\'ve saved your request and will import this photo automatically when the service is available.',
        'INSTAGRAM_QUEUED_FOR_RETRY',
        mockContext
      );
    });

    it('should work without context', () => {
      const result = InstagramApiError.createQueuedForRetry();
      
      expect(mockApiError.serviceUnavailable).toHaveBeenCalledWith(
        'Instagram is temporarily busy. We\'ve saved your request and will import this photo automatically when the service is available.',
        'INSTAGRAM_QUEUED_FOR_RETRY',
        undefined
      );
    });
  });

  describe('isRetryable', () => {
    it('should return false for non-retryable errors', () => {
      const nonRetryableCodes = [
        'INSTAGRAM_INVALID_REQUEST',
        'INSTAGRAM_AUTH_EXPIRED',
        'INSTAGRAM_ACCESS_DENIED',
        'INSTAGRAM_MEDIA_NOT_FOUND',
        'INSTAGRAM_DUPLICATE_IMPORT',
        'INSTAGRAM_UNSUPPORTED_MEDIA',
        'INSTAGRAM_PRIVATE_ACCOUNT'
      ];

      nonRetryableCodes.forEach(code => {
        const error = { code } as ApiError;
        expect(InstagramApiError.isRetryable(error)).toBe(false);
      });
    });

    it('should return true for retryable errors', () => {
      const retryableCodes = [
        'INSTAGRAM_SERVER_ERROR',
        'INSTAGRAM_TIMEOUT',
        'INSTAGRAM_CONNECTION_ERROR',
        'INSTAGRAM_SERVICE_UNAVAILABLE',
        'INSTAGRAM_NETWORK_ERROR'
      ];

      retryableCodes.forEach(code => {
        const error = { code } as ApiError;
        expect(InstagramApiError.isRetryable(error)).toBe(true);
      });
    });
  });

  describe('getActionSuggestion', () => {
    it('should return correct action suggestions', () => {
      const suggestions = [
        ['INSTAGRAM_AUTH_EXPIRED', 'Go to Settings → Integrations → Reconnect Instagram'],
        ['INSTAGRAM_RATE_LIMITED', 'Wait a few minutes before importing more photos'],
        ['INSTAGRAM_CONNECTION_ERROR', 'Check your internet connection'],
        ['INSTAGRAM_INVALID_REQUEST', 'Check the Instagram post URL and try again'],
        ['INSTAGRAM_DUPLICATE_IMPORT', 'This photo is already in your wardrobe']
      ];

      suggestions.forEach(([code, expectedSuggestion]) => {
        const error = { code } as ApiError;
        expect(InstagramApiError.getActionSuggestion(error)).toBe(expectedSuggestion);
      });
    });

    it('should return null for codes without suggestions', () => {
      const error = { code: 'UNKNOWN_CODE' } as ApiError;
      expect(InstagramApiError.getActionSuggestion(error)).toBe(null);
    });
  });

  describe('getErrorCategory', () => {
    it('should categorize user errors correctly', () => {
      const userErrorCodes = [
        'INSTAGRAM_INVALID_REQUEST',
        'INSTAGRAM_AUTH_EXPIRED',
        'INSTAGRAM_DUPLICATE_IMPORT'
      ];

      userErrorCodes.forEach(code => {
        const error = { code } as ApiError;
        expect(InstagramApiError.getErrorCategory(error)).toBe('user_error');
      });
    });

    it('should categorize system errors correctly', () => {
      const systemErrorCodes = [
        'INSTAGRAM_QUEUED_FOR_RETRY'
      ];

      systemErrorCodes.forEach(code => {
        const error = { code } as ApiError;
        expect(InstagramApiError.getErrorCategory(error)).toBe('system_error');
      });
    });

    it('should categorize external errors correctly', () => {
      const externalErrorCodes = [
        'INSTAGRAM_SERVER_ERROR',
        'INSTAGRAM_TIMEOUT',
        'INSTAGRAM_CONNECTION_ERROR',
        'INSTAGRAM_SERVICE_UNAVAILABLE'
      ];

      externalErrorCodes.forEach(code => {
        const error = { code } as ApiError;
        expect(InstagramApiError.getErrorCategory(error)).toBe('external_error');
      });
    });
  });

  describe('createMonitoringEvent', () => {
    let mockError: ApiError;

    beforeEach(() => {
      mockError = {
        code: 'INSTAGRAM_SERVER_ERROR',
        message: 'Instagram server error',
        getSeverity: jest.fn().mockReturnValue('medium')
      } as unknown as ApiError;
    });

    it('should create comprehensive monitoring event', () => {
      const context = {
        ...mockContext,
        retryAttempt: 2
      };

      const result = InstagramApiError.createMonitoringEvent(mockError, context);
      
      expect(result).toEqual({
        category: 'external_error',
        severity: 'medium',
        retryable: true,
        context: {
          code: 'INSTAGRAM_SERVER_ERROR',
          message: 'Instagram server error',
          userId: 'user-123',
          timestamp: expect.any(String),
          retryAttempt: 2
        }
      });
      
      expect(mockError.getSeverity).toHaveBeenCalled();
    });

    it('should work without context', () => {
      const result = InstagramApiError.createMonitoringEvent(mockError);
      
      expect(result).toEqual({
        category: 'external_error',
        severity: 'medium',
        retryable: true,
        context: {
          code: 'INSTAGRAM_SERVER_ERROR',
          message: 'Instagram server error',
          userId: undefined,
          timestamp: expect.any(String),
          retryAttempt: undefined
        }
      });
    });

    it('should handle different error categories and severities', () => {
      const userError = {
        code: 'INSTAGRAM_INVALID_REQUEST',
        message: 'Invalid request',
        getSeverity: jest.fn().mockReturnValue('low')
      } as unknown as ApiError;

      const result = InstagramApiError.createMonitoringEvent(userError, mockContext);
      
      expect(result.category).toBe('user_error');
      expect(result.severity).toBe('low');
      expect(result.retryable).toBe(false);
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle malformed response objects', () => {
      const malformedResponse = {
        headers: null
      } as unknown as Response;

      const result = InstagramApiError.fromHttpStatus(429, malformedResponse, mockContext);
      
      // Should use default retry time when headers are not accessible
      expect(mockApiError.rateLimited).toHaveBeenCalledWith(
        'Instagram rate limit reached. Please wait 5 minutes before importing more photos.',
        undefined,
        undefined,
        300
      );
    });

    it('should handle response with invalid retry-after header', () => {
      const mockResponse = {
        headers: {
          get: jest.fn().mockImplementation((header) => {
            return header === 'retry-after' ? 'invalid-number' : null;
          })
        }
      } as unknown as Response;

      const result = InstagramApiError.fromHttpStatus(429, mockResponse, mockContext);
      
      // Should use default retry time when header is invalid
      expect(mockApiError.rateLimited).toHaveBeenCalledWith(
        'Instagram rate limit reached. Please wait 5 minutes before importing more photos.',
        undefined,
        undefined,
        300
      );
    });

    it('should handle very large retry-after values', () => {
      const mockResponse = {
        headers: {
          get: jest.fn().mockImplementation((header) => {
            return header === 'retry-after' ? '86400' : null; // 24 hours
          })
        }
      } as unknown as Response;

      const result = InstagramApiError.fromHttpStatus(429, mockResponse, mockContext);
      
      expect(mockApiError.rateLimited).toHaveBeenCalledWith(
        'Instagram rate limit reached. Please wait 1440 minutes before trying again.',
        undefined,
        undefined,
        86400
      );
    });

    it('should handle context with all optional fields', () => {
      const fullContext: InstagramErrorContext = {
        url: 'https://instagram.com/test',
        userId: 'user-123',
        mediaId: 'media-456',
        rateLimitInfo: {
          limit: 100,
          remaining: 0,
          resetTime: new Date('2025-01-01T11:00:00Z')
        },
        retryAttempt: 3,
        timestamp: new Date('2025-01-01T10:00:00Z')
      };

      const result = InstagramApiError.fromBusinessRule('DUPLICATE_IMPORT', fullContext);
      
      expect(mockApiError.conflict).toHaveBeenCalledWith(
        'This Instagram photo has already been imported to your wardrobe.',
        'INSTAGRAM_DUPLICATE_IMPORT',
        fullContext
      );
    });
  });
});