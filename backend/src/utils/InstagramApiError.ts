// /backend/src/utils/InstagramApiError.ts
// Dedicated Instagram API error handling with user-friendly messages

import { ApiError } from './ApiError';

export interface InstagramErrorContext {
  url?: string;
  userId?: string;
  mediaId?: string;
  rateLimitInfo?: {
    limit: number;
    remaining: number;
    resetTime: Date;
  };
  retryAttempt?: number;
  timestamp?: Date;
}

export class InstagramApiError {
  
  /**
   * Map HTTP status codes to user-friendly Instagram errors
   */
  static fromHttpStatus(
    status: number, 
    response?: Response, 
    context?: InstagramErrorContext
  ): ApiError {
    switch (status) {
      case 400:
        return this.createBadRequestError(response, context);
      case 401:
        return this.createAuthError(context);
      case 403:
        return this.createForbiddenError(context);
      case 404:
        return this.createNotFoundError(context);
      case 429:
        return this.createRateLimitError(response, context);
      case 500:
      case 502:
      case 503:
      case 504:
        return this.createServerError(status, context);
      default:
        return this.createUnknownError(status, context);
    }
  }

  /**
   * Handle network/connection errors
   */
  static fromNetworkError(error: Error, context?: InstagramErrorContext): ApiError {
    switch (error.name) {
      case 'AbortError':
        return this.createTimeoutError(context);
      case 'TypeError':
        if (error.message.includes('fetch')) {
          return this.createConnectionError(context);
        }
        break;
    }

    // Handle specific error codes
    const errorCode = (error as any).code;
    switch (errorCode) {
      case 'ENOTFOUND':
      case 'ECONNREFUSED':
      case 'ECONNRESET':
        return this.createConnectionError(context);
      case 'ETIMEDOUT':
        return this.createTimeoutError(context);
      default:
        return this.createNetworkError(error, context);
    }
  }

  /**
   * Handle Instagram API business logic errors
   */
  static fromBusinessRule(
    rule: 'DUPLICATE_IMPORT' | 'UNSUPPORTED_MEDIA' | 'PRIVATE_ACCOUNT' | 'EXPIRED_MEDIA',
    context?: InstagramErrorContext
  ): ApiError {
    switch (rule) {
      case 'DUPLICATE_IMPORT':
        return ApiError.conflict(
          'This Instagram photo has already been imported to your wardrobe.',
          'INSTAGRAM_DUPLICATE_IMPORT',
          context
        );
      
      case 'UNSUPPORTED_MEDIA':
        return ApiError.badRequest(
          'This Instagram post type is not supported. Only photos can be imported.',
          'INSTAGRAM_UNSUPPORTED_MEDIA',
          context
        );
      
      case 'PRIVATE_ACCOUNT':
        return ApiError.forbidden(
          'Cannot import from private Instagram accounts.',
          'INSTAGRAM_PRIVATE_ACCOUNT',
          context
        );
      
      case 'EXPIRED_MEDIA':
        return ApiError.notFound(
          'This Instagram post is no longer available.',
          'INSTAGRAM_EXPIRED_MEDIA',
          context
        );
      
      default:
        return ApiError.badRequest(
          'Instagram import validation failed.',
          'INSTAGRAM_BUSINESS_RULE_ERROR',
          context
        );
    }
  }

  /**
   * Create service unavailable error with retry information
   */
  static createServiceUnavailable(
    consecutiveFailures: number = 0,
    estimatedRecoveryTime?: Date,
    context?: InstagramErrorContext
  ): ApiError {
    let message = 'Instagram services are temporarily unavailable.';
    
    if (estimatedRecoveryTime) {
      const minutes = Math.ceil((estimatedRecoveryTime.getTime() - Date.now()) / 60000);
      message += ` Please try again in approximately ${minutes} minutes.`;
    } else {
      message += ' Please try again later.';
    }

    return ApiError.serviceUnavailable(
      message,
      'INSTAGRAM_SERVICE_UNAVAILABLE',
      {
        ...context,
        consecutiveFailures,
        estimatedRecoveryTime: estimatedRecoveryTime?.toISOString()
      }
    );
  }

  /**
   * Create queued for retry error (user-friendly)
   */
  static createQueuedForRetry(context?: InstagramErrorContext): ApiError {
    return ApiError.serviceUnavailable(
      'Instagram is temporarily busy. We\'ve saved your request and will import this photo automatically when the service is available.',
      'INSTAGRAM_QUEUED_FOR_RETRY',
      context
    );
  }

  // Private helper methods for specific error types

  private static createBadRequestError(response?: Response, context?: InstagramErrorContext): ApiError {
    return ApiError.badRequest(
      'The Instagram photo URL is invalid or the post cannot be accessed.',
      'INSTAGRAM_INVALID_REQUEST',
      context
    );
  }

  private static createAuthError(context?: InstagramErrorContext): ApiError {
    return ApiError.unauthorized(
      'Your Instagram connection has expired. Please go to Settings and reconnect your Instagram account.',
      'INSTAGRAM_AUTH_EXPIRED',
      {
        ...context,
        userAction: 'reconnect_instagram',
        redirectTo: '/settings/integrations'
      }
    );
  }

  private static createForbiddenError(context?: InstagramErrorContext): ApiError {
    return ApiError.forbidden(
      'Access denied to this Instagram post. The post may be private or you may not have permission to view it.',
      'INSTAGRAM_ACCESS_DENIED',
      context
    );
  }

  private static createNotFoundError(context?: InstagramErrorContext): ApiError {
    return ApiError.notFound(
      'Instagram post not found. The post may have been deleted or the URL is incorrect.',
      'INSTAGRAM_MEDIA_NOT_FOUND',
      context
    );
  }

  private static createRateLimitError(response?: Response, context?: InstagramErrorContext): ApiError {
    // Extract rate limit info from headers
    const retryAfter = response?.headers.get('retry-after');
    const resetTime = response?.headers.get('x-ratelimit-reset');
    const remaining = response?.headers.get('x-ratelimit-remaining');
    
    const waitTime = retryAfter ? parseInt(retryAfter) : 300; // Default 5 minutes
    const waitMinutes = Math.ceil(waitTime / 60);
    
    const message = waitMinutes <= 5
      ? `Instagram rate limit reached. Please wait ${waitMinutes} minutes before importing more photos.`
      : `Instagram rate limit reached. Please wait ${waitMinutes} minutes before trying again.`;

    return ApiError.rateLimited(
      message,
      undefined,
      undefined,
      waitTime
    );
  }

  private static createServerError(status: number, context?: InstagramErrorContext): ApiError {
    const statusMessages: Record<number, string> = {
      500: 'Instagram is experiencing server issues.',
      502: 'Instagram gateway error.',
      503: 'Instagram service temporarily unavailable.',
      504: 'Instagram request timed out.'
    };

    const message = statusMessages[status] || 'Instagram server error.';
    
    return ApiError.serviceUnavailable(
      `${message} Please try again in a few minutes.`,
      'INSTAGRAM_SERVER_ERROR',
      {
        ...context,
        httpStatus: status
      }
    );
  }

  private static createTimeoutError(context?: InstagramErrorContext): ApiError {
    return ApiError.serviceUnavailable(
      'Instagram request timed out. The service may be slow right now. Please try again.',
      'INSTAGRAM_TIMEOUT',
      context
    );
  }

  private static createConnectionError(context?: InstagramErrorContext): ApiError {
    return ApiError.serviceUnavailable(
      'Unable to connect to Instagram. Please check your internet connection and try again.',
      'INSTAGRAM_CONNECTION_ERROR',
      context
    );
  }

  private static createNetworkError(error: Error, context?: InstagramErrorContext): ApiError {
    return ApiError.serviceUnavailable(
      'Network error while connecting to Instagram. Please try again.',
      'INSTAGRAM_NETWORK_ERROR',
      {
        ...context,
        originalError: error.message
      }
    );
  }

  private static createUnknownError(status: number, context?: InstagramErrorContext): ApiError {
    return ApiError.externalService(
      `Instagram returned an unexpected response (${status}). Please try again later.`,
      'instagram_api',
      new Error(`HTTP ${status}`)
    );
  }

  /**
   * Check if an error is retryable
   */
  static isRetryable(error: ApiError): boolean {
    const nonRetryableCodes = [
      'INSTAGRAM_INVALID_REQUEST',
      'INSTAGRAM_AUTH_EXPIRED',
      'INSTAGRAM_ACCESS_DENIED',
      'INSTAGRAM_MEDIA_NOT_FOUND',
      'INSTAGRAM_DUPLICATE_IMPORT',
      'INSTAGRAM_UNSUPPORTED_MEDIA',
      'INSTAGRAM_PRIVATE_ACCOUNT'
    ];

    return !nonRetryableCodes.includes(error.code);
  }

  /**
   * Get user-friendly action suggestions
   */
  static getActionSuggestion(error: ApiError): string | null {
    const actionMap: Record<string, string> = {
      'INSTAGRAM_AUTH_EXPIRED': 'Go to Settings → Integrations → Reconnect Instagram',
      'INSTAGRAM_RATE_LIMITED': 'Wait a few minutes before importing more photos',
      'INSTAGRAM_CONNECTION_ERROR': 'Check your internet connection',
      'INSTAGRAM_INVALID_REQUEST': 'Check the Instagram post URL and try again',
      'INSTAGRAM_DUPLICATE_IMPORT': 'This photo is already in your wardrobe'
    };

    return actionMap[error.code] || null;
  }

  /**
   * Get error category for analytics/monitoring
   */
  static getErrorCategory(error: ApiError): 'user_error' | 'system_error' | 'external_error' {
    const userErrorCodes = [
      'INSTAGRAM_INVALID_REQUEST',
      'INSTAGRAM_AUTH_EXPIRED',
      'INSTAGRAM_DUPLICATE_IMPORT'
    ];

    const systemErrorCodes = [
      'INSTAGRAM_QUEUED_FOR_RETRY'
    ];

    if (userErrorCodes.includes(error.code)) {
      return 'user_error';
    }
    
    if (systemErrorCodes.includes(error.code)) {
      return 'system_error';
    }
    
    return 'external_error';
  }

  /**
   * Create error for monitoring/logging (sanitized)
   */
  static createMonitoringEvent(error: ApiError, context?: InstagramErrorContext): {
    category: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    retryable: boolean;
    context: any;
  } {
    return {
      category: this.getErrorCategory(error),
      severity: error.getSeverity(),
      retryable: this.isRetryable(error),
      context: {
        code: error.code,
        message: error.message,
        userId: context?.userId,
        timestamp: new Date().toISOString(),
        retryAttempt: context?.retryAttempt
      }
    };
  }
}