// /backend/src/services/InstagramApiService.ts
// Updated to use dedicated InstagramApiError handler

import { InstagramApiError, InstagramErrorContext } from '../utils/InstagramApiError';
import { ApiError } from '../utils/ApiError';
import { storageService } from './storageService';
import { imageModel } from '../models/imageModel';
import { query } from '../models/db';
import sharp from 'sharp';

interface InstagramAPIHealth {
  isAvailable: boolean;
  lastChecked: Date;
  consecutiveFailures: number;
  estimatedRecoveryTime?: Date;
}

export class InstagramAPIService {
  private healthStatus: InstagramAPIHealth = {
    isAvailable: true,
    lastChecked: new Date(),
    consecutiveFailures: 0
  };

  /**
   * Import Instagram image with clean error handling
   */
  async importInstagramImage(instagramMediaUrl: string, userId: string) {
    const context: InstagramErrorContext = {
      url: instagramMediaUrl,
      userId,
      timestamp: new Date()
    };

    try {
      // Pre-flight health check
      await this.checkInstagramAPIHealth();

      // Validate URL format
      if (!this.isValidInstagramMediaUrl(instagramMediaUrl)) {
        throw InstagramApiError.fromBusinessRule('UNSUPPORTED_MEDIA', context);
      }

      // Check for duplicates
      if (await this.isDuplicateImport(instagramMediaUrl, userId)) {
        throw InstagramApiError.fromBusinessRule('DUPLICATE_IMPORT', context);
      }

      // Attempt import with retry
      const result = await this.withRetry(
        () => this.performImport(instagramMediaUrl, userId, context),
        3, // maxRetries
        context
      );

      // Mark success
      this.markAPIHealthy();
      return result;

    } catch (error) {
      return this.handleImportError(error, context);
    }
  }

  /**
   * Fetch Instagram image with comprehensive error mapping
   */
  private async fetchInstagramImageWithErrorHandling(
    url: string, 
    context: InstagramErrorContext
  ): Promise<Buffer> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000);

      const response = await fetch(url, {
        headers: {
          'User-Agent': 'YourApp/1.0',
          'Accept': 'image/*'
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      // Use dedicated error handler for HTTP status codes
      if (!response.ok) {
        throw InstagramApiError.fromHttpStatus(response.status, response, context);
      }

      // Validate content type
      const contentType = response.headers.get('content-type');
      if (!contentType?.startsWith('image/')) {
        throw ApiError.badRequest(
          `Expected image from Instagram, got ${contentType}`,
          'INSTAGRAM_INVALID_CONTENT',
          context
        );
      }

      const buffer = Buffer.from(await response.arrayBuffer());
      
      if (buffer.length === 0) {
        throw InstagramApiError.fromBusinessRule('EXPIRED_MEDIA', context);
      }

      return buffer;

    } catch (error) {
      // Use dedicated error handler for network errors
      if (!(error instanceof ApiError)) {
        throw InstagramApiError.fromNetworkError(error as Error, context);
      }
      throw error;
    }
  }

  /**
   * Perform import with clean error context
   */
  private async performImport(
    instagramMediaUrl: string, 
    userId: string, 
    context: InstagramErrorContext
  ) {
    // Fetch image
    const imageBuffer = await this.fetchInstagramImageWithErrorHandling(instagramMediaUrl, context);
    
    // Validate image
    const validation = await this.validateInstagramAPIImage(imageBuffer, instagramMediaUrl);
    
    if (!validation.isValid) {
      throw ApiError.badRequest(
        `Instagram image validation failed: ${validation.errors?.join(', ')}`,
        'INSTAGRAM_VALIDATION_ERROR',
        context
      );
    }

    // Save image
    return await this.saveInstagramImage(imageBuffer, validation.metadata, userId);
  }

  /**
   * Retry mechanism with dedicated error handling
   */
  private async withRetry<T>(
    operation: () => Promise<T>,
    maxRetries: number,
    context: InstagramErrorContext
  ): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        context.retryAttempt = attempt;
        return await operation();
      } catch (error) {
        lastError = error as Error;
        
        // Use InstagramApiError to determine if retryable
        if (error instanceof ApiError && !InstagramApiError.isRetryable(error)) {
          throw error;
        }
        
        if (attempt === maxRetries) {
          break;
        }
        
        // Exponential backoff
        const delay = Math.min(1000 * Math.pow(2, attempt), 30000);
        console.warn(`Instagram API attempt ${attempt + 1} failed, retrying in ${delay}ms:`, error);
        await this.sleep(delay);
      }
    }
    
    throw lastError!;
  }

  /**
   * Centralized error handling with fallback strategies
   */
  private async handleImportError(error: unknown, context: InstagramErrorContext) {
    const err = error instanceof Error ? error : new Error(String(error));
    
    // Log for monitoring
    if (error instanceof ApiError) {
      const monitoringEvent = InstagramApiError.createMonitoringEvent(error, context);
      console.warn('Instagram import error:', monitoringEvent);
    } else {
      console.error('Unexpected Instagram import error:', err.message);
    }

    // Handle specific error scenarios
    if (error instanceof ApiError) {
      switch (error.code) {
        case 'INSTAGRAM_SERVICE_UNAVAILABLE':
        case 'INSTAGRAM_SERVER_ERROR':
        case 'INSTAGRAM_TIMEOUT':
        case 'INSTAGRAM_CONNECTION_ERROR':
          // Queue for retry
          await this.saveFailedImportForRetry(context.url!, context.userId!);
          throw InstagramApiError.createQueuedForRetry(context);
          
        case 'INSTAGRAM_AUTH_EXPIRED':
          // Clear any cached tokens
          await this.clearUserInstagramAuth(context.userId!);
          throw error;
          
        case 'INSTAGRAM_RATE_LIMITED':
          // Track rate limiting for this user
          await this.trackRateLimit(context.userId!);
          throw error;
          
        default:
          throw error;
      }
    }

    // Fallback for unknown errors
    throw InstagramApiError.fromNetworkError(err, context);
  }

  /**
   * Health check with dedicated error handling
   */
  private async checkInstagramAPIHealth(): Promise<void> {
    const timeSinceLastCheck = Date.now() - this.healthStatus.lastChecked.getTime();
    if (this.healthStatus.isAvailable && timeSinceLastCheck < 60000) {
      return;
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      const response = await fetch('https://graph.instagram.com/', {
        method: 'HEAD',
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);

      if (response.ok) {
        this.markAPIHealthy();
      } else {
        throw new Error(`Health check failed: ${response.status}`);
      }
    } catch (error) {
      this.markAPIUnhealthy();
      
      if (this.healthStatus.consecutiveFailures >= 5) {
        throw InstagramApiError.createServiceUnavailable(
          this.healthStatus.consecutiveFailures,
          this.healthStatus.estimatedRecoveryTime
        );
      }
    }
  }

  // Helper methods with cleaner error handling

  private async isDuplicateImport(url: string, userId: string): Promise<boolean> {
    try {
      const existing = await query(
        'SELECT id FROM original_images WHERE user_id = $1 AND original_metadata->>\'source_url\' = $2',
        [userId, url]
      );
      return existing.rows.length > 0;
    } catch (error) {
      console.warn('Error checking for duplicate import:', error);
      return false; // Don't block import on check failure
    }
  }

  private async saveFailedImportForRetry(url: string, userId: string): Promise<void> {
    try {
      await query(
        `INSERT INTO failed_instagram_imports (user_id, instagram_url, created_at, retry_count) 
         VALUES ($1, $2, NOW(), 0)
         ON CONFLICT (user_id, instagram_url) DO NOTHING`,
        [userId, url]
      );
    } catch (error) {
      console.error('Failed to save import for retry:', error);
    }
  }

  private async clearUserInstagramAuth(userId: string): Promise<void> {
    try {
      // Clear cached Instagram tokens/auth
      await query(
        'DELETE FROM user_instagram_tokens WHERE user_id = $1',
        [userId]
      );
    } catch (error) {
      console.warn('Error clearing Instagram auth:', error);
    }
  }

  private async trackRateLimit(userId: string): Promise<void> {
    try {
      // Track rate limiting for analytics
      await query(
        `INSERT INTO instagram_rate_limits (user_id, hit_at) VALUES ($1, NOW())`,
        [userId]
      );
    } catch (error) {
      console.warn('Error tracking rate limit:', error);
    }
  }

  private markAPIHealthy(): void {
    this.healthStatus = {
      isAvailable: true,
      lastChecked: new Date(),
      consecutiveFailures: 0
    };
  }

  private markAPIUnhealthy(): void {
    this.healthStatus.consecutiveFailures++;
    this.healthStatus.lastChecked = new Date();
    
    if (this.healthStatus.consecutiveFailures >= 3) {
      this.healthStatus.isAvailable = false;
      const recoveryMinutes = Math.min(this.healthStatus.consecutiveFailures * 5, 60);
      this.healthStatus.estimatedRecoveryTime = new Date(Date.now() + recoveryMinutes * 60000);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  private isValidInstagramMediaUrl(url: string): boolean {
    const instagramUrlPatterns = [
      /^https:\/\/scontent[^.]*\.cdninstagram\.com\//,
      /^https:\/\/instagram\.[^.]*\.fbcdn\.net\//,
      /^https:\/\/scontent[^.]*\.xx\.fbcdn\.net\//
    ];
    return instagramUrlPatterns.some(pattern => pattern.test(url));
  }

  // Your existing validation and save methods...
  private async validateInstagramAPIImage(buffer: Buffer, sourceUrl: string) {
    // Your existing validation logic
    return { isValid: true, metadata: {}, errors: [] as string[] };
  }

  private async saveInstagramImage(buffer: Buffer, metadata: any, userId: string) {
    // Your existing save logic
    return {};
  }
}

// Export singleton instance
export const instagramAPIService = new InstagramAPIService();