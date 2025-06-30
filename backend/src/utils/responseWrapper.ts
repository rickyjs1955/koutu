// backend/src/utils/responseWrapper.ts
import { Response, Request } from 'express';

/**
 * Standard success response structure for Flutter compatibility
 */
export interface SuccessResponse<T = any> {
  success: true;
  data: T;
  message?: string;
  meta?: ResponseMeta;
  timestamp: string;
  requestId: string;
}

/**
 * Pagination metadata for list responses
 */
export interface PaginationMeta {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

/**
 * Additional metadata that can be included in responses
 */
export interface ResponseMeta {
  pagination?: PaginationMeta;
  filters?: Record<string, any>;
  sort?: {
    field: string;
    order: 'asc' | 'desc';
  };
  version?: string;
  cached?: boolean;
  processingTime?: number;
  [key: string]: any;
}

/**
 * Options for creating responses
 */
export interface ResponseOptions {
  message?: string;
  meta?: ResponseMeta;
  statusCode?: number;
}

/**
 * Response wrapper class for creating consistent API responses
 */
export class ResponseWrapper {
  private req: Request;
  private res: Response;
  private startTime: number;

  constructor(req: Request, res: Response) {
    this.req = req;
    this.res = res;
    this.startTime = Date.now();
  }

  /**
   * Get request ID from headers or generate one
   */
  private getRequestId(): string {
    return this.req.get('X-Request-ID') || this.generateRequestId();
  }

  /**
   * Generate a unique request ID
   */
  private generateRequestId(): string {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Calculate processing time since wrapper creation
   */
  private getProcessingTime(): number {
    return Date.now() - this.startTime;
  }

  /**
   * Send a success response
   */
  success<T>(data: T, options: ResponseOptions = {}): Response {
    const {
      message,
      meta = {},
      statusCode = 200
    } = options;

    // Add processing time to meta if not already present
    if (!meta.processingTime) {
      meta.processingTime = this.getProcessingTime();
    }

    const response: SuccessResponse<T> = {
      success: true,
      data,
      timestamp: new Date().toISOString(),
      requestId: this.getRequestId(),
      ...(message && { message }),
      ...(Object.keys(meta).length > 0 && { meta })
    };

    return this.res.status(statusCode).json(response);
  }

  /**
   * Send a paginated list response
   */
  successWithPagination<T>(
    data: T[],
    pagination: PaginationMeta,
    options: Omit<ResponseOptions, 'meta'> & { meta?: Omit<ResponseMeta, 'pagination'> } = {}
  ): Response {
    const { message, meta = {}, statusCode = 200 } = options;

    const responseOptions: ResponseOptions = {
      message,
      statusCode,
      meta: {
        ...meta,
        pagination,
        processingTime: this.getProcessingTime()
      }
    };

    return this.success(data, responseOptions);
  }

  /**
   * Send a created resource response (201)
   */
  created<T>(data: T, options: Omit<ResponseOptions, 'statusCode'> = {}): Response {
    return this.success(data, { ...options, statusCode: 201 });
  }

  /**
   * Send an accepted response (202) for async operations
   */
  accepted<T>(data: T, options: Omit<ResponseOptions, 'statusCode'> = {}): Response {
    const defaultMessage = 'Request accepted for processing';
    return this.success(data, { 
      message: defaultMessage,
      ...options, 
      statusCode: 202 
    });
  }

  /**
   * Send a no content response (204)
   */
  noContent(): Response {
    return this.res.status(204).send();
  }
}

/**
 * Utility functions for creating responses without the wrapper class
 */
export class ResponseUtils {
  /**
   * Create a success response object (without sending)
   */
  static createSuccessResponse<T>(
    data: T,
    requestId: string,
    options: ResponseOptions = {}
  ): SuccessResponse<T> {
    const { message, meta = {} } = options;

    return {
      success: true,
      data,
      timestamp: new Date().toISOString(),
      requestId,
      ...(message && { message }),
      ...(Object.keys(meta).length > 0 && { meta })
    };
  }

  /**
   * Create pagination metadata
   */
  static createPagination(
    page: number,
    limit: number,
    total: number
  ): PaginationMeta {
    const totalPages = Math.ceil(total / limit);
    
    return {
      page,
      limit,
      total,
      totalPages,
      hasNext: page < totalPages,
      hasPrev: page > 1
    };
  }

  /**
   * Validate pagination parameters
   */
  static validatePagination(page?: any, limit?: any): { page: number; limit: number } {
    const defaultPage = 1;
    const defaultLimit = 20;
    const maxLimit = 100;

    const validPage = Math.max(1, parseInt(page) || defaultPage);
    const validLimit = Math.min(maxLimit, Math.max(1, parseInt(limit) || defaultLimit));

    return { page: validPage, limit: validLimit };
  }
}

/**
 * Express middleware to add response wrapper to request object
 */
export const responseWrapperMiddleware = (req: Request, res: Response, next: any) => {
  // Add wrapper instance to request object
  (req as any).responseWrapper = new ResponseWrapper(req, res);
  
  // Add utility methods directly to response object for convenience
  res.success = function<T>(data: T, options: ResponseOptions = {}) {
    return (req as any).responseWrapper.success(data, options);
  };

  res.successWithPagination = function<T>(
    data: T[], 
    pagination: PaginationMeta, 
    options: Omit<ResponseOptions, 'meta'> & { meta?: Omit<ResponseMeta, 'pagination'> } = {}
  ) {
    return (req as any).responseWrapper.successWithPagination(data, pagination, options);
  };

  res.created = function<T>(data: T, options: Omit<ResponseOptions, 'statusCode'> = {}) {
    return (req as any).responseWrapper.created(data, options);
  };

  res.accepted = function<T>(data: T, options: Omit<ResponseOptions, 'statusCode'> = {}) {
    return (req as any).responseWrapper.accepted(data, options);
  };

  res.noContent = function() {
    return (req as any).responseWrapper.noContent();
  };

  next();
};

/**
 * Extend Express Response interface to include our methods
 */
declare global {
  namespace Express {
    interface Response {
      success<T>(data: T, options?: ResponseOptions): Response;
      successWithPagination<T>(
        data: T[], 
        pagination: PaginationMeta, 
        options?: Omit<ResponseOptions, 'meta'> & { meta?: Omit<ResponseMeta, 'pagination'> }
      ): Response;
      created<T>(data: T, options?: Omit<ResponseOptions, 'statusCode'>): Response;
      accepted<T>(data: T, options?: Omit<ResponseOptions, 'statusCode'>): Response;
      noContent(): Response;
    }
  }
}

/**
 * Common response messages
 */
export const ResponseMessages = {
  // CRUD Operations
  CREATED: 'Resource created successfully',
  UPDATED: 'Resource updated successfully',
  DELETED: 'Resource deleted successfully',
  RETRIEVED: 'Resource retrieved successfully',
  
  // List Operations
  LIST_RETRIEVED: 'Resources retrieved successfully',
  SEARCH_COMPLETED: 'Search completed successfully',
  
  // Authentication & Authorization
  LOGIN_SUCCESS: 'Login successful',
  LOGOUT_SUCCESS: 'Logout successful',
  PASSWORD_CHANGED: 'Password changed successfully',
  PROFILE_UPDATED: 'Profile updated successfully',
  
  // File Operations
  FILE_UPLOADED: 'File uploaded successfully',
  FILE_DELETED: 'File deleted successfully',
  
  // Async Operations
  PROCESSING_STARTED: 'Processing started successfully',
  TASK_QUEUED: 'Task queued for processing',
  
  // Generic
  SUCCESS: 'Operation completed successfully',
  NO_CONTENT: 'No content available'
} as const;

/**
 * Helper function for controllers to create consistent responses
 */
export const createResponse = {
  /**
   * Success response for single resource
   */
  success: <T>(data: T, message?: string, meta?: ResponseMeta) => ({
    data,
    message: message || ResponseMessages.SUCCESS,
    meta
  }),

  /**
   * Success response for resource creation
   */
  created: <T>(data: T, message?: string) => ({
    data,
    message: message || ResponseMessages.CREATED,
    statusCode: 201
  }),

  /**
   * Success response for resource list
   */
  list: <T>(data: T[], pagination?: PaginationMeta, message?: string) => ({
    data,
    message: message || ResponseMessages.LIST_RETRIEVED,
    ...(pagination && { pagination })
  }),

  /**
   * Success response for async operations
   */
  async: <T>(data: T, message?: string) => ({
    data,
    message: message || ResponseMessages.PROCESSING_STARTED,
    statusCode: 202
  })
};

/**
 * Type-safe response helpers for common patterns
 */
export class TypedResponse {
  /**
   * User-related responses
   */
  static user = {
    profile: (user: any) => createResponse.success(user, ResponseMessages.RETRIEVED),
    created: (user: any) => createResponse.created(user, 'User created successfully'),
    updated: (user: any) => createResponse.success(user, ResponseMessages.UPDATED),
    list: (users: any[], pagination?: PaginationMeta) => 
      createResponse.list(users, pagination, 'Users retrieved successfully')
  };

  /**
   * Authentication responses
   */
  static auth = {
    login: (data: { user: any; token: string; refreshToken?: string }) => 
      createResponse.success(data, ResponseMessages.LOGIN_SUCCESS),
    logout: () => createResponse.success({}, ResponseMessages.LOGOUT_SUCCESS),
    refresh: (tokens: { token: string; refreshToken?: string }) => 
      createResponse.success(tokens, 'Tokens refreshed successfully')
  };

  /**
   * File operation responses
   */
  static file = {
    uploaded: (fileInfo: any) => createResponse.success(fileInfo, ResponseMessages.FILE_UPLOADED),
    deleted: () => createResponse.success({}, ResponseMessages.FILE_DELETED),
    list: (files: any[], pagination?: PaginationMeta) => 
      createResponse.list(files, pagination, 'Files retrieved successfully')
  };
}

export default ResponseWrapper;