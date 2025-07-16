// /shared/src/schemas/index.ts

// User schemas
export * from './user';

// Garment schemas
export * from './garment';

// Wardrobe schemas
export * from './wardrobe';

// Image schemas
export * from './image';

// Export schemas
export * from './export';

// Polygon schemas
export * from './polygon';

// OAuth schemas
export * from './oauth';

// Base schemas
export * from './base/common';

// API schemas
export * from './api';

// Validator schemas
export * from './validator';

// Flutter-specific type helpers for JSON serialization
export interface FlutterSerializable {
  toJson(): Record<string, any>;
}

// Helper type for nullable fields in Flutter
export type Nullable<T> = T | null;

// Helper type for optional fields in Flutter
export type Optional<T> = T | undefined;

// Mobile-specific pagination params
export interface MobilePaginationParams {
  page: number;
  limit: number;
  cached?: boolean;
  lastSyncTimestamp?: string;
}

// Mobile-specific response wrapper
export interface MobileResponse<T> {
  data: T;
  metadata: {
    timestamp: string;
    version: string;
    cached: boolean;
    syncRequired?: boolean;
  };
}

// Flutter model generation hints
export interface FlutterModelHints {
  freezed?: boolean;
  jsonSerializable?: boolean;
  copyWith?: boolean;
  equatable?: boolean;
}

// Type conversion utilities for Dart compatibility
export const TypeConverters = {
  // Convert JavaScript Date to ISO string for Dart DateTime
  dateToString: (date: Date | string | null): string | null => {
    if (!date) return null;
    return typeof date === 'string' ? date : date.toISOString();
  },
  
  // Convert string to Date for JavaScript usage
  stringToDate: (dateString: string | null): Date | null => {
    if (!dateString) return null;
    return new Date(dateString);
  },
  
  // Ensure number types for Dart compatibility
  ensureNumber: (value: any): number | null => {
    if (value === null || value === undefined) return null;
    const num = Number(value);
    return isNaN(num) ? null : num;
  },
  
  // Ensure boolean types for Dart compatibility
  ensureBoolean: (value: any): boolean => {
    return Boolean(value);
  }
};

// Mobile-specific validation rules
export const MobileValidation = {
  // Max file size for mobile uploads (5MB)
  MAX_MOBILE_FILE_SIZE: 5 * 1024 * 1024,
  
  // Max string length for mobile text fields
  MAX_MOBILE_TEXT_LENGTH: 500,
  
  // Max array length for mobile lists
  MAX_MOBILE_ARRAY_LENGTH: 100,
  
  // Supported image formats for mobile
  MOBILE_IMAGE_FORMATS: ['jpeg', 'jpg', 'png', 'webp'] as const,
  
  // Mobile-specific regex patterns
  MOBILE_PATTERNS: {
    deviceId: /^[a-zA-Z0-9\-_]{16,128}$/,
    biometricId: /^[a-zA-Z0-9\-_]{32,256}$/,
    pushToken: /^[a-zA-Z0-9\-_:]{32,512}$/
  }
};

// Export format optimizations for mobile
export const MobileExportFormats = {
  IMAGE_THUMBNAIL: { width: 150, height: 150, quality: 0.7 },
  IMAGE_PREVIEW: { width: 600, height: 600, quality: 0.8 },
  IMAGE_FULL: { width: 1200, height: 1200, quality: 0.9 },
  BATCH_SIZE: 20,
  CHUNK_SIZE: 1024 * 1024 // 1MB chunks for progressive download
} as const;

// Re-export specific schemas that are used in routes
export { BiometricLoginSchema, DeviceRegistrationSchema } from './user';