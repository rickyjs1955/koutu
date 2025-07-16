// /shared/src/schemas/image.ts
import { z } from 'zod';

// Define mobile constants locally to avoid circular dependency
const MAX_MOBILE_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const MAX_MOBILE_ARRAY_LENGTH = 100;
const BATCH_SIZE = 20;
const CHUNK_SIZE = 1024 * 1024; // 1MB

// Mobile-specific image resolution variants
export const ImageVariantSchema = z.object({
  thumbnail: z.object({
    url: z.string().url(),
    width: z.number().int(),
    height: z.number().int(),
    size: z.number().int() // bytes
  }).optional(),
  preview: z.object({
    url: z.string().url(),
    width: z.number().int(),
    height: z.number().int(),
    size: z.number().int()
  }).optional(),
  full: z.object({
    url: z.string().url(),
    width: z.number().int(),
    height: z.number().int(),
    size: z.number().int()
  }).optional(),
  webp: z.object({ // WebP variant for modern mobile browsers
    url: z.string().url(),
    width: z.number().int(),
    height: z.number().int(),
    size: z.number().int()
  }).optional()
});

// Enhanced image metadata with mobile considerations
export const EnhancedImageMetadataSchema = z.object({
  filename: z.string().max(255),
  original_filename: z.string().max(255).optional(),
  mimetype: z.string(),
  size: z.number().int(), // Original file size in bytes
  width: z.number().int(),
  height: z.number().int(),
  format: z.enum(['jpeg', 'jpg', 'png', 'webp', 'gif', 'heic', 'heif']),
  orientation: z.number().int().min(1).max(8).optional(), // EXIF orientation
  has_transparency: z.boolean().optional(),
  color_space: z.enum(['srgb', 'rgb', 'cmyk', 'gray']).optional(),
  dpi: z.number().optional(),
  capture_date: z.date().optional(), // From EXIF
  camera_make: z.string().optional(),
  camera_model: z.string().optional(),
  gps_location: z.object({
    latitude: z.number(),
    longitude: z.number()
  }).optional(),
  hash: z.string().optional() // For duplicate detection
});

// Mobile-specific image fields
export const MobileImageFieldsSchema = z.object({
  variants: ImageVariantSchema.optional(),
  processing_status: z.enum(['pending', 'processing', 'complete', 'failed']).default('pending'),
  processing_progress: z.number().min(0).max(100).optional(),
  local_path: z.string().optional(), // For offline caching
  cached_at: z.date().optional(),
  sync_status: z.enum(['synced', 'pending', 'conflict']).default('synced'),
  upload_progress: z.number().min(0).max(100).optional(),
  retry_count: z.number().int().default(0),
  error_message: z.string().optional(),
  is_favorite: z.boolean().default(false),
  tags: z.array(z.string().max(50)).max(MAX_MOBILE_ARRAY_LENGTH).optional()
});

// Enhanced image schema with mobile support
export const ImageSchema = z.object({
  id: z.string().uuid().optional(),
  user_id: z.string().uuid(),
  file_path: z.string(),
  original_metadata: EnhancedImageMetadataSchema.optional(),
  upload_date: z.date().optional(),
  status: z.enum(['new', 'processed', 'labeled', 'archived']).optional()
}).merge(MobileImageFieldsSchema);

// Mobile upload schema with chunking support
export const MobileImageUploadSchema = z.object({
  filename: z.string().max(255),
  mimetype: z.string(),
  size: z.number().int().max(MAX_MOBILE_FILE_SIZE),
  chunk_size: z.number().int().default(CHUNK_SIZE),
  total_chunks: z.number().int().optional(),
  metadata: z.object({
    width: z.number().int(),
    height: z.number().int(),
    capture_date: z.string().optional(),
    location: z.object({
      latitude: z.number(),
      longitude: z.number()
    }).optional()
  }).optional(),
  generate_variants: z.boolean().default(true),
  auto_process: z.boolean().default(true)
});

// Chunk upload schema for resumable uploads
export const ImageChunkUploadSchema = z.object({
  upload_id: z.string().uuid(),
  chunk_index: z.number().int(),
  chunk_data: z.string(), // Base64 encoded
  checksum: z.string() // For integrity verification
});

// Schema for image response (mobile-optimized)
export const ImageResponseSchema = ImageSchema.omit({
  user_id: true,
  file_path: true // Use variant URLs instead
});

// Mobile-specific image list item
export const MobileImageListItemSchema = z.object({
  id: z.string().uuid(),
  thumbnail_url: z.string().url(),
  preview_url: z.string().url().optional(),
  metadata: z.object({
    filename: z.string(),
    width: z.number().int(),
    height: z.number().int(),
    size: z.number().int()
  }),
  upload_date: z.date(),
  status: z.enum(['new', 'processed', 'labeled', 'archived']),
  is_favorite: z.boolean(),
  has_garments: z.boolean().optional() // Quick indicator
});

// Image list response schema (mobile-optimized)
export const ImageListResponseSchema = z.object({
  images: z.array(MobileImageListItemSchema),
  pagination: z.object({
    page: z.number().int(),
    limit: z.number().int(),
    total: z.number().int(),
    has_more: z.boolean()
  }),
  sync_info: z.object({
    last_sync: z.date().optional(),
    pending_uploads: z.number().int(),
    pending_downloads: z.number().int()
  }).optional()
});

// Image filter schema for mobile queries
export const ImageFilterSchema = z.object({
  status: z.array(z.enum(['new', 'processed', 'labeled', 'archived'])).optional(),
  date_range: z.object({
    start: z.date(),
    end: z.date()
  }).optional(),
  has_garments: z.boolean().optional(),
  is_favorite: z.boolean().optional(),
  tags: z.array(z.string()).optional(),
  search: z.string().max(100).optional(),
  sort_by: z.enum(['upload_date', 'capture_date', 'size', 'name']).default('upload_date'),
  sort_order: z.enum(['asc', 'desc']).default('desc')
});

// Batch operation schemas
export const BatchImageOperationSchema = z.object({
  image_ids: z.array(z.string().uuid()).max(BATCH_SIZE),
  operation: z.enum(['delete', 'archive', 'favorite', 'unfavorite', 'tag']),
  tags: z.array(z.string()).optional() // For tag operation
});

// Derived TypeScript types
export type Image = z.infer<typeof ImageSchema>;
export type ImageVariants = z.infer<typeof ImageVariantSchema>;
export type EnhancedImageMetadata = z.infer<typeof EnhancedImageMetadataSchema>;
export type MobileImageUpload = z.infer<typeof MobileImageUploadSchema>;
export type ImageChunkUpload = z.infer<typeof ImageChunkUploadSchema>;
export type ImageResponse = z.infer<typeof ImageResponseSchema>;
export type MobileImageListItem = z.infer<typeof MobileImageListItemSchema>;
export type ImageListResponse = z.infer<typeof ImageListResponseSchema>;
export type ImageFilter = z.infer<typeof ImageFilterSchema>;
export type BatchImageOperation = z.infer<typeof BatchImageOperationSchema>;
export type ImageMetadata = z.infer<typeof EnhancedImageMetadataSchema>; // Keep for backward compatibility

// Flutter model generation hints
export const ImageFlutterHints = {
  freezed: true,
  jsonSerializable: true,
  copyWith: true,
  equatable: true,
  fields: {
    upload_date: 'DateTime?',
    cached_at: 'DateTime?',
    capture_date: 'DateTime?',
    variants: 'ImageVariants?',
    original_metadata: 'ImageMetadata?',
    gps_location: 'GpsLocation?'
  },
  enums: {
    status: 'ImageStatus',
    processing_status: 'ProcessingStatus',
    sync_status: 'SyncStatus',
    format: 'ImageFormat',
    color_space: 'ColorSpace'
  }
};

// Helper functions for mobile optimization
export const ImageHelpers = {
  // Get best variant URL for given constraints
  getBestVariantUrl: (image: ImageResponse, maxWidth?: number): string => {
    if (!image.variants) return '';
    
    if (maxWidth && maxWidth <= 150 && image.variants.thumbnail) {
      return image.variants.thumbnail.url;
    } else if (maxWidth && maxWidth <= 600 && image.variants.preview) {
      return image.variants.preview.url;
    } else if (image.variants.full) {
      return image.variants.full.url;
    }
    
    // Fallback order
    return image.variants.preview?.url || image.variants.thumbnail?.url || '';
  },
  
  // Calculate total size of all variants
  getTotalSize: (variants: ImageVariants): number => {
    let total = 0;
    if (variants.thumbnail) total += variants.thumbnail.size;
    if (variants.preview) total += variants.preview.size;
    if (variants.full) total += variants.full.size;
    if (variants.webp) total += variants.webp.size;
    return total;
  },
  
  // Check if image needs re-processing
  needsReprocessing: (image: Image): boolean => {
    return image.processing_status === 'failed' && image.retry_count < 3;
  },
  
  // Convert to list item
  toListItem: (image: Image): MobileImageListItem => ({
    id: image.id!,
    thumbnail_url: image.variants?.thumbnail?.url || '',
    preview_url: image.variants?.preview?.url,
    metadata: {
      filename: image.original_metadata?.filename || 'Unknown',
      width: image.original_metadata?.width || 0,
      height: image.original_metadata?.height || 0,
      size: image.original_metadata?.size || 0
    },
    upload_date: image.upload_date!,
    status: image.status || 'new',
    is_favorite: image.is_favorite,
    has_garments: false // Would be populated by backend
  }),
  
  // Prepare for offline caching
  forOfflineCache: (image: ImageResponse): Partial<ImageResponse> => ({
    id: image.id,
    variants: image.variants ? {
      thumbnail: image.variants.thumbnail,
      preview: image.variants.preview
    } : undefined,
    original_metadata: {
      filename: image.original_metadata?.filename || '',
      width: image.original_metadata?.width || 0,
      height: image.original_metadata?.height || 0,
      size: image.original_metadata?.size || 0,
      format: image.original_metadata?.format || 'jpeg'
    },
    upload_date: image.upload_date,
    status: image.status,
    is_favorite: image.is_favorite
  })
};