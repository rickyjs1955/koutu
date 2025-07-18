"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ImageHelpers = exports.ImageFlutterHints = exports.BatchImageOperationSchema = exports.ImageFilterSchema = exports.ImageListResponseSchema = exports.MobileImageListItemSchema = exports.ImageResponseSchema = exports.ImageChunkUploadSchema = exports.MobileImageUploadSchema = exports.ImageSchema = exports.MobileImageFieldsSchema = exports.EnhancedImageMetadataSchema = exports.ImageVariantSchema = void 0;
// /shared/src/schemas/image.ts
const zod_1 = require("zod");
// Define mobile constants locally to avoid circular dependency
const MAX_MOBILE_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const MAX_MOBILE_ARRAY_LENGTH = 100;
const BATCH_SIZE = 20;
const CHUNK_SIZE = 1024 * 1024; // 1MB
// Mobile-specific image resolution variants
exports.ImageVariantSchema = zod_1.z.object({
    thumbnail: zod_1.z.object({
        url: zod_1.z.string().url(),
        width: zod_1.z.number().int(),
        height: zod_1.z.number().int(),
        size: zod_1.z.number().int() // bytes
    }).optional(),
    preview: zod_1.z.object({
        url: zod_1.z.string().url(),
        width: zod_1.z.number().int(),
        height: zod_1.z.number().int(),
        size: zod_1.z.number().int()
    }).optional(),
    full: zod_1.z.object({
        url: zod_1.z.string().url(),
        width: zod_1.z.number().int(),
        height: zod_1.z.number().int(),
        size: zod_1.z.number().int()
    }).optional(),
    webp: zod_1.z.object({
        url: zod_1.z.string().url(),
        width: zod_1.z.number().int(),
        height: zod_1.z.number().int(),
        size: zod_1.z.number().int()
    }).optional()
});
// Enhanced image metadata with mobile considerations
exports.EnhancedImageMetadataSchema = zod_1.z.object({
    filename: zod_1.z.string().max(255),
    original_filename: zod_1.z.string().max(255).optional(),
    mimetype: zod_1.z.string(),
    size: zod_1.z.number().int(), // Original file size in bytes
    width: zod_1.z.number().int(),
    height: zod_1.z.number().int(),
    format: zod_1.z.enum(['jpeg', 'jpg', 'png', 'webp', 'gif', 'heic', 'heif']),
    orientation: zod_1.z.number().int().min(1).max(8).optional(), // EXIF orientation
    has_transparency: zod_1.z.boolean().optional(),
    color_space: zod_1.z.enum(['srgb', 'rgb', 'cmyk', 'gray']).optional(),
    dpi: zod_1.z.number().optional(),
    capture_date: zod_1.z.date().optional(), // From EXIF
    camera_make: zod_1.z.string().optional(),
    camera_model: zod_1.z.string().optional(),
    gps_location: zod_1.z.object({
        latitude: zod_1.z.number(),
        longitude: zod_1.z.number()
    }).optional(),
    hash: zod_1.z.string().optional() // For duplicate detection
});
// Mobile-specific image fields
exports.MobileImageFieldsSchema = zod_1.z.object({
    variants: exports.ImageVariantSchema.optional(),
    processing_status: zod_1.z.enum(['pending', 'processing', 'complete', 'failed']).default('pending'),
    processing_progress: zod_1.z.number().min(0).max(100).optional(),
    local_path: zod_1.z.string().optional(), // For offline caching
    cached_at: zod_1.z.date().optional(),
    sync_status: zod_1.z.enum(['synced', 'pending', 'conflict']).default('synced'),
    upload_progress: zod_1.z.number().min(0).max(100).optional(),
    retry_count: zod_1.z.number().int().default(0),
    error_message: zod_1.z.string().optional(),
    is_favorite: zod_1.z.boolean().default(false),
    tags: zod_1.z.array(zod_1.z.string().max(50)).max(MAX_MOBILE_ARRAY_LENGTH).optional()
});
// Enhanced image schema with mobile support
exports.ImageSchema = zod_1.z.object({
    id: zod_1.z.string().uuid().optional(),
    user_id: zod_1.z.string().uuid(),
    file_path: zod_1.z.string(),
    original_metadata: exports.EnhancedImageMetadataSchema.optional(),
    upload_date: zod_1.z.date().optional(),
    status: zod_1.z.enum(['new', 'processed', 'labeled', 'archived']).optional()
}).merge(exports.MobileImageFieldsSchema);
// Mobile upload schema with chunking support
exports.MobileImageUploadSchema = zod_1.z.object({
    filename: zod_1.z.string().max(255),
    mimetype: zod_1.z.string(),
    size: zod_1.z.number().int().max(MAX_MOBILE_FILE_SIZE),
    chunk_size: zod_1.z.number().int().default(CHUNK_SIZE),
    total_chunks: zod_1.z.number().int().optional(),
    metadata: zod_1.z.object({
        width: zod_1.z.number().int(),
        height: zod_1.z.number().int(),
        capture_date: zod_1.z.string().optional(),
        location: zod_1.z.object({
            latitude: zod_1.z.number(),
            longitude: zod_1.z.number()
        }).optional()
    }).optional(),
    generate_variants: zod_1.z.boolean().default(true),
    auto_process: zod_1.z.boolean().default(true)
});
// Chunk upload schema for resumable uploads
exports.ImageChunkUploadSchema = zod_1.z.object({
    upload_id: zod_1.z.string().uuid(),
    chunk_index: zod_1.z.number().int(),
    chunk_data: zod_1.z.string(), // Base64 encoded
    checksum: zod_1.z.string() // For integrity verification
});
// Schema for image response (mobile-optimized)
exports.ImageResponseSchema = exports.ImageSchema.omit({
    user_id: true,
    file_path: true // Use variant URLs instead
});
// Mobile-specific image list item
exports.MobileImageListItemSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
    thumbnail_url: zod_1.z.string().url(),
    preview_url: zod_1.z.string().url().optional(),
    metadata: zod_1.z.object({
        filename: zod_1.z.string(),
        width: zod_1.z.number().int(),
        height: zod_1.z.number().int(),
        size: zod_1.z.number().int()
    }),
    upload_date: zod_1.z.date(),
    status: zod_1.z.enum(['new', 'processed', 'labeled', 'archived']),
    is_favorite: zod_1.z.boolean(),
    has_garments: zod_1.z.boolean().optional() // Quick indicator
});
// Image list response schema (mobile-optimized)
exports.ImageListResponseSchema = zod_1.z.object({
    images: zod_1.z.array(exports.MobileImageListItemSchema),
    pagination: zod_1.z.object({
        page: zod_1.z.number().int(),
        limit: zod_1.z.number().int(),
        total: zod_1.z.number().int(),
        has_more: zod_1.z.boolean()
    }),
    sync_info: zod_1.z.object({
        last_sync: zod_1.z.date().optional(),
        pending_uploads: zod_1.z.number().int(),
        pending_downloads: zod_1.z.number().int()
    }).optional()
});
// Image filter schema for mobile queries
exports.ImageFilterSchema = zod_1.z.object({
    status: zod_1.z.array(zod_1.z.enum(['new', 'processed', 'labeled', 'archived'])).optional(),
    date_range: zod_1.z.object({
        start: zod_1.z.date(),
        end: zod_1.z.date()
    }).optional(),
    has_garments: zod_1.z.boolean().optional(),
    is_favorite: zod_1.z.boolean().optional(),
    tags: zod_1.z.array(zod_1.z.string()).optional(),
    search: zod_1.z.string().max(100).optional(),
    sort_by: zod_1.z.enum(['upload_date', 'capture_date', 'size', 'name']).default('upload_date'),
    sort_order: zod_1.z.enum(['asc', 'desc']).default('desc')
});
// Batch operation schemas
exports.BatchImageOperationSchema = zod_1.z.object({
    image_ids: zod_1.z.array(zod_1.z.string().uuid()).max(BATCH_SIZE),
    operation: zod_1.z.enum(['delete', 'archive', 'favorite', 'unfavorite', 'tag']),
    tags: zod_1.z.array(zod_1.z.string()).optional() // For tag operation
});
// Flutter model generation hints
exports.ImageFlutterHints = {
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
exports.ImageHelpers = {
    // Get best variant URL for given constraints
    getBestVariantUrl: (image, maxWidth) => {
        if (!image.variants)
            return '';
        if (maxWidth && maxWidth <= 150 && image.variants.thumbnail) {
            return image.variants.thumbnail.url;
        }
        else if (maxWidth && maxWidth <= 600 && image.variants.preview) {
            return image.variants.preview.url;
        }
        else if (image.variants.full) {
            return image.variants.full.url;
        }
        // Fallback order
        return image.variants.preview?.url || image.variants.thumbnail?.url || '';
    },
    // Calculate total size of all variants
    getTotalSize: (variants) => {
        let total = 0;
        if (variants.thumbnail)
            total += variants.thumbnail.size;
        if (variants.preview)
            total += variants.preview.size;
        if (variants.full)
            total += variants.full.size;
        if (variants.webp)
            total += variants.webp.size;
        return total;
    },
    // Check if image needs re-processing
    needsReprocessing: (image) => {
        return image.processing_status === 'failed' && image.retry_count < 3;
    },
    // Convert to list item
    toListItem: (image) => ({
        id: image.id,
        thumbnail_url: image.variants?.thumbnail?.url || '',
        preview_url: image.variants?.preview?.url,
        metadata: {
            filename: image.original_metadata?.filename || 'Unknown',
            width: image.original_metadata?.width || 0,
            height: image.original_metadata?.height || 0,
            size: image.original_metadata?.size || 0
        },
        upload_date: image.upload_date,
        status: image.status || 'new',
        is_favorite: image.is_favorite,
        has_garments: false // Would be populated by backend
    }),
    // Prepare for offline caching
    forOfflineCache: (image) => ({
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
            format: image.original_metadata?.format || 'jpeg',
            mimetype: image.original_metadata?.mimetype || 'image/jpeg'
        },
        upload_date: image.upload_date,
        status: image.status,
        is_favorite: image.is_favorite
    })
};
//# sourceMappingURL=image.js.map