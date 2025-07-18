"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GarmentHelpers = exports.GarmentFlutterHints = exports.GarmentFilterSchema = exports.MobileGarmentResponseSchema = exports.GarmentResponseSchema = exports.UpdateGarmentMetadataSchema = exports.BatchCreateGarmentSchema = exports.CreateGarmentSchema = exports.MobileGarmentListItemSchema = exports.GarmentSchema = exports.EnhancedMetadataSchema = exports.MobileGarmentFieldsSchema = void 0;
// /shared/src/schemas/garment.ts
const zod_1 = require("zod");
// Define mobile constants locally to avoid circular dependency
const MAX_MOBILE_ARRAY_LENGTH = 100;
const MAX_MOBILE_TEXT_LENGTH = 500;
const BATCH_SIZE = 20;
// Mobile-specific garment fields for optimized data transfer
exports.MobileGarmentFieldsSchema = zod_1.z.object({
    thumbnail_url: zod_1.z.string().url().optional(), // Small image for list views
    preview_url: zod_1.z.string().url().optional(), // Medium image for detail views
    full_image_url: zod_1.z.string().url().optional(), // Full resolution (lazy loaded)
    mask_thumbnail_url: zod_1.z.string().url().optional(), // Mask preview
    is_favorite: zod_1.z.boolean().default(false),
    wear_count: zod_1.z.number().int().default(0),
    last_worn_date: zod_1.z.date().optional(),
    local_id: zod_1.z.string().optional(), // For offline-first sync
    sync_status: zod_1.z.enum(['synced', 'pending', 'conflict']).default('synced'),
    cached_at: zod_1.z.date().optional(),
    file_size: zod_1.z.number().int().optional(), // In bytes
    dimensions: zod_1.z.object({
        width: zod_1.z.number().int(),
        height: zod_1.z.number().int()
    }).optional()
});
// Enhanced garment metadata with mobile considerations
exports.EnhancedMetadataSchema = zod_1.z.object({
    type: zod_1.z.enum(['shirt', 'pants', 'dress', 'jacket', 'skirt', 'accessories', 'shoes', 'bags', 'other']),
    color: zod_1.z.string().max(50), // Primary color
    secondary_colors: zod_1.z.array(zod_1.z.string().max(50)).optional(), // Additional colors
    pattern: zod_1.z.enum(['solid', 'striped', 'plaid', 'floral', 'geometric', 'abstract', 'animal_print', 'other']).optional(),
    season: zod_1.z.enum(['spring', 'summer', 'fall', 'winter', 'all']).optional(),
    occasion: zod_1.z.enum(['casual', 'formal', 'business', 'sport', 'party', 'beach', 'other']).optional(),
    brand: zod_1.z.string().max(100).optional(),
    size: zod_1.z.string().max(20).optional(),
    material: zod_1.z.string().max(100).optional(),
    care_instructions: zod_1.z.array(zod_1.z.string().max(200)).optional(),
    purchase_date: zod_1.z.date().optional(),
    purchase_price: zod_1.z.number().optional(),
    tags: zod_1.z.array(zod_1.z.string().max(50)).max(MAX_MOBILE_ARRAY_LENGTH).optional(),
    notes: zod_1.z.string().max(MAX_MOBILE_TEXT_LENGTH).optional()
});
// Base schema for a garment item (mobile-enhanced)
exports.GarmentSchema = zod_1.z.object({
    id: zod_1.z.string().uuid().optional(),
    user_id: zod_1.z.string().uuid(),
    original_image_id: zod_1.z.string().uuid(),
    file_path: zod_1.z.string(),
    mask_path: zod_1.z.string(),
    metadata: exports.EnhancedMetadataSchema,
    created_at: zod_1.z.date().optional(),
    updated_at: zod_1.z.date().optional(),
    data_version: zod_1.z.number().int().positive().optional()
}).merge(exports.MobileGarmentFieldsSchema);
// Mobile-optimized garment list item
exports.MobileGarmentListItemSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
    thumbnail_url: zod_1.z.string().url(),
    metadata: zod_1.z.object({
        type: exports.EnhancedMetadataSchema.shape.type,
        color: zod_1.z.string(),
        brand: zod_1.z.string().optional()
    }),
    is_favorite: zod_1.z.boolean(),
    wear_count: zod_1.z.number().int(),
    last_worn_date: zod_1.z.date().optional(),
    sync_status: zod_1.z.enum(['synced', 'pending', 'conflict'])
});
// Schema for creating a new garment (mobile-enhanced)
exports.CreateGarmentSchema = zod_1.z.object({
    original_image_id: zod_1.z.string().uuid(),
    file_path: zod_1.z.string().optional(),
    mask_path: zod_1.z.string().optional(),
    metadata: exports.EnhancedMetadataSchema,
    mask_data: zod_1.z.object({
        width: zod_1.z.number().int().positive(),
        height: zod_1.z.number().int().positive(),
        data: zod_1.z.array(zod_1.z.number()),
        format: zod_1.z.enum(['raw', 'rle', 'base64']).default('raw') // Support compressed formats
    }),
    local_id: zod_1.z.string().optional(), // For offline creation
    create_thumbnail: zod_1.z.boolean().default(true) // Auto-generate thumbnails
}).strip();
// Mobile batch upload schema
exports.BatchCreateGarmentSchema = zod_1.z.object({
    garments: zod_1.z.array(exports.CreateGarmentSchema).max(BATCH_SIZE),
    process_async: zod_1.z.boolean().default(true),
    notification_token: zod_1.z.string().optional() // For push notification on completion
});
// Schema for updating garment metadata (mobile-enhanced)
exports.UpdateGarmentMetadataSchema = zod_1.z.object({
    metadata: exports.EnhancedMetadataSchema.partial(), // Allow partial updates
    wear_count_increment: zod_1.z.number().int().optional(), // Increment wear count
    mark_as_worn: zod_1.z.boolean().optional(), // Update last_worn_date
    is_favorite: zod_1.z.boolean().optional()
});
// Schema for garment response (mobile-optimized)
exports.GarmentResponseSchema = exports.GarmentSchema.omit({
    user_id: true,
    file_path: true, // Use URL fields instead
    mask_path: true // Use URL fields instead
});
// Mobile-specific garment response with size optimization
exports.MobileGarmentResponseSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
    thumbnail_url: zod_1.z.string().url(),
    preview_url: zod_1.z.string().url().optional(),
    metadata: exports.EnhancedMetadataSchema,
    is_favorite: zod_1.z.boolean(),
    wear_count: zod_1.z.number().int(),
    last_worn_date: zod_1.z.date().optional(),
    sync_status: zod_1.z.enum(['synced', 'pending', 'conflict']),
    dimensions: zod_1.z.object({
        width: zod_1.z.number().int(),
        height: zod_1.z.number().int()
    }).optional()
});
// Garment filter schema for mobile queries
exports.GarmentFilterSchema = zod_1.z.object({
    types: zod_1.z.array(exports.EnhancedMetadataSchema.shape.type).optional(),
    colors: zod_1.z.array(zod_1.z.string()).optional(),
    seasons: zod_1.z.array(exports.EnhancedMetadataSchema.shape.season.unwrap()).optional(),
    occasions: zod_1.z.array(exports.EnhancedMetadataSchema.shape.occasion.unwrap()).optional(),
    brands: zod_1.z.array(zod_1.z.string()).optional(),
    tags: zod_1.z.array(zod_1.z.string()).optional(),
    is_favorite: zod_1.z.boolean().optional(),
    worn_recently: zod_1.z.boolean().optional(), // Last 30 days
    never_worn: zod_1.z.boolean().optional(),
    search: zod_1.z.string().max(100).optional()
});
// Flutter model generation hints
exports.GarmentFlutterHints = {
    freezed: true,
    jsonSerializable: true,
    copyWith: true,
    equatable: true,
    fields: {
        created_at: 'DateTime?',
        updated_at: 'DateTime?',
        last_worn_date: 'DateTime?',
        cached_at: 'DateTime?',
        purchase_date: 'DateTime?',
        metadata: 'GarmentMetadata',
        dimensions: 'GarmentDimensions?'
    },
    enums: {
        type: 'GarmentType',
        pattern: 'GarmentPattern',
        season: 'Season',
        occasion: 'Occasion',
        sync_status: 'SyncStatus'
    }
};
// Helper functions for mobile optimization
exports.GarmentHelpers = {
    // Convert full garment to list item
    toListItem: (garment) => ({
        id: garment.id,
        thumbnail_url: garment.thumbnail_url || garment.file_path,
        metadata: {
            type: garment.metadata.type,
            color: garment.metadata.color,
            brand: garment.metadata.brand
        },
        is_favorite: garment.is_favorite,
        wear_count: garment.wear_count,
        last_worn_date: garment.last_worn_date,
        sync_status: garment.sync_status
    }),
    // Check if garment needs sync
    needsSync: (garment) => {
        return garment.sync_status !== 'synced';
    },
    // Calculate cache age in hours
    getCacheAge: (garment) => {
        if (!garment.cached_at)
            return Infinity;
        return (Date.now() - new Date(garment.cached_at).getTime()) / (1000 * 60 * 60);
    },
    // Determine if cache is stale (older than 7 days)
    isCacheStale: (garment) => {
        return exports.GarmentHelpers.getCacheAge(garment) > 168; // 7 days
    },
    // Get appropriate image URL based on context
    getImageUrl: (garment, quality) => {
        switch (quality) {
            case 'thumbnail':
                return garment.thumbnail_url || garment.preview_url || garment.full_image_url || '';
            case 'preview':
                return garment.preview_url || garment.full_image_url || garment.thumbnail_url || '';
            case 'full':
                return garment.full_image_url || garment.preview_url || garment.thumbnail_url || '';
        }
    }
};
//# sourceMappingURL=garment.js.map