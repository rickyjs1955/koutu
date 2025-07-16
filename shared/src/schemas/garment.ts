// /shared/src/schemas/garment.ts
import { z } from 'zod';

// Define mobile constants locally to avoid circular dependency
const MAX_MOBILE_ARRAY_LENGTH = 100;
const MAX_MOBILE_TEXT_LENGTH = 500;
const BATCH_SIZE = 20;

// Mobile-specific garment fields for optimized data transfer
export const MobileGarmentFieldsSchema = z.object({
  thumbnail_url: z.string().url().optional(), // Small image for list views
  preview_url: z.string().url().optional(), // Medium image for detail views
  full_image_url: z.string().url().optional(), // Full resolution (lazy loaded)
  mask_thumbnail_url: z.string().url().optional(), // Mask preview
  is_favorite: z.boolean().default(false),
  wear_count: z.number().int().default(0),
  last_worn_date: z.date().optional(),
  local_id: z.string().optional(), // For offline-first sync
  sync_status: z.enum(['synced', 'pending', 'conflict']).default('synced'),
  cached_at: z.date().optional(),
  file_size: z.number().int().optional(), // In bytes
  dimensions: z.object({
    width: z.number().int(),
    height: z.number().int()
  }).optional()
});

// Enhanced garment metadata with mobile considerations
export const EnhancedMetadataSchema = z.object({
  type: z.enum(['shirt', 'pants', 'dress', 'jacket', 'skirt', 'accessories', 'shoes', 'bags', 'other']),
  color: z.string().max(50), // Primary color
  secondary_colors: z.array(z.string().max(50)).optional(), // Additional colors
  pattern: z.enum(['solid', 'striped', 'plaid', 'floral', 'geometric', 'abstract', 'animal_print', 'other']).optional(),
  season: z.enum(['spring', 'summer', 'fall', 'winter', 'all']).optional(),
  occasion: z.enum(['casual', 'formal', 'business', 'sport', 'party', 'beach', 'other']).optional(),
  brand: z.string().max(100).optional(),
  size: z.string().max(20).optional(),
  material: z.string().max(100).optional(),
  care_instructions: z.array(z.string().max(200)).optional(),
  purchase_date: z.date().optional(),
  purchase_price: z.number().optional(),
  tags: z.array(z.string().max(50)).max(MAX_MOBILE_ARRAY_LENGTH).optional(),
  notes: z.string().max(MAX_MOBILE_TEXT_LENGTH).optional()
});

// Base schema for a garment item (mobile-enhanced)
export const GarmentSchema = z.object({
  id: z.string().uuid().optional(),
  user_id: z.string().uuid(),
  original_image_id: z.string().uuid(),
  file_path: z.string(),
  mask_path: z.string(),
  metadata: EnhancedMetadataSchema,
  created_at: z.date().optional(),
  updated_at: z.date().optional(),
  data_version: z.number().int().positive().optional()
}).merge(MobileGarmentFieldsSchema);

// Mobile-optimized garment list item
export const MobileGarmentListItemSchema = z.object({
  id: z.string().uuid(),
  thumbnail_url: z.string().url(),
  metadata: z.object({
    type: EnhancedMetadataSchema.shape.type,
    color: z.string(),
    brand: z.string().optional()
  }),
  is_favorite: z.boolean(),
  wear_count: z.number().int(),
  last_worn_date: z.date().optional(),
  sync_status: z.enum(['synced', 'pending', 'conflict'])
});

// Schema for creating a new garment (mobile-enhanced)
export const CreateGarmentSchema = z.object({
  original_image_id: z.string().uuid(),
  file_path: z.string().optional(),
  mask_path: z.string().optional(),
  metadata: EnhancedMetadataSchema,
  mask_data: z.object({
    width: z.number().int().positive(),
    height: z.number().int().positive(),
    data: z.array(z.number()),
    format: z.enum(['raw', 'rle', 'base64']).default('raw') // Support compressed formats
  }),
  local_id: z.string().optional(), // For offline creation
  create_thumbnail: z.boolean().default(true) // Auto-generate thumbnails
}).strip();

// Mobile batch upload schema
export const BatchCreateGarmentSchema = z.object({
  garments: z.array(CreateGarmentSchema).max(BATCH_SIZE),
  process_async: z.boolean().default(true),
  notification_token: z.string().optional() // For push notification on completion
});

// Schema for updating garment metadata (mobile-enhanced)
export const UpdateGarmentMetadataSchema = z.object({
  metadata: EnhancedMetadataSchema.partial(), // Allow partial updates
  wear_count_increment: z.number().int().optional(), // Increment wear count
  mark_as_worn: z.boolean().optional(), // Update last_worn_date
  is_favorite: z.boolean().optional()
});

// Schema for garment response (mobile-optimized)
export const GarmentResponseSchema = GarmentSchema.omit({ 
  user_id: true,
  file_path: true, // Use URL fields instead
  mask_path: true // Use URL fields instead
});

// Mobile-specific garment response with size optimization
export const MobileGarmentResponseSchema = z.object({
  id: z.string().uuid(),
  thumbnail_url: z.string().url(),
  preview_url: z.string().url().optional(),
  metadata: EnhancedMetadataSchema,
  is_favorite: z.boolean(),
  wear_count: z.number().int(),
  last_worn_date: z.date().optional(),
  sync_status: z.enum(['synced', 'pending', 'conflict']),
  dimensions: z.object({
    width: z.number().int(),
    height: z.number().int()
  }).optional()
});

// Garment filter schema for mobile queries
export const GarmentFilterSchema = z.object({
  types: z.array(EnhancedMetadataSchema.shape.type).optional(),
  colors: z.array(z.string()).optional(),
  seasons: z.array(EnhancedMetadataSchema.shape.season.unwrap()).optional(),
  occasions: z.array(EnhancedMetadataSchema.shape.occasion.unwrap()).optional(),
  brands: z.array(z.string()).optional(),
  tags: z.array(z.string()).optional(),
  is_favorite: z.boolean().optional(),
  worn_recently: z.boolean().optional(), // Last 30 days
  never_worn: z.boolean().optional(),
  search: z.string().max(100).optional()
});

// Derived TypeScript types
export type GarmentMetadata = z.infer<typeof EnhancedMetadataSchema>;
export type Garment = z.infer<typeof GarmentSchema>;
export type MobileGarmentListItem = z.infer<typeof MobileGarmentListItemSchema>;
export type CreateGarmentInput = z.infer<typeof CreateGarmentSchema>;
export type BatchCreateGarmentInput = z.infer<typeof BatchCreateGarmentSchema>;
export type UpdateGarmentMetadata = z.infer<typeof UpdateGarmentMetadataSchema>;
export type GarmentResponse = z.infer<typeof GarmentResponseSchema>;
export type MobileGarmentResponse = z.infer<typeof MobileGarmentResponseSchema>;
export type GarmentFilter = z.infer<typeof GarmentFilterSchema>;

// Flutter model generation hints
export const GarmentFlutterHints = {
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
export const GarmentHelpers = {
  // Convert full garment to list item
  toListItem: (garment: Garment): MobileGarmentListItem => ({
    id: garment.id!,
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
  needsSync: (garment: Garment): boolean => {
    return garment.sync_status !== 'synced';
  },
  
  // Calculate cache age in hours
  getCacheAge: (garment: Garment): number => {
    if (!garment.cached_at) return Infinity;
    return (Date.now() - new Date(garment.cached_at).getTime()) / (1000 * 60 * 60);
  },
  
  // Determine if cache is stale (older than 7 days)
  isCacheStale: (garment: Garment): boolean => {
    return GarmentHelpers.getCacheAge(garment) > 168; // 7 days
  },
  
  // Get appropriate image URL based on context
  getImageUrl: (garment: GarmentResponse, quality: 'thumbnail' | 'preview' | 'full'): string => {
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