// /shared/src/schemas/api/index.ts
import { z } from 'zod';
import { 
  UUIDSchema, 
  EmailSchema, 
  PasswordSchema, 
  TimestampSchema,
  PaginationSchema,
  PointSchema,
  BoundingBoxSchema,
  DimensionsSchema,
  ImageStatusSchema,
  ExportFormatSchema,
  ImageFormatSchema,
  GarmentTypeSchema,
  GarmentPatternSchema,
  SeasonSchema,
  JobStatusSchema,
  FileMetadataSchema,
  ImageMetadataSchema,
  ApiSuccessSchema,
} from '../base/common';

// ==================== USER SCHEMAS ====================

export const UserSchema = z.object({
  id: UUIDSchema.optional(),
  email: EmailSchema,
  name: z.string().max(100, 'Name too long').optional(),
  avatar_url: z.string().url().optional(),
  oauth_provider: z.string().optional(),
  linkedProviders: z.array(z.string()).optional(),
  created_at: TimestampSchema.optional(),
  updated_at: TimestampSchema.optional(),
  password_hash: z.string().optional(), // Optional for API responses
});

export const RegisterUserSchema = z.object({
  email: EmailSchema,
  password: PasswordSchema
});

export const LoginUserSchema = z.object({
  email: EmailSchema,
  password: z.string().min(1, 'Password is required')
});

export const UserResponseSchema = UserSchema.omit({ password_hash: true });

export const AuthResponseSchema = z.object({
  user: UserResponseSchema,
  token: z.string()
});

// ==================== IMAGE SCHEMAS ====================

export const ImageSchema = z.object({
  id: UUIDSchema.optional(),
  user_id: UUIDSchema.optional(), // Optional for API responses
  file_path: z.string(),
  original_metadata: ImageMetadataSchema.optional(),
  upload_date: TimestampSchema.optional(),
  status: ImageStatusSchema.optional(),
  created_at: TimestampSchema.optional(),
  updated_at: TimestampSchema.optional()
});

export const ImageQuerySchema = PaginationSchema.extend({
  status: ImageStatusSchema.optional()
});

export const UpdateImageStatusSchema = z.object({
  status: ImageStatusSchema
});

export const ImageResponseSchema = ImageSchema.omit({ user_id: true });

export const BatchUpdateImageStatusSchema = z.object({
  imageIds: z.array(UUIDSchema).min(1, 'At least one image ID required').max(50, 'Too many images'),
  status: ImageStatusSchema
});

// ==================== POLYGON SCHEMAS ====================

export const PolygonMetadataSchema = z.object({
  label: z.string().max(100, 'Label too long').optional(),
  confidence: z.number().min(0).max(1).optional(),
  source: z.string().max(50, 'Source too long').optional(),
  notes: z.string().max(500, 'Notes too long').optional()
}).strict();

export const PolygonSchema = z.object({
  id: UUIDSchema.optional(),
  user_id: UUIDSchema.optional(), // Optional for API responses
  original_image_id: UUIDSchema,
  points: z.array(PointSchema).min(3, 'Polygon must have at least 3 points').max(1000, 'Too many points'),
  label: z.string().max(100, 'Label too long').optional(),
  metadata: PolygonMetadataSchema.optional(),
  created_at: TimestampSchema.optional(),
  updated_at: TimestampSchema.optional()
});

export const CreatePolygonSchema = z.object({
  original_image_id: UUIDSchema,
  points: z.array(PointSchema).min(3).max(1000),
  label: z.string().max(100).optional(),
  metadata: PolygonMetadataSchema.optional()
});

export const UpdatePolygonSchema = z.object({
  points: z.array(PointSchema).min(3).max(1000).optional(),
  label: z.string().max(100).optional(),
  metadata: PolygonMetadataSchema.optional()
});

export const PolygonResponseSchema = PolygonSchema.omit({ user_id: true });

// ==================== GARMENT SCHEMAS ====================

export const MaskDataSchema = z.object({
  width: DimensionsSchema.shape.width,
  height: DimensionsSchema.shape.height,
  data: z.union([
    z.array(z.number().int().min(0).max(255)),
    z.instanceof(Uint8ClampedArray)
  ])
}).refine(
  (data) => data.data.length === data.width * data.height,
  'Mask data length must match width × height'
);

export const GarmentMetadataSchema = z.object({
  type: GarmentTypeSchema,
  color: z.string().max(30, 'Color name too long'),
  pattern: GarmentPatternSchema.optional(),
  season: SeasonSchema.optional(),
  brand: z.string().max(50, 'Brand name too long').optional(),
  size: z.string().max(20, 'Size too long').optional(),
  material: z.string().max(100, 'Material description too long').optional(),
  tags: z.array(z.string().max(30, 'Tag too long')).max(10, 'Too many tags').optional()
}).strict();

export const GarmentSchema = z.object({
  id: UUIDSchema.optional(),
  user_id: UUIDSchema.optional(), // Optional for API responses
  original_image_id: UUIDSchema,
  file_path: z.string(),
  mask_path: z.string(),
  metadata: GarmentMetadataSchema,
  created_at: TimestampSchema.optional(),
  updated_at: TimestampSchema.optional(),
  data_version: z.number().int().positive().optional()
});

export const CreateGarmentSchema = z.object({
  original_image_id: UUIDSchema,
  mask_data: MaskDataSchema,
  metadata: GarmentMetadataSchema.optional()
});

export const UpdateGarmentMetadataSchema = z.object({
  metadata: GarmentMetadataSchema
});

export const GarmentQuerySchema = PaginationSchema.extend({
  filter: z.string().optional().transform((val) => {
    if (!val) return {};
    try {
      return JSON.parse(val);
    } catch {
      throw new Error('Invalid JSON in filter parameter');
    }
  }),
  replace: z.enum(['true', 'false']).optional().transform(val => val === 'true')
});

export const GarmentResponseSchema = GarmentSchema.omit({ user_id: true });

// ==================== WARDROBE SCHEMAS ====================

export const WardrobeSchema = z.object({
  id: UUIDSchema.optional(),
  user_id: UUIDSchema.optional(), // Optional for API responses
  name: z.string().min(1, 'Name is required').max(100, 'Name too long').trim(),
  description: z.string().max(1000, 'Description too long').trim().optional(),
  created_at: TimestampSchema.optional(),
  updated_at: TimestampSchema.optional()
});

export const CreateWardrobeSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name too long').trim(),
  description: z.string().max(1000, 'Description too long').trim().optional()
});

export const UpdateWardrobeSchema = z.object({
  name: z.string().min(1, 'Name cannot be empty').max(100, 'Name too long').trim().optional(),
  description: z.string().max(1000, 'Description too long').trim().optional()
});

export const AddGarmentToWardrobeSchema = z.object({
  garmentId: UUIDSchema,
  position: z.number().int().min(0, 'Position must be non-negative').optional()
});

export const WardrobeResponseSchema = WardrobeSchema.omit({ user_id: true }).extend({
  garments: z.array(GarmentResponseSchema).optional()
});

// ==================== EXPORT SCHEMAS ====================

export const MLExportOptionsSchema = z.object({
  format: ExportFormatSchema,
  garmentIds: z.array(UUIDSchema).optional(),
  categoryFilter: z.array(z.string().max(50)).optional(),
  imageFormat: ImageFormatSchema.default('jpg'),
  compressionQuality: z.number().min(10).max(100).default(85),
  includeMasks: z.boolean().default(false),
  includePolygons: z.boolean().default(true),
  includeImages: z.boolean().default(true),
  includeRawPolygons: z.boolean().default(true),
  dateRange: z.object({
    from: TimestampSchema.optional(),
    to: TimestampSchema.optional()
  }).optional(),
  splitRatio: z.object({
    train: z.number().min(0).max(1),
    validation: z.number().min(0).max(1),
    test: z.number().min(0).max(1)
  }).refine(
    (data) => Math.abs(data.train + data.validation + data.test - 1) < 0.001,
    'Split ratios must sum to 1'
  ).optional()
});

export const CreateMLExportSchema = z.object({
  options: MLExportOptionsSchema
});

export const MLExportBatchJobSchema = z.object({
  id: UUIDSchema,
  userId: UUIDSchema,
  status: JobStatusSchema,
  options: MLExportOptionsSchema,
  progress: z.number().min(0).max(100).default(0),
  totalItems: z.number().min(0).default(0),
  processedItems: z.number().min(0).default(0),
  outputUrl: z.string().url().optional(),
  error: z.string().optional(),
  createdAt: TimestampSchema,
  updatedAt: TimestampSchema,
  completedAt: TimestampSchema.optional(),
  expiresAt: TimestampSchema.optional()
});

export const DatasetStatsSchema = z.object({
  totalImages: z.number().min(0),
  totalGarments: z.number().min(0),
  categoryCounts: z.record(z.string(), z.number().min(0)),
  attributeCounts: z.record(z.string(), z.record(z.string(), z.number().min(0))),
  averagePolygonPoints: z.number().min(0)
});

// ==================== PARAMETER SCHEMAS ====================

export const UUIDParamSchema = z.object({
  id: UUIDSchema
});

export const ImageIdParamSchema = z.object({
  imageId: UUIDSchema
});

export const JobIdParamSchema = z.object({
  jobId: UUIDSchema
});

export const WardrobeItemParamSchema = z.object({
  id: UUIDSchema,
  itemId: UUIDSchema
});

// ==================== RESPONSE WRAPPERS ====================

export const ImageListResponseSchema = ApiSuccessSchema(z.object({
  images: z.array(ImageResponseSchema),
  count: z.number(),
  pagination: PaginationSchema.optional()
}));

export const PolygonListResponseSchema = ApiSuccessSchema(z.object({
  polygons: z.array(PolygonResponseSchema),
  count: z.number(),
  imageId: UUIDSchema
}));

export const GarmentListResponseSchema = ApiSuccessSchema(z.object({
  garments: z.array(GarmentResponseSchema),
  count: z.number(),
  pagination: PaginationSchema.optional()
}));

export const WardrobeListResponseSchema = ApiSuccessSchema(z.object({
  wardrobes: z.array(WardrobeResponseSchema),
  count: z.number()
}));

export const ExportJobListResponseSchema = ApiSuccessSchema(z.object({
  jobs: z.array(MLExportBatchJobSchema),
  count: z.number()
}));

// ==================== EXPORTED TYPES ====================

export type User = z.infer<typeof UserSchema>;
export type RegisterUserInput = z.infer<typeof RegisterUserSchema>;
export type LoginUserInput = z.infer<typeof LoginUserSchema>;
export type UserResponse = z.infer<typeof UserResponseSchema>;
export type AuthResponse = z.infer<typeof AuthResponseSchema>;

export type Image = z.infer<typeof ImageSchema>;
export type ImageQuery = z.infer<typeof ImageQuerySchema>;
export type UpdateImageStatus = z.infer<typeof UpdateImageStatusSchema>;
export type ImageResponse = z.infer<typeof ImageResponseSchema>;
export type BatchUpdateImageStatus = z.infer<typeof BatchUpdateImageStatusSchema>;

export type Polygon = z.infer<typeof PolygonSchema>;
export type PolygonMetadata = z.infer<typeof PolygonMetadataSchema>;
export type CreatePolygonInput = z.infer<typeof CreatePolygonSchema>;
export type UpdatePolygonInput = z.infer<typeof UpdatePolygonSchema>;
export type PolygonResponse = z.infer<typeof PolygonResponseSchema>;

export type Garment = z.infer<typeof GarmentSchema>;
export type MaskData = z.infer<typeof MaskDataSchema>;
export type GarmentMetadata = z.infer<typeof GarmentMetadataSchema>;
export type CreateGarmentInput = z.infer<typeof CreateGarmentSchema>;
export type UpdateGarmentMetadata = z.infer<typeof UpdateGarmentMetadataSchema>;
export type GarmentQuery = z.infer<typeof GarmentQuerySchema>;
export type GarmentResponse = z.infer<typeof GarmentResponseSchema>;

export type Wardrobe = z.infer<typeof WardrobeSchema>;
export type CreateWardrobeInput = z.infer<typeof CreateWardrobeSchema>;
export type UpdateWardrobeInput = z.infer<typeof UpdateWardrobeSchema>;
export type AddGarmentToWardrobeInput = z.infer<typeof AddGarmentToWardrobeSchema>;
export type WardrobeResponse = z.infer<typeof WardrobeResponseSchema>;

export type MLExportOptions = z.infer<typeof MLExportOptionsSchema>;
export type CreateMLExport = z.infer<typeof CreateMLExportSchema>;
export type MLExportBatchJob = z.infer<typeof MLExportBatchJobSchema>;
export type DatasetStats = z.infer<typeof DatasetStatsSchema>;

export type UUIDParam = z.infer<typeof UUIDParamSchema>;
export type ImageIdParam = z.infer<typeof ImageIdParamSchema>;
export type JobIdParam = z.infer<typeof JobIdParamSchema>;
export type WardrobeItemParam = z.infer<typeof WardrobeItemParamSchema>;