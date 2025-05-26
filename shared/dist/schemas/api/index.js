"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ExportJobListResponseSchema = exports.WardrobeListResponseSchema = exports.GarmentListResponseSchema = exports.PolygonListResponseSchema = exports.ImageListResponseSchema = exports.WardrobeItemParamSchema = exports.JobIdParamSchema = exports.ImageIdParamSchema = exports.UUIDParamSchema = exports.DatasetStatsSchema = exports.MLExportBatchJobSchema = exports.CreateMLExportSchema = exports.MLExportOptionsSchema = exports.WardrobeResponseSchema = exports.AddGarmentToWardrobeSchema = exports.UpdateWardrobeSchema = exports.CreateWardrobeSchema = exports.WardrobeSchema = exports.GarmentResponseSchema = exports.GarmentQuerySchema = exports.UpdateGarmentMetadataSchema = exports.CreateGarmentSchema = exports.GarmentSchema = exports.GarmentMetadataSchema = exports.MaskDataSchema = exports.PolygonResponseSchema = exports.UpdatePolygonSchema = exports.CreatePolygonSchema = exports.PolygonSchema = exports.PolygonMetadataSchema = exports.BatchUpdateImageStatusSchema = exports.ImageResponseSchema = exports.UpdateImageStatusSchema = exports.ImageQuerySchema = exports.ImageSchema = exports.AuthResponseSchema = exports.UserResponseSchema = exports.LoginUserSchema = exports.RegisterUserSchema = exports.UserSchema = void 0;
// /shared/src/schemas/api/index.ts
const zod_1 = require("zod");
const common_1 = require("../base/common");
// ==================== USER SCHEMAS ====================
exports.UserSchema = zod_1.z.object({
    id: common_1.UUIDSchema.optional(),
    email: common_1.EmailSchema,
    name: zod_1.z.string().max(100, 'Name too long').optional(),
    avatar_url: zod_1.z.string().url().optional(),
    oauth_provider: zod_1.z.string().optional(),
    linkedProviders: zod_1.z.array(zod_1.z.string()).optional(),
    created_at: common_1.TimestampSchema.optional(),
    updated_at: common_1.TimestampSchema.optional(),
    password_hash: zod_1.z.string().optional(), // Optional for API responses
});
exports.RegisterUserSchema = zod_1.z.object({
    email: common_1.EmailSchema,
    password: common_1.PasswordSchema
});
exports.LoginUserSchema = zod_1.z.object({
    email: common_1.EmailSchema,
    password: zod_1.z.string().min(1, 'Password is required')
});
exports.UserResponseSchema = exports.UserSchema.omit({ password_hash: true });
exports.AuthResponseSchema = zod_1.z.object({
    user: exports.UserResponseSchema,
    token: zod_1.z.string()
});
// ==================== IMAGE SCHEMAS ====================
exports.ImageSchema = zod_1.z.object({
    id: common_1.UUIDSchema.optional(),
    user_id: common_1.UUIDSchema.optional(), // Optional for API responses
    file_path: zod_1.z.string(),
    original_metadata: common_1.ImageMetadataSchema.optional(),
    upload_date: common_1.TimestampSchema.optional(),
    status: common_1.ImageStatusSchema.optional(),
    created_at: common_1.TimestampSchema.optional(),
    updated_at: common_1.TimestampSchema.optional()
});
exports.ImageQuerySchema = common_1.PaginationSchema.extend({
    status: common_1.ImageStatusSchema.optional()
});
exports.UpdateImageStatusSchema = zod_1.z.object({
    status: common_1.ImageStatusSchema
});
exports.ImageResponseSchema = exports.ImageSchema.omit({ user_id: true });
exports.BatchUpdateImageStatusSchema = zod_1.z.object({
    imageIds: zod_1.z.array(common_1.UUIDSchema).min(1, 'At least one image ID required').max(50, 'Too many images'),
    status: common_1.ImageStatusSchema
});
// ==================== POLYGON SCHEMAS ====================
exports.PolygonMetadataSchema = zod_1.z.object({
    label: zod_1.z.string().max(100, 'Label too long').optional(),
    confidence: zod_1.z.number().min(0).max(1).optional(),
    source: zod_1.z.string().max(50, 'Source too long').optional(),
    notes: zod_1.z.string().max(500, 'Notes too long').optional()
}).strict();
exports.PolygonSchema = zod_1.z.object({
    id: common_1.UUIDSchema.optional(),
    user_id: common_1.UUIDSchema.optional(), // Optional for API responses
    original_image_id: common_1.UUIDSchema,
    points: zod_1.z.array(common_1.PointSchema).min(3, 'Polygon must have at least 3 points').max(1000, 'Too many points'),
    label: zod_1.z.string().max(100, 'Label too long').optional(),
    metadata: exports.PolygonMetadataSchema.optional(),
    created_at: common_1.TimestampSchema.optional(),
    updated_at: common_1.TimestampSchema.optional()
});
exports.CreatePolygonSchema = zod_1.z.object({
    original_image_id: common_1.UUIDSchema,
    points: zod_1.z.array(common_1.PointSchema).min(3).max(1000),
    label: zod_1.z.string().max(100).optional(),
    metadata: exports.PolygonMetadataSchema.optional()
});
exports.UpdatePolygonSchema = zod_1.z.object({
    points: zod_1.z.array(common_1.PointSchema).min(3).max(1000).optional(),
    label: zod_1.z.string().max(100).optional(),
    metadata: exports.PolygonMetadataSchema.optional()
});
exports.PolygonResponseSchema = exports.PolygonSchema.omit({ user_id: true });
// ==================== GARMENT SCHEMAS ====================
exports.MaskDataSchema = zod_1.z.object({
    width: common_1.DimensionsSchema.shape.width,
    height: common_1.DimensionsSchema.shape.height,
    data: zod_1.z.union([
        zod_1.z.array(zod_1.z.number().int().min(0).max(255)),
        zod_1.z.instanceof(Uint8ClampedArray)
    ])
}).refine((data) => data.data.length === data.width * data.height, 'Mask data length must match width × height');
exports.GarmentMetadataSchema = zod_1.z.object({
    type: common_1.GarmentTypeSchema,
    color: zod_1.z.string().max(30, 'Color name too long'),
    pattern: common_1.GarmentPatternSchema.optional(),
    season: common_1.SeasonSchema.optional(),
    brand: zod_1.z.string().max(50, 'Brand name too long').optional(),
    size: zod_1.z.string().max(20, 'Size too long').optional(),
    material: zod_1.z.string().max(100, 'Material description too long').optional(),
    tags: zod_1.z.array(zod_1.z.string().max(30, 'Tag too long')).max(10, 'Too many tags').optional()
}).strict();
exports.GarmentSchema = zod_1.z.object({
    id: common_1.UUIDSchema.optional(),
    user_id: common_1.UUIDSchema.optional(), // Optional for API responses
    original_image_id: common_1.UUIDSchema,
    file_path: zod_1.z.string(),
    mask_path: zod_1.z.string(),
    metadata: exports.GarmentMetadataSchema,
    created_at: common_1.TimestampSchema.optional(),
    updated_at: common_1.TimestampSchema.optional(),
    data_version: zod_1.z.number().int().positive().optional()
});
exports.CreateGarmentSchema = zod_1.z.object({
    original_image_id: common_1.UUIDSchema,
    mask_data: exports.MaskDataSchema,
    metadata: exports.GarmentMetadataSchema.optional()
});
exports.UpdateGarmentMetadataSchema = zod_1.z.object({
    metadata: exports.GarmentMetadataSchema
});
exports.GarmentQuerySchema = common_1.PaginationSchema.extend({
    filter: zod_1.z.string().optional().transform((val) => {
        if (!val)
            return {};
        try {
            return JSON.parse(val);
        }
        catch {
            throw new Error('Invalid JSON in filter parameter');
        }
    }),
    replace: zod_1.z.enum(['true', 'false']).optional().transform(val => val === 'true')
});
exports.GarmentResponseSchema = exports.GarmentSchema.omit({ user_id: true });
// ==================== WARDROBE SCHEMAS ====================
exports.WardrobeSchema = zod_1.z.object({
    id: common_1.UUIDSchema.optional(),
    user_id: common_1.UUIDSchema.optional(), // Optional for API responses
    name: zod_1.z.string().min(1, 'Name is required').max(100, 'Name too long').trim(),
    description: zod_1.z.string().max(1000, 'Description too long').trim().optional(),
    created_at: common_1.TimestampSchema.optional(),
    updated_at: common_1.TimestampSchema.optional()
});
exports.CreateWardrobeSchema = zod_1.z.object({
    name: zod_1.z.string().min(1, 'Name is required').max(100, 'Name too long').trim(),
    description: zod_1.z.string().max(1000, 'Description too long').trim().optional()
});
exports.UpdateWardrobeSchema = zod_1.z.object({
    name: zod_1.z.string().min(1, 'Name cannot be empty').max(100, 'Name too long').trim().optional(),
    description: zod_1.z.string().max(1000, 'Description too long').trim().optional()
});
exports.AddGarmentToWardrobeSchema = zod_1.z.object({
    garmentId: common_1.UUIDSchema,
    position: zod_1.z.number().int().min(0, 'Position must be non-negative').optional()
});
exports.WardrobeResponseSchema = exports.WardrobeSchema.omit({ user_id: true }).extend({
    garments: zod_1.z.array(exports.GarmentResponseSchema).optional()
});
// ==================== EXPORT SCHEMAS ====================
exports.MLExportOptionsSchema = zod_1.z.object({
    format: common_1.ExportFormatSchema,
    garmentIds: zod_1.z.array(common_1.UUIDSchema).optional(),
    categoryFilter: zod_1.z.array(zod_1.z.string().max(50)).optional(),
    imageFormat: common_1.ImageFormatSchema.default('jpg'),
    compressionQuality: zod_1.z.number().min(10).max(100).default(85),
    includeMasks: zod_1.z.boolean().default(false),
    includePolygons: zod_1.z.boolean().default(true),
    includeImages: zod_1.z.boolean().default(true),
    includeRawPolygons: zod_1.z.boolean().default(true),
    dateRange: zod_1.z.object({
        from: common_1.TimestampSchema.optional(),
        to: common_1.TimestampSchema.optional()
    }).optional(),
    splitRatio: zod_1.z.object({
        train: zod_1.z.number().min(0).max(1),
        validation: zod_1.z.number().min(0).max(1),
        test: zod_1.z.number().min(0).max(1)
    }).refine((data) => Math.abs(data.train + data.validation + data.test - 1) < 0.001, 'Split ratios must sum to 1').optional()
});
exports.CreateMLExportSchema = zod_1.z.object({
    options: exports.MLExportOptionsSchema
});
exports.MLExportBatchJobSchema = zod_1.z.object({
    id: common_1.UUIDSchema,
    userId: common_1.UUIDSchema,
    status: common_1.JobStatusSchema,
    options: exports.MLExportOptionsSchema,
    progress: zod_1.z.number().min(0).max(100).default(0),
    totalItems: zod_1.z.number().min(0).default(0),
    processedItems: zod_1.z.number().min(0).default(0),
    outputUrl: zod_1.z.string().url().optional(),
    error: zod_1.z.string().optional(),
    createdAt: common_1.TimestampSchema,
    updatedAt: common_1.TimestampSchema,
    completedAt: common_1.TimestampSchema.optional(),
    expiresAt: common_1.TimestampSchema.optional()
});
exports.DatasetStatsSchema = zod_1.z.object({
    totalImages: zod_1.z.number().min(0),
    totalGarments: zod_1.z.number().min(0),
    categoryCounts: zod_1.z.record(zod_1.z.string(), zod_1.z.number().min(0)),
    attributeCounts: zod_1.z.record(zod_1.z.string(), zod_1.z.record(zod_1.z.string(), zod_1.z.number().min(0))),
    averagePolygonPoints: zod_1.z.number().min(0)
});
// ==================== PARAMETER SCHEMAS ====================
exports.UUIDParamSchema = zod_1.z.object({
    id: common_1.UUIDSchema
});
exports.ImageIdParamSchema = zod_1.z.object({
    imageId: common_1.UUIDSchema
});
exports.JobIdParamSchema = zod_1.z.object({
    jobId: common_1.UUIDSchema
});
exports.WardrobeItemParamSchema = zod_1.z.object({
    id: common_1.UUIDSchema,
    itemId: common_1.UUIDSchema
});
// ==================== RESPONSE WRAPPERS ====================
exports.ImageListResponseSchema = (0, common_1.ApiSuccessSchema)(zod_1.z.object({
    images: zod_1.z.array(exports.ImageResponseSchema),
    count: zod_1.z.number(),
    pagination: common_1.PaginationSchema.optional()
}));
exports.PolygonListResponseSchema = (0, common_1.ApiSuccessSchema)(zod_1.z.object({
    polygons: zod_1.z.array(exports.PolygonResponseSchema),
    count: zod_1.z.number(),
    imageId: common_1.UUIDSchema
}));
exports.GarmentListResponseSchema = (0, common_1.ApiSuccessSchema)(zod_1.z.object({
    garments: zod_1.z.array(exports.GarmentResponseSchema),
    count: zod_1.z.number(),
    pagination: common_1.PaginationSchema.optional()
}));
exports.WardrobeListResponseSchema = (0, common_1.ApiSuccessSchema)(zod_1.z.object({
    wardrobes: zod_1.z.array(exports.WardrobeResponseSchema),
    count: zod_1.z.number()
}));
exports.ExportJobListResponseSchema = (0, common_1.ApiSuccessSchema)(zod_1.z.object({
    jobs: zod_1.z.array(exports.MLExportBatchJobSchema),
    count: zod_1.z.number()
}));
//# sourceMappingURL=index.js.map