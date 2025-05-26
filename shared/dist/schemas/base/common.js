"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ApiSuccessSchema = exports.ApiErrorSchema = exports.ValidationErrorSchema = exports.ImageMetadataSchema = exports.FileMetadataSchema = exports.createRecordSchema = exports.createArraySchema = exports.createOptionalSchema = exports.JobStatusSchema = exports.SeasonSchema = exports.GarmentPatternSchema = exports.GarmentTypeSchema = exports.ImageFormatSchema = exports.ExportFormatSchema = exports.ImageStatusSchema = exports.DimensionsSchema = exports.BoundingBoxSchema = exports.PointSchema = exports.PaginationSchema = exports.TimestampSchema = exports.PasswordSchema = exports.EmailSchema = exports.UUIDSchema = void 0;
// /shared/src/schemas/base/common.ts
const zod_1 = require("zod");
// ==================== PRIMITIVE SCHEMAS ====================
exports.UUIDSchema = zod_1.z.string().uuid('Invalid UUID format');
exports.EmailSchema = zod_1.z.string().email('Invalid email format').max(255, 'Email too long');
exports.PasswordSchema = zod_1.z.string().min(8, 'Password must be at least 8 characters').max(128, 'Password too long');
exports.TimestampSchema = zod_1.z.string().datetime().or(zod_1.z.date());
exports.PaginationSchema = zod_1.z.object({
    page: zod_1.z.coerce.number().int().min(1, 'Page must be at least 1').optional(),
    limit: zod_1.z.coerce.number().int().min(1, 'Limit must be at least 1').max(100, 'Limit cannot exceed 100').optional(),
    offset: zod_1.z.coerce.number().int().min(0, 'Offset must be non-negative').optional()
});
// ==================== GEOMETRY SCHEMAS ====================
exports.PointSchema = zod_1.z.object({
    x: zod_1.z.number().min(0, 'X coordinate must be non-negative'),
    y: zod_1.z.number().min(0, 'Y coordinate must be non-negative')
});
exports.BoundingBoxSchema = zod_1.z.object({
    x: zod_1.z.number().min(0),
    y: zod_1.z.number().min(0),
    width: zod_1.z.number().min(0),
    height: zod_1.z.number().min(0)
});
exports.DimensionsSchema = zod_1.z.object({
    width: zod_1.z.number().int().min(1, 'Width must be positive').max(10000, 'Width too large'),
    height: zod_1.z.number().int().min(1, 'Height must be positive').max(10000, 'Height too large')
});
// ==================== ENUM SCHEMAS ====================
exports.ImageStatusSchema = zod_1.z.enum(['new', 'processed', 'labeled']);
exports.ExportFormatSchema = zod_1.z.enum(['coco', 'yolo', 'pascal_voc', 'csv', 'raw_json']);
exports.ImageFormatSchema = zod_1.z.enum(['jpg', 'png', 'webp']);
exports.GarmentTypeSchema = zod_1.z.enum(['shirt', 'pants', 'dress', 'jacket', 'skirt', 'other']);
exports.GarmentPatternSchema = zod_1.z.enum(['solid', 'striped', 'plaid', 'floral', 'geometric', 'other']);
exports.SeasonSchema = zod_1.z.enum(['spring', 'summer', 'fall', 'winter', 'all']);
exports.JobStatusSchema = zod_1.z.enum(['pending', 'processing', 'completed', 'failed', 'cancelled']);
// ==================== VALIDATION UTILITIES ====================
const createOptionalSchema = (schema) => schema.optional();
exports.createOptionalSchema = createOptionalSchema;
const createArraySchema = (schema, min = 0, max = 1000) => zod_1.z.array(schema).min(min).max(max);
exports.createArraySchema = createArraySchema;
const createRecordSchema = (valueSchema) => zod_1.z.record(zod_1.z.string(), valueSchema);
exports.createRecordSchema = createRecordSchema;
// ==================== FILE SCHEMAS ====================
exports.FileMetadataSchema = zod_1.z.object({
    filename: zod_1.z.string().max(255, 'Filename too long'),
    mimetype: zod_1.z.string().max(100, 'MIME type too long'),
    size: zod_1.z.number().int().min(1, 'File size must be positive'),
    uploadedAt: exports.TimestampSchema.optional()
});
exports.ImageMetadataSchema = exports.FileMetadataSchema.extend({
    width: zod_1.z.number().int().min(1).optional(),
    height: zod_1.z.number().int().min(1).optional(),
    format: zod_1.z.string().max(10).optional(),
    density: zod_1.z.number().optional(),
    hasProfile: zod_1.z.boolean().optional(),
    hasAlpha: zod_1.z.boolean().optional(),
    channels: zod_1.z.number().int().min(1).max(4).optional(),
    space: zod_1.z.string().optional()
});
// ==================== ERROR SCHEMAS ====================
exports.ValidationErrorSchema = zod_1.z.object({
    field: zod_1.z.string(),
    message: zod_1.z.string(),
    code: zod_1.z.string().optional(),
    value: zod_1.z.any().optional()
});
exports.ApiErrorSchema = zod_1.z.object({
    status: zod_1.z.literal('error'),
    code: zod_1.z.string(),
    message: zod_1.z.string(),
    errors: zod_1.z.array(exports.ValidationErrorSchema).optional(),
    requestId: zod_1.z.string().optional(),
    timestamp: exports.TimestampSchema.optional()
});
const ApiSuccessSchema = (dataSchema) => zod_1.z.object({
    status: zod_1.z.literal('success'),
    data: dataSchema,
    message: zod_1.z.string().optional(),
    requestId: zod_1.z.string().optional(),
    timestamp: exports.TimestampSchema.optional()
});
exports.ApiSuccessSchema = ApiSuccessSchema;
//# sourceMappingURL=common.js.map