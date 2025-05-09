"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ImageMetadataSchema = exports.ImageListResponseSchema = exports.ImageResponseSchema = exports.ImageSchema = void 0;
// /shared/src/schemas/image.ts
const zod_1 = require("zod");
// Image schema
exports.ImageSchema = zod_1.z.object({
    id: zod_1.z.string().uuid().optional(),
    user_id: zod_1.z.string().uuid(),
    file_path: zod_1.z.string(),
    original_metadata: zod_1.z.record(zod_1.z.any()).optional(), // JSON metadata from upload
    upload_date: zod_1.z.date().optional(),
    status: zod_1.z.enum(['new', 'processed', 'labeled']).optional()
});
// Schema for image response
exports.ImageResponseSchema = exports.ImageSchema;
// Image list response schema
exports.ImageListResponseSchema = zod_1.z.array(exports.ImageResponseSchema);
// Schema for image metadata
exports.ImageMetadataSchema = zod_1.z.object({
    filename: zod_1.z.string().optional(),
    mimetype: zod_1.z.string().optional(),
    size: zod_1.z.number().optional(),
    width: zod_1.z.number().optional(),
    height: zod_1.z.number().optional(),
    format: zod_1.z.string().optional()
});
//# sourceMappingURL=image.js.map