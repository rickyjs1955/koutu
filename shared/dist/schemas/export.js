"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.datasetStatsSchema = exports.mlExportBatchJobSchema = exports.mlExportRequestSchema = exports.mlExportOptionsSchema = exports.exportFormatSchema = exports.mlGarmentSchema = exports.pointSchema = void 0;
// /shared/src/schemas/export.ts
const zod_1 = require("zod");
// Polygon point schema
exports.pointSchema = zod_1.z.object({
    x: zod_1.z.number(),
    y: zod_1.z.number(),
});
// ML-ready garment data schema
exports.mlGarmentSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
    imageId: zod_1.z.string().uuid(),
    // The polygon points that define the garment boundary
    polygonPoints: zod_1.z.array(exports.pointSchema),
    // Mask representation as base64 string (optional for smaller payloads)
    maskBase64: zod_1.z.string().optional(),
    // Bounding box for quick reference
    boundingBox: zod_1.z.object({
        x: zod_1.z.number(),
        y: zod_1.z.number(),
        width: zod_1.z.number(),
        height: zod_1.z.number(),
    }),
    // Garment category and attributes
    category: zod_1.z.string(),
    attributes: zod_1.z.record(zod_1.z.string(), zod_1.z.union([zod_1.z.string(), zod_1.z.number(), zod_1.z.boolean()])),
    // Original creation metadata
    createdAt: zod_1.z.string().datetime(),
    updatedAt: zod_1.z.string().datetime(),
});
// ML export format options
exports.exportFormatSchema = zod_1.z.enum([
    'coco', // COCO dataset format
    'yolo', // YOLO format
    'pascal_voc', // Pascal VOC format
    'raw_json', // Custom raw JSON format
    'csv', // CSV format for tabular data
]);
// ML export options schema
exports.mlExportOptionsSchema = zod_1.z.object({
    format: exports.exportFormatSchema,
    includeImages: zod_1.z.boolean().default(true),
    includeRawPolygons: zod_1.z.boolean().default(true),
    includeMasks: zod_1.z.boolean().default(false),
    imageFormat: zod_1.z.enum(['jpg', 'png']).default('jpg'),
    compressionQuality: zod_1.z.number().min(0).max(100).default(90),
    garmentIds: zod_1.z.array(zod_1.z.string()).optional(),
    categoryFilter: zod_1.z.array(zod_1.z.string()).optional(),
    dateRange: zod_1.z.object({
        from: zod_1.z.string().datetime().optional(),
        to: zod_1.z.string().datetime().optional(),
    }).optional(),
});
// ML export request schema
exports.mlExportRequestSchema = zod_1.z.object({
    options: exports.mlExportOptionsSchema,
});
// ML export batch job schema
exports.mlExportBatchJobSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
    userId: zod_1.z.string().uuid(),
    status: zod_1.z.enum(['pending', 'processing', 'completed', 'failed']),
    options: exports.mlExportOptionsSchema,
    progress: zod_1.z.number().min(0).max(100).default(0),
    totalItems: zod_1.z.number().default(0),
    processedItems: zod_1.z.number().default(0),
    outputUrl: zod_1.z.string().url().optional(),
    error: zod_1.z.string().optional(),
    createdAt: zod_1.z.string().datetime(),
    updatedAt: zod_1.z.string().datetime(),
    completedAt: zod_1.z.string().datetime().optional(),
});
// Dataset statistics for ML
exports.datasetStatsSchema = zod_1.z.object({
    totalImages: zod_1.z.number(),
    totalGarments: zod_1.z.number(),
    categoryCounts: zod_1.z.record(zod_1.z.string(), zod_1.z.number()),
    attributeCounts: zod_1.z.record(zod_1.z.string(), zod_1.z.record(zod_1.z.string(), zod_1.z.number())),
    averagePolygonPoints: zod_1.z.number(),
});
//# sourceMappingURL=export.js.map