"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolygonResponseSchema = exports.UpdatePolygonSchema = exports.CreatePolygonSchema = exports.PolygonSchema = exports.PointSchema = void 0;
// /shared/src/schemas/polygon.ts
const zod_1 = require("zod");
// Define a point in a polygon
exports.PointSchema = zod_1.z.object({
    x: zod_1.z.number(),
    y: zod_1.z.number()
});
// Define the polygon schema
exports.PolygonSchema = zod_1.z.object({
    id: zod_1.z.string().uuid().optional(), // Will be generated on the server
    original_image_id: zod_1.z.string().uuid(), // Link to parent image
    points: zod_1.z.array(exports.PointSchema), // Array of points that make up the polygon
    label: zod_1.z.string().optional(), // Optional label for the polygon (e.g., "shirt", "pants")
    metadata: zod_1.z.record(zod_1.z.any()).optional(), // Additional metadata
    created_at: zod_1.z.date().optional(),
    updated_at: zod_1.z.date().optional()
});
// Schema for creating a new polygon
exports.CreatePolygonSchema = zod_1.z.object({
    original_image_id: zod_1.z.string().uuid(),
    points: zod_1.z.array(exports.PointSchema),
    label: zod_1.z.string().optional(),
    metadata: zod_1.z.record(zod_1.z.any()).optional()
});
// Schema for updating a polygon
exports.UpdatePolygonSchema = zod_1.z.object({
    points: zod_1.z.array(exports.PointSchema).optional(),
    label: zod_1.z.string().optional(),
    metadata: zod_1.z.record(zod_1.z.any()).optional()
});
// Polygon response schema
exports.PolygonResponseSchema = exports.PolygonSchema;
//# sourceMappingURL=polygon.js.map