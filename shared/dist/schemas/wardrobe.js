"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WardrobeResponseSchema = exports.AddGarmentToWardrobeSchema = exports.UpdateWardrobeSchema = exports.CreateWardrobeSchema = exports.WardrobeSchema = void 0;
// /shared/src/schemas/wardrobe.ts
const zod_1 = require("zod");
exports.WardrobeSchema = zod_1.z.object({
    id: zod_1.z.string().uuid().optional(),
    name: zod_1.z.string().min(1).max(100),
    description: zod_1.z.string().max(1000).optional(),
    created_at: zod_1.z.date().optional(),
    updated_at: zod_1.z.date().optional(),
});
exports.CreateWardrobeSchema = exports.WardrobeSchema.omit({
    id: true,
    created_at: true,
    updated_at: true
});
exports.UpdateWardrobeSchema = exports.CreateWardrobeSchema.partial();
exports.AddGarmentToWardrobeSchema = zod_1.z.object({
    garmentId: zod_1.z.string().uuid(),
    position: zod_1.z.number().int().nonnegative().optional().default(0),
});
exports.WardrobeResponseSchema = exports.WardrobeSchema.extend({
    garments: zod_1.z.array(zod_1.z.any()).optional(), // This would be the GarmentSchema in practice
});
//# sourceMappingURL=wardrobe.js.map