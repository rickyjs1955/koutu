"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthResponseSchema = exports.UserResponseSchema = exports.LoginUserSchema = exports.RegisterUserSchema = exports.UserSchema = void 0;
// /shared/src/schemas/user.ts
const zod_1 = require("zod");
// User schema
exports.UserSchema = zod_1.z.object({
    id: zod_1.z.string().uuid().optional(),
    email: zod_1.z.string().email(),
    name: zod_1.z.string().optional(), // Add this line for user's name
    password_hash: zod_1.z.string().optional(), // Only used in backend
    created_at: zod_1.z.date().optional(),
    updated_at: zod_1.z.date().optional(),
    linkedProviders: zod_1.z.array(zod_1.z.string()).optional(),
    oauth_provider: zod_1.z.string().optional()
});
// Schema for creating a new user
exports.RegisterUserSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(8, "Password must be at least 8 characters long")
});
// Schema for user login
exports.LoginUserSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string()
});
// Schema for user response (excludes sensitive info)
exports.UserResponseSchema = exports.UserSchema.omit({
    password_hash: true
});
// Schema for auth response
exports.AuthResponseSchema = zod_1.z.object({
    user: exports.UserResponseSchema,
    token: zod_1.z.string()
});
//# sourceMappingURL=user.js.map