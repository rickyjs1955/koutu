"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LinkedProvidersSchema = exports.OAuthUserInfoSchema = exports.OAuthProviderSchema = void 0;
// /shared/src/schemas/oauth.ts
const zod_1 = require("zod");
// OAuth provider schema
exports.OAuthProviderSchema = zod_1.z.enum([
    'google',
    'microsoft',
    'github'
]);
// OAuth user info schema
exports.OAuthUserInfoSchema = zod_1.z.object({
    id: zod_1.z.string(),
    email: zod_1.z.string().email(),
    name: zod_1.z.string().optional(),
    picture: zod_1.z.string().optional()
});
// OAuth linked providers schema
exports.LinkedProvidersSchema = zod_1.z.array(exports.OAuthProviderSchema);
//# sourceMappingURL=oauth.js.map