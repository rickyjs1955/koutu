"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserHelpers = exports.UserFlutterHints = exports.UpdateUserSchema = exports.MobileAuthResponseSchema = exports.AuthResponseSchema = exports.MobileUserResponseSchema = exports.UserResponseSchema = exports.DeviceRegistrationSchema = exports.BiometricLoginSchema = exports.LoginUserSchema = exports.RegisterUserSchema = exports.UserSchema = exports.MobileUserFieldsSchema = void 0;
// /shared/src/schemas/user.ts
const zod_1 = require("zod");
// Define mobile patterns locally to avoid circular dependency
const MOBILE_PATTERNS = {
    deviceId: /^[a-zA-Z0-9\-_]{16,128}$/,
    biometricId: /^[a-zA-Z0-9\-_]{32,256}$/,
    pushToken: /^[a-zA-Z0-9\-_:\[\]]{32,512}$/
};
// Mobile-specific user fields
exports.MobileUserFieldsSchema = zod_1.z.object({
    device_id: zod_1.z.string().regex(MOBILE_PATTERNS.deviceId).optional(),
    device_type: zod_1.z.enum(['ios', 'android', 'web']).optional(),
    device_name: zod_1.z.string().max(100).optional(),
    push_token: zod_1.z.string().regex(MOBILE_PATTERNS.pushToken).optional(),
    biometric_enabled: zod_1.z.boolean().default(false),
    biometric_id: zod_1.z.string().regex(MOBILE_PATTERNS.biometricId).optional(),
    app_version: zod_1.z.string().optional(),
    os_version: zod_1.z.string().optional(),
    last_sync_at: zod_1.z.date().optional(),
    profile_picture_url: zod_1.z.string().url().optional(),
    profile_picture_thumbnail: zod_1.z.string().url().optional(),
    preferences: zod_1.z.object({
        notifications_enabled: zod_1.z.boolean().default(true),
        offline_mode_enabled: zod_1.z.boolean().default(false),
        data_saver_mode: zod_1.z.boolean().default(false),
        theme: zod_1.z.enum(['light', 'dark', 'system']).default('system'),
        language: zod_1.z.string().default('en')
    }).optional()
});
// Enhanced User schema with mobile fields
exports.UserSchema = zod_1.z.object({
    id: zod_1.z.string().uuid().optional(),
    email: zod_1.z.string().email(),
    name: zod_1.z.string().optional(),
    password_hash: zod_1.z.string().optional(), // Only used in backend
    created_at: zod_1.z.date().optional(),
    updated_at: zod_1.z.date().optional(),
    linkedProviders: zod_1.z.array(zod_1.z.string()).optional(),
    oauth_provider: zod_1.z.string().optional()
}).merge(exports.MobileUserFieldsSchema);
// Schema for creating a new user (mobile-enhanced)
exports.RegisterUserSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(8, "Password must be at least 8 characters long"),
    name: zod_1.z.string().optional(),
    device_id: zod_1.z.string().regex(MOBILE_PATTERNS.deviceId).optional(),
    device_type: zod_1.z.enum(['ios', 'android', 'web']).optional(),
    device_name: zod_1.z.string().max(100).optional()
});
// Schema for user login (mobile-enhanced)
exports.LoginUserSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string(),
    device_id: zod_1.z.string().regex(MOBILE_PATTERNS.deviceId).optional(),
    remember_device: zod_1.z.boolean().default(false)
});
// Mobile-specific biometric login schema
exports.BiometricLoginSchema = zod_1.z.object({
    user_id: zod_1.z.string().uuid(),
    biometric_id: zod_1.z.string().regex(MOBILE_PATTERNS.biometricId),
    device_id: zod_1.z.string().regex(MOBILE_PATTERNS.deviceId),
    challenge: zod_1.z.string() // Server-provided challenge for security
});
// Mobile device registration schema
exports.DeviceRegistrationSchema = zod_1.z.object({
    device_id: zod_1.z.string().regex(MOBILE_PATTERNS.deviceId),
    device_type: zod_1.z.enum(['ios', 'android']),
    device_name: zod_1.z.string().max(100),
    push_token: zod_1.z.string().regex(MOBILE_PATTERNS.pushToken).optional(),
    app_version: zod_1.z.string(),
    os_version: zod_1.z.string()
});
// Schema for user response (excludes sensitive info)
exports.UserResponseSchema = exports.UserSchema.omit({
    password_hash: true,
    biometric_id: true // Don't expose biometric ID
});
// Mobile-optimized user response (minimal data)
exports.MobileUserResponseSchema = zod_1.z.object({
    id: zod_1.z.string().uuid(),
    email: zod_1.z.string().email(),
    name: zod_1.z.string().optional(),
    profile_picture_thumbnail: zod_1.z.string().url().optional(),
    preferences: zod_1.z.object({
        notifications_enabled: zod_1.z.boolean(),
        theme: zod_1.z.enum(['light', 'dark', 'system'])
    }).optional()
});
// Schema for auth response (mobile-enhanced)
exports.AuthResponseSchema = zod_1.z.object({
    user: exports.UserResponseSchema,
    token: zod_1.z.string(),
    refresh_token: zod_1.z.string().optional(),
    expires_in: zod_1.z.number().optional(), // Token expiry in seconds
    device_registered: zod_1.z.boolean().optional()
});
// Mobile auth response with additional metadata
exports.MobileAuthResponseSchema = exports.AuthResponseSchema.extend({
    sync_required: zod_1.z.boolean().default(false),
    server_time: zod_1.z.string(), // ISO string for time sync
    features: zod_1.z.object({
        biometric_available: zod_1.z.boolean(),
        offline_mode_available: zod_1.z.boolean(),
        push_notifications_available: zod_1.z.boolean()
    }).optional()
});
// User update schema (mobile-optimized)
exports.UpdateUserSchema = zod_1.z.object({
    name: zod_1.z.string().max(100).optional(),
    profile_picture_url: zod_1.z.string().url().optional(),
    preferences: zod_1.z.object({
        notifications_enabled: zod_1.z.boolean().optional(),
        offline_mode_enabled: zod_1.z.boolean().optional(),
        data_saver_mode: zod_1.z.boolean().optional(),
        theme: zod_1.z.enum(['light', 'dark', 'system']).optional(),
        language: zod_1.z.string().optional()
    }).optional()
});
// Flutter model generation hints
exports.UserFlutterHints = {
    freezed: true,
    jsonSerializable: true,
    copyWith: true,
    equatable: true,
    fields: {
        created_at: 'DateTime?',
        updated_at: 'DateTime?',
        last_sync_at: 'DateTime?',
        preferences: 'UserPreferences?',
        profile_picture_url: 'String?',
        profile_picture_thumbnail: 'String?'
    }
};
// Helper functions for mobile data optimization
exports.UserHelpers = {
    // Convert full user to mobile response
    toMobileResponse: (user) => ({
        id: user.id,
        email: user.email,
        name: user.name,
        profile_picture_thumbnail: user.profile_picture_thumbnail,
        preferences: user.preferences ? {
            notifications_enabled: user.preferences.notifications_enabled,
            theme: user.preferences.theme
        } : undefined
    }),
    // Check if user needs sync
    needsSync: (user) => {
        if (!user.last_sync_at)
            return true;
        const lastSync = new Date(user.last_sync_at);
        const hoursSinceSync = (Date.now() - lastSync.getTime()) / (1000 * 60 * 60);
        return hoursSinceSync > 24; // Sync if more than 24 hours
    },
    // Prepare user for offline storage
    forOfflineStorage: (user) => ({
        id: user.id,
        email: user.email,
        name: user.name,
        profile_picture_thumbnail: user.profile_picture_thumbnail,
        preferences: user.preferences
    })
};
//# sourceMappingURL=user.js.map