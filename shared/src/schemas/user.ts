// /shared/src/schemas/user.ts
import { z } from 'zod';

// Define mobile patterns locally to avoid circular dependency
const MOBILE_PATTERNS = {
  deviceId: /^[a-zA-Z0-9\-_]{16,128}$/,
  biometricId: /^[a-zA-Z0-9\-_]{32,256}$/,
  pushToken: /^[a-zA-Z0-9\-_:\[\]]{32,512}$/
};

// Mobile-specific user fields
export const MobileUserFieldsSchema = z.object({
  device_id: z.string().regex(MOBILE_PATTERNS.deviceId).optional(),
  device_type: z.enum(['ios', 'android', 'web']).optional(),
  device_name: z.string().max(100).optional(),
  push_token: z.string().regex(MOBILE_PATTERNS.pushToken).optional(),
  biometric_enabled: z.boolean().default(false),
  biometric_id: z.string().regex(MOBILE_PATTERNS.biometricId).optional(),
  app_version: z.string().optional(),
  os_version: z.string().optional(),
  last_sync_at: z.date().optional(),
  profile_picture_url: z.string().url().optional(),
  profile_picture_thumbnail: z.string().url().optional(),
  preferences: z.object({
    notifications_enabled: z.boolean().default(true),
    offline_mode_enabled: z.boolean().default(false),
    data_saver_mode: z.boolean().default(false),
    theme: z.enum(['light', 'dark', 'system']).default('system'),
    language: z.string().default('en')
  }).optional()
});

// Enhanced User schema with mobile fields
export const UserSchema = z.object({
  id: z.string().uuid().optional(),
  email: z.string().email(),
  name: z.string().optional(),
  password_hash: z.string().optional(), // Only used in backend
  created_at: z.date().optional(),
  updated_at: z.date().optional(),
  linkedProviders: z.array(z.string()).optional(),
  oauth_provider: z.string().optional()
}).merge(MobileUserFieldsSchema);

// Schema for creating a new user (mobile-enhanced)
export const RegisterUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8, "Password must be at least 8 characters long"),
  name: z.string().optional(),
  device_id: z.string().regex(MOBILE_PATTERNS.deviceId).optional(),
  device_type: z.enum(['ios', 'android', 'web']).optional(),
  device_name: z.string().max(100).optional()
});

// Schema for user login (mobile-enhanced)
export const LoginUserSchema = z.object({
  email: z.string().email(),
  password: z.string(),
  device_id: z.string().regex(MOBILE_PATTERNS.deviceId).optional(),
  remember_device: z.boolean().default(false)
});

// Mobile-specific biometric login schema
export const BiometricLoginSchema = z.object({
  user_id: z.string().uuid(),
  biometric_id: z.string().regex(MOBILE_PATTERNS.biometricId),
  device_id: z.string().regex(MOBILE_PATTERNS.deviceId),
  challenge: z.string() // Server-provided challenge for security
});

// Mobile device registration schema
export const DeviceRegistrationSchema = z.object({
  device_id: z.string().regex(MOBILE_PATTERNS.deviceId),
  device_type: z.enum(['ios', 'android']),
  device_name: z.string().max(100),
  push_token: z.string().regex(MOBILE_PATTERNS.pushToken).optional(),
  app_version: z.string(),
  os_version: z.string()
});

// Schema for user response (excludes sensitive info)
export const UserResponseSchema = UserSchema.omit({ 
  password_hash: true,
  biometric_id: true // Don't expose biometric ID
});

// Mobile-optimized user response (minimal data)
export const MobileUserResponseSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  name: z.string().optional(),
  profile_picture_thumbnail: z.string().url().optional(),
  preferences: z.object({
    notifications_enabled: z.boolean(),
    theme: z.enum(['light', 'dark', 'system'])
  }).optional()
});

// Schema for auth response (mobile-enhanced)
export const AuthResponseSchema = z.object({
  user: UserResponseSchema,
  token: z.string(),
  refresh_token: z.string().optional(),
  expires_in: z.number().optional(), // Token expiry in seconds
  device_registered: z.boolean().optional()
});

// Mobile auth response with additional metadata
export const MobileAuthResponseSchema = AuthResponseSchema.extend({
  sync_required: z.boolean().default(false),
  server_time: z.string(), // ISO string for time sync
  features: z.object({
    biometric_available: z.boolean(),
    offline_mode_available: z.boolean(),
    push_notifications_available: z.boolean()
  }).optional()
});

// User update schema (mobile-optimized)
export const UpdateUserSchema = z.object({
  name: z.string().max(100).optional(),
  profile_picture_url: z.string().url().optional(),
  preferences: z.object({
    notifications_enabled: z.boolean().optional(),
    offline_mode_enabled: z.boolean().optional(),
    data_saver_mode: z.boolean().optional(),
    theme: z.enum(['light', 'dark', 'system']).optional(),
    language: z.string().optional()
  }).optional()
});

// Derived TypeScript types with Flutter annotations
export type User = z.infer<typeof UserSchema>;
export type RegisterUserInput = z.infer<typeof RegisterUserSchema>;
export type LoginUserInput = z.infer<typeof LoginUserSchema>;
export type BiometricLoginInput = z.infer<typeof BiometricLoginSchema>;
export type DeviceRegistration = z.infer<typeof DeviceRegistrationSchema>;
export type UserResponse = z.infer<typeof UserResponseSchema>;
export type MobileUserResponse = z.infer<typeof MobileUserResponseSchema>;
export type AuthResponse = z.infer<typeof AuthResponseSchema>;
export type MobileAuthResponse = z.infer<typeof MobileAuthResponseSchema>;
export type UpdateUserInput = z.infer<typeof UpdateUserSchema>;

// Flutter model generation hints
export const UserFlutterHints = {
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
export const UserHelpers = {
  // Convert full user to mobile response
  toMobileResponse: (user: User): MobileUserResponse => ({
    id: user.id!,
    email: user.email,
    name: user.name,
    profile_picture_thumbnail: user.profile_picture_thumbnail,
    preferences: user.preferences ? {
      notifications_enabled: user.preferences.notifications_enabled,
      theme: user.preferences.theme
    } : undefined
  }),
  
  // Check if user needs sync
  needsSync: (user: User): boolean => {
    if (!user.last_sync_at) return true;
    const lastSync = new Date(user.last_sync_at);
    const hoursSinceSync = (Date.now() - lastSync.getTime()) / (1000 * 60 * 60);
    return hoursSinceSync > 24; // Sync if more than 24 hours
  },
  
  // Prepare user for offline storage
  forOfflineStorage: (user: UserResponse): Partial<UserResponse> => ({
    id: user.id,
    email: user.email,
    name: user.name,
    profile_picture_thumbnail: user.profile_picture_thumbnail,
    preferences: user.preferences
  })
};