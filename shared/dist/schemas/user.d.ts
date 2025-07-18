import { z } from 'zod';
export declare const MobileUserFieldsSchema: z.ZodObject<{
    device_id: z.ZodOptional<z.ZodString>;
    device_type: z.ZodOptional<z.ZodEnum<["ios", "android", "web"]>>;
    device_name: z.ZodOptional<z.ZodString>;
    push_token: z.ZodOptional<z.ZodString>;
    biometric_enabled: z.ZodDefault<z.ZodBoolean>;
    biometric_id: z.ZodOptional<z.ZodString>;
    app_version: z.ZodOptional<z.ZodString>;
    os_version: z.ZodOptional<z.ZodString>;
    last_sync_at: z.ZodOptional<z.ZodDate>;
    profile_picture_url: z.ZodOptional<z.ZodString>;
    profile_picture_thumbnail: z.ZodOptional<z.ZodString>;
    preferences: z.ZodOptional<z.ZodObject<{
        notifications_enabled: z.ZodDefault<z.ZodBoolean>;
        offline_mode_enabled: z.ZodDefault<z.ZodBoolean>;
        data_saver_mode: z.ZodDefault<z.ZodBoolean>;
        theme: z.ZodDefault<z.ZodEnum<["light", "dark", "system"]>>;
        language: z.ZodDefault<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        notifications_enabled: boolean;
        offline_mode_enabled: boolean;
        data_saver_mode: boolean;
        theme: "light" | "dark" | "system";
        language: string;
    }, {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    biometric_enabled: boolean;
    device_id?: string | undefined;
    device_type?: "ios" | "android" | "web" | undefined;
    device_name?: string | undefined;
    push_token?: string | undefined;
    biometric_id?: string | undefined;
    app_version?: string | undefined;
    os_version?: string | undefined;
    last_sync_at?: Date | undefined;
    profile_picture_url?: string | undefined;
    profile_picture_thumbnail?: string | undefined;
    preferences?: {
        notifications_enabled: boolean;
        offline_mode_enabled: boolean;
        data_saver_mode: boolean;
        theme: "light" | "dark" | "system";
        language: string;
    } | undefined;
}, {
    device_id?: string | undefined;
    device_type?: "ios" | "android" | "web" | undefined;
    device_name?: string | undefined;
    push_token?: string | undefined;
    biometric_enabled?: boolean | undefined;
    biometric_id?: string | undefined;
    app_version?: string | undefined;
    os_version?: string | undefined;
    last_sync_at?: Date | undefined;
    profile_picture_url?: string | undefined;
    profile_picture_thumbnail?: string | undefined;
    preferences?: {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    } | undefined;
}>;
export declare const UserSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    email: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    password_hash: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
    linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    oauth_provider: z.ZodOptional<z.ZodString>;
} & {
    device_id: z.ZodOptional<z.ZodString>;
    device_type: z.ZodOptional<z.ZodEnum<["ios", "android", "web"]>>;
    device_name: z.ZodOptional<z.ZodString>;
    push_token: z.ZodOptional<z.ZodString>;
    biometric_enabled: z.ZodDefault<z.ZodBoolean>;
    biometric_id: z.ZodOptional<z.ZodString>;
    app_version: z.ZodOptional<z.ZodString>;
    os_version: z.ZodOptional<z.ZodString>;
    last_sync_at: z.ZodOptional<z.ZodDate>;
    profile_picture_url: z.ZodOptional<z.ZodString>;
    profile_picture_thumbnail: z.ZodOptional<z.ZodString>;
    preferences: z.ZodOptional<z.ZodObject<{
        notifications_enabled: z.ZodDefault<z.ZodBoolean>;
        offline_mode_enabled: z.ZodDefault<z.ZodBoolean>;
        data_saver_mode: z.ZodDefault<z.ZodBoolean>;
        theme: z.ZodDefault<z.ZodEnum<["light", "dark", "system"]>>;
        language: z.ZodDefault<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        notifications_enabled: boolean;
        offline_mode_enabled: boolean;
        data_saver_mode: boolean;
        theme: "light" | "dark" | "system";
        language: string;
    }, {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    biometric_enabled: boolean;
    email: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    name?: string | undefined;
    device_id?: string | undefined;
    device_type?: "ios" | "android" | "web" | undefined;
    device_name?: string | undefined;
    push_token?: string | undefined;
    biometric_id?: string | undefined;
    app_version?: string | undefined;
    os_version?: string | undefined;
    last_sync_at?: Date | undefined;
    profile_picture_url?: string | undefined;
    profile_picture_thumbnail?: string | undefined;
    preferences?: {
        notifications_enabled: boolean;
        offline_mode_enabled: boolean;
        data_saver_mode: boolean;
        theme: "light" | "dark" | "system";
        language: string;
    } | undefined;
    password_hash?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
}, {
    email: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    name?: string | undefined;
    device_id?: string | undefined;
    device_type?: "ios" | "android" | "web" | undefined;
    device_name?: string | undefined;
    push_token?: string | undefined;
    biometric_enabled?: boolean | undefined;
    biometric_id?: string | undefined;
    app_version?: string | undefined;
    os_version?: string | undefined;
    last_sync_at?: Date | undefined;
    profile_picture_url?: string | undefined;
    profile_picture_thumbnail?: string | undefined;
    preferences?: {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    } | undefined;
    password_hash?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
}>;
export declare const RegisterUserSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    device_id: z.ZodOptional<z.ZodString>;
    device_type: z.ZodOptional<z.ZodEnum<["ios", "android", "web"]>>;
    device_name: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    name?: string | undefined;
    device_id?: string | undefined;
    device_type?: "ios" | "android" | "web" | undefined;
    device_name?: string | undefined;
}, {
    email: string;
    password: string;
    name?: string | undefined;
    device_id?: string | undefined;
    device_type?: "ios" | "android" | "web" | undefined;
    device_name?: string | undefined;
}>;
export declare const LoginUserSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    device_id: z.ZodOptional<z.ZodString>;
    remember_device: z.ZodDefault<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    remember_device: boolean;
    device_id?: string | undefined;
}, {
    email: string;
    password: string;
    device_id?: string | undefined;
    remember_device?: boolean | undefined;
}>;
export declare const BiometricLoginSchema: z.ZodObject<{
    user_id: z.ZodString;
    biometric_id: z.ZodString;
    device_id: z.ZodString;
    challenge: z.ZodString;
}, "strip", z.ZodTypeAny, {
    user_id: string;
    device_id: string;
    biometric_id: string;
    challenge: string;
}, {
    user_id: string;
    device_id: string;
    biometric_id: string;
    challenge: string;
}>;
export declare const DeviceRegistrationSchema: z.ZodObject<{
    device_id: z.ZodString;
    device_type: z.ZodEnum<["ios", "android"]>;
    device_name: z.ZodString;
    push_token: z.ZodOptional<z.ZodString>;
    app_version: z.ZodString;
    os_version: z.ZodString;
}, "strip", z.ZodTypeAny, {
    device_id: string;
    device_type: "ios" | "android";
    device_name: string;
    app_version: string;
    os_version: string;
    push_token?: string | undefined;
}, {
    device_id: string;
    device_type: "ios" | "android";
    device_name: string;
    app_version: string;
    os_version: string;
    push_token?: string | undefined;
}>;
export declare const UserResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    email: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    password_hash: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
    linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    oauth_provider: z.ZodOptional<z.ZodString>;
} & {
    device_id: z.ZodOptional<z.ZodString>;
    device_type: z.ZodOptional<z.ZodEnum<["ios", "android", "web"]>>;
    device_name: z.ZodOptional<z.ZodString>;
    push_token: z.ZodOptional<z.ZodString>;
    biometric_enabled: z.ZodDefault<z.ZodBoolean>;
    biometric_id: z.ZodOptional<z.ZodString>;
    app_version: z.ZodOptional<z.ZodString>;
    os_version: z.ZodOptional<z.ZodString>;
    last_sync_at: z.ZodOptional<z.ZodDate>;
    profile_picture_url: z.ZodOptional<z.ZodString>;
    profile_picture_thumbnail: z.ZodOptional<z.ZodString>;
    preferences: z.ZodOptional<z.ZodObject<{
        notifications_enabled: z.ZodDefault<z.ZodBoolean>;
        offline_mode_enabled: z.ZodDefault<z.ZodBoolean>;
        data_saver_mode: z.ZodDefault<z.ZodBoolean>;
        theme: z.ZodDefault<z.ZodEnum<["light", "dark", "system"]>>;
        language: z.ZodDefault<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        notifications_enabled: boolean;
        offline_mode_enabled: boolean;
        data_saver_mode: boolean;
        theme: "light" | "dark" | "system";
        language: string;
    }, {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    }>>;
}, "biometric_id" | "password_hash">, "strip", z.ZodTypeAny, {
    biometric_enabled: boolean;
    email: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    name?: string | undefined;
    device_id?: string | undefined;
    device_type?: "ios" | "android" | "web" | undefined;
    device_name?: string | undefined;
    push_token?: string | undefined;
    app_version?: string | undefined;
    os_version?: string | undefined;
    last_sync_at?: Date | undefined;
    profile_picture_url?: string | undefined;
    profile_picture_thumbnail?: string | undefined;
    preferences?: {
        notifications_enabled: boolean;
        offline_mode_enabled: boolean;
        data_saver_mode: boolean;
        theme: "light" | "dark" | "system";
        language: string;
    } | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
}, {
    email: string;
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    name?: string | undefined;
    device_id?: string | undefined;
    device_type?: "ios" | "android" | "web" | undefined;
    device_name?: string | undefined;
    push_token?: string | undefined;
    biometric_enabled?: boolean | undefined;
    app_version?: string | undefined;
    os_version?: string | undefined;
    last_sync_at?: Date | undefined;
    profile_picture_url?: string | undefined;
    profile_picture_thumbnail?: string | undefined;
    preferences?: {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    } | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
}>;
export declare const MobileUserResponseSchema: z.ZodObject<{
    id: z.ZodString;
    email: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    profile_picture_thumbnail: z.ZodOptional<z.ZodString>;
    preferences: z.ZodOptional<z.ZodObject<{
        notifications_enabled: z.ZodBoolean;
        theme: z.ZodEnum<["light", "dark", "system"]>;
    }, "strip", z.ZodTypeAny, {
        notifications_enabled: boolean;
        theme: "light" | "dark" | "system";
    }, {
        notifications_enabled: boolean;
        theme: "light" | "dark" | "system";
    }>>;
}, "strip", z.ZodTypeAny, {
    id: string;
    email: string;
    name?: string | undefined;
    profile_picture_thumbnail?: string | undefined;
    preferences?: {
        notifications_enabled: boolean;
        theme: "light" | "dark" | "system";
    } | undefined;
}, {
    id: string;
    email: string;
    name?: string | undefined;
    profile_picture_thumbnail?: string | undefined;
    preferences?: {
        notifications_enabled: boolean;
        theme: "light" | "dark" | "system";
    } | undefined;
}>;
export declare const AuthResponseSchema: z.ZodObject<{
    user: z.ZodObject<Omit<{
        id: z.ZodOptional<z.ZodString>;
        email: z.ZodString;
        name: z.ZodOptional<z.ZodString>;
        password_hash: z.ZodOptional<z.ZodString>;
        created_at: z.ZodOptional<z.ZodDate>;
        updated_at: z.ZodOptional<z.ZodDate>;
        linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        oauth_provider: z.ZodOptional<z.ZodString>;
    } & {
        device_id: z.ZodOptional<z.ZodString>;
        device_type: z.ZodOptional<z.ZodEnum<["ios", "android", "web"]>>;
        device_name: z.ZodOptional<z.ZodString>;
        push_token: z.ZodOptional<z.ZodString>;
        biometric_enabled: z.ZodDefault<z.ZodBoolean>;
        biometric_id: z.ZodOptional<z.ZodString>;
        app_version: z.ZodOptional<z.ZodString>;
        os_version: z.ZodOptional<z.ZodString>;
        last_sync_at: z.ZodOptional<z.ZodDate>;
        profile_picture_url: z.ZodOptional<z.ZodString>;
        profile_picture_thumbnail: z.ZodOptional<z.ZodString>;
        preferences: z.ZodOptional<z.ZodObject<{
            notifications_enabled: z.ZodDefault<z.ZodBoolean>;
            offline_mode_enabled: z.ZodDefault<z.ZodBoolean>;
            data_saver_mode: z.ZodDefault<z.ZodBoolean>;
            theme: z.ZodDefault<z.ZodEnum<["light", "dark", "system"]>>;
            language: z.ZodDefault<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            notifications_enabled: boolean;
            offline_mode_enabled: boolean;
            data_saver_mode: boolean;
            theme: "light" | "dark" | "system";
            language: string;
        }, {
            notifications_enabled?: boolean | undefined;
            offline_mode_enabled?: boolean | undefined;
            data_saver_mode?: boolean | undefined;
            theme?: "light" | "dark" | "system" | undefined;
            language?: string | undefined;
        }>>;
    }, "biometric_id" | "password_hash">, "strip", z.ZodTypeAny, {
        biometric_enabled: boolean;
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        device_id?: string | undefined;
        device_type?: "ios" | "android" | "web" | undefined;
        device_name?: string | undefined;
        push_token?: string | undefined;
        app_version?: string | undefined;
        os_version?: string | undefined;
        last_sync_at?: Date | undefined;
        profile_picture_url?: string | undefined;
        profile_picture_thumbnail?: string | undefined;
        preferences?: {
            notifications_enabled: boolean;
            offline_mode_enabled: boolean;
            data_saver_mode: boolean;
            theme: "light" | "dark" | "system";
            language: string;
        } | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    }, {
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        device_id?: string | undefined;
        device_type?: "ios" | "android" | "web" | undefined;
        device_name?: string | undefined;
        push_token?: string | undefined;
        biometric_enabled?: boolean | undefined;
        app_version?: string | undefined;
        os_version?: string | undefined;
        last_sync_at?: Date | undefined;
        profile_picture_url?: string | undefined;
        profile_picture_thumbnail?: string | undefined;
        preferences?: {
            notifications_enabled?: boolean | undefined;
            offline_mode_enabled?: boolean | undefined;
            data_saver_mode?: boolean | undefined;
            theme?: "light" | "dark" | "system" | undefined;
            language?: string | undefined;
        } | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    }>;
    token: z.ZodString;
    refresh_token: z.ZodOptional<z.ZodString>;
    expires_in: z.ZodOptional<z.ZodNumber>;
    device_registered: z.ZodOptional<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    user: {
        biometric_enabled: boolean;
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        device_id?: string | undefined;
        device_type?: "ios" | "android" | "web" | undefined;
        device_name?: string | undefined;
        push_token?: string | undefined;
        app_version?: string | undefined;
        os_version?: string | undefined;
        last_sync_at?: Date | undefined;
        profile_picture_url?: string | undefined;
        profile_picture_thumbnail?: string | undefined;
        preferences?: {
            notifications_enabled: boolean;
            offline_mode_enabled: boolean;
            data_saver_mode: boolean;
            theme: "light" | "dark" | "system";
            language: string;
        } | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    };
    token: string;
    refresh_token?: string | undefined;
    expires_in?: number | undefined;
    device_registered?: boolean | undefined;
}, {
    user: {
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        device_id?: string | undefined;
        device_type?: "ios" | "android" | "web" | undefined;
        device_name?: string | undefined;
        push_token?: string | undefined;
        biometric_enabled?: boolean | undefined;
        app_version?: string | undefined;
        os_version?: string | undefined;
        last_sync_at?: Date | undefined;
        profile_picture_url?: string | undefined;
        profile_picture_thumbnail?: string | undefined;
        preferences?: {
            notifications_enabled?: boolean | undefined;
            offline_mode_enabled?: boolean | undefined;
            data_saver_mode?: boolean | undefined;
            theme?: "light" | "dark" | "system" | undefined;
            language?: string | undefined;
        } | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    };
    token: string;
    refresh_token?: string | undefined;
    expires_in?: number | undefined;
    device_registered?: boolean | undefined;
}>;
export declare const MobileAuthResponseSchema: z.ZodObject<{
    user: z.ZodObject<Omit<{
        id: z.ZodOptional<z.ZodString>;
        email: z.ZodString;
        name: z.ZodOptional<z.ZodString>;
        password_hash: z.ZodOptional<z.ZodString>;
        created_at: z.ZodOptional<z.ZodDate>;
        updated_at: z.ZodOptional<z.ZodDate>;
        linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        oauth_provider: z.ZodOptional<z.ZodString>;
    } & {
        device_id: z.ZodOptional<z.ZodString>;
        device_type: z.ZodOptional<z.ZodEnum<["ios", "android", "web"]>>;
        device_name: z.ZodOptional<z.ZodString>;
        push_token: z.ZodOptional<z.ZodString>;
        biometric_enabled: z.ZodDefault<z.ZodBoolean>;
        biometric_id: z.ZodOptional<z.ZodString>;
        app_version: z.ZodOptional<z.ZodString>;
        os_version: z.ZodOptional<z.ZodString>;
        last_sync_at: z.ZodOptional<z.ZodDate>;
        profile_picture_url: z.ZodOptional<z.ZodString>;
        profile_picture_thumbnail: z.ZodOptional<z.ZodString>;
        preferences: z.ZodOptional<z.ZodObject<{
            notifications_enabled: z.ZodDefault<z.ZodBoolean>;
            offline_mode_enabled: z.ZodDefault<z.ZodBoolean>;
            data_saver_mode: z.ZodDefault<z.ZodBoolean>;
            theme: z.ZodDefault<z.ZodEnum<["light", "dark", "system"]>>;
            language: z.ZodDefault<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            notifications_enabled: boolean;
            offline_mode_enabled: boolean;
            data_saver_mode: boolean;
            theme: "light" | "dark" | "system";
            language: string;
        }, {
            notifications_enabled?: boolean | undefined;
            offline_mode_enabled?: boolean | undefined;
            data_saver_mode?: boolean | undefined;
            theme?: "light" | "dark" | "system" | undefined;
            language?: string | undefined;
        }>>;
    }, "biometric_id" | "password_hash">, "strip", z.ZodTypeAny, {
        biometric_enabled: boolean;
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        device_id?: string | undefined;
        device_type?: "ios" | "android" | "web" | undefined;
        device_name?: string | undefined;
        push_token?: string | undefined;
        app_version?: string | undefined;
        os_version?: string | undefined;
        last_sync_at?: Date | undefined;
        profile_picture_url?: string | undefined;
        profile_picture_thumbnail?: string | undefined;
        preferences?: {
            notifications_enabled: boolean;
            offline_mode_enabled: boolean;
            data_saver_mode: boolean;
            theme: "light" | "dark" | "system";
            language: string;
        } | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    }, {
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        device_id?: string | undefined;
        device_type?: "ios" | "android" | "web" | undefined;
        device_name?: string | undefined;
        push_token?: string | undefined;
        biometric_enabled?: boolean | undefined;
        app_version?: string | undefined;
        os_version?: string | undefined;
        last_sync_at?: Date | undefined;
        profile_picture_url?: string | undefined;
        profile_picture_thumbnail?: string | undefined;
        preferences?: {
            notifications_enabled?: boolean | undefined;
            offline_mode_enabled?: boolean | undefined;
            data_saver_mode?: boolean | undefined;
            theme?: "light" | "dark" | "system" | undefined;
            language?: string | undefined;
        } | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    }>;
    token: z.ZodString;
    refresh_token: z.ZodOptional<z.ZodString>;
    expires_in: z.ZodOptional<z.ZodNumber>;
    device_registered: z.ZodOptional<z.ZodBoolean>;
} & {
    sync_required: z.ZodDefault<z.ZodBoolean>;
    server_time: z.ZodString;
    features: z.ZodOptional<z.ZodObject<{
        biometric_available: z.ZodBoolean;
        offline_mode_available: z.ZodBoolean;
        push_notifications_available: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        biometric_available: boolean;
        offline_mode_available: boolean;
        push_notifications_available: boolean;
    }, {
        biometric_available: boolean;
        offline_mode_available: boolean;
        push_notifications_available: boolean;
    }>>;
}, "strip", z.ZodTypeAny, {
    user: {
        biometric_enabled: boolean;
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        device_id?: string | undefined;
        device_type?: "ios" | "android" | "web" | undefined;
        device_name?: string | undefined;
        push_token?: string | undefined;
        app_version?: string | undefined;
        os_version?: string | undefined;
        last_sync_at?: Date | undefined;
        profile_picture_url?: string | undefined;
        profile_picture_thumbnail?: string | undefined;
        preferences?: {
            notifications_enabled: boolean;
            offline_mode_enabled: boolean;
            data_saver_mode: boolean;
            theme: "light" | "dark" | "system";
            language: string;
        } | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    };
    token: string;
    sync_required: boolean;
    server_time: string;
    refresh_token?: string | undefined;
    expires_in?: number | undefined;
    device_registered?: boolean | undefined;
    features?: {
        biometric_available: boolean;
        offline_mode_available: boolean;
        push_notifications_available: boolean;
    } | undefined;
}, {
    user: {
        email: string;
        id?: string | undefined;
        created_at?: Date | undefined;
        updated_at?: Date | undefined;
        name?: string | undefined;
        device_id?: string | undefined;
        device_type?: "ios" | "android" | "web" | undefined;
        device_name?: string | undefined;
        push_token?: string | undefined;
        biometric_enabled?: boolean | undefined;
        app_version?: string | undefined;
        os_version?: string | undefined;
        last_sync_at?: Date | undefined;
        profile_picture_url?: string | undefined;
        profile_picture_thumbnail?: string | undefined;
        preferences?: {
            notifications_enabled?: boolean | undefined;
            offline_mode_enabled?: boolean | undefined;
            data_saver_mode?: boolean | undefined;
            theme?: "light" | "dark" | "system" | undefined;
            language?: string | undefined;
        } | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
    };
    token: string;
    server_time: string;
    refresh_token?: string | undefined;
    expires_in?: number | undefined;
    device_registered?: boolean | undefined;
    sync_required?: boolean | undefined;
    features?: {
        biometric_available: boolean;
        offline_mode_available: boolean;
        push_notifications_available: boolean;
    } | undefined;
}>;
export declare const UpdateUserSchema: z.ZodObject<{
    name: z.ZodOptional<z.ZodString>;
    profile_picture_url: z.ZodOptional<z.ZodString>;
    preferences: z.ZodOptional<z.ZodObject<{
        notifications_enabled: z.ZodOptional<z.ZodBoolean>;
        offline_mode_enabled: z.ZodOptional<z.ZodBoolean>;
        data_saver_mode: z.ZodOptional<z.ZodBoolean>;
        theme: z.ZodOptional<z.ZodEnum<["light", "dark", "system"]>>;
        language: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    }, {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    name?: string | undefined;
    profile_picture_url?: string | undefined;
    preferences?: {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    } | undefined;
}, {
    name?: string | undefined;
    profile_picture_url?: string | undefined;
    preferences?: {
        notifications_enabled?: boolean | undefined;
        offline_mode_enabled?: boolean | undefined;
        data_saver_mode?: boolean | undefined;
        theme?: "light" | "dark" | "system" | undefined;
        language?: string | undefined;
    } | undefined;
}>;
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
export declare const UserFlutterHints: {
    freezed: boolean;
    jsonSerializable: boolean;
    copyWith: boolean;
    equatable: boolean;
    fields: {
        created_at: string;
        updated_at: string;
        last_sync_at: string;
        preferences: string;
        profile_picture_url: string;
        profile_picture_thumbnail: string;
    };
};
export declare const UserHelpers: {
    toMobileResponse: (user: User) => MobileUserResponse;
    needsSync: (user: User) => boolean;
    forOfflineStorage: (user: UserResponse) => Partial<UserResponse>;
};
//# sourceMappingURL=user.d.ts.map