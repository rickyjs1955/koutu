import { z } from 'zod';
export declare const UserSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    email: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    avatar_url: z.ZodOptional<z.ZodString>;
    oauth_provider: z.ZodOptional<z.ZodString>;
    linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    password_hash: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    email: string;
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    name?: string | undefined;
    password_hash?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
    avatar_url?: string | undefined;
}, {
    email: string;
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    name?: string | undefined;
    password_hash?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
    avatar_url?: string | undefined;
}>;
export declare const RegisterUserSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
}, {
    email: string;
    password: string;
}>;
export declare const LoginUserSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
}, {
    email: string;
    password: string;
}>;
export declare const UserResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    email: z.ZodString;
    name: z.ZodOptional<z.ZodString>;
    avatar_url: z.ZodOptional<z.ZodString>;
    oauth_provider: z.ZodOptional<z.ZodString>;
    linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    password_hash: z.ZodOptional<z.ZodString>;
}, "password_hash">, "strip", z.ZodTypeAny, {
    email: string;
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    name?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
    avatar_url?: string | undefined;
}, {
    email: string;
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    name?: string | undefined;
    linkedProviders?: string[] | undefined;
    oauth_provider?: string | undefined;
    avatar_url?: string | undefined;
}>;
export declare const AuthResponseSchema: z.ZodObject<{
    user: z.ZodObject<Omit<{
        id: z.ZodOptional<z.ZodString>;
        email: z.ZodString;
        name: z.ZodOptional<z.ZodString>;
        avatar_url: z.ZodOptional<z.ZodString>;
        oauth_provider: z.ZodOptional<z.ZodString>;
        linkedProviders: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        password_hash: z.ZodOptional<z.ZodString>;
    }, "password_hash">, "strip", z.ZodTypeAny, {
        email: string;
        id?: string | undefined;
        created_at?: string | Date | undefined;
        updated_at?: string | Date | undefined;
        name?: string | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
        avatar_url?: string | undefined;
    }, {
        email: string;
        id?: string | undefined;
        created_at?: string | Date | undefined;
        updated_at?: string | Date | undefined;
        name?: string | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
        avatar_url?: string | undefined;
    }>;
    token: z.ZodString;
}, "strip", z.ZodTypeAny, {
    user: {
        email: string;
        id?: string | undefined;
        created_at?: string | Date | undefined;
        updated_at?: string | Date | undefined;
        name?: string | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
        avatar_url?: string | undefined;
    };
    token: string;
}, {
    user: {
        email: string;
        id?: string | undefined;
        created_at?: string | Date | undefined;
        updated_at?: string | Date | undefined;
        name?: string | undefined;
        linkedProviders?: string[] | undefined;
        oauth_provider?: string | undefined;
        avatar_url?: string | undefined;
    };
    token: string;
}>;
export declare const ImageSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodOptional<z.ZodString>;
    file_path: z.ZodString;
    original_metadata: z.ZodOptional<z.ZodObject<{
        filename: z.ZodString;
        mimetype: z.ZodString;
        size: z.ZodNumber;
        uploadedAt: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    } & {
        width: z.ZodOptional<z.ZodNumber>;
        height: z.ZodOptional<z.ZodNumber>;
        format: z.ZodOptional<z.ZodString>;
        density: z.ZodOptional<z.ZodNumber>;
        hasProfile: z.ZodOptional<z.ZodBoolean>;
        hasAlpha: z.ZodOptional<z.ZodBoolean>;
        channels: z.ZodOptional<z.ZodNumber>;
        space: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        size: number;
        filename: string;
        mimetype: string;
        width?: number | undefined;
        height?: number | undefined;
        format?: string | undefined;
        uploadedAt?: string | Date | undefined;
        density?: number | undefined;
        hasProfile?: boolean | undefined;
        hasAlpha?: boolean | undefined;
        channels?: number | undefined;
        space?: string | undefined;
    }, {
        size: number;
        filename: string;
        mimetype: string;
        width?: number | undefined;
        height?: number | undefined;
        format?: string | undefined;
        uploadedAt?: string | Date | undefined;
        density?: number | undefined;
        hasProfile?: boolean | undefined;
        hasAlpha?: boolean | undefined;
        channels?: number | undefined;
        space?: string | undefined;
    }>>;
    upload_date: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled"]>>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    user_id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    original_metadata?: {
        size: number;
        filename: string;
        mimetype: string;
        width?: number | undefined;
        height?: number | undefined;
        format?: string | undefined;
        uploadedAt?: string | Date | undefined;
        density?: number | undefined;
        hasProfile?: boolean | undefined;
        hasAlpha?: boolean | undefined;
        channels?: number | undefined;
        space?: string | undefined;
    } | undefined;
    upload_date?: string | Date | undefined;
}, {
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    user_id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    original_metadata?: {
        size: number;
        filename: string;
        mimetype: string;
        width?: number | undefined;
        height?: number | undefined;
        format?: string | undefined;
        uploadedAt?: string | Date | undefined;
        density?: number | undefined;
        hasProfile?: boolean | undefined;
        hasAlpha?: boolean | undefined;
        channels?: number | undefined;
        space?: string | undefined;
    } | undefined;
    upload_date?: string | Date | undefined;
}>;
export declare const ImageQuerySchema: z.ZodObject<{
    page: z.ZodOptional<z.ZodNumber>;
    limit: z.ZodOptional<z.ZodNumber>;
    offset: z.ZodOptional<z.ZodNumber>;
} & {
    status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled"]>>;
}, "strip", z.ZodTypeAny, {
    status?: "new" | "processed" | "labeled" | undefined;
    page?: number | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
}, {
    status?: "new" | "processed" | "labeled" | undefined;
    page?: number | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
}>;
export declare const UpdateImageStatusSchema: z.ZodObject<{
    status: z.ZodEnum<["new", "processed", "labeled"]>;
}, "strip", z.ZodTypeAny, {
    status: "new" | "processed" | "labeled";
}, {
    status: "new" | "processed" | "labeled";
}>;
export declare const ImageResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodOptional<z.ZodString>;
    file_path: z.ZodString;
    original_metadata: z.ZodOptional<z.ZodObject<{
        filename: z.ZodString;
        mimetype: z.ZodString;
        size: z.ZodNumber;
        uploadedAt: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    } & {
        width: z.ZodOptional<z.ZodNumber>;
        height: z.ZodOptional<z.ZodNumber>;
        format: z.ZodOptional<z.ZodString>;
        density: z.ZodOptional<z.ZodNumber>;
        hasProfile: z.ZodOptional<z.ZodBoolean>;
        hasAlpha: z.ZodOptional<z.ZodBoolean>;
        channels: z.ZodOptional<z.ZodNumber>;
        space: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        size: number;
        filename: string;
        mimetype: string;
        width?: number | undefined;
        height?: number | undefined;
        format?: string | undefined;
        uploadedAt?: string | Date | undefined;
        density?: number | undefined;
        hasProfile?: boolean | undefined;
        hasAlpha?: boolean | undefined;
        channels?: number | undefined;
        space?: string | undefined;
    }, {
        size: number;
        filename: string;
        mimetype: string;
        width?: number | undefined;
        height?: number | undefined;
        format?: string | undefined;
        uploadedAt?: string | Date | undefined;
        density?: number | undefined;
        hasProfile?: boolean | undefined;
        hasAlpha?: boolean | undefined;
        channels?: number | undefined;
        space?: string | undefined;
    }>>;
    upload_date: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled"]>>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "user_id">, "strip", z.ZodTypeAny, {
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    original_metadata?: {
        size: number;
        filename: string;
        mimetype: string;
        width?: number | undefined;
        height?: number | undefined;
        format?: string | undefined;
        uploadedAt?: string | Date | undefined;
        density?: number | undefined;
        hasProfile?: boolean | undefined;
        hasAlpha?: boolean | undefined;
        channels?: number | undefined;
        space?: string | undefined;
    } | undefined;
    upload_date?: string | Date | undefined;
}, {
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    original_metadata?: {
        size: number;
        filename: string;
        mimetype: string;
        width?: number | undefined;
        height?: number | undefined;
        format?: string | undefined;
        uploadedAt?: string | Date | undefined;
        density?: number | undefined;
        hasProfile?: boolean | undefined;
        hasAlpha?: boolean | undefined;
        channels?: number | undefined;
        space?: string | undefined;
    } | undefined;
    upload_date?: string | Date | undefined;
}>;
export declare const BatchUpdateImageStatusSchema: z.ZodObject<{
    imageIds: z.ZodArray<z.ZodString, "many">;
    status: z.ZodEnum<["new", "processed", "labeled"]>;
}, "strip", z.ZodTypeAny, {
    status: "new" | "processed" | "labeled";
    imageIds: string[];
}, {
    status: "new" | "processed" | "labeled";
    imageIds: string[];
}>;
export declare const PolygonMetadataSchema: z.ZodObject<{
    label: z.ZodOptional<z.ZodString>;
    confidence: z.ZodOptional<z.ZodNumber>;
    source: z.ZodOptional<z.ZodString>;
    notes: z.ZodOptional<z.ZodString>;
}, "strict", z.ZodTypeAny, {
    notes?: string | undefined;
    label?: string | undefined;
    confidence?: number | undefined;
    source?: string | undefined;
}, {
    notes?: string | undefined;
    label?: string | undefined;
    confidence?: number | undefined;
    source?: string | undefined;
}>;
export declare const PolygonSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodOptional<z.ZodString>;
    original_image_id: z.ZodString;
    points: z.ZodArray<z.ZodObject<{
        x: z.ZodNumber;
        y: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        x: number;
        y: number;
    }, {
        x: number;
        y: number;
    }>, "many">;
    label: z.ZodOptional<z.ZodString>;
    metadata: z.ZodOptional<z.ZodObject<{
        label: z.ZodOptional<z.ZodString>;
        confidence: z.ZodOptional<z.ZodNumber>;
        source: z.ZodOptional<z.ZodString>;
        notes: z.ZodOptional<z.ZodString>;
    }, "strict", z.ZodTypeAny, {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    }, {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    }>>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    id?: string | undefined;
    user_id?: string | undefined;
    metadata?: {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    } | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    label?: string | undefined;
}, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    id?: string | undefined;
    user_id?: string | undefined;
    metadata?: {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    } | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    label?: string | undefined;
}>;
export declare const CreatePolygonSchema: z.ZodObject<{
    original_image_id: z.ZodString;
    points: z.ZodArray<z.ZodObject<{
        x: z.ZodNumber;
        y: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        x: number;
        y: number;
    }, {
        x: number;
        y: number;
    }>, "many">;
    label: z.ZodOptional<z.ZodString>;
    metadata: z.ZodOptional<z.ZodObject<{
        label: z.ZodOptional<z.ZodString>;
        confidence: z.ZodOptional<z.ZodNumber>;
        source: z.ZodOptional<z.ZodString>;
        notes: z.ZodOptional<z.ZodString>;
    }, "strict", z.ZodTypeAny, {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    }, {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    metadata?: {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    } | undefined;
    label?: string | undefined;
}, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    metadata?: {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    } | undefined;
    label?: string | undefined;
}>;
export declare const UpdatePolygonSchema: z.ZodObject<{
    points: z.ZodOptional<z.ZodArray<z.ZodObject<{
        x: z.ZodNumber;
        y: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        x: number;
        y: number;
    }, {
        x: number;
        y: number;
    }>, "many">>;
    label: z.ZodOptional<z.ZodString>;
    metadata: z.ZodOptional<z.ZodObject<{
        label: z.ZodOptional<z.ZodString>;
        confidence: z.ZodOptional<z.ZodNumber>;
        source: z.ZodOptional<z.ZodString>;
        notes: z.ZodOptional<z.ZodString>;
    }, "strict", z.ZodTypeAny, {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    }, {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    metadata?: {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    } | undefined;
    points?: {
        x: number;
        y: number;
    }[] | undefined;
    label?: string | undefined;
}, {
    metadata?: {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    } | undefined;
    points?: {
        x: number;
        y: number;
    }[] | undefined;
    label?: string | undefined;
}>;
export declare const PolygonResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodOptional<z.ZodString>;
    original_image_id: z.ZodString;
    points: z.ZodArray<z.ZodObject<{
        x: z.ZodNumber;
        y: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        x: number;
        y: number;
    }, {
        x: number;
        y: number;
    }>, "many">;
    label: z.ZodOptional<z.ZodString>;
    metadata: z.ZodOptional<z.ZodObject<{
        label: z.ZodOptional<z.ZodString>;
        confidence: z.ZodOptional<z.ZodNumber>;
        source: z.ZodOptional<z.ZodString>;
        notes: z.ZodOptional<z.ZodString>;
    }, "strict", z.ZodTypeAny, {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    }, {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    }>>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "user_id">, "strip", z.ZodTypeAny, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    id?: string | undefined;
    metadata?: {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    } | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    label?: string | undefined;
}, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    id?: string | undefined;
    metadata?: {
        notes?: string | undefined;
        label?: string | undefined;
        confidence?: number | undefined;
        source?: string | undefined;
    } | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    label?: string | undefined;
}>;
export declare const MaskDataSchema: z.ZodEffects<z.ZodObject<{
    width: z.ZodNumber;
    height: z.ZodNumber;
    data: z.ZodUnion<[z.ZodArray<z.ZodNumber, "many">, z.ZodType<Uint8ClampedArray<ArrayBuffer>, z.ZodTypeDef, Uint8ClampedArray<ArrayBuffer>>]>;
}, "strip", z.ZodTypeAny, {
    width: number;
    height: number;
    data: number[] | Uint8ClampedArray<ArrayBuffer>;
}, {
    width: number;
    height: number;
    data: number[] | Uint8ClampedArray<ArrayBuffer>;
}>, {
    width: number;
    height: number;
    data: number[] | Uint8ClampedArray<ArrayBuffer>;
}, {
    width: number;
    height: number;
    data: number[] | Uint8ClampedArray<ArrayBuffer>;
}>;
export declare const GarmentMetadataSchema: z.ZodObject<{
    type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
    color: z.ZodString;
    pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
    season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
    brand: z.ZodOptional<z.ZodString>;
    size: z.ZodOptional<z.ZodString>;
    material: z.ZodOptional<z.ZodString>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
}, "strict", z.ZodTypeAny, {
    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
    color: string;
    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
    brand?: string | undefined;
    size?: string | undefined;
    material?: string | undefined;
    tags?: string[] | undefined;
}, {
    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
    color: string;
    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
    brand?: string | undefined;
    size?: string | undefined;
    material?: string | undefined;
    tags?: string[] | undefined;
}>;
export declare const GarmentSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodOptional<z.ZodString>;
    original_image_id: z.ZodString;
    file_path: z.ZodString;
    mask_path: z.ZodString;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
        color: z.ZodString;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        brand: z.ZodOptional<z.ZodString>;
        size: z.ZodOptional<z.ZodString>;
        material: z.ZodOptional<z.ZodString>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strict", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    }>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    data_version: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    file_path: string;
    mask_path: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    };
    id?: string | undefined;
    user_id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    data_version?: number | undefined;
}, {
    original_image_id: string;
    file_path: string;
    mask_path: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    };
    id?: string | undefined;
    user_id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    data_version?: number | undefined;
}>;
export declare const CreateGarmentSchema: z.ZodObject<{
    original_image_id: z.ZodString;
    mask_data: z.ZodEffects<z.ZodObject<{
        width: z.ZodNumber;
        height: z.ZodNumber;
        data: z.ZodUnion<[z.ZodArray<z.ZodNumber, "many">, z.ZodType<Uint8ClampedArray<ArrayBuffer>, z.ZodTypeDef, Uint8ClampedArray<ArrayBuffer>>]>;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
        data: number[] | Uint8ClampedArray<ArrayBuffer>;
    }, {
        width: number;
        height: number;
        data: number[] | Uint8ClampedArray<ArrayBuffer>;
    }>, {
        width: number;
        height: number;
        data: number[] | Uint8ClampedArray<ArrayBuffer>;
    }, {
        width: number;
        height: number;
        data: number[] | Uint8ClampedArray<ArrayBuffer>;
    }>;
    metadata: z.ZodOptional<z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
        color: z.ZodString;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        brand: z.ZodOptional<z.ZodString>;
        size: z.ZodOptional<z.ZodString>;
        material: z.ZodOptional<z.ZodString>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strict", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    mask_data: {
        width: number;
        height: number;
        data: number[] | Uint8ClampedArray<ArrayBuffer>;
    };
    metadata?: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    } | undefined;
}, {
    original_image_id: string;
    mask_data: {
        width: number;
        height: number;
        data: number[] | Uint8ClampedArray<ArrayBuffer>;
    };
    metadata?: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    } | undefined;
}>;
export declare const UpdateGarmentMetadataSchema: z.ZodObject<{
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
        color: z.ZodString;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        brand: z.ZodOptional<z.ZodString>;
        size: z.ZodOptional<z.ZodString>;
        material: z.ZodOptional<z.ZodString>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strict", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    }>;
}, "strip", z.ZodTypeAny, {
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    };
}, {
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    };
}>;
export declare const GarmentQuerySchema: z.ZodObject<{
    page: z.ZodOptional<z.ZodNumber>;
    limit: z.ZodOptional<z.ZodNumber>;
    offset: z.ZodOptional<z.ZodNumber>;
} & {
    filter: z.ZodEffects<z.ZodOptional<z.ZodString>, any, string | undefined>;
    replace: z.ZodEffects<z.ZodOptional<z.ZodEnum<["true", "false"]>>, boolean, "true" | "false" | undefined>;
}, "strip", z.ZodTypeAny, {
    replace: boolean;
    filter?: any;
    page?: number | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
}, {
    filter?: string | undefined;
    page?: number | undefined;
    limit?: number | undefined;
    offset?: number | undefined;
    replace?: "true" | "false" | undefined;
}>;
export declare const GarmentResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodOptional<z.ZodString>;
    original_image_id: z.ZodString;
    file_path: z.ZodString;
    mask_path: z.ZodString;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
        color: z.ZodString;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        brand: z.ZodOptional<z.ZodString>;
        size: z.ZodOptional<z.ZodString>;
        material: z.ZodOptional<z.ZodString>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strict", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    }>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    data_version: z.ZodOptional<z.ZodNumber>;
}, "user_id">, "strip", z.ZodTypeAny, {
    original_image_id: string;
    file_path: string;
    mask_path: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    };
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    data_version?: number | undefined;
}, {
    original_image_id: string;
    file_path: string;
    mask_path: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        tags?: string[] | undefined;
    };
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    data_version?: number | undefined;
}>;
export declare const WardrobeSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    description: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    name: string;
    id?: string | undefined;
    user_id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    description?: string | undefined;
}, {
    name: string;
    id?: string | undefined;
    user_id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    description?: string | undefined;
}>;
export declare const CreateWardrobeSchema: z.ZodObject<{
    name: z.ZodString;
    description: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    name: string;
    description?: string | undefined;
}, {
    name: string;
    description?: string | undefined;
}>;
export declare const UpdateWardrobeSchema: z.ZodObject<{
    name: z.ZodOptional<z.ZodString>;
    description: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    name?: string | undefined;
    description?: string | undefined;
}, {
    name?: string | undefined;
    description?: string | undefined;
}>;
export declare const AddGarmentToWardrobeSchema: z.ZodObject<{
    garmentId: z.ZodString;
    position: z.ZodOptional<z.ZodNumber>;
}, "strip", z.ZodTypeAny, {
    garmentId: string;
    position?: number | undefined;
}, {
    garmentId: string;
    position?: number | undefined;
}>;
export declare const WardrobeResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodOptional<z.ZodString>;
    name: z.ZodString;
    description: z.ZodOptional<z.ZodString>;
    created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "user_id"> & {
    garments: z.ZodOptional<z.ZodArray<z.ZodObject<Omit<{
        id: z.ZodOptional<z.ZodString>;
        user_id: z.ZodOptional<z.ZodString>;
        original_image_id: z.ZodString;
        file_path: z.ZodString;
        mask_path: z.ZodString;
        metadata: z.ZodObject<{
            type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
            color: z.ZodString;
            pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
            season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
            brand: z.ZodOptional<z.ZodString>;
            size: z.ZodOptional<z.ZodString>;
            material: z.ZodOptional<z.ZodString>;
            tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        }, "strict", z.ZodTypeAny, {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
            color: string;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            tags?: string[] | undefined;
        }, {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
            color: string;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            tags?: string[] | undefined;
        }>;
        created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        data_version: z.ZodOptional<z.ZodNumber>;
    }, "user_id">, "strip", z.ZodTypeAny, {
        original_image_id: string;
        file_path: string;
        mask_path: string;
        metadata: {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
            color: string;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            tags?: string[] | undefined;
        };
        id?: string | undefined;
        created_at?: string | Date | undefined;
        updated_at?: string | Date | undefined;
        data_version?: number | undefined;
    }, {
        original_image_id: string;
        file_path: string;
        mask_path: string;
        metadata: {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
            color: string;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            tags?: string[] | undefined;
        };
        id?: string | undefined;
        created_at?: string | Date | undefined;
        updated_at?: string | Date | undefined;
        data_version?: number | undefined;
    }>, "many">>;
}, "strip", z.ZodTypeAny, {
    name: string;
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    garments?: {
        original_image_id: string;
        file_path: string;
        mask_path: string;
        metadata: {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
            color: string;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            tags?: string[] | undefined;
        };
        id?: string | undefined;
        created_at?: string | Date | undefined;
        updated_at?: string | Date | undefined;
        data_version?: number | undefined;
    }[] | undefined;
    description?: string | undefined;
}, {
    name: string;
    id?: string | undefined;
    created_at?: string | Date | undefined;
    updated_at?: string | Date | undefined;
    garments?: {
        original_image_id: string;
        file_path: string;
        mask_path: string;
        metadata: {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
            color: string;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            tags?: string[] | undefined;
        };
        id?: string | undefined;
        created_at?: string | Date | undefined;
        updated_at?: string | Date | undefined;
        data_version?: number | undefined;
    }[] | undefined;
    description?: string | undefined;
}>;
export declare const MLExportOptionsSchema: z.ZodObject<{
    format: z.ZodEnum<["coco", "yolo", "pascal_voc", "csv", "raw_json"]>;
    garmentIds: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    categoryFilter: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    imageFormat: z.ZodDefault<z.ZodEnum<["jpg", "png", "webp"]>>;
    compressionQuality: z.ZodDefault<z.ZodNumber>;
    includeMasks: z.ZodDefault<z.ZodBoolean>;
    includePolygons: z.ZodDefault<z.ZodBoolean>;
    includeImages: z.ZodDefault<z.ZodBoolean>;
    includeRawPolygons: z.ZodDefault<z.ZodBoolean>;
    dateRange: z.ZodOptional<z.ZodObject<{
        from: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        to: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    }, "strip", z.ZodTypeAny, {
        from?: string | Date | undefined;
        to?: string | Date | undefined;
    }, {
        from?: string | Date | undefined;
        to?: string | Date | undefined;
    }>>;
    splitRatio: z.ZodOptional<z.ZodEffects<z.ZodObject<{
        train: z.ZodNumber;
        validation: z.ZodNumber;
        test: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        validation: number;
        train: number;
        test: number;
    }, {
        validation: number;
        train: number;
        test: number;
    }>, {
        validation: number;
        train: number;
        test: number;
    }, {
        validation: number;
        train: number;
        test: number;
    }>>;
}, "strip", z.ZodTypeAny, {
    format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
    includeImages: boolean;
    includeRawPolygons: boolean;
    includeMasks: boolean;
    imageFormat: "jpg" | "png" | "webp";
    compressionQuality: number;
    includePolygons: boolean;
    garmentIds?: string[] | undefined;
    categoryFilter?: string[] | undefined;
    dateRange?: {
        from?: string | Date | undefined;
        to?: string | Date | undefined;
    } | undefined;
    splitRatio?: {
        validation: number;
        train: number;
        test: number;
    } | undefined;
}, {
    format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
    includeImages?: boolean | undefined;
    includeRawPolygons?: boolean | undefined;
    includeMasks?: boolean | undefined;
    imageFormat?: "jpg" | "png" | "webp" | undefined;
    compressionQuality?: number | undefined;
    garmentIds?: string[] | undefined;
    categoryFilter?: string[] | undefined;
    dateRange?: {
        from?: string | Date | undefined;
        to?: string | Date | undefined;
    } | undefined;
    includePolygons?: boolean | undefined;
    splitRatio?: {
        validation: number;
        train: number;
        test: number;
    } | undefined;
}>;
export declare const CreateMLExportSchema: z.ZodObject<{
    options: z.ZodObject<{
        format: z.ZodEnum<["coco", "yolo", "pascal_voc", "csv", "raw_json"]>;
        garmentIds: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        categoryFilter: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        imageFormat: z.ZodDefault<z.ZodEnum<["jpg", "png", "webp"]>>;
        compressionQuality: z.ZodDefault<z.ZodNumber>;
        includeMasks: z.ZodDefault<z.ZodBoolean>;
        includePolygons: z.ZodDefault<z.ZodBoolean>;
        includeImages: z.ZodDefault<z.ZodBoolean>;
        includeRawPolygons: z.ZodDefault<z.ZodBoolean>;
        dateRange: z.ZodOptional<z.ZodObject<{
            from: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            to: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        }, "strip", z.ZodTypeAny, {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        }, {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        }>>;
        splitRatio: z.ZodOptional<z.ZodEffects<z.ZodObject<{
            train: z.ZodNumber;
            validation: z.ZodNumber;
            test: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            validation: number;
            train: number;
            test: number;
        }, {
            validation: number;
            train: number;
            test: number;
        }>, {
            validation: number;
            train: number;
            test: number;
        }, {
            validation: number;
            train: number;
            test: number;
        }>>;
    }, "strip", z.ZodTypeAny, {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages: boolean;
        includeRawPolygons: boolean;
        includeMasks: boolean;
        imageFormat: "jpg" | "png" | "webp";
        compressionQuality: number;
        includePolygons: boolean;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        } | undefined;
        splitRatio?: {
            validation: number;
            train: number;
            test: number;
        } | undefined;
    }, {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages?: boolean | undefined;
        includeRawPolygons?: boolean | undefined;
        includeMasks?: boolean | undefined;
        imageFormat?: "jpg" | "png" | "webp" | undefined;
        compressionQuality?: number | undefined;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        } | undefined;
        includePolygons?: boolean | undefined;
        splitRatio?: {
            validation: number;
            train: number;
            test: number;
        } | undefined;
    }>;
}, "strip", z.ZodTypeAny, {
    options: {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages: boolean;
        includeRawPolygons: boolean;
        includeMasks: boolean;
        imageFormat: "jpg" | "png" | "webp";
        compressionQuality: number;
        includePolygons: boolean;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        } | undefined;
        splitRatio?: {
            validation: number;
            train: number;
            test: number;
        } | undefined;
    };
}, {
    options: {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages?: boolean | undefined;
        includeRawPolygons?: boolean | undefined;
        includeMasks?: boolean | undefined;
        imageFormat?: "jpg" | "png" | "webp" | undefined;
        compressionQuality?: number | undefined;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        } | undefined;
        includePolygons?: boolean | undefined;
        splitRatio?: {
            validation: number;
            train: number;
            test: number;
        } | undefined;
    };
}>;
export declare const MLExportBatchJobSchema: z.ZodObject<{
    id: z.ZodString;
    userId: z.ZodString;
    status: z.ZodEnum<["pending", "processing", "completed", "failed", "cancelled"]>;
    options: z.ZodObject<{
        format: z.ZodEnum<["coco", "yolo", "pascal_voc", "csv", "raw_json"]>;
        garmentIds: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        categoryFilter: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        imageFormat: z.ZodDefault<z.ZodEnum<["jpg", "png", "webp"]>>;
        compressionQuality: z.ZodDefault<z.ZodNumber>;
        includeMasks: z.ZodDefault<z.ZodBoolean>;
        includePolygons: z.ZodDefault<z.ZodBoolean>;
        includeImages: z.ZodDefault<z.ZodBoolean>;
        includeRawPolygons: z.ZodDefault<z.ZodBoolean>;
        dateRange: z.ZodOptional<z.ZodObject<{
            from: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            to: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        }, "strip", z.ZodTypeAny, {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        }, {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        }>>;
        splitRatio: z.ZodOptional<z.ZodEffects<z.ZodObject<{
            train: z.ZodNumber;
            validation: z.ZodNumber;
            test: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            validation: number;
            train: number;
            test: number;
        }, {
            validation: number;
            train: number;
            test: number;
        }>, {
            validation: number;
            train: number;
            test: number;
        }, {
            validation: number;
            train: number;
            test: number;
        }>>;
    }, "strip", z.ZodTypeAny, {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages: boolean;
        includeRawPolygons: boolean;
        includeMasks: boolean;
        imageFormat: "jpg" | "png" | "webp";
        compressionQuality: number;
        includePolygons: boolean;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        } | undefined;
        splitRatio?: {
            validation: number;
            train: number;
            test: number;
        } | undefined;
    }, {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages?: boolean | undefined;
        includeRawPolygons?: boolean | undefined;
        includeMasks?: boolean | undefined;
        imageFormat?: "jpg" | "png" | "webp" | undefined;
        compressionQuality?: number | undefined;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        } | undefined;
        includePolygons?: boolean | undefined;
        splitRatio?: {
            validation: number;
            train: number;
            test: number;
        } | undefined;
    }>;
    progress: z.ZodDefault<z.ZodNumber>;
    totalItems: z.ZodDefault<z.ZodNumber>;
    processedItems: z.ZodDefault<z.ZodNumber>;
    outputUrl: z.ZodOptional<z.ZodString>;
    error: z.ZodOptional<z.ZodString>;
    createdAt: z.ZodUnion<[z.ZodString, z.ZodDate]>;
    updatedAt: z.ZodUnion<[z.ZodString, z.ZodDate]>;
    completedAt: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
    expiresAt: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    options: {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages: boolean;
        includeRawPolygons: boolean;
        includeMasks: boolean;
        imageFormat: "jpg" | "png" | "webp";
        compressionQuality: number;
        includePolygons: boolean;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        } | undefined;
        splitRatio?: {
            validation: number;
            train: number;
            test: number;
        } | undefined;
    };
    status: "pending" | "processing" | "completed" | "failed" | "cancelled";
    id: string;
    createdAt: string | Date;
    updatedAt: string | Date;
    userId: string;
    progress: number;
    totalItems: number;
    processedItems: number;
    outputUrl?: string | undefined;
    error?: string | undefined;
    completedAt?: string | Date | undefined;
    expiresAt?: string | Date | undefined;
}, {
    options: {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages?: boolean | undefined;
        includeRawPolygons?: boolean | undefined;
        includeMasks?: boolean | undefined;
        imageFormat?: "jpg" | "png" | "webp" | undefined;
        compressionQuality?: number | undefined;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | Date | undefined;
            to?: string | Date | undefined;
        } | undefined;
        includePolygons?: boolean | undefined;
        splitRatio?: {
            validation: number;
            train: number;
            test: number;
        } | undefined;
    };
    status: "pending" | "processing" | "completed" | "failed" | "cancelled";
    id: string;
    createdAt: string | Date;
    updatedAt: string | Date;
    userId: string;
    progress?: number | undefined;
    totalItems?: number | undefined;
    processedItems?: number | undefined;
    outputUrl?: string | undefined;
    error?: string | undefined;
    completedAt?: string | Date | undefined;
    expiresAt?: string | Date | undefined;
}>;
export declare const DatasetStatsSchema: z.ZodObject<{
    totalImages: z.ZodNumber;
    totalGarments: z.ZodNumber;
    categoryCounts: z.ZodRecord<z.ZodString, z.ZodNumber>;
    attributeCounts: z.ZodRecord<z.ZodString, z.ZodRecord<z.ZodString, z.ZodNumber>>;
    averagePolygonPoints: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    totalImages: number;
    totalGarments: number;
    categoryCounts: Record<string, number>;
    attributeCounts: Record<string, Record<string, number>>;
    averagePolygonPoints: number;
}, {
    totalImages: number;
    totalGarments: number;
    categoryCounts: Record<string, number>;
    attributeCounts: Record<string, Record<string, number>>;
    averagePolygonPoints: number;
}>;
export declare const UUIDParamSchema: z.ZodObject<{
    id: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
}, {
    id: string;
}>;
export declare const ImageIdParamSchema: z.ZodObject<{
    imageId: z.ZodString;
}, "strip", z.ZodTypeAny, {
    imageId: string;
}, {
    imageId: string;
}>;
export declare const JobIdParamSchema: z.ZodObject<{
    jobId: z.ZodString;
}, "strip", z.ZodTypeAny, {
    jobId: string;
}, {
    jobId: string;
}>;
export declare const WardrobeItemParamSchema: z.ZodObject<{
    id: z.ZodString;
    itemId: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
    itemId: string;
}, {
    id: string;
    itemId: string;
}>;
export declare const ImageListResponseSchema: z.ZodObject<{
    status: z.ZodLiteral<"success">;
    data: z.ZodObject<{
        images: z.ZodArray<z.ZodObject<Omit<{
            id: z.ZodOptional<z.ZodString>;
            user_id: z.ZodOptional<z.ZodString>;
            file_path: z.ZodString;
            original_metadata: z.ZodOptional<z.ZodObject<{
                filename: z.ZodString;
                mimetype: z.ZodString;
                size: z.ZodNumber;
                uploadedAt: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            } & {
                width: z.ZodOptional<z.ZodNumber>;
                height: z.ZodOptional<z.ZodNumber>;
                format: z.ZodOptional<z.ZodString>;
                density: z.ZodOptional<z.ZodNumber>;
                hasProfile: z.ZodOptional<z.ZodBoolean>;
                hasAlpha: z.ZodOptional<z.ZodBoolean>;
                channels: z.ZodOptional<z.ZodNumber>;
                space: z.ZodOptional<z.ZodString>;
            }, "strip", z.ZodTypeAny, {
                size: number;
                filename: string;
                mimetype: string;
                width?: number | undefined;
                height?: number | undefined;
                format?: string | undefined;
                uploadedAt?: string | Date | undefined;
                density?: number | undefined;
                hasProfile?: boolean | undefined;
                hasAlpha?: boolean | undefined;
                channels?: number | undefined;
                space?: string | undefined;
            }, {
                size: number;
                filename: string;
                mimetype: string;
                width?: number | undefined;
                height?: number | undefined;
                format?: string | undefined;
                uploadedAt?: string | Date | undefined;
                density?: number | undefined;
                hasProfile?: boolean | undefined;
                hasAlpha?: boolean | undefined;
                channels?: number | undefined;
                space?: string | undefined;
            }>>;
            upload_date: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled"]>>;
            created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        }, "user_id">, "strip", z.ZodTypeAny, {
            file_path: string;
            status?: "new" | "processed" | "labeled" | undefined;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            original_metadata?: {
                size: number;
                filename: string;
                mimetype: string;
                width?: number | undefined;
                height?: number | undefined;
                format?: string | undefined;
                uploadedAt?: string | Date | undefined;
                density?: number | undefined;
                hasProfile?: boolean | undefined;
                hasAlpha?: boolean | undefined;
                channels?: number | undefined;
                space?: string | undefined;
            } | undefined;
            upload_date?: string | Date | undefined;
        }, {
            file_path: string;
            status?: "new" | "processed" | "labeled" | undefined;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            original_metadata?: {
                size: number;
                filename: string;
                mimetype: string;
                width?: number | undefined;
                height?: number | undefined;
                format?: string | undefined;
                uploadedAt?: string | Date | undefined;
                density?: number | undefined;
                hasProfile?: boolean | undefined;
                hasAlpha?: boolean | undefined;
                channels?: number | undefined;
                space?: string | undefined;
            } | undefined;
            upload_date?: string | Date | undefined;
        }>, "many">;
        count: z.ZodNumber;
        pagination: z.ZodOptional<z.ZodObject<{
            page: z.ZodOptional<z.ZodNumber>;
            limit: z.ZodOptional<z.ZodNumber>;
            offset: z.ZodOptional<z.ZodNumber>;
        }, "strip", z.ZodTypeAny, {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        }, {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        images: {
            file_path: string;
            status?: "new" | "processed" | "labeled" | undefined;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            original_metadata?: {
                size: number;
                filename: string;
                mimetype: string;
                width?: number | undefined;
                height?: number | undefined;
                format?: string | undefined;
                uploadedAt?: string | Date | undefined;
                density?: number | undefined;
                hasProfile?: boolean | undefined;
                hasAlpha?: boolean | undefined;
                channels?: number | undefined;
                space?: string | undefined;
            } | undefined;
            upload_date?: string | Date | undefined;
        }[];
        count: number;
        pagination?: {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        } | undefined;
    }, {
        images: {
            file_path: string;
            status?: "new" | "processed" | "labeled" | undefined;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            original_metadata?: {
                size: number;
                filename: string;
                mimetype: string;
                width?: number | undefined;
                height?: number | undefined;
                format?: string | undefined;
                uploadedAt?: string | Date | undefined;
                density?: number | undefined;
                hasProfile?: boolean | undefined;
                hasAlpha?: boolean | undefined;
                channels?: number | undefined;
                space?: string | undefined;
            } | undefined;
            upload_date?: string | Date | undefined;
        }[];
        count: number;
        pagination?: {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        } | undefined;
    }>;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    status: "success";
    data: {
        images: {
            file_path: string;
            status?: "new" | "processed" | "labeled" | undefined;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            original_metadata?: {
                size: number;
                filename: string;
                mimetype: string;
                width?: number | undefined;
                height?: number | undefined;
                format?: string | undefined;
                uploadedAt?: string | Date | undefined;
                density?: number | undefined;
                hasProfile?: boolean | undefined;
                hasAlpha?: boolean | undefined;
                channels?: number | undefined;
                space?: string | undefined;
            } | undefined;
            upload_date?: string | Date | undefined;
        }[];
        count: number;
        pagination?: {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        } | undefined;
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}, {
    status: "success";
    data: {
        images: {
            file_path: string;
            status?: "new" | "processed" | "labeled" | undefined;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            original_metadata?: {
                size: number;
                filename: string;
                mimetype: string;
                width?: number | undefined;
                height?: number | undefined;
                format?: string | undefined;
                uploadedAt?: string | Date | undefined;
                density?: number | undefined;
                hasProfile?: boolean | undefined;
                hasAlpha?: boolean | undefined;
                channels?: number | undefined;
                space?: string | undefined;
            } | undefined;
            upload_date?: string | Date | undefined;
        }[];
        count: number;
        pagination?: {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        } | undefined;
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}>;
export declare const PolygonListResponseSchema: z.ZodObject<{
    status: z.ZodLiteral<"success">;
    data: z.ZodObject<{
        polygons: z.ZodArray<z.ZodObject<Omit<{
            id: z.ZodOptional<z.ZodString>;
            user_id: z.ZodOptional<z.ZodString>;
            original_image_id: z.ZodString;
            points: z.ZodArray<z.ZodObject<{
                x: z.ZodNumber;
                y: z.ZodNumber;
            }, "strip", z.ZodTypeAny, {
                x: number;
                y: number;
            }, {
                x: number;
                y: number;
            }>, "many">;
            label: z.ZodOptional<z.ZodString>;
            metadata: z.ZodOptional<z.ZodObject<{
                label: z.ZodOptional<z.ZodString>;
                confidence: z.ZodOptional<z.ZodNumber>;
                source: z.ZodOptional<z.ZodString>;
                notes: z.ZodOptional<z.ZodString>;
            }, "strict", z.ZodTypeAny, {
                notes?: string | undefined;
                label?: string | undefined;
                confidence?: number | undefined;
                source?: string | undefined;
            }, {
                notes?: string | undefined;
                label?: string | undefined;
                confidence?: number | undefined;
                source?: string | undefined;
            }>>;
            created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        }, "user_id">, "strip", z.ZodTypeAny, {
            original_image_id: string;
            points: {
                x: number;
                y: number;
            }[];
            id?: string | undefined;
            metadata?: {
                notes?: string | undefined;
                label?: string | undefined;
                confidence?: number | undefined;
                source?: string | undefined;
            } | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            label?: string | undefined;
        }, {
            original_image_id: string;
            points: {
                x: number;
                y: number;
            }[];
            id?: string | undefined;
            metadata?: {
                notes?: string | undefined;
                label?: string | undefined;
                confidence?: number | undefined;
                source?: string | undefined;
            } | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            label?: string | undefined;
        }>, "many">;
        count: z.ZodNumber;
        imageId: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        imageId: string;
        count: number;
        polygons: {
            original_image_id: string;
            points: {
                x: number;
                y: number;
            }[];
            id?: string | undefined;
            metadata?: {
                notes?: string | undefined;
                label?: string | undefined;
                confidence?: number | undefined;
                source?: string | undefined;
            } | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            label?: string | undefined;
        }[];
    }, {
        imageId: string;
        count: number;
        polygons: {
            original_image_id: string;
            points: {
                x: number;
                y: number;
            }[];
            id?: string | undefined;
            metadata?: {
                notes?: string | undefined;
                label?: string | undefined;
                confidence?: number | undefined;
                source?: string | undefined;
            } | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            label?: string | undefined;
        }[];
    }>;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    status: "success";
    data: {
        imageId: string;
        count: number;
        polygons: {
            original_image_id: string;
            points: {
                x: number;
                y: number;
            }[];
            id?: string | undefined;
            metadata?: {
                notes?: string | undefined;
                label?: string | undefined;
                confidence?: number | undefined;
                source?: string | undefined;
            } | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            label?: string | undefined;
        }[];
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}, {
    status: "success";
    data: {
        imageId: string;
        count: number;
        polygons: {
            original_image_id: string;
            points: {
                x: number;
                y: number;
            }[];
            id?: string | undefined;
            metadata?: {
                notes?: string | undefined;
                label?: string | undefined;
                confidence?: number | undefined;
                source?: string | undefined;
            } | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            label?: string | undefined;
        }[];
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}>;
export declare const GarmentListResponseSchema: z.ZodObject<{
    status: z.ZodLiteral<"success">;
    data: z.ZodObject<{
        garments: z.ZodArray<z.ZodObject<Omit<{
            id: z.ZodOptional<z.ZodString>;
            user_id: z.ZodOptional<z.ZodString>;
            original_image_id: z.ZodString;
            file_path: z.ZodString;
            mask_path: z.ZodString;
            metadata: z.ZodObject<{
                type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
                color: z.ZodString;
                pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
                season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
                brand: z.ZodOptional<z.ZodString>;
                size: z.ZodOptional<z.ZodString>;
                material: z.ZodOptional<z.ZodString>;
                tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
            }, "strict", z.ZodTypeAny, {
                type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                color: string;
                pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                brand?: string | undefined;
                size?: string | undefined;
                material?: string | undefined;
                tags?: string[] | undefined;
            }, {
                type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                color: string;
                pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                brand?: string | undefined;
                size?: string | undefined;
                material?: string | undefined;
                tags?: string[] | undefined;
            }>;
            created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            data_version: z.ZodOptional<z.ZodNumber>;
        }, "user_id">, "strip", z.ZodTypeAny, {
            original_image_id: string;
            file_path: string;
            mask_path: string;
            metadata: {
                type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                color: string;
                pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                brand?: string | undefined;
                size?: string | undefined;
                material?: string | undefined;
                tags?: string[] | undefined;
            };
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            data_version?: number | undefined;
        }, {
            original_image_id: string;
            file_path: string;
            mask_path: string;
            metadata: {
                type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                color: string;
                pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                brand?: string | undefined;
                size?: string | undefined;
                material?: string | undefined;
                tags?: string[] | undefined;
            };
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            data_version?: number | undefined;
        }>, "many">;
        count: z.ZodNumber;
        pagination: z.ZodOptional<z.ZodObject<{
            page: z.ZodOptional<z.ZodNumber>;
            limit: z.ZodOptional<z.ZodNumber>;
            offset: z.ZodOptional<z.ZodNumber>;
        }, "strip", z.ZodTypeAny, {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        }, {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        garments: {
            original_image_id: string;
            file_path: string;
            mask_path: string;
            metadata: {
                type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                color: string;
                pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                brand?: string | undefined;
                size?: string | undefined;
                material?: string | undefined;
                tags?: string[] | undefined;
            };
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            data_version?: number | undefined;
        }[];
        count: number;
        pagination?: {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        } | undefined;
    }, {
        garments: {
            original_image_id: string;
            file_path: string;
            mask_path: string;
            metadata: {
                type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                color: string;
                pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                brand?: string | undefined;
                size?: string | undefined;
                material?: string | undefined;
                tags?: string[] | undefined;
            };
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            data_version?: number | undefined;
        }[];
        count: number;
        pagination?: {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        } | undefined;
    }>;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    status: "success";
    data: {
        garments: {
            original_image_id: string;
            file_path: string;
            mask_path: string;
            metadata: {
                type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                color: string;
                pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                brand?: string | undefined;
                size?: string | undefined;
                material?: string | undefined;
                tags?: string[] | undefined;
            };
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            data_version?: number | undefined;
        }[];
        count: number;
        pagination?: {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        } | undefined;
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}, {
    status: "success";
    data: {
        garments: {
            original_image_id: string;
            file_path: string;
            mask_path: string;
            metadata: {
                type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                color: string;
                pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                brand?: string | undefined;
                size?: string | undefined;
                material?: string | undefined;
                tags?: string[] | undefined;
            };
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            data_version?: number | undefined;
        }[];
        count: number;
        pagination?: {
            page?: number | undefined;
            limit?: number | undefined;
            offset?: number | undefined;
        } | undefined;
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}>;
export declare const WardrobeListResponseSchema: z.ZodObject<{
    status: z.ZodLiteral<"success">;
    data: z.ZodObject<{
        wardrobes: z.ZodArray<z.ZodObject<Omit<{
            id: z.ZodOptional<z.ZodString>;
            user_id: z.ZodOptional<z.ZodString>;
            name: z.ZodString;
            description: z.ZodOptional<z.ZodString>;
            created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        }, "user_id"> & {
            garments: z.ZodOptional<z.ZodArray<z.ZodObject<Omit<{
                id: z.ZodOptional<z.ZodString>;
                user_id: z.ZodOptional<z.ZodString>;
                original_image_id: z.ZodString;
                file_path: z.ZodString;
                mask_path: z.ZodString;
                metadata: z.ZodObject<{
                    type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
                    color: z.ZodString;
                    pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
                    season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
                    brand: z.ZodOptional<z.ZodString>;
                    size: z.ZodOptional<z.ZodString>;
                    material: z.ZodOptional<z.ZodString>;
                    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
                }, "strict", z.ZodTypeAny, {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                }, {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                }>;
                created_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
                updated_at: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
                data_version: z.ZodOptional<z.ZodNumber>;
            }, "user_id">, "strip", z.ZodTypeAny, {
                original_image_id: string;
                file_path: string;
                mask_path: string;
                metadata: {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                };
                id?: string | undefined;
                created_at?: string | Date | undefined;
                updated_at?: string | Date | undefined;
                data_version?: number | undefined;
            }, {
                original_image_id: string;
                file_path: string;
                mask_path: string;
                metadata: {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                };
                id?: string | undefined;
                created_at?: string | Date | undefined;
                updated_at?: string | Date | undefined;
                data_version?: number | undefined;
            }>, "many">>;
        }, "strip", z.ZodTypeAny, {
            name: string;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            garments?: {
                original_image_id: string;
                file_path: string;
                mask_path: string;
                metadata: {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                };
                id?: string | undefined;
                created_at?: string | Date | undefined;
                updated_at?: string | Date | undefined;
                data_version?: number | undefined;
            }[] | undefined;
            description?: string | undefined;
        }, {
            name: string;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            garments?: {
                original_image_id: string;
                file_path: string;
                mask_path: string;
                metadata: {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                };
                id?: string | undefined;
                created_at?: string | Date | undefined;
                updated_at?: string | Date | undefined;
                data_version?: number | undefined;
            }[] | undefined;
            description?: string | undefined;
        }>, "many">;
        count: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        count: number;
        wardrobes: {
            name: string;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            garments?: {
                original_image_id: string;
                file_path: string;
                mask_path: string;
                metadata: {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                };
                id?: string | undefined;
                created_at?: string | Date | undefined;
                updated_at?: string | Date | undefined;
                data_version?: number | undefined;
            }[] | undefined;
            description?: string | undefined;
        }[];
    }, {
        count: number;
        wardrobes: {
            name: string;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            garments?: {
                original_image_id: string;
                file_path: string;
                mask_path: string;
                metadata: {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                };
                id?: string | undefined;
                created_at?: string | Date | undefined;
                updated_at?: string | Date | undefined;
                data_version?: number | undefined;
            }[] | undefined;
            description?: string | undefined;
        }[];
    }>;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    status: "success";
    data: {
        count: number;
        wardrobes: {
            name: string;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            garments?: {
                original_image_id: string;
                file_path: string;
                mask_path: string;
                metadata: {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                };
                id?: string | undefined;
                created_at?: string | Date | undefined;
                updated_at?: string | Date | undefined;
                data_version?: number | undefined;
            }[] | undefined;
            description?: string | undefined;
        }[];
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}, {
    status: "success";
    data: {
        count: number;
        wardrobes: {
            name: string;
            id?: string | undefined;
            created_at?: string | Date | undefined;
            updated_at?: string | Date | undefined;
            garments?: {
                original_image_id: string;
                file_path: string;
                mask_path: string;
                metadata: {
                    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
                    color: string;
                    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
                    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
                    brand?: string | undefined;
                    size?: string | undefined;
                    material?: string | undefined;
                    tags?: string[] | undefined;
                };
                id?: string | undefined;
                created_at?: string | Date | undefined;
                updated_at?: string | Date | undefined;
                data_version?: number | undefined;
            }[] | undefined;
            description?: string | undefined;
        }[];
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}>;
export declare const ExportJobListResponseSchema: z.ZodObject<{
    status: z.ZodLiteral<"success">;
    data: z.ZodObject<{
        jobs: z.ZodArray<z.ZodObject<{
            id: z.ZodString;
            userId: z.ZodString;
            status: z.ZodEnum<["pending", "processing", "completed", "failed", "cancelled"]>;
            options: z.ZodObject<{
                format: z.ZodEnum<["coco", "yolo", "pascal_voc", "csv", "raw_json"]>;
                garmentIds: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
                categoryFilter: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
                imageFormat: z.ZodDefault<z.ZodEnum<["jpg", "png", "webp"]>>;
                compressionQuality: z.ZodDefault<z.ZodNumber>;
                includeMasks: z.ZodDefault<z.ZodBoolean>;
                includePolygons: z.ZodDefault<z.ZodBoolean>;
                includeImages: z.ZodDefault<z.ZodBoolean>;
                includeRawPolygons: z.ZodDefault<z.ZodBoolean>;
                dateRange: z.ZodOptional<z.ZodObject<{
                    from: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
                    to: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
                }, "strip", z.ZodTypeAny, {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                }, {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                }>>;
                splitRatio: z.ZodOptional<z.ZodEffects<z.ZodObject<{
                    train: z.ZodNumber;
                    validation: z.ZodNumber;
                    test: z.ZodNumber;
                }, "strip", z.ZodTypeAny, {
                    validation: number;
                    train: number;
                    test: number;
                }, {
                    validation: number;
                    train: number;
                    test: number;
                }>, {
                    validation: number;
                    train: number;
                    test: number;
                }, {
                    validation: number;
                    train: number;
                    test: number;
                }>>;
            }, "strip", z.ZodTypeAny, {
                format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
                includeImages: boolean;
                includeRawPolygons: boolean;
                includeMasks: boolean;
                imageFormat: "jpg" | "png" | "webp";
                compressionQuality: number;
                includePolygons: boolean;
                garmentIds?: string[] | undefined;
                categoryFilter?: string[] | undefined;
                dateRange?: {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                } | undefined;
                splitRatio?: {
                    validation: number;
                    train: number;
                    test: number;
                } | undefined;
            }, {
                format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
                includeImages?: boolean | undefined;
                includeRawPolygons?: boolean | undefined;
                includeMasks?: boolean | undefined;
                imageFormat?: "jpg" | "png" | "webp" | undefined;
                compressionQuality?: number | undefined;
                garmentIds?: string[] | undefined;
                categoryFilter?: string[] | undefined;
                dateRange?: {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                } | undefined;
                includePolygons?: boolean | undefined;
                splitRatio?: {
                    validation: number;
                    train: number;
                    test: number;
                } | undefined;
            }>;
            progress: z.ZodDefault<z.ZodNumber>;
            totalItems: z.ZodDefault<z.ZodNumber>;
            processedItems: z.ZodDefault<z.ZodNumber>;
            outputUrl: z.ZodOptional<z.ZodString>;
            error: z.ZodOptional<z.ZodString>;
            createdAt: z.ZodUnion<[z.ZodString, z.ZodDate]>;
            updatedAt: z.ZodUnion<[z.ZodString, z.ZodDate]>;
            completedAt: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
            expiresAt: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
        }, "strip", z.ZodTypeAny, {
            options: {
                format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
                includeImages: boolean;
                includeRawPolygons: boolean;
                includeMasks: boolean;
                imageFormat: "jpg" | "png" | "webp";
                compressionQuality: number;
                includePolygons: boolean;
                garmentIds?: string[] | undefined;
                categoryFilter?: string[] | undefined;
                dateRange?: {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                } | undefined;
                splitRatio?: {
                    validation: number;
                    train: number;
                    test: number;
                } | undefined;
            };
            status: "pending" | "processing" | "completed" | "failed" | "cancelled";
            id: string;
            createdAt: string | Date;
            updatedAt: string | Date;
            userId: string;
            progress: number;
            totalItems: number;
            processedItems: number;
            outputUrl?: string | undefined;
            error?: string | undefined;
            completedAt?: string | Date | undefined;
            expiresAt?: string | Date | undefined;
        }, {
            options: {
                format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
                includeImages?: boolean | undefined;
                includeRawPolygons?: boolean | undefined;
                includeMasks?: boolean | undefined;
                imageFormat?: "jpg" | "png" | "webp" | undefined;
                compressionQuality?: number | undefined;
                garmentIds?: string[] | undefined;
                categoryFilter?: string[] | undefined;
                dateRange?: {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                } | undefined;
                includePolygons?: boolean | undefined;
                splitRatio?: {
                    validation: number;
                    train: number;
                    test: number;
                } | undefined;
            };
            status: "pending" | "processing" | "completed" | "failed" | "cancelled";
            id: string;
            createdAt: string | Date;
            updatedAt: string | Date;
            userId: string;
            progress?: number | undefined;
            totalItems?: number | undefined;
            processedItems?: number | undefined;
            outputUrl?: string | undefined;
            error?: string | undefined;
            completedAt?: string | Date | undefined;
            expiresAt?: string | Date | undefined;
        }>, "many">;
        count: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        count: number;
        jobs: {
            options: {
                format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
                includeImages: boolean;
                includeRawPolygons: boolean;
                includeMasks: boolean;
                imageFormat: "jpg" | "png" | "webp";
                compressionQuality: number;
                includePolygons: boolean;
                garmentIds?: string[] | undefined;
                categoryFilter?: string[] | undefined;
                dateRange?: {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                } | undefined;
                splitRatio?: {
                    validation: number;
                    train: number;
                    test: number;
                } | undefined;
            };
            status: "pending" | "processing" | "completed" | "failed" | "cancelled";
            id: string;
            createdAt: string | Date;
            updatedAt: string | Date;
            userId: string;
            progress: number;
            totalItems: number;
            processedItems: number;
            outputUrl?: string | undefined;
            error?: string | undefined;
            completedAt?: string | Date | undefined;
            expiresAt?: string | Date | undefined;
        }[];
    }, {
        count: number;
        jobs: {
            options: {
                format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
                includeImages?: boolean | undefined;
                includeRawPolygons?: boolean | undefined;
                includeMasks?: boolean | undefined;
                imageFormat?: "jpg" | "png" | "webp" | undefined;
                compressionQuality?: number | undefined;
                garmentIds?: string[] | undefined;
                categoryFilter?: string[] | undefined;
                dateRange?: {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                } | undefined;
                includePolygons?: boolean | undefined;
                splitRatio?: {
                    validation: number;
                    train: number;
                    test: number;
                } | undefined;
            };
            status: "pending" | "processing" | "completed" | "failed" | "cancelled";
            id: string;
            createdAt: string | Date;
            updatedAt: string | Date;
            userId: string;
            progress?: number | undefined;
            totalItems?: number | undefined;
            processedItems?: number | undefined;
            outputUrl?: string | undefined;
            error?: string | undefined;
            completedAt?: string | Date | undefined;
            expiresAt?: string | Date | undefined;
        }[];
    }>;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    status: "success";
    data: {
        count: number;
        jobs: {
            options: {
                format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
                includeImages: boolean;
                includeRawPolygons: boolean;
                includeMasks: boolean;
                imageFormat: "jpg" | "png" | "webp";
                compressionQuality: number;
                includePolygons: boolean;
                garmentIds?: string[] | undefined;
                categoryFilter?: string[] | undefined;
                dateRange?: {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                } | undefined;
                splitRatio?: {
                    validation: number;
                    train: number;
                    test: number;
                } | undefined;
            };
            status: "pending" | "processing" | "completed" | "failed" | "cancelled";
            id: string;
            createdAt: string | Date;
            updatedAt: string | Date;
            userId: string;
            progress: number;
            totalItems: number;
            processedItems: number;
            outputUrl?: string | undefined;
            error?: string | undefined;
            completedAt?: string | Date | undefined;
            expiresAt?: string | Date | undefined;
        }[];
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}, {
    status: "success";
    data: {
        count: number;
        jobs: {
            options: {
                format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
                includeImages?: boolean | undefined;
                includeRawPolygons?: boolean | undefined;
                includeMasks?: boolean | undefined;
                imageFormat?: "jpg" | "png" | "webp" | undefined;
                compressionQuality?: number | undefined;
                garmentIds?: string[] | undefined;
                categoryFilter?: string[] | undefined;
                dateRange?: {
                    from?: string | Date | undefined;
                    to?: string | Date | undefined;
                } | undefined;
                includePolygons?: boolean | undefined;
                splitRatio?: {
                    validation: number;
                    train: number;
                    test: number;
                } | undefined;
            };
            status: "pending" | "processing" | "completed" | "failed" | "cancelled";
            id: string;
            createdAt: string | Date;
            updatedAt: string | Date;
            userId: string;
            progress?: number | undefined;
            totalItems?: number | undefined;
            processedItems?: number | undefined;
            outputUrl?: string | undefined;
            error?: string | undefined;
            completedAt?: string | Date | undefined;
            expiresAt?: string | Date | undefined;
        }[];
    };
    message?: string | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}>;
export type User = z.infer<typeof UserSchema>;
export type RegisterUserInput = z.infer<typeof RegisterUserSchema>;
export type LoginUserInput = z.infer<typeof LoginUserSchema>;
export type UserResponse = z.infer<typeof UserResponseSchema>;
export type AuthResponse = z.infer<typeof AuthResponseSchema>;
export type Image = z.infer<typeof ImageSchema>;
export type ImageQuery = z.infer<typeof ImageQuerySchema>;
export type UpdateImageStatus = z.infer<typeof UpdateImageStatusSchema>;
export type ImageResponse = z.infer<typeof ImageResponseSchema>;
export type BatchUpdateImageStatus = z.infer<typeof BatchUpdateImageStatusSchema>;
export type Polygon = z.infer<typeof PolygonSchema>;
export type PolygonMetadata = z.infer<typeof PolygonMetadataSchema>;
export type CreatePolygonInput = z.infer<typeof CreatePolygonSchema>;
export type UpdatePolygonInput = z.infer<typeof UpdatePolygonSchema>;
export type PolygonResponse = z.infer<typeof PolygonResponseSchema>;
export type Garment = z.infer<typeof GarmentSchema>;
export type MaskData = z.infer<typeof MaskDataSchema>;
export type GarmentMetadata = z.infer<typeof GarmentMetadataSchema>;
export type CreateGarmentInput = z.infer<typeof CreateGarmentSchema>;
export type UpdateGarmentMetadata = z.infer<typeof UpdateGarmentMetadataSchema>;
export type GarmentQuery = z.infer<typeof GarmentQuerySchema>;
export type GarmentResponse = z.infer<typeof GarmentResponseSchema>;
export type Wardrobe = z.infer<typeof WardrobeSchema>;
export type CreateWardrobeInput = z.infer<typeof CreateWardrobeSchema>;
export type UpdateWardrobeInput = z.infer<typeof UpdateWardrobeSchema>;
export type AddGarmentToWardrobeInput = z.infer<typeof AddGarmentToWardrobeSchema>;
export type WardrobeResponse = z.infer<typeof WardrobeResponseSchema>;
export type MLExportOptions = z.infer<typeof MLExportOptionsSchema>;
export type CreateMLExport = z.infer<typeof CreateMLExportSchema>;
export type MLExportBatchJob = z.infer<typeof MLExportBatchJobSchema>;
export type DatasetStats = z.infer<typeof DatasetStatsSchema>;
export type UUIDParam = z.infer<typeof UUIDParamSchema>;
export type ImageIdParam = z.infer<typeof ImageIdParamSchema>;
export type JobIdParam = z.infer<typeof JobIdParamSchema>;
export type WardrobeItemParam = z.infer<typeof WardrobeItemParamSchema>;
//# sourceMappingURL=index.d.ts.map