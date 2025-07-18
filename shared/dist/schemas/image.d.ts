import { z } from 'zod';
export declare const ImageVariantSchema: z.ZodObject<{
    thumbnail: z.ZodOptional<z.ZodObject<{
        url: z.ZodString;
        width: z.ZodNumber;
        height: z.ZodNumber;
        size: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        url: string;
        width: number;
        height: number;
        size: number;
    }, {
        url: string;
        width: number;
        height: number;
        size: number;
    }>>;
    preview: z.ZodOptional<z.ZodObject<{
        url: z.ZodString;
        width: z.ZodNumber;
        height: z.ZodNumber;
        size: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        url: string;
        width: number;
        height: number;
        size: number;
    }, {
        url: string;
        width: number;
        height: number;
        size: number;
    }>>;
    full: z.ZodOptional<z.ZodObject<{
        url: z.ZodString;
        width: z.ZodNumber;
        height: z.ZodNumber;
        size: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        url: string;
        width: number;
        height: number;
        size: number;
    }, {
        url: string;
        width: number;
        height: number;
        size: number;
    }>>;
    webp: z.ZodOptional<z.ZodObject<{
        url: z.ZodString;
        width: z.ZodNumber;
        height: z.ZodNumber;
        size: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        url: string;
        width: number;
        height: number;
        size: number;
    }, {
        url: string;
        width: number;
        height: number;
        size: number;
    }>>;
}, "strip", z.ZodTypeAny, {
    thumbnail?: {
        url: string;
        width: number;
        height: number;
        size: number;
    } | undefined;
    preview?: {
        url: string;
        width: number;
        height: number;
        size: number;
    } | undefined;
    full?: {
        url: string;
        width: number;
        height: number;
        size: number;
    } | undefined;
    webp?: {
        url: string;
        width: number;
        height: number;
        size: number;
    } | undefined;
}, {
    thumbnail?: {
        url: string;
        width: number;
        height: number;
        size: number;
    } | undefined;
    preview?: {
        url: string;
        width: number;
        height: number;
        size: number;
    } | undefined;
    full?: {
        url: string;
        width: number;
        height: number;
        size: number;
    } | undefined;
    webp?: {
        url: string;
        width: number;
        height: number;
        size: number;
    } | undefined;
}>;
export declare const EnhancedImageMetadataSchema: z.ZodObject<{
    filename: z.ZodString;
    original_filename: z.ZodOptional<z.ZodString>;
    mimetype: z.ZodString;
    size: z.ZodNumber;
    width: z.ZodNumber;
    height: z.ZodNumber;
    format: z.ZodEnum<["jpeg", "jpg", "png", "webp", "gif", "heic", "heif"]>;
    orientation: z.ZodOptional<z.ZodNumber>;
    has_transparency: z.ZodOptional<z.ZodBoolean>;
    color_space: z.ZodOptional<z.ZodEnum<["srgb", "rgb", "cmyk", "gray"]>>;
    dpi: z.ZodOptional<z.ZodNumber>;
    capture_date: z.ZodOptional<z.ZodDate>;
    camera_make: z.ZodOptional<z.ZodString>;
    camera_model: z.ZodOptional<z.ZodString>;
    gps_location: z.ZodOptional<z.ZodObject<{
        latitude: z.ZodNumber;
        longitude: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        latitude: number;
        longitude: number;
    }, {
        latitude: number;
        longitude: number;
    }>>;
    hash: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    width: number;
    height: number;
    size: number;
    filename: string;
    mimetype: string;
    format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
    original_filename?: string | undefined;
    orientation?: number | undefined;
    has_transparency?: boolean | undefined;
    color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
    dpi?: number | undefined;
    capture_date?: Date | undefined;
    camera_make?: string | undefined;
    camera_model?: string | undefined;
    gps_location?: {
        latitude: number;
        longitude: number;
    } | undefined;
    hash?: string | undefined;
}, {
    width: number;
    height: number;
    size: number;
    filename: string;
    mimetype: string;
    format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
    original_filename?: string | undefined;
    orientation?: number | undefined;
    has_transparency?: boolean | undefined;
    color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
    dpi?: number | undefined;
    capture_date?: Date | undefined;
    camera_make?: string | undefined;
    camera_model?: string | undefined;
    gps_location?: {
        latitude: number;
        longitude: number;
    } | undefined;
    hash?: string | undefined;
}>;
export declare const MobileImageFieldsSchema: z.ZodObject<{
    variants: z.ZodOptional<z.ZodObject<{
        thumbnail: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        preview: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        full: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        webp: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
    }, "strip", z.ZodTypeAny, {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    }, {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    }>>;
    processing_status: z.ZodDefault<z.ZodEnum<["pending", "processing", "complete", "failed"]>>;
    processing_progress: z.ZodOptional<z.ZodNumber>;
    local_path: z.ZodOptional<z.ZodString>;
    cached_at: z.ZodOptional<z.ZodDate>;
    sync_status: z.ZodDefault<z.ZodEnum<["synced", "pending", "conflict"]>>;
    upload_progress: z.ZodOptional<z.ZodNumber>;
    retry_count: z.ZodDefault<z.ZodNumber>;
    error_message: z.ZodOptional<z.ZodString>;
    is_favorite: z.ZodDefault<z.ZodBoolean>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
}, "strip", z.ZodTypeAny, {
    processing_status: "pending" | "processing" | "complete" | "failed";
    sync_status: "pending" | "synced" | "conflict";
    retry_count: number;
    is_favorite: boolean;
    variants?: {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    } | undefined;
    processing_progress?: number | undefined;
    local_path?: string | undefined;
    cached_at?: Date | undefined;
    upload_progress?: number | undefined;
    error_message?: string | undefined;
    tags?: string[] | undefined;
}, {
    variants?: {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    } | undefined;
    processing_status?: "pending" | "processing" | "complete" | "failed" | undefined;
    processing_progress?: number | undefined;
    local_path?: string | undefined;
    cached_at?: Date | undefined;
    sync_status?: "pending" | "synced" | "conflict" | undefined;
    upload_progress?: number | undefined;
    retry_count?: number | undefined;
    error_message?: string | undefined;
    is_favorite?: boolean | undefined;
    tags?: string[] | undefined;
}>;
export declare const ImageSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodString;
    file_path: z.ZodString;
    original_metadata: z.ZodOptional<z.ZodObject<{
        filename: z.ZodString;
        original_filename: z.ZodOptional<z.ZodString>;
        mimetype: z.ZodString;
        size: z.ZodNumber;
        width: z.ZodNumber;
        height: z.ZodNumber;
        format: z.ZodEnum<["jpeg", "jpg", "png", "webp", "gif", "heic", "heif"]>;
        orientation: z.ZodOptional<z.ZodNumber>;
        has_transparency: z.ZodOptional<z.ZodBoolean>;
        color_space: z.ZodOptional<z.ZodEnum<["srgb", "rgb", "cmyk", "gray"]>>;
        dpi: z.ZodOptional<z.ZodNumber>;
        capture_date: z.ZodOptional<z.ZodDate>;
        camera_make: z.ZodOptional<z.ZodString>;
        camera_model: z.ZodOptional<z.ZodString>;
        gps_location: z.ZodOptional<z.ZodObject<{
            latitude: z.ZodNumber;
            longitude: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            latitude: number;
            longitude: number;
        }, {
            latitude: number;
            longitude: number;
        }>>;
        hash: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
        size: number;
        filename: string;
        mimetype: string;
        format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
        original_filename?: string | undefined;
        orientation?: number | undefined;
        has_transparency?: boolean | undefined;
        color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
        dpi?: number | undefined;
        capture_date?: Date | undefined;
        camera_make?: string | undefined;
        camera_model?: string | undefined;
        gps_location?: {
            latitude: number;
            longitude: number;
        } | undefined;
        hash?: string | undefined;
    }, {
        width: number;
        height: number;
        size: number;
        filename: string;
        mimetype: string;
        format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
        original_filename?: string | undefined;
        orientation?: number | undefined;
        has_transparency?: boolean | undefined;
        color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
        dpi?: number | undefined;
        capture_date?: Date | undefined;
        camera_make?: string | undefined;
        camera_model?: string | undefined;
        gps_location?: {
            latitude: number;
            longitude: number;
        } | undefined;
        hash?: string | undefined;
    }>>;
    upload_date: z.ZodOptional<z.ZodDate>;
    status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled", "archived"]>>;
} & {
    variants: z.ZodOptional<z.ZodObject<{
        thumbnail: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        preview: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        full: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        webp: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
    }, "strip", z.ZodTypeAny, {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    }, {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    }>>;
    processing_status: z.ZodDefault<z.ZodEnum<["pending", "processing", "complete", "failed"]>>;
    processing_progress: z.ZodOptional<z.ZodNumber>;
    local_path: z.ZodOptional<z.ZodString>;
    cached_at: z.ZodOptional<z.ZodDate>;
    sync_status: z.ZodDefault<z.ZodEnum<["synced", "pending", "conflict"]>>;
    upload_progress: z.ZodOptional<z.ZodNumber>;
    retry_count: z.ZodDefault<z.ZodNumber>;
    error_message: z.ZodOptional<z.ZodString>;
    is_favorite: z.ZodDefault<z.ZodBoolean>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
}, "strip", z.ZodTypeAny, {
    processing_status: "pending" | "processing" | "complete" | "failed";
    sync_status: "pending" | "synced" | "conflict";
    retry_count: number;
    is_favorite: boolean;
    user_id: string;
    file_path: string;
    status?: "new" | "processed" | "labeled" | "archived" | undefined;
    variants?: {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    } | undefined;
    processing_progress?: number | undefined;
    local_path?: string | undefined;
    cached_at?: Date | undefined;
    upload_progress?: number | undefined;
    error_message?: string | undefined;
    tags?: string[] | undefined;
    id?: string | undefined;
    original_metadata?: {
        width: number;
        height: number;
        size: number;
        filename: string;
        mimetype: string;
        format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
        original_filename?: string | undefined;
        orientation?: number | undefined;
        has_transparency?: boolean | undefined;
        color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
        dpi?: number | undefined;
        capture_date?: Date | undefined;
        camera_make?: string | undefined;
        camera_model?: string | undefined;
        gps_location?: {
            latitude: number;
            longitude: number;
        } | undefined;
        hash?: string | undefined;
    } | undefined;
    upload_date?: Date | undefined;
}, {
    user_id: string;
    file_path: string;
    status?: "new" | "processed" | "labeled" | "archived" | undefined;
    variants?: {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    } | undefined;
    processing_status?: "pending" | "processing" | "complete" | "failed" | undefined;
    processing_progress?: number | undefined;
    local_path?: string | undefined;
    cached_at?: Date | undefined;
    sync_status?: "pending" | "synced" | "conflict" | undefined;
    upload_progress?: number | undefined;
    retry_count?: number | undefined;
    error_message?: string | undefined;
    is_favorite?: boolean | undefined;
    tags?: string[] | undefined;
    id?: string | undefined;
    original_metadata?: {
        width: number;
        height: number;
        size: number;
        filename: string;
        mimetype: string;
        format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
        original_filename?: string | undefined;
        orientation?: number | undefined;
        has_transparency?: boolean | undefined;
        color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
        dpi?: number | undefined;
        capture_date?: Date | undefined;
        camera_make?: string | undefined;
        camera_model?: string | undefined;
        gps_location?: {
            latitude: number;
            longitude: number;
        } | undefined;
        hash?: string | undefined;
    } | undefined;
    upload_date?: Date | undefined;
}>;
export declare const MobileImageUploadSchema: z.ZodObject<{
    filename: z.ZodString;
    mimetype: z.ZodString;
    size: z.ZodNumber;
    chunk_size: z.ZodDefault<z.ZodNumber>;
    total_chunks: z.ZodOptional<z.ZodNumber>;
    metadata: z.ZodOptional<z.ZodObject<{
        width: z.ZodNumber;
        height: z.ZodNumber;
        capture_date: z.ZodOptional<z.ZodString>;
        location: z.ZodOptional<z.ZodObject<{
            latitude: z.ZodNumber;
            longitude: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            latitude: number;
            longitude: number;
        }, {
            latitude: number;
            longitude: number;
        }>>;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
        capture_date?: string | undefined;
        location?: {
            latitude: number;
            longitude: number;
        } | undefined;
    }, {
        width: number;
        height: number;
        capture_date?: string | undefined;
        location?: {
            latitude: number;
            longitude: number;
        } | undefined;
    }>>;
    generate_variants: z.ZodDefault<z.ZodBoolean>;
    auto_process: z.ZodDefault<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    size: number;
    filename: string;
    mimetype: string;
    chunk_size: number;
    generate_variants: boolean;
    auto_process: boolean;
    total_chunks?: number | undefined;
    metadata?: {
        width: number;
        height: number;
        capture_date?: string | undefined;
        location?: {
            latitude: number;
            longitude: number;
        } | undefined;
    } | undefined;
}, {
    size: number;
    filename: string;
    mimetype: string;
    chunk_size?: number | undefined;
    total_chunks?: number | undefined;
    metadata?: {
        width: number;
        height: number;
        capture_date?: string | undefined;
        location?: {
            latitude: number;
            longitude: number;
        } | undefined;
    } | undefined;
    generate_variants?: boolean | undefined;
    auto_process?: boolean | undefined;
}>;
export declare const ImageChunkUploadSchema: z.ZodObject<{
    upload_id: z.ZodString;
    chunk_index: z.ZodNumber;
    chunk_data: z.ZodString;
    checksum: z.ZodString;
}, "strip", z.ZodTypeAny, {
    upload_id: string;
    chunk_index: number;
    chunk_data: string;
    checksum: string;
}, {
    upload_id: string;
    chunk_index: number;
    chunk_data: string;
    checksum: string;
}>;
export declare const ImageResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodString;
    file_path: z.ZodString;
    original_metadata: z.ZodOptional<z.ZodObject<{
        filename: z.ZodString;
        original_filename: z.ZodOptional<z.ZodString>;
        mimetype: z.ZodString;
        size: z.ZodNumber;
        width: z.ZodNumber;
        height: z.ZodNumber;
        format: z.ZodEnum<["jpeg", "jpg", "png", "webp", "gif", "heic", "heif"]>;
        orientation: z.ZodOptional<z.ZodNumber>;
        has_transparency: z.ZodOptional<z.ZodBoolean>;
        color_space: z.ZodOptional<z.ZodEnum<["srgb", "rgb", "cmyk", "gray"]>>;
        dpi: z.ZodOptional<z.ZodNumber>;
        capture_date: z.ZodOptional<z.ZodDate>;
        camera_make: z.ZodOptional<z.ZodString>;
        camera_model: z.ZodOptional<z.ZodString>;
        gps_location: z.ZodOptional<z.ZodObject<{
            latitude: z.ZodNumber;
            longitude: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            latitude: number;
            longitude: number;
        }, {
            latitude: number;
            longitude: number;
        }>>;
        hash: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
        size: number;
        filename: string;
        mimetype: string;
        format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
        original_filename?: string | undefined;
        orientation?: number | undefined;
        has_transparency?: boolean | undefined;
        color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
        dpi?: number | undefined;
        capture_date?: Date | undefined;
        camera_make?: string | undefined;
        camera_model?: string | undefined;
        gps_location?: {
            latitude: number;
            longitude: number;
        } | undefined;
        hash?: string | undefined;
    }, {
        width: number;
        height: number;
        size: number;
        filename: string;
        mimetype: string;
        format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
        original_filename?: string | undefined;
        orientation?: number | undefined;
        has_transparency?: boolean | undefined;
        color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
        dpi?: number | undefined;
        capture_date?: Date | undefined;
        camera_make?: string | undefined;
        camera_model?: string | undefined;
        gps_location?: {
            latitude: number;
            longitude: number;
        } | undefined;
        hash?: string | undefined;
    }>>;
    upload_date: z.ZodOptional<z.ZodDate>;
    status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled", "archived"]>>;
} & {
    variants: z.ZodOptional<z.ZodObject<{
        thumbnail: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        preview: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        full: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
        webp: z.ZodOptional<z.ZodObject<{
            url: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            url: string;
            width: number;
            height: number;
            size: number;
        }, {
            url: string;
            width: number;
            height: number;
            size: number;
        }>>;
    }, "strip", z.ZodTypeAny, {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    }, {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    }>>;
    processing_status: z.ZodDefault<z.ZodEnum<["pending", "processing", "complete", "failed"]>>;
    processing_progress: z.ZodOptional<z.ZodNumber>;
    local_path: z.ZodOptional<z.ZodString>;
    cached_at: z.ZodOptional<z.ZodDate>;
    sync_status: z.ZodDefault<z.ZodEnum<["synced", "pending", "conflict"]>>;
    upload_progress: z.ZodOptional<z.ZodNumber>;
    retry_count: z.ZodDefault<z.ZodNumber>;
    error_message: z.ZodOptional<z.ZodString>;
    is_favorite: z.ZodDefault<z.ZodBoolean>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
}, "user_id" | "file_path">, "strip", z.ZodTypeAny, {
    processing_status: "pending" | "processing" | "complete" | "failed";
    sync_status: "pending" | "synced" | "conflict";
    retry_count: number;
    is_favorite: boolean;
    status?: "new" | "processed" | "labeled" | "archived" | undefined;
    variants?: {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    } | undefined;
    processing_progress?: number | undefined;
    local_path?: string | undefined;
    cached_at?: Date | undefined;
    upload_progress?: number | undefined;
    error_message?: string | undefined;
    tags?: string[] | undefined;
    id?: string | undefined;
    original_metadata?: {
        width: number;
        height: number;
        size: number;
        filename: string;
        mimetype: string;
        format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
        original_filename?: string | undefined;
        orientation?: number | undefined;
        has_transparency?: boolean | undefined;
        color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
        dpi?: number | undefined;
        capture_date?: Date | undefined;
        camera_make?: string | undefined;
        camera_model?: string | undefined;
        gps_location?: {
            latitude: number;
            longitude: number;
        } | undefined;
        hash?: string | undefined;
    } | undefined;
    upload_date?: Date | undefined;
}, {
    status?: "new" | "processed" | "labeled" | "archived" | undefined;
    variants?: {
        thumbnail?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        preview?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        full?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
        webp?: {
            url: string;
            width: number;
            height: number;
            size: number;
        } | undefined;
    } | undefined;
    processing_status?: "pending" | "processing" | "complete" | "failed" | undefined;
    processing_progress?: number | undefined;
    local_path?: string | undefined;
    cached_at?: Date | undefined;
    sync_status?: "pending" | "synced" | "conflict" | undefined;
    upload_progress?: number | undefined;
    retry_count?: number | undefined;
    error_message?: string | undefined;
    is_favorite?: boolean | undefined;
    tags?: string[] | undefined;
    id?: string | undefined;
    original_metadata?: {
        width: number;
        height: number;
        size: number;
        filename: string;
        mimetype: string;
        format: "webp" | "jpeg" | "jpg" | "png" | "gif" | "heic" | "heif";
        original_filename?: string | undefined;
        orientation?: number | undefined;
        has_transparency?: boolean | undefined;
        color_space?: "srgb" | "rgb" | "cmyk" | "gray" | undefined;
        dpi?: number | undefined;
        capture_date?: Date | undefined;
        camera_make?: string | undefined;
        camera_model?: string | undefined;
        gps_location?: {
            latitude: number;
            longitude: number;
        } | undefined;
        hash?: string | undefined;
    } | undefined;
    upload_date?: Date | undefined;
}>;
export declare const MobileImageListItemSchema: z.ZodObject<{
    id: z.ZodString;
    thumbnail_url: z.ZodString;
    preview_url: z.ZodOptional<z.ZodString>;
    metadata: z.ZodObject<{
        filename: z.ZodString;
        width: z.ZodNumber;
        height: z.ZodNumber;
        size: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
        size: number;
        filename: string;
    }, {
        width: number;
        height: number;
        size: number;
        filename: string;
    }>;
    upload_date: z.ZodDate;
    status: z.ZodEnum<["new", "processed", "labeled", "archived"]>;
    is_favorite: z.ZodBoolean;
    has_garments: z.ZodOptional<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    status: "new" | "processed" | "labeled" | "archived";
    is_favorite: boolean;
    id: string;
    upload_date: Date;
    metadata: {
        width: number;
        height: number;
        size: number;
        filename: string;
    };
    thumbnail_url: string;
    preview_url?: string | undefined;
    has_garments?: boolean | undefined;
}, {
    status: "new" | "processed" | "labeled" | "archived";
    is_favorite: boolean;
    id: string;
    upload_date: Date;
    metadata: {
        width: number;
        height: number;
        size: number;
        filename: string;
    };
    thumbnail_url: string;
    preview_url?: string | undefined;
    has_garments?: boolean | undefined;
}>;
export declare const ImageListResponseSchema: z.ZodObject<{
    images: z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        thumbnail_url: z.ZodString;
        preview_url: z.ZodOptional<z.ZodString>;
        metadata: z.ZodObject<{
            filename: z.ZodString;
            width: z.ZodNumber;
            height: z.ZodNumber;
            size: z.ZodNumber;
        }, "strip", z.ZodTypeAny, {
            width: number;
            height: number;
            size: number;
            filename: string;
        }, {
            width: number;
            height: number;
            size: number;
            filename: string;
        }>;
        upload_date: z.ZodDate;
        status: z.ZodEnum<["new", "processed", "labeled", "archived"]>;
        is_favorite: z.ZodBoolean;
        has_garments: z.ZodOptional<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        status: "new" | "processed" | "labeled" | "archived";
        is_favorite: boolean;
        id: string;
        upload_date: Date;
        metadata: {
            width: number;
            height: number;
            size: number;
            filename: string;
        };
        thumbnail_url: string;
        preview_url?: string | undefined;
        has_garments?: boolean | undefined;
    }, {
        status: "new" | "processed" | "labeled" | "archived";
        is_favorite: boolean;
        id: string;
        upload_date: Date;
        metadata: {
            width: number;
            height: number;
            size: number;
            filename: string;
        };
        thumbnail_url: string;
        preview_url?: string | undefined;
        has_garments?: boolean | undefined;
    }>, "many">;
    pagination: z.ZodObject<{
        page: z.ZodNumber;
        limit: z.ZodNumber;
        total: z.ZodNumber;
        has_more: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        page: number;
        limit: number;
        total: number;
        has_more: boolean;
    }, {
        page: number;
        limit: number;
        total: number;
        has_more: boolean;
    }>;
    sync_info: z.ZodOptional<z.ZodObject<{
        last_sync: z.ZodOptional<z.ZodDate>;
        pending_uploads: z.ZodNumber;
        pending_downloads: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        pending_uploads: number;
        pending_downloads: number;
        last_sync?: Date | undefined;
    }, {
        pending_uploads: number;
        pending_downloads: number;
        last_sync?: Date | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    images: {
        status: "new" | "processed" | "labeled" | "archived";
        is_favorite: boolean;
        id: string;
        upload_date: Date;
        metadata: {
            width: number;
            height: number;
            size: number;
            filename: string;
        };
        thumbnail_url: string;
        preview_url?: string | undefined;
        has_garments?: boolean | undefined;
    }[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        has_more: boolean;
    };
    sync_info?: {
        pending_uploads: number;
        pending_downloads: number;
        last_sync?: Date | undefined;
    } | undefined;
}, {
    images: {
        status: "new" | "processed" | "labeled" | "archived";
        is_favorite: boolean;
        id: string;
        upload_date: Date;
        metadata: {
            width: number;
            height: number;
            size: number;
            filename: string;
        };
        thumbnail_url: string;
        preview_url?: string | undefined;
        has_garments?: boolean | undefined;
    }[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        has_more: boolean;
    };
    sync_info?: {
        pending_uploads: number;
        pending_downloads: number;
        last_sync?: Date | undefined;
    } | undefined;
}>;
export declare const ImageFilterSchema: z.ZodObject<{
    status: z.ZodOptional<z.ZodArray<z.ZodEnum<["new", "processed", "labeled", "archived"]>, "many">>;
    date_range: z.ZodOptional<z.ZodObject<{
        start: z.ZodDate;
        end: z.ZodDate;
    }, "strip", z.ZodTypeAny, {
        start: Date;
        end: Date;
    }, {
        start: Date;
        end: Date;
    }>>;
    has_garments: z.ZodOptional<z.ZodBoolean>;
    is_favorite: z.ZodOptional<z.ZodBoolean>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    search: z.ZodOptional<z.ZodString>;
    sort_by: z.ZodDefault<z.ZodEnum<["upload_date", "capture_date", "size", "name"]>>;
    sort_order: z.ZodDefault<z.ZodEnum<["asc", "desc"]>>;
}, "strip", z.ZodTypeAny, {
    sort_by: "size" | "capture_date" | "upload_date" | "name";
    sort_order: "asc" | "desc";
    status?: ("new" | "processed" | "labeled" | "archived")[] | undefined;
    is_favorite?: boolean | undefined;
    tags?: string[] | undefined;
    has_garments?: boolean | undefined;
    date_range?: {
        start: Date;
        end: Date;
    } | undefined;
    search?: string | undefined;
}, {
    status?: ("new" | "processed" | "labeled" | "archived")[] | undefined;
    is_favorite?: boolean | undefined;
    tags?: string[] | undefined;
    has_garments?: boolean | undefined;
    date_range?: {
        start: Date;
        end: Date;
    } | undefined;
    search?: string | undefined;
    sort_by?: "size" | "capture_date" | "upload_date" | "name" | undefined;
    sort_order?: "asc" | "desc" | undefined;
}>;
export declare const BatchImageOperationSchema: z.ZodObject<{
    image_ids: z.ZodArray<z.ZodString, "many">;
    operation: z.ZodEnum<["delete", "archive", "favorite", "unfavorite", "tag"]>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
}, "strip", z.ZodTypeAny, {
    image_ids: string[];
    operation: "delete" | "archive" | "favorite" | "unfavorite" | "tag";
    tags?: string[] | undefined;
}, {
    image_ids: string[];
    operation: "delete" | "archive" | "favorite" | "unfavorite" | "tag";
    tags?: string[] | undefined;
}>;
export type Image = z.infer<typeof ImageSchema>;
export type ImageVariants = z.infer<typeof ImageVariantSchema>;
export type EnhancedImageMetadata = z.infer<typeof EnhancedImageMetadataSchema>;
export type MobileImageUpload = z.infer<typeof MobileImageUploadSchema>;
export type ImageChunkUpload = z.infer<typeof ImageChunkUploadSchema>;
export type ImageResponse = z.infer<typeof ImageResponseSchema>;
export type MobileImageListItem = z.infer<typeof MobileImageListItemSchema>;
export type ImageListResponse = z.infer<typeof ImageListResponseSchema>;
export type ImageFilter = z.infer<typeof ImageFilterSchema>;
export type BatchImageOperation = z.infer<typeof BatchImageOperationSchema>;
export type ImageMetadata = z.infer<typeof EnhancedImageMetadataSchema>;
export declare const ImageFlutterHints: {
    freezed: boolean;
    jsonSerializable: boolean;
    copyWith: boolean;
    equatable: boolean;
    fields: {
        upload_date: string;
        cached_at: string;
        capture_date: string;
        variants: string;
        original_metadata: string;
        gps_location: string;
    };
    enums: {
        status: string;
        processing_status: string;
        sync_status: string;
        format: string;
        color_space: string;
    };
};
export declare const ImageHelpers: {
    getBestVariantUrl: (image: ImageResponse, maxWidth?: number) => string;
    getTotalSize: (variants: ImageVariants) => number;
    needsReprocessing: (image: Image) => boolean;
    toListItem: (image: Image) => MobileImageListItem;
    forOfflineCache: (image: ImageResponse) => Partial<ImageResponse>;
};
//# sourceMappingURL=image.d.ts.map