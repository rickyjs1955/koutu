import { z } from 'zod';
export declare const MobileGarmentFieldsSchema: z.ZodObject<{
    thumbnail_url: z.ZodOptional<z.ZodString>;
    preview_url: z.ZodOptional<z.ZodString>;
    full_image_url: z.ZodOptional<z.ZodString>;
    mask_thumbnail_url: z.ZodOptional<z.ZodString>;
    is_favorite: z.ZodDefault<z.ZodBoolean>;
    wear_count: z.ZodDefault<z.ZodNumber>;
    last_worn_date: z.ZodOptional<z.ZodDate>;
    local_id: z.ZodOptional<z.ZodString>;
    sync_status: z.ZodDefault<z.ZodEnum<["synced", "pending", "conflict"]>>;
    cached_at: z.ZodOptional<z.ZodDate>;
    file_size: z.ZodOptional<z.ZodNumber>;
    dimensions: z.ZodOptional<z.ZodObject<{
        width: z.ZodNumber;
        height: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
    }, {
        width: number;
        height: number;
    }>>;
}, "strip", z.ZodTypeAny, {
    is_favorite: boolean;
    wear_count: number;
    sync_status: "pending" | "synced" | "conflict";
    thumbnail_url?: string | undefined;
    preview_url?: string | undefined;
    full_image_url?: string | undefined;
    mask_thumbnail_url?: string | undefined;
    last_worn_date?: Date | undefined;
    local_id?: string | undefined;
    cached_at?: Date | undefined;
    file_size?: number | undefined;
    dimensions?: {
        width: number;
        height: number;
    } | undefined;
}, {
    thumbnail_url?: string | undefined;
    preview_url?: string | undefined;
    full_image_url?: string | undefined;
    mask_thumbnail_url?: string | undefined;
    is_favorite?: boolean | undefined;
    wear_count?: number | undefined;
    last_worn_date?: Date | undefined;
    local_id?: string | undefined;
    sync_status?: "pending" | "synced" | "conflict" | undefined;
    cached_at?: Date | undefined;
    file_size?: number | undefined;
    dimensions?: {
        width: number;
        height: number;
    } | undefined;
}>;
export declare const EnhancedMetadataSchema: z.ZodObject<{
    type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>;
    color: z.ZodString;
    secondary_colors: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "abstract", "animal_print", "other"]>>;
    season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
    occasion: z.ZodOptional<z.ZodEnum<["casual", "formal", "business", "sport", "party", "beach", "other"]>>;
    brand: z.ZodOptional<z.ZodString>;
    size: z.ZodOptional<z.ZodString>;
    material: z.ZodOptional<z.ZodString>;
    care_instructions: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    purchase_date: z.ZodOptional<z.ZodDate>;
    purchase_price: z.ZodOptional<z.ZodNumber>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    notes: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
    color: string;
    secondary_colors?: string[] | undefined;
    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
    occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
    brand?: string | undefined;
    size?: string | undefined;
    material?: string | undefined;
    care_instructions?: string[] | undefined;
    purchase_date?: Date | undefined;
    purchase_price?: number | undefined;
    tags?: string[] | undefined;
    notes?: string | undefined;
}, {
    type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
    color: string;
    secondary_colors?: string[] | undefined;
    pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
    season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
    occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
    brand?: string | undefined;
    size?: string | undefined;
    material?: string | undefined;
    care_instructions?: string[] | undefined;
    purchase_date?: Date | undefined;
    purchase_price?: number | undefined;
    tags?: string[] | undefined;
    notes?: string | undefined;
}>;
export declare const GarmentSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodString;
    original_image_id: z.ZodString;
    file_path: z.ZodString;
    mask_path: z.ZodString;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>;
        color: z.ZodString;
        secondary_colors: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "abstract", "animal_print", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        occasion: z.ZodOptional<z.ZodEnum<["casual", "formal", "business", "sport", "party", "beach", "other"]>>;
        brand: z.ZodOptional<z.ZodString>;
        size: z.ZodOptional<z.ZodString>;
        material: z.ZodOptional<z.ZodString>;
        care_instructions: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        purchase_date: z.ZodOptional<z.ZodDate>;
        purchase_price: z.ZodOptional<z.ZodNumber>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        notes: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
    data_version: z.ZodOptional<z.ZodNumber>;
} & {
    thumbnail_url: z.ZodOptional<z.ZodString>;
    preview_url: z.ZodOptional<z.ZodString>;
    full_image_url: z.ZodOptional<z.ZodString>;
    mask_thumbnail_url: z.ZodOptional<z.ZodString>;
    is_favorite: z.ZodDefault<z.ZodBoolean>;
    wear_count: z.ZodDefault<z.ZodNumber>;
    last_worn_date: z.ZodOptional<z.ZodDate>;
    local_id: z.ZodOptional<z.ZodString>;
    sync_status: z.ZodDefault<z.ZodEnum<["synced", "pending", "conflict"]>>;
    cached_at: z.ZodOptional<z.ZodDate>;
    file_size: z.ZodOptional<z.ZodNumber>;
    dimensions: z.ZodOptional<z.ZodObject<{
        width: z.ZodNumber;
        height: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
    }, {
        width: number;
        height: number;
    }>>;
}, "strip", z.ZodTypeAny, {
    is_favorite: boolean;
    wear_count: number;
    sync_status: "pending" | "synced" | "conflict";
    user_id: string;
    original_image_id: string;
    file_path: string;
    mask_path: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    id?: string | undefined;
    thumbnail_url?: string | undefined;
    preview_url?: string | undefined;
    full_image_url?: string | undefined;
    mask_thumbnail_url?: string | undefined;
    last_worn_date?: Date | undefined;
    local_id?: string | undefined;
    cached_at?: Date | undefined;
    file_size?: number | undefined;
    dimensions?: {
        width: number;
        height: number;
    } | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    data_version?: number | undefined;
}, {
    user_id: string;
    original_image_id: string;
    file_path: string;
    mask_path: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    id?: string | undefined;
    thumbnail_url?: string | undefined;
    preview_url?: string | undefined;
    full_image_url?: string | undefined;
    mask_thumbnail_url?: string | undefined;
    is_favorite?: boolean | undefined;
    wear_count?: number | undefined;
    last_worn_date?: Date | undefined;
    local_id?: string | undefined;
    sync_status?: "pending" | "synced" | "conflict" | undefined;
    cached_at?: Date | undefined;
    file_size?: number | undefined;
    dimensions?: {
        width: number;
        height: number;
    } | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    data_version?: number | undefined;
}>;
export declare const MobileGarmentListItemSchema: z.ZodObject<{
    id: z.ZodString;
    thumbnail_url: z.ZodString;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>;
        color: z.ZodString;
        brand: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        brand?: string | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        brand?: string | undefined;
    }>;
    is_favorite: z.ZodBoolean;
    wear_count: z.ZodNumber;
    last_worn_date: z.ZodOptional<z.ZodDate>;
    sync_status: z.ZodEnum<["synced", "pending", "conflict"]>;
}, "strip", z.ZodTypeAny, {
    id: string;
    thumbnail_url: string;
    is_favorite: boolean;
    wear_count: number;
    sync_status: "pending" | "synced" | "conflict";
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        brand?: string | undefined;
    };
    last_worn_date?: Date | undefined;
}, {
    id: string;
    thumbnail_url: string;
    is_favorite: boolean;
    wear_count: number;
    sync_status: "pending" | "synced" | "conflict";
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        brand?: string | undefined;
    };
    last_worn_date?: Date | undefined;
}>;
export declare const CreateGarmentSchema: z.ZodObject<{
    original_image_id: z.ZodString;
    file_path: z.ZodOptional<z.ZodString>;
    mask_path: z.ZodOptional<z.ZodString>;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>;
        color: z.ZodString;
        secondary_colors: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "abstract", "animal_print", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        occasion: z.ZodOptional<z.ZodEnum<["casual", "formal", "business", "sport", "party", "beach", "other"]>>;
        brand: z.ZodOptional<z.ZodString>;
        size: z.ZodOptional<z.ZodString>;
        material: z.ZodOptional<z.ZodString>;
        care_instructions: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        purchase_date: z.ZodOptional<z.ZodDate>;
        purchase_price: z.ZodOptional<z.ZodNumber>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        notes: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }>;
    mask_data: z.ZodObject<{
        width: z.ZodNumber;
        height: z.ZodNumber;
        data: z.ZodArray<z.ZodNumber, "many">;
        format: z.ZodDefault<z.ZodEnum<["raw", "rle", "base64"]>>;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
        format: "raw" | "rle" | "base64";
        data: number[];
    }, {
        width: number;
        height: number;
        data: number[];
        format?: "raw" | "rle" | "base64" | undefined;
    }>;
    local_id: z.ZodOptional<z.ZodString>;
    create_thumbnail: z.ZodDefault<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    mask_data: {
        width: number;
        height: number;
        format: "raw" | "rle" | "base64";
        data: number[];
    };
    create_thumbnail: boolean;
    local_id?: string | undefined;
    file_path?: string | undefined;
    mask_path?: string | undefined;
}, {
    original_image_id: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    mask_data: {
        width: number;
        height: number;
        data: number[];
        format?: "raw" | "rle" | "base64" | undefined;
    };
    local_id?: string | undefined;
    file_path?: string | undefined;
    mask_path?: string | undefined;
    create_thumbnail?: boolean | undefined;
}>;
export declare const BatchCreateGarmentSchema: z.ZodObject<{
    garments: z.ZodArray<z.ZodObject<{
        original_image_id: z.ZodString;
        file_path: z.ZodOptional<z.ZodString>;
        mask_path: z.ZodOptional<z.ZodString>;
        metadata: z.ZodObject<{
            type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>;
            color: z.ZodString;
            secondary_colors: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
            pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "abstract", "animal_print", "other"]>>;
            season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
            occasion: z.ZodOptional<z.ZodEnum<["casual", "formal", "business", "sport", "party", "beach", "other"]>>;
            brand: z.ZodOptional<z.ZodString>;
            size: z.ZodOptional<z.ZodString>;
            material: z.ZodOptional<z.ZodString>;
            care_instructions: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
            purchase_date: z.ZodOptional<z.ZodDate>;
            purchase_price: z.ZodOptional<z.ZodNumber>;
            tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
            notes: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
            color: string;
            secondary_colors?: string[] | undefined;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            care_instructions?: string[] | undefined;
            purchase_date?: Date | undefined;
            purchase_price?: number | undefined;
            tags?: string[] | undefined;
            notes?: string | undefined;
        }, {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
            color: string;
            secondary_colors?: string[] | undefined;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            care_instructions?: string[] | undefined;
            purchase_date?: Date | undefined;
            purchase_price?: number | undefined;
            tags?: string[] | undefined;
            notes?: string | undefined;
        }>;
        mask_data: z.ZodObject<{
            width: z.ZodNumber;
            height: z.ZodNumber;
            data: z.ZodArray<z.ZodNumber, "many">;
            format: z.ZodDefault<z.ZodEnum<["raw", "rle", "base64"]>>;
        }, "strip", z.ZodTypeAny, {
            width: number;
            height: number;
            format: "raw" | "rle" | "base64";
            data: number[];
        }, {
            width: number;
            height: number;
            data: number[];
            format?: "raw" | "rle" | "base64" | undefined;
        }>;
        local_id: z.ZodOptional<z.ZodString>;
        create_thumbnail: z.ZodDefault<z.ZodBoolean>;
    }, "strip", z.ZodTypeAny, {
        original_image_id: string;
        metadata: {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
            color: string;
            secondary_colors?: string[] | undefined;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            care_instructions?: string[] | undefined;
            purchase_date?: Date | undefined;
            purchase_price?: number | undefined;
            tags?: string[] | undefined;
            notes?: string | undefined;
        };
        mask_data: {
            width: number;
            height: number;
            format: "raw" | "rle" | "base64";
            data: number[];
        };
        create_thumbnail: boolean;
        local_id?: string | undefined;
        file_path?: string | undefined;
        mask_path?: string | undefined;
    }, {
        original_image_id: string;
        metadata: {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
            color: string;
            secondary_colors?: string[] | undefined;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            care_instructions?: string[] | undefined;
            purchase_date?: Date | undefined;
            purchase_price?: number | undefined;
            tags?: string[] | undefined;
            notes?: string | undefined;
        };
        mask_data: {
            width: number;
            height: number;
            data: number[];
            format?: "raw" | "rle" | "base64" | undefined;
        };
        local_id?: string | undefined;
        file_path?: string | undefined;
        mask_path?: string | undefined;
        create_thumbnail?: boolean | undefined;
    }>, "many">;
    process_async: z.ZodDefault<z.ZodBoolean>;
    notification_token: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    garments: {
        original_image_id: string;
        metadata: {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
            color: string;
            secondary_colors?: string[] | undefined;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            care_instructions?: string[] | undefined;
            purchase_date?: Date | undefined;
            purchase_price?: number | undefined;
            tags?: string[] | undefined;
            notes?: string | undefined;
        };
        mask_data: {
            width: number;
            height: number;
            format: "raw" | "rle" | "base64";
            data: number[];
        };
        create_thumbnail: boolean;
        local_id?: string | undefined;
        file_path?: string | undefined;
        mask_path?: string | undefined;
    }[];
    process_async: boolean;
    notification_token?: string | undefined;
}, {
    garments: {
        original_image_id: string;
        metadata: {
            type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
            color: string;
            secondary_colors?: string[] | undefined;
            pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
            season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
            occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
            brand?: string | undefined;
            size?: string | undefined;
            material?: string | undefined;
            care_instructions?: string[] | undefined;
            purchase_date?: Date | undefined;
            purchase_price?: number | undefined;
            tags?: string[] | undefined;
            notes?: string | undefined;
        };
        mask_data: {
            width: number;
            height: number;
            data: number[];
            format?: "raw" | "rle" | "base64" | undefined;
        };
        local_id?: string | undefined;
        file_path?: string | undefined;
        mask_path?: string | undefined;
        create_thumbnail?: boolean | undefined;
    }[];
    process_async?: boolean | undefined;
    notification_token?: string | undefined;
}>;
export declare const UpdateGarmentMetadataSchema: z.ZodObject<{
    metadata: z.ZodObject<{
        type: z.ZodOptional<z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>>;
        color: z.ZodOptional<z.ZodString>;
        secondary_colors: z.ZodOptional<z.ZodOptional<z.ZodArray<z.ZodString, "many">>>;
        pattern: z.ZodOptional<z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "abstract", "animal_print", "other"]>>>;
        season: z.ZodOptional<z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>>;
        occasion: z.ZodOptional<z.ZodOptional<z.ZodEnum<["casual", "formal", "business", "sport", "party", "beach", "other"]>>>;
        brand: z.ZodOptional<z.ZodOptional<z.ZodString>>;
        size: z.ZodOptional<z.ZodOptional<z.ZodString>>;
        material: z.ZodOptional<z.ZodOptional<z.ZodString>>;
        care_instructions: z.ZodOptional<z.ZodOptional<z.ZodArray<z.ZodString, "many">>>;
        purchase_date: z.ZodOptional<z.ZodOptional<z.ZodDate>>;
        purchase_price: z.ZodOptional<z.ZodOptional<z.ZodNumber>>;
        tags: z.ZodOptional<z.ZodOptional<z.ZodArray<z.ZodString, "many">>>;
        notes: z.ZodOptional<z.ZodOptional<z.ZodString>>;
    }, "strip", z.ZodTypeAny, {
        type?: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other" | undefined;
        color?: string | undefined;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }, {
        type?: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other" | undefined;
        color?: string | undefined;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }>;
    wear_count_increment: z.ZodOptional<z.ZodNumber>;
    mark_as_worn: z.ZodOptional<z.ZodBoolean>;
    is_favorite: z.ZodOptional<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    metadata: {
        type?: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other" | undefined;
        color?: string | undefined;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    is_favorite?: boolean | undefined;
    wear_count_increment?: number | undefined;
    mark_as_worn?: boolean | undefined;
}, {
    metadata: {
        type?: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other" | undefined;
        color?: string | undefined;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    is_favorite?: boolean | undefined;
    wear_count_increment?: number | undefined;
    mark_as_worn?: boolean | undefined;
}>;
export declare const GarmentResponseSchema: z.ZodObject<Omit<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodString;
    original_image_id: z.ZodString;
    file_path: z.ZodString;
    mask_path: z.ZodString;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>;
        color: z.ZodString;
        secondary_colors: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "abstract", "animal_print", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        occasion: z.ZodOptional<z.ZodEnum<["casual", "formal", "business", "sport", "party", "beach", "other"]>>;
        brand: z.ZodOptional<z.ZodString>;
        size: z.ZodOptional<z.ZodString>;
        material: z.ZodOptional<z.ZodString>;
        care_instructions: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        purchase_date: z.ZodOptional<z.ZodDate>;
        purchase_price: z.ZodOptional<z.ZodNumber>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        notes: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
    data_version: z.ZodOptional<z.ZodNumber>;
} & {
    thumbnail_url: z.ZodOptional<z.ZodString>;
    preview_url: z.ZodOptional<z.ZodString>;
    full_image_url: z.ZodOptional<z.ZodString>;
    mask_thumbnail_url: z.ZodOptional<z.ZodString>;
    is_favorite: z.ZodDefault<z.ZodBoolean>;
    wear_count: z.ZodDefault<z.ZodNumber>;
    last_worn_date: z.ZodOptional<z.ZodDate>;
    local_id: z.ZodOptional<z.ZodString>;
    sync_status: z.ZodDefault<z.ZodEnum<["synced", "pending", "conflict"]>>;
    cached_at: z.ZodOptional<z.ZodDate>;
    file_size: z.ZodOptional<z.ZodNumber>;
    dimensions: z.ZodOptional<z.ZodObject<{
        width: z.ZodNumber;
        height: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
    }, {
        width: number;
        height: number;
    }>>;
}, "user_id" | "file_path" | "mask_path">, "strip", z.ZodTypeAny, {
    is_favorite: boolean;
    wear_count: number;
    sync_status: "pending" | "synced" | "conflict";
    original_image_id: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    id?: string | undefined;
    thumbnail_url?: string | undefined;
    preview_url?: string | undefined;
    full_image_url?: string | undefined;
    mask_thumbnail_url?: string | undefined;
    last_worn_date?: Date | undefined;
    local_id?: string | undefined;
    cached_at?: Date | undefined;
    file_size?: number | undefined;
    dimensions?: {
        width: number;
        height: number;
    } | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    data_version?: number | undefined;
}, {
    original_image_id: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    id?: string | undefined;
    thumbnail_url?: string | undefined;
    preview_url?: string | undefined;
    full_image_url?: string | undefined;
    mask_thumbnail_url?: string | undefined;
    is_favorite?: boolean | undefined;
    wear_count?: number | undefined;
    last_worn_date?: Date | undefined;
    local_id?: string | undefined;
    sync_status?: "pending" | "synced" | "conflict" | undefined;
    cached_at?: Date | undefined;
    file_size?: number | undefined;
    dimensions?: {
        width: number;
        height: number;
    } | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    data_version?: number | undefined;
}>;
export declare const MobileGarmentResponseSchema: z.ZodObject<{
    id: z.ZodString;
    thumbnail_url: z.ZodString;
    preview_url: z.ZodOptional<z.ZodString>;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>;
        color: z.ZodString;
        secondary_colors: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "abstract", "animal_print", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        occasion: z.ZodOptional<z.ZodEnum<["casual", "formal", "business", "sport", "party", "beach", "other"]>>;
        brand: z.ZodOptional<z.ZodString>;
        size: z.ZodOptional<z.ZodString>;
        material: z.ZodOptional<z.ZodString>;
        care_instructions: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        purchase_date: z.ZodOptional<z.ZodDate>;
        purchase_price: z.ZodOptional<z.ZodNumber>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        notes: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    }>;
    is_favorite: z.ZodBoolean;
    wear_count: z.ZodNumber;
    last_worn_date: z.ZodOptional<z.ZodDate>;
    sync_status: z.ZodEnum<["synced", "pending", "conflict"]>;
    dimensions: z.ZodOptional<z.ZodObject<{
        width: z.ZodNumber;
        height: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
    }, {
        width: number;
        height: number;
    }>>;
}, "strip", z.ZodTypeAny, {
    id: string;
    thumbnail_url: string;
    is_favorite: boolean;
    wear_count: number;
    sync_status: "pending" | "synced" | "conflict";
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    preview_url?: string | undefined;
    last_worn_date?: Date | undefined;
    dimensions?: {
        width: number;
        height: number;
    } | undefined;
}, {
    id: string;
    thumbnail_url: string;
    is_favorite: boolean;
    wear_count: number;
    sync_status: "pending" | "synced" | "conflict";
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other";
        color: string;
        secondary_colors?: string[] | undefined;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | "abstract" | "animal_print" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        occasion?: "other" | "casual" | "formal" | "business" | "sport" | "party" | "beach" | undefined;
        brand?: string | undefined;
        size?: string | undefined;
        material?: string | undefined;
        care_instructions?: string[] | undefined;
        purchase_date?: Date | undefined;
        purchase_price?: number | undefined;
        tags?: string[] | undefined;
        notes?: string | undefined;
    };
    preview_url?: string | undefined;
    last_worn_date?: Date | undefined;
    dimensions?: {
        width: number;
        height: number;
    } | undefined;
}>;
export declare const GarmentFilterSchema: z.ZodObject<{
    types: z.ZodOptional<z.ZodArray<z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "accessories", "shoes", "bags", "other"]>, "many">>;
    colors: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    seasons: z.ZodOptional<z.ZodArray<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>, "many">>;
    occasions: z.ZodOptional<z.ZodArray<z.ZodEnum<["casual", "formal", "business", "sport", "party", "beach", "other"]>, "many">>;
    brands: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    is_favorite: z.ZodOptional<z.ZodBoolean>;
    worn_recently: z.ZodOptional<z.ZodBoolean>;
    never_worn: z.ZodOptional<z.ZodBoolean>;
    search: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    is_favorite?: boolean | undefined;
    tags?: string[] | undefined;
    types?: ("shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other")[] | undefined;
    colors?: string[] | undefined;
    seasons?: ("spring" | "summer" | "fall" | "winter" | "all")[] | undefined;
    occasions?: ("other" | "casual" | "formal" | "business" | "sport" | "party" | "beach")[] | undefined;
    brands?: string[] | undefined;
    worn_recently?: boolean | undefined;
    never_worn?: boolean | undefined;
    search?: string | undefined;
}, {
    is_favorite?: boolean | undefined;
    tags?: string[] | undefined;
    types?: ("shirt" | "pants" | "dress" | "jacket" | "skirt" | "accessories" | "shoes" | "bags" | "other")[] | undefined;
    colors?: string[] | undefined;
    seasons?: ("spring" | "summer" | "fall" | "winter" | "all")[] | undefined;
    occasions?: ("other" | "casual" | "formal" | "business" | "sport" | "party" | "beach")[] | undefined;
    brands?: string[] | undefined;
    worn_recently?: boolean | undefined;
    never_worn?: boolean | undefined;
    search?: string | undefined;
}>;
export type GarmentMetadata = z.infer<typeof EnhancedMetadataSchema>;
export type Garment = z.infer<typeof GarmentSchema>;
export type MobileGarmentListItem = z.infer<typeof MobileGarmentListItemSchema>;
export type CreateGarmentInput = z.infer<typeof CreateGarmentSchema>;
export type BatchCreateGarmentInput = z.infer<typeof BatchCreateGarmentSchema>;
export type UpdateGarmentMetadata = z.infer<typeof UpdateGarmentMetadataSchema>;
export type GarmentResponse = z.infer<typeof GarmentResponseSchema>;
export type MobileGarmentResponse = z.infer<typeof MobileGarmentResponseSchema>;
export type GarmentFilter = z.infer<typeof GarmentFilterSchema>;
export declare const GarmentFlutterHints: {
    freezed: boolean;
    jsonSerializable: boolean;
    copyWith: boolean;
    equatable: boolean;
    fields: {
        created_at: string;
        updated_at: string;
        last_worn_date: string;
        cached_at: string;
        purchase_date: string;
        metadata: string;
        dimensions: string;
    };
    enums: {
        type: string;
        pattern: string;
        season: string;
        occasion: string;
        sync_status: string;
    };
};
export declare const GarmentHelpers: {
    toListItem: (garment: Garment) => MobileGarmentListItem;
    needsSync: (garment: Garment) => boolean;
    getCacheAge: (garment: Garment) => number;
    isCacheStale: (garment: Garment) => boolean;
    getImageUrl: (garment: GarmentResponse, quality: "thumbnail" | "preview" | "full") => string;
};
//# sourceMappingURL=garment.d.ts.map