import { z } from 'zod';
export declare const GarmentSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    original_image_id: z.ZodString;
    file_path: z.ZodString;
    mask_path: z.ZodString;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
        color: z.ZodString;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        brand: z.ZodOptional<z.ZodString>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    }>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
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
        tags?: string[] | undefined;
    };
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
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
        tags?: string[] | undefined;
    };
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    data_version?: number | undefined;
}>;
export declare const CreateGarmentSchema: z.ZodObject<{
    original_image_id: z.ZodString;
    file_path: z.ZodOptional<z.ZodString>;
    mask_path: z.ZodOptional<z.ZodString>;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
        color: z.ZodString;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        brand: z.ZodOptional<z.ZodString>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    }>;
    mask_data: z.ZodObject<{
        width: z.ZodNumber;
        height: z.ZodNumber;
        data: z.ZodArray<z.ZodNumber, "many">;
    }, "strip", z.ZodTypeAny, {
        width: number;
        height: number;
        data: number[];
    }, {
        width: number;
        height: number;
        data: number[];
    }>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    };
    mask_data: {
        width: number;
        height: number;
        data: number[];
    };
    file_path?: string | undefined;
    mask_path?: string | undefined;
}, {
    original_image_id: string;
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    };
    mask_data: {
        width: number;
        height: number;
        data: number[];
    };
    file_path?: string | undefined;
    mask_path?: string | undefined;
}>;
export declare const UpdateGarmentMetadataSchema: z.ZodObject<{
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
        color: z.ZodString;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        brand: z.ZodOptional<z.ZodString>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    }>;
}, "strip", z.ZodTypeAny, {
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    };
}, {
    metadata: {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    };
}>;
export declare const GarmentResponseSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    original_image_id: z.ZodString;
    file_path: z.ZodString;
    mask_path: z.ZodString;
    metadata: z.ZodObject<{
        type: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
        color: z.ZodString;
        pattern: z.ZodOptional<z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>>;
        season: z.ZodOptional<z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>>;
        brand: z.ZodOptional<z.ZodString>;
        tags: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strip", z.ZodTypeAny, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    }, {
        type: "shirt" | "pants" | "dress" | "jacket" | "skirt" | "other";
        color: string;
        pattern?: "other" | "solid" | "striped" | "plaid" | "floral" | "geometric" | undefined;
        season?: "spring" | "summer" | "fall" | "winter" | "all" | undefined;
        brand?: string | undefined;
        tags?: string[] | undefined;
    }>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
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
        tags?: string[] | undefined;
    };
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
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
        tags?: string[] | undefined;
    };
    id?: string | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    data_version?: number | undefined;
}>;
export type GarmentMetadata = z.infer<typeof GarmentSchema.shape.metadata>;
export type Garment = z.infer<typeof GarmentSchema>;
export type CreateGarmentInput = z.infer<typeof CreateGarmentSchema>;
export type UpdateGarmentMetadata = z.infer<typeof UpdateGarmentMetadataSchema>;
export type GarmentResponse = z.infer<typeof GarmentResponseSchema>;
//# sourceMappingURL=garment.d.ts.map