import { z } from 'zod';
export declare const PointSchema: z.ZodObject<{
    x: z.ZodNumber;
    y: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    x: number;
    y: number;
}, {
    x: number;
    y: number;
}>;
export declare const PolygonSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
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
    metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    id?: string | undefined;
    metadata?: Record<string, any> | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    label?: string | undefined;
}, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    id?: string | undefined;
    metadata?: Record<string, any> | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
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
    metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    metadata?: Record<string, any> | undefined;
    label?: string | undefined;
}, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    metadata?: Record<string, any> | undefined;
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
    metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
}, "strip", z.ZodTypeAny, {
    metadata?: Record<string, any> | undefined;
    points?: {
        x: number;
        y: number;
    }[] | undefined;
    label?: string | undefined;
}, {
    metadata?: Record<string, any> | undefined;
    points?: {
        x: number;
        y: number;
    }[] | undefined;
    label?: string | undefined;
}>;
export declare const PolygonResponseSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
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
    metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
    created_at: z.ZodOptional<z.ZodDate>;
    updated_at: z.ZodOptional<z.ZodDate>;
}, "strip", z.ZodTypeAny, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    id?: string | undefined;
    metadata?: Record<string, any> | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    label?: string | undefined;
}, {
    original_image_id: string;
    points: {
        x: number;
        y: number;
    }[];
    id?: string | undefined;
    metadata?: Record<string, any> | undefined;
    created_at?: Date | undefined;
    updated_at?: Date | undefined;
    label?: string | undefined;
}>;
export type Point = z.infer<typeof PointSchema>;
export type Polygon = z.infer<typeof PolygonSchema>;
export type CreatePolygonInput = z.infer<typeof CreatePolygonSchema>;
export type UpdatePolygonInput = z.infer<typeof UpdatePolygonSchema>;
export type PolygonResponse = z.infer<typeof PolygonResponseSchema>;
//# sourceMappingURL=polygon.d.ts.map