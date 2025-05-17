import { z } from 'zod';
export declare const ImageSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodString;
    file_path: z.ZodString;
    original_metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
    upload_date: z.ZodOptional<z.ZodDate>;
    status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled"]>>;
}, "strip", z.ZodTypeAny, {
    user_id: string;
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    original_metadata?: Record<string, any> | undefined;
    upload_date?: Date | undefined;
}, {
    user_id: string;
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    original_metadata?: Record<string, any> | undefined;
    upload_date?: Date | undefined;
}>;
export declare const ImageResponseSchema: z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodString;
    file_path: z.ZodString;
    original_metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
    upload_date: z.ZodOptional<z.ZodDate>;
    status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled"]>>;
}, "strip", z.ZodTypeAny, {
    user_id: string;
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    original_metadata?: Record<string, any> | undefined;
    upload_date?: Date | undefined;
}, {
    user_id: string;
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    original_metadata?: Record<string, any> | undefined;
    upload_date?: Date | undefined;
}>;
export declare const ImageListResponseSchema: z.ZodArray<z.ZodObject<{
    id: z.ZodOptional<z.ZodString>;
    user_id: z.ZodString;
    file_path: z.ZodString;
    original_metadata: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodAny>>;
    upload_date: z.ZodOptional<z.ZodDate>;
    status: z.ZodOptional<z.ZodEnum<["new", "processed", "labeled"]>>;
}, "strip", z.ZodTypeAny, {
    user_id: string;
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    original_metadata?: Record<string, any> | undefined;
    upload_date?: Date | undefined;
}, {
    user_id: string;
    file_path: string;
    status?: "new" | "processed" | "labeled" | undefined;
    id?: string | undefined;
    original_metadata?: Record<string, any> | undefined;
    upload_date?: Date | undefined;
}>, "many">;
export declare const ImageMetadataSchema: z.ZodObject<{
    filename: z.ZodOptional<z.ZodString>;
    mimetype: z.ZodOptional<z.ZodString>;
    size: z.ZodOptional<z.ZodNumber>;
    width: z.ZodOptional<z.ZodNumber>;
    height: z.ZodOptional<z.ZodNumber>;
    format: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    width?: number | undefined;
    height?: number | undefined;
    format?: string | undefined;
    filename?: string | undefined;
    mimetype?: string | undefined;
    size?: number | undefined;
}, {
    width?: number | undefined;
    height?: number | undefined;
    format?: string | undefined;
    filename?: string | undefined;
    mimetype?: string | undefined;
    size?: number | undefined;
}>;
export type Image = z.infer<typeof ImageSchema>;
export type ImageResponse = z.infer<typeof ImageResponseSchema>;
export type ImageListResponse = z.infer<typeof ImageListResponseSchema>;
export type ImageMetadata = z.infer<typeof ImageMetadataSchema>;
//# sourceMappingURL=image.d.ts.map