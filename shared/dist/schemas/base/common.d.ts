import { z } from 'zod';
export declare const UUIDSchema: z.ZodString;
export declare const EmailSchema: z.ZodString;
export declare const PasswordSchema: z.ZodString;
export declare const TimestampSchema: z.ZodUnion<[z.ZodString, z.ZodDate]>;
export declare const PaginationSchema: z.ZodObject<{
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
}>;
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
export declare const BoundingBoxSchema: z.ZodObject<{
    x: z.ZodNumber;
    y: z.ZodNumber;
    width: z.ZodNumber;
    height: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    x: number;
    y: number;
    width: number;
    height: number;
}, {
    x: number;
    y: number;
    width: number;
    height: number;
}>;
export declare const DimensionsSchema: z.ZodObject<{
    width: z.ZodNumber;
    height: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    width: number;
    height: number;
}, {
    width: number;
    height: number;
}>;
export declare const ImageStatusSchema: z.ZodEnum<["new", "processed", "labeled"]>;
export declare const ExportFormatSchema: z.ZodEnum<["coco", "yolo", "pascal_voc", "csv", "raw_json"]>;
export declare const ImageFormatSchema: z.ZodEnum<["jpg", "png", "webp"]>;
export declare const GarmentTypeSchema: z.ZodEnum<["shirt", "pants", "dress", "jacket", "skirt", "other"]>;
export declare const GarmentPatternSchema: z.ZodEnum<["solid", "striped", "plaid", "floral", "geometric", "other"]>;
export declare const SeasonSchema: z.ZodEnum<["spring", "summer", "fall", "winter", "all"]>;
export declare const JobStatusSchema: z.ZodEnum<["pending", "processing", "completed", "failed", "cancelled"]>;
export declare const createOptionalSchema: <T extends z.ZodTypeAny>(schema: T) => z.ZodOptional<T>;
export declare const createArraySchema: <T extends z.ZodTypeAny>(schema: T, min?: number, max?: number) => z.ZodArray<T, "many">;
export declare const createRecordSchema: <T extends z.ZodTypeAny>(valueSchema: T) => z.ZodRecord<z.ZodString, T>;
export declare const FileMetadataSchema: z.ZodObject<{
    filename: z.ZodString;
    mimetype: z.ZodString;
    size: z.ZodNumber;
    uploadedAt: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    filename: string;
    mimetype: string;
    size: number;
    uploadedAt?: string | Date | undefined;
}, {
    filename: string;
    mimetype: string;
    size: number;
    uploadedAt?: string | Date | undefined;
}>;
export declare const ImageMetadataSchema: z.ZodObject<{
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
    filename: string;
    mimetype: string;
    size: number;
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
    filename: string;
    mimetype: string;
    size: number;
    width?: number | undefined;
    height?: number | undefined;
    format?: string | undefined;
    uploadedAt?: string | Date | undefined;
    density?: number | undefined;
    hasProfile?: boolean | undefined;
    hasAlpha?: boolean | undefined;
    channels?: number | undefined;
    space?: string | undefined;
}>;
export declare const ValidationErrorSchema: z.ZodObject<{
    field: z.ZodString;
    message: z.ZodString;
    code: z.ZodOptional<z.ZodString>;
    value: z.ZodOptional<z.ZodAny>;
}, "strip", z.ZodTypeAny, {
    message: string;
    field: string;
    value?: any;
    code?: string | undefined;
}, {
    message: string;
    field: string;
    value?: any;
    code?: string | undefined;
}>;
export declare const ApiErrorSchema: z.ZodObject<{
    status: z.ZodLiteral<"error">;
    code: z.ZodString;
    message: z.ZodString;
    errors: z.ZodOptional<z.ZodArray<z.ZodObject<{
        field: z.ZodString;
        message: z.ZodString;
        code: z.ZodOptional<z.ZodString>;
        value: z.ZodOptional<z.ZodAny>;
    }, "strip", z.ZodTypeAny, {
        message: string;
        field: string;
        value?: any;
        code?: string | undefined;
    }, {
        message: string;
        field: string;
        value?: any;
        code?: string | undefined;
    }>, "many">>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, {
    code: string;
    message: string;
    status: "error";
    errors?: {
        message: string;
        field: string;
        value?: any;
        code?: string | undefined;
    }[] | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}, {
    code: string;
    message: string;
    status: "error";
    errors?: {
        message: string;
        field: string;
        value?: any;
        code?: string | undefined;
    }[] | undefined;
    requestId?: string | undefined;
    timestamp?: string | Date | undefined;
}>;
export declare const ApiSuccessSchema: <T extends z.ZodTypeAny>(dataSchema: T) => z.ZodObject<{
    status: z.ZodLiteral<"success">;
    data: T;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}, "strip", z.ZodTypeAny, z.objectUtil.addQuestionMarks<z.baseObjectOutputType<{
    status: z.ZodLiteral<"success">;
    data: T;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}>, any> extends infer T_1 ? { [k in keyof T_1]: z.objectUtil.addQuestionMarks<z.baseObjectOutputType<{
    status: z.ZodLiteral<"success">;
    data: T;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}>, any>[k]; } : never, z.baseObjectInputType<{
    status: z.ZodLiteral<"success">;
    data: T;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}> extends infer T_2 ? { [k_1 in keyof T_2]: z.baseObjectInputType<{
    status: z.ZodLiteral<"success">;
    data: T;
    message: z.ZodOptional<z.ZodString>;
    requestId: z.ZodOptional<z.ZodString>;
    timestamp: z.ZodOptional<z.ZodUnion<[z.ZodString, z.ZodDate]>>;
}>[k_1]; } : never>;
export type UUID = z.infer<typeof UUIDSchema>;
export type Email = z.infer<typeof EmailSchema>;
export type Password = z.infer<typeof PasswordSchema>;
export type Timestamp = z.infer<typeof TimestampSchema>;
export type Pagination = z.infer<typeof PaginationSchema>;
export type Point = z.infer<typeof PointSchema>;
export type BoundingBox = z.infer<typeof BoundingBoxSchema>;
export type Dimensions = z.infer<typeof DimensionsSchema>;
export type ImageStatus = z.infer<typeof ImageStatusSchema>;
export type ExportFormat = z.infer<typeof ExportFormatSchema>;
export type ImageFormat = z.infer<typeof ImageFormatSchema>;
export type GarmentType = z.infer<typeof GarmentTypeSchema>;
export type GarmentPattern = z.infer<typeof GarmentPatternSchema>;
export type Season = z.infer<typeof SeasonSchema>;
export type JobStatus = z.infer<typeof JobStatusSchema>;
export type FileMetadata = z.infer<typeof FileMetadataSchema>;
export type ImageMetadata = z.infer<typeof ImageMetadataSchema>;
export type ValidationError = z.infer<typeof ValidationErrorSchema>;
export type ApiError = z.infer<typeof ApiErrorSchema>;
export type ApiSuccess<T> = {
    status: 'success';
    data: T;
    message?: string;
    requestId?: string;
    timestamp?: Timestamp;
};
//# sourceMappingURL=common.d.ts.map