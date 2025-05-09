import { z } from 'zod';
export declare const pointSchema: z.ZodObject<{
    x: z.ZodNumber;
    y: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    x: number;
    y: number;
}, {
    x: number;
    y: number;
}>;
export declare const mlGarmentSchema: z.ZodObject<{
    id: z.ZodString;
    imageId: z.ZodString;
    polygonPoints: z.ZodArray<z.ZodObject<{
        x: z.ZodNumber;
        y: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        x: number;
        y: number;
    }, {
        x: number;
        y: number;
    }>, "many">;
    maskBase64: z.ZodOptional<z.ZodString>;
    boundingBox: z.ZodObject<{
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
    category: z.ZodString;
    attributes: z.ZodRecord<z.ZodString, z.ZodUnion<[z.ZodString, z.ZodNumber, z.ZodBoolean]>>;
    createdAt: z.ZodString;
    updatedAt: z.ZodString;
}, "strip", z.ZodTypeAny, {
    id: string;
    imageId: string;
    polygonPoints: {
        x: number;
        y: number;
    }[];
    boundingBox: {
        x: number;
        y: number;
        width: number;
        height: number;
    };
    category: string;
    attributes: Record<string, string | number | boolean>;
    createdAt: string;
    updatedAt: string;
    maskBase64?: string | undefined;
}, {
    id: string;
    imageId: string;
    polygonPoints: {
        x: number;
        y: number;
    }[];
    boundingBox: {
        x: number;
        y: number;
        width: number;
        height: number;
    };
    category: string;
    attributes: Record<string, string | number | boolean>;
    createdAt: string;
    updatedAt: string;
    maskBase64?: string | undefined;
}>;
export declare const exportFormatSchema: z.ZodEnum<["coco", "yolo", "pascal_voc", "raw_json", "csv"]>;
export declare const mlExportOptionsSchema: z.ZodObject<{
    format: z.ZodEnum<["coco", "yolo", "pascal_voc", "raw_json", "csv"]>;
    includeImages: z.ZodDefault<z.ZodBoolean>;
    includeRawPolygons: z.ZodDefault<z.ZodBoolean>;
    includeMasks: z.ZodDefault<z.ZodBoolean>;
    imageFormat: z.ZodDefault<z.ZodEnum<["jpg", "png"]>>;
    compressionQuality: z.ZodDefault<z.ZodNumber>;
    garmentIds: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    categoryFilter: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    dateRange: z.ZodOptional<z.ZodObject<{
        from: z.ZodOptional<z.ZodString>;
        to: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        from?: string | undefined;
        to?: string | undefined;
    }, {
        from?: string | undefined;
        to?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
    includeImages: boolean;
    includeRawPolygons: boolean;
    includeMasks: boolean;
    imageFormat: "jpg" | "png";
    compressionQuality: number;
    garmentIds?: string[] | undefined;
    categoryFilter?: string[] | undefined;
    dateRange?: {
        from?: string | undefined;
        to?: string | undefined;
    } | undefined;
}, {
    format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
    includeImages?: boolean | undefined;
    includeRawPolygons?: boolean | undefined;
    includeMasks?: boolean | undefined;
    imageFormat?: "jpg" | "png" | undefined;
    compressionQuality?: number | undefined;
    garmentIds?: string[] | undefined;
    categoryFilter?: string[] | undefined;
    dateRange?: {
        from?: string | undefined;
        to?: string | undefined;
    } | undefined;
}>;
export declare const mlExportRequestSchema: z.ZodObject<{
    options: z.ZodObject<{
        format: z.ZodEnum<["coco", "yolo", "pascal_voc", "raw_json", "csv"]>;
        includeImages: z.ZodDefault<z.ZodBoolean>;
        includeRawPolygons: z.ZodDefault<z.ZodBoolean>;
        includeMasks: z.ZodDefault<z.ZodBoolean>;
        imageFormat: z.ZodDefault<z.ZodEnum<["jpg", "png"]>>;
        compressionQuality: z.ZodDefault<z.ZodNumber>;
        garmentIds: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        categoryFilter: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        dateRange: z.ZodOptional<z.ZodObject<{
            from: z.ZodOptional<z.ZodString>;
            to: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            from?: string | undefined;
            to?: string | undefined;
        }, {
            from?: string | undefined;
            to?: string | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages: boolean;
        includeRawPolygons: boolean;
        includeMasks: boolean;
        imageFormat: "jpg" | "png";
        compressionQuality: number;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | undefined;
            to?: string | undefined;
        } | undefined;
    }, {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages?: boolean | undefined;
        includeRawPolygons?: boolean | undefined;
        includeMasks?: boolean | undefined;
        imageFormat?: "jpg" | "png" | undefined;
        compressionQuality?: number | undefined;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | undefined;
            to?: string | undefined;
        } | undefined;
    }>;
}, "strip", z.ZodTypeAny, {
    options: {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages: boolean;
        includeRawPolygons: boolean;
        includeMasks: boolean;
        imageFormat: "jpg" | "png";
        compressionQuality: number;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | undefined;
            to?: string | undefined;
        } | undefined;
    };
}, {
    options: {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages?: boolean | undefined;
        includeRawPolygons?: boolean | undefined;
        includeMasks?: boolean | undefined;
        imageFormat?: "jpg" | "png" | undefined;
        compressionQuality?: number | undefined;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | undefined;
            to?: string | undefined;
        } | undefined;
    };
}>;
export declare const mlExportBatchJobSchema: z.ZodObject<{
    id: z.ZodString;
    userId: z.ZodString;
    status: z.ZodEnum<["pending", "processing", "completed", "failed"]>;
    options: z.ZodObject<{
        format: z.ZodEnum<["coco", "yolo", "pascal_voc", "raw_json", "csv"]>;
        includeImages: z.ZodDefault<z.ZodBoolean>;
        includeRawPolygons: z.ZodDefault<z.ZodBoolean>;
        includeMasks: z.ZodDefault<z.ZodBoolean>;
        imageFormat: z.ZodDefault<z.ZodEnum<["jpg", "png"]>>;
        compressionQuality: z.ZodDefault<z.ZodNumber>;
        garmentIds: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        categoryFilter: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
        dateRange: z.ZodOptional<z.ZodObject<{
            from: z.ZodOptional<z.ZodString>;
            to: z.ZodOptional<z.ZodString>;
        }, "strip", z.ZodTypeAny, {
            from?: string | undefined;
            to?: string | undefined;
        }, {
            from?: string | undefined;
            to?: string | undefined;
        }>>;
    }, "strip", z.ZodTypeAny, {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages: boolean;
        includeRawPolygons: boolean;
        includeMasks: boolean;
        imageFormat: "jpg" | "png";
        compressionQuality: number;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | undefined;
            to?: string | undefined;
        } | undefined;
    }, {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages?: boolean | undefined;
        includeRawPolygons?: boolean | undefined;
        includeMasks?: boolean | undefined;
        imageFormat?: "jpg" | "png" | undefined;
        compressionQuality?: number | undefined;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | undefined;
            to?: string | undefined;
        } | undefined;
    }>;
    progress: z.ZodDefault<z.ZodNumber>;
    totalItems: z.ZodDefault<z.ZodNumber>;
    processedItems: z.ZodDefault<z.ZodNumber>;
    outputUrl: z.ZodOptional<z.ZodString>;
    error: z.ZodOptional<z.ZodString>;
    createdAt: z.ZodString;
    updatedAt: z.ZodString;
    completedAt: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    options: {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages: boolean;
        includeRawPolygons: boolean;
        includeMasks: boolean;
        imageFormat: "jpg" | "png";
        compressionQuality: number;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | undefined;
            to?: string | undefined;
        } | undefined;
    };
    status: "pending" | "processing" | "completed" | "failed";
    id: string;
    createdAt: string;
    updatedAt: string;
    userId: string;
    progress: number;
    totalItems: number;
    processedItems: number;
    outputUrl?: string | undefined;
    error?: string | undefined;
    completedAt?: string | undefined;
}, {
    options: {
        format: "coco" | "yolo" | "pascal_voc" | "raw_json" | "csv";
        includeImages?: boolean | undefined;
        includeRawPolygons?: boolean | undefined;
        includeMasks?: boolean | undefined;
        imageFormat?: "jpg" | "png" | undefined;
        compressionQuality?: number | undefined;
        garmentIds?: string[] | undefined;
        categoryFilter?: string[] | undefined;
        dateRange?: {
            from?: string | undefined;
            to?: string | undefined;
        } | undefined;
    };
    status: "pending" | "processing" | "completed" | "failed";
    id: string;
    createdAt: string;
    updatedAt: string;
    userId: string;
    progress?: number | undefined;
    totalItems?: number | undefined;
    processedItems?: number | undefined;
    outputUrl?: string | undefined;
    error?: string | undefined;
    completedAt?: string | undefined;
}>;
export declare const datasetStatsSchema: z.ZodObject<{
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
export type Point = z.infer<typeof pointSchema>;
export type MLGarment = z.infer<typeof mlGarmentSchema>;
export type ExportFormat = z.infer<typeof exportFormatSchema>;
export type MLExportOptions = z.infer<typeof mlExportOptionsSchema>;
export type MLExportRequest = z.infer<typeof mlExportRequestSchema>;
export type MLExportBatchJob = z.infer<typeof mlExportBatchJobSchema>;
export type DatasetStats = z.infer<typeof datasetStatsSchema>;
//# sourceMappingURL=export.d.ts.map