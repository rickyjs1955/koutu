export * from './user';
export * from './garment';
export * from './wardrobe';
export * from './image';
export * from './export';
export * from './polygon';
export * from './oauth';
export interface FlutterSerializable {
    toJson(): Record<string, any>;
}
export type Nullable<T> = T | null;
export type Optional<T> = T | undefined;
export interface MobilePaginationParams {
    page: number;
    limit: number;
    cached?: boolean;
    lastSyncTimestamp?: string;
}
export interface MobileResponse<T> {
    data: T;
    metadata: {
        timestamp: string;
        version: string;
        cached: boolean;
        syncRequired?: boolean;
    };
}
export interface FlutterModelHints {
    freezed?: boolean;
    jsonSerializable?: boolean;
    copyWith?: boolean;
    equatable?: boolean;
}
export declare const TypeConverters: {
    dateToString: (date: Date | string | null) => string | null;
    stringToDate: (dateString: string | null) => Date | null;
    ensureNumber: (value: any) => number | null;
    ensureBoolean: (value: any) => boolean;
};
export declare const MobileValidation: {
    MAX_MOBILE_FILE_SIZE: number;
    MAX_MOBILE_TEXT_LENGTH: number;
    MAX_MOBILE_ARRAY_LENGTH: number;
    MOBILE_IMAGE_FORMATS: readonly ["jpeg", "jpg", "png", "webp"];
    MOBILE_PATTERNS: {
        deviceId: RegExp;
        biometricId: RegExp;
        pushToken: RegExp;
    };
};
export declare const MobileExportFormats: {
    readonly IMAGE_THUMBNAIL: {
        readonly width: 150;
        readonly height: 150;
        readonly quality: 0.7;
    };
    readonly IMAGE_PREVIEW: {
        readonly width: 600;
        readonly height: 600;
        readonly quality: 0.8;
    };
    readonly IMAGE_FULL: {
        readonly width: 1200;
        readonly height: 1200;
        readonly quality: 0.9;
    };
    readonly BATCH_SIZE: 20;
    readonly CHUNK_SIZE: number;
};
export { BiometricLoginSchema, DeviceRegistrationSchema } from './user';
//# sourceMappingURL=index.d.ts.map