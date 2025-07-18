"use strict";
// /shared/src/schemas/index.ts
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.DeviceRegistrationSchema = exports.BiometricLoginSchema = exports.MobileExportFormats = exports.MobileValidation = exports.TypeConverters = void 0;
// User schemas
__exportStar(require("./user"), exports);
// Garment schemas
__exportStar(require("./garment"), exports);
// Wardrobe schemas
__exportStar(require("./wardrobe"), exports);
// Image schemas
__exportStar(require("./image"), exports);
// Export schemas
__exportStar(require("./export"), exports);
// Polygon schemas
__exportStar(require("./polygon"), exports);
// OAuth schemas
__exportStar(require("./oauth"), exports);
// Type conversion utilities for Dart compatibility
exports.TypeConverters = {
    // Convert JavaScript Date to ISO string for Dart DateTime
    dateToString: (date) => {
        if (!date)
            return null;
        return typeof date === 'string' ? date : date.toISOString();
    },
    // Convert string to Date for JavaScript usage
    stringToDate: (dateString) => {
        if (!dateString)
            return null;
        return new Date(dateString);
    },
    // Ensure number types for Dart compatibility
    ensureNumber: (value) => {
        if (value === null || value === undefined)
            return null;
        const num = Number(value);
        return isNaN(num) ? null : num;
    },
    // Ensure boolean types for Dart compatibility
    ensureBoolean: (value) => {
        return Boolean(value);
    }
};
// Mobile-specific validation rules
exports.MobileValidation = {
    // Max file size for mobile uploads (5MB)
    MAX_MOBILE_FILE_SIZE: 5 * 1024 * 1024,
    // Max string length for mobile text fields
    MAX_MOBILE_TEXT_LENGTH: 500,
    // Max array length for mobile lists
    MAX_MOBILE_ARRAY_LENGTH: 100,
    // Supported image formats for mobile
    MOBILE_IMAGE_FORMATS: ['jpeg', 'jpg', 'png', 'webp'],
    // Mobile-specific regex patterns
    MOBILE_PATTERNS: {
        deviceId: /^[a-zA-Z0-9\-_]{16,128}$/,
        biometricId: /^[a-zA-Z0-9\-_]{32,256}$/,
        pushToken: /^[a-zA-Z0-9\-_:]{32,512}$/
    }
};
// Export format optimizations for mobile
exports.MobileExportFormats = {
    IMAGE_THUMBNAIL: { width: 150, height: 150, quality: 0.7 },
    IMAGE_PREVIEW: { width: 600, height: 600, quality: 0.8 },
    IMAGE_FULL: { width: 1200, height: 1200, quality: 0.9 },
    BATCH_SIZE: 20,
    CHUNK_SIZE: 1024 * 1024 // 1MB chunks for progressive download
};
// Re-export specific schemas that are used in routes
var user_1 = require("./user");
Object.defineProperty(exports, "BiometricLoginSchema", { enumerable: true, get: function () { return user_1.BiometricLoginSchema; } });
Object.defineProperty(exports, "DeviceRegistrationSchema", { enumerable: true, get: function () { return user_1.DeviceRegistrationSchema; } });
// Temporarily comment out conflicting exports to fix build
/*
// Export schemas
export * from './export';

// Polygon schemas
export * from './polygon';
*/ 
//# sourceMappingURL=index.js.map