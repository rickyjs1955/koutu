// Mock for shared schemas index
export const UUIDSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value })),
  optional: jest.fn().mockReturnThis(),
  nullable: jest.fn().mockReturnThis()
};

export const ImageStatusSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value })),
  optional: jest.fn().mockReturnThis(),
  nullable: jest.fn().mockReturnThis()
};

export const TimestampSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value })),
  optional: jest.fn().mockReturnThis(),
  nullable: jest.fn().mockReturnThis()
};

export const UserSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value }))
};

export const CreateUserSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value }))
};

export const BiometricLoginSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value }))
};

export const DeviceRegistrationSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value }))
};

// Mobile validation constants and patterns
export const MobileValidation = {
  MAX_MOBILE_FILE_SIZE: 5 * 1024 * 1024,
  MAX_MOBILE_TEXT_LENGTH: 500,
  MAX_MOBILE_ARRAY_LENGTH: 100,
  MOBILE_IMAGE_FORMATS: ['jpeg', 'jpg', 'png', 'webp'] as const,
  MOBILE_PATTERNS: {
    deviceId: /^[a-zA-Z0-9\-_]{16,128}$/,
    biometricId: /^[a-zA-Z0-9\-_]{32,256}$/,
    pushToken: /^[a-zA-Z0-9\-_:]{32,512}$/
  }
};

// Mobile export formats
export const MobileExportFormats = {
  IMAGE_THUMBNAIL: { width: 150, height: 150, quality: 0.7 },
  IMAGE_PREVIEW: { width: 600, height: 600, quality: 0.8 },
  IMAGE_FULL: { width: 1200, height: 1200, quality: 0.9 },
  BATCH_SIZE: 20,
  CHUNK_SIZE: 1024 * 1024 // 1MB chunks for progressive download
};