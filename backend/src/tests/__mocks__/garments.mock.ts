// /backend/src/utils/garments.mock.ts - Comprehensive Mock Data for Garment Testing

import { v4 as uuidv4 } from 'uuid';
import { Garment, CreateGarmentInput } from '../../models/garmentModel';

// Base Test User IDs
export const MOCK_USER_IDS = {
  VALID_USER_1: 'f47ac10b-58cc-4372-a567-0e02b2c3d479',
  VALID_USER_2: 'f47ac10b-58cc-4372-a567-0e02b2c3d480',
  INVALID_USER: 'invalid-user-id'
} as const;

// Base Image IDs for testing
export const MOCK_IMAGE_IDS = {
  VALID_NEW_IMAGE: 'a1b2c3d4-e5f6-4789-a012-bcdef0123456',
  VALID_PROCESSED_IMAGE: 'a1b2c3d4-e5f6-4789-a012-bcdef0123457',
  LABELED_IMAGE: 'a1b2c3d4-e5f6-4789-a012-bcdef0123458',
  NONEXISTENT_IMAGE: 'a1b2c3d4-e5f6-4789-a012-bcdef0123999',
  OTHER_USER_IMAGE: 'a1b2c3d4-e5f6-4789-a012-bcdef0123400'
} as const;

// Base Garment IDs for testing
export const MOCK_GARMENT_IDS = {
  VALID_GARMENT_1: 'b1c2d3e4-f5g6-4789-b012-cdefg0123456',
  VALID_GARMENT_2: 'b1c2d3e4-f5g6-4789-b012-cdefg0123457',
  NONEXISTENT_GARMENT: 'b1c2d3e4-f5g6-4789-b012-cdefg0123999',
  OTHER_USER_GARMENT: 'b1c2d3e4-f5g6-4789-b012-cdefg0123400',
  INVALID_UUID: 'invalid-garment-id'
} as const;

// Mock Mask Data
export const MOCK_MASK_DATA = {
  VALID_SMALL: {
    width: 100,
    height: 100,
    data: new Array(10000).fill(0).map((_, i) => i % 2 === 0 ? 255 : 0) // Checkerboard pattern
  },
  VALID_MEDIUM: {
    width: 500,
    height: 400,
    data: new Array(200000).fill(0).map((_, i) => i < 100000 ? 255 : 0) // Half filled
  },
  VALID_LARGE: {
    width: 1200,
    height: 800,
    data: new Array(960000).fill(0).map((_, i) => Math.random() > 0.5 ? 255 : 0) // Random pattern
  },
  EMPTY_MASK: {
    width: 100,
    height: 100,
    data: new Array(10000).fill(0) // All zeros
  },
  SPARSE_MASK: {
    width: 100,
    height: 100,
    data: new Array(10000).fill(0).map((_, i) => i % 1000 === 0 ? 255 : 0) // Very few pixels
  },
  INVALID_DIMENSIONS: {
    width: 100,
    height: 100,
    data: new Array(5000) // Wrong size array
  },
  WRONG_SIZE_DATA: {
    width: 200,
    height: 200,
    data: new Array(30000).fill(255) // Should be 40000
  }
} as const;

// Mock Metadata Variations
export const MOCK_METADATA = {
  MINIMAL: {},
  BASIC_GARMENT: {
    category: 'shirt',
    color: 'blue',
    size: 'M'
  },
  DETAILED_GARMENT: {
    category: 'dress',
    color: 'red',
    size: 'L',
    brand: 'TestBrand',
    material: 'cotton',
    season: 'summer',
    style: 'casual',
    tags: ['comfortable', 'stylish'],
    price: 29.99,
    purchaseDate: '2024-01-15'
  },
  INVALID_TYPES: {
    category: 123, // Should be string
    size: ['M'], // Should be string
    color: null
  },
  LARGE_METADATA: {
    ...Object.fromEntries(
      Array.from({ length: 100 }, (_, i) => [`field_${i}`, `value_${i}`])
    )
  },
  GARMENT_CATEGORIES: {
    TOPS: { category: 'shirt', subcategory: 'button-down' },
    BOTTOMS: { category: 'pants', subcategory: 'jeans' },
    DRESSES: { category: 'dress', subcategory: 'maxi' },
    OUTERWEAR: { category: 'jacket', subcategory: 'blazer' },
    ACCESSORIES: { category: 'belt', subcategory: 'leather' }
  }
} as const;

// Mock Images for Testing
export const MOCK_IMAGES = {
  NEW_IMAGE: {
    id: MOCK_IMAGE_IDS.VALID_NEW_IMAGE,
    user_id: MOCK_USER_IDS.VALID_USER_1,
    file_path: '/uploads/test-image-new.jpg',
    original_metadata: {
      width: 1200,
      height: 800,
      format: 'jpeg',
      size: 1024000,
      filename: 'test-image.jpg'
    },
    upload_date: new Date('2024-01-15T10:00:00Z'),
    status: 'new' as const
  },
  PROCESSED_IMAGE: {
    id: MOCK_IMAGE_IDS.VALID_PROCESSED_IMAGE,
    user_id: MOCK_USER_IDS.VALID_USER_1,
    file_path: '/uploads/test-image-processed.jpg',
    original_metadata: {
      width: 800,
      height: 600,
      format: 'jpeg',
      size: 512000,
      filename: 'processed-image.jpg'
    },
    upload_date: new Date('2024-01-14T10:00:00Z'),
    status: 'processed' as const
  },
  LABELED_IMAGE: {
    id: MOCK_IMAGE_IDS.LABELED_IMAGE,
    user_id: MOCK_USER_IDS.VALID_USER_1,
    file_path: '/uploads/test-image-labeled.jpg',
    original_metadata: {
      width: 600,
      height: 400,
      format: 'jpeg',
      size: 256000,
      filename: 'labeled-image.jpg'
    },
    upload_date: new Date('2024-01-13T10:00:00Z'),
    status: 'labeled' as const
  },
  OTHER_USER_IMAGE: {
    id: MOCK_IMAGE_IDS.OTHER_USER_IMAGE,
    user_id: MOCK_USER_IDS.VALID_USER_2,
    file_path: '/uploads/other-user-image.jpg',
    original_metadata: {
      width: 1000,
      height: 1000,
      format: 'png',
      size: 2048000,
      filename: 'other-user-image.png'
    },
    upload_date: new Date('2024-01-12T10:00:00Z'),
    status: 'new' as const
  }
} as const;

// Mock Garments for Testing
export const MOCK_GARMENTS = {
  BASIC_SHIRT: {
    id: MOCK_GARMENT_IDS.VALID_GARMENT_1,
    user_id: MOCK_USER_IDS.VALID_USER_1,
    original_image_id: MOCK_IMAGE_IDS.LABELED_IMAGE,
    file_path: '/garments/shirt-masked.jpg',
    mask_path: '/garments/shirt-mask.png',
    metadata: MOCK_METADATA.BASIC_GARMENT,
    created_at: new Date('2024-01-15T12:00:00Z'),
    updated_at: new Date('2024-01-15T12:00:00Z'),
    data_version: 1
  } as Garment,
  
  DETAILED_DRESS: {
    id: MOCK_GARMENT_IDS.VALID_GARMENT_2,
    user_id: MOCK_USER_IDS.VALID_USER_1,
    original_image_id: MOCK_IMAGE_IDS.LABELED_IMAGE,
    file_path: '/garments/dress-masked.jpg',
    mask_path: '/garments/dress-mask.png',
    metadata: MOCK_METADATA.DETAILED_GARMENT,
    created_at: new Date('2024-01-16T12:00:00Z'),
    updated_at: new Date('2024-01-16T14:30:00Z'),
    data_version: 2
  } as Garment,

  OTHER_USER_GARMENT: {
    id: MOCK_GARMENT_IDS.OTHER_USER_GARMENT,
    user_id: MOCK_USER_IDS.VALID_USER_2,
    original_image_id: MOCK_IMAGE_IDS.OTHER_USER_IMAGE,
    file_path: '/garments/other-user-garment.jpg',
    mask_path: '/garments/other-user-mask.png',
    metadata: { category: 'pants', color: 'black' },
    created_at: new Date('2024-01-17T12:00:00Z'),
    updated_at: new Date('2024-01-17T12:00:00Z'),
    data_version: 1
  } as Garment
} as const;

// Create Garment Input Mocks
export const MOCK_CREATE_INPUTS = {
  VALID_BASIC: {
    user_id: MOCK_USER_IDS.VALID_USER_1,
    original_image_id: MOCK_IMAGE_IDS.VALID_NEW_IMAGE,
    file_path: '/garments/new-garment.jpg',
    mask_path: '/garments/new-mask.png',
    metadata: MOCK_METADATA.BASIC_GARMENT
  } as CreateGarmentInput,

  VALID_MINIMAL: {
    user_id: MOCK_USER_IDS.VALID_USER_1,
    original_image_id: MOCK_IMAGE_IDS.VALID_NEW_IMAGE,
    file_path: '/garments/minimal-garment.jpg',
    mask_path: '/garments/minimal-mask.png'
  } as CreateGarmentInput,

  VALID_DETAILED: {
    user_id: MOCK_USER_IDS.VALID_USER_1,
    original_image_id: MOCK_IMAGE_IDS.VALID_NEW_IMAGE,
    file_path: '/garments/detailed-garment.jpg',
    mask_path: '/garments/detailed-mask.png',
    metadata: MOCK_METADATA.DETAILED_GARMENT
  } as CreateGarmentInput,

  INVALID_USER: {
    user_id: 'invalid-uuid',
    original_image_id: MOCK_IMAGE_IDS.VALID_NEW_IMAGE,
    file_path: '/garments/test.jpg',
    mask_path: '/garments/test.png'
  } as CreateGarmentInput,

  INVALID_IMAGE: {
    user_id: MOCK_USER_IDS.VALID_USER_1,
    original_image_id: 'invalid-uuid',
    file_path: '/garments/test.jpg',
    mask_path: '/garments/test.png'
  } as CreateGarmentInput
} as const;

// Test Scenarios
export const TEST_SCENARIOS = {
  CREATE_GARMENT: {
    SUCCESS_BASIC: {
      input: MOCK_CREATE_INPUTS.VALID_BASIC,
      expectedResult: 'success'
    },
    SUCCESS_MINIMAL: {
      input: MOCK_CREATE_INPUTS.VALID_MINIMAL,
      expectedResult: 'success'
    },
    FAIL_INVALID_UUID: {
      input: { ...MOCK_CREATE_INPUTS.VALID_BASIC, user_id: 'invalid' },
      expectedError: 'validation'
    },
    FAIL_MISSING_PATHS: {
      input: { ...MOCK_CREATE_INPUTS.VALID_BASIC, file_path: '' },
      expectedError: 'validation'
    }
  },
  
  FIND_OPERATIONS: {
    FIND_BY_ID_SUCCESS: {
      garmentId: MOCK_GARMENT_IDS.VALID_GARMENT_1,
      expectedResult: MOCK_GARMENTS.BASIC_SHIRT
    },
    FIND_BY_ID_NOT_FOUND: {
      garmentId: MOCK_GARMENT_IDS.NONEXISTENT_GARMENT,
      expectedResult: null
    },
    FIND_BY_ID_INVALID_UUID: {
      garmentId: 'invalid-uuid',
      expectedResult: null
    }
  },

  UPDATE_METADATA: {
    SUCCESS_BASIC: {
      garmentId: MOCK_GARMENT_IDS.VALID_GARMENT_1,
      metadata: { color: 'green', size: 'L' },
      expectedResult: 'success'
    },
    SUCCESS_REPLACE: {
      garmentId: MOCK_GARMENT_IDS.VALID_GARMENT_1,
      metadata: { category: 'jacket' },
      options: { replace: true },
      expectedResult: 'success'
    },
    FAIL_INVALID_METADATA: {
      garmentId: MOCK_GARMENT_IDS.VALID_GARMENT_1,
      metadata: null,
      expectedError: 'validation'
    }
  }
} as const;

// Database Mock Responses
export const MOCK_DB_RESPONSES = {
  CREATE_SUCCESS: {
    rows: [MOCK_GARMENTS.BASIC_SHIRT],
    rowCount: 1
  },
  FIND_SUCCESS: {
    rows: [MOCK_GARMENTS.BASIC_SHIRT],
    rowCount: 1
  },
  FIND_EMPTY: {
    rows: [],
    rowCount: 0
  },
  UPDATE_SUCCESS: {
    rows: [{ ...MOCK_GARMENTS.BASIC_SHIRT, data_version: 2 }],
    rowCount: 1
  },
  DELETE_SUCCESS: {
    rows: [],
    rowCount: 1
  },
  DELETE_NOT_FOUND: {
    rows: [],
    rowCount: 0
  }
} as const;

// Helper function to generate dynamic mock data
export const createMockGarment = (overrides: Partial<Garment> = {}): Garment => ({
  id: uuidv4(),
  user_id: MOCK_USER_IDS.VALID_USER_1,
  original_image_id: MOCK_IMAGE_IDS.VALID_NEW_IMAGE,
  file_path: `/garments/${uuidv4()}.jpg`,
  mask_path: `/garments/${uuidv4()}.png`,
  metadata: {},
  created_at: new Date(),
  updated_at: new Date(),
  data_version: 1,
  ...overrides
});

export const createMockCreateInput = (overrides: Partial<CreateGarmentInput> = {}): CreateGarmentInput => ({
  user_id: MOCK_USER_IDS.VALID_USER_1,
  original_image_id: MOCK_IMAGE_IDS.VALID_NEW_IMAGE,
  file_path: `/garments/${uuidv4()}.jpg`,
  mask_path: `/garments/${uuidv4()}.png`,
  metadata: {},
  ...overrides
});

// Batch test data generators
export const createMockGarmentList = (count: number, userId?: string): Garment[] => {
  return Array.from({ length: count }, (_, index) => 
    createMockGarment({
      user_id: userId || MOCK_USER_IDS.VALID_USER_1,
      metadata: {
        category: ['shirt', 'pants', 'dress', 'jacket'][index % 4],
        color: ['red', 'blue', 'green', 'black'][index % 4],
        size: ['S', 'M', 'L', 'XL'][index % 4]
      }
    })
  );
};

export const createMockMaskData = (width: number, height: number, fillPattern?: 'empty' | 'full' | 'checkered' | 'random') => {
  const size = width * height;
  const data = new Array(size);
  
  switch (fillPattern) {
    case 'empty':
      data.fill(0);
      break;
    case 'full':
      data.fill(255);
      break;
    case 'checkered':
      for (let i = 0; i < size; i++) {
        data[i] = (Math.floor(i / width) + (i % width)) % 2 === 0 ? 255 : 0;
      }
      break;
    case 'random':
    default:
      for (let i = 0; i < size; i++) {
        data[i] = Math.random() > 0.5 ? 255 : 0;
      }
      break;
  }
  
  return { width, height, data };
};