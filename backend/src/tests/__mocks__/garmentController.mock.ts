// koutu/backend/src/tests/__mocks__/garmentController.mock.ts

/**
 * @file garmentController.mock.ts
 * @summary Mocks for garment controller unit tests
 */

import { Request, Response, NextFunction } from 'express';
import { Garment } from '../../models/garmentModel';
import { Image } from '../../models/imageModel';

export const VALID_UUID = '123e4567-e89b-12d3-a456-426614174000';

// Mock request factory
export function createMockRequest(options: any = {}) {
  return {
    user: { id: 'test-user-id', email: 'test@example.com' },
    body: {},
    params: {},
    query: {},
    ...options
  };
}

export function createRequestWithParams(params: any) {
  return createMockRequest({ params });
}

// Mock response factory
export const createMockResponse = (): Response => {
  const res = {} as Response;
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  return res;
};

// Mock next function
export const createMockNext = (): NextFunction => jest.fn();

// Mock garment data
export const mockGarment: Garment = {
  id: 'garment-123',
  user_id: 'test-user-id',
  original_image_id: 'image-123',
  file_path: '/uploads/garment-123_masked.jpg',
  mask_path: '/uploads/garment-123_mask.png',
  metadata: {
    type: 'shirt',
    color: 'blue',
    pattern: 'solid',
    season: 'summer',
    brand: 'TestBrand',
    tags: ['casual', 'cotton']
  },
  created_at: new Date('2024-01-01'),
  updated_at: new Date('2024-01-01'),
  data_version: 1
};

// Mock image data
export const mockImage: Image = {
  id: 'image-123',
  user_id: 'test-user-id',
  file_path: '/uploads/original-123.jpg',
  original_metadata: {
    filename: 'test.jpg',
    mimetype: 'image/jpeg',
    size: 1024000,
    width: 800,
    height: 600,
    format: 'jpeg'
  },
  upload_date: new Date('2024-01-01'),
  status: 'new'
};

// Mock create garment input
export const mockCreateGarmentInput = {
  original_image_id: 'image-123',
  mask_data: {
    width: 800,
    height: 600,
    data: new Uint8ClampedArray(800 * 600)
  },
  metadata: {
    type: 'shirt',
    color: 'blue',
    pattern: 'solid',
    season: 'summer',
    brand: 'TestBrand',
    tags: ['casual', 'cotton']
  }
};

// Mock update metadata input
export const mockUpdateMetadataInput = {
  metadata: {
    type: 'jacket',
    color: 'black',
    pattern: 'plain',
    season: 'winter',
    brand: 'UpdatedBrand',
    tags: ['formal', 'wool']
  }
};

// Mock labeling service response
export const mockLabelingServiceResponse = {
  maskedImagePath: '/uploads/garment-123_masked.jpg',
  maskPath: '/uploads/garment-123_mask.png'
};

// Mock multiple garments for list operations
export const mockGarmentsList: Garment[] = [
  mockGarment,
  {
    ...mockGarment,
    id: 'garment-456',
    metadata: {
      type: 'pants',
      color: 'black',
      pattern: 'plain',
      season: 'all-season',
      brand: 'AnotherBrand',
      tags: ['formal', 'office']
    }
  },
  {
    ...mockGarment,
    id: 'garment-789',
    metadata: {
      type: 'dress',
      color: 'red',
      pattern: 'floral',
      season: 'spring',
      brand: 'DressBrand',
      tags: ['party', 'elegant']
    }
  }
];

// Mock invalid inputs
export const mockInvalidUUID = 'not-a-valid-uuid';
export const mockNonExistentId = '550e8400-e29b-41d4-a716-446655440000';

// Mock error scenarios
export const mockDatabaseError = new Error('Database connection failed');
export const mockServiceError = new Error('Labeling service error');

// Mock sanitized response
export const mockSanitizedGarment = {
  id: 'garment-123',
  original_image_id: 'image-123',
  file_path: '/api/garments/garment-123/image',
  mask_path: '/api/garments/garment-123/mask',
  metadata: {
    type: 'shirt',
    color: 'blue',
    pattern: 'solid',
    season: 'summer',
    brand: 'TestBrand',
    tags: ['casual', 'cotton']
  },
  created_at: new Date('2024-01-01'),
  updated_at: new Date('2024-01-01'),
  data_version: 1
};

// Mock filter and pagination
export const mockFilter = {
  type: 'shirt',
  season: 'summer'
};

export const mockPagination = {
  page: 1,
  limit: 20
};