// filepath: c:\Users\monmo\koutu\backend\src\tests\__helpers__\garmentModel.helper.ts
/**
 * @file garmentModel.helper.ts
 * @summary Helper functions for testing garmentModel.ts.
 * This includes functions to generate mock data for garments.
 */

import { v4 as uuidv4 } from 'uuid';
import { Garment, CreateGarmentInput } from '../../models/garmentModel';

/**
 * Generates a mock Garment object.
 * @param overrides - Optional partial Garment object to override default values.
 * @returns A mock Garment object.
 */
export const createMockGarment = (overrides: Partial<Garment> = {}): Garment => {
  const now = new Date();
  return {
    id: uuidv4(),
    user_id: uuidv4(),
    original_image_id: uuidv4(),
    file_path: `/path/to/image-${uuidv4()}.jpg`,
    mask_path: `/path/to/mask-${uuidv4()}.png`,
    metadata: { color: 'blue', type: 'shirt' },
    created_at: now,
    updated_at: now,
    data_version: 1,
    ...overrides,
  };
};

/**
 * Generates mock input data for creating a Garment.
 * @param overrides - Optional partial CreateGarmentInput object to override default values.
 * @returns Mock CreateGarmentInput data.
 */
export const createMockCreateGarmentInput = (overrides: Partial<CreateGarmentInput> = {}): CreateGarmentInput => {
  return {
    user_id: uuidv4(),
    original_image_id: uuidv4(),
    file_path: `/path/to/new-image-${uuidv4()}.jpg`,
    mask_path: `/path/to/new-mask-${uuidv4()}.png`,
    metadata: { initial_prop: 'value' },
    ...overrides,
  };
};

/**
 * Generates mock input data for updating Garment metadata.
 * @param overrides - Optional partial metadata object to override default values.
 * @returns Mock metadata for updating a Garment.
 */
export const createMockUpdateGarmentMetadataInput = (metadataOverrides: Record<string, any> = {}) => {
  return {
    metadata: {
      updated_prop: 'new_value',
      ...metadataOverrides,
    },
  };
};