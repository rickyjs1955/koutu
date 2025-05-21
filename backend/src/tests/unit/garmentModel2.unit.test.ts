/**
 * @file garmentModel.unit.test.ts
 * @summary Unit tests for the garmentModel.
 */

import { garmentModel } from '../../models/garmentModel';
import { 
  createMockGarment, 
  createMockCreateGarmentInput, 
  createMockUpdateGarmentMetadataInput 
} from '../__helpers__/garmentModel.helper';
import { 
  mockDbQuery, 
  mockGetQueryFunction, // Keep these imports for controlling mocks in tests
  mockUuidv4, 
  mockIsUuid 
} from '../__mocks__/garmentModel.mock';
import { expect } from '@jest/globals';

// Mock dependencies
jest.mock('../../utils/modelUtils', () => {
  // Use require inside the factory to ensure mocks are loaded at the right time
  const { mockGetQueryFunction: modelUtilsMock } = require('../__mocks__/garmentModel.mock');
  return { getQueryFunction: modelUtilsMock };
});

jest.mock('uuid', () => {
  // Use require inside the factory
  const { mockUuidv4: uuidv4Mock, mockIsUuid: isUuidMock } = require('../__mocks__/garmentModel.mock');
  return { v4: uuidv4Mock, validate: isUuidMock };
});

describe('garmentModel', () => {
    beforeEach(() => {
        // Reset mocks before each test using the imported versions
        mockDbQuery.mockReset();
        mockGetQueryFunction.mockClear();
        mockUuidv4.mockClear();
        mockIsUuid.mockClear();

        // Default mock implementations using the imported versions
        mockIsUuid.mockReturnValue(true); // Assume valid UUID by default
    });

    describe('create', () => {
        it('should create a new garment and return it', async () => {
        const inputData = createMockCreateGarmentInput();
        const mockGarment = createMockGarment({ ...inputData, id: 'fixed-uuid-create' });
        mockUuidv4.mockReturnValue('fixed-uuid-create');
        mockDbQuery.mockResolvedValue({ rows: [mockGarment], rowCount: 1 });

        const result = await garmentModel.create(inputData);

        expect(mockGetQueryFunction).toHaveBeenCalledTimes(1);
        expect(mockDbQuery).toHaveBeenCalledWith(
            expect.stringContaining('INSERT INTO garment_items'),
            ['fixed-uuid-create', inputData.user_id, inputData.original_image_id, inputData.file_path, inputData.mask_path, JSON.stringify(inputData.metadata)]
        );
        expect(result).toEqual(mockGarment);
        });

        it('should create a new garment with default empty metadata if not provided', async () => {
        const { metadata, ...restInput } = createMockCreateGarmentInput();
        const mockGarment = createMockGarment({ ...restInput, id: 'fixed-uuid-default-meta', metadata: {} });
        mockUuidv4.mockReturnValue('fixed-uuid-default-meta');
        mockDbQuery.mockResolvedValue({ rows: [mockGarment], rowCount: 1 });

        const result = await garmentModel.create(restInput);
        
        expect(mockDbQuery).toHaveBeenCalledWith(
            expect.stringContaining('INSERT INTO garment_items'),
            ['fixed-uuid-default-meta', restInput.user_id, restInput.original_image_id, restInput.file_path, restInput.mask_path, JSON.stringify({})]
        );
        expect(result.metadata).toEqual({});
        });
    });

    describe('findById', () => {
        it('should return a garment if found', async () => {
        const mockGarment = createMockGarment();
        mockDbQuery.mockResolvedValue({ rows: [mockGarment], rowCount: 1 });
        mockIsUuid.mockReturnValue(true);

        const result = await garmentModel.findById(mockGarment.id);

        expect(mockIsUuid).toHaveBeenCalledWith(mockGarment.id);
        expect(mockGetQueryFunction).toHaveBeenCalledTimes(1);
        expect(mockDbQuery).toHaveBeenCalledWith('SELECT * FROM garment_items WHERE id = $1', [mockGarment.id]);
        expect(result).toEqual(mockGarment);
        });

        it('should return null if garment not found', async () => {
        mockDbQuery.mockResolvedValue({ rows: [], rowCount: 0 });
        mockIsUuid.mockReturnValue(true);
        const testId = 'non-existent-uuid';

        const result = await garmentModel.findById(testId);

        expect(mockIsUuid).toHaveBeenCalledWith(testId);
        expect(result).toBeNull();
        });

        it('should return null for an invalid UUID format', async () => {
        const invalidId = 'invalid-uuid-string';
        mockIsUuid.mockReturnValue(false);

        const result = await garmentModel.findById(invalidId);

        expect(mockIsUuid).toHaveBeenCalledWith(invalidId);
        expect(result).toBeNull();
        expect(mockDbQuery).not.toHaveBeenCalled();
        });
    });

    describe('findByUserId', () => {
        it('should return garments for a user', async () => {
        const userId = 'user-123';
        const mockGarments = [createMockGarment({ user_id: userId }), createMockGarment({ user_id: userId })];
        mockDbQuery.mockResolvedValue({ rows: mockGarments, rowCount: mockGarments.length });

        const result = await garmentModel.findByUserId(userId);

        expect(mockGetQueryFunction).toHaveBeenCalledTimes(1);
        expect(mockDbQuery).toHaveBeenCalledWith('SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at DESC', [userId]);
        expect(result).toEqual(mockGarments);
        });

        it('should return an empty array if no garments found for a user', async () => {
        const userId = 'user-without-garments';
        mockDbQuery.mockResolvedValue({ rows: [], rowCount: 0 });

        const result = await garmentModel.findByUserId(userId);

        expect(result).toEqual([]);
        });
    });

    describe('updateMetadata', () => {
        const garmentId = 'garment-to-update';
        const baseExistingGarment = createMockGarment({ 
            id: garmentId, 
            metadata: { old_key: 'old_value', common_key: 'common' }, 
            data_version: 1 
        });

        const UPDATE_GARMENT_SQL = `UPDATE garment_items 
      SET metadata = $1, updated_at = NOW(), data_version = data_version + 1 
      WHERE id = $2 
      RETURNING *`;

        beforeEach(() => {
            mockDbQuery.mockReset();
            mockIsUuid.mockReturnValue(true);
        });

        it('should update metadata by merging and return the updated garment', async () => {
            // ARRANGE
            const existingGarment = { 
                ...baseExistingGarment, 
                metadata: { ...baseExistingGarment.metadata } 
            };
            const updateInput = createMockUpdateGarmentMetadataInput({ 
                new_key: 'new_value', 
                common_key: 'merged_common' 
            });
            
            const expectedFinalMetadata = { ...existingGarment.metadata, ...updateInput.metadata };
            const garmentExpectedFromDb = { 
                ...existingGarment, 
                metadata: expectedFinalMetadata, 
                data_version: existingGarment.data_version + 1,
                updated_at: new Date() // This will be part of the mocked DB response
            };

            mockDbQuery
                .mockResolvedValueOnce({ rows: [existingGarment], rowCount: 1 }) // For findById
                .mockResolvedValueOnce({ rows: [garmentExpectedFromDb], rowCount: 1 }); // For the update query

            // ACT
            const result = await garmentModel.updateMetadata(garmentId, updateInput, { replace: false });

            // ASSERT
            expect(mockIsUuid).toHaveBeenCalledWith(garmentId);
            expect(mockDbQuery).toHaveBeenCalledTimes(2);
            expect(mockDbQuery).toHaveBeenNthCalledWith(1, 
                'SELECT * FROM garment_items WHERE id = $1', 
                [garmentId]
            );
            expect(mockDbQuery).toHaveBeenNthCalledWith(2,
                UPDATE_GARMENT_SQL,
                [JSON.stringify(expectedFinalMetadata), garmentId]
            );
            expect(result).toEqual(garmentExpectedFromDb);
            expect(result?.data_version).toBe(existingGarment.data_version + 1);
        });

        it('should update metadata by replacing and return the updated garment', async () => {
            // ARRANGE
            const existingGarment = { 
                ...baseExistingGarment, 
                metadata: { ...baseExistingGarment.metadata } 
            };
            const updateInput = createMockUpdateGarmentMetadataInput({ 
                brand_new_key: 'brand_new_value', 
                common_key: 'replaced_common' 
            });
            
            const expectedFinalMetadata = { ...updateInput.metadata }; // Replacement
            const garmentExpectedFromDb = { 
                ...existingGarment, 
                metadata: expectedFinalMetadata, 
                data_version: existingGarment.data_version + 1,
                updated_at: new Date() // This will be part of the mocked DB response
            };
            
            mockDbQuery
                .mockResolvedValueOnce({ rows: [existingGarment], rowCount: 1 }) // For findById
                .mockResolvedValueOnce({ rows: [garmentExpectedFromDb], rowCount: 1 }); // For the update query

            // ACT
            const result = await garmentModel.updateMetadata(garmentId, updateInput, { replace: true });

            // ASSERT
            expect(mockIsUuid).toHaveBeenCalledWith(garmentId);
            expect(mockDbQuery).toHaveBeenCalledTimes(2);
            expect(mockDbQuery).toHaveBeenNthCalledWith(1, 
                'SELECT * FROM garment_items WHERE id = $1', 
                [garmentId]
            );
            expect(mockDbQuery).toHaveBeenNthCalledWith(2,
                UPDATE_GARMENT_SQL,
                [JSON.stringify(expectedFinalMetadata), garmentId]
            );
            expect(result).toEqual(garmentExpectedFromDb);
            expect(result?.data_version).toBe(existingGarment.data_version + 1);
        });

        it('should return null if garment to update is not found', async () => {
        const updateInput = createMockUpdateGarmentMetadataInput();
        mockIsUuid.mockReturnValue(true);
        mockDbQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 }); // findById returns null

        const result = await garmentModel.updateMetadata('non-existent-id', updateInput);

        expect(result).toBeNull();
        // Ensure the update query was not called
        expect(mockDbQuery).toHaveBeenCalledTimes(1); // Only for findById
        });
        
        it('should return null for an invalid UUID format', async () => {
        const invalidId = 'invalid-uuid-string';
        mockIsUuid.mockReturnValue(false);
        const updateInput = createMockUpdateGarmentMetadataInput();

        const result = await garmentModel.updateMetadata(invalidId, updateInput);

        expect(mockIsUuid).toHaveBeenCalledWith(invalidId);
        expect(result).toBeNull();
        expect(mockDbQuery).not.toHaveBeenCalled();
        });

        it('should return null if metadata format is invalid (e.g., null, array)', async () => {
        mockIsUuid.mockReturnValue(true);
        let result = await garmentModel.updateMetadata(garmentId, { metadata: null as any });
        expect(result).toBeNull();

        result = await garmentModel.updateMetadata(garmentId, { metadata: [] as any });
        expect(result).toBeNull();
        
        result = await garmentModel.updateMetadata(garmentId, { metadata: "string" as any });
        expect(result).toBeNull();

        expect(mockDbQuery).not.toHaveBeenCalled(); // Should not proceed to DB calls
        });
    });

    describe('delete', () => {
        it('should return true if garment is deleted successfully', async () => {
        const garmentId = 'garment-to-delete';
        mockIsUuid.mockReturnValue(true);
        mockDbQuery.mockResolvedValue({ rows: [], rowCount: 1 }); // rowCount indicates success for DELETE

        const result = await garmentModel.delete(garmentId);

        expect(mockIsUuid).toHaveBeenCalledWith(garmentId);
        expect(mockGetQueryFunction).toHaveBeenCalledTimes(1);
        expect(mockDbQuery).toHaveBeenCalledWith('DELETE FROM garment_items WHERE id = $1', [garmentId]);
        expect(result).toBe(true);
        });

        it('should return false if garment to delete is not found', async () => {
        const garmentId = 'non-existent-garment';
        mockIsUuid.mockReturnValue(true);
        mockDbQuery.mockResolvedValue({ rows: [], rowCount: 0 });

        const result = await garmentModel.delete(garmentId);

        expect(result).toBe(false);
        });
        
        it('should return false for an invalid UUID format', async () => {
        const invalidId = 'invalid-uuid-string';
        mockIsUuid.mockReturnValue(false);

        const result = await garmentModel.delete(invalidId);

        expect(mockIsUuid).toHaveBeenCalledWith(invalidId);
        expect(result).toBe(false);
        expect(mockDbQuery).not.toHaveBeenCalled();
        });
    });
});