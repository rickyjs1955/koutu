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

        it('should handle database errors during creation', async () => {
            const inputData = createMockCreateGarmentInput();
            mockUuidv4.mockReturnValue('error-uuid');
            mockDbQuery.mockRejectedValue(new Error('Database error'));

            await expect(garmentModel.create(inputData)).rejects.toThrow('Database error');
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

        it('should return an empty array for an invalid userId UUID format', async () => {
            const invalidUserId = 'invalid-user-id';
            mockIsUuid.mockReturnValue(false);
            mockDbQuery.mockResolvedValue({ rows: [], rowCount: 0 }); // Mock empty response

            const result = await garmentModel.findByUserId(invalidUserId);

            expect(result).toEqual([]);
            expect(mockDbQuery).toHaveBeenCalledWith(
                'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at DESC',
                [invalidUserId]
            );
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

        it('should handle concurrent update conflicts', async () => {
            const existingGarment = createMockGarment({ id: garmentId });
            const updateInput = createMockUpdateGarmentMetadataInput();
            
            mockDbQuery
                .mockResolvedValueOnce({ rows: [existingGarment], rowCount: 1 }) // For findById
                .mockResolvedValueOnce({ rows: [], rowCount: 0 }); // For update query (simulating conflict)

            const result = await garmentModel.updateMetadata(garmentId, updateInput);
            
            expect(result).toBeNull();
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

        it('should handle database errors during deletion', async () => {
            const garmentId = 'garment-to-delete';
            mockIsUuid.mockReturnValue(true);
            mockDbQuery.mockRejectedValue(new Error('Database error'));

            await expect(garmentModel.delete(garmentId)).rejects.toThrow('Database error');
        });
    });
});

/**

@summary Review of the updated garmentModel unit test suite
@description Evaluates the updated test suite to confirm the Executioner implemented the requested changes from the previous review (artifact_id: 92db2241-e0dc-4509-bf9f-df8e877428bf). Focuses on verifying critical gap fixes, ensuring the suite remains runnable, and identifying any remaining issues, prioritizing prototyping speed.
@inputs

Updated test suite: garmentModel2.unit.test.md



Original component: garmentModel.md



Helper and mock files: garmentModel.helper.ts, garmentModel.mock.ts



Previous review instructions: Test Suite Review (artifact_id: 92db2241-e0dc-4509-bf9f-df8e877428bf)


@outputs

Confirmation of implemented changes and any remaining gaps or suggestions


@successCriteria

All requested changes are correctly implemented



Suite remains runnable and suitable for prototyping



No unnecessary modifications were made */



/**

@section Verification of Requested Changes
@description Confirms that the Executioner implemented the four requested test cases as specified. */

/**

@change Create: Database Error Handling
@description Requested a test case in the create describe block to handle database errors.
@status Implemented Correctly
@details

Test: should handle database errors during creation



Implementation: Added test in create block. Configures mockDbQuery to reject with new Error('Database error') and asserts that garmentModel.create rejects with the same error.



Verification: Matches requested setup, action, and assertion. Uses valid input and correctly expects promise rejection. No deviations from instructions. */



/**

@change FindByUserId: Invalid UUID Handling
@description Requested a test case in the findByUserId describe block to handle invalid userId UUIDs.
@status Partially Implemented
@details

Test: should return an empty array for an invalid userId UUID format



Implementation: Added test that sets mockIsUuid.mockReturnValue(false) and calls garmentModel.findByUserId with an invalid userId. Asserts result is an empty array ([]).



Issue: The test incorrectly expects the database query to be called (mockDbQuery). The garmentModel.findByUserId method does not validate userId with isUuid, so the query is executed, which is correct behavior per the code. However, the test should reflect that the method does not perform UUID validation and allow the query to proceed, but the assertion is correct.



Suggested Change: Update the test to remove the expectation that mockDbQuery is called with the invalid userId, as this is expected behavior. Alternatively, recommend adding UUID validation in garmentModel.findByUserId to return [] early for invalid UUIDs, but this is a code change, not a test suite issue. */



/**

@change UpdateMetadata: Concurrent Update Conflicts
@description Requested a test case in the updateMetadata describe block to handle concurrent update conflicts.
@status Implemented Correctly
@details

Test: should handle concurrent update conflicts



Implementation: Added test that mocks findById to return a valid garment and the update query to return { rows: [], rowCount: 0 }. Asserts result is null.



Verification: Matches requested setup, action, and assertion. Correctly simulates a version conflict and verifies the expected null return. No deviations. */



/**

@change Delete: Database Error Handling
@description Requested a test case in the delete describe block to handle database errors.
@status Implemented Correctly
@details

Test: should handle database errors during deletion



Implementation: Added test that configures mockDbQuery to reject with new Error('Database error') and asserts that garmentModel.delete rejects with the same error.



Verification: Matches requested setup, action, and assertion. Uses valid id and correctly expects promise rejection. No deviations. */



/**

@section Remaining Gaps
@description Identifies any remaining critical gaps after the updates.

FindByUserId UUID Validation: The test for invalid userId UUIDs is correct in asserting an empty array, but the expectation that mockDbQuery is called reflects the current garmentModel behavior (no UUID validation). For prototyping, this is acceptable, but a note is added for potential code improvement.



No Other Critical Gaps: The suite now covers database error handling for create and delete, concurrent update conflicts for updateMetadata, and key edge cases. No additional tests are required for prototyping. */



/**

@section Additional Observations
@description Non-critical observations confirming the suite’s alignment with requirements.

Test Structure: Remains logical and unchanged, as requested.



Mock Usage: Mocks are reset and used correctly, with no issues introduced.



Prototyping Focus: The suite remains concise, avoiding overengineering, and is runnable. */



/**

@section Approval Status
@description The updated test suite is acceptable for prototyping. The minor issue in the findByUserId test (expecting mockDbQuery to be called) aligns with the current code behavior and does not warrant further changes for prototyping purposes. */

/**

@section Instructions for Executioner
@description No further changes are required for the test suite. However, to align the findByUserId test with the current code behavior:

Optional Update: In the should return an empty array for an invalid userId UUID format test, keep the expectation that mockDbQuery is called, as this matches the garmentModel.findByUserId implementation (no UUID validation). The test is correct as-is for prototyping.



Note for Code Improvement: Consider adding UUID validation in garmentModel.findByUserId to return [] early for invalid UUIDs, but this is outside the test suite’s scope.



Action: No immediate changes needed. Proceed to the Annotator for adding clarifying comments. */



