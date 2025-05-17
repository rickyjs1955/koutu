// filepath: /backend/src/tests/unit/garmentController.unit.test.ts

jest.mock('../../models/db', () => ({
  query: jest.fn()
}));

jest.mock('uuid', () => ({
  v4: jest.fn()
}));

import { garmentModel, CreateGarmentInput, UpdateGarmentMetadataInput, Garment } from '../../models/garmentModel';
import { query } from '../../models/db';
import { v4 as uuidv4 } from 'uuid';

const mockQuery = query as jest.Mock;
const mockUuidv4 = uuidv4 as jest.Mock;

describe('garmentModel', () => {
    beforeEach(() => {
        mockQuery.mockReset();
        mockUuidv4.mockReset();
    });

    const mockTimestamp = new Date();
    const mockGarment: Garment = {
        id: 'test-garment-id',
        user_id: 'test-user-id',
        original_image_id: 'test-image-id',
        file_path: 'path/to/garment.jpg',
        mask_path: 'path/to/mask.png',
        metadata: { type: 'shirt', color: 'blue' },
        created_at: mockTimestamp,
        updated_at: mockTimestamp,
        data_version: 1,
    };

    describe('create', () => {
        it('should create a new garment and return it', async () => {
        const input: CreateGarmentInput = {
            user_id: 'test-user-id',
            original_image_id: 'test-image-id',
            file_path: 'path/to/garment.jpg',
            mask_path: 'path/to/mask.png',
            metadata: { type: 'shirt', color: 'blue' },
        };
        const newId = 'new-uuid-generated';
        mockUuidv4.mockReturnValue(newId);
        const expectedGarment = { ...mockGarment, id: newId, ...input };
        mockQuery.mockResolvedValue({ rows: [expectedGarment] });

        const result = await garmentModel.create(input);

        expect(mockUuidv4).toHaveBeenCalledTimes(1);
        expect(mockQuery).toHaveBeenCalledWith(
            expect.stringContaining('INSERT INTO garment_items'),
            [
            newId,
            input.user_id,
            input.original_image_id,
            input.file_path,
            input.mask_path,
            JSON.stringify(input.metadata),
            ]
        );
        expect(result).toEqual(expectedGarment);
        });

        it('should create a new garment with default empty metadata if not provided', async () => {
        const input: CreateGarmentInput = {
            user_id: 'test-user-id',
            original_image_id: 'test-image-id',
            file_path: 'path/to/garment.jpg',
            mask_path: 'path/to/mask.png',
        };
        const newId = 'new-uuid-generated-2';
        mockUuidv4.mockReturnValue(newId);
        const expectedGarment = { ...mockGarment, id: newId, ...input, metadata: {} };
        mockQuery.mockResolvedValue({ rows: [expectedGarment] });

        const result = await garmentModel.create(input);

        expect(mockQuery).toHaveBeenCalledWith(
            expect.stringContaining('INSERT INTO garment_items'),
            [
            newId,
            input.user_id,
            input.original_image_id,
            input.file_path,
            input.mask_path,
            JSON.stringify({}),
            ]
        );
        expect(result).toEqual(expectedGarment);
        });

        it('should propagate database errors when creating a garment', async () => {
            mockUuidv4.mockReturnValue('new-id');
            mockQuery.mockRejectedValue(new Error('DB error'));
            await expect(
                garmentModel.create({
                user_id: 'u',
                original_image_id: 'img',
                file_path: 'f',
                mask_path: 'm',
                metadata: { foo: 'bar' }
                })
            ).rejects.toThrow('DB error');
        });

        it('should handle complex nested metadata structures', async () => {
            const complexMetadata = {
            attributes: {
                colors: ['red', 'blue'],
                sizes: { us: 'M', eu: '38' }
            },
            tags: ['casual', 'summer'],
            materials: { primary: 'cotton', secondary: 'polyester' }
            };
            
            const input = {
            user_id: 'test-user-id',
            original_image_id: 'test-image-id',
            file_path: 'path/to/file',
            mask_path: 'path/to/mask',
            metadata: complexMetadata
            };
            
            mockUuidv4.mockReturnValue('complex-id');
            mockQuery.mockResolvedValue({ rows: [{ ...mockGarment, id: 'complex-id', metadata: complexMetadata }] });
            
            const result = await garmentModel.create(input);
            
            expect(mockQuery).toHaveBeenCalledWith(
            expect.stringContaining('INSERT INTO'),
            expect.arrayContaining([JSON.stringify(complexMetadata)])
            );
            expect(result.metadata).toEqual(complexMetadata);
        });
    });

    describe('findById', () => {
        it('should return a garment if found', async () => {
        mockQuery.mockResolvedValue({ rows: [mockGarment] });
        const result = await garmentModel.findById(mockGarment.id);

        expect(mockQuery).toHaveBeenCalledWith(
            'SELECT * FROM garment_items WHERE id = $1',
            [mockGarment.id]
        );
        expect(result).toEqual(mockGarment);
        });

        it('should return null if garment not found', async () => {
        mockQuery.mockResolvedValue({ rows: [] });
        const result = await garmentModel.findById('non-existent-id');

        expect(mockQuery).toHaveBeenCalledWith(
            'SELECT * FROM garment_items WHERE id = $1',
            ['non-existent-id']
        );
        expect(result).toBeNull();
        });

        it('should propagate database errors when retrieving a garment by ID', async () => {
            mockQuery.mockRejectedValue(new Error('DB error'));
            await expect(garmentModel.findById('some-id')).rejects.toThrow('DB error');
        });
    });

    describe('findByUserId', () => {
        it('should return an array of garments for a user', async () => {
        const garments = [mockGarment, { ...mockGarment, id: 'garment-2' }];
        mockQuery.mockResolvedValue({ rows: garments });
        const result = await garmentModel.findByUserId(mockGarment.user_id);

        expect(mockQuery).toHaveBeenCalledWith(
            'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at DESC',
            [mockGarment.user_id]
        );
        expect(result).toEqual(garments);
        });

        it('should return an empty array if no garments found for a user', async () => {
        mockQuery.mockResolvedValue({ rows: [] });
        const result = await garmentModel.findByUserId('user-with-no-garments');

        expect(mockQuery).toHaveBeenCalledWith(
            'SELECT * FROM garment_items WHERE user_id = $1 ORDER BY created_at DESC',
            ['user-with-no-garments']
        );
        expect(result).toEqual([]);
        });

        it('should propagate database errors when retrieving garments by user ID', async () => {
            mockQuery.mockRejectedValue(new Error('DB error'));
            await expect(garmentModel.findByUserId('user-id')).rejects.toThrow('DB error');
        });
    });

    describe('updateMetadata', () => {
        it('should update garment metadata and return the updated garment', async () => {
        const existingGarment = { ...mockGarment };
        const updates: UpdateGarmentMetadataInput = {
            metadata: { color: 'red', size: 'M' },
        };
        const expectedUpdatedMetadata = { ...existingGarment.metadata, ...updates.metadata };
        const updatedGarment = { ...existingGarment, metadata: expectedUpdatedMetadata, data_version: existingGarment.data_version + 1 };

        // Mock findById call
        mockQuery.mockResolvedValueOnce({ rows: [existingGarment] });
        // Mock update query call
        mockQuery.mockResolvedValueOnce({ rows: [updatedGarment] });

        const result = await garmentModel.updateMetadata(existingGarment.id, updates);

        expect(mockQuery.mock.calls[0]).toEqual([
            'SELECT * FROM garment_items WHERE id = $1',
            [existingGarment.id],
        ]);
        expect(mockQuery.mock.calls[1]).toEqual([
            expect.stringContaining('UPDATE garment_items'),
            [JSON.stringify(expectedUpdatedMetadata), existingGarment.id],
        ]);
        expect(result).toEqual(updatedGarment);
        });

        it('should return null if garment to update is not found', async () => {
        const updates: UpdateGarmentMetadataInput = {
            metadata: { color: 'red' },
        };
        mockQuery.mockResolvedValueOnce({ rows: [] }); // Mock findById returning null

        const result = await garmentModel.updateMetadata('non-existent-id', updates);

        expect(mockQuery).toHaveBeenCalledTimes(1); // Only findById should be called
        expect(mockQuery.mock.calls[0]).toEqual([
            'SELECT * FROM garment_items WHERE id = $1',
            ['non-existent-id'],
        ]);
        expect(result).toBeNull();
        });

        it('should overwrite existing metadata keys with new values in updateMetadata', async () => {
            const existingGarment = { ...mockGarment, metadata: { color: 'blue', size: 'L' } };
            const updates: UpdateGarmentMetadataInput = { metadata: { color: 'red' } };
            const expectedUpdatedMetadata = { color: 'red', size: 'L' };
            const updatedGarment = { ...existingGarment, metadata: expectedUpdatedMetadata, data_version: existingGarment.data_version + 1 };

            mockQuery.mockResolvedValueOnce({ rows: [existingGarment] }); // findById
            mockQuery.mockResolvedValueOnce({ rows: [updatedGarment] }); // update

            const result = await garmentModel.updateMetadata(existingGarment.id, updates);

            expect(result).toEqual(updatedGarment);
            expect(mockQuery.mock.calls[1][1][0]).toBe(JSON.stringify(expectedUpdatedMetadata));
        });

        it('should propagate database errors when updating garment metadata', async () => {
            // Simulate error on findById
            mockQuery.mockRejectedValue(new Error('DB error'));
            await expect(
                garmentModel.updateMetadata('some-id', { metadata: { foo: 'bar' } })
            ).rejects.toThrow('DB error');
        });

        it('should preserve existing metadata when updating with empty object', async () => {
            const existingGarment = { ...mockGarment, metadata: { color: 'blue', size: 'L' } };
            const updates = { metadata: {} };
            
            // The metadata should remain unchanged when merging with an empty object
            const expectedMetadata = { color: 'blue', size: 'L' };
            
            const updatedGarment = { 
                ...existingGarment, 
                metadata: expectedMetadata,
                data_version: existingGarment.data_version + 1 
            };
            
            mockQuery.mockResolvedValueOnce({ rows: [existingGarment] });
            mockQuery.mockResolvedValueOnce({ rows: [updatedGarment] });
            
            const result = await garmentModel.updateMetadata(existingGarment.id, updates);
            
            expect(result!.metadata).toEqual(expectedMetadata);
            expect(mockQuery.mock.calls[1][1][0]).toBe(JSON.stringify(expectedMetadata));
        });
        
        it('should handle deeply nested metadata updates correctly', async () => {
            const existingGarment = { 
            ...mockGarment, 
            metadata: { 
                attributes: { color: 'blue', size: 'L' },
                category: 'tops'
            } 
            };
            const updates = { 
            metadata: { 
                attributes: { color: 'red' },
                tags: ['casual']
            } 
            };
            const expectedMetadata = { 
            attributes: { color: 'red' },  // Overwrites the entire attributes object
            category: 'tops',              // Preserves this field
            tags: ['casual']               // Adds this new field
            };
            const updatedGarment = { 
            ...existingGarment, 
            metadata: expectedMetadata, 
            data_version: existingGarment.data_version + 1 
            };
            
            mockQuery.mockResolvedValueOnce({ rows: [existingGarment] });
            mockQuery.mockResolvedValueOnce({ rows: [updatedGarment] });
            
            const result = await garmentModel.updateMetadata(existingGarment.id, updates);
            
            expect(result!.metadata).toEqual(expectedMetadata);
            expect(JSON.parse(mockQuery.mock.calls[1][1][0])).toEqual(expectedMetadata);
        });
    });

    describe('delete', () => {
        it('should return true if a garment is deleted', async () => {
        mockQuery.mockResolvedValue({ rowCount: 1 });
        const result = await garmentModel.delete(mockGarment.id);

        expect(mockQuery).toHaveBeenCalledWith(
            'DELETE FROM garment_items WHERE id = $1',
            [mockGarment.id]
        );
        expect(result).toBe(true);
        });

        it('should return false if no garment is deleted', async () => {
        mockQuery.mockResolvedValue({ rowCount: 0 });
        const result = await garmentModel.delete('non-existent-id');

        expect(mockQuery).toHaveBeenCalledWith(
            'DELETE FROM garment_items WHERE id = $1',
            ['non-existent-id']
        );
        expect(result).toBe(false);
        });

        it('should handle null rowCount and return false', async () => {
        mockQuery.mockResolvedValue({ rowCount: null });
        const result = await garmentModel.delete('non-existent-id');
        expect(result).toBe(false);
        });

        it('should handle undefined rowCount and return false', async () => {
        mockQuery.mockResolvedValue({}); // rowCount is undefined
        const result = await garmentModel.delete('non-existent-id');
        expect(result).toBe(false);
        });

        it('should propagate database errors when deleting a garment', async () => {
            mockQuery.mockRejectedValue(new Error('DB error'));
            await expect(garmentModel.delete('some-id')).rejects.toThrow('DB error');
        });
    });
});