// /backend/tests/unit/models/wardrobeModel.test.ts
import { wardrobeModel, CreateWardrobeInput, UpdateWardrobeInput } from '../../../src/models/wardrobeModel';
import { query } from '../../../src/models/db';
import { v4 as uuidv4, validate as isUuid } from 'uuid';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';

// Mock the database query function
jest.mock('../../../src/models/db');
const mockQuery = query as jest.MockedFunction<typeof query>;

describe('wardrobeModel', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    describe('successful creation', () => {
      it('should create a wardrobe with all fields', async () => {
        const inputData = wardrobeMocks.createValidInput();
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({
            user_id: inputData.user_id,
            name: inputData.name,
            description: inputData.description
        });

        mockQuery.mockResolvedValueOnce(
            wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        const result = await wardrobeModel.create(inputData);

        expect(result).toEqual(expectedWardrobe);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('INSERT INTO wardrobes');
        expect(queryText).toContain('RETURNING *');
        expect(queryParams).toHaveLength(5); // id, user_id, name, description, is_default
        
        // Verify UUID generation
        expect(isUuid(queryParams![0])).toBe(true);
        expect(queryParams![1]).toBe(inputData.user_id);
        expect(queryParams![2]).toBe(inputData.name);
        expect(queryParams![3]).toBe(inputData.description);
        expect(queryParams![4]).toBe(false); // is_default default value
      });

      it('should create a wardrobe with empty description when not provided', async () => {
        const inputData = wardrobeMocks.createValidInput();
        delete (inputData as any).description;
        
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({
          user_id: inputData.user_id,
          name: inputData.name,
          description: ''
        });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        const result = await wardrobeModel.create(inputData);

        expect(result).toEqual(expectedWardrobe);
        expect(mockQuery.mock.calls[0][1]![3]).toBe(''); // description should be empty string
      });

      it('should create a wardrobe with minimal valid data', async () => {
        const inputData = wardrobeMocks.edgeCases.minName;
        const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        const result = await wardrobeModel.create(inputData);

        expect(result).toEqual(expectedWardrobe);
        expect(result.name).toBe('A');
        expect(result.description).toBe('');
      });

      it('should create a wardrobe with maximum valid data', async () => {
        const inputData = wardrobeMocks.edgeCases.maxDescription;
        const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        const result = await wardrobeModel.create(inputData);

        expect(result).toEqual(expectedWardrobe);
        expect(result.name.length).toBe(inputData.name!.length);
        expect(result.description!.length).toBe(1000);
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        const inputData = wardrobeMocks.createValidInput();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.create(inputData)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      it('should throw error on foreign key constraint violation', async () => {
        const inputData = wardrobeMocks.createValidInput();
        const fkError = wardrobeMocks.errorScenarios.foreignKeyError;
        
        mockQuery.mockRejectedValueOnce(fkError);

        await expect(wardrobeModel.create(inputData)).rejects.toThrow(fkError);
      });

      it('should throw error on unique constraint violation', async () => {
        const inputData = wardrobeMocks.createValidInput();
        const uniqueError = wardrobeMocks.errorScenarios.uniqueConstraintError;
        
        mockQuery.mockRejectedValueOnce(uniqueError);

        await expect(wardrobeModel.create(inputData)).rejects.toThrow(uniqueError);
      });
    });

    describe('data validation at model level', () => {
      it('should handle special characters in allowed fields correctly', async () => {
        const inputData = wardrobeMocks.edgeCases.allowedSpecialChars;
        const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        const result = await wardrobeModel.create(inputData);

        expect(result.name).toBe(inputData.name);
        expect(result.name).toMatch(/^[a-zA-Z0-9\s\-_\.]+$/);
      });
    });
  });

  describe('findById', () => {
    describe('successful retrieval', () => {
      it('should return wardrobe when found', async () => {
        const wardrobeId = uuidv4();
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({ id: wardrobeId });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectSingle(expectedWardrobe)
        );

        const result = await wardrobeModel.findById(wardrobeId);

        expect(result).toEqual(expectedWardrobe);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('SELECT * FROM wardrobes WHERE id = $1');
        expect(queryParams).toEqual([wardrobeId]);
      });

      it('should return null when wardrobe not found', async () => {
        const wardrobeId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.notFound());

        const result = await wardrobeModel.findById(wardrobeId);

        expect(result).toBeNull();
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });
    });

    describe('input validation', () => {
      it('should return null for invalid UUID format', async () => {
        const invalidId = 'invalid-uuid';

        const result = await wardrobeModel.findById(invalidId);

        expect(result).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled(); // Should not query DB for invalid UUID
      });

      it('should return null for empty string ID', async () => {
        const emptyId = '';

        const result = await wardrobeModel.findById(emptyId);

        expect(result).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();
      });

      it('should handle null/undefined ID gracefully', async () => {
        expect(await wardrobeModel.findById(null as any)).toBeNull();
        expect(await wardrobeModel.findById(undefined as any)).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        const wardrobeId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.findById(wardrobeId)).rejects.toThrow(dbError);
      });
    });
  });

  describe('findByUserId', () => {
    describe('successful retrieval', () => {
      it('should return wardrobes ordered by name', async () => {
        const userId = uuidv4();
        const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, 3);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(wardrobes)
        );

        const result = await wardrobeModel.findByUserId(userId);

        expect(result).toEqual(wardrobes);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('SELECT * FROM wardrobes WHERE user_id = $1');
        expect(queryText).toContain('ORDER BY name');
        expect(queryParams).toEqual([userId]);
      });

      it('should return empty array when user has no wardrobes', async () => {
        const userId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.selectMultiple([]));

        const result = await wardrobeModel.findByUserId(userId);

        expect(result).toEqual([]);
        expect(Array.isArray(result)).toBe(true);
        expect(result.length).toBe(0);
      });

      it('should handle user with single wardrobe', async () => {
        const userId = uuidv4();
        const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, 1);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(wardrobes)
        );

        const result = await wardrobeModel.findByUserId(userId);

        expect(result).toEqual(wardrobes);
        expect(result.length).toBe(1);
      });

      it('should handle user with maximum wardrobes', async () => {
        const userId = uuidv4();
        const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, 50);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(wardrobes)
        );

        const result = await wardrobeModel.findByUserId(userId);

        expect(result).toEqual(wardrobes);
        expect(result.length).toBe(50);
      });
    });

    describe('input validation', () => {
      it('should handle invalid user ID format gracefully', async () => {
        const invalidUserId = 'invalid-uuid';
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.selectMultiple([]));

        const result = await wardrobeModel.findByUserId(invalidUserId);

        expect(result).toEqual([]);
        expect(mockQuery).toHaveBeenCalledTimes(1); // Still queries DB, returns empty
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        const userId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.findByUserId(userId)).rejects.toThrow(dbError);
      });
    });
  });

  describe('update', () => {
    describe('successful updates', () => {
      it('should update wardrobe name only', async () => {
        const wardrobeId = uuidv4();
        const updateData: UpdateWardrobeInput = { name: 'Updated Name' };
        const updatedWardrobe = wardrobeMocks.createValidWardrobe({
          id: wardrobeId,
          name: updateData.name,
          updated_at: new Date()
        });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.updateSuccess(updatedWardrobe)
        );

        const result = await wardrobeModel.update(wardrobeId, updateData);

        expect(result).toEqual(updatedWardrobe);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('UPDATE wardrobes SET updated_at = NOW()');
        expect(queryText).toContain('name = $1');
        expect(queryText).toContain('WHERE id = $2');
        expect(queryText).toContain('RETURNING *');
        expect(queryParams).toEqual(['Updated Name', wardrobeId]);
      });

      it('should update wardrobe description only', async () => {
        const wardrobeId = uuidv4();
        const updateData: UpdateWardrobeInput = { description: 'Updated Description' };
        const updatedWardrobe = wardrobeMocks.createValidWardrobe({
          id: wardrobeId,
          description: updateData.description,
          updated_at: new Date()
        });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.updateSuccess(updatedWardrobe)
        );

        const result = await wardrobeModel.update(wardrobeId, updateData);

        expect(result).toEqual(updatedWardrobe);
        expect(mockQuery.mock.calls[0][1]).toEqual(['Updated Description', wardrobeId]);
      });

      it('should update both name and description', async () => {
        const wardrobeId = uuidv4();
        const updateData: UpdateWardrobeInput = {
          name: 'Updated Name',
          description: 'Updated Description'
        };
        const updatedWardrobe = wardrobeMocks.createValidWardrobe({
          id: wardrobeId,
          ...updateData,
          updated_at: new Date()
        });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.updateSuccess(updatedWardrobe)
        );

        const result = await wardrobeModel.update(wardrobeId, updateData);

        expect(result).toEqual(updatedWardrobe);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('name = $1');
        expect(queryText).toContain('description = $2');
        expect(queryParams).toEqual(['Updated Name', 'Updated Description', wardrobeId]);
      });

      it('should handle empty update (only updated_at changes)', async () => {
        const wardrobeId = uuidv4();
        const updateData: UpdateWardrobeInput = {};
        const updatedWardrobe = wardrobeMocks.createValidWardrobe({
          id: wardrobeId,
          updated_at: new Date()
        });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.updateSuccess(updatedWardrobe)
        );

        const result = await wardrobeModel.update(wardrobeId, updateData);

        expect(result).toEqual(updatedWardrobe);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('UPDATE wardrobes SET updated_at = NOW()');
        expect(queryText).toContain('WHERE id = $1');
        expect(queryParams).toEqual([wardrobeId]);
      });

      it('should handle undefined values correctly', async () => {
        const wardrobeId = uuidv4();
        const updateData: UpdateWardrobeInput = {
          name: undefined,
          description: 'Only description updated'
        };
        const updatedWardrobe = wardrobeMocks.createValidWardrobe({
          id: wardrobeId,
          description: updateData.description
        });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.updateSuccess(updatedWardrobe)
        );

        const result = await wardrobeModel.update(wardrobeId, updateData);

        expect(result).toEqual(updatedWardrobe);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).not.toContain('name = ');
        expect(queryText).toContain('description = $1');
        expect(queryParams).toEqual(['Only description updated', wardrobeId]);
      });
    });

    describe('not found scenarios', () => {
      it('should return null when wardrobe not found', async () => {
        const wardrobeId = uuidv4();
        const updateData = wardrobeMocks.createValidUpdateInput();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.notFound());

        const result = await wardrobeModel.update(wardrobeId, updateData);

        expect(result).toBeNull();
      });
    });

    describe('input validation', () => {
      it('should return null for invalid UUID format', async () => {
        const invalidId = 'invalid-uuid';
        const updateData = wardrobeMocks.createValidUpdateInput();

        const result = await wardrobeModel.update(invalidId, updateData);

        expect(result).toBeNull();
        expect(mockQuery).toHaveBeenCalledTimes(0); // Should not query DB for invalid UUID
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        const wardrobeId = uuidv4();
        const updateData = wardrobeMocks.createValidUpdateInput();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.update(wardrobeId, updateData)).rejects.toThrow(dbError);
      });
    });
  });

  describe('delete', () => {
    describe('successful deletion', () => {
      it('should delete wardrobe and associated items, return true', async () => {
        const wardrobeId = uuidv4();
        
        // Mock both deletion queries
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // Delete wardrobe_items
          .mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess()); // Delete wardrobe

        const result = await wardrobeModel.delete(wardrobeId);

        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(2);
        
        // Verify wardrobe_items deletion
        const [deleteItemsQuery, deleteItemsParams] = mockQuery.mock.calls[0];
        expect(deleteItemsQuery).toContain('DELETE FROM wardrobe_items WHERE wardrobe_id = $1');
        expect(deleteItemsParams).toEqual([wardrobeId]);
        
        // Verify wardrobe deletion
        const [deleteWardrobeQuery, deleteWardrobeParams] = mockQuery.mock.calls[1];
        expect(deleteWardrobeQuery).toContain('DELETE FROM wardrobes WHERE id = $1');
        expect(deleteWardrobeParams).toEqual([wardrobeId]);
      });

      it('should delete wardrobe with no items, return true', async () => {
        const wardrobeId = uuidv4();
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // No items to delete
          .mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess()); // Delete wardrobe

        const result = await wardrobeModel.delete(wardrobeId);

        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });

    describe('not found scenarios', () => {
      it('should return false when wardrobe not found', async () => {
        const wardrobeId = uuidv4();
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // No items to delete
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')); // Wardrobe not found

        const result = await wardrobeModel.delete(wardrobeId);

        expect(result).toBe(false);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });

    describe('input validation', () => {
      it('should return false for invalid UUID format', async () => {
        const invalidId = 'invalid-uuid';

        const result = await wardrobeModel.delete(invalidId);

        expect(result).toBe(false);
        expect(mockQuery).toHaveBeenCalledTimes(0); // Should not query DB for invalid UUID
      });
    });

    describe('error handling', () => {
      it('should handle errors when deleting wardrobe_items gracefully', async () => {
        const wardrobeId = uuidv4();
        const dbError = new Error('Connection refused');
        
        // Mock the first query (DELETE wardrobe_items) to fail
        mockQuery
          .mockRejectedValueOnce(dbError) // Items deletion fails
          .mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess()); // Wardrobe deletion succeeds

        const result = await wardrobeModel.delete(wardrobeId);

        expect(result).toBe(true); // Should still succeed since wardrobe deletion worked
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });

      it('should throw error when deleting wardrobe fails', async () => {
        const wardrobeId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // Items deletion succeeds
          .mockRejectedValueOnce(dbError); // Wardrobe deletion fails

        await expect(wardrobeModel.delete(wardrobeId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('addGarment', () => {
    describe('successful operations', () => {
      it('should add new garment to wardrobe', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const position = 0;
        
        // Mock: check existing (not found), then insert
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT')) // No existing item
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([{ id: 'mock' }], 'INSERT')); // Insert success

        const result = await wardrobeModel.addGarment(wardrobeId, garmentId, position);

        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(2);
        
        // Verify check query
        const [checkQuery, checkParams] = mockQuery.mock.calls[0];
        expect(checkQuery).toContain('SELECT * FROM wardrobe_items');
        expect(checkQuery).toContain('WHERE wardrobe_id = $1 AND garment_item_id = $2');
        expect(checkParams).toEqual([wardrobeId, garmentId]);
        
        // Verify insert query
        const [insertQuery, insertParams] = mockQuery.mock.calls[1];
        expect(insertQuery).toContain('INSERT INTO wardrobe_items');
        expect(insertParams).toEqual([wardrobeId, garmentId, position]);
      });

      it('should update position of existing garment in wardrobe', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const newPosition = 5;
        
        const existingItem = wardrobeMocks.wardrobeItems.createWardrobeItem(wardrobeId, garmentId, 0);
        
        // Mock: find existing item, then update
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([existingItem], 'SELECT')) // Existing item found
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([{ id: 'mock' }], 'UPDATE')); // Update success

        const result = await wardrobeModel.addGarment(wardrobeId, garmentId, newPosition);

        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(2);
        
        // Verify update query
        const [updateQuery, updateParams] = mockQuery.mock.calls[1];
        expect(updateQuery).toContain('UPDATE wardrobe_items SET position = $1');
        expect(updateQuery).toContain('WHERE wardrobe_id = $2 AND garment_item_id = $3');
        expect(updateParams).toEqual([newPosition, wardrobeId, garmentId]);
      });

      it('should handle default position (0)', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'))
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([{ id: 'mock' }], 'INSERT'));

        const result = await wardrobeModel.addGarment(wardrobeId, garmentId); // No position provided

        expect(result).toBe(true);
        
        const [, insertParams] = mockQuery.mock.calls[1];
        expect(insertParams![2]).toBe(0); // Default position
      });

      it('should handle various position values', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const testPositions = [0, 1, 5, 10, 99];
        
        for (const position of testPositions) {
          jest.clearAllMocks();
          
          mockQuery
            .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'))
            .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([{ id: 'mock' }], 'INSERT'));

          const result = await wardrobeModel.addGarment(wardrobeId, garmentId, position);

          expect(result).toBe(true);
          expect(mockQuery.mock.calls[1][1]![2]).toBe(position);
        }
      });
    });

    describe('error handling', () => {
      it('should throw error when check query fails', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.addGarment(wardrobeId, garmentId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      it('should throw error when insert query fails', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.uniqueConstraintError;
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'))
          .mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.addGarment(wardrobeId, garmentId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });

      it('should throw error when update query fails', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const existingItem = wardrobeMocks.wardrobeItems.createWardrobeItem(wardrobeId, garmentId, 0);
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([existingItem], 'SELECT'))
          .mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.addGarment(wardrobeId, garmentId, 5)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('removeGarment', () => {
    describe('successful removal', () => {
      it('should remove garment from wardrobe and return true', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess());

        const result = await wardrobeModel.removeGarment(wardrobeId, garmentId);

        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('DELETE FROM wardrobe_items');
        expect(queryText).toContain('WHERE wardrobe_id = $1 AND garment_item_id = $2');
        expect(queryParams).toEqual([wardrobeId, garmentId]);
      });

      it('should handle multiple garment removals', async () => {
        const wardrobeId = uuidv4();
        const garmentIds = [uuidv4(), uuidv4(), uuidv4()];
        
        for (const garmentId of garmentIds) {
          jest.clearAllMocks();
          mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess());
          
          const result = await wardrobeModel.removeGarment(wardrobeId, garmentId);
          expect(result).toBe(true);
        }
      });
    });

    describe('not found scenarios', () => {
      it('should return false when garment not in wardrobe', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE'));

        const result = await wardrobeModel.removeGarment(wardrobeId, garmentId);

        expect(result).toBe(false);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      it('should return false for non-existent wardrobe', async () => {
        const nonExistentWardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE'));

        const result = await wardrobeModel.removeGarment(nonExistentWardrobeId, garmentId);

        expect(result).toBe(false);
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.removeGarment(wardrobeId, garmentId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });
    });
  });

  describe('getGarments', () => {
    describe('successful retrieval', () => {
      it('should return garments ordered by position', async () => {
        const wardrobeId = uuidv4();
        const userId = uuidv4();
        const garments = wardrobeMocks.garments.createMultipleGarments(userId, 5);
        
        // Add position property to garments (as returned by JOIN query)
        const garmentsWithPosition = garments.map((garment, index) => ({
          ...garment,
          position: index
        }));

        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess(garmentsWithPosition, 'SELECT'));

        const result = await wardrobeModel.getGarments(wardrobeId);

        expect(result).toEqual(garmentsWithPosition);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('SELECT g.*, wi.position');
        expect(queryText).toContain('FROM garment_items g');
        expect(queryText).toContain('JOIN wardrobe_items wi ON g.id = wi.garment_item_id');
        expect(queryText).toContain('WHERE wi.wardrobe_id = $1');
        expect(queryText).toContain('ORDER BY wi.position');
        expect(queryParams).toEqual([wardrobeId]);
      });

      it('should return empty array when wardrobe has no garments', async () => {
        const wardrobeId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'));

        const result = await wardrobeModel.getGarments(wardrobeId);

        expect(result).toEqual([]);
        expect(Array.isArray(result)).toBe(true);
        expect(result.length).toBe(0);
      });

      it('should return single garment correctly', async () => {
        const wardrobeId = uuidv4();
        const userId = uuidv4();
        const garment = wardrobeMocks.garments.createMockGarment({ user_id: userId });
        const garmentWithPosition = { ...garment, position: 0 };

        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([garmentWithPosition], 'SELECT'));

        const result = await wardrobeModel.getGarments(wardrobeId);

        expect(result).toEqual([garmentWithPosition]);
        expect(result.length).toBe(1);
        expect(result[0]).toHaveProperty('position');
      });

      it('should handle garments with different positions', async () => {
        const wardrobeId = uuidv4();
        const userId = uuidv4();
        const positions = [0, 2, 5, 10];
        const garments = positions.map((position, index) => ({
          ...wardrobeMocks.garments.createMockGarment({ user_id: userId }),
          position
        }));

        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess(garments, 'SELECT'));

        const result = await wardrobeModel.getGarments(wardrobeId);

        expect(result).toEqual(garments);
        
        // Verify positions are included
        result.forEach((garment, index) => {
          expect(garment.position).toBe(positions[index]);
        });
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        const wardrobeId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        await expect(wardrobeModel.getGarments(wardrobeId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      it('should throw error on timeout', async () => {
        const wardrobeId = uuidv4();
        const timeoutError = wardrobeMocks.errorScenarios.timeoutError;
        
        mockQuery.mockRejectedValueOnce(timeoutError);

        await expect(wardrobeModel.getGarments(wardrobeId)).rejects.toThrow(timeoutError);
      });
    });
  });

  describe('edge cases and boundary conditions', () => {
    describe('UUID validation edge cases', () => {
      it('should handle various invalid UUID formats consistently', async () => {
        const invalidUuids = [
          '',
          'not-a-uuid',
          '123',
          'invalid-uuid-format',
          '12345678-1234-1234-1234-12345678901', // too short
          '12345678-1234-1234-1234-1234567890123', // too long
          null,
          undefined
        ];

        // Test findById
        for (const invalidUuid of invalidUuids) {
          const result = await wardrobeModel.findById(invalidUuid as any);
          expect(result).toBeNull();
        }
        
        // Test update
        for (const invalidUuid of invalidUuids) {
          const result = await wardrobeModel.update(invalidUuid as any, { name: 'test' });
          expect(result).toBeNull();
        }
        
        // Test delete
        for (const invalidUuid of invalidUuids) {
          const result = await wardrobeModel.delete(invalidUuid as any);
          expect(result).toBe(false);
        }
        
        // Verify no database calls were made for invalid UUIDs
        expect(mockQuery).not.toHaveBeenCalled();
      });

      it('should handle valid UUID formats correctly', async () => {
        const validUuids = [
          uuidv4(),
          uuidv4().toUpperCase(),
          uuidv4().toLowerCase()
        ];

        for (const validUuid of validUuids) {
          jest.clearAllMocks();
          mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.notFound());
          
          const result = await wardrobeModel.findById(validUuid);
          expect(result).toBeNull(); // Not found, but query was executed
          expect(mockQuery).toHaveBeenCalledTimes(1);
        }
      });
    });

    describe('data consistency edge cases', () => {
      it('should handle concurrent modifications gracefully', async () => {
        const wardrobeId = uuidv4();
        const updateData = wardrobeMocks.createValidUpdateInput();
        
        // Simulate concurrent modification - row was deleted between operations
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.selectMultiple([]));

        const result = await wardrobeModel.update(wardrobeId, updateData);

        expect(result).toBeNull();
      });

      it('should handle large result sets efficiently', async () => {
        const userId = uuidv4();
        const largeWardrobeSet = wardrobeMocks.createMultipleWardrobes(userId, 100);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(largeWardrobeSet)
        );

        const result = await wardrobeModel.findByUserId(userId);

        expect(result).toEqual(largeWardrobeSet);
        expect(result.length).toBe(100);
      });
    });

    describe('database connection edge cases', () => {
      it('should throw error on database connection timeout', async () => {
        const wardrobeId = uuidv4();
        const timeoutError = new Error('Connection timeout');
        
        mockQuery.mockRejectedValueOnce(timeoutError);

        await expect(wardrobeModel.findById(wardrobeId)).rejects.toThrow('Connection timeout');
      });

      it('should throw error on database connection pool exhaustion', async () => {
        const userId = uuidv4();
        const poolError = new Error('Connection pool exhausted');
        
        mockQuery.mockRejectedValueOnce(poolError);

        await expect(wardrobeModel.findByUserId(userId)).rejects.toThrow('Connection pool exhausted');
      });
    });
  });

  describe('performance considerations', () => {
    describe('query optimization', () => {
      it('should use parameterized queries for all operations', async () => {
        const wardrobeId = uuidv4();
        const userId = uuidv4();
        const inputData = wardrobeMocks.createValidInput({ user_id: userId });
        const updateData = wardrobeMocks.createValidUpdateInput();
        const garmentId = uuidv4();

        mockQuery.mockResolvedValue(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'));

        // Act - test all model methods that make DB calls
        await wardrobeModel.create(inputData);
        await wardrobeModel.findById(wardrobeId);
        await wardrobeModel.findByUserId(userId);
        await wardrobeModel.update(wardrobeId, updateData);
        await wardrobeModel.delete(wardrobeId);
        await wardrobeModel.addGarment(wardrobeId, garmentId);
        await wardrobeModel.removeGarment(wardrobeId, garmentId);
        await wardrobeModel.getGarments(wardrobeId);

        // Assert - verify all queries use parameters
        const allCalls = mockQuery.mock.calls;
        allCalls.forEach(([queryText, params]) => {
          expect(queryText).toMatch(/\$\d+/); // Contains parameter placeholders
          expect(params).toBeDefined();
          expect(Array.isArray(params)).toBe(true);
        });
      });

      it('should not perform unnecessary database calls for invalid UUIDs', async () => {
        jest.clearAllMocks();
        
        // These should all return early without hitting the database
        const result1 = await wardrobeModel.findById('invalid-uuid');
        const result2 = await wardrobeModel.findById('');
        const result3 = await wardrobeModel.findById(null as any);
        const result4 = await wardrobeModel.update('invalid-uuid', { name: 'test' });
        const result5 = await wardrobeModel.delete('invalid-uuid');
        
        expect(result1).toBeNull();
        expect(result2).toBeNull();
        expect(result3).toBeNull();
        expect(result4).toBeNull();
        expect(result5).toBe(false);
        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('memory efficiency', () => {
      it('should handle large datasets without memory issues', async () => {
        const userId = uuidv4();
        const largeDataset = Array.from({ length: 1000 }, (_, index) => 
          wardrobeMocks.createValidWardrobe({
            user_id: userId,
            name: `Wardrobe ${index + 1}`
          })
        );

        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.selectMultiple(largeDataset));

        const result = await wardrobeModel.findByUserId(userId);

        expect(result.length).toBe(1000);
        expect(result[0]).toHaveProperty('id');
        expect(result[999]).toHaveProperty('name', 'Wardrobe 1000');
      });
    });
  });

  describe('type safety verification', () => {
    describe('input type validation', () => {
      it('should accept properly typed CreateWardrobeInput', async () => {
        const validInput: CreateWardrobeInput = {
          user_id: uuidv4(),
          name: 'Test Wardrobe',
          description: 'Test Description'
        };

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(wardrobeMocks.createValidWardrobe())
        );

        // Act & Assert - Should compile and run without errors
        const result = await wardrobeModel.create(validInput);
        expect(result).toBeDefined();
      });

      it('should accept properly typed UpdateWardrobeInput', async () => {
        const wardrobeId = uuidv4();
        const validUpdate: UpdateWardrobeInput = {
          name: 'Updated Name',
          description: 'Updated Description'
        };

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.updateSuccess(wardrobeMocks.createValidWardrobe())
        );

        // Act & Assert - Should compile and run without errors
        const result = await wardrobeModel.update(wardrobeId, validUpdate);
        expect(result).toBeDefined();
      });
    });

    describe('return type validation', () => {
      it('should return properly typed Wardrobe objects', async () => {
        const expectedWardrobe = wardrobeMocks.createValidWardrobe();
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectSingle(expectedWardrobe)
        );

        const result = await wardrobeModel.findById(expectedWardrobe.id);

        // Assert - TypeScript should enforce proper typing
        expect(result).toBeDefined();
        if (result) {
          expect(typeof result.id).toBe('string');
          expect(typeof result.user_id).toBe('string');
          expect(typeof result.name).toBe('string');
          expect(typeof result.description).toBe('string');
          expect(result.created_at).toBeInstanceOf(Date);
          expect(result.updated_at).toBeInstanceOf(Date);
        }
      });

      it('should return properly typed arrays', async () => {
        const userId = uuidv4();
        const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, 3);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(wardrobes)
        );

        const result = await wardrobeModel.findByUserId(userId);

        // Assert - TypeScript should enforce Wardrobe[] type
        expect(Array.isArray(result)).toBe(true);
        result.forEach(wardrobe => {
          expect(typeof wardrobe.id).toBe('string');
          expect(typeof wardrobe.user_id).toBe('string');
          expect(typeof wardrobe.name).toBe('string');
        });
      });
    });
  });

  describe('integration with database constraints', () => {
    describe('foreign key constraints', () => {
      it('should throw error for invalid user_id in create', async () => {
        const invalidUserInput = wardrobeMocks.createValidInput({
          user_id: uuidv4() // Non-existent user
        });
        
        const foreignKeyError = new Error('Foreign key constraint violation');
        mockQuery.mockRejectedValueOnce(foreignKeyError);

        await expect(wardrobeModel.create(invalidUserInput)).rejects.toThrow(foreignKeyError);
      });

      it('should throw error for invalid garment_id in addGarment', async () => {
        const wardrobeId = uuidv4();
        const invalidGarmentId = uuidv4(); // Non-existent garment
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT')) // Check existing
          .mockRejectedValueOnce(new Error('Foreign key constraint violation')); // Insert fails

        await expect(wardrobeModel.addGarment(wardrobeId, invalidGarmentId))
          .rejects.toThrow('Foreign key constraint violation');
      });
    });

    describe('unique constraints', () => {
      it('should throw error on unique constraint violations', async () => {
        const inputData = wardrobeMocks.createValidInput();
        const uniqueError = new Error('Unique constraint violation');
        
        mockQuery.mockRejectedValueOnce(uniqueError);

        await expect(wardrobeModel.create(inputData)).rejects.toThrow(uniqueError);
      });
    });
  });

  describe('business logic validation', () => {
    describe('wardrobe lifecycle', () => {
      it('should maintain data consistency across operations', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        // Test sequence: create → add garment → update → remove garment → delete
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.insertSuccess(wardrobeMocks.createValidWardrobe()))
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT')) // Check existing
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([{ id: 'mock' }], 'INSERT')) // Add garment
          .mockResolvedValueOnce(wardrobeMocks.queryResults.updateSuccess(wardrobeMocks.createValidWardrobe()))
          .mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess()) // Remove garment
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // Delete items
          .mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess()); // Delete wardrobe

        // Execute lifecycle
        const created = await wardrobeModel.create(wardrobeMocks.createValidInput());
        const addResult = await wardrobeModel.addGarment(wardrobeId, garmentId, 1);
        const updated = await wardrobeModel.update(wardrobeId, { name: 'Updated' });
        const removeResult = await wardrobeModel.removeGarment(wardrobeId, garmentId);
        const deleteResult = await wardrobeModel.delete(wardrobeId);

        expect(created).toBeDefined();
        expect(addResult).toBe(true);
        expect(updated).toBeDefined();
        expect(removeResult).toBe(true);
        expect(deleteResult).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(7);
      });
    });

    describe('error recovery', () => {
      it('should handle partial operation failures gracefully', async () => {
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        // Simulate: successful check, failed insert
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'))
          .mockRejectedValueOnce(new Error('Insert failed'));

        await expect(wardrobeModel.addGarment(wardrobeId, garmentId))
          .rejects.toThrow('Insert failed');
        
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });
  });
});