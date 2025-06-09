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
        // Arrange
        const inputData = wardrobeMocks.createValidInput();
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({
          user_id: inputData.user_id,
          name: inputData.name,
          description: inputData.description
        });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        // Act
        const result = await wardrobeModel.create(inputData);

        // Assert
        expect(result).toEqual(expectedWardrobe);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('INSERT INTO wardrobes');
        expect(queryText).toContain('RETURNING *');
        expect(queryParams).toHaveLength(4);
        
        // Verify UUID generation
        expect(isUuid(queryParams![0])).toBe(true);
        expect(queryParams![1]).toBe(inputData.user_id);
        expect(queryParams![2]).toBe(inputData.name);
        expect(queryParams![3]).toBe(inputData.description);
      });

      it('should create a wardrobe with empty description when not provided', async () => {
        // Arrange
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

        // Act
        const result = await wardrobeModel.create(inputData);

        // Assert
        expect(result).toEqual(expectedWardrobe);
        expect(mockQuery.mock.calls[0][1]![3]).toBe(''); // description should be empty string
      });

      it('should create a wardrobe with minimal valid data', async () => {
        // Arrange
        const inputData = wardrobeMocks.edgeCases.minName;
        const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        // Act
        const result = await wardrobeModel.create(inputData);

        // Assert
        expect(result).toEqual(expectedWardrobe);
        expect(result.name).toBe('A');
        expect(result.description).toBe('');
      });

      it('should create a wardrobe with maximum valid data', async () => {
        // Arrange
        const inputData = wardrobeMocks.edgeCases.maxDescription;
        const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        // Act
        const result = await wardrobeModel.create(inputData);

        // Assert
        expect(result).toEqual(expectedWardrobe);
        expect(result.name.length).toBe(inputData.name!.length);
        expect(result.description!.length).toBe(1000);
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        // Arrange
        const inputData = wardrobeMocks.createValidInput();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.create(inputData)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      it('should throw error on foreign key constraint violation', async () => {
        // Arrange
        const inputData = wardrobeMocks.createValidInput();
        const fkError = wardrobeMocks.errorScenarios.foreignKeyError;
        
        mockQuery.mockRejectedValueOnce(fkError);

        // Act & Assert
        await expect(wardrobeModel.create(inputData)).rejects.toThrow(fkError);
      });

      it('should throw error on unique constraint violation', async () => {
        // Arrange
        const inputData = wardrobeMocks.createValidInput();
        const uniqueError = wardrobeMocks.errorScenarios.uniqueConstraintError;
        
        mockQuery.mockRejectedValueOnce(uniqueError);

        // Act & Assert
        await expect(wardrobeModel.create(inputData)).rejects.toThrow(uniqueError);
      });
    });

    describe('data validation at model level', () => {
      it('should handle special characters in allowed fields correctly', async () => {
        // Arrange
        const inputData = wardrobeMocks.edgeCases.allowedSpecialChars;
        const expectedWardrobe = wardrobeMocks.createValidWardrobe(inputData);

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.insertSuccess(expectedWardrobe)
        );

        // Act
        const result = await wardrobeModel.create(inputData);

        // Assert
        expect(result.name).toBe(inputData.name);
        expect(result.name).toMatch(/^[a-zA-Z0-9\s\-_\.]+$/);
      });
    });
  });

  describe('findById', () => {
    describe('successful retrieval', () => {
      it('should return wardrobe when found', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const expectedWardrobe = wardrobeMocks.createValidWardrobe({ id: wardrobeId });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectSingle(expectedWardrobe)
        );

        // Act
        const result = await wardrobeModel.findById(wardrobeId);

        // Assert
        expect(result).toEqual(expectedWardrobe);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('SELECT * FROM wardrobes WHERE id = $1');
        expect(queryParams).toEqual([wardrobeId]);
      });

      it('should return null when wardrobe not found', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.notFound());

        // Act
        const result = await wardrobeModel.findById(wardrobeId);

        // Assert
        expect(result).toBeNull();
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });
    });

    describe('input validation', () => {
      it('should return null for invalid UUID format', async () => {
        // Arrange
        const invalidId = 'invalid-uuid';

        // Act
        const result = await wardrobeModel.findById(invalidId);

        // Assert
        expect(result).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled(); // Should not query DB for invalid UUID
      });

      it('should return null for empty string ID', async () => {
        // Arrange
        const emptyId = '';

        // Act
        const result = await wardrobeModel.findById(emptyId);

        // Assert
        expect(result).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();
      });

      it('should handle null/undefined ID gracefully', async () => {
        // Act & Assert
        expect(await wardrobeModel.findById(null as any)).toBeNull();
        expect(await wardrobeModel.findById(undefined as any)).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.findById(wardrobeId)).rejects.toThrow(dbError);
      });
    });
  });

  describe('findByUserId', () => {
    describe('successful retrieval', () => {
      it('should return wardrobes ordered by name', async () => {
        // Arrange
        const userId = uuidv4();
        const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, 3);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(wardrobes)
        );

        // Act
        const result = await wardrobeModel.findByUserId(userId);

        // Assert
        expect(result).toEqual(wardrobes);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('SELECT * FROM wardrobes WHERE user_id = $1');
        expect(queryText).toContain('ORDER BY name');
        expect(queryParams).toEqual([userId]);
      });

      it('should return empty array when user has no wardrobes', async () => {
        // Arrange
        const userId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.selectMultiple([]));

        // Act
        const result = await wardrobeModel.findByUserId(userId);

        // Assert
        expect(result).toEqual([]);
        expect(Array.isArray(result)).toBe(true);
        expect(result.length).toBe(0);
      });

      it('should handle user with single wardrobe', async () => {
        // Arrange
        const userId = uuidv4();
        const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, 1);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(wardrobes)
        );

        // Act
        const result = await wardrobeModel.findByUserId(userId);

        // Assert
        expect(result).toEqual(wardrobes);
        expect(result.length).toBe(1);
      });

      it('should handle user with maximum wardrobes', async () => {
        // Arrange
        const userId = uuidv4();
        const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, 50);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(wardrobes)
        );

        // Act
        const result = await wardrobeModel.findByUserId(userId);

        // Assert
        expect(result).toEqual(wardrobes);
        expect(result.length).toBe(50);
      });
    });

    describe('input validation', () => {
      it('should handle invalid user ID format', async () => {
        // Arrange
        const invalidUserId = 'invalid-uuid';
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.selectMultiple([]));

        // Act
        const result = await wardrobeModel.findByUserId(invalidUserId);

        // Assert
        expect(result).toEqual([]);
        expect(mockQuery).toHaveBeenCalledTimes(1); // Still queries DB, returns empty
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        // Arrange
        const userId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.findByUserId(userId)).rejects.toThrow(dbError);
      });
    });
  });

  describe('update', () => {
    describe('successful updates', () => {
      it('should update wardrobe name only', async () => {
        // Arrange
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

        // Act
        const result = await wardrobeModel.update(wardrobeId, updateData);

        // Assert
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
        // Arrange
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

        // Act
        const result = await wardrobeModel.update(wardrobeId, updateData);

        // Assert
        expect(result).toEqual(updatedWardrobe);
        expect(mockQuery.mock.calls[0][1]).toEqual(['Updated Description', wardrobeId]);
      });

      it('should update both name and description', async () => {
        // Arrange
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

        // Act
        const result = await wardrobeModel.update(wardrobeId, updateData);

        // Assert
        expect(result).toEqual(updatedWardrobe);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('name = $1');
        expect(queryText).toContain('description = $2');
        expect(queryParams).toEqual(['Updated Name', 'Updated Description', wardrobeId]);
      });

      it('should handle empty update (only updated_at changes)', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const updateData: UpdateWardrobeInput = {};
        const updatedWardrobe = wardrobeMocks.createValidWardrobe({
          id: wardrobeId,
          updated_at: new Date()
        });

        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.updateSuccess(updatedWardrobe)
        );

        // Act
        const result = await wardrobeModel.update(wardrobeId, updateData);

        // Assert
        expect(result).toEqual(updatedWardrobe);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('UPDATE wardrobes SET updated_at = NOW()');
        expect(queryText).toContain('WHERE id = $1');
        expect(queryParams).toEqual([wardrobeId]);
      });

      it('should handle undefined values correctly', async () => {
        // Arrange
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

        // Act
        const result = await wardrobeModel.update(wardrobeId, updateData);

        // Assert
        expect(result).toEqual(updatedWardrobe);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).not.toContain('name = ');
        expect(queryText).toContain('description = $1');
        expect(queryParams).toEqual(['Only description updated', wardrobeId]);
      });
    });

    describe('not found scenarios', () => {
      it('should return null when wardrobe not found', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const updateData = wardrobeMocks.createValidUpdateInput();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.notFound());

        // Act
        const result = await wardrobeModel.update(wardrobeId, updateData);

        // Assert
        expect(result).toBeNull();
      });
    });

    describe('input validation', () => {
      it('should handle invalid UUID format', async () => {
        // Arrange
        const invalidId = 'invalid-uuid';
        const updateData = wardrobeMocks.createValidUpdateInput();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.notFound());

        // Act
        const result = await wardrobeModel.update(invalidId, updateData);

        // Assert
        expect(result).toBeNull();
        expect(mockQuery).toHaveBeenCalledTimes(1); // Still attempts query
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const updateData = wardrobeMocks.createValidUpdateInput();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.update(wardrobeId, updateData)).rejects.toThrow(dbError);
      });
    });
  });

  describe('delete', () => {
    describe('successful deletion', () => {
      it('should delete wardrobe and associated items, return true', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        
        // Mock both deletion queries
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // Delete wardrobe_items
          .mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess()); // Delete wardrobe

        // Act
        const result = await wardrobeModel.delete(wardrobeId);

        // Assert
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
        // Arrange
        const wardrobeId = uuidv4();
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // No items to delete
          .mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess()); // Delete wardrobe

        // Act
        const result = await wardrobeModel.delete(wardrobeId);

        // Assert
        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });

    describe('not found scenarios', () => {
      it('should return false when wardrobe not found', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // No items to delete
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')); // Wardrobe not found

        // Act
        const result = await wardrobeModel.delete(wardrobeId);

        // Assert
        expect(result).toBe(false);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });

    describe('input validation', () => {
      it('should handle invalid UUID format', async () => {
        // Arrange
        const invalidId = 'invalid-uuid';
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE'))
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE'));

        // Act
        const result = await wardrobeModel.delete(invalidId);

        // Assert
        expect(result).toBe(false);
        expect(mockQuery).toHaveBeenCalledTimes(2); // Still attempts queries
      });
    });

    describe('error handling', () => {
      it('should throw error when deleting wardrobe_items fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.delete(wardrobeId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1); // Fails on first query
      });

      it('should throw error when deleting wardrobe fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE')) // Items deletion succeeds
          .mockRejectedValueOnce(dbError); // Wardrobe deletion fails

        // Act & Assert
        await expect(wardrobeModel.delete(wardrobeId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('addGarment', () => {
    describe('successful operations', () => {
      it('should add new garment to wardrobe', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const position = 0;
        
        // Mock: check existing (not found), then insert
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT')) // No existing item
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'INSERT')); // Insert success

        // Act
        const result = await wardrobeModel.addGarment(wardrobeId, garmentId, position);

        // Assert
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
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const newPosition = 5;
        
        const existingItem = wardrobeMocks.wardrobeItems.createWardrobeItem(wardrobeId, garmentId, 0);
        
        // Mock: find existing item, then update
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([existingItem], 'SELECT')) // Existing item found
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'UPDATE')); // Update success

        // Act
        const result = await wardrobeModel.addGarment(wardrobeId, garmentId, newPosition);

        // Assert
        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(2);
        
        // Verify update query
        const [updateQuery, updateParams] = mockQuery.mock.calls[1];
        expect(updateQuery).toContain('UPDATE wardrobe_items SET position = $1');
        expect(updateQuery).toContain('WHERE wardrobe_id = $2 AND garment_item_id = $3');
        expect(updateParams).toEqual([newPosition, wardrobeId, garmentId]);
      });

      it('should handle default position (0)', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'))
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'INSERT'));

        // Act
        const result = await wardrobeModel.addGarment(wardrobeId, garmentId); // No position provided

        // Assert
        expect(result).toBe(true);
        
        const [, insertParams] = mockQuery.mock.calls[1];
        expect(insertParams![2]).toBe(0); // Default position
      });

      it('should handle various position values', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const testPositions = [0, 1, 5, 10, 99];
        
        for (const position of testPositions) {
          jest.clearAllMocks();
          
          mockQuery
            .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'))
            .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'INSERT'));

          // Act
          const result = await wardrobeModel.addGarment(wardrobeId, garmentId, position);

          // Assert
          expect(result).toBe(true);
          expect(mockQuery.mock.calls[1][1]![2]).toBe(position);
        }
      });
    });

    describe('error handling', () => {
      it('should throw error when check query fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.addGarment(wardrobeId, garmentId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      it('should throw error when insert query fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.uniqueConstraintError;
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'))
          .mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.addGarment(wardrobeId, garmentId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });

      it('should throw error when update query fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const existingItem = wardrobeMocks.wardrobeItems.createWardrobeItem(wardrobeId, garmentId, 0);
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([existingItem], 'SELECT'))
          .mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.addGarment(wardrobeId, garmentId, 5)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('removeGarment', () => {
    describe('successful removal', () => {
      it('should remove garment from wardrobe and return true', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.deleteSuccess());

        // Act
        const result = await wardrobeModel.removeGarment(wardrobeId, garmentId);

        // Assert
        expect(result).toBe(true);
        expect(mockQuery).toHaveBeenCalledTimes(1);
        
        const [queryText, queryParams] = mockQuery.mock.calls[0];
        expect(queryText).toContain('DELETE FROM wardrobe_items');
        expect(queryText).toContain('WHERE wardrobe_id = $1 AND garment_item_id = $2');
        expect(queryParams).toEqual([wardrobeId, garmentId]);
      });

      it('should handle multiple garment removals', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentIds = [uuidv4(), uuidv4(), uuidv4()];
        
        // Act & Assert
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
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE'));

        // Act
        const result = await wardrobeModel.removeGarment(wardrobeId, garmentId);

        // Assert
        expect(result).toBe(false);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      it('should return false for non-existent wardrobe', async () => {
        // Arrange
        const nonExistentWardrobeId = uuidv4();
        const garmentId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'DELETE'));

        // Act
        const result = await wardrobeModel.removeGarment(nonExistentWardrobeId, garmentId);

        // Assert
        expect(result).toBe(false);
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const garmentId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.removeGarment(wardrobeId, garmentId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });
    });
  });

  describe('getGarments', () => {
    describe('successful retrieval', () => {
      it('should return garments ordered by position', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const userId = uuidv4();
        const garments = wardrobeMocks.garments.createMultipleGarments(userId, 5);
        
        // Add position property to garments (as returned by JOIN query)
        const garmentsWithPosition = garments.map((garment, index) => ({
          ...garment,
          position: index
        }));

        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess(garmentsWithPosition, 'SELECT'));

        // Act
        const result = await wardrobeModel.getGarments(wardrobeId);

        // Assert
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
        // Arrange
        const wardrobeId = uuidv4();
        
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'));

        // Act
        const result = await wardrobeModel.getGarments(wardrobeId);

        // Assert
        expect(result).toEqual([]);
        expect(Array.isArray(result)).toBe(true);
        expect(result.length).toBe(0);
      });

      it('should return single garment correctly', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const userId = uuidv4();
        const garment = wardrobeMocks.garments.createMockGarment({ user_id: userId });
        const garmentWithPosition = { ...garment, position: 0 };

        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([garmentWithPosition], 'SELECT'));

        // Act
        const result = await wardrobeModel.getGarments(wardrobeId);

        // Assert
        expect(result).toEqual([garmentWithPosition]);
        expect(result.length).toBe(1);
        expect(result[0]).toHaveProperty('position');
      });

      it('should handle garments with different positions', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const userId = uuidv4();
        const positions = [0, 2, 5, 10];
        const garments = positions.map((position, index) => ({
          ...wardrobeMocks.garments.createMockGarment({ user_id: userId }),
          position
        }));

        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess(garments, 'SELECT'));

        // Act
        const result = await wardrobeModel.getGarments(wardrobeId);

        // Assert
        expect(result).toEqual(garments);
        
        // Verify positions are included
        result.forEach((garment, index) => {
          expect(garment.position).toBe(positions[index]);
        });
      });
    });

    describe('error handling', () => {
      it('should throw error when database query fails', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const dbError = wardrobeMocks.errorScenarios.dbConnectionError;
        
        mockQuery.mockRejectedValueOnce(dbError);

        // Act & Assert
        await expect(wardrobeModel.getGarments(wardrobeId)).rejects.toThrow(dbError);
        expect(mockQuery).toHaveBeenCalledTimes(1);
      });

      it('should throw error on timeout', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const timeoutError = wardrobeMocks.errorScenarios.timeoutError;
        
        mockQuery.mockRejectedValueOnce(timeoutError);

        // Act & Assert
        await expect(wardrobeModel.getGarments(wardrobeId)).rejects.toThrow(timeoutError);
      });
    });
  });

  describe('edge cases and boundary conditions', () => {
    describe('UUID validation edge cases', () => {
      it('should handle various invalid UUID formats', async () => {
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

        for (const invalidUuid of invalidUuids) {
          const result = await wardrobeModel.findById(invalidUuid as any);
          expect(result).toBeNull();
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
        // Arrange
        const wardrobeId = uuidv4();
        const updateData = wardrobeMocks.createValidUpdateInput();
        
        // Simulate concurrent modification - row was deleted between operations
        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.selectMultiple([]));

        // Act
        const result = await wardrobeModel.update(wardrobeId, updateData);

        // Assert
        expect(result).toBeNull();
      });

      it('should handle large result sets', async () => {
        // Arrange
        const userId = uuidv4();
        const largeWardrobeSet = wardrobeMocks.createMultipleWardrobes(userId, 100);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(largeWardrobeSet)
        );

        // Act
        const result = await wardrobeModel.findByUserId(userId);

        // Assert
        expect(result).toEqual(largeWardrobeSet);
        expect(result.length).toBe(100);
      });
    });

    describe('database connection edge cases', () => {
      it('should handle database connection timeout', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const timeoutError = new Error('Connection timeout');
        
        mockQuery.mockRejectedValueOnce(timeoutError);

        // Act & Assert
        await expect(wardrobeModel.findById(wardrobeId)).rejects.toThrow('Connection timeout');
      });

      it('should handle database connection pool exhaustion', async () => {
        // Arrange
        const userId = uuidv4();
        const poolError = new Error('Connection pool exhausted');
        
        mockQuery.mockRejectedValueOnce(poolError);

        // Act & Assert
        await expect(wardrobeModel.findByUserId(userId)).rejects.toThrow('Connection pool exhausted');
      });
    });
  });

  describe('performance considerations', () => {
    describe('query optimization', () => {
      it('should use parameterized queries for all operations', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const userId = uuidv4();
        const inputData = wardrobeMocks.createValidInput({ user_id: userId });
        const updateData = wardrobeMocks.createValidUpdateInput();
        const garmentId = uuidv4();

        mockQuery.mockResolvedValue(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'));

        // Act - test all model methods
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

      it('should not perform unnecessary database calls', async () => {
        // Test UUID validation prevents unnecessary DB calls
        jest.clearAllMocks();
        
        // These should all return null without hitting the database
        const result1 = await wardrobeModel.findById('invalid-uuid');
        const result2 = await wardrobeModel.findById('');
        const result3 = await wardrobeModel.findById(null as any);
        
        expect(result1).toBeNull();
        expect(result2).toBeNull();
        expect(result3).toBeNull();
        expect(mockQuery).not.toHaveBeenCalled();
      });
    });

    describe('memory efficiency', () => {
      it('should handle large datasets without memory issues', async () => {
        // Arrange
        const userId = uuidv4();
        const largeDataset = Array.from({ length: 1000 }, (_, index) => 
          wardrobeMocks.createValidWardrobe({
            user_id: userId,
            name: `Wardrobe ${index + 1}`
          })
        );

        mockQuery.mockResolvedValueOnce(wardrobeMocks.queryResults.selectMultiple(largeDataset));

        // Act
        const result = await wardrobeModel.findByUserId(userId);

        // Assert
        expect(result.length).toBe(1000);
        expect(result[0]).toHaveProperty('id');
        expect(result[999]).toHaveProperty('name', 'Wardrobe 1000');
      });
    });
  });

  describe('type safety verification', () => {
    describe('input type validation', () => {
      it('should accept properly typed CreateWardrobeInput', async () => {
        // Arrange
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
        // Arrange
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
        // Arrange
        const expectedWardrobe = wardrobeMocks.createValidWardrobe();
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectSingle(expectedWardrobe)
        );

        // Act
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
        // Arrange
        const userId = uuidv4();
        const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, 3);
        
        mockQuery.mockResolvedValueOnce(
          wardrobeMocks.queryResults.selectMultiple(wardrobes)
        );

        // Act
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
      it('should handle invalid user_id in create', async () => {
        // Arrange
        const invalidUserInput = wardrobeMocks.createValidInput({
          user_id: uuidv4() // Non-existent user
        });
        
        const foreignKeyError = new Error('Foreign key constraint violation');
        mockQuery.mockRejectedValueOnce(foreignKeyError);

        // Act & Assert
        await expect(wardrobeModel.create(invalidUserInput)).rejects.toThrow(foreignKeyError);
      });

      it('should handle invalid garment_id in addGarment', async () => {
        // Arrange
        const wardrobeId = uuidv4();
        const invalidGarmentId = uuidv4(); // Non-existent garment
        
        mockQuery
          .mockResolvedValueOnce(wardrobeMocks.queryResults.genericSuccess([], 'SELECT')) // Check existing
          .mockRejectedValueOnce(new Error('Foreign key constraint violation')); // Insert fails

        // Act & Assert
        await expect(wardrobeModel.addGarment(wardrobeId, invalidGarmentId))
          .rejects.toThrow('Foreign key constraint violation');
      });
    });

    describe('unique constraints', () => {
      it('should handle unique constraint violations appropriately', async () => {
        // Note: If there were unique constraints on wardrobe names per user,
        // this would test that scenario
        const inputData = wardrobeMocks.createValidInput();
        const uniqueError = new Error('Unique constraint violation');
        
        mockQuery.mockRejectedValueOnce(uniqueError);

        await expect(wardrobeModel.create(inputData)).rejects.toThrow(uniqueError);
      });
    });
  });
});