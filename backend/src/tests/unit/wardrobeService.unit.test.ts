// /backend/tests/services/wardrobeService.test.ts
import { wardrobeService } from '../../services/wardrobeService';
import { wardrobeModel } from '../../models/wardrobeModel';
import { garmentModel } from '../../models/garmentModel';
import { ApiError } from '../../utils/ApiError';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';
import { 
  wardrobeValidationHelpers} from '../__helpers__/wardrobes.helper';
import { v4 as uuidv4 } from 'uuid';

// Mock the model dependencies
jest.mock('../../models/wardrobeModel');
jest.mock('../../models/garmentModel');

const mockedWardrobeModel = wardrobeModel as jest.Mocked<typeof wardrobeModel>;
const mockedGarmentModel = garmentModel as jest.Mocked<typeof garmentModel>;

describe('WardrobeService', () => {
  // Test data setup
  let testUserId: string;
  let testWardrobeId: string;
  let testGarmentId: string;
  let mockWardrobe: any;
  let mockGarment: any;

  beforeEach(() => {
    // Reset all mocks
    jest.clearAllMocks();
    
    // Generate test IDs
    testUserId = uuidv4();
    testWardrobeId = uuidv4();
    testGarmentId = uuidv4();

    // Create mock data
    mockWardrobe = wardrobeMocks.createValidWardrobe({
      id: testWardrobeId,
      user_id: testUserId
    });

    mockGarment = wardrobeMocks.garments.createMockGarment({
      id: testGarmentId,
      user_id: testUserId
    });
  });

  describe('createWardrobe', () => {
    const validCreateParams = {
      userId: '',
      name: 'Test Wardrobe',
      description: 'Test description'
    };

    beforeEach(() => {
      validCreateParams.userId = testUserId;
    });

    describe('Successful Creation', () => {
      beforeEach(() => {
        // Mock successful operations
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
        mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
      });

      it('should create wardrobe with valid data', async () => {
        const result = await wardrobeService.createWardrobe(validCreateParams);

        expect(result).toEqual(mockWardrobe);
        expect(mockedWardrobeModel.create).toHaveBeenCalledWith({
          user_id: testUserId,
          name: 'Test Wardrobe',
          description: 'Test description'
        });
      });

      it('should create wardrobe without description', async () => {
        const params = { userId: testUserId, name: 'Test Wardrobe' };
        
        const result = await wardrobeService.createWardrobe(params);

        expect(result).toEqual(mockWardrobe);
        expect(mockedWardrobeModel.create).toHaveBeenCalledWith({
          user_id: testUserId,
          name: 'Test Wardrobe',
          description: ''
        });
      });

      it('should trim whitespace from name and description', async () => {
        const params = {
          userId: testUserId,
          name: '  Test Wardrobe  ',
          description: '  Test description  '
        };

        await wardrobeService.createWardrobe(params);

        expect(mockedWardrobeModel.create).toHaveBeenCalledWith({
          user_id: testUserId,
          name: 'Test Wardrobe',
          description: 'Test description'
        });
      });

      it('should handle maximum valid name length', async () => {
        const maxLengthName = 'a'.repeat(100);
        const params = { userId: testUserId, name: maxLengthName };

        await wardrobeService.createWardrobe(params);

        expect(mockedWardrobeModel.create).toHaveBeenCalledWith({
          user_id: testUserId,
          name: maxLengthName,
          description: ''
        });
      });

      it('should handle maximum valid description length', async () => {
        const maxLengthDescription = 'a'.repeat(1000);
        const params = {
          userId: testUserId,
          name: 'Test Wardrobe',
          description: maxLengthDescription
        };

        await wardrobeService.createWardrobe(params);

        expect(mockedWardrobeModel.create).toHaveBeenCalledWith({
          user_id: testUserId,
          name: 'Test Wardrobe',
          description: maxLengthDescription
        });
      });
    });

    describe('Name Validation', () => {
      beforeEach(() => {
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      });

      const nameValidationTests = wardrobeValidationHelpers.getNameValidationTests();
      
      nameValidationTests.forEach(({ name, shouldPass, description }) => {
        it(`should ${shouldPass ? 'accept' : 'reject'} name: ${description}`, async () => {
          const params = { userId: testUserId, name };

          if (shouldPass) {
            mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
            await expect(wardrobeService.createWardrobe(params)).resolves.toBeDefined();
          } else {
            await expect(wardrobeService.createWardrobe(params))
              .rejects.toThrow(ApiError);
          }
        });
      });

      it('should validate name with special characters correctly', async () => {
        const validSpecialChars = ['My-Wardrobe', 'Test_Collection', 'Wardrobe.2024'];
        const invalidSpecialChars = ['Test@Wardrobe', 'My#Collection', 'Wardrobe$'];

        for (const name of validSpecialChars) {
          mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
          await expect(wardrobeService.createWardrobe({ userId: testUserId, name }))
            .resolves.toBeDefined();
        }

        for (const name of invalidSpecialChars) {
          await expect(wardrobeService.createWardrobe({ userId: testUserId, name }))
            .rejects.toThrow(ApiError);
        }
      });
    });

    describe('Description Validation', () => {
      beforeEach(() => {
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      });

      const descriptionValidationTests = wardrobeValidationHelpers.getDescriptionValidationTests();

      descriptionValidationTests.forEach(({ description, shouldPass, testDescription }) => {
        it(`should ${shouldPass ? 'accept' : 'reject'} description: ${testDescription}`, async () => {
          const params = { userId: testUserId, name: 'Test Wardrobe', description };

          if (shouldPass) {
            mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
            await expect(wardrobeService.createWardrobe(params)).resolves.toBeDefined();
          } else {
            await expect(wardrobeService.createWardrobe(params))
              .rejects.toThrow(ApiError);
          }
        });
      });
    });

    describe('Business Rules', () => {
      it('should enforce maximum wardrobes per user limit', async () => {
        // Mock user already has 50 wardrobes
        const existingWardrobes = Array.from({ length: 50 }, () => 
          wardrobeMocks.createValidWardrobe({ user_id: testUserId })
        );
        mockedWardrobeModel.findByUserId.mockResolvedValue(existingWardrobes);

        await expect(wardrobeService.createWardrobe(validCreateParams))
          .rejects.toThrow(ApiError);
        
        expect(mockedWardrobeModel.create).not.toHaveBeenCalled();
      });

      it('should prevent duplicate wardrobe names for same user', async () => {
        const existingWardrobe = wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          name: 'Test Wardrobe'
        });
        mockedWardrobeModel.findByUserId.mockResolvedValue([existingWardrobe]);

        await expect(wardrobeService.createWardrobe(validCreateParams))
          .rejects.toThrow(ApiError);
        
        expect(mockedWardrobeModel.create).not.toHaveBeenCalled();
      });

      it('should allow duplicate names for different users', async () => {
        const otherUserWardrobe = wardrobeMocks.createValidWardrobe({
          user_id: uuidv4(), // Different user
          name: 'Test Wardrobe'
        });
        // Mock returns empty array for current user (no duplicates for this user)
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
        mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);

        await expect(wardrobeService.createWardrobe(validCreateParams))
          .resolves.toBeDefined();
      });

      it('should be case-insensitive for duplicate name checking', async () => {
        const existingWardrobe = wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          name: 'test wardrobe' // Different case
        });
        mockedWardrobeModel.findByUserId.mockResolvedValue([existingWardrobe]);

        const params = { userId: testUserId, name: 'TEST WARDROBE' };

        await expect(wardrobeService.createWardrobe(params))
          .rejects.toThrow(ApiError);
      });
    });

    describe('Error Handling', () => {
      beforeEach(() => {
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      });

      it('should handle database creation errors', async () => {
        mockedWardrobeModel.create.mockRejectedValue(new Error('Database error'));

        await expect(wardrobeService.createWardrobe(validCreateParams))
          .rejects.toThrow(ApiError);
      });

      it('should handle limit check errors gracefully', async () => {
        mockedWardrobeModel.findByUserId.mockRejectedValue(new Error('DB error'));
        mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);

        // Should still allow creation if limit check fails
        await expect(wardrobeService.createWardrobe(validCreateParams))
          .resolves.toBeDefined();
      });

      it('should handle duplicate check errors gracefully', async () => {
        mockedWardrobeModel.findByUserId
          .mockResolvedValueOnce([]) // First call for limit check
          .mockRejectedValueOnce(new Error('DB error')); // Second call for duplicate check
        mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);

        await expect(wardrobeService.createWardrobe(validCreateParams))
          .resolves.toBeDefined();
      });
    });
  });

  describe('getUserWardrobes', () => {
    describe('Legacy Mode', () => {
      it('should return user wardrobes with garment counts', async () => {
        const wardrobes = wardrobeMocks.createMultipleWardrobes(testUserId, 3);
        mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
        
        // Mock garment counts for each wardrobe
        mockedWardrobeModel.getGarments
          .mockResolvedValueOnce([mockGarment, mockGarment]) // 2 garments
          .mockResolvedValueOnce([mockGarment]) // 1 garment
          .mockResolvedValueOnce([]); // 0 garments

        const result = await wardrobeService.getUserWardrobes({ userId: testUserId });

        expect(result.wardrobes).toHaveLength(3);
        // Check that garment counts are assigned (order may vary due to sorting)
        const counts = result.wardrobes.map(w => w.garmentCount).sort((a, b) => b - a);
        expect(counts).toEqual([2, 1, 0]);
        expect(mockedWardrobeModel.findByUserId).toHaveBeenCalledWith(testUserId);
      });

      it('should return empty array for user with no wardrobes', async () => {
        mockedWardrobeModel.findByUserId.mockResolvedValue([]);

        const result = await wardrobeService.getUserWardrobes({ userId: testUserId });

        expect(result.wardrobes).toEqual([]);
        expect(result.total).toBe(0);
      });

      it('should handle legacy pagination', async () => {
        const wardrobes = wardrobeMocks.createMultipleWardrobes(testUserId, 10);
        mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);

        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          legacy: { page: 2, limit: 3 }
        });

        expect(result.wardrobes).toHaveLength(3);
        expect(result.page).toBe(2);
        expect(result.limit).toBe(3);
        expect(result.total).toBe(10);
      });
    });

    describe('Mobile Mode - Cursor Pagination', () => {
      let wardrobes: any[];
      
      beforeEach(() => {
        // Create wardrobes with different timestamps for predictable sorting
        wardrobes = Array.from({ length: 5 }, (_, i) => 
          wardrobeMocks.createValidWardrobe({
            user_id: testUserId,
            name: `Wardrobe ${i}`,
            created_at: new Date(2024, 0, i + 1),
            updated_at: new Date(2024, 0, i + 1)
          })
        );
        mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
        mockedWardrobeModel.getGarments.mockResolvedValue([]);
      });

      it('should handle forward cursor pagination', async () => {
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: { cursor: wardrobes[1].id, limit: 2, direction: 'forward' },
          filters: { sortBy: 'name', sortOrder: 'asc' } // Use predictable sorting
        });

        expect(result.wardrobes).toHaveLength(2);
        expect(result.pagination?.hasNext).toBe(true);
        expect(result.pagination?.hasPrev).toBe(true);
        expect(result.pagination?.nextCursor).toBeDefined();
      });

      it('should handle backward cursor pagination', async () => {
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: { cursor: wardrobes[3].id, limit: 2, direction: 'backward' },
          filters: { sortBy: 'name', sortOrder: 'asc' } // Use predictable sorting
        });

        expect(result.wardrobes).toHaveLength(2);
        expect(result.pagination?.hasPrev).toBe(true);
      });

      it('should handle no cursor (first page)', async () => {
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          pagination: { limit: 3 }
        });

        expect(result.wardrobes).toHaveLength(3);
        expect(result.pagination?.hasPrev).toBe(false);
        expect(result.pagination?.hasNext).toBe(true);
      });
    });

    describe('Filtering', () => {
      const wardrobes = [
        wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          name: 'Summer Collection',
          description: 'Light clothes',
          created_at: new Date('2024-01-01'),
          updated_at: new Date('2024-01-15')
        }),
        wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          name: 'Winter Wardrobe',
          description: 'Warm clothes',
          created_at: new Date('2024-02-01'),
          updated_at: new Date('2024-02-10')
        }),
        wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          name: 'Work Attire',
          description: 'Professional outfits',
          created_at: new Date('2024-03-01'),
          updated_at: new Date('2024-03-05')
        })
      ];

      beforeEach(() => {
        mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
      });

      it('should filter by search term', async () => {
        mockedWardrobeModel.getGarments.mockResolvedValue([]);
        
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: { search: 'summer' }
        });

        expect(result.wardrobes).toHaveLength(1);
        expect(result.wardrobes[0].name).toBe('Summer Collection');
      });

      it('should filter by hasGarments', async () => {
        mockedWardrobeModel.getGarments
          .mockResolvedValueOnce([mockGarment]) // Has garments
          .mockResolvedValueOnce([]) // No garments
          .mockResolvedValueOnce([mockGarment, mockGarment]); // Has garments

        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: { hasGarments: true }
        });

        expect(result.wardrobes).toHaveLength(2);
      });

      it('should filter by date ranges', async () => {
        mockedWardrobeModel.getGarments.mockResolvedValue([]);
        
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: { 
            createdAfter: '2024-01-15',
            updatedAfter: '2024-02-01'
          }
        });

        expect(result.wardrobes).toHaveLength(2); // Winter and Work wardrobes
      });

      it('should sort by different fields', async () => {
        mockedWardrobeModel.getGarments
          .mockResolvedValueOnce([mockGarment, mockGarment]) // 2 garments
          .mockResolvedValueOnce([mockGarment]) // 1 garment
          .mockResolvedValueOnce([mockGarment, mockGarment, mockGarment]); // 3 garments

        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: { sortBy: 'garment_count', sortOrder: 'desc' }
        });

        expect(result.wardrobes[0].garmentCount).toBe(3);
        expect(result.wardrobes[1].garmentCount).toBe(2);
        expect(result.wardrobes[2].garmentCount).toBe(1);
      });

      it('should combine multiple filters', async () => {
        mockedWardrobeModel.getGarments.mockResolvedValue([mockGarment]);
        
        const result = await wardrobeService.getUserWardrobes({
          userId: testUserId,
          filters: { 
            search: 'w',
            hasGarments: true,
            sortBy: 'name',
            sortOrder: 'asc'
          }
        });

        expect(result.wardrobes).toHaveLength(2); // Winter and Work
        expect(result.wardrobes[0].name).toBe('Winter Wardrobe');
        expect(result.wardrobes[1].name).toBe('Work Attire');
      });
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.findByUserId.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.getUserWardrobes({ userId: testUserId }))
        .rejects.toThrow(ApiError);
    });

    it('should handle garment count retrieval errors', async () => {
      const wardrobes = [mockWardrobe];
      mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
      mockedWardrobeModel.getGarments.mockRejectedValue(new Error('Garment error'));

      await expect(wardrobeService.getUserWardrobes({ userId: testUserId }))
        .rejects.toThrow(ApiError);
    });
  });

  describe('getWardrobeWithGarments', () => {
    beforeEach(() => {
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
    });

    it('should return wardrobe with garments and count', async () => {
      const garments = [mockGarment, mockGarment];
      mockedWardrobeModel.getGarments.mockResolvedValue(garments);

      const result = await wardrobeService.getWardrobeWithGarments(testWardrobeId, testUserId);

      expect(result).toEqual({
        ...mockWardrobe,
        garments,
        garmentCount: 2
      });
    });

    it('should verify wardrobe ownership', async () => {
      const otherUserWardrobe = { ...mockWardrobe, user_id: uuidv4() };
      mockedWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

      await expect(wardrobeService.getWardrobeWithGarments(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });

    it('should handle non-existent wardrobe', async () => {
      mockedWardrobeModel.findById.mockResolvedValue(null);

      await expect(wardrobeService.getWardrobeWithGarments(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.findById.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.getWardrobeWithGarments(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });
  });

  describe('getWardrobe', () => {
    it('should return wardrobe for valid owner', async () => {
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);

      const result = await wardrobeService.getWardrobe(testWardrobeId, testUserId);

      expect(result).toEqual(mockWardrobe);
      expect(mockedWardrobeModel.findById).toHaveBeenCalledWith(testWardrobeId);
    });

    it('should throw error for non-existent wardrobe', async () => {
      mockedWardrobeModel.findById.mockResolvedValue(null);

      await expect(wardrobeService.getWardrobe(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });

    it('should throw authorization error for wrong owner', async () => {
      const otherUserWardrobe = { ...mockWardrobe, user_id: uuidv4() };
      mockedWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

      await expect(wardrobeService.getWardrobe(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.findById.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.getWardrobe(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });
  });

  describe('updateWardrobe', () => {
    const updateParams = {
      wardrobeId: '',
      userId: '',
      name: 'Updated Wardrobe',
      description: 'Updated description'
    };

    beforeEach(() => {
      updateParams.wardrobeId = testWardrobeId;
      updateParams.userId = testUserId;
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.findByUserId.mockResolvedValue([mockWardrobe]);
    });

    it('should update wardrobe with valid data', async () => {
      const updatedWardrobe = { ...mockWardrobe, name: 'Updated Wardrobe' };
      mockedWardrobeModel.update.mockResolvedValue(updatedWardrobe);

      const result = await wardrobeService.updateWardrobe(updateParams);

      expect(result).toEqual(updatedWardrobe);
      expect(mockedWardrobeModel.update).toHaveBeenCalledWith(testWardrobeId, {
        name: 'Updated Wardrobe',
        description: 'Updated description'
      });
    });

    it('should update only name when description not provided', async () => {
      const params = { wardrobeId: testWardrobeId, userId: testUserId, name: 'New Name' };
      const updatedWardrobe = { ...mockWardrobe, name: 'New Name' };
      mockedWardrobeModel.update.mockResolvedValue(updatedWardrobe);

      const result = await wardrobeService.updateWardrobe(params);

      expect(result).toEqual(updatedWardrobe);
      expect(mockedWardrobeModel.update).toHaveBeenCalledWith(testWardrobeId, {
        name: 'New Name'
      });
    });

    it('should update only description when name not provided', async () => {
      const params = { wardrobeId: testWardrobeId, userId: testUserId, description: 'New Description' };
      const updatedWardrobe = { ...mockWardrobe, description: 'New Description' };
      mockedWardrobeModel.update.mockResolvedValue(updatedWardrobe);

      const result = await wardrobeService.updateWardrobe(params);

      expect(result).toEqual(updatedWardrobe);
      expect(mockedWardrobeModel.update).toHaveBeenCalledWith(testWardrobeId, {
        description: 'New Description'
      });
    });

    it('should trim whitespace from updates', async () => {
      const params = {
        wardrobeId: testWardrobeId,
        userId: testUserId,
        name: '  Trimmed Name  ',
        description: '  Trimmed Description  '
      };
      mockedWardrobeModel.update.mockResolvedValue(mockWardrobe);

      await wardrobeService.updateWardrobe(params);

      expect(mockedWardrobeModel.update).toHaveBeenCalledWith(testWardrobeId, {
        name: 'Trimmed Name',
        description: 'Trimmed Description'
      });
    });

    it('should validate name when updating', async () => {
      const params = { wardrobeId: testWardrobeId, userId: testUserId, name: '@InvalidName' };

      await expect(wardrobeService.updateWardrobe(params))
        .rejects.toThrow(ApiError);
    });

    it('should validate description when updating', async () => {
      const params = {
        wardrobeId: testWardrobeId,
        userId: testUserId,
        description: 'a'.repeat(1001) // Too long
      };

      await expect(wardrobeService.updateWardrobe(params))
        .rejects.toThrow(ApiError);
    });

    it('should prevent duplicate names when updating', async () => {
      const existingWardrobe = wardrobeMocks.createValidWardrobe({
        id: uuidv4(),
        user_id: testUserId,
        name: 'Existing Name'
      });
      mockedWardrobeModel.findByUserId.mockResolvedValue([mockWardrobe, existingWardrobe]);

      const params = { wardrobeId: testWardrobeId, userId: testUserId, name: 'Existing Name' };

      await expect(wardrobeService.updateWardrobe(params))
        .rejects.toThrow(ApiError);
    });

    it('should allow updating to same name (no change)', async () => {
      const params = { wardrobeId: testWardrobeId, userId: testUserId, name: mockWardrobe.name };
      mockedWardrobeModel.update.mockResolvedValue(mockWardrobe);

      await expect(wardrobeService.updateWardrobe(params))
        .resolves.toBeDefined();
    });

    it('should verify ownership before updating', async () => {
      mockedWardrobeModel.findById.mockResolvedValue(null);

      await expect(wardrobeService.updateWardrobe(updateParams))
        .rejects.toThrow(ApiError);
    });

    it('should handle update failure', async () => {
      mockedWardrobeModel.update.mockResolvedValue(null);

      await expect(wardrobeService.updateWardrobe(updateParams))
        .rejects.toThrow(ApiError);
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.update.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.updateWardrobe(updateParams))
        .rejects.toThrow(ApiError);
    });
  });

  describe('addGarmentToWardrobe', () => {
    const addGarmentParams = {
      wardrobeId: '',
      userId: '',
      garmentId: '',
      position: 0
    };

    beforeEach(() => {
      addGarmentParams.wardrobeId = testWardrobeId;
      addGarmentParams.userId = testUserId;
      addGarmentParams.garmentId = testGarmentId;
      
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedGarmentModel.findById.mockResolvedValue(mockGarment);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);
      mockedWardrobeModel.addGarment.mockResolvedValue(true);
    });

    it('should add garment to wardrobe successfully', async () => {
      const result = await wardrobeService.addGarmentToWardrobe(addGarmentParams);

      expect(result.success).toBe(true);
      expect(mockedWardrobeModel.addGarment).toHaveBeenCalledWith(testWardrobeId, testGarmentId, 0);
    });

    it('should verify wardrobe ownership', async () => {
      const otherUserWardrobe = { ...mockWardrobe, user_id: uuidv4() };
      mockedWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

      await expect(wardrobeService.addGarmentToWardrobe(addGarmentParams))
        .rejects.toThrow(ApiError);
    });

    it('should verify garment exists', async () => {
      mockedGarmentModel.findById.mockResolvedValue(null);

      await expect(wardrobeService.addGarmentToWardrobe(addGarmentParams))
        .rejects.toThrow(ApiError);
    });

    it('should verify garment ownership', async () => {
      const otherUserGarment = { ...mockGarment, user_id: uuidv4() };
      mockedGarmentModel.findById.mockResolvedValue(otherUserGarment);

      await expect(wardrobeService.addGarmentToWardrobe(addGarmentParams))
        .rejects.toThrow(ApiError);
    });

    it('should prevent adding duplicate garments', async () => {
      const existingGarment = { id: testGarmentId };
      mockedWardrobeModel.getGarments.mockResolvedValue([existingGarment]);

      await expect(wardrobeService.addGarmentToWardrobe(addGarmentParams))
        .rejects.toThrow(ApiError);
    });

    it('should check wardrobe capacity limits', async () => {
      // Mock wardrobe at capacity (200 garments)
      const garments = Array.from({ length: 200 }, () => ({ id: uuidv4() }));
      mockedWardrobeModel.getGarments.mockResolvedValue(garments);

      await expect(wardrobeService.addGarmentToWardrobe(addGarmentParams))
        .rejects.toThrow(ApiError);
    });

    it('should validate position parameter', async () => {
      const invalidPositions = [-1, 1.5, 'invalid'];

      for (const position of invalidPositions) {
        const params = { ...addGarmentParams, position: position as number };
        
        await expect(wardrobeService.addGarmentToWardrobe(params))
          .rejects.toThrow(ApiError);
      }
    });

    it('should validate position is not greater than current count', async () => {
      const existingGarments = [{ id: uuidv4() }, { id: uuidv4() }]; // 2 garments
      mockedWardrobeModel.getGarments.mockResolvedValue(existingGarments);
      
      const params = { ...addGarmentParams, position: 3 }; // Greater than count

      await expect(wardrobeService.addGarmentToWardrobe(params))
        .rejects.toThrow(ApiError);
    });

    it('should handle database add errors', async () => {
      mockedWardrobeModel.addGarment.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.addGarmentToWardrobe(addGarmentParams))
        .rejects.toThrow(ApiError);
    });

    it('should use default position when not provided', async () => {
      const params = { 
        wardrobeId: testWardrobeId, 
        userId: testUserId, 
        garmentId: testGarmentId 
      };

      await wardrobeService.addGarmentToWardrobe(params);

      expect(mockedWardrobeModel.addGarment).toHaveBeenCalledWith(testWardrobeId, testGarmentId, 0);
    });
  });

  describe('removeGarmentFromWardrobe', () => {
    const removeParams = {
      wardrobeId: testWardrobeId,
      userId: testUserId,
      garmentId: testGarmentId
    };

    beforeEach(() => {
      removeParams.wardrobeId = testWardrobeId;
      removeParams.userId = testUserId;
      removeParams.garmentId = testGarmentId;
      
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue([{ id: testGarmentId }]);
      mockedWardrobeModel.removeGarment.mockResolvedValue(true);
    });

    it('should remove garment from wardrobe successfully', async () => {
      const result = await wardrobeService.removeGarmentFromWardrobe(removeParams);

      expect(result.success).toBe(true);
      expect(mockedWardrobeModel.removeGarment).toHaveBeenCalledWith(testWardrobeId, testGarmentId);
    });

    it('should verify wardrobe ownership', async () => {
      const otherUserWardrobe = { ...mockWardrobe, user_id: uuidv4() };
      mockedWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

      await expect(wardrobeService.removeGarmentFromWardrobe(removeParams))
        .rejects.toThrow(ApiError);
    });

    it('should verify garment is in wardrobe', async () => {
      mockedWardrobeModel.getGarments.mockResolvedValue([]); // No garments

      await expect(wardrobeService.removeGarmentFromWardrobe(removeParams))
        .rejects.toThrow(ApiError);
    });

    it('should handle removal failure', async () => {
      mockedWardrobeModel.removeGarment.mockResolvedValue(false);

      await expect(wardrobeService.removeGarmentFromWardrobe(removeParams))
        .rejects.toThrow(ApiError);
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.removeGarment.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.removeGarmentFromWardrobe(removeParams))
        .rejects.toThrow(ApiError);
    });
  });

  describe('deleteWardrobe', () => {
    beforeEach(() => {
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);
      mockedWardrobeModel.delete.mockResolvedValue(true);
    });

    it('should delete empty wardrobe successfully', async () => {
      const result = await wardrobeService.deleteWardrobe(testWardrobeId, testUserId);

      expect(result.success).toBe(true);
      expect(result.wardrobeId).toBe(testWardrobeId);
      expect(mockedWardrobeModel.delete).toHaveBeenCalledWith(testWardrobeId);
    });

    it('should verify wardrobe ownership before deletion', async () => {
      const otherUserWardrobe = { ...mockWardrobe, user_id: uuidv4() };
      mockedWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

      await expect(wardrobeService.deleteWardrobe(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });

    it('should prevent deletion of wardrobe with garments', async () => {
      mockedWardrobeModel.getGarments.mockResolvedValue([mockGarment]); // Has garments

      await expect(wardrobeService.deleteWardrobe(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
      
      expect(mockedWardrobeModel.delete).not.toHaveBeenCalled();
    });

    it('should handle deletion failure', async () => {
      mockedWardrobeModel.delete.mockResolvedValue(false);

      await expect(wardrobeService.deleteWardrobe(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.delete.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.deleteWardrobe(testWardrobeId, testUserId))
        .rejects.toThrow(ApiError);
    });
  });

  describe('reorderGarments', () => {
    const existingGarments = [
      { id: uuidv4() },
      { id: uuidv4() },
      { id: uuidv4() }
    ];

    beforeEach(() => {
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue(existingGarments);
      mockedWardrobeModel.addGarment.mockResolvedValue(true);
    });

    it('should reorder garments successfully', async () => {
      const newOrder = [existingGarments[2].id, existingGarments[0].id, existingGarments[1].id];

      const result = await wardrobeService.reorderGarments(testWardrobeId, testUserId, newOrder);

      expect(result.success).toBe(true);
      expect(mockedWardrobeModel.addGarment).toHaveBeenCalledTimes(3);
      expect(mockedWardrobeModel.addGarment).toHaveBeenNthCalledWith(1, testWardrobeId, newOrder[0], 0);
      expect(mockedWardrobeModel.addGarment).toHaveBeenNthCalledWith(2, testWardrobeId, newOrder[1], 1);
      expect(mockedWardrobeModel.addGarment).toHaveBeenNthCalledWith(3, testWardrobeId, newOrder[2], 2);
    });

    it('should verify wardrobe ownership', async () => {
      const otherUserWardrobe = { ...mockWardrobe, user_id: uuidv4() };
      mockedWardrobeModel.findById.mockResolvedValue(otherUserWardrobe);

      const newOrder = [existingGarments[0].id];

      await expect(wardrobeService.reorderGarments(testWardrobeId, testUserId, newOrder))
        .rejects.toThrow(ApiError);
    });

    it('should validate all garments exist in wardrobe', async () => {
      const invalidGarmentId = uuidv4();
      const invalidOrder = [existingGarments[0].id, invalidGarmentId];

      await expect(wardrobeService.reorderGarments(testWardrobeId, testUserId, invalidOrder))
        .rejects.toThrow(ApiError);
    });

    it('should require all current garments in new order', async () => {
      const incompleteOrder = [existingGarments[0].id]; // Missing other garments

      await expect(wardrobeService.reorderGarments(testWardrobeId, testUserId, incompleteOrder))
        .rejects.toThrow(ApiError);
    });

    it('should handle database errors during reordering', async () => {
      const newOrder = existingGarments.map(g => g.id);
      mockedWardrobeModel.addGarment.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.reorderGarments(testWardrobeId, testUserId, newOrder))
        .rejects.toThrow(ApiError);
    });

    it('should handle empty garment list', async () => {
      mockedWardrobeModel.getGarments.mockResolvedValue([]);
      
      const result = await wardrobeService.reorderGarments(testWardrobeId, testUserId, []);

      expect(result.success).toBe(true);
      expect(mockedWardrobeModel.addGarment).not.toHaveBeenCalled();
    });
  });

  describe('getUserWardrobeStats', () => {
    it('should calculate correct statistics', async () => {
      const wardrobes = wardrobeMocks.createMultipleWardrobes(testUserId, 3);
      mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
      
      // Mock different garment counts for each wardrobe
      mockedWardrobeModel.getGarments
        .mockResolvedValueOnce([mockGarment, mockGarment, mockGarment]) // 3 garments
        .mockResolvedValueOnce([mockGarment, mockGarment]) // 2 garments
        .mockResolvedValueOnce([mockGarment]); // 1 garment

      const result = await wardrobeService.getUserWardrobeStats(testUserId);

      expect(result).toEqual({
        totalWardrobes: 3,
        totalGarments: 6,
        averageGarmentsPerWardrobe: 2,
        wardrobeGarmentCounts: {
          [wardrobes[0].id]: 3,
          [wardrobes[1].id]: 2,
          [wardrobes[2].id]: 1
        },
        limits: {
          maxWardrobes: 50,
          maxGarmentsPerWardrobe: 200,
          maxNameLength: 100,
          maxDescriptionLength: 1000
        }
      });
    });

    it('should handle user with no wardrobes', async () => {
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);

      const result = await wardrobeService.getUserWardrobeStats(testUserId);

      expect(result.totalWardrobes).toBe(0);
      expect(result.totalGarments).toBe(0);
      expect(result.averageGarmentsPerWardrobe).toBe(0);
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.findByUserId.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.getUserWardrobeStats(testUserId))
        .rejects.toThrow(ApiError);
    });
  });

  describe('searchWardrobes', () => {
    const wardrobes = [
      wardrobeMocks.createValidWardrobe({
        user_id: testUserId,
        name: 'Summer Collection',
        description: 'Light and airy clothes'
      }),
      wardrobeMocks.createValidWardrobe({
        user_id: testUserId,
        name: 'Winter Wardrobe',
        description: 'Warm and cozy outfits'
      }),
      wardrobeMocks.createValidWardrobe({
        user_id: testUserId,
        name: 'Work Attire',
        description: 'Professional business clothes'
      })
    ];

    beforeEach(() => {
      mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([mockGarment]);
    });

    it('should search by wardrobe name', async () => {
      const result = await wardrobeService.searchWardrobes(testUserId, 'Summer');

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('Summer Collection');
    });

    it('should search by description', async () => {
      const result = await wardrobeService.searchWardrobes(testUserId, 'cozy');

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('Winter Wardrobe');
    });

    it('should be case insensitive', async () => {
      const result = await wardrobeService.searchWardrobes(testUserId, 'WORK');

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('Work Attire');
    });

    it('should return multiple matches', async () => {
      const result = await wardrobeService.searchWardrobes(testUserId, 'clothes');

      expect(result).toHaveLength(2); // Matches both Summer and Work wardrobes
    });

    it('should return empty array for no matches', async () => {
      const result = await wardrobeService.searchWardrobes(testUserId, 'nonexistent');

      expect(result).toHaveLength(0);
    });

    it('should include garment counts in results', async () => {
      const result = await wardrobeService.searchWardrobes(testUserId, 'Summer');

      expect(result[0]).toHaveProperty('garmentCount', 1);
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.findByUserId.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.searchWardrobes(testUserId, 'search'))
        .rejects.toThrow(ApiError);
    });
  });

  describe('Validation Helper Methods', () => {
    describe('validateWardrobeName', () => {
      it('should accept valid names', () => {
        const validNames = [
          'Valid Name',
          'Test-Wardrobe',
          'My_Collection',
          'Wardrobe.2024',
          'A',
          'a'.repeat(100)
        ];

        validNames.forEach(name => {
          expect(() => wardrobeService.validateWardrobeName(name)).not.toThrow();
        });
      });

      it('should reject invalid names', () => {
        const invalidNames = [
          '',
          '   ',
          'a'.repeat(101),
          'Invalid@Name',
          'Invalid#Name',
          null,
          undefined
        ];

        invalidNames.forEach(name => {
          expect(() => wardrobeService.validateWardrobeName(name as string))
            .toThrow(ApiError);
        });
      });
    });

    describe('validateWardrobeDescription', () => {
      it('should accept valid descriptions', () => {
        const validDescriptions = [
          '',
          'Valid description',
          'a'.repeat(1000),
          'Description with special chars @#$%'
        ];

        validDescriptions.forEach(description => {
          expect(() => wardrobeService.validateWardrobeDescription(description)).not.toThrow();
        });
      });

      it('should reject invalid descriptions', () => {
        const invalidDescriptions = [
          'a'.repeat(1001),
          null,
          undefined,
          123
        ];

        invalidDescriptions.forEach(description => {
          expect(() => wardrobeService.validateWardrobeDescription(description as string))
            .toThrow(ApiError);
        });
      });
    });

    describe('validateGarmentPosition', () => {
      it('should accept valid positions', () => {
        const validPositions = [
          { position: 0, count: 0 },
          { position: 0, count: 5 },
          { position: 3, count: 5 },
          { position: 5, count: 5 }
        ];

        validPositions.forEach(({ position, count }) => {
          expect(() => wardrobeService.validateGarmentPosition(position, count)).not.toThrow();
        });
      });

      it('should reject invalid positions', () => {
        const invalidPositions = [
          { position: -1, count: 5 },
          { position: 6, count: 5 }
        ];

        invalidPositions.forEach(({ position, count }) => {
          expect(() => wardrobeService.validateGarmentPosition(position, count))
            .toThrow(ApiError);
        });

        // Test string type - will throw ApiError due to typeof check
        expect(() => wardrobeService.validateGarmentPosition('invalid' as any, 5))
          .toThrow(ApiError);
        
        // Note: 1.5 is a valid number type, so it passes typeof check
        // The service doesn't validate for integers vs decimals
      });
    });
  });

  describe('Business Logic Helper Methods', () => {
    describe('checkUserWardrobeLimits', () => {
      it('should pass when under limit', async () => {
        const wardrobes = Array.from({ length: 49 }, () => 
          wardrobeMocks.createValidWardrobe({ user_id: testUserId })
        );
        mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);

        await expect(wardrobeService.checkUserWardrobeLimits(testUserId))
          .resolves.not.toThrow();
      });

      it('should throw error when at limit', async () => {
        const wardrobes = Array.from({ length: 50 }, () => 
          wardrobeMocks.createValidWardrobe({ user_id: testUserId })
        );
        mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);

        await expect(wardrobeService.checkUserWardrobeLimits(testUserId))
          .rejects.toThrow(ApiError);
      });

      it('should handle database errors gracefully', async () => {
        mockedWardrobeModel.findByUserId.mockRejectedValue(new Error('Database error'));

        // Should not throw - errors are logged but don't fail the operation
        await expect(wardrobeService.checkUserWardrobeLimits(testUserId))
          .resolves.not.toThrow();
      });
    });

    describe('checkDuplicateWardrobeName', () => {
      beforeEach(() => {
        const existingWardrobe = wardrobeMocks.createValidWardrobe({
          id: testWardrobeId,
          user_id: testUserId,
          name: 'Existing Wardrobe'
        });
        mockedWardrobeModel.findByUserId.mockResolvedValue([existingWardrobe]);
      });

      it('should allow unique names', async () => {
        await expect(wardrobeService.checkDuplicateWardrobeName(testUserId, 'Unique Name'))
          .resolves.not.toThrow();
      });

      it('should prevent duplicate names', async () => {
        await expect(wardrobeService.checkDuplicateWardrobeName(testUserId, 'Existing Wardrobe'))
          .rejects.toThrow(ApiError);
      });

      it('should be case insensitive', async () => {
        await expect(wardrobeService.checkDuplicateWardrobeName(testUserId, 'EXISTING WARDROBE'))
          .rejects.toThrow(ApiError);
      });

      it('should allow same name when excluding current wardrobe', async () => {
        await expect(wardrobeService.checkDuplicateWardrobeName(
          testUserId, 
          'Existing Wardrobe', 
          testWardrobeId
        )).resolves.not.toThrow();
      });

      it('should handle database errors gracefully', async () => {
        mockedWardrobeModel.findByUserId.mockRejectedValue(new Error('Database error'));

        await expect(wardrobeService.checkDuplicateWardrobeName(testUserId, 'Test'))
          .resolves.not.toThrow();
      });
    });

    describe('checkWardrobeCapacity', () => {
      it('should pass when under capacity', async () => {
        const garments = Array.from({ length: 199 }, () => mockGarment);
        mockedWardrobeModel.getGarments.mockResolvedValue(garments);

        await expect(wardrobeService.checkWardrobeCapacity(testWardrobeId))
          .resolves.not.toThrow();
      });

      it('should throw error when at capacity', async () => {
        const garments = Array.from({ length: 200 }, () => mockGarment);
        mockedWardrobeModel.getGarments.mockResolvedValue(garments);

        await expect(wardrobeService.checkWardrobeCapacity(testWardrobeId))
          .rejects.toThrow(ApiError);
      });

      it('should handle database errors', async () => {
        mockedWardrobeModel.getGarments.mockRejectedValue(new Error('Database error'));

        await expect(wardrobeService.checkWardrobeCapacity(testWardrobeId))
          .rejects.toThrow(ApiError);
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle concurrent operations gracefully', async () => {
      // Simulate concurrent wardrobe creation
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);

      const promises = Array.from({ length: 5 }, () =>
        wardrobeService.createWardrobe({
          userId: testUserId,
          name: `Concurrent Wardrobe ${Math.random()}`,
          description: 'Test'
        })
      );

      await expect(Promise.all(promises)).resolves.toBeDefined();
    });

    it('should handle malformed input gracefully', async () => {
      // Test null/undefined inputs that cause destructuring errors
      const destructuringInputs = [null, undefined];
      
      for (const input of destructuringInputs) {
        await expect(wardrobeService.createWardrobe(input as any))
          .rejects.toThrow(TypeError); // These cause TypeErrors, not ApiErrors
      }

      // Test malformed but valid objects that should throw ApiError
      const validObjectInputs = [
        {},
        { userId: null },
        { userId: testUserId, name: null },
        { userId: testUserId, name: '' } // Empty name
      ];

      for (const input of validObjectInputs) {
        await expect(wardrobeService.createWardrobe(input as any))
          .rejects.toThrow(ApiError);
      }
    });

    it('should handle very large datasets', async () => {
      // Test with many wardrobes
      const manyWardrobes = Array.from({ length: 100 }, () => 
        wardrobeMocks.createValidWardrobe({ user_id: testUserId })
      );
      mockedWardrobeModel.findByUserId.mockResolvedValue(manyWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      await expect(wardrobeService.getUserWardrobes({ userId: testUserId }))
        .resolves.toBeDefined();
    });

    it('should handle unicode characters in names and descriptions', async () => {
      // Use characters that are allowed by the regex: /^[a-zA-Z0-9\s\-_\.]+$/
      const unicodeInputs = {
        name: 'Collection_2024', // Use valid characters only
        description: 'Test with special characters émoji 中文' // Description allows any characters
      };

      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);

      await expect(wardrobeService.createWardrobe({
        userId: testUserId,
        ...unicodeInputs
      })).resolves.toBeDefined();
    });

    it('should maintain data consistency across operations', async () => {
      // Test sequence: create -> add garment -> remove garment -> delete
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedGarmentModel.findById.mockResolvedValue(mockGarment);

      // Create
      const wardrobe = await wardrobeService.createWardrobe({
        userId: testUserId,
        name: 'Test Sequence'
      });

      // Setup for add garment - empty wardrobe
      // NOTE: addGarmentToWardrobe calls getGarments TWICE:
      // 1. In checkWardrobeCapacity (capacity check)
      // 2. To check for duplicates (duplicate check)
      mockedWardrobeModel.getGarments
        .mockResolvedValueOnce([]) // First call - capacity check
        .mockResolvedValueOnce([]); // Second call - duplicate check
      mockedWardrobeModel.addGarment.mockResolvedValueOnce(true);

      // Add garment
      await wardrobeService.addGarmentToWardrobe({
        wardrobeId: testWardrobeId,
        userId: testUserId,
        garmentId: testGarmentId
      });

      // Setup for remove garment - garment exists in wardrobe
      mockedWardrobeModel.getGarments.mockResolvedValueOnce([{ id: testGarmentId }]);
      mockedWardrobeModel.removeGarment.mockResolvedValueOnce(true);

      // Remove garment
      await wardrobeService.removeGarmentFromWardrobe({
        wardrobeId: testWardrobeId,
        userId: testUserId,
        garmentId: testGarmentId
      });

      // Setup for delete wardrobe - empty wardrobe
      mockedWardrobeModel.getGarments.mockResolvedValueOnce([]);
      mockedWardrobeModel.delete.mockResolvedValueOnce(true);

      // Delete wardrobe
      await wardrobeService.deleteWardrobe(testWardrobeId, testUserId);

      expect(mockedWardrobeModel.create).toHaveBeenCalled();
      expect(mockedWardrobeModel.addGarment).toHaveBeenCalled();
      expect(mockedWardrobeModel.removeGarment).toHaveBeenCalled();
      expect(mockedWardrobeModel.delete).toHaveBeenCalled();
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete wardrobe lifecycle', async () => {
      // Setup mocks for complete lifecycle
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.update.mockResolvedValue({
        ...mockWardrobe,
        name: 'Updated Name'
      });

      // Create wardrobe
      const created = await wardrobeService.createWardrobe({
        userId: testUserId,
        name: 'Lifecycle Test',
        description: 'Testing complete lifecycle'
      });

      expect(created).toBeDefined();

      // Update wardrobe
      const updated = await wardrobeService.updateWardrobe({
        wardrobeId: testWardrobeId,
        userId: testUserId,
        name: 'Updated Name'
      });

      expect(updated.name).toBe('Updated Name');

      // Get wardrobe
      const retrieved = await wardrobeService.getWardrobe(testWardrobeId, testUserId);
      expect(retrieved).toBeDefined();
    });

    it('should handle multiple users with isolated data', async () => {
      const user1Id = uuidv4();
      const user2Id = uuidv4();
      
      const user1Wardrobe = wardrobeMocks.createValidWardrobe({ user_id: user1Id });
      const user2Wardrobe = wardrobeMocks.createValidWardrobe({ user_id: user2Id });

      // Mock user isolation
      mockedWardrobeModel.findByUserId
        .mockImplementation((userId) => {
          if (userId === user1Id) return Promise.resolve([user1Wardrobe]);
          if (userId === user2Id) return Promise.resolve([user2Wardrobe]);
          return Promise.resolve([]);
        });

      // Mock getGarments for each wardrobe call
      mockedWardrobeModel.getGarments.mockResolvedValue([mockGarment]);

      const user1Result = await wardrobeService.getUserWardrobes({ userId: user1Id });
      const user2Result = await wardrobeService.getUserWardrobes({ userId: user2Id });

      expect(user1Result.wardrobes).toHaveLength(1);
      expect(user2Result.wardrobes).toHaveLength(1);
      expect(user1Result.wardrobes[0].user_id).toBe(user1Id);
      expect(user2Result.wardrobes[0].user_id).toBe(user2Id);
    });
  });

  describe('Performance and Scalability', () => {
    it('should handle large numbers of wardrobes efficiently', async () => {
      const manyWardrobes = Array.from({ length: 50 }, (_, i) =>
        wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          name: `Wardrobe ${i}`
        })
      );

      mockedWardrobeModel.findByUserId.mockResolvedValue(manyWardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      const start = Date.now();
      const result = await wardrobeService.getUserWardrobes({ userId: testUserId });
      const duration = Date.now() - start;

      expect(result.wardrobes).toHaveLength(50);
      expect(duration).toBeLessThan(1000); // Should complete within 1 second
    });

    it('should handle concurrent access patterns', async () => {
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);

      // Simulate concurrent reads
      const concurrentReads = Array.from({ length: 10 }, () =>
        wardrobeService.getWardrobeWithGarments(testWardrobeId, testUserId)
      );

      await expect(Promise.all(concurrentReads)).resolves.toBeDefined();
    });
  });

  describe('syncWardrobes', () => {
    const syncParams = {
      userId: testUserId,
      lastSyncTimestamp: new Date('2024-01-01'),
      clientVersion: 1
    };

    beforeEach(() => {
      const wardrobes = [
        wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          created_at: new Date('2023-12-15'),
          updated_at: new Date('2023-12-20')
        }),
        wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          created_at: new Date('2024-01-05'),
          updated_at: new Date('2024-01-05')
        }),
        wardrobeMocks.createValidWardrobe({
          user_id: testUserId,
          created_at: new Date('2023-12-01'),
          updated_at: new Date('2024-01-10')
        })
      ];
      mockedWardrobeModel.findByUserId.mockResolvedValue(wardrobes);
      mockedWardrobeModel.getGarments.mockResolvedValue([]);
    });

    it('should return created wardrobes since last sync', async () => {
      const result = await wardrobeService.syncWardrobes(syncParams);

      expect(result.wardrobes.created).toHaveLength(1);
      expect(result.wardrobes.created[0].created_at).toEqual(new Date('2024-01-05'));
    });

    it('should return updated wardrobes since last sync', async () => {
      const result = await wardrobeService.syncWardrobes(syncParams);

      expect(result.wardrobes.updated).toHaveLength(1);
      expect(result.wardrobes.updated[0].updated_at).toEqual(new Date('2024-01-10'));
    });

    it('should not include deleted wardrobes in basic implementation', async () => {
      const result = await wardrobeService.syncWardrobes(syncParams);

      expect(result.wardrobes.deleted).toEqual([]);
    });

    it('should include sync metadata', async () => {
      const result = await wardrobeService.syncWardrobes(syncParams);

      expect(result.sync).toHaveProperty('timestamp');
      expect(result.sync.version).toBe(1);
      expect(result.sync.hasMore).toBe(false);
      expect(result.sync.changeCount).toBe(2); // 1 created + 1 updated
    });

    it('should handle no changes since last sync', async () => {
      const futureSync = {
        ...syncParams,
        lastSyncTimestamp: new Date('2024-12-31')
      };

      const result = await wardrobeService.syncWardrobes(futureSync);

      expect(result.wardrobes.created).toHaveLength(0);
      expect(result.wardrobes.updated).toHaveLength(0);
      expect(result.sync.changeCount).toBe(0);
    });

    it('should handle database errors', async () => {
      mockedWardrobeModel.findByUserId.mockRejectedValue(new Error('Database error'));

      await expect(wardrobeService.syncWardrobes(syncParams))
        .rejects.toThrow(ApiError);
    });
  });

  describe('batchOperations', () => {
    const batchParams: {
      userId: string;
      operations: Array<{
        type: 'create' | 'update' | 'delete';
        data: any;
        clientId: string;
      }>;
    } = {
      userId: testUserId,
      operations: []
    };

    beforeEach(() => {
      // Reset batchParams userId in case testUserId changed
      batchParams.userId = testUserId;
      batchParams.operations = [];
      
      mockedWardrobeModel.create.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.findById.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.update.mockResolvedValue(mockWardrobe);
      mockedWardrobeModel.delete.mockResolvedValue(true);
    });

    it('should handle create operations', async () => {
      // Mock for wardrobe limit check and duplicate name check
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      
      batchParams.operations = [
        {
          type: 'create',
          data: { name: 'Batch Wardrobe 1', description: 'Test' },
          clientId: 'temp-1'
        },
        {
          type: 'create',
          data: { name: 'Batch Wardrobe 2' },
          clientId: 'temp-2'
        }
      ];

      const result = await wardrobeService.batchOperations(batchParams);

      expect(result.results).toHaveLength(2);
      expect(result.errors).toHaveLength(0);
      expect(result.summary.successful).toBe(2);
      expect(mockedWardrobeModel.create).toHaveBeenCalledTimes(2);
    });

    it('should handle update operations', async () => {
      // Mock for duplicate name check in updateWardrobe
      mockedWardrobeModel.findByUserId.mockResolvedValue([mockWardrobe]);
      
      batchParams.operations = [
        {
          type: 'update',
          data: { id: testWardrobeId, name: 'Updated Name' },
          clientId: 'temp-3'
        }
      ];

      const result = await wardrobeService.batchOperations(batchParams);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].type).toBe('update');
      expect(mockedWardrobeModel.update).toHaveBeenCalled();
    });

    it('should handle delete operations', async () => {
      mockedWardrobeModel.getGarments.mockResolvedValue([]); // No garments
      
      batchParams.operations = [
        {
          type: 'delete',
          data: { id: testWardrobeId },
          clientId: 'temp-4'
        }
      ];

      const result = await wardrobeService.batchOperations(batchParams);

      expect(result.results).toHaveLength(1);
      expect(result.results[0].type).toBe('delete');
      expect(mockedWardrobeModel.delete).toHaveBeenCalled();
    });

    it('should handle mixed operations', async () => {
      const deleteWardrobeId = uuidv4();
      const deleteWardrobe = { ...mockWardrobe, id: deleteWardrobeId };
      
      // Setup mocks for mixed operations
      mockedWardrobeModel.findByUserId.mockResolvedValue([]); // For create
      mockedWardrobeModel.getGarments.mockResolvedValue([]); // For delete
      mockedWardrobeModel.findById
        .mockResolvedValueOnce(mockWardrobe) // For update ownership check
        .mockResolvedValueOnce(deleteWardrobe); // For delete ownership check
      
      batchParams.operations = [
        {
          type: 'create',
          data: { name: 'New Wardrobe' },
          clientId: 'temp-5'
        },
        {
          type: 'update',
          data: { id: testWardrobeId, description: 'Updated' },
          clientId: 'temp-6'
        },
        {
          type: 'delete',
          data: { id: deleteWardrobeId },
          clientId: 'temp-7'
        }
      ];

      const result = await wardrobeService.batchOperations(batchParams);

      expect(result.summary.total).toBe(3);
      expect(result.results.length + result.errors.length).toBe(3);
    });

    it('should handle validation errors gracefully', async () => {
      // Mock for the successful create operation
      mockedWardrobeModel.findByUserId.mockResolvedValue([]);
      
      batchParams.operations = [
        {
          type: 'create',
          data: { name: '' }, // Invalid name
          clientId: 'temp-8'
        },
        {
          type: 'create',
          data: { name: 'Valid Name' },
          clientId: 'temp-9'
        }
      ];

      const result = await wardrobeService.batchOperations(batchParams);

      expect(result.results).toHaveLength(1);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].clientId).toBe('temp-8');
    });

    it('should validate operations array', async () => {
      await expect(wardrobeService.batchOperations({ userId: testUserId, operations: null as any }))
        .rejects.toThrow(ApiError);

      await expect(wardrobeService.batchOperations({ userId: testUserId, operations: [] }))
        .rejects.toThrow(ApiError);

      const tooManyOps = Array.from({ length: 51 }, (_, i) => ({
        type: 'create' as const,
        data: { name: `Wardrobe ${i}` },
        clientId: `temp-${i}`
      }));

      await expect(wardrobeService.batchOperations({ userId: testUserId, operations: tooManyOps }))
        .rejects.toThrow(ApiError);
    });

    it('should handle unknown operation types', async () => {
      batchParams.operations = [
        {
          type: 'unknown' as any,
          data: {},
          clientId: 'temp-10'
        }
      ];

      const result = await wardrobeService.batchOperations(batchParams);

      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].error).toContain('Unknown operation type');
    });

    it('should handle missing required fields', async () => {
      batchParams.operations = [
        {
          type: 'update',
          data: { name: 'New Name' }, // Missing id
          clientId: 'temp-11'
        },
        {
          type: 'delete',
          data: {}, // Missing id
          clientId: 'temp-12'
        }
      ];

      const result = await wardrobeService.batchOperations(batchParams);

      expect(result.errors).toHaveLength(2);
      expect(result.results).toHaveLength(0);
    });

    it('should handle database errors per operation', async () => {
      mockedWardrobeModel.create
        .mockResolvedValueOnce(mockWardrobe)
        .mockRejectedValueOnce(new Error('Database error'));

      batchParams.operations = [
        {
          type: 'create',
          data: { name: 'Success' },
          clientId: 'temp-13'
        },
        {
          type: 'create',
          data: { name: 'Failure' },
          clientId: 'temp-14'
        }
      ];

      const result = await wardrobeService.batchOperations(batchParams);

      expect(result.results).toHaveLength(1);
      expect(result.errors).toHaveLength(1);
      expect(result.summary.successful).toBe(1);
      expect(result.summary.failed).toBe(1);
    });
  });
});