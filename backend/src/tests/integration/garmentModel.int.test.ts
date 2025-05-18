import { garmentModel, Garment, CreateGarmentInput } from '../../models/garmentModel';
import { testQuery } from '../../utils/testSetup'; // Import the test query
import { v4 as uuidv4 } from 'uuid';
import { setupTestDatabase, teardownTestDatabase } from '../../utils/testSetup';

describe('Garment Model Integration Tests', () => {
  // Track created garments for cleanup
  const createdGarmentIds: string[] = [];
  
  // Setup test database - run before all tests
  beforeAll(async () => {
    // Set environment to test
    process.env.NODE_ENV = 'test';
    
    // Initialize test database
    await setupTestDatabase();
  });
  
  // Clean up after all tests
  afterAll(async () => {
    // Delete all test garments
    if (createdGarmentIds.length > 0) {
      await testQuery(`DELETE FROM garment_items WHERE id IN (${createdGarmentIds.map((_, i) => `$${i+1}`).join(',')})`, 
        createdGarmentIds);
    }
    
    // Close pool connections
    await teardownTestDatabase();
  });
  
  // Test data helpers
  const testUserId = 'integration-test-user';
  const testImageId = 'integration-test-image';
  
  const createTestGarment = async (overrides: Partial<CreateGarmentInput> = {}): Promise<Garment> => {
    const input: CreateGarmentInput = {
      user_id: overrides.user_id || testUserId, // Allow overriding user_id for specific tests
      original_image_id: testImageId,
      file_path: `/test/path/${uuidv4()}.jpg`,
      mask_path: `/test/mask/${uuidv4()}.png`,
      metadata: { test: true, source: 'integration-test' },
      ...overrides
    };
    
    const garment = await garmentModel.create(input);
    createdGarmentIds.push(garment.id);
    return garment;
  };

  // CRUD tests
  describe('create', () => {
    it('should create a garment in the database with all fields', async () => {
      // Arrange
      const metadata = { type: 'shirt', color: 'blue', test: true };
      const input: CreateGarmentInput = {
        user_id: testUserId,
        original_image_id: testImageId,
        file_path: '/test/garment.jpg',
        mask_path: '/test/mask.png',
        metadata
      };
      
      // Act
      const garment = await garmentModel.create(input);
      createdGarmentIds.push(garment.id);
      
      // Assert
      expect(garment.id).toBeDefined();
      expect(garment.user_id).toBe(input.user_id);
      expect(garment.original_image_id).toBe(input.original_image_id);
      expect(garment.file_path).toBe(input.file_path);
      expect(garment.mask_path).toBe(input.mask_path);
      expect(garment.metadata).toEqual(metadata);
      expect(garment.data_version).toBe(1);
      expect(garment.created_at).toBeInstanceOf(Date);
      expect(garment.updated_at).toBeInstanceOf(Date);
      
      // Verify persistence by loading the record again
      const retrieved = await garmentModel.findById(garment.id);
      expect(retrieved).toEqual(garment);
    });
    
    it('should create a garment with empty metadata when not provided', async () => {
      // Arrange
      const input: CreateGarmentInput = {
        user_id: testUserId,
        original_image_id: testImageId,
        file_path: '/test/garment2.jpg',
        mask_path: '/test/mask2.png'
      };
      
      // Act
      const garment = await garmentModel.create(input);
      createdGarmentIds.push(garment.id);
      
      // Assert
      expect(garment.metadata).toEqual({});
    });

    it('should set created_at and updated_at timestamps correctly on creation', async () => {
      const garment = await createTestGarment();
      expect(garment.created_at).toBeInstanceOf(Date);
      expect(garment.updated_at).toBeInstanceOf(Date);
      // Timestamps should be very close, but allow a small delta for processing
      expect(Math.abs(garment.updated_at.getTime() - garment.created_at.getTime())).toBeLessThan(1000); // Less than 1 second
    });
  });
  
  describe('findById', () => {
    it('should find a garment by ID', async () => {
      // Arrange
      const created = await createTestGarment();
      
      // Act
      const found = await garmentModel.findById(created.id);
      
      // Assert
      expect(found).toEqual(created);
    });
    
    it('should return null for non-existent ID', async () => {
      // Act
      const found = await garmentModel.findById('non-existent-garment-id');
      
      // Assert
      expect(found).toBeNull();
    });
  });
  
  describe('findByUserId', () => {
    it('should find all garments for a user in descending order by creation date', async () => {
      // Arrange - Create multiple garments for the same user
      const created1 = await createTestGarment();
      
      // Intentionally delay to ensure different creation timestamps
      await new Promise(resolve => setTimeout(resolve, 50));
      
      const created2 = await createTestGarment();
      
      // Act
      const garments = await garmentModel.findByUserId(testUserId);
      
      // Assert
      expect(garments.length).toBeGreaterThanOrEqual(2);
      
      // Find the two test garments in results
      const resultIds = garments.map(g => g.id);
      expect(resultIds).toContain(created1.id);
      expect(resultIds).toContain(created2.id);
      
      // Check order - newer garments should come first
      const idx1 = resultIds.indexOf(created1.id);
      const idx2 = resultIds.indexOf(created2.id);
      expect(idx2).toBeLessThan(idx1); // created2 is newer and should appear earlier in the array
    });
    
    it('should return empty array for user with no garments', async () => {
      // Act
      const garments = await garmentModel.findByUserId('non-existent-user');
      
      // Assert
      expect(garments).toEqual([]);
    });

    it('should only return garments for the specified user_id', async () => {
      // Arrange
      const user1Id = `user-${uuidv4()}`;
      const user2Id = `user-${uuidv4()}`;

      const garmentUser1 = await createTestGarment({ user_id: user1Id });
      await createTestGarment({ user_id: user2Id }); // Garment for another user

      // Act
      const garmentsUser1 = await garmentModel.findByUserId(user1Id);

      // Assert
      expect(garmentsUser1.length).toBe(1);
      expect(garmentsUser1[0].id).toBe(garmentUser1.id);
      expect(garmentsUser1[0].user_id).toBe(user1Id);
    });
  });
  
  describe('updateMetadata', () => {
    it('should update metadata while preserving existing fields', async () => {
      // Arrange
      const initialMetadata = { type: 'shirt', color: 'blue', size: 'M' };
      const created = await createTestGarment({ metadata: initialMetadata });
      const updates = { metadata: { color: 'red', pattern: 'striped' } };
      
      // Act
      const updated = await garmentModel.updateMetadata(created.id, updates);
      
      // Assert
      expect(updated).not.toBeNull();
      expect(updated!.metadata).toEqual({
        type: 'shirt',     // preserved
        color: 'red',      // updated
        size: 'M',         // preserved
        pattern: 'striped' // added
      });
      expect(updated!.data_version).toBe(created.data_version + 1);
      
      // Verify persistence
      const retrieved = await garmentModel.findById(created.id);
      expect(retrieved!.metadata).toEqual(updated!.metadata);
    });
    
    it('should handle complex nested metadata', async () => {
      // Arrange
      const initialMetadata = { 
        attributes: { color: 'blue', size: 'L' },
        category: 'tops'
      };
      const created = await createTestGarment({ metadata: initialMetadata });
      const updates = { 
        metadata: { 
          attributes: { color: 'red' }, // Should replace entire attributes object
          tags: ['casual']
        } 
      };
      
      // Act
      const updated = await garmentModel.updateMetadata(created.id, updates);
      
      // Assert
      expect(updated).not.toBeNull();
      expect(updated!.metadata).toEqual({
        attributes: { color: 'red' }, // complete replacement, not deep merge
        category: 'tops',             // preserved
        tags: ['casual']              // added
      });
    });
    
    it('should preserve all metadata when updating with empty object', async () => {
      // Arrange
      const initialMetadata = { type: 'shirt', color: 'blue' };
      const created = await createTestGarment({ metadata: initialMetadata });
      
      // Act
      const updated = await garmentModel.updateMetadata(created.id, { metadata: {} });
      
      // Assert
      expect(updated).not.toBeNull();
      expect(updated!.metadata).toEqual(initialMetadata);
    });
    
    it('should return null when updating non-existent garment', async () => {
      // Act
      const result = await garmentModel.updateMetadata('non-existent-id', { 
        metadata: { test: true } 
      });
      
      // Assert
      expect(result).toBeNull();
    });

    it('should update the updated_at timestamp', async () => {
      // Arrange
      const created = await createTestGarment();
      const initialUpdatedAt = created.updated_at;

      // Ensure a small delay so that the new updated_at timestamp is different
      await new Promise(resolve => setTimeout(resolve, 50));

      const updates = { metadata: { new_field: 'new_value' } };

      // Act
      const updated = await garmentModel.updateMetadata(created.id, updates);

      // Assert
      expect(updated).not.toBeNull();
      expect(updated!.updated_at).toBeInstanceOf(Date);
      expect(updated!.updated_at.getTime()).toBeGreaterThan(initialUpdatedAt.getTime());
      expect(updated!.created_at.getTime()).toEqual(created.created_at.getTime()); // created_at should not change
    });

    it('should correctly merge metadata when a key is added and another is modified', async () => {
      // Arrange
      const initialMetadata = { type: 'pants', color: 'black' };
      const created = await createTestGarment({ metadata: initialMetadata });
      const updates = { metadata: { color: 'navy', material: 'denim' } };

      // Act
      const updated = await garmentModel.updateMetadata(created.id, updates);

      // Assert
      expect(updated).not.toBeNull();
      expect(updated!.metadata).toEqual({
        type: 'pants',    // preserved
        color: 'navy',    // updated
        material: 'denim' // added
      });
    });
  });
  
  describe('delete', () => {
    it('should delete a garment from the database', async () => {
      // Arrange
      const created = await createTestGarment();
      
      // Act
      const deleted = await garmentModel.delete(created.id);
      
      // Assert
      expect(deleted).toBe(true);
      
      // Verify deletion
      const retrieved = await garmentModel.findById(created.id);
      expect(retrieved).toBeNull();
      
      // Remove from cleanup array since it's already deleted
      const index = createdGarmentIds.indexOf(created.id);
      if (index > -1) {
        createdGarmentIds.splice(index, 1);
      }
    });
    
    it('should return false when deleting non-existent garment', async () => {
      // Act
      const result = await garmentModel.delete('non-existent-id');
      
      // Assert
      expect(result).toBe(false);
    });
  });
  
  describe('Concurrent operations', () => {
    it('should handle concurrent metadata updates correctly', async () => {
      // Arrange
      const created = await createTestGarment({ 
        metadata: { field1: 'original', field2: 'original' } 
      });
      
      // Act - Perform two updates nearly simultaneously
      const [result1, result2] = await Promise.all([
        garmentModel.updateMetadata(created.id, { 
          metadata: { field1: 'changed-by-1' } 
        }),
        garmentModel.updateMetadata(created.id, { 
          metadata: { field2: 'changed-by-2' } 
        })
      ]);
      
      // Assert
      // Both updates should succeed but one will overwrite the other's changes
      expect(result1).not.toBeNull();
      expect(result2).not.toBeNull();
      
      // Get the final state
      const final = await garmentModel.findById(created.id);
      expect(final).not.toBeNull();
      
      // Depending on which update finished last, we'll have different results
      // This tests the behavior but doesn't assert a specific outcome
      // The data_version should be 3 (original + 2 updates)
      expect(final!.data_version).toBe(3);
      
      // The resulting metadata object will look different depending on which 
      // operation finished last, but we can check that at least one field changed
      const metadata = final!.metadata;
      expect(
        metadata.field1 !== 'original' || metadata.field2 !== 'original'
      ).toBe(true);
    });
  });
});