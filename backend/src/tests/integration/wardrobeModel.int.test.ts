// Simplified working version of wardrobeModel integration tests
import { jest } from '@jest/globals';
import { setupWardrobeTestQuickFix } from '../../utils/dockerMigrationHelper';
import { v4 as uuidv4 } from 'uuid';

// Initialize dual-mode test components
let TestDatabaseConnection: any;
let testUserModel: any;

// Mock database connection to use TestDatabaseConnection
jest.doMock('../../models/db', () => ({
  query: async (text: string, params?: any[]) => {
    return TestDatabaseConnection.query(text, params);
  }
}));

// Import models after mocking
import { wardrobeModel } from '../../models/wardrobeModel';

describe('Wardrobe Model - Integration Tests', () => {
    let testUser1: any;
    let testUser2: any;

    beforeAll(async () => {
        try {
            // Use the dual-mode quick fix setup
            const setup = await setupWardrobeTestQuickFix();
            TestDatabaseConnection = setup.TestDB;
            testUserModel = setup.testUserModel;
            
            // Create test users
            testUser1 = await testUserModel.create({
                email: 'user1@wardrobetest.com',
                password: 'SecurePass123!'
            });

            testUser2 = await testUserModel.create({
                email: 'user2@wardrobetest.com',
                password: 'SecurePass123!'
            });

        } catch (error) {
            console.error('Failed to set up test environment:', error);
            throw error;
        }
    }, 30000);

    afterAll(async () => {
        try {
            if (TestDatabaseConnection && TestDatabaseConnection.cleanup) {
                await TestDatabaseConnection.cleanup();
            }
        } catch (error) {
            console.warn('⚠️ Cleanup issues:', error);
        }
    }, 10000);

    beforeEach(async () => {
        try {
            // Clear wardrobe data before each test
            await TestDatabaseConnection.query('DELETE FROM wardrobe_items WHERE 1=1');
            await TestDatabaseConnection.query('DELETE FROM wardrobes WHERE 1=1');
        } catch (error) {
            console.warn('Could not clear tables in beforeEach:', error instanceof Error ? error.message : String(error));
        }
    });

    describe('CREATE Wardrobe Operations', () => {
        test('should create wardrobe with complete valid data', async () => {
            const wardrobeData = {
                user_id: testUser1.id,
                name: 'My Test Wardrobe',
                description: 'A test wardrobe description',
                is_default: false
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);

            expect(wardrobe).toHaveProperty('id');
            expect(wardrobe.user_id).toBe(testUser1.id);
            expect(wardrobe.name).toBe('My Test Wardrobe');
            expect(wardrobe.description).toBe('A test wardrobe description');
            expect(wardrobe.is_default).toBe(false);
            expect(wardrobe).toHaveProperty('created_at');
            expect(wardrobe).toHaveProperty('updated_at');
        });

        test('should create wardrobe with minimal required data', async () => {
            const wardrobeData = {
                user_id: testUser1.id,
                name: 'Minimal Wardrobe'
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);

            expect(wardrobe).toHaveProperty('id');
            expect(wardrobe.user_id).toBe(testUser1.id);
            expect(wardrobe.name).toBe('Minimal Wardrobe');
            expect(wardrobe.description).toBe(''); // Should default to empty string
            expect(wardrobe.is_default).toBe(false); // Should default to false
        });
    });

    describe('READ Wardrobe Operations', () => {
        test('should find wardrobe by valid ID', async () => {
            const created = await wardrobeModel.create({
                user_id: testUser1.id,
                name: 'Find Me',
                description: 'Find me test'
            });

            const found = await wardrobeModel.findById(created.id);

            expect(found).not.toBeNull();
            expect(found?.id).toBe(created.id);
            expect(found?.name).toBe('Find Me');
        });

        test('should return null for non-existent ID', async () => {
            const nonExistentId = uuidv4();
            const result = await wardrobeModel.findById(nonExistentId);
            expect(result).toBeNull();
        });

        test('should find all wardrobes for a user', async () => {
            // Create wardrobes for user1
            await wardrobeModel.create({
                user_id: testUser1.id,
                name: 'Wardrobe 1'
            });
            await wardrobeModel.create({
                user_id: testUser1.id,
                name: 'Wardrobe 2'
            });

            // Create wardrobe for user2
            await wardrobeModel.create({
                user_id: testUser2.id,
                name: 'User2 Wardrobe'
            });

            const user1Wardrobes = await wardrobeModel.findByUserId(testUser1.id);
            const user2Wardrobes = await wardrobeModel.findByUserId(testUser2.id);

            expect(user1Wardrobes).toHaveLength(2);
            expect(user2Wardrobes).toHaveLength(1);
            expect(user1Wardrobes.every(w => w.user_id === testUser1.id)).toBe(true);
            expect(user2Wardrobes.every(w => w.user_id === testUser2.id)).toBe(true);
        });
    });

    describe('UPDATE Wardrobe Operations', () => {
        test('should update wardrobe name', async () => {
            const created = await wardrobeModel.create({
                user_id: testUser1.id,
                name: 'Original Name',
                description: 'Original Description'
            });

            const updated = await wardrobeModel.update(created.id, {
                name: 'Updated Name'
            });

            expect(updated).not.toBeNull();
            expect(updated?.name).toBe('Updated Name');
            expect(updated?.description).toBe('Original Description'); // Should remain unchanged
        });

        test('should return null for non-existent wardrobe', async () => {
            const nonExistentId = uuidv4();
            const result = await wardrobeModel.update(nonExistentId, {
                name: 'New Name'
            });
            expect(result).toBeNull();
        });
    });

    describe('DELETE Wardrobe Operations', () => {
        test('should delete wardrobe successfully', async () => {
            const created = await wardrobeModel.create({
                user_id: testUser1.id,
                name: 'Delete Me'
            });

            const deleteResult = await wardrobeModel.delete(created.id);
            expect(deleteResult).toBe(true);

            // Verify it's deleted
            const found = await wardrobeModel.findById(created.id);
            expect(found).toBeNull();
        });

        test('should return false for non-existent wardrobe', async () => {
            const nonExistentId = uuidv4();
            const result = await wardrobeModel.delete(nonExistentId);
            expect(result).toBe(false);
        });
    });
});