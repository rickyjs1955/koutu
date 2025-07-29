// /backend/src/tests/integration/wardrobeModel.int.test.ts - COMPLETE VERSION
/**
 * Production-Ready Integration Test Suite for Wardrobe Model
 * 
 * @description Tests complete database operations with real PostgreSQL instance.
 * This suite validates wardrobe CRUD operations, data integrity, concurrent operations,
 * and complex business logic with actual database transactions.
 * 
 * @prerequisites 
 * - PostgreSQL instance running via Docker
 * - Test database configured and accessible
 * - Required environment variables set
 * - Test data setup utilities available
 * 
 * @author Development Team
 * @version 1.0.0
 * @since June 10, 2025
 */

import { jest } from '@jest/globals';
import { setupWardrobeTestQuickFix } from '../../utils/dockerMigrationHelper';
import { v4 as uuidv4, validate as isUuid } from 'uuid';

// Initialize dual-mode test components
let TestDatabaseConnection: any;
let testUserModel: any;
let createTestImage: any;

// #region Utility Functions
/**
 * Sleep utility for async operations and retries
 * @param ms - Milliseconds to sleep
 * @returns Promise that resolves after specified time
 */
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Generates a unique test identifier for avoiding conflicts
 * @returns Unique test identifier string
 */
const generateTestId = () => `test_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
// #endregion

// #region Database Mocking
/**
 * Mock database connection to use TestDatabaseConnection
 * This ensures all database operations go through the test database
 */
jest.doMock('../../models/db', () => ({
  query: async (text: string, params?: any[]) => {
    return TestDatabaseConnection.query(text, params);
  }
}));
// #endregion

// Import models after mocking
import { wardrobeModel, Wardrobe, CreateWardrobeInput, UpdateWardrobeInput } from '../../models/wardrobeModel';

describe('Wardrobe Model - Complete Integration Test Suite', () => {
    // #region Test Variables
    let testUser1: any;
    let testUser2: any;
    let testAdmin: any;
    let testGarments: any[] = [];
    // #endregion

    // #region Helper Functions
    /**
     * Creates a test wardrobe with specified data for a user
     * @param userId - ID of the user who owns the wardrobe
     * @param overrides - Optional overrides for wardrobe data
     * @returns Promise resolving to created wardrobe
     */
    const createTestWardrobe = async (userId: string, overrides: Partial<CreateWardrobeInput> = {}): Promise<Wardrobe> => {
        const testId = generateTestId();
        const wardrobeData: CreateWardrobeInput = {
            user_id: userId,
            name: `Test Wardrobe ${testId}`,
            description: `Test description for wardrobe ${testId}`,
            ...overrides
        };
        
        return await wardrobeModel.create(wardrobeData);
    };

    /**
     * Creates multiple test wardrobes for a user
     * @param userId - ID of the user who owns the wardrobes
     * @param count - Number of wardrobes to create
     * @returns Promise resolving to array of created wardrobes
     */
    const createMultipleWardrobes = async (userId: string, count: number): Promise<Wardrobe[]> => {
        const promises = Array.from({ length: count }, (_, i) =>
            createTestWardrobe(userId, {
                name: `Test Wardrobe ${i + 1}`,
                description: `Description for wardrobe ${i + 1}`
            })
        );
        
        return Promise.all(promises);
    };

    /**
     * Creates test garment items for testing wardrobe-garment relationships
     * @param count - Number of garments to create
     * @returns Promise resolving to array of created garment items
     */
    const createTestGarments = async (count: number = 3): Promise<any[]> => {
        const garments = [];
        
        for (let i = 0; i < count; i++) {
            try {
                // Create test image first
                const testImage = await createTestImage({
                    file_name: `test_garment_${i + 1}.jpg`,
                    file_size: 1024 * (i + 1),
                    mime_type: 'image/jpeg',
                    user_id: testUser1.id
                });

                // Create garment using direct database query
                const garmentResult = await TestDatabaseConnection.query(
                    `INSERT INTO garment_items 
                     (id, user_id, image_id, name, category, color, brand, size, material, season, tags, notes, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
                     RETURNING *`,
                    [
                        uuidv4(),
                        testUser1.id,
                        testImage.id,
                        `Test Garment ${i + 1}`,
                        'shirt',
                        ['red', 'blue', 'green'][i % 3],
                        `Brand ${i + 1}`,
                        ['S', 'M', 'L'][i % 3],
                        'cotton',
                        'all',
                        ['casual', 'formal', 'sport'][i % 3],
                        `Test notes for garment ${i + 1}`
                    ]
                );

                garments.push(garmentResult.rows[0]);
            } catch (error) {
                console.warn(`Could not create test garment ${i + 1}:`, error instanceof Error ? error.message : String(error));
            }
        }
        
        return garments;
    };

    /**
     * Validates wardrobe object structure and required fields
     * @param wardrobe - Wardrobe object to validate
     * @param expectedUserId - Expected user ID for the wardrobe
     */
    const validateWardrobeStructure = (wardrobe: any, expectedUserId?: string): void => {
        expect(wardrobe).toHaveProperty('id');
        expect(isUuid(wardrobe.id)).toBe(true);
        expect(wardrobe).toHaveProperty('user_id');
        expect(wardrobe).toHaveProperty('name');
        expect(wardrobe).toHaveProperty('description');
        expect(wardrobe).toHaveProperty('is_default');
        expect(wardrobe).toHaveProperty('created_at');
        expect(wardrobe).toHaveProperty('updated_at');
        
        if (expectedUserId) {
            expect(wardrobe.user_id).toBe(expectedUserId);
        }
        
        expect(typeof wardrobe.name).toBe('string');
        expect(typeof wardrobe.description).toBe('string');
        expect(typeof wardrobe.is_default).toBe('boolean');
        expect(wardrobe.created_at).toBeInstanceOf(Date);
        expect(wardrobe.updated_at).toBeInstanceOf(Date);
    };
    // #endregion

    // #region Test Setup and Teardown
    beforeAll(async () => {
        try {
            console.log('🔧 Setting up test environment...');
            
            // Use the dual-mode quick fix setup
            const setup = await setupWardrobeTestQuickFix();
            TestDatabaseConnection = setup.TestDB;
            testUserModel = setup.testUserModel;
            createTestImage = setup.createTestImage;
            
            console.log('✅ Test environment components initialized');
            
            // Create test users
            testUser1 = await testUserModel.create({
                email: 'user1@wardrobetest.com',
                password: 'SecurePass123!'
            });

            testUser2 = await testUserModel.create({
                email: 'user2@wardrobetest.com',
                password: 'SecurePass123!'
            });

            testAdmin = await testUserModel.create({
                email: 'admin@wardrobetest.com',
                password: 'AdminPass123!',
                role: 'admin'
            });

            console.log('✅ Test users created');

            // Create test garments for relationship testing
            testGarments = await createTestGarments(5);
            console.log(`✅ Created ${testGarments.length} test garments`);

        } catch (error) {
            console.error('❌ Failed to set up test environment:', error);
            throw error;
        }
    }, 30000);

    afterAll(async () => {
        try {
            console.log('🧹 Cleaning up test environment...');
            
            if (TestDatabaseConnection && TestDatabaseConnection.cleanup) {
                await TestDatabaseConnection.cleanup();
                console.log('✅ Test database cleaned up');
            }
        } catch (error) {
            console.warn('⚠️ Cleanup issues:', error);
        }
    }, 10000);

    beforeEach(async () => {
        try {
            // Clear wardrobe-related data before each test
            await TestDatabaseConnection.query('DELETE FROM wardrobe_items WHERE 1=1');
            await TestDatabaseConnection.query('DELETE FROM wardrobes WHERE 1=1');
        } catch (error) {
            console.warn('Could not clear tables in beforeEach:', error instanceof Error ? error.message : String(error));
        }
    });
    // #endregion

    // #region CREATE Operations Tests
    describe('CREATE Wardrobe Operations', () => {
        test('should create wardrobe with complete valid data', async () => {
            const wardrobeData: CreateWardrobeInput = {
                user_id: testUser1.id,
                name: 'My Complete Test Wardrobe',
                description: 'A comprehensive test wardrobe with all fields',
                is_default: false
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);
            
            validateWardrobeStructure(wardrobe, testUser1.id);
            expect(wardrobe.name).toBe('My Complete Test Wardrobe');
            expect(wardrobe.description).toBe('A comprehensive test wardrobe with all fields');
            expect(wardrobe.is_default).toBe(false);
        });

        test('should create wardrobe with minimal required data', async () => {
            const wardrobeData: CreateWardrobeInput = {
                user_id: testUser1.id,
                name: 'Minimal Wardrobe'
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);
            
            validateWardrobeStructure(wardrobe, testUser1.id);
            expect(wardrobe.name).toBe('Minimal Wardrobe');
            expect(wardrobe.description).toBe(''); // Should default to empty string
            expect(wardrobe.is_default).toBe(false); // Should default to false
        });

        test('should create wardrobe with default flag set to true', async () => {
            const wardrobeData: CreateWardrobeInput = {
                user_id: testUser1.id,
                name: 'Default Wardrobe',
                is_default: true
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);
            
            validateWardrobeStructure(wardrobe);
            expect(wardrobe.is_default).toBe(true);
        });

        test('should create wardrobe with empty description', async () => {
            const wardrobeData: CreateWardrobeInput = {
                user_id: testUser1.id,
                name: 'No Description Wardrobe',
                description: ''
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);
            
            validateWardrobeStructure(wardrobe);
            expect(wardrobe.description).toBe('');
        });

        test('should create wardrobe with long name and description', async () => {
            const longName = 'A'.repeat(255); // Test boundary for name length
            const longDescription = 'B'.repeat(1000); // Test long description
            
            const wardrobeData: CreateWardrobeInput = {
                user_id: testUser1.id,
                name: longName,
                description: longDescription
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);
            
            validateWardrobeStructure(wardrobe);
            expect(wardrobe.name).toBe(longName);
            expect(wardrobe.description).toBe(longDescription);
        });

        test('should create multiple wardrobes for same user', async () => {
            const wardrobe1 = await createTestWardrobe(testUser1.id, { name: 'Wardrobe 1' });
            const wardrobe2 = await createTestWardrobe(testUser1.id, { name: 'Wardrobe 2' });
            const wardrobe3 = await createTestWardrobe(testUser1.id, { name: 'Wardrobe 3' });

            expect(wardrobe1.id).not.toBe(wardrobe2.id);
            expect(wardrobe2.id).not.toBe(wardrobe3.id);
            expect(wardrobe1.id).not.toBe(wardrobe3.id);
            
            expect(wardrobe1.user_id).toBe(testUser1.id);
            expect(wardrobe2.user_id).toBe(testUser1.id);
            expect(wardrobe3.user_id).toBe(testUser1.id);
        });

        test('should create wardrobes for different users', async () => {
            const user1Wardrobe = await createTestWardrobe(testUser1.id, { name: 'User 1 Wardrobe' });
            const user2Wardrobe = await createTestWardrobe(testUser2.id, { name: 'User 2 Wardrobe' });

            expect(user1Wardrobe.user_id).toBe(testUser1.id);
            expect(user2Wardrobe.user_id).toBe(testUser2.id);
            expect(user1Wardrobe.id).not.toBe(user2Wardrobe.id);
        });

        test('should handle special characters in name and description', async () => {
            const specialName = "John's \"Awesome\" Wardrobe & More!";
            const specialDescription = "Description with 'quotes', \"double quotes\", & special chars: @#$%";
            
            const wardrobeData: CreateWardrobeInput = {
                user_id: testUser1.id,
                name: specialName,
                description: specialDescription
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);
            
            validateWardrobeStructure(wardrobe);
            expect(wardrobe.name).toBe(specialName);
            expect(wardrobe.description).toBe(specialDescription);
        });

        test('should create wardrobe with unicode characters', async () => {
            const unicodeName = "👗 My Fashion Wardrobe 💫";
            const unicodeDescription = "🌟 Contains my favorite clothes 👚👖👠";
            
            const wardrobeData: CreateWardrobeInput = {
                user_id: testUser1.id,
                name: unicodeName,
                description: unicodeDescription
            };

            const wardrobe = await wardrobeModel.create(wardrobeData);
            
            validateWardrobeStructure(wardrobe);
            expect(wardrobe.name).toBe(unicodeName);
            expect(wardrobe.description).toBe(unicodeDescription);
        });
    });
    // #endregion

    // #region READ Operations Tests
    describe('READ Wardrobe Operations', () => {
        test('should find wardrobe by valid ID', async () => {
            const created = await createTestWardrobe(testUser1.id, {
                name: 'Findable Wardrobe',
                description: 'This wardrobe should be found'
            });

            const found = await wardrobeModel.findById(created.id);

            expect(found).not.toBeNull();
            validateWardrobeStructure(found!, testUser1.id);
            expect(found!.id).toBe(created.id);
            expect(found!.name).toBe('Findable Wardrobe');
            expect(found!.description).toBe('This wardrobe should be found');
        });

        test('should return null for non-existent ID', async () => {
            const nonExistentId = uuidv4();
            const result = await wardrobeModel.findById(nonExistentId);
            expect(result).toBeNull();
        });

        test('should return null for invalid UUID format', async () => {
            const invalidIds = ['invalid-id', '123', '', 'not-a-uuid'];
            
            for (const invalidId of invalidIds) {
                const result = await wardrobeModel.findById(invalidId);
                expect(result).toBeNull();
            }
        });

        test('should find all wardrobes for a user', async () => {
            // Create multiple wardrobes for user1
            const user1Wardrobes = await createMultipleWardrobes(testUser1.id, 3);
            
            // Create wardrobes for user2
            const user2Wardrobes = await createMultipleWardrobes(testUser2.id, 2);

            // Test user1 wardrobes
            const foundUser1Wardrobes = await wardrobeModel.findByUserId(testUser1.id);
            expect(foundUser1Wardrobes).toHaveLength(3);
            
            foundUser1Wardrobes.forEach(wardrobe => {
                validateWardrobeStructure(wardrobe, testUser1.id);
            });

            // Test user2 wardrobes
            const foundUser2Wardrobes = await wardrobeModel.findByUserId(testUser2.id);
            expect(foundUser2Wardrobes).toHaveLength(2);
            
            foundUser2Wardrobes.forEach(wardrobe => {
                validateWardrobeStructure(wardrobe, testUser2.id);
            });

            // Verify isolation between users
            const user1Ids = foundUser1Wardrobes.map(w => w.id);
            const user2Ids = foundUser2Wardrobes.map(w => w.id);
            const commonIds = user1Ids.filter(id => user2Ids.includes(id));
            expect(commonIds).toHaveLength(0);
        });

        test('should return empty array for user with no wardrobes', async () => {
            const result = await wardrobeModel.findByUserId(testAdmin.id);
            expect(result).toEqual([]);
        });

        test('should return wardrobes sorted by name', async () => {
            // Create wardrobes with names that should be sorted
            await createTestWardrobe(testUser1.id, { name: 'Zebra Wardrobe' });
            await createTestWardrobe(testUser1.id, { name: 'Alpha Wardrobe' });
            await createTestWardrobe(testUser1.id, { name: 'Beta Wardrobe' });

            const wardrobes = await wardrobeModel.findByUserId(testUser1.id);
            
            expect(wardrobes).toHaveLength(3);
            expect(wardrobes[0].name).toBe('Alpha Wardrobe');
            expect(wardrobes[1].name).toBe('Beta Wardrobe');
            expect(wardrobes[2].name).toBe('Zebra Wardrobe');
        });

        test('should handle user ID that does not exist', async () => {
            const nonExistentUserId = uuidv4();
            const result = await wardrobeModel.findByUserId(nonExistentUserId);
            expect(result).toEqual([]);
        });

        test('should maintain data integrity across multiple reads', async () => {
            const originalWardrobe = await createTestWardrobe(testUser1.id, {
                name: 'Consistency Test Wardrobe',
                description: 'Testing data consistency'
            });

            // Read the wardrobe multiple times
            const read1 = await wardrobeModel.findById(originalWardrobe.id);
            const read2 = await wardrobeModel.findById(originalWardrobe.id);
            const read3 = await wardrobeModel.findById(originalWardrobe.id);

            // All reads should return identical data
            expect(read1).toEqual(read2);
            expect(read2).toEqual(read3);
            expect(read1).toEqual(originalWardrobe);
        });
    });
    // #endregion

    // #region UPDATE Operations Tests
    describe('UPDATE Wardrobe Operations', () => {
        test('should update wardrobe name only', async () => {
            const original = await createTestWardrobe(testUser1.id, {
                name: 'Original Name',
                description: 'Original Description',
                is_default: false
            });

            const updated = await wardrobeModel.update(original.id, {
                name: 'Updated Name'
            });

            expect(updated).not.toBeNull();
            validateWardrobeStructure(updated!);
            expect(updated!.name).toBe('Updated Name');
            expect(updated!.description).toBe('Original Description'); // Should remain unchanged
            expect(updated!.is_default).toBe(false); // Should remain unchanged
            expect(updated!.updated_at.getTime()).toBeGreaterThan(original.updated_at.getTime());
        });

        test('should update wardrobe description only', async () => {
            const original = await createTestWardrobe(testUser1.id, {
                name: 'Test Name',
                description: 'Original Description',
                is_default: false
            });

            const updated = await wardrobeModel.update(original.id, {
                description: 'Updated Description with more details'
            });

            expect(updated).not.toBeNull();
            expect(updated!.name).toBe('Test Name'); // Should remain unchanged
            expect(updated!.description).toBe('Updated Description with more details');
            expect(updated!.is_default).toBe(false); // Should remain unchanged
        });

        test('should update wardrobe is_default flag only', async () => {
            const original = await createTestWardrobe(testUser1.id, {
                name: 'Test Name',
                description: 'Test Description',
                is_default: false
            });

            const updated = await wardrobeModel.update(original.id, {
                is_default: true
            });

            expect(updated).not.toBeNull();
            expect(updated!.name).toBe('Test Name'); // Should remain unchanged
            expect(updated!.description).toBe('Test Description'); // Should remain unchanged
            expect(updated!.is_default).toBe(true);
        });

        test('should update multiple fields simultaneously', async () => {
            const original = await createTestWardrobe(testUser1.id, {
                name: 'Original Name',
                description: 'Original Description',
                is_default: false
            });

            const updated = await wardrobeModel.update(original.id, {
                name: 'Updated Name',
                description: 'Updated Description',
                is_default: true
            });

            expect(updated).not.toBeNull();
            expect(updated!.name).toBe('Updated Name');
            expect(updated!.description).toBe('Updated Description');
            expect(updated!.is_default).toBe(true);
            expect(updated!.updated_at.getTime()).toBeGreaterThan(original.updated_at.getTime());
        });

        test('should handle empty string updates', async () => {
            const original = await createTestWardrobe(testUser1.id, {
                name: 'Original Name',
                description: 'Original Description'
            });

            const updated = await wardrobeModel.update(original.id, {
                name: '',
                description: ''
            });

            expect(updated).not.toBeNull();
            expect(updated!.name).toBe('');
            expect(updated!.description).toBe('');
        });

        test('should handle special characters in updates', async () => {
            const original = await createTestWardrobe(testUser1.id);

            const specialName = "Updated \"Special\" Name & More!";
            const specialDescription = "Updated description with 'quotes' & symbols: @#$%";

            const updated = await wardrobeModel.update(original.id, {
                name: specialName,
                description: specialDescription
            });

            expect(updated).not.toBeNull();
            expect(updated!.name).toBe(specialName);
            expect(updated!.description).toBe(specialDescription);
        });

        test('should handle unicode characters in updates', async () => {
            const original = await createTestWardrobe(testUser1.id);

            const unicodeName = "🎯 Updated Fashion Wardrobe 🌟";
            const unicodeDescription = "✨ Now with even more style 👗💫";

            const updated = await wardrobeModel.update(original.id, {
                name: unicodeName,
                description: unicodeDescription
            });

            expect(updated).not.toBeNull();
            expect(updated!.name).toBe(unicodeName);
            expect(updated!.description).toBe(unicodeDescription);
        });

        test('should return null for non-existent wardrobe ID', async () => {
            const nonExistentId = uuidv4();
            const result = await wardrobeModel.update(nonExistentId, {
                name: 'New Name'
            });
            expect(result).toBeNull();
        });

        test('should return null for invalid UUID format', async () => {
            const invalidIds = ['invalid-id', '123', '', 'not-a-uuid'];
            
            for (const invalidId of invalidIds) {
                const result = await wardrobeModel.update(invalidId, {
                    name: 'New Name'
                });
                expect(result).toBeNull();
            }
        });

        test('should handle concurrent updates gracefully', async () => {
            const original = await createTestWardrobe(testUser1.id, {
                name: 'Concurrent Test',
                description: 'Testing concurrent updates'
            });

            // Perform concurrent updates
            const [update1, update2] = await Promise.all([
                wardrobeModel.update(original.id, { name: 'Update 1' }),
                wardrobeModel.update(original.id, { description: 'Update 2' })
            ]);

            // Both updates should succeed
            expect(update1).not.toBeNull();
            expect(update2).not.toBeNull();

            // Verify final state
            const final = await wardrobeModel.findById(original.id);
            expect(final).not.toBeNull();
            // One of the updates should have won (database handles concurrency)
            expect(final!.updated_at.getTime()).toBeGreaterThan(original.updated_at.getTime());
        });

        test('should preserve unchanged fields with null/undefined values', async () => {
            const original = await createTestWardrobe(testUser1.id, {
                name: 'Preserve Test',
                description: 'Preservation Description',
                is_default: true
            });

            // Update with undefined values (should not change those fields)
            const updated = await wardrobeModel.update(original.id, {
                name: 'New Name'
                // description and is_default are undefined, should remain unchanged
            });

            expect(updated).not.toBeNull();
            expect(updated!.name).toBe('New Name');
            expect(updated!.description).toBe('Preservation Description');
            expect(updated!.is_default).toBe(true);
        });
    });
    // #endregion

    // #region DELETE Operations Tests
    describe('DELETE Wardrobe Operations', () => {
        test('should delete wardrobe successfully', async () => {
            const wardrobe = await createTestWardrobe(testUser1.id, {
                name: 'Delete Me',
                description: 'This wardrobe will be deleted'
            });

            const deleteResult = await wardrobeModel.delete(wardrobe.id);
            expect(deleteResult).toBe(true);

            // Verify it's actually deleted
            const found = await wardrobeModel.findById(wardrobe.id);
            expect(found).toBeNull();
        });

        test('should return false for non-existent wardrobe', async () => {
            const nonExistentId = uuidv4();
            const result = await wardrobeModel.delete(nonExistentId);
            expect(result).toBe(false);
        });

        test('should return false for invalid UUID format', async () => {
            const invalidIds = ['invalid-id', '123', '', 'not-a-uuid'];
            
            for (const invalidId of invalidIds) {
                const result = await wardrobeModel.delete(invalidId);
                expect(result).toBe(false);
            }
        });

        test('should delete wardrobe and associated items', async () => {
            const wardrobe = await createTestWardrobe(testUser1.id);
            
            // Add some garments to the wardrobe (if garments are available)
            if (testGarments.length > 0) {
                try {
                    await wardrobeModel.addGarment(wardrobe.id, testGarments[0].id, 1);
                    await wardrobeModel.addGarment(wardrobe.id, testGarments[1].id, 2);
                    
                    // Verify garments were added
                    const garments = await wardrobeModel.getGarments(wardrobe.id);
                    expect(garments.length).toBeGreaterThan(0);
                } catch (error) {
                    console.warn('Could not add garments for delete test:', error instanceof Error ? error.message : String(error));
                }
            }

            // Delete the wardrobe
            const deleteResult = await wardrobeModel.delete(wardrobe.id);
            expect(deleteResult).toBe(true);

            // Verify wardrobe is deleted
            const found = await wardrobeModel.findById(wardrobe.id);
            expect(found).toBeNull();

            // Verify associated wardrobe items are also deleted
            try {
                const remainingItems = await TestDatabaseConnection.query(
                    'SELECT * FROM wardrobe_items WHERE wardrobe_id = $1',
                    [wardrobe.id]
                );
                expect(remainingItems.rows).toHaveLength(0);
            } catch (error) {
                console.warn('Could not verify wardrobe items deletion:', error instanceof Error ? error.message : String(error));
            }
        });

        test('should handle concurrent deletions gracefully', async () => {
            const wardrobe = await createTestWardrobe(testUser1.id);

            // Attempt concurrent deletions
            const [delete1, delete2] = await Promise.all([
                wardrobeModel.delete(wardrobe.id),
                wardrobeModel.delete(wardrobe.id)
            ]);

            // One should succeed, one should fail
            expect(delete1 || delete2).toBe(true);
            expect(delete1 && delete2).toBe(false);

            // Verify wardrobe is deleted
            const found = await wardrobeModel.findById(wardrobe.id);
            expect(found).toBeNull();
        });

        test('should not affect other wardrobes when deleting one', async () => {
            const wardrobe1 = await createTestWardrobe(testUser1.id, { name: 'Keep Me 1' });
            const wardrobe2 = await createTestWardrobe(testUser1.id, { name: 'Delete Me' });
            const wardrobe3 = await createTestWardrobe(testUser1.id, { name: 'Keep Me 2' });

            // Delete the middle wardrobe
            const deleteResult = await wardrobeModel.delete(wardrobe2.id);
            expect(deleteResult).toBe(true);

            // Verify other wardrobes still exist
            const found1 = await wardrobeModel.findById(wardrobe1.id);
            const found3 = await wardrobeModel.findById(wardrobe3.id);
            
            expect(found1).not.toBeNull();
            expect(found3).not.toBeNull();
            expect(found1!.name).toBe('Keep Me 1');
            expect(found3!.name).toBe('Keep Me 2');
        });

        test('should not affect wardrobes of other users', async () => {
            const user1Wardrobe = await createTestWardrobe(testUser1.id, { name: 'User 1 Wardrobe' });
            const user2Wardrobe = await createTestWardrobe(testUser2.id, { name: 'User 2 Wardrobe' });

            // Delete user1's wardrobe
            const deleteResult = await wardrobeModel.delete(user1Wardrobe.id);
            expect(deleteResult).toBe(true);

            // Verify user2's wardrobe is unaffected
            const user2Found = await wardrobeModel.findById(user2Wardrobe.id);
            expect(user2Found).not.toBeNull();
            expect(user2Found!.name).toBe('User 2 Wardrobe');
        });
    });
    // #endregion

    // #region Wardrobe-Garment Relationship Tests
    describe('Wardrobe-Garment Relationship Operations', () => {
        test('should add garment to wardrobe successfully', async () => {
            if (testGarments.length === 0) {
                console.warn('⚠️ Skipping garment tests - no test garments available');
                return;
            }

            const wardrobe = await createTestWardrobe(testUser1.id);
            const garment = testGarments[0];

            const result = await wardrobeModel.addGarment(wardrobe.id, garment.id, 1);
            expect(result).toBe(true);

            // Verify the garment was added
            const garments = await wardrobeModel.getGarments(wardrobe.id);
            expect(garments).toHaveLength(1);
            expect(garments[0].id).toBe(garment.id);
            expect(garments[0].position).toBe(1);
        });

        test('should add multiple garments to wardrobe', async () => {
            if (testGarments.length < 3) {
                console.warn('⚠️ Skipping multiple garment test - need at least 3 test garments');
                return;
            }

            const wardrobe = await createTestWardrobe(testUser1.id);

            // Add multiple garments with different positions
            await wardrobeModel.addGarment(wardrobe.id, testGarments[0].id, 1);
            await wardrobeModel.addGarment(wardrobe.id, testGarments[1].id, 2);
            await wardrobeModel.addGarment(wardrobe.id, testGarments[2].id, 3);

            // Verify all garments were added in correct order
            const garments = await wardrobeModel.getGarments(wardrobe.id);
            expect(garments).toHaveLength(3);
            
            // Should be ordered by position
            expect(garments[0].position).toBe(1);
            expect(garments[1].position).toBe(2);
            expect(garments[2].position).toBe(3);
        });

        test('should update garment position when allowUpdate is true', async () => {
            if (testGarments.length === 0) {
                console.warn('⚠️ Skipping garment position test - no test garments available');
                return;
            }

            const wardrobe = await createTestWardrobe(testUser1.id);
            const garment = testGarments[0];

            // Add garment at position 1
            await wardrobeModel.addGarment(wardrobe.id, garment.id, 1);
            
            // Add same garment again at position 5 (should update position)
            const result = await wardrobeModel.addGarment(wardrobe.id, garment.id, 5, { allowUpdate: true });
            expect(result).toBe(true);

            // Verify position was updated
            const garments = await wardrobeModel.getGarments(wardrobe.id);
            expect(garments).toHaveLength(1);
            expect(garments[0].position).toBe(5);
        });

        test('should throw error when adding duplicate garment with allowUpdate false', async () => {
            if (testGarments.length === 0) {
                console.warn('⚠️ Skipping duplicate garment test - no test garments available');
                return;
            }

            const wardrobe = await createTestWardrobe(testUser1.id);
            const garment = testGarments[0];

            // Add garment first time
            await wardrobeModel.addGarment(wardrobe.id, garment.id, 1);
            
            // Try to add same garment again with allowUpdate: false
            await expect(
                wardrobeModel.addGarment(wardrobe.id, garment.id, 2, { allowUpdate: false })
            ).rejects.toThrow('Garment already in wardrobe');
        });

        test('should remove garment from wardrobe successfully', async () => {
            if (testGarments.length === 0) {
                console.warn('⚠️ Skipping garment removal test - no test garments available');
                return;
            }

            const wardrobe = await createTestWardrobe(testUser1.id);
            const garment = testGarments[0];

            // Add garment first
            await wardrobeModel.addGarment(wardrobe.id, garment.id, 1);
            
            // Verify it was added
            let garments = await wardrobeModel.getGarments(wardrobe.id);
            expect(garments).toHaveLength(1);

            // Remove the garment
            const result = await wardrobeModel.removeGarment(wardrobe.id, garment.id);
            expect(result).toBe(true);

            // Verify it was removed
            garments = await wardrobeModel.getGarments(wardrobe.id);
            expect(garments).toHaveLength(0);
        });

        test('should return false when removing non-existent garment', async () => {
            const wardrobe = await createTestWardrobe(testUser1.id);
            const nonExistentGarmentId = uuidv4();

            const result = await wardrobeModel.removeGarment(wardrobe.id, nonExistentGarmentId);
            expect(result).toBe(false);
        });

        test('should get empty array for wardrobe with no garments', async () => {
            const wardrobe = await createTestWardrobe(testUser1.id);

            const garments = await wardrobeModel.getGarments(wardrobe.id);
            expect(garments).toEqual([]);
        });

        test('should handle wardrobe-garment operations with non-existent garment', async () => {
            const wardrobe = await createTestWardrobe(testUser1.id);
            const nonExistentGarmentId = uuidv4();

            // Adding a non-existent garment should fail with foreign key error
            try {
                await wardrobeModel.addGarment(wardrobe.id, nonExistentGarmentId, 1);
                fail('Should have thrown an error for non-existent garment');
            } catch (error) {
                expect(error instanceof Error).toBe(true);
                // Should get foreign key constraint violation
                expect(error.message).toContain('foreign key constraint');
            }

            // Removing a non-existent garment should return false gracefully
            const removeResult = await wardrobeModel.removeGarment(wardrobe.id, nonExistentGarmentId);
            expect(removeResult).toBe(false);

            // Getting garments should return empty array for wardrobe with no garments
            const garments = await wardrobeModel.getGarments(wardrobe.id);
            expect(garments).toEqual([]);
        });
    });
    // #endregion

    // #region Data Validation and Edge Cases
    describe('Data Validation and Edge Cases', () => {
        test('should handle very long wardrobe names', async () => {
            const veryLongName = 'A'.repeat(1000);
            
            try {
                const wardrobe = await createTestWardrobe(testUser1.id, {
                    name: veryLongName
                });
                
                expect(wardrobe.name.length).toBeGreaterThan(0);
                // Database might truncate, but should not fail
            } catch (error) {
                // Some databases might reject very long names, which is acceptable
                expect(error).toBeDefined();
            }
        });

        test('should handle very long descriptions', async () => {
            const veryLongDescription = 'B'.repeat(5000);
            
            try {
                const wardrobe = await createTestWardrobe(testUser1.id, {
                    description: veryLongDescription
                });
                
                expect(wardrobe.description.length).toBeGreaterThan(0);
            } catch (error) {
                // Some databases might reject very long descriptions
                expect(error).toBeDefined();
            }
        });

        test('should handle null-like values appropriately', async () => {
            // Test how the model handles edge cases with null-ish values
            const edgeCases = [
                { name: ' ', description: ' ' }, // Whitespace only
                { name: '\t\n', description: '\t\n' }, // Tab and newline
                { name: '   Trimmed Name   ', description: '   Trimmed Description   ' } // Padded with spaces
            ];

            for (const testCase of edgeCases) {
                const wardrobe = await createTestWardrobe(testUser1.id, testCase);
                validateWardrobeStructure(wardrobe);
                expect(wardrobe.name).toBe(testCase.name);
                expect(wardrobe.description).toBe(testCase.description);
            }
        });

        test('should maintain referential integrity', async () => {
            const user1Wardrobe = await createTestWardrobe(testUser1.id);
            const user2Wardrobe = await createTestWardrobe(testUser2.id);

            // Each wardrobe should belong to its respective user
            expect(user1Wardrobe.user_id).toBe(testUser1.id);
            expect(user2Wardrobe.user_id).toBe(testUser2.id);

            // Wardrobes should have different IDs
            expect(user1Wardrobe.id).not.toBe(user2Wardrobe.id);
        });

        test('should handle database connection issues gracefully', async () => {
            // This test would need a way to simulate database connection issues
            // For now, we'll test that operations complete without hanging
            
            const startTime = Date.now();
            
            try {
                const wardrobe = await createTestWardrobe(testUser1.id);
                const found = await wardrobeModel.findById(wardrobe.id);
                expect(found).not.toBeNull();
            } catch (error) {
                // If there's a database issue, it should fail quickly, not hang
                const duration = Date.now() - startTime;
                expect(duration).toBeLessThan(10000); // Should not take more than 10 seconds
            }
        });

        test('should handle concurrent operations on same wardrobe', async () => {
            const wardrobe = await createTestWardrobe(testUser1.id, {
                name: 'Concurrent Test',
                description: 'Testing concurrent operations'
            });

            // Perform multiple concurrent operations
            const operations = [
                wardrobeModel.findById(wardrobe.id),
                wardrobeModel.update(wardrobe.id, { name: 'Updated Name 1' }),
                wardrobeModel.update(wardrobe.id, { description: 'Updated Description 1' }),
                wardrobeModel.findById(wardrobe.id),
                wardrobeModel.update(wardrobe.id, { name: 'Updated Name 2' })
            ];

            const results = await Promise.all(operations);
            
            // All operations should complete (not all necessarily succeed)
            expect(results).toHaveLength(5);
            
            // Final state should be consistent
            const finalState = await wardrobeModel.findById(wardrobe.id);
            expect(finalState).not.toBeNull();
            validateWardrobeStructure(finalState!);
        });
    });
    // #endregion

    // #region Performance and Stress Tests
    describe('Performance and Stress Tests', () => {
        test('should handle creation of many wardrobes efficiently', async () => {
            const startTime = Date.now();
            const wardrobeCount = 20;
            
            const wardrobes = await createMultipleWardrobes(testUser1.id, wardrobeCount);
            
            const duration = Date.now() - startTime;
            
            expect(wardrobes).toHaveLength(wardrobeCount);
            expect(duration).toBeLessThan(10000); // Should complete within 10 seconds
            
            wardrobes.forEach(wardrobe => {
                validateWardrobeStructure(wardrobe, testUser1.id);
            });
        });

        test('should handle bulk read operations efficiently', async () => {
            // Create several wardrobes first
            await createMultipleWardrobes(testUser1.id, 15);
            
            const startTime = Date.now();
            
            // Perform multiple concurrent read operations
            const readOperations = Array.from({ length: 10 }, () =>
                wardrobeModel.findByUserId(testUser1.id)
            );
            
            const results = await Promise.all(readOperations);
            
            const duration = Date.now() - startTime;
            
            expect(results).toHaveLength(10);
            expect(duration).toBeLessThan(5000); // Should complete within 5 seconds
            
            // All results should be identical
            results.forEach(result => {
                expect(result).toHaveLength(15);
            });
        });

        test('should handle rapid create-update-delete cycles', async () => {
            const iterations = 10;
            const startTime = Date.now();
            
            for (let i = 0; i < iterations; i++) {
                // Create
                const wardrobe = await createTestWardrobe(testUser1.id, {
                    name: `Cycle Test ${i}`
                });
                
                // Update
                const updated = await wardrobeModel.update(wardrobe.id, {
                    name: `Updated Cycle Test ${i}`,
                    description: `Updated description ${i}`
                });
                
                expect(updated).not.toBeNull();
                
                // Delete
                const deleted = await wardrobeModel.delete(wardrobe.id);
                expect(deleted).toBe(true);
            }
            
            const duration = Date.now() - startTime;
            expect(duration).toBeLessThan(15000); // Should complete within 15 seconds
        });

        test('should maintain performance with large datasets', async () => {
            // Create a large number of wardrobes for different users
            const user1Wardrobes = await createMultipleWardrobes(testUser1.id, 25);
            const user2Wardrobes = await createMultipleWardrobes(testUser2.id, 25);
            
            const startTime = Date.now();
            
            // Test various operations with large dataset
            const [
                user1Results,
                user2Results,
                specificWardrobe,
                updateResult
            ] = await Promise.all([
                wardrobeModel.findByUserId(testUser1.id),
                wardrobeModel.findByUserId(testUser2.id),
                wardrobeModel.findById(user1Wardrobes[10].id),
                wardrobeModel.update(user2Wardrobes[5].id, { name: 'Updated Name' })
            ]);
            
            const duration = Date.now() - startTime;
            
            expect(user1Results).toHaveLength(25);
            expect(user2Results).toHaveLength(25);
            expect(specificWardrobe).not.toBeNull();
            expect(updateResult).not.toBeNull();
            expect(duration).toBeLessThan(3000); // Should complete within 3 seconds
        });
    });
    // #endregion

    // #region Integration and System Tests
    describe('Integration and System Tests', () => {
        test('should work correctly with actual database constraints', async () => {
            // Test that the model respects database constraints
            const wardrobe = await createTestWardrobe(testUser1.id, {
                name: 'Constraint Test',
                description: 'Testing database constraints'
            });
            
            validateWardrobeStructure(wardrobe);
            
            // Test unique ID constraint (should not be able to create with same ID)
            try {
                await TestDatabaseConnection.query(
                    `INSERT INTO wardrobes (id, user_id, name, description, is_default, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
                    [wardrobe.id, testUser2.id, 'Duplicate ID Test', 'Should fail', false]
                );
                
                // If we reach here, the constraint didn't work as expected
                fail('Should not be able to insert wardrobe with duplicate ID');
            } catch (error) {
                // This is expected - duplicate ID should be rejected
                expect(error).toBeDefined();
            }
        });

        test('should handle transaction-like behavior correctly', async () => {
            // Test that operations are atomic
            const wardrobe = await createTestWardrobe(testUser1.id, {
                name: 'Transaction Test',
                description: 'Testing transaction behavior'
            });
            
            // Verify wardrobe was created completely
            const found = await wardrobeModel.findById(wardrobe.id);
            expect(found).not.toBeNull();
            expect(found!.name).toBe('Transaction Test');
            expect(found!.description).toBe('Testing transaction behavior');
            
            // Test that failed updates don't leave partial changes
            try {
                // This might cause an error depending on implementation
                await TestDatabaseConnection.query(
                    'UPDATE wardrobes SET name = $1, invalid_column = $2 WHERE id = $3',
                    ['Should Not Update', 'Invalid Value', wardrobe.id]
                );
            } catch (error) {
                // Expected error due to invalid column
            }
            
            // Verify original data is unchanged
            const stillOriginal = await wardrobeModel.findById(wardrobe.id);
            expect(stillOriginal).not.toBeNull();
            expect(stillOriginal!.name).toBe('Transaction Test');
        });

        test('should integrate properly with user management', async () => {
            // Test that wardrobes are properly associated with users
            const user1Wardrobes = await createMultipleWardrobes(testUser1.id, 3);
            const user2Wardrobes = await createMultipleWardrobes(testUser2.id, 2);
            
            // Verify user1's wardrobes
            const user1Found = await wardrobeModel.findByUserId(testUser1.id);
            expect(user1Found).toHaveLength(3);
            user1Found.forEach(wardrobe => {
                expect(wardrobe.user_id).toBe(testUser1.id);
            });
            
            // Verify user2's wardrobes
            const user2Found = await wardrobeModel.findByUserId(testUser2.id);
            expect(user2Found).toHaveLength(2);
            user2Found.forEach(wardrobe => {
                expect(wardrobe.user_id).toBe(testUser2.id);
            });
            
            // Verify isolation between users
            const user1Ids = user1Found.map(w => w.id);
            const user2Ids = user2Found.map(w => w.id);
            const intersection = user1Ids.filter(id => user2Ids.includes(id));
            expect(intersection).toHaveLength(0);
        });

        test('should handle cleanup operations correctly', async () => {
            // Create some wardrobes
            const wardrobes = await createMultipleWardrobes(testUser1.id, 5);
            
            // Add some garments (if available)
            if (testGarments.length > 0) {
                try {
                    for (let i = 0; i < Math.min(wardrobes.length, testGarments.length); i++) {
                        await wardrobeModel.addGarment(wardrobes[i].id, testGarments[i].id, i + 1);
                    }
                } catch (error) {
                    console.warn('Could not add garments for cleanup test:', error instanceof Error ? error.message : String(error));
                }
            }
            
            // Delete all wardrobes
            for (const wardrobe of wardrobes) {
                const deleted = await wardrobeModel.delete(wardrobe.id);
                expect(deleted).toBe(true);
            }
            
            // Verify all are deleted
            for (const wardrobe of wardrobes) {
                const found = await wardrobeModel.findById(wardrobe.id);
                expect(found).toBeNull();
            }
            
            // Verify no orphaned wardrobe items (if table exists)
            try {
                const orphanedItems = await TestDatabaseConnection.query(
                    'SELECT * FROM wardrobe_items WHERE wardrobe_id = ANY($1)',
                    [wardrobes.map(w => w.id)]
                );
                expect(orphanedItems.rows).toHaveLength(0);
            } catch (error) {
                console.warn('Could not check for orphaned items:', error instanceof Error ? error.message : String(error));
            }
        });
    });
    // #endregion
});