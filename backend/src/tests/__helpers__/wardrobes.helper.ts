// /backend/tests/helpers/wardrobes.helper.ts
import { query } from '../../models/db';
import { v4 as uuidv4 } from 'uuid';
import { wardrobeMocks } from '../__mocks__/wardrobes.mock';
import { Wardrobe, CreateWardrobeInput } from '../../models/wardrobeModel';

/**
 * Database helper functions for wardrobe testing
 */
export const wardrobeDbHelpers = {
  /**
   * Clean up all test wardrobes from database
   */
  async cleanupWardrobes(userIds: string[] = []): Promise<void> {
    try {
      if (userIds.length > 0) {
        // Clean wardrobes for specific users
        const placeholders = userIds.map((_, index) => `$${index + 1}`).join(',');
        await query(`DELETE FROM wardrobe_items WHERE wardrobe_id IN (
          SELECT id FROM wardrobes WHERE user_id IN (${placeholders})
        )`, userIds);
        await query(`DELETE FROM wardrobes WHERE user_id IN (${placeholders})`, userIds);
      } else {
        // Clean all test wardrobes (be careful in production!)
        await query('DELETE FROM wardrobe_items WHERE wardrobe_id IN (SELECT id FROM wardrobes)');
        await query('DELETE FROM wardrobes');
      }
    } catch (error) {
      console.error('Error cleaning up wardrobes:', error);
      throw error;
    }
  },

  /**
   * Create a test wardrobe in database
   */
  async createTestWardrobe(wardrobeData: CreateWardrobeInput): Promise<Wardrobe> {
    const id = uuidv4();
    const result = await query(
      `INSERT INTO wardrobes (id, user_id, name, description, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, NOW(), NOW()) 
       RETURNING *`,
      [id, wardrobeData.user_id, wardrobeData.name, wardrobeData.description || '']
    );
    return result.rows[0];
  },

  /**
   * Create multiple test wardrobes
   */
  async createMultipleTestWardrobes(userId: string, count: number = 3): Promise<Wardrobe[]> {
    const wardrobes: Wardrobe[] = [];
    const wardrobeInputs = wardrobeMocks.createMultipleWardrobes(userId, count);
    
    for (const wardrobeInput of wardrobeInputs) {
      const wardrobe = await this.createTestWardrobe({
        user_id: wardrobeInput.user_id,
        name: wardrobeInput.name,
        description: wardrobeInput.description
      });
      wardrobes.push(wardrobe);
    }
    
    return wardrobes;
  },

  /**
   * Create test garment in database
   */
  async createTestGarment(garmentData: any): Promise<any> {
    const id = uuidv4();
    const result = await query(
      `INSERT INTO garment_items 
       (id, user_id, original_image_id, file_path, mask_path, metadata, data_version, created_at, updated_at) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW()) 
       RETURNING *`,
      [
        id, 
        garmentData.user_id, 
        garmentData.original_image_id,
        garmentData.file_path,
        garmentData.mask_path,
        JSON.stringify(garmentData.metadata),
        garmentData.data_version || 1
      ]
    );
    return result.rows[0];
  },

  /**
   * Add garment to wardrobe
   */
  async addGarmentToWardrobe(wardrobeId: string, garmentId: string, position: number = 0): Promise<void> {
    await query(
      `INSERT INTO wardrobe_items (wardrobe_id, garment_item_id, position) 
       VALUES ($1, $2, $3)
       ON CONFLICT (wardrobe_id, garment_item_id) 
       DO UPDATE SET position = EXCLUDED.position`,
      [wardrobeId, garmentId, position]
    );
  },

  /**
   * Get wardrobe by ID
   */
  async getWardrobeById(wardrobeId: string): Promise<Wardrobe | null> {
    const result = await query('SELECT * FROM wardrobes WHERE id = $1', [wardrobeId]);
    return result.rows[0] || null;
  },

  /**
   * Get wardrobes by user ID
   */
  async getWardrobesByUserId(userId: string): Promise<Wardrobe[]> {
    const result = await query(
      'SELECT * FROM wardrobes WHERE user_id = $1 ORDER BY name',
      [userId]
    );
    return result.rows;
  },

  /**
   * Get garments in wardrobe
   */
  async getWardrobeGarments(wardrobeId: string): Promise<any[]> {
    const result = await query(
      `SELECT g.*, wi.position 
       FROM garment_items g
       JOIN wardrobe_items wi ON g.id = wi.garment_item_id
       WHERE wi.wardrobe_id = $1
       ORDER BY wi.position`,
      [wardrobeId]
    );
    return result.rows;
  },

  /**
   * Count wardrobes for user
   */
  async countUserWardrobes(userId: string): Promise<number> {
    const result = await query(
      'SELECT COUNT(*) as count FROM wardrobes WHERE user_id = $1',
      [userId]
    );
    return parseInt(result.rows[0].count, 10);
  },

  /**
   * Check if wardrobe exists
   */
  async wardrobeExists(wardrobeId: string): Promise<boolean> {
    const result = await query(
      'SELECT 1 FROM wardrobes WHERE id = $1',
      [wardrobeId]
    );
    return result.rows.length > 0;
  },

  /**
   * Check if garment is in wardrobe
   */
  async isGarmentInWardrobe(wardrobeId: string, garmentId: string): Promise<boolean> {
    const result = await query(
      'SELECT 1 FROM wardrobe_items WHERE wardrobe_id = $1 AND garment_item_id = $2',
      [wardrobeId, garmentId]
    );
    return result.rows.length > 0;
  }
};

/**
 * Test user helper functions
 */
export const wardrobeUserHelpers = {
  /**
   * Create test user for wardrobe testing
   */
  async createTestUser(overrides: any = {}): Promise<any> {
    const id = uuidv4();
    const email = `test-${id}@example.com`;
    
    const result = await query(
      'INSERT INTO users (id, email, created_at, updated_at) VALUES ($1, $2, NOW(), NOW()) RETURNING id, email, created_at',
      [id, email]
    );
    
    return result.rows[0];
  },

  /**
   * Create multiple test users
   */
  async createMultipleTestUsers(count: number = 2): Promise<any[]> {
    const users: any[] = [];
    
    for (let i = 0; i < count; i++) {
      const user = await this.createTestUser();
      users.push(user);
    }
    
    return users;
  },

  /**
   * Clean up test users
   */
  async cleanupTestUsers(userIds: string[]): Promise<void> {
    if (userIds.length === 0) return;
    
    try {
      // Clean up related data first
      await wardrobeDbHelpers.cleanupWardrobes(userIds);
      
      // Clean up garments
      const placeholders = userIds.map((_, index) => `$${index + 1}`).join(',');
      await query(`DELETE FROM garment_items WHERE user_id IN (${placeholders})`, userIds);
      
      // Clean up users
      await query(`DELETE FROM users WHERE id IN (${placeholders})`, userIds);
    } catch (error) {
      console.error('Error cleaning up test users:', error);
      throw error;
    }
  }
};

/**
 * Test assertion helpers
 */
export const wardrobeAssertionHelpers = {
  /**
   * Assert wardrobe properties match expected values
   */
  assertWardrobeProperties(actual: Wardrobe, expected: Partial<Wardrobe>): void {
    if (expected.id) expect(actual.id).toBe(expected.id);
    if (expected.user_id) expect(actual.user_id).toBe(expected.user_id);
    if (expected.name) expect(actual.name).toBe(expected.name);
    if (expected.description !== undefined) expect(actual.description).toBe(expected.description);
    if (expected.created_at) expect(actual.created_at).toEqual(expected.created_at);
    if (expected.updated_at) expect(actual.updated_at).toEqual(expected.updated_at);
  },

  /**
   * Assert wardrobe has required fields
   */
  assertValidWardrobeStructure(wardrobe: Wardrobe): void {
    expect(wardrobe).toHaveProperty('id');
    expect(wardrobe).toHaveProperty('user_id');
    expect(wardrobe).toHaveProperty('name');
    expect(wardrobe).toHaveProperty('description');
    expect(wardrobe).toHaveProperty('created_at');
    expect(wardrobe).toHaveProperty('updated_at');
    
    expect(typeof wardrobe.id).toBe('string');
    expect(typeof wardrobe.user_id).toBe('string');
    expect(typeof wardrobe.name).toBe('string');
    expect(typeof wardrobe.description).toBe('string');
    expect(wardrobe.created_at).toBeInstanceOf(Date);
    expect(wardrobe.updated_at).toBeInstanceOf(Date);
  },

  /**
   * Assert wardrobe name follows validation rules
   */
  assertValidWardrobeName(name: string): void {
    expect(name.length).toBeGreaterThan(0);
    expect(name.length).toBeLessThanOrEqual(100);
    expect(name).toMatch(/^[a-zA-Z0-9\s\-_\.]+$/);
  },

  /**
   * Assert wardrobe description follows validation rules
   */
  assertValidWardrobeDescription(description: string): void {
    expect(description.length).toBeLessThanOrEqual(1000);
  },

  /**
   * Assert wardrobes are ordered correctly
   */
  assertWardrobesOrderedByName(wardrobes: Wardrobe[]): void {
    for (let i = 1; i < wardrobes.length; i++) {
      const currentName = wardrobes[i].name.toLowerCase();
      const previousName = wardrobes[i - 1].name.toLowerCase();
      expect(currentName.localeCompare(previousName)).toBeGreaterThanOrEqual(0);
    }
  },

  /**
   * Assert garments are ordered by position
   */
  assertGarmentsOrderedByPosition(garments: any[]): void {
    for (let i = 1; i < garments.length; i++) {
      expect(garments[i].position).toBeGreaterThanOrEqual(garments[i - 1].position);
    }
  }
};

/**
 * Performance testing helpers
 */
export const wardrobePerformanceHelpers = {
  /**
   * Time a database operation
   */
  async timeOperation<T>(operation: () => Promise<T>): Promise<{ result: T; duration: number }> {
    const start = Date.now();
    const result = await operation();
    const duration = Date.now() - start;
    
    return { result, duration };
  },

  /**
   * Create large dataset for performance testing
   */
  async createLargeDataset(userCount: number = 10, wardrobesPerUser: number = 20): Promise<any> {
    const users = await wardrobeUserHelpers.createMultipleTestUsers(userCount);
    const allWardrobes: Wardrobe[] = [];
    
    for (const user of users) {
      const wardrobes = await wardrobeDbHelpers.createMultipleTestWardrobes(user.id, wardrobesPerUser);
      allWardrobes.push(...wardrobes);
    }
    
    return {
      users,
      wardrobes: allWardrobes,
      totalWardrobes: allWardrobes.length
    };
  }
};

/**
 * Test scenario builders
 */
export const wardrobeScenarioBuilders = {
  /**
   * Build complete wardrobe ecosystem for testing
   */
  async buildWardrobeEcosystem(): Promise<any> {
    // Create test user
    const user = await wardrobeUserHelpers.createTestUser();
    
    // Create wardrobes
    const wardrobes = await wardrobeDbHelpers.createMultipleTestWardrobes(user.id, 3);
    
    // Create garments
    const garmentPromises = [];
    for (let i = 0; i < 10; i++) {
      const garmentData = wardrobeMocks.garments.createMockGarment({ user_id: user.id });
      garmentPromises.push(wardrobeDbHelpers.createTestGarment(garmentData));
    }
    const garments = await Promise.all(garmentPromises);
    
    // Add garments to wardrobes
    for (let i = 0; i < garments.length; i++) {
      const wardrobeIndex = i % wardrobes.length;
      const position = Math.floor(i / wardrobes.length);
      await wardrobeDbHelpers.addGarmentToWardrobe(
        wardrobes[wardrobeIndex].id,
        garments[i].id,
        position
      );
    }
    
    return {
      user,
      wardrobes,
      garments,
      wardrobeGarmentMapping: wardrobes.map((wardrobe, index) => ({
        wardrobeId: wardrobe.id,
        garmentIds: garments
          .filter((_, garmentIndex) => garmentIndex % wardrobes.length === index)
          .map(g => g.id)
      }))
    };
  },

  /**
   * Build cross-user isolation testing scenario
   */
  async buildCrossUserIsolationScenario(): Promise<any> {
    const users = await wardrobeUserHelpers.createMultipleTestUsers(3);
    const allData: any = {};
    
    for (const user of users) {
      const wardrobes = await wardrobeDbHelpers.createMultipleTestWardrobes(user.id, 2);
      allData[user.id] = {
        user,
        wardrobes,
        wardrobeIds: wardrobes.map(w => w.id)
      };
    }
    
    return allData;
  },

  /**
   * Build business rule testing scenarios
   */
  async buildBusinessRuleScenarios(): Promise<any> {
    const user = await wardrobeUserHelpers.createTestUser();
    
    return {
      user,
      // Will be used to test various business rules like:
      // - Duplicate name prevention
      // - User limits
      // - Capacity limits
      scenarios: {
        duplicateName: wardrobeMocks.businessScenarios.duplicateNameScenario(user.id),
        userLimit: wardrobeMocks.businessScenarios.userLimitScenario(user.id)
      }
    };
  }
};

/**
 * Test cleanup helpers
 */
export const wardrobeCleanupHelpers = {
  /**
   * Complete cleanup of all test data
   */
  async cleanupAll(userIds: string[] = []): Promise<void> {
    try {
      if (userIds.length > 0) {
        await wardrobeUserHelpers.cleanupTestUsers(userIds);
      } else {
        // Nuclear option - clean everything (use with caution!)
        console.warn('Performing complete database cleanup for wardrobe tests');
        await query('DELETE FROM wardrobe_items');
        await query('DELETE FROM wardrobes');
        await query('DELETE FROM garment_items');
      }
    } catch (error) {
      console.error('Error during complete cleanup:', error);
      throw error;
    }
  },

  /**
   * Verify cleanup was successful
   */
  async verifyCleanup(userIds: string[]): Promise<boolean> {
    try {
      for (const userId of userIds) {
        const wardrobeCount = await wardrobeDbHelpers.countUserWardrobes(userId);
        if (wardrobeCount > 0) {
          console.error(`Cleanup verification failed: User ${userId} still has ${wardrobeCount} wardrobes`);
          return false;
        }
      }
      return true;
    } catch (error) {
      console.error('Error verifying cleanup:', error);
      return false;
    }
  },

  /**
   * Safe cleanup with retry mechanism
   */
  async safeCleanup(userIds: string[], maxRetries: number = 3): Promise<void> {
    let attempt = 0;
    
    while (attempt < maxRetries) {
      try {
        await this.cleanupAll(userIds);
        const cleanupSuccessful = await this.verifyCleanup(userIds);
        
        if (cleanupSuccessful) {
          return;
        }
        
        attempt++;
        if (attempt < maxRetries) {
          console.warn(`Cleanup attempt ${attempt} failed, retrying...`);
          await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
        }
      } catch (error) {
        attempt++;
        if (attempt >= maxRetries) {
          throw new Error(`Cleanup failed after ${maxRetries} attempts: ${error}`);
        }
        console.warn(`Cleanup attempt ${attempt} failed, retrying...`);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
    
    throw new Error(`Cleanup failed after ${maxRetries} attempts`);
  }
};

/**
 * Mock query function for unit testing (without database)
 */
export const wardrobeMockQueryHelpers = {
  /**
   * Create mock query function that returns predefined results
   */
  createMockQuery(scenarios: Record<string, any>) {
    return jest.fn().mockImplementation((queryText: string, params?: any[]) => {
      // Detect query type and return appropriate mock result
      if (queryText.includes('INSERT INTO wardrobes')) {
        return Promise.resolve(scenarios.insertSuccess || wardrobeMocks.queryResults.insertSuccess(
          wardrobeMocks.createValidWardrobe()
        ));
      }
      
      if (queryText.includes('SELECT * FROM wardrobes WHERE id')) {
        return Promise.resolve(scenarios.selectById || wardrobeMocks.queryResults.selectSingle(
          wardrobeMocks.createValidWardrobe()
        ));
      }
      
      if (queryText.includes('SELECT * FROM wardrobes WHERE user_id')) {
        return Promise.resolve(scenarios.selectByUserId || wardrobeMocks.queryResults.selectMultiple(
          wardrobeMocks.createMultipleWardrobes(params?.[0] || 'test-user-id', 3)
        ));
      }
      
      if (queryText.includes('UPDATE wardrobes')) {
        return Promise.resolve(scenarios.update || wardrobeMocks.queryResults.updateSuccess(
          wardrobeMocks.createValidWardrobe()
        ));
      }
      
      if (queryText.includes('DELETE FROM wardrobes')) {
        return Promise.resolve(scenarios.delete || wardrobeMocks.queryResults.deleteSuccess());
      }
      
      if (queryText.includes('INSERT INTO wardrobe_items')) {
        return Promise.resolve(scenarios.addGarment || wardrobeMocks.queryResults.genericSuccess([], 'INSERT'));
      }
      
      if (queryText.includes('DELETE FROM wardrobe_items')) {
        return Promise.resolve(scenarios.removeGarment || wardrobeMocks.queryResults.genericSuccess([], 'DELETE'));
      }
      
      if (queryText.includes('SELECT g.*, wi.position')) {
        return Promise.resolve(scenarios.getGarments || wardrobeMocks.queryResults.selectMultiple(
          wardrobeMocks.garments.createMultipleGarments('test-user-id', 3)
        ));
      }
      
      // Default fallback
      return Promise.resolve(wardrobeMocks.queryResults.genericSuccess([], 'SELECT'));
    });
  },

  /**
   * Create error-throwing mock query for testing error scenarios
   */
  createErrorMockQuery(errorType: string) {
    return jest.fn().mockImplementation(() => {
      const error = wardrobeMocks.errorScenarios[errorType as keyof typeof wardrobeMocks.errorScenarios];
      return Promise.reject(error || new Error('Mock database error'));
    });
  },

  /**
   * Create conditional mock query that succeeds/fails based on conditions
   */
  createConditionalMockQuery(conditions: Record<string, boolean>) {
    return jest.fn().mockImplementation((queryText: string, params?: any[]) => {
      // Check conditions and throw errors or return success based on them
      if (conditions.shouldFailInsert && queryText.includes('INSERT')) {
        return Promise.reject(wardrobeMocks.errorScenarios.uniqueConstraintError);
      }
      
      if (conditions.shouldFailSelect && queryText.includes('SELECT')) {
        return Promise.reject(wardrobeMocks.errorScenarios.dbConnectionError);
      }
      
      if (conditions.shouldReturnEmpty && queryText.includes('SELECT')) {
        return Promise.resolve(wardrobeMocks.queryResults.notFound());
      }
      
      // Default success behavior
      return wardrobeMockQueryHelpers.createMockQuery({})(queryText, params);
    });
  }
};

/**
 * Integration test helpers
 */
export const wardrobeIntegrationHelpers = {
  /**
   * Setup complete test environment for integration tests
   */
  async setupIntegrationTestEnvironment(): Promise<any> {
    // Create test users
    const users = await wardrobeUserHelpers.createMultipleTestUsers(2);
    
    // Setup test scenarios
    const mainUser = users[0];
    const otherUser = users[1];
    
    // Create wardrobes for main user
    const mainUserWardrobes = await wardrobeDbHelpers.createMultipleTestWardrobes(mainUser.id, 3);
    
    // Create some garments for main user
    const garments = [];
    for (let i = 0; i < 6; i++) {
      const garmentData = wardrobeMocks.garments.createMockGarment({ 
        user_id: mainUser.id,
        metadata: {
          category: ['shirt', 'pants', 'dress'][i % 3],
          color: ['red', 'blue'][i % 2],
          size: 'M'
        }
      });
      const garment = await wardrobeDbHelpers.createTestGarment(garmentData);
      garments.push(garment);
    }
    
    // Add garments to wardrobes
    for (let i = 0; i < garments.length; i++) {
      const wardrobeIndex = i % mainUserWardrobes.length;
      await wardrobeDbHelpers.addGarmentToWardrobe(
        mainUserWardrobes[wardrobeIndex].id,
        garments[i].id,
        i
      );
    }
    
    return {
      users: { main: mainUser, other: otherUser },
      wardrobes: mainUserWardrobes,
      garments,
      cleanup: async () => {
        await wardrobeUserHelpers.cleanupTestUsers([mainUser.id, otherUser.id]);
      }
    };
  },

  /**
   * Test database transaction handling
   */
  async testWithTransaction<T>(testFn: () => Promise<T>): Promise<T> {
    await query('BEGIN');
    try {
      const result = await testFn();
      await query('COMMIT');
      return result;
    } catch (error) {
      await query('ROLLBACK');
      throw error;
    }
  },

  /**
   * Wait for database operations to complete
   */
  async waitForDbOperations(maxWaitMs: number = 5000): Promise<void> {
    const start = Date.now();
    while (Date.now() - start < maxWaitMs) {
      try {
        await query('SELECT 1');
        return;
      } catch (error) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    throw new Error(`Database operations did not complete within ${maxWaitMs}ms`);
  }
};

/**
 * Validation test helpers
 */
export const wardrobeValidationHelpers = {
  /**
   * Test all validation scenarios for wardrobe names
   */
  getNameValidationTests() {
    return [
      // Valid names
      {
        name: 'Simple valid name',
        description: 'Simple valid name',
        shouldPass: true
      },
      {
        name: 'Valid with allowed special chars',
        description: 'Valid with allowed special chars',
        shouldPass: true
      },
      {
        name: 'Valid with dots and spaces',
        description: 'Valid with dots and spaces',
        shouldPass: true
      },
      {
        name: 'A',
        description: 'Single character (minimum)',
        shouldPass: true
      },
      {
        name: 'a'.repeat(100),
        description: 'Maximum length (100 chars)',
        shouldPass: true
      },
      
      // Invalid names
      {
        name: '',
        description: 'Empty name',
        shouldPass: false
      },
      {
        name: '   ',
        description: 'Whitespace only',
        shouldPass: false
      },
      {
        name: 'a'.repeat(101),
        description: 'Name too long (101 chars)',
        shouldPass: false
      },
      {
        name: 'Invalid@Name',
        description: 'Contains invalid character @',
        shouldPass: false
      },
      {
        name: 'Invalid#Name',
        description: 'Contains invalid character #',
        shouldPass: false
      },
      {
        name: 'Invalid$Name',
        description: 'Contains invalid character $',
        shouldPass: false
      },
      {
        name: 'Invalid%Name',
        description: 'Contains invalid character %',
        shouldPass: false
      }
    ];
  },

  /**
   * Test all validation scenarios for wardrobe descriptions
   */
  getDescriptionValidationTests(): Array<{ description: string; shouldPass: boolean; testDescription: string }> {
    return [
      { description: '', shouldPass: true, testDescription: 'Empty description (allowed)' },
      { description: 'Valid description', shouldPass: true, testDescription: 'Normal description' },
      { description: 'a'.repeat(1000), shouldPass: true, testDescription: 'Maximum length (1000 chars)' },
      { description: 'a'.repeat(1001), shouldPass: false, testDescription: 'Description too long (1001 chars)' },
      { description: 'Description with special chars @#$%^&*()', shouldPass: true, testDescription: 'Special characters allowed in description' }
    ];
  }
};