// /backend/tests/mocks/wardrobes.mock.ts
import { v4 as uuidv4 } from 'uuid';
import { Wardrobe, CreateWardrobeInput, UpdateWardrobeInput } from '../../models/wardrobeModel';

/**
 * Mock wardrobe data factory functions
 */
export const wardrobeMocks = {
  /**
   * Create a valid wardrobe object
   */
  createValidWardrobe(overrides: Partial<Wardrobe> = {}): Wardrobe {
    const now = new Date();
    return {
      id: uuidv4(),
      user_id: uuidv4(),
      name: 'Summer Collection',
      description: 'My favorite summer outfits and accessories',
      created_at: now,
      updated_at: now,
      ...overrides
    };
  },

  /**
   * Create multiple wardrobes for a user
   */
  createMultipleWardrobes(userId: string, count: number = 3): Wardrobe[] {
    const wardrobes: Wardrobe[] = [];
    const baseNames = [
      'Summer Collection',
      'Winter Wardrobe',
      'Work Outfits',
      'Casual Wear',
      'Evening Dresses',
      'Athletic Wear',
      'Vintage Collection',
      'Designer Pieces'
    ];

    for (let i = 0; i < count; i++) {
      wardrobes.push(this.createValidWardrobe({
        user_id: userId,
        name: baseNames[i] || `Wardrobe ${i + 1}`,
        description: `Description for wardrobe ${i + 1}`
      }));
    }

    return wardrobes;
  },

  /**
   * Valid create wardrobe input
   */
  createValidInput(overrides: Partial<CreateWardrobeInput> = {}): CreateWardrobeInput {
    return {
      user_id: uuidv4(),
      name: 'My New Wardrobe',
      description: 'A collection of my favorite clothes',
      ...overrides
    };
  },

  /**
   * Valid update wardrobe input
   */
  createValidUpdateInput(overrides: Partial<UpdateWardrobeInput> = {}): UpdateWardrobeInput {
    return {
      name: 'Updated Wardrobe Name',
      description: 'Updated description',
      ...overrides
    };
  },

  /**
   * Invalid wardrobe inputs for validation testing
   */
  invalidInputs: {
    // Empty name
    emptyName: {
      user_id: uuidv4(),
      name: '',
      description: 'Valid description'
    },
    
    // Name too long
    nameTooLong: {
      user_id: uuidv4(),
      name: 'a'.repeat(101), // 101 characters
      description: 'Valid description'
    },
    
    // Invalid name with special characters
    invalidNameChars: {
      user_id: uuidv4(),
      name: 'Wardrobe@#$%',
      description: 'Valid description'
    },
    
    // Description too long
    descriptionTooLong: {
      user_id: uuidv4(),
      name: 'Valid Name',
      description: 'a'.repeat(1001) // 1001 characters
    },
    
    // Missing user_id
    missingUserId: {
      name: 'Valid Name',
      description: 'Valid description'
    },
    
    // Invalid user_id format
    invalidUserId: {
      user_id: 'invalid-uuid',
      name: 'Valid Name',
      description: 'Valid description'
    }
  },

  /**
   * Edge case wardrobes
   */
  edgeCases: {
    // Minimum valid name
    minName: {
      user_id: uuidv4(),
      name: 'A',
      description: ''
    },
    
    // Maximum valid name
    maxName: {
      user_id: uuidv4(),
      name: 'a'.repeat(100), // Exactly 100 characters
      description: ''
    },
    
    // No description
    noDescription: {
      user_id: uuidv4(),
      name: 'Wardrobe Without Description'
    },
    
    // Maximum description
    maxDescription: {
      user_id: uuidv4(),
      name: 'Wardrobe With Max Description',
      description: 'a'.repeat(1000) // Exactly 1000 characters
    },
    
    // Name with allowed special characters
    allowedSpecialChars: {
      user_id: uuidv4(),
      name: 'My-Wardrobe_2024.Collection',
      description: 'Testing allowed special characters'
    }
  },

  /**
   * Wardrobes for testing business logic scenarios
   */
  businessScenarios: {
    // For testing duplicate names
    duplicateNameScenario: (userId: string) => [
      {
        user_id: userId,
        name: 'Summer Collection',
        description: 'First summer collection'
      },
      {
        user_id: userId,
        name: 'Summer Collection', // Duplicate name
        description: 'Second summer collection'
      }
    ],
    
    // For testing user limits (50+ wardrobes)
    userLimitScenario: (userId: string) => {
      const wardrobes = [];
      for (let i = 0; i < 51; i++) {
        wardrobes.push({
          user_id: userId,
          name: `Wardrobe ${i + 1}`,
          description: `Description ${i + 1}`
        });
      }
      return wardrobes;
    },
    
    // For testing cross-user isolation
    crossUserScenario: () => {
      const user1 = uuidv4();
      const user2 = uuidv4();
      
      return {
        user1Wardrobes: [
          { user_id: user1, name: 'User 1 Wardrobe 1' },
          { user_id: user1, name: 'User 1 Wardrobe 2' }
        ],
        user2Wardrobes: [
          { user_id: user2, name: 'User 2 Wardrobe 1' },
          { user_id: user2, name: 'User 2 Wardrobe 2' }
        ]
      };
    }
  },

  /**
   * Mock garment data for wardrobe-garment relationship testing
   */
  garments: {
    createMockGarment(overrides: any = {}) {
      return {
        id: uuidv4(),
        user_id: uuidv4(),
        original_image_id: uuidv4(),
        file_path: '/uploads/garment_' + uuidv4() + '.jpg',
        mask_path: '/uploads/mask_' + uuidv4() + '.png',
        metadata: {
          category: 'shirt',
          color: 'blue',
          size: 'M'
        },
        created_at: new Date(),
        updated_at: new Date(),
        data_version: 1,
        ...overrides
      };
    },

    createMultipleGarments(userId: string, count: number = 5) {
      const garments = [];
      const categories = ['shirt', 'pants', 'dress', 'jacket', 'shoes'];
      const colors = ['red', 'blue', 'green', 'black', 'white'];
      
      for (let i = 0; i < count; i++) {
        garments.push(this.createMockGarment({
          user_id: userId,
          metadata: {
            category: categories[i % categories.length],
            color: colors[i % colors.length],
            size: 'M'
          }
        }));
      }
      
      return garments;
    }
  },

  /**
   * Wardrobe items (junction table) mock data
   */
  wardrobeItems: {
    createWardrobeItem(wardrobeId: string, garmentId: string, position: number = 0) {
      return {
        wardrobe_id: wardrobeId,
        garment_item_id: garmentId,
        position
      };
    },

    createMultipleItems(wardrobeId: string, garmentIds: string[]) {
      return garmentIds.map((garmentId, index) => 
        this.createWardrobeItem(wardrobeId, garmentId, index)
      );
    }
  },

  /**
   * Database query result mocks - Complete QueryResult interface
   */
  queryResults: {
    // Successful insert result
    insertSuccess: (wardrobe: Wardrobe) => ({
      rows: [wardrobe],
      rowCount: 1,
      command: 'INSERT' as const,
      oid: 0,
      fields: [],
      _types: undefined as any,
      _parsers: undefined as any,
      notice: undefined as any
    }),

    // Successful select result with multiple wardrobes
    selectMultiple: (wardrobes: Wardrobe[]) => ({
      rows: wardrobes,
      rowCount: wardrobes.length,
      command: 'SELECT' as const,
      oid: 0,
      fields: [],
      _types: undefined as any,
      _parsers: undefined as any,
      notice: undefined as any
    }),

    // Successful select result with single wardrobe
    selectSingle: (wardrobe: Wardrobe | null) => ({
      rows: wardrobe ? [wardrobe] : [],
      rowCount: wardrobe ? 1 : 0,
      command: 'SELECT' as const,
      oid: 0,
      fields: [],
      _types: undefined as any,
      _parsers: undefined as any,
      notice: undefined as any
    }),

    // Successful update result
    updateSuccess: (wardrobe: Wardrobe) => ({
      rows: [wardrobe],
      rowCount: 1,
      command: 'UPDATE' as const,
      oid: 0,
      fields: [],
      _types: undefined as any,
      _parsers: undefined as any,
      notice: undefined as any
    }),

    // Successful delete result
    deleteSuccess: () => ({
      rows: [],
      rowCount: 1,
      command: 'DELETE' as const,
      oid: 0,
      fields: [],
      _types: undefined as any,
      _parsers: undefined as any,
      notice: undefined as any
    }),

    // No rows affected (not found)
    notFound: () => ({
      rows: [],
      rowCount: 0,
      command: 'SELECT' as const,
      oid: 0,
      fields: [],
      _types: undefined as any,
      _parsers: undefined as any,
      notice: undefined as any
    }),

    // Generic success result for any operation
    genericSuccess: (rows: any[] = [], command: 'INSERT' | 'SELECT' | 'UPDATE' | 'DELETE' = 'SELECT') => ({
      rows,
      rowCount: rows.length,
      command,
      oid: 0,
      fields: [],
      _types: undefined as any,
      _parsers: undefined as any,
      notice: undefined as any
    })
  },

  /**
   * Error scenarios for testing
   */
  errorScenarios: {
    // Database connection error
    dbConnectionError: new Error('Connection refused'),
    
    // Foreign key constraint error
    foreignKeyError: new Error('Foreign key constraint violation'),
    
    // Unique constraint error
    uniqueConstraintError: new Error('Unique constraint violation'),
    
    // Invalid UUID error
    invalidUuidError: new Error('Invalid UUID format'),
    
    // Timeout error
    timeoutError: new Error('Query timeout')
  }
};

/**
 * Helper functions for creating test scenarios
 */
export const wardrobeTestScenarios = {
  /**
   * Setup scenario: User with multiple wardrobes
   */
  async setupUserWithWardrobes(userId: string, wardrobeCount: number = 3) {
    const wardrobes = wardrobeMocks.createMultipleWardrobes(userId, wardrobeCount);
    return {
      userId,
      wardrobes,
      wardrobeIds: wardrobes.map(w => w.id)
    };
  },

  /**
   * Setup scenario: Wardrobe with garments
   */
  async setupWardrobeWithGarments(userId: string, garmentCount: number = 5) {
    const wardrobe = wardrobeMocks.createValidWardrobe({ user_id: userId });
    const garments = wardrobeMocks.garments.createMultipleGarments(userId, garmentCount);
    const wardrobeItems = wardrobeMocks.wardrobeItems.createMultipleItems(
      wardrobe.id, 
      garments.map(g => g.id)
    );

    return {
      wardrobe,
      garments,
      wardrobeItems,
      garmentIds: garments.map(g => g.id)
    };
  },

  /**
   * Setup scenario: Cross-user data isolation testing
   */
  async setupCrossUserScenario() {
    const user1Id = uuidv4();
    const user2Id = uuidv4();
    
    const user1Wardrobes = wardrobeMocks.createMultipleWardrobes(user1Id, 2);
    const user2Wardrobes = wardrobeMocks.createMultipleWardrobes(user2Id, 2);

    return {
      user1: {
        id: user1Id,
        wardrobes: user1Wardrobes
      },
      user2: {
        id: user2Id,
        wardrobes: user2Wardrobes
      }
    };
  }
};

/**
 * Constants for testing limits and constraints
 */
export const wardrobeTestConstants = {
  limits: {
    maxNameLength: 100,
    maxDescriptionLength: 1000,
    maxWardrobesPerUser: 50,
    maxGarmentsPerWardrobe: 200
  },
  
  validNameChars: /^[a-zA-Z0-9\s\-_\.]+$/,
  
  sampleValidNames: [
    'Summer Collection',
    'Work-Wardrobe_2024',
    'Casual.Outfits',
    'My_Favorite-Clothes.Collection'
  ],
  
  sampleInvalidNames: [
    'Wardrobe@Home',
    'Collection#1',
    'My&Wardrobe',
    'Test%Collection'
  ]
};