// shared/src/__tests__/schema-evolution.test.ts

import { describe, test, expect, beforeAll } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { z } from 'zod';
import {
  UserSchema,
  GarmentSchema,
  ImageSchema,
  WardrobeSchema,
  CreateGarmentSchema,
  UpdateGarmentMetadataSchema
} from '../schemas/index';
import { PolygonSchema } from '../schemas/polygon';

/**
 * Schema Evolution Detection System
 * 
 * This test suite prevents breaking changes by:
 * 1. Taking snapshots of schema structures
 * 2. Comparing current schemas against previous versions
 * 3. Detecting breaking vs non-breaking changes
 * 4. Providing migration warnings
 */

interface SchemaStructure {
  name: string;
  version: string;
  timestamp: string;
  required: string[];
  optional: string[];
  types: Record<string, string>;
  nested: Record<string, SchemaStructure>;
  enums: Record<string, string[]>;
}

interface SchemaComparison {
  breaking: string[];
  nonBreaking: string[];
  additions: string[];
  removals: string[];
  typeChanges: string[];
}

class SchemaEvolutionDetector {
  private snapshotDir = path.join(__dirname, 'snapshots');

  constructor() {
    this.ensureSnapshotDir();
  }

  private ensureSnapshotDir() {
    if (!fs.existsSync(this.snapshotDir)) {
      fs.mkdirSync(this.snapshotDir, { recursive: true });
    }
  }

  /**
   * Extract schema structure for comparison
   */
  extractSchemaStructure(schema: z.ZodSchema, name: string): SchemaStructure {
    const structure: SchemaStructure = {
      name,
      version: '1.0.0', // You can increment this when making intentional changes
      timestamp: new Date().toISOString(),
      required: [],
      optional: [],
      types: {},
      nested: {},
      enums: {}
    };

    try {
      // Generate a sample object to understand schema structure
      const sampleData = this.generateSampleData(schema);
      this.analyzeSchema(schema, structure, sampleData);
    } catch (error) {
      console.warn(`Could not analyze schema ${name}:`, error);
    }

    return structure;
  }

  /**
   * Generate sample data that conforms to schema
   */
  private generateSampleData(schema: z.ZodSchema): any {
    // This is a simplified implementation
    // In practice, you'd have more sophisticated sample generation
    try {
      const result = schema.safeParse({});
      if (result.success) return result.data;
    } catch {}

    // Fallback sample data based on schema type
    return this.getDefaultSampleForSchema(schema);
  }

  private getDefaultSampleForSchema(schema: z.ZodSchema): any {
    // Return type-appropriate sample data
    if (schema instanceof z.ZodObject) {
      return {};
    }
    if (schema instanceof z.ZodArray) {
      return [];
    }
    if (schema instanceof z.ZodString) {
      return 'sample';
    }
    if (schema instanceof z.ZodNumber) {
      return 0;
    }
    return null;
  }

  /**
   * Analyze schema structure recursively
   */
  private analyzeSchema(schema: z.ZodSchema, structure: SchemaStructure, sampleData: any) {
    // This is a simplified version - in practice, you'd need to handle
    // all Zod schema types (ZodObject, ZodArray, ZodUnion, etc.)
    
    if (schema instanceof z.ZodObject) {
      const shape = (schema as any)._def.shape();
      
      Object.entries(shape).forEach(([key, fieldSchema]: [string, any]) => {
        if (fieldSchema.isOptional()) {
          structure.optional.push(key);
        } else {
          structure.required.push(key);
        }
        
        structure.types[key] = this.getZodTypeName(fieldSchema);
        
        // Handle enums
        if (fieldSchema instanceof z.ZodEnum) {
          structure.enums[key] = fieldSchema.options;
        }
        
        // Handle nested objects
        if (fieldSchema instanceof z.ZodObject) {
          structure.nested[key] = this.extractSchemaStructure(fieldSchema, `${structure.name}.${key}`);
        }
      });
    }
  }

  private getZodTypeName(schema: any): string {
    if (schema instanceof z.ZodString) return 'string';
    if (schema instanceof z.ZodNumber) return 'number';
    if (schema instanceof z.ZodBoolean) return 'boolean';
    if (schema instanceof z.ZodDate) return 'date';
    if (schema instanceof z.ZodArray) return 'array';
    if (schema instanceof z.ZodObject) return 'object';
    if (schema instanceof z.ZodEnum) return 'enum';
    if (schema instanceof z.ZodOptional) return this.getZodTypeName(schema.unwrap());
    return 'unknown';
  }

  /**
   * Save schema snapshot
   */
  saveSnapshot(structure: SchemaStructure): void {
    const filename = `${structure.name}.snapshot.json`;
    const filepath = path.join(this.snapshotDir, filename);
    
    fs.writeFileSync(filepath, JSON.stringify(structure, null, 2));
  }

  /**
   * Load previous schema snapshot
   */
  loadSnapshot(schemaName: string): SchemaStructure | null {
    const filename = `${schemaName}.snapshot.json`;
    const filepath = path.join(this.snapshotDir, filename);
    
    if (!fs.existsSync(filepath)) {
      return null;
    }
    
    try {
      const content = fs.readFileSync(filepath, 'utf8');
      return JSON.parse(content);
    } catch (error) {
      console.warn(`Could not load snapshot for ${schemaName}:`, error);
      return null;
    }
  }

  /**
   * Compare current schema with previous snapshot
   */
  compareSchemas(current: SchemaStructure, previous: SchemaStructure): SchemaComparison {
    const comparison: SchemaComparison = {
      breaking: [],
      nonBreaking: [],
      additions: [],
      removals: [],
      typeChanges: []
    };

    // Check for removed required fields (BREAKING)
    previous.required.forEach(field => {
      if (!current.required.includes(field) && !current.optional.includes(field)) {
        comparison.breaking.push(`Removed required field: ${field}`);
        comparison.removals.push(field);
      }
    });

    // Check for required fields that became optional (NON-BREAKING)
    previous.required.forEach(field => {
      if (current.optional.includes(field)) {
        comparison.nonBreaking.push(`Required field became optional: ${field}`);
      }
    });

    // Check for optional fields that became required (BREAKING)
    previous.optional.forEach(field => {
      if (current.required.includes(field)) {
        comparison.breaking.push(`Optional field became required: ${field}`);
      }
    });

    // Check for new required fields (BREAKING)
    current.required.forEach(field => {
      if (!previous.required.includes(field) && !previous.optional.includes(field)) {
        comparison.breaking.push(`Added new required field: ${field}`);
        comparison.additions.push(field);
      }
    });

    // Check for new optional fields (NON-BREAKING)
    current.optional.forEach(field => {
      if (!previous.required.includes(field) && !previous.optional.includes(field)) {
        comparison.nonBreaking.push(`Added new optional field: ${field}`);
        comparison.additions.push(field);
      }
    });

    // Check for type changes (POTENTIALLY BREAKING)
    Object.entries(current.types).forEach(([field, currentType]) => {
      const previousType = previous.types[field];
      if (previousType && previousType !== currentType) {
        comparison.breaking.push(`Type changed for field ${field}: ${previousType} → ${currentType}`);
        comparison.typeChanges.push(field);
      }
    });

    // Check for enum changes (POTENTIALLY BREAKING)
    Object.entries(current.enums).forEach(([field, currentValues]) => {
      const previousValues = previous.enums[field];
      if (previousValues) {
        const removedValues = previousValues.filter(v => !currentValues.includes(v));
        const addedValues = currentValues.filter(v => !previousValues.includes(v));
        
        if (removedValues.length > 0) {
          comparison.breaking.push(`Removed enum values for ${field}: ${removedValues.join(', ')}`);
        }
        
        if (addedValues.length > 0) {
          comparison.nonBreaking.push(`Added enum values for ${field}: ${addedValues.join(', ')}`);
        }
      }
    });

    return comparison;
  }

  /**
   * Generate migration suggestions
   */
  generateMigrationSuggestions(comparison: SchemaComparison): string[] {
    const suggestions: string[] = [];

    if (comparison.breaking.length > 0) {
      suggestions.push('🚨 BREAKING CHANGES DETECTED - Consider these migration steps:');
      
      comparison.additions.forEach(field => {
        suggestions.push(`  • Add default value for new required field: ${field}`);
      });
      
      comparison.removals.forEach(field => {
        suggestions.push(`  • Create migration to handle removal of: ${field}`);
      });
      
      comparison.typeChanges.forEach(field => {
        suggestions.push(`  • Create type conversion for field: ${field}`);
      });
    }

    if (comparison.nonBreaking.length > 0) {
      suggestions.push('✅ Non-breaking changes detected - Safe to deploy');
    }

    return suggestions;
  }
}

// ==================== SCHEMA EVOLUTION TESTS ====================

describe('Schema Evolution Detection', () => {
  let detector: SchemaEvolutionDetector;

  beforeAll(() => {
    detector = new SchemaEvolutionDetector();
  });

  const schemasToTrack = [
    { name: 'User', schema: UserSchema },
    { name: 'Garment', schema: GarmentSchema },
    { name: 'Image', schema: ImageSchema },
    { name: 'Polygon', schema: PolygonSchema },
    { name: 'Wardrobe', schema: WardrobeSchema },
    { name: 'CreateGarment', schema: CreateGarmentSchema },
    { name: 'UpdateGarmentMetadata', schema: UpdateGarmentMetadataSchema }
  ];

  describe('Schema Structure Tracking', () => {
    schemasToTrack.forEach(({ name, schema }) => {
      test(`should track ${name} schema structure`, () => {
        const structure = detector.extractSchemaStructure(schema, name);
        
        expect(structure.name).toBe(name);
        expect(structure.timestamp).toBeDefined();
        expect(Array.isArray(structure.required)).toBe(true);
        expect(Array.isArray(structure.optional)).toBe(true);
        expect(typeof structure.types).toBe('object');
        
        // Save snapshot for future comparisons
        detector.saveSnapshot(structure);
      });
    });
  });

  describe('Breaking Change Detection', () => {
    schemasToTrack.forEach(({ name, schema }) => {
      test(`should detect breaking changes in ${name} schema`, () => {
        const currentStructure = detector.extractSchemaStructure(schema, name);
        const previousStructure = detector.loadSnapshot(name);
        
        if (previousStructure) {
          const comparison = detector.compareSchemas(currentStructure, previousStructure);
          
          // Log comparison results for visibility
          if (comparison.breaking.length > 0) {
            console.warn(`🚨 BREAKING CHANGES in ${name}:`);
            comparison.breaking.forEach(change => console.warn(`  - ${change}`));
            
            const suggestions = detector.generateMigrationSuggestions(comparison);
            suggestions.forEach(suggestion => console.log(suggestion));
          }
          
          if (comparison.nonBreaking.length > 0) {
            console.log(`✅ Non-breaking changes in ${name}:`);
            comparison.nonBreaking.forEach(change => console.log(`  + ${change}`));
          }
          
          // Fail the test if there are breaking changes (unless intentional)
          // You can set an environment variable to skip this check during intentional changes
          if (process.env.ALLOW_BREAKING_CHANGES !== 'true') {
            expect(comparison.breaking).toHaveLength(0);
          }
          
          // Update snapshot with current structure
          detector.saveSnapshot(currentStructure);
        } else {
          // First run - just save the snapshot
          detector.saveSnapshot(currentStructure);
          console.log(`📸 Created initial snapshot for ${name} schema`);
        }
      });
    });
  });

  describe('Schema Version Compatibility', () => {
    test('should maintain backward compatibility', () => {
      // Test that old data still validates against new schemas
      const oldUserData = {
        email: 'test@example.com'
        // Missing newer fields like linkedProviders, oauth_provider
      };
      
      const result = UserSchema.safeParse(oldUserData);
      expect(result.success).toBe(true);
    });

    test('should handle graceful degradation', () => {
      // Test that new data can be safely downgraded
      const newUserData = {
        email: 'test@example.com',
        name: 'Test User',
        linkedProviders: ['google'],
        oauth_provider: 'google'
      };
      
      // Essential fields should always be present
      expect(newUserData.email).toBeDefined();
      
      // Optional fields can be safely ignored by older clients
      const essentialFields = { email: newUserData.email };
      const result = UserSchema.safeParse(essentialFields);
      expect(result.success).toBe(true);
    });
  });

  describe('Migration Path Validation', () => {
    test('should provide clear migration instructions', () => {
      // Mock a breaking change scenario
      const oldStructure: SchemaStructure = {
        name: 'MockUser',
        version: '1.0.0',
        timestamp: '2023-01-01T00:00:00.000Z',
        required: ['email'],
        optional: ['name'],
        types: { email: 'string', name: 'string' },
        nested: {},
        enums: {}
      };
      
      const newStructure: SchemaStructure = {
        name: 'MockUser',
        version: '2.0.0',
        timestamp: new Date().toISOString(),
        required: ['email', 'id'], // Added required field
        optional: ['name'],
        types: { email: 'string', name: 'string', id: 'string' },
        nested: {},
        enums: {}
      };
      
      const comparison = detector.compareSchemas(newStructure, oldStructure);
      const suggestions = detector.generateMigrationSuggestions(comparison);
      
      expect(comparison.breaking.length).toBeGreaterThan(0);
      expect(suggestions.length).toBeGreaterThan(0);
      expect(suggestions[0]).toContain('BREAKING CHANGES DETECTED');
    });
  });
});

// ==================== SCHEMA REGRESSION PREVENTION ====================

describe('Schema Regression Prevention', () => {
  test('should prevent accidental schema weakening', () => {
    // Ensure that validation rules don't accidentally become less strict
    
    // Email should still require valid format
    const invalidEmail = { email: 'not-an-email' };
    expect(UserSchema.safeParse(invalidEmail).success).toBe(false);
    
    // UUIDs should still be validated
    const invalidUUID = { 
      email: 'test@example.com', 
      id: 'not-a-uuid' 
    };
    expect(UserSchema.safeParse(invalidUUID).success).toBe(false);
    
    // Required fields should still be required
    const missingEmail = { name: 'Test User' };
    expect(UserSchema.safeParse(missingEmail).success).toBe(false);
  });

  test('should maintain enum constraint integrity', () => {
    // Ensure enum validations haven't been accidentally loosened
    const invalidGarmentType = {
      user_id: '123e4567-e89b-12d3-a456-426614174000',
      original_image_id: '123e4567-e89b-12d3-a456-426614174001',
      file_path: '/path/file.jpg',
      mask_path: '/path/mask.png',
      metadata: {
        type: 'invalid_type', // Should fail
        color: 'blue'
      }
    };
    
    expect(GarmentSchema.safeParse(invalidGarmentType).success).toBe(false);
  });
});

// ==================== EXPORT FOR CI/CD INTEGRATION ====================

export { SchemaEvolutionDetector };
export type { SchemaStructure, SchemaComparison };