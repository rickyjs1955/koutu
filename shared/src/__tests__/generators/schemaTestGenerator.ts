// ==================== AUTOMATED TEST GENERATION ====================

export const testGenerator = `
// shared/src/__tests__/generators/schemaTestGenerator.ts

import { z } from 'zod';
import fs from 'fs';
import path from 'path';

/**
 * Automated test generation for schemas
 */
export class SchemaTestGenerator {
  /**
   * Generate comprehensive tests for a schema
   */
  static generateTests(schemaName: string, schema: z.ZodSchema, outputPath: string) {
    const testContent = this.generateTestContent(schemaName, schema);
    fs.writeFileSync(outputPath, testContent);
  }

  private static generateTestContent(schemaName: string, schema: z.ZodSchema): string {
    return \`
// Auto-generated tests for \${schemaName}
import { describe, test, expect } from '@jest/globals';
import { \${schemaName} } from '../\${schemaName.toLowerCase()}';

describe('\${schemaName} Auto-Generated Tests', () => {
  describe('Basic Validation', () => {
    test('should validate minimal valid data', () => {
      const minimalData = \${this.generateMinimalValidData(schema)};
      expect(minimalData).toBeValidFor(\${schemaName});
    });

    test('should reject completely invalid data', () => {
      const invalidData = null;
      expect(invalidData).toBeInvalidFor(\${schemaName});
    });

    test('should reject empty object when required fields exist', () => {
      const emptyData = {};
      expect(emptyData).toBeInvalidFor(\${schemaName});
    });
  });

  describe('Field Validation', () => {
    \${this.generateFieldTests(schema)}
  });

  describe('Edge Cases', () => {
    \${this.generateEdgeCaseTests(schema)}
  });
});
\`;
  }

  private static generateMinimalValidData(schema: z.ZodSchema): string {
    // This would analyze the schema and generate minimal valid data
    // Implementation would be complex and specific to Zod internals
    return 'generateValidDataFromSchema(schema)';
  }

  private static generateFieldTests(schema: z.ZodSchema): string {
    // Generate tests for each field in the schema
    return '// Field-specific tests would be generated here';
  }

  private static generateEdgeCaseTests(schema: z.ZodSchema): string {
    // Generate edge case tests
    return '// Edge case tests would be generated here';
  }
}

// Usage example:
// SchemaTestGenerator.generateTests('UserSchema', UserSchema, './user.auto.test.ts');
`;