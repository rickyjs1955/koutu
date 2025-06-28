// shared/src/__tests__/setup/schemaMatchers.ts
export const schemaMatchers = `
import { expect } from '@jest/globals';
import { z } from 'zod';

// Custom Jest matchers for schema testing
expect.extend({
  /**
   * Test if data is valid for a schema
   */
  toBeValidFor(received: unknown, schema: z.ZodSchema) {
    const result = schema.safeParse(received);
    
    if (result.success) {
      return {
        message: () => \`Expected data not to be valid for schema\`,
        pass: true,
      };
    } else {
      return {
        message: () => 
          \`Expected data to be valid for schema, but got errors: \${
            result.error.issues.map(issue => \`\${issue.path.join('.')}: \${issue.message}\`).join(', ')
          }\`,
        pass: false,
      };
    }
  },

  /**
   * Test if data is invalid for a schema
   */
  toBeInvalidFor(received: unknown, schema: z.ZodSchema) {
    const result = schema.safeParse(received);
    
    if (!result.success) {
      return {
        message: () => \`Expected data to be valid for schema\`,
        pass: true,
      };
    } else {
      return {
        message: () => \`Expected data to be invalid for schema, but validation passed\`,
        pass: false,
      };
    }
  },

  /**
   * Test if validation error contains specific field
   */
  toHaveValidationErrorFor(received: unknown, schema: z.ZodSchema, field: string) {
    const result = schema.safeParse(received);
    
    if (!result.success) {
      const hasFieldError = result.error.issues.some(issue => 
        issue.path.join('.').includes(field) || issue.path.includes(field)
      );
      
      if (hasFieldError) {
        return {
          message: () => \`Expected validation not to have error for field '\${field}'\`,
          pass: true,
        };
      } else {
        return {
          message: () => 
            \`Expected validation to have error for field '\${field}', but errors were: \${
              result.error.issues.map(issue => issue.path.join('.')).join(', ')
            }\`,
          pass: false,
        };
      }
    } else {
      return {
        message: () => \`Expected validation to fail and have error for field '\${field}', but validation passed\`,
        pass: false,
      };
    }
  },

  /**
   * Test if schema transformation produces expected result
   */
  toTransformTo(received: unknown, schema: z.ZodSchema, expected: any) {
    const result = schema.safeParse(received);
    
    if (result.success) {
      if (JSON.stringify(result.data) === JSON.stringify(expected)) {
        return {
          message: () => \`Expected transformation not to produce expected result\`,
          pass: true,
        };
      } else {
        return {
          message: () => 
            \`Expected transformation to produce \${JSON.stringify(expected)}, but got \${JSON.stringify(result.data)}\`,
          pass: false,
        };
      }
    } else {
      return {
        message: () => \`Expected transformation to succeed, but got validation errors: \${
          result.error.issues.map(issue => issue.message).join(', ')
        }\`,
        pass: false,
      };
    }
  }
});

// Type declarations for custom matchers
declare global {
  namespace jest {
    interface Matchers<R> {
      toBeValidFor(schema: z.ZodSchema): R;
      toBeInvalidFor(schema: z.ZodSchema): R;
      toHaveValidationErrorFor(schema: z.ZodSchema, field: string): R;
      toTransformTo(schema: z.ZodSchema, expected: any): R;
    }
  }
}
`;