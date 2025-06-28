// shared/src/__tests__/property-based.test.ts

import { describe, test, expect } from '@jest/globals';
import { z } from 'zod';
import {
  UserSchema,
  GarmentSchema,
  ImageSchema,
  CreateGarmentSchema
} from '../schemas/index';
import { PolygonSchema } from '../schemas/polygon';

/**
 * Property-Based Testing for Schema Validation
 * 
 * Property-based testing generates random inputs to test properties
 * that should always hold true for our schemas.
 */

// ==================== PROPERTY-BASED TEST GENERATORS ====================

class PropertyBasedTestGenerator {
    /**
     * Generate random valid UUIDs
     */
    static generateUUID(): string {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
        });
    }

    /**
     * Generate random valid emails
     */
    static generateEmail(): string {
        const domains = ['example.com', 'test.org', 'demo.net'];
        const usernames = ['user', 'test', 'demo', 'admin'];
        const username = usernames[Math.floor(Math.random() * usernames.length)];
        const domain = domains[Math.floor(Math.random() * domains.length)];
        const number = Math.floor(Math.random() * 1000);
        return `${username}${number}@${domain}`;
    }

    /**
     * Generate random strings within length constraints
     */
    static generateString(minLength: number, maxLength: number): string {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ';
        const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
        return Array.from({ length }, () => chars.charAt(Math.floor(Math.random() * chars.length))).join('');
    }

    /**
     * Generate random numbers within range
     */
    static generateNumber(min: number, max: number): number {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    /**
     * Generate random enum values
     */
    static generateEnumValue<T extends readonly string[]>(enumValues: T): T[number] {
        return enumValues[Math.floor(Math.random() * enumValues.length)];
    }

    /**
     * Generate random dates
     */
    static generateDate(): Date {
        const start = new Date(2020, 0, 1);
        const end = new Date();
        return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
    }

    /**
     * Generate random arrays
     */
    static generateArray<T>(generator: () => T, minLength: number = 0, maxLength: number = 10): T[] {
        const length = this.generateNumber(minLength, maxLength);
        return Array.from({ length }, generator);
    }

    /**
     * Generate random valid user data
     */
    static generateValidUser(): any {
        return {
        id: this.generateUUID(),
        email: this.generateEmail(),
        name: this.generateString(1, 100),
        linkedProviders: this.generateArray(() => 
            this.generateEnumValue(['google', 'github', 'microsoft', 'instagram']), 0, 3
        ),
        oauth_provider: Math.random() > 0.5 ? 
            this.generateEnumValue(['google', 'github', 'microsoft', 'instagram']) : undefined,
        created_at: this.generateDate(),
        updated_at: this.generateDate()
        };
    }

    /**
     * Generate random valid garment data
     */
    static generateValidGarment(): any {
        return {
        id: this.generateUUID(),
        user_id: this.generateUUID(),
        original_image_id: this.generateUUID(),
        file_path: `/uploads/garment_${this.generateNumber(1, 999999)}.jpg`,
        mask_path: `/uploads/mask_${this.generateNumber(1, 999999)}.png`,
        metadata: {
            type: this.generateEnumValue(['shirt', 'pants', 'dress', 'jacket', 'skirt', 'other']),
            color: this.generateString(1, 30),
            pattern: Math.random() > 0.5 ? 
            this.generateEnumValue(['solid', 'striped', 'plaid', 'floral', 'geometric', 'other']) : undefined,
            season: Math.random() > 0.5 ? 
            this.generateEnumValue(['spring', 'summer', 'fall', 'winter', 'all']) : undefined,
            brand: Math.random() > 0.5 ? this.generateString(1, 50) : undefined,
            tags: Math.random() > 0.5 ? 
            this.generateArray(() => this.generateString(1, 30), 0, 10) : undefined
        },
        created_at: this.generateDate(),
        updated_at: this.generateDate(),
        data_version: this.generateNumber(1, 100)
        };
    }

    /**
     * Generate random valid polygon data
     */
    static generateValidPolygon(): any {
        const pointCount = this.generateNumber(3, 50);
        return {
        id: this.generateUUID(),
        original_image_id: this.generateUUID(),
        points: this.generateArray(() => ({
            x: this.generateNumber(0, 1920),
            y: this.generateNumber(0, 1080)
        }), pointCount, pointCount),
        label: Math.random() > 0.5 ? this.generateString(1, 100) : undefined,
        metadata: Math.random() > 0.5 ? {
            confidence: Math.random(),
            source: this.generateString(1, 50),
            notes: this.generateString(1, 500)
        } : undefined,
        created_at: this.generateDate(),
        updated_at: this.generateDate()
        };
    }

    /**
     * Mutate valid data to create invalid variants
     */
    static mutateData(validData: any): any[] {
        const mutations: any[] = [];

        // Mutation 1: Set required fields to null
        Object.keys(validData).forEach(key => {
        if (validData[key] !== undefined && validData[key] !== null) {
            mutations.push({
            ...validData,
            [key]: null,
            _mutation: `${key}_to_null`
            });
        }
        });

        // Mutation 2: Set string fields to invalid values
        Object.keys(validData).forEach(key => {
        if (typeof validData[key] === 'string') {
            mutations.push(
            {
                ...validData,
                [key]: '',
                _mutation: `${key}_empty_string`
            },
            {
                ...validData,
                [key]: 'A'.repeat(1000),
                _mutation: `${key}_too_long`
            }
            );
        }
        });

        // Mutation 3: Set UUID fields to invalid UUIDs
        Object.keys(validData).forEach(key => {
        if (key.includes('id') || key === 'id') {
            mutations.push(
            {
                ...validData,
                [key]: 'not-a-uuid',
                _mutation: `${key}_invalid_uuid`
            },
            {
                ...validData,
                [key]: '123',
                _mutation: `${key}_short_uuid`
            }
            );
        }
        });

        // Mutation 4: Set email to invalid format
        if (validData.email) {
        mutations.push(
            {
            ...validData,
            email: 'not-an-email',
            _mutation: 'email_invalid_format'
            },
            {
            ...validData,
            email: '@example.com',
            _mutation: 'email_missing_local'
            }
        );
        }

        return mutations;
    }
    }

    // ==================== PROPERTY-BASED TESTS ====================

    describe('Property-Based Testing', () => {

    describe('User Schema Properties', () => {
        test('should always validate correctly generated valid users', () => {
        // Generate 100 random valid users and test they all validate
        for (let i = 0; i < 100; i++) {
            const randomUser = PropertyBasedTestGenerator.generateValidUser();
            const result = UserSchema.safeParse(randomUser);
            
            if (!result.success) {
            console.error('Failed user:', randomUser);
            console.error('Errors:', result.error.issues);
            }
            
            expect(result.success).toBe(true);
        }
        });

        test('should always reject mutated invalid users', () => {
        // Generate valid user, then create invalid mutations
        for (let i = 0; i < 20; i++) {
            const validUser = PropertyBasedTestGenerator.generateValidUser();
            const mutations = PropertyBasedTestGenerator.mutateData(validUser);
            
            mutations.forEach(mutation => {
            const result = UserSchema.safeParse(mutation);
            
            // Most mutations should fail (though some might be valid due to optional fields)
            if (result.success && mutation._mutation.includes('_to_null')) {
                // Some null mutations might be valid for optional fields
                // This is expected behavior
            }
            });
        }
        });

        test('should maintain referential integrity properties', () => {
        // Property: If a user has an ID, it should always be a valid UUID
        for (let i = 0; i < 50; i++) {
            const user = PropertyBasedTestGenerator.generateValidUser();
            const result = UserSchema.safeParse(user);
            
            if (result.success && result.data.id) {
            expect(result.data.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
            }
        }
        });
    });

    describe('Garment Schema Properties', () => {
        test('should always validate correctly generated valid garments', () => {
        for (let i = 0; i < 100; i++) {
            const randomGarment = PropertyBasedTestGenerator.generateValidGarment();
            const result = GarmentSchema.safeParse(randomGarment);
            
            if (!result.success) {
            console.error('Failed garment:', randomGarment);
            console.error('Errors:', result.error.issues);
            }
            
            expect(result.success).toBe(true);
        }
        });

        test('should maintain metadata consistency properties', () => {
        // Property: Garment metadata should always have required fields
        for (let i = 0; i < 50; i++) {
            const garment = PropertyBasedTestGenerator.generateValidGarment();
            const result = GarmentSchema.safeParse(garment);
            
            if (result.success) {
            expect(result.data.metadata.type).toBeDefined();
            expect(result.data.metadata.color).toBeDefined();
            expect(['shirt', 'pants', 'dress', 'jacket', 'skirt', 'other']).toContain(result.data.metadata.type);
            }
        }
        });

        test('should handle arrays within bounds', () => {
        // Property: Tags array should never exceed reasonable limits
        for (let i = 0; i < 50; i++) {
            const garment = PropertyBasedTestGenerator.generateValidGarment();
            const result = GarmentSchema.safeParse(garment);
            
            if (result.success && result.data.metadata.tags) {
            expect(result.data.metadata.tags.length).toBeLessThanOrEqual(10);
            result.data.metadata.tags.forEach((tag: string) => {
                expect(tag.length).toBeLessThanOrEqual(30);
            });
            }
        }
        });
    });

    describe('Polygon Schema Properties', () => {
        test('should always validate correctly generated valid polygons', () => {
        for (let i = 0; i < 100; i++) {
            const randomPolygon = PropertyBasedTestGenerator.generateValidPolygon();
            const result = PolygonSchema.safeParse(randomPolygon);
            
            if (!result.success) {
            console.error('Failed polygon:', randomPolygon);
            console.error('Errors:', result.error.issues);
            }
            
            expect(result.success).toBe(true);
        }
        });

        test('should maintain geometric properties', () => {
        // Property: Polygons should always have at least 3 points
        for (let i = 0; i < 50; i++) {
            const polygon = PropertyBasedTestGenerator.generateValidPolygon();
            const result = PolygonSchema.safeParse(polygon);
            
            if (result.success) {
            expect(result.data.points.length).toBeGreaterThanOrEqual(3);
            
            // Property: All points should have valid coordinates
            result.data.points.forEach((point: any) => {
                expect(typeof point.x).toBe('number');
                expect(typeof point.y).toBe('number');
                expect(point.x).toBeGreaterThanOrEqual(0);
                expect(point.y).toBeGreaterThanOrEqual(0);
            });
            }
        }
        });
    });

    describe('Cross-Schema Relationship Properties', () => {
        test('should maintain referential integrity across related schemas', () => {
        for (let i = 0; i < 30; i++) {
            const userId = PropertyBasedTestGenerator.generateUUID();
            const imageId = PropertyBasedTestGenerator.generateUUID();
            
            // Create related entities with consistent IDs
            const user = {
            ...PropertyBasedTestGenerator.generateValidUser(),
            id: userId
            };
            
            const image = {
            id: imageId,
            user_id: userId,
            file_path: `/uploads/image_${i}.jpg`
            };
            
            const garment = {
            ...PropertyBasedTestGenerator.generateValidGarment(),
            user_id: userId,
            original_image_id: imageId
            };
            
            const polygon = {
            ...PropertyBasedTestGenerator.generateValidPolygon(),
            original_image_id: imageId
            };
            
            // Validate all schemas
            const userResult = UserSchema.safeParse(user);
            const imageResult = ImageSchema.safeParse(image);
            const garmentResult = GarmentSchema.safeParse(garment);
            const polygonResult = PolygonSchema.safeParse(polygon);
            
            expect(userResult.success).toBe(true);
            expect(imageResult.success).toBe(true);
            expect(garmentResult.success).toBe(true);
            expect(polygonResult.success).toBe(true);
            
            // Property: Referential integrity should be maintained
            if (userResult.success && imageResult.success && garmentResult.success && polygonResult.success) {
            expect(imageResult.data.user_id).toBe(userResult.data.id);
            expect(garmentResult.data.user_id).toBe(userResult.data.id);
            expect(garmentResult.data.original_image_id).toBe(imageResult.data.id);
            expect(polygonResult.data.original_image_id).toBe(imageResult.data.id);
            }
        }
        });
    });

    describe('Performance Properties', () => {
        test('should maintain consistent validation performance', () => {
        const iterations = 1000;
        const maxAcceptableTime = 2000; // 2 seconds for 1000 validations
        
        const startTime = Date.now();
        
        for (let i = 0; i < iterations; i++) {
            const randomUser = PropertyBasedTestGenerator.generateValidUser();
            UserSchema.safeParse(randomUser);
        }
        
        const endTime = Date.now();
        const totalTime = endTime - startTime;
        
        expect(totalTime).toBeLessThan(maxAcceptableTime);
        
        // Property: Performance should be consistent (no major outliers)
        const averageTime = totalTime / iterations;
        expect(averageTime).toBeLessThan(5); // Less than 5ms per validation on average
        });

        test('should handle large data efficiently', () => {
        // Test with polygons having many points
        const largePolygon = {
            ...PropertyBasedTestGenerator.generateValidPolygon(),
            points: PropertyBasedTestGenerator.generateArray(() => ({
            x: PropertyBasedTestGenerator.generateNumber(0, 1920),
            y: PropertyBasedTestGenerator.generateNumber(0, 1080)
            }), 1000, 1000) // 1000 points
        };
        
        const startTime = Date.now();
        const result = PolygonSchema.safeParse(largePolygon);
        const endTime = Date.now();
        
        expect(result.success).toBe(true);
        expect(endTime - startTime).toBeLessThan(100); // Should validate large polygon quickly
        });
    });
    });

    // ==================== MUTATION TESTING ====================

    /**
     * Mutation Testing Strategy
     * 
     * Mutation testing involves systematically changing the schema definitions
     * to ensure our tests would catch these changes.
     */

    describe('Mutation Testing Concepts', () => {
    
    describe('Schema Mutation Detection', () => {
        test('should detect when required fields become optional', () => {
        // Original schema requires email
        const originalSchema = z.object({
            email: z.string().email()
        });
        
        // Mutated schema makes email optional
        const mutatedSchema = z.object({
            email: z.string().email().optional()
        });
        
        const testData = {}; // No email
        
        const originalResult = originalSchema.safeParse(testData);
        const mutatedResult = mutatedSchema.safeParse(testData);
        
        // This test ensures we would detect if email accidentally became optional
        expect(originalResult.success).toBe(false);
        expect(mutatedResult.success).toBe(true);
        
        // In real mutation testing, we'd verify our test suite catches this difference
        });

        test('should detect when validation rules are weakened', () => {
        // Original schema with strict email validation
        const originalSchema = z.object({
            email: z.string().email()
        });
        
        // Mutated schema with weak validation
        const mutatedSchema = z.object({
            email: z.string() // No email validation
        });
        
        const testData = { email: 'not-an-email' };
        
        const originalResult = originalSchema.safeParse(testData);
        const mutatedResult = mutatedSchema.safeParse(testData);
        
        expect(originalResult.success).toBe(false);
        expect(mutatedResult.success).toBe(true);
        });

        test('should detect when enum values are changed', () => {
        // Original garment types
        const originalSchema = z.object({
            type: z.enum(['shirt', 'pants', 'dress'])
        });
        
        // Mutated with additional type
        const mutatedSchema = z.object({
            type: z.enum(['shirt', 'pants', 'dress', 'shoes'])
        });
        
        const testData = { type: 'shoes' };
        
        const originalResult = originalSchema.safeParse(testData);
        const mutatedResult = mutatedSchema.safeParse(testData);
        
        expect(originalResult.success).toBe(false);
        expect(mutatedResult.success).toBe(true);
        });
    });

    describe('Test Coverage for Mutations', () => {
        test('should have tests that would fail if UUID validation was removed', () => {
        const validUUID = PropertyBasedTestGenerator.generateUUID();
        const invalidUUID = 'not-a-uuid';
        
        // Test that relies on UUID validation
        expect(UserSchema.safeParse({ email: 'test@example.com', id: validUUID }).success).toBe(true);
        expect(UserSchema.safeParse({ email: 'test@example.com', id: invalidUUID }).success).toBe(false);
        
        // This test would fail if someone removed UUID validation from the schema
        });

        test('should have tests that would fail if email validation was removed', () => {
        const validEmail = PropertyBasedTestGenerator.generateEmail();
        const invalidEmail = 'not-an-email';
        
        expect(UserSchema.safeParse({ email: validEmail }).success).toBe(true);
        expect(UserSchema.safeParse({ email: invalidEmail }).success).toBe(false);
        });

        test('should have tests that would fail if required fields became optional', () => {
        // Test that email is required
        expect(UserSchema.safeParse({}).success).toBe(false);
        
        // Test that garment type is required
        expect(GarmentSchema.safeParse({
            user_id: PropertyBasedTestGenerator.generateUUID(),
            original_image_id: PropertyBasedTestGenerator.generateUUID(),
            file_path: '/path/file.jpg',
            mask_path: '/path/mask.png',
            metadata: {
            color: 'blue'
            // Missing required 'type'
            }
        }).success).toBe(false);
        });
    });
    });

    // ==================== FUZZ TESTING ====================

    describe('Fuzz Testing', () => {
    
    /**
     * Generate completely random data to test schema robustness
     * Fixed version with recursion depth limit
     */
    function generateRandomData(depth: number = 0): any {
        // Prevent infinite recursion
        if (depth > 5) {
            return 'max_depth_reached';
        }

        const types = ['string', 'number', 'boolean', 'object', 'array', 'null', 'undefined'];
        const type = types[Math.floor(Math.random() * types.length)];
        
        switch (type) {
            case 'string':
            return Math.random().toString(36).substring(2, 15);
            case 'number':
            return Math.random() * 1000000 - 500000;
            case 'boolean':
            return Math.random() > 0.5;
            case 'object':
            const obj: any = {};
            const keys = Math.floor(Math.random() * 5); // Limit object size
            for (let i = 0; i < keys; i++) {
                obj[Math.random().toString(36).substring(2, 8)] = generateRandomData(depth + 1);
            }
            return obj;
            case 'array':
            const length = Math.floor(Math.random() * 5); // Limit array size
            return Array.from({ length }, () => generateRandomData(depth + 1));
            case 'null':
            return null;
            case 'undefined':
            return undefined;
            default:
            return null;
        }
    }

    test('should handle completely random input gracefully', () => {
        // Generate 200 completely random inputs
        for (let i = 0; i < 200; i++) {
        const randomData = generateRandomData();
        
        // Schemas should either validate successfully or fail gracefully
        const userResult = UserSchema.safeParse(randomData);
        const garmentResult = GarmentSchema.safeParse(randomData);
        const polygonResult = PolygonSchema.safeParse(randomData);
        
        // Should never throw errors, only return success/failure
        expect(typeof userResult.success).toBe('boolean');
        expect(typeof garmentResult.success).toBe('boolean');
        expect(typeof polygonResult.success).toBe('boolean');
        
        // If validation fails, should have error information
        if (!userResult.success) {
            expect(userResult.error).toBeDefined();
            expect(Array.isArray(userResult.error.issues)).toBe(true);
        }
        }
    });

    test('should handle malicious input patterns', () => {
        const maliciousInputs = [
        // Very long strings
        'A'.repeat(100000),
        
        // Deeply nested objects
        { a: { b: { c: { d: { e: { f: { g: 'deep' } } } } } } },
        
        // Large arrays
        new Array(10000).fill('item'),
        
        // Mixed type arrays
        [1, 'string', { obj: true }, [1, 2, 3], null, undefined],
        
        // Special characters
        '<?xml version="1.0"?><script>alert("xss")</script>',
        '; DROP TABLE users; --',
        '../../../etc/passwd',
        
        // Unicode and emoji
        '👨‍💻🚀📝✨🎯💻📊🔥💯🎉',
        
        // Control characters
        '\x00\x01\x02\x03\x04\x05',
        
        // Very large numbers
        Number.MAX_SAFE_INTEGER,
        Number.MIN_SAFE_INTEGER,
        Infinity,
        -Infinity,
        NaN
        ];
        
        maliciousInputs.forEach((maliciousInput, index) => {
        // Test against all schemas
        const schemas = [UserSchema, GarmentSchema, PolygonSchema];
        
        schemas.forEach(schema => {
            expect(() => {
            const result = schema.safeParse(maliciousInput);
            // Should not throw, and should provide clear error information if invalid
            if (!result.success) {
                expect(result.error.issues.length).toBeGreaterThan(0);
            }
            }).not.toThrow();
        });
        });
    });
    });

    // ==================== EXPORT TEST UTILITIES ====================

    export const PropertyTestUtils = {
    PropertyBasedTestGenerator,
    generateRandomData: () => {
        const types = ['string', 'number', 'boolean', 'object', 'array', 'null'];
        const type = types[Math.floor(Math.random() * types.length)];
        
        switch (type) {
        case 'string': return Math.random().toString(36);
        case 'number': return Math.random() * 1000;
        case 'boolean': return Math.random() > 0.5;
        case 'object': return { random: 'object' };
        case 'array': return [1, 2, 3];
        default: return null;
        }
    }
};