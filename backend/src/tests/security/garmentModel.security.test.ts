// filepath: /backend/src/tests/unit/garmentModel.security.test.ts

// Mock dependencies BEFORE importing anything
jest.mock('../../utils/modelUtils', () => ({
  getQueryFunction: jest.fn()
}));

jest.mock('../../models/db', () => ({
  query: jest.fn()
}));

jest.mock('uuid', () => ({
  v4: jest.fn(),
  validate: jest.fn()
}));

// Now import dependencies
import * as uuid from 'uuid';
import { query } from '../../models/db';
import { getQueryFunction } from '../../utils/modelUtils';
import { garmentModel, CreateGarmentInput } from '../../models/garmentModel';

// Type the mocks for TypeScript
const mockQuery = query as jest.Mock;
const mockGetQueryFunction = getQueryFunction as jest.Mock;
const mockUuidV4 = uuid.v4 as jest.Mock;
const mockUuidValidate = uuid.validate as jest.Mock;

describe('Garment Model Security Tests', () => {
    // Sample test data
    const validUuid = '123e4567-e89b-12d3-a456-426614174000';
    const invalidUuid = 'not-a-valid-uuid';
    const sqlInjectionAttempt = "'; DROP TABLE garment_items; --";
    const mockTimestamp = new Date();
    let uuidCounter = 0;
    
    const generateUniqueValidUuid = () => 
      `123e4567-e89b-12d3-a456-${String(++uuidCounter).padStart(12, '0')}`;
    
    const mockGarment = {
        id: validUuid,
        user_id: 'user123',
        original_image_id: 'image123',
        file_path: '/path/to/file.jpg',
        mask_path: '/path/to/mask.png',
        metadata: { type: 'shirt' },
        created_at: mockTimestamp,
        updated_at: mockTimestamp,
        data_version: 1
    };

    beforeEach(() => {
        // Reset all mocks
        jest.clearAllMocks();
        uuidCounter = 0;
        
        // Setup UUID mocks
        mockUuidV4.mockImplementation(generateUniqueValidUuid);
        mockUuidValidate.mockImplementation((id) => {
            return typeof id === 'string' && 
                /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
        });
        
        // CRITICAL: Make getQueryFunction return our mockQuery
        mockGetQueryFunction.mockReturnValue(mockQuery);
    });

    describe('UUID Validation', () => {
        it('should reject invalid UUIDs in findById', async () => {
            const result = await garmentModel.findById(invalidUuid);
            
            expect(result).toBeNull();
            expect(mockQuery).not.toHaveBeenCalled();
        });

        it('should reject invalid UUIDs in updateMetadata', async () => {
            const result = await garmentModel.updateMetadata(invalidUuid, { metadata: { updated: true } });
            
            expect(result).toBeNull();
            expect(mockQuery).not.toHaveBeenCalled();
        });

        it('should reject invalid UUIDs in delete', async () => {
            const result = await garmentModel.delete(invalidUuid);
            
            expect(result).toBe(false);
            expect(mockQuery).not.toHaveBeenCalled();
        });
    });

    describe('SQL Injection Prevention', () => {
        it('should safely handle potential SQL injection in user_id parameter', async () => {
            // Setup mock to return empty results
            mockQuery.mockResolvedValueOnce({ rows: [] });
            
            await garmentModel.findByUserId(sqlInjectionAttempt);
            
            // Verify the raw SQL string was passed as a parameter, not interpolated
            expect(mockQuery).toHaveBeenCalledWith(
                expect.any(String),
                expect.arrayContaining([sqlInjectionAttempt])
            );
        });

        it('should safely handle potential SQL injection in garment_id', async () => {
            // Override UUID validation to let SQL injection string pass
            mockUuidValidate.mockReturnValueOnce(true);
            
            // Setup mock to return empty results
            mockQuery.mockResolvedValueOnce({ rows: [] });
            
            await garmentModel.findById(sqlInjectionAttempt);
            
            // Verify the raw input was passed as a parameter, not interpolated
            expect(mockQuery).toHaveBeenCalledWith(
                expect.any(String),
                expect.arrayContaining([sqlInjectionAttempt])
            );
        });

        it('should safely handle malicious content in metadata', async () => {
            const maliciousMetadata = {
                attack: `"'); DROP TABLE users; --`,
                script: `<script>alert('XSS')</script>`,
                nested: { dangerous: `'); DELETE FROM garment_items; --` }
            };
            
            // Generate a unique ID for this test
            const uniqueId = generateUniqueValidUuid();
            mockUuidV4.mockReturnValueOnce(uniqueId);
            
            // Mock create to return a successful result
            mockQuery.mockResolvedValueOnce({ 
                rows: [{
                    ...mockGarment,
                    id: uniqueId,
                    metadata: maliciousMetadata
                }]
            });
            
            await garmentModel.create({
                user_id: 'user123',
                original_image_id: 'image123',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png',
                metadata: maliciousMetadata
            });
            
            // Verify metadata was properly JSON stringified
            expect(mockQuery).toHaveBeenCalledWith(
                expect.any(String),
                expect.arrayContaining([
                    uniqueId,
                    'user123',
                    'image123',
                    '/path/to/file.jpg',
                    '/path/to/mask.png',
                    JSON.stringify(maliciousMetadata)
                ])
            );
        });

        it('should safely handle SQL injection attempts in string fields during create', async () => {
            const uniqueId = generateUniqueValidUuid();
            mockUuidV4.mockReturnValueOnce(uniqueId); // Ensure create uses a fresh, valid UUID

            const injectionInput: CreateGarmentInput = {
                user_id: sqlInjectionAttempt, // SQL Injection attempt
                original_image_id: sqlInjectionAttempt, // SQL Injection attempt
                file_path: sqlInjectionAttempt, // SQL Injection attempt
                mask_path: sqlInjectionAttempt, // SQL Injection attempt
                metadata: { safe: "data" }
            };
            // Mock the expected return after successful creation
            mockQuery.mockResolvedValueOnce({ rows: [{ ...injectionInput, id: uniqueId, created_at: mockTimestamp, updated_at: mockTimestamp, data_version: 1 }] });

            await garmentModel.create(injectionInput);

            expect(mockQuery).toHaveBeenCalledWith(
                expect.stringContaining('INSERT INTO garment_items'),
                [
                    uniqueId,
                    injectionInput.user_id,
                    injectionInput.original_image_id,
                    injectionInput.file_path,
                    injectionInput.mask_path,
                    JSON.stringify(injectionInput.metadata)
                ]
            );
        });
    });

    describe('Metadata Security', () => {
        it('should safely handle deeply nested metadata objects', async () => {
            const complexMetadata = {
                level1: {
                    level2: {
                        level3: {
                            level4: { sensitive: 'data' }
                        }
                    }
                },
                array: [1, 2, { nested: 'value' }]
            };
            
            // Generate a unique ID for this test
            const uniqueId = generateUniqueValidUuid();
            mockUuidV4.mockReturnValueOnce(uniqueId);
            
            // Mock create to return a successful result
            mockQuery.mockResolvedValueOnce({ 
                rows: [{
                    ...mockGarment,
                    id: uniqueId,
                    metadata: complexMetadata
                }]
            });
            
            await garmentModel.create({
                user_id: 'user123',
                original_image_id: 'image123',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png',
                metadata: complexMetadata
            });
            
            // Verify complex object was properly stringified
            expect(mockQuery).toHaveBeenCalledWith(
                expect.any(String),
                expect.arrayContaining([
                    uniqueId,
                    'user123',
                    'image123',
                    '/path/to/file.jpg',
                    '/path/to/mask.png',
                    JSON.stringify(complexMetadata)
                ])
            );
        });

        it('should prevent metadata prototype pollution', async () => {
            // Create an object with a potentially dangerous __proto__ property
            const dangerousMetadata = JSON.parse('{"__proto__": {"polluted": true}}');
            
            // Generate a unique ID for this test
            const uniqueId = generateUniqueValidUuid();
            mockUuidV4.mockReturnValueOnce(uniqueId);
            
            // Mock create to return a successful result
            mockQuery.mockResolvedValueOnce({ 
                rows: [{
                    ...mockGarment,
                    id: uniqueId,
                    metadata: dangerousMetadata
                }]
            });
            
            await garmentModel.create({
                user_id: 'user123',
                original_image_id: 'image123',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png',
                metadata: dangerousMetadata
            });
            
            // Verify the dangerous object was passed as-is to be stringified
            expect(mockQuery).toHaveBeenCalledWith(
                expect.any(String),
                expect.arrayContaining([
                    uniqueId,
                    'user123',
                    'image123',
                    '/path/to/file.jpg',
                    '/path/to/mask.png',
                    expect.stringContaining("__proto__")
                ])
            );
            
            // Verify Object prototype wasn't polluted
            expect({}.hasOwnProperty('polluted')).toBe(false);
        });

        it('should properly merge metadata during updates without losing data', async () => {
            // Setup existing garment with metadata
            const existingMetadata = { color: 'blue', size: 'medium' };
            const existingGarment = {
                ...mockGarment,
                metadata: existingMetadata
            };
            
            // Setup update with new partial metadata
            const updateMetadata = { color: 'red', material: 'cotton' };
            
            // Mock the first query (findById) to return existing garment
            mockQuery.mockResolvedValueOnce({ rows: [existingGarment] });
            
            // Mock the second query (update) to return updated garment
            mockQuery.mockResolvedValueOnce({ 
                rows: [{
                    ...existingGarment,
                    metadata: { ...existingMetadata, ...updateMetadata },
                    data_version: 2
                }]
            });
            
            const result = await garmentModel.updateMetadata(validUuid, { metadata: updateMetadata });
            
            // Verify the update query was called with properly merged metadata
            expect(mockQuery).toHaveBeenNthCalledWith(2,
                expect.any(String),
                expect.arrayContaining([
                    JSON.stringify({ color: 'red', size: 'medium', material: 'cotton' }),
                    validUuid
                ])
            );
            
            // Verify the returned object has the correctly merged metadata
            expect(result?.metadata).toEqual({
                color: 'red',
                size: 'medium',
                material: 'cotton'
            });
        });

        it('should prevent metadata prototype pollution when updating metadata', async () => {
            const dangerousUpdateMetadata = JSON.parse('{"__proto__": {"pollutedUpdate": true}}');
            const existingGarment = { ...mockGarment, id: validUuid, metadata: { original: "value" } };

            mockUuidValidate.mockReturnValueOnce(true); // Assume validUuid passes validation
            mockQuery.mockResolvedValueOnce({ rows: [existingGarment] }); // For findById
            // Mock the update query to return the garment with (theoretically) merged metadata
            mockQuery.mockResolvedValueOnce({ rows: [{ ...existingGarment, metadata: { original: "value", "__proto__": {"pollutedUpdate": true} } as any, updated_at: new Date(), data_version: existingGarment.data_version + 1 }] });

            await garmentModel.updateMetadata(validUuid, { metadata: dangerousUpdateMetadata });

            expect(mockQuery).toHaveBeenCalledTimes(2);
            // Check the second call (the actual update)
            const updateCallArgs = mockQuery.mock.calls[1];
            expect(updateCallArgs[0]).toContain('UPDATE garment_items');
            
            // The merged metadata should be stringified, including the __proto__ key
            const actualMetadataString = updateCallArgs[1][0]; // First parameter of the update query (metadata JSON)
            expect(actualMetadataString).toContain('"__proto__":');
            expect(actualMetadataString).toContain('"pollutedUpdate":true');
            expect(actualMetadataString).toContain('"original":"value"'); // Ensure original data is there
            
            expect(({} as any)['pollutedUpdate']).toBeUndefined();
            expect({}.hasOwnProperty('pollutedUpdate')).toBe(false);
        });

        it('should reject update if metadata is not an object', async () => {
            // Suppress console.error for this specific test
            const consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

            // Ensure the ID validation for 'id' itself passes
            mockUuidValidate.mockReturnValueOnce(true); 

            // Attempt to update with metadata that is not an object (e.g., a string)
            // We cast to 'any' to bypass TypeScript's strict type checking for this test input.
            const result = await garmentModel.updateMetadata(validUuid, { metadata: "not an object" as any });

            // Expect the model to return null due to invalid metadata format
            expect(result).toBeNull();
            
            // Crucially, expect that no database query was made because the 
            // metadata format validation should have caused an early exit.
            expect(mockQuery).not.toHaveBeenCalled();

            // Restore the original console.error implementation
            consoleErrorSpy.mockRestore();
        });
    });

    describe('Error Handling', () => {
        it('should propagate database errors during creation', async () => {
            const dbError = new Error('Database connection failed');
            mockQuery.mockRejectedValueOnce(dbError);
            
            // Generate a unique ID for this test
            const uniqueId = generateUniqueValidUuid();
            mockUuidV4.mockReturnValueOnce(uniqueId);
            
            await expect(garmentModel.create({
                user_id: 'user123',
                original_image_id: 'image123',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png'
            })).rejects.toThrow('Database connection failed');
        });

        it('should propagate database errors during findById', async () => {
            const dbError = new Error('Query execution failed');
            mockQuery.mockRejectedValueOnce(dbError);
            
            await expect(garmentModel.findById(validUuid)).rejects.toThrow('Query execution failed');
        });

        it('should handle empty result sets gracefully', async () => {
            mockQuery.mockResolvedValueOnce({ rows: [] });
            
            const result = await garmentModel.findById(validUuid);
            
            expect(result).toBeNull();
        });

        it('should return null when trying to update metadata for a non-existent garment', async () => {
            mockUuidValidate.mockReturnValueOnce(true); // Assume validUuid passes validation
            mockQuery.mockResolvedValueOnce({ rows: [] }); // findById returns no garment

            const result = await garmentModel.updateMetadata(validUuid, { metadata: { any: "data" } });

            expect(result).toBeNull();
            expect(mockQuery).toHaveBeenCalledTimes(1); // Only findById should be called
        });

        it('should propagate database errors during the UPDATE phase of updateMetadata', async () => {
            const dbError = new Error('DB UPDATE failed');
            mockUuidValidate.mockReturnValueOnce(true); // Assume validUuid passes validation
            mockQuery.mockResolvedValueOnce({ rows: [{ ...mockGarment, id: validUuid }] }); // findById succeeds
            mockQuery.mockRejectedValueOnce(dbError); // The actual UPDATE query fails

            await expect(garmentModel.updateMetadata(validUuid, { metadata: { any: "data" } })).rejects.toThrow('DB UPDATE failed');
            expect(mockQuery).toHaveBeenCalledTimes(2); // findById and the failed update
        });

        it('should return false when trying to delete a non-existent garment', async () => {
            mockUuidValidate.mockReturnValueOnce(true); // Assume validUuid passes validation
            mockQuery.mockResolvedValueOnce({ rowCount: 0 }); // DB reports 0 rows deleted

            const result = await garmentModel.delete(validUuid);

            expect(result).toBe(false);
            expect(mockQuery).toHaveBeenCalledTimes(1);
        });

        it('should propagate database errors during delete', async () => {
            const dbError = new Error('DB DELETE failed');
            mockUuidValidate.mockReturnValueOnce(true); // Assume validUuid passes validation
            mockQuery.mockRejectedValueOnce(dbError); // The DELETE query fails

            await expect(garmentModel.delete(validUuid)).rejects.toThrow('DB DELETE failed');
            expect(mockQuery).toHaveBeenCalledTimes(1);
        });
    });

    describe('Data Integrity', () => {
        it('should increment data_version during metadata updates', async () => {
            // Mock findById to return garment
            mockQuery.mockResolvedValueOnce({ rows: [mockGarment] });
            
            // Mock the update query
            mockQuery.mockResolvedValueOnce({ 
                rows: [{
                    ...mockGarment,
                    metadata: { type: 'shirt', updated: true },
                    data_version: 2
                }]
            });
            
            const result = await garmentModel.updateMetadata(validUuid, { 
                metadata: { updated: true } 
            });
            
            // Verify data_version was incremented in the query
            expect(mockQuery).toHaveBeenNthCalledWith(2,
                expect.stringContaining('data_version = data_version + 1'),
                expect.any(Array)
            );
            
            expect(result?.data_version).toBe(2);
        });

        it('should handle undefined metadata in create by using empty object', async () => {
            // Generate a unique ID for this test
            const uniqueId = generateUniqueValidUuid();
            mockUuidV4.mockReturnValueOnce(uniqueId);
            
            mockQuery.mockResolvedValueOnce({ 
                rows: [{
                    ...mockGarment,
                    id: uniqueId,
                    metadata: {}
                }]
            });
            
            await garmentModel.create({
                user_id: 'user123',
                original_image_id: 'image123',
                file_path: '/path/to/file.jpg',
                mask_path: '/path/to/mask.png'
                // metadata intentionally omitted
            });
            
            // Verify empty object was used for metadata
            expect(mockQuery).toHaveBeenCalledWith(
                expect.any(String),
                expect.arrayContaining([
                    uniqueId,
                    'user123',
                    'image123',
                    '/path/to/file.jpg',
                    '/path/to/mask.png',
                    '{}'
                ])
            );
        });
    });
});