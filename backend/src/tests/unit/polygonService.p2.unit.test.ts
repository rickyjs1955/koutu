// /backend/src/tests/unit/polygonService.p2.unit.test.ts
import { describe, test, expect, jest, beforeEach } from '@jest/globals';
import { polygonService } from '../../services/polygonService';
import { polygonModel } from '../../models/polygonModel';
import { imageModel } from '../../models/imageModel';
import { storageService } from '../../services/storageService';
import { PolygonServiceUtils } from '../../utils/PolygonServiceUtils';
import { polygonProcessor } from '../../utils/polygonProcessor';
import { ApiError } from '../../utils/ApiError';

// Mock all dependencies
jest.mock('../../models/polygonModel');
jest.mock('../../models/imageModel');
jest.mock('../../services/storageService');
jest.mock('../../utils/PolygonServiceUtils');
jest.mock('../../utils/polygonProcessor');

describe('PolygonService Unit Tests', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    describe('createPolygon', () => {
        const mockUserId = 'user123';
        const mockImageId = 'image123';
        const mockPoints = [
            { x: 10, y: 10 },
            { x: 50, y: 10 },
            { x: 50, y: 50 },
            { x: 10, y: 50 }
        ];
        const mockImage = {
            id: mockImageId,
            user_id: mockUserId,
            status: 'new',
            original_metadata: { width: 100, height: 100 }
        };
        const mockPolygon = {
            id: 'polygon123',
            user_id: mockUserId,
            original_image_id: mockImageId,
            points: mockPoints,
            label: 'test',
            metadata: {}
        };

        test('should create polygon successfully with valid data', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue([]);
            (polygonModel.create as jest.Mock).mockResolvedValue(mockPolygon);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(1600);
            (PolygonServiceUtils.savePolygonDataForML as jest.Mock).mockResolvedValue(undefined);
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(true);

            const result = await polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPoints,
                label: 'test'
            });

            expect(result).toEqual(mockPolygon);
            expect(imageModel.findById).toHaveBeenCalledWith(mockImageId);
            expect(polygonModel.create).toHaveBeenCalledWith({
                user_id: mockUserId,
                original_image_id: mockImageId,
                points: mockPoints,
                label: 'test',
                metadata: {}
            });
            expect(imageModel.updateStatus).toHaveBeenCalledWith(mockImageId, 'processed');
        });

        test('should throw ApiError when image not found', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(null);

            await expect(polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPoints
            })).rejects.toThrow(ApiError);

            await expect(polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPoints
            })).rejects.toMatchObject({
                statusCode: 404,
                code: 'IMAGE_NOT_FOUND'
            });
        });

        test('should throw authorization error when user does not own image', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue({
                ...mockImage,
                user_id: 'differentUser'
            });

            await expect(polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPoints
            })).rejects.toThrow(ApiError);

            await expect(polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPoints
            })).rejects.toMatchObject({
                statusCode: 403,
                code: 'AUTHORIZATION_ERROR',
                context: {
                    resource: 'image',
                    action: 'polygon_create'
                }
            });
        });

        test('should throw business logic error when image is already labeled', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue({
                ...mockImage,
                status: 'labeled'
            });

            await expect(polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPoints
            })).rejects.toMatchObject({
                statusCode: 400,
                code: 'BUSINESS_LOGIC_ERROR',
                context: {
                    rule: 'image_already_labeled',
                    entity: 'polygon'
                }
            });
        });

        test('should throw validation error for invalid polygon geometry', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            
            // Test with less than 3 points
            await expect(polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: [{ x: 10, y: 10 }, { x: 20, y: 20 }]
            })).rejects.toMatchObject({
                statusCode: 400,
                code: 'VALIDATION_ERROR',
                context: {
                    field: 'points'
                }
            });
        });

        test('should warn but not fail when polygon overlaps existing ones', async () => {
            const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
            
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue([mockPolygon]);
            (polygonModel.create as jest.Mock).mockResolvedValue(mockPolygon);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(1600);
            
            // Mock checkPolygonOverlap to return true
            jest.spyOn(polygonService, 'checkPolygonOverlap').mockResolvedValue(true);

            const result = await polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPoints
            });

            expect(result).toEqual(mockPolygon);
            expect(consoleWarnSpy).toHaveBeenCalledWith(
                expect.stringContaining('New polygon overlaps with existing polygons')
            );
            
            consoleWarnSpy.mockRestore();
        });
    });

    describe('validatePolygonGeometry', () => {
        const mockImage = {
            original_metadata: { width: 100, height: 100 }
        };

        test('should validate polygon with correct geometry', async () => {
            const points = [
                { x: 10, y: 10 },
                { x: 50, y: 10 },
                { x: 50, y: 50 },
                { x: 10, y: 50 }
            ];
            
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(1600);
            jest.spyOn(polygonService, 'checkSelfIntersection').mockReturnValue(false);

            const result = await polygonService.validatePolygonGeometry(points, mockImage);

            expect(result.isValid).toBe(true);
            expect(result.errors).toBeUndefined();
        });

        test('should reject polygon with less than 3 points', async () => {
            const points = [{ x: 10, y: 10 }, { x: 20, y: 20 }];

            const result = await polygonService.validatePolygonGeometry(points, mockImage);

            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Polygon must have at least 3 points');
        });

        test('should reject polygon with more than 1000 points', async () => {
            const points = Array(1001).fill({ x: 10, y: 10 });

            const result = await polygonService.validatePolygonGeometry(points, mockImage);

            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Polygon cannot have more than 1000 points');
        });

        test('should reject points outside image boundaries', async () => {
            const points = [
                { x: -10, y: 10 },
                { x: 50, y: 10 },
                { x: 50, y: 110 },
                { x: 10, y: 50 }
            ];

            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(1600);
            jest.spyOn(polygonService, 'checkSelfIntersection').mockReturnValue(false);

            const result = await polygonService.validatePolygonGeometry(points, mockImage);

            expect(result.isValid).toBe(false);
            expect(result.errors).toEqual(
                expect.arrayContaining([
                    expect.stringContaining('2 point(s) are outside image boundaries')
                ])
            );
        });

        test('should reject self-intersecting polygon', async () => {
            const points = [
                { x: 10, y: 10 },
                { x: 50, y: 50 },
                { x: 50, y: 10 },
                { x: 10, y: 50 }
            ];

            jest.spyOn(polygonService, 'checkSelfIntersection').mockReturnValue(true);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(1600);

            const result = await polygonService.validatePolygonGeometry(points, mockImage);

            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Polygon edges cannot intersect with each other');
        });

        test('should reject polygon with non-positive area', async () => {
            const points = [
                { x: 10, y: 10 },
                { x: 20, y: 20 },
                { x: 30, y: 30 }
            ];

            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(0);
            jest.spyOn(polygonService, 'checkSelfIntersection').mockReturnValue(false);

            const result = await polygonService.validatePolygonGeometry(points, mockImage);

            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Polygon must have positive area');
        });

        test('should reject polygon with area below minimum', async () => {
            const points = [
                { x: 10, y: 10 },
                { x: 12, y: 10 },
                { x: 12, y: 12 },
                { x: 10, y: 12 }
            ];

            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(4);
            jest.spyOn(polygonService, 'checkSelfIntersection').mockReturnValue(false);

            const result = await polygonService.validatePolygonGeometry(points, mockImage);

            expect(result.isValid).toBe(false);
            expect(result.errors).toContain('Polygon area too small (minimum: 100 pixels)');
        });
    });

    describe('checkSelfIntersection', () => {
        beforeEach(() => {
            // Ensure no mocks interfere with these tests
            jest.restoreAllMocks();
        });

        test('should detect self-intersecting polygon', () => {
            // Create a bow-tie/hourglass shape which clearly self-intersects
            // The edges (0,0)-(10,10) and (10,0)-(0,10) cross each other
            const points = [
                { x: 0, y: 0 },
                { x: 10, y: 10 },
                { x: 10, y: 0 },
                { x: 0, y: 10 }
            ];

            // Don't mock, test the actual implementation
            const result = polygonService.checkSelfIntersection(points);
            expect(result).toBe(true);
        });

        test('should accept non-intersecting polygon', () => {
            const points = [
                { x: 0, y: 0 },
                { x: 10, y: 0 },
                { x: 10, y: 10 },
                { x: 0, y: 10 }
            ];

            const result = polygonService.checkSelfIntersection(points);
            expect(result).toBe(false);
        });

        test('should handle triangles (cannot self-intersect)', () => {
            const points = [
                { x: 0, y: 0 },
                { x: 10, y: 0 },
                { x: 5, y: 10 }
            ];

            const result = polygonService.checkSelfIntersection(points);
            expect(result).toBe(false);
        });
    });

    describe('linesIntersect', () => {
        test('should detect intersecting lines', () => {
            const result = polygonService.linesIntersect(
                { x: 0, y: 0 }, { x: 10, y: 10 },
                { x: 0, y: 10 }, { x: 10, y: 0 }
            );
            expect(result).toBe(true);
        });

        test('should not detect parallel lines as intersecting', () => {
            const result = polygonService.linesIntersect(
                { x: 0, y: 0 }, { x: 10, y: 0 },
                { x: 0, y: 10 }, { x: 10, y: 10 }
            );
            expect(result).toBe(false);
        });

        test('should not detect non-intersecting lines', () => {
            const result = polygonService.linesIntersect(
                { x: 0, y: 0 }, { x: 5, y: 0 },
                { x: 6, y: 0 }, { x: 10, y: 0 }
            );
            expect(result).toBe(false);
        });
    });

    describe('pointInPolygon', () => {
        const square = [
            { x: 0, y: 0 },
            { x: 10, y: 0 },
            { x: 10, y: 10 },
            { x: 0, y: 10 }
        ];

        test('should detect point inside polygon', () => {
            expect(polygonService.pointInPolygon({ x: 5, y: 5 }, square)).toBe(true);
        });

        test('should detect point outside polygon', () => {
            expect(polygonService.pointInPolygon({ x: 15, y: 15 }, square)).toBe(false);
        });

        test('should handle points on polygon edge', () => {
            // Points on edges might be inside or outside depending on implementation
            const result = polygonService.pointInPolygon({ x: 5, y: 0 }, square);
            expect(typeof result).toBe('boolean');
        });
    });

    describe('getImagePolygons', () => {
        const mockUserId = 'user123';
        const mockImageId = 'image123';
        const mockPolygons = [
            { id: 'poly1', points: [] },
            { id: 'poly2', points: [] }
        ];

        test('should return polygons for owned image', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue({
                id: mockImageId,
                user_id: mockUserId
            });
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue(mockPolygons);

            const result = await polygonService.getImagePolygons(mockImageId, mockUserId);

            expect(result).toEqual(mockPolygons);
            expect(imageModel.findById).toHaveBeenCalledWith(mockImageId);
            expect(polygonModel.findByImageId).toHaveBeenCalledWith(mockImageId);
        });

        test('should throw error when image not found', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(null);

            await expect(
                polygonService.getImagePolygons(mockImageId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 404
            });
        });

        test('should throw authorization error for non-owned image', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue({
                id: mockImageId,
                user_id: 'differentUser'
            });

            await expect(
                polygonService.getImagePolygons(mockImageId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 403,
                code: 'AUTHORIZATION_ERROR',
                context: {
                    resource: 'image',
                    action: 'polygon_read'
                }
            });
        });
    });

    describe('updatePolygon', () => {
        const mockUserId = 'user123';
        const mockPolygonId = 'polygon123';
        const mockPolygon = {
            id: mockPolygonId,
            user_id: mockUserId,
            original_image_id: 'image123',
            points: [{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 10 }]
        };
        const mockImage = {
            id: 'image123',
            user_id: mockUserId,
            original_metadata: { width: 100, height: 100 }
        };

        test('should update polygon successfully', async () => {
            const newPoints = [
                { x: 0, y: 0 },
                { x: 20, y: 0 },
                { x: 20, y: 20 },
                { x: 0, y: 20 }
            ];
            const updatedPolygon = { ...mockPolygon, points: newPoints };

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(400);
            jest.spyOn(polygonService, 'checkSelfIntersection').mockReturnValue(false);
            (polygonModel.update as jest.Mock).mockResolvedValue(updatedPolygon);
            (PolygonServiceUtils.savePolygonDataForML as jest.Mock).mockResolvedValue(undefined);

            const result = await polygonService.updatePolygon({
                polygonId: mockPolygonId,
                userId: mockUserId,
                updates: { points: newPoints }
            });

            expect(result).toEqual(updatedPolygon);
            expect(polygonModel.update).toHaveBeenCalledWith(mockPolygonId, { points: newPoints });
        });

        test('should validate new geometry when updating points', async () => {
            const invalidPoints = [{ x: 0, y: 0 }, { x: 10, y: 0 }]; // Less than 3 points

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);

            await expect(
                polygonService.updatePolygon({
                    polygonId: mockPolygonId,
                    userId: mockUserId,
                    updates: { points: invalidPoints }
                })
            ).rejects.toMatchObject({
                statusCode: 400,
                code: 'VALIDATION_ERROR',
                context: {
                    field: 'points'
                }
            });
        });

        test('should handle ML data save failure gracefully', async () => {
            const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
            const newLabel = 'updated_label';
            const updatedPolygon = { ...mockPolygon, label: newLabel };

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.update as jest.Mock).mockResolvedValue(updatedPolygon);
            (PolygonServiceUtils.savePolygonDataForML as jest.Mock).mockRejectedValue(
                new Error('ML save failed')
            );

            const result = await polygonService.updatePolygon({
                polygonId: mockPolygonId,
                userId: mockUserId,
                updates: { label: newLabel }
            });

            expect(result).toEqual(updatedPolygon);
            expect(consoleWarnSpy).toHaveBeenCalledWith(
                'Failed to save ML data after polygon update:',
                expect.any(Error)
            );

            consoleWarnSpy.mockRestore();
        });
    });

    describe('deletePolygon', () => {
        const mockUserId = 'user123';
        const mockPolygonId = 'polygon123';
        const mockPolygon = {
            id: mockPolygonId,
            user_id: mockUserId,
            original_image_id: 'image123'
        };

        test('should delete polygon and cleanup files successfully', async () => {
            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (polygonModel.delete as jest.Mock).mockResolvedValue(true);
            (storageService.deleteFile as jest.Mock).mockResolvedValue(true);

            await polygonService.deletePolygon(mockPolygonId, mockUserId);

            expect(polygonModel.delete).toHaveBeenCalledWith(mockPolygonId);
            expect(storageService.deleteFile).toHaveBeenCalledWith(`data/polygons/${mockPolygonId}.json`);
        });

        test('should throw error when polygon deletion fails', async () => {
            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (polygonModel.delete as jest.Mock).mockResolvedValue(false);

            await expect(
                polygonService.deletePolygon(mockPolygonId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 500
            });
        });

        test('should not fail when file cleanup fails', async () => {
            const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (polygonModel.delete as jest.Mock).mockResolvedValue(true);
            (storageService.deleteFile as jest.Mock).mockRejectedValue(new Error('File not found'));

            await polygonService.deletePolygon(mockPolygonId, mockUserId);

            expect(consoleWarnSpy).toHaveBeenCalledWith(
                'Failed to delete polygon data file:',
                expect.any(Error)
            );

            consoleWarnSpy.mockRestore();
        });
    });

    describe('getUserPolygonStats', () => {
        const mockUserId = 'user123';

        test('should calculate stats correctly for multiple polygons', async () => {
            const mockPolygons = [
                {
                    id: 'poly1',
                    label: 'shirt',
                    points: [
                        { x: 0, y: 0 },
                        { x: 10, y: 0 },
                        { x: 10, y: 10 },
                        { x: 0, y: 10 }
                    ]
                },
                {
                    id: 'poly2',
                    label: 'shirt',
                    points: JSON.stringify([
                        { x: 0, y: 0 },
                        { x: 20, y: 0 },
                        { x: 20, y: 20 },
                        { x: 0, y: 20 }
                    ])
                },
                {
                    id: 'poly3',
                    label: 'pants',
                    points: [
                        { x: 0, y: 0 },
                        { x: 30, y: 0 },
                        { x: 30, y: 30 }
                    ]
                }
            ];

            (polygonModel.findByUserId as jest.Mock).mockResolvedValue(mockPolygons);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock)
                .mockReturnValueOnce(100)
                .mockReturnValueOnce(400)
                .mockReturnValueOnce(450);

            const result = await polygonService.getUserPolygonStats(mockUserId);

            expect(result).toEqual({
                total: 3,
                byLabel: {
                    shirt: 2,
                    pants: 1
                },
                averagePoints: 4,
                totalArea: 950,
                averageArea: 317
            });
        });

        test('should handle empty polygon list', async () => {
            (polygonModel.findByUserId as jest.Mock).mockResolvedValue([]);

            const result = await polygonService.getUserPolygonStats(mockUserId);

            expect(result).toEqual({
                total: 0,
                byLabel: {},
                averagePoints: 0,
                totalArea: 0,
                averageArea: 0
            });
        });

        test('should handle polygons without labels', async () => {
            const mockPolygons = [
                {
                    id: 'poly1',
                    points: [{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 10 }]
                }
            ];

            (polygonModel.findByUserId as jest.Mock).mockResolvedValue(mockPolygons);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(50);

            const result = await polygonService.getUserPolygonStats(mockUserId);

            expect(result.byLabel).toEqual({ unlabeled: 1 });
        });
    });

    describe('deleteImagePolygons', () => {
        const mockUserId = 'user123';
        const mockImageId = 'image123';

        test('should delete all polygons for an image', async () => {
            const mockPolygons = [
                { id: 'poly1' },
                { id: 'poly2' }
            ];

            (imageModel.findById as jest.Mock).mockResolvedValue({
                id: mockImageId,
                user_id: mockUserId
            });
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue(mockPolygons);
            (polygonModel.deleteByImageId as jest.Mock).mockResolvedValue(2);
            (storageService.deleteFile as jest.Mock).mockResolvedValue(true);

            const result = await polygonService.deleteImagePolygons(mockImageId, mockUserId);

            expect(result).toBe(2);
            expect(polygonModel.deleteByImageId).toHaveBeenCalledWith(mockImageId);
            expect(storageService.deleteFile).toHaveBeenCalledTimes(2);
        });

        test('should handle file cleanup failures gracefully', async () => {
            const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
            const mockPolygons = [{ id: 'poly1' }];

            (imageModel.findById as jest.Mock).mockResolvedValue({
                id: mockImageId,
                user_id: mockUserId
            });
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue(mockPolygons);
            (polygonModel.deleteByImageId as jest.Mock).mockResolvedValue(1);
            (storageService.deleteFile as jest.Mock).mockRejectedValue(new Error('File error'));

            const result = await polygonService.deleteImagePolygons(mockImageId, mockUserId);

            expect(result).toBe(1);
            expect(consoleWarnSpy).toHaveBeenCalled();

            consoleWarnSpy.mockRestore();
        });

        test('should throw authorization error for non-owned image', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue({
                id: mockImageId,
                user_id: 'differentUser'
            });

            await expect(
                polygonService.deleteImagePolygons(mockImageId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 403,
                code: 'AUTHORIZATION_ERROR',
                context: {
                    resource: 'image',
                    action: 'polygon_delete'
                }
            });
        });
    });

    describe('validatePolygonForGarment', () => {
        const mockUserId = 'user123';
        const mockPolygonId = 'polygon123';

        test('should validate suitable polygon for garment', async () => {
            const mockPolygon = {
                id: mockPolygonId,
                points: Array(100).fill(null).map((_, i) => ({ 
                    x: Math.cos(i * Math.PI / 50) * 50 + 50,
                    y: Math.sin(i * Math.PI / 50) * 50 + 50
                }))
            };

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(7850);
            jest.spyOn(polygonService, 'checkSelfIntersection').mockReturnValue(false);

            const result = await polygonService.validatePolygonForGarment(mockPolygonId, mockUserId);

            expect(result).toBe(true);
        });

        test('should reject polygon too small for garment', async () => {
            const mockPolygon = {
                id: mockPolygonId,
                points: [
                    { x: 0, y: 0 },
                    { x: 10, y: 0 },
                    { x: 10, y: 10 },
                    { x: 0, y: 10 }
                ]
            };

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(100);

            await expect(
                polygonService.validatePolygonForGarment(mockPolygonId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 400,
                code: 'BUSINESS_LOGIC_ERROR',
                context: {
                    rule: 'polygon_too_small_for_garment',
                    entity: 'polygon'
                }
            });
        });

        test('should reject polygon too complex for garment', async () => {
            const mockPolygon = {
                id: mockPolygonId,
                points: Array(501).fill({ x: 0, y: 0 })
            };

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(1000);

            await expect(
                polygonService.validatePolygonForGarment(mockPolygonId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 400,
                code: 'BUSINESS_LOGIC_ERROR',
                context: {
                    rule: 'polygon_too_complex_for_garment',
                    entity: 'polygon'
                }
            });
        });

        test('should reject self-intersecting polygon for garment', async () => {
            const mockPolygon = {
                id: mockPolygonId,
                points: [
                    { x: 0, y: 0 },
                    { x: 100, y: 100 },
                    { x: 100, y: 0 },
                    { x: 0, y: 100 }
                ]
            };

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(5000);
            jest.spyOn(polygonService, 'checkSelfIntersection').mockReturnValue(true);

            await expect(
                polygonService.validatePolygonForGarment(mockPolygonId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 400,
                code: 'BUSINESS_LOGIC_ERROR',
                context: {
                    rule: 'polygon_self_intersecting',
                    entity: 'polygon'
                }
            });
        });
    });

    describe('simplifyPolygon', () => {
        const mockUserId = 'user123';
        const mockPolygonId = 'polygon123';

        test('should simplify polygon successfully', async () => {
            const mockPolygon = {
                id: mockPolygonId,
                points: Array(50).fill(null).map((_, i) => ({ x: i, y: i % 2 * 10 }))
            };
            const simplifiedPoints = [
                { x: 0, y: 0 },
                { x: 25, y: 10 },
                { x: 49, y: 10 }
            ];
            const updatedPolygon = { ...mockPolygon, points: simplifiedPoints };

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (PolygonServiceUtils.douglasPeucker as jest.Mock).mockReturnValue(simplifiedPoints);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(250);
            jest.spyOn(polygonService, 'updatePolygon').mockResolvedValue(updatedPolygon as any);

            const result = await polygonService.simplifyPolygon(mockPolygonId, mockUserId, 5);

            expect(result).toEqual(updatedPolygon);
            expect(PolygonServiceUtils.douglasPeucker).toHaveBeenCalledWith(mockPolygon.points, 5);
        });

        test('should reject oversimplification below 3 points', async () => {
            const mockPolygon = {
                id: mockPolygonId,
                points: [
                    { x: 0, y: 0 },
                    { x: 10, y: 0 },
                    { x: 10, y: 10 },
                    { x: 0, y: 10 }
                ]
            };

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (PolygonServiceUtils.douglasPeucker as jest.Mock).mockReturnValue([
                { x: 0, y: 0 },
                { x: 10, y: 10 }
            ]);

            await expect(
                polygonService.simplifyPolygon(mockPolygonId, mockUserId, 50)
            ).rejects.toMatchObject({
                statusCode: 400,
                code: 'BUSINESS_LOGIC_ERROR',
                context: {
                    rule: 'polygon_oversimplified',
                    entity: 'polygon'
                }
            });
        });

        test('should reject simplification resulting in too small area', async () => {
            const mockPolygon = {
                id: mockPolygonId,
                points: Array(10).fill(null).map((_, i) => ({ x: i, y: i % 2 }))
            };
            const simplifiedPoints = [
                { x: 0, y: 0 },
                { x: 5, y: 1 },
                { x: 9, y: 1 }
            ];

            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (PolygonServiceUtils.douglasPeucker as jest.Mock).mockReturnValue(simplifiedPoints);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(4.5);

            await expect(
                polygonService.simplifyPolygon(mockPolygonId, mockUserId, 2)
            ).rejects.toMatchObject({
                statusCode: 400,
                code: 'BUSINESS_LOGIC_ERROR',
                context: {
                    rule: 'polygon_oversimplified',
                    entity: 'polygon'
                }
            });
        });
    });

    describe('AI-powered features', () => {
        const mockUserId = 'user123';
        const mockImageId = 'image123';
        const mockImage = {
            id: mockImageId,
            user_id: mockUserId,
            file_path: 'images/test.jpg',
            original_metadata: { width: 800, height: 600 }
        };
        const mockImageBuffer = Buffer.from('fake-image-data');

        describe('suggestPolygons', () => {
            test('should suggest polygons for an image', async () => {
                const mockSuggestions = [
                    {
                        original: Array(20).fill({ x: 0, y: 0 }),
                        simplified: [
                            { x: 100, y: 100 },
                            { x: 200, y: 100 },
                            { x: 200, y: 200 },
                            { x: 100, y: 200 }
                        ],
                        confidence: 0.95
                    }
                ];

                (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
                (storageService.getFile as jest.Mock).mockResolvedValue(mockImageBuffer);
                (polygonProcessor.suggestPolygons as jest.Mock).mockResolvedValue(mockSuggestions);

                const result = await polygonService.suggestPolygons(mockImageId, mockUserId, {
                    maxPolygons: 5,
                    minArea: 500
                });

                expect(result).toEqual([
                    {
                        points: mockSuggestions[0].simplified,
                        confidence: 0.95,
                        label: 'suggested_1'
                    }
                ]);
                expect(polygonProcessor.suggestPolygons).toHaveBeenCalledWith(
                    mockImageBuffer,
                    { width: 800, height: 600, channels: 4 },
                    { maxPolygons: 5, minArea: 500 }
                );
            });

            test('should throw authorization error for non-owned image', async () => {
                (imageModel.findById as jest.Mock).mockResolvedValue({
                    ...mockImage,
                    user_id: 'differentUser'
                });

                await expect(
                    polygonService.suggestPolygons(mockImageId, mockUserId)
                ).rejects.toMatchObject({
                    statusCode: 403,
                    code: 'AUTHORIZATION_ERROR',
                    context: {
                        resource: 'image',
                        action: 'polygon_suggest'
                    }
                });
            });
        });

        describe('enhancePolygon', () => {
            const mockPolygonId = 'polygon123';
            const mockPolygon = {
                id: mockPolygonId,
                original_image_id: mockImageId,
                points: [
                    { x: 100, y: 100 },
                    { x: 200, y: 100 },
                    { x: 200, y: 200 },
                    { x: 100, y: 200 }
                ],
                metadata: {}
            };
            const mockEnhanced = {
                original: mockPolygon.points,
                simplified: [
                    { x: 98, y: 98 },
                    { x: 202, y: 98 },
                    { x: 202, y: 202 },
                    { x: 98, y: 202 }
                ],
                confidence: 0.92
            };

            test('should enhance polygon successfully', async () => {
                jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
                (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
                (storageService.getFile as jest.Mock).mockResolvedValue(mockImageBuffer);
                (polygonProcessor.enhancePolygon as jest.Mock).mockResolvedValue(mockEnhanced);
                jest.spyOn(polygonService, 'updatePolygon').mockResolvedValue({
                    ...mockPolygon,
                    points: mockEnhanced.simplified,
                    metadata: {
                        enhanced: true,
                        enhancementConfidence: 0.92,
                        originalPoints: mockPolygon.points
                    }
                } as any);

                const result = await polygonService.enhancePolygon(mockPolygonId, mockUserId);

                expect(result.metadata).toMatchObject({
                    enhanced: true,
                    enhancementConfidence: 0.92
                });
                expect(polygonProcessor.enhancePolygon).toHaveBeenCalledWith(
                    mockPolygon.points,
                    mockImageBuffer,
                    { width: 800, height: 600, channels: 4 }
                );
            });
        });

        describe('getEdgeDetection', () => {
            test('should return edge detection visualization', async () => {
                const mockEdgeBuffer = Buffer.from('edge-image-data');

                (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
                (storageService.getFile as jest.Mock).mockResolvedValue(mockImageBuffer);
                (polygonProcessor.detectEdges as jest.Mock).mockResolvedValue(mockEdgeBuffer);

                const result = await polygonService.getEdgeDetection(
                    mockImageId,
                    mockUserId,
                    50,
                    150
                );

                expect(result).toEqual(mockEdgeBuffer);
                expect(polygonProcessor.detectEdges).toHaveBeenCalledWith(
                    mockImageBuffer,
                    { width: 800, height: 600, channels: 4 },
                    50,
                    150
                );
            });

            test('should use default thresholds when not provided', async () => {
                (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
                (storageService.getFile as jest.Mock).mockResolvedValue(mockImageBuffer);
                (polygonProcessor.detectEdges as jest.Mock).mockResolvedValue(Buffer.from('edges'));

                await polygonService.getEdgeDetection(mockImageId, mockUserId);

                expect(polygonProcessor.detectEdges).toHaveBeenCalledWith(
                    mockImageBuffer,
                    expect.any(Object),
                    100,
                    200
                );
            });
        });
    });
});