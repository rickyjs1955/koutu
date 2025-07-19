// /backend/src/tests/integration/polygonService.p2.mock.int.test.ts
// Mock-based integration tests that don't require a real database connection

import { describe, test, expect, beforeAll, afterAll, beforeEach, afterEach, jest } from '@jest/globals';
import { polygonService } from '../../services/polygonService';
import { ApiError } from '../../utils/ApiError';
import { storageService } from '../../services/storageService';
import { polygonModel } from '../../models/polygonModel';
import { imageModel } from '../../models/imageModel';
import { PolygonServiceUtils } from '../../utils/PolygonServiceUtils';
import { polygonProcessor } from '../../utils/polygonProcessor';
import path from 'path';
import fs from 'fs/promises';

// Mock all database models
jest.mock('../../models/polygonModel');
jest.mock('../../models/imageModel');
jest.mock('../../utils/PolygonServiceUtils');
jest.mock('../../utils/polygonProcessor');

describe('PolygonService Mock Integration Tests', () => {
    let uploadDir: string;
    const mockUserId = 'user-123';
    const mockImageId = 'image-123';
    const mockPolygonId = 'polygon-123';

    // Mock data
    const mockImage = {
        id: mockImageId,
        user_id: mockUserId,
        file_path: 'images/test.jpg',
        status: 'new',
        original_metadata: { width: 1000, height: 800 }
    };

    const mockPolygon = {
        id: mockPolygonId,
        user_id: mockUserId,
        original_image_id: mockImageId,
        points: [
            { x: 100, y: 100 },
            { x: 200, y: 100 },
            { x: 200, y: 200 },
            { x: 100, y: 200 }
        ],
        label: 'test-polygon',
        metadata: { source: 'manual' },
        created_at: new Date(),
        updated_at: new Date()
    };

    beforeAll(async () => {
        // Setup test upload directory
        uploadDir = path.join(process.cwd(), 'test-uploads-mock');
        await fs.mkdir(uploadDir, { recursive: true });

        // Mock storage service
        jest.spyOn(storageService, 'saveFile').mockImplementation(async (filePath, buffer) => {
            const fullPath = path.join(uploadDir, filePath);
            await fs.mkdir(path.dirname(fullPath), { recursive: true });
            await fs.writeFile(fullPath, buffer);
            return filePath;
        });

        jest.spyOn(storageService, 'getFile').mockImplementation(async (filePath) => {
            const fullPath = path.join(uploadDir, filePath);
            return await fs.readFile(fullPath);
        });

        jest.spyOn(storageService, 'deleteFile').mockImplementation(async (filePath) => {
            const fullPath = path.join(uploadDir, filePath);
            await fs.unlink(fullPath).catch(() => {});
            return true;
        });
    });

    afterAll(async () => {
        // Clean up test upload directory
        await fs.rm(uploadDir, { recursive: true, force: true });
        jest.restoreAllMocks();
    });

    beforeEach(async () => {
        jest.clearAllMocks();
        
        // Create a dummy image file
        const dummyImageBuffer = Buffer.from('dummy-image-data');
        await storageService.saveFile(`images/${mockImageId}.jpg`, dummyImageBuffer);
    });

    afterEach(async () => {
        // Clean up any files created during tests
        if (uploadDir) {
            await fs.rm(path.join(uploadDir, 'data'), { recursive: true, force: true }).catch(() => {});
        }
    });

    describe('Full polygon lifecycle', () => {
        test('should create, read, update, and delete polygon', async () => {
            // Setup mocks for create
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue([]);
            (polygonModel.create as jest.Mock).mockResolvedValue(mockPolygon);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(10000);
            (PolygonServiceUtils.savePolygonDataForML as jest.Mock).mockResolvedValue(undefined);
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(true);

            // Create polygon
            const createdPolygon = await polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPolygon.points,
                label: 'test-polygon',
                metadata: { source: 'manual' }
            });

            expect(createdPolygon).toMatchObject({
                user_id: mockUserId,
                original_image_id: mockImageId,
                points: mockPolygon.points,
                label: 'test-polygon',
                metadata: { source: 'manual' }
            });

            // Verify ML data was saved
            expect(PolygonServiceUtils.savePolygonDataForML).toHaveBeenCalledWith(
                mockPolygon,
                mockImage,
                storageService
            );

            // Setup mocks for read
            (polygonModel.findById as jest.Mock).mockResolvedValue(mockPolygon);

            // Read polygon
            const retrievedPolygon = await polygonService.getPolygonById(mockPolygonId, mockUserId);
            expect(retrievedPolygon).toEqual(mockPolygon);

            // Setup mocks for update
            const updatedPoints = [
                { x: 150, y: 150 },
                { x: 250, y: 150 },
                { x: 250, y: 250 },
                { x: 150, y: 250 }
            ];
            const updatedPolygon = { ...mockPolygon, points: updatedPoints, label: 'updated-polygon' };
            
            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (polygonModel.update as jest.Mock).mockResolvedValue(updatedPolygon);

            // Update polygon
            const result = await polygonService.updatePolygon({
                polygonId: mockPolygonId,
                userId: mockUserId,
                updates: {
                    points: updatedPoints,
                    label: 'updated-polygon'
                }
            });

            expect(result.points).toEqual(updatedPoints);
            expect(result.label).toBe('updated-polygon');

            // Setup mocks for delete
            (polygonModel.delete as jest.Mock).mockResolvedValue(true);

            // Delete polygon
            await polygonService.deletePolygon(mockPolygonId, mockUserId);

            // Verify polygon was deleted
            expect(polygonModel.delete).toHaveBeenCalledWith(mockPolygonId);
            expect(storageService.deleteFile).toHaveBeenCalledWith(`data/polygons/${mockPolygonId}.json`);
        });
    });

    describe('Multi-polygon operations', () => {
        test('should handle multiple polygons on same image', async () => {
            const polygons = [
                { ...mockPolygon, id: 'poly1', label: 'shirt' },
                { ...mockPolygon, id: 'poly2', label: 'pants', points: [{ x: 300, y: 300 }, { x: 400, y: 300 }, { x: 400, y: 400 }, { x: 300, y: 400 }] },
                { ...mockPolygon, id: 'poly3', label: 'accessory', points: [{ x: 500, y: 100 }, { x: 600, y: 100 }, { x: 550, y: 200 }] }
            ];

            // Mock for creating multiple polygons
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.findByImageId as jest.Mock)
                .mockResolvedValueOnce([])
                .mockResolvedValueOnce([polygons[0]])
                .mockResolvedValueOnce([polygons[0], polygons[1]])
                .mockResolvedValue(polygons);
            
            (polygonModel.create as jest.Mock)
                .mockResolvedValueOnce(polygons[0])
                .mockResolvedValueOnce(polygons[1])
                .mockResolvedValueOnce(polygons[2]);
            
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(10000);
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(true);

            // Create multiple polygons
            for (let i = 0; i < polygons.length; i++) {
                await polygonService.createPolygon({
                    userId: mockUserId,
                    originalImageId: mockImageId,
                    points: polygons[i].points,
                    label: polygons[i].label
                });
            }

            // Get all polygons for image
            const imagePolygons = await polygonService.getImagePolygons(mockImageId, mockUserId);
            expect(imagePolygons).toHaveLength(3);
            expect(imagePolygons.map(p => p.label).sort()).toEqual(['accessory', 'pants', 'shirt']);

            // Get user stats
            (polygonModel.findByUserId as jest.Mock).mockResolvedValue(polygons);
            const stats = await polygonService.getUserPolygonStats(mockUserId);
            
            expect(stats).toMatchObject({
                total: 3,
                byLabel: {
                    shirt: 1,
                    pants: 1,
                    accessory: 1
                }
            });

            // Batch delete all polygons
            (polygonModel.deleteByImageId as jest.Mock).mockResolvedValue(3);
            const deletedCount = await polygonService.deleteImagePolygons(mockImageId, mockUserId);
            expect(deletedCount).toBe(3);
        });

        test('should detect overlapping polygons', async () => {
            const existingPolygon = { ...mockPolygon, id: 'existing-poly' };
            
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue([existingPolygon]);
            (polygonModel.create as jest.Mock).mockResolvedValue(mockPolygon);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(10000);
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(true);

            // Mock console.warn to check for overlap warning
            const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();

            // Create overlapping polygon
            await polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: [
                    { x: 150, y: 150 },
                    { x: 250, y: 150 },
                    { x: 250, y: 250 },
                    { x: 150, y: 250 }
                ],
                label: 'overlapping'
            });

            expect(consoleWarnSpy).toHaveBeenCalledWith(
                expect.stringContaining('New polygon overlaps with existing polygons')
            );

            consoleWarnSpy.mockRestore();
        });
    });

    describe('Cross-user isolation', () => {
        const otherUserId = 'other-user-123';

        beforeEach(() => {
            // Restore only the spies on polygonService methods
            if (jest.isMockFunction(polygonService.getPolygonById)) {
                (polygonService.getPolygonById as jest.Mock).mockRestore();
            }
            if (jest.isMockFunction(polygonService.updatePolygon)) {
                (polygonService.updatePolygon as jest.Mock).mockRestore();
            }
        });

        test('should prevent unauthorized polygon access', async () => {
            // First call for getPolygonById will find the polygon
            (polygonModel.findById as jest.Mock).mockResolvedValue(mockPolygon);
            // Then when checking image ownership, the image belongs to another user
            (imageModel.findById as jest.Mock).mockResolvedValue({
                ...mockImage,
                user_id: otherUserId  // This is the key - the image belongs to another user
            });

            await expect(
                polygonService.getPolygonById(mockPolygonId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 403,
                code: 'AUTHORIZATION_ERROR'
            });
        });

        test('should prevent unauthorized polygon update', async () => {
            jest.spyOn(polygonService, 'getPolygonById').mockRejectedValue(
                ApiError.authorization('You do not have permission to access this polygon', 'polygon', 'read')
            );

            await expect(
                polygonService.updatePolygon({
                    polygonId: mockPolygonId,
                    userId: otherUserId,
                    updates: { label: 'hacked' }
                })
            ).rejects.toMatchObject({
                statusCode: 403
            });
        });

        test('should prevent adding polygons to other user images', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue({
                ...mockImage,
                user_id: otherUserId
            });

            await expect(
                polygonService.createPolygon({
                    userId: mockUserId,
                    originalImageId: mockImageId,
                    points: mockPolygon.points
                })
            ).rejects.toMatchObject({
                statusCode: 403,
                code: 'AUTHORIZATION_ERROR',
                context: {
                    action: 'polygon_create'
                }
            });
        });
    });

    describe('Business rules enforcement', () => {
        test('should enforce minimum polygon area', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(50); // Below minimum

            await expect(
                polygonService.createPolygon({
                    userId: mockUserId,
                    originalImageId: mockImageId,
                    points: [
                        { x: 100, y: 100 },
                        { x: 101, y: 100 },
                        { x: 101, y: 101 },
                        { x: 100, y: 101 }
                    ]
                })
            ).rejects.toMatchObject({
                statusCode: 400,
                message: expect.stringContaining('Polygon area too small')
            });
        });

        test('should prevent adding polygons to labeled images', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue({
                ...mockImage,
                status: 'labeled'
            });

            await expect(
                polygonService.createPolygon({
                    userId: mockUserId,
                    originalImageId: mockImageId,
                    points: mockPolygon.points
                })
            ).rejects.toMatchObject({
                statusCode: 400,
                code: 'BUSINESS_LOGIC_ERROR',
                context: {
                    rule: 'image_already_labeled'
                }
            });
        });

        test('should update image status from new to processed', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue([]);
            (polygonModel.create as jest.Mock).mockResolvedValue(mockPolygon);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(10000);
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(true);

            await polygonService.createPolygon({
                userId: mockUserId,
                originalImageId: mockImageId,
                points: mockPolygon.points
            });

            expect(imageModel.updateStatus).toHaveBeenCalledWith(mockImageId, 'processed');
        });
    });

    describe('Garment validation', () => {
        test('should validate polygon suitable for garment', async () => {
            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue({
                ...mockPolygon,
                points: Array(50).fill(null).map((_, i) => ({
                    x: 200 + Math.cos(i * Math.PI / 25) * 100,
                    y: 200 + Math.sin(i * Math.PI / 25) * 100
                }))
            } as any);
            
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(31416); // π * 100²

            const isValid = await polygonService.validatePolygonForGarment(mockPolygonId, mockUserId);
            expect(isValid).toBe(true);
        });

        test('should reject small polygon for garment', async () => {
            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(100); // Too small

            await expect(
                polygonService.validatePolygonForGarment(mockPolygonId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 400,
                code: 'BUSINESS_LOGIC_ERROR',
                context: {
                    rule: 'polygon_too_small_for_garment'
                }
            });
        });
    });

    describe('AI-powered features', () => {
        beforeEach(() => {
            (polygonProcessor.suggestPolygons as jest.Mock).mockResolvedValue([
                {
                    original: Array(50).fill({ x: 0, y: 0 }),
                    simplified: [
                        { x: 100, y: 100 },
                        { x: 300, y: 100 },
                        { x: 300, y: 300 },
                        { x: 100, y: 300 }
                    ],
                    confidence: 0.92
                }
            ]);

            (polygonProcessor.enhancePolygon as jest.Mock).mockImplementation(async (points) => ({
                original: points,
                simplified: points.map(p => ({ x: p.x + 2, y: p.y + 2 })),
                confidence: 0.88
            }));

            (polygonProcessor.detectEdges as jest.Mock).mockResolvedValue(
                Buffer.from('edge-detection-result')
            );
        });

        test('should suggest polygons for image', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            // Ensure getFile returns a buffer for AI processing
            (storageService.getFile as jest.Mock).mockResolvedValue(Buffer.from('test-image-data'));

            const suggestions = await polygonService.suggestPolygons(
                mockImageId,
                mockUserId,
                {
                    maxPolygons: 3,
                    minArea: 500,
                    simplificationTolerance: 2
                }
            );

            expect(suggestions).toHaveLength(1);
            expect(suggestions[0]).toMatchObject({
                points: expect.arrayContaining([
                    expect.objectContaining({ x: expect.any(Number), y: expect.any(Number) })
                ]),
                confidence: 0.92,
                label: 'suggested_1'
            });
        });

        test('should enhance existing polygon', async () => {
            jest.spyOn(polygonService, 'getPolygonById').mockResolvedValue(mockPolygon as any);
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            // Ensure getFile returns a buffer for AI processing
            (storageService.getFile as jest.Mock).mockResolvedValue(Buffer.from('test-image-data'));
            
            const enhancedPolygon = {
                ...mockPolygon,
                points: mockPolygon.points.map(p => ({ x: p.x + 2, y: p.y + 2 })),
                metadata: {
                    ...mockPolygon.metadata,
                    enhanced: true,
                    enhancementConfidence: 0.88,
                    originalPoints: mockPolygon.points
                }
            };
            
            jest.spyOn(polygonService, 'updatePolygon').mockResolvedValue(enhancedPolygon as any);

            const result = await polygonService.enhancePolygon(mockPolygonId, mockUserId);

            expect(result.metadata).toMatchObject({
                enhanced: true,
                enhancementConfidence: 0.88
            });
        });

        test('should prevent unauthorized AI operations', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue({
                ...mockImage,
                user_id: 'different-user'
            });

            await expect(
                polygonService.suggestPolygons(mockImageId, mockUserId)
            ).rejects.toMatchObject({
                statusCode: 403,
                code: 'AUTHORIZATION_ERROR',
                context: {
                    action: 'polygon_suggest'
                }
            });
        });
    });

    describe('Error handling and recovery', () => {
        test('should fail when ML data save fails during creation', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue([]);
            (polygonModel.create as jest.Mock).mockResolvedValue(mockPolygon);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(10000);
            (PolygonServiceUtils.savePolygonDataForML as jest.Mock).mockRejectedValue(
                new Error('ML service unavailable')
            );
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(true);

            // The service currently throws an error when ML save fails
            await expect(
                polygonService.createPolygon({
                    userId: mockUserId,
                    originalImageId: mockImageId,
                    points: mockPolygon.points
                })
            ).rejects.toMatchObject({
                statusCode: 500,
                message: 'Failed to create polygon'
            });
        });

        test('should handle concurrent polygon operations', async () => {
            (imageModel.findById as jest.Mock).mockResolvedValue(mockImage);
            (polygonModel.findByImageId as jest.Mock).mockResolvedValue([]);
            (PolygonServiceUtils.calculatePolygonArea as jest.Mock).mockReturnValue(10000);
            (PolygonServiceUtils.savePolygonDataForML as jest.Mock).mockResolvedValue(undefined);
            (imageModel.updateStatus as jest.Mock).mockResolvedValue(true);

            // Mock create to return different polygons for concurrent calls
            let callCount = 0;
            (polygonModel.create as jest.Mock).mockImplementation(async () => ({
                ...mockPolygon,
                id: `polygon-${callCount++}`,
                label: `polygon_${callCount}`
            }));

            // Create multiple polygons concurrently
            const promises = Array(5).fill(null).map((_, i) => 
                polygonService.createPolygon({
                    userId: mockUserId,
                    originalImageId: mockImageId,
                    points: [
                        { x: i * 100, y: 0 },
                        { x: (i + 1) * 100, y: 0 },
                        { x: (i + 1) * 100, y: 100 },
                        { x: i * 100, y: 100 }
                    ],
                    label: `polygon_${i}`
                })
            );

            const polygons = await Promise.all(promises);
            
            expect(polygons).toHaveLength(5);
            expect(new Set(polygons.map(p => p.id)).size).toBe(5); // All unique IDs
        });
    });
});