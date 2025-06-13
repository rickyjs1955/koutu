// /backend/src/controllers/__tests__/exportController.test.ts
import { Request, Response, NextFunction } from 'express';
import { exportController } from '../../controllers/exportController';
import { exportService } from '../../services/exportService';
import { MLExportOptions } from '../../../../shared/src/schemas/export';
import { ApiError } from '../../utils/ApiError';
import { ExportMocks } from '../__mocks__/exports.mock';
import { ExportTestHelpers } from '../__helpers__/exports.helper';

// Mock dependencies
jest.mock('../../services/exportService');
jest.mock('../../utils/ApiError');

const mockExportService = exportService as jest.Mocked<typeof exportService>;

describe('ExportController', () => {
  const mockUserId = 'user-123';
  const mockJobId = 'job-456';
  const mockDate = new Date('2024-01-15T10:00:00Z');

  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    jest.setSystemTime(mockDate);

    // Setup mock request with authenticated user
    mockRequest = ExportTestHelpers.createMockRequest({
      user: { id: mockUserId, email: 'test@example.com' },
      body: {},
      params: {},
      query: {}
    });

    // Setup mock response
    mockResponse = ExportTestHelpers.createMockResponse();

    // Setup mock next function
    mockNext = ExportTestHelpers.createMockNext();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('createMLExport', () => {
    it('should create ML export job successfully', async () => {
      // Arrange
      const options: MLExportOptions = ExportMocks.createMockMLExportOptions({
        format: 'coco',
        includeImages: true,
        categoryFilter: ['shirt', 'pants']
      });

      mockRequest.body = { options };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, options);
      expect(mockResponse.status).toHaveBeenCalledWith(202);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        message: 'ML export job created successfully',
        data: {
          jobId: mockJobId
        }
      });
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should handle missing user authentication', async () => {
      // Arrange
      mockRequest.user = undefined;
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.getBatchJob).not.toHaveBeenCalled();
    });

    it('should handle service errors', async () => {
      // Arrange
      mockRequest.params = { jobId: mockJobId };
      const serviceError = new Error('Database connection failed');
      mockExportService.getBatchJob.mockRejectedValue(serviceError);

      // Act
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(serviceError);
    });

    it('should handle different job statuses', async () => {
      // Arrange
      const statuses = ['pending', 'processing', 'completed', 'failed', 'cancelled'] as const;

      for (const status of statuses) {
        const mockJob = ExportMocks.createMockMLExportBatchJob({
          id: mockJobId,
          userId: mockUserId,
          status
        });

        mockRequest.params = { jobId: mockJobId };
        mockExportService.getBatchJob.mockResolvedValue(mockJob);

        // Act
        await exportController.getExportJob(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert
        expect(mockResponse.json).toHaveBeenCalledWith({
          success: true,
          data: expect.objectContaining({ status })
        });

        // Reset mocks for next iteration
        jest.clearAllMocks();
        mockResponse = ExportTestHelpers.createMockResponse();
      }
    });
  });

  describe('getUserExportJobs', () => {
    it('should return all jobs for authenticated user', async () => {
      // Arrange
      const mockJobs = [
        ExportMocks.createMockMLExportBatchJob({ 
          userId: mockUserId, 
          status: 'completed',
          createdAt: '2024-01-15T10:00:00Z'
        }),
        ExportMocks.createMockMLExportBatchJob({ 
          userId: mockUserId, 
          status: 'processing',
          createdAt: '2024-01-14T10:00:00Z'
        }),
        ExportMocks.createMockMLExportBatchJob({ 
          userId: mockUserId, 
          status: 'pending',
          createdAt: '2024-01-13T10:00:00Z'
        })
      ];

      mockExportService.getUserBatchJobs.mockResolvedValue(mockJobs);

      // Act
      await exportController.getUserExportJobs(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.getUserBatchJobs).toHaveBeenCalledWith(mockUserId);
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: mockJobs
      });
    });

    it('should return empty array when no jobs found', async () => {
      // Arrange
      mockExportService.getUserBatchJobs.mockResolvedValue([]);

      // Act
      await exportController.getUserExportJobs(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: []
      });
    });

    it('should handle missing authentication', async () => {
      // Arrange
      mockRequest.user = undefined;

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.getUserExportJobs(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.getUserBatchJobs).not.toHaveBeenCalled();
    });

    it('should handle service errors', async () => {
      // Arrange
      const serviceError = new Error('Database query failed');
      mockExportService.getUserBatchJobs.mockRejectedValue(serviceError);

      // Act
      await exportController.getUserExportJobs(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(serviceError);
    });

    it('should handle large number of jobs', async () => {
      // Arrange
      const manyJobs = Array.from({ length: 100 }, (_, i) =>
        ExportMocks.createMockMLExportBatchJob({
          userId: mockUserId,
          id: `job-${i}`
        })
      );

      mockExportService.getUserBatchJobs.mockResolvedValue(manyJobs);

      // Act
      await exportController.getUserExportJobs(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: manyJobs
      });
    });
  });

  describe('downloadExport', () => {
    it('should download completed export file', async () => {
      // Arrange
      const mockJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'completed'
      });

      const downloadInfo = {
        path: `/exports/${mockJobId}.zip`,
        filename: `koutu-export-${mockJobId.slice(0, 8)}.zip`
      };

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(mockJob);
      mockExportService.downloadExport.mockResolvedValue(downloadInfo);

      // Act
      await exportController.downloadExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.getBatchJob).toHaveBeenCalledWith(mockJobId);
      expect(mockExportService.downloadExport).toHaveBeenCalledWith(mockJobId);
      expect(mockResponse.download).toHaveBeenCalledWith(
        downloadInfo.path,
        downloadInfo.filename
      );
    });

    it('should handle job not found', async () => {
      // Arrange
      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(null);

      const mockApiError = new ApiError(404, 'Export job not found');
      (ApiError.notFound as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.downloadExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.notFound).toHaveBeenCalledWith('Export job not found');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.downloadExport).not.toHaveBeenCalled();
    });

    it('should prevent download of other users exports', async () => {
      // Arrange
      const otherUserJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: 'other-user-456',
        status: 'completed'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(otherUserJob);

      const mockApiError = new ApiError(403, 'You do not have permission to access this export');
      (ApiError.forbidden as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.downloadExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.forbidden).toHaveBeenCalledWith('You do not have permission to access this export');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should handle incomplete export jobs', async () => {
      // Arrange
      const incompleteStatuses = ['pending', 'processing', 'failed', 'cancelled'] as const;

      for (const status of incompleteStatuses) {
        const incompleteJob = ExportMocks.createMockMLExportBatchJob({
          id: mockJobId,
          userId: mockUserId,
          status
        });

        mockRequest.params = { jobId: mockJobId };
        mockExportService.getBatchJob.mockResolvedValue(incompleteJob);

        const mockApiError = new ApiError(400, `Export job is not ready for download (status: ${status})`);
        (ApiError.badRequest as jest.Mock).mockReturnValue(mockApiError);

        // Act
        await exportController.downloadExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert
        expect(ApiError.badRequest).toHaveBeenCalledWith(`Export job is not ready for download (status: ${status})`);
        expect(mockNext).toHaveBeenCalledWith(mockApiError);

        // Reset mocks for next iteration
        jest.clearAllMocks();
      }
    });

    it('should handle download service errors', async () => {
      // Arrange
      const completedJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'completed'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(completedJob);

      const downloadError = new Error('Export file not found');
      mockExportService.downloadExport.mockRejectedValue(downloadError);

      // Act
      await exportController.downloadExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(downloadError);
    });

    it('should handle missing authentication', async () => {
      // Arrange
      mockRequest.user = undefined;
      mockRequest.params = { jobId: mockJobId };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.downloadExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });
  });

  describe('getDatasetStats', () => {
    it('should return dataset statistics for user', async () => {
      // Arrange
      const mockStats = ExportMocks.createMockDatasetStats();
      mockExportService.getDatasetStats.mockResolvedValue(mockStats);

      // Act
      await exportController.getDatasetStats(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.getDatasetStats).toHaveBeenCalledWith(mockUserId);
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: mockStats
      });
    });

    it('should handle empty dataset', async () => {
      // Arrange
      const emptyStats = {
        totalImages: 0,
        totalGarments: 0,
        categoryCounts: {},
        attributeCounts: {},
        averagePolygonPoints: 0
      };

      mockExportService.getDatasetStats.mockResolvedValue(emptyStats);

      // Act
      await exportController.getDatasetStats(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: emptyStats
      });
    });

    it('should handle missing authentication', async () => {
      // Arrange
      mockRequest.user = undefined;

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.getDatasetStats(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.getDatasetStats).not.toHaveBeenCalled();
    });

    it('should handle service errors', async () => {
      // Arrange
      const serviceError = new Error('Database connection failed');
      mockExportService.getDatasetStats.mockRejectedValue(serviceError);

      // Act
      await exportController.getDatasetStats(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(serviceError);
    });

    it('should handle complex dataset statistics', async () => {
      // Arrange
      const complexStats = {
        totalImages: 5000,
        totalGarments: 7500,
        categoryCounts: {
          'shirt': 1500,
          'pants': 1200,
          'dress': 800,
          'jacket': 600,
          'shoes': 400,
          'accessories': 300,
          'other': 2700
        },
        attributeCounts: {
          'color': {
            'red': 500,
            'blue': 600,
            'green': 400,
            'black': 800,
            'white': 700,
            'other': 4500
          },
          'size': {
            'XS': 300,
            'S': 800,
            'M': 1500,
            'L': 1200,
            'XL': 600,
            'XXL': 200,
            'other': 2900
          },
          'material': {
            'cotton': 2000,
            'polyester': 1500,
            'wool': 800,
            'silk': 600,
            'denim': 900,
            'leather': 400,
            'other': 1300
          }
        },
        averagePolygonPoints: 12
      };

      mockExportService.getDatasetStats.mockResolvedValue(complexStats);

      // Act
      await exportController.getDatasetStats(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: complexStats
      });
    });
  });

  describe('getExportJob', () => {
    it('should return export job for authenticated user', async () => {
      // Arrange
      const mockJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'completed'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(mockJob);

      // Act
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.getBatchJob).toHaveBeenCalledWith(mockJobId);
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: mockJob
      });
    });

    it('should handle job not found', async () => {
      // Arrange
      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(null);

      const mockApiError = new ApiError(404, 'Export job not found');
      (ApiError.notFound as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.notFound).toHaveBeenCalledWith('Export job not found');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should prevent access to other users jobs', async () => {
      // Arrange
      const otherUserJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: 'other-user-456'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(otherUserJob);

      const mockApiError = new ApiError(403, 'You do not have permission to access this export job');
      (ApiError.forbidden as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.forbidden).toHaveBeenCalledWith('You do not have permission to access this export job');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should handle missing authentication', async () => {
      // Arrange
      mockRequest.user = undefined;
      mockRequest.params = { jobId: mockJobId };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.exportMLData).not.toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should handle null user object', async () => {
      // Arrange
      mockRequest.user = null;
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should handle different export formats', async () => {
      // Arrange
      const formats = ['coco', 'yolo', 'pascal_voc', 'csv', 'raw_json'] as const;

      for (const format of formats) {
        const options = ExportMocks.createMockMLExportOptions({ format });
        mockRequest.body = { options };
        mockExportService.exportMLData.mockResolvedValue(`job-${format}`);

        // Act
        await exportController.createMLExport(
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert
        expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, options);
        expect(mockResponse.json).toHaveBeenCalledWith(
          expect.objectContaining({
            data: { jobId: `job-${format}` }
          })
        );

        // Reset mocks for next iteration
        jest.clearAllMocks();
        mockResponse = ExportTestHelpers.createMockResponse();
      }
    });

    it('should handle complex export options', async () => {
      // Arrange
      const complexOptions: MLExportOptions = {
        format: 'coco',
        includeImages: true,
        includeMasks: true,
        imageFormat: 'png',
        compressionQuality: 95,
        garmentIds: ['garment-1', 'garment-2', 'garment-3'],
        categoryFilter: ['shirt', 'pants', 'dress']
      };

      mockRequest.body = { options: complexOptions };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, complexOptions);
      expect(mockResponse.status).toHaveBeenCalledWith(202);
    });

    it('should handle service errors', async () => {
      // Arrange
      const options = ExportMocks.createMockMLExportOptions();
      mockRequest.body = { options };

      const serviceError = new Error('Database connection failed');
      mockExportService.exportMLData.mockRejectedValue(serviceError);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(serviceError);
      expect(mockResponse.status).not.toHaveBeenCalled();
    });

    it('should handle invalid options structure', async () => {
      // Arrange
      mockRequest.body = { invalidField: 'invalid' }; // Missing options

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Should attempt to call service with undefined options
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, undefined);
    });
  });

  describe('cancelExportJob', () => {
    it('should cancel pending export job', async () => {
      // Arrange
      const pendingJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'pending'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(pendingJob);
      mockExportService.cancelExportJob.mockResolvedValue(undefined);

      // Act
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.getBatchJob).toHaveBeenCalledWith(mockJobId);
      expect(mockExportService.cancelExportJob).toHaveBeenCalledWith(mockJobId);
      expect(mockResponse.status).toHaveBeenCalledWith(200);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        message: 'Export job canceled successfully'
      });
    });

    it('should cancel processing export job', async () => {
      // Arrange
      const processingJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'processing'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(processingJob);
      mockExportService.cancelExportJob.mockResolvedValue(undefined);

      // Act
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.cancelExportJob).toHaveBeenCalledWith(mockJobId);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        message: 'Export job canceled successfully'
      });
    });

    it('should handle job not found', async () => {
      // Arrange
      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(null);

      const mockApiError = new ApiError(404, 'Export job not found');
      (ApiError.notFound as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.notFound).toHaveBeenCalledWith('Export job not found');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.cancelExportJob).not.toHaveBeenCalled();
    });

    it('should prevent cancellation of other users jobs', async () => {
      // Arrange
      const otherUserJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: 'other-user-456',
        status: 'pending'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(otherUserJob);

      const mockApiError = new ApiError(403, 'You do not have permission to cancel this export job');
      (ApiError.forbidden as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.forbidden).toHaveBeenCalledWith('You do not have permission to cancel this export job');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should handle cancellation of already completed job', async () => {
      // Arrange
      const completedJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'completed'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(completedJob);

      const mockApiError = new ApiError(400, 'Cannot cancel job with status: completed');
      (ApiError.badRequest as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.badRequest).toHaveBeenCalledWith('Cannot cancel job with status: completed');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.cancelExportJob).not.toHaveBeenCalled();
    });

    it('should handle cancellation of already failed job', async () => {
      // Arrange
      const failedJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'failed'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(failedJob);

      const mockApiError = new ApiError(400, 'Cannot cancel job with status: failed');
      (ApiError.badRequest as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.badRequest).toHaveBeenCalledWith('Cannot cancel job with status: failed');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
      expect(mockExportService.cancelExportJob).not.toHaveBeenCalled();
    });

    it('should handle missing authentication', async () => {
      // Arrange
      mockRequest.user = undefined;
      mockRequest.params = { jobId: mockJobId };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should handle service errors during cancellation', async () => {
      // Arrange
      const pendingJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'pending'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(pendingJob);

      const cancelError = new Error('Failed to cancel job');
      mockExportService.cancelExportJob.mockRejectedValue(cancelError);

      // Act
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(cancelError);
    });
  });

  describe('Error Handling', () => {
    it('should handle async errors with proper error propagation', async () => {
      // Arrange
      const asyncError = new Error('Async operation failed');
      mockExportService.exportMLData.mockRejectedValue(asyncError);
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(asyncError);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });

    it('should handle synchronous errors', async () => {
      // Arrange
      const syncError = new Error('Synchronous error');
      mockExportService.exportMLData.mockImplementation(() => {
        throw syncError;
      });
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(syncError);
    });

    it('should handle ApiError instances correctly', async () => {
      // Arrange
      const apiError = new ApiError(500, 'Internal server error', 'INTERNAL_ERROR');
      mockExportService.exportMLData.mockRejectedValue(apiError);
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(apiError);
    });

    it('should handle database connection errors', async () => {
      // Arrange
      const dbError = new Error('Database connection timeout');
      mockExportService.getUserBatchJobs.mockRejectedValue(dbError);

      // Act
      await exportController.getUserExportJobs(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(dbError);
    });

    it('should handle service unavailable errors', async () => {
      // Arrange
      const serviceError = new Error('Service temporarily unavailable');
      mockExportService.getDatasetStats.mockRejectedValue(serviceError);

      // Act
      await exportController.getDatasetStats(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockNext).toHaveBeenCalledWith(serviceError);
    });
  });

  describe('Request Validation', () => {
    it('should handle malformed request bodies', async () => {
      // Arrange
      mockRequest.body = null;

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Should throw an error when trying to access null.options
      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
      expect(mockExportService.exportMLData).not.toHaveBeenCalled();
    });

    it('should handle missing required parameters', async () => {
      // Arrange
      mockRequest.params = {}; // Missing jobId

      // Act
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.getBatchJob).toHaveBeenCalledWith(undefined);
    });

    it('should handle invalid parameter types', async () => {
      // Arrange
      mockRequest.params = { jobId: 123 as any }; // Number instead of string

      // Act
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.getBatchJob).toHaveBeenCalledWith(123);
    });

    it('should handle extremely large request bodies', async () => {
      // Arrange
      const largeOptions = {
        format: 'coco' as const,
        garmentIds: Array.from({ length: 100000 }, (_, i) => `garment-${i}`),
        categoryFilter: Array.from({ length: 10000 }, (_, i) => `category-${i}`),
        largeData: 'x'.repeat(1000000) // 1MB string
      };

      mockRequest.body = { options: largeOptions };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(mockExportService.exportMLData).toHaveBeenCalledWith(mockUserId, largeOptions);
      expect(mockResponse.status).toHaveBeenCalledWith(202);
    });
  });

  describe('Response Handling', () => {
    it('should return consistent response structure for success cases', async () => {
      // Arrange
      const options = ExportMocks.createMockMLExportOptions();
      mockRequest.body = { options };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      const responseCall = (mockResponse.json as jest.Mock).mock.calls[0][0];
      expect(responseCall).toHaveProperty('success', true);
      expect(responseCall).toHaveProperty('message');
      expect(responseCall).toHaveProperty('data');
      expect(typeof responseCall.message).toBe('string');
      expect(typeof responseCall.data).toBe('object');
    });

    it('should handle response serialization errors', async () => {
      // Arrange
      const circularObject = {};
      circularObject['self'] = circularObject; // Circular reference

      mockExportService.getUserBatchJobs.mockResolvedValue(circularObject as any);

      // Act
      await exportController.getUserExportJobs(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert - Should attempt to serialize (JSON serialization errors handled by Express)
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: circularObject
      });
    });

    it('should set appropriate HTTP status codes', async () => {
      // Arrange
      const testCases = [
        {
          method: 'createMLExport',
          setup: () => {
            mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };
            mockExportService.exportMLData.mockResolvedValue(mockJobId);
          },
          expectedStatus: 202
        },
        {
          method: 'getExportJob',
          setup: () => {
            mockRequest.params = { jobId: mockJobId };
            mockExportService.getBatchJob.mockResolvedValue(
              ExportMocks.createMockMLExportBatchJob({ userId: mockUserId })
            );
          },
          expectedStatus: 200
        },
        {
          method: 'getUserExportJobs',
          setup: () => {
            mockExportService.getUserBatchJobs.mockResolvedValue([]);
          },
          expectedStatus: 200
        },
        {
          method: 'getDatasetStats',
          setup: () => {
            mockExportService.getDatasetStats.mockResolvedValue(ExportMocks.createMockDatasetStats());
          },
          expectedStatus: 200
        },
        {
          method: 'cancelExportJob',
          setup: () => {
            mockRequest.params = { jobId: mockJobId };
            mockExportService.getBatchJob.mockResolvedValue(
              ExportMocks.createMockMLExportBatchJob({ userId: mockUserId, status: 'pending' })
            );
            mockExportService.cancelExportJob.mockResolvedValue(undefined);
          },
          expectedStatus: 200
        }
      ];

      for (const testCase of testCases) {
        // Reset mocks
        jest.clearAllMocks();
        mockResponse = ExportTestHelpers.createMockResponse();

        testCase.setup();

        // Act
        await (exportController as any)[testCase.method](
          mockRequest as Request,
          mockResponse as Response,
          mockNext
        );

        // Assert
        expect(mockResponse.status).toHaveBeenCalledWith(testCase.expectedStatus);
      }
    });
  });

  describe('Authentication Edge Cases', () => {
    it('should handle user object with missing id', async () => {
      // Arrange
      mockRequest.user = { email: 'test@example.com', name: 'Test User' } as any; // Missing id
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should handle user object with null id', async () => {
      // Arrange
      mockRequest.user = { id: null, email: 'test@example.com', name: 'Test User' } as any;
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });

    it('should handle user object with empty string id', async () => {
      // Arrange
      mockRequest.user = { id: '', email: 'test@example.com', name: 'Test User' };
      mockRequest.body = { options: ExportMocks.createMockMLExportOptions() };

      const mockApiError = new ApiError(401, 'User authentication required');
      (ApiError.unauthorized as jest.Mock).mockReturnValue(mockApiError);

      // Act
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert
      expect(ApiError.unauthorized).toHaveBeenCalledWith('User authentication required');
      expect(mockNext).toHaveBeenCalledWith(mockApiError);
    });
  });

  describe('Concurrent Request Handling', () => {
    it('should handle multiple concurrent export creation requests', async () => {
      // Arrange
      const concurrentRequests = 10;
      const promises: Promise<void>[] = [];

      for (let i = 0; i < concurrentRequests; i++) {
        const options = ExportMocks.createMockMLExportOptions({ format: 'coco' });
        const request = ExportTestHelpers.createMockRequest({
          user: { id: `user-${i}`, email: `user${i}@example.com`, name: `User ${i}` },
          body: { options }
        });
        const response = ExportTestHelpers.createMockResponse();
        const next = ExportTestHelpers.createMockNext();

        mockExportService.exportMLData.mockResolvedValue(`job-${i}`);

        promises.push(
          exportController.createMLExport(
            request as Request,
            response as Response,
            next
          )
        );
      }

      // Act
      await Promise.all(promises);

      // Assert
      expect(mockExportService.exportMLData).toHaveBeenCalledTimes(concurrentRequests);
    });

    it('should handle concurrent download requests for different users', async () => {
      // Arrange
      const users = ['user-1', 'user-2', 'user-3'];
      const promises: Promise<void>[] = [];

      users.forEach((userId, index) => {
        const jobId = `job-${index}`;
        const job = ExportMocks.createMockMLExportBatchJob({
          id: jobId,
          userId,
          status: 'completed'
        });

        const request = ExportTestHelpers.createMockRequest({
          user: { id: userId, email: `${userId}@example.com`, name: userId },
          params: { jobId }
        });
        const response = ExportTestHelpers.createMockResponse();
        const next = ExportTestHelpers.createMockNext();

        mockExportService.getBatchJob.mockResolvedValue(job);
        mockExportService.downloadExport.mockResolvedValue({
          path: `/exports/${jobId}.zip`,
          filename: `export-${jobId}.zip`
        });

        promises.push(
          exportController.downloadExport(
            request as Request,
            response as Response,
            next
          )
        );
      });

      // Act
      await Promise.all(promises);

      // Assert
      expect(mockExportService.getBatchJob).toHaveBeenCalledTimes(users.length);
      expect(mockExportService.downloadExport).toHaveBeenCalledTimes(users.length);
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete export workflow', async () => {
      // Arrange - Create export
      const options = ExportMocks.createMockMLExportOptions({ format: 'coco' });
      mockRequest.body = { options };
      mockExportService.exportMLData.mockResolvedValue(mockJobId);

      // Act - Create export
      await exportController.createMLExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert creation
      expect(mockResponse.status).toHaveBeenCalledWith(202);
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        message: 'ML export job created successfully',
        data: { jobId: mockJobId }
      });

      // Reset mocks for next step
      jest.clearAllMocks();
      mockResponse = ExportTestHelpers.createMockResponse();

      // Arrange - Check status
      const processingJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'processing',
        progress: 50
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(processingJob);

      // Act - Check status
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert status check
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: processingJob
      });

      // Reset mocks for final step
      jest.clearAllMocks();
      mockResponse = ExportTestHelpers.createMockResponse();

      // Arrange - Download completed export
      const completedJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'completed',
        progress: 100
      });

      mockExportService.getBatchJob.mockResolvedValue(completedJob);
      mockExportService.downloadExport.mockResolvedValue({
        path: `/exports/${mockJobId}.zip`,
        filename: `koutu-export-${mockJobId.slice(0, 8)}.zip`
      });

      // Act - Download
      await exportController.downloadExport(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert download
      expect(mockResponse.download).toHaveBeenCalledWith(
        `/exports/${mockJobId}.zip`,
        `koutu-export-${mockJobId.slice(0, 8)}.zip`
      );
    });

    it('should handle export cancellation workflow', async () => {
      // Arrange - Get job status (pending)
      const pendingJob = ExportMocks.createMockMLExportBatchJob({
        id: mockJobId,
        userId: mockUserId,
        status: 'pending'
      });

      mockRequest.params = { jobId: mockJobId };
      mockExportService.getBatchJob.mockResolvedValue(pendingJob);

      // Act - Check status
      await exportController.getExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert job is pending
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        data: pendingJob
      });

      // Reset mocks for cancellation
      jest.clearAllMocks();
      mockResponse = ExportTestHelpers.createMockResponse();

      // Arrange - Cancel job
      mockExportService.getBatchJob.mockResolvedValue(pendingJob);
      mockExportService.cancelExportJob.mockResolvedValue(undefined);

      // Act - Cancel
      await exportController.cancelExportJob(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      // Assert cancellation
      expect(mockResponse.json).toHaveBeenCalledWith({
        success: true,
        message: 'Export job canceled successfully'
      });
    });
  });

  
});

  