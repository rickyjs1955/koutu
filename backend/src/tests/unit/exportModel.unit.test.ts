// /backend/src/models/__tests__/exportModel.test.ts
import { exportModel, 
         ExportBatchJob, 
         CreateExportJobInput, 
         UpdateExportJobInput, 
         ExportJobQueryOptions
} from '../../models/exportModel';
import { query } from '../../models/db';
import { validate as isUuid } from 'uuid';
import { QueryResult } from 'pg';

// Type-safe mock interfaces
interface MockExportBatchJob extends ExportBatchJob {
  [key: string]: any;
}

// Mock dependencies with proper typing
jest.mock('../../models/db');
jest.mock('uuid', () => ({
  v4: jest.fn(),
  validate: jest.fn()
}));

const mockQuery = query as jest.MockedFunction<typeof query>;
const mockUuidV4 = require('uuid').v4 as jest.MockedFunction<() => string>;
const mockIsUuid = isUuid as jest.MockedFunction<typeof isUuid>;

// Mock helpers
class ExportMocks {
  static createMockExportBatchJob(overrides: Partial<ExportBatchJob> = {}): MockExportBatchJob {
    const mockDate = new Date('2024-01-15T10:00:00Z');
    return {
      id: 'job-456',
      user_id: 'user-123',
      status: 'pending',
      options: { format: 'coco' },
      progress: 0,
      total_items: 0,
      processed_items: 0,
      output_url: null,
      error: null,
      created_at: mockDate,
      updated_at: mockDate,
      completed_at: null,
      expires_at: null,
      ...overrides
    } as MockExportBatchJob;
  }

  static createMockStaleJobs(count: number): MockExportBatchJob[] {
    return Array.from({ length: count }, (_, i) => 
      this.createMockExportBatchJob({ 
        id: `stale-job-${i}`,
        status: i % 2 === 0 ? 'pending' : 'processing',
        created_at: new Date(Date.now() - (25 + i) * 60 * 60 * 1000) // 25+ hours ago
      })
    );
  }

  static createMockExpiredJobs(count: number): MockExportBatchJob[] {
    return Array.from({ length: count }, (_, i) => 
      this.createMockExportBatchJob({ 
        id: `expired-job-${i}`,
        status: 'completed',
        expires_at: new Date(Date.now() - (1 + i) * 24 * 60 * 60 * 1000) // 1+ days ago
      })
    );
  }

  static createMockProgressUpdates(): Array<{id: string, progress: number, processed_items: number}> {
    return [
      { id: 'job-1', progress: 25, processed_items: 25 },
      { id: 'job-2', progress: 50, processed_items: 50 },
      { id: 'job-3', progress: 75, processed_items: 75 }
    ];
  }
}

describe('ExportModel', () => {
  const mockUserId = 'user-123';
  const mockJobId = 'job-456';
  const mockDate = new Date('2024-01-15T10:00:00Z');

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    jest.setSystemTime(mockDate);

    // Default UUID mocks
    mockUuidV4.mockReturnValue(mockJobId);
    mockIsUuid.mockImplementation((id: unknown) => 
        typeof id === 'string' && id.includes('-')
    );
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('create', () => {
    it('should create a new export job with all required fields', async () => {
      // Arrange
      const inputData: CreateExportJobInput = {
        user_id: mockUserId,
        status: 'pending',
        options: { format: 'coco', includeImages: true },
        total_items: 50
      };

      const expectedJob = ExportMocks.createMockExportBatchJob({
        id: mockJobId,
        user_id: mockUserId,
        status: 'pending',
        options: inputData.options,
        total_items: 50,
        created_at: mockDate,
        updated_at: mockDate
      });

      mockQuery.mockResolvedValueOnce({
        rows: [expectedJob],
        rowCount: 1,
        command: 'INSERT',
        oid: 0,
        fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.create(inputData);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO export_batch_jobs'),
        expect.arrayContaining([
          mockJobId,
          mockUserId,
          'pending',
          JSON.stringify(inputData.options),
          0,
          50,
          0,
          expect.any(Date)
        ])
      );
      expect(result).toEqual(expectedJob);
    });

    it('should transform database record correctly', () => {
      // Arrange
      const rawDbRecord = {
        id: mockJobId,
        user_id: mockUserId,
        status: 'pending',
        options: '{"format":"yolo","includeImages":false}',
        progress: 0,
        total_items: 0,
        processed_items: 0,
        output_url: null,
        error: null,
        created_at: mockDate,
        updated_at: mockDate,
        completed_at: null,
        expires_at: null
      };

      // Act
      const result = exportModel.transformDbRecord(rawDbRecord);

      // Assert
      expect(result.options).toEqual({ format: 'yolo', includeImages: false });
      expect(typeof result.options).toBe('object');
    });

    it('should create job with default values when optional fields not provided', async () => {
      // Arrange
      const inputData: CreateExportJobInput = {
        user_id: mockUserId,
        status: 'processing',
        options: { format: 'yolo' }
      };

      const expectedJob = ExportMocks.createMockExportBatchJob({
        id: mockJobId,
        user_id: mockUserId,
        status: 'processing',
        total_items: 0,
        processed_items: 0,
        progress: 0
      });

      mockQuery.mockResolvedValueOnce({
        rows: [expectedJob],
        rowCount: 1,
        command: 'INSERT',
        oid: 0,
        fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.create(inputData);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO export_batch_jobs'),
        expect.arrayContaining([
          mockJobId,
          mockUserId,
          'processing',
          JSON.stringify(inputData.options),
          0,
          0, // default total_items
          0,
          expect.any(Date) // default expires_at (7 days from now)
        ])
      );
      expect(result.total_items).toBe(0);
    });

    it('should set default expiration date to 7 days from creation', async () => {
      // Arrange
      const inputData: CreateExportJobInput = {
        user_id: mockUserId,
        status: 'pending',
        options: { format: 'coco' }
      };

      const expectedExpirationDate = new Date(mockDate.getTime() + 7 * 24 * 60 * 60 * 1000);
      
      mockQuery.mockResolvedValueOnce({
        rows: [ExportMocks.createMockExportBatchJob()],
        rowCount: 1,
        command: 'INSERT',
        oid: 0,
        fields: []
        } as QueryResult<any>);

      // Act
      await exportModel.create(inputData);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO export_batch_jobs'),
        expect.arrayContaining([expectedExpirationDate])
      );
    });

    it('should use provided expiration date when specified', async () => {
      // Arrange
      const customExpirationDate = new Date('2024-02-01T10:00:00Z');
      const inputData: CreateExportJobInput = {
        user_id: mockUserId,
        status: 'pending',
        options: { format: 'coco' },
        expires_at: customExpirationDate
      };

      mockQuery.mockResolvedValueOnce({
        rows: [ExportMocks.createMockExportBatchJob()],
        rowCount: 1,
        command: 'INSERT',
        oid: 0,
        fields: []
        } as QueryResult<any>);

      // Act
      await exportModel.create(inputData);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO export_batch_jobs'),
        expect.arrayContaining([customExpirationDate])
      );
    });

    it('should properly serialize options object to JSON', async () => {
      // Arrange
      const complexOptions = {
        format: 'coco',
        includeImages: true,
        includeMasks: false,
        imageFormat: 'jpg',
        compressionQuality: 90,
        categoryFilter: ['shirt', 'pants'],
        customSettings: {
          nested: true,
          value: 42
        }
      };

      const inputData: CreateExportJobInput = {
        user_id: mockUserId,
        status: 'pending',
        options: complexOptions
      };

      mockQuery.mockResolvedValueOnce({
        rows: [ExportMocks.createMockExportBatchJob()],
        rowCount: 1,
        command: 'INSERT',
        oid: 0,
        fields: []
        } as QueryResult<any>);

      // Act
      await exportModel.create(inputData);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('INSERT INTO export_batch_jobs'),
        expect.arrayContaining([JSON.stringify(complexOptions)])
      );
    });

    it('should handle database errors gracefully', async () => {
      // Arrange
      const inputData: CreateExportJobInput = {
        user_id: mockUserId,
        status: 'pending',
        options: { format: 'coco' }
      };

      const dbError = new Error('Database connection failed');
      mockQuery.mockRejectedValueOnce(dbError);

      // Act & Assert
      await expect(exportModel.create(inputData)).rejects.toThrow('Database connection failed');
    });
  });

  describe('findById', () => {
    it('should find and return existing export job', async () => {
      // Arrange
      const expectedJob = ExportMocks.createMockExportBatchJob({
        id: mockJobId,
        user_id: mockUserId
      });

      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [expectedJob],
        rowCount: 1,
        command: 'INSERT',
        oid: 0,
        fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.findById(mockJobId);

      // Assert
      expect(mockIsUuid).toHaveBeenCalledWith(mockJobId);
      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM export_batch_jobs WHERE id = $1',
        [mockJobId]
      );
      expect(result).toEqual(expectedJob);
    });

    it('should return null when job not found', async () => {
      // Arrange
      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'SELECT',
        oid: 0,
        fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.findById(mockJobId);

      // Assert
      expect(result).toBeNull();
    });

    it('should return null for invalid UUID', async () => {
      // Arrange
      const invalidId = 'invalid-id';
      mockIsUuid.mockReturnValueOnce(false);

      // Act
      const result = await exportModel.findById(invalidId);

      // Assert
      expect(mockIsUuid).toHaveBeenCalledWith(invalidId);
      expect(mockQuery).not.toHaveBeenCalled();
      expect(result).toBeNull();
    });

    it('should properly transform database record', async () => {
      // Arrange
      const rawDbRecord = {
        id: mockJobId,
        user_id: mockUserId,
        status: 'completed',
        options: '{"format":"coco","includeImages":true}',
        progress: 100,
        total_items: 50,
        processed_items: 50,
        output_url: '/download/test.zip',
        error: null,
        created_at: mockDate,
        updated_at: mockDate,
        completed_at: mockDate,
        expires_at: null
      };

      const expectedTransformed = {
        id: mockJobId,
        user_id: mockUserId,
        status: 'completed',
        options: { format: 'coco', includeImages: true },
        progress: 100,
        total_items: 50,
        processed_items: 50,
        output_url: '/download/test.zip',
        error: null,
        created_at: mockDate,
        updated_at: mockDate,
        completed_at: mockDate,
        expires_at: null
      };

      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [rawDbRecord],
        rowCount: 1,
        command: 'SELECT',
        oid: 0,
        fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.findById(mockJobId);

      // Assert
      expect(result).toEqual(expectedTransformed);
      expect(typeof result?.options).toBe('object');
    });
  });

  describe('findByUserId', () => {
    const mockJobs = [
      ExportMocks.createMockExportBatchJob({ 
        user_id: mockUserId, 
        status: 'completed',
        created_at: new Date('2024-01-15T10:00:00Z')
      }),
      ExportMocks.createMockExportBatchJob({ 
        user_id: mockUserId, 
        status: 'processing',
        created_at: new Date('2024-01-14T10:00:00Z')
      }),
      ExportMocks.createMockExportBatchJob({ 
        user_id: mockUserId, 
        status: 'pending',
        created_at: new Date('2024-01-13T10:00:00Z')
      })
    ];

    it('should find all jobs for user with default options', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: mockJobs,
        rowCount: mockJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findByUserId(mockUserId);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringMatching(/SELECT \* FROM export_batch_jobs WHERE user_id = \$1.*ORDER BY created_at DESC/),
        [mockUserId]
      );
      expect(result).toHaveLength(mockJobs.length);
      expect(result[0].user_id).toBe(mockUserId);
    });

    it('should filter by status when provided', async () => {
      // Arrange
      const options: ExportJobQueryOptions = { status: 'completed' };
      const completedJobs = mockJobs.filter(job => job.status === 'completed');

      mockQuery.mockResolvedValueOnce({
        rows: completedJobs,
        rowCount: completedJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findByUserId(mockUserId, options);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('AND status = $2'),
        [mockUserId, 'completed']
      );
      expect(result).toHaveLength(completedJobs.length);
    });

    it('should exclude expired jobs by default', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: mockJobs,
        rowCount: mockJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      await exportModel.findByUserId(mockUserId);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('AND (expires_at IS NULL OR expires_at > NOW())'),
        [mockUserId]
      );
    });

    it('should include expired jobs when explicitly requested', async () => {
      // Arrange
      const options: ExportJobQueryOptions = { includeExpired: true };

      mockQuery.mockResolvedValueOnce({
        rows: mockJobs,
        rowCount: mockJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      await exportModel.findByUserId(mockUserId, options);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.not.stringContaining('expires_at'),
        [mockUserId]
      );
    });

    it('should apply pagination with limit and offset', async () => {
      // Arrange
      const options: ExportJobQueryOptions = { limit: 10, offset: 20 };
      const paginatedJobs = mockJobs.slice(0, 2);

      mockQuery.mockResolvedValueOnce({
        rows: paginatedJobs,
        rowCount: paginatedJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findByUserId(mockUserId, options);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringMatching(/LIMIT \$2.*OFFSET \$3/),
        [mockUserId, 10, 20]
      );
      expect(result).toHaveLength(paginatedJobs.length);
    });

    it('should combine multiple query options correctly', async () => {
      // Arrange
      const options: ExportJobQueryOptions = {
        status: 'processing',
        limit: 5,
        offset: 10,
        includeExpired: false
      };

      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      await exportModel.findByUserId(mockUserId, options);

      // Assert
      const queryCall = mockQuery.mock.calls[0];
      const queryText = queryCall[0];
      const queryParams = queryCall[1];

      expect(queryText).toContain('AND status = $2');
      expect(queryText).toContain('AND (expires_at IS NULL OR expires_at > NOW())');
      expect(queryText).toContain('LIMIT $3');
      expect(queryText).toContain('OFFSET $4');
      expect(queryParams).toEqual([mockUserId, 'processing', 5, 10]);
    });
  });

  describe('update', () => {
    it('should update job with single field', async () => {
      // Arrange
      const updateData: UpdateExportJobInput = { progress: 50 };
      const updatedJob = ExportMocks.createMockExportBatchJob({
        id: mockJobId,
        progress: 50
      });

      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [updatedJob],
        rowCount: 1,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.update(mockJobId, updateData);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE export_batch_jobs'),
        [50, mockJobId]
      );
      
      // Verify the query structure
      const queryCall = mockQuery.mock.calls[0];
      const queryText = queryCall[0];
      expect(queryText).toContain('SET progress = $1');
      expect(queryText).toContain('updated_at = NOW()');
      expect(queryText).toContain('WHERE id = $2');
      expect(queryText).toContain('RETURNING *');
      
      expect(result).toEqual(updatedJob);
    });

    it('should update job with multiple fields', async () => {
      // Arrange
      const updateData: UpdateExportJobInput = {
        status: 'completed',
        progress: 100,
        processed_items: 50,
        output_url: '/download/test.zip',
        completed_at: mockDate
      };

      const updatedJob = ExportMocks.createMockExportBatchJob({
        id: mockJobId,
        ...updateData
      });

      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [updatedJob],
        rowCount: 1,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.update(mockJobId, updateData);

      // Assert
      const queryCall = mockQuery.mock.calls[0];
      const queryText = queryCall[0];
      const queryParams = queryCall[1];

      expect(queryText).toContain('status = $1');
      expect(queryText).toContain('progress = $2');
      expect(queryText).toContain('processed_items = $3');
      expect(queryText).toContain('output_url = $4');
      expect(queryText).toContain('completed_at = $5');
      expect(queryText).toContain('updated_at = NOW()');
      expect(queryParams).toEqual(['completed', 100, 50, '/download/test.zip', mockDate, mockJobId]);
      expect(result).toEqual(updatedJob);
    });

    it('should return null for invalid UUID', async () => {
      // Arrange
      const invalidId = 'invalid-id';
      const updateData: UpdateExportJobInput = { progress: 50 };

      mockIsUuid.mockReturnValueOnce(false);

      // Act
      const result = await exportModel.update(invalidId, updateData);

      // Assert
      expect(mockIsUuid).toHaveBeenCalledWith(invalidId);
      expect(mockQuery).not.toHaveBeenCalled();
      expect(result).toBeNull();
    });

    it('should return null when job not found', async () => {
      // Arrange
      const updateData: UpdateExportJobInput = { progress: 50 };

      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.update(mockJobId, updateData);

      // Assert
      expect(result).toBeNull();
    });

    it('should return existing job when no real updates provided', async () => {
      // Arrange
      const updateData: UpdateExportJobInput = {}; // Empty update
      const existingJob = ExportMocks.createMockExportBatchJob({ id: mockJobId });

      mockIsUuid.mockReturnValueOnce(true);
      
      // Mock findById call
      jest.spyOn(exportModel, 'findById').mockResolvedValueOnce(existingJob);

      // Act
      const result = await exportModel.update(mockJobId, updateData);

      // Assert
      expect(exportModel.findById).toHaveBeenCalledWith(mockJobId);
      expect(mockQuery).not.toHaveBeenCalled();
      expect(result).toEqual(existingJob);
    });

    it('should handle undefined values correctly', async () => {
      // Arrange
      const updateData: UpdateExportJobInput = {
        status: 'failed',
        error: 'Processing failed',
        output_url: undefined,
        completed_at: undefined
      };

      const updatedJob = ExportMocks.createMockExportBatchJob({
        id: mockJobId,
        status: 'failed',
        error: 'Processing failed'
      });

      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [updatedJob],
        rowCount: 1,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.update(mockJobId, updateData);

      // Assert
      const queryCall = mockQuery.mock.calls[0];
      const queryText = queryCall[0];

      expect(queryText).toContain('status = $1');
      expect(queryText).toContain('error = $2');
      expect(queryText).not.toContain('output_url');
      expect(queryText).not.toContain('completed_at');
      expect(result).toEqual(updatedJob);
    });
  });

  describe('delete', () => {
    it('should delete existing job and return true', async () => {
      // Arrange
      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 1,
        command: 'DELETE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.delete(mockJobId);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        'DELETE FROM export_batch_jobs WHERE id = $1',
        [mockJobId]
      );
      expect(result).toBe(true);
    });

    it('should return false when job not found', async () => {
      // Arrange
      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'DELETE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.delete(mockJobId);

      // Assert
      expect(result).toBe(false);
    });

    it('should return false for invalid UUID', async () => {
      // Arrange
      const invalidId = 'invalid-id';
      mockIsUuid.mockReturnValueOnce(false);

      // Act
      const result = await exportModel.delete(invalidId);

      // Assert
      expect(mockIsUuid).toHaveBeenCalledWith(invalidId);
      expect(mockQuery).not.toHaveBeenCalled();
      expect(result).toBe(false);
    });

    it('should handle null rowCount gracefully', async () => {
      // Arrange
      mockIsUuid.mockReturnValueOnce(true);
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: null,
        command: 'DELETE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.delete(mockJobId);

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('findByStatus', () => {
    it('should find jobs by status with no limit', async () => {
      // Arrange
      const pendingJobs = [
        ExportMocks.createMockExportBatchJob({ status: 'pending' }),
        ExportMocks.createMockExportBatchJob({ status: 'pending' })
      ];

      mockQuery.mockResolvedValueOnce({
        rows: pendingJobs,
        rowCount: pendingJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findByStatus('pending');

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM export_batch_jobs WHERE status = $1 ORDER BY created_at ASC',
        ['pending']
      );
      expect(result).toHaveLength(pendingJobs.length);
      expect(result.every(job => job.status === 'pending')).toBe(true);
    });

    it('should find jobs by status with limit', async () => {
      // Arrange
      const processingJobs = [
        ExportMocks.createMockExportBatchJob({ status: 'processing' })
      ];

      mockQuery.mockResolvedValueOnce({
        rows: processingJobs,
        rowCount: processingJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findByStatus('processing', 5);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        'SELECT * FROM export_batch_jobs WHERE status = $1 ORDER BY created_at ASC LIMIT $2',
        ['processing', 5]
      );
      expect(result).toHaveLength(processingJobs.length);
    });

    it('should return empty array when no jobs found', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findByStatus('cancelled');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findStaleJobs', () => {
    it('should find stale jobs with default 24 hour cutoff', async () => {
      // Arrange
      const staleJobs = ExportMocks.createMockStaleJobs(3);
      const expectedCutoffTime = new Date(mockDate.getTime() - 24 * 60 * 60 * 1000);

      mockQuery.mockResolvedValueOnce({
        rows: staleJobs,
        rowCount: staleJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findStaleJobs();

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("WHERE status IN ('pending', 'processing')"),
        [expectedCutoffTime]
      );
      expect(result).toHaveLength(staleJobs.length);
    });

    it('should find stale jobs with custom cutoff time', async () => {
      // Arrange
      const customHours = 48;
      const staleJobs = ExportMocks.createMockStaleJobs(2);
      const expectedCutoffTime = new Date(mockDate.getTime() - customHours * 60 * 60 * 1000);

      mockQuery.mockResolvedValueOnce({
        rows: staleJobs,
        rowCount: staleJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findStaleJobs(customHours);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("WHERE status IN ('pending', 'processing')"),
        [expectedCutoffTime]
      );
      expect(result).toHaveLength(staleJobs.length);
    });

    it('should order results by creation date ascending', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      await exportModel.findStaleJobs();

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('ORDER BY created_at ASC'),
        expect.any(Array)
      );
    });
  });

  describe('findExpiredJobs', () => {
    it('should find expired completed jobs', async () => {
      // Arrange
      const expiredJobs = ExportMocks.createMockExpiredJobs(2);

      mockQuery.mockResolvedValueOnce({
        rows: expiredJobs,
        rowCount: expiredJobs.length,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.findExpiredJobs();

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringMatching(/WHERE expires_at IS NOT NULL.*AND expires_at < NOW\(\).*AND status = 'completed'/s)
      );
      expect(result).toHaveLength(expiredJobs.length);
      expect(result.every(job => job.status === 'completed')).toBe(true);
    });

    it('should order expired jobs by expiration date', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      await exportModel.findExpiredJobs();

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('ORDER BY expires_at ASC')
      );
    });
  });

  describe('getUserStats', () => {
    it('should calculate comprehensive user statistics', async () => {
      // Arrange
      const mockStatsRows = [
        { total: '10', status: 'completed', total_processed_items: '500', avg_processing_seconds: '120.5' },
        { total: '3', status: 'failed', total_processed_items: '50', avg_processing_seconds: null },
        { total: '2', status: 'pending', total_processed_items: '0', avg_processing_seconds: null },
        { total: '1', status: 'processing', total_processed_items: '25', avg_processing_seconds: null }
      ];

      const mockTodayRows = [
        { completed_today: '3' }
      ];

      // Mock the two separate queries
      mockQuery
        .mockResolvedValueOnce({
          rows: mockStatsRows,
          rowCount: mockStatsRows.length,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>)
        .mockResolvedValueOnce({
          rows: mockTodayRows,
          rowCount: 1,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.getUserStats(mockUserId);

      // Assert
      expect(mockQuery).toHaveBeenCalledTimes(2);
      
      // Verify first query (main stats)
      expect(mockQuery).toHaveBeenNthCalledWith(1,
        expect.stringContaining('GROUP BY status'),
        [mockUserId]
      );

      // Verify second query (today's completed jobs)
      expect(mockQuery).toHaveBeenNthCalledWith(2,
        expect.stringContaining("DATE(completed_at) = CURRENT_DATE"),
        [mockUserId]
      );

      // Verify calculated statistics with proper aggregation
      expect(result).toEqual({
        total: 16, // 10 + 3 + 2 + 1
        byStatus: {
          'completed': 10,
          'failed': 3,
          'pending': 2,
          'processing': 1
        },
        completedToday: 3,
        totalProcessedItems: 575, // 500 + 50 + 0 + 25
        averageProcessingTime: 121 // Rounded from 120.5 (only from completed jobs)
      });
    });

    it('should handle empty results gracefully', async () => {
      // Arrange
      mockQuery
        .mockResolvedValueOnce({
          rows: [],
          rowCount: 0,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>)
        .mockResolvedValueOnce({
          rows: [{ completed_today: null }],
          rowCount: 1,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.getUserStats(mockUserId);

      // Assert
      expect(result).toEqual({
        total: 0,
        byStatus: {},
        completedToday: 0,
        totalProcessedItems: 0,
        averageProcessingTime: 0
      });
    });

    it('should aggregate multiple rows with same status correctly', async () => {
      // Arrange
      const mockStatsRows = [
        { total: '5', status: 'completed', total_processed_items: '250', avg_processing_seconds: '100' },
        { total: '3', status: 'completed', total_processed_items: '150', avg_processing_seconds: '200' },
        { total: '2', status: 'failed', total_processed_items: '20', avg_processing_seconds: null }
      ];

      mockQuery
        .mockResolvedValueOnce({
          rows: mockStatsRows,
          rowCount: 3,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>)
        .mockResolvedValueOnce({
          rows: [{ completed_today: '1' }],
          rowCount: 1,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.getUserStats(mockUserId);

      // Assert
      expect(result.byStatus).toEqual({
        'completed': 8, // 5 + 3 (aggregated)
        'failed': 2
      });
      expect(result.averageProcessingTime).toBe(138); // (100*5 + 200*3) / 8 = 137.5 rounded to 138
    });

    it('should handle null processing times correctly', async () => {
      // Arrange
      const mockStatsRows = [
        { total: '5', status: 'completed', total_processed_items: null, avg_processing_seconds: '100' },
        { total: null, status: 'pending', total_processed_items: '0', avg_processing_seconds: null }
      ];

      mockQuery
        .mockResolvedValueOnce({
          rows: mockStatsRows,
          rowCount: 2,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>)
        .mockResolvedValueOnce({
          rows: [{ completed_today: null }],
          rowCount: 1,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>);

      // Act
      const result = await exportModel.getUserStats(mockUserId);

      // Assert
      expect(result.total).toBe(5); // null handled gracefully
      expect(result.totalProcessedItems).toBe(0); // null treated as 0
      expect(result.completedToday).toBe(0);
    });
  });

  describe('cleanupOldJobs', () => {
    it('should cleanup old jobs with default 30 day cutoff', async () => {
      // Arrange
      const expectedCutoffTime = new Date(mockDate.getTime() - 30 * 24 * 60 * 60 * 1000);
      
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 5,
        command: 'DELETE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.cleanupOldJobs();

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("WHERE created_at < $1"),
        [expectedCutoffTime]
      );
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("AND status IN ('completed', 'failed', 'cancelled')"),
        expect.any(Array)
      );
      expect(result).toBe(5);
    });

    it('should cleanup old jobs with custom cutoff days', async () => {
      // Arrange
      const customDays = 7;
      const expectedCutoffTime = new Date(mockDate.getTime() - customDays * 24 * 60 * 60 * 1000);
      
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 3,
        command: 'DELETE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.cleanupOldJobs(customDays);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("WHERE created_at < $1"),
        [expectedCutoffTime]
      );
      expect(result).toBe(3);
    });

    it('should handle null rowCount gracefully', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: null,
        command: 'DELETE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.cleanupOldJobs();

      // Assert
      expect(result).toBe(0);
    });
  });

  describe('cancelUserJobs', () => {
    it('should cancel all pending and processing jobs for user', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 3,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.cancelUserJobs(mockUserId);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE export_batch_jobs'),
        [mockUserId]
      );
      
      // Verify query structure
      const queryCall = mockQuery.mock.calls[0];
      const queryText = queryCall[0];
      expect(queryText).toContain("SET status = 'cancelled'");
      expect(queryText).toContain('updated_at = NOW()');
      expect(queryText).toContain('WHERE user_id = $1');
      expect(queryText).toContain("AND status IN ('pending', 'processing')");
      
      expect(result).toBe(3);
    });

    it('should return 0 when no jobs to cancel', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.cancelUserJobs(mockUserId);

      // Assert
      expect(result).toBe(0);
    });

    it('should handle null rowCount gracefully', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: null,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.cancelUserJobs(mockUserId);

      // Assert
      expect(result).toBe(0);
    });
  });

  describe('getActiveJobCount', () => {
    it('should return count of active jobs for user', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [{ active_count: '5' }],
        rowCount: 1,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.getActiveJobCount(mockUserId);

      // Assert
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("COUNT(*) as active_count"),
        [mockUserId]
      );
      expect(mockQuery).toHaveBeenCalledWith(
        expect.stringContaining("AND status IN ('pending', 'processing')"),
        expect.any(Array)
      );
      expect(result).toBe(5);
    });

    it('should return 0 when no active jobs found', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [{ active_count: null }],
        rowCount: 1,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.getActiveJobCount(mockUserId);

      // Assert
      expect(result).toBe(0);
    });

    it('should handle empty results gracefully', async () => {
      // Arrange
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 0,
        command: 'SELECT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.getActiveJobCount(mockUserId);

      // Assert
      expect(result).toBe(0);
    });
  });

  describe('transformDbRecord', () => {
    it('should transform database record to proper types', () => {
      // Arrange
      const rawDbRecord = {
        id: mockJobId,
        user_id: mockUserId,
        status: 'completed',
        options: '{"format":"coco","includeImages":true}',
        progress: 100,
        total_items: 50,
        processed_items: 50,
        output_url: '/download/test.zip',
        error: null,
        created_at: mockDate,
        updated_at: mockDate,
        completed_at: mockDate,
        expires_at: null
      };

      // Act
      const result = exportModel.transformDbRecord(rawDbRecord);

      // Assert
      expect(result).toEqual({
        id: mockJobId,
        user_id: mockUserId,
        status: 'completed',
        options: { format: 'coco', includeImages: true },
        progress: 100,
        total_items: 50,
        processed_items: 50,
        output_url: '/download/test.zip',
        error: null,
        created_at: mockDate,
        updated_at: mockDate,
        completed_at: mockDate,
        expires_at: null
      });
      expect(typeof result.options).toBe('object');
    });

    it('should handle already parsed options object', () => {
      // Arrange
      const rawDbRecord = {
        id: mockJobId,
        user_id: mockUserId,
        status: 'pending',
        options: { format: 'yolo', includeImages: false }, // Already an object
        progress: 0,
        total_items: 0,
        processed_items: 0,
        output_url: null,
        error: null,
        created_at: mockDate,
        updated_at: mockDate,
        completed_at: null,
        expires_at: null
      };

      // Act
      const result = exportModel.transformDbRecord(rawDbRecord);

      // Assert
      expect(result.options).toEqual({ format: 'yolo', includeImages: false });
      expect(typeof result.options).toBe('object');
    });

    it('should handle invalid JSON in options gracefully', () => {
      // Arrange
      const rawDbRecord = {
        id: mockJobId,
        user_id: mockUserId,
        status: 'failed',
        options: '{invalid json}', // Invalid JSON
        progress: 0,
        total_items: 0,
        processed_items: 0,
        output_url: null,
        error: 'Invalid options format',
        created_at: mockDate,
        updated_at: mockDate,
        completed_at: null,
        expires_at: null
      };

      // Act & Assert
      expect(() => exportModel.transformDbRecord(rawDbRecord)).toThrow();
    });
  });

  describe('batchUpdateProgress', () => {
    it('should update progress for multiple jobs efficiently', async () => {
      // Arrange
      const updates = ExportMocks.createMockProgressUpdates();
      
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: updates.length,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.batchUpdateProgress(updates);

      // Assert
      expect(mockQuery).toHaveBeenCalledTimes(1);
      
      const queryCall = mockQuery.mock.calls[0];
      const queryText = queryCall[0];
      const queryParams = queryCall[1];

      // Verify CASE statements are used for efficiency
      expect(queryText).toContain('CASE');
      expect(queryText).toContain('progress = CASE');
      expect(queryText).toContain('processed_items = CASE');
      expect(queryText).toContain('updated_at = NOW()');
      expect(queryText).toContain('WHERE id IN');

      // Verify parameters include all update data
      expect(queryParams).toHaveLength(updates.length * 4); // 3 params per update + all IDs
      expect(result).toBe(updates.length);
    });

    it('should return 0 for empty updates array', async () => {
      // Arrange
      const updates: Array<{id: string, progress: number, processed_items: number}> = [];

      // Act
      const result = await exportModel.batchUpdateProgress(updates);

      // Assert
      expect(mockQuery).not.toHaveBeenCalled();
      expect(result).toBe(0);
    });

    it('should handle single update correctly', async () => {
      // Arrange
      const updates = [{
        id: mockJobId,
        progress: 75,
        processed_items: 75
      }];

      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: 1,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.batchUpdateProgress(updates);

      // Assert
      expect(mockQuery).toHaveBeenCalledTimes(1);
      
      const queryCall = mockQuery.mock.calls[0];
      const queryParams = queryCall[1];

      expect(queryParams).toEqual([
        mockJobId, 75, 75, // Update data
        mockJobId // ID for WHERE clause
      ]);
      expect(result).toBe(1);
    });

    it('should handle null rowCount gracefully', async () => {
      // Arrange
      const updates = ExportMocks.createMockProgressUpdates();
      
      mockQuery.mockResolvedValueOnce({
        rows: [],
        rowCount: null,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act
      const result = await exportModel.batchUpdateProgress(updates);

      // Assert
      expect(result).toBe(0);
    });

    it('should handle database errors during batch update', async () => {
      // Arrange
      const updates = ExportMocks.createMockProgressUpdates();
      const dbError = new Error('Database connection lost');
      
      mockQuery.mockRejectedValueOnce(dbError);

      // Act & Assert
      await expect(exportModel.batchUpdateProgress(updates)).rejects.toThrow('Database connection lost');
    });
  });

  describe('Error Handling', () => {
    it('should propagate database errors from all methods', async () => {
      // Arrange
      const dbError = new Error('Connection timeout');
      mockQuery.mockRejectedValue(dbError);

      // Act & Assert
      await expect(exportModel.create({
        user_id: mockUserId,
        status: 'pending',
        options: {}
      })).rejects.toThrow('Connection timeout');

      mockIsUuid.mockReturnValue(true);
      await expect(exportModel.findById(mockJobId)).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.findByUserId(mockUserId)).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.update(mockJobId, { progress: 50 })).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.delete(mockJobId)).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.findByStatus('pending')).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.findStaleJobs()).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.findExpiredJobs()).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.getUserStats(mockUserId)).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.cleanupOldJobs()).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.cancelUserJobs(mockUserId)).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.getActiveJobCount(mockUserId)).rejects.toThrow('Connection timeout');
      
      await expect(exportModel.batchUpdateProgress([])).resolves.toBe(0); // This one doesn't call query for empty array
    });
  });

  describe('Integration Scenarios', () => {
    it('should handle complete job lifecycle', async () => {
      // Arrange - Create job
      const createInput: CreateExportJobInput = {
        user_id: mockUserId,
        status: 'pending',
        options: { format: 'coco', includeImages: true },
        total_items: 100
      };

      const createdJob = ExportMocks.createMockExportBatchJob({
        id: mockJobId,
        ...createInput,
        progress: 0,
        processed_items: 0
      });

      // Mock create
      mockQuery.mockResolvedValueOnce({
        rows: [createdJob],
        rowCount: 1,
        command: 'INSERT',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act - Create
      const newJob = await exportModel.create(createInput);
      expect(newJob.status).toBe('pending');

      // Arrange - Update to processing
      const processingJob = { ...createdJob, status: 'processing' as const, progress: 25, processed_items: 25 };
      mockIsUuid.mockReturnValue(true);
      mockQuery.mockResolvedValueOnce({
        rows: [processingJob],
        rowCount: 1,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act - Update
      const updatedJob = await exportModel.update(mockJobId, { 
        status: 'processing', 
        progress: 25, 
        processed_items: 25 
      });
      expect(updatedJob?.status).toBe('processing');

      // Arrange - Complete job
      const completedJob = { 
        ...processingJob, 
        status: 'completed' as const, 
        progress: 100, 
        processed_items: 100,
        output_url: '/download/test.zip',
        completed_at: mockDate
      };
      
      mockQuery.mockResolvedValueOnce({
        rows: [completedJob],
        rowCount: 1,
        command: 'UPDATE',
        oid: 0,
        fields: []
      } as QueryResult<any>);

      // Act - Complete
      const finalJob = await exportModel.update(mockJobId, {
        status: 'completed',
        progress: 100,
        processed_items: 100,
        output_url: '/download/test.zip',
        completed_at: mockDate
      });

      // Assert
      expect(finalJob?.status).toBe('completed');
      expect(finalJob?.progress).toBe(100);
      expect(finalJob?.output_url).toBe('/download/test.zip');
    });

    it('should handle concurrent job operations', async () => {
      // Test that multiple operations can be called without interfering
      const jobs = Array.from({ length: 3 }, (_, i) => 
        ExportMocks.createMockExportBatchJob({ user_id: mockUserId })
      );

      // Mock multiple query responses
      mockQuery
        .mockResolvedValueOnce({
          rows: jobs,
          rowCount: jobs.length,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>)
        .mockResolvedValueOnce({
          rows: [{ active_count: '2' }],
          rowCount: 1,
          command: 'SELECT',
          oid: 0,
          fields: []
        } as QueryResult<any>)
        .mockResolvedValueOnce({
          rows: [],
          rowCount: 1,
          command: 'UPDATE',
          oid: 0,
          fields: []
        } as QueryResult<any>);

      // Act - Simulate concurrent operations
      const [userJobs, activeCount, cancelResult] = await Promise.all([
        exportModel.findByUserId(mockUserId),
        exportModel.getActiveJobCount(mockUserId),
        exportModel.cancelUserJobs('other-user')
      ]);

      // Assert
      expect(userJobs).toHaveLength(3);
      expect(activeCount).toBe(2);
      expect(cancelResult).toBe(1);
      expect(mockQuery).toHaveBeenCalledTimes(3);
    });
  });
});