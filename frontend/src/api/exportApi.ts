// frontend/src/api/exportApi.ts
import { API_BASE_URL } from './index';
import { MLExportOptions, MLExportBatchJob, DatasetStats } from '@koutu/shared/schemas/export';

/**
 * Export API functions for ML data
 */
export const exportApi = {
  /**
   * Create a new ML export job
   */
  createMLExport: async (options: MLExportOptions): Promise<{ jobId: string }> => {
    const response = await fetch(`${API_BASE_URL}/export/ml`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ options })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to create ML export job');
    }

    const data = await response.json();
    return data.data;
  },

  /**
   * Get ML export job status
   */
  getExportJob: async (jobId: string): Promise<MLExportBatchJob> => {
    const response = await fetch(`${API_BASE_URL}/export/ml/jobs/${jobId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to get export job status');
    }

    const data = await response.json();
    return data.data;
  },

  /**
   * Get all ML export jobs for the user
   */
  getUserExportJobs: async (): Promise<MLExportBatchJob[]> => {
    const response = await fetch(`${API_BASE_URL}/export/ml/jobs`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to get export jobs');
    }

    const data = await response.json();
    return data.data;
  },

  /**
   * Cancel ML export job
   */
  cancelExportJob: async (jobId: string): Promise<void> => {
    const response = await fetch(`${API_BASE_URL}/export/ml/jobs/${jobId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to cancel export job');
    }
  },

  /**
   * Get dataset statistics for ML
   */
  getDatasetStats: async (): Promise<DatasetStats> => {
    const response = await fetch(`${API_BASE_URL}/export/ml/stats`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to get dataset statistics');
    }

    const data = await response.json();
    return data.data;
  },

  /**
   * Get download URL for ML export
   */
  getExportDownloadUrl: (jobId: string): string => {
    return `${API_BASE_URL}/export/ml/download/${jobId}`;
  }
};

// Update the index.ts to export the exportApi
// frontend/src/api/index.ts
// Add: export { exportApi } from './exportApi';