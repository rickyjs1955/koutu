// /frontend/src/hooks/useExportML.ts
import { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from 'react-query';
import { exportApi } from '../api/exportApi';
import { MLExportOptions, MLExportBatchJob, DatasetStats } from '@koutu/shared/schemas/export';

/**
 * Custom hook for ML export functionality
 */
export const useExportML = () => {
  const queryClient = useQueryClient();
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [pollingInterval, setPollingInterval] = useState<number | null>(null);

  // Query for dataset statistics
  const statsQuery = useQuery<DatasetStats, Error>(
    ['datasetStats'],
    () => exportApi.getDatasetStats(),
    {
      staleTime: 5 * 60 * 1000, // 5 minutes
      refetchOnWindowFocus: false
    }
  );

  // Query for all user's export jobs
  const jobsQuery = useQuery<MLExportBatchJob[], Error>(
    ['exportJobs'],
    () => exportApi.getUserExportJobs(),
    {
      staleTime: 60 * 1000, // 1 minute
      refetchOnWindowFocus: true
    }
  );

  // Query for active job status
  const activeJobQuery = useQuery<MLExportBatchJob, Error>(
    ['exportJob', activeJobId],
    () => exportApi.getExportJob(activeJobId as string),
    {
      enabled: !!activeJobId,
      refetchInterval: pollingInterval === null ? false : pollingInterval,
      onSuccess: (data) => {
        // Stop polling if job is complete or failed
        if (data.status === 'completed' || data.status === 'failed') {
          setPollingInterval(null);
          queryClient.invalidateQueries(['exportJobs']);
        }
      }
    }
  );

  // Create export job mutation
  const createExportMutation = useMutation<
    { jobId: string },
    Error,
    MLExportOptions
  >(
    (options) => exportApi.createMLExport(options),
    {
      onSuccess: (data) => {
        // Set active job and start polling
        setActiveJobId(data.jobId);
        setPollingInterval(2000); // Poll every 2 seconds
        queryClient.invalidateQueries(['exportJobs']);
      }
    }
  );

  // Cancel export job mutation
  const cancelExportMutation = useMutation<void, Error, string>(
    (jobId) => exportApi.cancelExportJob(jobId),
    {
      onSuccess: () => {
        if (activeJobId === cancelExportMutation.variables) {
          setActiveJobId(null);
          setPollingInterval(null);
        }
        queryClient.invalidateQueries(['exportJobs']);
      }
    }
  );

  // Helper to create a new export job
  const createExportJob = useCallback(
    (options: MLExportOptions) => {
      createExportMutation.mutate(options);
    },
    [createExportMutation]
  );

  // Helper to cancel an export job
  const cancelExportJob = useCallback(
    (jobId: string) => {
      cancelExportMutation.mutate(jobId);
    },
    [cancelExportMutation]
  );

  // Helper to set an existing job as active for tracking
  const trackExportJob = useCallback(
    (jobId: string) => {
      setActiveJobId(jobId);
      
      // Only set polling interval if job is still processing
      const job = jobsQuery.data?.find(j => j.id === jobId);
      if (job && (job.status === 'pending' || job.status === 'processing')) {
        setPollingInterval(2000);
      }
    },
    [jobsQuery.data]
  );

  // Helper to stop tracking a job
  const stopTrackingJob = useCallback(() => {
    setActiveJobId(null);
    setPollingInterval(null);
  }, []);

  // Helper to get download URL for an export
  const getExportDownloadUrl = useCallback(
    (jobId: string) => {
      return exportApi.getExportDownloadUrl(jobId);
    },
    []
  );

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      setPollingInterval(null);
    };
  }, []);

  return {
    // Queries
    stats: statsQuery.data,
    isLoadingStats: statsQuery.isLoading,
    statsError: statsQuery.error,
    
    jobs: jobsQuery.data || [],
    isLoadingJobs: jobsQuery.isLoading,
    jobsError: jobsQuery.error,
    
    activeJob: activeJobQuery.data,
    isLoadingActiveJob: activeJobQuery.isLoading,
    activeJobError: activeJobQuery.error,
    
    // Mutations
    createExportJob,
    isCreatingJob: createExportMutation.isLoading,
    createJobError: createExportMutation.error,
    
    cancelExportJob,
    isCancelingJob: cancelExportMutation.isLoading,
    cancelJobError: cancelExportMutation.error,
    
    // Helpers
    trackExportJob,
    stopTrackingJob,
    getExportDownloadUrl,
    
    // State
    activeJobId
  };
};

// Add to frontend/src/hooks/index.ts
// export { useExportML } from './useExportML';