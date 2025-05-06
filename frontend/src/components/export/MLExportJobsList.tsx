// frontend/src/components/export/MLExportJobsList.tsx
import React from 'react';
import { MLExportBatchJob } from '@koutu/shared/schemas/export';
import { useExportML } from '../../hooks/useExportML';

type MLExportJobsListProps = {
  onJobSelect?: (jobId: string) => void;
};

export const MLExportJobsList: React.FC<MLExportJobsListProps> = ({ onJobSelect }) => {
  const { 
    jobs, 
    isLoadingJobs, 
    jobsError, 
    activeJobId,
    cancelExportJob,
    isCancelingJob,
    trackExportJob,
    getExportDownloadUrl
  } = useExportML();

  if (isLoadingJobs) {
    return <div className="p-4 text-center">Loading export jobs...</div>;
  }

  if (jobsError) {
    return (
      <div className="p-4 text-center text-red-600">
        Error loading export jobs: {jobsError.message}
      </div>
    );
  }

  if (!jobs || jobs.length === 0) {
    return (
      <div className="p-4 text-center text-gray-500">
        No export jobs found. Create a new export to get started.
      </div>
    );
  }

  // Format date for display
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  // Get status badge color
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-green-100 text-green-800';
      case 'processing':
        return 'bg-blue-100 text-blue-800';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800';
      case 'failed':
        return 'bg-red-100 text-red-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden">
      <h2 className="text-xl font-bold p-4 border-b">Your Export Jobs</h2>
      
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Created
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Format
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Progress
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {jobs.map((job) => (
              <tr key={job.id} className={activeJobId === job.id ? 'bg-blue-50' : ''}>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900">{formatDate(job.createdAt)}</div>
                  {job.completedAt && (
                    <div className="text-xs text-gray-500">
                      Completed: {formatDate(job.completedAt)}
                    </div>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-900">{job.options.format.toUpperCase()}</div>
                  <div className="text-xs text-gray-500">
                    {job.totalItems} items
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs rounded-full ${getStatusColor(job.status)}`}>
                    {job.status}
                  </span>
                  {job.error && (
                    <div className="text-xs text-red-500 mt-1">
                      Error: {job.error}
                    </div>
                  )}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="relative pt-1">
                    <div className="overflow-hidden h-2 text-xs flex rounded bg-gray-200">
                      <div
                        style={{ width: `${job.progress}%` }}
                        className={`shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center ${
                          job.status === 'failed' ? 'bg-red-500' : 'bg-blue-500'
                        }`}
                      ></div>
                    </div>
                    <div className="text-xs text-gray-500 mt-1 text-right">
                      {job.processedItems} / {job.totalItems} ({job.progress}%)
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                  <div className="flex space-x-2">
                    {job.status === 'completed' && (
                      <a
                        href={getExportDownloadUrl(job.id)}
                        download
                        className="text-green-600 hover:text-green-900"
                      >
                        Download
                      </a>
                    )}
                    
                    {(job.status === 'pending' || job.status === 'processing') && (
                      <button
                        onClick={() => cancelExportJob(job.id)}
                        disabled={isCancelingJob}
                        className="text-red-600 hover:text-red-900 disabled:text-red-300"
                      >
                        Cancel
                      </button>
                    )}
                    
                    {onJobSelect && (
                      <button
                        onClick={() => {
                          trackExportJob(job.id);
                          onJobSelect(job.id);
                        }}
                        className="text-blue-600 hover:text-blue-900"
                      >
                        {activeJobId === job.id ? 'Selected' : 'Select'}
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};