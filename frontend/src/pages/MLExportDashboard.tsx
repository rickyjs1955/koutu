// /frontend/src/pages/MLExportDashboard.tsx
import React, { useState } from 'react';
import { MLExportForm } from '../components/export/MLExportForm';
import { MLExportJobsList } from '../components/export/MLExportJobsList';
import { useExportML } from '../hooks/useExportML';

export const MLExportDashboard: React.FC = () => {
  const { activeJob, activeJobId, stopTrackingJob } = useExportML();
  const [activeTab, setActiveTab] = useState<'form' | 'jobs'>('form');

  const handleExportStarted = () => {
    setActiveTab('jobs');
  };

  const handleJobSelect = (jobId: string) => {
    // This function is handled by the useExportML hook via trackExportJob
    // We just switch to the jobs tab to show the active job
    setActiveTab('jobs');
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-3xl font-bold mb-6">ML Export Dashboard</h1>
      
      <div className="mb-6">
        <div className="border-b border-gray-200">
          <nav className="-mb-px flex">
            <button
              onClick={() => setActiveTab('form')}
              className={`mr-8 py-4 px-1 ${
                activeTab === 'form'
                  ? 'border-b-2 border-blue-500 text-blue-600 font-medium'
                  : 'text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Create Export
            </button>
            <button
              onClick={() => setActiveTab('jobs')}
              className={`py-4 px-1 ${
                activeTab === 'jobs'
                  ? 'border-b-2 border-blue-500 text-blue-600 font-medium'
                  : 'text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              Export Jobs
            </button>
          </nav>
        </div>
      </div>
      
      {activeTab === 'form' ? (
        <MLExportForm onExportStarted={handleExportStarted} />
      ) : (
        <div>
          {/* Active Job Details */}
          {activeJob && (
            <div className="mb-8 p-6 bg-white rounded-lg shadow-md relative">
              <button
                onClick={stopTrackingJob}
                className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
                aria-label="Close"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="h-6 w-6"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
              
              <h2 className="text-2xl font-bold mb-4">Export Job Details</h2>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="font-semibold mb-2">Job Information</h3>
                  <div className="space-y-2 text-sm">
                    <div>
                      <span className="text-gray-600">Job ID:</span> {activeJob.id}
                    </div>
                    <div>
                      <span className="text-gray-600">Created:</span>{' '}
                      {new Date(activeJob.createdAt).toLocaleString()}
                    </div>
                    {activeJob.completedAt && (
                      <div>
                        <span className="text-gray-600">Completed:</span>{' '}
                        {new Date(activeJob.completedAt).toLocaleString()}
                      </div>
                    )}
                    <div>
                      <span className="text-gray-600">Status:</span>{' '}
                      <span
                        className={`px-2 py-0.5 rounded-full text-xs ${
                          activeJob.status === 'completed'
                            ? 'bg-green-100 text-green-800'
                            : activeJob.status === 'processing'
                            ? 'bg-blue-100 text-blue-800'
                            : activeJob.status === 'pending'
                            ? 'bg-yellow-100 text-yellow-800'
                            : 'bg-red-100 text-red-800'
                        }`}
                      >
                        {activeJob.status}
                      </span>
                    </div>
                    <div>
                      <span className="text-gray-600">Progress:</span>{' '}
                      {activeJob.processedItems} of {activeJob.totalItems} items (
                      {activeJob.progress}%)
                    </div>
                  </div>
                </div>
                
                <div>
                  <h3 className="font-semibold mb-2">Export Options</h3>
                  <div className="space-y-2 text-sm">
                    <div>
                      <span className="text-gray-600">Format:</span>{' '}
                      {activeJob.options.format.toUpperCase()}
                    </div>
                    <div>
                      <span className="text-gray-600">Include Images:</span>{' '}
                      {activeJob.options.includeImages ? 'Yes' : 'No'}
                    </div>
                    <div>
                      <span className="text-gray-600">Include Masks:</span>{' '}
                      {activeJob.options.includeMasks ? 'Yes' : 'No'}
                    </div>
                    <div>
                      <span className="text-gray-600">Include Polygons:</span>{' '}
                      {activeJob.options.includeRawPolygons ? 'Yes' : 'No'}
                    </div>
                    <div>
                      <span className="text-gray-600">Image Format:</span>{' '}
                      {activeJob.options.imageFormat.toUpperCase()}
                    </div>
                    {activeJob.options.categoryFilter && activeJob.options.categoryFilter.length > 0 && (
                      <div>
                        <span className="text-gray-600">Categories:</span>{' '}
                        {activeJob.options.categoryFilter.join(', ')}
                      </div>
                    )}
                  </div>
                </div>
              </div>
              
              {/* Progress Bar */}
              <div className="mt-6">
                <div className="relative pt-1">
                  <div className="overflow-hidden h-4 text-xs flex rounded-full bg-gray-200">
                    <div
                      style={{ width: `${activeJob.progress}%` }}
                      className={`shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center ${
                        activeJob.status === 'failed' ? 'bg-red-500' : 'bg-blue-500'
                      }`}
                    ></div>
                  </div>
                </div>
              </div>
              
              {/* Job Actions */}
              <div className="mt-6 flex justify-end">
                {activeJob.status === 'completed' && activeJob.outputUrl && (
                  <a
                    href={activeJob.outputUrl}
                    download
                    className="bg-green-600 hover:bg-green-700 text-white font-medium py-2 px-4 rounded"
                  >
                    Download Export
                  </a>
                )}
                
                {activeJob.error && (
                  <div className="mt-4 p-3 bg-red-100 text-red-800 rounded">
                    <strong>Error:</strong> {activeJob.error}
                  </div>
                )}
              </div>
            </div>
          )}
          
          <MLExportJobsList onJobSelect={handleJobSelect} />
        </div>
      )}
      
      {/* ML Data Usage Guide */}
      <div className="mt-12 p-6 bg-white rounded-lg shadow-md">
        <h2 className="text-2xl font-bold mb-4">ML Data Usage Guide</h2>
        
        <div className="prose prose-blue">
          <p>
            The exported data packages are designed to be easily loaded into Python for training machine learning models. Each export includes a <code>load_dataset.py</code> file that provides helper functions for loading and visualizing the data.
          </p>
          
          <h3>Getting Started with the Data</h3>
          
          <pre className="bg-gray-100 p-4 rounded">
            <code>
{`# Example Python code
import os
from load_dataset import load_koutu_dataset, display_sample

# Update this path to your dataset directory
dataset_dir = '/path/to/extracted/export'

# Load the dataset based on your chosen format
# Example for COCO format:
coco = load_koutu_dataset(dataset_dir)

# Display dataset info
print(f"Total images: {len(coco.imgs)}")
print(f"Total annotations: {len(coco.anns)}")

# Display a random sample
display_sample(coco)`}
            </code>
          </pre>
          
          <h3>Format-Specific Usage</h3>
          
          <h4>COCO Format</h4>
          <p>
            COCO format is widely supported by libraries like PyTorch, TensorFlow, and MMDetection. The export includes an <code>annotations.json</code> file and an <code>images</code> directory.
          </p>
          
          <h4>YOLO Format</h4>
          <p>
            YOLO format provides normalized bounding box coordinates and is ideal for training YOLO models. The export includes <code>images</code> and <code>labels</code> directories, plus a <code>classes.txt</code> file.
          </p>
          
          <h4>Pascal VOC Format</h4>
          <p>
            Pascal VOC format is organized with separate directories for images, annotations, and optional segmentation masks. It's compatible with many object detection frameworks.
          </p>
          
          <h4>Raw JSON Format</h4>
          <p>
            The raw JSON format provides the most complete data with all garment details, polygon points, and metadata in a single <code>dataset.json</code> file, plus the associated images.
          </p>
          
          <h4>CSV Format</h4>
          <p>
            CSV format is ideal for data analysis and exploration with pandas. It provides a tabular representation of the dataset with references to image files.
          </p>
        </div>
      </div>
    </div>
  );
};

// Add to routes in app.tsx
/*
<Route path="/export/ml" element={<MLExportDashboard />} />
*/