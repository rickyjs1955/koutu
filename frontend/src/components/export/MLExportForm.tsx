// /frontend/src/components/export/MLExportForm.tsx
import React, { useState } from 'react';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { mlExportOptionsSchema, ExportFormat } from '@koutu/shared/schemas/export';
import { useExportML } from '../../hooks/useExportML';
import { useGarments } from '../../hooks/useGarments';

type MLExportFormProps = {
  onExportStarted?: () => void;
};

// Convert zod schema to react-hook-form type
type MLExportFormData = z.infer<typeof mlExportOptionsSchema>;

export const MLExportForm: React.FC<MLExportFormProps> = ({ onExportStarted }) => {
  const { createExportJob, isCreatingJob, createJobError, stats } = useExportML();

  // Define the expected type for the data from useGarments.
  // Using 'any' for garment items as the specific type isn't crucial for this fix
  // and avoids defining a potentially complex Garment type here.
  type ExpectedGarmentsData = {
    garments: any[];
    categories: string[];
  };

  const { data: rawGarmentsData } = useGarments();
  // Assert the type of rawGarmentsData to what the component expects.
  const garmentsData = rawGarmentsData as ExpectedGarmentsData | undefined;

  const garments = garmentsData?.garments;
  const categories = garmentsData?.categories;
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Setup form with Zod validation
  const { control, handleSubmit, watch, formState: { errors }, reset } = useForm<MLExportFormData>({
    resolver: zodResolver(mlExportOptionsSchema),
    defaultValues: {
      format: 'coco',
      includeImages: true,
      includeRawPolygons: true,
      includeMasks: false,
      imageFormat: 'jpg',
      compressionQuality: 90
    }
  });

  // Currently selected format
  const selectedFormat = watch('format');

  // Handle form submission
  const onSubmit = (data: MLExportFormData) => {
    createExportJob(data);
    if (onExportStarted) {
      onExportStarted();
    }
    reset();
  };

  // Format descriptions for tooltip
  const formatDescriptions: Record<ExportFormat, string> = {
    coco: 'COCO (Common Objects in Context) format used by many ML frameworks like PyTorch, TensorFlow, and MMDetection.',
    yolo: 'YOLO format for object detection. Used by YOLO, Darknet and related frameworks.',
    pascal_voc: 'Pascal VOC format widely used for object detection and segmentation tasks.',
    raw_json: 'Raw JSON format with all data including polygon points. Most flexible but requires custom parsing.',
    csv: 'Simple CSV format for tabular data analysis and import into spreadsheets or pandas.'
  };

  return (
    <div className="p-6 bg-white rounded-lg shadow-md">
      <h2 className="text-2xl font-bold mb-4">Export Data for ML Training</h2>
      
      {/* Stats summary if available */}
      {stats && (
        <div className="mb-6 p-4 bg-blue-50 rounded-md">
          <h3 className="font-semibold mb-2">Your Dataset:</h3>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <span className="font-medium">Images:</span> {stats.totalImages}
            </div>
            <div>
              <span className="font-medium">Garments:</span> {stats.totalGarments}
            </div>
            <div>
              <span className="font-medium">Points/Polygon:</span> {stats.averagePolygonPoints}
            </div>
          </div>
          <div className="mt-2 text-sm">
            <span className="font-medium">Categories:</span> {Object.entries(stats.categoryCounts)
              .map(([cat, count]) => `${cat} (${count})`)
              .join(', ')}
          </div>
        </div>
      )}
      
      {createJobError && (
        <div className="mb-4 p-3 bg-red-100 text-red-800 rounded-md">
          Error: {createJobError.message}
        </div>
      )}
      
      <form onSubmit={handleSubmit(onSubmit)}>
        {/* Export Format */}
        <div className="mb-4">
          <label className="block text-gray-700 mb-2">Export Format</label>
          <Controller
            name="format"
            control={control}
            render={({ field }) => (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {(Object.keys(formatDescriptions) as ExportFormat[]).map((format) => (
                  <div
                    key={format}
                    className={`
                      p-3 rounded-md border cursor-pointer
                      ${field.value === format ? 'border-blue-500 bg-blue-50' : 'border-gray-300'}
                    `}
                    onClick={() => field.onChange(format)}
                  >
                    <div className="font-medium">{format.toUpperCase()}</div>
                    <div className="text-xs text-gray-600 mt-1">{formatDescriptions[format]}</div>
                  </div>
                ))}
              </div>
            )}
          />
          {errors.format && <span className="text-red-500 text-sm">{errors.format.message}</span>}
        </div>
        
        {/* Basic Options */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          {/* Include Images */}
          <div>
            <Controller
              name="includeImages"
              control={control}
              render={({ field }) => (
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={field.value}
                    onChange={(e) => field.onChange(e.target.checked)}
                    className="h-4 w-4 text-blue-600"
                  />
                  <span>Include Images</span>
                </label>
              )}
            />
          </div>
          
          {/* Include Raw Polygons */}
          <div>
            <Controller
              name="includeRawPolygons"
              control={control}
              render={({ field }) => (
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={field.value}
                    onChange={(e) => field.onChange(e.target.checked)}
                    className="h-4 w-4 text-blue-600"
                  />
                  <span>Include Raw Polygon Points</span>
                </label>
              )}
            />
          </div>
          
          {/* Include Masks */}
          <div>
            <Controller
              name="includeMasks"
              control={control}
              render={({ field }) => (
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={field.value}
                    onChange={(e) => field.onChange(e.target.checked)}
                    className="h-4 w-4 text-blue-600"
                  />
                  <span>Generate Binary Masks</span>
                </label>
              )}
            />
          </div>
          
          {/* Image Format */}
          <div>
            <Controller
              name="imageFormat"
              control={control}
              render={({ field }) => (
                <div className="flex items-center space-x-4">
                  <span>Image Format:</span>
                  <label className="inline-flex items-center space-x-1 cursor-pointer">
                    <input
                      type="radio"
                      value="jpg"
                      checked={field.value === 'jpg'}
                      onChange={() => field.onChange('jpg')}
                      className="h-4 w-4 text-blue-600"
                    />
                    <span>JPG</span>
                  </label>
                  <label className="inline-flex items-center space-x-1 cursor-pointer">
                    <input
                      type="radio"
                      value="png"
                      checked={field.value === 'png'}
                      onChange={() => field.onChange('png')}
                      className="h-4 w-4 text-blue-600"
                    />
                    <span>PNG</span>
                  </label>
                </div>
              )}
            />
          </div>
        </div>
        
        {/* Toggle Advanced Options */}
        <div className="mb-4">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="text-blue-600 text-sm font-medium flex items-center"
          >
            {showAdvanced ? 'Hide Advanced Options' : 'Show Advanced Options'}
            <svg 
              xmlns="http://www.w3.org/2000/svg" 
              className={`h-4 w-4 ml-1 transition-transform ${showAdvanced ? 'rotate-180' : ''}`} 
              fill="none" 
              viewBox="0 0 24 24" 
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>
        
        {/* Advanced Options */}
        {showAdvanced && (
          <div className="mb-6 border p-4 rounded-md bg-gray-50">
            <h3 className="font-medium mb-3">Advanced Options</h3>
            
            {/* Compression Quality */}
            <div className="mb-4">
              <label className="block text-gray-700 mb-1">
                Compression Quality ({watch('compressionQuality')}%)
              </label>
              <Controller
                name="compressionQuality"
                control={control}
                render={({ field }) => (
                  <input
                    type="range"
                    min="10"
                    max="100"
                    step="5"
                    className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
                    {...field}
                    onChange={(e) => field.onChange(parseInt(e.target.value))}
                  />
                )}
              />
              {errors.compressionQuality && (
                <span className="text-red-500 text-sm">{errors.compressionQuality.message}</span>
              )}
            </div>
            
            {/* Category Filter */}
            {categories && categories.length > 0 && (
              <div className="mb-4">
                <label className="block text-gray-700 mb-1">Filter by Categories</label>
                <Controller
                  name="categoryFilter"
                  control={control}
                  render={({ field }) => (
                    <div className="flex flex-wrap gap-2">
                      {categories.map((category) => (
                        <label key={category} className="inline-flex items-center px-3 py-1 rounded-full bg-white border cursor-pointer">
                          <input
                            type="checkbox"
                            className="mr-2"
                            value={category}
                            checked={field.value?.includes(category) || false}
                            onChange={(e) => {
                              const currentValue = field.value || [];
                              if (e.target.checked) {
                                field.onChange([...currentValue, category]);
                              } else {
                                field.onChange(currentValue.filter(c => c !== category));
                              }
                            }}
                          />
                          {category}
                        </label>
                      ))}
                    </div>
                  )}
                />
              </div>
            )}
            
            {/* Date Range Filter - Implementation left as an exercise */}
          </div>
        )}
        
        {/* Form Actions */}
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={isCreatingJob}
            className={`
              px-4 py-2 rounded-md text-white font-medium
              ${isCreatingJob ? 'bg-blue-300' : 'bg-blue-600 hover:bg-blue-700'}
            `}
          >
            {isCreatingJob ? 'Creating Export...' : 'Start Export'}
          </button>
        </div>
      </form>
    </div>
  );
};