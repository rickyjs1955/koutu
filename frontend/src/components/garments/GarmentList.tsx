// /frontend/src/components/garments/GarmentList.tsx
import React from 'react';
import { useGarments, useDeleteGarment } from '../../hooks/useGarments';
import { Link } from 'react-router-dom';

const GarmentList: React.FC = () => {
  const { data: garments, isLoading, error } = useGarments();
  const deleteGarment = useDeleteGarment();
  
  if (isLoading) {
    return <div className="text-center">Loading garments...</div>;
  }
  
  if (error) {
    return <div className="text-red-500">Error loading garments</div>;
  }
  
  if (!garments || garments.length === 0) {
    return (
      <div className="text-center">
        <p>No garments found. Get started by adding your first garment!</p>
        <Link 
          to="/images" 
          className="mt-4 inline-block px-4 py-2 bg-indigo-600 text-white rounded-md"
        >
          Upload an Image
        </Link>
      </div>
    );
  }
  
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      {garments.map((garment) => (
        <div 
          key={garment.id} 
          className="border rounded-lg overflow-hidden shadow-md bg-white"
        >
          <div className="relative h-64 bg-gray-100">
            <img 
              src={`/api/v1/files/${garment.file_path}`} 
              alt={`${garment.metadata.type} - ${garment.metadata.color}`}
              className="object-contain w-full h-full"
            />
          </div>
          
          <div className="p-4">
            <div className="flex justify-between items-start">
              <div>
                <h3 className="text-lg font-semibold capitalize">
                  {garment.metadata.color} {garment.metadata.type}
                </h3>
                <p className="text-sm text-gray-600">
                  {garment.metadata.pattern && (
                    <span className="capitalize">{garment.metadata.pattern} • </span>
                  )}
                  <span className="capitalize">{garment.metadata.season}</span>
                  {garment.metadata.brand && (
                    <span> • {garment.metadata.brand}</span>
                  )}
                </p>
              </div>
              
              <div className="flex space-x-2">
                <Link 
                  to={`/garments/${garment.id}`}
                  className="text-blue-500 hover:text-blue-700"
                >
                  Edit
                </Link>
                <button
                  onClick={() => {
                    if (window.confirm('Are you sure you want to delete this garment?')) {
                      deleteGarment.mutate(garment.id as string);
                    }
                  }}
                  className="text-red-500 hover:text-red-700"
                  disabled={deleteGarment.isLoading} // Changed from isPending to isLoading
                >
                  Delete
                </button>
              </div>
            </div>
            
            {garment.metadata.tags && garment.metadata.tags.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-1">
                {garment.metadata.tags.map((tag, index) => (
                  <span 
                    key={index}
                    className="px-2 py-1 bg-gray-100 text-gray-800 text-xs rounded-full"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
};

export default GarmentList;