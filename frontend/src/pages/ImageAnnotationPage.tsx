// /frontend/src/pages/ImageAnnotationPage.tsx
import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useImage } from '../hooks/useImages';
import { useImagePolygons } from '../hooks/usePolygons';
import PolygonDrawer from '../components/polygon/PolygonDrawer';
import PolygonViewer from '../components/polygon/PolygonViewer';
import PolygonList from '../components/polygon/PolygonList';
import { Polygon } from '../../../shared/src/schemas/polygon';
import { useImageUrl } from '../hooks/useImages';

const ImageAnnotationPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [mode, setMode] = useState<'view' | 'draw'>('view');
  const [selectedPolygonId, setSelectedPolygonId] = useState<string | undefined>();
  
  // Fetch image data
  const { data: image, isLoading: isLoadingImage, error: imageError } = useImage(id || '');
  
  // Fetch image polygons
  const { data: polygons, isLoading: isLoadingPolygons } = useImagePolygons(id || '');
  
  // Get image URL
  const imageUrl = useImageUrl(image?.file_path);
  
  // Handle mode toggle
  const toggleMode = () => {
    setMode(mode === 'view' ? 'draw' : 'view');
    setSelectedPolygonId(undefined);
  };
  
  // Handle polygon selection
  const handleSelectPolygon = (polygon: Polygon) => {
    setSelectedPolygonId(polygon.id);
    setMode('view');
  };
  
  // Handle polygon creation completion
  const handlePolygonComplete = (polygonId: string) => {
    setSelectedPolygonId(polygonId);
    setMode('view');
  };
  
  // Handle back button
  const handleBack = () => {
    navigate('/images');
  };
  
  if (isLoadingImage) {
    return (
      <div className="loading-container">
        <div className="spinner-border" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
        <p>Loading image...</p>
      </div>
    );
  }
  
  if (imageError || !image) {
    return (
      <div className="error-container">
        <div className="alert alert-danger">
          <h4>Error loading image</h4>
          <p>The image could not be loaded. Please try again later.</p>
          <button className="btn btn-primary" onClick={handleBack}>
            Back to Images
          </button>
        </div>
      </div>
    );
  }
  
  return (
    <div className="container mt-4 image-annotation-page">
      <div className="row mb-3">
        <div className="col">
          <h2>Image Annotation</h2>
          <div className="d-flex align-items-center">
            <button className="btn btn-outline-secondary me-2" onClick={handleBack}>
              <i className="bi bi-arrow-left"></i> Back
            </button>
            <span className="image-info ms-2">
              {image.original_metadata?.filename || 'Image'}
            </span>
          </div>
        </div>
      </div>
      
      <div className="row">
        <div className="col-md-8">
          <div className="card">
            <div className="card-header d-flex justify-content-between align-items-center">
              <h5 className="mb-0">
                {mode === 'view' ? 'View Mode' : 'Drawing Mode'}
              </h5>
              <button
                className={`btn ${mode === 'view' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={toggleMode}
              >
                {mode === 'view' ? 'Switch to Draw Mode' : 'Switch to View Mode'}
              </button>
            </div>
            <div className="card-body">
              {mode === 'draw' ? (
                <PolygonDrawer
                  imageUrl={imageUrl}
                  imageId={id || ''}
                  onComplete={handlePolygonComplete}
                />
              ) : (
                <PolygonViewer
                  imageUrl={imageUrl}
                  polygons={polygons || []}
                  selectedPolygonId={selectedPolygonId}
                  onPolygonClick={setSelectedPolygonId}
                />
              )}
            </div>
          </div>
        </div>
        
        <div className="col-md-4">
          <div className="card">
            <div className="card-header">
              <h5 className="mb-0">Annotations</h5>
            </div>
            <div className="card-body">
              {isLoadingPolygons ? (
                <div className="loading">Loading annotations...</div>
              ) : (
                <PolygonList
                  imageId={id || ''}
                  onSelectPolygon={handleSelectPolygon}
                  selectedPolygonId={selectedPolygonId}
                />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ImageAnnotationPage;