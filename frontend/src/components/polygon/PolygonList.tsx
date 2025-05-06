// /frontend/src/components/polygon/PolygonList.tsx
import React from 'react';
import { useImagePolygons, useDeletePolygon } from '../../hooks/usePolygons';
import { Polygon } from '../../../../shared/src/schemas/polygon';

interface PolygonListProps {
  imageId: string;
  onSelectPolygon?: (polygon: Polygon) => void;
  selectedPolygonId?: string;
}

const PolygonList: React.FC<PolygonListProps> = ({
  imageId,
  onSelectPolygon,
  selectedPolygonId
}) => {
  const { data: polygons, isLoading, error } = useImagePolygons(imageId);
  const deletePolygon = useDeletePolygon();

  if (isLoading) {
    return <div className="loading">Loading polygons...</div>;
  }

  if (error) {
    return <div className="error">Error loading polygons</div>;
  }

  if (!polygons || polygons.length === 0) {
    return (
      <div className="no-polygons">
        <p>No polygons found for this image.</p>
        <p>Use the drawing tool to create polygons.</p>
      </div>
    );
  }

  const handleDelete = (id: string) => {
    if (window.confirm('Are you sure you want to delete this polygon?')) {
      deletePolygon.mutate(id);
    }
  };

  return (
    <div className="polygon-list">
      <h3>Image Polygons</h3>
      <ul className="list-group">
        {polygons.map((polygon) => (
          <li
            key={polygon.id}
            className={`list-group-item d-flex justify-content-between align-items-center ${
              selectedPolygonId === polygon.id ? 'active' : ''
            }`}
            onClick={() => onSelectPolygon && onSelectPolygon(polygon)}
          >
            <div className="polygon-info">
              <span className="polygon-label">
                {polygon.label || 'Unlabeled'}
              </span>
              <small className="text-muted">
                {polygon.points.length} points
              </small>
            </div>
            <div className="polygon-actions">
              <button
                className="btn btn-sm btn-danger"
                onClick={(e) => {
                  e.stopPropagation();
                  handleDelete(polygon.id as string);
                }}
                disabled={deletePolygon.isLoading}
              >
                {deletePolygon.isLoading &&
                deletePolygon.variables === polygon.id
                  ? 'Deleting...'
                  : 'Delete'}
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default PolygonList;