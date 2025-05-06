// /frontend/src/components/polygon/PolygonViewer.tsx
import React, { useState, useEffect } from 'react';
import { Stage, Layer, Image as KonvaImage, Line } from 'react-konva';
import { Polygon } from '../../../../shared/src/schemas/polygon';

interface PolygonViewerProps {
  imageUrl: string;
  polygons: Polygon[];
  selectedPolygonId?: string;
  maxWidth?: number;
  maxHeight?: number;
  onPolygonClick?: (polygonId: string) => void;
}

const PolygonViewer: React.FC<PolygonViewerProps> = ({
  imageUrl,
  polygons,
  selectedPolygonId,
  maxWidth = 800,
  maxHeight = 600,
  onPolygonClick
}) => {
  const [image, setImage] = useState<HTMLImageElement | null>(null);
  const [stageSize, setStageSize] = useState({ width: 0, height: 0 });

  // Load the image
  useEffect(() => {
    const img = new window.Image();
    img.crossOrigin = 'Anonymous';
    img.src = imageUrl;
    img.onload = () => {
      setImage(img);
      
      // Calculate stage size based on image dimensions and max constraints
      const scale = Math.min(
        maxWidth / img.width,
        maxHeight / img.height,
        1 // Don't scale up images smaller than maxWidth/maxHeight
      );
      
      setStageSize({
        width: img.width * scale,
        height: img.height * scale
      });
    };
  }, [imageUrl, maxWidth, maxHeight]);

  if (!image || stageSize.width === 0) {
    return <div className="loading">Loading image...</div>;
  }

  // Generate random color for a polygon based on its ID
  const getPolygonColor = (id: string, isSelected: boolean): string => {
    if (isSelected) {
      return '#FF0000'; // Red for selected polygon
    }
    
    // Generate a stable color based on the polygon ID
    let hash = 0;
    for (let i = 0; i < id.length; i++) {
      hash = id.charCodeAt(i) + ((hash << 5) - hash);
    }
    
    const c = (hash & 0x00FFFFFF)
      .toString(16)
      .toUpperCase()
      .padStart(6, '0');
    
    return `#${c}`;
  };

  return (
    <div className="polygon-viewer">
      <Stage
        width={stageSize.width}
        height={stageSize.height}
      >
        <Layer>
          {/* Background Image */}
          <KonvaImage
            image={image}
            width={stageSize.width}
            height={stageSize.height}
          />
          
          {/* Polygons */}
          {polygons.map((polygon) => {
            const isSelected = selectedPolygonId === polygon.id;
            const color = getPolygonColor(polygon.id || '', isSelected);
            
            // Generate flat array of points for Konva Line
            const flattenedPoints = polygon.points.flatMap(point => [point.x, point.y]);
            
            return (
              <Line
                key={polygon.id}
                points={flattenedPoints}
                stroke={color}
                strokeWidth={isSelected ? 3 : 2}
                closed={true}
                fill={`${color}33`} // Add transparency to the fill color
                onClick={() => onPolygonClick && polygon.id && onPolygonClick(polygon.id)}
                onTap={() => onPolygonClick && polygon.id && onPolygonClick(polygon.id)}
              />
            );
          })}
        </Layer>
      </Stage>
    </div>
  );
};

export default PolygonViewer;