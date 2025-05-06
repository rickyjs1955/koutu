// /frontend/src/components/polygon/PolygonDrawer.tsx
import React, { useState, useEffect, useRef } from 'react';
import { Stage, Layer, Image as KonvaImage, Line, Circle } from 'react-konva';
import { Point } from '../../../../shared/src/schemas/polygon';
import { useCreatePolygon } from '../../hooks/usePolygons';

interface PolygonDrawerProps {
  imageUrl: string;
  imageId: string;
  onComplete?: (polygonId: string) => void;
  maxWidth?: number;
  maxHeight?: number;
}

const PolygonDrawer: React.FC<PolygonDrawerProps> = ({
  imageUrl,
  imageId,
  onComplete,
  maxWidth = 800,
  maxHeight = 600
}) => {
  const [image, setImage] = useState<HTMLImageElement | null>(null);
  const [points, setPoints] = useState<Point[]>([]);
  const [stageSize, setStageSize] = useState({ width: 0, height: 0 });
  const [isDrawing, setIsDrawing] = useState(false);
  const stageRef = useRef<any>(null);
  const createPolygon = useCreatePolygon();

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

  // Start drawing
  const handleStageClick = (e: any) => {
    if (!isDrawing) {
      setIsDrawing(true);
    }
    
    const stage = e.target.getStage();
    const pointerPosition = stage.getPointerPosition();
    
    const newPoint = {
      x: pointerPosition.x,
      y: pointerPosition.y
    };
    
    setPoints([...points, newPoint]);
  };

  // Complete polygon by connecting back to the first point
  const handleClosePolygon = () => {
    if (points.length < 3) {
      alert('Please add at least 3 points to create a polygon');
      return;
    }
    
    // Create the polygon
    createPolygon.mutate({
      original_image_id: imageId,
      points,
      label: 'garment', // Default label, can be customized in a real implementation
      metadata: {
        imageWidth: image?.width,
        imageHeight: image?.height,
        stageWidth: stageSize.width,
        stageHeight: stageSize.height,
        scaleX: image ? stageSize.width / image.width : 1,
        scaleY: image ? stageSize.height / image.height : 1
      }
    }, {
      onSuccess: (newPolygon) => {
        // Reset the drawing state
        setPoints([]);
        setIsDrawing(false);
        
        // Call the onComplete callback if provided
        if (onComplete && newPolygon.id) {
          onComplete(newPolygon.id);
        }
      },
      onError: (error) => {
        console.error('Error creating polygon:', error);
        alert('Failed to save polygon. Please try again.');
      }
    });
  };

  // Reset polygon drawing
  const handleResetPolygon = () => {
    setPoints([]);
    setIsDrawing(false);
  };

  // Generate flat array of points for Konva Line
  const flattenedPoints = points.flatMap(point => [point.x, point.y]);

  if (!image || stageSize.width === 0) {
    return <div className="loading">Loading image...</div>;
  }

  return (
    <div className="polygon-drawer">
      <div className="stage-container">
        <Stage
          ref={stageRef}
          width={stageSize.width}
          height={stageSize.height}
          onClick={handleStageClick}
        >
          <Layer>
            {/* Background Image */}
            <KonvaImage
              image={image}
              width={stageSize.width}
              height={stageSize.height}
            />
            
            {/* Polygon Line */}
            {points.length > 0 && (
              <Line
                points={flattenedPoints}
                stroke="#FF0000"
                strokeWidth={2}
                closed={false}
                fill="rgba(255, 0, 0, 0.2)"
              />
            )}
            
            {/* Points */}
            {points.map((point, index) => (
              <Circle
                key={index}
                x={point.x}
                y={point.y}
                radius={5}
                fill="#FF0000"
              />
            ))}
          </Layer>
        </Stage>
      </div>
      
      <div className="controls">
        <button
          onClick={handleClosePolygon}
          disabled={points.length < 3 || createPolygon.isLoading}
          className="btn btn-primary"
        >
          {createPolygon.isLoading ? 'Saving...' : 'Complete Polygon'}
        </button>
        
        <button
          onClick={handleResetPolygon}
          disabled={points.length === 0 || createPolygon.isLoading}
          className="btn btn-secondary"
        >
          Reset
        </button>
        
        <div className="instructions">
          <p>Click on the image to add points to the polygon.</p>
          <p>Add at least 3 points, then click "Complete Polygon" to save.</p>
        </div>
      </div>
    </div>
  );
};

export default PolygonDrawer;