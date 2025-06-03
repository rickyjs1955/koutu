// Create a separate utility class for polygon service helpers
export class PolygonServiceUtils {
  /**
   * Calculate polygon perimeter
   */
  static calculatePolygonPerimeter(points: Array<{ x: number; y: number }>): number {
    if (points.length < 2) return 0;

    let perimeter = 0;
    for (let i = 0; i < points.length; i++) {
      const current = points[i];
      const next = points[(i + 1) % points.length];
      
      const dx = next.x - current.x;
      const dy = next.y - current.y;
      perimeter += Math.sqrt(dx * dx + dy * dy);
    }

    return perimeter;
  }

  /**
   * Douglas-Peucker polygon simplification algorithm
   */
  static douglasPeucker(points: Array<{ x: number; y: number }>, tolerance: number): Array<{ x: number; y: number }> {
    if (points.length <= 2) {
        return points;
    }

    // Find the point with the maximum distance from the line segment
    let maxDistance = 0;
    let maxIndex = 0;
    const start = points[0];
    const end = points[points.length - 1];

    for (let i = 1; i < points.length - 1; i++) {
        const distance = this.perpendicularDistance(points[i], start, end);
        if (distance > maxDistance) {
            maxDistance = distance;
            maxIndex = i;
        }
    }

    // If the maximum distance is greater than tolerance, recursively simplify
    if (maxDistance > tolerance) {
        const leftSide = this.douglasPeucker(points.slice(0, maxIndex + 1), tolerance);
        const rightSide = this.douglasPeucker(points.slice(maxIndex), tolerance);
        
        // Combine results (remove duplicate point at the join)
        return leftSide.slice(0, -1).concat(rightSide);
    } else {
        // If no point is further than tolerance, return just the endpoints
        return [start, end];
    }
  }

  static perpendicularDistance(
      point: { x: number; y: number },
      lineStart: { x: number; y: number },
      lineEnd: { x: number; y: number }
  ): number {
      const dx = lineEnd.x - lineStart.x;
      const dy = lineEnd.y - lineStart.y;
      
      if (dx === 0 && dy === 0) {
          // Line segment is actually a point
          return Math.sqrt(
              Math.pow(point.x - lineStart.x, 2) + Math.pow(point.y - lineStart.y, 2)
          );
      }
      
      const t = ((point.x - lineStart.x) * dx + (point.y - lineStart.y) * dy) / (dx * dx + dy * dy);
      
      let closestPoint;
      if (t < 0) {
          closestPoint = lineStart;
      } else if (t > 1) {
          closestPoint = lineEnd;
      } else {
          closestPoint = {
              x: lineStart.x + t * dx,
              y: lineStart.y + t * dy
          };
      }
      
      return Math.sqrt(
          Math.pow(point.x - closestPoint.x, 2) + Math.pow(point.y - closestPoint.y, 2)
      );
  }

  /**
   * Calculate distance from point to line
   */
  static pointToLineDistance(
    point: { x: number; y: number },
    lineStart: { x: number; y: number },
    lineEnd: { x: number; y: number }
  ): number {
    const A = point.x - lineStart.x;
    const B = point.y - lineStart.y;
    const C = lineEnd.x - lineStart.x;
    const D = lineEnd.y - lineStart.y;

    const dot = A * C + B * D;
    const lenSq = C * C + D * D;
    
    if (lenSq === 0) {
      // Line start and end are the same point
      return Math.sqrt(A * A + B * B);
    }

    const param = dot / lenSq;
    
    let xx: number, yy: number;
    
    if (param < 0) {
      xx = lineStart.x;
      yy = lineStart.y;
    } else if (param > 1) {
      xx = lineEnd.x;
      yy = lineEnd.y;
    } else {
      xx = lineStart.x + param * C;
      yy = lineStart.y + param * D;
    }

    const dx = point.x - xx;
    const dy = point.y - yy;
    
    return Math.sqrt(dx * dx + dy * dy);
  }

  /**
   * Save polygon data for AI/ML operations
   */
  static async savePolygonDataForML(polygon: any, image: any, storageService: any): Promise<void> {
    try {
      const mlData = {
        polygon: {
          id: polygon.id,
          points: polygon.points,
          label: polygon.label,
          metadata: polygon.metadata,
          area: this.calculatePolygonArea(polygon.points),
          perimeter: this.calculatePolygonPerimeter(polygon.points),
          created_at: polygon.created_at
        },
        image: {
          id: image.id,
          file_path: image.file_path,
          width: image.original_metadata?.width ?? null,
          height: image.original_metadata?.height ?? null,
          format: image.original_metadata?.format ?? null
        },
        export_metadata: {
          exported_at: new Date().toISOString(),
          format_version: '1.0'
        }
      };

      const jsonData = JSON.stringify(mlData, null, 2);
      const buffer = Buffer.from(jsonData, 'utf-8');
      
      const filePath = `data/polygons/${polygon.id}.json`;
      await storageService.saveFile(buffer, filePath);
    } catch (error) {
      console.error('Error saving polygon data for ML:', error);
      // Don't throw - this is a supplementary operation
    }
  }

  /**
   * Calculate polygon area using shoelace formula
   */
  static calculatePolygonArea(points: Array<{ x: number; y: number }>): number {
    if (points.length < 3) return 0;

    let area = 0;
    for (let i = 0; i < points.length; i++) {
      const j = (i + 1) % points.length;
      area += points[i].x * points[j].y;
      area -= points[j].x * points[i].y;
    }

    return Math.abs(area / 2);
  }
}