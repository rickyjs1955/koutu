import { PolygonServiceUtils } from "../../utils/PolygonServiceUtils";

describe('PolygonServiceUtils', () => {
  describe('calculatePolygonPerimeter', () => {
    it('should return 0 for empty array', () => {
      const result = PolygonServiceUtils.calculatePolygonPerimeter([]);
      expect(result).toBe(0);
    });

    it('should return 0 for single point', () => {
      const points = [{ x: 1, y: 1 }];
      const result = PolygonServiceUtils.calculatePolygonPerimeter(points);
      expect(result).toBe(0);
    });

    it('should calculate perimeter for a square', () => {
      const square = [
        { x: 0, y: 0 },
        { x: 4, y: 0 },
        { x: 4, y: 4 },
        { x: 0, y: 4 }
      ];
      const result = PolygonServiceUtils.calculatePolygonPerimeter(square);
      expect(result).toBe(16);
    });

    it('should calculate perimeter for a triangle', () => {
      const triangle = [
        { x: 0, y: 0 },
        { x: 3, y: 0 },
        { x: 0, y: 4 }
      ];
      const result = PolygonServiceUtils.calculatePolygonPerimeter(triangle);
      expect(result).toBe(12); // 3 + 4 + 5 (3-4-5 triangle)
    });

    it('should handle decimal coordinates', () => {
      const points = [
        { x: 0.5, y: 0.5 },
        { x: 1.5, y: 0.5 }
      ];
      const result = PolygonServiceUtils.calculatePolygonPerimeter(points);
      expect(result).toBeCloseTo(2, 5); // Distance is 1, but it's a closed loop so 2
    });
  });

  describe('calculatePolygonArea', () => {
    it('should return 0 for less than 3 points', () => {
      expect(PolygonServiceUtils.calculatePolygonArea([])).toBe(0);
      expect(PolygonServiceUtils.calculatePolygonArea([{ x: 1, y: 1 }])).toBe(0);
      expect(PolygonServiceUtils.calculatePolygonArea([{ x: 1, y: 1 }, { x: 2, y: 2 }])).toBe(0);
    });

    it('should calculate area for a square', () => {
      const square = [
        { x: 0, y: 0 },
        { x: 4, y: 0 },
        { x: 4, y: 4 },
        { x: 0, y: 4 }
      ];
      const result = PolygonServiceUtils.calculatePolygonArea(square);
      expect(result).toBe(16);
    });

    it('should calculate area for a triangle', () => {
      const triangle = [
        { x: 0, y: 0 },
        { x: 4, y: 0 },
        { x: 2, y: 3 }
      ];
      const result = PolygonServiceUtils.calculatePolygonArea(triangle);
      expect(result).toBe(6); // Base 4, height 3, area = 0.5 * 4 * 3 = 6
    });

    it('should handle clockwise and counterclockwise orientations', () => {
      const clockwise = [
        { x: 0, y: 0 },
        { x: 0, y: 4 },
        { x: 4, y: 4 },
        { x: 4, y: 0 }
      ];
      const counterclockwise = [
        { x: 0, y: 0 },
        { x: 4, y: 0 },
        { x: 4, y: 4 },
        { x: 0, y: 4 }
      ];
      
      const clockwiseArea = PolygonServiceUtils.calculatePolygonArea(clockwise);
      const counterclockwiseArea = PolygonServiceUtils.calculatePolygonArea(counterclockwise);
      
      expect(clockwiseArea).toBe(16);
      expect(counterclockwiseArea).toBe(16);
      expect(clockwiseArea).toBe(counterclockwiseArea);
    });
  });

  describe('pointToLineDistance', () => {
    it('should calculate distance from point to horizontal line', () => {
      const point = { x: 2, y: 3 };
      const lineStart = { x: 0, y: 1 };
      const lineEnd = { x: 4, y: 1 };
      
      const result = PolygonServiceUtils.pointToLineDistance(point, lineStart, lineEnd);
      expect(result).toBe(2); // Point is 2 units above the line
    });

    it('should calculate distance from point to vertical line', () => {
      const point = { x: 3, y: 2 };
      const lineStart = { x: 1, y: 0 };
      const lineEnd = { x: 1, y: 4 };
      
      const result = PolygonServiceUtils.pointToLineDistance(point, lineStart, lineEnd);
      expect(result).toBe(2); // Point is 2 units to the right of the line
    });

    it('should return 0 when point is on the line', () => {
      const point = { x: 2, y: 2 };
      const lineStart = { x: 0, y: 0 };
      const lineEnd = { x: 4, y: 4 };
      
      const result = PolygonServiceUtils.pointToLineDistance(point, lineStart, lineEnd);
      expect(result).toBeCloseTo(0, 5);
    });

    it('should handle case when line start and end are the same point', () => {
      const point = { x: 3, y: 4 };
      const lineStart = { x: 0, y: 0 };
      const lineEnd = { x: 0, y: 0 };
      
      const result = PolygonServiceUtils.pointToLineDistance(point, lineStart, lineEnd);
      expect(result).toBe(5); // Distance from (3,4) to (0,0)
    });

    it('should calculate distance to closest endpoint when projection is outside line segment', () => {
      const point = { x: -1, y: 0 };
      const lineStart = { x: 0, y: 0 };
      const lineEnd = { x: 2, y: 0 };
      
      const result = PolygonServiceUtils.pointToLineDistance(point, lineStart, lineEnd);
      expect(result).toBe(1); // Distance to closest endpoint (0,0)
    });
  });

  describe('douglasPeucker', () => {
    it('should return original points when there are 2 or fewer points', () => {
      const singlePoint = [{ x: 1, y: 1 }];
      const twoPoints = [{ x: 0, y: 0 }, { x: 1, y: 1 }];
      
      expect(PolygonServiceUtils.douglasPeucker(singlePoint, 1)).toEqual(singlePoint);
      expect(PolygonServiceUtils.douglasPeucker(twoPoints, 1)).toEqual(twoPoints);
    });

    it('should simplify a straight line to just endpoints', () => {
      const straightLine = [
        { x: 0, y: 0 },
        { x: 1, y: 1 },
        { x: 2, y: 2 },
        { x: 3, y: 3 }
      ];
      
      const result = PolygonServiceUtils.douglasPeucker(straightLine, 0.1);
      expect(result).toEqual([{ x: 0, y: 0 }, { x: 3, y: 3 }]);
    });

    it('should preserve points that deviate significantly from the line', () => {
      const zigzag = [
        { x: 0, y: 0 },
        { x: 1, y: 0 },
        { x: 1, y: 2 }, // Significant deviation
        { x: 2, y: 0 },
        { x: 3, y: 0 }
      ];
      
      const result = PolygonServiceUtils.douglasPeucker(zigzag, 0.5);
      expect(result.length).toBeGreaterThan(2);
      expect(result).toContainEqual({ x: 1, y: 2 }); // The peak should be preserved
    });

    it('should handle different tolerance levels', () => {
      const curve = [
        { x: 0, y: 0 },
        { x: 1, y: 1 },
        { x: 2, y: 1.1 },
        { x: 3, y: 1 },
        { x: 4, y: 0 }
      ];
      
      const strictResult = PolygonServiceUtils.douglasPeucker(curve, 0.05);
      const lenientResult = PolygonServiceUtils.douglasPeucker(curve, 1.0);
      
      expect(strictResult.length).toBeGreaterThanOrEqual(lenientResult.length);
    });

    it('should always preserve first and last points', () => {
      const points = [
        { x: 0, y: 0 },
        { x: 1, y: 1 },
        { x: 2, y: 1 },
        { x: 3, y: 0 }
      ];
      
      const result = PolygonServiceUtils.douglasPeucker(points, 2);
      expect(result[0]).toEqual({ x: 0, y: 0 });
      expect(result[result.length - 1]).toEqual({ x: 3, y: 0 });
    });
  });
});