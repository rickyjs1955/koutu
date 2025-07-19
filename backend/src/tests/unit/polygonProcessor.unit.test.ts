import { polygonProcessor } from '../../utils/polygonProcessor';

describe('PolygonProcessor', () => {
  describe('validatePolygon', () => {
    it('should validate a valid polygon', () => {
      const points = [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
        { x: 100, y: 100 },
        { x: 0, y: 100 }
      ];

      const result = polygonProcessor.validatePolygon(points);
      expect(result.valid).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should reject polygon with less than 3 points', () => {
      const points = [
        { x: 0, y: 0 },
        { x: 100, y: 0 }
      ];

      const result = polygonProcessor.validatePolygon(points);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Polygon must have at least 3 points');
    });

    it('should reject polygon with too many points', () => {
      const points = Array.from({ length: 1001 }, (_, i) => ({ x: i, y: i }));

      const result = polygonProcessor.validatePolygon(points);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Polygon has too many points (max 1000)');
    });

    it('should reject polygon with duplicate consecutive points', () => {
      const points = [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
        { x: 100, y: 0 }, // duplicate
        { x: 100, y: 100 },
        { x: 0, y: 100 }
      ];

      const result = polygonProcessor.validatePolygon(points);
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Polygon contains duplicate consecutive points');
    });
  });

  describe('initialize', () => {
    it('should initialize successfully', async () => {
      await expect(polygonProcessor.initialize()).resolves.not.toThrow();
    });
  });
});