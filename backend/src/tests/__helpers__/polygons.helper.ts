// tests/__helpers__/polygon.helper.ts
import { v4 as uuidv4 } from 'uuid';
import { 
  MockPolygon, 
  MockPolygonCreate, 
  createMockPolygon,
  createValidPolygonPoints,
  createInvalidPolygonPoints,
  createPolygonMetadataVariations
} from '../__mocks__/polygons.mock';
import { createMockImage } from '../__mocks__/images.mock';

// ==================== GEOMETRIC CALCULATION HELPERS ====================

/**
 * Calculate polygon area using shoelace formula
 */
export function calculatePolygonArea(points: Array<{ x: number; y: number }>): number {
  if (points.length < 3) return 0;

  let area = 0;
  for (let i = 0; i < points.length; i++) {
    const j = (i + 1) % points.length;
    area += points[i].x * points[j].y;
    area -= points[j].x * points[i].y;
  }

  return Math.abs(area / 2);
}

/**
 * Calculate polygon perimeter
 */
export function calculatePolygonPerimeter(points: Array<{ x: number; y: number }>): number {
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
 * Calculate polygon centroid
 */
export function calculatePolygonCentroid(points: Array<{ x: number; y: number }>): { x: number; y: number } {
  if (points.length === 0) return { x: 0, y: 0 };

  let centroidX = 0;
  let centroidY = 0;
  let signedArea = 0;

  for (let i = 0; i < points.length; i++) {
    const x0 = points[i].x;
    const y0 = points[i].y;
    const x1 = points[(i + 1) % points.length].x;
    const y1 = points[(i + 1) % points.length].y;
    
    const a = x0 * y1 - x1 * y0;
    signedArea += a;
    centroidX += (x0 + x1) * a;
    centroidY += (y0 + y1) * a;
  }

  signedArea *= 0.5;
  centroidX /= (6.0 * signedArea);
  centroidY /= (6.0 * signedArea);

  return { x: Math.round(centroidX), y: Math.round(centroidY) };
}

/**
 * Calculate polygon bounding box
 */
export function calculateBoundingBox(points: Array<{ x: number; y: number }>): {
  x: number;
  y: number;
  width: number;
  height: number;
} {
  if (points.length === 0) return { x: 0, y: 0, width: 0, height: 0 };

  let minX = points[0].x;
  let maxX = points[0].x;
  let minY = points[0].y;
  let maxY = points[0].y;

  for (const point of points) {
    minX = Math.min(minX, point.x);
    maxX = Math.max(maxX, point.x);
    minY = Math.min(minY, point.y);
    maxY = Math.max(maxY, point.y);
  }

  return {
    x: minX,
    y: minY,
    width: maxX - minX,
    height: maxY - minY
  };
}

// ==================== VALIDATION HELPERS ====================

/**
 * Check if a point is inside a polygon using ray casting algorithm
 */
export function pointInPolygon(
  point: { x: number; y: number }, 
  polygon: Array<{ x: number; y: number }>
): boolean {
  let inside = false;
  
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    if (
      (polygon[i].y > point.y) !== (polygon[j].y > point.y) &&
      point.x < (polygon[j].x - polygon[i].x) * (point.y - polygon[i].y) / (polygon[j].y - polygon[i].y) + polygon[i].x
    ) {
      inside = !inside;
    }
  }
  
  return inside;
}

/**
 * Check if two line segments intersect
 */
export function linesIntersect(
  p1: { x: number; y: number },
  p2: { x: number; y: number },
  p3: { x: number; y: number },
  p4: { x: number; y: number }
): boolean {
  const det = (p2.x - p1.x) * (p4.y - p3.y) - (p4.x - p3.x) * (p2.y - p1.y);
  
  if (det === 0) return false; // Lines are parallel
  
  const lambda = ((p4.y - p3.y) * (p4.x - p1.x) + (p3.x - p4.x) * (p4.y - p1.y)) / det;
  const gamma = ((p1.y - p2.y) * (p4.x - p1.x) + (p2.x - p1.x) * (p4.y - p1.y)) / det;
  
  return (0 < lambda && lambda < 1) && (0 < gamma && gamma < 1);
}

/**
 * Check if polygon has self-intersections
 */
export function hasSelfintersection(points: Array<{ x: number; y: number }>): boolean {
  if (points.length < 4) return false;

  for (let i = 0; i < points.length; i++) {
    const p1 = points[i];
    const p2 = points[(i + 1) % points.length];

    for (let j = i + 2; j < points.length; j++) {
      if (j === points.length - 1 && i === 0) continue; // Skip adjacent edges

      const p3 = points[j];
      const p4 = points[(j + 1) % points.length];

      if (linesIntersect(p1, p2, p3, p4)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check if polygon points are within image bounds
 */
export function validatePointsBounds(
  points: Array<{ x: number; y: number }>,
  imageWidth: number,
  imageHeight: number
): { valid: boolean; invalidPoints: Array<{ x: number; y: number }>; } {
  const invalidPoints = points.filter(point => 
    point.x < 0 || point.x > imageWidth ||
    point.y < 0 || point.y > imageHeight
  );

  return {
    valid: invalidPoints.length === 0,
    invalidPoints
  };
}

/**
 * Validate Instagram aspect ratio for polygon bounds
 */
export function validateInstagramAspectRatio(width: number, height: number): {
  isValid: boolean;
  ratio: number;
  type: 'too_tall' | 'too_wide' | 'valid';
} {
  const ratio = width / height;
  return {
    ratio,
    isValid: ratio >= 0.8 && ratio <= 1.91,
    type: ratio < 0.8 ? 'too_tall' : ratio > 1.91 ? 'too_wide' : 'valid'
  };
}

/**
 * Validate polygon for garment creation
 */
export function validateForGarment(points: Array<{ x: number; y: number }>): {
  isValid: boolean;
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check area
  const area = calculatePolygonArea(points);
  if (area < 500) {
    errors.push('Polygon too small for garment creation (minimum area: 500 pixels)');
  }

  // Check complexity
  if (points.length > 500) {
    errors.push('Polygon too complex for garment creation (maximum 500 points)');
  } else if (points.length > 100) {
    warnings.push('Polygon is complex and may slow down processing');
  }

  // Check self-intersections
  if (hasSelfintersection(points)) {
    errors.push('Self-intersecting polygons cannot be used for garment creation');
  }

  // Check aspect ratio for reasonable garment shape
  const bbox = calculateBoundingBox(points);
  if (bbox.width > 0 && bbox.height > 0) {
    const aspectRatio = bbox.width / bbox.height;
    if (aspectRatio > 5 || aspectRatio < 0.2) {
      warnings.push('Unusual aspect ratio for garment shape');
    }
  }

  return {
    isValid: errors.length === 0,
    errors,
    warnings
  };
}

// ==================== POLYGON GENERATION HELPERS ====================

/**
 * Create a polygon with specific area
 */
export function createPolygonWithArea(targetArea: number, centerX = 200, centerY = 200): Array<{ x: number; y: number }> {
  // Create a square with the target area
  const sideLength = Math.sqrt(targetArea);
  const halfSide = sideLength / 2;

  return [
    { x: centerX - halfSide, y: centerY - halfSide },
    { x: centerX + halfSide, y: centerY - halfSide },
    { x: centerX + halfSide, y: centerY + halfSide },
    { x: centerX - halfSide, y: centerY + halfSide }
  ];
}

/**
 * Create a polygon with specific number of points (regular polygon)
 */
export function createRegularPolygon(
  pointCount: number, 
  centerX = 200, 
  centerY = 200, 
  radius = 50
): Array<{ x: number; y: number }> {
  const points = [];
  for (let i = 0; i < pointCount; i++) {
    const angle = (2 * Math.PI * i) / pointCount;
    points.push({
      x: Math.round(centerX + radius * Math.cos(angle)),
      y: Math.round(centerY + radius * Math.sin(angle))
    });
  }
  return points;
}

/**
 * Create overlapping polygons for testing overlap detection
 */
export function createOverlappingPolygons(): {
  polygon1: Array<{ x: number; y: number }>;
  polygon2: Array<{ x: number; y: number }>;
  overlapType: 'partial' | 'complete' | 'touching' | 'none';
} {
  const polygon1 = createValidPolygonPoints.square(); // 100,100 to 200,200
  const polygon2 = [
    { x: 150, y: 150 },
    { x: 250, y: 150 },
    { x: 250, y: 250 },
    { x: 150, y: 250 }
  ]; // Partial overlap

  return {
    polygon1,
    polygon2,
    overlapType: 'partial'
  };
}

/**
 * Create self-intersecting polygon for testing
 */
export function createSelfIntersectingPolygon(): Array<{ x: number; y: number }> {
  return [
    { x: 100, y: 100 },
    { x: 200, y: 200 },
    { x: 100, y: 200 },
    { x: 200, y: 100 }
  ]; // Figure-8 shape
}

/**
 * Create polygon that violates specific validation rules
 */
export function createInvalidPolygon(violationType: 
  'insufficient_points' | 'too_many_points' | 'self_intersecting' | 
  'out_of_bounds' | 'zero_area' | 'negative_coords'
): Array<{ x: number; y: number }> {
  
  switch (violationType) {
    case 'insufficient_points':
      return createInvalidPolygonPoints.insufficientPoints();
    case 'too_many_points':
      return createInvalidPolygonPoints.tooManyPoints();
    case 'self_intersecting':
      return createSelfIntersectingPolygon();
    case 'out_of_bounds':
      return createInvalidPolygonPoints.outOfBounds();
    case 'zero_area':
      return createInvalidPolygonPoints.zeroArea();
    case 'negative_coords':
      return createInvalidPolygonPoints.negativeCoordinates();
    default:
      return createInvalidPolygonPoints.insufficientPoints();
  }
}

// ==================== TEST DATA FACTORIES ====================

/**
 * Create test polygons for a specific image
 */
export function createTestPolygonsForImage(
  imageId: string, 
  userId: string, 
  count: number = 3
): MockPolygon[] {
  return Array.from({ length: count }, (_, index) => createMockPolygon({
    user_id: userId,
    original_image_id: imageId,
    label: `test_polygon_${index + 1}`,
    points: createValidPolygonPoints.custom(150 + index * 20, 100 + index * 15, 'simple'),
    metadata: {
      ...createPolygonMetadataVariations.basic,
      sequence: index + 1,
      test_polygon: true
    }
  }));
}

/**
 * Create polygon test scenarios for different complexity levels
 */
export function createComplexityTestScenarios(): {
  simple: MockPolygon;
  medium: MockPolygon;
  complex: MockPolygon;
  extreme: MockPolygon;
} {
  const baseUserId = uuidv4();
  const baseImageId = uuidv4();

  return {
    simple: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createValidPolygonPoints.square(),
      label: 'simple_polygon',
      metadata: { complexity: 'simple', point_count: 4 }
    }),
    medium: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createValidPolygonPoints.pentagon(),
      label: 'medium_polygon',
      metadata: { complexity: 'medium', point_count: 12 }
    }),
    complex: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createValidPolygonPoints.complex(),
      label: 'complex_polygon',
      metadata: { complexity: 'complex', point_count: 50 }
    }),
    extreme: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createRegularPolygon(200, 400, 300, 100),
      label: 'extreme_polygon',
      metadata: { complexity: 'extreme', point_count: 200 }
    })
  };
}

/**
 * Create polygons with different geometric properties
 */
export function createGeometricTestPolygons(): {
  largeArea: MockPolygon;
  smallArea: MockPolygon;
  longPerimeter: MockPolygon;
  shortPerimeter: MockPolygon;
  squareShape: MockPolygon;
  elongatedShape: MockPolygon;
} {
  const baseUserId = uuidv4();
  const baseImageId = uuidv4();

  return {
    largeArea: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createPolygonWithArea(50000, 400, 300),
      label: 'large_area',
      metadata: { area: 50000, test_type: 'geometric' }
    }),
    smallArea: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createPolygonWithArea(500, 200, 200),
      label: 'small_area',
      metadata: { area: 500, test_type: 'geometric' }
    }),
    longPerimeter: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createValidPolygonPoints.circle(400, 300, 150, 50),
      label: 'long_perimeter',
      metadata: { shape: 'circle_approximation', test_type: 'geometric' }
    }),
    shortPerimeter: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createValidPolygonPoints.triangle(),
      label: 'short_perimeter',
      metadata: { shape: 'triangle', test_type: 'geometric' }
    }),
    squareShape: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: createValidPolygonPoints.square(),
      label: 'square_shape',
      metadata: { aspect_ratio: 1.0, test_type: 'geometric' }
    }),
    elongatedShape: createMockPolygon({
      user_id: baseUserId,
      original_image_id: baseImageId,
      points: [
        { x: 100, y: 200 },
        { x: 500, y: 200 },
        { x: 500, y: 250 },
        { x: 100, y: 250 }
      ],
      label: 'elongated_shape',
      metadata: { aspect_ratio: 8.0, test_type: 'geometric' }
    })
  };
}

/**
 * Create test data for polygon relationships and dependencies
 */
export function createRelationshipTestData(): {
  imageWithPolygons: { image: any; polygons: MockPolygon[] };
  polygonWithGarment: MockPolygon;
  overlappingPolygons: MockPolygon[];
  hierarchicalPolygons: MockPolygon[];
} {
  const userId = uuidv4();
  const imageId = uuidv4();
  const image = createMockImage({ 
    id: imageId, 
    user_id: userId, 
    status: 'processed' 
  });

  const basePolygons = createTestPolygonsForImage(imageId, userId, 3);
  
  const overlapping = createOverlappingPolygons();
  const overlappingPolygons = [
    createMockPolygon({
      user_id: userId,
      original_image_id: imageId,
      points: overlapping.polygon1,
      label: 'overlap_1',
      metadata: { overlap_test: true }
    }),
    createMockPolygon({
      user_id: userId,
      original_image_id: imageId,
      points: overlapping.polygon2,
      label: 'overlap_2',
      metadata: { overlap_test: true }
    })
  ];

  const hierarchicalPolygons = [
    createMockPolygon({
      user_id: userId,
      original_image_id: imageId,
      points: createValidPolygonPoints.square(),
      label: 'parent_region',
      metadata: { hierarchy_level: 1, parent_id: null }
    }),
    createMockPolygon({
      user_id: userId,
      original_image_id: imageId,
      points: [
        { x: 120, y: 120 },
        { x: 180, y: 120 },
        { x: 180, y: 180 },
        { x: 120, y: 180 }
      ],
      label: 'child_region',
      metadata: { hierarchy_level: 2, parent_id: 'parent_region' }
    })
  ];

  return {
    imageWithPolygons: { image, polygons: basePolygons },
    polygonWithGarment: createMockPolygon({
      user_id: userId,
      original_image_id: imageId,
      points: createValidPolygonPoints.garmentSuitable(),
      label: 'garment_polygon',
      metadata: {
        ...createPolygonMetadataVariations.garmentSpecific,
        has_garment: true,
        garment_id: uuidv4()
      }
    }),
    overlappingPolygons,
    hierarchicalPolygons
  };
}

// ==================== PERFORMANCE TESTING HELPERS ====================

/**
 * Generate large datasets for performance testing
 */
export function generatePolygonPerformanceData(size: number): {
  polygons: MockPolygon[];
  imageId: string;
  userId: string;
} {
  const userId = uuidv4();
  const imageId = uuidv4();
  
  const polygons = Array.from({ length: size }, (_, index) => {
    const complexity = index % 3 === 0 ? 'simple' : index % 3 === 1 ? 'medium' : 'complex';
    let points;
    
    switch (complexity) {
      case 'simple':
        points = createValidPolygonPoints.custom(100 + (index % 10) * 50, 100 + (index % 10) * 30, 'simple');
        break;
      case 'medium':
        points = createValidPolygonPoints.custom(100 + (index % 10) * 50, 100 + (index % 10) * 30, 'medium');
        break;
      case 'complex':
        points = createRegularPolygon(20 + (index % 30), 200 + (index % 5) * 100, 200 + (index % 5) * 100, 40);
        break;
      default:
        points = createValidPolygonPoints.square();
    }

    return createMockPolygon({
      user_id: userId,
      original_image_id: imageId,
      points,
      label: `perf_test_${index}`,
      metadata: {
        performance_test: true,
        index,
        complexity,
        point_count: points.length
      }
    });
  });

  return { polygons, imageId, userId };
}

/**
 * Measure polygon operation performance
 */
export async function measurePolygonOperation<T>(
  operation: () => Promise<T>,
  label: string = 'Polygon Operation'
): Promise<{ result: T; duration: number; memoryUsage: any }> {
  const initialMemory = process.memoryUsage();
  const start = performance.now();
  
  const result = await operation();
  
  const duration = performance.now() - start;
  const finalMemory = process.memoryUsage();
  
  const memoryUsage = {
    heapUsedDelta: finalMemory.heapUsed - initialMemory.heapUsed,
    heapTotalDelta: finalMemory.heapTotal - initialMemory.heapTotal,
    externalDelta: finalMemory.external - initialMemory.external
  };
  
  console.log(`${label} took ${duration.toFixed(2)}ms, heap delta: ${memoryUsage.heapUsedDelta} bytes`);
  
  return { result, duration, memoryUsage };
}

/**
 * Run concurrent polygon operations for testing race conditions
 */
export async function runConcurrentPolygonOperations<T>(
  operations: (() => Promise<T>)[],
  maxConcurrency: number = 10
): Promise<{ results: T[]; errors: Error[]; duration: number }> {
  const start = performance.now();
  const results: T[] = [];
  const errors: Error[] = [];
  
  // Process operations in batches
  for (let i = 0; i < operations.length; i += maxConcurrency) {
    const batch = operations.slice(i, i + maxConcurrency);
    const promises = batch.map(async (op, index) => {
      try {
        const result = await op();
        results[i + index] = result;
      } catch (error) {
        errors.push(error as Error);
      }
    });
    
    await Promise.allSettled(promises);
  }
  
  const duration = performance.now() - start;
  return { results, errors, duration };
}

// ==================== SECURITY TESTING HELPERS ====================

/**
 * Create malicious polygon payloads for security testing
 */
export function createMaliciousPolygonPayloads(): {
  sqlInjection: MockPolygonCreate;
  xssAttempt: MockPolygonCreate;
  pathTraversal: MockPolygonCreate;
  oversizedData: MockPolygonCreate;
  bufferOverflow: MockPolygonCreate;
} {
  const baseImageId = uuidv4();
  
  return {
    sqlInjection: {
      original_image_id: baseImageId,
      points: createValidPolygonPoints.triangle(),
      label: "'; DROP TABLE polygons; --",
      metadata: {
        description: "'; DELETE FROM images WHERE '1'='1",
        malicious: true
      }
    },
    xssAttempt: {
      original_image_id: baseImageId,
      points: createValidPolygonPoints.square(),
      label: '<script>alert("XSS")</script>',
      metadata: {
        description: '<img src="x" onerror="alert(\'XSS\')">'
      }
    },
    pathTraversal: {
      original_image_id: baseImageId,
      points: createValidPolygonPoints.triangle(),
      label: '../../../etc/passwd',
      metadata: {
        file_path: '../../../../sensitive/data'
      }
    },
    oversizedData: {
      original_image_id: baseImageId,
      points: createValidPolygonPoints.square(),
      label: 'x'.repeat(10000),
      metadata: {
        description: 'a'.repeat(1024 * 1024), // 1MB string
        oversized: true
      }
    },
    bufferOverflow: {
      original_image_id: baseImageId,
      points: createValidPolygonPoints.triangle(),
      label: 'test\x00\x01\x02\x03\x04',
      metadata: {
        unicode_attack: 'safe\u202Edangerous\u202C',
        null_bytes: 'normal\x00hidden'
      }
    }
  };
}

/**
 * Create authorization bypass test scenarios
 */
export function createAuthorizationBypassScenarios(): {
  crossUserAccess: {
    attackerId: string;
    victimId: string;
    victimImageId: string;
    victimPolygonId: string;
  };
  elevationAttempt: {
    regularUserId: string;
    adminOperations: string[];
  };
  sessionManipulation: {
    validSessionId: string;
    invalidSessionId: string;
    expiredSessionId: string;
  };
} {
  return {
    crossUserAccess: {
      attackerId: uuidv4(),
      victimId: uuidv4(),
      victimImageId: uuidv4(),
      victimPolygonId: uuidv4()
    },
    elevationAttempt: {
      regularUserId: uuidv4(),
      adminOperations: [
        'bulk_delete_all_polygons',
        'system_polygon_operations',
        'cross_tenant_access'
      ]
    },
    sessionManipulation: {
      validSessionId: uuidv4(),
      invalidSessionId: 'invalid-session-123',
      expiredSessionId: uuidv4()
    }
  };
}

/**
 * Generate denial of service attack scenarios for polygons
 */
export function createPolygonDoSScenarios(): {
  resourceExhaustion: {
    massivePolygonCount: number;
    complexityPerPolygon: number;
    targetImageId: string;
  };
  memoryExhaustion: {
    extremePointCount: number;
    polygonCount: number;
  };
  processingOverload: {
    selfIntersectingCount: number;
    overlapValidationCount: number;
  };
} {
  return {
    resourceExhaustion: {
      massivePolygonCount: 10000,
      complexityPerPolygon: 1000,
      targetImageId: uuidv4()
    },
    memoryExhaustion: {
      extremePointCount: 100000,
      polygonCount: 100
    },
    processingOverload: {
      selfIntersectingCount: 1000,
      overlapValidationCount: 500
    }
  };
}

// ==================== INTEGRATION TESTING HELPERS ====================

/**
 * Create end-to-end workflow test data
 */
export function createWorkflowTestData(): {
  userJourney: {
    user: any;
    image: any;
    polygonSequence: MockPolygonCreate[];
    expectedStates: string[];
  };
  multiUserScenario: {
    users: any[];
    sharedImage: any;
    collaborativePolygons: MockPolygonCreate[];
  };
  crossDomainIntegration: {
    imageToPolygonFlow: any;
    polygonToGarmentFlow: any;
  };
} {
  const userId = uuidv4();
  const imageId = uuidv4();
  
  return {
    userJourney: {
      user: { id: userId, email: 'workflow@test.com' },
      image: createMockImage({ id: imageId, user_id: userId, status: 'new' }),
      polygonSequence: [
        {
          original_image_id: imageId,
          points: createValidPolygonPoints.triangle(),
          label: 'first_annotation',
          metadata: { step: 1 }
        },
        {
          original_image_id: imageId,
          points: createValidPolygonPoints.square(),
          label: 'second_annotation',
          metadata: { step: 2 }
        },
        {
          original_image_id: imageId,
          points: createValidPolygonPoints.garmentSuitable(),
          label: 'garment_ready',
          metadata: { step: 3, ready_for_garment: true }
        }
      ],
      expectedStates: ['new', 'processed', 'processed', 'labeled']
    },
    multiUserScenario: {
      users: [
        { id: uuidv4(), email: 'user1@test.com' },
        { id: uuidv4(), email: 'user2@test.com' }
      ],
      sharedImage: createMockImage({ status: 'processed' }),
      collaborativePolygons: [
        {
          original_image_id: imageId,
          points: createValidPolygonPoints.triangle(),
          label: 'collaborative_1',
          metadata: { collaboration: true }
        }
      ]
    },
    crossDomainIntegration: {
      imageToPolygonFlow: {
        imageUpload: createMockImage({ status: 'new' }),
        polygonCreation: {
          original_image_id: imageId,
          points: createValidPolygonPoints.square(),
          label: 'cross_domain_test'
        },
        imageStatusUpdate: 'processed'
      },
      polygonToGarmentFlow: {
        polygon: createMockPolygon({
          points: createValidPolygonPoints.garmentSuitable(),
          label: 'garment_source',
          metadata: createPolygonMetadataVariations.garmentSpecific
        }),
        garmentCreation: {
          source_polygon_id: uuidv4(),
          expected_garment_data: {
            type: 'shirt',
            fit: 'regular',
            color: 'blue'
          }
        }
      }
    }
  };
}

/**
 * Create database integration test helpers
 */
export function createDatabaseIntegrationHelpers(): {
  transactionTest: () => Promise<void>;
  constraintTest: () => Promise<void>;
  performanceTest: () => Promise<void>;
} {
  return {
    transactionTest: async () => {
      // Test transaction rollback on error
      console.log('Testing database transaction rollback...');
    },
    constraintTest: async () => {
      // Test foreign key constraints
      console.log('Testing database constraints...');
    },
    performanceTest: async () => {
      // Test query performance with large datasets
      console.log('Testing database performance...');
    }
  };
}

// ==================== VALIDATION ASSERTION HELPERS ====================

/**
 * Custom assertions for polygon testing
 */
export const polygonAssertions = {
  /**
   * Assert polygon has valid geometry
   */
  hasValidGeometry(polygon: MockPolygon): void {
    expect(polygon.points).toBeDefined();
    expect(polygon.points.length).toBeGreaterThanOrEqual(3);
    expect(polygon.points.length).toBeLessThanOrEqual(1000);
    
    // Check for valid coordinates
    polygon.points.forEach(point => {
      expect(typeof point.x).toBe('number');
      expect(typeof point.y).toBe('number');
      expect(isFinite(point.x)).toBe(true);
      expect(isFinite(point.y)).toBe(true);
    });
    
    // Check area is positive
    const area = calculatePolygonArea(polygon.points);
    expect(area).toBeGreaterThan(0);
  },

  /**
   * Assert polygon is suitable for garment creation
   */
  isSuitableForGarment(polygon: MockPolygon): void {
    const validation = validateForGarment(polygon.points);
    expect(validation.isValid).toBe(true);
    expect(validation.errors).toHaveLength(0);
    
    const area = calculatePolygonArea(polygon.points);
    expect(area).toBeGreaterThanOrEqual(500);
    
    expect(polygon.points.length).toBeLessThanOrEqual(500);
    expect(hasSelfintersection(polygon.points)).toBe(false);
  },

  /**
   * Assert polygon is within image bounds
   */
  isWithinImageBounds(polygon: MockPolygon, imageWidth: number, imageHeight: number): void {
    const validation = validatePointsBounds(polygon.points, imageWidth, imageHeight);
    expect(validation.valid).toBe(true);
    expect(validation.invalidPoints).toHaveLength(0);
  },

  /**
   * Assert polygon has expected metadata structure
   */
  hasValidMetadata(polygon: MockPolygon): void {
    expect(polygon.metadata).toBeDefined();
    expect(typeof polygon.metadata).toBe('object');
    
    // Common metadata validations
    if (polygon.metadata.area) {
      expect(typeof polygon.metadata.area).toBe('number');
      expect(polygon.metadata.area).toBeGreaterThan(0);
    }
    
    if (polygon.metadata.perimeter) {
      expect(typeof polygon.metadata.perimeter).toBe('number');
      expect(polygon.metadata.perimeter).toBeGreaterThan(0);
    }
  },

  /**
   * Assert polygon operation error structure
   */
  hasValidErrorStructure(error: any): void {
    expect(error).toHaveProperty('message');
    expect(error).toHaveProperty('statusCode');
    expect(typeof error.message).toBe('string');
    expect(typeof error.statusCode).toBe('number');
    expect(error.message.length).toBeGreaterThan(0);
  },

  /**
   * Assert polygon statistics are valid
   */
  hasValidStatistics(stats: any): void {
    expect(stats).toHaveProperty('total');
    expect(stats).toHaveProperty('byLabel');
    expect(stats).toHaveProperty('averagePoints');
    expect(stats).toHaveProperty('totalArea');
    expect(stats).toHaveProperty('averageArea');
    
    expect(typeof stats.total).toBe('number');
    expect(stats.total).toBeGreaterThanOrEqual(0);
    expect(typeof stats.byLabel).toBe('object');
    expect(typeof stats.averagePoints).toBe('number');
    expect(typeof stats.totalArea).toBe('number');
    expect(typeof stats.averageArea).toBe('number');
  }
};

// ==================== ERROR SIMULATION HELPERS ====================

/**
 * Simulate various error conditions for polygon operations
 */
export const simulatePolygonErrors = {
  databaseConnection: () => {
    const error = new Error('Connection to database lost');
    (error as any).code = 'ECONNRESET';
    return error;
  },

  validationError: (field: string, value: any) => {
    const error = new Error(`Validation failed for field: ${field}`);
    (error as any).statusCode = 400;
    (error as any).field = field;
    (error as any).value = value;
    return error;
  },

  authorizationError: (operation: string) => {
    const error = new Error(`Unauthorized to perform operation: ${operation}`);
    (error as any).statusCode = 403;
    (error as any).operation = operation;
    return error;
  },

  businessLogicError: (rule: string) => {
    const error = new Error(`Business rule violation: ${rule}`);
    (error as any).statusCode = 400;
    (error as any).rule = rule;
    return error;
  },

  geometryProcessingError: () => {
    const error = new Error('Failed to process polygon geometry');
    (error as any).statusCode = 422;
    (error as any).category = 'geometry';
    return error;
  },

  mlDataSaveError: () => {
    const error = new Error('Failed to save polygon data for ML operations');
    (error as any).code = 'ML_SAVE_FAILED';
    return error;
  }
};

// ==================== CLEANUP HELPERS ====================

/**
 * Clean up test polygon data
 */
export const cleanupPolygonTestData = {
  /**
   * Remove test polygons from database
   */
  async removeTestPolygons(testUserIds: string[]): Promise<void> {
    console.log(`Would remove polygons for test users: ${testUserIds.join(', ')}`);
  },

  /**
   * Clear ML data files
   */
  async clearMLDataFiles(polygonIds: string[]): Promise<void> {
    console.log(`Would clear ML data files for polygons: ${polygonIds.join(', ')}`);
  },

  /**
   * Reset polygon-related mocks
   */
  resetPolygonMocks(): void {
    // Reset any persistent mock state
    delete (global as any).__POLYGON_MOCK_STATE__;
  },

  /**
   * Clean up performance test data
   */
  async cleanupPerformanceData(): Promise<void> {
    console.log('Would clean up performance test data');
  }
};

// ==================== EXPORT ALL HELPERS ====================

export default {
  // ==================== GEOMETRIC CALCULATIONS ====================
  calculatePolygonArea,
  calculatePolygonPerimeter,
  calculatePolygonCentroid,
  calculateBoundingBox,

  // ==================== VALIDATION HELPERS ====================
  pointInPolygon,
  linesIntersect,
  hasSelfintersection,
  validatePointsBounds,
  validateInstagramAspectRatio,
  validateForGarment,

  // ==================== POLYGON GENERATORS ====================
  createPolygonWithArea,
  createRegularPolygon,
  createOverlappingPolygons,
  createSelfIntersectingPolygon,
  createInvalidPolygon,

  // ==================== TEST DATA FACTORIES ====================
  createTestPolygonsForImage,
  createComplexityTestScenarios,
  createGeometricTestPolygons,
  createRelationshipTestData,

  // ==================== PERFORMANCE TESTING ====================
  generatePolygonPerformanceData,
  measurePolygonOperation,
  runConcurrentPolygonOperations,

  // ==================== SECURITY TESTING ====================
  createMaliciousPolygonPayloads,
  createAuthorizationBypassScenarios,
  createPolygonDoSScenarios,

  // ==================== INTEGRATION TESTING ====================
  createWorkflowTestData,
  createDatabaseIntegrationHelpers,

  // ==================== ASSERTIONS ====================
  polygonAssertions,

  // ==================== ERROR SIMULATION ====================
  simulatePolygonErrors,

  // ==================== CLEANUP ====================
  cleanupPolygonTestData
};