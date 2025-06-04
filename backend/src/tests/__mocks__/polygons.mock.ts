// tests/__mocks__/polygons.mock.ts
import { v4 as uuidv4 } from 'uuid';
import { createMockImage } from './images.mock';

// ==================== TYPE DEFINITIONS ====================

export interface MockPolygon {
  id: string;
  user_id: string;
  original_image_id: string;
  points: Array<{ x: number; y: number }>;
  label?: string;
  metadata: Record<string, any>;
  created_at: Date;
  updated_at: Date;
}

export interface MockPolygonCreate {
  original_image_id: string;
  points: Array<{ x: number; y: number }>;
  label?: string;
  metadata?: Record<string, any>;
}

export interface MockPolygonUpdate {
  points?: Array<{ x: number; y: number }>;
  label?: string;
  metadata?: Record<string, any>;
}

export interface MockPolygonValidationResult {
  isValid: boolean;
  errors?: string[];
  warnings?: string[];
}

export interface MockGarmentPolygon extends MockPolygon {
  garment_suitable: boolean;
  complexity_score: number;
}

// ==================== MOCK DATA FACTORIES ====================

export const createMockPolygon = (overrides: Partial<MockPolygon> = {}): MockPolygon => ({
  id: uuidv4(),
  user_id: uuidv4(),
  original_image_id: uuidv4(),
  points: createValidPolygonPoints.triangle(),
  label: 'test_polygon',
  metadata: {
    area: 15000,
    perimeter: 400,
    complexity: 'simple',
    created_by: 'user',
    version: '1.0'
  },
  created_at: new Date(),
  updated_at: new Date(),
  ...overrides
});

export const createMockPolygonCreate = (overrides: Partial<MockPolygonCreate> = {}): MockPolygonCreate => ({
  original_image_id: uuidv4(),
  points: createValidPolygonPoints.triangle(),
  label: 'test_polygon',
  metadata: {},
  ...overrides
});

export const createMockPolygonUpdate = (overrides: Partial<MockPolygonUpdate> = {}): MockPolygonUpdate => ({
  label: 'updated_polygon',
  metadata: { updated: true },
  ...overrides
});

// ==================== POLYGON POINT GENERATORS ====================

export const createValidPolygonPoints = {
  // Basic shapes
  triangle: (): Array<{ x: number; y: number }> => [
    { x: 100, y: 100 },
    { x: 200, y: 100 },
    { x: 150, y: 200 }
  ],

  square: (): Array<{ x: number; y: number }> => [
    { x: 100, y: 100 },
    { x: 200, y: 100 },
    { x: 200, y: 200 },
    { x: 100, y: 200 }
  ],

  rectangle: (): Array<{ x: number; y: number }> => [
    { x: 100, y: 100 },
    { x: 300, y: 100 },
    { x: 300, y: 200 },
    { x: 100, y: 200 }
  ],

  pentagon: (): Array<{ x: number; y: number }> => [
    { x: 200, y: 100 },
    { x: 250, y: 130 },
    { x: 230, y: 190 },
    { x: 170, y: 190 },
    { x: 150, y: 130 }
  ],

  // Complex shapes
  complex: (): Array<{ x: number; y: number }> => [
    { x: 100, y: 100 }, { x: 150, y: 80 }, { x: 200, y: 100 },
    { x: 220, y: 130 }, { x: 250, y: 120 }, { x: 280, y: 150 },
    { x: 260, y: 180 }, { x: 230, y: 200 }, { x: 200, y: 190 },
    { x: 170, y: 210 }, { x: 140, y: 190 }, { x: 120, y: 160 }
  ],

  // For garment creation
  garmentSuitable: (): Array<{ x: number; y: number }> => [
    { x: 200, y: 150 }, { x: 280, y: 150 }, { x: 300, y: 200 },
    { x: 320, y: 280 }, { x: 300, y: 360 }, { x: 280, y: 400 },
    { x: 200, y: 400 }, { x: 120, y: 400 }, { x: 100, y: 360 },
    { x: 80, y: 280 }, { x: 100, y: 200 }, { x: 120, y: 150 }
  ],

  // Instagram compatible dimensions
  instagramSquare: (): Array<{ x: number; y: number }> => [
    { x: 200, y: 200 },
    { x: 880, y: 200 },
    { x: 880, y: 880 },
    { x: 200, y: 880 }
  ],

  instagramPortrait: (): Array<{ x: number; y: number }> => [
    { x: 200, y: 200 },
    { x: 880, y: 200 },
    { x: 880, y: 1150 },
    { x: 200, y: 1150 }
  ],

  // Edge cases
  minimal: (): Array<{ x: number; y: number }> => [
    { x: 0, y: 0 },
    { x: 10, y: 0 },
    { x: 5, y: 10 }
  ],

  // Curved approximation (many points)
  circle: (centerX = 200, centerY = 200, radius = 50, points = 20): Array<{ x: number; y: number }> => {
    const polygonPoints = [];
    for (let i = 0; i < points; i++) {
      const angle = (2 * Math.PI * i) / points;
      polygonPoints.push({
        x: Math.round(centerX + radius * Math.cos(angle)),
        y: Math.round(centerY + radius * Math.sin(angle))
      });
    }
    return polygonPoints;
  },

  // Custom generator
  custom: (width = 200, height = 150, complexity = 'simple'): Array<{ x: number; y: number }> => {
    const baseX = 100;
    const baseY = 100;
    
    switch (complexity) {
      case 'simple':
        return [
          { x: baseX, y: baseY },
          { x: baseX + width, y: baseY },
          { x: baseX + width, y: baseY + height },
          { x: baseX, y: baseY + height }
        ];
      case 'medium':
        return [
          { x: baseX, y: baseY },
          { x: baseX + width/2, y: baseY - 20 },
          { x: baseX + width, y: baseY },
          { x: baseX + width + 20, y: baseY + height/2 },
          { x: baseX + width, y: baseY + height },
          { x: baseX + width/2, y: baseY + height + 20 },
          { x: baseX, y: baseY + height },
          { x: baseX - 20, y: baseY + height/2 }
        ];
      case 'complex':
        const points = [];
        const numPoints = 12;
        for (let i = 0; i < numPoints; i++) {
          const angle = (2 * Math.PI * i) / numPoints;
          const r = 80 + Math.random() * 40; // Irregular radius
          points.push({
            x: Math.round(baseX + width/2 + r * Math.cos(angle)),
            y: Math.round(baseY + height/2 + r * Math.sin(angle))
          });
        }
        return points;
      default:
        return createValidPolygonPoints.square();
    }
  }
};

export const createInvalidPolygonPoints = {
  // Too few points
  insufficientPoints: (): Array<{ x: number; y: number }> => [
    { x: 100, y: 100 },
    { x: 200, y: 100 }
  ],

  // Too many points
  tooManyPoints: (): Array<{ x: number; y: number }> => {
    const points = [];
    for (let i = 0; i < 1001; i++) {
      points.push({ x: i % 100, y: Math.floor(i / 100) });
    }
    return points;
  },

  // Self-intersecting polygon
  selfIntersecting: (): Array<{ x: number; y: number }> => [
    { x: 100, y: 100 },
    { x: 200, y: 200 },
    { x: 100, y: 200 },
    { x: 200, y: 100 }
  ],

  // Points outside image bounds (assuming 800x600 image)
  outOfBounds: (): Array<{ x: number; y: number }> => [
    { x: -10, y: 100 },
    { x: 810, y: 100 },
    { x: 400, y: 610 }
  ],

  // Zero area polygon (collinear points)
  zeroArea: (): Array<{ x: number; y: number }> => [
    { x: 100, y: 100 },
    { x: 150, y: 100 },
    { x: 200, y: 100 }
  ],

  // Negative coordinates
  negativeCoordinates: (): Array<{ x: number; y: number }> => [
    { x: -50, y: -50 },
    { x: 50, y: -50 },
    { x: 0, y: 50 }
  ],

  // NaN coordinates
  nanCoordinates: (): Array<{ x: number; y: number }> => [
    { x: NaN, y: 100 },
    { x: 200, y: NaN },
    { x: 150, y: 200 }
  ],

  // Infinite coordinates
  infiniteCoordinates: (): Array<{ x: number; y: number }> => [
    { x: Infinity, y: 100 },
    { x: 200, y: 100 },
    { x: 150, y: 200 }
  ],

  // Extremely small area
  tooSmallArea: (): Array<{ x: number; y: number }> => [
    { x: 100, y: 100 },
    { x: 101, y: 100 },
    { x: 100.5, y: 101 }
  ]
};

// ==================== POLYGON METADATA VARIATIONS ====================

export const createPolygonMetadataVariations = {
  basic: {
    type: 'annotation',
    confidence: 0.95,
    annotator: 'user'
  },

  detailed: {
    type: 'garment',
    category: 'clothing',
    subcategory: 'shirt',
    color: 'blue',
    pattern: 'solid',
    material: 'cotton',
    confidence: 0.98,
    annotator: 'user',
    validation_status: 'approved',
    tags: ['summer', 'casual']
  },

  aiGenerated: {
    type: 'ai_detection',
    model: 'polygon_detector_v2.1',
    confidence: 0.87,
    processing_time: 0.234,
    annotator: 'ai',
    validation_status: 'pending'
  },

  garmentSpecific: {
    type: 'garment',
    garment_type: 'top',
    fit_type: 'regular',
    size_estimate: 'medium',
    color_palette: ['#1a472a', '#2d5a3d', '#3f6d50'],
    texture_confidence: 0.92,
    fabric_type: 'woven'
  },

  withMeasurements: {
    type: 'measurement',
    area_pixels: 15000,
    perimeter_pixels: 400,
    bounding_box: { x: 100, y: 100, width: 200, height: 150 },
    centroid: { x: 200, y: 175 },
    aspect_ratio: 1.33
  },

  versioned: {
    version: '2.1',
    previous_versions: ['1.0', '2.0'],
    changes: 'Refined boundary points',
    edited_by: 'user_123',
    edit_reason: 'improved_accuracy'
  }
};

// ==================== DATABASE MOCK RESULTS ====================

export const mockPolygonModelOperations = {
  create: jest.fn(),
  findById: jest.fn(),
  findByImageId: jest.fn(),
  findByUserId: jest.fn(),
  update: jest.fn(),
  delete: jest.fn(),
  deleteByImageId: jest.fn(),
  countByUserId: jest.fn(),
  findWithMetadata: jest.fn(),
  batchCreate: jest.fn(),
  batchUpdate: jest.fn(),
  batchDelete: jest.fn()
};

export const createMockPolygonQueryResult = (polygons: MockPolygon[], rowCount?: number) => ({
  rows: polygons.map(polygon => ({
    ...polygon,
    points: JSON.stringify(polygon.points),
    metadata: JSON.stringify(polygon.metadata)
  })),
  rowCount: rowCount ?? polygons.length,
  fields: [],
  command: 'SELECT',
  oid: 0
});

// ==================== POLYGON SERVICE MOCKS ====================

export const mockPolygonService = {
  createPolygon: jest.fn(),
  validatePolygonGeometry: jest.fn(),
  checkSelfIntersection: jest.fn(),
  linesIntersect: jest.fn(),
  checkPolygonOverlap: jest.fn(),
  polygonsOverlap: jest.fn(),
  pointInPolygon: jest.fn(),
  getImagePolygons: jest.fn(),
  getPolygonById: jest.fn(),
  updatePolygon: jest.fn(),
  deletePolygon: jest.fn(),
  getUserPolygonStats: jest.fn(),
  deleteImagePolygons: jest.fn(),
  validatePolygonForGarment: jest.fn(),
  simplifyPolygon: jest.fn()
};

// ==================== POLYGON SERVICE UTILS MOCKS ====================

export const mockPolygonServiceUtils = {
  calculatePolygonPerimeter: jest.fn(),
  douglasPeucker: jest.fn(),
  pointToLineDistance: jest.fn(),
  savePolygonDataForML: jest.fn(),
  calculatePolygonArea: jest.fn()
};

// ==================== POLYGON CONTROLLER MOCKS ====================

export const mockPolygonController = {
  createPolygon: jest.fn(),
  getImagePolygons: jest.fn(),
  getPolygon: jest.fn(),
  updatePolygon: jest.fn(),
  deletePolygon: jest.fn()
};

// ==================== VALIDATION RESULT GENERATORS ====================

export const createValidationResults = {
  valid: (): MockPolygonValidationResult => ({
    isValid: true,
    errors: [],
    warnings: []
  }),

  invalidGeometry: (): MockPolygonValidationResult => ({
    isValid: false,
    errors: [
      'Polygon must have at least 3 points',
      'Polygon edges cannot intersect with each other'
    ],
    warnings: []
  }),

  outOfBounds: (): MockPolygonValidationResult => ({
    isValid: false,
    errors: [
      '2 point(s) are outside image boundaries (800x600)'
    ],
    warnings: []
  }),

  tooSmall: (): MockPolygonValidationResult => ({
    isValid: false,
    errors: [
      'Polygon area too small (minimum: 100 pixels)'
    ],
    warnings: []
  }),

  withWarnings: (): MockPolygonValidationResult => ({
    isValid: true,
    errors: [],
    warnings: [
      'Polygon is very close to image boundary',
      'Consider simplifying polygon for better performance'
    ]
  }),

  complexityWarning: (): MockPolygonValidationResult => ({
    isValid: true,
    errors: [],
    warnings: [
      'Polygon has many points and may impact performance',
      'Consider using simplification'
    ]
  })
};

// ==================== GEOMETRIC CALCULATION RESULTS ====================

export const createGeometricResults = {
  triangle: {
    area: 5000,
    perimeter: 341.42,
    centroid: { x: 150, y: 133.33 },
    boundingBox: { x: 100, y: 100, width: 100, height: 100 }
  },

  square: {
    area: 10000,
    perimeter: 400,
    centroid: { x: 150, y: 150 },
    boundingBox: { x: 100, y: 100, width: 100, height: 100 }
  },

  rectangle: {
    area: 20000,
    perimeter: 600,
    centroid: { x: 200, y: 150 },
    boundingBox: { x: 100, y: 100, width: 200, height: 100 }
  },

  complex: {
    area: 18750,
    perimeter: 687.32,
    centroid: { x: 200, y: 155 },
    boundingBox: { x: 100, y: 80, width: 180, height: 130 }
  }
};

// ==================== OVERLAP AND INTERSECTION TEST DATA ====================

export const createOverlapTestScenarios = {
  noOverlap: {
    polygon1: createValidPolygonPoints.square(),
    polygon2: [
      { x: 300, y: 300 },
      { x: 400, y: 300 },
      { x: 400, y: 400 },
      { x: 300, y: 400 }
    ],
    expectedOverlap: false
  },

  partialOverlap: {
    polygon1: createValidPolygonPoints.square(),
    polygon2: [
      { x: 150, y: 150 },
      { x: 250, y: 150 },
      { x: 250, y: 250 },
      { x: 150, y: 250 }
    ],
    expectedOverlap: true
  },

  completeOverlap: {
    polygon1: createValidPolygonPoints.square(),
    polygon2: [
      { x: 120, y: 120 },
      { x: 180, y: 120 },
      { x: 180, y: 180 },
      { x: 120, y: 180 }
    ],
    expectedOverlap: true
  },

  touching: {
    polygon1: createValidPolygonPoints.square(),
    polygon2: [
      { x: 200, y: 100 },
      { x: 300, y: 100 },
      { x: 300, y: 200 },
      { x: 200, y: 200 }
    ],
    expectedOverlap: false // Just touching edges
  }
};

export const createIntersectionTestScenarios = {
  noIntersection: {
    line1: { p1: { x: 0, y: 0 }, p2: { x: 10, y: 0 } },
    line2: { p1: { x: 0, y: 10 }, p2: { x: 10, y: 10 } },
    expectedIntersection: false
  },

  intersection: {
    line1: { p1: { x: 0, y: 0 }, p2: { x: 10, y: 10 } },
    line2: { p1: { x: 0, y: 10 }, p2: { x: 10, y: 0 } },
    expectedIntersection: true
  },

  parallel: {
    line1: { p1: { x: 0, y: 0 }, p2: { x: 10, y: 0 } },
    line2: { p1: { x: 0, y: 5 }, p2: { x: 10, y: 5 } },
    expectedIntersection: false
  },

  collinear: {
    line1: { p1: { x: 0, y: 0 }, p2: { x: 10, y: 0 } },
    line2: { p1: { x: 5, y: 0 }, p2: { x: 15, y: 0 } },
    expectedIntersection: false // Overlapping but not intersecting
  }
};

// ==================== USER STATISTICS MOCK DATA ====================

export const createMockPolygonStats = (overrides: Partial<any> = {}) => ({
  total: 25,
  byLabel: {
    'shirt': 8,
    'pants': 6,
    'dress': 4,
    'jacket': 3,
    'skirt': 2,
    'unlabeled': 2
  },
  averagePoints: 12,
  totalArea: 375000,
  averageArea: 15000,
  byComplexity: {
    simple: 15,
    medium: 8,
    complex: 2
  },
  createdThisMonth: 5,
  lastCreated: new Date(),
  ...overrides
});

// ==================== ERROR SCENARIOS ====================

export const createPolygonErrorScenarios = {
  validationErrors: {
    insufficientPoints: {
      points: createInvalidPolygonPoints.insufficientPoints(),
      expectedError: 'Polygon must have at least 3 points'
    },
    tooManyPoints: {
      points: createInvalidPolygonPoints.tooManyPoints(),
      expectedError: 'Polygon cannot have more than 1000 points'
    },
    selfIntersecting: {
      points: createInvalidPolygonPoints.selfIntersecting(),
      expectedError: 'Polygon edges cannot intersect with each other'
    },
    outOfBounds: {
      points: createInvalidPolygonPoints.outOfBounds(),
      expectedError: 'point(s) are outside image boundaries'
    },
    zeroArea: {
      points: createInvalidPolygonPoints.zeroArea(),
      expectedError: 'Polygon must have positive area'
    },
    tooSmallArea: {
      points: createInvalidPolygonPoints.tooSmallArea(),
      expectedError: 'Polygon area too small (minimum: 100 pixels)'
    }
  },

  businessLogicErrors: {
    imageNotFound: {
      imageId: uuidv4(),
      expectedError: 'Image not found'
    },
    imageAlreadyLabeled: {
      imageStatus: 'labeled',
      expectedError: 'Image is already labeled and cannot accept new polygons'
    },
    unauthorizedAccess: {
      userId: uuidv4(),
      imageOwnerId: uuidv4(),
      expectedError: 'You do not have permission to add polygons to this image'
    },
    polygonNotFound: {
      polygonId: uuidv4(),
      expectedError: 'Polygon not found'
    }
  },

  garmentValidationErrors: {
    tooSmallForGarment: {
      area: 400, // Below 500 pixel minimum
      expectedError: 'Polygon too small for garment creation (minimum area: 500 pixels)'
    },
    tooComplexForGarment: {
      pointCount: 600, // Above 500 point maximum
      expectedError: 'Polygon too complex for garment creation (maximum 500 points)'
    },
    selfIntersectingGarment: {
      points: createInvalidPolygonPoints.selfIntersecting(),
      expectedError: 'Self-intersecting polygons cannot be used for garment creation'
    }
  }
};

// ==================== SIMPLIFICATION TEST DATA ====================

export const createSimplificationTestData = {
  highDetail: {
    original: createValidPolygonPoints.circle(200, 200, 50, 50), // 50 points
    tolerance: 2,
    expectedPointReduction: 0.6 // Expect ~60% reduction
  },

  mediumDetail: {
    original: createValidPolygonPoints.complex(),
    tolerance: 5,
    expectedPointReduction: 0.3 // Expect ~30% reduction
  },

  alreadySimple: {
    original: createValidPolygonPoints.square(),
    tolerance: 2,
    expectedPointReduction: 0 // Should remain unchanged
  },

  overSimplification: {
    original: createValidPolygonPoints.triangle(),
    tolerance: 100, // Very high tolerance
    expectedError: 'Cannot simplify polygon below 3 points'
  }
};

// ==================== CONCURRENT OPERATION TEST DATA ====================

export const createConcurrencyTestScenarios = {
  multipleCreation: {
    imageId: uuidv4(),
    userId: uuidv4(),
    polygonCount: 10,
    expectedBehavior: 'all_succeed'
  },

  raceConditionUpdate: {
    polygonId: uuidv4(),
    userId: uuidv4(),
    updateCount: 5,
    expectedBehavior: 'last_update_wins'
  },

  concurrentDelete: {
    imageId: uuidv4(),
    userId: uuidv4(),
    expectedBehavior: 'single_deletion'
  }
};

// ==================== SECURITY TEST PAYLOADS ====================

export const createPolygonSecurityPayloads = () => ({
  maliciousLabels: [
    '<script>alert("xss")</script>',
    "'; DROP TABLE polygons; --",
    '../../../etc/passwd',
    'label'.repeat(1000),
    '\x00\x01\x02\x03\x04'
  ],
  maliciousMetadata: {
    oversized: 'x'.repeat(1024 * 1024),
    sqlInjection: "'; DELETE FROM images WHERE '1'='1",
    xssPayload: '<img src="x" onerror="alert(\'XSS\')">',
    pathTraversal: '../../../sensitive/data'
  },
  maliciousPoints: [
    { x: Number.MAX_SAFE_INTEGER, y: Number.MAX_SAFE_INTEGER },
    { x: -Number.MAX_SAFE_INTEGER, y: -Number.MAX_SAFE_INTEGER },
    { x: 0, y: 0 }
  ],
  dos: {
    tooManyPolygons: {
      count: 10000,
      targetImageId: uuidv4()
    },
    complexPolygon: {
      pointCount: 100000,
      targetImageId: uuidv4()
    },
    rapidRequests: {
      requestCount: 1000,
      timeframe: 1000
    }
  }
});

// ==================== PERFORMANCE TEST DATA ====================

export const createPerformanceTestData = () => ({
  scalability: {
    smallBatch: { polygonCount: 10, complexity: 'simple' },
    mediumBatch: { polygonCount: 100, complexity: 'medium' },
    largeBatch: { polygonCount: 1000, complexity: 'complex' }
  },
  complexityLevels: {
    simple: { pointCount: 4, expectedProcessingTime: 10 },
    medium: { pointCount: 20, expectedProcessingTime: 50 },
    complex: { pointCount: 100, expectedProcessingTime: 200 },
    extreme: { pointCount: 500, expectedProcessingTime: 1000 }
  },
  memoryUsage: {
    baseline: { polygonCount: 0 },
    moderate: { polygonCount: 100 },
    heavy: { polygonCount: 1000 },
    extreme: { polygonCount: 10000 }
  }
});

// ==================== REQUEST/RESPONSE MOCKS ====================

export const createMockPolygonRequest = (overrides: Partial<any> = {}) => ({
  user: {
    id: uuidv4(),
    email: 'test@example.com'
  },
  params: {
    id: uuidv4(),
    imageId: uuidv4()
  },
  body: createMockPolygonCreate(),
  query: {},
  headers: {
    'content-type': 'application/json'
  },
  method: 'POST',
  path: '/api/v1/polygons',
  ...overrides
});

export const createMockPolygonResponse = () => ({
  status: jest.fn().mockReturnThis(),
  json: jest.fn().mockReturnThis(),
  send: jest.fn().mockReturnThis(),
  locals: {}
});

// ==================== SETUP AND RESET UTILITIES ====================

export const setupPolygonHappyPathMocks = () => {
  // Model operations succeed
  mockPolygonModelOperations.create.mockResolvedValue(createMockPolygon());
  mockPolygonModelOperations.findById.mockResolvedValue(createMockPolygon());
  mockPolygonModelOperations.findByImageId.mockResolvedValue([createMockPolygon()]);
  mockPolygonModelOperations.findByUserId.mockResolvedValue([createMockPolygon()]);
  mockPolygonModelOperations.update.mockResolvedValue(createMockPolygon());
  mockPolygonModelOperations.delete.mockResolvedValue(true);
  mockPolygonModelOperations.deleteByImageId.mockResolvedValue(5);

  // Service operations succeed
  mockPolygonService.createPolygon.mockResolvedValue(createMockPolygon());
  mockPolygonService.validatePolygonGeometry.mockResolvedValue(createValidationResults.valid());
  mockPolygonService.checkSelfIntersection.mockReturnValue(false);
  mockPolygonService.linesIntersect.mockReturnValue(false);
  mockPolygonService.checkPolygonOverlap.mockResolvedValue(false);
  mockPolygonService.polygonsOverlap.mockReturnValue(false);
  mockPolygonService.pointInPolygon.mockReturnValue(false);
  mockPolygonService.getImagePolygons.mockResolvedValue([createMockPolygon()]);
  mockPolygonService.getPolygonById.mockResolvedValue(createMockPolygon());
  mockPolygonService.updatePolygon.mockResolvedValue(createMockPolygon());
  mockPolygonService.deletePolygon.mockResolvedValue(undefined);
  mockPolygonService.getUserPolygonStats.mockResolvedValue(createMockPolygonStats());
  mockPolygonService.deleteImagePolygons.mockResolvedValue(5);
  mockPolygonService.validatePolygonForGarment.mockResolvedValue(true);
  mockPolygonService.simplifyPolygon.mockResolvedValue(createMockPolygon());

  // Service utils succeed
  mockPolygonServiceUtils.calculatePolygonPerimeter.mockReturnValue(400);
  mockPolygonServiceUtils.calculatePolygonArea.mockReturnValue(15000);
  mockPolygonServiceUtils.douglasPeucker.mockReturnValue(createValidPolygonPoints.square());
  mockPolygonServiceUtils.pointToLineDistance.mockReturnValue(5.0);
  mockPolygonServiceUtils.savePolygonDataForML.mockResolvedValue(undefined);

  // Controller operations succeed
  mockPolygonController.createPolygon.mockImplementation((req, res) => {
    res.status(201).json({
      status: 'success',
      data: { polygon: createMockPolygon() }
    });
  });
  mockPolygonController.getImagePolygons.mockImplementation((req, res) => {
    res.status(200).json({
      status: 'success',
      data: { polygons: [createMockPolygon()], count: 1 }
    });
  });
  mockPolygonController.getPolygon.mockImplementation((req, res) => {
    res.status(200).json({
      status: 'success',
      data: { polygon: createMockPolygon() }
    });
  });
  mockPolygonController.updatePolygon.mockImplementation((req, res) => {
    res.status(200).json({
      status: 'success',
      data: { polygon: createMockPolygon() }
    });
  });
  mockPolygonController.deletePolygon.mockImplementation((req, res) => {
    res.status(200).json({
      status: 'success',
      data: null,
      message: 'Polygon deleted successfully'
    });
  });
};

export const setupPolygonErrorMocks = () => {
  // Model operations fail
  mockPolygonModelOperations.create.mockRejectedValue(new Error('Database error'));
  mockPolygonModelOperations.findById.mockRejectedValue(new Error('Database error'));
  mockPolygonModelOperations.findByImageId.mockRejectedValue(new Error('Database error'));
  mockPolygonModelOperations.update.mockRejectedValue(new Error('Database error'));
  mockPolygonModelOperations.delete.mockRejectedValue(new Error('Database error'));

  // Service operations fail
  mockPolygonService.createPolygon.mockRejectedValue(new Error('Service error'));
  mockPolygonService.validatePolygonGeometry.mockResolvedValue(createValidationResults.invalidGeometry());
  mockPolygonService.checkSelfIntersection.mockReturnValue(true);
  mockPolygonService.getPolygonById.mockRejectedValue(new Error('Polygon not found'));
  mockPolygonService.updatePolygon.mockRejectedValue(new Error('Update failed'));
  mockPolygonService.deletePolygon.mockRejectedValue(new Error('Delete failed'));
  mockPolygonService.validatePolygonForGarment.mockRejectedValue(new Error('Invalid for garment'));

  // Service utils fail
  mockPolygonServiceUtils.calculatePolygonArea.mockReturnValue(0); // Invalid area
  mockPolygonServiceUtils.savePolygonDataForML.mockRejectedValue(new Error('ML save failed'));
};

export const resetPolygonMocks = () => {
  // Reset model mocks
  Object.values(mockPolygonModelOperations).forEach(mock => mock.mockReset());
  
  // Reset service mocks
  Object.values(mockPolygonService).forEach(mock => mock.mockReset());
  Object.values(mockPolygonServiceUtils).forEach(mock => mock.mockReset());
  
  // Reset controller mocks
  Object.values(mockPolygonController).forEach(mock => mock.mockReset());
};

// ==================== INTEGRATION TEST DATA ====================

export const createIntegrationTestData = {
  fullWorkflow: {
    user: {
      id: uuidv4(),
      email: 'integration@test.com'
    },
    image: createMockImage(),
    polygons: [
      createMockPolygon({ label: 'shirt' }),
      createMockPolygon({ label: 'pants' }),
      createMockPolygon({ label: 'jacket' })
    ]
  },

  crossDomainValidation: {
    imageWithPolygons: {
      image: createMockImage({ status: 'processed' }),
      polygons: [
        createMockPolygon(),
        createMockPolygon({ label: 'garment_ready' })
      ]
    },
    garmentCreation: {
      sourcePolygon: createMockPolygon({
        points: createValidPolygonPoints.garmentSuitable(),
        label: 'shirt',
        metadata: createPolygonMetadataVariations.garmentSpecific
      })
    }
  },

  bulkOperations: {
    batchCreate: {
      imageId: uuidv4(),
      polygonData: Array.from({ length: 10 }, (_, i) => 
        createMockPolygonCreate({
          label: `polygon_${i + 1}`,
          points: createValidPolygonPoints.custom(100 + i * 10, 100 + i * 5)
        })
      )
    },
    batchUpdate: {
      polygonIds: Array.from({ length: 5 }, () => uuidv4()),
      updateData: {
        metadata: { batch_updated: true, timestamp: new Date().toISOString() }
      }
    },
    batchDelete: {
      imageId: uuidv4(),
      expectedDeleteCount: 8
    }
  }
};

// ==================== ML/AI INTEGRATION MOCKS ====================

export const createMLIntegrationMocks = {
  polygonDataExport: {
    successful: {
      polygonId: uuidv4(),
      exportPath: 'data/polygons/test-polygon.json',
      exportData: {
        polygon: createMockPolygon(),
        image: createMockImage(),
        export_metadata: {
          exported_at: new Date().toISOString(),
          format_version: '1.0'
        }
      }
    },
    failed: {
      polygonId: uuidv4(),
      error: new Error('Failed to save ML data')
    }
  },

  aiValidation: {
    confident: {
      confidence: 0.95,
      validation_status: 'approved',
      ai_suggestions: []
    },
    uncertain: {
      confidence: 0.65,
      validation_status: 'needs_review',
      ai_suggestions: [
        'Consider refining boundary near coordinates (150, 200)',
        'Polygon may be missing corner detail'
      ]
    },
    rejected: {
      confidence: 0.30,
      validation_status: 'rejected',
      ai_suggestions: [
        'Polygon appears to be incorrectly labeled',
        'Consider re-annotating this area'
      ]
    }
  }
};

// ==================== WORKFLOW STATE MOCKS ====================

export const createWorkflowStateMocks = {
  newImage: {
    image: createMockImage({ status: 'new' }),
    allowedOperations: ['create_polygon'],
    restrictedOperations: ['finalize_labeling']
  },

  processedImage: {
    image: createMockImage({ status: 'processed' }),
    polygons: [createMockPolygon()],
    allowedOperations: ['create_polygon', 'update_polygon', 'delete_polygon'],
    restrictedOperations: []
  },

  labeledImage: {
    image: createMockImage({ status: 'labeled' }),
    polygons: [createMockPolygon(), createMockPolygon()],
    allowedOperations: ['read_polygon'],
    restrictedOperations: ['create_polygon', 'update_polygon', 'delete_polygon']
  },

  imageWithGarments: {
    image: createMockImage({ status: 'labeled' }),
    polygons: [
      createMockPolygon({ 
        label: 'shirt',
        metadata: { has_garment: true, garment_id: uuidv4() }
      })
    ],
    allowedOperations: ['read_polygon'],
    restrictedOperations: ['delete_polygon'] // Can't delete polygons with garments
  }
};

// ==================== AUTHORIZATION TEST DATA ====================

export const createAuthorizationTestData = {
  validAccess: {
    userId: uuidv4(),
    imageOwnerId: null, // Will be set to same as userId
    polygonOwnerId: null, // Will be set to same as userId
    expectedResult: 'success'
  },

  invalidAccess: {
    userId: uuidv4(),
    imageOwnerId: uuidv4(),
    polygonOwnerId: uuidv4(),
    expectedResult: 'forbidden'
  },

  crossUserAttempts: {
    attackerId: uuidv4(),
    victimId: uuidv4(),
    attempts: [
      'read_other_user_polygons',
      'update_other_user_polygons',
      'delete_other_user_polygons',
      'create_polygons_on_other_user_image'
    ]
  },

  elevationAttempts: {
    regularUserId: uuidv4(),
    attempts: [
      'access_admin_polygon_endpoints',
      'bulk_delete_all_polygons',
      'system_polygon_operations'
    ]
  }
};

// ==================== EDGE CASE TEST DATA ====================

export const createEdgeCaseTestData = {
  boundaryConditions: {
    exactlyThreePoints: createValidPolygonPoints.triangle(),
    exactlyThousandPoints: (() => {
      const points = [];
      for (let i = 0; i < 1000; i++) {
        const angle = (2 * Math.PI * i) / 1000;
        points.push({
          x: Math.round(400 + 200 * Math.cos(angle)),
          y: Math.round(300 + 200 * Math.sin(angle))
        });
      }
      return points;
    })(),
    minimumValidArea: [
      { x: 100, y: 100 },
      { x: 110, y: 100 },
      { x: 105, y: 110 }
    ], // Area exactly 50 pixels
    maximumImageBounds: [
      { x: 0, y: 0 },
      { x: 799, y: 0 },
      { x: 799, y: 599 },
      { x: 0, y: 599 }
    ]
  },

  numericalPrecision: {
    highPrecisionCoordinates: [
      { x: 100.999999, y: 100.000001 },
      { x: 200.000001, y: 100.999999 },
      { x: 150.500000, y: 200.500000 }
    ],
    integerOverflow: [
      { x: 2147483647, y: 100 }, // Max int32
      { x: 100, y: 2147483647 },
      { x: 150, y: 200 }
    ]
  },

  unicodeHandling: {
    unicodeLabels: [
      '测试多边形', // Chinese
      'مضلع اختبار', // Arabic
      'тестовый полигон', // Russian
      '🔺 Triangle', // Emoji
      'Pólígono tëst', // Accents
      'पॉलिगॉन परीक्षण' // Hindi
    ],
    unicodeMetadata: {
      description: 'Тест with émojis 🎨 and spëcial chârs',
      tags: ['🏷️ tag1', 'тег2', '标签3']
    }
  },

  temporalEdgeCases: {
    timestampPrecision: {
      created_at: new Date('2023-12-31T23:59:59.999Z'),
      updated_at: new Date('2024-01-01T00:00:00.001Z')
    },
    futureTimestamp: new Date('2030-01-01T00:00:00.000Z'),
    epochTimestamp: new Date('1970-01-01T00:00:00.000Z')
  }
};

// ==================== EXPORT ALL MOCKS ====================

export default {
  // ==================== FACTORIES ====================
  createMockPolygon,
  createMockPolygonCreate,
  createMockPolygonUpdate,
  createMockPolygonRequest,
  createMockPolygonResponse,

  // ==================== POINT GENERATORS ====================
  createValidPolygonPoints,
  createInvalidPolygonPoints,

  // ==================== SERVICE MOCKS ====================
  mockPolygonModelOperations,
  mockPolygonService,
  mockPolygonServiceUtils,
  mockPolygonController,

  // ==================== TEST DATA GENERATORS ====================
  createPolygonMetadataVariations,
  createValidationResults,
  createGeometricResults,
  createOverlapTestScenarios,
  createIntersectionTestScenarios,
  createMockPolygonStats,
  createPolygonErrorScenarios,
  createSimplificationTestData,
  createConcurrencyTestScenarios,
  createPolygonSecurityPayloads,
  createPerformanceTestData,

  // ==================== INTEGRATION TEST DATA ====================
  createIntegrationTestData,
  createMLIntegrationMocks,
  createWorkflowStateMocks,
  createAuthorizationTestData,
  createEdgeCaseTestData,

  // ==================== DATABASE UTILITIES ====================
  createMockPolygonQueryResult,

  // ==================== SETUP UTILITIES ====================
  setupPolygonHappyPathMocks,
  setupPolygonErrorMocks,
  resetPolygonMocks
};