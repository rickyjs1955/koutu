// Mock for opencv-wasm module
const cv = {
  Point: jest.fn(),
  Mat: jest.fn(),
  MatVector: jest.fn(), 
  Size: jest.fn(),
  Rect: jest.fn(),
  RotatedRect: jest.fn(),
  Scalar: jest.fn(),
  cvtColor: jest.fn(),
  COLOR_BGR2GRAY: 0,
  COLOR_GRAY2BGR: 1,
  COLOR_BGR2RGB: 2,
  threshold: jest.fn(),
  THRESH_BINARY: 0,
  THRESH_BINARY_INV: 1,
  findContours: jest.fn(),
  RETR_EXTERNAL: 0,
  RETR_LIST: 1,
  RETR_TREE: 2,
  CHAIN_APPROX_SIMPLE: 0,
  CHAIN_APPROX_TC89_L1: 1,
  drawContours: jest.fn(),
  contourArea: jest.fn(),
  arcLength: jest.fn(),
  approxPolyDP: jest.fn(),
  convexHull: jest.fn(),
  minAreaRect: jest.fn(),
  boundingRect: jest.fn(),
  pointPolygonTest: jest.fn(),
  fillPoly: jest.fn(),
  polylines: jest.fn(),
  CV_8UC1: 0,
  CV_8UC3: 16,
  CV_8UC4: 24,
  CV_32FC1: 5,
  imshow: jest.fn(),
  imread: jest.fn(),
  imwrite: jest.fn(),
  // Add additional methods that might be used
  waitKey: jest.fn(),
  destroyAllWindows: jest.fn(),
  circle: jest.fn(),
  line: jest.fn(),
  rectangle: jest.fn(),
  putText: jest.fn()
};

// Export both as default and named export to cover different import styles
module.exports = cv;
module.exports.default = cv;