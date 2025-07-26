// Mock for polygon schemas
export const CreatePolygonSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value })),
  extend: jest.fn(() => ({
    parse: jest.fn((value) => value),
    safeParse: jest.fn((value) => ({ success: true, data: value }))
  }))
};

export const UpdatePolygonSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value })),
  extend: jest.fn(() => ({
    parse: jest.fn((value) => value),
    safeParse: jest.fn((value) => ({ success: true, data: value }))
  }))
};

export const PolygonSchema = {
  parse: jest.fn((value) => value),
  safeParse: jest.fn((value) => ({ success: true, data: value }))
};