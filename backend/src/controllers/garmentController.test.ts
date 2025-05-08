import { describe, expect, test, jest } from '@jest/globals';

// Mock dependencies
jest.mock('../models/garmentModel', () => ({
  getAllGarments: jest.fn<() => Promise<{ id: string; name: string; createdAt: Date; }[]>>().mockResolvedValue([
    { id: '1', name: 'T-Shirt', createdAt: new Date() },
    { id: '2', name: 'Jeans', createdAt: new Date() }
  ]),
  getGarmentById: jest.fn().mockImplementation((id) => {
    if (id === '1') {
      return Promise.resolve({ id: '1', name: 'T-Shirt', createdAt: new Date() });
    }
    return Promise.resolve(null);
  }),
  createGarment: jest.fn<() => Promise<{ id: string; name: string; createdAt: Date; }>>().mockResolvedValue({ id: '3', name: 'New Garment', createdAt: new Date() }),
}));

// Add a simple test
describe('Garment Controller', () => {
  test('a basic test', () => {
    expect(true).toBe(true);
  });
});