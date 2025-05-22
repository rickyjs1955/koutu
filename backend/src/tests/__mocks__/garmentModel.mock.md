// filepath: c:\Users\monmo\koutu\backend\src\tests\__mocks__\garmentModel.mock.ts
/**
 * @file garmentModel.mock.ts
 * @summary Mock implementations for dependencies of garmentModel.ts.
 * This includes mocking database utility functions and UUID generation.
 */

// Mock for the database query function that garmentModel uses.
// This function simulates the behavior of executing a SQL query.
export const mockDbQuery = jest.fn();

// Mock for the getQueryFunction utility.
// This function is expected to return the mockDbQuery.
export const mockGetQueryFunction = jest.fn(() => mockDbQuery);

// Mock for the uuidv4 function used to generate unique IDs.
export const mockUuidv4 = jest.fn();

// Mock for the isUuid function used to validate UUIDs.
export const mockIsUuid = jest.fn();

// Note: The actual jest.mock calls that use these functions
// are placed in the .unit.test.ts file to ensure they are
// hoisted and applied before the garmentModel module is imported.