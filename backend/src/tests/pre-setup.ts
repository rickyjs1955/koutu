// Pre-setup file that runs BEFORE module imports
// This is necessary to mock modules that are used at the module level

// Use the manual mock we created
jest.mock('../../../shared/src/schemas');