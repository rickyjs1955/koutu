// Jest setup for memory optimization

// Set lower memory thresholds for tests
if (typeof process !== 'undefined' && process.env) {
  // Limit memory usage for test environment
  process.env.NODE_OPTIONS = '--max-old-space-size=2048';
}

// Export empty object to make this a valid module
module.exports = {};