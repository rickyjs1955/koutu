// Setup file for stress tests

// Increase event listener limit for stress tests
require('events').EventEmitter.defaultMaxListeners = 100;

// Enable garbage collection exposure if running with --expose-gc
if (global.gc) {
  console.log('✅ Manual garbage collection is available');
} else {
  console.log('⚠️  Manual garbage collection is not available. Run with --expose-gc flag for better memory management');
}

// Set longer timeout for stress tests
jest.setTimeout(180000); // 3 minutes

// Monitor memory usage
const startMemory = process.memoryUsage();
console.log(`📊 Initial memory usage: ${Math.round(startMemory.heapUsed / 1024 / 1024)}MB`);

// Log memory usage periodically during tests
const memoryInterval = setInterval(() => {
  const current = process.memoryUsage();
  const heapUsedMB = Math.round(current.heapUsed / 1024 / 1024);
  const heapTotalMB = Math.round(current.heapTotal / 1024 / 1024);
  
  if (heapUsedMB > heapTotalMB * 0.9) {
    console.warn(`⚠️  High memory usage: ${heapUsedMB}MB / ${heapTotalMB}MB (${Math.round(heapUsedMB / heapTotalMB * 100)}%)`);
  }
}, 10000); // Every 10 seconds

// Clean up interval after tests
afterAll(() => {
  clearInterval(memoryInterval);
});