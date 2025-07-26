# Stress Tests

This directory contains stress tests for the backend API endpoints. These tests are designed to validate performance, stability, and resource management under high load conditions.

## Running Stress Tests

### Run all stress tests:
```bash
npm run test:stress
```

### Run specific stress test:
```bash
npm run test:stress:auth
```

### Watch mode (for development):
```bash
npm run test:stress:watch
```

## Configuration

The stress tests are configured to run with:
- **4GB heap size** (`--max-old-space-size=4096`)
- **Manual garbage collection** (`--expose-gc`)
- **Serial execution** (`--runInBand`) to prevent resource contention
- **3-minute timeout** per test suite

## Optimization Details

The stress tests have been optimized to prevent memory exhaustion:

1. **Cache Management**
   - Rate limit and token caches have size limits (1000 and 500 entries respectively)
   - Automatic cleanup when caches exceed limits
   - Caches are cleared between tests

2. **Reduced Test Scale**
   - Iteration counts reduced to manageable levels
   - Concurrency levels optimized for stability
   - Batch processing with delays for GC

3. **Memory Management**
   - Periodic garbage collection between batches
   - Limited error tracking (only first 10 errors)
   - Response time arrays cleared periodically
   - Memory samples limited to last 10 entries

4. **Test Structure**
   - Tests run serially to prevent resource contention
   - Cleanup hooks after each test
   - Force GC when available

## Test Categories

### Authentication Routes (`authRoutes.stress.test.ts`)
- **Registration**: 500 concurrent requests
- **Login**: 1000 concurrent requests  
- **Token Operations**: 1500 validation requests
- **Mobile Endpoints**: Device registration and biometric login
- **Protected Endpoints**: Profile and password management
- **Memory Management**: 2000 operations to test for leaks

## Performance Targets

- **Response Time**: < 500ms average for most operations
- **Throughput**: > 100 ops/sec for simple operations
- **Success Rate**: > 80% for non-rate-limited endpoints
- **Memory Growth**: < 200MB for extended test runs

## Troubleshooting

If tests fail with memory errors:
1. Ensure you're running with the npm scripts (includes heap size increase)
2. Check system available memory
3. Run tests individually rather than all at once
4. Consider further reducing iteration counts

## Development Tips

1. Always use the provided npm scripts to ensure proper configuration
2. Monitor memory usage during test development
3. Clear caches and force GC between test suites
4. Keep error arrays small to prevent memory accumulation
5. Use batching for large-scale operations