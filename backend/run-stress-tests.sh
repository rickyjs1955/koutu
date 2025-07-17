#!/bin/bash
# Run stress tests with increased memory limit and garbage collection

echo "Running stress tests with optimized memory settings..."
echo "Note: This may take several minutes to complete."

# Run with increased memory (2GB) and expose garbage collection
node --max-old-space-size=2048 --expose-gc node_modules/.bin/jest --config jest.config.cjs src/tests/stress/exportRoutes.stress.test.ts --runInBand --forceExit

echo "Stress tests completed!"