# Integration Tests

## Overview

This directory contains integration tests for the backend services. These tests run against a real PostgreSQL database to ensure the services work correctly with actual database operations.

## Running Tests

### Prerequisites

1. Docker Desktop must be running
2. PostgreSQL test database must be available on port 5433

### Starting the Test Database

```bash
docker-compose up postgres-test
```

### Running Integration Tests

```bash
npm test -- src/tests/integration/
```

## Test Files

- `polygonService.p2.int.test.ts` - Integration tests for polygon service
- `storageService.p2.int.test.ts` - Integration tests for storage service

## Known Issues

### polygonService.p2.int.test.ts

Two tests are currently skipped due to Jest module caching issues:
1. "should update image status from new to processed"
2. "should handle concurrent polygon operations"

These tests pass when run in isolation but fail when run with the full test suite due to mock interference. To run them individually:

```bash
# Run single test in isolation
npm test -- src/tests/integration/polygonService.p2.int.test.ts -t "should update image status from new to processed"
```

## Test Structure

Integration tests follow this pattern:

1. **Setup**: Initialize database connection and create test data
2. **Execute**: Run the service method being tested
3. **Verify**: Check database state and returned values
4. **Cleanup**: Remove test data and restore state

## Mocking

Some external dependencies are mocked to avoid:
- AI/ML processing (polygonProcessor)
- File system operations (storageService)
- Complex calculations (PolygonServiceUtils)

## Database Schema

Tests use the same database schema as production, defined in:
- `/backend/migrations/` - Database migration files
- `/backend/src/tests/fixtures/testHelpers.ts` - Test data creation utilities