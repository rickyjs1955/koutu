# Running Integration Tests

## Prerequisites

1. Docker must be running with PostgreSQL on port 5433
2. Node.js and npm installed
3. PowerShell (for Windows users)

## Quick Start (Windows PowerShell)

Run the provided PowerShell script:

```powershell
# Run all polygon service tests
.\run-integration-test.ps1

# Run a specific test file
.\run-integration-test.ps1 -TestFile "testImageModel.int.test.ts"
```

## Manual Setup

If the PowerShell script doesn't work, you can run the tests manually:

1. Initialize the test database:
   ```bash
   node init-test-db.js
   ```

2. Set environment variables and run tests:
   ```powershell
   $env:NODE_ENV="test"
   $env:USE_DOCKER_TESTS="true"
   $env:TEST_DATABASE_URL="postgresql://postgres:postgres@localhost:5433/koutu_test"
   npx jest polygonService.p2.int.test.ts
   ```

## Troubleshooting

### "Image not found" errors
This usually means the test database wasn't properly initialized. Run:
```bash
node init-test-db.js
```

### "Cannot connect to database" errors
Make sure Docker is running and PostgreSQL is available on port 5433:
```bash
docker ps
```

### Tests hang or don't exit
Add the `--forceExit` flag to Jest:
```bash
npx jest polygonService.p2.int.test.ts --forceExit
```

## Test Files

- `polygonService.p2.int.test.ts` - Tests for polygon creation, validation, and management
- `testImageModel.int.test.ts` - Tests for image model database operations

## Database Schema

The test database uses a schema defined in `migrations/test_schema.sql` which includes:
- users
- original_images
- polygons
- garment_items
- wardrobes
- wardrobe_items

The schema is automatically applied when you run `init-test-db.js`.