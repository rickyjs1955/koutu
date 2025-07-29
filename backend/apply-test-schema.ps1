# PowerShell script to apply test schema for Windows users
$ErrorActionPreference = "Stop"

Write-Host "Applying test schema for Windows environment..." -ForegroundColor Cyan

# Set environment variables
$env:NODE_ENV = "test"
$env:USE_DOCKER_TESTS = "true"
$env:TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:5433/koutu_test"

# Run the Node.js script
try {
    node apply-test-schema.js
    Write-Host "Test schema applied successfully!" -ForegroundColor Green
} catch {
    Write-Host "Error applying test schema: $_" -ForegroundColor Red
    exit 1
}

Write-Host "`nYou can now run the tests with:" -ForegroundColor Yellow
Write-Host '$env:USE_DOCKER_TESTS="true" ; npx jest polygonService.p2.int.test.ts' -ForegroundColor White