# PowerShell script to run integration tests with proper setup
param(
    [string]$TestFile = "",
    [switch]$All = $false
)

$ErrorActionPreference = "Stop"

Write-Host "Setting up integration test environment..." -ForegroundColor Cyan

# Set environment variables
$env:NODE_ENV = "test"
$env:USE_DOCKER_TESTS = "true"
$env:TEST_DATABASE_URL = "postgresql://postgres:postgres@localhost:5433/koutu_test"

Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "  NODE_ENV: $env:NODE_ENV"
Write-Host "  USE_DOCKER_TESTS: $env:USE_DOCKER_TESTS"
Write-Host "  TEST_DATABASE_URL: $env:TEST_DATABASE_URL"

# Initialize test database
Write-Host "`nInitializing test database..." -ForegroundColor Cyan
try {
    node init-test-db.js
    Write-Host "Test database initialized successfully!" -ForegroundColor Green
} catch {
    Write-Host "Error initializing test database: $_" -ForegroundColor Red
    Write-Host "Make sure Docker PostgreSQL is running on port 5433" -ForegroundColor Yellow
    exit 1
}

# Small delay to ensure database is ready
Start-Sleep -Seconds 1

# Run the tests
if ($All -or $TestFile -eq "") {
    Write-Host "`nRunning ALL integration tests..." -ForegroundColor Cyan
    try {
        npm run test:integration:all -w backend
    } catch {
        Write-Host "Some tests failed. Check the output above for details." -ForegroundColor Yellow
    }
} else {
    Write-Host "`nRunning test: $TestFile" -ForegroundColor Cyan
    try {
        npx jest $TestFile --forceExit
    } catch {
        Write-Host "Test execution completed with errors" -ForegroundColor Yellow
    }
}