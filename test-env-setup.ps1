# test-env-setup.ps1 - Windows PowerShell version
param(
    [Parameter(Position=0)]
    [string]$Command = "help"
)

Write-Host "🧪 Koutu Integration Test Environment Setup" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow

function Clean-Everything {
    Write-Host "🧹 Cleaning up all test resources..." -ForegroundColor Cyan
    
    # Stop all containers
    docker-compose down -v
    
    # Remove specific volumes
    docker volume rm koutu_postgres_test_data 2>$null
    docker volume rm koutu_postgres_dev_data 2>$null  
    docker volume rm koutu_firebase_emulator_data 2>$null
    
    Write-Host "✅ All test resources cleaned" -ForegroundColor Green
}

function Start-PostgresOnly {
    Write-Host "🐘 Starting PostgreSQL services only..." -ForegroundColor Cyan
    docker-compose up -d postgres-dev postgres-test
    
    Write-Host "⏳ Waiting for PostgreSQL to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 15
    
    Check-Postgres
}

function Start-FirebaseOnly {
    Write-Host "🔥 Starting Firebase emulator only..." -ForegroundColor Cyan
    docker-compose up -d firebase-emulator
    
    Write-Host "⏳ Waiting for Firebase emulator to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 20
    
    Check-Firebase
}

function Start-AllServices {
    Write-Host "🚀 Starting all test services..." -ForegroundColor Cyan
    docker-compose up -d
    
    Write-Host "⏳ Waiting for all services to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
    
    Check-Postgres
    Check-Firebase
}

function Check-Postgres {
    Write-Host "🔍 Checking PostgreSQL services..." -ForegroundColor Cyan
    
    # Check dev database
    $devResult = docker exec koutu-postgres-dev pg_isready -U postgres -d postgres 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PostgreSQL Dev (port 5432): Ready" -ForegroundColor Green
        
        # Check if koutu database exists
        $dbCheck = docker exec koutu-postgres-dev psql -U postgres -lqt 2>$null | Select-String "koutu"
        if ($dbCheck) {
            Write-Host "✅ Database 'koutu' exists" -ForegroundColor Green
        } else {
            Write-Host "⚠️ Database 'koutu' not found" -ForegroundColor Yellow
        }
    } else {
        Write-Host "❌ PostgreSQL Dev: Not ready" -ForegroundColor Red
    }
    
    # Check test database  
    $testResult = docker exec koutu-postgres-test pg_isready -U postgres -d postgres 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PostgreSQL Test (port 5433): Ready" -ForegroundColor Green
        
        # Check if koutu_test database exists
        $testDbCheck = docker exec koutu-postgres-test psql -U postgres -lqt 2>$null | Select-String "koutu_test"
        if ($testDbCheck) {
            Write-Host "✅ Database 'koutu_test' exists" -ForegroundColor Green
        } else {
            Write-Host "⚠️ Database 'koutu_test' not found - creating it..." -ForegroundColor Yellow
            Create-TestDatabase
        }
    } else {
        Write-Host "❌ PostgreSQL Test: Not ready" -ForegroundColor Red
    }
}

function Check-Firebase {
    Write-Host "🔍 Checking Firebase emulator..." -ForegroundColor Cyan
    
    $services = @(
        @{Name="Auth"; Port=9099},
        @{Name="Firestore"; Port=9100}, 
        @{Name="Storage"; Port=9199},
        @{Name="UI"; Port=4000}
    )
    
    foreach ($service in $services) {
        try {
            if ($service.Name -eq "Storage") {
                # Storage returns 501 - this is expected
                $response = Invoke-WebRequest -Uri "http://localhost:$($service.Port)" -TimeoutSec 5 -ErrorAction Stop
                if ($response.StatusCode -eq 501) {
                    Write-Host "✅ Firebase $($service.Name) (port $($service.Port)): Ready (501 expected)" -ForegroundColor Green
                } else {
                    Write-Host "❌ Firebase $($service.Name) (port $($service.Port)): Unexpected status $($response.StatusCode)" -ForegroundColor Red
                }
            } else {
                $response = Invoke-WebRequest -Uri "http://localhost:$($service.Port)" -TimeoutSec 5 -ErrorAction Stop
                Write-Host "✅ Firebase $($service.Name) (port $($service.Port)): Ready" -ForegroundColor Green
            }
        } catch {
            Write-Host "❌ Firebase $($service.Name) (port $($service.Port)): Not ready" -ForegroundColor Red
        }
    }
}

function Create-TestDatabase {
    Write-Host "🛠️ Creating test database manually..." -ForegroundColor Cyan
    
    docker exec koutu-postgres-test psql -U postgres -c "CREATE DATABASE koutu_test;" 2>$null
    docker exec koutu-postgres-test psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE koutu_test TO postgres;" 2>$null
    
    Write-Host "✅ Test database created" -ForegroundColor Green
}

function Start-ApiErrorTests {
    Write-Host "🧪 Running ApiError integration tests..." -ForegroundColor Cyan
    Push-Location backend
    
    # Set environment for PostgreSQL only
    $env:NODE_ENV = "test"
    $env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5433/koutu_test"
    $env:DATABASE_HOST = "localhost"
    $env:DATABASE_PORT = "5433"
    $env:DATABASE_NAME = "koutu_test"
    $env:DATABASE_USER = "postgres"
    $env:DATABASE_PASSWORD = "postgres"
    
    Write-Host "🔧 Environment variables set for PostgreSQL" -ForegroundColor Green
    
    npx jest ApiError.int.test.ts --verbose
    Pop-Location
}

function Start-FirebaseTests {
    Write-Host "🧪 Running Firebase integration tests..." -ForegroundColor Cyan
    Push-Location backend
    
    # Set environment for Firebase emulators
    $env:NODE_ENV = "test"
    $env:FIRESTORE_EMULATOR_HOST = "localhost:9100"
    $env:FIREBASE_AUTH_EMULATOR_HOST = "localhost:9099"
    $env:FIREBASE_STORAGE_EMULATOR_HOST = "localhost:9199"
    $env:GCLOUD_PROJECT = "demo-test-project"
    $env:FIREBASE_PROJECT_ID = "demo-test-project"
    
    # Also set PostgreSQL for tests that need both
    $env:DATABASE_URL = "postgresql://postgres:postgres@localhost:5433/koutu_test"
    $env:DATABASE_HOST = "localhost"
    $env:DATABASE_PORT = "5433"
    $env:DATABASE_NAME = "koutu_test"
    $env:DATABASE_USER = "postgres"
    $env:DATABASE_PASSWORD = "postgres"
    
    Write-Host "🔧 Environment variables set for Firebase + PostgreSQL" -ForegroundColor Green
    
    # Clear Firebase data first
    try {
        Invoke-WebRequest -Uri "http://localhost:9099/emulator/v1/projects/demo-test-project/accounts" -Method DELETE -ErrorAction SilentlyContinue
    } catch {}
    
    npx jest firebase.int.test.ts --verbose
    Pop-Location
}

function Start-AllTests {
    Write-Host "🧪 Running all integration tests..." -ForegroundColor Cyan
    
    Write-Host "1️⃣ Running ApiError tests (PostgreSQL only)..." -ForegroundColor Yellow
    Start-ApiErrorTests
    
    Write-Host ""
    Write-Host "2️⃣ Running Firebase tests (Firebase + PostgreSQL)..." -ForegroundColor Yellow
    Start-FirebaseTests
    
    Write-Host ""
    Write-Host "🎉 All integration tests completed!" -ForegroundColor Green
}

function Show-Status {
    Write-Host "📊 Service Status:" -ForegroundColor Cyan
    Write-Host "=================="
    docker-compose ps
    
    Write-Host ""
    Check-Postgres
    Write-Host ""
    Check-Firebase
    
    Write-Host ""
    Write-Host "🌐 Available Services:" -ForegroundColor Cyan
    Write-Host "• PostgreSQL Dev:      localhost:5432"
    Write-Host "• PostgreSQL Test:     localhost:5433"
    Write-Host "• Firebase Auth:       localhost:9099"
    Write-Host "• Firebase Firestore:  localhost:9100"
    Write-Host "• Firebase Storage:    localhost:9199"
    Write-Host "• Firebase UI:         http://localhost:4000"
}

function Restart-Everything {
    Clean-Everything
    Start-Sleep -Seconds 5
    Start-AllServices
}

# Main command processing
switch ($Command.ToLower()) {
    "clean" { 
        Clean-Everything 
    }
    "postgres" { 
        Start-PostgresOnly 
    }
    "firebase" { 
        Start-FirebaseOnly 
    }
    "start" { 
        Start-AllServices 
    }
    "all" { 
        Start-AllServices 
    }
    "status" { 
        Show-Status 
    }
    "test-api" { 
        Start-ApiErrorTests 
    }
    "test-firebase" { 
        Start-FirebaseTests 
    }
    "test-all" { 
        Start-AllTests 
    }
    "restart" { 
        Restart-Everything 
    }
    default {
        Write-Host "Usage: .\test-env-setup.ps1 {clean|postgres|firebase|start|status|test-api|test-firebase|test-all|restart}" -ForegroundColor White
        Write-Host ""
        Write-Host "Commands:" -ForegroundColor Cyan
        Write-Host "  clean          - Clean all containers and volumes"
        Write-Host "  postgres       - Start only PostgreSQL services"
        Write-Host "  firebase       - Start only Firebase emulator"
        Write-Host "  start/all      - Start all services"
        Write-Host "  status         - Show service status"
        Write-Host "  test-api       - Run ApiError tests (PostgreSQL only)"
        Write-Host "  test-firebase  - Run Firebase tests (Firebase + PostgreSQL)"
        Write-Host "  test-all       - Run all integration tests"
        Write-Host "  restart        - Clean and restart everything"
        Write-Host ""
        Write-Host "🎯 Quick start: " -NoNewline -ForegroundColor White
        Write-Host ".\test-env-setup.ps1 restart" -ForegroundColor Green
        Write-Host "Then: " -NoNewline -ForegroundColor White  
        Write-Host ".\test-env-setup.ps1 test-all" -ForegroundColor Green
    }
}