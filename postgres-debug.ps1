# postgres-debug.ps1 - Debug PostgreSQL issues
Write-Host "🔍 PostgreSQL Debug Analysis" -ForegroundColor Yellow
Write-Host "=============================" -ForegroundColor Yellow

Write-Host "📦 1. Container Status:" -ForegroundColor Cyan
docker ps | Select-String postgres

Write-Host "`n📋 2. PostgreSQL Test Container Logs:" -ForegroundColor Cyan
docker logs koutu-postgres-test --tail 20

Write-Host "`n🔌 3. Testing Direct Connection:" -ForegroundColor Cyan
Write-Host "Testing connection to PostgreSQL test container..."

try {
    $result = docker exec koutu-postgres-test pg_isready -U postgres -d postgres 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PostgreSQL test container is accepting connections" -ForegroundColor Green
    } else {
        Write-Host "❌ PostgreSQL test container is NOT accepting connections" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Failed to check PostgreSQL connection: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n📊 4. Database List:" -ForegroundColor Cyan
try {
    $databases = docker exec koutu-postgres-test psql -U postgres -c "\l" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Databases in PostgreSQL test container:"
        Write-Host $databases
        
        # Check specifically for koutu_test
        if ($databases -match "koutu_test") {
            Write-Host "✅ koutu_test database exists" -ForegroundColor Green
        } else {
            Write-Host "❌ koutu_test database MISSING" -ForegroundColor Red
        }
    } else {
        Write-Host "❌ Could not list databases" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Failed to list databases: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🔧 5. Environment Variables in Container:" -ForegroundColor Cyan
docker exec koutu-postgres-test env | Select-String POSTGRES

Write-Host "`n🌐 6. Network Test:" -ForegroundColor Cyan
Write-Host "Testing connection from host to container on port 5433..."

try {
    # Try to connect using .NET SqlClient (if available) or use telnet-like test
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.ConnectAsync("localhost", 5433).Wait(5000)
    
    if ($tcpClient.Connected) {
        Write-Host "✅ Port 5433 is reachable" -ForegroundColor Green
        $tcpClient.Close()
    } else {
        Write-Host "❌ Port 5433 is NOT reachable" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Cannot reach port 5433: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n🛠️ 7. Manual Database Creation Test:" -ForegroundColor Cyan
Write-Host "Trying to create koutu_test database manually..."

try {
    docker exec koutu-postgres-test psql -U postgres -c "CREATE DATABASE koutu_test;" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ koutu_test database created successfully" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Database might already exist or creation failed" -ForegroundColor Yellow
    }
    
    docker exec koutu-postgres-test psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE koutu_test TO postgres;" 2>$null
    Write-Host "✅ Granted privileges to postgres user" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to create database: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n💡 8. Recommendations:" -ForegroundColor Cyan
Write-Host "Based on the above analysis:" -ForegroundColor White

# Check if container is running
$containerRunning = docker ps | Select-String "koutu-postgres-test"
if (-not $containerRunning) {
    Write-Host "🔧 Container not running - start with: docker-compose up -d postgres-test" -ForegroundColor Yellow
} else {
    Write-Host "🔧 Container is running" -ForegroundColor Green
}

Write-Host "🔧 If database is missing - run: .\test-env-setup.ps1 clean && .\test-env-setup.ps1 restart" -ForegroundColor Yellow
Write-Host "🔧 If connection fails - check your testSetup.ts uses port 5433" -ForegroundColor Yellow

Write-Host "`n🧪 9. Test Your Current testSetup.ts Configuration:" -ForegroundColor Cyan
Write-Host "Your testSetup.ts should be connecting to:" -ForegroundColor White
Write-Host "  Host: localhost" -ForegroundColor Gray
Write-Host "  Port: 5433" -ForegroundColor Gray
Write-Host "  Database: koutu_test" -ForegroundColor Gray
Write-Host "  User: postgres" -ForegroundColor Gray
Write-Host "  Password: postgres" -ForegroundColor Gray