@echo off
echo 🔍 Testing Phone Connection Setup
echo ================================
echo.

echo 1. Checking your IP address...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (
    for /f "tokens=1" %%b in ("%%a") do (
        echo    Found IP: %%b
        set MY_IP=%%b
    )
)

echo.
echo 2. Testing if port 8085 is in use...
netstat -an | findstr :8085 >nul
if %errorlevel% equ 0 (
    echo    ⚠️  Port 8085 is already in use!
    echo    Kill any existing servers first.
) else (
    echo    ✅ Port 8085 is available
)

echo.
echo 3. Checking Python availability...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py -3 --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo    ❌ Python not found
    ) else (
        echo    ✅ Python 3 found (py -3)
    )
) else (
    echo    ✅ Python found
)

echo.
echo 4. Creating a simple test file...
if not exist "test_server" mkdir test_server
echo ^<html^>^<body^>^<h1^>Phone Connection Test Successful!^</h1^>^<p^>If you can see this on your phone, the connection works.^</p^>^</body^>^</html^> > test_server\index.html

echo.
echo 5. Starting test server...
echo.
echo 📱 On your phone, try: http://%MY_IP%:8085
echo.
echo If the test works, we know the connection is good.
echo Press Ctrl+C to stop
echo.

cd test_server
python -m http.server 8085 --bind 0.0.0.0 2>nul || py -3 -m http.server 8085 --bind 0.0.0.0