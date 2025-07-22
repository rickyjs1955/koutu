@echo off
echo.
echo 🔍 Checking which ports are in use...
echo ====================================
echo.

echo Common ports status:
echo.

for %%p in (8080 8090 3000 5000 5001 8081 9000) do (
    netstat -an | findstr :%%p >nul
    if errorlevel 1 (
        echo ✅ Port %%p is AVAILABLE
    ) else (
        echo ❌ Port %%p is IN USE
    )
)

echo.
echo To see what's using a specific port:
echo   netstat -ano ^| findstr :PORT_NUMBER
echo.
pause