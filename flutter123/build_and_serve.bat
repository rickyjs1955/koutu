@echo off
echo 🚀 KOUTU Build and Serve Options
echo ================================
echo.
echo Choose your mode:
echo 1. Development mode (hot reload, desktop only)
echo 2. Production mode (works on phone + desktop)
echo.
set /p mode="Enter your choice (1 or 2): "

if "%mode%"=="1" (
    echo.
    echo Starting Flutter development server...
    echo This mode has hot reload but only works on desktop.
    echo.
    echo The app will be accessible at:
    echo   - Local: http://localhost:5000
    echo.
    echo Press Ctrl+C to stop the server
    echo.
    flutter run -d chrome --web-port=5000
) else if "%mode%"=="2" (
    echo.
    echo Building production version...
    call flutter build web --release
    echo.
    echo Finding your IP address...
    echo.
    echo Your computer's IP addresses:
    echo ============================
    for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do echo %%a
    echo.
    cd build\web
    echo Starting web server...
    echo.
    echo The app is accessible at:
    echo   - Desktop: http://localhost:5000
    echo   - Phone: http://[YOUR-IP]:5000
    echo.
    echo Make sure your phone is on the same WiFi network!
    echo.
    echo Press Ctrl+C to stop the server
    echo.
    python -m http.server 5000 --bind 0.0.0.0
) else (
    echo Invalid choice. Please run again and select 1 or 2.
)