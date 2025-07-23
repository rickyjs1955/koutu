@echo off
echo 🚀 Building and Serving KOUTU with Enhanced Wardrobe Effect
echo ==========================================================
echo.

echo Step 1: Navigating to Flutter directory...
cd /d "%~dp0\..\flutter"

echo.
echo Step 2: Cleaning previous build...
call flutter clean >nul 2>&1

echo.
echo Step 3: Getting dependencies...
call flutter pub get

echo.
echo Step 4: Building with enhanced wardrobe animation...
echo This will include the proportionally 30%% larger wardrobe doors...
call flutter build web --release

echo.
echo ✅ Build complete with enhanced wardrobe effect!
echo.

echo Step 5: Starting multi-platform server...
cd build\web

echo.
echo 📱 Server starting on port 8888...
echo.
echo Access your app with the enlarged wardrobe effect:
echo   - Local: http://localhost:8888
echo   - Network: http://%COMPUTERNAME%:8888
echo.
echo To access from your phone:
echo   1. Ensure phone is on same WiFi network
echo   2. Find your IP with 'ipconfig' command
echo   3. Visit http://[YOUR-IP]:8888 on phone
echo.
echo The splash screen will show the proportionally 30%% larger wardrobe doors!
echo.
echo Press Ctrl+C to stop the server
echo.

python -m http.server 8888