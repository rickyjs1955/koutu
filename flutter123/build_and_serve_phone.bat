@echo off
echo 🚀 Building and Serving KOUTU for Desktop and Phone
echo ==================================================
echo.

echo Step 1: Building production web version...
echo.
call flutter build web --release
echo.
echo ✅ Build complete!
echo.

echo Step 2: Finding your IP address...
echo.
echo Your computer's IP addresses:
echo ============================
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do echo %%a
echo.

echo Step 3: Starting web server for phone access...
echo.
cd build\web
echo The app is now accessible at:
echo   - Desktop: http://localhost:5000
echo   - Phone: http://[YOUR-IP]:5000
echo     (Use one of the IP addresses shown above)
echo.
echo Make sure your phone is on the same WiFi network!
echo.
echo Press Ctrl+C to stop the server
echo.
python -m http.server 5000 --bind 0.0.0.0