@echo off
echo 🚀 Running KOUTU with Flutter Development Server
echo ===============================================
echo.

echo Finding your IP address for phone access...
echo.
echo Your computer's IP addresses:
echo ============================
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do echo %%a
echo.

echo Starting Flutter development server...
echo.
echo The app will be accessible at:
echo   - Local: http://localhost:5000
echo   - Phone: http://[YOUR-IP]:5000
echo     (Use one of the IP addresses shown above)
echo.
echo Make sure your phone is on the same WiFi network!
echo.
echo Press Ctrl+C to stop the server
echo.

flutter run -d chrome --web-port=5000