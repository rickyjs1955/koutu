@echo off
echo 📱 KOUTU Local Test Server
echo =========================
echo.

cd build\web

echo Starting server on http://localhost:8888
echo.
echo To test on mobile:
echo 1. Make sure your phone is on the same WiFi network
echo 2. Find your computer's IP address (run 'ipconfig')
echo 3. Open http://[YOUR-IP]:8888 on your phone
echo.
echo Press Ctrl+C to stop the server
echo.
python -m http.server 8888