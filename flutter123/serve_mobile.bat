@echo off
echo 📱 KOUTU Mobile Test Server
echo =========================
echo.

cd build\web

echo Finding your IP address...
echo.
echo Your computer's IP addresses:
echo ============================
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do echo %%a
echo.

echo Starting server on http://0.0.0.0:8888
echo.
echo To test on your phone:
echo 1. Make sure your phone is on the same WiFi network
echo 2. Open your phone's browser
echo 3. Type: http://[YOUR-COMPUTER-IP]:8888
echo    (Use one of the IP addresses shown above)
echo.
echo Example: http://192.168.1.100:8888
echo.
echo Press Ctrl+C to stop the server
echo.
python -m http.server 8888 --bind 0.0.0.0