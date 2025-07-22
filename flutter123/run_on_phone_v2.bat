@echo off
echo.
echo 🚀 Running Koutu Animation for Phone Access
echo ==========================================
echo.

:: Get IP address
set IP=
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address" ^| findstr /v "127.0.0.1"') do (
    for /f "tokens=* delims= " %%b in ("%%a") do (
        set IP=%%b
        goto :found
    )
)
:found

echo 💻 To view on THIS computer:
echo    http://localhost:5001
echo.
echo 📱 To view on your PHONE:
echo    1. Make sure your phone is on the same WiFi network
echo    2. Open your phone's browser
if defined IP (
    echo    3. Go to: http://%IP%:5001
) else (
    echo    3. Run 'ipconfig' to find your IPv4 address
    echo       Then go to: http://[YOUR-IP]:5001
)
echo.
echo Starting Flutter web server...
echo Press Ctrl+C to stop
echo.

:: Run Flutter with web server accessible from network
flutter run -d chrome --web-port=5001 --web-hostname=0.0.0.0 lib/main_with_export.dart