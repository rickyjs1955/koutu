@echo off
echo.
echo 🚀 Running Koutu Animation in Debug Mode
echo ========================================
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

echo Running in debug mode for better performance...
echo.
echo 💻 To view on THIS computer:
echo    http://localhost:9090
echo.
echo 📱 To view on your PHONE:
if defined IP (
    echo    http://%IP%:9090
) else (
    echo    http://[YOUR-IP]:9090
)
echo.
echo Starting Flutter web server...
echo Press Ctrl+C to stop
echo.

:: Run in debug mode without release flag
flutter run -d chrome --web-port=9090 lib/main_web_loop.dart