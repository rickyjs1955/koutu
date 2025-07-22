@echo off
echo.
echo 🚀 Running Koutu Animation Loop Version
echo ======================================
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

echo This version loops the animation continuously!
echo.
echo 💻 To view on THIS computer:
echo    http://localhost:8090
echo.
echo 📱 To view on your PHONE:
if defined IP (
    echo    http://%IP%:8090
) else (
    echo    http://[YOUR-IP]:8090
)
echo.
echo Starting Flutter web server...
echo Press Ctrl+C to stop
echo.

:: Run the looping version
flutter run -d chrome --web-port=8090 --release lib/main_web_loop.dart