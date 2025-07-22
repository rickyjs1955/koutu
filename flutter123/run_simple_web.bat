@echo off
echo.
echo 🚀 Building and Running Koutu Animation (Simple Mode)
echo ====================================================
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

echo Building web version...
flutter build web

echo.
echo ✅ Build complete! Starting web server...
echo.
echo 💻 To view on THIS computer:
echo    http://localhost:8080
echo.
echo 📱 To view on your PHONE:
if defined IP (
    echo    http://%IP%:8080
) else (
    echo    http://[YOUR-IP]:8080
)
echo.
echo Press Ctrl+C to stop the server
echo.

:: Use Python to serve the built files
cd build\web
python -m http.server 8080