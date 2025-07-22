@echo off
echo 🚀 Running Koutu Animation (Release Mode - Phone Friendly)
echo ========================================================
echo.

echo Running in release mode (no debugging, works great on phones!)...
echo.

echo 💻 To view on THIS computer:
echo    http://localhost:8085
echo.

echo 📱 To view on your PHONE:
echo    http://192.168.1.126:8085
echo.

echo Starting Flutter web server...
echo Press Ctrl+C to stop
echo.

REM Run in release mode with network access
flutter run -d chrome --release --web-port=8085 --web-hostname=0.0.0.0

pause