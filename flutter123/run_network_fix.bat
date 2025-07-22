@echo off
echo 🚀 Running Koutu Animation (Network Fix Version)
echo ==========================================
echo.

echo Running with network accessibility...
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

REM Force Flutter to bind to all interfaces, not just localhost
flutter run -d chrome --web-port=8085 --web-hostname=0.0.0.0

pause