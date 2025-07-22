@echo off
echo 🚀 Running Koutu Animation (Python Server)
echo =========================================
echo.

echo First, let's build the web version...
flutter build web
echo.

echo Starting Python web server...
echo.

echo 💻 To view on THIS computer:
echo    http://localhost:8085
echo.

echo 📱 To view on your PHONE:
echo    http://192.168.1.126:8085
echo.

echo Press Ctrl+C to stop
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0

pause