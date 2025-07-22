@echo off
echo 🚀 Building and Serving Koutu Animation (Best for Phones)
echo =========================================================
echo.

echo Step 1: Building optimized web version...
flutter build web --release
echo.

echo Step 2: Starting web server...
echo.

echo 💻 To view on THIS computer:
echo    http://localhost:8085
echo.

echo 📱 To view on your PHONE:
echo    http://192.168.1.126:8085
echo.

echo ✨ This version works perfectly on phones!
echo Press Ctrl+C to stop
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0

pause