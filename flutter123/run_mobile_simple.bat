@echo off
echo 📱 Building Simplified Mobile Version
echo ===================================
echo.

echo This version has simpler animations that work better on phones...
echo.

flutter build web --release --target=lib/mobile_simple.dart

echo.
echo Starting server...
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0