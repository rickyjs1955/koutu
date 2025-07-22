@echo off
echo 🔧 Mobile Browser Fix for Koutu (Updated)
echo ========================================
echo.

echo Building with mobile optimizations...
flutter build web --release --web-renderer=html

echo.
echo 📱 This build uses HTML renderer for better mobile compatibility
echo.

echo Starting server...
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0