@echo off
echo 🧪 Testing Simple Version of Koutu
echo =================================
echo.

echo Building simple test version...
flutter build web --release --target=lib/simple_test.dart

echo.
echo Starting server...
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.
echo This simple version should work on all devices.
echo If this works but the main app doesn't, the animations might be too complex.
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0