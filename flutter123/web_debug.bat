@echo off
echo 🔍 Running Koutu Animation - Debug Version
echo ========================================
echo.

echo Building web version with source maps for debugging...
flutter build web --source-maps

echo.
echo 📱 Instructions for debugging on phone:
echo 1. Connect your phone to Chrome DevTools
echo 2. Open Chrome on your computer
echo 3. Go to: chrome://inspect/#devices
echo 4. Open http://192.168.1.126:8085 on your phone
echo 5. Click "inspect" when your phone appears
echo.

echo Starting server...
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0