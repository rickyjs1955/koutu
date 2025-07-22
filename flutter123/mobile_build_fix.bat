@echo off
echo 📱 Building Mobile-Optimized Koutu
echo =================================
echo.

echo Step 1: Cleaning old build...
rmdir /s /q build\web 2>nul

echo.
echo Step 2: Building with mobile optimizations...
echo This may take a minute...
flutter build web --release --dart-define=FLUTTER_WEB_USE_SKIA=false --pwa-strategy=none

echo.
echo Step 3: Patching for better mobile support...
echo ^<script^>window.flutterWebRenderer = "html";^</script^> > build\web\renderer.js

echo.
echo Step 4: Starting server...
echo.
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.
echo 🔄 On your phone: Try refreshing 2-3 times if stuck
echo 💡 Also try: Clear browser cache on phone
echo.

cd build\web
python -m http.server 8085 --bind 0.0.0.0