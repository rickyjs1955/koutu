@echo off
echo 📱 Building Mobile-Optimized Koutu with Simple Animation
echo =========================================
echo.

echo Step 1: Backing up original main.dart...
copy lib\main.dart lib\main_original.dart >nul 2>&1

echo Step 2: Replacing with mobile-optimized version...
copy lib\mobile_simple.dart lib\main.dart >nul 2>&1

echo Step 3: Cleaning old build...
call flutter clean >nul 2>&1

echo Step 4: Building with mobile optimizations...
echo This may take a minute...
call flutter build web --web-renderer=canvaskit --release

echo Step 5: Restoring original main.dart...
copy lib\main_original.dart lib\main.dart >nul 2>&1
del lib\main_original.dart >nul 2>&1

echo.
echo ✅ Build complete!
echo.
echo 📂 Your mobile-optimized build is in: build\web
echo.
echo To test locally:
echo   cd build\web
echo   python -m http.server 8000
echo.
echo Then open http://localhost:8000 on your mobile device
echo.
pause