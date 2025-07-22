@echo off
echo 🌟 Building KOUTU with Full Stunning Animation
echo ============================================
echo.

echo Step 1: Cleaning old build...
call flutter clean >nul 2>&1

echo Step 2: Getting dependencies...
call flutter pub get

echo Step 3: Building with full animation (this uses main.dart)...
echo This may take a minute...
call flutter build web --release

echo.
echo ✅ Build complete with full animation!
echo.
echo 📂 Your stunning build is in: build\web
echo.
echo To test locally:
echo   .\serve_app.bat
echo.
echo Or deploy the build\web folder to your web server.
echo.
pause