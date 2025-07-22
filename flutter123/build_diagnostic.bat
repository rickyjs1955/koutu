@echo off
echo 📱 Building Mobile Diagnostic Version
echo ===================================
echo.

echo Step 1: Backing up original main.dart...
copy lib\main.dart lib\main_original.dart >nul 2>&1

echo Step 2: Using diagnostic version...
copy lib\mobile_diagnostic.dart lib\main.dart >nul 2>&1

echo Step 3: Building...
call flutter build web --release

echo Step 4: Restoring original main.dart...
copy lib\main_original.dart lib\main.dart >nul 2>&1
del lib\main_original.dart >nul 2>&1

echo.
echo ✅ Diagnostic build complete!
echo.
echo 📂 Your diagnostic build is in: build\web
echo.
echo This version will show:
echo - Loading status messages
echo - Screen dimensions
echo - Debug logs
echo - A simple animation test
echo - An interaction test button
echo.
pause