@echo off
echo 🚀 Building and Serving KOUTU
echo ============================
echo.

echo Step 1: Building with full animation...
call .\build_full_animation.bat

echo.
echo Step 2: Starting local server...
call .\serve_app.bat