@echo off
echo 🚀 Koutu Animation - Simple HTTP Server
echo =====================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found! Trying Python 3...
    py -3 --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo ❌ Python 3 not found either!
        echo.
        echo Please install Python from https://www.python.org/downloads/
        echo Or use Node.js alternative below.
        pause
        exit /b 1
    ) else (
        set PYTHON_CMD=py -3
    )
) else (
    set PYTHON_CMD=python
)

echo ✅ Python found!
echo.

REM Check if web build exists
if not exist "build\web\index.html" (
    echo 📦 Building web version first...
    flutter build web --release
)

echo 🌐 Starting web server...
echo.
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.
echo Press Ctrl+C to stop
echo.

cd build\web
%PYTHON_CMD% -m http.server 8085 --bind 0.0.0.0