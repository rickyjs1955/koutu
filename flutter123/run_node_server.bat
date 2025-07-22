@echo off
echo 🚀 Koutu Animation - Node.js Server
echo ==================================
echo.

REM Check if Node.js is available
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js not found!
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

REM Check if web build exists
if not exist "build\web\index.html" (
    echo 📦 Building web version first...
    flutter build web --release
)

REM Check if http-server is installed
npx http-server --version >nul 2>&1
if %errorlevel% neq 0 (
    echo 📦 Installing http-server...
    npm install -g http-server
)

echo 🌐 Starting web server...
echo.
echo 💻 Local: http://localhost:8085
echo 📱 Phone: http://192.168.1.126:8085
echo.
echo Press Ctrl+C to stop
echo.

cd build\web
npx http-server -p 8085 -a 0.0.0.0 --cors